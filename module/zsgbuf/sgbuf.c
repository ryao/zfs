/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2013, Richard Yao. All rights reserved.
 */

/*
 * Scatter-gather buffers
 *
 * This is a lowlevel interface that was invented to replace slab allocation
 * for ZIO buffers. The replacement is done by using sgbuf_t pointers in place
 * of void pointers in code that uses ZIO buffers with sgbuf_t pointers.
 * sgbuf_alloc() is called to create a scatter-gather buffer containing the
 * number of pages required to store data. Accessing the pages directly is not
 * advised. Various functions are provided for data manipulation. All functions
 * contain assertions to validate that sane inputs have been provided.
 *
 * Thread safety is the responsibility of the caller.
 *
 * Original idea by Brian Behlendorf:
 * https://github.com/zfsonlinux/zfs/issues/75
 */

#ifdef _KERNEL
#include <sys/kmem.h>
#include <sys/list.h>
#include <sys/mutex.h>
#else
#include <sys/zfs_context.h>
#endif

#include <sys/sgbuf.h>
#include <sys/sysmacros.h>

typedef struct free_page {
	list_node_t free_list;
	struct page *page;
} free_page_t;

#ifndef _KERNEL

/* Page allocation routines */
#  define native_alloc_page(n)	malloc(PAGE_SIZE)
#  define native_free_page(n)	free(n)

/* Page mapping routines (permits access to high mem pages) */
#  define native_page_map(n)	((void *)(n))
#  define native_page_unmap(n)	((void)0)

#elif defined(__linux__)

/* Page allocation routines */
#  define native_alloc_page(n)	alloc_page(n)
#  define native_free_page(n)	__free_page(n)

/* Page mapping routines (permits access to high mem pages) */
#  define native_page_map(n)	kmap(n)
#  define native_page_unmap(n)	kunmap(n)

#else
#  error "Unsupported kernel"
#endif

/* Inline trick borrowed from LZ4 */
#ifdef __GNUC__
#  define FORCE_INLINE static inline __attribute__((always_inline))
#else
#  define FORCE_INLINE static inline
#endif

#define SGBUF_PAGE(n, i) ((n)->pages[(i)])
#define SGBUF_PAGE_INDEX(n) ((n) >> PAGE_SHIFT)
#define SGBUF_PAGE_OFFSET(n) (P2PHASE((n), PAGE_SIZE))

static kmem_cache_t *sgbuf_cache;

/* Variables for managing free page pool */
static list_t sg_buf_page_free_list;
static volatile unsigned long sg_buf_page_free_count = 0;
static unsigned long sg_buf_page_free_max = 64;
static kmutex_t sg_buf_alloc_lock;

static struct page *
sgbuf_page_alloc(int flags)
{
	/* XXX: This will always be satisfied on Solaris because KM_SLEEP is 0
	 * there. That is wrong. This works on the Linux port because we
	 * currently set bits internal to Linux. We should modify the Linux
	 * port to use the Solaris bits and then modify this to check for
	 * KM_SLEEP correctly.
	 * */
	if ((flags & KM_SLEEP) == KM_SLEEP)
		return native_alloc_page(flags);

	if (sg_buf_page_free_count > 0) {
		mutex_enter(&sg_buf_alloc_lock);
		if (sg_buf_page_free_count > 0) {
			free_page_t *entry;
			struct page *page;
			ASSERT(!list_is_empty(&sg_buf_page_free_list));
			entry = list_remove_head(&sg_buf_page_free_list);
			sg_buf_page_free_count--;
			mutex_exit(&sg_buf_alloc_lock);
			page = entry->page;
			kmem_free(entry, sizeof (free_page_t));
			return (page);
		}

		ASSERT(list_is_empty(&sg_buf_page_free_list));
		mutex_exit(&sg_buf_alloc_lock);
	}

	return native_alloc_page(flags);
}

static void
sgbuf_page_free(struct page *page)
{
	if (sg_buf_page_free_count < sg_buf_page_free_max) {
		mutex_enter(&sg_buf_alloc_lock);

		if (sg_buf_page_free_count < sg_buf_page_free_max) {
			free_page_t *entry;

			entry =  kmem_alloc(sizeof (free_page_t), KM_NOSLEEP);

			if (entry == NULL) {
				mutex_exit(&sg_buf_alloc_lock);
				native_free_page(page);
				return;
			}

			entry->page = page;

			list_link_init(&entry->free_list);
			list_insert_tail(&sg_buf_page_free_list, entry);
			sg_buf_page_free_count++;

		}

		mutex_exit(&sg_buf_alloc_lock);
	}

	native_free_page(page);
}

static void
sgbuf_dest(void *arg, void *unused)
{
	int i;
	sgbuf_t *buf = (sgbuf_t*)arg;

#ifdef _KERNEL
	if (buf->addr)
		sgbuf_unmap(buf);
#endif

	for ( i = 0 ; i < buf->count ; i++ )
		sgbuf_page_free(buf->pages[i]);

	kmem_free(buf->pages, buf->count * sizeof(struct page*));

	buf->addr = NULL;
	buf->count = 0;
}

int
sgbuf_init(void)
{
	sgbuf_cache = kmem_cache_create("sgbuf_cache", sizeof (sgbuf_t), 0, NULL, sgbuf_dest, NULL, NULL, NULL, KMC_KMEM);

	/* XXX: SPL Mutex implements MUTEX_SPIN as MUTEX_DEFAULT */
	mutex_init(&sg_buf_alloc_lock, NULL, MUTEX_SPIN, NULL);
	list_create(&sg_buf_page_free_list, sizeof (free_page_t),
		offsetof(free_page_t, free_list));
	return sgbuf_cache == 0;
}

int
sgbuf_fini(void)
{
	while (!list_is_empty(&sg_buf_page_free_list))
		native_free_page(list_remove_head(&sg_buf_page_free_list));
	list_destroy(&sg_buf_page_free_list);
	mutex_destroy(&sg_buf_alloc_lock);

	kmem_cache_destroy(sgbuf_cache);

	return 0;
}

sgbuf_t *
sgbuf_alloc(int size, int flags)
{
	int i;
	sgbuf_t *buf = kmem_cache_alloc(sgbuf_cache, flags);

	buf->count = P2ROUNDUP(size, PAGE_SIZE) >> PAGE_SHIFT;
	buf->pages = kmem_alloc(sizeof(struct pages*) * buf->count,
		flags | KM_NODEBUG);
	if (buf->pages == NULL) {
		buf->count = 0;
		return NULL;
	}

	/* XXX: alloc_page() can fail */
	for ( i = 0 ; i < buf->count ; i++ )
		buf->pages[i] = sgbuf_page_alloc(flags);

	buf->addr = NULL;

#ifdef DEBUG
	buf->magic = SGBUF_MAGIC;
#endif

	return buf;
}

sgbuf_t *
sgbuf_zalloc(int size, int flags)
{
	sgbuf_t *ret = sgbuf_alloc(size, flags);
	sgbuf_bzero(ret, 0, SGBUF_SIZE(ret));
	return ret;
}

void
sgbuf_free(sgbuf_t *buf)
{
	ASSERT_SGBUF(buf);
	kmem_cache_free(sgbuf_cache, buf);
}

#ifdef _KERNEL
void *
sgbuf_map(sgbuf_t *buf)
{
	ASSERT_SGBUF(buf);
	if (buf->addr)
		return buf->addr;

	return buf->addr = vm_map_ram(buf->pages, buf->count, NUMA_NO_NODE, PAGE_KERNEL);
}

void
sgbuf_unmap(sgbuf_t * buf)
{
	ASSERT_SGBUF(buf);
	if (buf->addr)
		vm_unmap_ram(buf->addr, buf->count);

	buf->addr = NULL;
}
#endif

/*
 * sgbuf_bcmp(): sgbuf_t version of bcmp().
 *
 * This is functionally identical to bcmp(). The only real difference is the
 * inclusion of assertions to check that valid buffers have been passed.
 */

int
sgbuf_bcmp(sgbuf_t *s1, sgbuf_t *s2, size_t size)
{
	int i, ret;

	ASSERT_SGBUF(s1);
	ASSERT_SGBUF(s2);
	ASSERT(size <= SGBUF_SIZE(s1));
	ASSERT(size <= SGBUF_SIZE(s2));


	for ( i = 0 ; size >= PAGE_SIZE; size -= PAGE_SIZE, i++ ) {
		void *p1 = native_page_map(s1->pages[i]);
		void *p2 = native_page_map(s2->pages[i]);

		ret = bcmp(p1, p2, PAGE_SIZE);

		native_page_unmap(s1->pages[i]);
		native_page_unmap(s2->pages[i]);

		if (ret)
			return ret;
	}

	if (size) {
		void *p1 = native_page_map(s1->pages[i]);
		void *p2 = native_page_map(s2->pages[i]);

		ret = bcmp(p1, p2, size);

		native_page_unmap(s1->pages[i]);
		native_page_unmap(s2->pages[i]);
	}

	return ret;
}

/*
 * Internal sgbuf_bcopy() implementation that handles copies with page alignment
 */

FORCE_INLINE void
sgbuf_bcopy_aligned(const sgbuf_t *s1, sgbuf_t *s2, size_t off1, size_t off2, size_t size)
{

	int i = off1 >> PAGE_SHIFT, j = off2 >> PAGE_SHIFT;

	/* XXX: We could subsitute COW for memcpy() */
	for (  ; size >= PAGE_SIZE; size -= PAGE_SIZE, i++, j++ ) {
		void *p1 = native_page_map(s1->pages[i]);
		void *p2 = native_page_map(s2->pages[j]);

		memcpy(p2, p1, PAGE_SIZE);

		native_page_unmap(s1->pages[i]);
		native_page_unmap(s2->pages[j]);
	}

	if (size) {
		void *p1 = native_page_map(s1->pages[i]);
		void *p2 = native_page_map(s2->pages[j]);

		memcpy(p2, p1, size);

		native_page_unmap(s1->pages[i]);
		native_page_unmap(s2->pages[j]);
	}


}

/*
 * Internal sgbuf_bcopy implementation that handles copies without page alignment
 */

FORCE_INLINE void
sgbuf_bcopy_unaligned(const sgbuf_t *s1, sgbuf_t *s2, size_t off1, size_t off2, size_t size)
{

	int i = off1 >> PAGE_SHIFT, j = off2 >> PAGE_SHIFT;
	void *p1 = NULL, *p2 = NULL;
	int tocopy = 0;

	while (size) {
		p1 = (p1) ? p1 : native_page_map(s1->pages[i]);
		p2 = (p2) ? p2 : native_page_map(s2->pages[j]);

		off1 = P2PHASE(off1 + tocopy, PAGE_SIZE);
		off2 = P2PHASE(off2 + tocopy, PAGE_SIZE);

		tocopy = PAGE_SIZE - MAX(off1, off2);
		tocopy = MIN(tocopy, size);

		memcpy(p2 + off2, p1 + off1, tocopy);

		if (off1 <= off2) {
			native_page_unmap(s1->pages[i]);
			p1 = NULL;
			i++;
		}

		if (off1 <= off2) {
			native_page_unmap(s2->pages[j]);
			p2 = NULL;
			j++;
		}

		size -= tocopy;
	}

	if (p1)
		native_page_unmap(s1->pages[i]);
	if (p2)
		native_page_unmap(s2->pages[j]);

}

/*
 * sgbuf_bcopy(): sgbuf_t version of bcopy().
 *
 * This is similar to bcopy(), except it takes sgbuf_t pointers and an
 * additional offset argument. The offset argument is permits translation of
 * bcopy(src + offset, dest, size) into sgbuf_bcopy(src, dest offset, size).
 */

void
sgbuf_bcopy(const sgbuf_t *s1, sgbuf_t *s2, size_t off1, size_t off2, size_t size)
{
	ASSERT_SGBUF(s1);
	ASSERT_SGBUF(s2);
	ASSERT(off1 + size <= SGBUF_SIZE(s1));
	ASSERT(off2 + size <= SGBUF_SIZE(s2));

	if (((P2PHASE(off1, PAGE_SIZE)) == 0) && ((P2PHASE(off2, PAGE_SIZE)) == 0))
		sgbuf_bcopy_aligned(s1, s2, off1, off2, size);
	else
		sgbuf_bcopy_unaligned(s1, s2, off1, off2, size);
}

/*
 * Function to zero sgbuf.
 *
 * One would typically do `bzero(addr + offset, len)` to zero the tail of a
 * buffer. Conversion to an sgbuf makes this `sgbuf_bzero(buf, offset, len)`.
 *
 * Note: Linux does expensive native_page_map()/native_page_unmap() calls whenever a high memory page
 * is touched. These involve page table manipulation.
 */

void
sgbuf_bzero(sgbuf_t *buf, size_t offset, size_t len) {
	size_t i = offset >> PAGE_SHIFT;

	ASSERT_SGBUF(buf);
	ASSERT(offset + len <= SGBUF_SIZE(buf));

	offset = P2PHASE(offset, PAGE_SIZE);

	/* Handle partial page at beginning */
	if (offset) {
		void *p = native_page_map(buf->pages[i]);
		bzero(p + offset, MIN(PAGE_SIZE - offset, len));
		native_page_unmap(buf->pages[i++]);
		len -= PAGE_SIZE - offset;
	}

	/* XXX: We could do page table manipulation to use CoW */
	for (  ; len > PAGE_SIZE ; i++, len -= PAGE_SIZE ) {
		void *p = native_page_map(buf->pages[i]);
		bzero(p, PAGE_SIZE);
		native_page_unmap(buf->pages[i]);
	}

	/* Handle partial page at end */
	if (len > 0) {
		void *p = native_page_map(buf->pages[i]);
		bzero(p, len);
		native_page_unmap(buf->pages[i]);
	}

}
void
sgbuf_bswap16(sgbuf_t *buf, size_t offset, size_t len) {
	size_t i = offset >> PAGE_SHIFT;

	ASSERT_SGBUF(buf);
	ASSERT(offset + len <= SGBUF_SIZE(buf));
	ASSERT(ISP2(offset) && offset >= sizeof(uint16_t));
	ASSERT(ISP2(len) && len >= sizeof(uint16_t));

	offset = P2PHASE(offset, PAGE_SIZE);

	while (len > 0) {
		uint16_t *p = native_page_map(buf->pages[i]);
		int amount = MIN(PAGE_SIZE - offset, len);
		int j = amount / sizeof(uint16_t);
		while (j-- > 0) {
			p[j] = BSWAP_16(p[j]);
		}
		native_page_unmap(buf->pages[i++]);
		len -= amount;
		offset = 0;
	}

}

void
sgbuf_bswap32(sgbuf_t *buf, size_t offset, size_t len) {
	size_t i = offset >> PAGE_SHIFT;

	ASSERT_SGBUF(buf);
	ASSERT(offset + len <= SGBUF_SIZE(buf));
	ASSERT(ISP2(offset) && offset >= sizeof(uint32_t));
	ASSERT(ISP2(len) && len >= sizeof(uint32_t));

	offset = P2PHASE(offset, PAGE_SIZE);

	while (len > 0) {
		uint32_t *p = native_page_map(buf->pages[i]);
		int amount = MIN(PAGE_SIZE - offset, len);
		int j = amount / sizeof(uint32_t);
		while (j-- > 0) {
			p[j] = BSWAP_32(p[j]);
		}
		native_page_unmap(buf->pages[i++]);
		len -= amount;
		offset = 0;
	}

}

void
sgbuf_bswap64(sgbuf_t *buf, size_t offset, size_t len) {
	size_t i = offset >> PAGE_SHIFT;

	ASSERT_SGBUF(buf);
	ASSERT(offset + len <= SGBUF_SIZE(buf));
	ASSERT(ISP2(offset) && offset >= sizeof(uint64_t));
	ASSERT(ISP2(len) && len >= sizeof(uint64_t));

	offset = P2PHASE(offset, PAGE_SIZE);

	while (len > 0) {
		uint64_t *p = native_page_map(buf->pages[i]);
		int amount = MIN(PAGE_SIZE - offset, len);
		int j = amount / sizeof(uint64_t);
		while (j-- > 0) {
			p[j] = BSWAP_64(p[j]);
		}
		native_page_unmap(buf->pages[i++]);
		len -= amount;
		offset = 0;
	}

}
uint16_t sgbuf_getu16(sgbuf_t *buf, size_t index) {
	size_t bytes = index * sizeof(uint16_t);
	struct page *page;
	void *p;
	uint16_t ret;

	ASSERT_SGBUF(buf);
	ASSERT(bytes <= SGBUF_SIZE(buf));

	page = SGBUF_PAGE(buf, SGBUF_PAGE_INDEX(bytes));

	p = native_page_map(page);
	ret = ((uint16_t *)p)[SGBUF_PAGE_OFFSET(bytes) / sizeof(uint16_t)];
	native_page_unmap(page);

	return ret;
}

uint32_t sgbuf_getu32(sgbuf_t *buf, size_t index) {
	size_t bytes = index * sizeof(uint32_t);
	struct page *page;
	void *p;
	uint32_t ret;

	ASSERT_SGBUF(buf);
	ASSERT(bytes <= SGBUF_SIZE(buf));

	page = SGBUF_PAGE(buf, SGBUF_PAGE_INDEX(bytes));

	p = native_page_map(page);
	ret = ((uint32_t *)p)[SGBUF_PAGE_OFFSET(bytes) / sizeof(uint32_t)];
	native_page_unmap(page);

	return ret;
}

uint64_t sgbuf_getu64(sgbuf_t *buf, size_t index) {
	size_t bytes = index * sizeof(uint64_t);
	struct page *page;
	void *p;
	uint64_t ret;

	ASSERT_SGBUF(buf);
	ASSERT(bytes <= SGBUF_SIZE(buf));

	page = SGBUF_PAGE(buf, SGBUF_PAGE_INDEX(bytes));

	p = native_page_map(page);
	ret = ((uint64_t *)p)[SGBUF_PAGE_OFFSET(bytes) / sizeof(uint64_t)];
	native_page_unmap(page);

	return ret;
}

void sgbuf_setu16(sgbuf_t *buf, size_t index, uint16_t val) {
	size_t bytes = index * sizeof(uint16_t);
	struct page *page;
	void *p;

	ASSERT_SGBUF(buf);
	ASSERT(bytes <= SGBUF_SIZE(buf));

	page = SGBUF_PAGE(buf, SGBUF_PAGE_INDEX(bytes));

	p = native_page_map(page);
	((uint16_t *)p)[SGBUF_PAGE_OFFSET(bytes) / sizeof(uint16_t)] = val;
	native_page_unmap(page);
}

void sgbuf_setu32(sgbuf_t *buf, size_t index, uint32_t val) {
	size_t bytes = index * sizeof(uint32_t);
	struct page *page;
	void *p;

	ASSERT_SGBUF(buf);
	ASSERT(bytes <= SGBUF_SIZE(buf));

	page = SGBUF_PAGE(buf, SGBUF_PAGE_INDEX(bytes));

	p = native_page_map(page);
	((uint32_t *)p)[SGBUF_PAGE_OFFSET(bytes) / sizeof(uint32_t)] = val;
	native_page_unmap(page);
}

void sgbuf_setu64(sgbuf_t *buf, size_t index, uint64_t val) {
	size_t bytes = index * sizeof(uint64_t);
	struct page *page;
	void *p;

	ASSERT_SGBUF(buf);
	ASSERT(bytes <= SGBUF_SIZE(buf));

	page = SGBUF_PAGE(buf, SGBUF_PAGE_INDEX(bytes));

	p = native_page_map(page);
	((uint64_t *)p)[SGBUF_PAGE_OFFSET(bytes) / sizeof(uint64_t)] = val;
	native_page_unmap(page);
}
/*
 * Function to clone a sgbuf_t.
 *
 * Upon success, the return value will contain a pointer to a new sgbuf_t whose
 * contents are identical to those of the original.
 */

sgbuf_t *
sgbuf_dup(sgbuf_t *orig, int flags)
{

	sgbuf_t *copy;
	int size;

	ASSERT(orig);

	size = SGBUF_SIZE(orig);
	copy = sgbuf_alloc(size, flags);

	if (copy == NULL)
		return copy;

	sgbuf_bcopy(orig, copy, 0, 0, size);

	return copy;

}

FORCE_INLINE void
convert_to_sgbuf(void *s1, sgbuf_t *s2, size_t offset, size_t n)
{
	int i = SGBUF_PAGE_INDEX(offset);

	if ((offset = SGBUF_PAGE_OFFSET(offset))) {
		void *p2 = native_page_map(s2->pages[i]);
		memcpy(p2 + offset, s1, PAGE_SIZE - offset);
		native_page_unmap(s2->pages[i]);
		i++;
		n -= PAGE_SIZE - offset;
		s1 += PAGE_SIZE - offset;
	}

	for (  ; n > PAGE_SIZE ; i++, n -= PAGE_SIZE, s1 += PAGE_SIZE ) {
		void *p2 = native_page_map(s2->pages[i]);
		memcpy(p2, s1, PAGE_SIZE);
		native_page_unmap(s2->pages[i]);
	}

	if (n > 0) {
		void *p2 = native_page_map(s2->pages[i]);
		memcpy(p2, s1, n);
		native_page_unmap(s2->pages[i]);
	}
}

FORCE_INLINE void
convert_to_void(void *s1, sgbuf_t *s2, size_t offset, size_t n)
{
	int i = SGBUF_PAGE_INDEX(offset);

	if ((offset = SGBUF_PAGE_OFFSET(offset))) {
		void *p2 = native_page_map(s2->pages[i]);
		memcpy(s1, p2 + offset, PAGE_SIZE - offset);
		native_page_unmap(s2->pages[i]);
		i++;
		n -= PAGE_SIZE - offset;
		s1 += PAGE_SIZE - offset;
	}

	for (  ; n > PAGE_SIZE ; i++, n -= PAGE_SIZE, s1 += PAGE_SIZE ) {
		void *p2 = native_page_map(s2->pages[i]);
		memcpy(s1, p2, PAGE_SIZE);
		native_page_unmap(s2->pages[i]);
	}

	if (n > 0) {
		void *p2 = native_page_map(s2->pages[i]);
		memcpy(s1, p2, n);
		native_page_unmap(s2->pages[i]);
	}
}

void
sgbuf_convert(void *s1, sgbuf_t *s2, sgbuf_convert_t rw, size_t off1, size_t off2, size_t n)
{
	ASSERT(s1);
	ASSERT_SGBUF(s2);
	ASSERT(SGBUF_SIZE(s2) >= n + off2);

	switch (rw) {
		case TO_SGBUF:
		return convert_to_sgbuf(s1 + off1, s2, off2, n);

		case TO_VOIDP:
		return convert_to_void(s1 + off1, s2, off2, n);
	}

	VERIFY(0);
}

/* Run callback on all chunks in buf */

int
sgbuf_eval(sgbuf_t *buf, sgbuf_callback_func_t func,
	uint32_t chunk_size, uint32_t count, void *data)
{
	uint32_t i, j, i_max, tmp, remain;

	ASSERT_SGBUF(buf);
	/* Only power of 2 chunks are valid */
	ASSERT(chunk_size <= PAGE_SIZE);
	ASSERT(ISP2(chunk_size));

	if (count) {
		tmp = (buf->count * PAGE_SIZE) / chunk_size;
		tmp = MIN(tmp, count);
		i_max = ((tmp * chunk_size) >> PAGE_SHIFT);
		remain = P2PHASE(tmp * chunk_size, PAGE_SIZE);
	} else {
		i_max = buf->count;
		remain = 0;
	}

	for ( i = 0 ; i < i_max ; i++ ) {
		void *p = native_page_map(buf->pages[i]);
		for ( j = 0 ; j < PAGE_SIZE ; j += chunk_size) {
			int ret = func(i * PAGE_SIZE + j, p + j, data);
			if (ret) {
				native_page_unmap(buf->pages[i]);
				return ret;
			}
		}
		native_page_unmap(buf->pages[i]);
	}

	if (remain) {
		void *p = native_page_map(buf->pages[i_max + 1]);
		for ( j = 0 ; j < remain ; j += chunk_size) {
			int ret = func((i_max + 1) * PAGE_SIZE + j, p + j, data);
			if (ret) {
				native_page_unmap(buf->pages[i_max + 1]);
				return ret;
			}
		}
		native_page_unmap(buf->pages[i_max + 1]);
	}

	return 0;

}

#if defined(_KERNEL) && defined(HAVE_SPL)

spl_module_init(sgbuf_init);
spl_module_exit(sgbuf_fini);

MODULE_AUTHOR("Richard Yao");
MODULE_DESCRIPTION("Kernel scatter-gather buffers");
MODULE_LICENSE("CDDL");

module_param(sg_buf_page_free_max, ulong, 0644);
MODULE_PARM_DESC(sg_buf_page_free_max, "Maximum number of pages to save for high priority allocations.");

EXPORT_SYMBOL(sgbuf_alloc);
EXPORT_SYMBOL(sgbuf_zalloc);
EXPORT_SYMBOL(sgbuf_free);
EXPORT_SYMBOL(sgbuf_map);
EXPORT_SYMBOL(sgbuf_unmap);
EXPORT_SYMBOL(sgbuf_bcmp);
EXPORT_SYMBOL(sgbuf_bcopy);
EXPORT_SYMBOL(sgbuf_bzero);
EXPORT_SYMBOL(sgbuf_bswap16);
EXPORT_SYMBOL(sgbuf_bswap32);
EXPORT_SYMBOL(sgbuf_bswap64);
EXPORT_SYMBOL(sgbuf_getu16);
EXPORT_SYMBOL(sgbuf_getu32);
EXPORT_SYMBOL(sgbuf_getu64);
EXPORT_SYMBOL(sgbuf_setu16);
EXPORT_SYMBOL(sgbuf_setu32);
EXPORT_SYMBOL(sgbuf_setu64);
EXPORT_SYMBOL(sgbuf_dup);
EXPORT_SYMBOL(sgbuf_convert);
EXPORT_SYMBOL(sgbuf_eval);

#endif
