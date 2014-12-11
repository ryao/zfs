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
 * Copyright (c) 2015, ClusterHQ LLC. All rights reserved.
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

#ifdef _KERNEL
/* Variables for managing free page pool */
static list_t sg_buf_page_free_list;
#if 0
static volatile unsigned long sg_buf_page_free_count = 0;
#endif
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
#if 0
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
#endif
	return native_alloc_page(flags);
}

static void
sgbuf_page_free(struct page *page)
{
#if 0
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
#endif

	native_free_page(page);
}
#endif

int
sgbuf_init(void)
{

#ifdef _KERNEL
	/* XXX: SPL Mutex implements MUTEX_SPIN as MUTEX_DEFAULT */
	mutex_init(&sg_buf_alloc_lock, NULL, MUTEX_SPIN, NULL);
	list_create(&sg_buf_page_free_list, sizeof (free_page_t),
		offsetof(free_page_t, free_list));
#endif
	return (0);
}

int
sgbuf_fini(void)
{

#ifdef _KERNEL
	while (!list_is_empty(&sg_buf_page_free_list))
		native_free_page(list_remove_head(&sg_buf_page_free_list));
	list_destroy(&sg_buf_page_free_list);
	mutex_destroy(&sg_buf_alloc_lock);
#endif

	return (0);
}

sgbuf_t *
sgbuf_alloc(size_t size, int flags)
{
	int i;
	int count;
	sgbuf_t *buf;

	if (size == 0)
		return NULL;

	count = P2ROUNDUP(size, PAGE_SIZE) >> PAGE_SHIFT;
	buf = kmem_alloc(sizeof(struct page *) * count + sizeof(sgbuf_t),
		flags | KM_NODEBUG);
	buf->count = count;

#ifdef _KERNEL
	buf->addr = NULL;

	/* XXX: alloc_page() can fail */
	for ( i = 0 ; i < buf->count ; i++ )
		buf->pages[i] = sgbuf_page_alloc(flags);
#else
	posix_memalign(&buf->addr, PAGE_SIZE, SGBUF_SIZE(buf));

	for ( i = 0 ; i < buf->count ; i++ )
		buf->pages[i] = (void *)((char *)buf->addr + PAGE_SIZE * i);
#endif

#ifdef DEBUG
	buf->magic = SGBUF_MAGIC;
#endif

	return buf;
}

sgbuf_t *
sgbuf_zalloc(size_t size, int flags)
{
	sgbuf_t *ret = sgbuf_alloc(size, flags);
	sgbuf_bzero(ret, 0, SGBUF_SIZE(ret));
	return ret;
}

void
sgbuf_free(sgbuf_t *buf, size_t size)
{
#ifdef _KERNEL
	int i;
#endif
	ASSERT_SGBUF(buf);
	ASSERT3U(buf->count, ==, (P2ROUNDUP(size, PAGE_SIZE) >> PAGE_SHIFT));
#ifdef _KERNEL
	if (buf->addr)
		sgbuf_unmap(buf);

	for ( i = 0 ; i < buf->count ; i++ )
		sgbuf_page_free(buf->pages[i]);
#else
	kmem_free(buf->addr, SGBUF_SIZE(buf));
#endif
	kmem_free(buf, sizeof(struct page *) * buf->count + sizeof(sgbuf_t));
}

void *
sgbuf_map(sgbuf_t *buf)
{
	if (buf == NULL)
		return NULL;

	ASSERT_SGBUF(buf);

#ifdef _KERNEL
	if (buf->addr == NULL)
		buf->addr = vm_map_ram(buf->pages, buf->count, NUMA_NO_NODE,
		    PAGE_KERNEL);
#endif

	return (buf->addr);
}

void
sgbuf_unmap(sgbuf_t * buf)
{
	ASSERT_SGBUF(buf);
	return;
}

typedef int(*sgbuf_1arg_f)(void *buf, size_t n, void *data);
typedef int(*sgbuf_2arg_f)(void *s1, void *s2, size_t n, void *data);

/*
 * Internal function for implementing operations on contiguous regions of
 * sgbufs with page alignment. Examples include bswap and iszero.
 */
FORCE_INLINE void
sgbuf_generic_1arg(sgbuf_1arg_f func, void *data,
    const sgbuf_t *buf, size_t off, size_t size)
{
	int i = off >> PAGE_SHIFT;
	void *p;
	int tocmp = 0;

	ASSERT_SGBUF(buf);
	ASSERT(off + size <= SGBUF_SIZE(buf));

	off = P2PHASE(off, PAGE_SIZE);

	tocmp = PAGE_SIZE - off;
	tocmp = MIN(tocmp, size);

	while (size) {
		p = native_page_map(buf->pages[i]);

		if (func(p + off, tocmp, data))
			break;

		native_page_unmap(buf->pages[i]);
		i++;

		size -= tocmp;
		tocmp = MIN(size, PAGE_SIZE);
		off = 0;
	}
}

/*
 * Internal function for implementing operations on contiguous regions of
 * sgbufs or void pointers with page alignment. Examples include bcmp, bcopy
 * and conversions.
 */
FORCE_INLINE void
sgbuf_2arg_generic(sgbuf_2arg_f func, void *data, void *s1, void *s2,
    size_t off1, size_t off2, int type1, int type2, size_t size)
{
	int i = off1 >> PAGE_SHIFT, j = off2 >> PAGE_SHIFT;
	void *p1 = NULL, *p2 = NULL;
	int tocmp = 0;

	ASSERT(s1 != s2);
	if (type1) {
		ASSERT_SGBUF((sgbuf_t *)s1);
		ASSERT(off1 + size <= SGBUF_SIZE((sgbuf_t *)s1));
	} else {
		ASSERT(s1);
	}

	if (type2) {
		ASSERT_SGBUF((sgbuf_t *)s2);
		ASSERT(off2 + size <= SGBUF_SIZE((sgbuf_t *)s2));
	} else {
		ASSERT(s2);
	}

	while (size) {
		if (type1)
			p1 = (p1) ? p1 :
			    native_page_map(((sgbuf_t*)s1)->pages[i]);
		else
			p1 = s1 + PAGE_SIZE * i;

		if (type2)
			p2 = (p2) ? p2 :
			    native_page_map(((sgbuf_t*)s2)->pages[j]);
		else
			p2 = s2 + PAGE_SIZE * j;

		off1 = P2PHASE(off1 + tocmp, PAGE_SIZE);
		off2 = P2PHASE(off2 + tocmp, PAGE_SIZE);

		tocmp = PAGE_SIZE - MAX(off1, off2);
		tocmp = MIN(tocmp, size);

		if (func(p1 + off1, p2 + off2, tocmp, data))
			break;

		if (off2 <= off1) {
			if (type1) {
				native_page_unmap(((sgbuf_t *)s1)->pages[i]);
				p1 = NULL;
			}
			i++;
		}

		if (off1 <= off2) {
			if (type2) {
				native_page_unmap(((sgbuf_t *)s2)->pages[j]);
				p2 = NULL;
			}
			j++;
		}

		size -= tocmp;
	}
}

FORCE_INLINE void
sgbuf_generic_2arg(sgbuf_2arg_f func, void *data,
    const sgbuf_t *s1, sgbuf_t *s2, size_t off1, size_t off2, size_t size)
{
	sgbuf_2arg_generic(func, data, (sgbuf_t *)s1, s2, off1, off2, 1, 1,
	    size);
}

/* Internal callback function for implementing sgbuf_bcmp() */
FORCE_INLINE int
sgbuf_bcmp_cb(void *p1, void *p2, size_t n, void *data)
{
	int err = bcmp(p1, p2, n);

	if (err) {
		int *t = data;
		*t = err;
		return (err);
	}

	return (0);
}

/*
 * sgbuf_bcmp(): sgbuf_t version of bcmp().
 *
 * This is functionally identical to bcmp(). The only real difference is the
 * inclusion of assertions to check that valid buffers have been passed.
 */
int
sgbuf_bcmp(const sgbuf_t *s1, const sgbuf_t *s2, size_t off1, size_t off2, size_t size)
{
	int r = 0;
	sgbuf_generic_2arg(&sgbuf_bcmp_cb, &r, (sgbuf_t *)s1, (sgbuf_t *)s2, off1, off2, size);
	return (r);
}

/* Internal callback function for implementing sgbuf_bcopy() */
FORCE_INLINE int
sgbuf_bcopy_cb(void *p1, void *p2, size_t n, void *data)
{
	memcpy(p2, p1, n);
	return (0);
}

/*
 * sgbuf_bcmp(): sgbuf_t version of bcopy().
 *
 * This is functionally identical to bcopy(). The only real difference is the
 * inclusion of assertions to check that valid buffers have been passed.
 */
void
sgbuf_bcopy(const sgbuf_t *s1, sgbuf_t *s2, size_t off1, size_t off2, size_t size)
{
	/* XXX: We could subsitute COW for memcpy() when pages are aligned */
	sgbuf_generic_2arg(&sgbuf_bcopy_cb, NULL, (sgbuf_t *)s1, s2, off1, off2, size);
}

/* Internal callback function for implementing sgbuf_bzero() */
FORCE_INLINE int
sgbuf_bzero_cb(void *p, size_t n, void *data)
{
	bzero(p, n);
	return (0);
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
sgbuf_bzero(sgbuf_t *buf, size_t offset, size_t size)
{
	/* XXX: We could subsitute COW for memcpy() when pages are aligned */
	sgbuf_generic_1arg(&sgbuf_bzero_cb, NULL, buf, offset, size);
}

FORCE_INLINE int
sgbuf_bswap16_cb(void *p, size_t n, void *data)
{
	uint16_t *val = p;

	while ( n > 0 ) {
		val[0] = BSWAP_16(val[0]);
		val++;
		n -= sizeof(uint16_t);
	}

	return (0);
}

void
sgbuf_bswap16(sgbuf_t *buf, size_t offset, size_t size)
{
	ASSERT(ISP2(offset) && offset >= sizeof(uint16_t));
	ASSERT(ISP2(offset) && offset >= sizeof(uint16_t));
	sgbuf_generic_1arg(&sgbuf_bswap16_cb, NULL, buf, offset, size);
}

FORCE_INLINE int
sgbuf_bswap32_cb(void *p, size_t n, void *data)
{
	uint32_t *val = p;

	while ( n > 0 ) {
		val[0] = BSWAP_32(val[0]);
		val++;
		n -= sizeof(uint32_t);
	}

	return (0);
}

void
sgbuf_bswap32(sgbuf_t *buf, size_t offset, size_t size)
{
	ASSERT(ISP2(offset) && offset >= sizeof(uint32_t));
	ASSERT(ISP2(offset) && offset >= sizeof(uint32_t));
	sgbuf_generic_1arg(&sgbuf_bswap32_cb, NULL, buf, offset, size);
}

FORCE_INLINE int
sgbuf_bswap64_cb(void *p, size_t n, void *data)
{
	uint64_t *val = p;

	while ( n > 0 ) {
		val[0] = BSWAP_64(val[0]);
		val++;
		n -= sizeof(uint64_t);
	}

	return (0);
}

void
sgbuf_bswap64(sgbuf_t *buf, size_t offset, size_t size)
{
	ASSERT(ISP2(offset) && offset >= sizeof(uint64_t));
	ASSERT(ISP2(offset) && offset >= sizeof(uint64_t));
	sgbuf_generic_1arg(&sgbuf_bswap64_cb, NULL, buf, offset, size);
}

FORCE_INLINE int
sgbuf_getu16_cb(void *p, size_t n, void *data)
{
	*(uint16_t*)data = *(uint16_t*)p;
	return (0);
}

uint16_t
sgbuf_getu16(sgbuf_t *buf, size_t index)
{
	uint16_t r;
	sgbuf_generic_1arg(&sgbuf_getu16_cb, &r, buf, index * sizeof(uint16_t),
	    sizeof(uint16_t));
	return (r);
}

FORCE_INLINE int
sgbuf_getu32_cb(void *p, size_t n, void *data)
{
	*(uint32_t*)data = *(uint32_t*)p;
	return (0);
}

uint32_t
sgbuf_getu32(sgbuf_t *buf, size_t index)
{
	uint32_t r;
	sgbuf_generic_1arg(&sgbuf_getu32_cb, &r, buf, index * sizeof(uint32_t),
	    sizeof(uint32_t));
	return (r);
}

FORCE_INLINE int
sgbuf_getu64_cb(void *p, size_t n, void *data)
{
	*(uint64_t*)data = *(uint64_t*)p;
	return (0);
}

uint64_t
sgbuf_getu64(sgbuf_t *buf, size_t index)
{
	uint64_t r;
	sgbuf_generic_1arg(&sgbuf_getu64_cb, &r, buf, index * sizeof(uint64_t),
	    sizeof(uint64_t));
	return (r);
}

FORCE_INLINE int
sgbuf_setu16_cb(void *p, size_t n, void *data)
{
	*(uint16_t*)p = *(uint16_t*)data;
	return (0);
}

void
sgbuf_setu16(sgbuf_t *buf, size_t index, uint16_t val)
{
	sgbuf_generic_1arg(&sgbuf_setu16_cb, &val, buf, index * sizeof(uint16_t),
	    sizeof(uint16_t));
}

FORCE_INLINE int
sgbuf_setu32_cb(void *p, size_t n, void *data)
{
	*(uint32_t*)p = *(uint32_t*)data;
	return (0);
}

void
sgbuf_setu32(sgbuf_t *buf, size_t index, uint32_t val)
{
	sgbuf_generic_1arg(&sgbuf_setu32_cb, &val, buf, index * sizeof(uint32_t),
	    sizeof(uint32_t));
}

FORCE_INLINE int
sgbuf_setu64_cb(void *p, size_t n, void *data)
{
	*(uint64_t*)p = *(uint64_t*)data;
	return (0);
}

void
sgbuf_setu64(sgbuf_t *buf, size_t index, uint64_t val)
{
	sgbuf_generic_1arg(&sgbuf_setu64_cb, &val, buf, index * sizeof(uint64_t),
	    sizeof(uint64_t));
}

/*
 * Function to clone a sgbuf_t.
 *
 * Upon success, the return value will contain a pointer to a new sgbuf_t whose
 * contents are identical to those of the original.
 *
 * XXX: There is an opportunity to use CoW on the pages.
 */

sgbuf_t *
sgbuf_dup(sgbuf_t *orig, int flags)
{

	sgbuf_t *copy;
	int size;

	ASSERT_SGBUF(orig);

	size = SGBUF_SIZE(orig);
	copy = sgbuf_alloc(size, flags);

	if (copy == NULL)
		return copy;

	sgbuf_bcopy(orig, copy, 0, 0, size);

	return copy;

}

void
sgbuf_convert(void *s1, sgbuf_t *s2, sgbuf_convert_t rw,
    size_t off1, size_t off2, size_t size)
{
	switch (rw) {
		case TO_SGBUF:
			sgbuf_2arg_generic(&sgbuf_bcopy_cb, NULL, s1, s2, off1,
			    off2, 0, 1, size);
			return;

		case TO_VOIDP:
			sgbuf_2arg_generic(&sgbuf_bcopy_cb, NULL, s2, s1, off2,
			    off1, 1, 0, size);
			return;
	}

	VERIFY(0);
}

FORCE_INLINE int
sgbuf_iszero_cb(void *p, size_t n, void *data)
{
	uint64_t *val = p;

	while ( n > 0 ) {
		if (val[0]) {
			*(int*)data = 1;
			return (1);
		}
		val++;
		n -= sizeof(uint64_t);
	}
	return (0);
}

int
sgbuf_iszero(sgbuf_t *buf, size_t offset, size_t size)
{
	int a = 0;
	sgbuf_generic_1arg(&sgbuf_iszero_cb, &a, buf, offset, size);
	return (a == 0);
}

#if defined(_KERNEL) && defined(HAVE_SPL)
#include <linux/module_compat.h>
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
