// SPDX-License-Identifier: CDDL-1.0
/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * https://opensource.org/license/CDDL-1.0.
 */
/*
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, 2018 by Delphix. All rights reserved.
 * Copyright (c) 2016 Actifio, Inc. All rights reserved.
 * Copyright (c) 2025, Klara, Inc.
 * Copyright (c) 2026, TrueNAS.
 */

#include <sys/kmem.h>
#include <sys/debug.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#if defined(__GLIBC__)
#include <malloc.h>
#endif

/*
 * KM_SLEEP in the kernel blocks in the page allocator, which reclaims.
 * malloc() does not. A tight retry is what produces
 * "__vm_enough_memory: N callbacks suppressed" from zfsd: every failed
 * malloc is another commit-charge check, and the bytes were not kept.
 * Sleep so the ARC evict thread can run, and give glibc a chance to
 * return free heap (small allocations never munmap on free()).
 *
 * Page-sized and larger allocations must also leave CommitLimit when
 * freed. Branching kmem_free() on the caller's size and munmap()ing
 * is not safe: ZFS sometimes frees with a different length than it
 * allocated, and a raw mmap pointer passed to free() segfaults (the
 * chunk header is the previous page). mallopt disables glibc's
 * dynamic threshold so malloc/posix_memalign of a page or more is an
 * anonymous mmap and free() unmaps it.
 */
static void (*kmem_reclaim_cb)(void);

static void
kmem_mallopt_init(void)
{
#if defined(__GLIBC__)
	static int once;

	if (once)
		return;
	once = 1;
	if (mallopt(M_MMAP_THRESHOLD, 4096) == 0)
		(void) mallopt(M_MMAP_THRESHOLD, 131072);
	(void) mallopt(M_TRIM_THRESHOLD, 128 * 1024);
	(void) mallopt(M_MMAP_MAX, 65536);
#endif
}

void
kmem_register_reclaim(void (*cb)(void))
{
	kmem_reclaim_cb = cb;
}

static void
kmem_blocked(size_t size, int attempt)
{
	if (attempt == 1 || attempt == 100) {
		char msg[128];
		int n = snprintf(msg, sizeof (msg),
		    "kmem: allocation of %zu bytes failed (attempt %d); "
		    "reclaiming\n", size, attempt);

		if (n > 0) {
			ssize_t w = write(STDERR_FILENO, msg, (size_t)n);

			(void) w;
		}
	}
	/*
	 * A multi-gigabyte request under overcommit_memory=2 will never
	 * succeed. Spinning here is the 10-minute ZTS kill: the FUSE
	 * thread never answers, and dd sits in fuse_perform_write.
	 */
	if (attempt >= 50 && size >= (256ULL << 20)) {
		char msg[160];
		int n = snprintf(msg, sizeof (msg),
		    "kmem: giving up on %zu byte KM_SLEEP allocation\n",
		    size);

		if (n > 0) {
			ssize_t w = write(STDERR_FILENO, msg, (size_t)n);

			(void) w;
		}
		abort();
	}
	if (kmem_reclaim_cb != NULL)
		kmem_reclaim_cb();
#if defined(__GLIBC__)
	(void) malloc_trim(0);
#endif
	{
		int slept = usleep(10000);

		(void) slept;
	}
}

void *
kmem_alloc(size_t size, int flags)
{
	void *ptr = NULL;
	int attempt = 0;

	kmem_mallopt_init();
	do {
		ptr = malloc(size);
		if (ptr != NULL || (flags & KM_SLEEP) == 0)
			break;
		kmem_blocked(size, ++attempt);
	} while (ptr == NULL);

	return (ptr);
}

void *
kmem_zalloc(size_t size, int flags)
{
	void *ptr = NULL;

	ptr = kmem_alloc(size, flags);
	if (ptr)
		memset(ptr, 0, size);

	return (ptr);
}

void
kmem_free(const void *ptr, size_t size)
{
	if (ptr == NULL)
		return;
	(void) size;
	free((void *)ptr);
}

static int
kmem_align_ok(size_t align)
{
	return (align >= sizeof (void *) && (align & (align - 1)) == 0);
}

void *
kmem_alloc_aligned(size_t size, size_t align, int flags)
{
	void *ptr = NULL;
	int rc;
	int attempt = 0;

	if (!kmem_align_ok(align)) {
		fprintf(stderr, "%s: invalid memory alignment (%zd)\n",
		    __func__, align);
		if (flags & KM_SLEEP)
			abort();
		return (NULL);
	}

	kmem_mallopt_init();
	do {
		rc = posix_memalign(&ptr, align, size);
		if (rc != ENOMEM || (flags & KM_SLEEP) == 0)
			break;
		kmem_blocked(size, ++attempt);
	} while (rc == ENOMEM);

	if (rc == EINVAL) {
		fprintf(stderr, "%s: invalid memory alignment (%zd)\n",
		    __func__, align);
		if (flags & KM_SLEEP)
			abort();
		return (NULL);
	}

	return (ptr);
}

/*
 * kmem_free_aligned was added for supporting portability
 * with non-POSIX platforms that require a different free
 * to be used with aligned allocations.
 */
void
kmem_free_aligned(void *ptr, size_t size)
{
	if (ptr == NULL)
		return;
	(void) size;
#ifndef _WIN32
	free(ptr);
#else
	_aligned_free(ptr);
#endif
}

char *
kmem_strdup(const char *str)
{
	size_t len = strlen(str);
	char *new = kmem_alloc(len + 1, KM_SLEEP);
	memcpy(new, str, len + 1);
	return (new);
}

void
kmem_strfree(char *str)
{
	kmem_free(str, strlen(str) + 1);
}

char *
kmem_vasprintf(const char *fmt, va_list adx)
{
	char *buf = NULL;
	va_list adx_copy;

	va_copy(adx_copy, adx);
	VERIFY(vasprintf(&buf, fmt, adx_copy) != -1);
	va_end(adx_copy);

	return (buf);
}

char *
kmem_asprintf(const char *fmt, ...)
{
	char *buf = NULL;
	va_list adx;

	va_start(adx, fmt);
	VERIFY(vasprintf(&buf, fmt, adx) != -1);
	va_end(adx);

	return (buf);
}

/*
 * kmem_scnprintf() will return the number of characters that it would have
 * printed whenever it is limited by value of the size variable, rather than
 * the number of characters that it did print. This can cause misbehavior on
 * subsequent uses of the return value, so we define a safe version that will
 * return the number of characters actually printed, minus the NULL format
 * character.  Subsequent use of this by the safe string functions is safe
 * whether it is snprintf(), strlcat() or strlcpy().
 */
int
kmem_scnprintf(char *restrict str, size_t size, const char *restrict fmt, ...)
{
	int n;
	va_list ap;

	/* Make the 0 case a no-op so that we do not return -1 */
	if (size == 0)
		return (0);

	va_start(ap, fmt);
	n = vsnprintf(str, size, fmt, ap);
	va_end(ap);

	if (n >= size)
		n = size - 1;

	return (n);
}

fstrans_cookie_t
spl_fstrans_mark(void)
{
	return ((fstrans_cookie_t)0);
}

void
spl_fstrans_unmark(fstrans_cookie_t cookie)
{
	(void) cookie;
}
