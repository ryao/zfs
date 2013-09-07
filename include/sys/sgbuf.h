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

#ifndef _SGBUF_H
#define	_SGBUF_H

#ifdef _KERNEL
#include <sys/param.h>
#elif defined(__linux__)
#include <assert.h>
#include <sys/user.h>
#endif

#include <sys/types.h>

typedef struct sgbuf {
	struct page **pages;
	void * addr;
	int count;
#ifdef DEBUG
	uint32_t magic;
#endif

} sgbuf_t;

typedef enum sgbuf_convert {
	TO_SGBUF =     0,
	TO_VOIDP =     1,
} sgbuf_convert_t;

typedef int sgbuf_callback_func_t(uint64_t, void *, void *);

#ifdef DEBUG
#define SGBUF_MAGIC	0xDEADC0DE
#define ASSERT_SGBUF(n)	ASSERT((n) && (n)->magic == SGBUF_MAGIC)
#else
#define ASSERT_SGBUF(n)	ASSERT(n)
#endif

#define SGBUF_SIZE(n)	((n)->count * PAGE_SIZE)

int sgbuf_init(void);
int sgbuf_fini(void);

sgbuf_t *sgbuf_alloc(int size, int flags);
sgbuf_t *sgbuf_zalloc(int size, int flags);
void sgbuf_free(sgbuf_t *buf);

/* XXX: These will be removed */
#ifdef _KERNEL
void *sgbuf_map (sgbuf_t *buf);
void sgbuf_unmap (sgbuf_t *buf);
#endif

int sgbuf_bcmp(sgbuf_t *s1, sgbuf_t *s2, size_t size);
void sgbuf_bcopy(const sgbuf_t *s1, sgbuf_t *s2, size_t off1, size_t off2, size_t size);
void sgbuf_bzero(sgbuf_t *s1, size_t offset, size_t len);

void sgbuf_bswap16(sgbuf_t *s1, size_t offset, size_t len);
void sgbuf_bswap32(sgbuf_t *s1, size_t offset, size_t len);
void sgbuf_bswap64(sgbuf_t *s1, size_t offset, size_t len);

/* XXX: Find a way to enable compiler optimizations when doing multiple calls in a loop */
uint16_t sgbuf_getu16(sgbuf_t *buf, size_t index);
uint32_t sgbuf_getu32(sgbuf_t *buf, size_t index);
uint64_t sgbuf_getu64(sgbuf_t *buf, size_t index);

void sgbuf_setu16(sgbuf_t *buf, size_t index, uint16_t val);
void sgbuf_setu32(sgbuf_t *buf, size_t index, uint32_t val);
void sgbuf_setu64(sgbuf_t *buf, size_t index, uint64_t val);

sgbuf_t * sgbuf_dup(sgbuf_t *orig, int flags);
void sgbuf_convert(void *s1, sgbuf_t *s2, sgbuf_convert_t rw,
	size_t off1, size_t off2, size_t n);
int sgbuf_eval(sgbuf_t *buf, sgbuf_callback_func_t func,
	uint32_t chunk_size, uint32_t count, void *data);

#endif	/* _SGBUF_H */
