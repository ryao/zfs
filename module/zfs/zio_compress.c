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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2013 by Saso Kiselkov. All rights reserved.
 */

/*
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

#include <sys/zfs_context.h>
#include <sys/compress.h>
#include <sys/spa.h>
#include <sys/zio.h>
#include <sys/zio_compress.h>

/*
 * Compression vectors.
 */

zio_compress_info_t zio_compress_table[ZIO_COMPRESS_FUNCTIONS] = {
	{NULL,			NULL,			0,	"inherit"},
	{NULL,			NULL,			0,	"on"},
	{NULL,			NULL,			0,	"uncompressed"},
	{lzjb_compress,		lzjb_decompress,	0,	"lzjb"},
	{NULL,			NULL,			0,	"empty"},
	{gzip_compress,		gzip_decompress,	1,	"gzip-1"},
	{gzip_compress,		gzip_decompress,	2,	"gzip-2"},
	{gzip_compress,		gzip_decompress,	3,	"gzip-3"},
	{gzip_compress,		gzip_decompress,	4,	"gzip-4"},
	{gzip_compress,		gzip_decompress,	5,	"gzip-5"},
	{gzip_compress,		gzip_decompress,	6,	"gzip-6"},
	{gzip_compress,		gzip_decompress,	7,	"gzip-7"},
	{gzip_compress,		gzip_decompress,	8,	"gzip-8"},
	{gzip_compress,		gzip_decompress,	9,	"gzip-9"},
	{zle_compress,		zle_decompress,		64,	"zle"},
	{lz4_compress_zfs,	lz4_decompress_zfs,	0,	"lz4"},
};

enum zio_compress
zio_compress_select(enum zio_compress child, enum zio_compress parent)
{
	ASSERT(child < ZIO_COMPRESS_FUNCTIONS);
	ASSERT(parent < ZIO_COMPRESS_FUNCTIONS);
	ASSERT(parent != ZIO_COMPRESS_INHERIT && parent != ZIO_COMPRESS_ON);

	if (child == ZIO_COMPRESS_INHERIT)
		return (parent);

	if (child == ZIO_COMPRESS_ON)
		return (ZIO_COMPRESS_ON_VALUE);

	return (child);
}


size_t
zio_compress_data(enum zio_compress c, sgbuf_t *src, sgbuf_t *dst,
    uint32_t src_offset, uint32_t dst_offset, size_t s_len)
{
	size_t c_len, d_len;
	zio_compress_info_t *ci = &zio_compress_table[c];

	ASSERT((uint_t)c < ZIO_COMPRESS_FUNCTIONS);
	ASSERT((uint_t)c == ZIO_COMPRESS_EMPTY || ci->ci_compress != NULL);

	/*
	 * If the data is all zeroes, we don't even need to allocate
	 * a block for it.  We indicate this by returning zero size.
	 */
	if (sgbuf_iszero(src, src_offset, s_len))
		return (0);

	if (c == ZIO_COMPRESS_EMPTY)
		return (s_len);

	/* Compress at least 12.5% */
	d_len = s_len - (s_len >> 3);

	/* XXX: Convert compression interface to use sgbufs directly */
	c_len = ci->ci_compress(SGBUF_MAP_OFFSET(src, src_offset, char),
	    SGBUF_MAP_OFFSET(dst, dst_offset, char), s_len, d_len,
	    ci->ci_level);

	sgbuf_unmap(src);
	sgbuf_unmap(dst);

	if (c_len > d_len)
		return (s_len);

	ASSERT3U(c_len, <=, d_len);
	return (c_len);
}

int
zio_decompress_data(enum zio_compress c, sgbuf_t *src, sgbuf_t *dst,
    uint32_t src_offset, uint32_t dst_offset, size_t s_len, size_t d_len)
{
	zio_compress_info_t *ci = &zio_compress_table[c];
	int ret;

	if ((uint_t)c >= ZIO_COMPRESS_FUNCTIONS || ci->ci_decompress == NULL)
		return (SET_ERROR(EINVAL));

	/* XXX: Convert compression interface to use sgbufs directly */
	ret = ci->ci_decompress(SGBUF_MAP_OFFSET(src, src_offset, char),
	    SGBUF_MAP_OFFSET(dst, dst_offset, char), s_len, d_len,
	    ci->ci_level);

	sgbuf_unmap(src);
	sgbuf_unmap(dst);

	return ret;
}
