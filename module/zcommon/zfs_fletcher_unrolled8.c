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
 * Copyright (C) 2020 Richard Yao. All rights reserved.
 */

#include <sys/byteorder.h>
#include <sys/debug.h>
#include <sys/spa_checksum.h>
#include <sys/strings.h>
#include <sys/sysmacros.h>
#include <zfs_fletcher.h>

static void
fletcher_4_unrolled8_init(fletcher_4_ctx_t *ctx)
{
	ZIO_SET_CHECKSUM(&ctx->scalar, 0, 0, 0, 0);
}

static void
fletcher_4_unrolled8_fini(fletcher_4_ctx_t *ctx, zio_cksum_t *zcp)
{
	memcpy(zcp, &ctx->scalar, sizeof (zio_cksum_t));
}

static void
fletcher_4_unrolled8_native(fletcher_4_ctx_t *ctx, const void *buf,
    uint64_t size)
{
	const uint32_t *ip = buf;
	const uint32_t *ipend = ip + (size / sizeof (uint32_t));
	uint64_t a, b, c, d;

	ASSERT0(P2NPHASE(size, 8 * sizeof (uint32_t)));

	a = ctx->scalar.zc_word[0];
	b = ctx->scalar.zc_word[1];
	c = ctx->scalar.zc_word[2];
	d = ctx->scalar.zc_word[3];

	for (; ip != ipend; ip += 8) {
		uint64_t t0, t1, t2, t3, t4, t5, t6, t7, a0, a1, a2, a3, a4;
		uint64_t a5, a6, b0, b1, b2, b3, b4, b5, b6, c0, c1, c2, c3;
		uint64_t c4, c5, c6, d0, d1, d2, d3, d4, d5, d6;

		t0 = ip[0];
		t1 = ip[1];
		t2 = ip[2];
		t3 = ip[3];
		t4 = ip[4];
		t5 = ip[5];
		t6 = ip[6];
		t7 = ip[7];

		a0 = a + t0;
		a1 = a0 + t1;
		a2 = a1 + t2;
		a3 = a2 + t3;
		a4 = a3 + t4;
		a5 = a4 + t5;
		a6 = a5 + t6;
		a = a6 + t7;
		b0 = b + a0;
		b1 = b0 + a1;
		b2 = b1 + a2;
		b3 = b2 + a3;
		b4 = b3 + a4;
		b5 = b4 + a5;
		b6 = b5 + a6;
		b = b6 + a;
		c0 = c + b0;
		c1 = c0 + b1;
		c2 = c1 + b2;
		c3 = c2 + b3;
		c4 = c3 + b4;
		c5 = c4 + b5;
		c6 = c5 + b6;
		c = c6 + b;
		d0 = d + c0;
		d1 = d0 + c1;
		d2 = d1 + c2;
		d3 = d2 + c3;
		d4 = d3 + c4;
		d5 = d4 + c5;
		d6 = d5 + c6;
		d = d6 + c;
	}

	ZIO_SET_CHECKSUM(&ctx->scalar, a, b, c, d);
}

static void
fletcher_4_unrolled8_byteswap(fletcher_4_ctx_t *ctx,
    const void *buf, uint64_t size)
{
	const uint32_t *ip = buf;
	const uint32_t *ipend = ip + (size / sizeof (uint32_t));
	uint64_t a, b, c, d;

	ASSERT0(P2NPHASE(size, 8 * sizeof (uint32_t)));

	a = ctx->scalar.zc_word[0];
	b = ctx->scalar.zc_word[1];
	c = ctx->scalar.zc_word[2];
	d = ctx->scalar.zc_word[3];

	for (; ip != ipend; ip += 8) {
		uint64_t t0, t1, t2, t3, t4, t5, t6, t7, a0, a1, a2, a3, a4;
		uint64_t a5, a6, b0, b1, b2, b3, b4, b5, b6, c0, c1, c2, c3;
		uint64_t c4, c5, c6, d0, d1, d2, d3, d4, d5, d6;

		t0 = BSWAP_32(ip[0]);
		t1 = BSWAP_32(ip[1]);
		t2 = BSWAP_32(ip[2]);
		t3 = BSWAP_32(ip[3]);
		t4 = BSWAP_32(ip[4]);
		t5 = BSWAP_32(ip[5]);
		t6 = BSWAP_32(ip[6]);
		t7 = BSWAP_32(ip[7]);

		a0 = a + t0;
		a1 = a0 + t1;
		a2 = a1 + t2;
		a3 = a2 + t3;
		a4 = a3 + t4;
		a5 = a4 + t5;
		a6 = a5 + t6;
		a = a6 + t7;
		b0 = b + a0;
		b1 = b0 + a1;
		b2 = b1 + a2;
		b3 = b2 + a3;
		b4 = b3 + a4;
		b5 = b4 + a5;
		b6 = b5 + a6;
		b = b6 + a;
		c0 = c + b0;
		c1 = c0 + b1;
		c2 = c1 + b2;
		c3 = c2 + b3;
		c4 = c3 + b4;
		c5 = c4 + b5;
		c6 = c5 + b6;
		c = c6 + b;
		d0 = d + c0;
		d1 = d0 + c1;
		d2 = d1 + c2;
		d3 = d2 + c3;
		d4 = d3 + c4;
		d5 = d4 + c5;
		d6 = d5 + c6;
		d = d6 + c;
	}

	ZIO_SET_CHECKSUM(&ctx->scalar, a, b, c, d);
}

static boolean_t fletcher_4_unrolled8_valid(void)
{
	return (B_TRUE);
}

const fletcher_4_ops_t fletcher_4_unrolled8_ops = {
	.init_native = fletcher_4_unrolled8_init,
	.compute_native = fletcher_4_unrolled8_native,
	.fini_native = fletcher_4_unrolled8_fini,
	.init_byteswap = fletcher_4_unrolled8_init,
	.compute_byteswap = fletcher_4_unrolled8_byteswap,
	.fini_byteswap = fletcher_4_unrolled8_fini,
	.valid = fletcher_4_unrolled8_valid,
	.name = "unrolled8"
};
