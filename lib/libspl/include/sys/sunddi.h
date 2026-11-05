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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2012, 2018 by Delphix. All rights reserved.
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 */

#ifndef	_SYS_SUNDDI_H
#define	_SYS_SUNDDI_H

#include <string.h>
#include <errno.h>

extern int ddi_strtoull(const char *str, char **nptr, int base,
    u_longlong_t *result);

/*
 * Userspace: the caller has already mapped the buffer into this
 * process (zfsd rewrites zfs_cmd_t nested pointers to local copies).
 */
static inline int
ddi_copyin(const void *from, void *to, size_t len, int flags)
{
	(void) flags;
	if (from == NULL || to == NULL)
		return (-1);
	(void) memcpy(to, from, len);
	return (0);
}

static inline int
ddi_copyout(const void *from, void *to, size_t len, int flags)
{
	(void) flags;
	if (from == NULL || to == NULL)
		return (-1);
	(void) memcpy(to, from, len);
	return (0);
}

static inline int
copyinstr(const void *from, void *to, size_t len, size_t *done)
{
	size_t n;

	if (from == NULL || to == NULL || len == 0)
		return (EFAULT);
	n = strnlen((const char *)from, len);
	if (n >= len)
		return (ENAMETOOLONG);
	(void) memcpy(to, from, n + 1);
	if (done != NULL)
		*done = n + 1;
	return (0);
}

static inline int
xcopyout(const void *from, void *to, size_t len)
{
	if (from == NULL || to == NULL)
		return (EFAULT);
	(void) memcpy(to, from, len);
	return (0);
}

#endif	/* _SYS_SUNDDI_H */
