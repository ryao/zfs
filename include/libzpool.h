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

#ifndef _LIBZPOOL_H
#define	_LIBZPOOL_H extern __attribute__((visibility("default")))

#include <sys/zfs_context.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern char *vn_dumpdir;

_LIBZPOOL_H void kernel_init(int mode);
_LIBZPOOL_H void kernel_fini(void);

struct spa;
_LIBZPOOL_H void show_pool_stats(struct spa *);
_LIBZPOOL_H int handle_tunable_option(const char *, boolean_t);

/*
 * Access libzpool's linker-set tunables from another DSO. The
 * zfs_tunable_* symbols in libspl are hidden (each library that
 * links libspl.a gets its own empty or full table). These wrap
 * the copy compiled into libzpool.so, which is the one with the
 * ZFS_MODULE_PARAM objects from module/zfs/*.c.
 */
typedef int (*libzpool_tunable_iter_t)(const char *name, boolean_t writable,
    void *arg);
_LIBZPOOL_H void libzpool_tunable_iter(libzpool_tunable_iter_t cb, void *arg);
_LIBZPOOL_H int libzpool_tunable_get(const char *name, char *buf, size_t n);
_LIBZPOOL_H int libzpool_tunable_set(const char *name, const char *val);

#ifdef	__cplusplus
}
#endif

#endif
