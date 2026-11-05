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

#ifndef	_SYS_ZONE_H
#define	_SYS_ZONE_H

#define	zone_dataset_visible(x, y)	(1)

#define	INGLOBALZONE(z)			(1)

#define	is_system_labeled()		(0)

typedef enum {
	ZONE_OP_CREATE,
	ZONE_OP_SNAPSHOT,
	ZONE_OP_CLONE,
	ZONE_OP_DESTROY,
	ZONE_OP_RENAME,
	ZONE_OP_SETPROP
} zone_uid_op_t;

typedef enum {
	ZONE_ADMIN_NOT_APPLICABLE,
	ZONE_ADMIN_ALLOWED,
	ZONE_ADMIN_DENIED
} zone_admin_result_t;

#define	zone_dataset_admin_check(d, o, a)	(ZONE_ADMIN_NOT_APPLICABLE)
#define	zone_dataset_attach_uid(c, d, u)	(0)
#define	zone_dataset_detach_uid(c, d, u)	(0)

extern uint32_t zone_get_hostid(void *zonep);

#endif /* _SYS_ZONE_H */
