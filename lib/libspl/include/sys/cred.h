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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _LIBSPL_SYS_CRED_H
#define	_LIBSPL_SYS_CRED_H

#include <sys/stat.h>

/*
 * Credentials
 */

typedef struct cred cred_t;

extern uid_t crgetuid(cred_t *cr);
extern uid_t crgetruid(cred_t *cr);
extern gid_t crgetgid(cred_t *cr);
extern int crgetngroups(cred_t *cr);
extern gid_t *crgetgroups(cred_t *cr);
extern int groupmember(gid_t gid, const cred_t *cr);

/*
 * zfsd binds the ioctl caller's uid/gid to this thread so
 * dsl_deleg_access() (which uses crgetuid/crgetgid) sees the
 * real client, not uid 0. CRED() stays NULL; the getters read TLS.
 */
int zfsd_crset(uid_t uid, gid_t gid, int ngroups, const gid_t *groups);
void zfsd_crclr(void);


/*
 * zfsd_daemon is 0 for ztest/zdb/zfs/zpool. zfsd calls
 * zfsd_mark_daemon() at startup so in-process libspl (getzoneid)
 * can see it. Not an environment variable.
 */
extern int zfsd_daemon;
void zfsd_mark_daemon(void);

#define	kcred		NULL
#define	CRED()		NULL

#define	crhold(cr)	((void)cr)
#define	crfree(cr)	((void)cr)

#endif
