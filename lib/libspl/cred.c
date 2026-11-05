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
 */

#include <sys/cred.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>


#ifndef	ZFSD_NGROUPS_MAX
#define	ZFSD_NGROUPS_MAX	65536
#endif

typedef struct {
	int	set;
	uid_t	uid;
	gid_t	gid;
	int	ngroups;
	int	groups_cap;
	gid_t	*groups;
} zfsd_tls_cred_t;

static __thread zfsd_tls_cred_t tcred;
static pthread_key_t tcred_key;
static pthread_once_t tcred_once = PTHREAD_ONCE_INIT;

static void
zfsd_tcred_dtor(void *p)
{
	(void) pthread_setspecific(tcred_key, NULL);
	if (p == tcred.groups) {
		tcred.groups = NULL;
		tcred.groups_cap = 0;
		tcred.ngroups = 0;
	}
	free(p);
}

static void
zfsd_tcred_key_init(void)
{
	(void) pthread_key_create(&tcred_key, zfsd_tcred_dtor);
}

int zfsd_daemon;

void
zfsd_mark_daemon(void)
{
	zfsd_daemon = 1;
}

int
zfsd_crset(uid_t uid, gid_t gid, int ngroups, const gid_t *groups)
{
	if (ngroups < 0)
		ngroups = 0;
	if (ngroups > ZFSD_NGROUPS_MAX)
		return (-1);
	if (ngroups > 0 && groups == NULL)
		return (-1);
	if (ngroups > tcred.groups_cap) {
		gid_t *n = realloc(tcred.groups,
		    (size_t)ngroups * sizeof (gid_t));
		if (n == NULL)
			return (-1);
		tcred.groups = n;
		tcred.groups_cap = ngroups;
	}
	(void) pthread_once(&tcred_once, zfsd_tcred_key_init);
	(void) pthread_setspecific(tcred_key, tcred.groups);
	tcred.set = 1;
	tcred.uid = uid;
	tcred.gid = gid;
	tcred.ngroups = ngroups;
	if (ngroups > 0)
		(void) memcpy(tcred.groups, groups,
		    (size_t)ngroups * sizeof (gid_t));
	return (0);
}

void
zfsd_crclr(void)
{
	tcred.set = 0;
	tcred.uid = 0;
	tcred.gid = 0;
	tcred.ngroups = 0;
}


uid_t
crgetuid(cred_t *cr)
{
	(void) cr;
	return (tcred.set ? tcred.uid : 0);
}

uid_t
crgetruid(cred_t *cr)
{
	(void) cr;
	return (tcred.set ? tcred.uid : 0);
}

gid_t
crgetgid(cred_t *cr)
{
	(void) cr;
	return (tcred.set ? tcred.gid : 0);
}

int
crgetngroups(cred_t *cr)
{
	(void) cr;
	return (tcred.set ? tcred.ngroups : 0);
}

gid_t *
crgetgroups(cred_t *cr)
{
	(void) cr;
	return (tcred.set ? tcred.groups : NULL);
}

int
groupmember(gid_t gid, const cred_t *cr)
{
	int i, n;
	gid_t *g;

	if (crgetgid((cred_t *)cr) == gid)
		return (1);
	n = crgetngroups((cred_t *)cr);
	g = crgetgroups((cred_t *)cr);
	if (g == NULL)
		return (0);
	for (i = 0; i < n; i++) {
		if (g[i] == gid)
			return (1);
	}
	return (0);
}
