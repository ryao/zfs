// SPDX-License-Identifier: CDDL-1.0
/*
 * Delegated SMB share via `net usershare`.
 */

#ifndef _GNU_SOURCE
#define	_GNU_SOURCE
#endif
#include <sys/zfs_context.h>
#include "zfsd_impl.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#ifdef __linux__

int
zfsd_smb_available(void)
{
	struct stat st;

	if (access(ZFSD_SMB_NET, X_OK) != 0)
		return (0);
	if (lstat(ZFSD_SMB_SHAREDIR, &st) != 0 || !S_ISDIR(st.st_mode))
		return (0);
	return (1);
}

static void
zfsd_smb_name(const char *ds, char *name, size_t n)
{
	char *p;

	(void) strlcpy(name, ds, n);
	for (p = name; *p != '\0'; p++) {
		if (*p == '/' || *p == '-' || *p == ':' || *p == ' ')
			*p = '_';
	}
}

int
zfsd_smb_enable(const char *ds, const char *mnt, const char *opts)
{
	char name[256], comment[256];
	char *argv[10];

	if (ds == NULL || ds[0] == '\0')
		return (EINVAL);
	if (opts != NULL && strcmp(opts, "off") == 0)
		return (0);
	if (!zfsd_smb_available())
		return (ENOSYS);
	zfsd_smb_name(ds, name, sizeof (name));
	(void) snprintf(comment, sizeof (comment), "Comment: %s", mnt);
	argv[0] = (char *)ZFSD_SMB_NET;
	argv[1] = (char *)"-S";
	argv[2] = (char *)ZFSD_SMB_HOST;
	argv[3] = (char *)"usershare";
	argv[4] = (char *)"add";
	argv[5] = name;
	argv[6] = (char *)mnt;
	argv[7] = comment;
	argv[8] = (char *)"Everyone:F";
	argv[9] = NULL;
	return (zfsd_run(argv));
}

int
zfsd_smb_disable(const char *ds, const char *mnt)
{
	char name[256];
	char *argv[8];

	(void) mnt;
	if (ds == NULL || ds[0] == '\0')
		return (EINVAL);
	if (!zfsd_smb_available())
		return (0);
	zfsd_smb_name(ds, name, sizeof (name));
	argv[0] = (char *)ZFSD_SMB_NET;
	argv[1] = (char *)"-S";
	argv[2] = (char *)ZFSD_SMB_HOST;
	argv[3] = (char *)"usershare";
	argv[4] = (char *)"delete";
	argv[5] = name;
	argv[6] = NULL;
	(void) zfsd_run(argv);
	return (0);
}

#endif /* __linux__ */

#ifndef __linux__
int
zfsd_smb_available(void)
{
	return (0);
}

int
zfsd_smb_enable(const char *ds, const char *mnt, const char *opts)
{
	(void) ds;
	(void) mnt;
	(void) opts;
	return (ENOTSUP);
}

int
zfsd_smb_disable(const char *ds, const char *mnt)
{
	(void) ds;
	(void) mnt;
	return (0);
}
#endif
