// SPDX-License-Identifier: CDDL-1.0
/*
 * Stub for module/zfs/zfs_replay.c. The kernel zpl.h is Linux VFS.
 * Replay calls zfs_* vnops, not zpl_* inode ops.
 */
#ifndef	_SYS_ZPL_H
#define	_SYS_ZPL_H

#include <sys/types.h>

typedef struct zidmap zidmap_t;
extern zidmap_t *zfs_init_idmap;

struct znode;
struct cred;
int zfsd_xattr_get(struct znode *, const char *, void *, size_t);
int zfsd_xattr_dup(struct znode *, const char *, void **, size_t *);
int zfsd_xattr_set(struct znode *, const char *, const void *, size_t, int);
int zfsd_posix_acl_equiv_mode(const void *, size_t, mode_t *);
int zfsd_posix_acl_has_named(const void *, size_t);
int zfsd_posix_acl_access(struct znode *, struct cred *, int);

#endif	/* _SYS_ZPL_H */
