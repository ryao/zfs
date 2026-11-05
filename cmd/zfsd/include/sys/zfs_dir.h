// SPDX-License-Identifier: CDDL-1.0
#ifndef	_SYS_FS_ZFS_DIR_H
#define	_SYS_FS_ZFS_DIR_H

#include <sys/pathname.h>
#include <sys/dmu.h>
#include <sys/zfs_znode.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	ZNEW		0x0001
#define	ZEXISTS		0x0002
#define	ZSHARED		0x0004
#define	ZXATTR		0x0008
#define	ZRENAMING	0x0010
#define	ZCILOOK		0x0020
#define	ZCIEXACT	0x0040
#define	ZHAVELOCK	0x0080

#define	IS_ROOT_NODE	0x01
#define	IS_XATTR	0x02
#define	IS_TMPFILE	0x04

extern int zfs_dirent_lock(zfs_dirlock_t **, znode_t *, char *, znode_t **,
    int, int *, pathname_t *);
extern void zfs_dirent_unlock(zfs_dirlock_t *);
extern int zfs_drop_nlink(znode_t *, dmu_tx_t *, boolean_t *);
extern int zfs_link_create(zfs_dirlock_t *, znode_t *, dmu_tx_t *, int);
extern int zfs_link_destroy(zfs_dirlock_t *, znode_t *, dmu_tx_t *, int,
    boolean_t *);
extern int zfs_dirlook(znode_t *, char *, znode_t **, int, int *,
    pathname_t *);
extern void zfs_mknode(znode_t *, vattr_t *, dmu_tx_t *, cred_t *,
    uint_t, znode_t **, zfs_acl_ids_t *);
extern void zfs_rmnode(znode_t *);
extern void zfs_dl_name_switch(zfs_dirlock_t *dl, char *new, char **old);
extern boolean_t zfs_dirempty(znode_t *);
extern void zfs_unlinked_add(znode_t *, dmu_tx_t *);
extern void zfs_unlinked_drain(zfsvfs_t *zfsvfs);
extern void zfs_unlinked_drain_stop_wait(zfsvfs_t *zfsvfs);
extern int zfs_sticky_remove_access(znode_t *, znode_t *, cred_t *cr);
extern int zfs_get_xattrdir(znode_t *, znode_t **, cred_t *, int);
extern int zfs_make_xattrdir(znode_t *, vattr_t *, znode_t **, cred_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_ZFS_DIR_H */
