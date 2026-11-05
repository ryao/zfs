// SPDX-License-Identifier: CDDL-1.0
#ifndef	_ZFS_CTLDIR_H
#define	_ZFS_CTLDIR_H

#include <sys/zfs_vfsops.h>
#include <sys/zfs_znode.h>

#define	ZFS_CTLDIR_NAME		".zfs"
#define	ZFS_SNAPDIR_NAME	"snapshot"
#define	ZFS_SHAREDIR_NAME	"shares"

#define	zfs_has_ctldir(zdp)	\
	((zdp)->z_id == ZTOZSB(zdp)->z_root && \
	(ZTOZSB(zdp)->z_ctldir != NULL))
#define	zfs_show_ctldir(zdp)	\
	(zfs_has_ctldir(zdp) && \
	(ZTOZSB(zdp)->z_show_ctldir == ZFS_SNAPDIR_VISIBLE))

struct inode;
extern int zfsctl_root_lookup(struct inode *, char *, struct inode **,
    int, cred_t *, int *, struct pathname *);
extern struct inode *zfsctl_root(znode_t *);
extern int zfsctl_snapshot_unmount(const char *snapname);

#endif	/* _ZFS_CTLDIR_H */
