// SPDX-License-Identifier: CDDL-1.0
/*
 * FUSE mount handle. The ZPL is zfsvfs_t; this is the FUSE session
 * around a mounted zfsvfs. Create uses zfs_create_fs, mount uses
 * zfsvfs_create + zfsvfs_setup.
 *
 * Snapshots under .zfs/snapshot/<name> are served from the parent
 * FUSE session (zpl_snapos in zfsd_ctldir.c).
 */
#ifndef	ZFSD_ZPL_H
#define	ZFSD_ZPL_H

#include <sys/dmu.h>
#include <sys/fs/zfs.h>
#include <sys/zfs_vfsops.h>
#include <sys/types.h>
#include <pthread.h>
#include <limits.h>
#include <time.h>

#define	ZFSD_SNAP_EXPIRE	300	/* kernel zfs_expire_snapshot */

typedef struct zpl_mnt {
	char		ds[ZFS_MAX_DATASET_NAME_LEN];
	char		mnt[MAXPATHLEN];
	zfsvfs_t	*zfsvfs;
	struct fuse	*fuse;
	pthread_t	tid;
	int		running;
	int		loop_done;	/* fuse loop returned; not joined yet */
	int		dying;
	int		readonly;
	int		snap;		/* automounted .zfs/snapshot */
	int		pending;	/* insert reserved, not yet mounted */
	int		inuse;		/* refcount; always under g_mntlock */
	time_t		used;		/* CLOCK_MONOTONIC seconds */
	dev_t		fsid_dev;	/* s_dev from mountinfo, not stat(mnt) */
	pthread_mutex_t	lock;
	struct zpl_mnt	*parent;
	struct zpl_mnt	*next;
} zpl_mnt_t;


struct fuse_operations;
struct znode;
extern const struct fuse_operations zpl_ops;
void zpl_lock_purge_fs(uint64_t fsid);
int zfsd_zpl_snap_ensure(zpl_mnt_t *parent, const char *snapname, int wait);
int zfsd_zpl_snap_borrow(zpl_mnt_t *parent, const char *snapname,
    zfsvfs_t **zfvp, zpl_mnt_t **mp, int wait);
void zfsd_zpl_snap_rele(zpl_mnt_t *m);
int zpl_snapos_hold(zpl_mnt_t *parent, const char *snapname,
    zfsvfs_t **zfvp);
void zpl_snapos_rele(zfsvfs_t *zfsvfs);
void zpl_snapos_drop(const char *ds);
void zpl_snapos_drop_all(void);
extern pthread_mutex_t g_mntlock;
extern zpl_mnt_t *g_mnts;
void zfsd_tunables_refresh(void);
int zfsd_zpl_zget_by_dev(dev_t dev, uint64_t ino, struct znode **zpp);
void zfsd_zpl_inval_fs(zfsvfs_t *zfsvfs);


#endif
