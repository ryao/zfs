// SPDX-License-Identifier: CDDL-1.0
/*
 * zfsd znode OS fields. No Linux inode: FUSE holds znodes by object id.
 * Macros keep the names used by module/zfs/zfs_vnops.c and the OS glue.
 */
#ifndef	_SYS_ZFS_ZNODE_IMPL_H
#define	_SYS_ZFS_ZNODE_IMPL_H

#include <sys/isa_defs.h>
#include <sys/types32.h>
#include <sys/list.h>
#include <sys/dmu.h>
#include <sys/sa.h>
#include <sys/time.h>
#include <sys/zfs_vfsops.h>
#include <sys/rrwlock.h>
#include <sys/zfs_sa.h>
#include <sys/zfs_stat.h>
#include <sys/zfs_rlock.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	ZNODE_OS_FIELDS			\
	zfsvfs_t	*z_zfsvfs;	\
	uint64_t	z_uid;		\
	uint64_t	z_gid;		\
	uint64_t	z_links;	\
	uint_t		z_ref;		\
	uint32_t	z_gen;		\
	inode_timespec_t z_atime;	\
	inode_timespec_t z_mtime;	\
	inode_timespec_t z_ctime;	\
	inode_timespec_t z_btime;

#define	ZTOZSB(znode)	((znode)->z_zfsvfs)
#define	ZTOTYPE(zp)	((zp)->z_mode)
#define	ZTOGID(zp)	((zp)->z_gid)
#define	ZTOUID(zp)	((zp)->z_uid)
#define	ZTONLNK(zp)	((zp)->z_links)

#define	Z_ISBLK(type)	S_ISBLK(type)
#define	Z_ISCHR(type)	S_ISCHR(type)
#define	Z_ISLNK(type)	S_ISLNK(type)
#define	Z_ISDEV(type)	(S_ISCHR(type) || S_ISBLK(type) || S_ISFIFO(type))
#define	Z_ISDIR(type)	S_ISDIR(type)

/* FUSE has no page cache. */
#define	zn_has_cached_data(zp, start, end)	(B_FALSE)
#define	zn_flush_cached_data(zp, sync)		((void)0)
#define	zn_rlimit_fsize(size)			(0)
#define	zn_rlimit_fsize_uio(zp, uio)		(0)
#define	zn_zero_eof_page(zp, lr, end)		((void)0)

#ifndef	KUID_TO_SUID
#define	KUID_TO_SUID(x)	(x)
#define	KGID_TO_SGID(x)	(x)
#endif

void zhold(struct znode *zp);
void zrele(struct znode *zp);

static inline int
zfs_enter(zfsvfs_t *zfsvfs, const char *tag)
{
	ZFS_TEARDOWN_ENTER_READ(zfsvfs, tag);
	if (zfsvfs->z_unmounted) {
		ZFS_TEARDOWN_EXIT_READ(zfsvfs, tag);
		return (SET_ERROR(EIO));
	}
	return (0);
}

static inline void
zfs_exit(zfsvfs_t *zfsvfs, const char *tag)
{
	zfs_exit_fs(zfsvfs);
	ZFS_TEARDOWN_EXIT_READ(zfsvfs, tag);
}

#define	ZFS_OBJ_MTX_SZ		64
#define	ZFS_OBJ_MTX_MAX		(1024 * 1024)
#define	ZFS_OBJ_HASH(zfsvfs, obj)	((obj) & ((zfsvfs)->z_hold_size - 1))

extern unsigned int zfs_object_mutex_size;

#define	ZFS_TIME_ENCODE(tp, stmp)		\
do {						\
	(stmp)[0] = (uint64_t)(tp)->tv_sec;	\
	(stmp)[1] = (uint64_t)(tp)->tv_nsec;	\
} while (0)

#define	ZFS_TIME_DECODE(tp, stmp)		\
do {						\
	(tp)->tv_sec = (time_t)(stmp)[0];	\
	(tp)->tv_nsec = (long)(stmp)[1];	\
} while (0)

struct znode;
extern boolean_t zfs_relatime_need_update(const struct znode *);

/*
 * Linux kernel ZFS leaves this empty and lets VFS stamp i_atime.
 * zfsd has no inode, so update zp->z_atime here (FreeBSD-style).
 */
#define	ZFS_ACCESSTIME_STAMP(zfsvfs, zp) do { \
	if ((zfsvfs)->z_atime && !zfs_is_readonly(zfsvfs) && \
	    (!(zfsvfs)->z_relatime || zfs_relatime_need_update(zp))) \
		zfs_tstamp_update_setup((zp), ACCESSED, NULL, NULL); \
} while (0)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ZFS_ZNODE_IMPL_H */
