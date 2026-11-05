// SPDX-License-Identifier: CDDL-1.0
/*
 * zfsd zfsvfs_t. Same fields as the Linux OS header minus super_block
 * and inode. vfs_t is the mount-option container used on Linux too.
 */
#ifndef	_SYS_FS_ZFS_VFSOPS_H
#define	_SYS_FS_ZFS_VFSOPS_H

#include <sys/dataset_kstats.h>
#include <sys/isa_defs.h>
#include <sys/types32.h>
#include <sys/list.h>
#include <sys/vfs.h>
#include <sys/zil.h>
#include <sys/sa.h>
#include <sys/rrwlock.h>
#include <sys/dsl_dataset.h>
#include <sys/objlist.h>
#include <sys/zfs_ioctl.h>
#include <sys/taskq.h>
#include <sys/fs/zfs.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct zfsvfs zfsvfs_t;
struct znode;

typedef struct vfs {
	struct zfsvfs	*vfs_data;
	char		*vfs_mntpoint;
	uint64_t	vfs_xattr;
	boolean_t	vfs_readonly;
	boolean_t	vfs_do_readonly;
	boolean_t	vfs_setuid;
	boolean_t	vfs_do_setuid;
	boolean_t	vfs_exec;
	boolean_t	vfs_do_exec;
	boolean_t	vfs_devices;
	boolean_t	vfs_do_devices;
	boolean_t	vfs_do_xattr;
	boolean_t	vfs_atime;
	boolean_t	vfs_do_atime;
	boolean_t	vfs_relatime;
	boolean_t	vfs_do_relatime;
	boolean_t	vfs_nbmand;
	boolean_t	vfs_do_nbmand;
	kmutex_t	vfs_mntpt_lock;
} vfs_t;

struct zfsvfs {
	vfs_t		*z_vfs;
	void		*z_sb;
	struct zfsvfs	*z_parent;
	objset_t	*z_os;
	uint64_t	z_flags;
	uint64_t	z_root;
	uint64_t	z_unlinkedobj;
	uint64_t	z_max_blksz;
	uint64_t	z_fuid_obj;
	uint64_t	z_fuid_size;
	avl_tree_t	z_fuid_idx;
	avl_tree_t	z_fuid_domain;
	krwlock_t	z_fuid_lock;
	boolean_t	z_fuid_loaded;
	boolean_t	z_fuid_dirty;
	struct zfs_fuid_info	*z_fuid_replay;
	zilog_t		*z_log;
	uint_t		z_acl_mode;
	uint_t		z_acl_inherit;
	uint_t		z_acl_type;
	zfs_case_t	z_case;
	boolean_t	z_utf8;
	int		z_norm;
	boolean_t	z_relatime;
	boolean_t	z_atime;
	boolean_t	z_unmounted;
	boolean_t	z_use_hold;
	rrmlock_t	z_teardown_lock;
	krwlock_t	z_teardown_inactive_lock;
	list_t		z_all_znodes;
	uint64_t	z_rollback_time;
	uint64_t	z_snap_atime;
	kmutex_t	z_znodes_lock;
	void		*z_arc_prune;
	void		*z_ctldir;
	uint_t		z_show_ctldir;
	boolean_t	z_issnap;
	boolean_t	z_use_fuids;
	boolean_t	z_replay;
	boolean_t	z_use_sa;
	boolean_t	z_xattr_sa;
	boolean_t	z_draining;
	boolean_t	z_drain_cancel;
	boolean_t	z_longname;
	uint64_t	z_version;
	uint64_t	z_shares_dir;
	dataset_kstats_t	z_kstat;
	kmutex_t	z_lock;
	uint64_t	z_userquota_obj;
	uint64_t	z_groupquota_obj;
	uint64_t	z_userobjquota_obj;
	uint64_t	z_groupobjquota_obj;
	uint64_t	z_projectquota_obj;
	uint64_t	z_projectobjquota_obj;
	uint64_t	z_defaultuserquota;
	uint64_t	z_defaultgroupquota;
	uint64_t	z_defaultprojectquota;
	uint64_t	z_defaultuserobjquota;
	uint64_t	z_defaultgroupobjquota;
	uint64_t	z_defaultprojectobjquota;
	uint64_t	z_replay_eof;
	sa_attr_type_t	*z_attr_table;
	uint64_t	z_hold_size;
	avl_tree_t	*z_hold_trees;
	kmutex_t	*z_hold_locks;
	taskqid_t	z_drain_task;
};

void zfsd_zfsvfs_refresh_props(zfsvfs_t *);

#define	ZFS_TEARDOWN_INIT(zfsvfs)		\
	rrm_init(&(zfsvfs)->z_teardown_lock, B_FALSE)

#define	ZFS_TEARDOWN_DESTROY(zfsvfs)		\
	rrm_destroy(&(zfsvfs)->z_teardown_lock)

#define	ZFS_TEARDOWN_ENTER_READ(zfsvfs, tag)	\
	rrm_enter_read(&(zfsvfs)->z_teardown_lock, tag)

#define	ZFS_TEARDOWN_EXIT_READ(zfsvfs, tag)	\
	rrm_exit(&(zfsvfs)->z_teardown_lock, tag)

#define	ZFS_TEARDOWN_ENTER_WRITE(zfsvfs, tag)	\
	rrm_enter(&(zfsvfs)->z_teardown_lock, RW_WRITER, tag)

#define	ZFS_TEARDOWN_EXIT_WRITE(zfsvfs)		\
	rrm_exit(&(zfsvfs)->z_teardown_lock, FTAG)

#define	ZFS_TEARDOWN_EXIT(zfsvfs, tag)		\
	rrm_exit(&(zfsvfs)->z_teardown_lock, tag)

#define	ZFS_TEARDOWN_READ_HELD(zfsvfs)		\
	RRM_READ_HELD(&(zfsvfs)->z_teardown_lock)

#define	ZFS_TEARDOWN_WRITE_HELD(zfsvfs)		\
	RRM_WRITE_HELD(&(zfsvfs)->z_teardown_lock)

#define	ZFS_TEARDOWN_HELD(zfsvfs)		\
	RRM_LOCK_HELD(&(zfsvfs)->z_teardown_lock)

#define	ZSB_XATTR	0x0001
#define	ZFS_LINK_MAX		((1U << 31) - 1U)

extern void zfs_exit_fs(zfsvfs_t *zfsvfs);
extern boolean_t zfs_is_readonly(zfsvfs_t *zfsvfs);
extern int zfsvfs_create(const char *name, boolean_t readonly, zfsvfs_t **zfvp);
extern int zfsvfs_create_hold(const char *name, zfsvfs_t **zfvp);
extern int zfsvfs_create_impl(zfsvfs_t **zfvp, zfsvfs_t *zfsvfs, objset_t *os);
extern int zfsvfs_setup(zfsvfs_t *zfsvfs, boolean_t mounting);
extern void zfsvfs_free(zfsvfs_t *zfsvfs);
extern void zfsvfs_teardown(zfsvfs_t *zfsvfs, boolean_t unmounting);
extern vfs_t *zfsvfs_vfs_alloc(void);
extern void zfsvfs_vfs_free(vfs_t *vfsp);
extern void zfsvfs_update_fromname(const char *, const char *);
extern int zfs_suspend_fs(zfsvfs_t *zfsvfs);
extern int zfs_resume_fs(zfsvfs_t *zfsvfs, struct dsl_dataset *ds);
extern int zfs_end_fs(zfsvfs_t *zfsvfs, struct dsl_dataset *ds);
extern int zfs_set_version(zfsvfs_t *zfsvfs, uint64_t newvers);
extern int zfs_set_default_quota(zfsvfs_t *zfsvfs, zfs_prop_t zfs_prop,
    uint64_t quota);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_ZFS_VFSOPS_H */
