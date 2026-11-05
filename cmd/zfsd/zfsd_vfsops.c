// SPDX-License-Identifier: CDDL-1.0
/*
 * zfsd OS vfsops -- same names as module/os/linux/zfs/zfs_vfsops.c.
 * zfsvfs_create attaches an existing objset. It does not create a ZPL.
 */

#include <sys/zfs_context.h>
#include <sys/zfs_vfsops.h>
#include <sys/zfs_ioctl_impl.h>
#include <sys/zfs_znode.h>
#include <sys/zfs_dir.h>
#include <sys/zfs_vnops.h>
#include <sys/zfs_quota.h>
#include <sys/dmu_objset.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_prop.h>
#include <sys/dsl_pool.h>
#include <sys/spa.h>
#include <sys/zap.h>
#include <sys/sa.h>
#include <sys/zfs_sa.h>
#include <sys/zil.h>
#include <sys/zfeature.h>
#include <sys/dataset_kstats.h>
#include <sys/cmn_err.h>
#include <sys/zfs_fuid.h>
#include <zfs_comutil.h>
#include <sys/txg.h>
#include <stdio.h>
#include <string.h>

extern int zil_replay_disable;
extern zil_replay_func_t *const zfs_replay_vector[TX_MAX_TYPE];

boolean_t
zfs_is_readonly(zfsvfs_t *zfsvfs)
{
	if (zfsvfs->z_vfs != NULL && zfsvfs->z_vfs->vfs_readonly)
		return (B_TRUE);
	if (zfsvfs->z_os != NULL && dmu_objset_is_snapshot(zfsvfs->z_os))
		return (B_TRUE);
	return (B_FALSE);
}

void
zfsd_zfsvfs_refresh_props(zfsvfs_t *zfsvfs)
{
	/*
	 * Properties are cached by dsl_prop_register callbacks in
	 * zfsvfs_setup. Polling dsl_pool_config_enter from a vnop
	 * (under dirlocks / z_lock) is a lock-order hazard.
	 */
	(void) zfsvfs;
}

static void
xattr_changed_cb(void *arg, uint64_t newval)
{
	zfsvfs_t *zfsvfs = arg;

	mutex_enter(&zfsvfs->z_lock);
	if (newval == ZFS_XATTR_OFF) {
		zfsvfs->z_flags &= ~ZSB_XATTR;
		zfsvfs->z_xattr_sa = B_FALSE;
	} else {
		zfsvfs->z_flags |= ZSB_XATTR;
		zfsvfs->z_xattr_sa =
		    (newval == ZFS_XATTR_SA) ? B_TRUE : B_FALSE;
	}
	mutex_exit(&zfsvfs->z_lock);
}

static void
acltype_changed_cb(void *arg, uint64_t newval)
{
	zfsvfs_t *zfsvfs = arg;

	mutex_enter(&zfsvfs->z_lock);
	zfsvfs->z_acl_type = (uint_t)newval;
	mutex_exit(&zfsvfs->z_lock);
}

static void
readonly_changed_cb(void *arg, uint64_t newval)
{
	zfsvfs_t *zfsvfs = arg;
	vfs_t *vfsp = zfsvfs->z_vfs;

	if (vfsp == NULL)
		return;
	mutex_enter(&zfsvfs->z_lock);
	if (newval)
		vfsp->vfs_readonly = B_TRUE;
	else if (!vfsp->vfs_do_readonly)
		vfsp->vfs_readonly = B_FALSE;
	mutex_exit(&zfsvfs->z_lock);
}


static void
blksz_changed_cb(void *arg, uint64_t newval)
{
	zfsvfs_t *zfsvfs = arg;

	if (zfsvfs == NULL || zfsvfs->z_os == NULL)
		return;
	if (newval < SPA_MINBLOCKSIZE ||
	    newval > spa_maxblocksize(dmu_objset_spa(zfsvfs->z_os)) ||
	    !ISP2(newval))
		return;
	zfsvfs->z_max_blksz = newval;
}

static void
snapdir_changed_cb(void *arg, uint64_t newval)
{
	((zfsvfs_t *)arg)->z_show_ctldir = newval;
}

static void
atime_changed_cb(void *arg, uint64_t newval)
{
	((zfsvfs_t *)arg)->z_atime = (newval != 0);
}

static void
relatime_changed_cb(void *arg, uint64_t newval)
{
	((zfsvfs_t *)arg)->z_relatime = (newval != 0);
}

void
zfs_exit_fs(zfsvfs_t *zfsvfs)
{
	(void) zfsvfs;
}


vfs_t *
zfsvfs_vfs_alloc(void)
{
	vfs_t *vfsp = kmem_zalloc(sizeof (vfs_t), KM_SLEEP);

	mutex_init(&vfsp->vfs_mntpt_lock, NULL, MUTEX_DEFAULT, NULL);
	return (vfsp);
}

void
zfsvfs_vfs_free(vfs_t *vfsp)
{
	if (vfsp == NULL)
		return;
	if (vfsp->vfs_mntpoint != NULL)
		kmem_strfree(vfsp->vfs_mntpoint);
	mutex_destroy(&vfsp->vfs_mntpt_lock);
	kmem_free(vfsp, sizeof (vfs_t));
}

void
zfsvfs_update_fromname(const char *oldname, const char *newname)
{
	(void) oldname;
	(void) newname;
}

boolean_t
zfs_get_vfs_flag_unmounted(objset_t *os)
{
	zfsvfs_t *zfvp;
	boolean_t unmounted = B_FALSE;

	mutex_enter(&os->os_user_ptr_lock);
	zfvp = dmu_objset_get_user(os);
	if (zfvp != NULL && zfvp->z_unmounted)
		unmounted = B_TRUE;
	mutex_exit(&os->os_user_ptr_lock);
	return (unmounted);
}

static int
zfsvfs_init(zfsvfs_t *zfsvfs, objset_t *os)
{
	int error;
	uint64_t val;
	uint64_t sa_obj = 0;

	zfsvfs->z_max_blksz = SPA_OLD_MAXBLOCKSIZE;
	zfsvfs->z_show_ctldir = ZFS_SNAPDIR_VISIBLE;
	zfsvfs->z_os = os;


	error = zfs_get_zplprop(os, ZFS_PROP_VERSION, &zfsvfs->z_version);
	if (error != 0)
		return (error);
	if (zfsvfs->z_version >
	    (uint64_t)zfs_zpl_version_map(spa_version(dmu_objset_spa(os))))
		return (SET_ERROR(ENOTSUP));

	error = zfs_get_zplprop(os, ZFS_PROP_NORMALIZE, &val);
	if (error != 0)
		return (error);
	zfsvfs->z_norm = (int)val;

	error = zfs_get_zplprop(os, ZFS_PROP_UTF8ONLY, &val);
	if (error != 0)
		return (error);
	zfsvfs->z_utf8 = (val != 0);

	error = zfs_get_zplprop(os, ZFS_PROP_CASE, &val);
	if (error != 0)
		return (error);
	zfsvfs->z_case = (zfs_case_t)val;

	if ((error = zfs_get_zplprop(os, ZFS_PROP_ACLTYPE, &val)) != 0)
		return (error);
	zfsvfs->z_acl_type = (uint_t)val;

	if (zfsvfs->z_case == ZFS_CASE_INSENSITIVE ||
	    zfsvfs->z_case == ZFS_CASE_MIXED)
		zfsvfs->z_norm |= U8_TEXTPREP_TOUPPER;

	zfsvfs->z_use_fuids = USE_FUIDS(zfsvfs->z_version, zfsvfs->z_os);
	zfsvfs->z_use_sa = USE_SA(zfsvfs->z_version, zfsvfs->z_os);

	if (zfsvfs->z_use_sa) {
		error = zap_lookup(os, MASTER_NODE_OBJ, ZFS_SA_ATTRS, 8, 1,
		    &sa_obj);
		if (error != 0)
			return (error);
		error = zfs_get_zplprop(os, ZFS_PROP_XATTR, &val);
		if ((error == 0) && (val == ZFS_XATTR_SA))
			zfsvfs->z_xattr_sa = B_TRUE;
	}

	error = zfs_get_zplprop(os, ZFS_PROP_DEFAULTUSERQUOTA,
	    &zfsvfs->z_defaultuserquota);
	if (error != 0)
		return (error);
	error = zfs_get_zplprop(os, ZFS_PROP_DEFAULTGROUPQUOTA,
	    &zfsvfs->z_defaultgroupquota);
	if (error != 0)
		return (error);
	error = zfs_get_zplprop(os, ZFS_PROP_DEFAULTPROJECTQUOTA,
	    &zfsvfs->z_defaultprojectquota);
	if (error != 0)
		return (error);
	error = zfs_get_zplprop(os, ZFS_PROP_DEFAULTUSEROBJQUOTA,
	    &zfsvfs->z_defaultuserobjquota);
	if (error != 0)
		return (error);
	error = zfs_get_zplprop(os, ZFS_PROP_DEFAULTGROUPOBJQUOTA,
	    &zfsvfs->z_defaultgroupobjquota);
	if (error != 0)
		return (error);
	error = zfs_get_zplprop(os, ZFS_PROP_DEFAULTPROJECTOBJQUOTA,
	    &zfsvfs->z_defaultprojectobjquota);
	if (error != 0)
		return (error);

	error = zap_lookup(os, MASTER_NODE_OBJ, ZFS_ROOT_OBJ, 8, 1,
	    &zfsvfs->z_root);
	if (error != 0)
		return (error);

	error = zap_lookup(os, MASTER_NODE_OBJ, ZFS_UNLINKED_SET, 8, 1,
	    &zfsvfs->z_unlinkedobj);
	if (error != 0)
		return (error);

	error = zap_lookup(os, MASTER_NODE_OBJ,
	    zfs_userquota_prop_prefixes[ZFS_PROP_USERQUOTA],
	    8, 1, &zfsvfs->z_userquota_obj);
	if (error == ENOENT)
		zfsvfs->z_userquota_obj = 0;
	else if (error != 0)
		return (error);

	error = zap_lookup(os, MASTER_NODE_OBJ,
	    zfs_userquota_prop_prefixes[ZFS_PROP_GROUPQUOTA],
	    8, 1, &zfsvfs->z_groupquota_obj);
	if (error == ENOENT)
		zfsvfs->z_groupquota_obj = 0;
	else if (error != 0)
		return (error);

	error = zap_lookup(os, MASTER_NODE_OBJ,
	    zfs_userquota_prop_prefixes[ZFS_PROP_PROJECTQUOTA],
	    8, 1, &zfsvfs->z_projectquota_obj);
	if (error == ENOENT)
		zfsvfs->z_projectquota_obj = 0;
	else if (error != 0)
		return (error);

	error = zap_lookup(os, MASTER_NODE_OBJ,
	    zfs_userquota_prop_prefixes[ZFS_PROP_USEROBJQUOTA],
	    8, 1, &zfsvfs->z_userobjquota_obj);
	if (error == ENOENT)
		zfsvfs->z_userobjquota_obj = 0;
	else if (error != 0)
		return (error);

	error = zap_lookup(os, MASTER_NODE_OBJ,
	    zfs_userquota_prop_prefixes[ZFS_PROP_GROUPOBJQUOTA],
	    8, 1, &zfsvfs->z_groupobjquota_obj);
	if (error == ENOENT)
		zfsvfs->z_groupobjquota_obj = 0;
	else if (error != 0)
		return (error);

	error = zap_lookup(os, MASTER_NODE_OBJ,
	    zfs_userquota_prop_prefixes[ZFS_PROP_PROJECTOBJQUOTA],
	    8, 1, &zfsvfs->z_projectobjquota_obj);
	if (error == ENOENT)
		zfsvfs->z_projectobjquota_obj = 0;
	else if (error != 0)
		return (error);

	error = zap_lookup(os, MASTER_NODE_OBJ, ZFS_FUID_TABLES, 8, 1,
	    &zfsvfs->z_fuid_obj);
	if (error == ENOENT)
		zfsvfs->z_fuid_obj = 0;
	else if (error != 0)
		return (error);

	error = zap_lookup(os, MASTER_NODE_OBJ, ZFS_SHARES_DIR, 8, 1,
	    &zfsvfs->z_shares_dir);
	if (error == ENOENT)
		zfsvfs->z_shares_dir = 0;
	else if (error != 0)
		return (error);

	error = sa_setup(os, sa_obj, zfs_attr_table, ZPL_END,
	    &zfsvfs->z_attr_table);
	if (error != 0)
		return (error);

	if (zfsvfs->z_version >= ZPL_VERSION_SA)
		sa_register_update_callback(os, zfs_sa_upgrade);

	zfsvfs->z_issnap = dmu_objset_is_snapshot(os);
	return (0);
}

int
zfsvfs_create_impl(zfsvfs_t **zfvp, zfsvfs_t *zfsvfs, objset_t *os)
{
	int error;
	int size;
	int i;

	zfsvfs->z_vfs = NULL;
	zfsvfs->z_sb = NULL;
	zfsvfs->z_parent = zfsvfs;

	mutex_init(&zfsvfs->z_znodes_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&zfsvfs->z_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&zfsvfs->z_all_znodes, sizeof (znode_t),
	    offsetof(znode_t, z_link_node));
	ZFS_TEARDOWN_INIT(zfsvfs);
	rw_init(&zfsvfs->z_teardown_inactive_lock, NULL, RW_DEFAULT, NULL);
	rw_init(&zfsvfs->z_fuid_lock, NULL, RW_DEFAULT, NULL);

	size = MIN(1 << (highbit64(zfs_object_mutex_size) - 1),
	    ZFS_OBJ_MTX_MAX);
	if (size == 0)
		size = ZFS_OBJ_MTX_SZ;
	zfsvfs->z_hold_size = size;
	zfsvfs->z_hold_trees = vmem_zalloc(sizeof (avl_tree_t) * size,
	    KM_SLEEP);
	zfsvfs->z_hold_locks = vmem_zalloc(sizeof (kmutex_t) * size, KM_SLEEP);
	for (i = 0; i != size; i++) {
		avl_create(&zfsvfs->z_hold_trees[i], zfs_znode_hold_compare,
		    sizeof (znode_hold_t), offsetof(znode_hold_t, zh_node));
		mutex_init(&zfsvfs->z_hold_locks[i], NULL, MUTEX_DEFAULT, NULL);
	}

	zil_sums_init(&zfsvfs->z_kstat.dk_zil_sums);

	error = zfsvfs_init(zfsvfs, os);
	if (error != 0) {
		if (zfsvfs->z_use_hold)
			dmu_objset_rele(os, zfsvfs);
		else
			dmu_objset_disown(os, B_TRUE, zfsvfs);
		*zfvp = NULL;
		zfsvfs_free(zfsvfs);
		return (error);
	}

	zfsvfs->z_drain_task = TASKQID_INVALID;
	zfsvfs->z_draining = B_FALSE;
	zfsvfs->z_drain_cancel = B_TRUE;
	zfsvfs->z_atime = B_TRUE;

	*zfvp = zfsvfs;
	return (0);
}

int
zfsvfs_create(const char *osname, boolean_t readonly, zfsvfs_t **zfvp)
{
	objset_t *os;
	zfsvfs_t *zfsvfs;
	int error;
	boolean_t ro = (readonly || (strchr(osname, '@') != NULL));

	zfsvfs = kmem_zalloc(sizeof (zfsvfs_t), KM_SLEEP);
	error = dmu_objset_own(osname, DMU_OST_ZFS, ro, B_TRUE, zfsvfs, &os);
	if (error != 0) {
		kmem_free(zfsvfs, sizeof (zfsvfs_t));
		return (error);
	}
	return (zfsvfs_create_impl(zfvp, zfsvfs, os));
}

int
zfsvfs_create_hold(const char *osname, zfsvfs_t **zfvp)
{
	objset_t *os;
	zfsvfs_t *zfsvfs;
	int error;

	zfsvfs = kmem_zalloc(sizeof (zfsvfs_t), KM_SLEEP);
	error = dmu_objset_hold(osname, zfsvfs, &os);
	if (error != 0) {
		kmem_free(zfsvfs, sizeof (zfsvfs_t));
		return (error);
	}
	if (dmu_objset_type(os) != DMU_OST_ZFS) {
		dmu_objset_rele(os, zfsvfs);
		kmem_free(zfsvfs, sizeof (zfsvfs_t));
		return (SET_ERROR(EINVAL));
	}
	zfsvfs->z_use_hold = B_TRUE;
	return (zfsvfs_create_impl(zfvp, zfsvfs, os));
}

int
zfsvfs_setup(zfsvfs_t *zfsvfs, boolean_t mounting)
{
	int error;
	boolean_t readonly = zfs_is_readonly(zfsvfs);
	dsl_dataset_t *ds;

	/*
	 * Match Linux zfs_domount: snapshots never zil_open, and
	 * os_sync is DISABLED so the existing zfs_fsync guard (shared
	 * with the kernel) is a no-op. Opening a zilog here made
	 * zil_commit ASSERT on FUSE flush-on-close.
	 */
	if (zfsvfs->z_issnap) {
		zfsvfs->z_os->os_sync = ZFS_SYNC_DISABLED;
		if (mounting)
			zfsvfs->z_sb = zfsvfs;
		if (zfsvfs->z_vfs != NULL) {
			zfsvfs->z_vfs->vfs_do_readonly = B_TRUE;
			zfsvfs->z_vfs->vfs_readonly = B_TRUE;
		}
		mutex_enter(&zfsvfs->z_os->os_user_ptr_lock);
		dmu_objset_set_user(zfsvfs->z_os, zfsvfs);
		mutex_exit(&zfsvfs->z_os->os_user_ptr_lock);
		return (0);
	}

	if (!mounting) {
		zfsvfs->z_log = zil_open(zfsvfs->z_os, zfs_get_data,
		    &zfsvfs->z_kstat.dk_zil_sums);
		return (0);
	}

	error = dataset_kstats_create(&zfsvfs->z_kstat, zfsvfs->z_os);
	if (error != 0) {
		/*
		 * libspl kstat_create is a stub that always returns
		 * NULL, so dataset_kstats_create reports ENOMEM.
		 * Kstats are optional in zfsd. zil_sums were
		 * initialized in zfsvfs_create_impl.
		 */
		error = 0;
	}
	zfsvfs->z_log = zil_open(zfsvfs->z_os, zfs_get_data,
	    &zfsvfs->z_kstat.dk_zil_sums);

	if (mounting)
		zfsvfs->z_sb = zfsvfs;
	zfsvfs->z_ctldir = (void *)(uintptr_t)1;

	/*
	 * Same stash as Linux zfs_register_callbacks. An explicit
	 * mount -o ro/rw (vfs_do_readonly already set) must survive
	 * the readonly property callback. Otherwise a readonly
	 * property or an unwriteable spa forces the mount ro.
	 */
	{
		boolean_t explicit = B_FALSE;
		boolean_t explicit_val = B_FALSE;

		if (zfsvfs->z_vfs != NULL && zfsvfs->z_vfs->vfs_do_readonly) {
			explicit = B_TRUE;
			explicit_val = zfsvfs->z_vfs->vfs_readonly;
		} else if (zfsvfs->z_vfs != NULL &&
		    (readonly ||
		    !spa_writeable(dmu_objset_spa(zfsvfs->z_os)))) {
			zfsvfs->z_vfs->vfs_do_readonly = B_TRUE;
			zfsvfs->z_vfs->vfs_readonly = B_TRUE;
			explicit = B_TRUE;
			explicit_val = B_TRUE;
		}
		if (zfsvfs->z_vfs != NULL &&
		    !spa_writeable(dmu_objset_spa(zfsvfs->z_os))) {
			zfsvfs->z_vfs->vfs_do_readonly = B_TRUE;
			zfsvfs->z_vfs->vfs_readonly = B_TRUE;
			explicit = B_TRUE;
			explicit_val = B_TRUE;
		}

		if (!zfsvfs->z_issnap) {
			ds = dmu_objset_ds(zfsvfs->z_os);
			dsl_pool_config_enter(dmu_objset_pool(zfsvfs->z_os),
			    FTAG);
			error = dsl_prop_register(ds,
			    zfs_prop_to_name(ZFS_PROP_XATTR), xattr_changed_cb,
			    zfsvfs);
			if (error == 0)
				error = dsl_prop_register(ds,
				    zfs_prop_to_name(ZFS_PROP_ACLTYPE),
				    acltype_changed_cb, zfsvfs);
			if (error == 0)
				error = dsl_prop_register(ds,
				    zfs_prop_to_name(ZFS_PROP_SNAPDIR),
				    snapdir_changed_cb, zfsvfs);
			if (error == 0)
				error = dsl_prop_register(ds,
				    zfs_prop_to_name(ZFS_PROP_READONLY),
				    readonly_changed_cb, zfsvfs);
			if (error == 0)
				error = dsl_prop_register(ds,
				    zfs_prop_to_name(ZFS_PROP_RECORDSIZE),
				    blksz_changed_cb, zfsvfs);
			if (error == 0)
				error = dsl_prop_register(ds,
				    zfs_prop_to_name(ZFS_PROP_ATIME),
				    atime_changed_cb, zfsvfs);
			if (error == 0)
				error = dsl_prop_register(ds,
				    zfs_prop_to_name(ZFS_PROP_RELATIME),
				    relatime_changed_cb, zfsvfs);

			dsl_pool_config_exit(dmu_objset_pool(zfsvfs->z_os),
			    FTAG);
			if (error != 0) {
				dsl_prop_unregister_all(ds, zfsvfs);
				return (error);
			}
		}
		if (explicit && zfsvfs->z_vfs != NULL)
			zfsvfs->z_vfs->vfs_readonly = explicit_val;
	}

	if (!readonly) {
		zfs_unlinked_drain(zfsvfs);
		if (spa_writeable(dmu_objset_spa(zfsvfs->z_os))) {
			if (zil_replay_disable) {
				zil_destroy(zfsvfs->z_log, B_FALSE);
			} else {
				zfsvfs->z_replay = B_TRUE;
				zil_replay(zfsvfs->z_os, zfsvfs,
				    zfs_replay_vector);
				zfsvfs->z_replay = B_FALSE;
			}
		}
	}

	mutex_enter(&zfsvfs->z_os->os_user_ptr_lock);
	dmu_objset_set_user(zfsvfs->z_os, zfsvfs);
	mutex_exit(&zfsvfs->z_os->os_user_ptr_lock);
	return (0);
}


void
zfsvfs_free(zfsvfs_t *zfsvfs)
{
	int i, size;

	if (zfsvfs == NULL)
		return;
	size = zfsvfs->z_hold_size;
	zfs_fuid_destroy(zfsvfs);
	mutex_destroy(&zfsvfs->z_znodes_lock);
	mutex_destroy(&zfsvfs->z_lock);
	list_destroy(&zfsvfs->z_all_znodes);
	ZFS_TEARDOWN_DESTROY(zfsvfs);
	rw_destroy(&zfsvfs->z_teardown_inactive_lock);
	rw_destroy(&zfsvfs->z_fuid_lock);
	for (i = 0; i != size; i++) {
		avl_destroy(&zfsvfs->z_hold_trees[i]);
		mutex_destroy(&zfsvfs->z_hold_locks[i]);
	}
	vmem_free(zfsvfs->z_hold_trees, sizeof (avl_tree_t) * size);
	vmem_free(zfsvfs->z_hold_locks, sizeof (kmutex_t) * size);
	zfsvfs_vfs_free(zfsvfs->z_vfs);
	if (zfsvfs->z_kstat.dk_kstats != NULL)
		dataset_kstats_destroy(&zfsvfs->z_kstat);
	else
		zil_sums_fini(&zfsvfs->z_kstat.dk_zil_sums);
	kmem_free(zfsvfs, sizeof (zfsvfs_t));
}

void
zfsvfs_teardown(zfsvfs_t *zfsvfs, boolean_t unmounting)
{
	znode_t *zp;

	if (zfsvfs == NULL)
		return;
	zfs_unlinked_drain_stop_wait(zfsvfs);
	ZFS_TEARDOWN_ENTER_WRITE(zfsvfs, FTAG);
	zfsvfs->z_unmounted = B_TRUE;
	if (zfsvfs->z_log != NULL) {
		zil_close(zfsvfs->z_log);
		zfsvfs->z_log = NULL;
	}
	/*
	 * After FUSE has joined, leftover z_ref > 1 is a missed
	 * forget/release. Force-drop those holds so spa_export can
	 * see a zero refcount. Do not brute-force znodes belonging
	 * to a snapshot objset whose parent FUSE session is still
	 * live (zpl_snapos).
	 */
	if (!zfsvfs->z_issnap) {
		mutex_enter(&zfsvfs->z_znodes_lock);
		while ((zp = list_head(&zfsvfs->z_all_znodes)) != NULL) {
			int r;

			mutex_enter(&zp->z_lock);
			r = (int)zp->z_ref;
			mutex_exit(&zp->z_lock);
			mutex_exit(&zfsvfs->z_znodes_lock);
			if (r < 1) {
				mutex_enter(&zfsvfs->z_znodes_lock);
				if (list_link_active(&zp->z_link_node))
					list_remove(&zfsvfs->z_all_znodes, zp);
				continue;
			}
			if (r > 1) {
				(void) fprintf(stderr,
				    "zfsd: teardown: znode %llu had %d refs\n",
				    (u_longlong_t)zp->z_id, r);
			}
			while (r-- > 0)
				zrele(zp);
			mutex_enter(&zfsvfs->z_znodes_lock);
		}
		mutex_exit(&zfsvfs->z_znodes_lock);
	}

	if (zfsvfs->z_os != NULL) {
		if (!zfsvfs->z_issnap && dmu_objset_ds(zfsvfs->z_os) != NULL)
			dsl_prop_unregister_all(dmu_objset_ds(zfsvfs->z_os),
			    zfsvfs);
		mutex_enter(&zfsvfs->z_os->os_user_ptr_lock);
		dmu_objset_set_user(zfsvfs->z_os, NULL);
		mutex_exit(&zfsvfs->z_os->os_user_ptr_lock);
		if (zfsvfs->z_use_hold)
			dmu_objset_rele(zfsvfs->z_os, zfsvfs);
		else
			dmu_objset_disown(zfsvfs->z_os, B_TRUE, zfsvfs);
		zfsvfs->z_os = NULL;
	}
	ZFS_TEARDOWN_EXIT_WRITE(zfsvfs);
	(void) unmounting;
	zfsvfs_free(zfsvfs);
}

boolean_t
zfs_vfs_held(zfsvfs_t *zfsvfs)
{
	return (zfsvfs != NULL && zfsvfs->z_sb != NULL);
}

int
zfs_vfs_ref(zfsvfs_t **zfvp)
{
	if (*zfvp == NULL || (*zfvp)->z_sb == NULL)
		return (SET_ERROR(ESRCH));
	return (0);
}

void
zfs_vfs_rele(zfsvfs_t *zfsvfs)
{
	(void) zfsvfs;
}

int
zfs_suspend_fs(zfsvfs_t *zfsvfs)
{
	znode_t *zp;
	objset_t *os;

	if (zfsvfs == NULL)
		return (SET_ERROR(EINVAL));
	/*
	 * Stop unlinked drain before taking teardown write. The drain
	 * task zget/zrele's znodes; running it across sa_handle_destroy
	 * in the loop below is a UAF. Kernel zfsvfs_teardown does the
	 * same stop before the writer lock.
	 */
	zfs_unlinked_drain_stop_wait(zfsvfs);
	ZFS_TEARDOWN_ENTER_WRITE(zfsvfs, FTAG);
	rw_enter(&zfsvfs->z_teardown_inactive_lock, RW_WRITER);
	if (zfsvfs->z_log != NULL) {
		zil_close(zfsvfs->z_log);
		zfsvfs->z_log = NULL;
	}

	/*
	 * Drop SA handles before rollback/recv can evict the objset.
	 * A later FUSE RELEASE must not sa_handle_destroy against a
	 * torn-down os_sa (posix_005 holds a file open across rollback).
	 * Extra z_ref keeps the znode alive until zfs_resume_fs.
	 */
	mutex_enter(&zfsvfs->z_znodes_lock);
	for (zp = list_head(&zfsvfs->z_all_znodes); zp != NULL;
	    zp = list_next(&zfsvfs->z_all_znodes, zp)) {
		boolean_t pin = B_FALSE;

		mutex_enter(&zp->z_lock);
		if (zp->z_ref > 0 && !zp->z_suspended) {
			zp->z_ref++;
			zp->z_suspended = B_TRUE;
			pin = B_TRUE;
		}
		mutex_exit(&zp->z_lock);
		if (pin && zp->z_sa_hdl != NULL)
			zfs_znode_dmu_fini(zp);
	}
	mutex_exit(&zfsvfs->z_znodes_lock);

	os = zfsvfs->z_os;
	if (os != NULL) {
		boolean_t os_dirty = B_FALSE;
		int t;

		for (t = 0; t < TXG_SIZE; t++) {
			if (dmu_objset_is_dirty(os, t)) {
				os_dirty = B_TRUE;
				break;
			}
		}
		if (!zfs_is_readonly(zfsvfs) && os_dirty)
			txg_wait_synced(dmu_objset_pool(os), 0);
		dmu_objset_evict_dbufs(os);
	}
	return (0);
}

int
zfs_resume_fs(zfsvfs_t *zfsvfs, dsl_dataset_t *ds)
{
	objset_t *os;
	znode_t *zp;
	int err;

	ASSERT(ZFS_TEARDOWN_WRITE_HELD(zfsvfs));
	VERIFY3P(ds->ds_owner, ==, zfsvfs);
	VERIFY(dsl_dataset_long_held(ds));
	{
		dsl_pool_t *dp = spa_get_dsl(dsl_dataset_get_spa(ds));
		dsl_pool_config_enter(dp, FTAG);
		VERIFY0(dmu_objset_from_ds(ds, &os));
		dsl_pool_config_exit(dp, FTAG);
	}
	err = zfsvfs_init(zfsvfs, os);
	if (err == 0)
		err = zfsvfs_setup(zfsvfs, B_FALSE);
	if (err == 0) {
		zfsvfs->z_rollback_time = gethrtime();
		mutex_enter(&zfsvfs->z_znodes_lock);
		zp = list_head(&zfsvfs->z_all_znodes);
		while (zp != NULL) {
			znode_t *next;

			next = list_next(&zfsvfs->z_all_znodes, zp);
			mutex_exit(&zfsvfs->z_znodes_lock);
			(void) zfs_rezget(zp);
			if (zp->z_suspended) {
				zp->z_suspended = B_FALSE;
				zrele(zp);
			}
			mutex_enter(&zfsvfs->z_znodes_lock);
			zp = next;
		}
		mutex_exit(&zfsvfs->z_znodes_lock);
		if (!zfs_is_readonly(zfsvfs) && !zfsvfs->z_unmounted)
			zfs_unlinked_drain(zfsvfs);
	}
	rw_exit(&zfsvfs->z_teardown_inactive_lock);
	ZFS_TEARDOWN_EXIT_WRITE(zfsvfs);
	if (err == 0) {
		extern void zfsd_zpl_inval_fs(zfsvfs_t *);
		zfsd_zpl_inval_fs(zfsvfs);
	} else {
		char name[ZFS_MAX_DATASET_NAME_LEN];

		zfsvfs->z_unmounted = B_TRUE;
		dmu_objset_name(os, name);
		{
			extern int zfsd_zpl_unmount(const char *, const char *,
			    uint64_t);
			(void) zfsd_zpl_unmount(name, NULL, 1);
		}
	}
	return (err);
}

static void
zfsd_set_fuid_feature(zfsvfs_t *zfsvfs)
{
	zfsvfs->z_use_fuids = USE_FUIDS(zfsvfs->z_version, zfsvfs->z_os);
	zfsvfs->z_use_sa = USE_SA(zfsvfs->z_version, zfsvfs->z_os);
}

int
zfs_end_fs(zfsvfs_t *zfsvfs, dsl_dataset_t *ds)
{
	char name[ZFS_MAX_DATASET_NAME_LEN];
	objset_t *os;

	ASSERT(ZFS_TEARDOWN_WRITE_HELD(zfsvfs));
	VERIFY3P(ds->ds_owner, ==, zfsvfs);
	VERIFY(dsl_dataset_long_held(ds));
	{
		dsl_pool_t *dp = spa_get_dsl(dsl_dataset_get_spa(ds));
		dsl_pool_config_enter(dp, FTAG);
		VERIFY0(dmu_objset_from_ds(ds, &os));
		dsl_pool_config_exit(dp, FTAG);
	}
	zfsvfs->z_os = os;
	dmu_objset_name(os, name);
	rw_exit(&zfsvfs->z_teardown_inactive_lock);
	ZFS_TEARDOWN_EXIT(zfsvfs, FTAG);
	{
		extern int zfsd_zpl_unmount(const char *, const char *,
		    uint64_t);
		(void) zfsd_zpl_unmount(name, NULL, 1);
	}
	/*
	 * zfsd_zpl_unmount -> zfsvfs_teardown -> zfsvfs_free.
	 * Do not touch zfsvfs after this.
	 */
	return (0);
}

int
zfs_set_version(zfsvfs_t *zfsvfs, uint64_t newvers)
{
	int error;
	objset_t *os = zfsvfs->z_os;
	dmu_tx_t *tx;

	if (newvers < ZPL_VERSION_INITIAL || newvers > ZPL_VERSION)
		return (SET_ERROR(EINVAL));
	if (newvers < zfsvfs->z_version)
		return (SET_ERROR(EINVAL));
	if (zfs_spa_version_map(newvers) >
	    spa_version(dmu_objset_spa(zfsvfs->z_os)))
		return (SET_ERROR(ENOTSUP));

	tx = dmu_tx_create(os);
	dmu_tx_hold_zap(tx, MASTER_NODE_OBJ, B_FALSE, ZPL_VERSION_STR);
	if (newvers >= ZPL_VERSION_SA && !zfsvfs->z_use_sa) {
		dmu_tx_hold_zap(tx, MASTER_NODE_OBJ, B_TRUE, ZFS_SA_ATTRS);
		dmu_tx_hold_zap(tx, DMU_NEW_OBJECT, B_FALSE, NULL);
	}
	error = dmu_tx_assign(tx, DMU_TX_WAIT);
	if (error) {
		dmu_tx_abort(tx);
		return (error);
	}

	error = zap_update(os, MASTER_NODE_OBJ, ZPL_VERSION_STR,
	    8, 1, &newvers, tx);
	if (error) {
		dmu_tx_commit(tx);
		return (error);
	}

	if (newvers >= ZPL_VERSION_SA && !zfsvfs->z_use_sa) {
		uint64_t sa_obj;

		sa_obj = zap_create(os, DMU_OT_SA_MASTER_NODE,
		    DMU_OT_NONE, 0, tx);
		error = zap_add(os, MASTER_NODE_OBJ,
		    ZFS_SA_ATTRS, 8, 1, &sa_obj, tx);
		ASSERT0(error);
		VERIFY0(sa_set_sa_object(os, sa_obj));
		sa_register_update_callback(os, zfs_sa_upgrade);
	}

	spa_history_log_internal_ds(dmu_objset_ds(os), "upgrade", tx,
	    "from %llu to %llu",
	    (u_longlong_t)zfsvfs->z_version, (u_longlong_t)newvers);
	dmu_tx_commit(tx);

	zfsvfs->z_version = newvers;
	os->os_version = newvers;
	zfsd_set_fuid_feature(zfsvfs);
	return (0);
}

int
zfs_set_default_quota(zfsvfs_t *zfsvfs, zfs_prop_t prop, uint64_t quota)
{
	int error;
	objset_t *os = zfsvfs->z_os;
	const char *propstr = zfs_prop_to_name(prop);
	dmu_tx_t *tx;

	tx = dmu_tx_create(os);
	dmu_tx_hold_zap(tx, MASTER_NODE_OBJ, B_FALSE, propstr);
	error = dmu_tx_assign(tx, DMU_TX_WAIT);
	if (error) {
		dmu_tx_abort(tx);
		return (error);
	}

	if (quota == 0) {
		error = zap_remove(os, MASTER_NODE_OBJ, propstr, tx);
		if (error == ENOENT)
			error = 0;
	} else {
		error = zap_update(os, MASTER_NODE_OBJ, propstr, 8, 1,
		    &quota, tx);
	}
	if (error == 0) {
		switch (prop) {
		case ZFS_PROP_DEFAULTUSERQUOTA:
			zfsvfs->z_defaultuserquota = quota;
			break;
		case ZFS_PROP_DEFAULTGROUPQUOTA:
			zfsvfs->z_defaultgroupquota = quota;
			break;
		case ZFS_PROP_DEFAULTPROJECTQUOTA:
			zfsvfs->z_defaultprojectquota = quota;
			break;
		case ZFS_PROP_DEFAULTUSEROBJQUOTA:
			zfsvfs->z_defaultuserobjquota = quota;
			break;
		case ZFS_PROP_DEFAULTGROUPOBJQUOTA:
			zfsvfs->z_defaultgroupobjquota = quota;
			break;
		case ZFS_PROP_DEFAULTPROJECTOBJQUOTA:
			zfsvfs->z_defaultprojectobjquota = quota;
			break;
		default:
			break;
		}
	}
	dmu_tx_commit(tx);
	return (error);
}
