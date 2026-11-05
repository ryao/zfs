// SPDX-License-Identifier: CDDL-1.0
/*
 * zfsd OS znode ops -- same names as module/os/linux/zfs/zfs_znode_os.c
 * except zfs_create_fs, which libzpool implements as a zfsd_active
 * check (ztest/zdb no-op) and dispatches here.
 */

#include <sys/zfs_context.h>
#include <sys/zfs_vfsops.h>
#include <sys/zfs_znode.h>
#include <sys/zfs_dir.h>
#include <sys/zfs_vnops.h>
#include <sys/zfs_acl.h>
#include <sys/zfs_acl_impl.h>
#include <sys/zfs_sa.h>
#include <sys/zfs_fuid.h>
#include <sys/dmu.h>
#include <sys/dmu_objset.h>
#include <sys/sa.h>
#include <sys/zap.h>
#include <sys/zil.h>
#include <sys/zfs_rlock.h>
#include <sys/cmn_err.h>
#include <sys/xvattr.h>
#include <sys/vnode.h>
#include <sys/dmu_tx.h>
#include <zfs_comutil.h>
#include <string.h>

unsigned int zfs_object_mutex_size = ZFS_OBJ_MTX_SZ;
int zfs_unlink_suspend_progress = 0;

static kmem_cache_t *znode_cache = NULL;
static kmem_cache_t *znode_hold_cache = NULL;

static uint64_t empty_xattr;
static uint64_t pad[4];
static zfs_acl_phys_t acl_phys;

/*
 * Convert RL_APPEND to RL_WRITER at EOF and widen the lock if the
 * write might grow the block size. Called with rl_lock held.
 */
static void
zfs_rangelock_cb(zfs_locked_range_t *new, void *arg)
{
	znode_t *zp = arg;
	uint64_t end_size;

	if (new->lr_type == RL_APPEND) {
		new->lr_offset = zp->z_size;
		new->lr_type = RL_WRITER;
	}
	end_size = MAX(zp->z_size, new->lr_offset + new->lr_length);
	/*
	 * z_blksz == 0 means the first write has not chosen a block size yet
	 * (zfs_mknode passes 0). A FUSE SETATTR may already have set z_size to
	 * the logical EOF, which would otherwise skip this widen and leave
	 * every later write logging with a zero block size.
	 */
	if (zp->z_blksz == 0 ||
	    (zp->z_size <= zp->z_blksz && end_size > zp->z_blksz &&
	    (!ISP2(zp->z_blksz) || zp->z_blksz < ZTOZSB(zp)->z_max_blksz))) {
		new->lr_offset = 0;
		new->lr_length = UINT64_MAX;
	}
}

static int
zfs_znode_cache_constructor(void *buf, void *arg, int kmflags)
{
	znode_t *zp = buf;

	(void) arg;
	(void) kmflags;
	memset(zp, 0, sizeof (znode_t));
	mutex_init(&zp->z_lock, NULL, MUTEX_DEFAULT, NULL);
	rw_init(&zp->z_parent_lock, NULL, RW_DEFAULT, NULL);
	rw_init(&zp->z_name_lock, NULL, RW_DEFAULT, NULL);
	mutex_init(&zp->z_acl_lock, NULL, MUTEX_DEFAULT, NULL);
	rw_init(&zp->z_xattr_lock, NULL, RW_DEFAULT, NULL);
	zfs_rangelock_init(&zp->z_rangelock, zfs_rangelock_cb, zp);
	return (0);
}

static void
zfs_znode_cache_destructor(void *buf, void *arg)
{
	znode_t *zp = buf;

	(void) arg;
	zfs_rangelock_fini(&zp->z_rangelock);
	mutex_destroy(&zp->z_lock);
	rw_destroy(&zp->z_parent_lock);
	rw_destroy(&zp->z_name_lock);
	mutex_destroy(&zp->z_acl_lock);
	rw_destroy(&zp->z_xattr_lock);
}

static int
zfs_znode_hold_cache_constructor(void *buf, void *arg, int kmflags)
{
	znode_hold_t *zh = buf;

	(void) arg;
	(void) kmflags;
	mutex_init(&zh->zh_lock, NULL, MUTEX_DEFAULT, NULL);
	zh->zh_refcount = 0;
	return (0);
}

static void
zfs_znode_hold_cache_destructor(void *buf, void *arg)
{
	znode_hold_t *zh = buf;

	(void) arg;
	mutex_destroy(&zh->zh_lock);
}

void
zfs_znode_init(void)
{
	if (znode_cache == NULL) {
		znode_cache = kmem_cache_create("zfsd_znode_cache",
		    sizeof (znode_t), 0, zfs_znode_cache_constructor,
		    zfs_znode_cache_destructor, NULL, NULL, NULL, 0);
	}
	if (znode_hold_cache == NULL) {
		znode_hold_cache = kmem_cache_create("zfsd_znode_hold_cache",
		    sizeof (znode_hold_t), 0, zfs_znode_hold_cache_constructor,
		    zfs_znode_hold_cache_destructor, NULL, NULL, NULL, 0);
	}
}

void
zfs_znode_fini(void)
{
	if (znode_cache) {
		kmem_cache_destroy(znode_cache);
		znode_cache = NULL;
	}
	if (znode_hold_cache) {
		kmem_cache_destroy(znode_hold_cache);
		znode_hold_cache = NULL;
	}
}

int
zfs_znode_hold_compare(const void *a, const void *b)
{
	const znode_hold_t *zh_a = a;
	const znode_hold_t *zh_b = b;

	return (TREE_CMP(zh_a->zh_obj, zh_b->zh_obj));
}

znode_hold_t *
zfs_znode_hold_enter(zfsvfs_t *zfsvfs, uint64_t obj)
{
	znode_hold_t *zh, *zh_new, search;
	int i = ZFS_OBJ_HASH(zfsvfs, obj);
	boolean_t found = B_FALSE;

	if (znode_hold_cache == NULL)
		zfs_znode_init();
	zh_new = kmem_cache_alloc(znode_hold_cache, KM_SLEEP);
	search.zh_obj = obj;

	mutex_enter(&zfsvfs->z_hold_locks[i]);
	zh = avl_find(&zfsvfs->z_hold_trees[i], &search, NULL);
	if (zh == NULL) {
		zh = zh_new;
		zh->zh_obj = obj;
		avl_add(&zfsvfs->z_hold_trees[i], zh);
	} else {
		found = B_TRUE;
	}
	zh->zh_refcount++;
	mutex_exit(&zfsvfs->z_hold_locks[i]);

	if (found)
		kmem_cache_free(znode_hold_cache, zh_new);

	ASSERT(MUTEX_NOT_HELD(&zh->zh_lock));
	mutex_enter(&zh->zh_lock);
	return (zh);
}

void
zfs_znode_hold_exit(zfsvfs_t *zfsvfs, znode_hold_t *zh)
{
	int i = ZFS_OBJ_HASH(zfsvfs, zh->zh_obj);
	boolean_t remove = B_FALSE;

	mutex_exit(&zh->zh_lock);
	mutex_enter(&zfsvfs->z_hold_locks[i]);
	if (--zh->zh_refcount == 0) {
		avl_remove(&zfsvfs->z_hold_trees[i], zh);
		remove = B_TRUE;
	}
	mutex_exit(&zfsvfs->z_hold_locks[i]);
	if (remove)
		kmem_cache_free(znode_hold_cache, zh);
}

dev_t
zfs_cmpldev(uint64_t dev)
{
	return (dev);
}

void
zhold(znode_t *zp)
{
	mutex_enter(&zp->z_lock);
	zp->z_ref++;
	mutex_exit(&zp->z_lock);
}

/*
 * Last-ref teardown. Caller holds zh and this function always releases
 * it. On the unlinked path the hold is dropped before zfs_rmnode(),
 * which takes the same per-object lock (a non-recursive mutex).
 */
static void
zfs_zinactive_held(znode_t *zp, znode_hold_t *zh)
{
	zfsvfs_t *zfsvfs = ZTOZSB(zp);

	if (zp->z_sa_hdl == NULL) {
		zfs_znode_hold_exit(zfsvfs, zh);
		return;
	}
	mutex_enter(&zp->z_lock);
	if (zp->z_unlinked && !zfs_is_readonly(zfsvfs) &&
	    !zfs_unlink_suspend_progress) {
		mutex_exit(&zp->z_lock);
		zfs_znode_hold_exit(zfsvfs, zh);
		zfs_rmnode(zp);
		return;
	}
	mutex_exit(&zp->z_lock);
	if (zp->z_atime_dirty && zp->z_unlinked == B_FALSE &&
	    zp->z_sa_hdl != NULL && !zfs_is_readonly(zfsvfs)) {
		dmu_tx_t *tx = dmu_tx_create(zfsvfs->z_os);
		uint64_t atime[2];
		int error;

		ZFS_TIME_ENCODE(&zp->z_atime, atime);
		dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
		error = dmu_tx_assign(tx, DMU_TX_WAIT);
		if (error != 0) {
			dmu_tx_abort(tx);
		} else {
			mutex_enter(&zp->z_lock);
			(void) sa_update(zp->z_sa_hdl, SA_ZPL_ATIME(zfsvfs),
			    atime, sizeof (atime), tx);
			zp->z_atime_dirty = B_FALSE;
			mutex_exit(&zp->z_lock);
			dmu_tx_commit(tx);
		}
	}
	zfs_znode_dmu_fini(zp);
	zfs_znode_hold_exit(zfsvfs, zh);
}

void
zrele(znode_t *zp)
{
	zfsvfs_t *zfsvfs;
	uint64_t obj;
	znode_hold_t *zh;
	uint_t ref;
	int need_unlock = 0;

	if (zp == NULL)
		return;
	mutex_enter(&zp->z_lock);
	ASSERT3U(zp->z_ref, >, 0);
	if (zp->z_ref > 1) {
		zp->z_ref--;
		mutex_exit(&zp->z_lock);
		return;
	}
	obj = zp->z_id;
	zfsvfs = ZTOZSB(zp);
	mutex_exit(&zp->z_lock);

	/*
	 * Serialize the last-ref transition with zfs_zget() via the
	 * object hold so a concurrent lookup cannot resurrect zp after
	 * z_ref hits 0. zh->zh_lock is a non-recursive mutex: the
	 * inactive path must use the held form, not zfs_zinactive().
	 */
	zh = zfs_znode_hold_enter(zfsvfs, obj);
	mutex_enter(&zp->z_lock);
	ASSERT3U(zp->z_ref, >, 0);
	ref = --zp->z_ref;
	if (ref != 0) {
		mutex_exit(&zp->z_lock);
		zfs_znode_hold_exit(zfsvfs, zh);
		return;
	}
	mutex_exit(&zp->z_lock);

	mutex_enter(&zfsvfs->z_znodes_lock);
	if (list_link_active(&zp->z_link_node))
		list_remove(&zfsvfs->z_all_znodes, zp);
	mutex_exit(&zfsvfs->z_znodes_lock);

	if (!RW_WRITE_HELD(&zfsvfs->z_teardown_inactive_lock)) {
		rw_enter(&zfsvfs->z_teardown_inactive_lock, RW_READER);
		need_unlock = 1;
	}
	zfs_zinactive_held(zp, zh);
	if (need_unlock)
		rw_exit(&zfsvfs->z_teardown_inactive_lock);

	if (zp->z_acl_cached) {
		zfs_acl_free(zp->z_acl_cached);
		zp->z_acl_cached = NULL;
	}
	if (zp->z_xattr_cached) {
		nvlist_free(zp->z_xattr_cached);
		zp->z_xattr_cached = NULL;
	}
	kmem_cache_free(znode_cache, zp);
}


void
zfs_zrele_async(znode_t *zp)
{
	zrele(zp);
}

void
zfs_znode_update_vfs(znode_t *zp)
{
	(void) zp;
}

static void
zfs_znode_sa_init(zfsvfs_t *zfsvfs, znode_t *zp, dmu_buf_t *db,
    dmu_object_type_t obj_type, sa_handle_t *sa_hdl)
{
	mutex_enter(&zp->z_lock);
	if (sa_hdl == NULL) {
		VERIFY0(sa_handle_get_from_db(zfsvfs->z_os, db, zp,
		    SA_HDL_SHARED, &zp->z_sa_hdl));
	} else {
		zp->z_sa_hdl = sa_hdl;
		sa_set_userp(sa_hdl, zp);
	}
	zp->z_is_sa = (obj_type == DMU_OT_SA) ? B_TRUE : B_FALSE;
	mutex_exit(&zp->z_lock);
}

void
zfs_znode_dmu_fini(znode_t *zp)
{
	if (zp->z_sa_hdl != NULL) {
		sa_handle_destroy(zp->z_sa_hdl);
		zp->z_sa_hdl = NULL;
	}
}

static znode_t *
zfs_znode_alloc(zfsvfs_t *zfsvfs, dmu_buf_t *db, int blksz,
    dmu_object_type_t obj_type, sa_handle_t *hdl)
{
	znode_t *zp;
	uint64_t mode, parent, tmp_gen, links;
	uint64_t z_uid, z_gid;
	uint64_t atime[2], mtime[2], ctime[2], btime[2];
	uint64_t projid = ZFS_DEFAULT_PROJID;
	sa_bulk_attr_t bulk[12];
	int count = 0;

	if (znode_cache == NULL)
		zfs_znode_init();
	zp = kmem_cache_alloc(znode_cache, KM_SLEEP);
	zp->z_unlinked = B_FALSE;
	zp->z_atime_dirty = B_FALSE;
	zp->z_is_ctldir = B_FALSE;
	zp->z_suspended = B_FALSE;
	zp->z_xattr_dir_absent = B_FALSE;
	zp->z_sa_hdl = NULL;
	zp->z_mapcnt = 0;
	zp->z_id = db->db_object;
	zp->z_blksz = blksz;
	zp->z_sync_cnt = 0;
	zp->z_dirlocks = NULL;
	zp->z_acl_cached = NULL;
	zp->z_xattr_cached = NULL;
	zp->z_zfsvfs = zfsvfs;
	zp->z_ref = 1;

	zfs_znode_sa_init(zfsvfs, zp, db, obj_type, hdl);

	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_MODE(zfsvfs), NULL, &mode, 8);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_GEN(zfsvfs), NULL, &tmp_gen, 8);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_SIZE(zfsvfs), NULL,
	    &zp->z_size, 8);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_LINKS(zfsvfs), NULL, &links, 8);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_FLAGS(zfsvfs), NULL,
	    &zp->z_pflags, 8);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_PARENT(zfsvfs), NULL,
	    &parent, 8);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_UID(zfsvfs), NULL, &z_uid, 8);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_GID(zfsvfs), NULL, &z_gid, 8);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_ATIME(zfsvfs), NULL, &atime, 16);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_MTIME(zfsvfs), NULL, &mtime, 16);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_CTIME(zfsvfs), NULL, &ctime, 16);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_CRTIME(zfsvfs), NULL, &btime, 16);

	if (sa_bulk_lookup(zp->z_sa_hdl, bulk, count) != 0 || tmp_gen == 0) {
		if (hdl == NULL)
			sa_handle_destroy(zp->z_sa_hdl);
		zp->z_sa_hdl = NULL;
		kmem_cache_free(znode_cache, zp);
		return (NULL);
	}
	if (dmu_objset_projectquota_enabled(zfsvfs->z_os) &&
	    (zp->z_pflags & ZFS_PROJID))
		(void) sa_lookup(zp->z_sa_hdl, SA_ZPL_PROJID(zfsvfs),
		    &projid, 8);

	if (zp->z_is_sa && sa_lookup(zp->z_sa_hdl, SA_ZPL_SEQ(zfsvfs),
	    &zp->z_seq, sizeof (zp->z_seq)) == 0) {
		zp->z_has_seq = B_TRUE;
	} else {
		zp->z_has_seq = B_FALSE;
		zp->z_seq = (ctime[0] + 1) << 32;
	}

	zp->z_projid = projid;
	zp->z_mode = mode;
	zp->z_links = links;
	zp->z_uid = z_uid;
	zp->z_gid = z_gid;
	zp->z_gen = (uint32_t)tmp_gen;
	ZFS_TIME_DECODE(&zp->z_atime, atime);
	ZFS_TIME_DECODE(&zp->z_mtime, mtime);
	ZFS_TIME_DECODE(&zp->z_ctime, ctime);
	ZFS_TIME_DECODE(&zp->z_btime, btime);
	if (zp->z_pflags & ZFS_XATTR)
		zp->z_xattr_parent = parent;
	if (links == 0)
		zp->z_unlinked = B_TRUE;

	mutex_enter(&zfsvfs->z_znodes_lock);
	list_insert_tail(&zfsvfs->z_all_znodes, zp);
	mutex_exit(&zfsvfs->z_znodes_lock);
	return (zp);
}

int
zfs_zget(zfsvfs_t *zfsvfs, uint64_t obj_num, znode_t **zpp)
{
	dmu_object_info_t doi;
	dmu_buf_t *db;
	znode_t *zp;
	znode_hold_t *zh;
	int err;
	sa_handle_t *hdl;

	*zpp = NULL;
	zh = zfs_znode_hold_enter(zfsvfs, obj_num);
	err = sa_buf_hold(zfsvfs->z_os, obj_num, NULL, &db);
	if (err) {
		zfs_znode_hold_exit(zfsvfs, zh);
		return (err);
	}
	dmu_object_info_from_db(db, &doi);
	if (doi.doi_bonus_type != DMU_OT_SA &&
	    (doi.doi_bonus_type != DMU_OT_ZNODE ||
	    doi.doi_bonus_size < sizeof (znode_phys_t))) {
		sa_buf_rele(db, NULL);
		zfs_znode_hold_exit(zfsvfs, zh);
		return (SET_ERROR(EINVAL));
	}
	hdl = dmu_buf_get_user(db);
	if (hdl != NULL) {
		zp = sa_get_userdata(hdl);
		mutex_enter(&zp->z_lock);
		if (zp->z_ref == 0 || (zp->z_unlinked && zp->z_links == 0)) {
			mutex_exit(&zp->z_lock);
			sa_buf_rele(db, NULL);
			zfs_znode_hold_exit(zfsvfs, zh);
			return (SET_ERROR(ENOENT));
		}

		zp->z_ref++;
		mutex_exit(&zp->z_lock);
		*zpp = zp;
		sa_buf_rele(db, NULL);
		zfs_znode_hold_exit(zfsvfs, zh);
		return (0);
	}
	zp = zfs_znode_alloc(zfsvfs, db, doi.doi_data_block_size,
	    doi.doi_bonus_type, NULL);
	if (zp == NULL) {
		err = SET_ERROR(ENOENT);
	} else {
		*zpp = zp;
		err = 0;
	}
	zfs_znode_hold_exit(zfsvfs, zh);
	return (err);
}

int
zfs_rezget(znode_t *zp)
{
	zfsvfs_t *zfsvfs = ZTOZSB(zp);
	dmu_object_info_t doi;
	dmu_buf_t *db;
	uint64_t obj_num = zp->z_id;
	uint64_t mode, links, gen;
	uint64_t z_uid, z_gid;
	uint64_t atime[2], mtime[2], ctime[2], btime[2];
	uint64_t projid = ZFS_DEFAULT_PROJID;
	sa_bulk_attr_t bulk[12];
	int err;
	int count = 0;
	znode_hold_t *zh;

	if (zp->z_is_ctldir)
		return (0);

	zh = zfs_znode_hold_enter(zfsvfs, obj_num);

	mutex_enter(&zp->z_acl_lock);
	if (zp->z_acl_cached) {
		zfs_acl_free(zp->z_acl_cached);
		zp->z_acl_cached = NULL;
	}
	mutex_exit(&zp->z_acl_lock);

	rw_enter(&zp->z_xattr_lock, RW_WRITER);
	if (zp->z_xattr_cached) {
		nvlist_free(zp->z_xattr_cached);
		zp->z_xattr_cached = NULL;
	}
	zp->z_xattr_dir_absent = B_FALSE;
	rw_exit(&zp->z_xattr_lock);

	if (zp->z_sa_hdl != NULL)
		zfs_znode_dmu_fini(zp);

	if (zfsvfs->z_os == NULL) {
		zfs_znode_hold_exit(zfsvfs, zh);
		return (SET_ERROR(EIO));
	}

	err = sa_buf_hold(zfsvfs->z_os, obj_num, NULL, &db);
	if (err != 0) {
		zfs_znode_hold_exit(zfsvfs, zh);
		return (err);
	}

	dmu_object_info_from_db(db, &doi);
	if (doi.doi_bonus_type != DMU_OT_SA &&
	    (doi.doi_bonus_type != DMU_OT_ZNODE ||
	    doi.doi_bonus_size < sizeof (znode_phys_t))) {
		sa_buf_rele(db, NULL);
		zfs_znode_hold_exit(zfsvfs, zh);
		return (SET_ERROR(EINVAL));
	}

	zfs_znode_sa_init(zfsvfs, zp, db, doi.doi_bonus_type, NULL);

	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_GEN(zfsvfs), NULL, &gen, 8);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_SIZE(zfsvfs), NULL,
	    &zp->z_size, 8);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_LINKS(zfsvfs), NULL, &links, 8);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_FLAGS(zfsvfs), NULL,
	    &zp->z_pflags, 8);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_UID(zfsvfs), NULL, &z_uid, 8);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_GID(zfsvfs), NULL, &z_gid, 8);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_MODE(zfsvfs), NULL, &mode, 8);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_ATIME(zfsvfs), NULL, &atime, 16);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_MTIME(zfsvfs), NULL, &mtime, 16);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_CTIME(zfsvfs), NULL, &ctime, 16);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_CRTIME(zfsvfs), NULL, &btime, 16);

	if (sa_bulk_lookup(zp->z_sa_hdl, bulk, count) != 0) {
		zfs_znode_dmu_fini(zp);
		zfs_znode_hold_exit(zfsvfs, zh);
		return (SET_ERROR(EIO));
	}

	if (dmu_objset_projectquota_enabled(zfsvfs->z_os)) {
		err = sa_lookup(zp->z_sa_hdl, SA_ZPL_PROJID(zfsvfs),
		    &projid, 8);
		if (err != 0 && err != ENOENT) {
			zfs_znode_dmu_fini(zp);
			zfs_znode_hold_exit(zfsvfs, zh);
			return (SET_ERROR(err));
		}
	}
	zp->z_projid = projid;
	zp->z_has_seq = (zp->z_is_sa &&
	    sa_lookup(zp->z_sa_hdl, SA_ZPL_SEQ(zfsvfs),
	    &zp->z_seq, sizeof (zp->z_seq)) == 0);

	if ((uint32_t)gen != zp->z_gen) {
		zfs_znode_dmu_fini(zp);
		zfs_znode_hold_exit(zfsvfs, zh);
		return (SET_ERROR(EIO));
	}

	zp->z_mode = mode;
	zp->z_uid = z_uid;
	zp->z_gid = z_gid;
	zp->z_links = links;
	zp->z_blksz = doi.doi_data_block_size;
	zp->z_atime_dirty = B_FALSE;
	ZFS_TIME_DECODE(&zp->z_atime, atime);
	ZFS_TIME_DECODE(&zp->z_mtime, mtime);
	ZFS_TIME_DECODE(&zp->z_ctime, ctime);
	ZFS_TIME_DECODE(&zp->z_btime, btime);

	/*
	 * Zero links after recv/rollback: drop the SA handle so
	 * zfs_zinactive does not try to free an object that is already
	 * in the unlinked set.
	 */
	zp->z_unlinked = (links == 0);
	if (zp->z_unlinked)
		zfs_znode_dmu_fini(zp);

	zfs_znode_hold_exit(zfsvfs, zh);
	return (0);
}

void
zfs_znode_delete(znode_t *zp, dmu_tx_t *tx)
{
	zfsvfs_t *zfsvfs = ZTOZSB(zp);
	objset_t *os = zfsvfs->z_os;
	uint64_t obj = zp->z_id;
	uint64_t acl_obj = zfs_external_acl(zp);
	znode_hold_t *zh;

	zh = zfs_znode_hold_enter(zfsvfs, obj);
	if (acl_obj)
		VERIFY0(dmu_object_free(os, acl_obj, tx));
	VERIFY0(dmu_object_free(os, obj, tx));
	zfs_znode_dmu_fini(zp);
	zfs_znode_hold_exit(zfsvfs, zh);
}

void
zfs_zinactive(znode_t *zp)
{
	zfsvfs_t *zfsvfs = ZTOZSB(zp);
	znode_hold_t *zh;

	zh = zfs_znode_hold_enter(zfsvfs, zp->z_id);
	zfs_zinactive_held(zp, zh);
}

void
zfs_tstamp_update_setup(znode_t *zp, uint_t flag, uint64_t mtime[2],
    uint64_t ctime[2])
{
	inode_timespec_t now;

	gethrestime(&now);
	atomic_inc_64(&zp->z_seq);
	if (flag & ATTR_ATIME) {
		zp->z_atime = now;
		zp->z_atime_dirty = B_TRUE;
	}
	if (flag & ATTR_MTIME) {
		ZFS_TIME_ENCODE(&now, mtime);
		ZFS_TIME_DECODE(&zp->z_mtime, mtime);
		if (ZTOZSB(zp)->z_use_fuids)
			zp->z_pflags |= (ZFS_ARCHIVE | ZFS_AV_MODIFIED);
	}
	if (flag & ATTR_CTIME) {
		ZFS_TIME_ENCODE(&now, ctime);
		ZFS_TIME_DECODE(&zp->z_ctime, ctime);
		if (ZTOZSB(zp)->z_use_fuids)
			zp->z_pflags |= ZFS_ARCHIVE;
	}
}

boolean_t
zfs_relatime_need_update(const znode_t *zp)
{
	inode_timespec_t now;

	if (zp == NULL)
		return (B_FALSE);
	gethrestime(&now);
	if (zp->z_mtime.tv_sec > zp->z_atime.tv_sec ||
	    (zp->z_mtime.tv_sec == zp->z_atime.tv_sec &&
	    zp->z_mtime.tv_nsec >= zp->z_atime.tv_nsec))
		return (B_TRUE);
	if (zp->z_ctime.tv_sec > zp->z_atime.tv_sec ||
	    (zp->z_ctime.tv_sec == zp->z_atime.tv_sec &&
	    zp->z_ctime.tv_nsec >= zp->z_atime.tv_nsec))
		return (B_TRUE);
	if ((int64_t)now.tv_sec - (int64_t)zp->z_atime.tv_sec >= 24 * 60 * 60)
		return (B_TRUE);
	return (B_FALSE);
}

void
zfs_grow_blocksize(znode_t *zp, uint64_t size, dmu_tx_t *tx)
{
	int error;
	u_longlong_t dummy;

	if (size <= zp->z_blksz)
		return;
	if (zp->z_blksz && zp->z_size > zp->z_blksz)
		return;
	error = dmu_object_set_blocksize(ZTOZSB(zp)->z_os, zp->z_id,
	    size, 0, tx);
	if (error == ENOTSUP)
		return;
	ASSERT0(error);
	dmu_object_size_from_db(sa_get_db(zp->z_sa_hdl), &zp->z_blksz, &dummy);
}

int
zfs_freesp(znode_t *zp, uint64_t off, uint64_t len, int flag, boolean_t log)
{
	dmu_tx_t *tx;
	zfsvfs_t *zfsvfs = ZTOZSB(zp);
	zilog_t *zilog = zfsvfs->z_log;
	zfs_locked_range_t *lr;
	uint64_t mtime[2], ctime[2];
	sa_bulk_attr_t bulk[5];
	int count = 0;
	int error;
	uint64_t newsize;

	(void) flag;
	lr = zfs_rangelock_enter(&zp->z_rangelock, 0, UINT64_MAX, RL_WRITER);
	newsize = zp->z_size;
	if (len == 0) {
		error = dmu_free_long_range(zfsvfs->z_os, zp->z_id, off,
		    DMU_OBJECT_END);
		if (error == 0)
			newsize = off;
	} else {
		if (off > UINT64_MAX - len) {
			zfs_rangelock_exit(lr);
			return (SET_ERROR(EFBIG));
		}
		error = dmu_free_long_range(zfsvfs->z_os, zp->z_id, off, len);
		/*
		 * Hole punch does not change z_size. Truncate (len == 0)
		 * is the only path that may shrink it.
		 */
	}

	if (error) {
		zfs_rangelock_exit(lr);
		return (error);
	}
	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_sa(tx, zp->z_sa_hdl, ZFS_SEQ_MAY_GROW(zp));
	dmu_tx_mark_netfree(tx);
	error = dmu_tx_assign(tx, DMU_TX_WAIT);
	if (error) {
		dmu_tx_abort(tx);
		zfs_rangelock_exit(lr);
		return (error);
	}
	if (len == 0)
		zp->z_size = newsize;
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_SIZE(zfsvfs), NULL,
	    &zp->z_size, 8);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_MTIME(zfsvfs), NULL, mtime, 16);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_CTIME(zfsvfs), NULL, ctime, 16);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_FLAGS(zfsvfs), NULL,
	    &zp->z_pflags, 8);
	zfs_tstamp_update_setup(zp, CONTENT_MODIFIED, mtime, ctime);
	ZFS_PERSIST_SEQ(zp, bulk, count);
	error = sa_bulk_update(zp->z_sa_hdl, bulk, count, tx);
	if (log && zilog != NULL)
		zfs_log_truncate(zilog, tx, TX_TRUNCATE, zp, off, len);
	dmu_tx_commit(tx);
	zfs_rangelock_exit(lr);
	return (error);
}

void
zfs_mknode(znode_t *dzp, vattr_t *vap, dmu_tx_t *tx, cred_t *cr,
    uint_t flag, znode_t **zpp, zfs_acl_ids_t *acl_ids)
{
	uint64_t crtime[2], atime[2], mtime[2], ctime[2];
	uint64_t mode, size, links, parent, pflags;
	uint64_t projid = ZFS_DEFAULT_PROJID;
	uint64_t rdev = 0;
	zfsvfs_t *zfsvfs = ZTOZSB(dzp);
	dmu_buf_t *db;
	inode_timespec_t now;
	uint64_t gen, obj;
	int bonuslen;
	int dnodesize;
	sa_handle_t *sa_hdl;
	dmu_object_type_t obj_type;
	sa_bulk_attr_t *sa_attrs;
	int cnt = 0;
	zfs_acl_locator_cb_t locate = { 0 };
	znode_hold_t *zh;

	(void) cr;
	if (zfsvfs->z_replay) {
		obj = vap->va_nodeid;
		now = vap->va_ctime;
		gen = vap->va_nblocks;
		dnodesize = vap->va_fsid;
	} else {
		obj = 0;
		gethrestime(&now);
		gen = dmu_tx_get_txg(tx);
		dnodesize = dmu_objset_dnodesize(zfsvfs->z_os);
	}
	if (dnodesize == 0)
		dnodesize = DNODE_MIN_SIZE;

	obj_type = zfsvfs->z_use_sa ? DMU_OT_SA : DMU_OT_ZNODE;
	bonuslen = (obj_type == DMU_OT_SA) ?
	    DN_BONUS_SIZE(dnodesize) : ZFS_OLD_ZNODE_PHYS_SIZE;

	if (S_ISDIR(vap->va_mode)) {
		if (zfsvfs->z_replay) {
			VERIFY0(zap_create_claim_norm_dnsize(zfsvfs->z_os, obj,
			    zfsvfs->z_norm, DMU_OT_DIRECTORY_CONTENTS,
			    obj_type, bonuslen, dnodesize, tx));
		} else {
			obj = zap_create_norm_dnsize(zfsvfs->z_os,
			    zfsvfs->z_norm, DMU_OT_DIRECTORY_CONTENTS,
			    obj_type, bonuslen, dnodesize, tx);
		}
	} else {
		if (zfsvfs->z_replay) {
			VERIFY0(dmu_object_claim_dnsize(zfsvfs->z_os, obj,
			    DMU_OT_PLAIN_FILE_CONTENTS, 0,
			    obj_type, bonuslen, dnodesize, tx));
		} else {
			obj = dmu_object_alloc_dnsize(zfsvfs->z_os,
			    DMU_OT_PLAIN_FILE_CONTENTS, 0,
			    obj_type, bonuslen, dnodesize, tx);
		}
	}

	zh = zfs_znode_hold_enter(zfsvfs, obj);
	VERIFY0(sa_buf_hold(zfsvfs->z_os, obj, NULL, &db));

	if (flag & IS_ROOT_NODE)
		dzp->z_id = obj;
	if (dzp->z_pflags & ZFS_XATTR)
		flag |= IS_XATTR;

	if (zfsvfs->z_use_fuids)
		pflags = ZFS_ARCHIVE | ZFS_AV_MODIFIED;
	else
		pflags = 0;

	if (S_ISDIR(vap->va_mode)) {
		size = 2;
		links = 2;
	} else {
		size = 0;
		links = (flag & IS_TMPFILE) ? 0 : 1;
	}
	if (S_ISBLK(vap->va_mode) || S_ISCHR(vap->va_mode))
		rdev = vap->va_rdev;

	parent = dzp->z_id;
	mode = acl_ids->z_mode;
	if (flag & IS_XATTR)
		pflags |= ZFS_XATTR;
	if (obj_type != DMU_OT_ZNODE &&
	    dmu_objset_projectquota_enabled(zfsvfs->z_os))
		pflags |= ZFS_PROJID;
	projid = zfs_inherit_projid(dzp);
	if ((S_ISREG(vap->va_mode) || S_ISDIR(vap->va_mode)) &&
	    (dzp->z_pflags & ZFS_PROJINHERIT))
		pflags |= ZFS_PROJINHERIT;
	if (acl_ids->z_aclp != NULL)
		pflags |= acl_ids->z_aclp->z_hints &
		    (ZFS_ACL_TRIVIAL|ZFS_INHERIT_ACE|ZFS_ACL_AUTO_INHERIT|
		    ZFS_ACL_DEFAULTED|ZFS_ACL_PROTECTED);

	ZFS_TIME_ENCODE(&now, crtime);
	ZFS_TIME_ENCODE(&now, ctime);
	if (vap->va_mask & ATTR_ATIME)
		ZFS_TIME_ENCODE(&vap->va_atime, atime);
	else
		ZFS_TIME_ENCODE(&now, atime);
	if (vap->va_mask & ATTR_MTIME)
		ZFS_TIME_ENCODE(&vap->va_mtime, mtime);
	else
		ZFS_TIME_ENCODE(&now, mtime);

	VERIFY0(sa_handle_get_from_db(zfsvfs->z_os, db, NULL, SA_HDL_SHARED,
	    &sa_hdl));
	sa_attrs = kmem_alloc(sizeof (sa_bulk_attr_t) * ZPL_END, KM_SLEEP);

	if (obj_type == DMU_OT_ZNODE) {
		SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_ATIME(zfsvfs),
		    NULL, &atime, 16);
		SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_MTIME(zfsvfs),
		    NULL, &mtime, 16);
		SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_CTIME(zfsvfs),
		    NULL, &ctime, 16);
		SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_CRTIME(zfsvfs),
		    NULL, &crtime, 16);
		SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_GEN(zfsvfs),
		    NULL, &gen, 8);
		SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_MODE(zfsvfs),
		    NULL, &mode, 8);
		SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_SIZE(zfsvfs),
		    NULL, &size, 8);
		SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_PARENT(zfsvfs),
		    NULL, &parent, 8);
	} else {
		SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_MODE(zfsvfs),
		    NULL, &mode, 8);
		SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_SIZE(zfsvfs),
		    NULL, &size, 8);
		SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_GEN(zfsvfs),
		    NULL, &gen, 8);
		SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_UID(zfsvfs),
		    NULL, &acl_ids->z_fuid, 8);
		SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_GID(zfsvfs),
		    NULL, &acl_ids->z_fgid, 8);
		SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_PARENT(zfsvfs),
		    NULL, &parent, 8);
		SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_FLAGS(zfsvfs),
		    NULL, &pflags, 8);
		SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_ATIME(zfsvfs),
		    NULL, &atime, 16);
		SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_MTIME(zfsvfs),
		    NULL, &mtime, 16);
		SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_CTIME(zfsvfs),
		    NULL, &ctime, 16);
		SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_CRTIME(zfsvfs),
		    NULL, &crtime, 16);
	}
	SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_LINKS(zfsvfs), NULL, &links, 8);
	if (obj_type == DMU_OT_ZNODE) {
		SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_XATTR(zfsvfs), NULL,
		    &empty_xattr, 8);
	} else if (dmu_objset_projectquota_enabled(zfsvfs->z_os) &&
	    (pflags & ZFS_PROJID)) {
		SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_PROJID(zfsvfs),
		    NULL, &projid, 8);
	}
	if (obj_type == DMU_OT_ZNODE ||
	    (S_ISBLK(vap->va_mode) || S_ISCHR(vap->va_mode))) {
		SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_RDEV(zfsvfs),
		    NULL, &rdev, 8);
	}
	if (obj_type == DMU_OT_ZNODE) {
		SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_FLAGS(zfsvfs),
		    NULL, &pflags, 8);
		SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_UID(zfsvfs), NULL,
		    &acl_ids->z_fuid, 8);
		SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_GID(zfsvfs), NULL,
		    &acl_ids->z_fgid, 8);
		SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_PAD(zfsvfs), NULL, pad,
		    sizeof (uint64_t) * 4);
		SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_ZNODE_ACL(zfsvfs), NULL,
		    &acl_phys, sizeof (zfs_acl_phys_t));
	} else if (acl_ids->z_aclp != NULL &&
	    acl_ids->z_aclp->z_version >= ZFS_ACL_VERSION_FUID) {
		SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_DACL_COUNT(zfsvfs), NULL,
		    &acl_ids->z_aclp->z_acl_count, 8);
		locate.cb_aclp = acl_ids->z_aclp;
		SA_ADD_BULK_ATTR(sa_attrs, cnt, SA_ZPL_DACL_ACES(zfsvfs),
		    zfs_acl_data_locator, &locate,
		    acl_ids->z_aclp->z_acl_bytes);
		mode = zfs_mode_compute(mode, acl_ids->z_aclp, &pflags,
		    acl_ids->z_fuid, acl_ids->z_fgid);
	}

	VERIFY0(sa_replace_all_by_template(sa_hdl, sa_attrs, cnt, tx));

	if (!(flag & IS_ROOT_NODE)) {
		*zpp = zfs_znode_alloc(zfsvfs, db, 0, obj_type, sa_hdl);
		VERIFY(*zpp != NULL);
	} else {
		*zpp = dzp;
		(*zpp)->z_sa_hdl = sa_hdl;
		sa_set_userp(sa_hdl, *zpp);
		(*zpp)->z_id = obj;
	}
	(*zpp)->z_pflags = pflags;
	(*zpp)->z_mode = mode;
	(*zpp)->z_links = links;
	(*zpp)->z_size = size;
	(*zpp)->z_uid = acl_ids->z_fuid;
	(*zpp)->z_gid = acl_ids->z_fgid;
	(*zpp)->z_dnodesize = dnodesize;
	(*zpp)->z_projid = projid;
	(*zpp)->z_is_sa = (obj_type == DMU_OT_SA);
	(*zpp)->z_gen = (uint32_t)gen;
	ZFS_TIME_DECODE(&(*zpp)->z_atime, atime);
	ZFS_TIME_DECODE(&(*zpp)->z_mtime, mtime);
	ZFS_TIME_DECODE(&(*zpp)->z_ctime, ctime);
	ZFS_TIME_DECODE(&(*zpp)->z_btime, crtime);

	if (obj_type == DMU_OT_ZNODE ||
	    acl_ids->z_aclp == NULL ||
	    acl_ids->z_aclp->z_version < ZFS_ACL_VERSION_FUID)
		VERIFY0(zfs_aclset_common(*zpp, acl_ids->z_aclp, cr, tx));
	kmem_free(sa_attrs, sizeof (sa_bulk_attr_t) * ZPL_END);
	zfs_znode_hold_exit(zfsvfs, zh);
}

void
zfsd_create_fs(objset_t *os, cred_t *cr, nvlist_t *zplprops, dmu_tx_t *tx)
{
	zfsvfs_t *zfsvfs;
	uint64_t moid, obj, sa_obj, version;
	uint64_t sense = ZFS_CASE_SENSITIVE;
	uint64_t norm = 0;
	nvpair_t *elem;
	int size, i, error;
	znode_t *rootzp;
	vattr_t vattr;
	znode_t *zp;
	zfs_acl_ids_t acl_ids;

	moid = MASTER_NODE_OBJ;
	error = zap_create_claim(os, moid, DMU_OT_MASTER_NODE,
	    DMU_OT_NONE, 0, tx);
	ASSERT0(error);

	version = zfs_zpl_version_map(spa_version(dmu_objset_spa(os)));
	elem = NULL;
	while (zplprops != NULL &&
	    (elem = nvlist_next_nvpair(zplprops, elem)) != NULL) {
		uint64_t val;
		const char *name;

		if (nvpair_type(elem) != DATA_TYPE_UINT64)
			continue;
		VERIFY0(nvpair_value_uint64(elem, &val));
		name = nvpair_name(elem);
		if (strcmp(name, zfs_prop_to_name(ZFS_PROP_VERSION)) == 0) {
			if (val < version)
				version = val;
		} else {
			error = zap_update(os, moid, name, 8, 1, &val, tx);
			ASSERT0(error);
		}
		if (strcmp(name, zfs_prop_to_name(ZFS_PROP_NORMALIZE)) == 0)
			norm = val;
		else if (strcmp(name, zfs_prop_to_name(ZFS_PROP_CASE)) == 0)
			sense = val;
	}
	ASSERT(version != 0);
	error = zap_update(os, moid, ZPL_VERSION_STR, 8, 1, &version, tx);
	ASSERT0(error);

	if (version >= ZPL_VERSION_SA) {
		sa_obj = zap_create(os, DMU_OT_SA_MASTER_NODE,
		    DMU_OT_NONE, 0, tx);
		error = zap_add(os, moid, ZFS_SA_ATTRS, 8, 1, &sa_obj, tx);
		ASSERT0(error);
	} else {
		sa_obj = 0;
	}

	obj = zap_create(os, DMU_OT_UNLINKED_SET, DMU_OT_NONE, 0, tx);
	error = zap_add(os, moid, ZFS_UNLINKED_SET, 8, 1, &obj, tx);
	ASSERT0(error);

	memset(&vattr, 0, sizeof (vattr));
	vattr.va_mask = ATTR_MODE | ATTR_UID | ATTR_GID;
	vattr.va_mode = S_IFDIR | 0755;
	vattr.va_uid = crgetuid(cr);
	vattr.va_gid = crgetgid(cr);

	if (znode_cache == NULL)
		zfs_znode_init();
	rootzp = kmem_cache_alloc(znode_cache, KM_SLEEP);
	rootzp->z_unlinked = B_FALSE;
	rootzp->z_atime_dirty = B_FALSE;
	rootzp->z_xattr_dir_absent = B_FALSE;
	rootzp->z_is_sa = USE_SA(version, os);
	rootzp->z_pflags = 0;
	rootzp->z_sa_hdl = NULL;
	rootzp->z_dirlocks = NULL;
	rootzp->z_acl_cached = NULL;
	rootzp->z_xattr_cached = NULL;
	rootzp->z_ref = 1;
	rootzp->z_gen = 1;

	zfsvfs = kmem_zalloc(sizeof (zfsvfs_t), KM_SLEEP);
	zfsvfs->z_os = os;
	zfsvfs->z_parent = zfsvfs;
	zfsvfs->z_version = version;
	zfsvfs->z_use_fuids = USE_FUIDS(version, os);
	zfsvfs->z_use_sa = USE_SA(version, os);
	zfsvfs->z_norm = norm;
	rootzp->z_zfsvfs = zfsvfs;

	error = sa_setup(os, sa_obj, zfs_attr_table, ZPL_END,
	    &zfsvfs->z_attr_table);
	ASSERT0(error);

	if (sense == ZFS_CASE_INSENSITIVE || sense == ZFS_CASE_MIXED)
		zfsvfs->z_norm |= U8_TEXTPREP_TOUPPER;

	mutex_init(&zfsvfs->z_znodes_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&zfsvfs->z_all_znodes, sizeof (znode_t),
	    offsetof(znode_t, z_link_node));

	size = MIN(1 << (highbit64(zfs_object_mutex_size) - 1), ZFS_OBJ_MTX_MAX);
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

	VERIFY0(zfs_acl_ids_create(rootzp, IS_ROOT_NODE, &vattr,
	    cr, NULL, &acl_ids, NULL));
	zfs_mknode(rootzp, &vattr, tx, cr, IS_ROOT_NODE, &zp, &acl_ids);
	ASSERT3P(zp, ==, rootzp);
	error = zap_add(os, moid, ZFS_ROOT_OBJ, 8, 1, &rootzp->z_id, tx);
	ASSERT0(error);
	zfs_acl_ids_free(&acl_ids);

	if (rootzp->z_sa_hdl != NULL)
		sa_handle_destroy(rootzp->z_sa_hdl);
	rootzp->z_sa_hdl = NULL;
	kmem_cache_free(znode_cache, rootzp);

	for (i = 0; i != size; i++) {
		avl_destroy(&zfsvfs->z_hold_trees[i]);
		mutex_destroy(&zfsvfs->z_hold_locks[i]);
	}
	vmem_free(zfsvfs->z_hold_trees, sizeof (avl_tree_t) * size);
	vmem_free(zfsvfs->z_hold_locks, sizeof (kmutex_t) * size);
	list_destroy(&zfsvfs->z_all_znodes);
	mutex_destroy(&zfsvfs->z_znodes_lock);
	kmem_free(zfsvfs, sizeof (zfsvfs_t));
}

void
zfs_xvattr_set(znode_t *zp, xvattr_t *xvap, dmu_tx_t *tx)
{
	xoptattr_t *xoap;

	xoap = xva_getxoptattr(xvap);
	if (xoap == NULL)
		return;

	if (XVA_ISSET_REQ(xvap, XAT_CREATETIME)) {
		uint64_t times[2];
		ZFS_TIME_ENCODE(&xoap->xoa_createtime, times);
		(void) sa_update(zp->z_sa_hdl, SA_ZPL_CRTIME(ZTOZSB(zp)),
		    &times, sizeof (times), tx);
		XVA_SET_RTN(xvap, XAT_CREATETIME);
	}
	if (XVA_ISSET_REQ(xvap, XAT_READONLY)) {
		ZFS_ATTR_SET(zp, ZFS_READONLY, xoap->xoa_readonly,
		    zp->z_pflags, tx);
		XVA_SET_RTN(xvap, XAT_READONLY);
	}
	if (XVA_ISSET_REQ(xvap, XAT_HIDDEN)) {
		ZFS_ATTR_SET(zp, ZFS_HIDDEN, xoap->xoa_hidden,
		    zp->z_pflags, tx);
		XVA_SET_RTN(xvap, XAT_HIDDEN);
	}
	if (XVA_ISSET_REQ(xvap, XAT_SYSTEM)) {
		ZFS_ATTR_SET(zp, ZFS_SYSTEM, xoap->xoa_system,
		    zp->z_pflags, tx);
		XVA_SET_RTN(xvap, XAT_SYSTEM);
	}
	if (XVA_ISSET_REQ(xvap, XAT_ARCHIVE)) {
		ZFS_ATTR_SET(zp, ZFS_ARCHIVE, xoap->xoa_archive,
		    zp->z_pflags, tx);
		XVA_SET_RTN(xvap, XAT_ARCHIVE);
	}
	if (XVA_ISSET_REQ(xvap, XAT_IMMUTABLE)) {
		ZFS_ATTR_SET(zp, ZFS_IMMUTABLE, xoap->xoa_immutable,
		    zp->z_pflags, tx);
		XVA_SET_RTN(xvap, XAT_IMMUTABLE);
	}
	if (XVA_ISSET_REQ(xvap, XAT_NOUNLINK)) {
		ZFS_ATTR_SET(zp, ZFS_NOUNLINK, xoap->xoa_nounlink,
		    zp->z_pflags, tx);
		XVA_SET_RTN(xvap, XAT_NOUNLINK);
	}
	if (XVA_ISSET_REQ(xvap, XAT_APPENDONLY)) {
		ZFS_ATTR_SET(zp, ZFS_APPENDONLY, xoap->xoa_appendonly,
		    zp->z_pflags, tx);
		XVA_SET_RTN(xvap, XAT_APPENDONLY);
	}
	if (XVA_ISSET_REQ(xvap, XAT_NODUMP)) {
		ZFS_ATTR_SET(zp, ZFS_NODUMP, xoap->xoa_nodump,
		    zp->z_pflags, tx);
		XVA_SET_RTN(xvap, XAT_NODUMP);
	}
	if (XVA_ISSET_REQ(xvap, XAT_OPAQUE)) {
		ZFS_ATTR_SET(zp, ZFS_OPAQUE, xoap->xoa_opaque,
		    zp->z_pflags, tx);
		XVA_SET_RTN(xvap, XAT_OPAQUE);
	}
	if (XVA_ISSET_REQ(xvap, XAT_AV_QUARANTINED)) {
		ZFS_ATTR_SET(zp, ZFS_AV_QUARANTINED,
		    xoap->xoa_av_quarantined, zp->z_pflags, tx);
		XVA_SET_RTN(xvap, XAT_AV_QUARANTINED);
	}
	if (XVA_ISSET_REQ(xvap, XAT_AV_MODIFIED)) {
		ZFS_ATTR_SET(zp, ZFS_AV_MODIFIED, xoap->xoa_av_modified,
		    zp->z_pflags, tx);
		XVA_SET_RTN(xvap, XAT_AV_MODIFIED);
	}
	if (XVA_ISSET_REQ(xvap, XAT_AV_SCANSTAMP)) {
		zfs_sa_set_scanstamp(zp, xvap, tx);
		XVA_SET_RTN(xvap, XAT_AV_SCANSTAMP);
	}
	if (XVA_ISSET_REQ(xvap, XAT_REPARSE)) {
		ZFS_ATTR_SET(zp, ZFS_REPARSE, xoap->xoa_reparse,
		    zp->z_pflags, tx);
		XVA_SET_RTN(xvap, XAT_REPARSE);
	}
	if (XVA_ISSET_REQ(xvap, XAT_OFFLINE)) {
		ZFS_ATTR_SET(zp, ZFS_OFFLINE, xoap->xoa_offline,
		    zp->z_pflags, tx);
		XVA_SET_RTN(xvap, XAT_OFFLINE);
	}
	if (XVA_ISSET_REQ(xvap, XAT_SPARSE)) {
		ZFS_ATTR_SET(zp, ZFS_SPARSE, xoap->xoa_sparse,
		    zp->z_pflags, tx);
		XVA_SET_RTN(xvap, XAT_SPARSE);
	}
	if (XVA_ISSET_REQ(xvap, XAT_PROJINHERIT)) {
		ZFS_ATTR_SET(zp, ZFS_PROJINHERIT, xoap->xoa_projinherit,
		    zp->z_pflags, tx);
		XVA_SET_RTN(xvap, XAT_PROJINHERIT);
	}
	if (XVA_ISSET_REQ(xvap, XAT_PROJID)) {
		zp->z_projid = xoap->xoa_projid;
		zp->z_pflags |= ZFS_PROJID;
		(void) sa_update(zp->z_sa_hdl, SA_ZPL_PROJID(ZTOZSB(zp)),
		    &zp->z_projid, sizeof (uint64_t), tx);
		(void) sa_update(zp->z_sa_hdl, SA_ZPL_FLAGS(ZTOZSB(zp)),
		    &zp->z_pflags, sizeof (uint64_t), tx);
		XVA_SET_RTN(xvap, XAT_PROJID);
	}
}

void
zfs_upgrade(zfsvfs_t *zfsvfs, dmu_tx_t *tx)
{
	(void) zfsvfs;
	(void) tx;
}
