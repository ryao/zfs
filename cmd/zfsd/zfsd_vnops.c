// SPDX-License-Identifier: CDDL-1.0
/*
 * zfsd OS vnops -- same names as module/os/linux/zfs/zfs_vnops_os.c.
 * Common zfs_read/zfs_write/zfs_fsync live in module/zfs/zfs_vnops.c.
 */

#include <sys/zfs_context.h>
#include <sys/zfs_vfsops.h>
#include <sys/zfs_znode.h>
#include <sys/zfs_dir.h>
#include <sys/zfs_acl.h>
#include <sys/zfs_acl_impl.h>
#include <sys/zfs_vnops.h>
#include <sys/zfs_fuid.h>
#include <sys/zfs_ctldir.h>
#include <sys/zfs_quota.h>
#include <sys/dmu.h>
#include <sys/dmu_objset.h>
#include <sys/sa.h>
#include <sys/zfs_sa.h>
#include <sys/zap.h>
#include <sys/zil.h>
#include <sys/zfs_rlock.h>
#include <sys/policy.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/uio.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/u8_textprep.h>
#include <sys/xvattr.h>
#include <string.h>
#include <dirent.h>

int
mappedread(znode_t *zp, int nbytes, zfs_uio_t *uio)
{
	(void) zp;
	(void) nbytes;
	(void) uio;
	return (SET_ERROR(EIO));
}

int
mappedread_sf(znode_t *zp, int nbytes, zfs_uio_t *uio)
{
	return (mappedread(zp, nbytes, uio));
}

void
update_pages(znode_t *zp, int64_t off, int len, objset_t *os)
{
	(void) zp;
	(void) off;
	(void) len;
	(void) os;
}

int
zfs_open(znode_t *zp, int mode, int flag, cred_t *cr)
{
	zfsvfs_t *zfsvfs = ZTOZSB(zp);
	int error;

	(void) mode;
	(void) cr;
	if ((error = zfs_enter_verify_zp(zfsvfs, zp, FTAG)) != 0)
		return (error);
	if (flag & (FSYNC | FDSYNC))
		atomic_inc_32(&zp->z_sync_cnt);
	zfs_exit(zfsvfs, FTAG);
	return (0);
}

int
zfs_close(znode_t *zp, int flag, cred_t *cr)
{
	zfsvfs_t *zfsvfs = ZTOZSB(zp);
	int error;

	(void) cr;
	if ((error = zfs_enter_verify_zp(zfsvfs, zp, FTAG)) != 0)
		return (error);
	if ((flag & (FSYNC | FDSYNC)) && zp->z_sync_cnt > 0)
		atomic_dec_32(&zp->z_sync_cnt);
	zfs_exit(zfsvfs, FTAG);
	return (0);
}

int
zfs_write_simple(znode_t *zp, const void *data, size_t len, loff_t pos,
    size_t *resid)
{
	zfs_uio_t uio;
	struct iovec iov;
	int error;

	iov.iov_base = (void *)(uintptr_t)data;
	iov.iov_len = len;
	zfs_uio_iovec_init(&uio, &iov, 1, pos, UIO_SYSSPACE, len, 0);
	error = zfs_write(zp, &uio, 0, CRED());
	if (resid != NULL)
		*resid = (size_t)zfs_uio_resid(&uio);
	return (error);
}

int
zfs_lookup(znode_t *zdp, char *nm, znode_t **zpp, int flags, cred_t *cr,
    int *direntflags, pathname_t *realpnp)
{
	zfsvfs_t *zfsvfs = ZTOZSB(zdp);
	int error = 0;

	if (!(flags & (LOOKUP_XATTR | FIGNORECASE))) {
		if (!S_ISDIR(zdp->z_mode))
			return (SET_ERROR(ENOTDIR));
		if (zdp->z_sa_hdl == NULL)
			return (SET_ERROR(EIO));
		if (nm != NULL && (nm[0] == '\0' ||
		    (nm[0] == '.' && nm[1] == '\0'))) {
			error = zfs_fastaccesschk_execute(zdp, cr);
			if (!error) {
				*zpp = zdp;
				zhold(*zpp);
				return (0);
			}
			return (error);
		}
	}

	if ((error = zfs_enter_verify_zp(zfsvfs, zdp, FTAG)) != 0)
		return (error);
	*zpp = NULL;

	if (flags & LOOKUP_XATTR) {
		if (zdp->z_pflags & ZFS_XATTR) {
			zfs_exit(zfsvfs, FTAG);
			return (SET_ERROR(EINVAL));
		}
		if ((error = zfs_get_xattrdir(zdp, zpp, cr, flags))) {
			zfs_exit(zfsvfs, FTAG);
			return (error);
		}
		if ((error = zfs_zaccess(*zpp, ACE_EXECUTE, 0, B_TRUE, cr))) {
			zrele(*zpp);
			*zpp = NULL;
		}
		zfs_exit(zfsvfs, FTAG);
		return (error);
	}

	if (!S_ISDIR(zdp->z_mode)) {
		zfs_exit(zfsvfs, FTAG);
		return (SET_ERROR(ENOTDIR));
	}
	if ((error = zfs_zaccess(zdp, ACE_EXECUTE, 0, B_FALSE, cr))) {
		zfs_exit(zfsvfs, FTAG);
		return (error);
	}
	if (nm != NULL && zfsvfs->z_utf8 && u8_validate(nm, strlen(nm),
	    NULL, U8_VALIDATE_ENTIRE, &error) < 0) {
		zfs_exit(zfsvfs, FTAG);
		return (SET_ERROR(EILSEQ));
	}
	error = zfs_dirlook(zdp, nm, zpp, flags, direntflags, realpnp);
	zfs_exit(zfsvfs, FTAG);
	return (error);
}

int
zfs_create(znode_t *dzp, char *name, vattr_t *vap, int excl, int mode,
    znode_t **zpp, cred_t *cr, int flag, vsecattr_t *vsecp)
{
	znode_t *zp = NULL;
	zfsvfs_t *zfsvfs = ZTOZSB(dzp);
	zilog_t *zilog;
	zfs_dirlock_t *dl = NULL;
	dmu_tx_t *tx;
	int error;
	zfs_acl_ids_t acl_ids;
	boolean_t have_acl = B_FALSE;
	boolean_t waited = B_FALSE;
	int zflg = 0;

	if (name == NULL)
		return (SET_ERROR(EINVAL));
	if ((error = zfs_enter_verify_zp(zfsvfs, dzp, FTAG)) != 0)
		return (error);
	zilog = zfsvfs->z_log;
	if (flag & FIGNORECASE)
		zflg |= ZCILOOK;

top:
	*zpp = NULL;
	error = zfs_dirent_lock(&dl, dzp, name, &zp, zflg, NULL, NULL);
	if (error) {
		if (have_acl)
			zfs_acl_ids_free(&acl_ids);
		if (strcmp(name, "..") == 0)
			error = SET_ERROR(EISDIR);
		zfs_exit(zfsvfs, FTAG);
		return (error);
	}

	if (zp == NULL) {
		uint64_t txtype;

		if ((error = zfs_zaccess(dzp, ACE_ADD_FILE, 0, B_FALSE, cr)))
			goto out;
		if ((dzp->z_pflags & ZFS_XATTR) && !S_ISREG(vap->va_mode)) {
			error = SET_ERROR(EINVAL);
			goto out;
		}
		if (!have_acl && (error = zfs_acl_ids_create(dzp, 0, vap,
		    cr, vsecp, &acl_ids, NULL)) != 0)
			goto out;
		have_acl = B_TRUE;
		if (zfs_acl_ids_overquota(zfsvfs, &acl_ids,
		    zfs_inherit_projid(dzp))) {
			error = SET_ERROR(EDQUOT);
			goto out;
		}
		tx = dmu_tx_create(zfsvfs->z_os);
		dmu_tx_hold_sa_create(tx, acl_ids.z_aclp->z_acl_bytes +
		    ZFS_SA_BASE_ATTR_SIZE);
		dmu_tx_hold_zap(tx, dzp->z_id, TRUE, name);
		dmu_tx_hold_sa(tx, dzp->z_sa_hdl, ZFS_SEQ_MAY_GROW(dzp));
		error = dmu_tx_assign(tx,
		    (waited ? DMU_TX_NOTHROTTLE : 0) | DMU_TX_NOWAIT);
		if (error) {
			zfs_dirent_unlock(dl);
			dl = NULL;
			if (error == ERESTART) {
				waited = B_TRUE;
				dmu_tx_wait(tx);
				dmu_tx_abort(tx);
				goto top;
			}
			zfs_acl_ids_free(&acl_ids);
			dmu_tx_abort(tx);
			zfs_exit(zfsvfs, FTAG);
			return (error);
		}
		zfs_mknode(dzp, vap, tx, cr, 0, &zp, &acl_ids);
		error = zfs_link_create(dl, zp, tx, ZNEW);
		if (error != 0) {
			zfs_znode_delete(zp, tx);
			zfs_acl_ids_free(&acl_ids);
			dmu_tx_commit(tx);
			goto out;
		}
		txtype = zfs_log_create_txtype(Z_FILE, vsecp, vap);
		if (flag & FIGNORECASE)
			txtype |= TX_CI;
		if (zilog != NULL)
			zfs_log_create(zilog, tx, txtype, dzp, zp, name,
			    vsecp, acl_ids.z_fuidp, vap);
		zfs_acl_ids_free(&acl_ids);
		have_acl = B_FALSE;
		dmu_tx_commit(tx);
	} else {
		if (have_acl) {
			zfs_acl_ids_free(&acl_ids);
			have_acl = B_FALSE;
		}
		if (excl) {
			error = SET_ERROR(EEXIST);
			goto out;
		}
		if (S_ISDIR(zp->z_mode)) {
			error = SET_ERROR(EISDIR);
			goto out;
		}
		if (mode && (error = zfs_zaccess_rwx(zp, mode, 0, cr)))
			goto out;
		if (S_ISREG(zp->z_mode) &&
		    (vap->va_mask & ATTR_SIZE) && vap->va_size == 0) {
			zfs_dirent_unlock(dl);
			dl = NULL;
			error = zfs_freesp(zp, 0, 0, mode, B_TRUE);
		}
	}
out:
	if (have_acl)
		zfs_acl_ids_free(&acl_ids);
	if (dl)
		zfs_dirent_unlock(dl);
	if (error) {
		if (zp)
			zrele(zp);
	} else {
		*zpp = zp;
	}
	if (error == 0 && zilog != NULL && zfsvfs->z_os->os_sync == ZFS_SYNC_ALWAYS)
		error = zil_commit(zilog, 0);
	zfs_exit(zfsvfs, FTAG);
	return (error);
}

int
zfs_mkdir(znode_t *dzp, char *dirname, vattr_t *vap, znode_t **zpp,
    cred_t *cr, int flags, vsecattr_t *vsecp)
{
	znode_t *zp;
	zfsvfs_t *zfsvfs = ZTOZSB(dzp);
	zilog_t *zilog;
	zfs_dirlock_t *dl;
	dmu_tx_t *tx;
	int error;
	int zf = ZNEW;
	zfs_acl_ids_t acl_ids;
	boolean_t waited = B_FALSE;
	uint64_t txtype;

	if (dirname == NULL)
		return (SET_ERROR(EINVAL));
	if ((error = zfs_enter_verify_zp(zfsvfs, dzp, FTAG)) != 0)
		return (error);
	zilog = zfsvfs->z_log;
	if (dzp->z_pflags & ZFS_XATTR) {
		zfs_exit(zfsvfs, FTAG);
		return (SET_ERROR(EINVAL));
	}
	if (flags & FIGNORECASE)
		zf |= ZCILOOK;
	if ((error = zfs_acl_ids_create(dzp, 0, vap, cr, vsecp,
	    &acl_ids, NULL)) != 0) {
		zfs_exit(zfsvfs, FTAG);
		return (error);
	}
top:
	*zpp = NULL;
	if ((error = zfs_dirent_lock(&dl, dzp, dirname, &zp, zf,
	    NULL, NULL))) {
		zfs_acl_ids_free(&acl_ids);
		zfs_exit(zfsvfs, FTAG);
		return (error);
	}
	if ((error = zfs_zaccess(dzp, ACE_ADD_SUBDIRECTORY, 0, B_FALSE, cr))) {
		zfs_acl_ids_free(&acl_ids);
		zfs_dirent_unlock(dl);
		zfs_exit(zfsvfs, FTAG);
		return (error);
	}
	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_zap(tx, dzp->z_id, TRUE, dirname);
	dmu_tx_hold_zap(tx, DMU_NEW_OBJECT, FALSE, NULL);
	dmu_tx_hold_sa(tx, dzp->z_sa_hdl, ZFS_SEQ_MAY_GROW(dzp));
	dmu_tx_hold_sa_create(tx, acl_ids.z_aclp->z_acl_bytes +
	    ZFS_SA_BASE_ATTR_SIZE);
	error = dmu_tx_assign(tx,
	    (waited ? DMU_TX_NOTHROTTLE : 0) | DMU_TX_NOWAIT);
	if (error) {
		zfs_dirent_unlock(dl);
		if (error == ERESTART) {
			waited = B_TRUE;
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		zfs_acl_ids_free(&acl_ids);
		dmu_tx_abort(tx);
		zfs_exit(zfsvfs, FTAG);
		return (error);
	}
	zfs_mknode(dzp, vap, tx, cr, 0, &zp, &acl_ids);
	error = zfs_link_create(dl, zp, tx, ZNEW);
	if (error != 0)
		zfs_znode_delete(zp, tx);
	else {
		txtype = zfs_log_create_txtype(Z_DIR, vsecp, vap);
		if (flags & FIGNORECASE)
			txtype |= TX_CI;
		if (zilog != NULL)
			zfs_log_create(zilog, tx, txtype, dzp, zp, dirname,
			    vsecp, acl_ids.z_fuidp, vap);
		*zpp = zp;
	}
	zfs_acl_ids_free(&acl_ids);
	dmu_tx_commit(tx);
	zfs_dirent_unlock(dl);
	if (error != 0)
		zrele(zp);
	else if (zilog != NULL && zfsvfs->z_os->os_sync == ZFS_SYNC_ALWAYS)
		error = zil_commit(zilog, 0);
	zfs_exit(zfsvfs, FTAG);
	return (error);
}

int
zfs_remove(znode_t *dzp, char *name, cred_t *cr, int flags)
{
	znode_t *zp;
	zfsvfs_t *zfsvfs = ZTOZSB(dzp);
	zilog_t *zilog;
	zfs_dirlock_t *dl;
	dmu_tx_t *tx;
	boolean_t unlinked;
	int error;
	int zflg = ZEXISTS;
	boolean_t waited = B_FALSE;
	uint64_t obj;

	if (name == NULL)
		return (SET_ERROR(EINVAL));
	if ((error = zfs_enter_verify_zp(zfsvfs, dzp, FTAG)) != 0)
		return (error);
	zilog = zfsvfs->z_log;
	if (flags & FIGNORECASE)
		zflg |= ZCILOOK;
top:
	if ((error = zfs_dirent_lock(&dl, dzp, name, &zp, zflg,
	    NULL, NULL))) {
		zfs_exit(zfsvfs, FTAG);
		return (error);
	}
	if ((error = zfs_zaccess_delete(dzp, zp, cr, NULL)))
		goto out;
	if (S_ISDIR(zp->z_mode)) {
		error = SET_ERROR(EPERM);
		goto out;
	}
	obj = zp->z_id;
	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_zap(tx, dzp->z_id, FALSE, name);
	dmu_tx_hold_sa(tx, zp->z_sa_hdl, ZFS_SEQ_MAY_GROW(zp));
	dmu_tx_hold_sa(tx, dzp->z_sa_hdl, ZFS_SEQ_MAY_GROW(dzp));
	dmu_tx_hold_zap(tx, zfsvfs->z_unlinkedobj, FALSE, NULL);
	dmu_tx_mark_netfree(tx);
	error = dmu_tx_assign(tx,
	    (waited ? DMU_TX_NOTHROTTLE : 0) | DMU_TX_NOWAIT);
	if (error) {
		zfs_dirent_unlock(dl);
		if (error == ERESTART) {
			waited = B_TRUE;
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			zrele(zp);
			goto top;
		}
		dmu_tx_abort(tx);
		zrele(zp);
		zfs_exit(zfsvfs, FTAG);
		return (error);
	}
	error = zfs_link_destroy(dl, zp, tx, zflg, &unlinked);
	if (error == 0 && zilog != NULL)
		zfs_log_remove(zilog, tx,
		    (flags & FIGNORECASE) ? (TX_REMOVE | TX_CI) : TX_REMOVE,
		    dzp, name, obj, unlinked);
	dmu_tx_commit(tx);
out:
	zfs_dirent_unlock(dl);
	zrele(zp);
	if (error == 0 && zilog != NULL && zfsvfs->z_os->os_sync == ZFS_SYNC_ALWAYS)
		error = zil_commit(zilog, 0);
	zfs_exit(zfsvfs, FTAG);
	return (error);
}

int
zfs_rmdir(znode_t *dzp, char *name, znode_t *cwd, cred_t *cr, int flags)
{
	znode_t *zp;
	zfsvfs_t *zfsvfs = ZTOZSB(dzp);
	zilog_t *zilog;
	zfs_dirlock_t *dl;
	dmu_tx_t *tx;
	int error;
	int zflg = ZEXISTS;
	boolean_t waited = B_FALSE;

	if (name == NULL)
		return (SET_ERROR(EINVAL));
	if ((error = zfs_enter_verify_zp(zfsvfs, dzp, FTAG)) != 0)
		return (error);
	zilog = zfsvfs->z_log;
	if (flags & FIGNORECASE)
		zflg |= ZCILOOK;
top:
	if ((error = zfs_dirent_lock(&dl, dzp, name, &zp, zflg,
	    NULL, NULL))) {
		zfs_exit(zfsvfs, FTAG);
		return (error);
	}
	if (zp == cwd) {
		error = SET_ERROR(EINVAL);
		goto out;
	}
	if (!S_ISDIR(zp->z_mode)) {
		error = SET_ERROR(ENOTDIR);
		goto out;
	}
	if ((error = zfs_zaccess_delete(dzp, zp, cr, NULL)))
		goto out;
	/*
	 * Match Linux zfs_rmdir: hold name/parent locks so lookup and
	 * rename cannot race the directory out from under us. Pass
	 * unlinkedp=NULL so zfs_link_destroy puts the dir on the
	 * unlinked list. zfs_log_remove may only see unlinked=true
	 * with TX_REMOVE (not TX_RMDIR).
	 */
	rw_enter(&zp->z_name_lock, RW_WRITER);
	rw_enter(&zp->z_parent_lock, RW_WRITER);
	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_zap(tx, dzp->z_id, FALSE, name);
	dmu_tx_hold_sa(tx, zp->z_sa_hdl, ZFS_SEQ_MAY_GROW(zp));
	dmu_tx_hold_sa(tx, dzp->z_sa_hdl, ZFS_SEQ_MAY_GROW(dzp));
	dmu_tx_hold_zap(tx, zfsvfs->z_unlinkedobj, FALSE, NULL);
	dmu_tx_mark_netfree(tx);
	error = dmu_tx_assign(tx,
	    (waited ? DMU_TX_NOTHROTTLE : 0) | DMU_TX_NOWAIT);
	if (error) {
		rw_exit(&zp->z_parent_lock);
		rw_exit(&zp->z_name_lock);
		zfs_dirent_unlock(dl);
		if (error == ERESTART) {
			waited = B_TRUE;
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			zrele(zp);
			goto top;
		}
		dmu_tx_abort(tx);
		zrele(zp);
		zfs_exit(zfsvfs, FTAG);
		return (error);
	}
	error = zfs_link_destroy(dl, zp, tx, zflg, NULL);
	if (error == 0) {
		uint64_t txtype = TX_RMDIR;
		if (flags & FIGNORECASE)
			txtype |= TX_CI;
		zfs_log_remove(zilog, tx, txtype, dzp, name, ZFS_NO_OBJECT,
		    B_FALSE);
	}
	dmu_tx_commit(tx);
	rw_exit(&zp->z_parent_lock);
	rw_exit(&zp->z_name_lock);
out:
	zfs_dirent_unlock(dl);
	zrele(zp);
	if (error == 0 && zilog != NULL && zfsvfs->z_os->os_sync == ZFS_SYNC_ALWAYS)
		error = zil_commit(zilog, 0);
	zfs_exit(zfsvfs, FTAG);
	return (error);
}

int
zfs_readdir(znode_t *zp, void *dirent, cred_t *cr, int *eofp, uint64_t *offp,
    int (*filler)(void *, const char *, int, loff_t, ino_t, unsigned))
{
	zfsvfs_t *zfsvfs = ZTOZSB(zp);
	zap_cursor_t zc;
	zap_attribute_t *za;
	int error;
	uint64_t offset;

	(void) cr;
	if ((error = zfs_enter_verify_zp(zfsvfs, zp, FTAG)) != 0)
		return (error);
	if (!S_ISDIR(zp->z_mode)) {
		zfs_exit(zfsvfs, FTAG);
		return (SET_ERROR(ENOTDIR));
	}
	offset = *offp;
	za = zap_attribute_alloc();
	if (offset == 0) {
		if (filler(dirent, ".", 1, 1, zp->z_id, DT_DIR) != 0)
			goto done;
		offset = 1;
	}
	if (offset == 1) {
		uint64_t parent = zp->z_id;

		(void) sa_lookup(zp->z_sa_hdl, SA_ZPL_PARENT(zfsvfs),
		    &parent, sizeof (parent));
		if (filler(dirent, "..", 2, 2, (ino_t)parent, DT_DIR) != 0)
			goto done;
		offset = 2;
	}
	if (offset <= 2)
		zap_cursor_init(&zc, zfsvfs->z_os, zp->z_id);
	else
		zap_cursor_init_serialized(&zc, zfsvfs->z_os, zp->z_id, offset);
	while ((error = zap_cursor_retrieve(&zc, za)) == 0) {
		uint64_t obj = ZFS_DIRENT_OBJ(za->za_first_integer);
		unsigned type = ZFS_DIRENT_TYPE(za->za_first_integer);
		uint64_t next = zap_cursor_serialize(&zc);

		if (filler(dirent, za->za_name, strlen(za->za_name),
		    (loff_t)next, (ino_t)obj, type ? type : DT_UNKNOWN) != 0)
			break;
		offset = next;
		zap_cursor_advance(&zc);
	}
	if (error == ENOENT) {
		error = 0;
		if (eofp)
			*eofp = 1;
	}
	zap_cursor_fini(&zc);
done:
	*offp = offset;
	zap_attribute_free(za);
	zfs_exit(zfsvfs, FTAG);
	return (error);
}

int
zfs_setattr(znode_t *zp, vattr_t *vap, int flag, cred_t *cr)
{
	zfsvfs_t *zfsvfs = ZTOZSB(zp);
	zilog_t *zilog;
	dmu_tx_t *tx;
	uint_t mask = vap->va_mask;
	sa_bulk_attr_t bulk[8];
	int count = 0;
	int error, aclerr = 0;
	uint64_t mtime[2], ctime[2], atime[2];
	uint64_t uid, gid, mode;
	uint64_t old_uid, old_gid, old_mode, old_pflags;
	inode_timespec_t old_atime, old_mtime, old_ctime;
	vattr_t oldva;
	zfs_acl_t *aclp = NULL;
	uint64_t new_mode;

	(void) flag;
	if ((error = zfs_enter_verify_zp(zfsvfs, zp, FTAG)) != 0)
		return (error);
	zilog = zfsvfs->z_log;
	if ((zp->z_pflags & (ZFS_IMMUTABLE | ZFS_READONLY)) &&
	    (mask & (ATTR_SIZE | ATTR_MODE | ATTR_UID | ATTR_GID | ATTR_MTIME))) {
		zfs_exit(zfsvfs, FTAG);
		return (SET_ERROR(EPERM));
	}
	if ((mask & ATTR_SIZE) && S_ISDIR(zp->z_mode)) {
		zfs_exit(zfsvfs, FTAG);
		return (SET_ERROR(EISDIR));
	}
	if (mask & AT_XVATTR) {
		error = secpolicy_xvattr((xvattr_t *)vap, (uid_t)zp->z_uid,
		    cr, zp->z_mode);
		if (error) {
			zfs_exit(zfsvfs, FTAG);
			return (error);
		}
	}
	memset(&oldva, 0, sizeof (oldva));
	mutex_enter(&zp->z_lock);
	oldva.va_mode = zp->z_mode;
	oldva.va_uid = (uid_t)zp->z_uid;
	oldva.va_gid = (gid_t)zp->z_gid;
	mutex_exit(&zp->z_lock);
	error = secpolicy_vnode_setattr(cr, NULL, vap, &oldva, flag,
	    zfs_zaccess_unix, zp);
	if (error) {
		zfs_exit(zfsvfs, FTAG);
		return (error);
	}
	if ((mask & ATTR_UID) && vap->va_uid != oldva.va_uid &&
	    zfs_id_overquota(zfsvfs, DMU_USERUSED_OBJECT, vap->va_uid)) {
		zfs_exit(zfsvfs, FTAG);
		return (SET_ERROR(EDQUOT));
	}
	if ((mask & ATTR_GID) && vap->va_gid != oldva.va_gid &&
	    zfs_id_overquota(zfsvfs, DMU_GROUPUSED_OBJECT, vap->va_gid)) {
		zfs_exit(zfsvfs, FTAG);
		return (SET_ERROR(EDQUOT));
	}
	if ((mask & ATTR_MODE) &&
	    zfsvfs->z_acl_mode == ZFS_ACL_RESTRICTED &&
	    !(zp->z_pflags & ZFS_ACL_TRIVIAL)) {
		zfs_exit(zfsvfs, FTAG);
		return (SET_ERROR(EPERM));
	}
	if (mask & ATTR_SIZE) {
		error = zfs_freesp(zp, vap->va_size, 0, 0, B_TRUE);
		if (error) {
			zfs_exit(zfsvfs, FTAG);
			return (error);
		}
	}
	if (mask & ATTR_MODE) {
		new_mode = (zp->z_mode & S_IFMT) | (vap->va_mode & ~S_IFMT);
		error = zfs_acl_chmod_setattr(zp, &aclp, new_mode);
		if (error) {
			zfs_exit(zfsvfs, FTAG);
			return (error);
		}
	}
	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_sa(tx, zp->z_sa_hdl, (mask & ATTR_MODE) ? B_TRUE : B_FALSE);
	error = dmu_tx_assign(tx, DMU_TX_WAIT);
	if (error) {
		dmu_tx_abort(tx);
		if (aclp != NULL)
			zfs_acl_free(aclp);
		zfs_exit(zfsvfs, FTAG);
		return (error);
	}
	if (mask & (ATTR_UID | ATTR_GID | ATTR_MODE))
		mutex_enter(&zp->z_acl_lock);
	mutex_enter(&zp->z_lock);
	old_uid = zp->z_uid;
	old_gid = zp->z_gid;
	old_mode = zp->z_mode;
	old_pflags = zp->z_pflags;
	old_atime = zp->z_atime;
	old_mtime = zp->z_mtime;
	old_ctime = zp->z_ctime;
	uid = zp->z_uid;
	gid = zp->z_gid;
	mode = zp->z_mode;
	ZFS_TIME_ENCODE(&zp->z_atime, atime);
	ZFS_TIME_ENCODE(&zp->z_mtime, mtime);
	ZFS_TIME_ENCODE(&zp->z_ctime, ctime);
	if (mask & ATTR_UID) {
		uid = vap->va_uid;
		zp->z_uid = uid;
		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_UID(zfsvfs), NULL,
		    &uid, 8);
	}
	if (mask & ATTR_GID) {
		gid = vap->va_gid;
		zp->z_gid = gid;
		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_GID(zfsvfs), NULL,
		    &gid, 8);
	}
	if (mask & ATTR_MODE) {
		mode = (mode & S_IFMT) | (vap->va_mode & ~S_IFMT);
		zp->z_mode = mode;
		if (aclp != NULL) {
			aclerr = zfs_aclset_common(zp, aclp, cr, tx);
			if (aclerr == 0) {
				if (zp->z_acl_cached &&
				    zp->z_acl_cached != aclp)
					zfs_acl_free(zp->z_acl_cached);
				zp->z_acl_cached = aclp;
				aclp = NULL;
				mode = zp->z_mode;
			}
		} else {
			SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_MODE(zfsvfs), NULL,
			    &mode, 8);
		}
	}
	if ((mask & (ATTR_UID | ATTR_GID)) && !(mask & ATTR_MODE)) {
		aclerr = zfs_acl_chown_setattr(zp);
		if (aclerr == 0) {
			mode = zp->z_mode;
			SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_MODE(zfsvfs),
			    NULL, &mode, 8);
		}
	}
	if (mask & ATTR_ATIME)
		ZFS_TIME_ENCODE(&vap->va_atime, atime);
	if (mask & (ATTR_MTIME | ATTR_CTIME | ATTR_MODE | ATTR_UID | ATTR_GID |
	    ATTR_ATIME | ATTR_SIZE))
		zfs_tstamp_update_setup(zp, STATE_CHANGED, mtime, ctime);
	if (mask & ATTR_MTIME)
		ZFS_TIME_ENCODE(&vap->va_mtime, mtime);
	if (mask & ATTR_ATIME) {
		ZFS_TIME_DECODE(&zp->z_atime, atime);
		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_ATIME(zfsvfs), NULL,
		    atime, 16);
	}
	if (mask & (ATTR_MTIME | ATTR_MODE | ATTR_UID | ATTR_GID | ATTR_SIZE)) {
		ZFS_TIME_DECODE(&zp->z_mtime, mtime);
		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_MTIME(zfsvfs), NULL,
		    mtime, 16);
	}
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_CTIME(zfsvfs), NULL, ctime, 16);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_FLAGS(zfsvfs), NULL,
	    &zp->z_pflags, 8);
	if (mask & AT_XVATTR)
		zfs_xvattr_set(zp, (xvattr_t *)vap, tx);
	error = sa_bulk_update(zp->z_sa_hdl, bulk, count, tx);
	if (error == 0)
		error = aclerr;
	if (error != 0) {
		zp->z_uid = old_uid;
		zp->z_gid = old_gid;
		zp->z_mode = old_mode;
		zp->z_pflags = old_pflags;
		zp->z_atime = old_atime;
		zp->z_mtime = old_mtime;
		zp->z_ctime = old_ctime;
	} else {
		zp->z_uid = uid;
		zp->z_gid = gid;
		zp->z_mode = mode;
		ZFS_TIME_DECODE(&zp->z_ctime, ctime);
	}
	mutex_exit(&zp->z_lock);
	if (mask & (ATTR_UID | ATTR_GID | ATTR_MODE))
		mutex_exit(&zp->z_acl_lock);
	if (aclp != NULL)
		zfs_acl_free(aclp);
	if (error == 0 && zilog != NULL)
		zfs_log_setattr(zilog, tx, TX_SETATTR, zp, vap, mask, NULL);
	dmu_tx_commit(tx);
	if (error == 0 && zilog != NULL &&
	    zfsvfs->z_os->os_sync == ZFS_SYNC_ALWAYS)
		error = zil_commit(zilog, 0);
	zfs_exit(zfsvfs, FTAG);
	return (error);
}

typedef struct zfs_zlock {
	krwlock_t	*zl_rwlock;
	znode_t		*zl_znode;
	struct zfs_zlock *zl_next;
} zfs_zlock_t;

static void
zfs_rename_unlock(zfs_zlock_t **zlpp)
{
	zfs_zlock_t *zl;

	while ((zl = *zlpp) != NULL) {
		if (zl->zl_znode != NULL)
			zfs_zrele_async(zl->zl_znode);
		rw_exit(zl->zl_rwlock);
		*zlpp = zl->zl_next;
		kmem_free(zl, sizeof (*zl));
	}
}

static int
zfs_rename_lock(znode_t *szp, znode_t *tdzp, znode_t *sdzp, zfs_zlock_t **zlpp)
{
	zfs_zlock_t *zl;
	znode_t *zp = tdzp;
	uint64_t rootid = ZTOZSB(zp)->z_root;
	uint64_t oidp = zp->z_id;
	krwlock_t *rwlp = &szp->z_parent_lock;
	krw_t rw = RW_WRITER;

	do {
		if (!rw_tryenter(rwlp, rw)) {
			if (rw == RW_READER && zp->z_id > szp->z_id) {
				zfs_rename_unlock(zlpp);
				*zlpp = NULL;
				zp = tdzp;
				oidp = zp->z_id;
				rwlp = &szp->z_parent_lock;
				rw = RW_WRITER;
				continue;
			}
			rw_enter(rwlp, rw);
		}
		zl = kmem_alloc(sizeof (*zl), KM_SLEEP);
		zl->zl_rwlock = rwlp;
		zl->zl_znode = NULL;
		zl->zl_next = *zlpp;
		*zlpp = zl;
		if (oidp == szp->z_id)
			return (SET_ERROR(EINVAL));
		if (oidp == rootid)
			return (0);
		if (rw == RW_READER) {
			int error = zfs_zget(ZTOZSB(zp), oidp, &zp);
			if (error)
				return (error);
			zl->zl_znode = zp;
		}
		(void) sa_lookup(zp->z_sa_hdl, SA_ZPL_PARENT(ZTOZSB(zp)),
		    &oidp, sizeof (oidp));
		rwlp = &zp->z_parent_lock;
		rw = RW_READER;
	} while (zp->z_id != sdzp->z_id);
	return (0);
}

int
zfs_rename(znode_t *sdzp, char *snm, znode_t *tdzp, char *tnm, cred_t *cr,
    int flags, uint64_t rflags, vattr_t *wo_vap)
{
	znode_t *szp = NULL, *tzp = NULL;
	zfsvfs_t *zfsvfs = ZTOZSB(sdzp);
	zilog_t *zilog;
	zfs_dirlock_t *sdl = NULL, *tdl = NULL;
	dmu_tx_t *tx;
	zfs_zlock_t *zl = NULL;
	int error;
	int zflg = 0;
	boolean_t waited = B_FALSE;

	(void) wo_vap;
	if (snm == NULL || tnm == NULL)
		return (SET_ERROR(EINVAL));
	if (rflags & RENAME_EXCHANGE)
		return (SET_ERROR(ENOTSUP));
	if (rflags & ~(RENAME_NOREPLACE))
		return (SET_ERROR(EINVAL));
	if ((error = zfs_enter_verify_zp(zfsvfs, sdzp, FTAG)) != 0)
		return (error);
	if (ZTOZSB(tdzp) != zfsvfs) {
		zfs_exit(zfsvfs, FTAG);
		return (SET_ERROR(EXDEV));
	}
	if ((error = zfs_verify_zp(tdzp)) != 0) {
		zfs_exit(zfsvfs, FTAG);
		return (error);
	}
	if ((tdzp->z_pflags & ZFS_XATTR) != (sdzp->z_pflags & ZFS_XATTR)) {
		zfs_exit(zfsvfs, FTAG);
		return (SET_ERROR(EINVAL));
	}
	zilog = zfsvfs->z_log;
	if (flags & FIGNORECASE)
		zflg |= ZCILOOK;
	if (sdzp == tdzp && strcmp(snm, tnm) == 0) {
		zfs_exit(zfsvfs, FTAG);
		return (0);
	}
top:
	/*
	 * Same directory: take z_name_lock once. A second rw_enter
	 * (glibc writer-preferring pthread_rwlock) deadlocks if a
	 * writer arrives between the two dirent_lock calls.
	 */
	if (sdzp == tdzp) {
		zflg |= ZHAVELOCK;
		rw_enter(&sdzp->z_name_lock, RW_READER);
	}
	if (sdzp->z_id < tdzp->z_id) {
		error = zfs_dirent_lock(&sdl, sdzp, snm, &szp,
		    ZEXISTS | zflg, NULL, NULL);
		if (error == 0) {
			error = zfs_dirent_lock(&tdl, tdzp, tnm, &tzp,
			    zflg, NULL, NULL);
		}
	} else {
		error = zfs_dirent_lock(&tdl, tdzp, tnm, &tzp,
		    zflg, NULL, NULL);
		if (error == 0) {
			error = zfs_dirent_lock(&sdl, sdzp, snm, &szp,
			    ZEXISTS | zflg, NULL, NULL);
		}
	}
	if (error) {
		if (sdl) {
			zfs_dirent_unlock(sdl);
			sdl = NULL;
		}
		if (tdl) {
			zfs_dirent_unlock(tdl);
			tdl = NULL;
		}
		if (szp) {
			zrele(szp);
			szp = NULL;
		}
		if (tzp) {
			zrele(tzp);
			tzp = NULL;
		}
		if (sdzp == tdzp)
			rw_exit(&sdzp->z_name_lock);
		zfs_exit(zfsvfs, FTAG);
		return (error);
	}
	if ((error = zfs_zaccess_rename(sdzp, szp, tdzp, tzp, cr, NULL)))
		goto out;
	if (S_ISDIR(szp->z_mode)) {
		error = zfs_rename_lock(szp, tdzp, sdzp, &zl);
		if (error)
			goto out;
	}
	if (tzp != NULL) {
		if (rflags & RENAME_NOREPLACE) {
			error = SET_ERROR(EEXIST);
			goto out;
		}
		if (S_ISDIR(szp->z_mode) != S_ISDIR(tzp->z_mode)) {
			error = SET_ERROR(S_ISDIR(tzp->z_mode) ? EISDIR :
			    ENOTDIR);
			goto out;
		}
	}
	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_sa(tx, szp->z_sa_hdl, ZFS_SEQ_MAY_GROW(szp));
	dmu_tx_hold_sa(tx, sdzp->z_sa_hdl, ZFS_SEQ_MAY_GROW(sdzp));
	dmu_tx_hold_zap(tx, sdzp->z_id, FALSE, snm);
	dmu_tx_hold_zap(tx, tdzp->z_id, TRUE, tnm);
	if (sdzp != tdzp) {
		dmu_tx_hold_sa(tx, tdzp->z_sa_hdl, ZFS_SEQ_MAY_GROW(tdzp));
	}
	if (tzp)
		dmu_tx_hold_sa(tx, tzp->z_sa_hdl, ZFS_SEQ_MAY_GROW(tzp));
	error = dmu_tx_assign(tx,
	    (waited ? DMU_TX_NOTHROTTLE : 0) | DMU_TX_NOWAIT);
	if (error) {
		if (zl) {
			zfs_rename_unlock(&zl);
			zl = NULL;
		}
		zfs_dirent_unlock(sdl);
		zfs_dirent_unlock(tdl);
		sdl = tdl = NULL;
		if (sdzp == tdzp)
			rw_exit(&sdzp->z_name_lock);
		if (error == ERESTART) {
			waited = B_TRUE;
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			zrele(szp);
			if (tzp)
				zrele(tzp);
			szp = tzp = NULL;
			goto top;
		}
		dmu_tx_abort(tx);
		zrele(szp);
		if (tzp)
			zrele(tzp);
		zfs_exit(zfsvfs, FTAG);
		return (error);
	}
	if (tzp)
		error = zfs_link_destroy(tdl, tzp, tx, zflg, NULL);
	if (error == 0)
		error = zfs_link_create(tdl, szp, tx, ZRENAMING);
	if (error == 0)
		error = zfs_link_destroy(sdl, szp, tx, ZRENAMING, NULL);
	if (error == 0 && zilog != NULL)
		zfs_log_rename(zilog, tx,
		    (flags & FIGNORECASE) ? (TX_RENAME | TX_CI) : TX_RENAME,
		    sdzp, snm, tdzp, tnm, szp);
	dmu_tx_commit(tx);
out:
	if (zl)
		zfs_rename_unlock(&zl);
	if (sdl)
		zfs_dirent_unlock(sdl);
	if (tdl)
		zfs_dirent_unlock(tdl);
	if (sdzp == tdzp)
		rw_exit(&sdzp->z_name_lock);
	if (szp)
		zrele(szp);
	if (tzp)
		zrele(tzp);
	if (error == 0 && zilog != NULL && zfsvfs->z_os->os_sync == ZFS_SYNC_ALWAYS)
		error = zil_commit(zilog, 0);
	zfs_exit(zfsvfs, FTAG);
	return (error);
}

int
zfs_symlink(znode_t *dzp, char *name, vattr_t *vap, char *link,
    znode_t **zpp, cred_t *cr, int flags)
{
	znode_t *zp;
	zfs_dirlock_t *dl;
	dmu_tx_t *tx;
	zfsvfs_t *zfsvfs = ZTOZSB(dzp);
	zilog_t *zilog;
	uint64_t len = strlen(link);
	int error;
	int zflg = ZNEW;
	zfs_acl_ids_t acl_ids;
	boolean_t waited = B_FALSE;
	uint64_t txtype = TX_SYMLINK;

	if (name == NULL)
		return (SET_ERROR(EINVAL));
	if ((error = zfs_enter_verify_zp(zfsvfs, dzp, FTAG)) != 0)
		return (error);
	zilog = zfsvfs->z_log;
	if (len > MAXPATHLEN) {
		zfs_exit(zfsvfs, FTAG);
		return (SET_ERROR(ENAMETOOLONG));
	}
	if (flags & FIGNORECASE)
		zflg |= ZCILOOK;
	if ((error = zfs_acl_ids_create(dzp, 0, vap, cr, NULL,
	    &acl_ids, NULL)) != 0) {
		zfs_exit(zfsvfs, FTAG);
		return (error);
	}
top:
	*zpp = NULL;
	error = zfs_dirent_lock(&dl, dzp, name, &zp, zflg, NULL, NULL);
	if (error) {
		zfs_acl_ids_free(&acl_ids);
		zfs_exit(zfsvfs, FTAG);
		return (error);
	}
	if ((error = zfs_zaccess(dzp, ACE_ADD_FILE, 0, B_FALSE, cr))) {
		zfs_acl_ids_free(&acl_ids);
		zfs_dirent_unlock(dl);
		zfs_exit(zfsvfs, FTAG);
		return (error);
	}
	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_write(tx, DMU_NEW_OBJECT, 0, MAX(1, len));
	dmu_tx_hold_zap(tx, dzp->z_id, TRUE, name);
	dmu_tx_hold_sa_create(tx, acl_ids.z_aclp->z_acl_bytes +
	    ZFS_SA_BASE_ATTR_SIZE + len);
	dmu_tx_hold_sa(tx, dzp->z_sa_hdl, ZFS_SEQ_MAY_GROW(dzp));
	error = dmu_tx_assign(tx,
	    (waited ? DMU_TX_NOTHROTTLE : 0) | DMU_TX_NOWAIT);
	if (error) {
		zfs_dirent_unlock(dl);
		if (error == ERESTART) {
			waited = B_TRUE;
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		zfs_acl_ids_free(&acl_ids);
		dmu_tx_abort(tx);
		zfs_exit(zfsvfs, FTAG);
		return (error);
	}
	zfs_mknode(dzp, vap, tx, cr, 0, &zp, &acl_ids);
	mutex_enter(&zp->z_lock);
	if (zp->z_is_sa)
		error = sa_update(zp->z_sa_hdl, SA_ZPL_SYMLINK(zfsvfs),
		    link, len, tx);
	else
		zfs_sa_symlink(zp, link, len, tx);
	mutex_exit(&zp->z_lock);
	zp->z_size = len;
	(void) sa_update(zp->z_sa_hdl, SA_ZPL_SIZE(zfsvfs),
	    &zp->z_size, sizeof (zp->z_size), tx);
	error = zfs_link_create(dl, zp, tx, ZNEW);
	if (error != 0)
		zfs_znode_delete(zp, tx);
	else if (zilog != NULL) {
		if (flags & FIGNORECASE)
			txtype |= TX_CI;
		zfs_log_symlink(zilog, tx, txtype, dzp, zp, name, link);
	}
	zfs_acl_ids_free(&acl_ids);
	dmu_tx_commit(tx);
	zfs_dirent_unlock(dl);
	if (error == 0)
		*zpp = zp;
	else
		zrele(zp);
	if (error == 0 && zilog != NULL && zfsvfs->z_os->os_sync == ZFS_SYNC_ALWAYS)
		error = zil_commit(zilog, 0);
	zfs_exit(zfsvfs, FTAG);
	return (error);
}

int
zfs_readlink(znode_t *zp, zfs_uio_t *uio, cred_t *cr)
{
	zfsvfs_t *zfsvfs = ZTOZSB(zp);
	int error;
	void *buf;

	(void) cr;
	if ((error = zfs_enter_verify_zp(zfsvfs, zp, FTAG)) != 0)
		return (error);
	mutex_enter(&zp->z_lock);
	if (zp->z_is_sa) {
		buf = kmem_alloc(zp->z_size + 1, KM_SLEEP);
		error = sa_lookup(zp->z_sa_hdl, SA_ZPL_SYMLINK(zfsvfs),
		    buf, zp->z_size);
		if (error == 0)
			error = zfs_uiomove(buf, zp->z_size, UIO_READ, uio);
		kmem_free(buf, zp->z_size + 1);
	} else {
		error = zfs_sa_readlink(zp, uio);
	}
	mutex_exit(&zp->z_lock);
	zfs_exit(zfsvfs, FTAG);
	return (error);
}

int
zfs_link(znode_t *tdzp, znode_t *szp, char *name, cred_t *cr, int flags)
{
	znode_t *tzp;
	zfsvfs_t *zfsvfs = ZTOZSB(tdzp);
	zilog_t *zilog;
	zfs_dirlock_t *dl;
	dmu_tx_t *tx;
	int error;
	int zf = ZNEW;
	boolean_t waited = B_FALSE;

	if (name == NULL)
		return (SET_ERROR(EINVAL));
	if ((error = zfs_enter_verify_zp(zfsvfs, tdzp, FTAG)) != 0)
		return (error);
	zilog = zfsvfs->z_log;
	if (S_ISDIR(szp->z_mode)) {
		zfs_exit(zfsvfs, FTAG);
		return (SET_ERROR(EPERM));
	}
	if ((error = zfs_verify_zp(szp)) != 0) {
		zfs_exit(zfsvfs, FTAG);
		return (error);
	}
	if (ZTOZSB(szp) != zfsvfs) {
		zfs_exit(zfsvfs, FTAG);
		return (SET_ERROR(EXDEV));
	}
	if ((szp->z_pflags & ZFS_XATTR) != (tdzp->z_pflags & ZFS_XATTR)) {
		zfs_exit(zfsvfs, FTAG);
		return (SET_ERROR(EINVAL));
	}
	if ((error = zfs_zaccess(tdzp, ACE_ADD_FILE, 0, B_FALSE, cr))) {
		zfs_exit(zfsvfs, FTAG);
		return (error);
	}
	if (flags & FIGNORECASE)
		zf |= ZCILOOK;
top:
	error = zfs_dirent_lock(&dl, tdzp, name, &tzp, zf, NULL, NULL);
	if (error) {
		zfs_exit(zfsvfs, FTAG);
		return (error);
	}
	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_sa(tx, szp->z_sa_hdl, ZFS_SEQ_MAY_GROW(szp));
	dmu_tx_hold_zap(tx, tdzp->z_id, TRUE, name);
	dmu_tx_hold_sa(tx, tdzp->z_sa_hdl, ZFS_SEQ_MAY_GROW(tdzp));
	error = dmu_tx_assign(tx,
	    (waited ? DMU_TX_NOTHROTTLE : 0) | DMU_TX_NOWAIT);
	if (error) {
		zfs_dirent_unlock(dl);
		if (error == ERESTART) {
			waited = B_TRUE;
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		zfs_exit(zfsvfs, FTAG);
		return (error);
	}
	error = zfs_link_create(dl, szp, tx, 0);
	if (error == 0 && zilog != NULL)
		zfs_log_link(zilog, tx, TX_LINK, tdzp, szp, name);
	dmu_tx_commit(tx);
	zfs_dirent_unlock(dl);
	if (error == 0 && zilog != NULL && zfsvfs->z_os->os_sync == ZFS_SYNC_ALWAYS)
		error = zil_commit(zilog, 0);
	zfs_exit(zfsvfs, FTAG);
	return (error);
}

int
zfs_space(znode_t *zp, int cmd, flock64_t *bfp, int flag, offset_t offset,
    cred_t *cr)
{
	zfsvfs_t *zfsvfs = ZTOZSB(zp);
	int error;

	(void) offset;
	(void) cr;
	if (cmd != F_FREESP)
		return (SET_ERROR(EINVAL));
	if (bfp == NULL || bfp->l_start < 0 || bfp->l_len < 0)
		return (SET_ERROR(EINVAL));
	if ((error = zfs_enter_verify_zp(zfsvfs, zp, FTAG)) != 0)

		return (error);
	error = zfs_freesp(zp, bfp->l_start, bfp->l_len, flag, B_TRUE);
	zfs_exit(zfsvfs, FTAG);
	return (error);
}

void
zfs_inactive(znode_t *zp)
{
	(void) zp;
}
