// SPDX-License-Identifier: CDDL-1.0
/*
 * secpolicy_* used by module/zfs/zfs_vnops.c and zfsd ioctl
 * authorization (mount/share/destroy delegations).
 */

#include <sys/zfs_context.h>
#include <sys/zfs_vfsops.h>
#include <sys/zfs_znode.h>
#include <sys/policy.h>
#include <sys/vnode.h>
#include <sys/xvattr.h>
#include <sys/cred.h>
#include <sys/fs/zfs.h>
#include <sys/zfs_ioctl.h>
#include <sys/dsl_deleg.h>
#include <sys/zfsd.h>
#include <zfs_namecheck.h>
#include "zfsd_impl.h"
#include <sys/stat.h>
#include <string.h>

int
secpolicy_vnode_setid_retain(znode_t *zp, const cred_t *cr, boolean_t issuid)
{
	(void) zp;
	(void) issuid;
	return (crgetuid((cred_t *)cr) == 0 ? 0 : SET_ERROR(EPERM));
}

int
secpolicy_xvattr(xvattr_t *xvap, uid_t uid, cred_t *cr, mode_t mode)
{
	(void) mode;
	if (crgetuid(cr) == 0)
		return (0);
	if (xvap != NULL && (XVA_ISSET_REQ(xvap, XAT_IMMUTABLE) ||
	    XVA_ISSET_REQ(xvap, XAT_APPENDONLY)))
		return (SET_ERROR(EPERM));
	if (crgetuid(cr) == uid)
		return (0);
	return (SET_ERROR(EPERM));
}

int
secpolicy_vnode_access2(const cred_t *cr, struct inode *ip,
    uid_t owner, mode_t cur, mode_t want)
{
	mode_t missing;

	(void) ip;
	(void) owner;
	missing = ~cur & want;
	if (missing == 0)
		return (0);
	if (crgetuid((cred_t *)cr) != 0)
		return (SET_ERROR(EACCES));
	/*
	 * generic_permission: CAP_DAC_OVERRIDE for read/write; exec
	 * only if some execute bit is set, not solely S_IXUSR.
	 */
	if ((want & S_IXUSR) != 0 &&
	    (cur & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0)
		return (SET_ERROR(EACCES));
	return (0);
}

int
secpolicy_vnode_setdac(const cred_t *cr, uid_t owner)
{
	uid_t uid = crgetuid((cred_t *)cr);

	if (uid == 0 || uid == owner)
		return (0);
	return (SET_ERROR(EPERM));
}

int
secpolicy_vnode_chown(const cred_t *cr, uid_t owner)
{
	(void) owner;
	return (crgetuid((cred_t *)cr) == 0 ? 0 : SET_ERROR(EPERM));
}

int
secpolicy_vnode_remove(const cred_t *cr)
{
	return (crgetuid((cred_t *)cr) == 0 ? 0 : SET_ERROR(EPERM));
}

int
secpolicy_vnode_create_gid(const cred_t *cr)
{
	return (crgetuid((cred_t *)cr) == 0 ? 0 : SET_ERROR(EPERM));
}

int
secpolicy_basic_link(const cred_t *cr)
{
	return (crgetuid((cred_t *)cr) == 0 ? 0 : SET_ERROR(EPERM));
}

void
secpolicy_setid_clear(vattr_t *vap, cred_t *cr)
{
	if (crgetuid(cr) != 0)
		vap->va_mode &= ~(S_ISUID | S_ISGID);
}

int
secpolicy_setid_setsticky_clear(struct inode *ip, vattr_t *vap,
    const vattr_t *ovap, cred_t *cr)
{
	(void) ip;
	if ((vap->va_mode & S_ISUID) != 0 &&
	    crgetuid(cr) != ovap->va_uid && crgetuid(cr) != 0)
		return (SET_ERROR(EPERM));
	if (!S_ISDIR(ovap->va_mode) && (vap->va_mode & S_ISVTX) != 0 &&
	    crgetuid(cr) != 0)
		vap->va_mode &= ~S_ISVTX;
	if ((vap->va_mode & S_ISGID) != 0 && crgetuid(cr) != 0 &&
	    !groupmember(ovap->va_gid, cr))
		vap->va_mode &= ~S_ISGID;
	return (0);
}

int
secpolicy_vnode_setattr(cred_t *cr, struct inode *ip, vattr_t *vap,
    const vattr_t *ovap, int flags,
    int (*unlocked_access)(void *, int, cred_t *), void *node)
{
	uint_t mask = vap->va_mask;
	int error;

	(void) flags;
	if (mask & ATTR_SIZE) {
		if (S_ISDIR(ovap->va_mode))
			return (SET_ERROR(EISDIR));
		error = unlocked_access(node, S_IWUSR, cr);
		if (error)
			return (error);
	}
	if (mask & ATTR_MODE) {
		error = secpolicy_vnode_setdac(cr, ovap->va_uid);
		if (error)
			return (error);
		error = secpolicy_setid_setsticky_clear(ip, vap, ovap, cr);
		if (error)
			return (error);
	}
	if (mask & (ATTR_UID | ATTR_GID)) {
		error = secpolicy_vnode_setdac(cr, ovap->va_uid);
		if (error)
			return (error);
		if ((mask & ATTR_UID) && vap->va_uid != ovap->va_uid) {
			error = secpolicy_vnode_chown(cr, vap->va_uid);
			if (error)
				return (error);
		}
		if ((mask & ATTR_GID) && vap->va_gid != ovap->va_gid &&
		    crgetuid(cr) != 0 && !groupmember(vap->va_gid, cr))
			return (SET_ERROR(EPERM));
		if (((mask & ATTR_UID) && vap->va_uid != ovap->va_uid) ||
		    ((mask & ATTR_GID) && vap->va_gid != ovap->va_gid))
			secpolicy_setid_clear(vap, cr);
	}
	if (mask & (ATTR_ATIME | ATTR_MTIME)) {
		error = secpolicy_vnode_setdac(cr, ovap->va_uid);
		if (error) {
			if ((vap->va_vaflags & VA_UTIMES_NULL) == 0)
				return (error);
			error = unlocked_access(node, S_IWUSR, cr);
			if (error)
				return (error);
		}
	}
	return (0);
}

int
secpolicy_zfs(const cred_t *cr)
{
	return (crgetuid((cred_t *)cr) == 0 ? 0 : SET_ERROR(EPERM));
}

int
secpolicy_sys_config(const cred_t *cr, boolean_t checkonly)
{
	(void) checkonly;
	return (secpolicy_zfs(cr));
}

int
secpolicy_zinject(const cred_t *cr)
{
	return (secpolicy_zfs(cr));
}

/*
 * uid 0, or zfs allow ... mount. ECANCELED (delegations off) is EPERM.
 */
int
zfsd_allow_mount(const char *ds)
{
	int err;

	if (secpolicy_zfs(CRED()) == 0)
		return (0);
	if (ds == NULL || ds[0] == '\0')
		return (EPERM);
	err = dsl_deleg_access(ds, ZFS_DELEG_PERM_MOUNT, CRED());
	return (err == 0 ? 0 : EPERM);
}

int
zfsd_allow_destroy(const char *ds)
{
	int err;

	if (secpolicy_zfs(CRED()) == 0)
		return (0);
	if (ds == NULL || ds[0] == '\0')
		return (EPERM);
	err = dsl_deleg_access(ds, ZFS_DELEG_PERM_DESTROY, CRED());
	return (err == 0 ? 0 : EPERM);
}

/*
 * uid 0, or zfs allow ... share. The daemon does the privileged
 * NFS/SMB work (exports file, exportfs, net usershare).
 */
int
zfsd_allow_share(const char *ds)
{
	int err;

	if (secpolicy_zfs(CRED()) == 0)
		return (0);
	if (ds == NULL || ds[0] == '\0')
		return (EPERM);
	err = dsl_deleg_access(ds, ZFS_DELEG_PERM_SHARE, CRED());
	return (err == 0 ? 0 : EPERM);
}

int
zfs_secpolicy_zfsd_mount(zfs_cmd_t *zc, nvlist_t *innvl, cred_t *cr)
{
	(void) innvl;
	if (secpolicy_zfs(cr) == 0)
		return (0);
	if (zc->zc_name[0] == '\0')
		return (SET_ERROR(EPERM));
	if (entity_namecheck(zc->zc_name, NULL, NULL) != 0)
		return (SET_ERROR(EINVAL));
	return (dsl_deleg_access(zc->zc_name, ZFS_DELEG_PERM_MOUNT, cr) == 0 ?
	    0 : SET_ERROR(EPERM));
}

int
zfs_secpolicy_zfsd_share(zfs_cmd_t *zc, nvlist_t *innvl, cred_t *cr)
{
	(void) innvl;
	if (secpolicy_zfs(cr) == 0)
		return (0);
	if (zc->zc_name[0] == '\0')
		return (SET_ERROR(EPERM));
	if (entity_namecheck(zc->zc_name, NULL, NULL) != 0)
		return (SET_ERROR(EINVAL));
	return (dsl_deleg_access(zc->zc_name, ZFS_DELEG_PERM_SHARE, cr) == 0 ?
	    0 : SET_ERROR(EPERM));
}
