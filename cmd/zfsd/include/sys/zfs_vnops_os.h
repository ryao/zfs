// SPDX-License-Identifier: CDDL-1.0
#ifndef	_SYS_FS_ZFS_VNOPS_OS_H
#define	_SYS_FS_ZFS_VNOPS_OS_H

#include <sys/vnode.h>
#include <sys/xvattr.h>
#include <sys/uio.h>
#include <sys/cred.h>
#include <sys/fcntl.h>
#include <sys/pathname.h>
#include <sys/zpl.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct znode;
struct zfsvfs;

extern int zfs_open(struct znode *zp, int mode, int flag, cred_t *cr);
extern int zfs_close(struct znode *zp, int flag, cred_t *cr);
extern int zfs_write_simple(struct znode *zp, const void *data, size_t len,
    loff_t pos, size_t *resid);
extern int zfs_lookup(struct znode *dzp, char *nm, struct znode **zpp,
    int flags, cred_t *cr, int *direntflags, pathname_t *realpnp);
extern int zfs_create(struct znode *dzp, char *name, vattr_t *vap, int excl,
    int mode, struct znode **zpp, cred_t *cr, int flag, vsecattr_t *vsecp);
extern int zfs_remove(struct znode *dzp, char *name, cred_t *cr, int flags);
extern int zfs_mkdir(struct znode *dzp, char *dirname, vattr_t *vap,
    struct znode **zpp, cred_t *cr, int flags, vsecattr_t *vsecp);
extern int zfs_rmdir(struct znode *dzp, char *name, struct znode *cwd,
    cred_t *cr, int flags);
extern int zfs_readdir(struct znode *zp, void *dirent, cred_t *cr,
    int *eofp, uint64_t *offp,
    int (*filler)(void *, const char *, int, loff_t, ino_t, unsigned));
extern int zfs_setattr(struct znode *zp, vattr_t *vap, int flag, cred_t *cr);
extern int zfs_rename(struct znode *sdzp, char *snm, struct znode *tdzp,
    char *tnm, cred_t *cr, int flags, uint64_t rflags, vattr_t *wo_vap);
extern int zfs_symlink(struct znode *dzp, char *name, vattr_t *vap,
    char *link, struct znode **zpp, cred_t *cr, int flags);
extern int zfs_readlink(struct znode *zp, zfs_uio_t *uio, cred_t *cr);
extern int zfs_link(struct znode *tdzp, struct znode *szp,
    char *name, cred_t *cr, int flags);
extern void zfs_inactive(struct znode *zp);
extern int zfs_space(struct znode *zp, int cmd, flock64_t *bfp, int flag,
    offset_t offset, cred_t *cr);
extern void zfs_zrele_async(struct znode *zp);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_ZFS_VNOPS_OS_H */
