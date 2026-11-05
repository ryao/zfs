// SPDX-License-Identifier: CDDL-1.0
/*
 * FUSE 3 adapter. Linux zpl_*.c and FreeBSD zfs_vnodeops map onto
 * fuse_operations. Each method walks to a znode and calls the real
 * zfs_* vnops (zfs_read, zfs_create, zfsvfs_create, ...).
 *
 * Creating a filesystem is zfs_create_fs. Mounting is zfsvfs_create
 * plus zfsvfs_setup. FUSE ops live here; .zfs snapshots are in
 * zfsd_ctldir.c.
 */

#define	FUSE_USE_VERSION	31
#ifndef _GNU_SOURCE
#define	_GNU_SOURCE
#endif

#include <sys/zfs_context.h>
#include <libzpool.h>
#include <sys/spa.h>
#include <sys/dmu.h>
#include <sys/dmu_objset.h>
#include <sys/dmu_tx.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_pool.h>
#include <sys/zap.h>
#include <sys/nvpair.h>
#include <sys/fs/zfs.h>
#include <sys/zfs_znode.h>
#include <sys/zfs_vfsops.h>
#include <sys/zfs_vnops.h>
#include <sys/zfs_dir.h>
#include <sys/zfs_acl.h>
#include <sys/zil.h>
#include <sys/sa.h>
#include <sys/zfs_sa.h>
#include <sys/zfs_ioctl.h>
#include <sys/policy.h>
#include <sys/vnode.h>
#include <sys/zpl.h>
#include <sys/xvattr.h>
#include <sys/zfs_project.h>
#include <sys/zfeature.h>
#include <fuse3/fuse.h>


#include <signal.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <ctype.h>
#ifdef __linux__
#include <mntent.h>
#include <sys/sysmacros.h>
#include <sys/mount.h>
#include <linux/fs.h>
#include <linux/falloc.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#endif

#include "zfsd_zpl.h"
#include "zfsd_impl.h"
#include "zfsd_zvol.h"

#ifndef	FUSE_CAP_COPY_FILE_RANGE
#define	FUSE_CAP_COPY_FILE_RANGE	(1u << 20)
#endif
#ifndef	FUSE_CAP_POSIX_ACL
#define	FUSE_CAP_POSIX_ACL		(1u << 19)
#endif
#ifndef	DTTOIF
#define	DTTOIF(t)	((t) << 12)
#endif
#ifdef __linux__
#ifndef	FICLONE
#define	FICLONE		_IOW(0x94, 9, int)
#endif
#ifndef	FICLONERANGE
#define	FICLONERANGE	_IOW(0x94, 13, struct file_clone_range)
#endif
#ifndef	FIDEDUPERANGE
#define	FIDEDUPERANGE	_IOWR(0x94, 54, struct file_dedupe_range)
#endif
#ifndef	FS_PROJINHERIT_FL
#define	FS_PROJINHERIT_FL	0x20000000
#endif
#ifndef	FS_XFLAG_IMMUTABLE
#define	FS_XFLAG_IMMUTABLE	0x00000008
#endif
#ifndef	FS_XFLAG_APPEND
#define	FS_XFLAG_APPEND		0x00000010
#endif
#ifndef	FS_XFLAG_NODUMP
#define	FS_XFLAG_NODUMP		0x00000080
#endif
#ifndef	FS_XFLAG_PROJINHERIT
#define	FS_XFLAG_PROJINHERIT	0x00000200
#endif
#ifndef	FS_IOC32_GETVERSION
#define	FS_IOC32_GETVERSION	_IOR('v', 1, int)
#endif
#ifndef	FS_IOC32_GETFLAGS
#define	FS_IOC32_GETFLAGS	_IOR('f', 1, int)
#endif
#ifndef	FS_IOC32_SETFLAGS
#define	FS_IOC32_SETFLAGS	_IOW('f', 2, int)
#endif
#ifndef	ZFS_FL_USER_VISIBLE
#define	ZFS_FL_USER_VISIBLE	(FS_FL_USER_VISIBLE | FS_PROJINHERIT_FL)
#endif
#ifndef	ZFS_FL_USER_MODIFIABLE
#define	ZFS_FL_USER_MODIFIABLE	(FS_FL_USER_MODIFIABLE | FS_PROJINHERIT_FL)
#endif
#ifndef	ARRAY_SIZE
#define	ARRAY_SIZE(a)	(sizeof (a) / sizeof ((a)[0]))
#endif
#endif
#ifndef	FALLOC_FL_KEEP_SIZE
#define	FALLOC_FL_KEEP_SIZE	0x01
#endif
#ifndef	FALLOC_FL_PUNCH_HOLE
#define	FALLOC_FL_PUNCH_HOLE	0x02
#endif
#ifndef	SEEK_DATA
#define	SEEK_DATA	3
#endif
#ifndef	SEEK_HOLE
#define	SEEK_HOLE	4
#endif
#ifndef	XATTR_CREATE
#define	XATTR_CREATE	0x1
#endif
#ifndef	XATTR_REPLACE
#define	XATTR_REPLACE	0x2
#endif
#ifndef	OFF_MAX
#define	OFF_MAX	((off_t)(((uint64_t)1 << (sizeof (off_t) * 8 - 1)) - 1))
#endif
#ifndef	RENAME_NOREPLACE
#define	RENAME_NOREPLACE	(1 << 0)
#endif
#ifndef	RENAME_EXCHANGE
#define	RENAME_EXCHANGE		(1 << 1)
#endif

#define	ZPL_DIRENT_BIAS	16
#define	ZPL_NAME_MAX	255

enum zpl_kind {
	ZPL_NORM = 0,
	ZPL_CTLDIR,
	ZPL_SNAPDIR,
	ZPL_SNAPROOT,
	ZPL_SNAPENT,
	ZPL_SHARESDIR
};

typedef struct zpl_file {
	znode_t		*zp;
	uint64_t	obj;
	int		kind;
	int		flags;
	int		snap;
	zfsvfs_t	*snapvfs;	/* snapos hold until release */
	char		snapds[ZFS_MAX_DATASET_NAME_LEN];
} zpl_file_t;

struct zpl_res {
	zpl_mnt_t	*m;
	zfsvfs_t	*zfsvfs;
	znode_t		*zp;
	int		kind;
	int		owned;	/* zfsvfs is a snapshot hold we must free */
	zpl_mnt_t	*snapmnt;
};

typedef struct zpl_lockent {
	uint64_t	fsid;
	uint64_t	obj;
	uint64_t	owner;
	pid_t		pid;
	off_t		start;
	off_t		end;
	short		type;
	int		is_flock;
	struct zpl_lockent *next;
} zpl_lockent_t;


static pthread_mutex_t	zpl_state_mx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t	zpl_lock_cv = PTHREAD_COND_INITIALIZER;
static zpl_lockent_t	*zpl_locks;
static int		zpl_dont_mask;

int fuse_loop_mt_312(struct fuse *, struct fuse_loop_config *);
static void zfsd_zpl_unmount_dead(const char *mnt);

static zpl_mnt_t *
zpl_from_fuse(void)
{
	struct fuse_context *ctx = fuse_get_context();
	zpl_mnt_t *m;

	m = ctx != NULL ? ctx->private_data : NULL;
	if (m == NULL)
		return (NULL);
	pthread_mutex_lock(&m->lock);
	if (m->dying) {
		pthread_mutex_unlock(&m->lock);
		return (NULL);
	}
	{
		struct timespec ts;
		if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
			m->used = ts.tv_sec;
	}
	pthread_mutex_unlock(&m->lock);
	return (m);
}

static void
zpl_cred_dtor(int *p)
{
	(void) p;
	zfsd_crclr();
}

static int
zpl_bind_cred(void)
{
	struct fuse_context *ctx = fuse_get_context();
	gid_t *groups = NULL;
	int n, got, cap;

	if (ctx == NULL)
		return (0);
	n = fuse_getgroups(0, NULL);
	if (n < 0) {
		gid_t tmp[256];

		n = fuse_getgroups(256, tmp);
		if (n < 0)
			return (zfsd_crset(ctx->uid, ctx->gid, 0, NULL));
		if (n > 256)
			n = 256;
		return (zfsd_crset(ctx->uid, ctx->gid, n, tmp));
	}
	if (n == 0)
		return (zfsd_crset(ctx->uid, ctx->gid, 0, NULL));
	if (n > NGROUPS_MAX)
		n = NGROUPS_MAX;
	cap = n;
	groups = malloc((size_t)cap * sizeof (gid_t));
	if (groups == NULL)
		return (-1);
	got = fuse_getgroups(cap, groups);
	if (got < 0) {
		free(groups);
		return (-1);
	}
	if (got > cap)
		got = cap;
	n = zfsd_crset(ctx->uid, ctx->gid, got, groups);
	free(groups);
	return (n);
}

#define	ZPL_CRED() \
	int __attribute__((cleanup(zpl_cred_dtor))) _zpl_cred = 1; \
	zfsd_tunables_refresh(); \
	if (zpl_bind_cred() != 0) \
		return (-EIO)

static int zpl_inherit_posix_acl(znode_t *, znode_t *, int);
static uint64_t zpl_fsid(zfsvfs_t *);
static void zpl_lock_drop_owner(uint64_t, uint64_t, uint64_t, int);


static off_t
zpl_dir_off(uint64_t cookie)
{
	if (cookie > UINT64_MAX - (uint64_t)ZPL_DIRENT_BIAS)
		return ((off_t)UINT64_MAX);
	return ((off_t)(cookie + (uint64_t)ZPL_DIRENT_BIAS));
}

static uint64_t
zpl_dir_cookie(off_t off)
{
	if (off < ZPL_DIRENT_BIAS)
		return (0);
	return ((uint64_t)off - (uint64_t)ZPL_DIRENT_BIAS);
}

static int
zpl_walk(zfsvfs_t *zfsvfs, const char *path, znode_t **zpp)
{
	znode_t *dzp, *zp;
	char buf[MAXPATHLEN];
	char *tok, *save = NULL;
	int err;

	*zpp = NULL;
	err = zfs_zget(zfsvfs, zfsvfs->z_root, &dzp);
	if (err != 0)
		return (err);
	if (path == NULL || path[0] == '\0' || strcmp(path, "/") == 0) {
		*zpp = dzp;
		return (0);
	}
	if (strlen(path) >= sizeof (buf)) {
		zrele(dzp);
		return (ENAMETOOLONG);
	}
	(void) strlcpy(buf, path, sizeof (buf));

	zp = dzp;
	for (tok = strtok_r(buf, "/", &save); tok != NULL;
	    tok = strtok_r(NULL, "/", &save)) {
		znode_t *next = NULL;

		if (strcmp(tok, ".") == 0)
			continue;
		err = zfs_lookup(zp, tok, &next, 0, CRED(), NULL, NULL);
		zrele(zp);
		zp = NULL;
		if (err != 0)
			return (err);
		zp = next;
	}
	*zpp = zp;
	return (0);
}

static int
zpl_parent_name(const char *path, char *dir, size_t dirsz, const char **base)
{
	char *slash;

	if (path == NULL || path[0] == '\0')
		return (EINVAL);
	if (strlen(path) >= dirsz)
		return (ENAMETOOLONG);
	(void) strlcpy(dir, path, dirsz);
	slash = strrchr(dir, '/');

	if (slash == NULL)
		return (EINVAL);
	*base = path + (slash - dir) + 1;
	if (slash == dir)
		dir[1] = '\0';
	else
		*slash = '\0';
	if ((*base)[0] == '\0' || strcmp(*base, ".") == 0 ||
	    strcmp(*base, "..") == 0)
		return (EINVAL);
	if (strlen(*base) > ZPL_NAME_MAX)
		return (ENAMETOOLONG);
	return (0);
}

static void
zpl_res_rele(struct zpl_res *r)
{
	if (r->zp != NULL) {
		zrele(r->zp);
		r->zp = NULL;
	}
	if (r->owned && r->zfsvfs != NULL) {
		zpl_snapos_rele(r->zfsvfs);
		r->zfsvfs = NULL;
	}
	r->owned = 0;
	if (r->snapmnt != NULL) {
		zfsd_zpl_snap_rele(r->snapmnt);
		r->snapmnt = NULL;
	}
}

static int
zpl_snap_parse(const char *path, char *snap, size_t snapsz, const char **relp)
{
	const char *p, *slash;
	size_t n;

	if (path == NULL || strncmp(path, "/.zfs/snapshot/", 15) != 0)
		return (EINVAL);
	p = path + 15;
	if (p[0] == '\0' || p[0] == '/')
		return (EINVAL);
	slash = strchr(p, '/');
	n = slash ? (size_t)(slash - p) : strlen(p);
	if (n == 0 || n >= snapsz)
		return (EINVAL);
	if ((n == 1 && p[0] == '.') ||
	    (n == 2 && p[0] == '.' && p[1] == '.'))
		return (EINVAL);
	if (memchr(p, '@', n) != NULL)
		return (EINVAL);
	(void) memcpy(snap, p, n);
	snap[n] = '\0';
	if (relp != NULL) {
		if (slash == NULL || slash[1] == '\0')
			*relp = NULL;
		else
			*relp = slash;
	}
	return (0);
}

static int
zpl_resolve(const char *path, struct zpl_res *r)
{
	zpl_mnt_t *m = zpl_from_fuse();
	int err;

	memset(r, 0, sizeof (*r));
	if (m == NULL || m->zfsvfs == NULL)
		return (ENOENT);
	r->m = m;
	r->zfsvfs = m->zfsvfs;
	if (path == NULL)
		path = "/";

	if (strcmp(path, "/.zfs") == 0) {
		r->kind = ZPL_CTLDIR;
		return (0);
	}
	if (strcmp(path, "/.zfs/snapshot") == 0) {
		r->kind = ZPL_SNAPDIR;
		return (0);
	}
	if (strcmp(path, "/.zfs/shares") == 0) {
		r->kind = ZPL_SHARESDIR;
		return (0);
	}
	if (strncmp(path, "/.zfs/snapshot/", 15) == 0) {
		char snapname[ZFS_MAX_DATASET_NAME_LEN];
		const char *rel = NULL;

		err = zpl_snap_parse(path, snapname, sizeof (snapname), &rel);
		if (err != 0)
			return (err);
		/*
		 * Serve the snapshot from this FUSE session. Nested
		 * fuse_mount of the same path deadlocks or returns
		 * EAGAIN (Resource temporarily unavailable) to
		 * opendir/stat, and the leftover mount then makes
		 * `zfs destroy` EBUSY.
		 */
		err = zpl_snapos_hold(m, snapname, &r->zfsvfs);
		if (err != 0)
			return (err);
		r->owned = 1;
		r->kind = (rel == NULL) ? ZPL_SNAPROOT : ZPL_SNAPENT;
		err = zpl_walk(r->zfsvfs, rel != NULL ? rel : "/", &r->zp);
		if (err != 0)
			zpl_res_rele(r);
		return (err);
	}
	r->kind = ZPL_NORM;
	err = zpl_walk(r->zfsvfs, path, &r->zp);
	if (err != 0)
		return (err);
	return (0);
}

static int
zpl_obj_or_walk(struct zpl_res *r, const char *path, struct fuse_file_info *fi)
{
	zpl_mnt_t *m = zpl_from_fuse();
	zpl_file_t *f;

	memset(r, 0, sizeof (*r));
	if (m == NULL || m->zfsvfs == NULL)
		return (ENOENT);
	if (fi != NULL && fi->fh != 0) {
		f = (zpl_file_t *)(uintptr_t)fi->fh;
		if (f == NULL)
			return (EBADF);
		if (f->kind == ZPL_CTLDIR || f->kind == ZPL_SNAPDIR ||
		    f->kind == ZPL_SHARESDIR) {
			r->m = m;
			r->zfsvfs = m->zfsvfs;
			r->kind = f->kind;
			return (0);
		}
		if (f->zp == NULL)
			return (EBADF);
		r->m = m;
		r->zfsvfs = f->zp->z_zfsvfs != NULL ? f->zp->z_zfsvfs :
		    m->zfsvfs;
		r->kind = f->kind ? f->kind : ZPL_NORM;
		zhold(f->zp);
		r->zp = f->zp;
		return (0);
	}
	return (zpl_resolve(path, r));
}

static void
zpl_fillstat(struct zpl_res *r, struct stat *st)
{
	znode_t *zp = r->zp;
	dmu_object_info_t doi;

	memset(st, 0, sizeof (*st));
	if (r->kind == ZPL_CTLDIR || r->kind == ZPL_SNAPDIR ||
	    r->kind == ZPL_SHARESDIR ||
	    (r->kind == ZPL_SNAPROOT && zp == NULL)) {
		st->st_mode = S_IFDIR | 0555;
		st->st_nlink = 2;
		st->st_ino = (ino_t)(UINT64_MAX - (uint64_t)r->kind);
		return;
	}
	if (zp == NULL)
		return;
	st->st_mode = zp->z_mode;
	st->st_uid = (uid_t)zp->z_uid;
	st->st_gid = (gid_t)zp->z_gid;
	st->st_nlink = (nlink_t)zp->z_links;
	st->st_size = (off_t)zp->z_size;
	st->st_ino = zp->z_id;
	st->st_mtime = zp->z_mtime.tv_sec;
	st->st_ctime = zp->z_ctime.tv_sec;
	st->st_atime = zp->z_atime.tv_sec;
#if defined(__linux__)
	st->st_mtim.tv_nsec = zp->z_mtime.tv_nsec;
	st->st_ctim.tv_nsec = zp->z_ctime.tv_nsec;
	st->st_atim.tv_nsec = zp->z_atime.tv_nsec;
#endif
	st->st_blksize = zp->z_blksz ? (blksize_t)zp->z_blksz : 131072;
	st->st_blocks = 0;
	if (r->zfsvfs != NULL &&
	    dmu_object_info(r->zfsvfs->z_os, zp->z_id, &doi) == 0) {
		if (doi.doi_data_block_size)
			st->st_blksize = (blksize_t)doi.doi_data_block_size;
		st->st_blocks = (blkcnt_t)doi.doi_physical_blocks_512;
	}

}

static int
zpl_ro(struct zpl_res *r)
{
	if (r->m != NULL && r->m->readonly)
		return (1);
	if (r->zfsvfs != NULL && zfs_is_readonly(r->zfsvfs))
		return (1);
	return (0);
}

/*
 * .zfs, .zfs/snapshot, .zfs/shares (and the snapshot root) are
 * synthetic directories with r->zp == NULL. Mutating vnops must not
 * pass that into zfs_create/remove/... which dereference ZTOZSB.
 */
static int
zpl_dir_mut_ok(struct zpl_res *dr)
{
	if (dr->kind == ZPL_CTLDIR || dr->kind == ZPL_SNAPDIR ||
	    dr->kind == ZPL_SHARESDIR || dr->kind == ZPL_SNAPROOT)
		return (EPERM);
	if (dr->kind == ZPL_SNAPENT ||
	    (dr->zfsvfs != NULL && dr->zfsvfs->z_issnap))
		return (EROFS);
	if (dr->zp == NULL)
		return (EPERM);
	return (0);
}

static int
zpl_resolve_mut_dir(const char *dir, struct zpl_res *dr)
{
	int err;

	err = zpl_resolve(dir, dr);
	if (err != 0)
		return (err);
	err = zpl_dir_mut_ok(dr);
	if (err != 0) {
		zpl_res_rele(dr);
		return (err);
	}
	if (zpl_ro(dr)) {
		zpl_res_rele(dr);
		return (EROFS);
	}
	return (0);
}

static int
zpl_name_ok(const char *name)
{
	if (name == NULL || name[0] == '\0' || name[0] == '/')
		return (EINVAL);
	if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
		return (EINVAL);
	if (strlen(name) > ZPL_NAME_MAX)
		return (ENAMETOOLONG);
	return (0);
}

static int
zpl_xattr_privileged(const char *name)
{
	if (strncmp(name, "trusted.", 8) == 0)
		return (1);
	if (strncmp(name, "security.", 9) == 0)
		return (1);
	if (strncmp(name, "system.", 7) == 0 &&
	    strcmp(name, "system.posix_acl_access") != 0 &&
	    strcmp(name, "system.posix_acl_default") != 0)
		return (1);
	return (0);
}

static int
zpl_xattr_ns_check(znode_t *zp, const char *name, int writing)
{
	int posix_acl;

	if (name == NULL || name[0] == '\0' || strchr(name, '.') == NULL)
		return (EINVAL);
	posix_acl = (strcmp(name, "system.posix_acl_access") == 0 ||
	    strcmp(name, "system.posix_acl_default") == 0);
	if (zpl_xattr_privileged(name)) {
		if (crgetuid(CRED()) != 0)
			return (EPERM);
		return (0);
	}
	if (posix_acl) {
		if (writing)
			return (secpolicy_vnode_setdac(CRED(), zp->z_uid));
		return (0);
	}
	if (strncmp(name, "user.", 5) == 0) {
		if (writing)
			return (zfs_zaccess(zp, ACE_WRITE_NAMED_ATTRS, 0,
			    B_FALSE, CRED()));
		return (zfs_zaccess(zp, ACE_READ_NAMED_ATTRS, 0, B_FALSE,
		    CRED()));
	}
	return (EPERM);
}


static void
zpl_vap_init(vattr_t *vap, mode_t mode)
{
	struct fuse_context *ctx = fuse_get_context();

	memset(vap, 0, sizeof (*vap));
	vap->va_mask = ATTR_MODE | ATTR_UID | ATTR_GID;
	/*
	 * FUSE_CAP_POSIX_ACL sets dont_mask: the kernel passes the
	 * raw mode and umask, and userspace must apply umask.
	 */
	if (zpl_dont_mask && ctx != NULL)
		mode = (mode & S_IFMT) | ((mode & 07777) & ~ctx->umask);
	vap->va_mode = mode;
	vap->va_uid = ctx ? ctx->uid : 0;
	vap->va_gid = ctx ? ctx->gid : 0;
}

static zpl_file_t *
zpl_fh_alloc(znode_t *zp, int kind, int flags, const char *snapds)
{
	zpl_file_t *f;

	f = calloc(1, sizeof (*f));
	if (f == NULL)
		return (NULL);
	f->zp = zp;
	f->obj = zp != NULL ? zp->z_id : 0;
	f->kind = kind;
	f->flags = flags;
	if (snapds != NULL && snapds[0] != '\0') {
		f->snap = 1;
		(void) strlcpy(f->snapds, snapds, sizeof (f->snapds));
	}
	return (f);
}

static int
zpl_fill(void *buf, fuse_fill_dir_t filler, const char *name,
    const struct stat *st, off_t off, enum fuse_fill_dir_flags flags)
{
	return (filler(buf, name, st, off, flags));
}

static int
zpl_getattr(const char *path, struct stat *st, struct fuse_file_info *fi)
{
	struct zpl_res r;
	int err;

	ZPL_CRED();
	err = zpl_obj_or_walk(&r, path, fi);
	if (err != 0)
		return (-err);
	zpl_fillstat(&r, st);
	zpl_res_rele(&r);
	return (0);
}

static int
zpl_access(const char *path, int mask)
{
	struct zpl_res r;
	int err, mode = 0;

	ZPL_CRED();
	err = zpl_resolve(path, &r);
	if (err != 0)
		return (-err);
	if (r.kind != ZPL_NORM && r.kind != ZPL_SNAPENT &&
	    r.kind != ZPL_SNAPROOT) {
		zpl_res_rele(&r);
		return ((mask & W_OK) ? -EACCES : 0);
	}
	if (r.zp == NULL) {
		zpl_res_rele(&r);
		return (-ENOENT);
	}
	if (mask & R_OK)
		mode |= 4;
	if (mask & W_OK)
		mode |= 2;
	if (mask & X_OK)
		mode |= 1;
	/*
	 * zfs_zaccess_rwx() maps unix_to_v4(mode >> 6), so pass the
	 * owner-byte form. FUSE R_OK/W_OK/X_OK are already other-bits
	 * (4/2/1); without the shift the check is a no-op.
	 */
	err = zfs_access(r.zp, mode << 6, 0, CRED());
	zpl_res_rele(&r);
	return (-err);
}

static int
zpl_readlink(const char *path, char *buf, size_t n)
{
	struct zpl_res r;
	zfs_uio_t uio;
	iovec_t iov;
	int err;

	ZPL_CRED();
	err = zpl_resolve(path, &r);
	if (err != 0)
		return (-err);
	if (r.zp == NULL || !S_ISLNK(r.zp->z_mode)) {
		zpl_res_rele(&r);
		return (-EINVAL);
	}
	if (n == 0) {
		zpl_res_rele(&r);
		return (0);
	}
	iov.iov_base = buf;
	iov.iov_len = n - 1;
	zfs_uio_iovec_init(&uio, &iov, 1, 0, UIO_SYSSPACE, n - 1, 0);
	err = zfs_readlink(r.zp, &uio, CRED());
	if (err == 0)
		buf[(n - 1) - (size_t)uio.uio_resid] = '\0';
	zpl_res_rele(&r);
	return (-err);
}

static int
zpl_mknod(const char *path, mode_t mode, dev_t rdev)
{
	struct zpl_res dr;
	char dir[MAXPATHLEN];
	const char *base;
	vattr_t vap;
	znode_t *zp = NULL;
	int err;

	ZPL_CRED();
	err = zpl_parent_name(path, dir, sizeof (dir), &base);
	if (err != 0)
		return (-err);
	err = zpl_name_ok(base);
	if (err != 0)
		return (-err);
	err = zpl_resolve_mut_dir(dir, &dr);
	if (err != 0)
		return (-err);
	zpl_vap_init(&vap, mode);
	if (S_ISREG(mode)) {
		vap.va_mask |= ATTR_SIZE;
		vap.va_size = 0;
	} else if (S_ISCHR(mode) || S_ISBLK(mode)) {
		if (crgetuid(CRED()) != 0) {
			zpl_res_rele(&dr);
			return (-EPERM);
		}
		vap.va_rdev = rdev;
	} else {
		vap.va_rdev = rdev;
	}
	err = zfs_create(dr.zp, (char *)base, &vap, 0, 0, &zp, CRED(), 0, NULL);
	if (err == 0 && zp != NULL) {
		err = zpl_inherit_posix_acl(dr.zp, zp, 0);
		if (err != 0) {
			(void) zfs_remove(dr.zp, (char *)base, CRED(), 0);
			zrele(zp);
			zp = NULL;
		}
	}
	if (zp != NULL)
		zrele(zp);
	zpl_res_rele(&dr);
	return (-err);
}

static int
zpl_mkdir(const char *path, mode_t mode)
{
	struct zpl_res dr;
	char dir[MAXPATHLEN];
	const char *base;
	vattr_t vap;
	znode_t *zp = NULL;
	int err;

	ZPL_CRED();
	err = zpl_parent_name(path, dir, sizeof (dir), &base);
	if (err != 0)
		return (-err);
	err = zpl_name_ok(base);
	if (err != 0)
		return (-err);
	err = zpl_resolve_mut_dir(dir, &dr);
	if (err != 0)
		return (-err);
	zpl_vap_init(&vap, S_IFDIR | (mode & ~S_IFMT));
	err = zfs_mkdir(dr.zp, (char *)base, &vap, &zp, CRED(), 0, NULL);
	if (err == 0 && zp != NULL) {
		err = zpl_inherit_posix_acl(dr.zp, zp, 1);
		if (err != 0) {
			(void) zfs_rmdir(dr.zp, (char *)base, NULL, CRED(), 0);
			zrele(zp);
			zp = NULL;
		}
	}
	if (zp != NULL)
		zrele(zp);
	zpl_res_rele(&dr);
	return (-err);
}

static int
zpl_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	struct zpl_res dr;
	char dir[MAXPATHLEN];
	const char *base;
	vattr_t vap;
	znode_t *zp = NULL;
	zpl_file_t *f;
	int err, zflag = 0;

	ZPL_CRED();
	err = zpl_parent_name(path, dir, sizeof (dir), &base);
	if (err != 0)
		return (-err);
	err = zpl_name_ok(base);
	if (err != 0)
		return (-err);
	err = zpl_resolve_mut_dir(dir, &dr);
	if (err != 0)
		return (-err);
	zpl_vap_init(&vap, S_IFREG | (mode & ~S_IFMT));
	vap.va_mask |= ATTR_SIZE;
	vap.va_size = 0;
	if (fi != NULL && (fi->flags & O_EXCL))
		err = zfs_create(dr.zp, (char *)base, &vap, 1, 0, &zp,
		    CRED(), 0, NULL);
	else
		err = zfs_create(dr.zp, (char *)base, &vap, 0, 0, &zp,
		    CRED(), 0, NULL);
	if (err == 0 && zp != NULL) {
		err = zpl_inherit_posix_acl(dr.zp, zp, 0);
		if (err != 0) {
			(void) zfs_remove(dr.zp, (char *)base, CRED(), 0);
			zrele(zp);
			zp = NULL;
		}
	}
	zpl_res_rele(&dr);
	if (err != 0)
		return (-err);
	if (zp == NULL)
		return (-EIO);
	if (fi != NULL && (fi->flags & O_SYNC))
		zflag |= FSYNC;
	if (fi != NULL && (fi->flags & O_DSYNC))
		zflag |= FDSYNC;
	(void) zfs_open(zp, 0, zflag, CRED());
	f = zpl_fh_alloc(zp, ZPL_NORM, fi ? fi->flags : 0, NULL);
	if (f == NULL) {
		(void) zfs_close(zp, zflag, CRED());
		zrele(zp);
		return (-ENOMEM);
	}
	fi->fh = (uint64_t)(uintptr_t)f;
	return (0);
}

static int
zpl_unlink(const char *path)
{
	struct zpl_res dr;
	char dir[MAXPATHLEN];
	const char *base;
	int err;

	ZPL_CRED();
	err = zpl_parent_name(path, dir, sizeof (dir), &base);
	if (err != 0)
		return (-err);
	err = zpl_resolve_mut_dir(dir, &dr);
	if (err != 0)
		return (-err);
	err = zfs_remove(dr.zp, (char *)base, CRED(), 0);
	zpl_res_rele(&dr);
	return (-err);
}

static int
zpl_rmdir(const char *path)
{
	struct zpl_res dr;
	char dir[MAXPATHLEN];
	const char *base;
	int err;

	ZPL_CRED();
	err = zpl_parent_name(path, dir, sizeof (dir), &base);
	if (err != 0)
		return (-err);
	err = zpl_resolve_mut_dir(dir, &dr);
	if (err != 0)
		return (-err);
	err = zfs_rmdir(dr.zp, (char *)base, NULL, CRED(), 0);
	zpl_res_rele(&dr);
	return (-err);
}

static int
zpl_symlink(const char *to, const char *from)
{
	struct zpl_res dr;
	char dir[MAXPATHLEN];
	const char *base;
	vattr_t vap;
	znode_t *zp = NULL;
	int err;

	ZPL_CRED();
	err = zpl_parent_name(from, dir, sizeof (dir), &base);
	if (err != 0)
		return (-err);
	err = zpl_name_ok(base);
	if (err != 0)
		return (-err);
	err = zpl_resolve_mut_dir(dir, &dr);
	if (err != 0)
		return (-err);
	zpl_vap_init(&vap, S_IFLNK | 0777);
	err = zfs_symlink(dr.zp, (char *)base, &vap, (char *)to, &zp,
	    CRED(), 0);
	if (zp != NULL)
		zrele(zp);
	zpl_res_rele(&dr);
	return (-err);
}

static int
zpl_link(const char *from, const char *to)
{
	struct zpl_res sr, dr;
	char dir[MAXPATHLEN];
	const char *base;
	int err;

	ZPL_CRED();
	err = zpl_parent_name(to, dir, sizeof (dir), &base);
	if (err != 0)
		return (-err);
	err = zpl_name_ok(base);
	if (err != 0)
		return (-err);
	err = zpl_resolve(from, &sr);
	if (err != 0)
		return (-err);
	if (sr.zp == NULL) {
		zpl_res_rele(&sr);
		return (-EPERM);
	}
	err = zpl_resolve_mut_dir(dir, &dr);
	if (err != 0) {
		zpl_res_rele(&sr);
		return (-err);
	}
	err = zfs_link(dr.zp, sr.zp, (char *)base, CRED(), 0);
	zpl_res_rele(&sr);
	zpl_res_rele(&dr);
	return (-err);
}

static int
zpl_rename(const char *from, const char *to, unsigned int flags)
{
	struct zpl_res sd, td;
	char sdir[MAXPATHLEN], tdir[MAXPATHLEN];
	const char *sbase, *tbase;
	int err, zflags = 0;
	uint64_t rflags = 0;

	ZPL_CRED();
	if (flags & RENAME_NOREPLACE)
		rflags |= RENAME_NOREPLACE;
	if (flags & RENAME_EXCHANGE)
		return (-EOPNOTSUPP);
	if (flags & ~(RENAME_NOREPLACE | RENAME_EXCHANGE))
		return (-EINVAL);
	err = zpl_parent_name(from, sdir, sizeof (sdir), &sbase);
	if (err != 0)
		return (-err);
	err = zpl_parent_name(to, tdir, sizeof (tdir), &tbase);
	if (err != 0)
		return (-err);
	err = zpl_resolve_mut_dir(sdir, &sd);
	if (err != 0)
		return (-err);
	err = zpl_resolve_mut_dir(tdir, &td);
	if (err != 0) {
		zpl_res_rele(&sd);
		return (-err);
	}
	err = zfs_rename(sd.zp, (char *)sbase, td.zp, (char *)tbase,
	    CRED(), zflags, rflags, NULL);

	zpl_res_rele(&sd);
	zpl_res_rele(&td);
	return (-err);
}

static int
zpl_setattr(znode_t *zp, vattr_t *vap)
{
	return (zfs_setattr(zp, vap, 0, CRED()));
}

static int
zpl_chmod(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	struct zpl_res r;
	vattr_t vap;
	int err;

	ZPL_CRED();
	err = zpl_obj_or_walk(&r, path, fi);
	if (err != 0)
		return (-err);
	if (r.zp == NULL) {
		zpl_res_rele(&r);
		return (-EPERM);
	}
	if (zpl_ro(&r)) {
		zpl_res_rele(&r);
		return (-EROFS);
	}
	memset(&vap, 0, sizeof (vap));
	vap.va_mask = ATTR_MODE;
	vap.va_mode = (r.zp->z_mode & S_IFMT) | (mode & ~S_IFMT);
	err = zpl_setattr(r.zp, &vap);
	zpl_res_rele(&r);
	return (-err);
}

static int
zpl_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi)
{
	struct zpl_res r;
	vattr_t vap;
	int err;

	ZPL_CRED();
	err = zpl_obj_or_walk(&r, path, fi);
	if (err != 0)
		return (-err);
	if (r.zp == NULL) {
		zpl_res_rele(&r);
		return (-EPERM);
	}
	if (zpl_ro(&r)) {
		zpl_res_rele(&r);
		return (-EROFS);
	}
	memset(&vap, 0, sizeof (vap));
	if (uid != (uid_t)-1) {
		vap.va_mask |= ATTR_UID;
		vap.va_uid = uid;
	}
	if (gid != (gid_t)-1) {
		vap.va_mask |= ATTR_GID;
		vap.va_gid = gid;
	}
	err = zpl_setattr(r.zp, &vap);
	zpl_res_rele(&r);
	return (-err);
}

static int
zpl_truncate(const char *path, off_t size, struct fuse_file_info *fi)
{
	struct zpl_res r;
	vattr_t vap;
	int err;

	ZPL_CRED();
	if (size < 0)
		return (-EINVAL);
	err = zpl_obj_or_walk(&r, path, fi);
	if (err != 0)
		return (-err);
	if (r.zp == NULL) {
		zpl_res_rele(&r);
		return (-EINVAL);
	}
	if (zpl_ro(&r)) {
		zpl_res_rele(&r);
		return (-EROFS);
	}
	memset(&vap, 0, sizeof (vap));
	vap.va_mask = ATTR_SIZE;
	vap.va_size = (uint64_t)size;

	err = zpl_setattr(r.zp, &vap);
	zpl_res_rele(&r);
	return (-err);
}

static int
zpl_utimens(const char *path, const struct timespec tv[2],
    struct fuse_file_info *fi)
{
	struct zpl_res r;
	vattr_t vap;
	int err;

	ZPL_CRED();
	err = zpl_obj_or_walk(&r, path, fi);
	if (err != 0)
		return (-err);
	if (r.zp == NULL) {
		zpl_res_rele(&r);
		return (-EPERM);
	}
	if (zpl_ro(&r)) {
		zpl_res_rele(&r);
		return (-EROFS);
	}
	memset(&vap, 0, sizeof (vap));
	if (tv == NULL) {
		vap.va_mask = ATTR_ATIME | ATTR_MTIME;
		vap.va_vaflags |= VA_UTIMES_NULL;
		gethrestime(&vap.va_atime);
		vap.va_mtime = vap.va_atime;
	} else {
		int explicit = 0;

		if (tv[0].tv_nsec != UTIME_OMIT) {
			vap.va_mask |= ATTR_ATIME;
			if (tv[0].tv_nsec == UTIME_NOW)
				gethrestime(&vap.va_atime);
			else {
				vap.va_atime = tv[0];
				explicit = 1;
			}
		}
		if (tv[1].tv_nsec != UTIME_OMIT) {
			vap.va_mask |= ATTR_MTIME;
			if (tv[1].tv_nsec == UTIME_NOW)
				gethrestime(&vap.va_mtime);
			else {
				vap.va_mtime = tv[1];
				explicit = 1;
			}
		}
		if (!explicit)
			vap.va_vaflags |= VA_UTIMES_NULL;
	}

	err = vap.va_mask ? zpl_setattr(r.zp, &vap) : 0;
	zpl_res_rele(&r);
	return (-err);
}

static int
zpl_open(const char *path, struct fuse_file_info *fi)
{
	struct zpl_res r;
	zpl_file_t *f;
	int err, zflag = 0;

	ZPL_CRED();
	err = zpl_resolve(path, &r);
	if (err != 0)
		return (-err);
	if (r.kind == ZPL_CTLDIR || r.kind == ZPL_SNAPDIR ||
	    r.kind == ZPL_SHARESDIR) {
		f = zpl_fh_alloc(NULL, r.kind, fi->flags, NULL);
		zpl_res_rele(&r);
		if (f == NULL)
			return (-ENOMEM);
		fi->fh = (uint64_t)(uintptr_t)f;
		return (0);
	}
	if (r.zp == NULL) {
		zpl_res_rele(&r);
		return (-ENOENT);
	}
	{
		int acc = 0;
		int am = fi->flags & O_ACCMODE;

		if (am != O_WRONLY)
			acc |= ACE_READ_DATA;
		if (am != O_RDONLY)
			acc |= ACE_WRITE_DATA;
		err = zfs_zaccess(r.zp, acc, 0, B_FALSE, CRED());
		if (err != 0) {
			zpl_res_rele(&r);
			return (-err);
		}
	}
	if ((fi->flags & O_TRUNC) && S_ISREG(r.zp->z_mode)) {
		vattr_t vap;

		if (zpl_ro(&r)) {
			zpl_res_rele(&r);
			return (-EROFS);
		}
		memset(&vap, 0, sizeof (vap));
		vap.va_mask = ATTR_SIZE;
		vap.va_size = 0;
		err = zfs_setattr(r.zp, &vap, 0, CRED());
		if (err != 0) {
			zpl_res_rele(&r);
			return (-err);
		}
	}
	if (fi->flags & O_SYNC)
		zflag |= FSYNC;
	if (fi->flags & O_DSYNC)
		zflag |= FDSYNC;
	err = zfs_open(r.zp, 0, zflag, CRED());
	if (err != 0) {
		zpl_res_rele(&r);
		return (-err);
	}
	/*
	 * Empty-file cat may never call zpl_read when the kernel
	 * already knows i_size==0 (no direct_io). Stamp atime on
	 * open so ZTS atime_001 sees an update after cat.
	 */
	if ((fi->flags & O_ACCMODE) != O_WRONLY)
		ZFS_ACCESSTIME_STAMP(ZTOZSB(r.zp), r.zp);
	f = zpl_fh_alloc(r.zp, r.kind, fi->flags, NULL);
	if (f == NULL) {
		(void) zfs_close(r.zp, zflag, CRED());
		zpl_res_rele(&r);
		return (-ENOMEM);
	}
	/* fh holds the znode; do not zrele in res_rele */
	r.zp = NULL;
	if (r.owned) {
		f->snapvfs = r.zfsvfs;
		r.owned = 0;
		r.zfsvfs = NULL;
	}
	zpl_res_rele(&r);
	fi->fh = (uint64_t)(uintptr_t)f;
	return (0);
}

static int
zpl_flush(const char *path, struct fuse_file_info *fi)
{
	struct zpl_res r;
	int err;

	ZPL_CRED();
	err = zpl_obj_or_walk(&r, path, fi);
	if (err != 0)
		return (-err);
	/*
	 * POSIX fcntl locks belong to lock_owner and must drop on
	 * close. libfuse calls flush for each close(); flock stays
	 * until release (open-file lifetime).
	 */
	if (fi != NULL && r.zp != NULL) {
		uint64_t fsid = zpl_fsid(ZTOZSB(r.zp));
		uint64_t obj = r.zp->z_id;

		pthread_mutex_lock(&zpl_state_mx);
		zpl_lock_drop_owner(fsid, obj, fi->lock_owner, 0);
		(void) pthread_cond_broadcast(&zpl_lock_cv);
		pthread_mutex_unlock(&zpl_state_mx);
	}
	if (r.zp != NULL && !ZTOZSB(r.zp)->z_issnap)
		err = zfs_fsync(r.zp, 0, CRED());
	zpl_res_rele(&r);
	return (-err);
}

static int
zpl_release(const char *path, struct fuse_file_info *fi)
{
	zpl_file_t *f;
	int zflag = 0;

	(void) path;
	ZPL_CRED();
	if (fi == NULL || fi->fh == 0)
		return (0);
	f = (zpl_file_t *)(uintptr_t)fi->fh;
	fi->fh = 0;
	if (f->flags & O_SYNC)
		zflag |= FSYNC;
	if (f->flags & O_DSYNC)
		zflag |= FDSYNC;
	if (f->zp != NULL) {
		zfsvfs_t *zfsvfs = ZTOZSB(f->zp);
		uint64_t fsid = zpl_fsid(zfsvfs);
		uint64_t obj = f->zp->z_id;
		uint64_t owner = fi->lock_owner;

		pthread_mutex_lock(&zpl_state_mx);
		zpl_lock_drop_owner(fsid, obj, owner, 0);
		zpl_lock_drop_owner(fsid, obj, owner, 1);
		(void) pthread_cond_broadcast(&zpl_lock_cv);
		pthread_mutex_unlock(&zpl_state_mx);
		if (zfs_enter_verify_zp(zfsvfs, f->zp, FTAG) == 0) {
			(void) zfs_close(f->zp, zflag, CRED());
			zfs_exit(zfsvfs, FTAG);
		}
		zrele(f->zp);
	}
	if (f->snapvfs != NULL)
		zpl_snapos_rele(f->snapvfs);

	free(f);
	return (0);
}

static int
zpl_fsync(const char *path, int datasync, struct fuse_file_info *fi)
{
	struct zpl_res r;
	int err;

	ZPL_CRED();
	err = zpl_obj_or_walk(&r, path, fi);
	if (err != 0)
		return (-err);
	if (r.zp != NULL && !ZTOZSB(r.zp)->z_issnap)
		err = zfs_fsync(r.zp, datasync ? FDSYNC : FSYNC, CRED());
	zpl_res_rele(&r);
	return (-err);
}

static int
zpl_ioflag(struct fuse_file_info *fi)
{
	int ioflag = 0;

	if (fi == NULL)
		return (0);
	if (fi->flags & O_APPEND)
		ioflag |= O_APPEND;
	if (fi->flags & O_SYNC)
		ioflag |= O_SYNC;
	if (fi->flags & O_DIRECT)
		ioflag |= O_DIRECT;
	return (ioflag);
}

static int
zpl_read(const char *path, char *buf, size_t n, off_t off,
    struct fuse_file_info *fi)
{
	struct zpl_res r;
	zfs_uio_t uio;
	iovec_t iov;
	int err;

	ZPL_CRED();
	err = zpl_obj_or_walk(&r, path, fi);
	if (err != 0)
		return (-err);
	if (r.zp == NULL) {
		zpl_res_rele(&r);
		return (-EISDIR);
	}
	iov.iov_base = buf;
	iov.iov_len = n;
	zfs_uio_iovec_init(&uio, &iov, 1, off, UIO_SYSSPACE, (ssize_t)n, 0);
	err = zfs_read(r.zp, &uio, zpl_ioflag(fi), CRED());
	zpl_res_rele(&r);
	if (err != 0)
		return (-err);
	return ((int)(n - (size_t)uio.uio_resid));
}

static int
zpl_write(const char *path, const char *buf, size_t n, off_t off,
    struct fuse_file_info *fi)
{
	struct zpl_res r;
	zfs_uio_t uio;
	iovec_t iov;
	int err;

	ZPL_CRED();
	err = zpl_obj_or_walk(&r, path, fi);
	if (err != 0)
		return (-err);
	if (r.zp == NULL) {
		zpl_res_rele(&r);
		return (-EISDIR);
	}
	if (zpl_ro(&r)) {
		zpl_res_rele(&r);
		return (-EROFS);
	}
	iov.iov_base = (void *)(uintptr_t)buf;
	iov.iov_len = n;
	zfs_uio_iovec_init(&uio, &iov, 1, off, UIO_SYSSPACE, (ssize_t)n, 0);
	err = zfs_write(r.zp, &uio, zpl_ioflag(fi), CRED());
	zpl_res_rele(&r);
	if (err != 0)
		return (-err);
	return ((int)(n - (size_t)uio.uio_resid));
}

static int
zpl_statfs(const char *path, struct statvfs *st)
{
	zpl_mnt_t *m = zpl_from_fuse();
	uint64_t refd, avail, usedobjs, availobjs;

	(void) path;
	memset(st, 0, sizeof (*st));
	if (m == NULL || m->zfsvfs == NULL || m->zfsvfs->z_os == NULL)
		return (-ENOENT);
	dmu_objset_space(m->zfsvfs->z_os, &refd, &avail, &usedobjs, &availobjs);
	st->f_bsize = 131072;
	st->f_frsize = 512;
	st->f_blocks = (refd + avail) / 512;
	st->f_bfree = avail / 512;
	st->f_bavail = st->f_bfree;
	st->f_files = usedobjs + availobjs;
	st->f_ffree = availobjs;
	st->f_namemax = ZPL_NAME_MAX;
	st->f_fsid = (unsigned long)m->zfsvfs->z_root;
	return (0);
}

static int
zpl_xattr_dir(znode_t *zp, znode_t **xzpp, int create)
{
	int flags = LOOKUP_XATTR;

	if (create)
		flags |= CREATE_XATTR_DIR;
	return (zfs_lookup(zp, NULL, xzpp, flags, CRED(), NULL, NULL));
}

static int
zpl_xattr_get_sa(znode_t *zp, const char *name, void *value, size_t size)
{
	uchar_t *nv_value;
	uint_t nv_size;
	int error = 0;

	ASSERT(RW_LOCK_HELD(&zp->z_xattr_lock));
	mutex_enter(&zp->z_lock);
	if (zp->z_xattr_cached == NULL)
		error = zfs_sa_get_xattr(zp);
	mutex_exit(&zp->z_lock);
	if (error != 0)
		return (error == ENOENT ? -ENODATA : -error);
	if (zp->z_xattr_cached == NULL)
		return (-ENODATA);
	error = nvlist_lookup_byte_array(zp->z_xattr_cached, name,
	    &nv_value, &nv_size);
	if (error != 0)
		return (error == ENOENT ? -ENODATA : -error);
	if (size == 0 || value == NULL)
		return ((int)nv_size);
	if (size < nv_size)
		return (-ERANGE);
	(void) memcpy(value, nv_value, nv_size);
	return ((int)nv_size);
}

static int
zpl_xattr_get_dir(znode_t *zp, const char *name, void *value, size_t size)
{
	znode_t *xdir = NULL, *xzp = NULL;
	zfs_uio_t uio;
	iovec_t iov;
	int err, n;

	err = zpl_xattr_dir(zp, &xdir, 0);
	if (err != 0)
		return (err == ENOENT ? -ENODATA : -err);
	err = zfs_lookup(xdir, (char *)name, &xzp, 0, CRED(), NULL, NULL);
	zrele(xdir);
	if (err != 0)
		return (err == ENOENT ? -ENODATA : -err);
	if (size == 0 || value == NULL) {
		n = (int)xzp->z_size;
		zrele(xzp);
		return (n);
	}
	if (size < xzp->z_size) {
		zrele(xzp);
		return (-ERANGE);
	}
	iov.iov_base = value;
	iov.iov_len = size;
	zfs_uio_iovec_init(&uio, &iov, 1, 0, UIO_SYSSPACE, (ssize_t)size, 0);
	err = zfs_read(xzp, &uio, 0, CRED());
	n = err ? -err : (int)(size - (size_t)uio.uio_resid);
	zrele(xzp);
	return (n);
}

/*
 * Xattr get: Linux-style signed result. >= 0 is the value length
 * (present, including a zero-length value). < 0 is -errno; missing
 * attributes are -ENODATA. Lengths and errno values can overlap as
 * unsigned ints, so callers must not test n == ENODATA.
 */
int
zfsd_xattr_get(znode_t *zp, const char *name, void *value, size_t size)
{
	zfsvfs_t *zfsvfs = ZTOZSB(zp);
	int error;

	rw_enter(&zp->z_xattr_lock, RW_READER);
	if (zfsvfs->z_use_sa && zp->z_is_sa) {
		error = zpl_xattr_get_sa(zp, name, value, size);
		if (error != -ENODATA) {
			rw_exit(&zp->z_xattr_lock);
			return (error);
		}
	}
	error = zpl_xattr_get_dir(zp, name, value, size);
	rw_exit(&zp->z_xattr_lock);
	if (error == -ENOENT)
		error = -ENODATA;
	return (error);
}

int
zfsd_xattr_dup(znode_t *zp, const char *name, void **bufp, size_t *alenp)
{
	int n, got;
	void *buf;

	*bufp = NULL;
	*alenp = 0;
	n = zfsd_xattr_get(zp, name, NULL, 0);
	if (n < 0)
		return (n);
	if (n == 0)
		return (0);
	buf = kmem_alloc((size_t)n, KM_SLEEP);
	got = zfsd_xattr_get(zp, name, buf, (size_t)n);
	if (got < 0) {
		kmem_free(buf, (size_t)n);
		return (got);
	}
	if (got == 0) {
		kmem_free(buf, (size_t)n);
		return (0);
	}
	*bufp = buf;
	*alenp = (size_t)n;
	return (got);
}

static int
zpl_xattr_set_dir(znode_t *zp, const char *name, const void *value,
    size_t size, int flags)
{
	znode_t *xdir = NULL, *xzp = NULL;
	vattr_t vap;
	int lflags = LOOKUP_XATTR;
	int err;

	if (value != NULL)
		lflags |= CREATE_XATTR_DIR;
	err = zfs_lookup(zp, NULL, &xdir, lflags, CRED(), NULL, NULL);
	if (err != 0)
		return (err == ENOENT ? ENODATA : err);
	err = zfs_lookup(xdir, (char *)name, &xzp, 0, CRED(), NULL, NULL);
	if (err != 0 && err != ENOENT) {
		zrele(xdir);
		return (err);
	}
	if (value == NULL) {
		if (xzp != NULL)
			err = zfs_remove(xdir, (char *)name, CRED(), 0);
		else
			err = ENODATA;
		if (xzp != NULL)
			zrele(xzp);
		zrele(xdir);
		return (err == ENOENT ? ENODATA : err);
	}
	if (xzp == NULL) {
		if (flags & XATTR_REPLACE) {
			zrele(xdir);
			return (ENODATA);
		}
		memset(&vap, 0, sizeof (vap));
		vap.va_mode = S_IFREG | 0644;
		vap.va_mask = ATTR_MODE;
		vap.va_uid = crgetuid(CRED());
		vap.va_gid = crgetgid(CRED());
		err = zfs_create(xdir, (char *)name, &vap, 0, 0644, &xzp,
		    CRED(), ATTR_NOACLCHECK, NULL);
		if (err != 0) {
			zrele(xdir);
			return (err);
		}
	} else if (flags & XATTR_CREATE) {
		zrele(xzp);
		zrele(xdir);
		return (EEXIST);
	}
	err = zfs_freesp(xzp, 0, 0, S_IFREG | 0644, B_TRUE);
	if (err == 0 && size > 0)
		err = zfs_write_simple(xzp, value, size, 0, NULL);
	zrele(xzp);
	zrele(xdir);
	return (err);
}

static int
zpl_xattr_set_sa(znode_t *zp, const char *name, const void *value,
    size_t size, int flags)
{
	nvlist_t *nvl;
	size_t sa_size;
	int error = 0;

	mutex_enter(&zp->z_lock);
	if (zp->z_xattr_cached == NULL)
		error = zfs_sa_get_xattr(zp);
	mutex_exit(&zp->z_lock);
	if (error != 0)
		return (error);
	nvl = zp->z_xattr_cached;
	if (value == NULL) {
		error = nvlist_remove(nvl, name, DATA_TYPE_BYTE_ARRAY);
		if (error == ENOENT)
			return (zpl_xattr_set_dir(zp, name, NULL, 0, flags));
	} else {
		if (size > DXATTR_MAX_ENTRY_SIZE)
			return (EFBIG);
		error = nvlist_size(nvl, &sa_size, NV_ENCODE_XDR);
		if (error != 0)
			return (error);
		if (sa_size > DXATTR_MAX_SA_SIZE)
			return (EFBIG);
		error = nvlist_add_byte_array(nvl, name,
		    (uchar_t *)(uintptr_t)value, size);
	}
	if (error == 0)
		error = zfs_sa_set_xattr(zp, name, value, size);
	if (error != 0) {
		nvlist_free(nvl);
		zp->z_xattr_cached = NULL;
	}
	return (error);
}

int
zfsd_xattr_set(znode_t *zp, const char *name, const void *value,
    size_t size, int flags)
{
	zfsvfs_t *zfsvfs = ZTOZSB(zp);
	int error, where_sa = 0, where_dir = 0, n;

	rw_enter(&zp->z_xattr_lock, RW_WRITER);
	if (zfsvfs->z_use_sa && zp->z_is_sa) {
		n = zpl_xattr_get_sa(zp, name, NULL, 0);
		if (n >= 0)
			where_sa = 1;
		else if (n != -ENODATA) {
			rw_exit(&zp->z_xattr_lock);
			return (-n);
		}
	}
	n = zpl_xattr_get_dir(zp, name, NULL, 0);
	if (n >= 0)
		where_dir = 1;
	else if (n != -ENODATA) {
		rw_exit(&zp->z_xattr_lock);
		return (-n);
	}
	if (!where_sa && !where_dir) {
		if (flags & XATTR_REPLACE) {
			rw_exit(&zp->z_xattr_lock);
			return (ENODATA);
		}
		if (value == NULL) {
			rw_exit(&zp->z_xattr_lock);
			return (0);
		}
	} else if (flags & XATTR_CREATE) {
		rw_exit(&zp->z_xattr_lock);
		return (EEXIST);
	}
	if (zfsvfs->z_use_sa && zp->z_is_sa &&
	    (zfsvfs->z_xattr_sa || (value == NULL && where_sa))) {
		error = zpl_xattr_set_sa(zp, name, value, size, flags);
		if (error == 0) {
			if (where_dir)
				(void) zpl_xattr_set_dir(zp, name, NULL, 0, 0);
			rw_exit(&zp->z_xattr_lock);
			return (0);
		}
	}
	error = zpl_xattr_set_dir(zp, name, value, size, flags);
	if (error == 0 && where_sa)
		(void) zpl_xattr_set_sa(zp, name, NULL, 0, 0);
	rw_exit(&zp->z_xattr_lock);
	return (error);
}

static int
zpl_inherit_posix_acl(znode_t *dzp, znode_t *zp, int isdir)
{
	void *buf = NULL;
	size_t alen = 0;
	int n, err;
	mode_t mode;
	vattr_t vap;

	if (ZTOZSB(dzp)->z_acl_type != ZFS_ACLTYPE_POSIX)
		zfsd_zfsvfs_refresh_props(ZTOZSB(dzp));
	if (ZTOZSB(dzp)->z_acl_type != ZFS_ACLTYPE_POSIX)
		return (0);
	n = zfsd_xattr_dup(dzp, "system.posix_acl_default", &buf, &alen);
	if (n == -ENODATA || n == -ENOENT || n == 0)
		return (0);
	if (n < 0)
		return (-n);
	err = zfsd_xattr_set(zp, "system.posix_acl_access", buf, (size_t)n, 0);
	if (err == 0 && isdir)
		err = zfsd_xattr_set(zp, "system.posix_acl_default", buf,
		    (size_t)n, 0);
	if (err == 0) {
		mode = zp->z_mode;
		if (zfsd_posix_acl_equiv_mode(buf, (size_t)n, &mode) == 0 &&
		    mode != zp->z_mode) {
			memset(&vap, 0, sizeof (vap));
			vap.va_mask = ATTR_MODE;
			vap.va_mode = mode;
			err = zfs_setattr(zp, &vap, 0, CRED());
		}
	}
	kmem_free(buf, alen);
	return (err);
}

static int
zpl_setxattr(const char *path, const char *name, const char *val, size_t sz,
    int flags)
{
	struct zpl_res r;
	int err;
	mode_t mode;

	ZPL_CRED();
	if (name == NULL || name[0] == '\0')
		return (-EINVAL);
	err = zpl_resolve(path, &r);
	if (err != 0)
		return (-err);
	if (r.zp == NULL || zpl_ro(&r)) {
		int rc = (r.zp == NULL) ? -ENODATA : -EROFS;
		zpl_res_rele(&r);
		return (rc);
	}
	err = zpl_xattr_ns_check(r.zp, name, 1);
	if (err != 0) {
		zpl_res_rele(&r);
		return (-err);
	}
	zfsd_zfsvfs_refresh_props(ZTOZSB(r.zp));
	if (strcmp(name, "system.posix_acl_access") == 0 ||
	    strcmp(name, "system.posix_acl_default") == 0) {
		mode_t dummy = r.zp->z_mode;
		int posix;

		posix = (ZTOZSB(r.zp)->z_acl_type == ZFS_ACLTYPE_POSIX);
		if (val != NULL && sz > 0 &&
		    zfsd_posix_acl_equiv_mode(val, sz, &dummy) != 0) {
			zpl_res_rele(&r);
			return (-EINVAL);
		}
		if (!posix) {
			int merr = 0;

			/*
			 * FUSE_CAP_POSIX_ACL rewrites chmod as a POSIX
			 * ACL set. With acltype=off that is just mode.
			 * Named entries need acltype=posix.
			 */
			if (val != NULL && sz > 0 &&
			    zfsd_posix_acl_has_named(val, sz)) {
				zpl_res_rele(&r);
				return (-EOPNOTSUPP);
			}
			if (val != NULL && sz > 0 &&
			    strcmp(name, "system.posix_acl_access") == 0) {
				vattr_t vap;

				memset(&vap, 0, sizeof (vap));
				vap.va_mask = ATTR_MODE;
				vap.va_mode = dummy;
				merr = zfs_setattr(r.zp, &vap, 0, CRED());
			}
			zpl_res_rele(&r);
			return (-merr);
		}
	}
	err = zfsd_xattr_set(r.zp, name, val, sz, flags);
	if (err == 0 && strcmp(name, "system.posix_acl_access") == 0 &&
	    val != NULL && sz > 0) {
		mode = r.zp->z_mode;
		if (zfsd_posix_acl_equiv_mode(val, sz, &mode) == 0 &&
		    mode != r.zp->z_mode) {
			vattr_t vap;
			int merr;

			memset(&vap, 0, sizeof (vap));
			vap.va_mask = ATTR_MODE;
			vap.va_mode = mode;
			merr = zfs_setattr(r.zp, &vap, 0, CRED());
			if (merr != 0)
				err = merr;
		}
	}

	zpl_res_rele(&r);
	return (-err);
}

static int
zpl_getxattr(const char *path, const char *name, char *val, size_t sz)
{
	struct zpl_res r;
	int err, n;

	ZPL_CRED();
	err = zpl_resolve(path, &r);
	if (err != 0)
		return (-err);
	if (r.zp == NULL) {
		zpl_res_rele(&r);
		return (-ENODATA);
	}
	if (name == NULL || name[0] == '\0') {
		zpl_res_rele(&r);
		return (-EINVAL);
	}
	err = zpl_xattr_ns_check(r.zp, name, 0);
	if (err != 0) {
		zpl_res_rele(&r);
		return (err == EPERM ? -ENODATA : -err);
	}
	zfsd_zfsvfs_refresh_props(ZTOZSB(r.zp));
	if ((strcmp(name, "system.posix_acl_access") == 0 ||
	    strcmp(name, "system.posix_acl_default") == 0) &&
	    ZTOZSB(r.zp)->z_acl_type != ZFS_ACLTYPE_POSIX) {
		zpl_res_rele(&r);
		return (-ENODATA);
	}

	n = zfsd_xattr_get(r.zp, name, (sz == 0) ? NULL : val, sz);
	zpl_res_rele(&r);
	if (n == -ENOENT)
		return (-ENODATA);
	return (n);
}

static int
zpl_listxattr_add(char *buf, size_t sz, size_t *used, const char *name)
{
	size_t n;

	if (zpl_xattr_privileged(name) && crgetuid(CRED()) != 0)
		return (0);
	n = strlen(name) + 1;
	if (buf != NULL) {
		if (*used + n > sz)
			return (ERANGE);
		(void) memcpy(buf + *used, name, n);
	}
	*used += n;
	return (0);
}


static int
zpl_listxattr(const char *path, char *buf, size_t sz)
{
	struct zpl_res r;
	znode_t *xdir = NULL;
	zap_cursor_t zc;
	zap_attribute_t *za;
	size_t used = 0;
	int err;

	ZPL_CRED();
	err = zpl_resolve(path, &r);
	if (err != 0)
		return (-err);
	if (r.zp == NULL) {
		zpl_res_rele(&r);
		return (0);
	}
	rw_enter(&r.zp->z_xattr_lock, RW_READER);
	if (ZTOZSB(r.zp)->z_use_sa && r.zp->z_is_sa) {
		mutex_enter(&r.zp->z_lock);
		if (r.zp->z_xattr_cached == NULL)
			(void) zfs_sa_get_xattr(r.zp);
		mutex_exit(&r.zp->z_lock);
		if (r.zp->z_xattr_cached != NULL) {
			nvpair_t *nvp = NULL;

			while ((nvp = nvlist_next_nvpair(r.zp->z_xattr_cached,
			    nvp)) != NULL) {
				err = zpl_listxattr_add(buf, sz, &used,
				    nvpair_name(nvp));
				if (err != 0) {
					rw_exit(&r.zp->z_xattr_lock);
					zpl_res_rele(&r);
					return (-err);
				}
			}
		}
	}
	rw_exit(&r.zp->z_xattr_lock);
	err = zpl_xattr_dir(r.zp, &xdir, 0);
	if (err == ENOENT) {
		zpl_res_rele(&r);
		return ((int)used);
	}
	if (err != 0) {
		zpl_res_rele(&r);
		return (-err);
	}
	za = zap_attribute_alloc();
	zap_cursor_init(&zc, ZTOZSB(xdir)->z_os, xdir->z_id);
	while (zap_cursor_retrieve(&zc, za) == 0) {
		if (strcmp(za->za_name, ".") == 0 ||
		    strcmp(za->za_name, "..") == 0) {
			zap_cursor_advance(&zc);
			continue;
		}
		err = zpl_listxattr_add(buf, sz, &used, za->za_name);
		if (err != 0) {
			zap_cursor_fini(&zc);
			zap_attribute_free(za);
			zrele(xdir);
			zpl_res_rele(&r);
			return (-err);
		}
		zap_cursor_advance(&zc);
	}
	zap_cursor_fini(&zc);
	zap_attribute_free(za);
	zrele(xdir);
	zpl_res_rele(&r);
	return ((int)used);
}

static int
zpl_removexattr(const char *path, const char *name)
{
	struct zpl_res r;
	int err;

	ZPL_CRED();
	err = zpl_resolve(path, &r);
	if (err != 0)
		return (-err);
	if (r.zp == NULL || zpl_ro(&r)) {
		int rc = (r.zp == NULL) ? -ENODATA : -EROFS;
		zpl_res_rele(&r);
		return (rc);
	}
	if (name == NULL || name[0] == '\0') {
		zpl_res_rele(&r);
		return (-EINVAL);
	}
	err = zpl_xattr_ns_check(r.zp, name, 1);
	if (err != 0) {
		zpl_res_rele(&r);
		return (-err);
	}
	err = zfsd_xattr_set(r.zp, name, NULL, 0, 0);

	zpl_res_rele(&r);
	return (err == ENOENT ? -ENODATA : -err);
}

static int
zpl_opendir(const char *path, struct fuse_file_info *fi)
{
	return (zpl_open(path, fi));
}

static int
zpl_releasedir(const char *path, struct fuse_file_info *fi)
{
	return (zpl_release(path, fi));
}

static int
zpl_fsyncdir(const char *path, int datasync, struct fuse_file_info *fi)
{
	return (zpl_fsync(path, datasync, fi));
}

static int
zpl_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t off,
    struct fuse_file_info *fi, enum fuse_readdir_flags flags)
{
	struct zpl_res r;
	int err;
	off_t cursor = off;

	ZPL_CRED();
	err = zpl_obj_or_walk(&r, path, fi);
	if (err != 0)
		return (-err);

	if (cursor <= 0) {
		if (zpl_fill(buf, filler, ".", NULL, 1, 0) != 0)
			goto done;
		cursor = 1;
	}
	if (cursor == 1) {
		if (zpl_fill(buf, filler, "..", NULL, 2, 0) != 0)
			goto done;
		cursor = 2;
	}
	if (r.kind == ZPL_CTLDIR) {
		if (cursor <= 2) {
			if (zpl_fill(buf, filler, "snapshot", NULL, 3, 0) != 0)
				goto done;
			cursor = 3;
		}
		if (cursor == 3) {
			if (zpl_fill(buf, filler, "shares", NULL, 4, 0) != 0)
				goto done;
		}
		goto done;

	}
	if (r.kind == ZPL_SHARESDIR)
		goto done;
	if (r.kind == ZPL_SNAPDIR) {
		uint64_t cookie;
		char name[MAXNAMELEN];
		dsl_pool_t *dp = dmu_objset_pool(r.m->zfsvfs->z_os);

		cookie = (cursor < ZPL_DIRENT_BIAS) ? 0 :
		    zpl_dir_cookie(cursor);
		dsl_pool_config_enter(dp, FTAG);
		for (;;) {
			err = dmu_snapshot_list_next(r.m->zfsvfs->z_os,
			    sizeof (name), name, NULL, &cookie, NULL);
			if (err != 0)
				break;
			if (zpl_fill(buf, filler, name, NULL,
			    zpl_dir_off(cookie), 0) != 0)
				break;
		}
		dsl_pool_config_exit(dp, FTAG);
		goto done;
	}
	if (r.kind == ZPL_NORM && r.zp != NULL &&
	    r.zp->z_id == r.zfsvfs->z_root && cursor <= 2 &&
	    r.zfsvfs->z_show_ctldir == ZFS_SNAPDIR_VISIBLE) {
		if (zpl_fill(buf, filler, ".zfs", NULL, 3, 0) != 0)
			goto done;
		cursor = 3;
	}

	if (r.zp == NULL)
		goto done;
	{
		zap_cursor_t zc;
		zap_attribute_t *za;
		uint64_t zoff = 0;
		objset_t *os = r.zfsvfs->z_os;
		int plus = (flags & FUSE_READDIR_PLUS) ? FUSE_FILL_DIR_PLUS : 0;

		if (cursor >= ZPL_DIRENT_BIAS)
			zoff = zpl_dir_cookie(cursor);
		za = zap_attribute_alloc();
		(void) zap_cursor_init_serialized(&zc, os, r.zp->z_id, zoff);
		while (zap_cursor_retrieve(&zc, za) == 0) {
			struct stat st;
			off_t next;

			if (strcmp(za->za_name, ".") == 0 ||
			    strcmp(za->za_name, "..") == 0) {
				zap_cursor_advance(&zc);
				continue;
			}
			zap_cursor_advance(&zc);
			next = zpl_dir_off(zap_cursor_serialize(&zc));
			memset(&st, 0, sizeof (st));
			st.st_ino = ZFS_DIRENT_OBJ(za->za_first_integer);
			st.st_mode = DTTOIF(ZFS_DIRENT_TYPE(
			    za->za_first_integer));
			if (plus) {
				znode_t *ezp = NULL;

				if (zfs_zget(r.zfsvfs, st.st_ino, &ezp) == 0) {
					st.st_mode = ezp->z_mode;
					st.st_nlink = (nlink_t)ezp->z_links;
					st.st_size = (off_t)ezp->z_size;
					st.st_uid = (uid_t)ezp->z_uid;
					st.st_gid = (gid_t)ezp->z_gid;
					zrele(ezp);
				}
			}
			if (zpl_fill(buf, filler, za->za_name, &st,
			    next, plus) != 0)
				break;
		}
		zap_cursor_fini(&zc);
		zap_attribute_free(za);
	}
done:
	zpl_res_rele(&r);
	return (0);
}

static void *
zpl_init(struct fuse_conn_info *conn, struct fuse_config *cfg)
{
	if (conn != NULL) {
		unsigned cap = FUSE_CAP_ATOMIC_O_TRUNC | FUSE_CAP_IOCTL_DIR |
		    FUSE_CAP_EXPORT_SUPPORT | FUSE_CAP_PARALLEL_DIROPS |
		    FUSE_CAP_POSIX_LOCKS |
		    FUSE_CAP_FLOCK_LOCKS | FUSE_CAP_AUTO_INVAL_DATA |
		    FUSE_CAP_ASYNC_READ | FUSE_CAP_COPY_FILE_RANGE;
		conn->want |= (conn->capable & cap);
		conn->want &= ~FUSE_CAP_WRITEBACK_CACHE;
		/*
		 * Always request POSIX ACL support. Tests often
		 * `zfs set acltype=posix` after mount, and without
		 * this cap the kernel never caches system.posix_acl_*
		 * so execve uses i_mode (other+x) instead of the ACL.
		 * FUSE_CAP_POSIX_ACL does not enable default_permissions.
		 * With the cap, chmod is rewritten as a POSIX ACL
		 * setxattr: acltype=off treats an equiv-mode ACL as
		 * setattr and returns ENODATA for getxattr.
		 */
		if (conn->capable & FUSE_CAP_POSIX_ACL) {
			conn->want |= FUSE_CAP_POSIX_ACL;
			zpl_dont_mask = 1;
		}
		if (conn->max_background == 0 || conn->max_background > 16)
			conn->max_background = 16;
		if (conn->congestion_threshold == 0 ||
		    conn->congestion_threshold > 8)
			conn->congestion_threshold = 8;
		/*
		 * write_buf/read_buf make libfuse enable SPLICE_READ by
		 * default. With a capped fuse_loop_mt pool, splice of a
		 * 1MiB FUSE request can occupy every worker so umount
		 * and CUSE ioctl never complete (classic FUSE deadlock).
		 */
		conn->want &= ~(FUSE_CAP_SPLICE_READ | FUSE_CAP_SPLICE_WRITE |
		    FUSE_CAP_SPLICE_MOVE);
	}
	cfg->kernel_cache = 0;
	/*
	 * direct_io disables mmap (ENODEV). ZTS exec_001 runs
	 * mmap PROT_EXEC on a binary in the filesystem; keep the
	 * page cache so that mapping works. kernel_cache stays
	 * off so libfuse does not set FOPEN_KEEP_CACHE.
	 */
	cfg->direct_io = 0;
	cfg->nullpath_ok = 1;
	cfg->use_ino = 1;
	cfg->hard_remove = 0;
	cfg->attr_timeout = 0;
	cfg->entry_timeout = 0;
	cfg->negative_timeout = 0;
	cfg->intr = 0;
	return (fuse_get_context()->private_data);
}

static void
zpl_destroy(void *data)
{
	(void) data;
}

static off_t
zpl_lseek(const char *path, off_t off, int whence, struct fuse_file_info *fi)
{
	struct zpl_res r;
	loff_t noff = off;
	int err;
	ulong_t cmd;

	ZPL_CRED();
	if (whence != SEEK_HOLE && whence != SEEK_DATA)
		return (-EINVAL);
	err = zpl_obj_or_walk(&r, path, fi);
	if (err != 0)
		return (-err);
	if (r.zp == NULL) {
		zpl_res_rele(&r);
		return (-EINVAL);
	}
	cmd = (whence == SEEK_HOLE) ? F_SEEK_HOLE : F_SEEK_DATA;
	err = zfs_holey(r.zp, cmd, &noff);
	zpl_res_rele(&r);
	if (err != 0)
		return (-err);
	return ((off_t)noff);
}

static int
zpl_fallocate(const char *path, int mode, off_t off, off_t len,
    struct fuse_file_info *fi)
{
	struct zpl_res r;
	flock64_t bf;
	int err;

	ZPL_CRED();
	err = zpl_obj_or_walk(&r, path, fi);
	if (err != 0)
		return (-err);
	if (r.zp == NULL || zpl_ro(&r)) {
		zpl_res_rele(&r);
		return (r.zp == NULL ? -EINVAL : -EROFS);
	}
	if (off < 0 || len < 0) {
		zpl_res_rele(&r);
		return (-EINVAL);
	}
	if (mode & ~(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE)) {
		zpl_res_rele(&r);
		return (-EOPNOTSUPP);
	}
	if (mode & FALLOC_FL_PUNCH_HOLE) {
		if ((mode & FALLOC_FL_KEEP_SIZE) == 0) {
			zpl_res_rele(&r);
			return (-EOPNOTSUPP);
		}
		memset(&bf, 0, sizeof (bf));
		bf.l_start = off;
		bf.l_len = len;
		err = zfs_space(r.zp, F_FREESP, &bf, 0, 0, CRED());
	} else {
		uint64_t end;

		if ((uint64_t)off > UINT64_MAX - (uint64_t)len) {
			zpl_res_rele(&r);
			return (-EFBIG);
		}
		end = (uint64_t)off + (uint64_t)len;
		if (!(mode & FALLOC_FL_KEEP_SIZE) && end > r.zp->z_size) {
			vattr_t vap;
			memset(&vap, 0, sizeof (vap));
			vap.va_mask = ATTR_SIZE;
			vap.va_size = end;
			err = zfs_setattr(r.zp, &vap, 0, CRED());
		} else {
			err = 0;
		}
	}

	zpl_res_rele(&r);
	return (-err);
}

/*
 * One zfs_clone_range() of a 128MiB FUSE copy_file_range holds every L0
 * dbuf in the range (dmu_read_l0_bps / dmu_brt_clone). Userspace ARC can
 * sit at MIN_ARC_MAX (64MiB); reclaim waits on those holds and the FUSE
 * request never completes, so block_cloning_large_offset is KILLed.
 * Cap each clone at a quarter of DMU_MAX_ACCESS and keep it record-aligned.
 * The first chunk at a large offset still grows dest nlevels -- that is
 * the case the test exists for — without pinning 1024 128K dbufs at once.
 */
static uint64_t
zpl_clone_chunk(uint64_t blksz, uint64_t len)
{
	uint64_t chunk = (uint64_t)DMU_MAX_ACCESS / 4;

	if (chunk > len)
		chunk = len;
	/*
	 * Only split a request that does not fit in the cap. The last
	 * piece, including a partial EOF block, has to be one
	 * zfs_clone_range() call: a non-multiple length is legal at
	 * EOF, but a follow-up call of just that tail is rejected
	 * (it would pin the destination at a tiny block size).
	 * Aligning a 513-byte hole down to 512 and then dropping the
	 * last byte made bclone_samefs_hole clone a short file.
	 */
	if (blksz > 1 && ISP2(blksz) && chunk >= blksz && chunk < len)
		chunk = P2ALIGN_TYPED(chunk, blksz, uint64_t);
	if (chunk == 0)
		chunk = len;
	return (chunk);
}

static int
zpl_clone_range_chunked(znode_t *inzp, uint64_t *inoffp, znode_t *outzp,
    uint64_t *outoffp, uint64_t *lenp, cred_t *cr)
{
	uint64_t inoff = *inoffp, outoff = *outoffp, left = *lenp, done = 0;
	int err = 0;

	while (left > 0) {
		uint64_t got = zpl_clone_chunk(inzp->z_blksz, left);

		err = zfs_clone_range(inzp, &inoff, outzp, &outoff, &got, cr);
		if (err != 0)
			break;
		if (got == 0)
			break;
		done += got;
		left -= got;
	}
	*inoffp = inoff;
	*outoffp = outoff;
	*lenp = done;
	if (done > 0)
		return (0);
	return (err);
}

/*
 * Byte copy used when zfs_clone_range cannot take the range (disabled,
 * unaligned, EXDEV, EAGAIN), matching Linux zpl_copy_file_range's
 * generic_copy_file_range fallback. clonefile -f of large_offset still
 * requires a real clone; this path is for copy_file_range compatibility.
 */
static int
zpl_copy_range_data(znode_t *inzp, uint64_t inoff, znode_t *outzp,
    uint64_t outoff, uint64_t *lenp)
{
	uint64_t left = *lenp, done = 0;
	const size_t buflen = 131072;
	char *buf;
	int err = 0;

	buf = malloc(buflen);
	if (buf == NULL)
		return (ENOMEM);
	while (left > 0) {
		size_t n = (size_t)MIN(left, (uint64_t)buflen);
		zfs_uio_t uio;
		iovec_t iov;

		iov.iov_base = buf;
		iov.iov_len = n;
		zfs_uio_iovec_init(&uio, &iov, 1, inoff + done, UIO_SYSSPACE,
		    (ssize_t)n, 0);
		err = zfs_read(inzp, &uio, 0, CRED());
		if (err != 0)
			break;
		n -= (size_t)uio.uio_resid;
		if (n == 0)
			break;
		iov.iov_base = buf;
		iov.iov_len = n;
		zfs_uio_iovec_init(&uio, &iov, 1, outoff + done, UIO_SYSSPACE,
		    (ssize_t)n, 0);
		err = zfs_write(outzp, &uio, 0, CRED());
		if (err != 0)
			break;
		n -= (size_t)uio.uio_resid;
		if (n == 0)
			break;
		done += n;
		left -= n;
	}
	free(buf);
	*lenp = done;
	if (done > 0)
		return (0);
	return (err);
}

static ssize_t
zpl_copy_file_range(const char *path_in, struct fuse_file_info *fi_in,
    off_t off_in, const char *path_out, struct fuse_file_info *fi_out,
    off_t off_out, size_t len, int flags)
{
	struct zpl_res in, out;
	uint64_t inoff = (uint64_t)off_in, outoff = (uint64_t)off_out;
	uint64_t copylen = 0;
	int err;

	ZPL_CRED();
	if (off_in < 0 || off_out < 0 || flags != 0)
		return (flags != 0 ? -EOPNOTSUPP : -EINVAL);
	if ((uint64_t)off_in > UINT64_MAX - (uint64_t)len ||
	    (uint64_t)off_out > UINT64_MAX - (uint64_t)len)
		return (-EFBIG);
	err = zpl_obj_or_walk(&in, path_in, fi_in);
	if (err != 0)
		return (-err);
	err = zpl_obj_or_walk(&out, path_out, fi_out);
	if (err != 0) {
		zpl_res_rele(&in);
		return (-err);
	}
	if (in.zp == NULL || out.zp == NULL || zpl_ro(&out)) {
		zpl_res_rele(&in);
		zpl_res_rele(&out);
		return (-EPERM);
	}
	if (zfs_bclone_enabled) {
		copylen = len;
		err = zpl_clone_range_chunked(in.zp, &inoff, out.zp, &outoff,
		    &copylen, CRED());
	} else {
		err = EOPNOTSUPP;
	}
	/*
	 * Linux zpl_copy_file_range falls back to a generic byte copy on
	 * EOPNOTSUPP/EINVAL/EXDEV/EAGAIN. FUSE has no VFS helper, so do
	 * the copy here. Only when clone made no progress: a short clone
	 * must not be mixed with a rewrite of the rest (get_same_blocks).
	 */
	if (copylen == 0 && (err == EOPNOTSUPP || err == EINVAL ||
	    err == EXDEV || err == EAGAIN)) {
		uint64_t remain = len;

		err = zpl_copy_range_data(in.zp, inoff, out.zp, outoff,
		    &remain);
		copylen = remain;
	}
	zpl_res_rele(&in);
	zpl_res_rele(&out);
	if (err != 0)
		return (-err);
	return ((ssize_t)copylen);
}

#ifdef __linux__
/*
 * Read st_dev for a mount from /proc/self/mountinfo. Never stat() a
 * live FUSE path from the daemon: attr_timeout is 0, so getattr
 * re-enters the worker and deadlocks (or wedges the CUSE mount
 * thread if fuse_loop has not yet taken a request).
 */
static int
zpl_mountinfo_dev(const char *mnt, dev_t *devp)
{
	FILE *fp;
	char line[4096];
	size_t want;

	if (mnt == NULL || mnt[0] == '\0' || devp == NULL)
		return (EINVAL);
	*devp = 0;
	want = strlen(mnt);
	fp = fopen("/proc/self/mountinfo", "r");
	if (fp == NULL)
		return (errno);
	while (fgets(line, sizeof (line), fp) != NULL) {
		unsigned id, parent, maj, min;
		char *p;
		size_t mpl;
		int n;

		if (sscanf(line, "%u %u %u:%u", &id, &parent, &maj, &min) != 4)
			continue;
		p = line;
		for (n = 0; *p != '\0' && n < 4; n++) {
			while (*p == ' ')
				p++;
			while (*p != '\0' && *p != ' ')
				p++;
		}
		while (*p == ' ')
			p++;
		mpl = 0;
		while (p[mpl] != '\0' && p[mpl] != ' ')
			mpl++;
		if (mpl == want && strncmp(p, mnt, want) == 0) {
			*devp = makedev(maj, min);
			(void) fclose(fp);
			return (0);
		}
	}
	(void) fclose(fp);
	return (ENOENT);
}

static int
zpl_mountinfo_dev_by_id(unsigned mnt_id, dev_t *devp)
{
	FILE *fp;
	char line[4096];

	if (devp == NULL)
		return (EINVAL);
	*devp = 0;
	fp = fopen("/proc/self/mountinfo", "r");
	if (fp == NULL)
		return (errno);
	while (fgets(line, sizeof (line), fp) != NULL) {
		unsigned id, parent, maj, min;

		if (sscanf(line, "%u %u %u:%u", &id, &parent, &maj, &min) != 4)
			continue;
		if (id == mnt_id) {
			*devp = makedev(maj, min);
			(void) fclose(fp);
			return (0);
		}
	}
	(void) fclose(fp);
	return (ENOENT);
}

/*
 * ino/mnt_id/flags for a client fd without dup'ing it or fstat.
 * Linux 4.20+ fdinfo includes ino. fstat of a stolen FUSE fd
 * issues getattr into this daemon (attr_timeout=0).
 */
static int
zpl_fdinfo_lookup(pid_t pid, int fd, uint64_t *inop, unsigned *mnt_idp,
    int *flagsp)
{
	char path[64], line[256];
	FILE *fp;
	uint64_t ino = 0;
	unsigned mnt_id = 0;
	int flags = -1, got_ino = 0;

	if (pid <= 0 || fd < 0)
		return (EBADF);
	(void) snprintf(path, sizeof (path), "/proc/%d/fdinfo/%d",
	    (int)pid, fd);
	fp = fopen(path, "r");
	if (fp == NULL)
		return (errno);
	while (fgets(line, sizeof (line), fp) != NULL) {
		if (strncmp(line, "ino:", 4) == 0) {
			ino = strtoull(line + 4, NULL, 0);
			got_ino = 1;
		} else if (strncmp(line, "mnt_id:", 7) == 0) {
			mnt_id = (unsigned)strtoul(line + 7, NULL, 0);
		} else if (strncmp(line, "flags:", 6) == 0) {
			flags = (int)strtol(line + 6, NULL, 8);
		}
	}
	(void) fclose(fp);
	if (!got_ino || flags < 0)
		return (EBADF);
	if (inop != NULL)
		*inop = ino;
	if (mnt_idp != NULL)
		*mnt_idp = mnt_id;
	if (flagsp != NULL)
		*flagsp = flags;
	return (0);
}

static int
zpl_zget_client_fd(zfsvfs_t *zfsvfs, pid_t pid, int clfd, znode_t **zpp)
{
	uint64_t ino = 0;
	unsigned mnt_id = 0;
	int err, fl, acc;
	dev_t dev = 0;

	*zpp = NULL;
	if (zfsvfs == NULL)
		return (EBADF);
	pid = zfsd_linux_tgid(pid);
	err = zpl_fdinfo_lookup(pid, clfd, &ino, &mnt_id, &fl);
	if (err != 0)
		return (EBADF);
#ifdef O_PATH
	if (fl & O_PATH)
		return (EBADF);
#endif
	acc = fl & O_ACCMODE;
	if (acc == O_WRONLY)
		return (EBADF);
	if (mnt_id != 0)
		(void) zpl_mountinfo_dev_by_id(mnt_id, &dev);
	if (dev != 0)
		err = zfsd_zpl_zget_by_dev(dev, ino, zpp);
	else
		err = zfs_zget(zfsvfs, ino, zpp);
	if (err != 0)
		return (err);
	if (*zpp == NULL || ZTOZSB(*zpp) != zfsvfs) {
		if (*zpp != NULL)
			zrele(*zpp);
		*zpp = NULL;
		return (EXDEV);
	}
	if (!S_ISREG((*zpp)->z_mode)) {
		zrele(*zpp);
		*zpp = NULL;
		return (EINVAL);
	}
	err = zfs_zaccess(*zpp, ACE_READ_DATA, 0, B_FALSE, CRED());
	if (err != 0) {
		zrele(*zpp);
		*zpp = NULL;
	}
	return (err);
}

static int
zpl_clone_ioctl(struct zpl_res *dst, int srcfd, uint64_t inoff,
    uint64_t outoff, uint64_t len)
{
	struct fuse_context *ctx = fuse_get_context();
	znode_t *inzp = NULL;
	uint64_t want;
	int err;
	pid_t pid;

	if (!zfs_bclone_enabled)
		return (EOPNOTSUPP);
	if (dst->zp == NULL || zpl_ro(dst))
		return (EPERM);
	err = zfs_zaccess(dst->zp, ACE_WRITE_DATA, 0, B_FALSE, CRED());
	if (err != 0)
		return (err);
	pid = (ctx != NULL) ? ctx->pid : 0;
	err = zpl_zget_client_fd(dst->zfsvfs, pid, srcfd, &inzp);
	if (err != 0)
		return (err);
	if (len == 0) {
		if (inoff >= inzp->z_size) {
			zrele(inzp);
			return (0);
		}
		len = inzp->z_size - inoff;
	}
	want = len;
	err = zpl_clone_range_chunked(inzp, &inoff, dst->zp, &outoff, &len,
	    CRED());
	zrele(inzp);
	if (err == 0 && want != 0 && len != want)
		err = EINVAL;
	return (err);
}
#endif

#ifdef __linux__
static struct {
	uint64_t zfs_flag;
	uint32_t fs_flag;
	uint32_t xflag;
} zpl_flags_lookup[] = {
	{ ZFS_IMMUTABLE, FS_IMMUTABLE_FL, FS_XFLAG_IMMUTABLE },
	{ ZFS_APPENDONLY, FS_APPEND_FL, FS_XFLAG_APPEND },
	{ ZFS_NODUMP, FS_NODUMP_FL, FS_XFLAG_NODUMP },
	{ ZFS_PROJINHERIT, FS_PROJINHERIT_FL, FS_XFLAG_PROJINHERIT }
};

#define	zpl_fchange(f0, f1, b0, b1)	(!((f0) & (b0)) != !((f1) & (b1)))

static uint32_t
zpl_ioctl_getflags_val(znode_t *zp)
{
	uint64_t zfs_flags = zp->z_pflags;
	uint32_t ioctl_flags = 0;
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(zpl_flags_lookup); i++) {
		if (zfs_flags & zpl_flags_lookup[i].zfs_flag)
			ioctl_flags |= zpl_flags_lookup[i].fs_flag;
	}
	return (ioctl_flags & ZFS_FL_USER_VISIBLE);
}

static uint32_t
zpl_ioctl_getxflags_val(znode_t *zp)
{
	uint64_t zfs_flags = zp->z_pflags;
	uint32_t ioctl_flags = 0;
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(zpl_flags_lookup); i++) {
		if (zfs_flags & zpl_flags_lookup[i].zfs_flag)
			ioctl_flags |= zpl_flags_lookup[i].xflag;
	}
	return (ioctl_flags);
}

static int
zpl_ioc_copyout(void *data, const void *src, size_t n, unsigned int cmd)
{
	size_t sz = _IOC_SIZE(cmd);

	if (data == NULL)
		return (EFAULT);
	if (sz == 0)
		sz = n;
	if (sz < n)
		return (EINVAL);
	(void) memcpy(data, src, n);
	if (sz > n)
		(void) memset((char *)data + n, 0, sz - n);
	return (0);
}

static int
zpl_ioc_copyin(void *dst, const void *data, size_t n, unsigned int cmd)
{
	size_t sz = _IOC_SIZE(cmd);

	if (data == NULL)
		return (EFAULT);
	if (sz == 0)
		sz = n;
	if (sz < n)
		return (EINVAL);
	(void) memcpy(dst, data, n);
	return (0);
}

static int
zpl_ioctl_owner_or_root(znode_t *zp)
{
	uid_t uid = crgetuid(CRED());

	if (uid == 0 || uid == (uid_t)zp->z_uid)
		return (0);
	return (EACCES);
}

static int
zpl_ioctl_setflags_xva(znode_t *zp, uint32_t ioctl_flags, xvattr_t *xva)
{
	uint64_t zfs_flags = zp->z_pflags;
	xoptattr_t *xoap;

	if (ioctl_flags & ~(FS_IMMUTABLE_FL | FS_APPEND_FL | FS_NODUMP_FL |
	    FS_PROJINHERIT_FL))
		return (EOPNOTSUPP);
	if (ioctl_flags & ~ZFS_FL_USER_MODIFIABLE)
		return (EACCES);
	if ((zpl_fchange(ioctl_flags, zfs_flags, FS_IMMUTABLE_FL,
	    ZFS_IMMUTABLE) ||
	    zpl_fchange(ioctl_flags, zfs_flags, FS_APPEND_FL,
	    ZFS_APPENDONLY)) && crgetuid(CRED()) != 0)
		return (EPERM);
	if (zpl_ioctl_owner_or_root(zp) != 0)
		return (EACCES);

	xva_init(xva);
	xoap = xva_getxoptattr(xva);
	if (xoap == NULL)
		return (ENOMEM);

#define	ZPL_FLAG_CHANGE(iflag, zflag, xflag, xfield)	do {	\
	if (((ioctl_flags & (iflag)) && !(zfs_flags & (zflag))) || \
	    ((zfs_flags & (zflag)) && !(ioctl_flags & (iflag)))) { \
		XVA_SET_REQ(xva, (xflag));			\
		(xfield) = ((ioctl_flags & (iflag)) != 0);	\
	}							\
} while (0)

	ZPL_FLAG_CHANGE(FS_IMMUTABLE_FL, ZFS_IMMUTABLE, XAT_IMMUTABLE,
	    xoap->xoa_immutable);
	ZPL_FLAG_CHANGE(FS_APPEND_FL, ZFS_APPENDONLY, XAT_APPENDONLY,
	    xoap->xoa_appendonly);
	ZPL_FLAG_CHANGE(FS_NODUMP_FL, ZFS_NODUMP, XAT_NODUMP,
	    xoap->xoa_nodump);
	ZPL_FLAG_CHANGE(FS_PROJINHERIT_FL, ZFS_PROJINHERIT, XAT_PROJINHERIT,
	    xoap->xoa_projinherit);
#undef	ZPL_FLAG_CHANGE
	return (0);
}

static int
zpl_ioctl_setdosflags_xva(znode_t *zp, uint64_t ioctl_flags, xvattr_t *xva)
{
	uint64_t zfs_flags = zp->z_pflags;
	xoptattr_t *xoap;

	if (ioctl_flags & (~ZFS_DOS_FL_USER_VISIBLE))
		return (EOPNOTSUPP);
	if ((zpl_fchange(ioctl_flags, zfs_flags, ZFS_IMMUTABLE,
	    ZFS_IMMUTABLE) ||
	    zpl_fchange(ioctl_flags, zfs_flags, ZFS_APPENDONLY,
	    ZFS_APPENDONLY)) && crgetuid(CRED()) != 0)
		return (EPERM);
	if (zpl_ioctl_owner_or_root(zp) != 0)
		return (EACCES);

	xva_init(xva);
	xoap = xva_getxoptattr(xva);
	if (xoap == NULL)
		return (ENOMEM);

#define	ZPL_DOS_CHANGE(iflag, xflag, xfield)	do {		\
	if (((ioctl_flags & (iflag)) && !(zfs_flags & (iflag))) || \
	    ((zfs_flags & (iflag)) && !(ioctl_flags & (iflag)))) { \
		XVA_SET_REQ(xva, (xflag));			\
		(xfield) = ((ioctl_flags & (iflag)) != 0);	\
	}							\
} while (0)

	ZPL_DOS_CHANGE(ZFS_IMMUTABLE, XAT_IMMUTABLE, xoap->xoa_immutable);
	ZPL_DOS_CHANGE(ZFS_APPENDONLY, XAT_APPENDONLY, xoap->xoa_appendonly);
	ZPL_DOS_CHANGE(ZFS_NODUMP, XAT_NODUMP, xoap->xoa_nodump);
	ZPL_DOS_CHANGE(ZFS_READONLY, XAT_READONLY, xoap->xoa_readonly);
	ZPL_DOS_CHANGE(ZFS_HIDDEN, XAT_HIDDEN, xoap->xoa_hidden);
	ZPL_DOS_CHANGE(ZFS_SYSTEM, XAT_SYSTEM, xoap->xoa_system);
	ZPL_DOS_CHANGE(ZFS_ARCHIVE, XAT_ARCHIVE, xoap->xoa_archive);
	ZPL_DOS_CHANGE(ZFS_NOUNLINK, XAT_NOUNLINK, xoap->xoa_nounlink);
	ZPL_DOS_CHANGE(ZFS_REPARSE, XAT_REPARSE, xoap->xoa_reparse);
	ZPL_DOS_CHANGE(ZFS_OFFLINE, XAT_OFFLINE, xoap->xoa_offline);
	ZPL_DOS_CHANGE(ZFS_SPARSE, XAT_SPARSE, xoap->xoa_sparse);
#undef	ZPL_DOS_CHANGE
	return (0);
}

static int
zpl_ioctl_setxflags_xva(znode_t *zp, uint32_t ioctl_flags, xvattr_t *xva)
{
	uint64_t zfs_flags = zp->z_pflags;
	xoptattr_t *xoap;

	if (ioctl_flags & ~(FS_XFLAG_IMMUTABLE | FS_XFLAG_APPEND |
	    FS_XFLAG_NODUMP | FS_XFLAG_PROJINHERIT))
		return (EOPNOTSUPP);
	if ((zpl_fchange(ioctl_flags, zfs_flags, FS_XFLAG_IMMUTABLE,
	    ZFS_IMMUTABLE) ||
	    zpl_fchange(ioctl_flags, zfs_flags, FS_XFLAG_APPEND,
	    ZFS_APPENDONLY)) && crgetuid(CRED()) != 0)
		return (EPERM);
	if (zpl_ioctl_owner_or_root(zp) != 0)
		return (EACCES);

	xva_init(xva);
	xoap = xva_getxoptattr(xva);
	if (xoap == NULL)
		return (ENOMEM);

#define	ZPL_XFLAG_CHANGE(iflag, zflag, xflag, xfield)	do {	\
	if (((ioctl_flags & (iflag)) && !(zfs_flags & (zflag))) || \
	    ((zfs_flags & (zflag)) && !(ioctl_flags & (iflag)))) { \
		XVA_SET_REQ(xva, (xflag));			\
		(xfield) = ((ioctl_flags & (iflag)) != 0);	\
	}							\
} while (0)

	ZPL_XFLAG_CHANGE(FS_XFLAG_IMMUTABLE, ZFS_IMMUTABLE, XAT_IMMUTABLE,
	    xoap->xoa_immutable);
	ZPL_XFLAG_CHANGE(FS_XFLAG_APPEND, ZFS_APPENDONLY, XAT_APPENDONLY,
	    xoap->xoa_appendonly);
	ZPL_XFLAG_CHANGE(FS_XFLAG_NODUMP, ZFS_NODUMP, XAT_NODUMP,
	    xoap->xoa_nodump);
	ZPL_XFLAG_CHANGE(FS_XFLAG_PROJINHERIT, ZFS_PROJINHERIT,
	    XAT_PROJINHERIT, xoap->xoa_projinherit);
#undef	ZPL_XFLAG_CHANGE
	return (0);
}
#endif

static int
zpl_ioctl(const char *path, int cmd, void *arg,
    struct fuse_file_info *fi, unsigned int flags, void *data)
{
	struct zpl_res r;
	int err;
	unsigned int ucmd = (unsigned int)cmd;

	(void) arg;
	(void) flags;
	ZPL_CRED();
	err = zpl_obj_or_walk(&r, path, fi);
	if (err != 0)
		return (-err);
	if (r.zp == NULL) {
		zpl_res_rele(&r);
		return (-ENOTTY);
	}
#ifdef __linux__
	if (ucmd == FS_IOC32_GETVERSION)
		ucmd = FS_IOC_GETVERSION;
	if (ucmd == FS_IOC32_GETFLAGS)
		ucmd = FS_IOC_GETFLAGS;
	if (ucmd == FS_IOC32_SETFLAGS)
		ucmd = FS_IOC_SETFLAGS;

	switch (ucmd) {
	case FS_IOC_GETVERSION: {
		uint32_t generation = r.zp->z_gen;

		err = zpl_ioc_copyout(data, &generation, sizeof (generation),
		    ucmd);
		zpl_res_rele(&r);
		return (-err);
	}
	case FS_IOC_GETFLAGS: {
		uint32_t fl = zpl_ioctl_getflags_val(r.zp);

		err = zpl_ioc_copyout(data, &fl, sizeof (fl), ucmd);
		zpl_res_rele(&r);
		return (-err);
	}
	case FS_IOC_SETFLAGS: {
		uint32_t fl = 0;
		xvattr_t xva;

		err = zpl_ioc_copyin(&fl, data, sizeof (fl), ucmd);
		if (err == 0)
			err = zpl_ioctl_setflags_xva(r.zp, fl, &xva);
		if (err == 0)
			err = zfs_setattr(r.zp, (vattr_t *)&xva, 0, CRED());
		zpl_res_rele(&r);
		return (-err);
	}
	case ZFS_IOC_FSGETXATTR: {
		zfsxattr_t fsx;

		memset(&fsx, 0, sizeof (fsx));
		fsx.fsx_xflags = zpl_ioctl_getxflags_val(r.zp);
		fsx.fsx_projid = (uint32_t)r.zp->z_projid;
		err = zpl_ioc_copyout(data, &fsx, sizeof (fsx), ucmd);
		zpl_res_rele(&r);
		return (-err);
	}
	case ZFS_IOC_FSSETXATTR: {
		zfsxattr_t fsx;
		xvattr_t xva;
		xoptattr_t *xoap;

		err = zpl_ioc_copyin(&fsx, data, sizeof (fsx), ucmd);
		if (err == 0 && !zpl_is_valid_projid(fsx.fsx_projid))
			err = EINVAL;
		if (err == 0)
			err = zpl_ioctl_setxflags_xva(r.zp, fsx.fsx_xflags,
			    &xva);
		if (err == 0) {
			xoap = xva_getxoptattr(&xva);
			if (xoap == NULL) {
				err = ENOMEM;
			} else {
				XVA_SET_REQ(&xva, XAT_PROJID);
				xoap->xoa_projid = fsx.fsx_projid;
				err = zfs_setattr(r.zp, (vattr_t *)&xva, 0,
				    CRED());
			}
		}
		zpl_res_rele(&r);
		return (-err);
	}
	case ZFS_IOC_GETDOSFLAGS: {
		uint64_t dosflags = r.zp->z_pflags & ZFS_DOS_FL_USER_VISIBLE;

		err = zpl_ioc_copyout(data, &dosflags, sizeof (dosflags),
		    ucmd);
		zpl_res_rele(&r);
		return (-err);
	}
	case ZFS_IOC_SETDOSFLAGS: {
		uint64_t dosflags = 0;
		xvattr_t xva;

		err = zpl_ioc_copyin(&dosflags, data, sizeof (dosflags),
		    ucmd);
		if (err == 0)
			err = zpl_ioctl_setdosflags_xva(r.zp, dosflags, &xva);
		if (err == 0)
			err = zfs_setattr(r.zp, (vattr_t *)&xva, 0, CRED());
		zpl_res_rele(&r);
		return (-err);
	}
	case ZFS_IOC_REWRITE: {
		zfs_rewrite_args_t args;

		if (fi != NULL && (fi->flags & O_ACCMODE) == O_RDONLY) {
			zpl_res_rele(&r);
			return (-EBADF);
		}
		err = zpl_ioc_copyin(&args, data, sizeof (args), ucmd);
		if (err == 0)
			err = zfs_rewrite(r.zp, args.off, args.len,
			    args.flags, args.arg);
		zpl_res_rele(&r);
		return (-err);
	}
	default:
		break;
	}

	/*
	 * FUSE extras: the VFS usually consumes FICLONE / FICLONERANGE /
	 * FIDEDUPERANGE via remap_file_range, which fuse.ko does not
	 * implement. If an ioctl does reach us, clone through the same
	 * zfs_clone_range path as copy_file_range.
	 */
	if (ucmd == (unsigned int)FICLONE) {
		int srcfd = -1;

		if (fi != NULL && (fi->flags & O_ACCMODE) == O_RDONLY) {
			zpl_res_rele(&r);
			return (-EBADF);
		}
		if (data != NULL)
			srcfd = *(int *)data;
		err = zpl_clone_ioctl(&r, srcfd, 0, 0, 0);
		zpl_res_rele(&r);
		return (-err);
	}
	if (ucmd == (unsigned int)FICLONERANGE) {
		struct file_clone_range fcr;

		if (fi != NULL && (fi->flags & O_ACCMODE) == O_RDONLY) {
			zpl_res_rele(&r);
			return (-EBADF);
		}
		if (data == NULL) {
			zpl_res_rele(&r);
			return (-EFAULT);
		}
		(void) memcpy(&fcr, data, sizeof (fcr));
		err = zpl_clone_ioctl(&r, (int)fcr.src_fd, fcr.src_offset,
		    fcr.dest_offset, fcr.src_length);
		zpl_res_rele(&r);
		return (-err);
	}
#endif
	(void) data;
	zpl_res_rele(&r);
	return (-ENOTTY);
}

static uint64_t
zpl_fsid(zfsvfs_t *zfsvfs)
{
	if (zfsvfs == NULL || zfsvfs->z_os == NULL)
		return (0);
	return (dmu_objset_fsid_guid(zfsvfs->z_os));
}

static int
zpl_lock_overlap(off_t a0, off_t a1, off_t b0, off_t b1)
{
	return (a0 < b1 && b0 < a1);
}

static int
zpl_lock_conflict(uint64_t fsid, uint64_t obj, off_t start, off_t end,
    short type, uint64_t owner, int is_flock)
{
	zpl_lockent_t *c;

	for (c = zpl_locks; c != NULL; c = c->next) {
		if (c->fsid != fsid || c->obj != obj)
			continue;
		if (c->is_flock != is_flock)
			continue;
		if (c->owner == owner)
			continue;
		if (!zpl_lock_overlap(c->start, c->end, start, end))
			continue;
		if (c->type == F_WRLCK || type == F_WRLCK)
			return (1);
	}
	return (0);
}

static zpl_lockent_t *
zpl_lock_new(uint64_t fsid, uint64_t obj, uint64_t owner, pid_t pid,
    off_t start, off_t end, short type, int is_flock)
{
	zpl_lockent_t *n;

	n = calloc(1, sizeof (*n));
	if (n == NULL)
		return (NULL);
	n->fsid = fsid;
	n->obj = obj;
	n->owner = owner;
	n->pid = pid;
	n->start = start;
	n->end = end;
	n->type = type;
	n->is_flock = is_flock;
	return (n);
}

static int
zpl_lock_insert(zpl_lockent_t *n)
{
	if (n == NULL)
		return (ENOMEM);
	n->next = zpl_locks;
	zpl_locks = n;
	return (0);
}

/*
 * POSIX: unlock/replace only the requested range, splitting owner
 * records that overlap it.
 */
static int
zpl_lock_replace_range(uint64_t fsid, uint64_t obj, uint64_t owner,
    int is_flock, off_t start, off_t end, short type, pid_t pid)
{
	zpl_lockent_t **pp, *c;
	int err = 0;

	pp = &zpl_locks;
	while ((c = *pp) != NULL) {
		off_t c0 = c->start, c1 = c->end;
		zpl_lockent_t *left, *right;

		if (c->fsid != fsid || c->obj != obj ||
		    c->owner != owner || c->is_flock != is_flock ||
		    !zpl_lock_overlap(c0, c1, start, end)) {
			pp = &c->next;
			continue;
		}
		left = NULL;
		right = NULL;
		if (c0 < start) {
			left = zpl_lock_new(fsid, obj, owner, c->pid,
			    c0, start, c->type, is_flock);
			if (left == NULL) {
				err = ENOMEM;
				pp = &c->next;
				continue;
			}
		}
		if (end < c1) {
			right = zpl_lock_new(fsid, obj, owner, c->pid,
			    end, c1, c->type, is_flock);
			if (right == NULL) {
				free(left);
				err = ENOMEM;
				pp = &c->next;
				continue;
			}
		}
		*pp = c->next;
		free(c);
		if (left != NULL)
			(void) zpl_lock_insert(left);
		if (right != NULL)
			(void) zpl_lock_insert(right);
	}
	if (type != F_UNLCK && err == 0) {
		zpl_lockent_t *n = zpl_lock_new(fsid, obj, owner, pid,
		    start, end, type, is_flock);
		if (n == NULL)
			err = ENOMEM;
		else
			(void) zpl_lock_insert(n);
	}
	return (err);
}

static void
zpl_lock_drop_owner(uint64_t fsid, uint64_t obj, uint64_t owner, int is_flock)
{
	zpl_lockent_t **pp, *c;

	pp = &zpl_locks;
	while ((c = *pp) != NULL) {
		if (c->fsid == fsid && c->obj == obj &&
		    c->owner == owner && c->is_flock == is_flock) {
			*pp = c->next;
			free(c);
		} else {
			pp = &c->next;
		}
	}
}

void
zpl_lock_purge_fs(uint64_t fsid)
{
	zpl_lockent_t **pp, *c;

	pthread_mutex_lock(&zpl_state_mx);
	pp = &zpl_locks;
	while ((c = *pp) != NULL) {
		if (c->fsid == fsid) {
			*pp = c->next;
			free(c);
		} else {
			pp = &c->next;
		}
	}
	(void) pthread_cond_broadcast(&zpl_lock_cv);
	pthread_mutex_unlock(&zpl_state_mx);
}

static int
zpl_lock_impl(const char *path, struct fuse_file_info *fi, int cmd,
    struct flock *lock, int is_flock)
{
	struct zpl_res r;
	uint64_t fsid, obj, owner;
	off_t start, end;
	int err, owned;

	if (lock == NULL)
		return (-EINVAL);
	if (lock->l_whence != SEEK_SET)
		return (-EINVAL);
	ZPL_CRED();
	err = zpl_obj_or_walk(&r, path, fi);

	if (err != 0)
		return (-err);
	fsid = zpl_fsid(r.zfsvfs);
	obj = r.zp ? r.zp->z_id : 0;
	owned = r.owned;
	owner = fi ? fi->lock_owner : 0;
	start = lock->l_start;
	end = (lock->l_len == 0) ? OFF_MAX : start + lock->l_len;
	if (start < 0 || end < start) {
		zpl_res_rele(&r);
		return (-EINVAL);
	}
	if (owned && cmd == F_SETLKW) {
		zpl_res_rele(&r);
		return (-ENOLCK);
	}
	if (!owned)
		zpl_res_rele(&r);
	pthread_mutex_lock(&zpl_state_mx);
	if (cmd == F_GETLK) {
		zpl_lockent_t *c;
		int hit = 0;

		for (c = zpl_locks; c != NULL; c = c->next) {
			if (c->fsid != fsid || c->obj != obj)
				continue;
			if (c->is_flock != is_flock || c->owner == owner)
				continue;
			if (!zpl_lock_overlap(c->start, c->end, start, end))
				continue;
			if (c->type != F_WRLCK && lock->l_type != F_WRLCK)
				continue;
			lock->l_type = c->type;
			lock->l_whence = SEEK_SET;
			lock->l_start = c->start;
			lock->l_len = (c->end == OFF_MAX) ? 0 :
			    (c->end - c->start);
			lock->l_pid = c->pid;
			hit = 1;
			break;
		}
		if (!hit)
			lock->l_type = F_UNLCK;
		pthread_mutex_unlock(&zpl_state_mx);
		if (owned)
			zpl_res_rele(&r);
		return (0);
	}
	if (lock->l_type == F_UNLCK) {
		(void) zpl_lock_replace_range(fsid, obj, owner, is_flock,
		    start, end, F_UNLCK, lock->l_pid);
		pthread_cond_broadcast(&zpl_lock_cv);
		pthread_mutex_unlock(&zpl_state_mx);
		if (owned)
			zpl_res_rele(&r);
		return (0);
	}
	for (;;) {
		if (!zpl_lock_conflict(fsid, obj, start, end, lock->l_type,
		    owner, is_flock))
			break;
		if (cmd == F_SETLK) {
			pthread_mutex_unlock(&zpl_state_mx);
			if (owned)
				zpl_res_rele(&r);
			return (-EAGAIN);
		}
		pthread_cond_wait(&zpl_lock_cv, &zpl_state_mx);
	}
	err = zpl_lock_replace_range(fsid, obj, owner, is_flock,
	    start, end, lock->l_type, lock->l_pid);
	pthread_mutex_unlock(&zpl_state_mx);
	if (owned)
		zpl_res_rele(&r);
	return (err ? -err : 0);
}

static int
zpl_lock(const char *path, struct fuse_file_info *fi, int cmd,
    struct flock *lock)
{
	return (zpl_lock_impl(path, fi, cmd, lock, 0));
}

static int
zpl_flock(const char *path, struct fuse_file_info *fi, int op)
{
	struct flock fl;
	int cmd;

	memset(&fl, 0, sizeof (fl));
	fl.l_whence = SEEK_SET;
	if (op & LOCK_UN)
		fl.l_type = F_UNLCK;
	else if (op & LOCK_EX)
		fl.l_type = F_WRLCK;
	else
		fl.l_type = F_RDLCK;
	cmd = (op & LOCK_NB) ? F_SETLK : F_SETLKW;
	return (zpl_lock_impl(path, fi, cmd, &fl, 1));
}

static int
zpl_poll(const char *path, struct fuse_file_info *fi,
    struct fuse_pollhandle *ph, unsigned *reventsp)
{
	(void) path;
	(void) fi;
	if (ph)
		fuse_pollhandle_destroy(ph);
	if (reventsp)
		*reventsp = POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM;
	return (0);
}

static int
zpl_write_buf(const char *path, struct fuse_bufvec *buf, off_t off,
    struct fuse_file_info *fi)
{
	size_t size;
	char *tmp;
	struct fuse_bufvec dst;
	int n;

	if (buf == NULL)
		return (-EINVAL);
	size = fuse_buf_size(buf);
	tmp = malloc(size ? size : 1);
	if (tmp == NULL)
		return (-ENOMEM);
	dst = FUSE_BUFVEC_INIT(size);
	dst.buf[0].mem = tmp;
	if (fuse_buf_copy(&dst, buf, 0) < 0) {
		free(tmp);
		return (-EIO);
	}
	n = zpl_write(path, tmp, size, off, fi);
	free(tmp);
	return (n);
}

static int
zpl_read_buf(const char *path, struct fuse_bufvec **bufp,
    size_t size, off_t off, struct fuse_file_info *fi)
{
	struct fuse_bufvec *b;
	int n;

	if (bufp == NULL)
		return (-EINVAL);
	b = calloc(1, sizeof (*b));
	if (b == NULL)
		return (-ENOMEM);
	*b = FUSE_BUFVEC_INIT(size);
	b->buf[0].mem = malloc(size ? size : 1);
	if (b->buf[0].mem == NULL) {
		free(b);
		return (-ENOMEM);
	}
	n = zpl_read(path, b->buf[0].mem, size, off, fi);
	if (n < 0) {
		free(b->buf[0].mem);
		free(b);
		return (n);
	}
	b->buf[0].size = (size_t)n;
	*bufp = b;
	return (n);
}

const struct fuse_operations zpl_ops = {
	.getattr	= zpl_getattr,
	.readlink	= zpl_readlink,
	.mknod		= zpl_mknod,
	.mkdir		= zpl_mkdir,
	.unlink		= zpl_unlink,
	.rmdir		= zpl_rmdir,
	.symlink	= zpl_symlink,
	.rename		= zpl_rename,
	.link		= zpl_link,
	.chmod		= zpl_chmod,
	.chown		= zpl_chown,
	.truncate	= zpl_truncate,
	.open		= zpl_open,
	.read		= zpl_read,
	.write		= zpl_write,
	.statfs		= zpl_statfs,
	.flush		= zpl_flush,
	.release	= zpl_release,
	.fsync		= zpl_fsync,
	.setxattr	= zpl_setxattr,
	.getxattr	= zpl_getxattr,
	.listxattr	= zpl_listxattr,
	.removexattr	= zpl_removexattr,
	.opendir	= zpl_opendir,
	.readdir	= zpl_readdir,
	.releasedir	= zpl_releasedir,
	.fsyncdir	= zpl_fsyncdir,
	.init		= zpl_init,
	.destroy	= zpl_destroy,
	.access		= zpl_access,
	.create		= zpl_create,
	.lock		= zpl_lock,
	.utimens	= zpl_utimens,
	.ioctl		= zpl_ioctl,
	.poll		= zpl_poll,
	.write_buf	= zpl_write_buf,
	.read_buf	= zpl_read_buf,
	.flock		= zpl_flock,
	.fallocate	= zpl_fallocate,
	.copy_file_range = zpl_copy_file_range,
	.lseek		= zpl_lseek,
};

pthread_mutex_t g_mntlock = PTHREAD_MUTEX_INITIALIZER;
zpl_mnt_t *g_mnts;
static pthread_t g_reaper_tid;
static pthread_mutex_t g_reaper_mx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_reaper_cv;
static int g_reaper_cv_inited;
static int g_reaper_running;

static void
zfsd_reaper_cv_init(void)
{
	pthread_condattr_t attr;

	if (g_reaper_cv_inited)
		return;
	(void) pthread_condattr_init(&attr);
#ifdef CLOCK_MONOTONIC
	(void) pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
#endif
	(void) pthread_cond_init(&g_reaper_cv, &attr);
	(void) pthread_condattr_destroy(&attr);
	g_reaper_cv_inited = 1;
}

static int
zfsd_mnt_sensitive(const char *mnt)
{
	static const char *const bad[] = {
		"/proc", "/sys", "/dev", NULL
	};
	int i;
	size_t n;

	if (mnt == NULL || mnt[0] != '/' || mnt[1] == '\0')
		return (1);
	if (strstr(mnt, "/../") != NULL || strstr(mnt, "/./") != NULL)
		return (1);
	n = strlen(mnt);
	if (n >= 3 && strcmp(mnt + n - 3, "/..") == 0)
		return (1);
	if (n >= 2 && strcmp(mnt + n - 2, "/.") == 0)
		return (1);
	for (i = 0; bad[i] != NULL; i++) {
		size_t b = strlen(bad[i]);
		if (strcmp(mnt, bad[i]) == 0)
			return (1);
		if (strncmp(mnt, bad[i], b) == 0 && mnt[b] == '/')
			return (1);
	}
	return (0);
}

static int
zfsd_mnt_walk(const char *mnt, int last_must_exist, int *fdp)
{
	char name[256];
	const char *p, *sl;
	int fd, next, last;
	size_t len;
	int oflags, rootfl;

	if (fdp != NULL)
		*fdp = -1;
	if (mnt == NULL || mnt[0] != '/')
		return (EINVAL);
	oflags = O_RDONLY;
#ifdef O_DIRECTORY
	oflags |= O_DIRECTORY;
#endif
#ifdef O_NOFOLLOW
	oflags |= O_NOFOLLOW;
#endif
#ifdef O_CLOEXEC
	oflags |= O_CLOEXEC;
#endif
	rootfl = O_RDONLY;
#ifdef O_DIRECTORY
	rootfl |= O_DIRECTORY;
#endif
#ifdef O_CLOEXEC
	rootfl |= O_CLOEXEC;
#endif
	fd = open("/", rootfl);
	if (fd < 0)
		return (errno);
	p = mnt + 1;
	while (*p == '/')
		p++;
	if (*p == '\0') {
		if (fdp != NULL && last_must_exist)
			*fdp = fd;
		else
			(void) close(fd);
		return (0);
	}
	for (;;) {
		sl = strchr(p, '/');
		last = (sl == NULL);
		len = last ? strlen(p) : (size_t)(sl - p);
		if (len == 0) {
			if (last)
				break;
			p = sl + 1;
			continue;
		}
		if (len >= sizeof (name)) {
			(void) close(fd);
			return (ENAMETOOLONG);
		}
		(void) memcpy(name, p, len);
		name[len] = '\0';
		if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
			(void) close(fd);
			return (EPERM);
		}
		next = openat(fd, name, oflags);
		if (next < 0) {
			int e = errno;

			(void) close(fd);
			if (e == ELOOP)
				return (EPERM);
			if (e == ENOENT && !last_must_exist)
				return (0);
			return (e);
		}
		(void) close(fd);
		fd = next;
		if (last)
			break;
		p = sl + 1;
		while (*p == '/')
			p++;
		if (*p == '\0')
			break;
	}
	if (fdp != NULL)
		*fdp = fd;
	else
		(void) close(fd);
	return (0);
}

static int
zfsd_mnt_path_ok(const char *mnt)
{
	if (mnt == NULL || mnt[0] != '/')
		return (EINVAL);
	if (strlen(mnt) >= MAXPATHLEN)
		return (ENAMETOOLONG);
	if (zfsd_mnt_sensitive(mnt))
		return (EPERM);
	return (zfsd_mnt_walk(mnt, 0, NULL));
}

static int
zfsd_mnt_open_dir(const char *mnt, int need_owner, int *fdp)
{
	struct stat st;
	int fd, err;

	if (mnt == NULL || mnt[0] == '\0')
		return (EINVAL);
	err = zfsd_mnt_walk(mnt, 1, &fd);
	if (err != 0)
		return (err);
	if (fstat(fd, &st) != 0) {
		err = errno;
		(void) close(fd);
		return (err);
	}
	if (!S_ISDIR(st.st_mode)) {
		(void) close(fd);
		return (ENOTDIR);
	}
	if (need_owner && st.st_uid != crgetuid(CRED())) {
		(void) close(fd);
		return (EPERM);
	}
	*fdp = fd;
	return (0);
}

/*
 * Path still names the inode we opened (O_NOFOLLOW). Closes the
 * window where the caller rmdir/symlink-swaps mnt after the
 * ownership check and before umount2/fuse_mount.
 */
static int
zfsd_mnt_still_same(int fd, const char *mnt, int need_owner)
{
	struct stat fs, ls;

	if (fd < 0 || mnt == NULL)
		return (EINVAL);
	if (fstat(fd, &fs) != 0)
		return (errno);
	if (lstat(mnt, &ls) != 0)
		return (errno);
	if (S_ISLNK(ls.st_mode))
		return (EPERM);
	if (!S_ISDIR(ls.st_mode) || !S_ISDIR(fs.st_mode))
		return (ENOTDIR);
	if (fs.st_dev != ls.st_dev || fs.st_ino != ls.st_ino)
		return (EPERM);
	if (need_owner && ls.st_uid != crgetuid(CRED()))
		return (EPERM);
	return (0);
}

static void *
zpl_loop(void *arg)
{
	zpl_mnt_t *m = arg;
	struct fuse_loop_config *cfg = fuse_loop_cfg_create();

	if (cfg == NULL) {
		(void) fuse_loop_mt(m->fuse, 0);
		return (NULL);
	}
	fuse_loop_cfg_set_max_threads(cfg, ZFSD_FUSE_MAX_THREADS);
	fuse_loop_cfg_set_idle_threads(cfg, 2);
	(void) fuse_loop_mt_312(m->fuse, cfg);
	fuse_loop_cfg_destroy(cfg);
	m->loop_done = 1;
	return (NULL);
}
/*
 * Detach first. If fuse_exit/unmount/join run while the VFS mount still
 * exists, the kernel marks the mount ENOTCONN. Stock zpool(8) does
 * opendir(mountpoint) before ZFS_IOC_POOL_CREATE and treats any errno
 * other than ENOENT as fatal ("Transport endpoint is not connected").
 */
void
zfsd_lazy_umount(const char *mnt)
{
	if (mnt == NULL || mnt[0] == '\0')
		return;
#ifdef __linux__
	(void) umount2(mnt, MNT_DETACH | UMOUNT_NOFOLLOW);
#endif
#ifdef __FreeBSD__
	(void) unmount(mnt, 0);
#endif
}
/*
 * True if some other process has cwd, root, or an fd under mnt.
 * Skip our pid: the FUSE daemon holds /dev/fuse, not the tree.
 * Used so unmount/destroy of a busy dataset returns EBUSY like kmod zfs
 * instead of MNT_DETACH succeeding with files still open.
 */
static int
zfsd_path_busy(const char *mnt)
{
	DIR *proc, *fdd;
	struct dirent *de, *fe;
	char path[64], link[MAXPATHLEN];
	size_t n;
	ssize_t k;
	pid_t self;

	if (mnt == NULL || mnt[0] != '/')
		return (0);
	n = strlen(mnt);
	if (n == 0 || n >= MAXPATHLEN)
		return (0);
	self = getpid();
	proc = opendir("/proc");
	if (proc == NULL)
		return (0);
	while ((de = readdir(proc)) != NULL) {
		pid_t pid;
		const char *s;
		int ispid = 1;

		for (s = de->d_name; *s != '\0'; s++) {
			if (!isdigit((unsigned char)*s)) {
				ispid = 0;
				break;
			}
		}
		if (!ispid)
			continue;
		pid = (pid_t)atoi(de->d_name);
		if (pid <= 0 || pid == self)
			continue;
		(void) snprintf(path, sizeof (path), "/proc/%s/cwd",
		    de->d_name);
		k = readlink(path, link, sizeof (link) - 1);
		if (k > 0) {
			link[k] = '\0';
			if (strncmp(link, mnt, n) == 0 &&
			    (link[n] == '\0' || link[n] == '/')) {
				(void) closedir(proc);
				return (1);
			}
		}
		(void) snprintf(path, sizeof (path), "/proc/%s/root",
		    de->d_name);
		k = readlink(path, link, sizeof (link) - 1);
		if (k > 0) {
			link[k] = '\0';
			if (strncmp(link, mnt, n) == 0 &&
			    (link[n] == '\0' || link[n] == '/')) {
				(void) closedir(proc);
				return (1);
			}
		}
		(void) snprintf(path, sizeof (path), "/proc/%s/fd", de->d_name);
		fdd = opendir(path);
		if (fdd == NULL)
			continue;
		while ((fe = readdir(fdd)) != NULL) {
			if (fe->d_name[0] == '.')
				continue;
			(void) snprintf(path, sizeof (path), "/proc/%s/fd/%s",
			    de->d_name, fe->d_name);
			k = readlink(path, link, sizeof (link) - 1);
			if (k <= 0)
				continue;
			link[k] = '\0';
			if (strncmp(link, mnt, n) == 0 &&
			    (link[n] == '\0' || link[n] == '/')) {
				(void) closedir(fdd);
				(void) closedir(proc);
				return (1);
			}
		}
		(void) closedir(fdd);
	}
	(void) closedir(proc);
	return (0);
}
static void
zfsd_fuse_wake_nop(int sig)
{
	(void) sig;
}

static void
zfsd_fuse_wake_init(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof (sa));
	sa.sa_handler = zfsd_fuse_wake_nop;
	(void) sigemptyset(&sa.sa_mask);
	/*
	 * glibc signal() sets SA_RESTART, and a restarted sem_wait
	 * would not return to the libfuse mt loop. Leave it off.
	 */
	sa.sa_flags = 0;
	(void) sigaction(SIGUSR2, &sa, NULL);
}

/*
 * fuse_exit() only sets a flag. The mt loop thread is already inside
 * sem_wait, and its workers are inside read(/dev/fuse), so neither
 * sees the flag. Close from fuse_unmount does not wake another
 * thread's read. MNT_FORCE would abort the connection, but umount2
 * returns EPERM for that flag without CAP_SYS_ADMIN in the initial
 * user namespace. Wake the loop thread instead: sem_wait returns
 * EINTR, the loop sees the flag, cancels the workers, and joins them.
 */
static void
zfsd_fuse_loop_stop(pthread_t tid)
{
	static pthread_once_t once = PTHREAD_ONCE_INIT;
	struct timespec ts;
	int i;

	(void) pthread_once(&once, zfsd_fuse_wake_init);
	for (i = 0; i < 50; i++) {
		(void) pthread_kill(tid, SIGUSR2);
		if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
			break;
		ts.tv_nsec += 20000000L;
		if (ts.tv_nsec >= 1000000000L) {
			ts.tv_sec++;
			ts.tv_nsec -= 1000000000L;
		}
		if (pthread_timedjoin_np(tid, NULL, &ts) == 0)
			return;
	}
	(void) pthread_join(tid, NULL);
}

void
zfsd_zpl_teardown(zpl_mnt_t *m)
{
	zpl_mnt_t *other;
	int running;
	int cover = 0;

	if (m == NULL)
		return;
	pthread_mutex_lock(&g_mntlock);
	for (other = g_mnts; other != NULL; other = other->next) {
		if (other->dying || other->mnt[0] == '\0')
			continue;
		if (strcmp(other->mnt, m->mnt) == 0) {
			cover = 1;
			break;
		}
	}
	pthread_mutex_unlock(&g_mntlock);
	pthread_mutex_lock(&m->lock);
	running = m->running;
	m->running = 0;
	m->dying = 1;
	pthread_mutex_unlock(&m->lock);
	if (m->zfsvfs != NULL && m->zfsvfs->z_os != NULL)
		zpl_lock_purge_fs(dmu_objset_fsid_guid(m->zfsvfs->z_os));
	if (m->fuse)
		fuse_exit(m->fuse);
	if (running)
		zfsd_fuse_loop_stop(m->tid);
	/*
	 * umount2(path) drops only the top mount. The first detach is
	 * this session: libfuse then sees POLLERR and does not umount
	 * again. A second detach would drop the dataset an overlay was
	 * covering (zfs mount -O).
	 */
	zfsd_lazy_umount(m->mnt);
	if (m->fuse)
		fuse_unmount(m->fuse);
	if (m->fuse) {
		fuse_destroy(m->fuse);
		m->fuse = NULL;
	}
	if (m->zfsvfs) {
		zpl_mnt_t *st;
		int shared = 0;

		pthread_mutex_lock(&g_mntlock);
		for (st = g_mnts; st != NULL; st = st->next) {
			if (st != m && st->zfsvfs == m->zfsvfs) {
				shared = 1;
				break;
			}
		}
		pthread_mutex_unlock(&g_mntlock);
		/*
		 * A second mount of the same dataset shares the
		 * objset. Drop it only with the last fuse session.
		 */
		if (!shared)
			zfsvfs_teardown(m->zfsvfs, B_TRUE);
		m->zfsvfs = NULL;
	}
	(void) pthread_mutex_destroy(&m->lock);
	if (!cover)
		zfsd_lazy_umount(m->mnt);
	free(m);
}
static int
zpl_ds_in_pool(const char *ds, const char *pool)
{
	size_t n;

	if (ds == NULL || pool == NULL)
		return (0);
	n = strlen(pool);
	if (strcmp(ds, pool) == 0)
		return (1);
	return (strncmp(ds, pool, n) == 0 && ds[n] == '/');
}
void
zfsd_zpl_reap_stale(void)
{
#ifdef __linux__
	struct mntent ent;
	char buf[4096];
	char *paths[64];
	FILE *fp;
	int n = 0, i;

	fp = setmntent("/proc/self/mounts", "r");
	if (fp == NULL)
		return;
	while (getmntent_r(fp, &ent, buf, sizeof (buf)) != NULL) {
		if (ent.mnt_type == NULL || ent.mnt_dir == NULL)
			continue;
		if (strcmp(ent.mnt_type, "fuse.zfs") != 0)
			continue;
		/*
		 * Orphan kernel mounts only. A live session is not
		 * stale. stat() of a mount we serve is a GETATTR, and
		 * that worker deadlocks pool export's join.
		 */
		if (n < 64)
			paths[n++] = strdup(ent.mnt_dir);
	}
	endmntent(fp);
	for (i = 0; i < n; i++) {
		zfsd_zpl_unmount_dead(paths[i]);
		free(paths[i]);
	}
#endif
}
static void *
zpl_reaper(void *arg)
{
	(void) arg;
	pthread_mutex_lock(&g_reaper_mx);
	while (g_reaper_running) {
		struct timespec ts;

		pthread_mutex_unlock(&g_reaper_mx);
		zfsd_zpl_reap_stale();
		zfsd_zpl_reap_detached();
		zfsd_zpl_expire_snaps();
		pthread_mutex_lock(&g_reaper_mx);
		if (!g_reaper_running)
			break;
		(void) clock_gettime(CLOCK_MONOTONIC, &ts);

		ts.tv_nsec += 250000000L;
		if (ts.tv_nsec >= 1000000000L) {
			ts.tv_sec++;
			ts.tv_nsec -= 1000000000L;
		}
		(void) pthread_cond_timedwait(&g_reaper_cv, &g_reaper_mx, &ts);
	}
	pthread_mutex_unlock(&g_reaper_mx);
	return (NULL);
}
time_t
zfsd_mono_sec(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return ((time_t)time(NULL));
	return (ts.tv_sec);
}
int
zfsd_zpl_mount(const char *dsname, const char *mnt, uint64_t flags,
    const char *opts)
{
	return (zfsd_zpl_mount_impl(dsname, mnt, flags, opts, 0, NULL));
}
static void
zfsd_mnt_unlink(zpl_mnt_t *m)
{
	zpl_mnt_t **pp;

	if (m == NULL)
		return;
	pthread_mutex_lock(&g_mntlock);
	for (pp = &g_mnts; *pp != NULL; pp = &(*pp)->next) {
		if (*pp == m) {
			*pp = m->next;
			break;
		}
	}
	pthread_mutex_unlock(&g_mntlock);
}

/*
 * Comma-separated mount token. "suid" must not match "nosuid".
 */
static int
zfsd_opt_tok(const char *opts, const char *tok)
{
	size_t n;
	const char *p;

	if (opts == NULL || tok == NULL || tok[0] == '\0')
		return (0);
	n = strlen(tok);
	for (p = opts; *p != '\0'; ) {
		if (strncmp(p, tok, n) == 0 &&
		    (p[n] == '\0' || p[n] == ',' || p[n] == '='))
			return (1);
		p = strchr(p, ',');
		if (p == NULL)
			return (0);
		p++;
	}
	return (0);
}

/*
 * Kernel mount is gone (umount(8), or umount_tree from a parent
 * MNT_DETACH) but this zfsvfs is still held. mountinfo is not a
 * FUSE request. Do not stat() the path and do not read mountinfo
 * while holding g_mntlock: a FICLONE worker needs that lock, and a
 * stat needs a FUSE worker.
 */
struct zpl_reap_cand {
	char *mnt;
	dev_t fsid_dev;
	int loop_done;
	int dead;
};

void
zfsd_zpl_reap_detached(void)
{
	struct zpl_reap_cand cand[64];
	zpl_mnt_t *list = NULL;
	zpl_mnt_t *m, **pp;
	int n = 0, i;

	memset(cand, 0, sizeof (cand));
	pthread_mutex_lock(&g_mntlock);
	for (m = g_mnts; m != NULL && n < 64; m = m->next) {
		if (m->pending || m->dying || m->inuse != 0 || m->mnt[0] == '\0')
			continue;
		cand[n].mnt = strdup(m->mnt);
		if (cand[n].mnt == NULL)
			break;
		cand[n].fsid_dev = m->fsid_dev;
		cand[n].loop_done = m->loop_done;
		n++;
	}
	pthread_mutex_unlock(&g_mntlock);

	for (i = 0; i < n; i++) {
		dev_t dev = 0;
		int err;

		if (cand[i].loop_done) {
			cand[i].dead = 1;
			continue;
		}
		if (cand[i].fsid_dev == 0)
			continue;
		err = zpl_mountinfo_dev(cand[i].mnt, &dev);
		cand[i].dead = (err == ENOENT);
	}

	pthread_mutex_lock(&g_mntlock);
	for (i = 0; i < n; i++) {
		if (!cand[i].dead || cand[i].mnt == NULL)
			continue;
		for (pp = &g_mnts; (m = *pp) != NULL; pp = &m->next) {
			if (m->pending || m->dying || m->inuse != 0)
				continue;
			if (strcmp(m->mnt, cand[i].mnt) != 0)
				continue;
			if (m->fsid_dev != cand[i].fsid_dev)
				continue;
			if (!cand[i].loop_done && !m->loop_done &&
			    m->fsid_dev == 0)
				continue;
			*pp = m->next;
			m->next = list;
			list = m;
			break;
		}
	}
	pthread_mutex_unlock(&g_mntlock);
	for (i = 0; i < n; i++)
		free(cand[i].mnt);
	while (list != NULL) {
		zpl_mnt_t *nx = list->next;

		zfsd_zpl_teardown(list);
		list = nx;
	}
}

int
zfsd_zpl_mount_impl(const char *dsname, const char *mnt, uint64_t flags,
    const char *opts, int snap, zpl_mnt_t *parent)
{
	zpl_mnt_t *m = NULL, *have;
	zfsvfs_t *zfsvfs = NULL;
	vfs_t *vfsp;
	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
	char fsname[ZFS_MAX_DATASET_NAME_LEN + 256];
	boolean_t mnt_ro;
	int explicit_rw;
	int tok_suid, tok_nosuid, tok_dev, tok_nodev, tok_noexec, tok_noatime;
	int err, mkerr, priv, mntfd = -1, pin_owner = 0, owns_vfs = 0;

	if (dsname == NULL || dsname[0] == '\0' || mnt == NULL)
		return (EINVAL);
	if (snap) {
		if (parent == NULL || strchr(dsname, '@') == NULL)
			return (EINVAL);
		flags |= MS_RDONLY | MS_NOSUID | MS_NODEV;
		priv = 1;
	} else {
		err = zfsd_mnt_path_ok(mnt);
		if (err != 0)
			return (err);
		priv = (secpolicy_zfs(CRED()) == 0);
		if (!priv) {
			/*
			 * Delegated mount: like FreeBSD zfs_mount plus
			 * fusermount nosuid,nodev. Do not mkdir; the
			 * mountpoint must already exist and be owned.
			 * Pin it with an openat(O_NOFOLLOW) walk so a
			 * later rmdir/symlink swap cannot redirect
			 * umount2 or fuse_mount.
			 */
			flags |= MS_NOSUID | MS_NODEV;
			pin_owner = 1;
			err = zfsd_mnt_open_dir(mnt, 1, &mntfd);
			if (err != 0)
				return (err);
		}
	}
	mnt_ro = (flags & MS_RDONLY) != 0;
	/*
	 * mount(8) passes "rw" with no MS_RDONLY bit. That is an
	 * explicit read-write mount and must beat readonly=on.
	 * "ro" is already MS_RDONLY. libfuse defaults nosuid,nodev;
	 * a positive suid/dev token is what clears them.
	 */
	explicit_rw = (!mnt_ro && zfsd_opt_tok(opts, "rw") &&
	    !zfsd_opt_tok(opts, "ro"));
	tok_suid = zfsd_opt_tok(opts, "suid");
	tok_nosuid = zfsd_opt_tok(opts, "nosuid") || (flags & MS_NOSUID);
	tok_dev = zfsd_opt_tok(opts, "dev");
	tok_nodev = zfsd_opt_tok(opts, "nodev") || (flags & MS_NODEV);
	tok_noexec = zfsd_opt_tok(opts, "noexec") || (flags & MS_NOEXEC);
	tok_noatime = zfsd_opt_tok(opts, "noatime") || (flags & MS_NOATIME);
	zfsd_zpl_reap_detached();

	m = calloc(1, sizeof (*m));
	if (m == NULL) {
		if (mntfd >= 0)
			(void) close(mntfd);
		return (ENOMEM);
	}
	(void) strlcpy(m->ds, dsname, sizeof (m->ds));
	(void) strlcpy(m->mnt, mnt, sizeof (m->mnt));
	m->snap = snap;
	m->parent = parent;
	m->pending = 1;
	m->used = zfsd_mono_sec();
	(void) pthread_mutex_init(&m->lock, NULL);

	pthread_mutex_lock(&g_mntlock);
	for (have = g_mnts; have != NULL; have = have->next) {
		/*
		 * Same dataset at a second path is a multi-mount.
		 * A different dataset at this path is an overlay.
		 * Only an exact duplicate is busy.
		 */
		if (strcmp(have->ds, dsname) == 0 &&
		    strcmp(have->mnt, mnt) == 0) {
			pthread_mutex_unlock(&g_mntlock);
			(void) pthread_mutex_destroy(&m->lock);
			free(m);
			if (mntfd >= 0)
				(void) close(mntfd);
			return (EBUSY);
		}
	}
	m->next = g_mnts;
	g_mnts = m;
	pthread_mutex_unlock(&g_mntlock);

	{
		zpl_mnt_t *share = NULL;

		pthread_mutex_lock(&g_mntlock);
		for (have = g_mnts; have != NULL; have = have->next) {
			if (have == m || have->dying || have->zfsvfs == NULL)
				continue;
			if (strcmp(have->ds, dsname) == 0) {
				share = have;
				break;
			}
		}
		pthread_mutex_unlock(&g_mntlock);
		if (share != NULL)
			zfsvfs = share->zfsvfs;
	}
	if (zfsvfs == NULL) {
		err = zfsvfs_create(dsname, mnt_ro, &zfsvfs);
		if (err != 0)
			goto fail_vfs;
		owns_vfs = 1;
		vfsp = zfsvfs_vfs_alloc();
		/*
		 * vfs_do_readonly means the caller passed -o ro or -o rw.
		 * zfsvfs_setup restores that after the readonly property
		 * callback. No flag: the property decides, and a readonly
		 * dataset is mounted ro.
		 */
		if (mnt_ro) {
			vfsp->vfs_readonly = B_TRUE;
			vfsp->vfs_do_readonly = B_TRUE;
		} else if (explicit_rw) {
			vfsp->vfs_readonly = B_FALSE;
			vfsp->vfs_do_readonly = B_TRUE;
		}
		vfsp->vfs_data = zfsvfs;
		zfsvfs->z_vfs = vfsp;
		err = zfsvfs_setup(zfsvfs, B_TRUE);
		if (err != 0)
			goto fail_vfs;
	}
	if (priv && !snap) {
		mkerr = zfsd_mkdirs(mnt, 0755);
		if (mkerr != 0) {
			err = mkerr;
			goto fail_vfs;
		}
		err = zfsd_mnt_path_ok(mnt);
		if (err != 0)
			goto fail_vfs;
		if (mntfd < 0) {
			err = zfsd_mnt_open_dir(mnt, 0, &mntfd);
			if (err != 0)
				goto fail_vfs;
		}
	}
	/*
	 * Always detach a leftover FUSE/mount on this path. After
	 * export the kernel can still list the old fuse.zfs mount
	 * (path_dead is 0 while it answers stat) and fuse_mount
	 * then fails with EINVAL. Delegated mounts re-check the
	 * pinned inode first; umount2 uses UMOUNT_NOFOLLOW so a
	 * symlink swap cannot detach some other mount.
	 */
	if (mntfd >= 0) {
		err = zfsd_mnt_still_same(mntfd, mnt, pin_owner);
		if (err != 0)
			goto fail_vfs;
	}
	/*
	 * Detach a leftover kernel mount that zfsd is not serving.
	 * Do not detach a live g_mnts entry: overlay mounts stack
	 * on that path, and MNT_DETACH would drop the lower dataset.
	 */
	{
		int stacked = 0;
		zpl_mnt_t *st;

		pthread_mutex_lock(&g_mntlock);
		for (st = g_mnts; st != NULL; st = st->next) {
			if (st != m && !st->dying && !st->pending &&
			    strcmp(st->mnt, mnt) == 0) {
				stacked = 1;
				break;
			}
		}
		pthread_mutex_unlock(&g_mntlock);
		if (!stacked)
			zfsd_lazy_umount(mnt);
	}
	m->zfsvfs = zfsvfs;
	m->readonly = zfs_is_readonly(zfsvfs);
	/*
	 * default_permissions: kernel generic_permission uses i_mode
	 * (and POSIX ACLs when FUSE_CAP_POSIX_ACL is on). Without it
	 * fuse_permission returns 0 for execve/open and zpl_access is
	 * never asked, so a mode/ACL deny still runs the file.
	 * FUSE_CAP_POSIX_ACL does not turn this on by itself.
	 */
	(void) snprintf(fsname, sizeof (fsname),
	    "allow_other,default_permissions,subtype=%s,fsname=%s",
	    zfsd_native ? "zfs" : "uzfs", dsname);

	if (zfs_is_readonly(zfsvfs))
		(void) strlcat(fsname, ",ro", sizeof (fsname));
	if (tok_suid && !tok_nosuid)
		(void) strlcat(fsname, ",suid", sizeof (fsname));
	else if (tok_nosuid)
		(void) strlcat(fsname, ",nosuid", sizeof (fsname));
	if (tok_dev && !tok_nodev)
		(void) strlcat(fsname, ",dev", sizeof (fsname));
	else if (tok_nodev)
		(void) strlcat(fsname, ",nodev", sizeof (fsname));
	if (tok_noexec)
		(void) strlcat(fsname, ",noexec", sizeof (fsname));
	if (tok_noatime)
		(void) strlcat(fsname, ",noatime", sizeof (fsname));
	(void) fuse_opt_add_arg(&args, "zfsd-mount");
	(void) fuse_opt_add_arg(&args, "-o");
	(void) fuse_opt_add_arg(&args, fsname);
	m->fuse = fuse_new(&args, &zpl_ops, sizeof (zpl_ops), m);
	fuse_opt_free_args(&args);
	if (m->fuse == NULL) {
		err = EIO;
		goto fail_m;
	}
	if (mntfd >= 0) {
		err = zfsd_mnt_still_same(mntfd, mnt, pin_owner);
		if (err != 0)
			goto fail_m;
	}
	if (fuse_mount(m->fuse, mnt) != 0) {
		fuse_destroy(m->fuse);
		m->fuse = NULL;
		err = EIO;
		goto fail_m;
	}
	if (mntfd >= 0) {
		(void) close(mntfd);
		mntfd = -1;
	}
	{
		dev_t dev = 0;

		/*
		 * mountinfo has the kernel's s_dev without getattr.
		 * Record it before fuse_loop so FICLONE can match
		 * the client's fdinfo mnt_id without stat(mnt).
		 */
#ifdef __linux__
		(void) zpl_mountinfo_dev(mnt, &dev);
#endif
		pthread_mutex_lock(&g_mntlock);
		m->fsid_dev = dev;
		m->pending = 0;
		pthread_mutex_unlock(&g_mntlock);
	}
	m->running = 1;
	if (pthread_create(&m->tid, NULL, zpl_loop, m) != 0) {
		zfsd_lazy_umount(mnt);
		fuse_unmount(m->fuse);
		fuse_destroy(m->fuse);
		m->fuse = NULL;
		err = EIO;
		goto fail_m;
	}
	return (0);

fail_m:
	zfsd_mnt_unlink(m);
	(void) pthread_mutex_destroy(&m->lock);
	free(m);
	m = NULL;
fail_vfs:
	if (m != NULL) {
		zfsd_mnt_unlink(m);
		(void) pthread_mutex_destroy(&m->lock);
		free(m);
	}
	if (mntfd >= 0)
		(void) close(mntfd);
	if (zfsvfs != NULL && owns_vfs)
		zfsvfs_teardown(zfsvfs, B_TRUE);
	return (err);
}
int
zfsd_zpl_mntpath(const char *ds, char *buf, size_t n)
{
	zpl_mnt_t *m;
	int err = ENOENT;

	if (ds == NULL || ds[0] == '\0' || buf == NULL || n == 0)
		return (EINVAL);
	pthread_mutex_lock(&g_mntlock);
	for (m = g_mnts; m != NULL; m = m->next) {
		if (strcmp(m->ds, ds) == 0) {
			(void) strlcpy(buf, m->mnt, n);
			err = 0;
			break;
		}
	}
	pthread_mutex_unlock(&g_mntlock);
	return (err);
}
int
zfsd_zpl_zget_by_dev(dev_t dev, uint64_t ino, znode_t **zpp)
{
	zpl_mnt_t *m, *found = NULL;
	int err;

	*zpp = NULL;
	pthread_mutex_lock(&g_mntlock);
	for (m = g_mnts; m != NULL; m = m->next) {
		if (m->pending || m->zfsvfs == NULL || m->mnt[0] == '\0')
			continue;
		if (m->fsid_dev != 0 && m->fsid_dev == dev) {
			found = m;
			found->inuse++;
			break;
		}
	}
	pthread_mutex_unlock(&g_mntlock);
	if (found == NULL)
		return (EXDEV);
	err = zfs_zget(found->zfsvfs, ino, zpp);
	pthread_mutex_lock(&g_mntlock);
	found->inuse--;
	pthread_mutex_unlock(&g_mntlock);
	return (err);
}
int
zfsd_zpl_ds_from_mnt(const char *mnt, char *ds, size_t n)
{
	zpl_mnt_t *m;
	int err = ENOENT;

	if (mnt == NULL || mnt[0] == '\0' || ds == NULL || n == 0)
		return (EINVAL);
	pthread_mutex_lock(&g_mntlock);
	for (m = g_mnts; m != NULL; m = m->next) {
		if (strcmp(m->mnt, mnt) == 0) {
			(void) strlcpy(ds, m->ds, n);
			err = 0;
			break;
		}
	}
	pthread_mutex_unlock(&g_mntlock);
	return (err);
}
void
zfsd_zpl_drop_children(zpl_mnt_t *parent, zpl_mnt_t **dropp)
{
	zpl_mnt_t **pp, *m;

	if (parent == NULL)
		return;
	pp = &g_mnts;
	while ((m = *pp) != NULL) {
		if (m->parent == parent || (m->snap && parent->mnt[0] != '\0' &&
		    strncmp(m->mnt, parent->mnt, strlen(parent->mnt)) == 0 &&
		    m->mnt[strlen(parent->mnt)] == '/')) {
			*pp = m->next;
			m->next = *dropp;
			*dropp = m;
		} else {
			pp = &m->next;
		}
	}
}
int
zfsd_zpl_unmount(const char *dsname, const char *mnt, uint64_t flags)
{
	zpl_mnt_t **pp, *m, *c;
	zpl_mnt_t *kids = NULL;
	int force;

	if (dsname != NULL)
		zpl_snapos_drop(dsname);
	force = (flags & (MNT_FORCE | MNT_DETACH)) != 0;
	pthread_mutex_lock(&g_mntlock);
	m = NULL;
	for (pp = &g_mnts; (c = *pp) != NULL; pp = &c->next) {
		/*
		 * Dataset and path together identify one mount.
		 * Matching either one unmounts the lower filesystem
		 * when an overlay shares the path, or a different
		 * path of a multi-mount.
		 */
		if (dsname != NULL && dsname[0] != '\0') {
			if (strcmp(c->ds, dsname) != 0)
				continue;
			if (mnt != NULL && mnt[0] != '\0' &&
			    strcmp(c->mnt, mnt) != 0)
				continue;
		} else if (mnt == NULL || strcmp(c->mnt, mnt) != 0) {
			continue;
		}
		m = c;
		break;
	}
	if (m != NULL && (m->pending || m->inuse != 0)) {
		pthread_mutex_unlock(&g_mntlock);
		return (EBUSY);
	}
	if (m != NULL && !force) {
		if (zfsd_path_busy(m->mnt)) {
			pthread_mutex_unlock(&g_mntlock);
			return (EBUSY);
		}
		if (!m->snap) {
			for (c = g_mnts; c != NULL; c = c->next) {
				if (c == m)
					continue;
				if (c->parent == m || (c->snap &&
				    m->mnt[0] != '\0' &&
				    strncmp(c->mnt, m->mnt, strlen(m->mnt))
				    == 0 &&
				    c->mnt[strlen(m->mnt)] == '/')) {
					if (zfsd_path_busy(c->mnt)) {
						pthread_mutex_unlock(
						    &g_mntlock);
						return (EBUSY);
					}
				}
			}
		}
	}
	if (m != NULL) {
		*pp = m->next;
		if (!m->snap)
			zfsd_zpl_drop_children(m, &kids);
	}
	pthread_mutex_unlock(&g_mntlock);
	if (m == NULL) {
		if (mnt != NULL && mnt[0] != '\0') {
			if (!force && zfsd_path_busy(mnt))
				return (EBUSY);
			zfsd_lazy_umount(mnt);
		}
		/* Match kernel zfs: unmount of a not-mounted dataset is 0. */
		return (0);
	}
	while (kids != NULL) {
		zpl_mnt_t *n = kids->next;
		zfsd_zpl_teardown(kids);
		kids = n;
	}
	zfsd_zpl_teardown(m);
	return (0);
}

/*
 * libzfs unmounts the primary mount, renames, then mounts the new
 * name. Extra mounts of the same dataset still hold the objset under
 * the old name, so the new mount must find that zfsvfs.
 */
void
zfsd_zpl_note_rename(const char *oldname, const char *newname)
{
	zpl_mnt_t *m;
	size_t olen, nlen;

	if (oldname == NULL || newname == NULL || oldname[0] == '\0' ||
	    newname[0] == '\0')
		return;
	olen = strlen(oldname);
	nlen = strlen(newname);
	pthread_mutex_lock(&g_mntlock);
	for (m = g_mnts; m != NULL; m = m->next) {
		char renamed[ZFS_MAX_DATASET_NAME_LEN];
		const char *rest = NULL;

		if (strcmp(m->ds, oldname) == 0) {
			rest = "";
		} else if (strncmp(m->ds, oldname, olen) == 0 &&
		    (m->ds[olen] == '/' || m->ds[olen] == '@')) {
			rest = m->ds + olen;
		} else {
			continue;
		}
		if (nlen + strlen(rest) >= sizeof (renamed))
			continue;
		(void) memcpy(renamed, newname, nlen);
		(void) memcpy(renamed + nlen, rest, strlen(rest) + 1);
		(void) memcpy(m->ds, renamed, strlen(renamed) + 1);
	}
	pthread_mutex_unlock(&g_mntlock);
}
/*
 * Reaper path. Never stat() the mount: that GETATTR deadlocks a
 * saturated session and a pool export that is joining it. A path we
 * still serve is left alone (reap_detached drops it once the kernel
 * mount is gone). Anything else is a leftover kernel mount.
 */
static void
zfsd_zpl_unmount_dead(const char *mnt)
{
	zpl_mnt_t *m;
	int serve = 0;

	if (mnt == NULL || mnt[0] == '\0')
		return;
	pthread_mutex_lock(&g_mntlock);
	for (m = g_mnts; m != NULL; m = m->next) {
		if (strcmp(m->mnt, mnt) == 0) {
			serve = 1;
			break;
		}
	}
	pthread_mutex_unlock(&g_mntlock);
	if (!serve)
		zfsd_lazy_umount(mnt);
}
void
zfsd_zpl_unmount_all(void)
{
	zpl_mnt_t *m, *snaps = NULL, *rest = NULL;

	zpl_snapos_drop_all();
	pthread_mutex_lock(&g_mntlock);
	m = g_mnts;
	g_mnts = NULL;
	pthread_mutex_unlock(&g_mntlock);
	while (m != NULL) {
		zpl_mnt_t *n = m->next;
		if (m->snap) {
			m->next = snaps;
			snaps = m;
		} else {
			m->next = rest;
			rest = m;
		}
		m = n;
	}
	while (snaps != NULL) {
		zpl_mnt_t *n = snaps->next;
		zfsd_zpl_teardown(snaps);
		snaps = n;
	}
	while (rest != NULL) {
		zpl_mnt_t *n = rest->next;
		zfsd_zpl_teardown(rest);
		rest = n;
	}
}
void
zfsd_zpl_unmount_pool(const char *pool)
{
	zpl_mnt_t *drop = NULL, **pp, *m;

	if (pool == NULL || pool[0] == '\0') {
		zfsd_zpl_unmount_all();
		zfsd_zvol_unpublish_pool(NULL);
		return;
	}
	zpl_snapos_drop(pool);
	pthread_mutex_lock(&g_mntlock);
	pp = &g_mnts;
	while ((m = *pp) != NULL) {
		if (zpl_ds_in_pool(m->ds, pool)) {
			*pp = m->next;
			m->next = drop;
			drop = m;
		} else {
			pp = &m->next;
		}
	}
	pthread_mutex_unlock(&g_mntlock);
	while (drop != NULL) {
		zpl_mnt_t *nxt = drop->next;
		zfsd_zpl_teardown(drop);
		drop = nxt;
	}
	zfsd_zvol_unpublish_pool(pool);
}
/*
 * Drop kernel FUSE attr/ACL caches after rollback. Paths are
 * relative to the mount (libfuse's name cache). Cap the walk so a
 * huge dataset cannot stall the ioctl thread.
 */

static void
zfsd_inval_dir(struct fuse *f, objset_t *os, uint64_t dirobj,
    char *path, size_t plen, int depth, int *left)
{
	zap_cursor_t zc;
	zap_attribute_t *za;

	if (f == NULL || os == NULL || left == NULL || *left <= 0)
		return;
	if (depth > ZFSD_INVAL_DEPTH || plen >= MAXPATHLEN - 2)
		return;
	za = zap_attribute_alloc();
	if (za == NULL)
		return;
	for (zap_cursor_init(&zc, os, dirobj);
	    zap_cursor_retrieve(&zc, za) == 0 && *left > 0;
	    zap_cursor_advance(&zc)) {
		size_t nlen;
		uint64_t obj;
		dmu_object_info_t doi;

		if (za->za_name[0] == '\0' ||
		    strcmp(za->za_name, ".") == 0 ||
		    strcmp(za->za_name, "..") == 0)
			continue;
		nlen = strlen(za->za_name);
		if (plen + 1 + nlen >= MAXPATHLEN)
			continue;
		path[plen] = '/';
		(void) memcpy(path + plen + 1, za->za_name, nlen + 1);
		(void) fuse_invalidate_path(f, path);
		(*left)--;
		obj = ZFS_DIRENT_OBJ(za->za_first_integer);
		memset(&doi, 0, sizeof (doi));
		if (dmu_object_info(os, obj, &doi) == 0 &&
		    doi.doi_type == DMU_OT_DIRECTORY_CONTENTS)
			zfsd_inval_dir(f, os, obj, path,
			    plen + 1 + nlen, depth + 1, left);
		path[plen] = '\0';
	}
	zap_cursor_fini(&zc);
	zap_attribute_free(za);
}

void
zfsd_zpl_inval_fs(zfsvfs_t *zfsvfs)
{
	zpl_mnt_t *m;
	struct fuse *f = NULL;
	char path[MAXPATHLEN];
	int left = ZFSD_INVAL_MAX;

	if (zfsvfs == NULL)
		return;
	pthread_mutex_lock(&g_mntlock);
	for (m = g_mnts; m != NULL; m = m->next) {
		if (m->zfsvfs == zfsvfs && m->fuse != NULL && !m->dying) {
			f = m->fuse;
			break;
		}
	}
	pthread_mutex_unlock(&g_mntlock);
	if (f == NULL)
		return;
	(void) fuse_invalidate_path(f, "/");
	path[0] = '\0';
	if (zfsvfs->z_os != NULL && zfsvfs->z_root != 0)
		zfsd_inval_dir(f, zfsvfs->z_os, zfsvfs->z_root, path, 0, 0,
		    &left);
}

void
zfsd_zpl_workers_start(void)
{
	zfsd_reaper_cv_init();
	pthread_mutex_lock(&g_reaper_mx);
	g_reaper_running = 1;
	pthread_mutex_unlock(&g_reaper_mx);
	if (pthread_create(&g_reaper_tid, NULL, zpl_reaper, NULL) != 0) {
		pthread_mutex_lock(&g_reaper_mx);
		g_reaper_running = 0;
		pthread_mutex_unlock(&g_reaper_mx);
	}
}

void
zfsd_zpl_workers_stop(void)
{
	pthread_mutex_lock(&g_reaper_mx);
	if (g_reaper_running) {
		g_reaper_running = 0;
		(void) pthread_cond_broadcast(&g_reaper_cv);
		pthread_mutex_unlock(&g_reaper_mx);
		(void) pthread_join(g_reaper_tid, NULL);
	} else {
		pthread_mutex_unlock(&g_reaper_mx);
	}
}
