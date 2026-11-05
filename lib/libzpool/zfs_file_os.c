// SPDX-License-Identifier: CDDL-1.0
/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * https://opensource.org/license/CDDL-1.0.
 */
/*
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, 2018 by Delphix. All rights reserved.
 * Copyright (c) 2016 Actifio, Inc. All rights reserved.
 * Copyright (c) 2025, Klara, Inc.
 */

#include <sys/zfs_context.h>
#include <sys/zfs_file.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

typedef struct {
	int f_fd;
	int f_dump_fd;
	int f_stolen;
} file_t;

/* If set, all blocks read will be copied to the specified directory. */
char *vn_dumpdir = NULL;

__thread int (*zfsd_file_steal_hook)(int fd) = NULL;

/*
 * Open file
 *
 * path - fully qualified path to file
 * flags - file attributes O_READ / O_WRITE / O_EXCL
 * fpp - pointer to return file pointer
 *
 * Returns 0 on success underlying error on failure.
 */
int
zfs_file_open(const char *path, int flags, int mode, cred_t *cr,
    zfs_file_t **zfpp)
{
	(void) cr;
	int fd;
	int dump_fd;
	int err;
	int old_umask = 0;
	file_t *fp;
	struct stat64 st;

	if (!(flags & O_CREAT) && stat64(path, &st) == -1)
		return (errno);

	if (!(flags & O_CREAT) && S_ISBLK(st.st_mode))
		flags |= O_DIRECT;

	if (flags & O_CREAT)
		old_umask = umask(0);

	fd = open64(path, flags, mode);
	err = errno;

	if (flags & O_CREAT)
		(void) umask(old_umask);

	if (fd == -1)
		return (err);

	if (vn_dumpdir != NULL) {
		char *dumppath = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
		const char *bn = strrchr(path, '/');
		const char *inpath = (bn ? bn + 1 : path);

		(void) snprintf(dumppath, MAXPATHLEN,
		    "%s/%s", vn_dumpdir, inpath);
		dump_fd = open64(dumppath, O_CREAT | O_WRONLY, 0666);
		kmem_free(dumppath, MAXPATHLEN);
		if (dump_fd == -1) {
			err = errno;
			close(fd);
			return (err);
		}
	} else {
		dump_fd = -1;
	}

	(void) fcntl(fd, F_SETFD, FD_CLOEXEC);

	fp = kmem_zalloc(sizeof (file_t), KM_SLEEP);
	fp->f_fd = fd;
	fp->f_dump_fd = dump_fd;
	*zfpp = fp;

	return (0);
}

void
zfs_file_close(zfs_file_t *zfp)
{
	file_t *fp = zfp;
	close(fp->f_fd);
	if (fp->f_dump_fd != -1)
		close(fp->f_dump_fd);

	kmem_free(fp, sizeof (file_t));
}

/*
 * Stateful write - use os internal file pointer to determine where to
 * write and update on successful completion.
 *
 * fp -  pointer to file (pipe, socket, etc) to write to
 * buf - buffer to write
 * count - # of bytes to write
 * resid -  pointer to count of unwritten bytes  (if short write)
 *
 * Returns 0 on success errno on failure.
 */
int
zfs_file_write(zfs_file_t *zfp, const void *buf, size_t count, ssize_t *resid)
{
	file_t *fp = zfp;
	ssize_t rc;

	rc = write(fp->f_fd, buf, count);
	if (rc < 0)
		return (errno);

	if (resid) {
		*resid = count - rc;
	} else if (rc != count) {
		return (EIO);
	}

	return (0);
}

/*
 * Stateless write - os internal file pointer is not updated.
 *
 * fp -  pointer to file (pipe, socket, etc) to write to
 * buf - buffer to write
 * count - # of bytes to write
 * off - file offset to write to (only valid for seekable types)
 * resid -  pointer to count of unwritten bytes
 *
 * Returns 0 on success errno on failure.
 */
#ifdef __linux__
/*
 * Block vdevs are opened O_DIRECT. Linux then rejects a pread/pwrite
 * whose buffer is not logical-block aligned (EINVAL) and the old
 * code abort()ed zfsd. ABD data is not aligned, so bounce those I/Os.
 * A still-misaligned count or offset is returned to the caller; it
 * must not take the daemon down.
 */
static int
zfs_file_is_odirect(int fd)
{
	int fl = fcntl(fd, F_GETFL);

	return (fl >= 0 && (fl & O_DIRECT) != 0);
}

static int
zfs_odirect_bounce(int fd, const void *buf, size_t count, loff_t off,
    int copyin, void **bouncep)
{
	void *abuf;

	*bouncep = NULL;
	if (!zfs_file_is_odirect(fd))
		return (0);
	if ((((uintptr_t)buf | (uintptr_t)count | (uintptr_t)off) & 511) == 0)
		return (0);
	if ((count & 511) != 0 || (off & 511) != 0)
		return (EINVAL);
	if (posix_memalign(&abuf, 4096, count == 0 ? 512 : count) != 0)
		return (ENOMEM);
	if (copyin && count != 0)
		memcpy(abuf, buf, count);
	*bouncep = abuf;
	return (0);
}
#endif

int
zfs_file_pwrite(zfs_file_t *zfp, const void *buf,
    size_t count, loff_t pos, uint8_t ashift, ssize_t *resid)
{
	file_t *fp = zfp;
	ssize_t rc, split, done = 0;
	int sectors;
	const void *iobuf = buf;
#ifdef __linux__
	void *bounce = NULL;
	int berr;
#endif

	/*
	 * To simulate partial disk writes, we split writes into two
	 * system calls so that the process can be killed in between.
	 * This is used by ztest to simulate realistic failure modes.
	 */
#ifdef __linux__
	berr = zfs_odirect_bounce(fp->f_fd, buf, count, pos, 1, &bounce);
	if (berr != 0)
		return (berr);
	if (bounce != NULL)
		iobuf = bounce;
#endif
	sectors = count >> ashift;
	split = (sectors > 0 ? rand() % sectors : 0) << ashift;
	rc = pwrite64(fp->f_fd, iobuf, split, pos);
	if (rc != -1) {
		done = rc;
		rc = pwrite64(fp->f_fd, (char *)iobuf + split,
		    count - split, pos + split);
	}
#ifdef __linux__
	free(bounce);
#endif

	if (rc < 0)
		return (errno);

	done += rc;

	if (resid) {
		*resid = count - done;
	} else if (done != count) {
		return (EIO);
	}

	return (0);
}

/*
 * Stateful read - use os internal file pointer to determine where to
 * read and update on successful completion.
 *
 * fp -  pointer to file (pipe, socket, etc) to read from
 * buf - buffer to write
 * count - # of bytes to read
 * resid -  pointer to count of unread bytes (if short read)
 *
 * Returns 0 on success errno on failure.
 */
int
zfs_file_read(zfs_file_t *zfp, void *buf, size_t count, ssize_t *resid)
{
	file_t *fp = zfp;
	int rc;

	rc = read(fp->f_fd, buf, count);
	if (rc < 0)
		return (errno);

	if (resid) {
		*resid = count - rc;
	} else if (rc != count) {
		return (EIO);
	}

	return (0);
}

/*
 * Stateless read - os internal file pointer is not updated.
 *
 * fp -  pointer to file (pipe, socket, etc) to read from
 * buf - buffer to write
 * count - # of bytes to write
 * off - file offset to read from (only valid for seekable types)
 * resid -  pointer to count of unwritten bytes (if short write)
 *
 * Returns 0 on success errno on failure.
 */
int
zfs_file_pread(zfs_file_t *zfp, void *buf, size_t count, loff_t off,
    ssize_t *resid)
{
	file_t *fp = zfp;
	ssize_t rc;
	void *iobuf = buf;
#ifdef __linux__
	void *bounce = NULL;
	int berr;

	berr = zfs_odirect_bounce(fp->f_fd, buf, count, off, 0, &bounce);
	if (berr != 0)
		return (berr);
	if (bounce != NULL)
		iobuf = bounce;
#endif

	rc = pread64(fp->f_fd, iobuf, count, off);
#ifdef __linux__
	if (rc > 0 && bounce != NULL)
		memcpy(buf, bounce, rc);
	free(bounce);
#endif
	if (rc < 0)
		return (errno);

	if (fp->f_dump_fd != -1) {
		int status;

		status = pwrite64(fp->f_dump_fd, buf, rc, off);
		ASSERT(status != -1);
	}

	if (resid) {
		*resid = count - rc;
	} else if (rc != count) {
		return (EIO);
	}

	return (0);
}

/*
 * lseek - set / get file pointer
 *
 * fp -  pointer to file (pipe, socket, etc) to read from
 * offp - value to seek to, returns current value plus passed offset
 * whence - see man pages for standard lseek whence values
 *
 * Returns 0 on success errno on failure (ESPIPE for non seekable types)
 */
int
zfs_file_seek(zfs_file_t *zfp, loff_t *offp, int whence)
{
	file_t *fp = zfp;
	loff_t rc;

	rc = lseek(fp->f_fd, *offp, whence);
	if (rc < 0)
		return (errno);

	*offp = rc;

	return (0);
}

/*
 * Get file attributes
 *
 * filp - file pointer
 * zfattr - pointer to file attr structure
 *
 * Currently only used for fetching size and file mode
 *
 * Returns 0 on success or error code of underlying getattr call on failure.
 */
int
zfs_file_getattr(zfs_file_t *zfp, zfs_file_attr_t *zfattr)
{
	file_t *fp = zfp;
	struct stat64 st;

	if (fstat64_blk(fp->f_fd, &st) == -1)
		return (errno);

	zfattr->zfa_size = st.st_size;
	zfattr->zfa_mode = st.st_mode;

	return (0);
}

/*
 * Sync file to disk
 *
 * filp - file pointer
 * flags - O_SYNC and or O_DSYNC
 *
 * Returns 0 on success or error code of underlying sync call on failure.
 */
int
zfs_file_fsync(zfs_file_t *zfp, int flags)
{
	file_t *fp = zfp;
	(void) flags;

	if (fsync(fp->f_fd) < 0)
		return (errno);

	return (0);
}

/*
 * deallocate - zero and/or deallocate file storage
 *
 * fp - file pointer
 * offset - offset to start zeroing or deallocating
 * len - length to zero or deallocate
 */
int
zfs_file_deallocate(zfs_file_t *zfp, loff_t offset, loff_t len)
{
	file_t *fp = zfp;
	int rc;
#if defined(__linux__)
	rc = fallocate(fp->f_fd,
	    FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, offset, len);
	if (rc == -1)
		rc = errno;
#elif defined(__FreeBSD__) && (__FreeBSD_version >= 1400029)
	struct spacectl_range rqsr = {
		.r_offset = offset,
		.r_len = len,
	};
	rc = fspacectl(fp->f_fd, SPACECTL_DEALLOC, &rqsr, 0, &rqsr);
	if (rc == -1)
		rc = errno;
#else
	(void) fp, (void) offset, (void) len;
	rc = EOPNOTSUPP;
#endif
	if (rc)
		return (SET_ERROR(rc));
	return (0);
}

/*
 * Request current file pointer offset
 *
 * fp - pointer to file
 *
 * Returns current file offset.
 */
loff_t
zfs_file_off(zfs_file_t *zfp)
{
	file_t *fp = zfp;
	return (lseek(fp->f_fd, 0, SEEK_CUR));
}

/*
 * unlink file
 *
 * path - fully qualified file path
 *
 * Returns 0 on success errno on failure.
 *
 * OPTIONAL
 */
int
zfs_file_unlink(const char *path)
{
	if (remove(path) == -1)
		return (errno);

	return (0);
}

/*
 * Get reference to file pointer
 *
 * fd - input file descriptor
 *
 * Returns pointer to file struct or NULL. On the zfsd ioctl path the
 * fd number is the caller's; zfsd_file_steal_hook (TLS) dup's it into
 * this process. f_stolen means zfs_file_put() closes that dup; the
 * caller's fd is not closed. With no hook this does not dup or close.
 */
zfs_file_t *
zfs_file_get(int fd)
{
	file_t *fp;
	struct stat64 st;
	int real_fd = fd;
	int stolen = 0;

	if (fd < 0)
		return (NULL);
	if (zfsd_file_steal_hook != NULL) {
		real_fd = zfsd_file_steal_hook(fd);
		if (real_fd < 0)
			return (NULL);
		stolen = 1;
	}
	if (fstat64(real_fd, &st) != 0) {
		if (stolen)
			(void) close(real_fd);
		return (NULL);
	}
	fp = kmem_zalloc(sizeof (file_t), KM_SLEEP);
	fp->f_fd = real_fd;
	fp->f_dump_fd = -1;
	fp->f_stolen = stolen;
	return (fp);
}

/*
 * Drop reference to file pointer
 *
 * fp - pointer to file struct
 */
void
zfs_file_put(zfs_file_t *zfp)
{
	file_t *fp = zfp;

	if (fp == NULL)
		return;
	if (fp->f_stolen && fp->f_fd >= 0)
		(void) close(fp->f_fd);
	kmem_free(fp, sizeof (file_t));
}

void *
zfs_file_private(zfs_file_t *zfp)
{
	/*
	 * Userspace zfsdev_private_set_state() stores the zfsdev_state_t*
	 * through the pointer this returns, and zfsdev_getminor() compares
	 * that pointer with the state object. The previous zfsd object was
	 * the file itself, so keep returning it.
	 */
	return (zfp);
}
