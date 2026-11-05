// SPDX-License-Identifier: CDDL-1.0
/*
 * Userspace vattr/vnode bits for compiling module/zfs/zfs_{vnops,log,replay}
 * into zfsd. Attribute bits match the Linux ZPL ATTR_* values.
 */
#ifndef	_SYS_VNODE_H
#define	_SYS_VNODE_H

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/fcntl.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	ATTR_MODE
#define	ATTR_MODE	(1 << 0)
#define	ATTR_UID	(1 << 1)
#define	ATTR_GID	(1 << 2)
#define	ATTR_SIZE	(1 << 3)
#define	ATTR_ATIME	(1 << 4)
#define	ATTR_MTIME	(1 << 5)
#define	ATTR_CTIME	(1 << 6)
#endif

#define	AT_MODE		ATTR_MODE
#define	AT_UID		ATTR_UID
#define	AT_GID		ATTR_GID
#define	AT_SIZE		ATTR_SIZE
#define	AT_ATIME	ATTR_ATIME
#define	AT_MTIME	ATTR_MTIME
#define	AT_CTIME	ATTR_CTIME

#define	ATTR_XVATTR	(1U << 31)
#define	AT_XVATTR	ATTR_XVATTR
#define	ATTR_NOACLCHECK	0x20

#define	CRCREAT		0x01
#define	RMFILE		0x02
#define	LOOKUP_DIR		0x01
#define	LOOKUP_XATTR		0x02
#define	CREATE_XATTR_DIR	0x04
#ifndef	FIGNORECASE
#define	FIGNORECASE	0x80000
#endif
#define	ED_CASE_CONFLICT	0x10
#define	F_FREESP	11
#ifndef	F_SEEK_DATA
#define	F_SEEK_DATA	3
#define	F_SEEK_HOLE	4
#endif

#ifndef	RENAME_NOREPLACE
#define	RENAME_NOREPLACE	(1 << 0)
#define	RENAME_EXCHANGE		(1 << 1)
#define	RENAME_WHITEOUT		(1 << 2)
#endif

/*
 * Solaris file flags used by zfs_open/zfs_fsync. glibc's BSD FAPPEND
 * (O_APPEND) is a different constant; always use the ZPL values.
 */
#undef	FREAD
#undef	FWRITE
#undef	FAPPEND
#undef	FSYNC
#undef	FDSYNC
#define	FREAD		0x01
#define	FWRITE		0x02
#define	FAPPEND		0x08
#define	FSYNC		0x10
#define	FDSYNC		0x40

#ifndef	umode_t
typedef mode_t umode_t;
#endif

typedef struct flock flock64_t;

typedef struct vattr {
	uint_t		va_mask;
	mode_t		va_mode;
	uid_t		va_uid;
	gid_t		va_gid;
	long		va_fsid;
	uint64_t	va_nodeid;
	uint32_t	va_nlink;
	uint64_t	va_size;
	inode_timespec_t va_atime;
	inode_timespec_t va_mtime;
	inode_timespec_t va_ctime;
	dev_t		va_rdev;
	uint64_t	va_nblocks;
	uint32_t	va_blksize;
	void		*va_dentry;
	uint_t		va_vaflags;
} vattr_t;

#ifndef	VA_UTIMES_NULL
#define	VA_UTIMES_NULL	0x01
#endif


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_VNODE_H */
