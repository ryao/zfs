// SPDX-License-Identifier: CDDL-1.0
/*
 * zfsd control node. Unmodified zfs(8)/zpool(8) issue the stock ioctl
 * ABI (zfs_cmd_t with nested nvlist pointers). FUSE cannot copy those
 * nested pointers, so zfsd uses process_vm_{readv,writev} / ptrace to
 * copy them out of the caller's address space -- the same privilege
 * check as PTRACE_ATTACH. File descriptors in send/recv are stolen
 * via pidfd_getfd (atomic dup, no /proc/<pid>/fd TOCTOU).
 *
 * ZFSDEV is a token, never a path:
 *   unset  -> /dev/zfs (kernel ioctl or zfsd --native)
 *   native -> /dev/zfs, zfsd (module must be absent)
 *   fuse   -> /dev/uzfs, zfsd beside an optional module
 * It selects the control node. It does not gate libzfs/libspl
 * behaviour; zfsd sets zfsd_daemon in-process for that.
 */
#ifndef	_SYS_ZFSD_H
#define	_SYS_ZFSD_H

#include <stdint.h>
#include <sys/types.h>
#include <sys/fs/zfs.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	ZFS_DEV_FUSE	"/dev/uzfs"
#define	ZFSDEV_ENV	"ZFSDEV"
#define	ZFSDEV_NATIVE	"native"
#define	ZFSDEV_FUSE	"fuse"

/*
 * Cap on nested pointer / history copies out of the caller.
 */
#define	ZFSD_PTRACE_MAX	(16U * 1024U * 1024U)

/*
 * zfsd-only ioctls, registered in zfs_ioctl_init() for non-kernel
 * builds and served through zfsdev_ioctl_common like the rest of
 * the ABI. Numbers live in the per-platform 0x80.. range.
 */
#define	ZFSD_IOC_MOUNT		((uint32_t)ZFS_IOC_ZFSD_MOUNT)
#define	ZFSD_IOC_UNMOUNT	((uint32_t)ZFS_IOC_ZFSD_UNMOUNT)
#define	ZFSD_IOC_SHARE		((uint32_t)ZFS_IOC_ZFSD_SHARE)
#define	ZFSD_IOC_UNSHARE	((uint32_t)ZFS_IOC_ZFSD_UNSHARE)

uint32_t zfsd_ioc_canon(uint32_t ioc);

typedef struct zfsd_pidpin {
	pid_t		pid;
	int		pidfd;
	int		procfd;
	uint64_t	starttime;
} zfsd_pidpin_t;

void zfsd_copy_begin(const zfsd_pidpin_t *pin);
void zfsd_copy_end(void);
int zfsd_ddi_copyin(const void *from, void *to, size_t len, int flags);
int zfsd_ddi_copyout(const void *from, void *to, size_t len, int flags);
int zfsd_copyinstr(const void *from, void *to, size_t len, size_t *done);
int zfsd_file_steal(int fd);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ZFSD_H */
