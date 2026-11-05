// SPDX-License-Identifier: CDDL-1.0
/*
 * Userspace vfs bits. libspl's sys/vfs.h pulls in linux/fs.h (UAPI),
 * which is not a VFS. zfsd supplies the mount-option vfs_t used by
 * include/os/linux/zfs/sys/zfs_vfsops_os.h -- this file is the
 * include-path override for <sys/vfs.h>.
 */
#ifndef	_SYS_VFS_H
#define	_SYS_VFS_H

#include <sys/types.h>
#include <sys/statfs.h>
#include <sys/mount.h>

#ifndef	MS_RDONLY
#define	MS_RDONLY	1
#endif
#ifndef	MS_NOSUID
#define	MS_NOSUID	2
#endif
#ifndef	MS_NODEV
#define	MS_NODEV	4
#endif
#ifndef	MS_NOEXEC
#define	MS_NOEXEC	8
#endif
#ifndef	MS_NOATIME
#define	MS_NOATIME	1024
#endif

#endif	/* _SYS_VFS_H */
