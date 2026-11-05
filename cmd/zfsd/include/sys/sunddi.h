// SPDX-License-Identifier: CDDL-1.0
/*
 * zfsd copyin/copyout. Nested zfs_cmd_t pointers stay as the
 * caller's addresses; zfsdev_ioctl_common copies them through
 * these helpers, matching Linux zfsdev_ioctl.
 */
#ifndef	_ZFSD_SYS_SUNDDI_H
#define	_ZFSD_SYS_SUNDDI_H

#define	_SYS_SUNDDI_H

#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/zfsd.h>

extern int ddi_strtoull(const char *str, char **nptr, int base,
    u_longlong_t *result);

static inline int
ddi_copyin(const void *from, void *to, size_t len, int flags)
{
	return (zfsd_ddi_copyin(from, to, len, flags));
}

static inline int
ddi_copyout(const void *from, void *to, size_t len, int flags)
{
	return (zfsd_ddi_copyout(from, to, len, flags));
}

static inline int
copyinstr(const void *from, void *to, size_t len, size_t *done)
{
	return (zfsd_copyinstr(from, to, len, done));
}

static inline int
xcopyout(const void *from, void *to, size_t len)
{
	return (zfsd_ddi_copyout(from, to, len, 0) != 0 ? EFAULT : 0);
}

#endif	/* _ZFSD_SYS_SUNDDI_H */
