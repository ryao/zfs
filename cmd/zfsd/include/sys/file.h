// SPDX-License-Identifier: CDDL-1.0
#ifndef	_SYS_FILE_H
#define	_SYS_FILE_H

#include <sys/types.h>
#include <fcntl.h>

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

#ifndef	FKIOCTL
#define	FKIOCTL		0x80000000
#endif

#ifndef	FIGNORECASE
#define	FIGNORECASE	0x00080000
#endif

#ifndef	ED_CASE_CONFLICT
#define	ED_CASE_CONFLICT	0x10
#endif

#endif	/* _SYS_FILE_H */
