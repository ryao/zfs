// SPDX-License-Identifier: CDDL-1.0
/*
 * Linux ZPL uses PAGE_SIZE. libspl exposes PAGESIZE (spl_pagesize()).
 */
#ifndef	_ZFSD_SYS_PARAM_H
#define	_ZFSD_SYS_PARAM_H

#include_next <sys/param.h>

#ifndef	PAGE_SIZE
#define	PAGE_SIZE	PAGESIZE
#endif

#endif
