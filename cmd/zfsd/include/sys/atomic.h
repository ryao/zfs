// SPDX-License-Identifier: CDDL-1.0
/*
 * Linux ZPL sources include <sys/atomic.h>. libspl now provides that
 * header itself (the old <atomic.h> wrapper is gone). This file is
 * earlier on zfsd's -I path, so step past it to the libspl copy.
 */
#ifndef	_ZFSD_SYS_ATOMIC_H
#define	_ZFSD_SYS_ATOMIC_H

#include_next <sys/atomic.h>

#endif