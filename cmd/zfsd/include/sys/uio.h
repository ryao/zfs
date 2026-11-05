// SPDX-License-Identifier: CDDL-1.0
/*
 * Extend libspl's zfs_uio_t with the helpers module/zfs/zfs_vnops.c
 * expects. Layout stays the libspl struct so dmu_read/write in libzpool
 * stay ABI-compatible. Direct I/O is not implemented: page-aligned
 * reports false so zfs_setup_direct falls through to ARC.
 */
#ifndef	_ZFSD_SYS_UIO_H
#define	_ZFSD_SYS_UIO_H

#include_next <sys/uio.h>
#include <limits.h>
#include <string.h>


#ifndef	UIO_DIRECT
#define	UIO_DIRECT	0x0001
#endif
#ifndef	UIO_UNCACHED
#define	UIO_UNCACHED	0x0002 /* Caller will not reuse the data */
#endif
#ifndef	UIO_DIO_DENY
#define	UIO_DIO_DENY		0x0004
#endif
#ifndef	UIO_DIO_CKSUM_RETRIED
#define	UIO_DIO_CKSUM_RETRIED	0x0008
#endif
#ifndef	UIO_DIO_BOUNCE
#define	UIO_DIO_BOUNCE		0x0010
#endif

#ifndef	zfs_uio_setoffset
#define	zfs_uio_setoffset(u, off)	((u)->uio_loffset = (off))
#endif
#ifndef	zfs_uio_setsoffset
#define	zfs_uio_setsoffset(u, off)	((void)(off))
#endif
#ifndef	zfs_uio_fault_disable
#define	zfs_uio_fault_disable(u, set)	((void)(set))
#endif
#ifndef	zfs_uio_soffset
#define	zfs_uio_soffset(u)		((u)->uio_loffset)
#endif

static inline int
zfs_uio_prefaultpages(ssize_t n, zfs_uio_t *uio)
{
	(void) n;
	(void) uio;
	return (0);
}

static inline void
zfs_uio_iovec_init(zfs_uio_t *uio, const struct iovec *iov,
    unsigned long nr_segs, offset_t offset, zfs_uio_seg_t seg, ssize_t resid,
    size_t skip)
{
	memset(uio, 0, sizeof (*uio));
	if (nr_segs > (unsigned long)INT_MAX)
		nr_segs = (unsigned long)INT_MAX;
	if (resid < 0)
		resid = 0;
	uio->uio_iov = (struct iovec *)(uintptr_t)iov;
	uio->uio_iovcnt = (int)nr_segs;
	uio->uio_loffset = offset;
	uio->uio_segflg = seg;
	uio->uio_resid = resid;
	uio->uio_skip = skip;
}


#ifndef	zfs_uio_aligned
static inline boolean_t
zfs_uio_aligned(zfs_uio_t *uio, uint64_t blksz)
{
	return (zfs_dio_aligned(zfs_uio_offset(uio), zfs_uio_resid(uio),
	    blksz));
}
#endif

extern int zfs_uiomove(void *, size_t, zfs_uio_rw_t, zfs_uio_t *);
extern int zfs_uiocopy(void *, size_t, zfs_uio_rw_t, zfs_uio_t *, size_t *);
extern void zfs_uioskip(zfs_uio_t *, size_t);
extern int zfs_uio_fault_move(void *, size_t, zfs_uio_rw_t, zfs_uio_t *);
extern boolean_t zfs_uio_page_aligned(zfs_uio_t *);
extern int zfs_uio_get_dio_pages_alloc(zfs_uio_t *, zfs_uio_rw_t);
extern void zfs_uio_free_dio_pages(zfs_uio_t *, zfs_uio_rw_t);

#endif	/* _ZFSD_SYS_UIO_H */
