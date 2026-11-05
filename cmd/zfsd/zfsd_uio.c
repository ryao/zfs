// SPDX-License-Identifier: CDDL-1.0
/*
 * Userspace zfs_uiomove and dmu_*_uio_dbuf. Kernel copies live under
 * #ifdef _KERNEL in dmu.c / zfs_uio.c; zfsd supplies the same names.
 */

#include <sys/zfs_context.h>
#include <sys/uio.h>
#include <sys/dmu.h>
#include <sys/dmu_impl.h>
#include <sys/dnode.h>
#include <sys/dbuf.h>
#include <string.h>

extern int zfs_uiomove(void *, size_t, zfs_uio_rw_t, zfs_uio_t *);
extern int zfs_uiocopy(void *, size_t, zfs_uio_rw_t, zfs_uio_t *, size_t *);
extern void zfs_uioskip(zfs_uio_t *, size_t);
extern int zfs_uio_fault_move(void *, size_t, zfs_uio_rw_t, zfs_uio_t *);
extern boolean_t zfs_uio_page_aligned(zfs_uio_t *);
extern int zfs_uio_get_dio_pages_alloc(zfs_uio_t *, zfs_uio_rw_t);
extern void zfs_uio_free_dio_pages(zfs_uio_t *, zfs_uio_rw_t);

int
zfs_uiomove(void *p, size_t n, zfs_uio_rw_t rw, zfs_uio_t *uio)
{
	struct iovec *iov = uio->uio_iov;
	size_t skip = uio->uio_skip;
	size_t cnt;

	if (n > (size_t)zfs_uio_resid(uio))
		n = (size_t)zfs_uio_resid(uio);
	while (n != 0 && uio->uio_resid != 0 && uio->uio_iovcnt > 0) {
		if (skip >= iov->iov_len) {
			skip = 0;
			uio->uio_iov = (++iov);
			uio->uio_iovcnt--;
			continue;
		}
		cnt = MIN(iov->iov_len - skip, n);
		if (rw == UIO_READ)
			(void) memcpy((char *)iov->iov_base + skip, p, cnt);
		else
			(void) memcpy(p, (char *)iov->iov_base + skip, cnt);
		skip += cnt;
		if (skip == iov->iov_len) {
			skip = 0;
			uio->uio_iov = (++iov);
			uio->uio_iovcnt--;
		}
		uio->uio_skip = skip;
		uio->uio_resid -= (ssize_t)cnt;
		uio->uio_loffset += (offset_t)cnt;
		p = (char *)p + cnt;
		n -= cnt;
	}
	uio->uio_skip = skip;
	if (n > 0)
		return (SET_ERROR(EFAULT));
	return (0);
}



int
zfs_uiocopy(void *p, size_t n, zfs_uio_rw_t rw, zfs_uio_t *uio, size_t *cbytes)
{
	zfs_uio_t clone = *uio;
	int error;

	error = zfs_uiomove(p, n, rw, &clone);
	*cbytes = (size_t)(zfs_uio_resid(uio) - zfs_uio_resid(&clone));
	return (error);
}

void
zfs_uioskip(zfs_uio_t *uio, size_t n)
{
	if (n > (size_t)uio->uio_resid)
		return;
	uio->uio_skip += n;
	while (uio->uio_iovcnt > 0 &&
	    uio->uio_skip >= uio->uio_iov->iov_len) {
		uio->uio_skip -= uio->uio_iov->iov_len;
		uio->uio_iov++;
		uio->uio_iovcnt--;
	}
	uio->uio_loffset += (offset_t)n;
	uio->uio_resid -= (ssize_t)n;
}


int
zfs_uio_fault_move(void *p, size_t n, zfs_uio_rw_t rw, zfs_uio_t *uio)
{
	return (zfs_uiomove(p, n, rw, uio));
}

boolean_t
zfs_uio_page_aligned(zfs_uio_t *uio)
{
	(void) uio;
	return (B_FALSE);
}

int
zfs_uio_get_dio_pages_alloc(zfs_uio_t *uio, zfs_uio_rw_t rw)
{
	(void) uio;
	(void) rw;
	return (SET_ERROR(ENOTSUP));
}

void
zfs_uio_free_dio_pages(zfs_uio_t *uio, zfs_uio_rw_t rw)
{
	(void) uio;
	(void) rw;
}

int
dmu_read_uio_dnode(dnode_t *dn, zfs_uio_t *uio, uint64_t size,
    dmu_flags_t flags)
{
	void *buf;
	int err;
	offset_t off;

	if (size == 0)
		return (0);
	buf = kmem_alloc(size, KM_SLEEP);
	off = zfs_uio_offset(uio);
	err = dmu_read(dn->dn_objset, dn->dn_object, off, size, buf, flags);
	if (err == 0)
		err = zfs_uiomove(buf, size, UIO_READ, uio);
	kmem_free(buf, size);
	return (err);
}

int
dmu_read_uio_dbuf(dmu_buf_t *zdb, zfs_uio_t *uio, uint64_t size,
    dmu_flags_t flags)
{
	dmu_buf_impl_t *db = (dmu_buf_impl_t *)zdb;
	dnode_t *dn;
	int err;

	if (size == 0)
		return (0);
	DB_DNODE_ENTER(db);
	dn = DB_DNODE(db);
	err = dmu_read_uio_dnode(dn, uio, size, flags);
	DB_DNODE_EXIT(db);
	return (err);
}

int
dmu_write_uio_dnode(dnode_t *dn, zfs_uio_t *uio, uint64_t size, dmu_tx_t *tx,
    dmu_flags_t flags)
{
	dmu_buf_t **dbp = NULL;
	int numbufs = 0, i, err;
	uint64_t offset;

	(void) flags;
	if (size == 0)
		return (0);
	offset = zfs_uio_offset(uio);
	err = dmu_buf_hold_array_by_dnode(dn, offset, size, B_FALSE, FTAG,
	    &numbufs, &dbp, flags);
	if (err != 0)
		return (err);
	for (i = 0; i < numbufs; i++) {
		dmu_buf_t *db = dbp[i];
		int64_t bufoff = (int64_t)(offset - db->db_offset);
		uint64_t tocpy;

		if (bufoff < 0 || (uint64_t)bufoff >= db->db_size) {
			dmu_buf_rele_array(dbp, numbufs, FTAG);
			return (SET_ERROR(EIO));
		}
		tocpy = MIN(db->db_size - (uint64_t)bufoff, size);
		dmu_buf_will_dirty(db, tx);
		if (db->db_data == NULL) {
			dmu_buf_rele_array(dbp, numbufs, FTAG);
			return (SET_ERROR(EIO));
		}
		err = zfs_uiomove((char *)db->db_data + bufoff, (size_t)tocpy,
		    UIO_WRITE, uio);
		if (err != 0) {
			dmu_buf_rele_array(dbp, numbufs, FTAG);
			return (err);
		}
		offset += tocpy;
		size -= tocpy;
	}
	dmu_buf_rele_array(dbp, numbufs, FTAG);
	return (size == 0 ? 0 : SET_ERROR(EIO));
}

int
dmu_write_uio_dbuf(dmu_buf_t *zdb, zfs_uio_t *uio, uint64_t size,
    dmu_tx_t *tx, dmu_flags_t flags)
{
	dmu_buf_impl_t *db = (dmu_buf_impl_t *)zdb;
	dnode_t *dn;
	int err;

	if (size == 0)
		return (0);
	DB_DNODE_ENTER(db);
	dn = DB_DNODE(db);
	err = dmu_write_uio_dnode(dn, uio, size, tx, flags);
	DB_DNODE_EXIT(db);
	return (err);
}
