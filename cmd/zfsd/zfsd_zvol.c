// SPDX-License-Identifier: CDDL-1.0
/*
 * zfsd zvol: ublk (or NBD fallback) block devices for DMU_OST_ZVOL
 * datasets. CUSE /dev/zfs lives in zfsd_ioctl.c; ZPL mounts in
 * zfsd_zpl.c.
 */

#define	FUSE_USE_VERSION	31
#ifndef _GNU_SOURCE
#define	_GNU_SOURCE
#endif
#include <sys/zfs_context.h>
#include <libzpool.h>
#include <sys/spa.h>
#include <sys/dmu.h>
#include <sys/dmu_objset.h>
#include <sys/dmu_tx.h>
#include <sys/dsl_pool.h>
#include <sys/dsl_prop.h>
#include <sys/txg.h>
#include <sys/zap.h>
#include <sys/nvpair.h>
#include <sys/fs/zfs.h>
#include <sys/zfs_ioctl.h>
#include <sys/zvol.h>
#include <sys/zil.h>
#include <sys/dnode.h>
#include <sys/zfs_rlock.h>
#include "zfsd_zvol.h"
#include "zfsd_impl.h"
#include "zfs_prop.h"
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#ifdef __linux__
#include <sys/mman.h>
#include <linux/io_uring.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <endian.h>
#include <linux/fs.h>
#include <mntent.h>
#include <time.h>
#ifndef SOCK_CLOEXEC
#define	SOCK_CLOEXEC	0
#endif
extern int umount2(const char *, int);
#endif

#ifdef __linux__
#ifndef	__NR_io_uring_setup
#if defined(__x86_64__) || defined(__i386__) || defined(__aarch64__) || \
    defined(__arm__) || defined(__riscv) || defined(__loongarch__)
#define	__NR_io_uring_setup	425
#define	__NR_io_uring_enter	426
#endif
#endif
#ifndef	IORING_OFF_SQ_RING
#define	IORING_OFF_SQ_RING	0ULL
#define	IORING_OFF_CQ_RING	0x8000000ULL
#define	IORING_OFF_SQES		0x10000000ULL
#endif
#ifndef	IORING_ENTER_GETEVENTS
#define	IORING_ENTER_GETEVENTS	(1U << 0)
#endif
#ifndef	IORING_SETUP_SQE128
#define	IORING_SETUP_SQE128	(1U << 10)
#endif
#ifndef	IORING_FEAT_SINGLE_MMAP
#define	IORING_FEAT_SINGLE_MMAP	(1U << 0)
#endif
/*
 * ublk ids are an idr with no compile-time cap. UBLK_MAX_UBLKS is
 * UBLK_MINORS (1<<MINORBITS). The ublks_max sysfs knob is the
 * unprivileged ceiling and does not apply to a privileged zfsd.
 */
#define	ZFSD_UBLK_ID_AUTO	((uint32_t)-1)
#define	ZFSD_UBLK_ID_CEILING	(1U << 20)
#ifndef	NBD_SET_SOCK
#define	NBD_SET_SOCK		_IO(0xab, 0)
#define	NBD_SET_BLKSIZE		_IO(0xab, 1)
#define	NBD_SET_SIZE		_IO(0xab, 2)
#define	NBD_DO_IT		_IO(0xab, 3)
#define	NBD_CLEAR_SOCK		_IO(0xab, 4)
#define	NBD_CLEAR_QUE		_IO(0xab, 5)
#define	NBD_SET_SIZE_BLOCKS	_IO(0xab, 7)
#define	NBD_DISCONNECT		_IO(0xab, 8)
#define	NBD_SET_TIMEOUT		_IO(0xab, 9)
#define	NBD_SET_FLAGS		_IO(0xab, 10)
#endif
#ifndef	NBD_FLAG_SEND_FLUSH
#define	NBD_FLAG_HAS_FLAGS	(1 << 0)
#define	NBD_FLAG_READ_ONLY	(1 << 1)
#define	NBD_FLAG_SEND_FLUSH	(1 << 2)
#define	NBD_FLAG_SEND_TRIM	(1 << 5)
#endif
#define	ZFSD_NBD_REQUEST_MAGIC	0x25609513u
#define	ZFSD_NBD_REPLY_MAGIC	0x67446698u
#define	ZFSD_NBD_CMD_READ	0
#define	ZFSD_NBD_CMD_WRITE	1
#define	ZFSD_NBD_CMD_DISC	2
#define	ZFSD_NBD_CMD_FLUSH	3
#define	ZFSD_NBD_CMD_TRIM	4
#define	ZFSD_NBD_FLAG_FUA	(1u << 16)
#define	ZFSD_NBD_MAXIO		(32u << 20)
/*
 * ublk UAPI (linux/ublk_cmd.h). Embedded so zfsd builds against
 * Debian 12 headers that may predate later ublk fields. SET_PARAMS
 * uses the 6.1-sized params prefix so a newer struct is not
 * rejected as too long.
 */
#define	UBLK_CMD_GET_DEV_INFO	0x02
#define	UBLK_CMD_ADD_DEV	0x04
#define	UBLK_CMD_DEL_DEV	0x05
#define	UBLK_CMD_START_DEV	0x06
#define	UBLK_CMD_STOP_DEV	0x07
#define	UBLK_CMD_SET_PARAMS	0x08
#define	UBLK_IO_FETCH_REQ	0x20
#define	UBLK_IO_COMMIT_AND_FETCH_REQ	0x21
#define	UBLK_IO_RES_OK		0
#define	UBLK_IO_RES_ABORT	(-ENODEV)
#define	UBLKSRV_CMD_BUF_OFFSET	0
#define	UBLK_F_CMD_IOCTL_ENCODE	(1ULL << 6)
#define	UBLK_IO_OP_READ		0
#define	UBLK_IO_OP_WRITE	1
#define	UBLK_IO_OP_FLUSH	2
#define	UBLK_IO_OP_DISCARD	3
#define	UBLK_IO_OP_WRITE_ZEROES	5
#define	UBLK_IO_F_FUA		(1U << 13)
#define	UBLK_ATTR_READ_ONLY	(1U << 0)
#define	UBLK_ATTR_VOLATILE_CACHE	(1U << 2)
#define	UBLK_ATTR_FUA		(1U << 3)
#define	UBLK_PARAM_TYPE_BASIC	(1U << 0)
#define	UBLK_PARAM_TYPE_DISCARD	(1U << 1)

struct ublksrv_ctrl_cmd {
	uint32_t	dev_id;
	uint16_t	queue_id;
	uint16_t	len;
	uint64_t	addr;
	uint64_t	data[1];
	uint16_t	dev_path_len;
	uint16_t	pad;
	uint32_t	reserved;
};

struct ublksrv_ctrl_dev_info {
	uint16_t	nr_hw_queues;
	uint16_t	queue_depth;
	uint16_t	state;
	uint16_t	io_desc_size;
	uint32_t	max_io_buf_bytes;
	uint32_t	dev_id;
	int32_t		ublksrv_pid;
	uint32_t	pad1;
	uint64_t	flags;
	uint64_t	ublksrv_flags;
	uint32_t	owner_uid;
	uint32_t	owner_gid;
	uint64_t	reserved1;
	uint64_t	reserved2;
};

struct ublksrv_io_desc {
	uint32_t	op_flags;
	uint32_t	nr_sectors;
	uint64_t	start_sector;
	uint64_t	addr;
};

struct ublksrv_io_cmd {
	uint16_t	q_id;
	uint16_t	tag;
	int32_t		result;
	uint64_t	addr;
};

struct ublk_param_basic {
	uint32_t	attrs;
	uint8_t		logical_bs_shift;
	uint8_t		physical_bs_shift;
	uint8_t		io_opt_shift;
	uint8_t		io_min_shift;
	uint32_t	max_sectors;
	uint32_t	chunk_sectors;
	uint64_t	dev_sectors;
	uint64_t	virt_boundary_mask;
};

struct ublk_param_discard {
	uint32_t	discard_alignment;
	uint32_t	discard_granularity;
	uint32_t	max_discard_sectors;
	uint32_t	max_write_zeroes_sectors;
	uint16_t	max_discard_segments;
	uint16_t	reserved0;
};

struct ublk_param_devt {
	uint32_t	char_major;
	uint32_t	char_minor;
	uint32_t	disk_major;
	uint32_t	disk_minor;
};

struct zfsd_ublk_params {
	uint32_t		len;
	uint32_t		types;
	struct ublk_param_basic	basic;
	struct ublk_param_discard discard;
	struct ublk_param_devt	devt;
};

/*
 * 6.1 ublk_params is header + basic + discard (no param_devt).
 * A longer SET_PARAMS buffer is EINVAL on that kernel.
 */
#define	ZFSD_UBLK_PARAMS_V1	\
	((uint32_t)offsetof(struct zfsd_ublk_params, devt))

#define	UBLK_U_CMD_GET_DEV_INFO	\
	_IOR('u', UBLK_CMD_GET_DEV_INFO, struct ublksrv_ctrl_cmd)
#define	UBLK_U_CMD_ADD_DEV	\
	_IOWR('u', UBLK_CMD_ADD_DEV, struct ublksrv_ctrl_cmd)
#define	UBLK_U_CMD_DEL_DEV	\
	_IOWR('u', UBLK_CMD_DEL_DEV, struct ublksrv_ctrl_cmd)
#define	UBLK_U_CMD_START_DEV	\
	_IOWR('u', UBLK_CMD_START_DEV, struct ublksrv_ctrl_cmd)
#define	UBLK_U_CMD_STOP_DEV	\
	_IOWR('u', UBLK_CMD_STOP_DEV, struct ublksrv_ctrl_cmd)
#define	UBLK_U_CMD_SET_PARAMS	\
	_IOWR('u', UBLK_CMD_SET_PARAMS, struct ublksrv_ctrl_cmd)
#define	UBLK_U_IO_FETCH_REQ	\
	_IOWR('u', UBLK_IO_FETCH_REQ, struct ublksrv_io_cmd)
#define	UBLK_U_IO_COMMIT_AND_FETCH_REQ	\
	_IOWR('u', UBLK_IO_COMMIT_AND_FETCH_REQ, struct ublksrv_io_cmd)
#endif /* ublk UAPI */


/* ---- /dev/zvol as ublk block devices ----
 *
 * /dev/zfs stays CUSE. Zvols do not: Linux cuse_read_iter and
 * cuse_write_iter force pos = 0 and llseek is noop_llseek, so
 * pwrite/mke2fs always hit byte 0. That is the CUSE frontend, not
 * a character-device rule -- /dev/mem seeks; CUSE never will.
 * People write CUSE nodes as streams or via ioctl (the libfuse
 * example's FIOC_READ/WRITE). A zvol is a disk.
 *
 * ublk is the character-device path that still seeks. The daemon
 * talks to /dev/ublkcN (S_ISCHR, io_uring, start_sector in the
 * iod). Tools open /dev/ublkbN (S_ISBLK); the block layer supplies
 * seek, BLKGETSIZE64, HDIO_GETGEO. /dev/zvol/pool/vol is the usual
 * symlink. Not a FUSE file. Requires ublk_drv.
 */

typedef struct zfsd_uring {
	int		fd;
	unsigned	sqe_size;
	unsigned	sq_entries;
	unsigned	sq_mask;
	unsigned	cq_mask;
	unsigned	pending;
	unsigned	*sq_head;
	unsigned	*sq_tail;
	unsigned	*sq_array;
	unsigned	*cq_head;
	unsigned	*cq_tail;
	void		*sqes;
	void		*cqes;
	void		*sq_ring;
	void		*cq_ring;
	size_t		sq_ring_sz;
	size_t		cq_ring_sz;
	size_t		sqes_sz;
} zfsd_uring_t;

typedef struct zfsd_zvol {
	char			ds[ZFS_MAX_DATASET_NAME_LEN];
	char			devname[32];		/* ublkbN or nbdN */
	char			devpath[64];		/* /dev/ublkbN or /dev/nbdN */
	char			linkpath[MAXPATHLEN];	/* /dev/zvol/ds */
	int			ublk_id;
	int			ublkc_fd;
	int			ioctl_enc;
	uint32_t		qdepth;
	uint32_t		max_io;
	void			*iod_map;
	size_t			iod_map_sz;
	void			**io_bufs;
	zfsd_uring_t		ring;
	int			nbd_fd;
	int			nbd_sock;
	pthread_t		serve_tid;
	pthread_t		doit_tid;
	int			running;
	int			dying;
	int			fetches_armed;
	int			prop_ro;	/* snapshot or ZFS readonly */
	int			dev_ro;
	pthread_rwlock_t	io;
	pthread_mutex_t		os_mx;
	pthread_cond_t		os_cv;
	int			os_holds;	/* -1: last rele is closing */
	objset_t		*os;
	dnode_t			*dn;
	zilog_t			*zilog;
	zil_sums_t		zil_sums;
	zfs_rangelock_t		rlock;
	uint64_t		volsize;
	uint64_t		volblocksize;
	struct zfsd_zvol	*next;
} zfsd_zvol_t;

static pthread_mutex_t g_zvol_lock = PTHREAD_MUTEX_INITIALIZER;
static zfsd_zvol_t *g_zvols;
static int zvol_thread_create(pthread_t *, void *(*)(void *), void *);
static void zvol_teardown(zfsd_zvol_t *zv);
static int zvol_dmu_write_copy(zfsd_zvol_t *, uint64_t, uint64_t,
    const void *, dmu_tx_t *);
#ifdef __linux__
static int g_ublk_ctrl_fd = -1;
static pthread_mutex_t g_ublk_ctrl_mx = PTHREAD_MUTEX_INITIALIZER;
static zfsd_uring_t g_ublk_ctrl_ring;
static int g_ublk_ctrl_ready;
static int g_ublk_enc = -1;	/* -1 unknown, 0 legacy, 1 ioctl encode */
static uint32_t g_ublk_id_next;
static uint32_t g_ublk_id_max;	/* 0 = not yet discovered */
#endif

static int
zvol_ds_prefix(const char *ds, const char *prefix)
{
	size_t n;

	if (ds == NULL || prefix == NULL || prefix[0] == '\0')
		return (1);
	n = strlen(prefix);
	if (strcmp(ds, prefix) == 0)
		return (1);
	return (strncmp(ds, prefix, n) == 0 &&
	    (ds[n] == '/' || ds[n] == '@'));
}

static int
zvol_ro(zfsd_zvol_t *zv)
{
	return (zv->prop_ro || zv->dev_ro);
}

static void
zvol_prepare_root(void)
{
	struct stat st;

	if (lstat("/dev/zvol", &st) == 0 && !S_ISDIR(st.st_mode))
		(void) unlink("/dev/zvol");
	(void) mkdir("/dev/zvol", 0755);
}

static int
zvol_zil_get_data(void *arg, uint64_t arg2, lr_write_t *lr, char *buf,
    struct lwb *lwb, zio_t *zio)
{
	zfsd_zvol_t *zv = arg;
	zfs_locked_range_t *rl;
	uint64_t off, size;
	int err;

	(void) arg2;
	(void) lwb;
	(void) zio;
	/*
	 * zl_get_data runs on ZIL/zio threads, not under zvol_dmu_write.
	 * Take the same I/O lock the writers use so a concurrent write
	 * cannot tear the range we copy into the log.
	 */
	if (zv == NULL)
		return (EIO);
	pthread_rwlock_rdlock(&zv->io);
	if (zv->os == NULL || buf == NULL) {
		pthread_rwlock_unlock(&zv->io);
		return (EIO);
	}
	off = lr->lr_offset;
	size = lr->lr_length;
	rl = zfs_rangelock_enter(&zv->rlock, off, size, RL_READER);
	if (zv->dn != NULL)
		err = dmu_read_by_dnode(zv->dn, off, size, buf,
		    DMU_READ_NO_PREFETCH);
	else
		err = dmu_read(zv->os, ZVOL_OBJ, off, size, buf,
		    DMU_READ_NO_PREFETCH);
	zfs_rangelock_exit(rl);
	pthread_rwlock_unlock(&zv->io);
	return (err);
}

static int
zvol_need_commit(zfsd_zvol_t *zv, int fua)
{
	return (fua || (zv->os != NULL &&
	    zv->os->os_sync == ZFS_SYNC_ALWAYS));
}

static void
zvol_log_write(zfsd_zvol_t *zv, dmu_tx_t *tx, uint64_t off, uint64_t len,
    const void *buf, int sync)
{
	itx_t *itx;
	lr_write_t *lr;
	itx_wr_state_t st;

	if (zv == NULL || zv->zilog == NULL || zil_replaying(zv->zilog, tx))
		return;
	if (len > zil_max_copied_data(zv->zilog))
		st = WR_NEED_COPY;
	else
		st = WR_COPIED;
	itx = zil_itx_create(TX_WRITE,
	    sizeof (*lr) + (st == WR_COPIED ? (size_t)len : 0));
	lr = (lr_write_t *)&itx->itx_lr;
	lr->lr_foid = ZVOL_OBJ;
	lr->lr_offset = off;
	lr->lr_length = len;
	lr->lr_flags = 0;
	memset(&lr->lr_blkptr, 0, sizeof (lr->lr_blkptr));
	if (st == WR_COPIED && buf != NULL)
		memcpy(lr + 1, buf, (size_t)len);
	itx->itx_wr_state = st;
	itx->itx_sync = sync ? B_TRUE : B_FALSE;
	itx->itx_private = zv;
	zil_itx_assign(zv->zilog, itx, tx);
	dsl_pool_wrlog_count(dmu_objset_pool(zv->os),
	    (int64_t)itx->itx_size + (st == WR_NEED_COPY ? (int64_t)len : 0),
	    dmu_tx_get_txg(tx));
}

static void
zvol_log_truncate(zfsd_zvol_t *zv, dmu_tx_t *tx, uint64_t off, uint64_t len)
{
	itx_t *itx;
	lr_truncate_t *lr;

	if (zv == NULL || zv->zilog == NULL || zil_replaying(zv->zilog, tx))
		return;
	itx = zil_itx_create(TX_TRUNCATE, sizeof (*lr));
	lr = (lr_truncate_t *)&itx->itx_lr;
	lr->lr_foid = ZVOL_OBJ;
	lr->lr_offset = off;
	lr->lr_length = len;
	zil_itx_assign(zv->zilog, itx, tx);
}

static int
zvol_replay_err(void *arg1, void *arg2, boolean_t byteswap)
{
	(void) arg1, (void) arg2, (void) byteswap;
	return (SET_ERROR(ENOTSUP));
}

static int
zvol_replay_truncate(void *arg1, void *arg2, boolean_t byteswap)
{
	zfsd_zvol_t *zv = arg1;
	lr_truncate_t *lr = arg2;
	dmu_tx_t *tx;
	int error;

	if (byteswap)
		byteswap_uint64_array(lr, sizeof (*lr));
	tx = dmu_tx_create(zv->os);
	dmu_tx_mark_netfree(tx);
	error = dmu_tx_assign(tx, DMU_TX_WAIT);
	if (error != 0) {
		dmu_tx_abort(tx);
	} else {
		(void) zil_replaying(zv->zilog, tx);
		dmu_tx_commit(tx);
		error = dmu_free_long_range(zv->os, ZVOL_OBJ,
		    lr->lr_offset, lr->lr_length);
	}
	return (error);
}

static int
zvol_replay_write(void *arg1, void *arg2, boolean_t byteswap)
{
	zfsd_zvol_t *zv = arg1;
	lr_write_t *lr = arg2;
	char *data = (char *)(lr + 1);
	uint64_t offset, length;
	dmu_tx_t *tx;
	int error;

	if (byteswap)
		byteswap_uint64_array(lr, sizeof (*lr));
	offset = lr->lr_offset;
	length = lr->lr_length;
	if (lr->lr_common.lrc_reclen == sizeof (lr_write_t)) {
		uint64_t blocksize = BP_GET_LSIZE(&lr->lr_blkptr);
		if (length < blocksize) {
			offset -= offset % blocksize;
			length = blocksize;
		}
	}
	tx = dmu_tx_create(zv->os);
	if (zv->dn != NULL)
		dmu_tx_hold_write_by_dnode(tx, zv->dn, offset, length);
	else
		dmu_tx_hold_write(tx, ZVOL_OBJ, offset, length);
	error = dmu_tx_assign(tx, DMU_TX_WAIT);
	if (error != 0) {
		dmu_tx_abort(tx);
	} else {
		error = zvol_dmu_write_copy(zv, offset, length, data, tx);
		(void) zil_replaying(zv->zilog, tx);
		dmu_tx_commit(tx);
	}
	return (error);
}

static zil_replay_func_t *const zvol_replay_vector[TX_MAX_TYPE] = {
	zvol_replay_err,
	zvol_replay_err,
	zvol_replay_err,
	zvol_replay_err,
	zvol_replay_err,
	zvol_replay_err,
	zvol_replay_err,
	zvol_replay_err,
	zvol_replay_err,
	zvol_replay_write,
	zvol_replay_truncate,
	zvol_replay_err,
	zvol_replay_err,
	zvol_replay_err,
	zvol_replay_err,
	zvol_replay_err,
	zvol_replay_err,
	zvol_replay_err,
	zvol_replay_err,
	zvol_replay_err,
	zvol_replay_err,
	zvol_replay_err,
	zvol_replay_err,
	zvol_replay_err,
	zvol_replay_err,
};

/*
 * Kernel zvol owns the objset from first open until last close
 * (zvol_first_open / zvol_last_close). Per-bio open/close is not
 * that. zil_close() VERIFYs !zilog_is_dirty after it commits. A
 * write's async itx stays on dp_dirty_zilogs until that txg syncs,
 * and the write thread does not hold os_mx across zil_itx_assign, so
 * a concurrent read can drop the last per-bio hold and close the log
 * while it is still dirty. alloc_class_013 hit that on zfsd-nbd-srv
 * (2G zvol, mke2fs) and the watchdog then failed 014-018 in 0s.
 *
 * The NBD/ublk serve thread is the open. One hold spans that thread;
 * per-bio hold/rele only nest. zil_close runs when the thread exits,
 * after I/O has stopped. os_holds == -1 means that close is in
 * progress and the objset pointers have already been taken. The
 * close itself runs without os_mx: zil_close txg_waits, and teardown
 * also needs os_mx. Holding the mutex across the wait pinned
 * spa_zvol_taskq, so zpool destroy's ioctl never returned and every
 * later ZTS command sat in FUSE until the runner killed it.
 * zfs destroy drops this hold first (zfsd_zvol_release_idle);
 * otherwise dsl_destroy_*_check returns EBUSY forever, because the
 * minor used to be removed only after the check passed.
 */
static int
zvol_os_hold(zfsd_zvol_t *zv)
{
	objset_t *os;
	int err, ro;

	if (zv == NULL || zv->dying)
		return (EIO);
	pthread_mutex_lock(&zv->os_mx);
	while (zv->os_holds < 0) {
		if (zv->dying) {
			pthread_mutex_unlock(&zv->os_mx);
			return (EIO);
		}
		(void) pthread_cond_wait(&zv->os_cv, &zv->os_mx);
	}
	if (zv->dying) {
		pthread_mutex_unlock(&zv->os_mx);
		return (EIO);
	}
	if (zv->os_holds > 0) {
		zv->os_holds++;
		pthread_mutex_unlock(&zv->os_mx);
		return (0);
	}
	ro = zv->prop_ro || zv->dev_ro;
	err = dmu_objset_own(zv->ds, DMU_OST_ZVOL, ro ? B_TRUE : B_FALSE,
	    B_TRUE, zv, &os);
	if (err != 0) {
		pthread_mutex_unlock(&zv->os_mx);
		return (err);
	}
	zv->os = os;
	zv->dn = NULL;
	err = dnode_hold(os, ZVOL_OBJ, zv, &zv->dn);
	if (err != 0) {
		dmu_objset_disown(os, B_TRUE, zv);
		zv->os = NULL;
		pthread_mutex_unlock(&zv->os_mx);
		return (err);
	}
	zil_sums_init(&zv->zil_sums);
	zv->zilog = zil_open(os, zvol_zil_get_data, &zv->zil_sums);
	zv->os_holds = 1;
	pthread_mutex_unlock(&zv->os_mx);
	return (0);
}

static void
zvol_os_rele(zfsd_zvol_t *zv)
{
	objset_t *os;
	dnode_t *dn;
	zilog_t *zilog;

	if (zv == NULL)
		return;
	pthread_mutex_lock(&zv->os_mx);
	/*
	 * 0: nothing owned. -1: another thread is already in zil_close
	 * with the pointers. Teardown may steal a leaked serve hold by
	 * setting os_holds to 1 and calling here; the serve thread then
	 * observes <= 0 and must not close twice.
	 */
	if (zv->os_holds <= 0) {
		pthread_mutex_unlock(&zv->os_mx);
		return;
	}
	if (--zv->os_holds > 0) {
		pthread_mutex_unlock(&zv->os_mx);
		return;
	}
	zv->os_holds = -1;
	zilog = zv->zilog;
	zv->zilog = NULL;
	dn = zv->dn;
	zv->dn = NULL;
	os = zv->os;
	zv->os = NULL;
	pthread_mutex_unlock(&zv->os_mx);

	if (zilog != NULL) {
		zil_close(zilog);
		zil_sums_fini(&zv->zil_sums);
	}
	if (dn != NULL)
		dnode_rele(dn, zv);
	if (os != NULL)
		dmu_objset_disown(os, B_TRUE, zv);

	pthread_mutex_lock(&zv->os_mx);
	zv->os_holds = 0;
	(void) pthread_cond_broadcast(&zv->os_cv);
	pthread_mutex_unlock(&zv->os_mx);
}

/*
 * dmu_write() VERIFY0s dmu_buf_hold_array. A failed hold (ENOMEM
 * under overcommit=2, EIO on a sparse zvol, ...) abort()s the
 * daemon and takes /dev/zfs with it. alloc_class_013 died that
 * way in ~1.6s of mke2fs. Hold with the error-returning API.
 */
static int
zvol_dmu_write_copy(zfsd_zvol_t *zv, uint64_t off, uint64_t len,
    const void *buf, dmu_tx_t *tx)
{
	dmu_buf_t **dbp = NULL;
	int n = 0, i, err;

	if (len == 0)
		return (0);
	if (zv->dn != NULL)
		err = dmu_buf_hold_array_by_dnode(zv->dn, off, len, B_FALSE,
		    FTAG, &n, &dbp, DMU_READ_PREFETCH);
	else
		err = dmu_buf_hold_array(zv->os, ZVOL_OBJ, off, len, FALSE,
		    FTAG, &n, &dbp, DMU_READ_PREFETCH);
	if (err != 0)
		return (err);
	for (i = 0; i < n; i++) {
		dmu_buf_t *db = dbp[i];
		int64_t bufoff;
		uint64_t tocpy;

		bufoff = (int64_t)(off - db->db_offset);
		if (bufoff < 0 || (uint64_t)bufoff >= db->db_size) {
			dmu_buf_rele_array(dbp, n, FTAG);
			return (EIO);
		}
		tocpy = MIN(db->db_size - (uint64_t)bufoff, len);
		dmu_buf_will_dirty(db, tx);
		if (db->db_data == NULL) {
			dmu_buf_rele_array(dbp, n, FTAG);
			return (EIO);
		}
		(void) memcpy((char *)db->db_data + bufoff, buf, (size_t)tocpy);
		off += tocpy;
		len -= tocpy;
		buf = (const char *)buf + tocpy;
	}
	dmu_buf_rele_array(dbp, n, FTAG);
	return (len == 0 ? 0 : EIO);
}

static int
zvol_dmu_read(zfsd_zvol_t *zv, uint64_t off, uint32_t len, void *buf)
{
	uint64_t volsize;
	zfs_locked_range_t *rl;
	int err;

	if (zv == NULL || zv->dying)
		return (EIO);
	err = zvol_os_hold(zv);
	if (err != 0)
		return (err);
	pthread_rwlock_rdlock(&zv->io);
	if (zv->dying || zv->os == NULL) {
		pthread_rwlock_unlock(&zv->io);
		zvol_os_rele(zv);
		return (EIO);
	}
	volsize = zv->volsize;
	if (off >= volsize || (uint64_t)len > volsize - off) {
		pthread_rwlock_unlock(&zv->io);
		zvol_os_rele(zv);
		return (EINVAL);
	}
	rl = zfs_rangelock_enter(&zv->rlock, off, len, RL_READER);
	if (zv->dn != NULL)
		err = dmu_read_by_dnode(zv->dn, off, len, buf, 0);
	else
		err = dmu_read(zv->os, ZVOL_OBJ, off, len, buf, 0);
	zfs_rangelock_exit(rl);
	pthread_rwlock_unlock(&zv->io);
	zvol_os_rele(zv);
	return (err);
}

static int
zvol_dmu_write(zfsd_zvol_t *zv, uint64_t off, uint32_t len, const void *buf,
    int fua)
{
	uint64_t volsize, resid, woff;
	const char *wbuf;
	zfs_locked_range_t *rl;
	int err, sync;

	if (zv == NULL || zv->dying)
		return (EIO);
	if (len > 0 && buf == NULL)
		return (EIO);
	err = zvol_os_hold(zv);
	if (err != 0)
		return (err);
	/*
	 * Kernel zvol_write takes zv_suspend_lock as RW_READER. A
	 * wrlock here deadlocks ZIL get_data (also a reader) when
	 * dmu_tx_assign waits for a txg that needs zvol_zil_get_data.
	 */
	pthread_rwlock_rdlock(&zv->io);
	if (zv->dying || zv->os == NULL) {
		pthread_rwlock_unlock(&zv->io);
		zvol_os_rele(zv);
		return (EIO);
	}
	if (zvol_ro(zv)) {
		pthread_rwlock_unlock(&zv->io);
		zvol_os_rele(zv);
		return (EROFS);
	}
	volsize = zv->volsize;
	if (off >= volsize || (uint64_t)len > volsize - off) {
		pthread_rwlock_unlock(&zv->io);
		zvol_os_rele(zv);
		return (EINVAL);
	}
	sync = zvol_need_commit(zv, fua);
	rl = zfs_rangelock_enter(&zv->rlock, off, len, RL_WRITER);
	resid = len;
	woff = off;
	wbuf = buf;
	while (resid > 0 && woff < volsize) {
		uint64_t bytes = MIN(resid, DMU_MAX_ACCESS >> 1);
		dmu_tx_t *tx;

		if (bytes > volsize - woff)
			bytes = volsize - woff;
		tx = dmu_tx_create(zv->os);
		if (zv->dn != NULL)
			dmu_tx_hold_write_by_dnode(tx, zv->dn, woff,
			    (int)bytes);
		else
			dmu_tx_hold_write(tx, ZVOL_OBJ, woff, (int)bytes);
		err = dmu_tx_assign(tx, DMU_TX_WAIT);
		if (err != 0) {
			dmu_tx_abort(tx);
			break;
		}
		err = zvol_dmu_write_copy(zv, woff, bytes, wbuf, tx);
		if (err == 0)
			zvol_log_write(zv, tx, woff, bytes, wbuf, sync);
		dmu_tx_commit(tx);
		if (err != 0)
			break;
		woff += bytes;
		wbuf += bytes;
		resid -= bytes;
	}
	zfs_rangelock_exit(rl);
	pthread_rwlock_unlock(&zv->io);
	if (err == 0 && sync && zv->zilog != NULL)
		err = zil_commit(zv->zilog, ZVOL_OBJ);
	zvol_os_rele(zv);
	return (err);
}

static int
zvol_dmu_flush(zfsd_zvol_t *zv)
{
	zilog_t *zilog;
	objset_t *os;
	int err = 0;

	if (zv == NULL || zv->dying)
		return (EIO);
	err = zvol_os_hold(zv);
	if (err != 0)
		return (err);
	pthread_rwlock_rdlock(&zv->io);
	if (zv->dying) {
		pthread_rwlock_unlock(&zv->io);
		zvol_os_rele(zv);
		return (EIO);
	}
	zilog = zv->zilog;
	os = zv->os;
	pthread_rwlock_unlock(&zv->io);
	if (zilog != NULL)
		err = zil_commit(zilog, ZVOL_OBJ);
	else if (os != NULL)
		txg_wait_synced(dmu_objset_pool(os), 0);
	zvol_os_rele(zv);
	return (err);
}

static int
zvol_dmu_trim(zfsd_zvol_t *zv, uint64_t off, uint64_t len, int fua)
{
	uint64_t volsize, start, end, bs;
	dmu_tx_t *tx;
	int err, sync;

	if (zv == NULL || zv->dying)
		return (EIO);
	err = zvol_os_hold(zv);
	if (err != 0)
		return (err);
	pthread_rwlock_rdlock(&zv->io);
	if (zv->dying || zv->os == NULL) {
		pthread_rwlock_unlock(&zv->io);
		zvol_os_rele(zv);
		return (EIO);
	}
	if (zvol_ro(zv)) {
		pthread_rwlock_unlock(&zv->io);
		zvol_os_rele(zv);
		return (EROFS);
	}
	volsize = zv->volsize;
	if (off >= volsize) {
		pthread_rwlock_unlock(&zv->io);
		zvol_os_rele(zv);
		return (EINVAL);
	}
	if (len > volsize - off)
		len = volsize - off;
	bs = zv->volblocksize != 0 ? zv->volblocksize : 512;
	start = P2ROUNDUP(off, bs);
	end = P2ALIGN_TYPED(off + len, bs, uint64_t);
	if (end <= start) {
		pthread_rwlock_unlock(&zv->io);
		zvol_os_rele(zv);
		return (0);
	}
	sync = zvol_need_commit(zv, fua);
	tx = dmu_tx_create(zv->os);
	dmu_tx_mark_netfree(tx);
	err = dmu_tx_assign(tx, DMU_TX_WAIT);
	if (err != 0) {
		dmu_tx_abort(tx);
		pthread_rwlock_unlock(&zv->io);
		zvol_os_rele(zv);
		return (err);
	}
	zvol_log_truncate(zv, tx, start, end - start);
	dmu_tx_commit(tx);
	err = dmu_free_long_range(zv->os, ZVOL_OBJ, start, end - start);
	pthread_rwlock_unlock(&zv->io);
	if (err == 0 && sync && zv->zilog != NULL)
		err = zil_commit(zv->zilog, ZVOL_OBJ);
	zvol_os_rele(zv);
	return (err);
}

/*
 * WRITE_ZEROES must actually zero. DISCARD may punch whole volblocks
 * only; zeroes have to fill partial head/tail blocks as well.
 */
static int
zvol_dmu_zero(zfsd_zvol_t *zv, uint64_t off, uint64_t len, int fua)
{
	uint64_t volsize, bs;
	int err = 0, sync;

	if (zv == NULL || zv->dying)
		return (EIO);
	err = zvol_os_hold(zv);
	if (err != 0)
		return (err);
	pthread_rwlock_rdlock(&zv->io);
	if (zv->dying || zv->os == NULL) {
		pthread_rwlock_unlock(&zv->io);
		zvol_os_rele(zv);
		return (EIO);
	}
	if (zvol_ro(zv)) {
		pthread_rwlock_unlock(&zv->io);
		zvol_os_rele(zv);
		return (EROFS);
	}
	volsize = zv->volsize;
	if (off >= volsize) {
		pthread_rwlock_unlock(&zv->io);
		zvol_os_rele(zv);
		return (EINVAL);
	}
	if (len > volsize - off)
		len = volsize - off;
	bs = zv->volblocksize != 0 ? zv->volblocksize : 512;
	sync = zvol_need_commit(zv, fua);

	while (len > 0 && err == 0) {
		uint64_t chunk, phase;
		void *zbuf;
		dmu_tx_t *tx;

		phase = off & (bs - 1);
		if (phase != 0)
			chunk = MIN(len, bs - phase);
		else if (len < bs)
			chunk = len;
		else {
			chunk = P2ALIGN_TYPED(len, bs, uint64_t);
			tx = dmu_tx_create(zv->os);
			dmu_tx_mark_netfree(tx);
			err = dmu_tx_assign(tx, DMU_TX_WAIT);
			if (err != 0) {
				dmu_tx_abort(tx);
				break;
			}
			zvol_log_truncate(zv, tx, off, chunk);
			dmu_tx_commit(tx);
			err = dmu_free_long_range(zv->os, ZVOL_OBJ, off,
			    chunk);
			off += chunk;
			len -= chunk;
			continue;
		}
		zbuf = kmem_zalloc((size_t)chunk, KM_SLEEP);
		tx = dmu_tx_create(zv->os);
		if (zv->dn != NULL)
			dmu_tx_hold_write_by_dnode(tx, zv->dn, off, chunk);
		else
			dmu_tx_hold_write(tx, ZVOL_OBJ, off, chunk);
		err = dmu_tx_assign(tx, DMU_TX_WAIT);
		if (err != 0) {
			dmu_tx_abort(tx);
			kmem_free(zbuf, (size_t)chunk);
			break;
		}
		err = zvol_dmu_write_copy(zv, off, chunk, zbuf, tx);
		if (err == 0)
			zvol_log_write(zv, tx, off, chunk, zbuf, sync);
		dmu_tx_commit(tx);
		kmem_free(zbuf, (size_t)chunk);
		off += chunk;
		len -= chunk;
	}
	pthread_rwlock_unlock(&zv->io);
	if (err == 0 && sync && zv->zilog != NULL)
		err = zil_commit(zv->zilog, ZVOL_OBJ);
	zvol_os_rele(zv);
	return (err);
}

#ifdef __linux__
static void
zvol_uring_exit(zfsd_uring_t *r)
{
	if (r == NULL || r->fd < 0)
		return;
	if (r->sqes != NULL && r->sqes != MAP_FAILED)
		(void) munmap(r->sqes, r->sqes_sz);
	if (r->sq_ring != NULL && r->sq_ring != MAP_FAILED)
		(void) munmap(r->sq_ring, r->sq_ring_sz);
	if (r->cq_ring != NULL && r->cq_ring != MAP_FAILED &&
	    r->cq_ring != r->sq_ring)
		(void) munmap(r->cq_ring, r->cq_ring_sz);
	(void) close(r->fd);
	memset(r, 0, sizeof (*r));
	r->fd = -1;
}

static int
zvol_uring_setup(zfsd_uring_t *r, unsigned entries, int sqe128)
{
	struct io_uring_params p;
	size_t sq_sz, cq_sz;
	unsigned i;
	void *sq, *cq, *sqes;
	int fd;

	memset(r, 0, sizeof (*r));
	r->fd = -1;
	memset(&p, 0, sizeof (p));
	if (sqe128)
		p.flags |= IORING_SETUP_SQE128;
	fd = (int)syscall(__NR_io_uring_setup, entries, &p);
	if (fd < 0)
		return (-1);
	r->fd = fd;
	r->sqe_size = sqe128 ? 128 : 64;
	r->sq_entries = p.sq_entries;
	sq_sz = p.sq_off.array + p.sq_entries * sizeof (unsigned);
	cq_sz = p.cq_off.cqes + p.cq_entries * sizeof (struct io_uring_cqe);
	if (p.features & IORING_FEAT_SINGLE_MMAP) {
		size_t n = sq_sz > cq_sz ? sq_sz : cq_sz;
		sq = mmap(NULL, n, PROT_READ | PROT_WRITE,
		    MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQ_RING);
		if (sq == MAP_FAILED) {
			zvol_uring_exit(r);
			return (-1);
		}
		cq = sq;
		r->sq_ring = sq;
		r->cq_ring = NULL;
		r->sq_ring_sz = n;
		r->cq_ring_sz = 0;
	} else {
		sq = mmap(NULL, sq_sz, PROT_READ | PROT_WRITE,
		    MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQ_RING);
		cq = mmap(NULL, cq_sz, PROT_READ | PROT_WRITE,
		    MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_CQ_RING);
		if (sq == MAP_FAILED || cq == MAP_FAILED) {
			if (sq != MAP_FAILED)
				(void) munmap(sq, sq_sz);
			if (cq != MAP_FAILED)
				(void) munmap(cq, cq_sz);
			zvol_uring_exit(r);
			return (-1);
		}
		r->sq_ring = sq;
		r->cq_ring = cq;
		r->sq_ring_sz = sq_sz;
		r->cq_ring_sz = cq_sz;
	}
	r->sqes_sz = (size_t)p.sq_entries * r->sqe_size;
	sqes = mmap(NULL, r->sqes_sz, PROT_READ | PROT_WRITE,
	    MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQES);
	if (sqes == MAP_FAILED) {
		zvol_uring_exit(r);
		return (-1);
	}
	r->sqes = sqes;
	r->sq_head = (unsigned *)((char *)sq + p.sq_off.head);
	r->sq_tail = (unsigned *)((char *)sq + p.sq_off.tail);
	r->sq_array = (unsigned *)((char *)sq + p.sq_off.array);
	r->sq_mask = *(unsigned *)((char *)sq + p.sq_off.ring_mask);
	r->cq_head = (unsigned *)((char *)cq + p.cq_off.head);
	r->cq_tail = (unsigned *)((char *)cq + p.cq_off.tail);
	r->cq_mask = *(unsigned *)((char *)cq + p.cq_off.ring_mask);
	r->cqes = (char *)cq + p.cq_off.cqes;
	for (i = 0; i < p.sq_entries; i++)
		r->sq_array[i] = i;
	return (0);
}

static void *
zvol_uring_get_sqe(zfsd_uring_t *r)
{
	unsigned tail, head, idx;

	tail = __atomic_load_n(r->sq_tail, __ATOMIC_RELAXED);
	head = __atomic_load_n(r->sq_head, __ATOMIC_ACQUIRE);
	if (tail - head >= r->sq_entries)
		return (NULL);
	idx = tail & r->sq_mask;
	r->sq_array[idx] = idx;
	return ((char *)r->sqes + (size_t)idx * r->sqe_size);
}

static void
zvol_uring_push(zfsd_uring_t *r)
{
	unsigned tail;

	tail = __atomic_load_n(r->sq_tail, __ATOMIC_RELAXED);
	__atomic_store_n(r->sq_tail, tail + 1, __ATOMIC_RELEASE);
	r->pending++;
}

static int
zvol_uring_enter(zfsd_uring_t *r, unsigned min_complete)
{
	int ret;
	unsigned to_submit = r->pending;

	do {
		ret = (int)syscall(__NR_io_uring_enter, r->fd, to_submit,
		    min_complete, IORING_ENTER_GETEVENTS, NULL, 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0)
		return (-1);
	r->pending = 0;
	return (ret);
}

static struct io_uring_cqe *
zvol_uring_cqe_peek(zfsd_uring_t *r)
{
	unsigned head, tail;

	head = __atomic_load_n(r->cq_head, __ATOMIC_ACQUIRE);
	tail = __atomic_load_n(r->cq_tail, __ATOMIC_ACQUIRE);
	if (head == tail)
		return (NULL);
	return ((struct io_uring_cqe *)((char *)r->cqes +
	    (size_t)(head & r->cq_mask) * sizeof (struct io_uring_cqe)));
}

static void
zvol_uring_cqe_advance(zfsd_uring_t *r)
{
	unsigned head;

	head = __atomic_load_n(r->cq_head, __ATOMIC_RELAXED);
	__atomic_store_n(r->cq_head, head + 1, __ATOMIC_RELEASE);
}

static int
zvol_ublk_ctrl_open(void)
{
	if (g_ublk_ctrl_ready)
		return (0);
	g_ublk_ctrl_fd = open("/dev/ublk-control", O_RDWR | O_CLOEXEC);
	if (g_ublk_ctrl_fd < 0)
		return (-1);
	/*
	 * SQE128 exists from 6.7 and holds a full ublksrv_ctrl_cmd.
	 * Debian 12 is 6.1: 64-byte SQEs, 16-byte cmd overlay, data[0]
	 * sits in the 8 bytes the 6.1 driver reads past the SQE.
	 */
	if (zvol_uring_setup(&g_ublk_ctrl_ring, 4, 1) != 0 &&
	    zvol_uring_setup(&g_ublk_ctrl_ring, 4, 0) != 0) {
		(void) close(g_ublk_ctrl_fd);
		g_ublk_ctrl_fd = -1;
		return (-1);
	}
	g_ublk_ctrl_ready = 1;
	return (0);
}

void
zfsd_zvol_ctrl_fini(void)
{
	pthread_mutex_lock(&g_ublk_ctrl_mx);
	if (g_ublk_ctrl_ready) {
		zvol_uring_exit(&g_ublk_ctrl_ring);
		if (g_ublk_ctrl_fd >= 0)
			(void) close(g_ublk_ctrl_fd);
		g_ublk_ctrl_fd = -1;
		g_ublk_ctrl_ready = 0;
		g_ublk_enc = -1;
		g_ublk_id_next = 0;
		g_ublk_id_max = 0;
	}
	pthread_mutex_unlock(&g_ublk_ctrl_mx);
}

static int
zvol_ublk_ctrl_once(uint32_t cmd_op, uint32_t dev_id, void *buf, uint16_t len,
    uint64_t data0)
{
	struct ublksrv_ctrl_cmd cmd;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	int res;

	memset(&cmd, 0, sizeof (cmd));
	cmd.dev_id = dev_id;
	cmd.queue_id = (uint16_t)-1;
	cmd.len = len;
	cmd.addr = (uint64_t)(uintptr_t)buf;
	cmd.data[0] = data0;
	sqe = zvol_uring_get_sqe(&g_ublk_ctrl_ring);
	if (sqe == NULL)
		return (-EAGAIN);
	memset(sqe, 0, g_ublk_ctrl_ring.sqe_size);
	sqe->opcode = IORING_OP_URING_CMD;
	sqe->fd = g_ublk_ctrl_fd;
	sqe->cmd_op = cmd_op;
	sqe->user_data = 1;
	{
		size_t ncopy;

		/*
		 * 128-byte SQE: the whole ctrl cmd. 64-byte SQE: 16-byte
		 * overlay plus 8-byte data[0] the 6.1 driver over-reads
		 * from the next SQE (we submit one ctrl command at a time).
		 */
		ncopy = (g_ublk_ctrl_ring.sqe_size >= 128) ?
		    sizeof (cmd) : offsetof(struct ublksrv_ctrl_cmd,
		    dev_path_len);
		if (ncopy > g_ublk_ctrl_ring.sqe_size)
			ncopy = g_ublk_ctrl_ring.sqe_size;
		memcpy(sqe->cmd, &cmd, ncopy);
	}
	zvol_uring_push(&g_ublk_ctrl_ring);
	if (zvol_uring_enter(&g_ublk_ctrl_ring, 1) < 0)
		return (-errno);
	cqe = zvol_uring_cqe_peek(&g_ublk_ctrl_ring);
	if (cqe == NULL)
		return (-EIO);
	res = cqe->res;
	zvol_uring_cqe_advance(&g_ublk_ctrl_ring);
	return (res);
}

static int
zvol_ublk_ctrl(uint32_t u_cmd, uint32_t raw_cmd, uint32_t dev_id, void *buf,
    uint16_t len, uint64_t data0)
{
	uint32_t cmds[2];
	int n, i, ret = -EINVAL;

	if (g_ublk_enc == 1) {
		cmds[0] = u_cmd;
		n = 1;
	} else if (g_ublk_enc == 0) {
		cmds[0] = raw_cmd;
		n = 1;
	} else {
		cmds[0] = u_cmd;
		cmds[1] = raw_cmd;
		n = 2;
	}
	for (i = 0; i < n; i++) {
		ret = zvol_ublk_ctrl_once(cmds[i], dev_id, buf, len, data0);
		if (ret >= 0) {
			g_ublk_enc = (cmds[i] == u_cmd);
			return (ret);
		}
		if (ret != -EINVAL && ret != -ENOTTY && ret != -EOPNOTSUPP &&
		    ret != -ENOSYS)
			return (ret);
	}
	return (ret);
}

static int
zvol_ublk_add_one(struct ublksrv_ctrl_dev_info *info, uint32_t id,
    uint32_t qdepth, uint32_t max_io)
{
	memset(info, 0, sizeof (*info));
	info->nr_hw_queues = 1;
	info->queue_depth = (uint16_t)qdepth;
	info->max_io_buf_bytes = max_io;
	info->dev_id = id;
	info->ublksrv_pid = (int32_t)getpid();
	return (zvol_ublk_ctrl(UBLK_U_CMD_ADD_DEV, UBLK_CMD_ADD_DEV,
	    id, info, (uint16_t)sizeof (*info), 0));
}

/*
 * Allocate a ublk id the way kernel zvol allocates minors: ida/idr,
 * no predefined limit. Prefer auto-assign (U32_MAX). Kernels that
 * reject that get a walk from g_ublk_id_next up to UBLK_MINORS.
 * EINVAL on id 0 is a bad request; EINVAL on a later id is the
 * driver's real max and is cached.
 */
static int
zvol_ublk_add_dev(struct ublksrv_ctrl_dev_info *info, uint32_t qdepth,
    uint32_t max_io)
{
	uint32_t id, max, start, scanned;
	int err;

	err = zvol_ublk_add_one(info, ZFSD_UBLK_ID_AUTO, qdepth, max_io);
	if (err >= 0) {
		if (info->dev_id == ZFSD_UBLK_ID_AUTO)
			return (-EIO);
		g_ublk_id_next = info->dev_id + 1;
		return (err);
	}
	/* Working auto-assign: ENOSPC means the idr is full. */
	if (err == -ENOSPC)
		return (err);

	max = g_ublk_id_max != 0 ? g_ublk_id_max : ZFSD_UBLK_ID_CEILING;
	start = g_ublk_id_next;
	if (start >= max)
		start = 0;
	id = start;
	scanned = 0;
	do {
		err = zvol_ublk_add_one(info, id, qdepth, max_io);
		if (err >= 0) {
			if (info->dev_id == ZFSD_UBLK_ID_AUTO)
				info->dev_id = id;
			g_ublk_id_next = info->dev_id + 1;
			return (err);
		}
		if (err == -EINVAL) {
			if (id == 0)
				return (err);
			g_ublk_id_max = id;
			max = id;
			if (start >= max)
				start = 0;
			id = 0;
			if (id == start && scanned > 0)
				break;
			continue;
		}
		if (err != -EEXIST && err != -EBUSY && err != -ENOSPC)
			return (err);
		id++;
		scanned++;
		if (id >= max)
			id = 0;
	} while (id != start && scanned < max);

	return (err < 0 ? err : -ENOSPC);
}

static int
zvol_ublk_sqe_io(zfsd_zvol_t *zv, uint32_t cmd_op, uint16_t tag, int32_t result,
    void *buf)
{
	struct ublksrv_io_cmd cmd;
	struct io_uring_sqe *sqe;

	memset(&cmd, 0, sizeof (cmd));
	cmd.q_id = 0;
	cmd.tag = tag;
	cmd.result = result;
	cmd.addr = (uint64_t)(uintptr_t)buf;
	sqe = zvol_uring_get_sqe(&zv->ring);
	if (sqe == NULL) {
		if (zvol_uring_enter(&zv->ring, 0) < 0)
			return (-1);
		sqe = zvol_uring_get_sqe(&zv->ring);
		if (sqe == NULL)
			return (-1);
	}
	memset(sqe, 0, zv->ring.sqe_size);
	sqe->opcode = IORING_OP_URING_CMD;
	sqe->fd = zv->ublkc_fd;
	sqe->cmd_op = cmd_op;
	sqe->user_data = tag;
	memcpy(sqe->cmd, &cmd, sizeof (cmd));
	zvol_uring_push(&zv->ring);
	return (0);
}

static int
zvol_ublk_handle(zfsd_zvol_t *zv, const struct ublksrv_io_desc *iod, void *buf)
{
	uint32_t op;
	uint64_t off, nbytes;
	int err, fua;

	op = iod->op_flags & 0xffu;
	fua = (iod->op_flags & UBLK_IO_F_FUA) != 0;
	off = (uint64_t)iod->start_sector << 9;
	nbytes = (uint64_t)iod->nr_sectors << 9;
	if ((op == UBLK_IO_OP_READ || op == UBLK_IO_OP_WRITE ||
	    op == UBLK_IO_OP_DISCARD || op == UBLK_IO_OP_WRITE_ZEROES) &&
	    nbytes > zv->max_io)
		return (-EINVAL);
	switch (op) {
	case UBLK_IO_OP_READ:
		if (nbytes == 0)
			return (0);
		if (buf == NULL)
			return (-EIO);
		memset(buf, 0, (size_t)nbytes);
		err = zvol_dmu_read(zv, off, (uint32_t)nbytes, buf);
		return (err != 0 ? -err : (int)nbytes);
	case UBLK_IO_OP_WRITE:
		if (nbytes == 0)
			return (0);
		if (buf == NULL)
			return (-EIO);
		err = zvol_dmu_write(zv, off, (uint32_t)nbytes, buf, fua);
		return (err != 0 ? -err : (int)nbytes);
	case UBLK_IO_OP_FLUSH:
		err = zvol_dmu_flush(zv);
		return (err != 0 ? -err : 0);
	case UBLK_IO_OP_DISCARD:
		err = zvol_dmu_trim(zv, off, nbytes, fua);
		return (err != 0 ? -err : 0);
	case UBLK_IO_OP_WRITE_ZEROES:
		err = zvol_dmu_zero(zv, off, nbytes, fua);
		return (err != 0 ? -err : 0);
	default:
		return (-ENOTSUP);
	}
}

static void *
zvol_ublk_serve(void *arg)
{
	zfsd_zvol_t *zv = arg;
	uint32_t fetch_op, commit_op;
	uint16_t t;
	int inflight;
	int held;

	(void) pthread_setname_np(pthread_self(), "zfsd-ublk-srv");
	held = (zvol_os_hold(zv) == 0);
	fetch_op = zv->ioctl_enc ? UBLK_U_IO_FETCH_REQ : UBLK_IO_FETCH_REQ;
	commit_op = zv->ioctl_enc ? UBLK_U_IO_COMMIT_AND_FETCH_REQ :
	    UBLK_IO_COMMIT_AND_FETCH_REQ;
	for (t = 0; t < zv->qdepth; t++) {
		if (zvol_ublk_sqe_io(zv, fetch_op, t, 0, zv->io_bufs[t]) != 0) {
			__atomic_store_n(&zv->fetches_armed, -1,
			    __ATOMIC_RELEASE);
			goto out;
		}
	}
	if (zvol_uring_enter(&zv->ring, 0) < 0) {
		__atomic_store_n(&zv->fetches_armed, -1, __ATOMIC_RELEASE);
		goto out;
	}
	__atomic_store_n(&zv->fetches_armed, 1, __ATOMIC_RELEASE);
	inflight = (int)zv->qdepth;
	while (inflight > 0) {
		struct io_uring_cqe *cqe;
		struct ublksrv_io_desc iod;
		uint16_t tag;
		int res, result;

		cqe = zvol_uring_cqe_peek(&zv->ring);
		if (cqe == NULL) {
			if (zvol_uring_enter(&zv->ring, 1) < 0) {
				if (errno == EINTR)
					continue;
				break;
			}
			continue;
		}
		tag = (uint16_t)cqe->user_data;
		res = cqe->res;
		zvol_uring_cqe_advance(&zv->ring);
		if (tag >= zv->qdepth) {
			inflight--;
			continue;
		}
		if (res == UBLK_IO_RES_ABORT || res == -ENODEV || zv->dying) {
			inflight--;
			continue;
		}
		if (res != UBLK_IO_RES_OK) {
			if (zv->dying) {
				inflight--;
				continue;
			}
			if (zvol_ublk_sqe_io(zv, fetch_op, tag, 0,
			    zv->io_bufs[tag]) == 0)
				(void) zvol_uring_enter(&zv->ring, 0);
			else
				inflight--;
			continue;
		}
		iod = ((struct ublksrv_io_desc *)zv->iod_map)[tag];
		result = zvol_ublk_handle(zv, &iod, zv->io_bufs[tag]);
		if (zv->dying) {
			inflight--;
			continue;
		}
		if (zvol_ublk_sqe_io(zv, commit_op, tag, result,
		    zv->io_bufs[tag]) == 0)
			(void) zvol_uring_enter(&zv->ring, 0);
		else
			inflight--;
	}
out:
	if (held)
		zvol_os_rele(zv);
	return (NULL);
}

static int
zvol_wait_path(const char *path, int isblk)
{
	int tries, fd;
	struct stat st;

	for (tries = 50; tries > 0; tries--) {
		if (stat(path, &st) == 0 &&
		    (isblk ? S_ISBLK(st.st_mode) : S_ISCHR(st.st_mode))) {
			fd = open(path, O_RDWR | O_CLOEXEC);
			if (fd >= 0)
				return (fd);
		}
		usleep(20000);
	}
	return (-1);
}

static int
zvol_shift(uint64_t n)
{
	int s = 0;

	if (n == 0)
		return (9);
	while ((1ULL << s) < n && s < 31)
		s++;
	return (s);
}

static int
zvol_nbd_rw(int fd, void *buf, size_t n, int do_write)
{
	char *p = buf;

	while (n > 0) {
		ssize_t r;

		if (do_write)
			r = send(fd, p, n, MSG_NOSIGNAL);
		else
			r = recv(fd, p, n, 0);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return (-1);
		}
		if (r == 0)
			return (-1);
		p += r;
		n -= (size_t)r;
	}
	return (0);
}

static int
zvol_nbd_drop(int fd, uint32_t len)
{
	char buf[4096];

	while (len > 0) {
		uint32_t n = len > sizeof (buf) ? (uint32_t)sizeof (buf) : len;

		if (zvol_nbd_rw(fd, buf, n, 0) != 0)
			return (-1);
		len -= n;
	}
	return (0);
}

struct zfsd_nbd_req {
	uint32_t	magic;
	uint32_t	type;
	uint64_t	handle;
	uint64_t	from;
	uint32_t	len;
} __attribute__((packed));
_Static_assert(sizeof (struct zfsd_nbd_req) == 28,
    "NBD request is 28 bytes packed");

struct zfsd_nbd_rep {
	uint32_t	magic;
	uint32_t	error;
	uint64_t	handle;
} __attribute__((packed));

static void *
zvol_nbd_serve(void *arg)
{
	zfsd_zvol_t *zv = arg;
	int fd = zv->nbd_sock;
	sigset_t sset;
	int held;

	sigfillset(&sset);
	(void) pthread_sigmask(SIG_BLOCK, &sset, NULL);
	(void) pthread_setname_np(pthread_self(), "zfsd-nbd-srv");
	/*
	 * One hold for the thread. Per-bio hold/rele nest under it, so
	 * zil_close runs only after this loop stops. See zvol_os_hold.
	 */
	held = (zvol_os_hold(zv) == 0);

	for (;;) {
		struct zfsd_nbd_req req;
		struct zfsd_nbd_rep rep;
		uint32_t type, len, raw;
		uint64_t off;
		int err = 0, fua = 0;
		void *buf = NULL;

		if (zv->dying)
			break;
		if (zvol_nbd_rw(fd, &req, sizeof (req), 0) != 0)
			break;
		if (be32toh(req.magic) != ZFSD_NBD_REQUEST_MAGIC)
			break;
		raw = be32toh(req.type);
		type = raw & 0xffffu;
		fua = (raw & ZFSD_NBD_FLAG_FUA) != 0;
		off = be64toh(req.from);
		len = be32toh(req.len);
		if (type == ZFSD_NBD_CMD_DISC)
			break;
		if ((type == ZFSD_NBD_CMD_READ ||
		    type == ZFSD_NBD_CMD_WRITE) && len > ZFSD_NBD_MAXIO)
			err = EINVAL;
		if ((type == ZFSD_NBD_CMD_READ ||
		    type == ZFSD_NBD_CMD_WRITE) && len > 0 && err == 0) {
			buf = malloc(len);
			if (buf == NULL)
				err = ENOMEM;
		}
		if (type == ZFSD_NBD_CMD_WRITE && len > 0) {
			if (buf != NULL) {
				if (zvol_nbd_rw(fd, buf, len, 0) != 0) {
					free(buf);
					break;
				}
			} else if (zvol_nbd_drop(fd, len) != 0) {
				free(buf);
				break;
			}
		}
		if (err == 0 && !zv->dying) {
			switch (type) {
			case ZFSD_NBD_CMD_READ:
				if (buf != NULL)
					memset(buf, 0, len);
				if (len == 0)
					err = 0;
				else if (buf != NULL)
					err = zvol_dmu_read(zv, off, len, buf);
				else
					err = EIO;
				break;
			case ZFSD_NBD_CMD_WRITE:
				err = zvol_dmu_write(zv, off, len, buf, fua);
				break;
			case ZFSD_NBD_CMD_FLUSH:
				err = zvol_dmu_flush(zv);
				break;
			case ZFSD_NBD_CMD_TRIM:
				err = zvol_dmu_trim(zv, off, len, fua);
				break;
			default:
				err = EINVAL;
				break;
			}
		} else if (err == 0) {
			err = EIO;
		}
		rep.magic = htobe32(ZFSD_NBD_REPLY_MAGIC);
		rep.error = htobe32((uint32_t)err);
		rep.handle = req.handle;
		if (zvol_nbd_rw(fd, &rep, sizeof (rep), 1) != 0) {
			free(buf);
			break;
		}
		if (type == ZFSD_NBD_CMD_READ && err == 0 && buf != NULL) {
			if (zvol_nbd_rw(fd, buf, len, 1) != 0) {
				free(buf);
				break;
			}
		}
		free(buf);
	}
	(void) fprintf(stderr, "zfsd: nbd serve %s exiting dying=%d\n",
	    zv->ds, zv->dying);
	if (held)
		zvol_os_rele(zv);
	return (NULL);
}

static void *
zvol_nbd_doit(void *arg)
{
	zfsd_zvol_t *zv = arg;
	sigset_t sset;
	int err;

	/*
	 * NBD_DO_IT is wait_event_interruptible. Any unblocked
	 * signal returns it, the driver shuts the socket, and
	 * in-flight mke2fs I/O errors — without "Connection timed
	 * out". Block everything on this thread.
	 */
	sigfillset(&sset);
	(void) pthread_sigmask(SIG_BLOCK, &sset, NULL);
	(void) pthread_setname_np(pthread_self(), "zfsd-nbd-doit");
	err = ioctl(zv->nbd_fd, NBD_DO_IT, 0);
	(void) fprintf(stderr,
	    "zfsd: NBD_DO_IT %s returned %d errno=%d dying=%d\n",
	    zv->devpath, err, errno, zv->dying);
	return (NULL);
}

static int
zvol_nbd_open_free(char *path, size_t npath)
{
	int i, fd, max;
	char sys[64], buf[32];
	FILE *fp;
	unsigned long v;

	max = 1 << 20;
	fp = fopen("/sys/module/nbd/parameters/nbds_max", "r");
	if (fp != NULL) {
		if (fscanf(fp, "%lu", &v) == 1 && v > 0 && v <= (1UL << 20))
			max = (int)v;
		(void) fclose(fp);
	}

	for (i = 0; i < max; i++) {
		(void) snprintf(sys, sizeof (sys), "/sys/block/nbd%d/pid", i);
		fp = fopen(sys, "r");
		if (fp != NULL) {
			if (fgets(buf, sizeof (buf), fp) != NULL &&
			    atoi(buf) > 0) {
				(void) fclose(fp);
				continue;
			}
			(void) fclose(fp);
		}
		(void) snprintf(path, npath, "/dev/nbd%d", i);
		fd = open(path, O_RDWR | O_CLOEXEC);
		if (fd >= 0)
			return (fd);
		if (errno == ENOENT)
			break;
	}
	return (-1);
}

#define	ZFSD_NBD_ABORT_FDS	32

static int zfsd_nbd_abort_fds[ZFSD_NBD_ABORT_FDS] = {
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1
};

/*
 * Linux 6.1 nbd_send_cmd holds nsock->tx_lock across a blocking
 * sock_sendmsg. A fatal signal makes NBD_DO_IT return into
 * sock_shutdown, which mutex_locks that same lock. do_coredump waits
 * until every thread has left the kernel, so z_wr_iss sits in
 * wait_for_completion while zfsd-nbd-doit sits on tx_lock and the
 * suite never records the FAIL (alloc_class after 012). Shut our end
 * down before abort() so the send fails with EPIPE and drops the lock.
 * The fd table is lock-free: the asserting thread may already hold
 * g_zvol_lock.
 */
static void
zfsd_abort_shutdown_nbd(void)
{
	int i, fd;

	for (i = 0; i < ZFSD_NBD_ABORT_FDS; i++) {
		fd = __atomic_load_n(&zfsd_nbd_abort_fds[i], __ATOMIC_RELAXED);
		if (fd >= 0)
			(void) shutdown(fd, SHUT_RDWR);
	}
	(void) usleep(20000);
}

static void
zfsd_nbd_abort_add(int fd)
{
	int i;

	libspl_set_abort_cb(zfsd_abort_shutdown_nbd);
	if (fd < 0)
		return;
	for (i = 0; i < ZFSD_NBD_ABORT_FDS; i++) {
		int exp = -1;

		if (__atomic_compare_exchange_n(&zfsd_nbd_abort_fds[i],
		    &exp, fd, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED))
			return;
	}
}

static void
zfsd_nbd_abort_del(int fd)
{
	int i;

	if (fd < 0)
		return;
	for (i = 0; i < ZFSD_NBD_ABORT_FDS; i++) {
		int cur = __atomic_load_n(&zfsd_nbd_abort_fds[i],
		    __ATOMIC_RELAXED);

		if (cur != fd)
			continue;
		(void) __atomic_compare_exchange_n(&zfsd_nbd_abort_fds[i],
		    &cur, -1, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED);
	}
}

static int
zvol_attach_nbd(zfsd_zvol_t *zv)
{
	int sv[2];
	unsigned long flags;
	char pidp[80];
	int tries, err;
	const char *base;

	zv->nbd_fd = zvol_nbd_open_free(zv->devpath, sizeof (zv->devpath));
	if (zv->nbd_fd < 0) {
		(void) fprintf(stderr,
		    "zfsd: no free /dev/nbd* for zvol %s (modprobe nbd)\n",
		    zv->ds);
		return (-1);
	}
	base = strrchr(zv->devpath, '/');
	(void) strlcpy(zv->devname, base != NULL ? base + 1 : zv->devpath,
	    sizeof (zv->devname));
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0)
		return (-1);
	zv->nbd_sock = sv[0];
	zfsd_nbd_abort_add(sv[0]);
	(void) ioctl(zv->nbd_fd, NBD_CLEAR_SOCK, 0);
	(void) ioctl(zv->nbd_fd, NBD_SET_BLKSIZE, 512);
	(void) ioctl(zv->nbd_fd, NBD_SET_SIZE_BLOCKS,
	    (unsigned long)(zv->volsize / 512));
	flags = NBD_FLAG_HAS_FLAGS | NBD_FLAG_SEND_FLUSH | NBD_FLAG_SEND_TRIM;
	if (zvol_ro(zv))
		flags |= NBD_FLAG_READ_ONLY;
	(void) ioctl(zv->nbd_fd, NBD_SET_FLAGS, flags);
	/*
	 * Linux 6.1 nbd_set_cmd_timeout(0) does not clear the
	 * blk-mq default of 30*HZ. A non-zero value does. 600s is
	 * a ZTS test budget; sysfs io_timeout is milliseconds.
	 */
	(void) ioctl(zv->nbd_fd, NBD_SET_TIMEOUT, 600);
	if (ioctl(zv->nbd_fd, NBD_SET_SOCK, sv[1]) != 0) {
		err = errno;
		(void) close(sv[1]);
		(void) fprintf(stderr, "zfsd: NBD_SET_SOCK %s: %s\n",
		    zv->devpath, strerror(err));
		return (-1);
	}
	(void) close(sv[1]);
	if (zvol_thread_create(&zv->serve_tid, zvol_nbd_serve, zv) != 0)
		return (-1);
	if (zvol_thread_create(&zv->doit_tid, zvol_nbd_doit, zv) != 0) {
		zv->dying = 1;
		(void) shutdown(zv->nbd_sock, SHUT_RDWR);
		return (-1);
	}
	zv->running = 1;
	(void) snprintf(pidp, sizeof (pidp), "/sys/block/%s/pid", zv->devname);
	for (tries = 50; tries && access(pidp, F_OK) != 0; tries--)
		usleep(20000);
	{
		char qto[96];
		int tfd;

		(void) snprintf(qto, sizeof (qto),
		    "/sys/block/%s/queue/io_timeout", zv->devname);
		tfd = open(qto, O_WRONLY | O_CLOEXEC);
		if (tfd >= 0) {
			(void) write(tfd, "600000\n", 7);
			(void) close(tfd);
		}
	}
	return (0);
}
#else
void
zfsd_zvol_ctrl_fini(void)
{
}
#endif /* __linux__ */

static void
zvol_join(pthread_t tid)
{
	(void) pthread_join(tid, NULL);
}

static int
zvol_thread_create(pthread_t *tid, void *(*fn)(void *), void *arg)
{
	pthread_attr_t attr;
	int err;

	if (pthread_attr_init(&attr) != 0)
		return (-1);
	(void) pthread_attr_setstacksize(&attr, ZFSD_ZVOL_STACK);
	(void) pthread_attr_setguardsize(&attr, 4096);
	err = pthread_create(tid, &attr, fn, arg);
	(void) pthread_attr_destroy(&attr);
	return (err == 0 ? 0 : -1);
}

static int
zvol_join_timeout(pthread_t tid, unsigned sec)
{
#ifdef __linux__
	struct timespec ts;

	if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
		zvol_join(tid);
		return (0);
	}
	ts.tv_sec += (time_t)sec;
	if (pthread_timedjoin_np(tid, NULL, &ts) == ETIMEDOUT) {
		(void) pthread_detach(tid);
		return (-1);
	}
	return (0);
#else
	(void) sec;
	zvol_join(tid);
	return (0);
#endif
}

static void
zvol_free_bufs(zfsd_zvol_t *zv)
{
#ifdef __linux__
	uint32_t i;

	if (zv->io_bufs != NULL) {
		for (i = 0; i < zv->qdepth; i++)
			free(zv->io_bufs[i]);
		free(zv->io_bufs);
		zv->io_bufs = NULL;
	}
	if (zv->iod_map != NULL && zv->iod_map != MAP_FAILED) {
		(void) munmap(zv->iod_map, zv->iod_map_sz);
		zv->iod_map = NULL;
	}
#endif
}

static void
zvol_teardown(zfsd_zvol_t *zv)
{
	int leaked = 0;

	if (zv == NULL)
		return;
	zv->dying = 1;
#ifdef __linux__
	if (zv->linkpath[0])
		(void) umount2(zv->linkpath, MNT_DETACH);
	if (zv->devpath[0])
		(void) umount2(zv->devpath, MNT_DETACH);
	/*
	 * NBD_DISCONNECT locks the socket tx_lock. The kernel holds
	 * that lock inside sock_sendmsg until the peer reads. The
	 * serve thread stops reading once dying is set, so the ioctl
	 * waits out the 600s nbd timeout and spa_export never returns
	 * (alloc_class_016 sat in zpool destroy until ZTS killed it).
	 * Shut our end down first: in-flight sends fail, recv exits,
	 * NBD_DO_IT returns. Do not call NBD_DISCONNECT.
	 */
	if (zv->nbd_sock >= 0)
		(void) shutdown(zv->nbd_sock, SHUT_RDWR);
	if (zv->running) {
		if (zv->nbd_fd >= 0 &&
		    zvol_join_timeout(zv->doit_tid, 3) != 0)
			leaked = 1;
		if (zvol_join_timeout(zv->serve_tid, 5) != 0)
			leaked = 1;
		zv->running = 0;
	}
	if (!leaked && zv->nbd_fd >= 0)
		(void) ioctl(zv->nbd_fd, NBD_CLEAR_SOCK, 0);
	if (zv->ublk_id >= 0 && g_ublk_ctrl_ready) {
		pthread_mutex_lock(&g_ublk_ctrl_mx);
		(void) zvol_ublk_ctrl(UBLK_U_CMD_STOP_DEV, UBLK_CMD_STOP_DEV,
		    (uint32_t)zv->ublk_id, NULL, 0, 0);
		pthread_mutex_unlock(&g_ublk_ctrl_mx);
	}
	if (zv->ublk_id >= 0 && g_ublk_ctrl_ready) {
		pthread_mutex_lock(&g_ublk_ctrl_mx);
		(void) zvol_ublk_ctrl(UBLK_U_CMD_DEL_DEV, UBLK_CMD_DEL_DEV,
		    (uint32_t)zv->ublk_id, NULL, 0, 0);
		pthread_mutex_unlock(&g_ublk_ctrl_mx);
		zv->ublk_id = -1;
	}
	zvol_uring_exit(&zv->ring);
	if (zv->ublkc_fd >= 0) {
		(void) close(zv->ublkc_fd);
		zv->ublkc_fd = -1;
	}
	zvol_free_bufs(zv);
	if (zv->nbd_sock >= 0) {
		zfsd_nbd_abort_del(zv->nbd_sock);
		(void) close(zv->nbd_sock);
		zv->nbd_sock = -1;
	}
	if (zv->nbd_fd >= 0) {
		(void) close(zv->nbd_fd);
		zv->nbd_fd = -1;
	}
#endif
	if (zv->linkpath[0])
		(void) unlink(zv->linkpath);
	/*
	 * Drop the objset even if an NBD thread is stuck, so
	 * spa_export is not EBUSY. Only destroy locks after join.
	 */
	if (!leaked)
		(void) pthread_rwlock_wrlock(&zv->io);
	pthread_mutex_lock(&zv->os_mx);
	while (zv->os_holds < 0)
		(void) pthread_cond_wait(&zv->os_cv, &zv->os_mx);
	if (zv->os_holds > 0)
		zv->os_holds = 1;
	pthread_mutex_unlock(&zv->os_mx);
	zvol_os_rele(zv);
	if (leaked) {
		(void) fprintf(stderr,
		    "zfsd: zvol %s: NBD thread did not exit; leaking\n",
		    zv->ds);
		return;
	}
	(void) pthread_rwlock_unlock(&zv->io);
	(void) pthread_cond_destroy(&zv->os_cv);
	(void) pthread_mutex_destroy(&zv->os_mx);
	(void) pthread_rwlock_destroy(&zv->io);
	zfs_rangelock_fini(&zv->rlock);
	free(zv);
}

/*
 * dd(1) to an NBD zvol dirties the block-device page cache. zpool
 * sync only waits for a txg, so those pages are still invisible to
 * the allocation-class checks (alloc_class_016: file data landed,
 * the zvol's 10M was on no vdev). Flush before the sync ioctl so
 * the bios become dirty DMU data in the txg that sync then writes.
 * Kernel zd* devices take the same bios inside the kernel; NBD
 * does not see them until writeback.
 */
void
zfsd_zvol_flush_bdevs(void)
{
#ifdef __linux__
	zfsd_zvol_t *zv;
	int fds[64];
	int n = 0, i;

	pthread_mutex_lock(&g_zvol_lock);
	for (zv = g_zvols; zv != NULL && n < 64; zv = zv->next) {
		if (zv->dying || zv->nbd_fd < 0)
			continue;
		fds[n] = dup(zv->nbd_fd);
		if (fds[n] >= 0)
			n++;
	}
	pthread_mutex_unlock(&g_zvol_lock);
	for (i = 0; i < n; i++) {
		(void) ioctl(fds[i], BLKFLSBUF);
		(void) close(fds[i]);
	}
#endif
}

static int
zfsd_ds_prop_readonly(const char *dsname, int *rop)
{
	uint64_t ro = 0;
	int err;

	if (dsname == NULL || dsname[0] == '\0')
		return (EINVAL);
	if (strchr(dsname, '@') != NULL) {
		*rop = 1;
		return (0);
	}
	err = dsl_prop_get_integer(dsname,
	    zfs_prop_to_name(ZFS_PROP_READONLY), &ro, NULL);
	if (err != 0)
		return (err);
	*rop = (ro != 0);
	return (0);
}

static int zfsd_zvol_publish_impl(const char *dsname);

static void
zfsd_zvol_publish_task(void *arg)
{
	char *name = arg;

	(void) zfsd_zvol_publish_impl(name);
	kmem_strfree(name);
}

/*
 * txg_sync already holds the config lock as writer. dsl_prop_get and
 * dmu_objset_own take it as a reader. Queue the publish and return.
 * TQ_NOSLEEP: system_taskq's maxalloc is 512, and sleeping here stalls
 * spa_sync. Dropping the publish beats aborting the daemon.
 * Returns B_TRUE if the caller must not continue inline.
 */
static boolean_t
zfsd_zvol_defer_if_syncing(const char *dsname, task_func_t fn)
{
	char *name;
	taskq_t *tq;

	if (!txg_thread_is_syncing() || dsname == NULL || dsname[0] == '\0')
		return (B_FALSE);
	tq = system_taskq;
	if (tq == NULL || fn == NULL)
		return (B_TRUE);
	name = kmem_strdup(dsname);
	if (name == NULL)
		return (B_TRUE);
	if (taskq_dispatch(tq, fn, name, TQ_NOSLEEP) == TASKQID_INVALID)
		kmem_strfree(name);
	return (B_TRUE);
}

static int
zfsd_zvol_publish_impl(const char *dsname)
{
	zfsd_zvol_t *zv, *p;
	objset_t *os = NULL;
	dmu_object_info_t doi;
	uint64_t sz = 0;
	int err, ro;

	if (dsname == NULL || dsname[0] == '\0')
		return (0);

	pthread_mutex_lock(&g_zvol_lock);
	for (p = g_zvols; p != NULL; p = p->next) {
		if (strcmp(p->ds, dsname) == 0) {
			pthread_mutex_unlock(&g_zvol_lock);
			return (0);
		}
	}
	pthread_mutex_unlock(&g_zvol_lock);

	if (strchr(dsname, '@') != NULL) {
		uint64_t snapdev = ZFS_SNAPDEV_HIDDEN;

		/*
		 * Kernel zvol_create_minors_cb does not create a minor
		 * for a snapshot unless snapdev=visible. A hidden snap
		 * published here would own the dataset for the life of
		 * the NBD thread, so destroy of the snap is EBUSY and a
		 * clone shows up as three devices.
		 */
		if (dsl_prop_get_integer(dsname,
		    zfs_prop_to_name(ZFS_PROP_SNAPDEV), &snapdev, NULL) != 0 ||
		    snapdev != ZFS_SNAPDEV_VISIBLE)
			return (0);
	}

	ro = 0;
	(void) zfsd_ds_prop_readonly(dsname, &ro);
	zv = calloc(1, sizeof (*zv));
	if (zv == NULL)
		return (ENOMEM);
	(void) strlcpy(zv->ds, dsname, sizeof (zv->ds));
	zv->prop_ro = ro;
	zv->dev_ro = 0;
	zv->ublk_id = -1;
	zv->ublkc_fd = -1;
	zv->nbd_fd = -1;
	zv->nbd_sock = -1;
	zv->ring.fd = -1;
	zv->qdepth = ZFSD_UBLK_QDEPTH;
	zv->max_io = ZFSD_UBLK_MAXIO;
	(void) pthread_rwlock_init(&zv->io, NULL);
	(void) pthread_mutex_init(&zv->os_mx, NULL);
	(void) pthread_cond_init(&zv->os_cv, NULL);
	zfs_rangelock_init(&zv->rlock, NULL, NULL);

	err = dmu_objset_own(dsname, DMU_OST_ZVOL, ro ? B_TRUE : B_FALSE,
	    B_TRUE, zv, &os);
	if (err != 0) {
		zfs_rangelock_fini(&zv->rlock);
		(void) pthread_cond_destroy(&zv->os_cv);
		(void) pthread_mutex_destroy(&zv->os_mx);
		(void) pthread_rwlock_destroy(&zv->io);
		free(zv);
		if (err == ENOENT || err == ENOTSUP || err == EINVAL)
			return (0);
		return (err);
	}
	if (!spa_writeable(dmu_objset_spa(os)))
		zv->prop_ro = 1;
	zv->os = os;
	zil_sums_init(&zv->zil_sums);
	zv->zilog = zil_open(os, zvol_zil_get_data, &zv->zil_sums);
	if (spa_writeable(dmu_objset_spa(os))) {
		if (zil_replay_disable)
			(void) zil_destroy(zv->zilog, B_FALSE);
		else
			(void) zil_replay(os, zv, zvol_replay_vector);
	}
	(void) zap_lookup(os, ZVOL_ZAP_OBJ, "size", 8, 1, &sz);
	zv->volsize = sz;
	memset(&doi, 0, sizeof (doi));
	if (dmu_object_info(os, ZVOL_OBJ, &doi) == 0)
		zv->volblocksize = doi.doi_data_block_size;
	if (zv->volblocksize == 0)
		zv->volblocksize = 8192;
	/*
	 * Kernel zvol_os_create_minor disowns after setup. Idle
	 * minors must not hold a spa ref or spa_export is EBUSY
	 * before zvol_remove_minors.
	 */
	zil_close(zv->zilog);
	zv->zilog = NULL;
	zil_sums_fini(&zv->zil_sums);
	dmu_objset_disown(os, B_TRUE, zv);
	zv->os = NULL;

	(void) snprintf(zv->linkpath, sizeof (zv->linkpath), "/dev/zvol/%s",
	    dsname);

#ifndef __linux__
	(void) fprintf(stderr, "zfsd: zvol %s: ublk is Linux-only\n", dsname);
	zvol_teardown(zv);
	return (0);
#else
	{
		struct ublksrv_ctrl_dev_info info;
		struct zfsd_ublk_params params;
		char ublkc[64], parent[MAXPATHLEN];
		char *slash;
		long pgsz;
		uint32_t i;
		int tries, pshift;
		struct group *gr;

		pthread_mutex_lock(&g_ublk_ctrl_mx);
		if (zvol_ublk_ctrl_open() != 0) {
			pthread_mutex_unlock(&g_ublk_ctrl_mx);
			(void) fprintf(stderr,
			    "zfsd: ublk missing for zvol %s, trying NBD\n",
			    dsname);
			goto nbd_fallback;
		}
		err = zvol_ublk_add_dev(&info, zv->qdepth, zv->max_io);
		if (err < 0) {
			pthread_mutex_unlock(&g_ublk_ctrl_mx);
			(void) fprintf(stderr,
			    "zfsd: ublk ADD_DEV %s: %s, trying NBD\n",
			    dsname, strerror(-err));
			goto nbd_fallback;
		}
		zv->ublk_id = (int)info.dev_id;
		zv->ioctl_enc = (info.flags & UBLK_F_CMD_IOCTL_ENCODE) != 0 ||
		    g_ublk_enc == 1;
		memset(&params, 0, sizeof (params));
		params.len = ZFSD_UBLK_PARAMS_V1;
		params.types = UBLK_PARAM_TYPE_BASIC | UBLK_PARAM_TYPE_DISCARD;
		pshift = zvol_shift(zv->volblocksize);
		if (pshift < 9)
			pshift = 9;
		params.basic.logical_bs_shift = 9;
		params.basic.physical_bs_shift = (uint8_t)pshift;
		params.basic.io_opt_shift = (uint8_t)pshift;
		params.basic.io_min_shift = 9;
		params.basic.max_sectors = zv->max_io >> 9;
		params.basic.dev_sectors = zv->volsize >> 9;
		params.basic.attrs = UBLK_ATTR_VOLATILE_CACHE | UBLK_ATTR_FUA;
		if (zvol_ro(zv))
			params.basic.attrs |= UBLK_ATTR_READ_ONLY;
		params.discard.discard_granularity = (uint32_t)zv->volblocksize;
		params.discard.discard_alignment = (uint32_t)zv->volblocksize;
		params.discard.max_discard_sectors = zv->max_io >> 9;
		params.discard.max_write_zeroes_sectors = zv->max_io >> 9;
		params.discard.max_discard_segments = 1;
		err = zvol_ublk_ctrl(UBLK_U_CMD_SET_PARAMS, UBLK_CMD_SET_PARAMS,
		    info.dev_id, &params, (uint16_t)params.len, 0);
		if (err < 0) {
			params.types = UBLK_PARAM_TYPE_BASIC;
			(void) zvol_ublk_ctrl(UBLK_U_CMD_SET_PARAMS,
			    UBLK_CMD_SET_PARAMS, info.dev_id, &params,
			    (uint16_t)params.len, 0);
		}
		pthread_mutex_unlock(&g_ublk_ctrl_mx);

		(void) snprintf(ublkc, sizeof (ublkc), "/dev/ublkc%u",
		    info.dev_id);
		zv->ublkc_fd = zvol_wait_path(ublkc, 0);
		if (zv->ublkc_fd < 0) {
			(void) fprintf(stderr, "zfsd: open %s: %s\n", ublkc,
			    strerror(errno));
			zvol_teardown(zv);
			return (0);
		}
		pgsz = sysconf(_SC_PAGESIZE);
		if (pgsz <= 0)
			pgsz = 4096;
		zv->iod_map_sz = ((size_t)zv->qdepth *
		    sizeof (struct ublksrv_io_desc) + (size_t)pgsz - 1) &
		    ~((size_t)pgsz - 1);
		zv->iod_map = mmap(NULL, zv->iod_map_sz, PROT_READ,
		    MAP_SHARED | MAP_POPULATE, zv->ublkc_fd,
		    UBLKSRV_CMD_BUF_OFFSET);
		if (zv->iod_map == MAP_FAILED) {
			(void) fprintf(stderr, "zfsd: mmap %s: %s\n", ublkc,
			    strerror(errno));
			zv->iod_map = NULL;
			zvol_teardown(zv);
			return (0);
		}
		zv->io_bufs = calloc(zv->qdepth, sizeof (void *));
		if (zv->io_bufs == NULL) {
			zvol_teardown(zv);
			return (ENOMEM);
		}
		for (i = 0; i < zv->qdepth; i++) {
			if (posix_memalign(&zv->io_bufs[i], (size_t)pgsz,
			    zv->max_io) != 0) {
				zvol_teardown(zv);
				return (ENOMEM);
			}
		}
		if (zvol_uring_setup(&zv->ring, zv->qdepth * 2, 0) != 0) {
			(void) fprintf(stderr,
			    "zfsd: io_uring setup for zvol %s failed\n",
			    dsname);
			zvol_teardown(zv);
			return (0);
		}
		if (zvol_thread_create(&zv->serve_tid, zvol_ublk_serve,
		    zv) != 0) {
			zvol_teardown(zv);
			return (EIO);
		}
		zv->running = 1;
		for (tries = 200; tries > 0; tries--) {
			if (__atomic_load_n(&zv->fetches_armed,
			    __ATOMIC_ACQUIRE) != 0)
				break;
			usleep(10000);
		}
		if (__atomic_load_n(&zv->fetches_armed,
		    __ATOMIC_ACQUIRE) != 1) {
			(void) fprintf(stderr,
			    "zfsd: ublk FETCH_REQ for %s failed\n", dsname);
			zvol_teardown(zv);
			return (0);
		}
		pthread_mutex_lock(&g_ublk_ctrl_mx);
		err = zvol_ublk_ctrl(UBLK_U_CMD_START_DEV, UBLK_CMD_START_DEV,
		    info.dev_id, NULL, 0, (uint64_t)(uint32_t)getpid());
		pthread_mutex_unlock(&g_ublk_ctrl_mx);
		if (err < 0) {
			(void) fprintf(stderr, "zfsd: ublk START_DEV %s: %s\n",
			    dsname, strerror(-err));
			zvol_teardown(zv);
			return (0);
		}
		(void) snprintf(zv->devpath, sizeof (zv->devpath),
		    "/dev/ublkb%u", info.dev_id);
		(void) snprintf(zv->devname, sizeof (zv->devname), "ublkb%u",
		    info.dev_id);
		for (tries = 50; tries && access(zv->devpath, F_OK) != 0;
		    tries--)
			usleep(20000);
		goto zvol_link;
nbd_fallback:
		if (zvol_attach_nbd(zv) != 0) {
			zvol_teardown(zv);
			return (0);
		}
zvol_link:
		zvol_prepare_root();
		gr = getgrnam("disk");
		if (gr != NULL)
			(void) chown(zv->devpath, 0, gr->gr_gid);
		(void) chmod(zv->devpath, 0660);
		(void) strlcpy(parent, zv->linkpath, sizeof (parent));
		slash = strrchr(parent, '/');
		if (slash != NULL) {
			*slash = '\0';
			(void) zfsd_mkdirs(parent, 0755);
		}
		(void) unlink(zv->linkpath);
		if (symlink(zv->devpath, zv->linkpath) != 0) {
			(void) fprintf(stderr, "zfsd: symlink %s -> %s: %s\n",
			    zv->linkpath, zv->devpath, strerror(errno));
			zvol_teardown(zv);
			return (errno);
		}
		/*
		 * Do not pin the objset here. spa_export checks spa_refcnt
		 * before zvol_remove_minors. dmu_objset_own holds a spa
		 * ref, so an idle NBD zvol makes zpool destroy EBUSY.
		 * ZTS log_must_busy then retries ~31s and the leftover
		 * pool fails every later test. Own around I/O only,
		 * like kernel idle minors / zvol_first_open.
		 */
	}

	pthread_mutex_lock(&g_zvol_lock);
	for (p = g_zvols; p != NULL; p = p->next) {
		if (strcmp(p->ds, dsname) == 0) {
			pthread_mutex_unlock(&g_zvol_lock);
			zvol_teardown(zv);
			return (0);
		}
	}
	zv->next = g_zvols;
	g_zvols = zv;
	pthread_mutex_unlock(&g_zvol_lock);
	(void) fprintf(stderr, "zfsd: published %s %s -> %s size=%llu\n",
	    zv->nbd_fd >= 0 ? "nbd" : "ublk",
	    zv->linkpath, zv->devpath, (unsigned long long)zv->volsize);
	return (0);
#endif
}

int
zfsd_zvol_publish(const char *dsname)
{
	if (zfsd_zvol_defer_if_syncing(dsname, zfsd_zvol_publish_task))
		return (0);
	return (zfsd_zvol_publish_impl(dsname));
}

static int
zvol_mnt_has(const char *path)
{
	FILE *fp;
	struct mntent *me;

	if (path == NULL || path[0] == '\0')
		return (0);
	fp = setmntent("/proc/self/mounts", "r");
	if (fp == NULL)
		return (0);
	while ((me = getmntent(fp)) != NULL) {
		if (me->mnt_fsname != NULL &&
		    strcmp(me->mnt_fsname, path) == 0) {
			endmntent(fp);
			return (1);
		}
	}
	endmntent(fp);
	return (0);
}

int
zfsd_zvol_unpublish(const char *dsname)
{
	zfsd_zvol_t **pp, *zv = NULL;

	if (dsname == NULL)
		return (0);
	pthread_mutex_lock(&g_zvol_lock);
	for (pp = &g_zvols; (zv = *pp) != NULL; pp = &zv->next) {
		if (strcmp(zv->ds, dsname) == 0)
			break;
	}
	if (zv != NULL && (zvol_mnt_has(zv->devpath) ||
	    zvol_mnt_has(zv->linkpath))) {
#ifdef __linux__
		pthread_mutex_unlock(&g_zvol_lock);
		(void) umount2(zv->devpath, MNT_DETACH);
		(void) umount2(zv->linkpath, MNT_DETACH);
		pthread_mutex_lock(&g_zvol_lock);
		for (pp = &g_zvols; (zv = *pp) != NULL; pp = &zv->next) {
			if (strcmp(zv->ds, dsname) == 0)
				break;
		}
		if (zv != NULL && (zvol_mnt_has(zv->devpath) ||
		    zvol_mnt_has(zv->linkpath))) {
			pthread_mutex_unlock(&g_zvol_lock);
			return (EBUSY);
		}
#else
		pthread_mutex_unlock(&g_zvol_lock);
		return (EBUSY);
#endif
	}
	if (zv != NULL)
		*pp = zv->next;
	pthread_mutex_unlock(&g_zvol_lock);
	zvol_teardown(zv);
	return (0);
}

/*
 * Drop the serve-thread objset own for an unmounted zvol. zfs_ioc_destroy
 * calls this before dsl_destroy_*_check. The check counts ds_longholds
 * and returns EBUSY while the NBD thread still owns the dataset, and
 * zvol_remove_minors used to run only after that check succeeded.
 */
int
zfsd_zvol_release_idle(const char *dsname)
{
	zfsd_zvol_t *zv;
	int mounted = 0;

	if (dsname == NULL || dsname[0] == '\0')
		return (0);
	pthread_mutex_lock(&g_zvol_lock);
	for (zv = g_zvols; zv != NULL; zv = zv->next) {
		if (strcmp(zv->ds, dsname) == 0)
			break;
	}
	if (zv != NULL)
		mounted = zvol_mnt_has(zv->devpath) ||
		    zvol_mnt_has(zv->linkpath);
	pthread_mutex_unlock(&g_zvol_lock);
	if (mounted)
		return (EBUSY);
	return (zfsd_zvol_unpublish(dsname));
}

int
zfsd_zvol_set_prop_ro(const char *name, boolean_t val)
{
	zfsd_zvol_t *zv;

	if (name == NULL || name[0] == '\0')
		return (0);
	pthread_mutex_lock(&g_zvol_lock);
	for (zv = g_zvols; zv != NULL; zv = zv->next) {
		if (strcmp(zv->ds, name) == 0)
			break;
	}
	if (zv == NULL) {
		pthread_mutex_unlock(&g_zvol_lock);
		return (0);
	}
	pthread_rwlock_wrlock(&zv->io);
	zv->prop_ro = val || (strchr(zv->ds, '@') != NULL);
	if (zv->prop_ro)
		zv->dev_ro = 1;
	pthread_rwlock_unlock(&zv->io);
	pthread_mutex_unlock(&g_zvol_lock);
	return (0);
}

typedef struct zvol_pub_list {
	char	**names;
	int	n;
	int	cap;
} zvol_pub_list_t;

static int
zvol_collect_cb(const char *ds, void *arg)
{
	zvol_pub_list_t *l = arg;
	char **n;
	int ncap;

	if (ds == NULL || ds[0] == '\0')
		return (0);
	if (l->n == l->cap) {
		ncap = l->cap != 0 ? l->cap * 2 : 16;
		n = realloc(l->names, (size_t)ncap * sizeof (*n));
		if (n == NULL)
			return (ENOMEM);
		l->names = n;
		l->cap = ncap;
	}
	l->names[l->n] = strdup(ds);
	if (l->names[l->n] == NULL)
		return (ENOMEM);
	l->n++;
	return (0);
}

static void
zfsd_zvol_publish_pool_task(void *arg)
{
	char *name = arg;

	/*
	 * Not the txg thread, so publish_pool will not defer again.
	 * It walks children; a pool name is not itself a zvol.
	 */
	(void) zfsd_zvol_publish_pool(name);
	kmem_strfree(name);
}

int
zfsd_zvol_publish_pool(const char *pool)
{
	zvol_pub_list_t l = { 0 };
	uint64_t snapdev;
	int i, err;

	if (pool == NULL || pool[0] == '\0')
		return (0);
	/*
	 * dmu_objset_find and dsl_prop_get_integer both dsl_pool_hold.
	 * Same writer-thread assert as zfsd_zvol_publish.
	 */
	if (zfsd_zvol_defer_if_syncing(pool, zfsd_zvol_publish_pool_task))
		return (0);
	err = dmu_objset_find(pool, zvol_collect_cb, &l,
	    DS_FIND_CHILDREN | DS_FIND_SNAPSHOTS);
	for (i = 0; i < l.n; i++) {
		if (err == 0) {
			if (strchr(l.names[i], '@') != NULL) {
				snapdev = ZFS_SNAPDEV_HIDDEN;
				if (dsl_prop_get_integer(l.names[i],
				    zfs_prop_to_name(ZFS_PROP_SNAPDEV),
				    &snapdev, NULL) != 0 ||
				    snapdev != ZFS_SNAPDEV_VISIBLE) {
					free(l.names[i]);
					continue;
				}
			}
			(void) zfsd_zvol_publish(l.names[i]);
		}
		free(l.names[i]);
	}
	free(l.names);
	return (err);
}

void
zfsd_zvol_unpublish_pool(const char *pool)
{
	zfsd_zvol_t *drop = NULL, **pp, *zv;

	pthread_mutex_lock(&g_zvol_lock);
	pp = &g_zvols;
	while ((zv = *pp) != NULL) {
		if (pool == NULL || zvol_ds_prefix(zv->ds, pool)) {
			*pp = zv->next;
			zv->next = drop;
			drop = zv;
		} else {
			pp = &zv->next;
		}
	}
	pthread_mutex_unlock(&g_zvol_lock);
	while (drop != NULL) {
		zv = drop;
		drop = drop->next;
		zvol_teardown(zv);
	}
}

boolean_t
zfsd_zvol_published_match(const char *name)
{
	zfsd_zvol_t *zv;
	boolean_t hit = B_FALSE;

	if (name == NULL || name[0] == '\0')
		return (B_FALSE);
	pthread_mutex_lock(&g_zvol_lock);
	for (zv = g_zvols; zv != NULL; zv = zv->next) {
		if (zvol_ds_prefix(zv->ds, name)) {
			hit = B_TRUE;
			break;
		}
	}
	pthread_mutex_unlock(&g_zvol_lock);
	return (hit);
}

/*
 * Rewrite published zvol minors whose dataset name is oldname or a
 * child/snapshot of it. Runs off txg_sync: publish owns the objset.
 */
void
zfsd_zvol_rename_published(const char *oldname, const char *newname)
{
	zfsd_zvol_t *zv;
	char **oldv = NULL;
	int n = 0, cap = 0, i;
	size_t olen;

	if (oldname == NULL || oldname[0] == '\0' || newname == NULL)
		return;
	olen = strlen(oldname);
	pthread_mutex_lock(&g_zvol_lock);
	for (zv = g_zvols; zv != NULL; zv = zv->next) {
		char **nv;

		if (!zvol_ds_prefix(zv->ds, oldname))
			continue;
		if (n == cap) {
			cap = cap != 0 ? cap * 2 : 4;
			nv = realloc(oldv, (size_t)cap * sizeof (*nv));
			if (nv == NULL)
				break;
			oldv = nv;
		}
		oldv[n] = strdup(zv->ds);
		if (oldv[n] == NULL)
			break;
		n++;
	}
	pthread_mutex_unlock(&g_zvol_lock);

	for (i = 0; i < n; i++) {
		char *nn;
		size_t slen = strlen(oldv[i] + olen);
		size_t nlen = strlen(newname);

		nn = malloc(nlen + slen + 1);
		if (nn != NULL) {
			(void) memcpy(nn, newname, nlen);
			(void) memcpy(nn + nlen, oldv[i] + olen, slen + 1);
			(void) zfsd_zvol_unpublish(oldv[i]);
			(void) zfsd_zvol_publish(nn);
			free(nn);
		}
		free(oldv[i]);
	}
	free(oldv);
}
