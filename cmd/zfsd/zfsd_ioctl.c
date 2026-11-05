// SPDX-License-Identifier: CDDL-1.0
/*
 * zfsd OS glue for module/zfs/zfs_ioctl.c, plus the CUSE /dev/zfs
 * ioctl path (process_vm copy of the caller's zfs_cmd_t).
 * zfsdev_ioctl_common and the registered handlers live in
 * module/zfs/zfs_ioctl.c unchanged. zvol_create/remove/rename_minors
 * are the same libzpool hooks spa.c and dsl_destroy.c already call;
 * zfsd installs the impls. Root objset format is zfs_create_fs from
 * dsl_pool_create, same call site as the kernel.
 */

#ifndef _GNU_SOURCE
#define	_GNU_SOURCE
#endif

#define	FUSE_USE_VERSION	31

#include <sys/zfs_context.h>
#include <sys/kmem.h>
#include <sys/taskq.h>
#include <sys/spa.h>
#include <sys/dmu.h>
#include <sys/dmu_objset.h>
#include <sys/dmu_tx.h>
#include <sys/dsl_prop.h>
#include <sys/dsl_pool.h>
#include <sys/txg.h>
#include <sys/zap.h>
#include <sys/nvpair.h>
#include <sys/fs/zfs.h>
#include <sys/zfs_ioctl.h>
#include <sys/zfs_vfsops.h>
#include <sys/zfs_ioctl_impl.h>
#include <sys/zfs_onexit.h>
#include <sys/zfs_znode.h>
#include <sys/zvol.h>
#include <sys/spa_impl.h>
#include <sys/fm/util.h>
#include <sys/zfsd.h>
#include <sys/zcp.h>
#include <sys/cred.h>
#include <sys/policy.h>
#include <sys/zfeature.h>
#include "zfs_prop.h"
#include <stddef.h>
#include <string.h>
#include <sys/zfs_file.h>
#include <sys/dsl_deleg.h>
#include <zfs_namecheck.h>
#include <fuse3/fuse.h>
#include <fuse3/cuse_lowlevel.h>
#include <fuse3/fuse_lowlevel.h>
#include "zfsd_zpl.h"
#include "zfsd_zvol.h"
#include "zfsd_impl.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/uio.h>
#ifdef __linux__
#include <sys/mount.h>
#include <sys/syscall.h>
#endif
#ifdef __FreeBSD__
#include <sys/ptrace.h>
#endif

extern uint64_t zfs_max_nvlist_src_size;
extern uint_t zfs_max_recordsize;

static void
zfsd_allow_log_destroy(void *arg)
{
	if (arg != NULL)
		kmem_strfree(arg);
}

uint64_t
zfs_max_nvlist_src_size_os(void)
{
	if (zfs_max_nvlist_src_size != 0)
		return (zfs_max_nvlist_src_size);
	return ((uint64_t)ZFSD_PTRACE_MAX);
}


void
zfs_ioctl_update_mount_cache(const char *dsname)
{
	(void) dsname;
}

static int
zfsd_ioc_userns_unavail(zfs_cmd_t *zc)
{
	(void) zc;
	return (SET_ERROR(ENOTSUP));
}

void
zfs_ioctl_init_os(void)
{
	zfs_ioctl_register_dataset_nolog(ZFS_IOC_USERNS_ATTACH,
	    zfsd_ioc_userns_unavail, zfs_secpolicy_config, POOL_CHECK_NONE);
	zfs_ioctl_register_dataset_nolog(ZFS_IOC_USERNS_DETACH,
	    zfsd_ioc_userns_unavail, zfs_secpolicy_config, POOL_CHECK_NONE);
}

int
zfsdev_attach(void)
{
	return (0);
}

void
zfsdev_detach(void)
{
}

void
zfsdev_private_set_state(void *priv, zfsdev_state_t *zs)
{
	*(zfsdev_state_t **)priv = zs;
}

zfsdev_state_t *
zfsdev_private_get_state(void *priv)
{
	return (*(zfsdev_state_t **)priv);
}


void
zfs_zevent_init(zfs_zevent_t **zep)
{
	*zep = kmem_zalloc(sizeof (zfs_zevent_t), KM_SLEEP);
}

void
zfs_zevent_destroy(zfs_zevent_t *ze)
{
	if (ze != NULL)
		kmem_free(ze, sizeof (zfs_zevent_t));
}

int
zfs_zevent_next(zfs_zevent_t *ze, nvlist_t **nvlp, uint64_t *dropped,
    uint64_t *eid)
{
	(void) ze, (void) nvlp, (void) dropped, (void) eid;
	return (SET_ERROR(ENOENT));
}

int
zfs_zevent_wait(zfs_zevent_t *ze)
{
	(void) ze;
	return (SET_ERROR(ENOTSUP));
}

int
zfs_zevent_seek(zfs_zevent_t *ze, uint64_t eid)
{
	(void) ze, (void) eid;
	return (SET_ERROR(ENOTSUP));
}

zfs_file_t *
zfs_zevent_fd_hold(int fd, minor_t *minorp, zfs_zevent_t **ze)
{
	(void) fd;
	if (minorp != NULL)
		*minorp = 0;
	if (ze != NULL)
		*ze = NULL;
	return (NULL);
}

void
zfs_zevent_fd_rele(zfs_file_t *fp)
{
	(void) fp;
}

void
zfs_zevent_drain_all(uint_t *count)
{
	if (count != NULL)
		*count = 0;
}


void
zvol_create_cb(objset_t *os, void *arg, cred_t *cr, dmu_tx_t *tx)
{
	zfs_creat_t *zct = arg;
	nvlist_t *nvprops = zct->zct_props;
	int error;
	uint64_t volblocksize, volsize;

	(void) cr;
	VERIFY0(nvlist_lookup_uint64(nvprops,
	    zfs_prop_to_name(ZFS_PROP_VOLSIZE), &volsize));
	if (nvlist_lookup_uint64(nvprops,
	    zfs_prop_to_name(ZFS_PROP_VOLBLOCKSIZE), &volblocksize) != 0)
		volblocksize = zfs_prop_default_numeric(ZFS_PROP_VOLBLOCKSIZE);
	VERIFY0(nvlist_remove_all(nvprops, zfs_prop_to_name(ZFS_PROP_VOLSIZE)));
	(void) nvlist_remove_all(nvprops,
	    zfs_prop_to_name(ZFS_PROP_VOLBLOCKSIZE));
	error = dmu_object_claim(os, ZVOL_OBJ, DMU_OT_ZVOL, volblocksize,
	    DMU_OT_NONE, 0, tx);
	ASSERT0(error);
	error = zap_create_claim(os, ZVOL_ZAP_OBJ, DMU_OT_ZVOL_PROP,
	    DMU_OT_NONE, 0, tx);
	ASSERT0(error);
	error = zap_update(os, ZVOL_ZAP_OBJ, "size", 8, 1, &volsize, tx);
	ASSERT0(error);
}

int
zvol_get_stats(objset_t *os, nvlist_t *nv)
{
	int error;
	dmu_object_info_t doi;
	uint64_t val;

	error = zap_lookup(os, ZVOL_ZAP_OBJ, "size", 8, 1, &val);
	if (error)
		return (error);
	dsl_prop_nvlist_add_uint64(nv, ZFS_PROP_VOLSIZE, val);
	error = dmu_object_info(os, ZVOL_OBJ, &doi);
	if (error == 0) {
		dsl_prop_nvlist_add_uint64(nv, ZFS_PROP_VOLBLOCKSIZE,
		    doi.doi_data_block_size);
	}
	return (error);
}

int
zvol_check_volsize(uint64_t volsize, uint64_t blocksize)
{
	if (volsize == 0)
		return (SET_ERROR(EINVAL));
	if (volsize % blocksize != 0)
		return (SET_ERROR(EINVAL));
	return (0);
}

int
zvol_check_volblocksize(const char *name, uint64_t volblocksize)
{
	if (volblocksize > SPA_OLD_MAXBLOCKSIZE) {
		spa_t *spa;
		int error;

		if ((error = spa_open(name, &spa, FTAG)) != 0)
			return (error);
		if (!spa_feature_is_enabled(spa, SPA_FEATURE_LARGE_BLOCKS)) {
			spa_close(spa, FTAG);
			return (SET_ERROR(ENOTSUP));
		}
		if (volblocksize > zfs_max_recordsize) {
			spa_close(spa, FTAG);
			return (SET_ERROR(EDOM));
		}
		spa_close(spa, FTAG);
	}
	if (volblocksize < SPA_MINBLOCKSIZE ||
	    volblocksize > SPA_MAXBLOCKSIZE ||
	    !ISP2(volblocksize))
		return (SET_ERROR(EDOM));
	return (0);
}

static int
zvol_update_volsize(uint64_t volsize, objset_t *os)
{
	dmu_tx_t *tx;
	int error;
	uint64_t txg;

	tx = dmu_tx_create(os);
	dmu_tx_hold_zap(tx, ZVOL_ZAP_OBJ, TRUE, NULL);
	dmu_tx_mark_netfree(tx);
	error = dmu_tx_assign(tx, DMU_TX_WAIT);
	if (error) {
		dmu_tx_abort(tx);
		return (error);
	}
	txg = dmu_tx_get_txg(tx);
	error = zap_update(os, ZVOL_ZAP_OBJ, "size", 8, 1, &volsize, tx);
	dmu_tx_commit(tx);
	txg_wait_synced(dmu_objset_pool(os), txg);
	if (error == 0)
		error = dmu_free_long_range(os, ZVOL_OBJ, volsize,
		    DMU_OBJECT_END);
	return (error);
}

int
zvol_set_volsize(const char *name, uint64_t volsize)
{
	objset_t *os = NULL;
	dmu_object_info_t doi;
	uint64_t readonly;
	int error;

	error = dsl_prop_get_integer(name,
	    zfs_prop_to_name(ZFS_PROP_READONLY), &readonly, NULL);
	if (error != 0)
		return (error);
	if (readonly)
		return (SET_ERROR(EROFS));
	error = dmu_objset_own(name, DMU_OST_ZVOL, B_FALSE, B_TRUE, FTAG, &os);
	if (error != 0)
		return (error);
	error = dmu_object_info(os, ZVOL_OBJ, &doi);
	if (error == 0)
		error = zvol_check_volsize(volsize, doi.doi_data_block_size);
	if (error == 0)
		error = zvol_update_volsize(volsize, os);
	dmu_objset_disown(os, B_TRUE, FTAG);
	return (error);
}

int
zvol_set_volthreading(const char *name, boolean_t val)
{
	(void) name, (void) val;
	return (0);
}

int
zvol_set_common(const char *name, zfs_prop_t prop, zprop_source_t source,
    uint64_t val)
{
	(void) name, (void) prop, (void) source, (void) val;
	return (0);
}

int
zvol_set_ro(const char *name, boolean_t val)
{
	return (zfsd_zvol_set_prop_ro(name, val));
}

boolean_t
zvol_is_zvol(const char *name)
{
	objset_t *os;
	boolean_t v = B_FALSE;

	if (dmu_objset_hold(name, FTAG, &os) == 0) {
		v = (dmu_objset_type(os) == DMU_OST_ZVOL);
		dmu_objset_rele(os, FTAG);
	}
	return (v);
}

int
zvol_suspend(const char *name, zvol_state_handle_t **zvp)
{
	objset_t *os;

	if (dmu_objset_hold(name, FTAG, &os) != 0)
		return (SET_ERROR(EINVAL));
	if (dmu_objset_type(os) != DMU_OST_ZVOL) {
		dmu_objset_rele(os, FTAG);
		return (SET_ERROR(EINVAL));
	}
	dmu_objset_rele(os, FTAG);
	zfsd_zvol_unpublish(name);
	*zvp = (zvol_state_handle_t *)kmem_strdup(name);
	return (0);
}

int
zvol_resume(zvol_state_handle_t *zv)
{
	char *name = (char *)zv;

	if (name != NULL) {
		(void) zfsd_zvol_publish(name);
		kmem_strfree(name);
	}
	return (0);
}

void *
zvol_tag(zvol_state_handle_t *zv)
{
	return (zv);
}

static void
zfsd_zvol_create_minors(const char *name)
{
	if (name == NULL || name[0] == '\0')
		return;
	if (strchr(name, '/') == NULL)
		(void) zfsd_zvol_publish_pool(name);
	else
		(void) zfsd_zvol_publish(name);
}

typedef struct zfsd_zvol_minors_arg {
	char	name[ZFS_MAX_DATASET_NAME_LEN];
} zfsd_zvol_minors_arg_t;

static void
zfsd_zvol_remove_task(void *arg)
{
	zfsd_zvol_minors_arg_t *a = arg;

	if (strchr(a->name, '/') == NULL)
		zfsd_zvol_unpublish_pool(a->name);
	else
		zfsd_zvol_unpublish(a->name);
	kmem_free(a, sizeof (*a));
}

static boolean_t
zfsd_on_txg_sync(spa_t *spa)
{
	dsl_pool_t *dp;

	if (txg_thread_is_syncing())
		return (B_TRUE);
	if (spa == NULL)
		return (B_FALSE);
	dp = spa->spa_dsl_pool;
	if (dp == NULL)
		return (B_FALSE);
	/*
	 * dsl_pool_sync_context covers the sync thread and dp_sync_taskq.
	 * The writer check covers a thread that holds the lock but is
	 * not the sync thread (should not happen; cheap).
	 */
	return (dsl_pool_sync_context(dp) ||
	    dsl_pool_config_held_writer(dp));
}

static void
zfsd_zvol_remove_minors(spa_t *spa, const char *name, boolean_t async)
{
	zfsd_zvol_minors_arg_t *a;
	taskqid_t id;
	boolean_t on_sync;

	if (name == NULL || name[0] == '\0')
		return;
	/*
	 * spa_export waits on spa_zvol_taskq after zvol_remove_minors.
	 * dsl_destroy_head_sync calls us from the txg thread: dispatch
	 * so ublk teardown is not inline in spa_sync, same as kernel
	 * zvol.c. Inline teardown calls zil_close, which txg_wait_synced
	 * while this thread still holds the config lock as writer.
	 */
	on_sync = zfsd_on_txg_sync(spa);
	if (spa != NULL && spa->spa_zvol_taskq != NULL) {
		a = kmem_alloc(sizeof (*a), KM_SLEEP);
		(void) strlcpy(a->name, name, sizeof (a->name));
		id = taskq_dispatch(spa->spa_zvol_taskq,
		    zfsd_zvol_remove_task, a, TQ_SLEEP);
		if (id != TASKQID_INVALID) {
			if (!async && !on_sync)
				taskq_wait_id(spa->spa_zvol_taskq, id);
			return;
		}
		kmem_free(a, sizeof (*a));
	}
	if (on_sync)
		return;
	if (strchr(name, '/') == NULL)
		zfsd_zvol_unpublish_pool(name);
	else
		zfsd_zvol_unpublish(name);
}

typedef struct zfsd_zvol_rename_arg {
	char	oldname[ZFS_MAX_DATASET_NAME_LEN];
	char	newname[ZFS_MAX_DATASET_NAME_LEN];
} zfsd_zvol_rename_arg_t;

static void
zfsd_zvol_rename_task(void *arg)
{
	zfsd_zvol_rename_arg_t *a = arg;

	zfsd_zvol_rename_published(a->oldname, a->newname);
	kmem_free(a, sizeof (*a));
}

static void
zfsd_zvol_rename_minors(spa_t *spa, const char *oldname, const char *newname,
    boolean_t async)
{
	zfsd_zvol_rename_arg_t *a;
	taskq_t *tq;
	taskqid_t id;
	boolean_t on_sync;

	if (oldname == NULL || oldname[0] == '\0')
		return;
	/*
	 * dsl_dataset_rename_snapshot_sync and dsl_dir_rename_sync call
	 * this from txg_sync, which already holds dp_config_rwlock as
	 * writer. publish -> dsl_prop_get / dmu_objset_own takes that
	 * lock as a reader and asserts rr_writer != curthread.
	 * Dataset rename (no '@') dies in dsl_prop_get; a snapshot dies
	 * in dmu_objset_own. Kernel zvol_rename_minors only rewrites
	 * minors that already exist, on spa_zvol_taskq.
	 *
	 * Never run the rename on this thread when it is txg_sync, and
	 * never taskq_wait here: the worker needs the reader lock.
	 * A failed dispatch drops the minor update. Aborting the daemon
	 * takes every later test with it.
	 */
	if (!zfsd_zvol_published_match(oldname))
		return;

	on_sync = zfsd_on_txg_sync(spa);
	tq = (spa != NULL) ? spa->spa_zvol_taskq : NULL;
	if (tq == NULL)
		tq = system_taskq;
	if (tq != NULL) {
		a = kmem_zalloc(sizeof (*a), KM_SLEEP);
		(void) strlcpy(a->oldname, oldname, sizeof (a->oldname));
		if (newname != NULL)
			(void) strlcpy(a->newname, newname,
			    sizeof (a->newname));
		id = taskq_dispatch(tq, zfsd_zvol_rename_task, a,
		    on_sync ? TQ_NOSLEEP : TQ_SLEEP);
		if (id != TASKQID_INVALID) {
			if (!async && !on_sync)
				taskq_wait_id(tq, id);
			return;
		}
		kmem_free(a, sizeof (*a));
	}
	if (on_sync)
		return;
	zfsd_zvol_rename_published(oldname, newname != NULL ? newname : "");
}

static void zfsd_zcp_begin(zcp_run_info_t *);
static void zfsd_zcp_end(zcp_run_info_t *);
static boolean_t zfsd_zcp_gone(zcp_run_info_t *);

void
zfsd_ioctl_init(void)
{
	extern kmutex_t zfsdev_state_lock;
	extern uint_t zfs_allow_log_key;

	mutex_init(&zfsdev_state_lock, NULL, MUTEX_DEFAULT, NULL);
	tsd_create(&zfs_allow_log_key, zfsd_allow_log_destroy);
	zfs_ioctl_init();
	zfsd_zvol_create_minors_impl = zfsd_zvol_create_minors;
	zfsd_zvol_remove_minors_impl = zfsd_zvol_remove_minors;
	zfsd_zvol_rename_minors_impl = zfsd_zvol_rename_minors;
	zfsd_zvol_release_for_destroy_impl = zfsd_zvol_release_idle;
	zfsd_set_create_fs(zfsd_create_fs);
	zfsd_zcp_on_begin = zfsd_zcp_begin;
	zfsd_zcp_on_end = zfsd_zcp_end;
	zfsd_zcp_client_gone = zfsd_zcp_gone;
}

int
zvol_init(void)
{
	return (0);
}

void
zvol_fini(void)
{
}

int
zvol_busy(void)
{
	return (0);
}

void
zfs_init(void)
{
}

void
zfs_fini(void)
{
}

void
zone_register_zoned_uid_callback(uid_t (*fn)(const char *, char *, size_t))
{
	(void) fn;
}

void
zone_unregister_zoned_uid_callback(void)
{
}

void
zfs_ereport_taskq_fini(void)
{
}

int zfsd_native;

static char g_dev_mnt[MAXPATHLEN];
static pthread_t g_dev_tid;
static int g_dev_running;
static struct fuse_session *g_zfs_se;
static char g_linkpath[MAXPATHLEN];

static __thread const zfsd_pidpin_t *zfsd_copy_pin;
static __thread fuse_req_t zfsd_zcp_req;

/* ---- ptrace / process_vm copy of the caller's zfs_cmd_t ---- */

/*
 * Pin the ioctl caller's pid at request arrival. fuse_req_ctx()->pid
 * is a number; if that process exits and the kernel recycles the pid
 * before we copy or steal an fd, a later pidfd_open/process_vm would
 * hit an unrelated task. pidfd_open here holds struct pid. process_vm
 * still takes a pid_t, so we check pidfd_send_signal(0) before and
 * after the copy and fail ESRCH if the pinned task is gone.
 *
 * fuse_req_ctx()->pid is often the calling thread's TID, not the
 * thread-group leader. pidfd_open(tid, 0) is EINVAL on kernels
 * without PIDFD_THREAD (Debian 12 6.1). Import and `zfs mount -a`
 * dispatch onto a taskq worker, so TID != TGID and the ioctl used
 * to fail EINVAL before FUSE-mounting the pool root. Resolve Tgid
 * from /proc/<tid>/status and pin that. If pidfd_open still fails,
 * keep /proc and process_vm -- do not fail the ioctl with EINVAL.
 * pidfd is required only for pidfd_getfd (send/recv).
 */

pid_t
zfsd_linux_tgid(pid_t pid)
{
#ifdef __linux__
	char path[64], buf[512];
	char *p, *end;
	int fd, n;
	long v;

	if (pid <= 0)
		return (pid);
	(void) snprintf(path, sizeof (path), "/proc/%d/status", (int)pid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return (pid);
	n = (int)read(fd, buf, sizeof (buf) - 1);
	(void) close(fd);
	if (n <= 0)
		return (pid);
	buf[n] = '\0';
	p = strstr(buf, "Tgid:");
	if (p == NULL)
		return (pid);
	p += 5;
	while (*p == ' ' || *p == '\t')
		p++;
	errno = 0;
	v = strtol(p, &end, 10);
	if (errno != 0 || end == p || v <= 0)
		return (pid);
	return ((pid_t)v);
#else
	return (pid);
#endif
}

/*
 * /proc/<pid>/stat field 22 (starttime). comm is in parens and may
 * contain spaces, so count tokens after the last ')'.
 */
static uint64_t
zfsd_pid_starttime(pid_t pid)
{
#ifdef __linux__
	char path[64], buf[1024];
	char *p, *end;
	int fd, n, i;
	unsigned long long st;

	if (pid <= 0)
		return (0);
	(void) snprintf(path, sizeof (path), "/proc/%d/stat", (int)pid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return (0);
	n = (int)read(fd, buf, sizeof (buf) - 1);
	(void) close(fd);
	if (n <= 0)
		return (0);
	buf[n] = '\0';
	p = strrchr(buf, ')');
	if (p == NULL)
		return (0);
	p++;
	for (i = 0; i < 20; i++) {
		while (*p == ' ')
			p++;
		if (*p == '\0')
			return (0);
		if (i == 19) {
			errno = 0;
			st = strtoull(p, &end, 10);
			if (errno != 0 || end == p)
				return (0);
			return ((uint64_t)st);
		}
		while (*p != '\0' && *p != ' ')
			p++;
	}
	return (0);
#else
	(void) pid;
	return (0);
#endif
}

int
zfsd_pid_alive(const zfsd_pidpin_t *pin)
{
	if (pin == NULL || pin->pid <= 0)
		return (0);
#ifdef __linux__
#if defined(__NR_pidfd_send_signal)
	if (pin->pidfd >= 0) {
		if (syscall(__NR_pidfd_send_signal, pin->pidfd, 0,
		    NULL, 0U) == 0)
			return (1);
		return (0);
	}
#endif
	if (pin->starttime != 0)
		return (zfsd_pid_starttime(pin->pid) == pin->starttime);
	return (0);
#else
	return (1);
#endif
}

int
zfsd_pid_pin(pid_t pid, zfsd_pidpin_t *pin)
{
	char path[64];
	pid_t tgid;

	memset(pin, 0, sizeof (*pin));
	pin->pid = pid;
	pin->pidfd = -1;
	pin->procfd = -1;
	if (pid <= 0)
		return (ESRCH);
#ifdef __linux__
	tgid = zfsd_linux_tgid(pid);
	pin->pid = tgid;
#if defined(__NR_pidfd_open)
	pin->pidfd = (int)syscall(__NR_pidfd_open, tgid, 0U);
	if (pin->pidfd < 0)
		pin->pidfd = -1;
	else
		(void) fcntl(pin->pidfd, F_SETFD, FD_CLOEXEC);
#endif
	(void) snprintf(path, sizeof (path), "/proc/%d", (int)tgid);
	pin->procfd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (pin->procfd < 0 && tgid != pid) {
		(void) snprintf(path, sizeof (path), "/proc/%d", (int)pid);
		pin->procfd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (pin->procfd >= 0)
			pin->pid = pid;
	}
	if (pin->procfd < 0 && pin->pidfd < 0)
		return (errno != 0 ? errno : ESRCH);
	pin->starttime = zfsd_pid_starttime(pin->pid);
	if (pin->pidfd < 0 && pin->starttime == 0) {
		if (pin->procfd >= 0)
			(void) close(pin->procfd);
		pin->procfd = -1;
		return (ESRCH);
	}
#else
	(void) path;
	(void) tgid;
#endif
	return (0);
}

void
zfsd_pid_unpin(zfsd_pidpin_t *pin)
{
	if (pin == NULL)
		return;
	if (pin->pidfd >= 0)
		(void) close(pin->pidfd);
	if (pin->procfd >= 0)
		(void) close(pin->procfd);
	pin->pidfd = -1;
	pin->procfd = -1;
}

/*
 * Copy `n` bytes between our address space and pid's at `addr`.
 * Linux: process_vm_{readv,writev} only. process_vm_writev honors the
 * target VMA protections (PROT_WRITE), so a caller cannot smash a
 * read-only mapping. Do not fall back to /proc/<pid>/mem -- pwrite
 * there as root bypasses those protections. Do not PTRACE_ATTACH:
 * the caller is blocked in FUSE ioctl, so attaching would deadlock.
 * FreeBSD: ptrace PT_IO.
 */
static int
zfsd_ptrace_copy(const zfsd_pidpin_t *pin, int wr, uint64_t addr,
    void *buf, size_t n)
{
	pid_t pid;

	if (n == 0)
		return (0);
	if (pin == NULL || pin->pid <= 0 || addr == 0 || buf == NULL ||
	    n > ZFSD_PTRACE_MAX)
		return (EFAULT);
	if (!zfsd_pid_alive(pin))
		return (ESRCH);
	pid = pin->pid;
#ifdef __linux__
	{
		struct iovec local, remote;
		ssize_t r;

		local.iov_base = buf;
		local.iov_len = n;
		remote.iov_base = (void *)(uintptr_t)addr;
		remote.iov_len = n;
		while (local.iov_len > 0) {
			if (wr)
				r = process_vm_writev(pid, &local, 1,
				    &remote, 1, 0);
			else
				r = process_vm_readv(pid, &local, 1,
				    &remote, 1, 0);
			if (r < 0)
				return (errno != 0 ? errno : EFAULT);
			if (r == 0)
				return (EFAULT);
			local.iov_base = (char *)local.iov_base + r;
			local.iov_len -= (size_t)r;
			remote.iov_base = (char *)remote.iov_base + r;
			remote.iov_len -= (size_t)r;
		}
		return (zfsd_pid_alive(pin) ? 0 : ESRCH);
	}
#elif defined(__FreeBSD__)
	{
		struct ptrace_io_desc iod;

		iod.piod_op = wr ? PIOD_WRITE_D : PIOD_READ_D;
		iod.piod_offs = (void *)(uintptr_t)addr;
		iod.piod_addr = buf;
		iod.piod_len = n;
		if (ptrace(PT_IO, pid, (caddr_t)&iod, 0) != 0)
			return (errno);
		return (iod.piod_len == n ? 0 : EFAULT);
	}
#else
	(void) pid;
	(void) wr;
	(void) addr;
	(void) buf;
	return (ENOSYS);
#endif
}

static int
zfsd_ptrace_read(const zfsd_pidpin_t *pin, uint64_t addr, void *buf, size_t n)
{
	return (zfsd_ptrace_copy(pin, 0, addr, buf, n));
}

static int
zfsd_ptrace_write(const zfsd_pidpin_t *pin, uint64_t addr, const void *buf,
    size_t n)
{
	return (zfsd_ptrace_copy(pin, 1, addr, (void *)buf, n));
}

void
zfsd_copy_begin(const zfsd_pidpin_t *pin)
{
	zfsd_copy_pin = pin;
	/* TLS: each CUSE worker has its own hook. A global would race. */
	zfsd_file_steal_hook = zfsd_file_steal;
}

void
zfsd_copy_end(void)
{
	zfsd_file_steal_hook = NULL;
	zfsd_copy_pin = NULL;
}

int
zfsd_ddi_copyin(const void *from, void *to, size_t len, int flags)
{
	const zfsd_pidpin_t *pin = zfsd_copy_pin;
	int err;

	(void) flags;
	if (from == NULL || to == NULL)
		return (-1);
	if (len == 0)
		return (0);
	if (pin == NULL) {
		(void) memcpy(to, from, len);
		return (0);
	}
	err = zfsd_ptrace_read(pin, (uint64_t)(uintptr_t)from, to, len);
	return (err != 0 ? -1 : 0);
}

int
zfsd_ddi_copyout(const void *from, void *to, size_t len, int flags)
{
	const zfsd_pidpin_t *pin = zfsd_copy_pin;
	int err;

	(void) flags;
	if (from == NULL || to == NULL)
		return (-1);
	if (len == 0)
		return (0);
	if (pin == NULL) {
		(void) memcpy(to, from, len);
		return (0);
	}
	err = zfsd_ptrace_write(pin, (uint64_t)(uintptr_t)to, from, len);
	return (err != 0 ? -1 : 0);
}

int
zfsd_copyinstr(const void *from, void *to, size_t len, size_t *done)
{
	const zfsd_pidpin_t *pin = zfsd_copy_pin;
	char *dst = to;
	size_t n, i, chunk;
	int err;

	if (from == NULL || to == NULL || len == 0)
		return (EFAULT);
	if (pin == NULL) {
		n = strnlen((const char *)from, len);
		if (n >= len)
			return (ENAMETOOLONG);
		(void) memcpy(to, from, n + 1);
		if (done != NULL)
			*done = n + 1;
		return (0);
	}
	n = 0;
	while (n < len) {
		chunk = MIN(len - n, 256);
		err = zfsd_ptrace_read(pin, (uint64_t)(uintptr_t)from + n,
		    dst + n, chunk);
		if (err != 0)
			return (EFAULT);
		for (i = 0; i < chunk; i++) {
			if (dst[n + i] == '\0') {
				if (done != NULL)
					*done = n + i + 1;
				return (0);
			}
		}
		n += chunk;
	}
	return (ENAMETOOLONG);
}

int
zfsd_file_steal(int clfd)
{
	const zfsd_pidpin_t *pin = zfsd_copy_pin;

#if defined(__linux__) && defined(__NR_pidfd_open) && defined(__NR_pidfd_getfd)
	int fd;

	if (pin == NULL || clfd < 0)
		return (-1);
	if (clfd < 0 || pin->pidfd < 0 || !zfsd_pid_alive(pin))
		return (-1);
	fd = (int)syscall(__NR_pidfd_getfd, pin->pidfd, clfd, 0U);
	if (fd < 0)
		return (-1);
	(void) fcntl(fd, F_SETFD, FD_CLOEXEC);
	return (fd);
#else
	if (pin == NULL || clfd < 0)
		return (-1);
	(void) clfd;
	return (-1);
#endif
}

static void
zfsd_zcmd_term(zfs_cmd_t *zc)
{
	zc->zc_name[sizeof (zc->zc_name) - 1] = '\0';
	zc->zc_value[sizeof (zc->zc_value) - 1] = '\0';
	zc->zc_string[sizeof (zc->zc_string) - 1] = '\0';
}

/*
 * FUSE_IOCTL_COMPAT: 32-bit ioctl on a 64-bit daemon. OpenZFS zfs_cmd_t
 * is declared 32/64-layout identical (uint64_t nested pointers, explicit
 * pad), matching the kernel's compat_ioctl passthrough. 32-bit libzfs
 * still sometimes sign-extends a pointer into those uint64_t slots;
 * strip that so copyin of nested nvlists uses a canonical userspace
 * address. Field-by-field so a later 32-bit split has one place to go.
 */
static uint64_t
zfsd_compat_uptr(uint64_t p)
{
	if (p == 0)
		return (0);
	if ((p & 0xffffffff00000000ULL) == 0xffffffff00000000ULL)
		return (p & 0xffffffffULL);
	return (p);
}

static void
zfsd_zcmd_compat_in(zfs_cmd_t *zc)
{
	zfs_cmd_t n = *zc;

	n.zc_nvlist_src = zfsd_compat_uptr(zc->zc_nvlist_src);
	n.zc_nvlist_dst = zfsd_compat_uptr(zc->zc_nvlist_dst);
	n.zc_nvlist_conf = zfsd_compat_uptr(zc->zc_nvlist_conf);
	n.zc_history = zfsd_compat_uptr(zc->zc_history);
	n.zc_share.z_exportdata = zfsd_compat_uptr(zc->zc_share.z_exportdata);
	n.zc_share.z_sharedata = zfsd_compat_uptr(zc->zc_share.z_sharedata);
	*zc = n;
}

/* ---- /dev/zfs CUSE character device ---- */

/*
 * Linux zfsdev_ioctl: copyin zc, zfsdev_ioctl_common, copyout zc.
 * Nested pointers stay in the caller's address space; ddi_copyin
 * (cmd/zfsd/include/sys/sunddi.h) copies them via the TLS pin.
 */
static int
zfsd_dev_ioctl_pid(const zfsd_pidpin_t *pin, unsigned int cmd, void *arg,
    int compat)
{
	zfs_cmd_t zc;
	uint64_t argp;
	int err, werr;

	char rename_old[ZFS_MAX_DATASET_NAME_LEN];
	char rename_new[ZFS_MAX_DATASET_NAME_LEN];
	boolean_t is_rename = B_FALSE;

	if (pin == NULL || pin->pid <= 0 || arg == NULL)
		return (EFAULT);

	zfsd_tunables_refresh();
	cmd = zfsd_ioc_canon(cmd);
	argp = (uint64_t)(uintptr_t)arg;
	if (compat)
		argp = zfsd_compat_uptr(argp);
	if (argp == 0)
		return (EFAULT);

	zfsd_copy_begin(pin);
	err = zfsd_ddi_copyin((void *)(uintptr_t)argp, &zc, sizeof (zc), 0);
	if (err != 0) {
		zfsd_copy_end();
		return (EFAULT);
	}
	zfsd_zcmd_term(&zc);
	if (compat)
		zfsd_zcmd_compat_in(&zc);
	/*
	 * umount(8) and a parent MNT_DETACH drop the kernel mount
	 * without an unmount ioctl. The zfsvfs hold then makes the
	 * next mount EBUSY and pool destroy "pool is busy".
	 */
	if (cmd == ZFS_IOC_POOL_DESTROY || cmd == ZFS_IOC_POOL_EXPORT ||
	    cmd == ZFS_IOC_DESTROY)
		zfsd_zpl_reap_detached();
	if (cmd == ZFS_IOC_RENAME) {
		(void) strlcpy(rename_old, zc.zc_name, sizeof (rename_old));
		(void) strlcpy(rename_new, zc.zc_value, sizeof (rename_new));
		is_rename = B_TRUE;
	}
	err = (int)zfsdev_ioctl_common(cmd - ZFS_IOC_FIRST, &zc, 0);
	if (err == 0 && is_rename)
		zfsd_zpl_note_rename(rename_old, rename_new);
	werr = zfsd_ddi_copyout(&zc, (void *)(uintptr_t)argp, sizeof (zc), 0);
	zfsd_copy_end();
	if (err == 0 && werr != 0)
		err = EFAULT;
	return (err);
}

static void
zfsd_crset_from_ctx(const zfsd_pidpin_t *pin, uid_t uid, gid_t gid)
{
	gid_t *groups = NULL;
	int ng = 0, cap = 0;

#ifdef __linux__
	if (pin != NULL && pin->procfd >= 0) {
		FILE *fp;
		char *line = NULL;
		size_t linesz = 0;
		int fd;

		fd = openat(pin->procfd, "status", O_RDONLY | O_CLOEXEC);
		fp = (fd >= 0) ? fdopen(fd, "r") : NULL;
		if (fp == NULL) {
			if (fd >= 0)
				(void) close(fd);
		} else {
			while (getline(&line, &linesz, fp) > 0) {
				if (strncmp(line, "Groups:", 7) != 0)
					continue;
				{
					char *p = line + 7;
					char *end;
					unsigned long g;

					while (*p != '\0') {
						while (*p == ' ' || *p == '\t')
							p++;
						if (*p < '0' || *p > '9')
							break;
						g = strtoul(p, &end, 10);
						if (end == p)
							break;
						if (ng == cap) {
							int ncap = cap ?
							    cap * 2 : 64;
							gid_t *n;

							n = realloc(groups,
							    (size_t)ncap *
							    sizeof (gid_t));
							if (n == NULL)
								break;
							groups = n;
							cap = ncap;
						}
						groups[ng++] = (gid_t)g;
						p = end;
					}
				}
				break;
			}
			free(line);
			(void) fclose(fp);
		}
	}
#else
	(void) pin;
#endif
	(void) zfsd_crset(uid, gid, ng, groups);
	free(groups);
}

/*
 * Signals whose default action is to kill the caller. The kernel
 * cancels a sync channel program when any such signal wakes
 * cv_wait_sig on the ioctl thread. That thread is the client; here
 * it is a daemon worker, so issig() never fires.
 */
#define	ZFSD_ZCP_FATAL_SIGS	( \
	(1ULL << (SIGHUP - 1)) | (1ULL << (SIGINT - 1)) | \
	(1ULL << (SIGQUIT - 1)) | (1ULL << (SIGKILL - 1)) | \
	(1ULL << (SIGPIPE - 1)) | (1ULL << (SIGALRM - 1)) | \
	(1ULL << (SIGTERM - 1)) | (1ULL << (SIGUSR1 - 1)) | \
	(1ULL << (SIGUSR2 - 1)))

static uint64_t
zfsd_status_hex(const char *buf, const char *key)
{
	const char *p;
	uint64_t v = 0;
	int n = 0;

	p = strstr(buf, key);
	if (p == NULL)
		return (0);
	p += strlen(key);
	while (*p == ' ' || *p == '\t' || *p == ':')
		p++;
	for (; isxdigit((unsigned char)*p) && n < 16; p++, n++) {
		unsigned char c = (unsigned char)*p;

		v <<= 4;
		if (c <= '9')
			v |= (uint64_t)(c - '0');
		else if (c >= 'a')
			v |= (uint64_t)(c - 'a' + 10);
		else
			v |= (uint64_t)(c - 'A' + 10);
	}
	return (v);
}

/*
 * libfuse holds the request lock across this callback, and also
 * across fuse_req_interrupt_func(), so clearing the hook in
 * zfsd_zcp_end cannot race a call into a dead runinfo. Do not
 * take a lock or do I/O here.
 */
static void
zfsd_zcp_intr(fuse_req_t req, void *data)
{
	zcp_run_info_t *ri = data;

	(void) req;
	if (ri != NULL)
		ri->zri_canceled = B_TRUE;
}

static void
zfsd_zcp_begin(zcp_run_info_t *ri)
{
	const zfsd_pidpin_t *pin = zfsd_copy_pin;
	fuse_req_t req = zfsd_zcp_req;

	ri->zri_client_tgid = 0;
	ri->zri_client_start = 0;
	if (pin != NULL && pin->pid > 0) {
		ri->zri_client_tgid = pin->pid;
		ri->zri_client_start = pin->starttime;
	}
	if (req != NULL)
		fuse_req_interrupt_func(req, zfsd_zcp_intr, ri);
}

static void
zfsd_zcp_end(zcp_run_info_t *ri)
{
	fuse_req_t req = zfsd_zcp_req;

	(void) ri;
	if (req != NULL)
		fuse_req_interrupt_func(req, NULL, NULL);
}

static boolean_t
zfsd_zcp_gone(zcp_run_info_t *ri)
{
	char path[64];
	char buf[2048];
	char *rp;
	int fd, n;
	hrtime_t now;
	pid_t tgid;
	uint64_t pend, blk, st;

	if (ri->zri_canceled)
		return (B_TRUE);
	tgid = ri->zri_client_tgid;
	if (tgid <= 0)
		return (B_FALSE);
	now = gethrtime();
	if (ri->zri_cancel_check != 0 &&
	    now - (hrtime_t)ri->zri_cancel_check < MSEC2NSEC(50))
		return (B_FALSE);
	ri->zri_cancel_check = (uint64_t)now;

	(void) snprintf(path, sizeof (path), "/proc/%d/stat", (int)tgid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return (B_TRUE);
	n = (int)read(fd, buf, sizeof (buf) - 1);
	(void) close(fd);
	if (n <= 0)
		return (B_TRUE);
	buf[n] = '\0';
	rp = strrchr(buf, ')');
	if (rp != NULL && rp[1] == ' ' && (rp[2] == 'Z' || rp[2] == 'X'))
		return (B_TRUE);
	if (ri->zri_client_start != 0) {
		st = zfsd_pid_starttime(tgid);
		if (st != 0 && st != ri->zri_client_start)
			return (B_TRUE);
	}

	(void) snprintf(path, sizeof (path), "/proc/%d/status", (int)tgid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return (B_TRUE);
	n = (int)read(fd, buf, sizeof (buf) - 1);
	(void) close(fd);
	if (n <= 0)
		return (B_FALSE);
	buf[n] = '\0';
	pend = zfsd_status_hex(buf, "SigPnd");
	pend |= zfsd_status_hex(buf, "ShdPnd");
	blk = zfsd_status_hex(buf, "SigBlk");
	if ((pend & ~blk & ZFSD_ZCP_FATAL_SIGS) != 0)
		return (B_TRUE);
	return (B_FALSE);
}

static void
zfs_cuse_open(fuse_req_t req, struct fuse_file_info *fi)
{
	const struct fuse_ctx *ctx = fuse_req_ctx(req);
	zfsd_zs_t *zs;

	zs = zfsd_zs_open(ctx != NULL ? ctx->pid : 0,
	    ctx != NULL ? ctx->uid : 0,
	    ctx != NULL ? ctx->gid : 0);
	if (zs == NULL) {
		fuse_reply_err(req, ENOMEM);
		return;
	}
	fi->direct_io = 1;
	fi->nonseekable = 1;
	fi->fh = (uint64_t)(uintptr_t)zs;
	fuse_reply_open(req, fi);
}

static void
zfs_cuse_release(fuse_req_t req, struct fuse_file_info *fi)
{
	zfsd_zs_release((zfsd_zs_t *)(uintptr_t)fi->fh);
	fi->fh = 0;
	fuse_reply_err(req, 0);
}

static void
zfs_cuse_ioctl(fuse_req_t req, int cmd, void *arg,
    struct fuse_file_info *fi, unsigned flags,
    const void *in_buf, size_t in_bufsz, size_t out_bufsz)
{
	const struct fuse_ctx *ctx = fuse_req_ctx(req);
	zfsd_zs_t *zs = (zfsd_zs_t *)(uintptr_t)fi->fh;
	zfsd_pidpin_t pin;
	int err, compat;

	(void) in_buf;
	(void) in_bufsz;
	(void) out_bufsz;
	if (ctx == NULL || ctx->pid <= 0) {
		fuse_reply_err(req, EFAULT);
		return;
	}
	compat = (flags & FUSE_IOCTL_COMPAT) ? 1 : 0;
	err = zfsd_pid_pin(ctx->pid, &pin);
	if (err != 0) {
		fuse_reply_err(req, err);
		return;
	}
	zfsd_crset_from_ctx(&pin, ctx->uid, ctx->gid);
	zfsd_zs_begin(zs, pin.pid);
	if ((unsigned int)cmd == ZFS_IOC_POOL_SYNC)
		zfsd_zvol_flush_bdevs();
	zfsd_zcp_req = req;
	err = zfsd_dev_ioctl_pid(&pin, (unsigned int)cmd, arg, compat);
	zfsd_zcp_req = NULL;
	zfsd_zs_end(zs);
	zfsd_crclr();
	zfsd_pid_unpin(&pin);
	/*
	 * libfuse rejects fuse header errors <= -1000 and substitutes
	 * ERANGE ("Numerical result out of range"). ZFS_ERR_* starts
	 * at 1024 (ZFS_ERR_EXPORT_IN_PROGRESS is 1038). The kernel
	 * ioctl path returns outarg.result when the header error is 0,
	 * and glibc turns a result of -1038 into errno 1038.
	 */
	if (err >= 1000)
		fuse_reply_ioctl(req, -err, NULL, 0);
	else if (err != 0)
		fuse_reply_err(req, err);
	else
		fuse_reply_ioctl(req, 0, NULL, 0);
}

static const struct cuse_lowlevel_ops zfs_cuse_ops = {
	.open		= zfs_cuse_open,
	.release	= zfs_cuse_release,
	.ioctl		= zfs_cuse_ioctl,
};

/* FUSE_USE_VERSION 31 hides the 3.12 config form of fuse_loop_mt. */
int fuse_loop_mt_312(struct fuse *, struct fuse_loop_config *);
int fuse_session_loop_mt_312(struct fuse_session *, struct fuse_loop_config *);

static void
zfsd_session_loop_mt(struct fuse_session *se)
{
	struct fuse_loop_config *cfg = fuse_loop_cfg_create();

	if (cfg == NULL) {
		(void) fuse_session_loop_mt(se, 0);
		return;
	}
	fuse_loop_cfg_set_max_threads(cfg, ZFSD_FUSE_MAX_THREADS);
	fuse_loop_cfg_set_idle_threads(cfg, 2);
	(void) fuse_session_loop_mt_312(se, cfg);
	fuse_loop_cfg_destroy(cfg);
}

static void *
cuse_loop(void *arg)
{
	struct fuse_session *se = arg;

	/*
	 * fuse_session_loop() serializes every ioctl on this CUSE node.
	 * Per-open zfsd_zs_t bookkeeping is already thread-local, so
	 * run a worker pool. Cap threads: glibc's 8MiB stacks plus an
	 * unbounded pool OOMs a 2GiB overcommit=2 guest.
	 */
	zfsd_session_loop_mt(se);
	return (NULL);
}

static int
zfsd_sharepath_ok(const char *mnt)
{
	if (mnt == NULL || mnt[0] != '/')
		return (0);
	if (strpbrk(mnt, "\n\r") != NULL)
		return (0);
	return (1);
}

static int
zfsd_share_opts_ok(const char *s)
{
	const char *p;

	if (s == NULL || s[0] == '\0')
		return (1);
	for (p = s; *p != '\0'; p++) {
		if ((*p >= 'a' && *p <= 'z') ||
		    (*p >= 'A' && *p <= 'Z') ||
		    (*p >= '0' && *p <= '9') ||
		    *p == '=' || *p == ',' || *p == ':' ||
		    *p == '.' || *p == '*' || *p == '@' ||
		    *p == '/' || *p == '_' || *p == '-' ||
		    *p == '%')
			continue;
		return (0);
	}
	return (1);
}

static const char *
zfsd_share_opts(const zfs_cmd_t *zc)
{
	size_t mlen, rlen;
	const char *rest;

	if (zc->zc_string[0] != '\0')
		return (zc->zc_string);
	mlen = strnlen(zc->zc_value, sizeof (zc->zc_value));
	if (mlen + 1 >= sizeof (zc->zc_value))
		return ("");
	rest = zc->zc_value + mlen + 1;
	rlen = sizeof (zc->zc_value) - mlen - 1;
	if (strnlen(rest, rlen) >= rlen)
		return ("");
	return (rest);
}

static int
zfsd_share_enable(const char *ds, const char *mnt, const char *opts, int proto)
{
	if (!zfsd_sharepath_ok(mnt) || !zfsd_share_opts_ok(opts))
		return (EINVAL);
	if (proto == 0)
		return (zfsd_nfs_enable(mnt, opts));
	if (proto == 1)
		return (zfsd_smb_enable(ds, mnt, opts));
	return (EINVAL);
}

static int
zfsd_share_disable(const char *ds, const char *mnt, int proto)
{
	if (!zfsd_sharepath_ok(mnt))
		return (EINVAL);
	if (proto == 0)
		return (zfsd_nfs_disable(mnt));
	if (proto == 1)
		return (zfsd_smb_disable(ds, mnt));
	return (EINVAL);
}

static int
zfsd_share_commit(int proto)
{
	if (proto == 0)
		return (zfsd_nfs_exportfs());
	if (proto == 1)
		return (0);
	return (EINVAL);
}

static int
zfsd_share_truncate(int proto)
{
	if (proto == 0)
		return (zfsd_nfs_truncate());
	if (proto == 1)
		return (0);
	return (EINVAL);
}

static int
zfsd_ioc_share(zfs_cmd_t *zc, unsigned int cmd)
{
#ifndef __linux__
	(void) zc;
	(void) cmd;
	return (ENOTSUP);
#else
	char dsbuf[ZFS_MAX_DATASET_NAME_LEN];
	const char *ds, *mnt, *opts;
	uint64_t proto, act;
	int err;

	proto = zc->zc_cookie;
	act = zc->zc_perm_action;
	if (proto > 1)
		return (EINVAL);

	if (cmd == ZFSD_IOC_SHARE && act == ZFSD_SHARE_COMMIT) {
		if (secpolicy_zfs(CRED()) != 0)
			return (EPERM);
		return (zfsd_share_commit((int)proto));
	}
	if (cmd == ZFSD_IOC_SHARE && act == ZFSD_SHARE_TRUNCATE) {
		if (secpolicy_zfs(CRED()) != 0)
			return (EPERM);
		return (zfsd_share_truncate((int)proto));
	}

	ds = zc->zc_name[0] ? zc->zc_name : NULL;
	if (ds != NULL && entity_namecheck(ds, NULL, NULL) != 0)
		return (EINVAL);
	mnt = zc->zc_value[0] ? zc->zc_value : NULL;
	opts = zfsd_share_opts(zc);
	if (ds == NULL && mnt != NULL &&
	    zfsd_zpl_ds_from_mnt(mnt, dsbuf, sizeof (dsbuf)) == 0)
		ds = dsbuf;
	if (ds != NULL)
		err = zfsd_allow_share(ds);
	else
		err = secpolicy_zfs(CRED());
	if (err != 0)
		return (err);
	if (mnt == NULL)
		return (EINVAL);
	/*
	 * mnt is caller-controlled (zc_value). Bind it to the live
	 * FUSE mount of ds so a share delegation cannot export /etc.
	 */
	if (ds != NULL) {
		char live[MAXPATHLEN];

		err = zfsd_zpl_mntpath(ds, live, sizeof (live));
		if (err != 0)
			return (err);
		if (strcmp(mnt, live) != 0)
			return (EPERM);
	} else if (secpolicy_zfs(CRED()) != 0) {
		return (EPERM);
	}
	if (cmd == ZFSD_IOC_UNSHARE)
		return (zfsd_share_disable(ds, mnt, (int)proto));
	return (zfsd_share_enable(ds, mnt, opts, (int)proto));
#endif
}

int
zfs_ioc_zfsd_mount(zfs_cmd_t *zc)
{
	const char *mnt, *opts;

	if (zc->zc_name[0] == '\0' || zc->zc_value[0] == '\0')
		return (SET_ERROR(EINVAL));
	if (entity_namecheck(zc->zc_name, NULL, NULL) != 0)
		return (SET_ERROR(EINVAL));
	mnt = zc->zc_value;
	opts = mnt + strlen(mnt) + 1;
	if (opts >= zc->zc_value + sizeof (zc->zc_value))
		opts = "";
	return (zfsd_zpl_mount(zc->zc_name, mnt, zc->zc_cookie, opts));
}

int
zfs_ioc_zfsd_unmount(zfs_cmd_t *zc)
{
	char dsbuf[ZFS_MAX_DATASET_NAME_LEN];
	const char *dsname;
	int err;

	dsname = zc->zc_name[0] ? zc->zc_name : NULL;
	if (dsname != NULL && entity_namecheck(dsname, NULL, NULL) != 0)
		return (SET_ERROR(EINVAL));
	if (dsname == NULL && zc->zc_value[0] != '\0' &&
	    zfsd_zpl_ds_from_mnt(zc->zc_value, dsbuf, sizeof (dsbuf)) == 0)
		dsname = dsbuf;
	if (dsname != NULL)
		err = zfsd_allow_mount(dsname);
	else
		err = secpolicy_zfs(CRED());
	if (err != 0)
		return (err);
	return (zfsd_zpl_unmount(dsname != NULL ? dsname : zc->zc_name,
	    zc->zc_value[0] ? zc->zc_value : NULL, zc->zc_cookie));
}

int
zfs_ioc_zfsd_share(zfs_cmd_t *zc)
{
	return (zfsd_ioc_share(zc, ZFSD_IOC_SHARE));
}

int
zfs_ioc_zfsd_unshare(zfs_cmd_t *zc)
{
	return (zfsd_ioc_share(zc, ZFSD_IOC_UNSHARE));
}

static struct fuse_session *
zfsd_cuse_session(const char *devname, const struct cuse_lowlevel_ops *ops,
    void *ud)
{
	char info[MAXPATHLEN];
	const char *infoargv[1];
	struct cuse_info ci;
	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
	struct fuse_session *se;
	int mt = 0;

	(void) snprintf(info, sizeof (info), "DEVNAME=%s", devname);
	infoargv[0] = info;
	memset(&ci, 0, sizeof (ci));
	ci.dev_major = 0;
	ci.dev_minor = 0;
	ci.dev_info_argc = 1;
	ci.dev_info_argv = infoargv;
	ci.flags = CUSE_UNRESTRICTED_IOCTL;

	(void) fuse_opt_add_arg(&args, "zfsd-cuse");
	(void) fuse_opt_add_arg(&args, "-f");
	se = cuse_lowlevel_setup(args.argc, args.argv, &ci, ops, &mt, ud);
	fuse_opt_free_args(&args);
	return (se);
}

int
zfsd_dev_start(const char *rundir, int native)
{
	const char *devname;
	const char *linkpath = native ? ZFS_DEV : ZFS_DEV_FUSE;
	int tries;

#ifndef __linux__
	(void) rundir;
	(void) native;
	(void) fprintf(stderr,
	    "zfsd: CUSE /dev/zfs and zvol devices are Linux-only "
	    "(no /dev/cuse on this platform)\n");
	return (-1);
#endif

	if (native) {
		devname = "zfs";
	} else {
		const char *slash = strrchr(ZFS_DEV_FUSE, '/');
		devname = (slash != NULL) ? slash + 1 : ZFS_DEV_FUSE;
	}

	zfsd_onexit_fd_hold_impl = zfsd_onexit_fd_hold;
	zfsd_onexit_fd_rele_impl = zfsd_onexit_fd_rele;
	zfsd_onexit_add_cb_impl = zfsd_onexit_add_cb;

	zfsd_native = native;
	(void) snprintf(g_dev_mnt, sizeof (g_dev_mnt), "%s/dev", rundir);
	(void) zfsd_mkdirs(g_dev_mnt, 0755);
	(void) snprintf(g_linkpath, sizeof (g_linkpath), "%s", linkpath);

	/* Leftover FUSE symlink or stale node -- CUSE will recreate a chrdev. */
#ifdef __linux__
	(void) umount2(g_dev_mnt, MNT_DETACH);
#endif
	(void) unlink(linkpath);

	g_zfs_se = zfsd_cuse_session(devname, &zfs_cuse_ops, NULL);
	if (g_zfs_se == NULL) {
		(void) fprintf(stderr,
		    "zfsd: CUSE setup for /dev/%s failed (is /dev/cuse there?)\n",
		    devname);
		return (-1);
	}
	g_dev_running = 1;
	if (pthread_create(&g_dev_tid, NULL, cuse_loop, g_zfs_se) != 0) {
		cuse_lowlevel_teardown(g_zfs_se);
		g_zfs_se = NULL;
		g_dev_running = 0;
		zfsd_onexit_fd_hold_impl = NULL;
		zfsd_onexit_fd_rele_impl = NULL;
		zfsd_onexit_add_cb_impl = NULL;
		return (-1);
	}
	for (tries = 50; tries && access(linkpath, F_OK) != 0; tries--)
		usleep(20000);
	if (access(linkpath, F_OK) != 0) {
		(void) fprintf(stderr, "zfsd: /dev/%s did not appear\n",
		    devname);
		fuse_session_exit(g_zfs_se);
		(void) pthread_join(g_dev_tid, NULL);
		g_dev_running = 0;
		cuse_lowlevel_teardown(g_zfs_se);
		g_zfs_se = NULL;
		zfsd_onexit_fd_hold_impl = NULL;
		zfsd_onexit_fd_rele_impl = NULL;
		zfsd_onexit_add_cb_impl = NULL;
		return (-1);
	}
	/*
	 * 0666 is deliberate. Kernel /dev/zfs is often 0600/0660, but
	 * zfsd still policy-checks every ioctl against the caller's
	 * uid (root, or zfs allow). Delegated non-root clients must be
	 * able to open the node; group-disk is not enough for zfs allow.
	 */
	(void) chmod(linkpath, 0666);
	{
		struct stat st;
		if (stat(linkpath, &st) == 0 && !S_ISCHR(st.st_mode)) {
			(void) fprintf(stderr,
			    "zfsd: %s is not a character device (mode 0%o)\n",
			    linkpath, (int)st.st_mode);
			fuse_session_exit(g_zfs_se);
			(void) pthread_join(g_dev_tid, NULL);
			g_dev_running = 0;
			cuse_lowlevel_teardown(g_zfs_se);
			g_zfs_se = NULL;
			zfsd_onexit_fd_hold_impl = NULL;
			zfsd_onexit_fd_rele_impl = NULL;
			zfsd_onexit_add_cb_impl = NULL;
			return (-1);
		}
	}
	(void) fprintf(stderr, "zfsd: published CUSE chrdev %s\n", linkpath);
	zfsd_zpl_workers_start();
	zfsd_ctldir_start();
	return (0);
}

void
zfsd_dev_stop(void)
{
	zfsd_ctldir_stop();
	zfsd_zpl_workers_stop();
	/*
	 * Stop CUSE workers before freeing per-open state. An ioctl
	 * worker may still hold zfsd_zs_t via fi->fh until the session
	 * has joined.
	 */
	if (g_zfs_se)
		fuse_session_exit(g_zfs_se);
	if (g_dev_running) {
		(void) pthread_join(g_dev_tid, NULL);
		g_dev_running = 0;
	}
	zfsd_zvol_unpublish_pool(NULL);
	zfsd_zvol_ctrl_fini();
	zfsd_zs_drain_all();
	zfsd_onexit_fd_hold_impl = NULL;
	zfsd_onexit_fd_rele_impl = NULL;
	zfsd_onexit_add_cb_impl = NULL;
	if (g_zfs_se) {
		cuse_lowlevel_teardown(g_zfs_se);
		g_zfs_se = NULL;
	}
	(void) unlink(zfsd_native ? ZFS_DEV : ZFS_DEV_FUSE);
}
