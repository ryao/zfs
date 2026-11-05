// SPDX-License-Identifier: CDDL-1.0
/*
 * Per-open /dev/zfs client state and onexit callbacks. Kernel
 * zfsdev_open creates a zfsdev_state with an onexit list; close
 * runs the callbacks. History (zfs_allow_log_key) is stored here,
 * not in pthread TLS -- CUSE workers are reused across clients.
 */

#ifndef _GNU_SOURCE
#define	_GNU_SOURCE
#endif
#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/fs/zfs.h>
#include <sys/zfs_file.h>
#include <sys/zfs_onexit.h>
#include <sys/zfsd.h>
#include "zfsd_impl.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif

typedef struct zfsd_onexit_act {
	struct zfsd_onexit_act	*next;
	void			(*func)(void *);
	void			*data;
} zfsd_onexit_act_t;

typedef struct zfsd_zs {
	struct zfsd_zs		*next;
	minor_t			minor;
	pid_t			pid;
	uid_t			uid;
	gid_t			gid;
	int			fd;		/* client fd, -1 until known */
	int			busy;
	int			closed;
	char			*allow_log;	/* pool name, or NULL */
	zfsd_onexit_act_t	*actions;
} zfsd_zs_t;

static pthread_mutex_t g_zs_lock = PTHREAD_MUTEX_INITIALIZER;
static zfsd_zs_t *g_zs_list;
static minor_t g_zs_last_minor;
static __thread zfsd_zs_t *zfsd_req_zs;
static __thread pid_t zfsd_req_pid;

static int zfsd_fd_is_zfsdev(pid_t pid, int fd);

/*
 * Native and compat ioctl numbers. 32-bit userland on a 64-bit
 * kernel reports the compat nr in /proc/<pid>/syscall (54 on
 * x86_64/ia32, not 16). Unknown ABIs fail closed -- do not treat
 * arg0 of an arbitrary syscall as a file descriptor.
 */
static int
zfsd_syscall_is_ioctl(long nr)
{
#if defined(__x86_64__)
	return (nr == 16 || nr == 54);
#elif defined(__i386__)
	return (nr == 54);
#elif defined(__aarch64__)
	return (nr == 29 || nr == 54);
#elif defined(__arm__)
	return (nr == 54);
#elif defined(__riscv) || defined(__loongarch__)
	return (nr == 29);
#elif defined(__powerpc__) || defined(__s390__) || defined(__sparc__)
	return (nr == 54);
#else
	(void) nr;
	return (0);
#endif
}

static int
zfsd_pid_ioctl_fd(pid_t pid)
{
#ifdef __linux__
	char path[64], buf[256];
	FILE *fp;
	long nr = -1;
	unsigned long fd = 0;
	int n;

	if (pid <= 0)
		return (-1);
	(void) snprintf(path, sizeof (path), "/proc/%d/syscall", (int)pid);
	fp = fopen(path, "r");
	if (fp == NULL)
		return (-1);
	if (fgets(buf, sizeof (buf), fp) == NULL) {
		(void) fclose(fp);
		return (-1);
	}
	(void) fclose(fp);
	if (strncmp(buf, "running", 7) == 0)
		return (-1);
	n = sscanf(buf, "%ld %lx", &nr, &fd);
	if (n < 2)
		return (-1);
	if (!zfsd_syscall_is_ioctl(nr))
		return (-1);
	if (fd > 0x100000UL)
		return (-1);
	if (!zfsd_fd_is_zfsdev(pid, (int)fd))
		return (-1);
	return ((int)fd);
#else
	(void) pid;
	return (-1);
#endif
}

static int
zfsd_fd_is_zfsdev(pid_t pid, int fd)
{
#ifdef __linux__
	char path[64], link[MAXPATHLEN];
	ssize_t n;

	if (pid <= 0 || fd < 0)
		return (0);
	(void) snprintf(path, sizeof (path), "/proc/%d/fd/%d", (int)pid, fd);
	n = readlink(path, link, sizeof (link) - 1);
	if (n <= 0)
		return (0);
	link[n] = '\0';
	return (strcmp(link, ZFS_DEV) == 0 || strcmp(link, ZFS_DEV_FUSE) == 0);
#else
	(void) pid;
	(void) fd;
	return (0);
#endif
}

static minor_t
zfsd_zs_alloc_minor(void)
{
	minor_t m, start;
	unsigned checked = 0;

	/* caller holds g_zs_lock */
	start = g_zs_last_minor;
	m = start;
	do {
		zfsd_zs_t *p;
		int used = 0;

		m++;
		if (m == 0)
			m = 1;
		if (++checked > 65536)
			return (0);
		for (p = g_zs_list; p != NULL; p = p->next) {
			if (p->minor == m) {
				used = 1;
				break;
			}
		}
		if (!used) {
			g_zs_last_minor = m;
			return (m);
		}
	} while (m != start);
	return (0);
}

static void
zfsd_zs_destroy(zfsd_zs_t *zs)
{
	zfsd_onexit_act_t *ap;

	if (zs == NULL)
		return;
	while ((ap = zs->actions) != NULL) {
		zs->actions = ap->next;
		if (ap->func != NULL)
			ap->func(ap->data);
		free(ap);
	}
	free(zs->allow_log);
	free(zs);
}

static void
zfsd_zs_unlink_locked(zfsd_zs_t *zs)
{
	zfsd_zs_t **pp;

	for (pp = &g_zs_list; *pp != NULL; pp = &(*pp)->next) {
		if (*pp == zs) {
			*pp = zs->next;
			zs->next = NULL;
			return;
		}
	}
}

zfsd_zs_t *
zfsd_zs_open(pid_t pid, uid_t uid, gid_t gid)
{
	zfsd_zs_t *zs;
	minor_t m;

	zs = calloc(1, sizeof (*zs));
	if (zs == NULL)
		return (NULL);
	zs->pid = pid;
	zs->uid = uid;
	zs->gid = gid;
	zs->fd = -1;
	pthread_mutex_lock(&g_zs_lock);
	m = zfsd_zs_alloc_minor();
	if (m == 0) {
		pthread_mutex_unlock(&g_zs_lock);
		free(zs);
		return (NULL);
	}
	zs->minor = m;
	zs->next = g_zs_list;
	g_zs_list = zs;
	pthread_mutex_unlock(&g_zs_lock);
	return (zs);
}

void
zfsd_zs_release(zfsd_zs_t *zs)
{
	int fire = 0;

	if (zs == NULL)
		return;
	pthread_mutex_lock(&g_zs_lock);
	if (zs->busy > 0) {
		zs->closed = 1;
	} else {
		zfsd_zs_unlink_locked(zs);
		fire = 1;
	}
	pthread_mutex_unlock(&g_zs_lock);
	if (fire)
		zfsd_zs_destroy(zs);
}

void
zfsd_zs_begin(zfsd_zs_t *zs, pid_t pid)
{
	int fd;

	/*
	 * Parse /proc/<pid>/syscall before taking g_zs_lock -- it is a
	 * slow path. Then publish busy/pid/fd under the lock in one
	 * critical section. fuse_session_loop_mt can run two ioctls on
	 * the same open at once; zfsd_onexit_fd_hold() reads zs->fd
	 * while holding this lock. FUSE holds the file for the ioctl
	 * request, so RELEASE cannot free zs during the parse.
	 */
	fd = zfsd_pid_ioctl_fd(pid);
	pthread_mutex_lock(&g_zs_lock);
	if (zs != NULL) {
		zs->busy++;
		if (pid > 0)
			zs->pid = pid;
		if (fd >= 0)
			zs->fd = fd;
	}
	pthread_mutex_unlock(&g_zs_lock);
	zfsd_req_zs = zs;
	zfsd_req_pid = pid;
}

void
zfsd_zs_end(zfsd_zs_t *zs)
{
	int fire = 0;

	zfsd_req_zs = NULL;
	zfsd_req_pid = 0;
	if (zs == NULL)
		return;
	pthread_mutex_lock(&g_zs_lock);
	if (zs->busy > 0)
		zs->busy--;
	if (zs->closed && zs->busy == 0) {
		zfsd_zs_unlink_locked(zs);
		fire = 1;
	}
	pthread_mutex_unlock(&g_zs_lock);
	if (fire)
		zfsd_zs_destroy(zs);
}

void
zfsd_zs_drain_all(void)
{
	zfsd_zs_t *zs;
	int busy;

	for (;;) {
		busy = 0;
		pthread_mutex_lock(&g_zs_lock);
		for (zs = g_zs_list; zs != NULL; zs = zs->next) {
			if (zs->busy > 0)
				busy = 1;
		}
		if (!busy)
			break;
		pthread_mutex_unlock(&g_zs_lock);
		usleep(1000);
	}
	zs = g_zs_list;
	g_zs_list = NULL;
	pthread_mutex_unlock(&g_zs_lock);
	while (zs != NULL) {
		zfsd_zs_t *n = zs->next;
		zfsd_zs_destroy(zs);
		zs = n;
	}
}

/*
 * Match a client's cleanup_fd to a zfsd_zs_t. The kernel looks up the
 * file* for that fd in the calling process. We have the CUSE open
 * (zfsd_req_zs) and any fd numbers captured from /proc/<pid>/syscall
 * on earlier ioctls.
 *
 * Known limitation: a process with two /dev/zfs fds that have never
 * issued an ioctl (both zs->fd == -1) cannot be disambiguated. zfs
 * hold -t then returns EBADF. The unique-unmatched fallback covers
 * the common single-handle case.
 */
zfs_file_t *
zfsd_onexit_fd_hold(int fd, minor_t *minorp)
{
	zfsd_zs_t *zs, *unmatched = NULL;
	int n_unmatched = 0;
	pid_t pid = zfsd_req_pid;

	if (minorp == NULL)
		return (NULL);
	*minorp = 0;
	if (fd < 0)
		return (NULL);

	pthread_mutex_lock(&g_zs_lock);
	if (zfsd_req_zs != NULL && zfsd_req_zs->fd == fd) {
		*minorp = zfsd_req_zs->minor;
		zs = zfsd_req_zs;
		pthread_mutex_unlock(&g_zs_lock);
		return ((zfs_file_t *)zs);
	}
	for (zs = g_zs_list; zs != NULL; zs = zs->next) {
		if (pid > 0 && zs->pid != pid)
			continue;
		if (zs->fd == fd) {
			*minorp = zs->minor;
			pthread_mutex_unlock(&g_zs_lock);
			return ((zfs_file_t *)zs);
		}
		if (zs->fd < 0) {
			unmatched = zs;
			n_unmatched++;
		}
	}
	if (n_unmatched == 1 && unmatched != NULL &&
	    zfsd_fd_is_zfsdev(pid, fd)) {
		unmatched->fd = fd;
		*minorp = unmatched->minor;
		pthread_mutex_unlock(&g_zs_lock);
		return ((zfs_file_t *)unmatched);
	}
	pthread_mutex_unlock(&g_zs_lock);
	return (NULL);
}

void
zfsd_onexit_fd_rele(zfs_file_t *fp)
{
	(void) fp;
}

int
zfsd_onexit_add_cb(minor_t minor, void (*func)(void *), void *data,
    uintptr_t *action_handle)
{
	zfsd_zs_t *zs;
	zfsd_onexit_act_t *ap;

	if (minor == 0 || func == NULL)
		return (EBADF);
	ap = calloc(1, sizeof (*ap));
	if (ap == NULL)
		return (ENOMEM);
	ap->func = func;
	ap->data = data;
	pthread_mutex_lock(&g_zs_lock);
	for (zs = g_zs_list; zs != NULL; zs = zs->next) {
		if (zs->minor == minor && !zs->closed)
			break;
	}
	if (zs == NULL) {
		pthread_mutex_unlock(&g_zs_lock);
		free(ap);
		return (EBADF);
	}
	ap->next = zs->actions;
	zs->actions = ap;
	pthread_mutex_unlock(&g_zs_lock);
	if (action_handle != NULL)
		*action_handle = (uintptr_t)ap;
	return (0);
}

void
zfsd_hist_note(const char *dataset)
{
	zfsd_zs_t *zs = zfsd_req_zs;
	char pool[ZFS_MAX_DATASET_NAME_LEN];
	char *cut;

	if (zs == NULL || dataset == NULL || dataset[0] == '\0')
		return;
	(void) strlcpy(pool, dataset, sizeof (pool));
	cut = pool + strcspn(pool, "/@#");
	*cut = '\0';
	if (pool[0] == '\0')
		return;
	pthread_mutex_lock(&g_zs_lock);
	free(zs->allow_log);
	zs->allow_log = strdup(pool);
	pthread_mutex_unlock(&g_zs_lock);
}

int
zfsd_hist_commit(const char *message)
{
	zfsd_zs_t *zs = zfsd_req_zs;
	char *pool = NULL;
	spa_t *spa = NULL;
	int err;

	if (zs == NULL)
		return (EPERM);
	pthread_mutex_lock(&g_zs_lock);
	pool = zs->allow_log;
	zs->allow_log = NULL;
	pthread_mutex_unlock(&g_zs_lock);
	if (pool == NULL)
		return (EPERM);
	if (message == NULL || message[0] == '\0') {
		free(pool);
		return (EINVAL);
	}
	err = spa_open(pool, &spa, FTAG);
	free(pool);
	if (err != 0)
		return (err);
	err = spa_history_log(spa, message);
	spa_close(spa, FTAG);
	return (err);
}

void
zfs_onexit_init(zfs_onexit_t **zop)
{
	zfs_onexit_t *zo;

	zo = *zop = kmem_zalloc(sizeof (zfs_onexit_t), KM_SLEEP);
	mutex_init(&zo->zo_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&zo->zo_actions, sizeof (zfs_onexit_action_node_t),
	    offsetof(zfs_onexit_action_node_t, za_link));
}

void
zfs_onexit_destroy(zfs_onexit_t *zo)
{
	zfs_onexit_action_node_t *ap;

	if (zo == NULL)
		return;
	mutex_enter(&zo->zo_lock);
	while ((ap = list_remove_head(&zo->zo_actions)) != NULL) {
		mutex_exit(&zo->zo_lock);
		ap->za_func(ap->za_data);
		kmem_free(ap, sizeof (zfs_onexit_action_node_t));
		mutex_enter(&zo->zo_lock);
	}
	mutex_exit(&zo->zo_lock);
	list_destroy(&zo->zo_actions);
	mutex_destroy(&zo->zo_lock);
	kmem_free(zo, sizeof (zfs_onexit_t));
}
