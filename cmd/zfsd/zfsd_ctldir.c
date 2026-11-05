// SPDX-License-Identifier: CDDL-1.0
/*
 * .zfs control directory: snapshot objsets served from the parent
 * FUSE session, plus the nested-mount snap worker.
 */

#ifndef _GNU_SOURCE
#define	_GNU_SOURCE
#endif
#include <sys/zfs_context.h>
#include <sys/fs/zfs.h>
#include <sys/zfs_vfsops.h>
#include <sys/zfs_znode.h>
#include <sys/zfs_ctldir.h>
#include <sys/zfsd.h>
#include "zfsd_zpl.h"
#include "zfsd_impl.h"
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>

/*
 * Snapshot objsets served from the parent FUSE session. Nested
 * fuse_mount of .zfs/snapshot/<name> races with path-walk and
 * returns EAGAIN to opendir/stat, which then leaves the dataset
 * busy. One zfsvfs per snapshot, dropped on last rele so destroy
 * is not EBUSY after the last fd is gone.
 */
typedef struct zpl_snapos {
	char		ds[ZFS_MAX_DATASET_NAME_LEN];
	zfsvfs_t	*zfsvfs;
	int		ref;
	struct zpl_snapos *next;
} zpl_snapos_t;

static pthread_mutex_t	zpl_snapos_mx = PTHREAD_MUTEX_INITIALIZER;
static zpl_snapos_t	*zpl_snaposes;

int
zpl_snapos_hold(zpl_mnt_t *parent, const char *snapname, zfsvfs_t **zfvp)
{
	char ds[ZFS_MAX_DATASET_NAME_LEN];
	zpl_snapos_t *s;
	zfsvfs_t *zfsvfs = NULL;
	int err;

	if (zfvp == NULL || parent == NULL || snapname == NULL ||
	    snapname[0] == '\0')
		return (EINVAL);
	*zfvp = NULL;
	if ((size_t)snprintf(ds, sizeof (ds), "%s@%s", parent->ds,
	    snapname) >= sizeof (ds))
		return (ENAMETOOLONG);

	pthread_mutex_lock(&zpl_snapos_mx);
	for (s = zpl_snaposes; s != NULL; s = s->next) {
		if (strcmp(s->ds, ds) == 0) {
			s->ref++;
			*zfvp = s->zfsvfs;
			pthread_mutex_unlock(&zpl_snapos_mx);
			return (0);
		}
	}
	err = zfsvfs_create(ds, B_TRUE, &zfsvfs);
	if (err != 0) {
		pthread_mutex_unlock(&zpl_snapos_mx);
		return (err);
	}
	err = zfsvfs_setup(zfsvfs, B_TRUE);
	if (err != 0) {
		pthread_mutex_unlock(&zpl_snapos_mx);
		zfsvfs_teardown(zfsvfs, B_TRUE);
		return (err);
	}
	s = calloc(1, sizeof (*s));
	if (s == NULL) {
		pthread_mutex_unlock(&zpl_snapos_mx);
		zfsvfs_teardown(zfsvfs, B_TRUE);
		return (ENOMEM);
	}
	(void) strlcpy(s->ds, ds, sizeof (s->ds));
	s->zfsvfs = zfsvfs;
	s->ref = 1;
	s->next = zpl_snaposes;
	zpl_snaposes = s;
	*zfvp = zfsvfs;
	pthread_mutex_unlock(&zpl_snapos_mx);
	return (0);
}

void
zpl_snapos_rele(zfsvfs_t *zfsvfs)
{
	zpl_snapos_t **pp, *s;

	if (zfsvfs == NULL)
		return;
	pthread_mutex_lock(&zpl_snapos_mx);
	for (pp = &zpl_snaposes; (s = *pp) != NULL; pp = &s->next) {
		if (s->zfsvfs != zfsvfs)
			continue;
		if (s->ref > 0)
			s->ref--;
		/*
		 * Keep idle (ref == 0) entries so zpl_snapos_drop
		 * can tear them down on unmount/destroy. Freeing here
		 * made drop a no-op.
		 */
		break;
	}
	pthread_mutex_unlock(&zpl_snapos_mx);
}

static int
zpl_snapos_match(const char *ent, const char *ds)
{
	size_t n;

	if (ent == NULL)
		return (0);
	if (ds == NULL || ds[0] == '\0')
		return (1);
	if (strcmp(ent, ds) == 0)
		return (1);
	n = strlen(ds);
	return (strncmp(ent, ds, n) == 0 &&
	    (ent[n] == '@' || ent[n] == '/'));
}

void
zpl_snapos_drop(const char *ds)
{
	zpl_snapos_t *drop = NULL, **pp, *s;

	pthread_mutex_lock(&zpl_snapos_mx);
	pp = &zpl_snaposes;
	while ((s = *pp) != NULL) {
		if (s->ref == 0 && zpl_snapos_match(s->ds, ds)) {
			*pp = s->next;
			s->next = drop;
			drop = s;
		} else {
			pp = &s->next;
		}
	}
	pthread_mutex_unlock(&zpl_snapos_mx);
	while (drop != NULL) {
		s = drop->next;
		zfsvfs_teardown(drop->zfsvfs, B_TRUE);
		free(drop);
		drop = s;
	}
}

void
zpl_snapos_drop_all(void)
{
	zpl_snapos_t *s, *n;

	pthread_mutex_lock(&zpl_snapos_mx);
	s = zpl_snaposes;
	zpl_snaposes = NULL;
	pthread_mutex_unlock(&zpl_snapos_mx);
	while (s != NULL) {
		n = s->next;
		zfsvfs_teardown(s->zfsvfs, B_TRUE);
		free(s);
		s = n;
	}
}


typedef struct zfsd_snapq {
	zpl_mnt_t	*parent;
	char		snapname[ZFS_MAX_DATASET_NAME_LEN];
	char		mnt[MAXPATHLEN];
	char		ds[ZFS_MAX_DATASET_NAME_LEN];
	int		err;
	int		done;
	int		waiters;
	pthread_cond_t	cv;
	struct zfsd_snapq *next;
} zfsd_snapq_t;

static pthread_mutex_t g_snapq_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_snapq_work = PTHREAD_COND_INITIALIZER;
static zfsd_snapq_t *g_snapq;
static pthread_t g_snap_tid;
static int g_snap_running;

static int
zfsd_snap_name_ok(const char *name)
{
	size_t n;

	if (name == NULL || name[0] == '\0')
		return (0);
	n = strlen(name);
	if (n >= ZFS_MAX_DATASET_NAME_LEN)
		return (0);
	if (strchr(name, '/') != NULL || strchr(name, '@') != NULL)
		return (0);
	if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
		return (0);
	return (1);
}

static zfsd_snapq_t *
zfsd_snapq_find(const char *mnt)
{
	zfsd_snapq_t *j;

	for (j = g_snapq; j != NULL; j = j->next) {
		if (strcmp(j->mnt, mnt) == 0)
			return (j);
	}
	return (NULL);
}

static int
zfsd_snap_parent_hold(zpl_mnt_t *parent)
{
	zpl_mnt_t *have;

	if (parent == NULL)
		return (ENOENT);
	pthread_mutex_lock(&g_mntlock);
	for (have = g_mnts; have != NULL; have = have->next) {
		if (have == parent && !have->pending) {
			parent->inuse++;
			pthread_mutex_unlock(&g_mntlock);
			return (0);
		}
	}
	pthread_mutex_unlock(&g_mntlock);
	return (ENOENT);
}

static void
zfsd_snap_parent_rele(zpl_mnt_t *parent)
{
	if (parent == NULL)
		return;
	pthread_mutex_lock(&g_mntlock);
	if (parent->inuse > 0)
		parent->inuse--;
	pthread_mutex_unlock(&g_mntlock);
}

static void
zfsd_snapq_free(zfsd_snapq_t *j)
{
	zpl_mnt_t *parent;

	if (j == NULL)
		return;
	parent = j->parent;
	j->parent = NULL;
	(void) pthread_cond_destroy(&j->cv);
	free(j);
	zfsd_snap_parent_rele(parent);
}

static void *
zfsd_snap_worker(void *arg)
{
	(void) arg;
	zfsd_snapq_t *j;

	pthread_mutex_lock(&g_snapq_lock);
	while (g_snap_running) {

		for (j = g_snapq; j != NULL; j = j->next) {
			if (!j->done)
				break;
		}
		if (j == NULL) {
			(void) pthread_cond_wait(&g_snapq_work, &g_snapq_lock);
			continue;
		}
		pthread_mutex_unlock(&g_snapq_lock);
		{
			zpl_mnt_t *parent = j->parent;

			if (parent == NULL)
				j->err = ENOENT;
			else {
				j->err = zfsd_zpl_mount_impl(j->ds, j->mnt,
				    MS_RDONLY | MS_NOSUID | MS_NODEV, NULL, 1,
				    parent);
				if (j->err == EBUSY)
					j->err = 0;
			}
		}
		pthread_mutex_lock(&g_snapq_lock);
		j->done = 1;
		(void) pthread_cond_broadcast(&j->cv);
		if (j->waiters == 0) {
			zfsd_snapq_t **pp = &g_snapq;
			while (*pp != NULL && *pp != j)
				pp = &(*pp)->next;
			if (*pp == j)
				*pp = j->next;
			zfsd_snapq_free(j);
		}
	}
	while (g_snapq != NULL) {
		j = g_snapq;
		g_snapq = j->next;
		j->done = 1;
		j->err = ENXIO;
		(void) pthread_cond_broadcast(&j->cv);
		if (j->waiters == 0)
			zfsd_snapq_free(j);
	}
	pthread_mutex_unlock(&g_snapq_lock);
	return (NULL);
}

int
zfsd_zpl_snap_ensure(zpl_mnt_t *parent, const char *snapname, int wait)
{
	char ds[ZFS_MAX_DATASET_NAME_LEN];
	char mnt[MAXPATHLEN];
	zpl_mnt_t *have;
	zfsd_snapq_t *j;
	int err = 0;

	if (parent == NULL || !zfsd_snap_name_ok(snapname))
		return (EINVAL);
	if ((size_t)snprintf(ds, sizeof (ds), "%s@%s", parent->ds,
	    snapname) >= sizeof (ds))
		return (ENAMETOOLONG);
	if ((size_t)snprintf(mnt, sizeof (mnt), "%s/.zfs/snapshot/%s",
	    parent->mnt, snapname) >= sizeof (mnt))
		return (ENAMETOOLONG);

	pthread_mutex_lock(&g_mntlock);
	for (have = g_mnts; have != NULL; have = have->next) {
		if (strcmp(have->ds, ds) == 0 || strcmp(have->mnt, mnt) == 0) {
			have->used = zfsd_mono_sec();
			pthread_mutex_unlock(&g_mntlock);
			return (0);
		}
	}
	pthread_mutex_unlock(&g_mntlock);

	pthread_mutex_lock(&g_snapq_lock);
	if (!g_snap_running) {
		pthread_mutex_unlock(&g_snapq_lock);
		return (ENXIO);
	}
	j = zfsd_snapq_find(mnt);
	if (j == NULL) {
		if (zfsd_snap_parent_hold(parent) != 0) {
			pthread_mutex_unlock(&g_snapq_lock);
			return (ENOENT);
		}
		j = calloc(1, sizeof (*j));
		if (j == NULL) {
			pthread_mutex_unlock(&g_snapq_lock);
			zfsd_snap_parent_rele(parent);
			return (ENOMEM);
		}
		j->parent = parent;
		(void) strlcpy(j->snapname, snapname, sizeof (j->snapname));
		(void) strlcpy(j->mnt, mnt, sizeof (j->mnt));
		(void) strlcpy(j->ds, ds, sizeof (j->ds));
		(void) pthread_cond_init(&j->cv, NULL);
		j->next = g_snapq;
		g_snapq = j;
		(void) pthread_cond_signal(&g_snapq_work);
	}
	if (!wait) {
		pthread_mutex_unlock(&g_snapq_lock);
		return (0);
	}
	j->waiters++;
	while (!j->done && g_snap_running)
		(void) pthread_cond_wait(&j->cv, &g_snapq_lock);
	err = j->done ? j->err : ENXIO;
	j->waiters--;
	if (j->done && j->waiters == 0) {
		zfsd_snapq_t **pp = &g_snapq;
		while (*pp != NULL && *pp != j)
			pp = &(*pp)->next;
		if (*pp == j)
			*pp = j->next;
		zfsd_snapq_free(j);
	}
	pthread_mutex_unlock(&g_snapq_lock);
	return (err);
}

int
zfsd_zpl_snap_borrow(zpl_mnt_t *parent, const char *snapname,
    zfsvfs_t **zfvp, zpl_mnt_t **mp, int wait)
{
	char ds[ZFS_MAX_DATASET_NAME_LEN];
	zpl_mnt_t *have;
	int err;

	if (zfvp == NULL)
		return (EINVAL);
	*zfvp = NULL;
	if (mp != NULL)
		*mp = NULL;
	err = zfsd_zpl_snap_ensure(parent, snapname, wait);
	if (err != 0)
		return (err);
	if ((size_t)snprintf(ds, sizeof (ds), "%s@%s", parent->ds,
	    snapname) >= sizeof (ds))
		return (ENAMETOOLONG);
	pthread_mutex_lock(&g_mntlock);
	for (have = g_mnts; have != NULL; have = have->next) {
		if (strcmp(have->ds, ds) != 0)
			continue;
		pthread_mutex_lock(&have->lock);
		if (have->dying) {
			pthread_mutex_unlock(&have->lock);
			break;
		}
		have->inuse++;
		have->used = zfsd_mono_sec();
		*zfvp = have->zfsvfs;
		if (mp != NULL)
			*mp = have;
		pthread_mutex_unlock(&have->lock);
		pthread_mutex_unlock(&g_mntlock);
		return (0);
	}
	pthread_mutex_unlock(&g_mntlock);
	return (wait ? ENOENT : EAGAIN);
}

void
zfsd_zpl_snap_rele(zpl_mnt_t *m)
{
	if (m == NULL)
		return;
	pthread_mutex_lock(&g_mntlock);
	if (m->inuse > 0)
		m->inuse--;
	pthread_mutex_unlock(&g_mntlock);
}

static int
zfsd_snap_idle(zpl_mnt_t *m, time_t now)
{
	znode_t *zp;
	int busy = 0;

	if (m == NULL || m->pending || !m->snap || m->zfsvfs == NULL)
		return (0);
	if (m->inuse != 0)
		return (0);
	pthread_mutex_lock(&m->lock);
	if (m->dying ||
	    now < m->used || (now - m->used) < ZFSD_SNAP_EXPIRE) {
		pthread_mutex_unlock(&m->lock);
		return (0);
	}
	pthread_mutex_unlock(&m->lock);
	mutex_enter(&m->zfsvfs->z_znodes_lock);
	for (zp = list_head(&m->zfsvfs->z_all_znodes); zp != NULL;
	    zp = list_next(&m->zfsvfs->z_all_znodes, zp)) {
		mutex_enter(&zp->z_lock);
		if (zp->z_ref != 1)
			busy = 1;
		mutex_exit(&zp->z_lock);
		if (busy)
			break;
	}
	mutex_exit(&m->zfsvfs->z_znodes_lock);
	return (busy ? 0 : 1);
}

void
zfsd_zpl_expire_snaps(void)
{
	zpl_mnt_t *drop = NULL, **pp, *m;
	time_t now = zfsd_mono_sec();

	pthread_mutex_lock(&g_mntlock);
	pp = &g_mnts;
	while ((m = *pp) != NULL) {
		if (zfsd_snap_idle(m, now)) {
			*pp = m->next;
			m->next = drop;
			drop = m;
		} else {
			pp = &m->next;
		}
	}
	pthread_mutex_unlock(&g_mntlock);
	while (drop != NULL) {
		zpl_mnt_t *n = drop->next;
		zfsd_zpl_teardown(drop);
		drop = n;
	}
}

int
zfsctl_snapshot_unmount(const char *snapname)
{
	/*
	 * Kernel zfs_unmount_snap is best-effort and detaches the
	 * .zfs/snapshot automount so destroy is not EBUSY. Match that
	 * with MNT_DETACH (2) rather than a busy-checked unmount.
	 */
#ifndef	MNT_DETACH
#define	MNT_DETACH	2
#endif
	zpl_snapos_drop(snapname);
	return (zfsd_zpl_unmount(snapname, NULL, MNT_DETACH));
}

void
zfsd_ctldir_start(void)
{
	pthread_mutex_lock(&g_snapq_lock);
	g_snap_running = 1;
	pthread_mutex_unlock(&g_snapq_lock);
	if (pthread_create(&g_snap_tid, NULL, zfsd_snap_worker, NULL) != 0) {
		pthread_mutex_lock(&g_snapq_lock);
		g_snap_running = 0;
		(void) pthread_cond_broadcast(&g_snapq_work);
		pthread_mutex_unlock(&g_snapq_lock);
	}
}

void
zfsd_ctldir_stop(void)
{
	pthread_mutex_lock(&g_snapq_lock);
	if (g_snap_running) {
		g_snap_running = 0;
		(void) pthread_cond_broadcast(&g_snapq_work);
		pthread_mutex_unlock(&g_snapq_lock);
		(void) pthread_join(g_snap_tid, NULL);
	} else {
		pthread_mutex_unlock(&g_snapq_lock);
	}
}
