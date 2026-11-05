// SPDX-License-Identifier: CDDL-1.0
/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * https://opensource.org/license/CDDL-1.0.
 */

/*
 * Copyright (c) 2021 Klara, Inc.
 */

#include <alloca.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/inotify.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <libzfs.h>
#include <libzfs_core.h>

#include "../../libzfs_impl.h"
#include "zfs_prop.h"
#include <libzutil.h>
#include <sys/zfs_sysfs.h>
#include <sys/zfsd.h>

#define	ZDIFF_SHARESDIR		"/.zfs/shares/"

const char *
libzfs_error_init(int error)
{
	/*
	 * zfsd is not zfs.ko. Do not tell the operator to modprobe
	 * when TEST_ZFSD / ZFSDEV selected a userspace control node.
	 */
	if (getenv("TEST_ZFSD") != NULL || getenv(ZFSDEV_ENV) != NULL ||
	    strcmp(zfs_dev_path(), ZFS_DEV_FUSE) == 0) {
		switch (error) {
		case ENXIO:
		case ENOENT:
		case ENOEXEC:
			return ("The zfsd control node "
			    "is not available.\nIs zfsd running?");
		case EACCES:
			return ("Permission denied the "
			    "ZFS utilities must be run as root.");
		default:
			return ("Failed to initialize "
			    "the libzfs library.");
		}
	}
	switch (error) {
	case ENXIO:
		return ("The ZFS modules are not "
		    "loaded.\nTry running 'modprobe zfs' as root "
		    "to load them.");
	case ENOENT:
		return ("/dev/zfs and /proc/self/mounts "
		    "are required.\nTry running 'udevadm trigger' and 'mount "
		    "-t proc proc /proc' as root.");
	case ENOEXEC:
		return ("The ZFS modules cannot be "
		    "auto-loaded.\nTry running 'modprobe zfs' as "
		    "root to manually load them.");
	case EACCES:
		return ("Permission denied the "
		    "ZFS utilities must be run as root.");
	default:
		return ("Failed to initialize the "
		    "libzfs library.");
	}
}

static int
in_container(void)
{
	char buffer[4096];
	ssize_t count;
	int fd;

	if (access("/run/systemd/container", R_OK) == 0)
		return (1);

	fd = open("/proc/1/cgroup", O_RDONLY);
	if (fd == -1)
		return (0);

	count = read(fd, buffer, sizeof (buffer) - 1);
	close(fd);

	if (count <= 0)
		return (0);

	buffer[count] = '\0';

	if (strstr(buffer, "docker") ||
	    strstr(buffer, "containerd") ||
	    strstr(buffer, "kubepods") ||
	    strstr(buffer, "lxc")) {
		return (1);
	}

	return (0);
}

/*
 * zfs(4) is loaded by udev if there's a fstype=zfs device present,
 * but if there isn't, load them automatically;
 * always wait for the control node to appear via udev.
 *
 * Environment variables:
 * - ZFS_MODULE_TIMEOUT="<seconds>" - Seconds to wait for the control
 *                                    node, defaults to 10, max. 10 min.
 */
int
libzfs_load_module(void)
{
	const char *dev = zfs_dev_path();
	const char *zfsdev = getenv(ZFSDEV_ENV);
	struct stat st;

	if (stat(dev, &st) == 0 && S_ISCHR(st.st_mode))
		return (0);

	/*
	 * zfsd client: never autoload zfs.ko. ZFSDEV selects the
	 * control node (native=/dev/zfs, fuse=/dev/uzfs). TEST_ZFSD
	 * is set by zfs-tests.sh --test-zfsd=. A missing node is a
	 * dead daemon, not a missing kernel module.
	 */
	if (zfsdev != NULL || getenv("TEST_ZFSD") != NULL ||
	    strcmp(dev, ZFS_DEV_FUSE) == 0)
		return (ENOENT);

	if (access(ZFS_SYSFS_DIR, F_OK) != 0) {
		char *argv[] = {(char *)"modprobe", (char *)"zfs", NULL};
		if (libzfs_run_process("modprobe", argv, 0))
			return (ENOEXEC);

		if (access(ZFS_SYSFS_DIR, F_OK) != 0)
			return (ENXIO);
	}

	const char *timeout_str = getenv("ZFS_MODULE_TIMEOUT");
	int seconds = 10;

	/* Set timeout to zero if inside of a container */
	if (in_container())
		seconds = 0;

	if (timeout_str)
		seconds = MIN(strtol(timeout_str, NULL, 0), 600);
	struct itimerspec timeout = {.it_value.tv_sec = MAX(seconds, 0)};

	int ino = inotify_init1(IN_CLOEXEC);
	if (ino == -1)
		return (ENOENT);
	inotify_add_watch(ino, ZFS_DEVDIR, IN_CREATE);

	if (access(dev, F_OK) == 0) {
		close(ino);
		return (0);
	} else if (seconds == 0) {
		close(ino);
		return (ENOENT);
	}

	size_t evsz = sizeof (struct inotify_event) + NAME_MAX + 1;
	struct inotify_event *ev = alloca(evsz);

	int tout = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
	if (tout == -1) {
		close(ino);
		return (ENOENT);
	}
	timerfd_settime(tout, 0, &timeout, NULL);

	int ret = ENOENT;
	struct pollfd pfds[] = {
		{.fd = ino, .events = POLLIN},
		{.fd = tout, .events = POLLIN},
	};
	while (poll(pfds, ARRAY_SIZE(pfds), -1) != -1) {
		if (pfds[0].revents & POLLIN) {
			verify(read(ino, ev, evsz) >
			    sizeof (struct inotify_event));
			if (strncmp(ev->name, &dev[sizeof (ZFS_DEVDIR)],
			    ev->len) == 0) {
				ret = 0;
				break;
			}
		}
		if (pfds[1].revents & POLLIN)
			break;
	}
	close(tout);
	close(ino);
	return (ret);
}

int
find_shares_object(differ_info_t *di)
{
	char fullpath[MAXPATHLEN];
	struct stat64 sb = { 0 };

	(void) strlcpy(fullpath, di->dsmnt, MAXPATHLEN);
	(void) strlcat(fullpath, ZDIFF_SHARESDIR, MAXPATHLEN);

	if (stat64(fullpath, &sb) != 0) {
		(void) snprintf(di->errbuf, sizeof (di->errbuf),
		    "Cannot stat %s", fullpath);
		return (zfs_error(di->zhp->zfs_hdl, EZFS_DIFF, di->errbuf));
	}

	di->shares = (uint64_t)sb.st_ino;
	return (0);
}

int
zfs_destroy_snaps_nvl_os(libzfs_handle_t *hdl, nvlist_t *snaps)
{
	(void) hdl, (void) snaps;
	return (0);
}

/*
 * Return allocated loaded module version, or NULL on error (with errno set)
 */
char *
zfs_version_kernel(void)
{
	FILE *f = fopen(ZFS_SYSFS_DIR "/version", "re");
	if (f == NULL)
		return (NULL);

	char *ret = NULL;
	size_t l;
	ssize_t read;
	if ((read = getline(&ret, &l, f)) == -1) {
		int err = errno;
		fclose(f);
		errno = err;
		return (NULL);
	}

	fclose(f);
	if (ret[read - 1] == '\n')
		ret[read - 1] = '\0';
	return (ret);
}

/*
 * Add or delete the given filesystem to/from the given user namespace.
 */
int
zfs_userns(zfs_handle_t *zhp, const char *nspath, int attach)
{
	libzfs_handle_t *hdl = zhp->zfs_hdl;
	zfs_cmd_t zc = {"\0"};
	char errbuf[1024];
	unsigned long cmd;
	int ret;

	if (attach) {
		(void) snprintf(errbuf, sizeof (errbuf),
		    "cannot add '%s' to namespace",
		    zhp->zfs_name);
	} else {
		(void) snprintf(errbuf, sizeof (errbuf),
		    "cannot remove '%s' from namespace",
		    zhp->zfs_name);
	}

	switch (zhp->zfs_type) {
	case ZFS_TYPE_VOLUME:
		zfs_error_aux(hdl,
		    "volumes can not be namespaced");
		return (zfs_error(hdl, EZFS_BADTYPE, errbuf));
	case ZFS_TYPE_SNAPSHOT:
		zfs_error_aux(hdl,
		    "snapshots can not be namespaced");
		return (zfs_error(hdl, EZFS_BADTYPE, errbuf));
	case ZFS_TYPE_BOOKMARK:
		zfs_error_aux(hdl,
		    "bookmarks can not be namespaced");
		return (zfs_error(hdl, EZFS_BADTYPE, errbuf));
	case ZFS_TYPE_VDEV:
		zfs_error_aux(hdl,
		    "vdevs can not be namespaced");
		return (zfs_error(hdl, EZFS_BADTYPE, errbuf));
	case ZFS_TYPE_INVALID:
		zfs_error_aux(hdl,
		    "invalid zfs_type_t: ZFS_TYPE_INVALID");
		return (zfs_error(hdl, EZFS_BADTYPE, errbuf));
	case ZFS_TYPE_POOL:
		zfs_error_aux(hdl,
		    "pools can not be namespaced");
		return (zfs_error(hdl, EZFS_BADTYPE, errbuf));
	case ZFS_TYPE_FILESYSTEM:
		break;
	}
	assert(zhp->zfs_type == ZFS_TYPE_FILESYSTEM);

	(void) strlcpy(zc.zc_name, zhp->zfs_name, sizeof (zc.zc_name));
	zc.zc_objset_type = DMU_OST_ZFS;
	zc.zc_cleanup_fd = open(nspath, O_RDONLY);
	if (zc.zc_cleanup_fd < 0) {
		return (zfs_error(hdl, EZFS_NOT_USER_NAMESPACE, errbuf));
	}

	cmd = attach ? ZFS_IOC_USERNS_ATTACH : ZFS_IOC_USERNS_DETACH;
	if ((ret = zfs_ioctl(hdl, cmd, &zc)) != 0)
		zfs_standard_error(hdl, errno, errbuf);

	(void) close(zc.zc_cleanup_fd);

	return (ret);
}
