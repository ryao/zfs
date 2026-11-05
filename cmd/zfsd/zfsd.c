// SPDX-License-Identifier: CDDL-1.0
/*
 * zfsd -- userspace OpenZFS daemon. Occupies /dev/zfs (ZFSDEV=native) or
 * /dev/uzfs and dispatches the stock zfs ioctl ABI through libzpool
 * plus module/zfs/zfs_ioctl.c. Nested zfs_cmd_t pointers are copied
 * from the caller with process_vm_{readv,writev}. There is no private
 * SPA; kernel_init() brings up the same pool layer used by ztest.
 */

#ifndef _GNU_SOURCE
#define	_GNU_SOURCE
#endif

#include <sys/zfs_context.h>
#include <libzpool.h>
#include <sys/spa.h>
#include <sys/arc.h>
#include <sys/cred.h>
#include <sys/zfsd.h>
#include <sys/zfs_ioctl.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <malloc.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/tunables.h>
#include <sys/wait.h>
#include <unistd.h>
#include "zfsd_impl.h"


extern void zfs_znode_init(void);
extern void zfs_znode_fini(void);
extern void zfsd_ioctl_init(void);

extern uint64_t zfs_arc_max;
extern boolean_t zfs_arc_honor_max;
extern boolean_t zfs_tryimport_skip_aux;

static int g_native = 1;
static char g_rundir[MAXPATHLEN] = "/run/zfsd";
static uint64_t g_arc_max;

static char g_tun_dir[MAXPATHLEN];

int
zfsd_mkdirs(const char *path, mode_t mode)
{
	char buf[MAXPATHLEN];
	char *p;
	struct stat st;

	if (path == NULL || path[0] != '/')
		return (EINVAL);
	if (strlen(path) >= sizeof (buf))
		return (ENAMETOOLONG);
	(void) strlcpy(buf, path, sizeof (buf));
	for (p = buf + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			if (mkdir(buf, mode) != 0) {
				if (errno != EEXIST) {
					*p = '/';
					return (errno);
				}
				if (lstat(buf, &st) != 0)
					return (errno);
				if (!S_ISDIR(st.st_mode))
					return (ENOTDIR);
			}
			*p = '/';
		}
	}
	if (mkdir(buf, mode) == 0)
		return (0);
	if (errno != EEXIST)
		return (errno);
	if (lstat(buf, &st) != 0)
		return (errno);
	return (S_ISDIR(st.st_mode) ? 0 : ENOTDIR);
}

int
zfsd_run(char *const argv[])
{
	pid_t pid;
	int st;

	if (argv == NULL || argv[0] == NULL)
		return (EINVAL);
	pid = fork();
	if (pid < 0)
		return (errno);
	if (pid == 0) {
		int fd = open("/dev/null", O_RDWR | O_CLOEXEC);
		if (fd >= 0) {
			(void) dup2(fd, STDIN_FILENO);
			(void) dup2(fd, STDOUT_FILENO);
			(void) dup2(fd, STDERR_FILENO);
			if (fd > 2)
				(void) close(fd);
		}
#if defined(__NR_close_range)
		(void) syscall(__NR_close_range, 3, ~0U, 0U);
#endif
		(void) execv(argv[0], argv);
		_exit(127);
	}
	if (waitpid(pid, &st, 0) < 0)
		return (errno);
	if (WIFEXITED(st) && WEXITSTATUS(st) == 0)
		return (0);
	return (EIO);
}


static int
zfsd_tun_name_ok(const char *name)
{
	if (name == NULL || name[0] == '\0' || name[0] == '.')
		return (0);
	if (strchr(name, '/') != NULL)
		return (0);
	return (1);
}

static int
zfsd_tun_write_one(const char *name, boolean_t writable, void *arg)
{
	char path[MAXPATHLEN], val[256];
	FILE *fp;
	int err;

	(void) arg;
	if (!zfsd_tun_name_ok(name))
		return (0);
	err = libzpool_tunable_get(name, val, sizeof (val));
	if (err != 0)
		return (0);
	(void) snprintf(path, sizeof (path), "%s/%s", g_tun_dir, name);
	{
		int fd, mode;

		mode = writable ? 0644 : 0444;
		fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
		if (fd < 0)
			return (0);
		(void) fchmod(fd, mode);
		fp = fdopen(fd, "w");
		if (fp == NULL) {
			(void) close(fd);
			return (0);
		}
	}
	(void) fprintf(fp, "%s\n", val);
	(void) fclose(fp);
	return (0);
}

static int
zfsd_tun_apply_one(const char *name, boolean_t writable, void *arg)
{
	char path[MAXPATHLEN], buf[256], *nl;
	FILE *fp;

	(void) arg;
	if (!writable || !zfsd_tun_name_ok(name))
		return (0);
	(void) snprintf(path, sizeof (path), "%s/%s", g_tun_dir, name);
	fp = fopen(path, "r");
	if (fp == NULL)
		return (0);
	if (fgets(buf, sizeof (buf), fp) != NULL) {
		nl = strchr(buf, '\n');
		if (nl != NULL)
			*nl = '\0';
		if (libzpool_tunable_set(name, buf) != 0) {
			/*
			 * Rejected write: restore the live value so
			 * get_tunable does not echo a request the
			 * daemon never applied.
			 */
			(void) fclose(fp);
			(void) zfsd_tun_write_one(name, writable, NULL);
			return (0);
		}
	}
	(void) fclose(fp);
	return (0);
}

/*
 * zfs_vnops.c, zfs_ioctl.c and dataset_kstats.c are linked into zfsd,
 * not libzpool. Their ZFS_MODULE_PARAM records live in this executable's
 * zfs_tunables section. zfs_tunable_iter() only walks libzpool's copy,
 * so BCLONE_WAIT_DIRTY and the other seven never appeared under
 * /run/zfsd/parameters and set_tunable failed closed.
 */
extern const zfs_tunable_t *__start_zfs_tunables;
extern const zfs_tunable_t *__stop_zfs_tunables;

static int
zfsd_exe_tun_get(const zfs_tunable_t *zt, char *val, size_t valsz)
{
	if (zt == NULL || zt->zt_varp == NULL || val == NULL || valsz == 0)
		return (EINVAL);
	switch (zt->zt_type) {
	case ZFS_TUNABLE_TYPE_INT:
		(void) snprintf(val, valsz, "%d", *(int *)zt->zt_varp);
		return (0);
	case ZFS_TUNABLE_TYPE_UINT:
		(void) snprintf(val, valsz, "%u",
		    *(unsigned int *)zt->zt_varp);
		return (0);
	case ZFS_TUNABLE_TYPE_ULONG:
		(void) snprintf(val, valsz, "%lu",
		    *(unsigned long *)zt->zt_varp);
		return (0);
	case ZFS_TUNABLE_TYPE_U64:
		(void) snprintf(val, valsz, "%" PRIu64,
		    *(uint64_t *)zt->zt_varp);
		return (0);
	default:
		return (EOPNOTSUPP);
	}
}

static int
zfsd_exe_tun_set(const zfs_tunable_t *zt, const char *val)
{
	char *end;
	intmax_t s;
	uintmax_t u;

	if (zt == NULL || zt->zt_varp == NULL || val == NULL || val[0] == '\0')
		return (EINVAL);
	errno = 0;
	switch (zt->zt_type) {
	case ZFS_TUNABLE_TYPE_INT:
		s = strtoimax(val, &end, 0);
		if (errno != 0 || end == val || *end != '\0' ||
		    s < INT_MIN || s > INT_MAX)
			return (EINVAL);
		*(int *)zt->zt_varp = (int)s;
		return (0);
	case ZFS_TUNABLE_TYPE_UINT:
		if (strchr(val, '-') != NULL)
			return (ERANGE);
		u = strtoumax(val, &end, 0);
		if (errno != 0 || end == val || *end != '\0' || u > UINT_MAX)
			return (EINVAL);
		*(unsigned int *)zt->zt_varp = (unsigned int)u;
		return (0);
	case ZFS_TUNABLE_TYPE_ULONG:
		if (strchr(val, '-') != NULL)
			return (ERANGE);
		u = strtoumax(val, &end, 0);
		if (errno != 0 || end == val || *end != '\0' || u > ULONG_MAX)
			return (EINVAL);
		*(unsigned long *)zt->zt_varp = (unsigned long)u;
		return (0);
	case ZFS_TUNABLE_TYPE_U64:
		if (strchr(val, '-') != NULL)
			return (ERANGE);
		u = strtoumax(val, &end, 0);
		if (errno != 0 || end == val || *end != '\0')
			return (EINVAL);
		*(uint64_t *)zt->zt_varp = (uint64_t)u;
		return (0);
	default:
		return (EOPNOTSUPP);
	}
}

static void
zfsd_exe_tun_write(const zfs_tunable_t *zt)
{
	char path[MAXPATHLEN], val[256];
	FILE *fp;
	int fd, mode;

	if (zt == NULL || !zfsd_tun_name_ok(zt->zt_name))
		return;
	if (zfsd_exe_tun_get(zt, val, sizeof (val)) != 0)
		return;
	(void) snprintf(path, sizeof (path), "%s/%s", g_tun_dir, zt->zt_name);
	mode = (zt->zt_perm == ZFS_TUNABLE_PERM_ZMOD_RW) ? 0644 : 0444;
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
	if (fd < 0)
		return;
	(void) fchmod(fd, mode);
	fp = fdopen(fd, "w");
	if (fp == NULL) {
		(void) close(fd);
		return;
	}
	(void) fprintf(fp, "%s\n", val);
	(void) fclose(fp);
}

static void
zfsd_exe_tun_apply(const zfs_tunable_t *zt)
{
	char path[MAXPATHLEN], buf[256], *nl;
	FILE *fp;

	if (zt == NULL || zt->zt_perm != ZFS_TUNABLE_PERM_ZMOD_RW ||
	    !zfsd_tun_name_ok(zt->zt_name))
		return;
	(void) snprintf(path, sizeof (path), "%s/%s", g_tun_dir, zt->zt_name);
	fp = fopen(path, "r");
	if (fp == NULL)
		return;
	if (fgets(buf, sizeof (buf), fp) != NULL) {
		nl = strchr(buf, '\n');
		if (nl != NULL)
			*nl = '\0';
		if (zfsd_exe_tun_set(zt, buf) != 0) {
			(void) fclose(fp);
			zfsd_exe_tun_write(zt);
			return;
		}
	}
	(void) fclose(fp);
}

static void
zfsd_exe_tunables(void (*fn)(const zfs_tunable_t *))
{
	const zfs_tunable_t **ztp;

	for (ztp = &__start_zfs_tunables; ztp != &__stop_zfs_tunables; ztp++) {
		if (*ztp != NULL)
			fn(*ztp);
	}
}

void
zfsd_tunables_refresh(void)
{
	if (g_tun_dir[0] == '\0')
		return;
	libzpool_tunable_iter(zfsd_tun_apply_one, NULL);
	zfsd_exe_tunables(zfsd_exe_tun_apply);
}

static void
zfsd_tunables_start(const char *rundir)
{
	(void) snprintf(g_tun_dir, sizeof (g_tun_dir), "%s/parameters", rundir);
	(void) mkdir(g_tun_dir, 0755);
	libzpool_tunable_iter(zfsd_tun_write_one, NULL);
	zfsd_exe_tunables(zfsd_exe_tun_write);
}

uint32_t
zfsd_ioc_canon(uint32_t ioc)
{
#ifdef _IOC_TYPE
	/*
	 * libzfs issues private zfsd ioctls as _IOWR('Z', nr, zfs_cmd_t)
	 * so CUSE/FUSE copies the struct. Stock ZFS ioctls stay 0x5aNN
	 * (size 0). Strip size/dir when present so comparisons use the
	 * ZFS_IOC_FIRST+nr form.
	 */
	if (_IOC_TYPE(ioc) == 'Z' && _IOC_SIZE(ioc) != 0)
		return (ZFS_IOC_FIRST + (uint32_t)_IOC_NR(ioc));
#endif
	if (ioc < ZFS_IOC_FIRST)
		ioc += ZFS_IOC_FIRST;
	return (ioc);
}

static uint64_t
parse_size(const char *s)
{
	char *end = NULL;
	unsigned long long v;
	unsigned long long mul = 1;

	if (s == NULL || s[0] == '\0')
		return (0);
	errno = 0;
	v = strtoull(s, &end, 0);
	if (end == s || errno == ERANGE)
		return (0);
	if (*end == 'G' || *end == 'g') {
		mul = 1024ULL * 1024ULL * 1024ULL;
		end++;
	} else if (*end == 'M' || *end == 'm') {
		mul = 1024ULL * 1024ULL;
		end++;
	} else if (*end == 'K' || *end == 'k') {
		mul = 1024ULL;
		end++;
	}
	if (*end == 'B' || *end == 'b')
		end++;
	if (*end != '\0')
		return (0);
	if (mul != 1 && v > UINT64_MAX / mul)
		return (0);
	return ((uint64_t)(v * mul));
}

static void
zfsd_write_pid(void)
{
	char path[MAXPATHLEN];
	int fd;
	FILE *fp;

	(void) snprintf(path, sizeof (path), "%s/zfsd.pid", g_rundir);
	(void) mkdir(g_rundir, 0755);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
	    0644);
	if (fd < 0)
		return;
	fp = fdopen(fd, "w");
	if (fp == NULL) {
		(void) close(fd);
		return;
	}
	(void) fprintf(fp, "%d\n", (int)getpid());
	(void) fclose(fp);
}


static void
usage(const char *argv0)
{
	(void) fprintf(stderr,
	    "usage: %s [-f] [-r rundir] [--native|--fuse] [--arc-max SIZE]\n"
	    "  --native     occupy /dev/zfs (kernel module must be absent)\n"
	    "  --fuse       publish /dev/uzfs beside a loaded module\n"
	    "  --arc-max N  cap ARC (bytes, or K/M/G suffix). Default: libzpool\n",
	    argv0);

}

int
main(int argc, char **argv)
{
	int c, foreground = 0;
	static struct option longopts[] = {
		{ "native", no_argument, NULL, 'N' },
		{ "fuse", no_argument, NULL, 'F' },
		{ "arc-max", required_argument, NULL, 'M' },
		{ 0, 0, 0, 0 }
	};

	/*
	 * glibc keeps one malloc arena per contending thread, up to
	 * 8 * ncpu, and each arena reserves a 64MiB mapping. That
	 * reservation is a commit charge under overcommit_memory=2
	 * even while RSS stays a few dozen megabytes, and it is not
	 * returned when the pool is destroyed. Importing one pool on
	 * a 2-CPU host already committed ~1GiB here. A 2GiB guest
	 * then has nothing left. kmem_alloc(KM_SLEEP) retries the
	 * failed malloc forever, the CUSE worker never replies, and
	 * zpool list / status / destroy sit in the kernel until the
	 * runner kills cleanup.ksh. Four arenas still grow when the
	 * process actually needs the memory.
	 *
	 * libfuse workers do not use the pthread default stack.
	 * fuse_start_thread() builds its own pthread_attr and, unless
	 * FUSE_THREAD_STACK is set, gets glibc's 8MiB. glibc caches
	 * those stacks after the thread exits, so a hundred datasets
	 * keep the charge. Taskq threads already pass 256KiB.
	 */
#if defined(__GLIBC__)
	if (mallopt(M_ARENA_MAX, 4) != 1) {
		(void) fprintf(stderr, "zfsd: M_ARENA_MAX: failed\n");
	}
#endif
#ifdef __linux__
	{
		pthread_attr_t attr;

		if (pthread_attr_init(&attr) == 0) {
			if (pthread_attr_setstacksize(&attr, 256 * 1024) == 0)
				(void) pthread_setattr_default_np(&attr);
			(void) pthread_attr_destroy(&attr);
		}
		if (setenv("FUSE_THREAD_STACK", "262144", 0) != 0)
			(void) fprintf(stderr,
			    "zfsd: FUSE_THREAD_STACK: %s\n", strerror(errno));
	}
#endif

	while ((c = getopt_long(argc, argv, "fr:M:", longopts, NULL)) != -1) {
		switch (c) {
		case 'f':
			foreground = 1;
			break;
		case 'r':
			if (strlcpy(g_rundir, optarg, sizeof (g_rundir)) >=
			    sizeof (g_rundir)) {
				(void) fprintf(stderr,
				    "zfsd: -r path too long\n");
				return (2);
			}
			break;
		case 'N':
			g_native = 1;
			break;
		case 'F':
			g_native = 0;
			break;
		case 'M':
			g_arc_max = parse_size(optarg);
			if (g_arc_max == 0) {
				(void) fprintf(stderr,
				    "zfsd: invalid --arc-max '%s'\n", optarg);
				return (2);
			}
			if (g_arc_max < MIN_ARC_MAX) {
				(void) fprintf(stderr,
				    "zfsd: --arc-max must be at least %llu "
				    "(MIN_ARC_MAX)\n",
				    (unsigned long long)MIN_ARC_MAX);
				return (2);
			}
			break;
		default:
			usage(argv[0]);
			return (2);
		}
	}

	if (g_native && access("/sys/module/zfs", F_OK) == 0) {
		(void) fprintf(stderr,
		    "zfsd: kernel ZFS module is loaded; refusing --native\n");
		return (1);
	}

	if (g_arc_max != 0)
		zfs_arc_max = g_arc_max;
	zfs_arc_honor_max = B_TRUE;
	zfs_tryimport_skip_aux = B_TRUE;
	zfsd_mark_daemon();

	if (!foreground) {
		if (daemon(0, 0) != 0) {
			perror("zfsd: daemon");
			return (1);
		}
	}

	{
		sigset_t set;
		int sig;

		(void) signal(SIGPIPE, SIG_IGN);
		sigemptyset(&set);
		sigaddset(&set, SIGTERM);
		sigaddset(&set, SIGINT);
		(void) pthread_sigmask(SIG_BLOCK, &set, NULL);

		zfsd_write_pid();
		kernel_init(SPA_MODE_READ | SPA_MODE_WRITE);
		zfsd_tunables_start(g_rundir);
		zfs_znode_init();
		zfsd_ioctl_init();

		if (zfsd_dev_start(g_rundir, g_native) != 0) {
			(void) fprintf(stderr,
			    "zfsd: failed to publish control node\n");
			kernel_fini();
			return (1);
		}
		zfsd_zpl_reap_stale();

		(void) fprintf(stderr,
		    "zfsd: control %s (libzpool) rundir=%s pid=%d arc_max=%llu\n",
		    g_native ? ZFS_DEV : ZFS_DEV_FUSE, g_rundir, (int)getpid(),
		    (unsigned long long)zfs_arc_max);

		while (sigwait(&set, &sig) == 0) {
			if (sig == SIGTERM || sig == SIGINT)
				break;
		}
	}

	zfsd_zpl_unmount_all();
	zfsd_dev_stop();
	zfs_znode_fini();
	kernel_fini();
	return (0);
}
