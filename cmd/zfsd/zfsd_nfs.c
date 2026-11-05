// SPDX-License-Identifier: CDDL-1.0
/*
 * Delegated NFS share: /etc/exports.d/zfs.exports plus exportfs -ra.
 */

#ifndef _GNU_SOURCE
#define	_GNU_SOURCE
#endif
#include <sys/zfs_context.h>
#include <sys/cred.h>
#include <sys/policy.h>
#include <sys/fs/zfs.h>
#include "zfsd_impl.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>

#ifndef	LOCK_EX
#define	LOCK_EX	2
#define	LOCK_UN	8
#endif
int flock(int, int);

#ifdef __linux__

static int
zfsd_nfs_escape(const char *mp, char *out, size_t n)
{
	size_t i = 0;
	const char *c;

	for (c = mp; *c != '\0'; c++) {
		if (strchr("\t\n\v\f\r \\", *c) != NULL) {
			if (i + 4 >= n)
				return (ENAMETOOLONG);
			(void) snprintf(out + i, n - i, "\\%03hho", *c);
			i += 4;
		} else {
			if (i + 1 >= n)
				return (ENAMETOOLONG);
			out[i++] = *c;
		}
	}
	out[i] = '\0';
	return (0);
}

static int
zfsd_nfs_tok_ok(const char *k, const char *v)
{
	const char *p;

	if (k == NULL || k[0] == '\0')
		return (0);
	for (p = k; *p != '\0'; p++) {
		if (!((*p >= 'a' && *p <= 'z') ||
		    (*p >= 'A' && *p <= 'Z') ||
		    (*p >= '0' && *p <= '9') || *p == '_'))
			return (0);
	}
	if (v == NULL)
		return (1);
	if (strpbrk(v, " \t\n\r()\\\"';|&") != NULL)
		return (0);
	return (1);
}

/*
 * Delegated (non-root) sharenfs may not turn off root squash, pick
 * an anon uid, or mark the export insecure. Root keeps the full set.
 */
static int
zfsd_nfs_deleg_tok_ok(const char *k)
{
	static const char *ok[] = {
		"rw", "ro", "crossmnt", "sec", "nosub",
		"subtree_check", "no_subtree_check",
		"async", "sync", "secure", "root_squash",
		NULL
	};
	int i;

	if (k == NULL)
		return (0);
	for (i = 0; ok[i] != NULL; i++) {
		if (strcmp(k, ok[i]) == 0)
			return (1);
	}
	return (0);
}

static int
zfsd_nfs_host_ok(const char *h)
{
	const char *p;

	if (h == NULL || h[0] == '\0')
		return (0);
	for (p = h; *p != '\0'; p++) {
		if ((*p >= 'a' && *p <= 'z') ||
		    (*p >= 'A' && *p <= 'Z') ||
		    (*p >= '0' && *p <= '9') ||
		    *p == '.' || *p == ':' || *p == '/' ||
		    *p == '-' || *p == '_' || *p == '*' || *p == '%')
			continue;
		return (0);
	}
	return (1);
}

static int
zfsd_nfs_sec_ok(const char *v)
{
	const char *p;

	if (v == NULL || v[0] == '\0')
		return (0);
	for (p = v; *p != '\0'; p++) {
		if ((*p >= 'a' && *p <= 'z') ||
		    (*p >= '0' && *p <= '9') ||
		    *p == ',' || *p == ':')
			continue;
		return (0);
	}
	return (1);
}

static int
zfsd_nfs_write_lines(FILE *fp, const char *mp, const char *shareopts)
{
	char esc[MAXPATHLEN];
	char extra[512];
	char opts_dup[512];
	char secbuf[32];
	char hostv[32][256];
	char hosta[32][4];
	char *cur, *comma, *eq, *h, *hn;
	const char *opts, *curkey;
	const char *defacc = "rw";
	int nhosts = 0, i, err;

	err = zfsd_nfs_escape(mp, esc, sizeof (esc));
	if (err != 0)
		return (err);
	opts = shareopts;
	if (opts == NULL || opts[0] == '\0' || strcmp(opts, "on") == 0)
		opts = "rw,crossmnt";
	if (strlen(opts) >= sizeof (opts_dup))
		return (E2BIG);
	(void) strlcpy(opts_dup, opts, sizeof (opts_dup));
	(void) strlcpy(extra, "no_subtree_check,mountpoint", sizeof (extra));
	(void) strlcpy(secbuf, "sys", sizeof (secbuf));

	cur = opts_dup;
	while (cur != NULL && *cur != '\0') {
		comma = strchr(cur, ',');
		if (comma != NULL)
			*comma = '\0';
		eq = strchr(cur, '=');
		if (eq != NULL)
			*eq = '\0';
		if (cur[0] == '\0')
			goto next;
		if (strcmp(cur, "sec") == 0) {
			if (eq != NULL && eq[1] != '\0') {
				if (!zfsd_nfs_sec_ok(eq + 1))
					return (EINVAL);
				(void) strlcpy(secbuf, eq + 1, sizeof (secbuf));
			}
			goto next;
		}
		if (strcmp(cur, "rw") == 0 || strcmp(cur, "ro") == 0) {
			defacc = (*cur == 'r' && cur[1] == 'w') ? "rw" : "ro";
			if (eq == NULL || eq[1] == '\0')
				goto next;
			h = eq + 1;
			while (h != NULL && *h != '\0') {
				char hostbuf[256];

				hostbuf[0] = '\0';
				if (*h == '[') {
					h++;
					hn = strchr(h, ']');
					if (hn == NULL)
						return (EINVAL);
					*hn = '\0';
					(void) strlcpy(hostbuf, h, sizeof (hostbuf));
					hn++;
					if (*hn == '/') {
						char *cidr = hn;
						hn = strchr(hn, ':');
						if (hn != NULL) {
							*hn = '\0';
							hn++;
						}
						(void) strlcat(hostbuf, cidr,
						    sizeof (hostbuf));
					} else if (*hn == ':') {
						hn++;
					} else if (*hn != '\0') {
						return (EINVAL);
					} else {
						hn = NULL;
					}
				} else {
					hn = strchr(h, ':');
					if (hn != NULL) {
						*hn = '\0';
						hn++;
					}
					if (*h == '@')
						h++;
					(void) strlcpy(hostbuf, h,
					    sizeof (hostbuf));
				}
				if (hostbuf[0] != '\0') {
					if (!zfsd_nfs_host_ok(hostbuf))
						return (EINVAL);
					if (nhosts < 32) {
						(void) strlcpy(hostv[nhosts],
						    hostbuf, sizeof (hostv[0]));
						(void) strlcpy(hosta[nhosts],
						    defacc, sizeof (hosta[0]));
						nhosts++;
					}
				}
				h = hn;
			}
			goto next;
		}
		if (strcmp(cur, "anon") == 0)
			curkey = "anonuid";
		else if (strcmp(cur, "root_mapping") == 0) {
			(void) strlcat(extra, ",root_squash", sizeof (extra));
			curkey = "anonuid";
		} else if (strcmp(cur, "nosub") == 0)
			curkey = "subtree_check";
		else
			curkey = cur;
		if (!zfsd_nfs_tok_ok(curkey, eq != NULL ? eq + 1 : NULL))
			return (EINVAL);
		if (secpolicy_zfs(CRED()) != 0 &&
		    !zfsd_nfs_deleg_tok_ok(curkey))
			return (EPERM);
		(void) strlcat(extra, ",", sizeof (extra));
		(void) strlcat(extra, curkey, sizeof (extra));
		if (eq != NULL && eq[1] != '\0') {
			(void) strlcat(extra, "=", sizeof (extra));
			(void) strlcat(extra, eq + 1, sizeof (extra));
		}
next:
		cur = comma != NULL ? comma + 1 : NULL;
	}

	if (nhosts == 0) {
		if (fprintf(fp, "%s *(sec=%s,%s,%s)\n", esc, secbuf, defacc,
		    extra) < 0)
			return (EIO);
		return (0);
	}
	for (i = 0; i < nhosts; i++) {
		if (fprintf(fp, "%s %s(sec=%s,%s,%s)\n", esc, hostv[i],
		    secbuf, hosta[i], extra) < 0)
			return (EIO);
	}
	return (0);
}

static int
zfsd_nfs_lock(int *fdp)
{
	int fd, err;

	*fdp = -1;
	if (mkdir(ZFSD_EXPORTS_DIR, 0755) != 0 && errno != EEXIST)
		return (errno);
	fd = open(ZFSD_EXPORTS_LOCK, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (fd < 0)
		return (errno);
	while ((err = flock(fd, LOCK_EX)) != 0 && errno == EINTR)
		;
	if (err != 0) {
		err = errno;
		(void) close(fd);
		return (err);
	}
	*fdp = fd;
	return (0);
}

static int
zfsd_nfs_copy_skip(FILE *out, const char *esc)
{
	FILE *in;
	char *buf = NULL;
	size_t buflen = 0;
	size_t mlen = strlen(esc);

	if (fputs(ZFSD_NFS_HEADER, out) < 0)
		return (EIO);
	in = fopen(ZFSD_EXPORTS_FILE, "re");
	if (in == NULL)
		return (errno == ENOENT ? 0 : errno);
	while (getline(&buf, &buflen, in) != -1) {
		char *sep;

		if (buf[0] == '\n' || buf[0] == '#')
			continue;
		sep = strpbrk(buf, "\t \n");
		if (sep != NULL && (size_t)(sep - buf) == mlen &&
		    strncmp(buf, esc, mlen) == 0)
			continue;
		if (fputs(buf, out) < 0) {
			free(buf);
			(void) fclose(in);
			return (EIO);
		}
	}
	free(buf);
	(void) fclose(in);
	return (0);
}

static int
zfsd_nfs_rewrite(const char *mnt, const char *opts, int enable)
{
	char tmp[sizeof (ZFSD_EXPORTS_FILE) + 16];
	char esc[MAXPATHLEN];
	int lfd = -1, tfd, err;
	FILE *fp;

	err = zfsd_nfs_escape(mnt, esc, sizeof (esc));
	if (err != 0)
		return (err);
	err = zfsd_nfs_lock(&lfd);
	if (err != 0)
		return (err);
	(void) snprintf(tmp, sizeof (tmp), "%s.XXXXXX", ZFSD_EXPORTS_FILE);
	tfd = mkostemp(tmp, O_CLOEXEC);
	if (tfd < 0) {
		err = errno;
		(void) close(lfd);
		return (err);
	}
	fp = fdopen(tfd, "w");
	if (fp == NULL) {
		err = errno;
		(void) close(tfd);
		(void) unlink(tmp);
		(void) close(lfd);
		return (err);
	}
	err = zfsd_nfs_copy_skip(fp, esc);
	if (err == 0 && enable)
		err = zfsd_nfs_write_lines(fp, mnt, opts);
	if (err == 0 && fflush(fp) != 0)
		err = EIO;
	if (err == 0)
		(void) fchmod(fileno(fp), 0644);
	if (err == 0 && rename(tmp, ZFSD_EXPORTS_FILE) != 0)
		err = errno;
	if (err != 0)
		(void) unlink(tmp);
	(void) fclose(fp);
	(void) flock(lfd, LOCK_UN);
	(void) close(lfd);
	return (err);
}

int
zfsd_nfs_available(void)
{
	/*
	 * Same probe as libzfs nfs_available(): the exportfs binary,
	 * not a running nfsd. Disable/unshare must succeed when it is
	 * missing so mountpoint changes do not fail on a box with no NFS.
	 */
	return (access("/usr/sbin/exportfs", F_OK) == 0);
}

int
zfsd_nfs_exportfs(void)
{
	char *argv[] = {
		(char *)"/usr/sbin/exportfs",
		(char *)"-ra",
		NULL
	};

	if (!zfsd_nfs_available())
		return (0);
	if (access(argv[0], X_OK) != 0)
		return (0);
	return (zfsd_run(argv));
}

int
zfsd_nfs_enable(const char *mnt, const char *opts)
{
	int err;

	if (!zfsd_nfs_available())
		return (ENOSYS);
	err = zfsd_nfs_rewrite(mnt, opts, 1);

	if (err != 0)
		return (err);
	return (zfsd_nfs_exportfs());
}

int
zfsd_nfs_disable(const char *mnt)
{
	int err;

	if (!zfsd_nfs_available())
		return (0);
	err = zfsd_nfs_rewrite(mnt, NULL, 0);

	if (err != 0)
		return (err);
	return (zfsd_nfs_exportfs());
}

int
zfsd_nfs_truncate(void)
{
	int lfd = -1, err;

	if (!zfsd_nfs_available())
		return (0);
	err = zfsd_nfs_lock(&lfd);
	if (err != 0)
		return (err);
	if (truncate(ZFSD_EXPORTS_FILE, 0) != 0 && errno != ENOENT)
		err = errno;
	(void) flock(lfd, LOCK_UN);
	(void) close(lfd);
	return (err);
}

#endif /* __linux__ */

#ifndef __linux__
int
zfsd_nfs_available(void)
{
	return (0);
}

int
zfsd_nfs_enable(const char *mnt, const char *opts)
{
	(void) mnt;
	(void) opts;
	return (ENOTSUP);
}

int
zfsd_nfs_disable(const char *mnt)
{
	(void) mnt;
	return (0);
}

int
zfsd_nfs_exportfs(void)
{
	return (0);
}

int
zfsd_nfs_truncate(void)
{
	return (0);
}
#endif
