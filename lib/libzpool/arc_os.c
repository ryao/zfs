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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2018, Joyent, Inc.
 * Copyright (c) 2011, 2019 by Delphix. All rights reserved.
 * Copyright (c) 2014 by Saso Kiselkov. All rights reserved.
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/zfs_context.h>
#include <sys/arc_impl.h>
#ifdef __linux__
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#endif

/*
 * Return a default max arc size based on the amount of physical memory.
 * This may be overridden by tuning the zfs_arc_max module parameter.
 */
uint64_t
arc_default_max(uint64_t min, uint64_t allmem)
{
	uint64_t size;

	if (allmem >= 1 << 30)
		size = allmem - (1 << 30);
	else
		size = min;
	return (MAX(allmem * 5 / 8, size));
}

#ifdef __linux__
/*
 * vm.overcommit_memory=2 fails mappings once Committed_AS hits
 * CommitLimit, and nothing in the kernel reclaims them for us.
 * Report the bytes still reservable, minus a reserve for the test
 * processes (64 * 8MiB glibc stacks, zpool, zdb). A negative value
 * makes arc_reclaim_needed() shrink the ARC before malloc fails.
 * overcommit_memory=1 never fails a mapping for size, so keep the
 * historical "no pressure" answer there.
 */
static int
arc_overcommit_mode(void)
{
	static int mode = -1;
	char buf[16];
	ssize_t n;
	int fd;

	if (mode >= 0)
		return (mode);
	fd = open("/proc/sys/vm/overcommit_memory", O_RDONLY);
	if (fd < 0)
		return (mode = 1);
	n = read(fd, buf, sizeof (buf) - 1);
	(void) close(fd);
	if (n <= 0)
		return (mode = 1);
	buf[n] = '\0';
	mode = (int)strtol(buf, NULL, 10);
	if (mode < 0 || mode > 2)
		mode = 1;
	return (mode);
}

static int64_t
arc_commit_headroom(void)
{
	static int64_t cached = INT64_MAX;
	static hrtime_t last = 0;
	hrtime_t now = gethrtime();
	char buf[2048];
	ssize_t n;
	int fd;
	unsigned long long commit_limit = 0, committed = 0, memavail = 0;
	int64_t commit_free, avail, reserve, head;
	char *line, *nl;

	if (last != 0 && now - last < 50 * 1000 * 1000)
		return (cached);
	last = now;

	fd = open("/proc/meminfo", O_RDONLY);
	if (fd < 0)
		return (cached);
	n = read(fd, buf, sizeof (buf) - 1);
	(void) close(fd);
	if (n <= 0)
		return (cached);
	buf[n] = '\0';
	for (line = buf; line != NULL && *line != '\0'; line = nl) {
		unsigned long long v;

		nl = strchr(line, '\n');
		if (nl != NULL)
			*nl++ = '\0';
		if (sscanf(line, "CommitLimit: %llu", &v) == 1)
			commit_limit = v;
		else if (sscanf(line, "Committed_AS: %llu", &v) == 1)
			committed = v;
		else if (sscanf(line, "MemAvailable: %llu", &v) == 1)
			memavail = v;
	}
	if (commit_limit == 0)
		return (cached);

	/* meminfo values are KiB. Leave room for non-ARC allocators. */
	reserve = (int64_t)commit_limit * 1024 / 8;
	if (reserve < (64LL << 20))
		reserve = 64LL << 20;
	if (reserve > (512LL << 20))
		reserve = 512LL << 20;
	if (committed >= commit_limit)
		commit_free = -((int64_t)(committed - commit_limit) * 1024);
	else
		commit_free = (int64_t)(commit_limit - committed) * 1024;
	avail = (int64_t)memavail * 1024;
	if (arc_overcommit_mode() == 2)
		head = commit_free - reserve;
	else
		head = avail - reserve;
	if (avail > 0 && avail - reserve < head)
		head = avail - reserve;
	cached = head;
	return (head);
}
#endif

int64_t
arc_available_memory(void)
{
	int64_t lowest = INT64_MAX;

#ifdef __linux__
	if (arc_overcommit_mode() != 1)
		lowest = arc_commit_headroom();
#endif
	/* Every 100 calls, free a small amount (ztest reclaim coverage). */
	if (lowest > (1LL << 30) && random_in_range(100) == 0)
		lowest = -1024;

	return (lowest);
}

int
arc_memory_throttle(spa_t *spa, uint64_t reserve, uint64_t txg)
{
	int64_t avail;

	(void) spa;
	(void) reserve;
	(void) txg;

	/*
	 * dsl_pool_dirty_space() delays the tx on EAGAIN. Without this,
	 * dirty dbufs are not evictable, so a long ZTS run commits RAM
	 * until __vm_enough_memory fails and the FUSE write never returns.
	 */
	avail = arc_available_memory();
	if (avail < 0) {
		uint64_t deficit = (uint64_t)(-avail);

		if (deficit < (8ULL << 20))
			deficit = 8ULL << 20;
		(void) arc_reduce_target_size(deficit);
		return (SET_ERROR(EAGAIN));
	}
	return (0);
}

uint64_t
arc_all_memory(void)
{
	return (ptob(physmem) / 2);
}

uint64_t
arc_free_memory(void)
{
	return (random_in_range(arc_all_memory() * 20 / 100));
}

void
arc_register_hotplug(void)
{
}

void
arc_unregister_hotplug(void)
{
}
