#!/bin/ksh
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/cli_root/zfs_copies/zfs_copies.kshlib

#
# DESCRIPTION:
#	Verify that copies cannot be set with pool version 1
#
# STRATEGY:
#	1. Create filesystems with copies set in a pool with version 1
#	2. Verify that the create operations fail
#

verify_runnable "global"

function cleanup
{
	if poolexists $ZPOOL_VERSION_1_NAME; then
		destroy_pool $ZPOOL_VERSION_1_NAME
	fi

	if [[ -f $TESTDIR/$ZPOOL_VERSION_1_FILES ]]; then
		rm -f $TESTDIR/$ZPOOL_VERSION_1_FILES
	fi

	if is_linux; then
		echo 1 > /sys/module/zfs/parameters/zfs_vdev_parallel_open_enabled
	fi
}

log_assert "Verify that copies cannot be set with pool version 1"
log_onexit cleanup

if is_linux; then
	echo 0 > /sys/module/zfs/parameters/zfs_vdev_parallel_open_enabled
fi

$CP $STF_SUITE/tests/functional/cli_root/zpool_upgrade/blockfiles/$ZPOOL_VERSION_1_FILES $TESTDIR
$BUNZIP2 $TESTDIR/$ZPOOL_VERSION_1_FILES
log_must $ZPOOL import -d $TESTDIR $ZPOOL_VERSION_1_NAME
log_must $ZFS create $ZPOOL_VERSION_1_NAME/$TESTFS
log_must $ZFS create -V 1m $ZPOOL_VERSION_1_NAME/$TESTVOL

for val in 3 2 1; do
	for ds in $ZPOOL_VERSION_1_NAME/$TESTFS $ZPOOL_VERSION_1_NAME/$TESTVOL; do
		log_mustnot $ZFS set copies=$val $ds
	done
	for ds in $ZPOOL_VERSION_1_NAME/$TESTFS1 $ZPOOL_VERSION_1_NAME/$TESTVOL1; do
		log_mustnot $ZFS create -o copies=$val $ds
	done
done

log_pass "Verification pass: copies cannot be set with pool version 1. "
