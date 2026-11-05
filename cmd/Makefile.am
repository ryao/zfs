# SPDX-License-Identifier: CDDL-1.0
bin_SCRIPTS =
bin_PROGRAMS =
sbin_SCRIPTS =
sbin_PROGRAMS =
dist_bin_SCRIPTS =
zfsexec_PROGRAMS =
mounthelper_PROGRAMS =


sbin_SCRIPTS      += fsck.zfs
SHELLCHECKSCRIPTS += fsck.zfs
CLEANFILES        += fsck.zfs
dist_noinst_DATA  += %D%/fsck.zfs.in
$(call SUBST,fsck.zfs,%D%/)


sbin_PROGRAMS   += zfs_ids_to_path
CPPCHECKTARGETS += zfs_ids_to_path

zfs_ids_to_path_SOURCES = \
	%D%/zfs_ids_to_path.c

zfs_ids_to_path_LDADD = \
	libzfs.la


zhack_CPPFLAGS = $(AM_CPPFLAGS) $(LIBZPOOL_CPPFLAGS)

sbin_PROGRAMS   += zhack
CPPCHECKTARGETS += zhack

zhack_SOURCES = \
	%D%/zhack.c

zhack_LDADD = \
	libzpool.la \
	libzfs_core.la \
	libnvpair.la \
	librange_tree.la

ztest_CFLAGS    = $(AM_CFLAGS) $(KERNEL_CFLAGS)
ztest_CPPFLAGS  = $(AM_CPPFLAGS) $(LIBZPOOL_CPPFLAGS)

sbin_PROGRAMS   += ztest
CPPCHECKTARGETS += ztest

ztest_SOURCES = \
	%D%/ztest.c

ztest_LDADD = \
	libzpool.la \
	libzfs_core.la \
	libnvpair.la

ztest_LDADD += -lm


include $(srcdir)/%D%/zfsd/Makefile.am


include $(srcdir)/%D%/raidz_test/Makefile.am
include $(srcdir)/%D%/zdb/Makefile.am
include $(srcdir)/%D%/zfs/Makefile.am
include $(srcdir)/%D%/zinject/Makefile.am
include $(srcdir)/%D%/zpool/Makefile.am
include $(srcdir)/%D%/zpool_influxdb/Makefile.am
include $(srcdir)/%D%/zstream/Makefile.am


if BUILD_LINUX
mounthelper_PROGRAMS += mount.zfs
CPPCHECKTARGETS      += mount.zfs

mount_zfs_SOURCES = \
	%D%/mount_zfs.c

mount_zfs_LDADD = \
	libzfs.la \
	libzfs_core.la \
	libnvpair.la

dist_noinst_SCRIPTS += %D%/zfsd-mount

# fuse.zfs remounts (mountpoint only) are dispatched to mount.fuse.zfs.
# "mount -o remount dataset mnt" skips helpers; sbin/mount is that check
# and is what the ZTS constrained path finds before /usr/bin/mount.
cmd-mount-zfs-install-exec-hook:
	$(MKDIR_P) $(DESTDIR)$(mounthelperdir)
	cd $(DESTDIR)$(mounthelperdir) && $(LN_S) -f mount.zfs mount.fuse.zfs
	$(MKDIR_P) $(DESTDIR)$(sbindir)
	$(INSTALL) -m 755 $(srcdir)/%D%/zfsd-mount $(DESTDIR)$(sbindir)/mount

INSTALL_EXEC_HOOKS += cmd-mount-zfs-install-exec-hook

CPPCHECKTARGETS += raidz_test


sbin_PROGRAMS   += zgenhostid
CPPCHECKTARGETS += zgenhostid

zgenhostid_SOURCES = \
	%D%/zgenhostid.c


dist_bin_SCRIPTS  += %D%/zvol_wait
SHELLCHECKSCRIPTS += %D%/zvol_wait


include $(srcdir)/%D%/zed/Makefile.am
endif


if USING_PYTHON
bin_SCRIPTS      += zarcsummary     zarcstat        dbufstat        zilstat
CLEANFILES       += zarcsummary     zarcstat        dbufstat        zilstat
dist_noinst_DATA += %D%/zarcsummary %D%/zarcstat.in %D%/dbufstat.in %D%/zilstat.in

$(call SUBST,zarcstat,%D%/)
$(call SUBST,dbufstat,%D%/)
$(call SUBST,zilstat,%D%/)
zarcsummary: %D%/zarcsummary
	$(AM_V_at)cp $< $@
endif

PHONY += cmd
cmd: $(bin_SCRIPTS) $(bin_PROGRAMS) $(sbin_SCRIPTS) $(sbin_PROGRAMS) $(dist_bin_SCRIPTS) $(zfsexec_PROGRAMS) $(mounthelper_PROGRAMS)
