# SPDX-License-Identifier: CDDL-1.0
if BUILD_ZFSD
zfsd_CPPFLAGS  = -I$(top_srcdir)/cmd/zfsd/include -DZFSD_BUILD
zfsd_CPPFLAGS += $(AM_CPPFLAGS) $(LIBZPOOL_CPPFLAGS) $(FUSE3_CFLAGS)
zfsd_CPPFLAGS += -DFUSE_USE_VERSION=31
zfsd_CFLAGS    = $(AM_CFLAGS)

sbin_PROGRAMS   += zfsd
CPPCHECKTARGETS += zfsd

zfsd_SOURCES = \
	%D%/zfsd.c \
	%D%/zfsd_ioctl.c \
	%D%/zfsd_onexit.c \
	%D%/zfsd_policy.c \
	%D%/zfsd_nfs.c \
	%D%/zfsd_smb.c \
	%D%/zfsd_ctldir.c \
	%D%/zfsd_zvol.c \
	%D%/zfsd_zpl.c \
	%D%/zfsd_vfsops.c \
	%D%/zfsd_znode.c \
	%D%/zfsd_dir.c \
	%D%/zfsd_vnops.c \
	%D%/zfsd_acl.c \
	%D%/zfsd_uio.c \
	%D%/zfsd_sa.c \
	%D%/zfsd_zpl.h \
	%D%/zfsd_impl.h \
	%D%/zfsd_zvol.h \
	%D%/include/sys/atomic.h \
	%D%/include/sys/file.h \
	%D%/include/sys/param.h \
	%D%/include/sys/policy.h \
	%D%/include/sys/sunddi.h \
	%D%/include/sys/uio.h \
	%D%/include/sys/vfs.h \
	%D%/include/sys/vnode.h \
	%D%/include/sys/zfs_acl_impl.h \
	%D%/include/sys/zfs_ctldir.h \
	%D%/include/sys/zfs_dir.h \
	%D%/include/sys/zfs_vfsops_os.h \
	%D%/include/sys/zfs_vnops_os.h \
	%D%/include/sys/zfs_znode_impl.h \
	%D%/include/sys/zpl.h \
	module/zfs/zfs_vnops.c \
	module/zfs/zfs_log.c \
	module/zfs/zfs_replay.c \
	module/zfs/zfs_quota.c \
	module/zfs/dataset_kstats.c \
	module/zfs/zfs_ioctl.c

zfsd_LDADD = \
	libzpool.la \
	libzfs_core.la \
	libnvpair.la \
	$(FUSE3_LIBS)
endif
