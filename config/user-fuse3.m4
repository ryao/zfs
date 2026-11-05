dnl # SPDX-License-Identifier: CDDL-1.0
dnl #
dnl # libfuse3 is required to build zfsd, the userspace /dev/zfs daemon.
dnl #
AC_DEFUN([ZFS_AC_CONFIG_USER_FUSE3], [
	PKG_CHECK_MODULES([FUSE3], [fuse3], [
		have_fuse3=yes
	], [
		AC_CHECK_LIB([fuse3], [fuse_new], [
			FUSE3_LIBS="-lfuse3 -lpthread"
			FUSE3_CFLAGS="-D_FILE_OFFSET_BITS=64"
			have_fuse3=yes
		], [
			have_fuse3=no
		])
	])
	AC_MSG_CHECKING([whether zfsd will be built])
	AS_IF([test "x$have_fuse3" = xyes], [
		AC_MSG_RESULT([yes])
	], [
		AC_MSG_RESULT([no (libfuse3 not found)])
	])
	AC_SUBST([FUSE3_CFLAGS])
	AC_SUBST([FUSE3_LIBS])
])
