dnl #
dnl # Linux 2.6.33 - 3.x API
dnl #
AC_DEFUN([ZFS_AC_KERNEL_BLK_DEV_DISCARD_ZEROES_DATA_CHECK], [
	ZFS_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		struct queue_limits test;
		test.discard_zeroes_data = 1;
	],[
		AC_MSG_RESULT([discard_zeroes_data])
		AC_DEFINE(HAVE_BLK_DEV_DISCARD_ZEROES_DATA, 1,
			[struct queue_limits with discard_zeroes_data])
	],[
	])
])

AC_DEFUN([ZFS_AC_KERNEL_BLK_DEV_DISCARD_ZEROES_DATA], [
	AC_MSG_CHECKING([whether struct queue_limits has])
	ZFS_AC_KERNEL_BLK_DEV_DISCARD_ZEROES_DATA_CHECK
])
