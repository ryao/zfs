dnl #
dnl # Use the AVL tree implementation based on the Linux kernel's Red-Black
dnl # tree implementation. This is only meant for debugging purposes.
dnl #
AC_DEFUN([ZFS_AC_AVL_EMULATION], [
	AC_MSG_CHECKING([whether SPL provides AVL tree emulation])
	AC_ARG_ENABLE([avl-emulation],
		[AS_HELP_STRING([--enable-avl-emulation],
		[Emulated AVL tree support from SPL @<:@default=check@:>@])])

	tmp_flags="$EXTRA_KCFLAGS"
	EXTRA_KCFLAGS="-include $SPL_OBJ/spl_config.h"
	ZFS_LINUX_TRY_COMPILE([
	],[
		void f(int i){return;}
		int i = SPL_AVL_EMULATION;
		f(i);
	],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_AVL_EMULATION, 1,
		          [bdev_logical_block_size() is available])
	],[
		AC_SUBST(USE_OWN_AVL, [avl])
		AC_MSG_RESULT(no)
	])
	EXTRA_KCFLAGS="$tmp_flags"

	AM_CONDITIONAL([USE_OWN_AVL], [test "x$HAVE_AVL_EMULATION" = x1])

])
