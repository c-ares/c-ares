#***************************************************************************
#
# Copyright (C) Daniel Stenberg et al
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose and without fee is hereby granted, provided
# that the above copyright notice appear in all copies and that both that
# copyright notice and this permission notice appear in supporting
# documentation, and that the name of M.I.T. not be used in advertising or
# publicity pertaining to distribution of the software without specific,
# written prior permission.  M.I.T. makes no representations about the
# suitability of this software for any purpose.  It is provided "as is"
# without express or implied warranty.
#
# SPDX-License-Identifier: MIT
#***************************************************************************

# File version for 'aclocal' use. Keep it a single number.
# serial 11


dnl CARES_CHECK_OPTION_SYMBOL_HIDING
dnl -------------------------------------------------
dnl Verify if configure has been invoked with option
dnl --enable-symbol-hiding or --disable-symbol-hiding,
dnl setting shell variable want_symbol_hiding value.

AC_DEFUN([CARES_CHECK_OPTION_SYMBOL_HIDING], [
  AC_BEFORE([$0],[CARES_CHECK_COMPILER_SYMBOL_HIDING])dnl
  AC_MSG_CHECKING([whether to enable hiding of library internal symbols])
  OPT_SYMBOL_HIDING="default"
  AC_ARG_ENABLE(symbol-hiding,
AS_HELP_STRING([--enable-symbol-hiding],[Enable hiding of library internal symbols])
AS_HELP_STRING([--disable-symbol-hiding],[Disable hiding of library internal symbols]),
  OPT_SYMBOL_HIDING=$enableval)
  case "$OPT_SYMBOL_HIDING" in
    no)
      dnl --disable-symbol-hiding option used.
      dnl This is an indication to not attempt hiding of library internal
      dnl symbols. Default symbol visibility will be used, which normally
      dnl exposes all library internal symbols.
      want_symbol_hiding="no"
      AC_MSG_RESULT([no])
      ;;
    default)
      dnl configure's symbol-hiding option not specified.
      dnl Handle this as if --enable-symbol-hiding option was given.
      want_symbol_hiding="yes"
      AC_MSG_RESULT([yes])
      ;;
    *)
      dnl --enable-symbol-hiding option used.
      dnl This is an indication to attempt hiding of library internal
      dnl symbols. This is only supported on some compilers/linkers.
      want_symbol_hiding="yes"
      AC_MSG_RESULT([yes])
      ;;
  esac
])



dnl CARES_CONFIGURE_SYMBOL_HIDING
dnl -------------------------------------------------
dnl Depending on --enable-symbol-hiding or --disable-symbol-hiding
dnl configure option, and compiler capability to actually honor such
dnl option, this will modify compiler flags as appropriate and also
dnl provide needed definitions for configuration and Makefile.am files.
dnl This macro should not be used until all compilation tests have
dnl been done to prevent interferences on other tests.

AC_DEFUN([CARES_CONFIGURE_SYMBOL_HIDING], [
  AC_MSG_CHECKING([whether hiding of library internal symbols will actually happen])
  CFLAG_CARES_SYMBOL_HIDING=""
  doing_symbol_hiding="no"
  if test x"$ac_cv_native_windows" != "xyes" &&
    test "$want_symbol_hiding" = "yes" &&
    test "$supports_symbol_hiding" = "yes"; then
    doing_symbol_hiding="yes"
    CFLAG_CARES_SYMBOL_HIDING="$symbol_hiding_CFLAGS"
    AC_MSG_RESULT([yes])
  else
    AC_MSG_RESULT([no])
  fi
  AM_CONDITIONAL(DOING_CARES_SYMBOL_HIDING, test x$doing_symbol_hiding = xyes)
  AC_SUBST(CFLAG_CARES_SYMBOL_HIDING)
  if test "$doing_symbol_hiding" = "yes"; then
    AC_DEFINE_UNQUOTED(CARES_SYMBOL_HIDING, 1,
      [Defined for build with symbol hiding.])
  fi
])

