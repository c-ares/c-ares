# Copyright (C) The c-ares project and its contributors
# SPDX-License-Identifier: MIT


dnl CURL_CHECK_FUNC_CLOCK_GETTIME_MONOTONIC
dnl -------------------------------------------------
dnl Check if monotonic clock_gettime is available.

AC_DEFUN([CURL_CHECK_FUNC_CLOCK_GETTIME_MONOTONIC], [
  AC_CHECK_HEADERS(sys/types.h sys/time.h time.h)
  AC_MSG_CHECKING([for monotonic clock_gettime])
  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#ifdef TIME_WITH_SYS_TIME
#include <time.h>
#endif
#else
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#endif
    ]],[[
      struct timespec ts;
      (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    ]])
  ],[
    AC_MSG_RESULT([yes])
    ac_cv_func_clock_gettime="yes"
  ],[
    AC_MSG_RESULT([no])
    ac_cv_func_clock_gettime="no"
  ])
  dnl Definition of HAVE_CLOCK_GETTIME_MONOTONIC is intentionally postponed
  dnl until library linking and run-time checks for clock_gettime succeed.
])


dnl CURL_CHECK_LIBS_CLOCK_GETTIME_MONOTONIC
dnl -------------------------------------------------
dnl If monotonic clock_gettime is available then,
dnl check and prepended to LIBS any needed libraries.

AC_DEFUN([CURL_CHECK_LIBS_CLOCK_GETTIME_MONOTONIC], [
  AC_REQUIRE([CURL_CHECK_FUNC_CLOCK_GETTIME_MONOTONIC])dnl
  #
  if test "$ac_cv_func_clock_gettime" = "yes"; then
    #
    AC_MSG_CHECKING([for clock_gettime in libraries])
    #
    cares_cv_save_LIBS="$LIBS"
    cares_cv_gclk_LIBS="unknown"
    #
    for x_xlibs in '' '-lrt' '-lposix4' ; do
      if test "$cares_cv_gclk_LIBS" = "unknown"; then
        if test -z "$x_xlibs"; then
          LIBS="$cares_cv_save_LIBS"
        else
          LIBS="$x_xlibs $cares_cv_save_LIBS"
        fi
        AC_LINK_IFELSE([
          AC_LANG_PROGRAM([[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#ifdef TIME_WITH_SYS_TIME
#include <time.h>
#endif
#else
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#endif
          ]],[[
            struct timespec ts;
            (void)clock_gettime(CLOCK_MONOTONIC, &ts);
          ]])
        ],[
          cares_cv_gclk_LIBS="$x_xlibs"
        ])
      fi
    done
    #
    LIBS="$cares_cv_save_LIBS"
    #
    case X-"$cares_cv_gclk_LIBS" in
      X-unknown)
        AC_MSG_RESULT([cannot find clock_gettime])
        AC_MSG_WARN([HAVE_CLOCK_GETTIME_MONOTONIC will not be defined])
        ac_cv_func_clock_gettime="no"
        ;;
      X-)
        AC_MSG_RESULT([no additional lib required])
        ac_cv_func_clock_gettime="yes"
        ;;
      *)
        if test -z "$cares_cv_save_LIBS"; then
          LIBS="$cares_cv_gclk_LIBS"
        else
          LIBS="$cares_cv_gclk_LIBS $cares_cv_save_LIBS"
        fi
        AC_MSG_RESULT([$cares_cv_gclk_LIBS])
        ac_cv_func_clock_gettime="yes"
        ;;
    esac
    #
    dnl only do runtime verification when not cross-compiling
    if test "x$cross_compiling" != "xyes" &&
      test "$ac_cv_func_clock_gettime" = "yes"; then
      AC_MSG_CHECKING([if monotonic clock_gettime works])
      AC_RUN_IFELSE([
        AC_LANG_PROGRAM([[
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#ifdef TIME_WITH_SYS_TIME
#include <time.h>
#endif
#else
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#endif
        ]],[[
          struct timespec ts;
          if (0 == clock_gettime(CLOCK_MONOTONIC, &ts))
            exit(0);
          else
            exit(1);
        ]])
      ],[
        AC_MSG_RESULT([yes])
      ],[
        AC_MSG_RESULT([no])
        AC_MSG_WARN([HAVE_CLOCK_GETTIME_MONOTONIC will not be defined])
        ac_cv_func_clock_gettime="no"
        LIBS="$cares_cv_save_LIBS"
      ])
    fi
    #
    case "$ac_cv_func_clock_gettime" in
      yes)
        AC_DEFINE_UNQUOTED(HAVE_CLOCK_GETTIME_MONOTONIC, 1,
          [Define to 1 if you have the clock_gettime function and monotonic timer.])
        ;;
    esac
    #
  fi
  #
])


dnl CARES_DEFINE_UNQUOTED (VARIABLE, [VALUE])
dnl -------------------------------------------------
dnl Like AC_DEFINE_UNQUOTED this macro will define a C preprocessor
dnl symbol that can be further used in custom template configuration
dnl files. This macro, unlike AC_DEFINE_UNQUOTED, does not use a third
dnl argument for the description. Symbol definitions done with this
dnl macro are intended to be exclusively used in handcrafted *.h.in
dnl template files. Contrary to what AC_DEFINE_UNQUOTED does, this one
dnl prevents autoheader generation and insertion of symbol template
dnl stub and definition into the first configuration header file. Do
dnl not use this macro as a replacement for AC_DEFINE_UNQUOTED, each
dnl one serves different functional needs.

AC_DEFUN([CARES_DEFINE_UNQUOTED], [
cat >>confdefs.h <<_EOF
[@%:@define] $1 ifelse($#, 2, [$2], 1)
_EOF
])


