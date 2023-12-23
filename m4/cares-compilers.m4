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
# serial 75




dnl CARES_CONVERT_INCLUDE_TO_ISYSTEM
dnl -------------------------------------------------
dnl Changes standard include paths present in CFLAGS
dnl and CPPFLAGS into isystem include paths. This is
dnl done to prevent GNUC from generating warnings on
dnl headers from these locations, although on ancient
dnl GNUC versions these warnings are not silenced.

AC_DEFUN([CARES_CONVERT_INCLUDE_TO_ISYSTEM], [
  AC_REQUIRE([CARES_SHFUNC_SQUEEZE])dnl
  if test "$ax_cv_c_compiler_vendor" = "gnu" ||
    test "$ax_cv_c_compiler_vendor" = "clang"; then
    tmp_has_include="no"
    tmp_chg_FLAGS="$CFLAGS"
    for word1 in $tmp_chg_FLAGS; do
      case "$word1" in
        -I*)
          tmp_has_include="yes"
          ;;
      esac
    done
    if test "$tmp_has_include" = "yes"; then
      tmp_chg_FLAGS=`echo "$tmp_chg_FLAGS" | "$SED" 's/^-I/ -isystem /g'`
      tmp_chg_FLAGS=`echo "$tmp_chg_FLAGS" | "$SED" 's/ -I/ -isystem /g'`
      CFLAGS="$tmp_chg_FLAGS"
      squeeze CFLAGS
    fi
    tmp_has_include="no"
    tmp_chg_FLAGS="$CPPFLAGS"
    for word1 in $tmp_chg_FLAGS; do
      case "$word1" in
        -I*)
          tmp_has_include="yes"
          ;;
      esac
    done
    if test "$tmp_has_include" = "yes"; then
      tmp_chg_FLAGS=`echo "$tmp_chg_FLAGS" | "$SED" 's/^-I/ -isystem /g'`
      tmp_chg_FLAGS=`echo "$tmp_chg_FLAGS" | "$SED" 's/ -I/ -isystem /g'`
      CPPFLAGS="$tmp_chg_FLAGS"
      squeeze CPPFLAGS
    fi
  fi
])

dnl CARES_SHFUNC_SQUEEZE
dnl -------------------------------------------------
dnl Declares a shell function squeeze() which removes
dnl redundant whitespace out of a shell variable.

AC_DEFUN([CARES_SHFUNC_SQUEEZE], [
squeeze() {
  _sqz_result=""
  eval _sqz_input=\[$][$]1
  for _sqz_token in $_sqz_input; do
    if test -z "$_sqz_result"; then
      _sqz_result="$_sqz_token"
    else
      _sqz_result="$_sqz_result $_sqz_token"
    fi
  done
  eval [$]1=\$_sqz_result
  return 0
}
])



dnl CARES_CHECK_COMPILER_STRUCT_MEMBER_SIZE
dnl -------------------------------------------------
dnl Verifies if the compiler is capable of handling the
dnl size of a struct member, struct which is a function
dnl result, as a compilation-time condition inside the
dnl type definition of a constant array.

AC_DEFUN([CARES_CHECK_COMPILER_STRUCT_MEMBER_SIZE], [
  AC_REQUIRE([CARES_CHECK_COMPILER_ARRAY_SIZE_NEGATIVE])dnl
  AC_MSG_CHECKING([if compiler struct member size checking works])
  tst_compiler_check_one_works="unknown"
  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[
      struct mystruct {
        int  mi;
        char mc;
        struct mystruct *next;
      };
      struct mystruct myfunc();
      typedef char good_t1[sizeof(myfunc().mi) == sizeof(int)  ? 1 : -1 ];
      typedef char good_t2[sizeof(myfunc().mc) == sizeof(char) ? 1 : -1 ];
    ]],[[
      good_t1 dummy1;
      good_t2 dummy2;
    ]])
  ],[
    tst_compiler_check_one_works="yes"
  ],[
    tst_compiler_check_one_works="no"
    sed 's/^/cc-src: /' conftest.$ac_ext >&6
    sed 's/^/cc-err: /' conftest.err >&6
  ])
  tst_compiler_check_two_works="unknown"
  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[
      struct mystruct {
        int  mi;
        char mc;
        struct mystruct *next;
      };
      struct mystruct myfunc();
      typedef char bad_t1[sizeof(myfunc().mi) != sizeof(int)  ? 1 : -1 ];
      typedef char bad_t2[sizeof(myfunc().mc) != sizeof(char) ? 1 : -1 ];
    ]],[[
      bad_t1 dummy1;
      bad_t2 dummy2;
    ]])
  ],[
    tst_compiler_check_two_works="no"
  ],[
    tst_compiler_check_two_works="yes"
  ])
  if test "$tst_compiler_check_one_works" = "yes" &&
    test "$tst_compiler_check_two_works" = "yes"; then
    AC_MSG_RESULT([yes])
  else
    AC_MSG_RESULT([no])
    AC_MSG_ERROR([compiler fails struct member size checking.])
  fi
])


dnl CARES_CHECK_COMPILER_SYMBOL_HIDING
dnl -------------------------------------------------
dnl Verify if compiler supports hiding library internal symbols, setting
dnl shell variable supports_symbol_hiding value as appropriate, as well as
dnl variables symbol_hiding_CFLAGS and symbol_hiding_EXTERN when supported.

AC_DEFUN([CARES_CHECK_COMPILER_SYMBOL_HIDING], [
  AC_BEFORE([$0],[CARES_CONFIGURE_SYMBOL_HIDING])dnl
  AC_MSG_CHECKING([if compiler supports hiding library internal symbols])
  supports_symbol_hiding="no"
  symbol_hiding_CFLAGS=""
  symbol_hiding_EXTERN=""
  tmp_CFLAGS=""
  tmp_EXTERN=""
  case "$ax_cv_c_compiler_vendor" in
    clang)
      dnl All versions of clang support -fvisibility=
      tmp_EXTERN="__attribute__ ((__visibility__ (\"default\")))"
      tmp_CFLAGS="-fvisibility=hidden"
      supports_symbol_hiding="yes"
      ;;
    gnu)
      dnl Only gcc 3.4 or later
      if test "$compiler_num" -ge "304"; then
        if $CC --help --verbose 2>&1 | grep fvisibility= > /dev/null ; then
          tmp_EXTERN="__attribute__ ((__visibility__ (\"default\")))"
          tmp_CFLAGS="-fvisibility=hidden"
          supports_symbol_hiding="yes"
        fi
      fi
      ;;
    intel)
      dnl Only icc 9.0 or later
      if test "$compiler_num" -ge "900"; then
        if $CC --help --verbose 2>&1 | grep fvisibility= > /dev/null ; then
          tmp_save_CFLAGS="$CFLAGS"
          CFLAGS="$CFLAGS -fvisibility=hidden"
          AC_LINK_IFELSE([
            AC_LANG_PROGRAM([[
#             include <stdio.h>
            ]],[[
              printf("icc fvisibility bug test");
            ]])
          ],[
            tmp_EXTERN="__attribute__ ((__visibility__ (\"default\")))"
            tmp_CFLAGS="-fvisibility=hidden"
            supports_symbol_hiding="yes"
          ])
          CFLAGS="$tmp_save_CFLAGS"
        fi
      fi
      ;;
    sun)
      if $CC 2>&1 | grep flags >/dev/null && $CC -flags | grep xldscope= >/dev/null ; then
        tmp_EXTERN="__global"
        tmp_CFLAGS="-xldscope=hidden"
        supports_symbol_hiding="yes"
      fi
      ;;
  esac
  if test "$supports_symbol_hiding" = "yes"; then
    tmp_save_CFLAGS="$CFLAGS"
    CFLAGS="$tmp_save_CFLAGS $tmp_CFLAGS"
    squeeze CFLAGS
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $tmp_EXTERN char *dummy(char *buff);
        char *dummy(char *buff)
        {
         if(buff)
           return ++buff;
         else
           return buff;
        }
      ]],[[
        char b[16];
        char *r = dummy(&b[0]);
        if(r)
          return (int)*r;
      ]])
    ],[
      supports_symbol_hiding="yes"
      if test -f conftest.err; then
        grep 'visibility' conftest.err >/dev/null
        if test "$?" -eq "0"; then
          supports_symbol_hiding="no"
        fi
      fi
    ],[
      supports_symbol_hiding="no"
      echo " " >&6
      sed 's/^/cc-src: /' conftest.$ac_ext >&6
      sed 's/^/cc-err: /' conftest.err >&6
      echo " " >&6
    ])
    CFLAGS="$tmp_save_CFLAGS"
  fi
  if test "$supports_symbol_hiding" = "yes"; then
    AC_MSG_RESULT([yes])
    symbol_hiding_CFLAGS="$tmp_CFLAGS"
    symbol_hiding_EXTERN="$tmp_EXTERN"
  else
    AC_MSG_RESULT([no])
  fi
])



dnl CARES_VAR_MATCH (VARNAME, VALUE)
dnl -------------------------------------------------
dnl Verifies if shell variable VARNAME contains VALUE.
dnl Contents of variable VARNAME and VALUE are handled
dnl as whitespace separated lists of words. If at least
dnl one word of VALUE is present in VARNAME the match
dnl is considered positive, otherwise false.

AC_DEFUN([CARES_VAR_MATCH], [
  ac_var_match_word="no"
  for word1 in $[$1]; do
    for word2 in [$2]; do
      if test "$word1" = "$word2"; then
        ac_var_match_word="yes"
      fi
    done
  done
])


dnl CARES_VAR_MATCH_IFELSE (VARNAME, VALUE,
dnl                        [ACTION-IF-MATCH], [ACTION-IF-NOT-MATCH])
dnl -------------------------------------------------
dnl This performs a CURL_VAR_MATCH check and executes
dnl first branch if the match is positive, otherwise
dnl the second branch is executed.

AC_DEFUN([CARES_VAR_MATCH_IFELSE], [
  CARES_VAR_MATCH([$1],[$2])
  if test "$ac_var_match_word" = "yes"; then
  ifelse($3,,:,[$3])
  ifelse($4,,,[else
    $4])
  fi
])


dnl CARES_VAR_STRIP (VARNAME, VALUE)
dnl -------------------------------------------------
dnl Contents of variable VARNAME and VALUE are handled
dnl as whitespace separated lists of words. Each word
dnl from VALUE is removed from VARNAME when present.

AC_DEFUN([CARES_VAR_STRIP], [
  AC_REQUIRE([CARES_SHFUNC_SQUEEZE])dnl
  ac_var_stripped=""
  for word1 in $[$1]; do
    ac_var_strip_word="no"
    for word2 in [$2]; do
      if test "$word1" = "$word2"; then
        ac_var_strip_word="yes"
      fi
    done
    if test "$ac_var_strip_word" = "no"; then
      ac_var_stripped="$ac_var_stripped $word1"
    fi
  done
  dnl squeeze whitespace out of result
  [$1]="$ac_var_stripped"
  squeeze [$1]
])

