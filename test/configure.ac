AC_PREREQ(2.57)
AC_INIT([c-ares-test],[-],[-])
AC_CONFIG_SRCDIR([ares-test.cc])
AC_CONFIG_MACRO_DIR([../m4])

AM_INIT_AUTOMAKE([no-define])

dnl Checks for programs.
AC_PROG_CXX
AX_CXX_COMPILE_STDCXX_11([noext],[mandatory])
LT_INIT
AC_SUBST(LIBTOOL_DEPS)
AX_PTHREAD
AX_CODE_COVERAGE

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
