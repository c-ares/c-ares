AUTOMAKE_OPTIONS = foreign nostdinc

ACLOCAL_AMFLAGS = -I m4

# Specify our include paths here, and do it relative to $(top_srcdir) and
# $(top_builddir), to ensure that these paths which belong to the library
# being currently built and tested are searched before the library which
# might possibly already be installed in the system.

AM_CPPFLAGS = -I$(top_builddir)/include \
              -I$(top_srcdir)/include

lib_LTLIBRARIES = libcares.la

man_MANS = $(MANPAGES)

# adig and ahost are just sample programs and thus not mentioned with the
# regular sources and headers
EXTRA_DIST = Makefile.inc Makefile.dj Makefile.m32 Makefile.netware		\
 Makefile.msvc Makefile.Watcom config-win32.h ares_build.h.in $(CSOURCES)	\
 $(HHEADERS) config-dos.h

DISTCLEANFILES = ares_build.h

DIST_SUBDIRS = 

CARES_VERSION_INFO = -version-info 4:0:2
# This flag accepts an argument of the form current[:revision[:age]]. So,
# passing -version-info 3:12:1 sets current to 3, revision to 12, and age to
# 1.
#
# If either revision or age are omitted, they default to 0. Also note that age
# must be less than or equal to the current interface number.
#
# Here are a set of rules to help you update your library version information: 
#
# 1.Start with version information of 0:0:0 for each libtool library.
#
# 2.Update the version information only immediately before a public release of
# your software. More frequent updates are unnecessary, and only guarantee
# that the current interface number gets larger faster.
#
# 3.If the library source code has changed at all since the last update, then
# increment revision (c:r+1:a)
#
# 4.If any interfaces have been added, removed, or changed since the last
# update, increment current, and set revision to 0. (c+1:r=0:a)
#
# 5.If any interfaces have been added since the last public release, then
# increment age. (c:r:a+1)
#
# 6.If any interfaces have been removed since the last public release, then
# set age to 0. (c:r:a=0)
#

AM_LDFLAGS =

libcares_la_LDFLAGS_EXTRA =

if CARES_LT_SHLIB_USE_VERSION_INFO
libcares_la_LDFLAGS_EXTRA += $(CARES_VERSION_INFO)
endif

if CARES_LT_SHLIB_USE_NO_UNDEFINED
libcares_la_LDFLAGS_EXTRA += -no-undefined
endif

if CARES_LT_SHLIB_USE_MIMPURE_TEXT
libcares_la_LDFLAGS_EXTRA += -mimpure-text
endif

libcares_la_LDFLAGS = $(AM_LDFLAGS) $(libcares_la_LDFLAGS_EXTRA)

# Add -Werror if defined
CFLAGS += @CARES_CFLAG_EXTRAS@

if USE_CPPFLAG_CARES_STATICLIB
AM_CPPFLAGS += $(CPPFLAG_CARES_STATICLIB)
endif

libcares_la_CFLAGS_EXTRA =

libcares_la_CPPFLAGS_EXTRA = -DCARES_BUILDING_LIBRARY

if DOING_CARES_SYMBOL_HIDING
libcares_la_CFLAGS_EXTRA += $(CFLAG_CARES_SYMBOL_HIDING)
libcares_la_CPPFLAGS_EXTRA += -DCARES_SYMBOL_HIDING
endif

@CODE_COVERAGE_RULES@
libcares_la_LDFLAGS += $(CODE_COVERAGE_LDFLAGS)
libcares_la_CFLAGS_EXTRA += $(CODE_COVERAGE_CFLAGS)

libcares_la_CFLAGS = $(AM_CFLAGS) $(libcares_la_CFLAGS_EXTRA)

libcares_la_CPPFLAGS = $(AM_CPPFLAGS) $(libcares_la_CPPFLAGS_EXTRA)

# Makefile.inc provides the CSOURCES and HHEADERS defines
include Makefile.inc

libcares_la_SOURCES = $(CSOURCES) $(HHEADERS)

