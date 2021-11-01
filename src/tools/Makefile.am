AUTOMAKE_OPTIONS = foreign subdir-objects nostdinc 1.9.6
PROGS = ahost adig acountry

EXTRA_DIST = CMakeLists.txt Makefile.inc

noinst_PROGRAMS =$(PROGS)

# Specify our include paths here, and do it relative to $(top_srcdir) and
# $(top_builddir), to ensure that these paths which belong to the library
# being currently built and tested are searched before the library which
# might possibly already be installed in the system.

AM_CPPFLAGS = -I$(top_builddir)/include \
              -I$(top_builddir)/src/lib \
              -I$(top_srcdir)/include \
              -I$(top_srcdir)/src/lib

if USE_CPPFLAG_CARES_STATICLIB
AM_CPPFLAGS += $(CPPFLAG_CARES_STATICLIB)
endif

include Makefile.inc

LDADD = $(top_builddir)/src/lib/libcares.la

ahost_SOURCES = ahost.c $(SAMPLESOURCES) $(SAMPLEHEADERS)
ahost_CFLAGS = $(AM_CFLAGS) $(CODE_COVERAGE_CFLAGS)
ahost_CPPFLAGS = $(AM_CPPFLAGS) $(CODE_COVERAGE_CPPFLAGS)
ahost_LIBS = $(CODE_COVERAGE_LIBS)

adig_SOURCES = adig.c $(SAMPLESOURCES) $(SAMPLEHEADERS)
adig_CFLAGS = $(AM_CFLAGS) $(CODE_COVERAGE_CFLAGS)
adig_CPPFLAGS = $(AM_CPPFLAGS) $(CODE_COVERAGE_CPPFLAGS)
adig_LIBS = $(CODE_COVERAGE_LIBS)

acountry_SOURCES = acountry.c $(SAMPLESOURCES) $(SAMPLEHEADERS)
acountry_CFLAGS = $(AM_CFLAGS) $(CODE_COVERAGE_CFLAGS)
acountry_CPPFLAGS = $(AM_CPPFLAGS) $(CODE_COVERAGE_CPPFLAGS)
acountry_LIBS = $(CODE_COVERAGE_LIBS)
