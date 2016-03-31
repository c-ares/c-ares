# Where to find the c-ares source code; needed because the tests use library-internal headers
ARES_SRC_DIR = ..
# Where to find the built c-ares static library
ARES_BLD_DIR = ..
AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I ../m4
GMOCK_DIR = gmock-1.7.0
GTEST_DIR = $(GMOCK_DIR)/gtest
# Note use of -isystem to force use of local gMock/gTest even if there's an installed version.
CPPFLAGS += -I$(ARES_SRC_DIR) -isystem $(GTEST_DIR)/include -isystem $(GMOCK_DIR)/include
CXXFLAGS += -Wall $(PTHREAD_CFLAGS)

# Makefile.inc provides the TESTSOURCES, TESTHEADERS and FUZZSOURCES defines
include Makefile.inc

TESTS = arestest fuzzcheck.sh

noinst_PROGRAMS = arestest aresfuzz dnsdump
arestest_SOURCES = $(TESTSOURCES) $(TESTHEADERS)
arestest_LDADD = libgmock.la libgtest.la $(ARES_BLD_DIR)/libcares.la $(PTHREAD_LIBS)

# Not interested in coverage of test code, but linking the test binary needs the coverage option
@CODE_COVERAGE_RULES@
arestest_LDFLAGS = $(CODE_COVERAGE_LDFLAGS)

noinst_LTLIBRARIES = libgmock.la libgtest.la

libgmock_la_SOURCES = $(GMOCK_DIR)/src/gmock-all.cc
libgmock_la_CPPFLAGS = -isystem $(GTEST_DIR)/include -I$(GTEST_DIR) -isystem $(GMOCK_DIR)/include -I$(GMOCK_DIR)
libgtest_la_SOURCES = $(GTEST_DIR)/src/gtest-all.cc
libgtest_la_CPPFLAGS = -isystem $(GTEST_DIR)/include -I$(GTEST_DIR) -isystem $(GMOCK_DIR)/include -I$(GMOCK_DIR)

aresfuzz_SOURCES = $(FUZZSOURCES)
aresfuzz_LDADD = $(ARES_BLD_DIR)/libcares.la

dnsdump_SOURCES = $(DUMPSOURCES)
dnsdump_LDADD = $(ARES_BLD_DIR)/libcares.la

test: check
