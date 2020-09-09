AUTOMAKE_OPTIONS = foreign nostdinc 1.9.6
ACLOCAL_AMFLAGS = -I m4 --install

MSVCFILES = msvc_ver.inc

# adig and ahost are just sample programs and thus not mentioned with the
# regular sources and headers
EXTRA_DIST = AUTHORS CHANGES README.cares $(man_MANS) RELEASE-NOTES	\
 libcares.pc.in buildconf get_ver.awk maketgz TODO README.msvc	\
 $(MSVCFILES) INSTALL.md README.md LICENSE.md \
 CMakeLists.txt \
 Makefile.dj Makefile.m32 Makefile.netware Makefile.msvc Makefile.Watcom \
 AUTHORS CONTRIBUTING.md SECURITY.md TODO


CLEANFILES = $(PDFPAGES) $(HTMLPAGES)

DISTCLEANFILES = include/ares_build.h

DIST_SUBDIRS = include src test docs

SUBDIRS = @BUILD_SUBDIRS@

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libcares.pc

CARES_VERSION_INFO = -version-info 6:1:4
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

# where to install the c-ares headers
libcares_ladir = $(includedir)


# Make files named *.dist replace the file without .dist extension
dist-hook:
	find $(distdir) -name "*.dist" -exec rm {} \;
	(distit=`find $(srcdir) -name "*.dist"`; \
	for file in $$distit; do \
	  strip=`echo $$file | sed -e s/^$(srcdir)// -e s/\.dist//`; \
	  cp $$file $(distdir)$$strip; \
	done)
