AUTOMAKE_OPTIONS = foreign nostdinc

ACLOCAL_AMFLAGS = -I m4

MSVCFILES = vc/vc6aws.dsw vc/acountry/vc6acountry.dsp vc/adig/vc6adig.dsp	\
 vc/ahost/vc6ahost.dsp vc/cares/vc6cares.dsp vc/cares/vc6cares.dsw		\
 msvc_ver.inc

# adig and ahost are just sample programs and thus not mentioned with the
# regular sources and headers
EXTRA_DIST = AUTHORS CHANGES README.cares $(man_MANS) RELEASE-NOTES	\
 libcares.pc.in buildconf get_ver.awk maketgz TODO cares.rc README.msvc	\
 $(MSVCFILES) INSTALL.md README.md LICENSE.md

CLEANFILES = $(PDFPAGES) $(HTMLPAGES)

DISTCLEANFILES = ares_build.h

DIST_SUBDIRS = test docs examples include

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libcares.pc

SUBDIRS = lib

# where to install the c-ares headers
libcares_ladir = $(includedir)
# what headers to install on 'make install':
include_HEADERS = include/ares.h include/ares_version.h include/ares_dns.h \
	include/ares_build.h include/ares_rules.h

# Make files named *.dist replace the file without .dist extension
dist-hook:
	find $(distdir) -name "*.dist" -exec rm {} \;
	(distit=`find $(srcdir) -name "*.dist"`; \
	for file in $$distit; do \
	  strip=`echo $$file | sed -e s/^$(srcdir)// -e s/\.dist//`; \
	  cp $$file $(distdir)$$strip; \
	done)
