#***************************************************************************

###########################################################################

AUTOMAKE_OPTIONS = foreign subdir-objects no-dependencies

include Makefile.inc

man_MANS = $(MANPAGES)

EXTRA_DIST = $(MANPAGES) ahost.1 adig.1 acountry.1 Makefile.inc CMakeLists.txt

SOURCEDMANDIR = man3
SOURCEDMANPAGES = ares_init.3

clean-local: clean-sourced-manpages

clean-sourced-manpages:
	@srcdmandir='$(SOURCEDMANDIR)'; \
	echo "rm -rf $(top_builddir)/$$srcdmandir"; \
	rm -rf $(top_builddir)/$$srcdmandir

sourced-manpages: clean-sourced-manpages
	@srcdmandir='$(SOURCEDMANDIR)'; \
	srcdmanfiles='$(SOURCEDMANPAGES)'; \
	mkdir $(top_builddir)/$$srcdmandir; \
	for file in $$srcdmanfiles; do \
	  if test -f $(top_srcdir)/$$file; then \
	    echo "cp $(top_srcdir)/$$file $(top_builddir)/$$srcdmandir/$$file"; \
	    cp $(top_srcdir)/$$file $(top_builddir)/$$srcdmandir/$$file; \
	  fi; \
	done

MAN2HTML = roffit --mandir=. < $< >$@

SUFFIXES = .3 .html

html: sourced-manpages $(HTMLPAGES)

.3.html:
	$(MAN2HTML)

pdf: sourced-manpages $(PDFPAGES)


.3.pdf:
	@(foo=`echo $@ | sed -e 's/\.[0-9]$$//g'`; \
	groff -Tps -man $< >$$foo.ps; \
	ps2pdf $$foo.ps $@; \
	rm $$foo.ps; \
	echo "converted $< to $@")
