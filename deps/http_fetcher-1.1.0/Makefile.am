# $Id: Makefile.am,v 1.1.1.1 2003/10/14 21:44:46 lhanson Exp $

SUBDIRS = src include docs

EXTRA_DIST = README \
			 CREDITS \
			 INSTALL \
			 LICENSE \
			 ChangeLog \
			 http-fetcher.m4 \
			 http_fetcher-1.1.0-1.spec \
             autogen.sh \
             clean.sh

CLEANFILES = @PROJ_NAME@-@PROJ_VERSION@.tar.gz
DISTCLEANFILES = *~ *.~*

# M4 macro file for inclusion with autoconf
m4datadir = $(datadir)/aclocal
m4data_DATA = http-fetcher.m4

# Grab the test directory for the distribution
dist-hook:
	if test -f testfetch/Makefile; then (cd testfetch; make distclean); fi
	cp -rp testfetch $(distdir)
