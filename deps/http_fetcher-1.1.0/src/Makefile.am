# $Id: Makefile.am,v 1.1.1.1 2003/10/14 21:45:15 lhanson Exp $

DISTCLEANFILES = *~ *.~*

lib_LTLIBRARIES = libhttp_fetcher.la

libhttp_fetcher_la_SOURCES = http_fetcher.c http_error_codes.c

INCLUDES = -I../include

libhttp_fetcher_la_LDFLAGS = -version-info @VERSION_MAJOR@:@VERSION_MINOR@:@VERSION_MICRO@
