#!/bin/sh
# $Id: clean.sh,v 1.1.1.1 2003/10/14 21:45:14 lhanson Exp $

PROGNAME=http_fetcher
FILES='	aclocal.m4
	config.cache
	config.cross.cache
	config.log
	config.status
	configure
	Makefile
	Makefile.in
	*.tar.gz
	src/*.o
	src/Makefile
	src/Makefile.in
	src/$PROGNAME
	src/std*.txt
	include/Makefile
	include/Makefile.in
	docs/Makefile
	docs/Makefile.in
	docs/man/Makefile
	docs/man/Makefile.in
	docs/html/Makefile
	docs/html/Makefile.in'

test -w configure && (if (./configure) then make distclean; fi)
for file in $FILES; do test -w $file && rm -f $file; done
test -w src/.deps && rm -rf src/.deps
