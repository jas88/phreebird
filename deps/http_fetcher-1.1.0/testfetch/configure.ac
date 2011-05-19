# Process this file with autoconf to produce a configure script.
# $Id: configure.ac,v 1.1.1.1 2003/10/14 21:45:28 lhanson Exp $
# Setup for automake

AC_INIT(testfetch, 1.0)
AC_CONFIG_SRCDIR(testfetch.c)
# Detect the canonical host and target build environment
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

## This now uses the new version of automake.
AM_INIT_AUTOMAKE([foreign])

# Check for tools
AC_PROG_CC
AC_PROG_AWK     # Used to parse out the path of headers/libs if it comes to that

# Check for compiler environment
AC_C_CONST

# Find where http-fetcher is installed and set CFLAGS and -rpath accordingly.
AC_PATH_HFETCHER()

## Turn on certain options only with --enable-maintainer-mode.  God willing,
## this will keep the auto-regeneration of configure files down.
AM_MAINTAINER_MODE

# Check to see if the user specified any --enable or --disable options

AC_ARG_ENABLE(debug,
[  --enable-debug     Compiles with gdb debugging info (-g) [default = no]],
    CFLAGS="$CFLAGS -g", CFLAGS=`echo " $CFLAGS " | sed -e "s/ -g / /"`)

AC_ARG_ENABLE(strict,
[  --enable-strict    Compiles with strict CFLAGS [default = no]],
    CFLAGS="$CFLAGS -Wbad-function-cast -Wcast-align -Wpointer-arith -Wcast-qual -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -fkeep-static-consts -fkeep-inline-functions -Wundef -Wwrite-strings -Waggregate-return -Wmissing-noreturn -Wredundant-decls -Wnested-externs -Wtrigraphs") 



# Finally create all the generated files
AC_OUTPUT(Makefile)
