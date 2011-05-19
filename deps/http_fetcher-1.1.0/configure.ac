# Process this file with autoconf to produce a configure script.
# $Id: configure.ac,v 1.1 2004/03/03 15:41:57 lhanson Exp $
AC_INIT(README)

# This version silliness is strict libtool versioning.  The project version
#	goes up a patchlevel but the libtool version goes up a "revision".
#	As long as the PROJECT_VERSION variable is set correctly, libtool will
#	use this silly stuff to produce the right thing, and the package retains
#	its intuitively correct version.
# Version information
VERSION_MAJOR=2		# Current
VERSION_MINOR=0		# Revision
VERSION_MICRO=1		# Age

AC_SUBST(VERSION_MAJOR)
AC_SUBST(VERSION_MINOR)
AC_SUBST(VERSION_MICRO)

# Setup for automake
PROJ_NAME=http_fetcher
PROJ_VERSION="1.1.0"	# No longer taken from the libtool interface version..
AM_INIT_AUTOMAKE($PROJ_NAME, $PROJ_VERSION)

# Turn on certain options only with --enable-maintainer-mode.  This should
# keep the auto-regeneration of autoconf/make files due to CVS not storing
# relative timestamps down to a minimum.
AM_MAINTAINER_MODE

AC_SUBST(PROJ_NAME)
AC_SUBST(PROJ_VERSION)

# Detect the canonical host and target build environment
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

# Check for tools
AC_PROG_LIBTOOL
AC_PROG_CC

# Check for compiler environment
AC_C_CONST

# See if hstrerror is present (is in glibc6, not in libc5)
AC_CHECK_FUNC(hstrerror, CFLAGS="$CFLAGS -DHAVE_HSTRERROR")

# Check for some crucial functions we need to proceed.
# We currently provide no implemenation for these functions, so failure
#	to find them means that http_fetcher can not be built on that system.
AC_CHECK_FUNCS(select, have_select=yes)
AC_CHECK_FUNC(socket, have_socket=yes, AC_CHECK_LIB(socket, socket, have_socket=yes))
AC_CHECK_FUNC(strerror, have_strerror=yes)
AC_CHECK_FUNC(strstr, have_strstr=yes)

MISSING_FUNCTION=""
if test x$have_select != xyes; then
	MISSING_FUNCTION=select;
elif test x$have_socket != xyes; then
	MISSING_FUNCTION=socket;
elif test x$have_strerror != xyes; then
	MISSING_FUNCTION=strerror;
elif test x$have_strstr != xyes; then
	MISSING_FUNCTION=strstr;
fi

# Print an error message if any of the functions weren't found.
if test x$MISSING_FUNCTION != x; then
	AC_MSG_ERROR([

*** Could not find the '$MISSING_FUNCTION' function on your system.
***
*** This function is necessary for http_fetcher.  Either install the proper
*** library, or contact lhanson@users.sourceforge.net with details about
*** your system and we will try to improve compatibility.
])
fi


# Check to see if the user specified any --enable or --disable options
AC_ARG_ENABLE(debug,
[  --enable-debug	  Compiles with gdb debugging info (-g) [default = no]],
		, enable_debug=no)
if test x$enable_debug != xyes;
	then
	# Don't compile with -g
	CFLAGS=`echo " $CFLAGS " | sed -e "s/ -g / /"`
fi

AC_ARG_ENABLE(strict,
[  --enable-strict	  Compiles with -ansi -pedantic -Wall [default = yes]],
		, enable_strict=yes)
if test x$enable_strict != xno;
	then
	CFLAGS="$CFLAGS -ansi -pedantic -Wall"
fi

# Finally create all the generated files
AC_OUTPUT(
Makefile 
docs/Makefile 
docs/html/Makefile
docs/man/Makefile 
src/Makefile 
include/Makefile 
)
