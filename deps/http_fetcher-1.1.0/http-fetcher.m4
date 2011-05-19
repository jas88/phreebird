# Configure paths for http_fetcher
# Lyle Hanson 4/17/02

dnl AC_PATH_HFETCHER()
dnl Tests for http_fetcher installation.  If http_fetcher is installed in
dnl  a location where the dynamic linker cannot find it automatically,
dnl  sets ld_rpath variable (used in libhttp_fetcher_la_LDFLAGS in
dnl  src/Makefile.am) for executables to use to hardcode the path.  My
dnl  understanding is that this should only be done if necessary.
dnl  The macro also adds the appropriate -L and -I values to CFLAGS so that
dnl  headers are found and libraries are linked.
dnl
AC_DEFUN(AC_PATH_HFETCHER,
[dnl

darwin=no;
solaris=no;
extra_libs="";

case "$target" in
    powerpc-apple-darwin*)
        echo "Compiling on darwin, using dylib_file instead of -rpath"
        darwin=yes;
        ;;

	*-sun-solaris*)
		echo "Compiling on Solaris, using -R instead of -rpath"
		solaris=yes;
		extra_libs=" -lsocket -lresolv";
		;;

    *)
        ;;
esac


# First try to find HTTP Fetcher installed in a standard location
AC_CHECK_HEADER(http_fetcher.h, found_header=yes)
AC_CHECK_LIB(http_fetcher, http_fetch, found_library=yes)

# See if the user specified where the HTTP Fetcher headers and libraries are
AC_ARG_WITH(includes,
    [  --with-includes=DIR     HTTP Fetcher headers located in DIR],
    header_path_specified=yes, header_path_specified=no)
if test x$header_path_specified != xno;
    then
        # Check to see if it's REALLY there!
        AC_PATH_PROG(verified_header_path, http_fetcher.h, no, $withval)
        if test x$verified_header_path != xno;
            then    
            CFLAGS="$CFLAGS -I$withval"
        else
            AC_MSG_ERROR([

*** Couldn't find header (http_fetcher.h) in the specified location
*** ($withval).
***
*** Run 'configure --with-includes=DIR', where DIR is the path to the header
*** file, then try 'make' again.
])
        fi
fi

AC_ARG_WITH(libraries,
    [  --with-libraries=DIR    HTTP Fetcher libraries located in DIR],
    lib_path_specified=yes, lib_path_specified=no)
if test x$lib_path_specified != xno;
    then
        # Check to see if it's REALLY there!
        AC_PATH_PROG(verified_library_path, libhttp_fetcher.a, no, $withval)
        if test x$verified_library_path != xno;
            then
            CFLAGS="$CFLAGS -L$withval"
            specified_library_path=$withval     # Save it for -rpath
        else
            AC_MSG_ERROR([

*** Couldn't find library (libhttp_fetcher.a) in the specified location
*** ($withval).
***
*** Run 'configure --with-libraries=DIR', where DIR is the path to the header
*** file, then try 'make' again.
])
        fi
fi

# If header not found in either case, check special cases, then alert the user
if test x$found_header != xyes;
    then
        # Didn't find header in a standard place...
        if test x$header_path_specified != xyes;
            then
            # Didn't specify it, either...
            # Before erroring out, look in their home dir
            AC_PATH_PROG(found_header_path, http_fetcher.h, no, $HOME/include)
            if test x$found_header_path != xno;
                then
                # Cut the actual filename out of the path
                number_of_fields=`echo $found_header_path | \
                awk -F/ '{print NF-1}'`
                found_header_path=`echo $found_header_path | \
                cut -d/ -f1-$number_of_fields`
                CFLAGS="$CFLAGS -I$found_header_path"
            else
            AC_MSG_ERROR([

*** Couldn't find header (http_fetcher.h) in a standard location.
*** HTTP Fetcher needs to be installed to continue.  If it IS installed,
*** perhaps it was installed in a non-standard location.
***
*** Run 'configure --with-includes=DIR', where DIR is the path to the header
*** file, then try 'make' again.
])
            fi
        fi
fi


# If library not found in either case, alert the user
if test x$found_library != xyes;
    then
        # Didn't find library in standard place...
        if test x$lib_path_specified != xyes;
            then
            # Didn't specify it, either...
            # Before erroring out, check their home dir
            AC_PATH_PROG(found_library_path, libhttp_fetcher.a, no, $HOME/lib)
            if test x$found_library_path != xno;
                then
                # Cut the actual filename out of the path
                number_of_fields=`echo $found_library_path | \
                awk -F/ '{print NF-1}'`
                found_library_path=`echo $found_library_path | \
                cut -d/ -f1-$number_of_fields`
                if test x$darwin != xno;
                    then
                    ld_rpath="-dylib_file /usr/local/lib:$found_library_path" 
				elif test x$solaris != xno;
					then
                    ld_rpath="-R $found_library_path"
                else
                    ld_rpath="-Wl,-rpath $found_library_path"
                fi
                CFLAGS="$CFLAGS -L$found_library_path"
            else
            AC_MSG_ERROR([

*** Couldn't find library (http_fetcher) in a standard location.
*** HTTP Fetcher needs to be installed to continue.  If it IS installed,
*** perhaps it was installed in a non-standard location.
***
*** Run 'configure --with-libraries=DIR', where DIR is the path to the library,
*** then try 'make' again.
])
            fi
        else
            # Set the -rpath as specified
            if test x$darwin != xno;
                then
                ld_rpath="-dylib_file /usr/local/lib:$specified_library_path" 
			elif test x$solaris != xno;
				then
                ld_rpath="-R $found_library_path"
            else
                ld_rpath="-Wl,-rpath $specified_library_path"
            fi
        fi
fi


# Substitute the proper -rpath argument to link with wherever the library is
#   installed.  Ah, this magic is wonderful once you finally get it working!!
AC_SUBST(ld_rpath)

# On Solaris we need to specifically link: -lsocket and -lresolv
AC_SUBST(extra_libs)

if test "$ld_rpath" != "";
    then
    echo "Hard-coding library path into executable:"
    echo "ld_rpath = $ld_rpath"
fi

])
