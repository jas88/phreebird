Summary:    A small, robust, flexible library for downloading files via HTTP.
# Note that releases 2.x.x and above are named 'http-fetcher'
Name:       http_fetcher
Release:    1
Version:    1.1.0
Copyright:  LGPL
Group:      Libraries
Source:     http://prdownloads.sourceforge.net/http-fetcher/http_fetcher-1.1.0.tar.gz
Packager:   Lyle Hanson (lhanson@users.sourceforge.net)
URL:        http://http-fetcher.sourceforge.net
BuildRoot:  /var/tmp/http_fetcher-%{version}-root
Prefix:     /usr
Requires:   glibc

%description
HTTP Fetcher is a small, robust, flexible library for downloading files via
HTTP using the GET method.

It's easy to use, but allows you to customize and manipulate your file requests
through altering the User Agent, Referer, timeout, etc.  The error reporting
functions give you a simple, clean interface through which to obtain
information about a problem.

%package devel
Summary: Libraries, includes, and developer docs for using HTTP Fetcher.
Group: Development/Libraries
# Note that releases 2.x.x and above are named 'http-fetcher', but this devel
#	package requires the 'http_fetcher' versions
Requires: http_fetcher

%description devel
HTTP Fetcher is a small, robust, flexible library for downloading files via
HTTP using the GET method.

It's easy to use, but allows you to customize and manipulate your file requests
through altering the User Agent, Referer, timeout, etc.  The error reporting
functions give you a simple, clean interface through which to obtain
information about a problem.

This package contains developer docs, headers, and libraries needed to develop
programs that make use of HTTP Fetcher.


# Unpacks the source tarball from SOURCES into BUILD
# Apply any patches here
%prep
%setup

# Configures, then makes the package
%build
%{configure}
make

# Removes BuildRoot, to get rid of old files, then recreates it.
%install
 rm -rf $RPM_BUILD_ROOT
%{makeinstall}

# Removes BuildRoot
%clean
 rm -rf $RPM_BUILD_ROOT

# Post-install stage.. update the dynamic linker
%post -p /sbin/ldconfig

# Post-uninstall stage... update the dynamic linker again
%postun -p /sbin/ldconfig

# Files included in the RPM.  Taken from $RPM_BUILD_ROOT.  Wildcards are
# accepted.
%files
 %defattr(-, root, root)
 /usr/lib/libhttp_fetcher.so.1.1.0
 /usr/lib/libhttp_fetcher.so.1
 %doc INSTALL
 %doc LICENSE
 %doc README
 %doc CREDITS
 %doc ChangeLog

%files devel
 /usr/lib/libhttp_fetcher.so
 /usr/lib/libhttp_fetcher.la
 /usr/lib/libhttp_fetcher.a
 /usr/include/http_fetcher.h
 /usr/include/http_error_codes.h
 /usr/share/aclocal/http-fetcher.m4
 %doc /usr/share/man/man3/http_fetch.3.gz
 %doc /usr/share/man/man3/http_parseFilename.3.gz
 %doc /usr/share/man/man3/http_perror.3.gz
 %doc /usr/share/man/man3/http_setRedirects.3.gz
 %doc /usr/share/man/man3/http_setReferer.3.gz
 %doc /usr/share/man/man3/http_setTimeout.3.gz
 %doc /usr/share/man/man3/http_setUserAgent.3.gz
 %doc /usr/share/man/man3/http_strerror.3.gz

%changelog
* Mon Mar 8 2004 Lyle Hanson <lhanson@users.sourceforge.net>
- Revision bump to 1.1.0.  Added http_setRedirects and other minor fixes.

* Tue Oct 14 2003 Lyle Hanson <lhanson@users.sourceforge.net>
- Updated to 1.0.3.  Several fixes and feature additions.

* Thu Apr 22 2003 Lyle Hanson <lhanson@users.sourceforge.net>
- Updated to 1.0.2.  Requires glibc because libc5 doesn't provide hstrerror().

* Tue Jul 31 2001 Lyle Hanson <lhanson@users.sourceforge.net>
- Initial specfile w/ example from sun (candy@camelos.org).  Thanks, btw!
