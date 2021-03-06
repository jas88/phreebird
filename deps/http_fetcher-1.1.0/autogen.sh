#!/bin/sh
# $Id: autogen.sh,v 1.1.1.1 2003/10/14 21:45:14 lhanson Exp $

# Remove any previously created cache files
test -w config.cache && rm config.cache
test -w config.cross.cache && rm config.cross.cache

# Regenerate configuration files
aclocal
automake --foreign
autoconf

# Run configure for this platform
#./configure $*
echo "Now you are ready to run ./configure"
