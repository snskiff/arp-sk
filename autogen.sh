#! /bin/sh

rm -f config.cache
rm -f config.log

aclocal
autoconf
autoheader
#libtoolize -c --force --ltdl --automake
automake --gnu -a -c

