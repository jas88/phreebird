#!/bin/sh

cd deps &&

cd ldns-1.6.5 &&
./configure --prefix=`pwd`/.. --enable-static --disable-shared &&
make &&
make install &&
cd ../libevent-2.0.1-alpha &&
./configure --prefix=`pwd`/.. --enable-static --disable-shared &&
make &&
make install &&
cd ../libghthash-0.6.2 &&
./configure --prefix=`pwd`/.. --enable-static --disable-shared &&
make &&
make install &&
cd ../unbound-1.4.3 &&
./configure --prefix=`pwd`/.. --enable-static --disable-shared &&
make &&
make install &&
cd .. &&

cd ..

