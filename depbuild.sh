#!/bin/sh

cd deps &&

tar xzvf ldns-1.6.5.tar.gz &&
cd ldns-1.6.5 &&
./configure &&
make &&
make install &&
cd .. &&
tar xzvf libevent-2.0.1-alpha.tar.gz &&
cd libevent-2.0.1-alpha &&
./configure &&
make &&
make install &&
cd .. &&
tar xzvf libghthash-0.6.2.tar.gz &&
cd libghthash-0.6.2 &&
./configure &&
make &&
make install &&
cd .. &&
tar xzvf unbound-1.4.3_lite.tar.gz &&
cd unbound-1.4.3 &&
./configure &&
make &&
make install &&
cd .. &&

cd ..

