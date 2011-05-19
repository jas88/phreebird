VERSION=1.02
CC=gcc -Ldeps/lib -Ideps/include -O2 -g -DPB_VERSION="\"$(VERSION)\""
INSTALLDIR=/usr/local

.PHONY: deps

all: phreebird phreeload ldns_chase unbound_trace

deps:
	( cd deps/ldns-1.6.5 && ./configure --prefix=`pwd`/.. --enable-static --disable-shared )
	$(MAKE) -C deps/ldns-1.6.5 all install
	( cd deps/libevent-2.0.1-alpha && ./configure --prefix=`pwd`/.. --enable-static --disable-shared )
	$(MAKE) -C deps/libevent-2.0.1-alpha all install
	( cd deps/libghthash-0.6.2 && ./configure --prefix=`pwd`/.. --enable-static --disable-shared )
	$(MAKE) -C deps/libghthash-0.6.2 all install
	( cd deps/unbound-1.4.3 && ./configure --prefix=`pwd`/.. --enable-static --disable-shared )
	$(MAKE) -C deps/unbound-1.4.3 all install

bin:
	mkdir bin

lib:
	mkdir lib

phreebird: bin
	$(CC) -o bin/phreebird phreebird.c -lldns -lcrypto -levent -lghthash $(EXTRA_LIBS)

phreeload: bin lib
	$(CC) -D_GNU_SOURCE -lunbound -lcrypto -ldl -Wall -shared -fPIC -o lib/phreeload.so phreeload.c -I /usr/local/ssl/include
	cp phreeload bin

ldns_chase: bin
	$(CC) -o bin/ldns_chase ldns_chase.c -lldns -lcrypto $(EXTRA_LIBS)

unbound_trace: bin
	$(CC) -o bin/unbound_trace unbound_trace.c -lunbound -lldns -lcrypto $(EXTRA_LIBS)

package:
	rm -rf phreebird_suite_$(VERSION) 
	mkdir phreebird_suite_$(VERSION)
	cp -rvf Makefile depbuild.sh LICENCE README.txt CHANGELOG.txt HACKING.txt phreebird.c \
	   phreeload.c phreeload ldns_chase.c unbound_trace.c patches INSTALL.txt deps phreebird_suite_$(VERSION)
	tar czvf phreebird_suite_$(VERSION).tar.gz phreebird_suite_$(VERSION)
	rm -rf phreebird_suite_$(VERSION) 

phreebird_deps:
	sh depbuild.sh

install: all
	cp bin/phreebird bin/phreeload bin/ldns_chase bin/unbound_trace $(INSTALLDIR)/bin;
	cp lib/phreeload.so $(INSTALLDIR)/lib;

uninstall: all
	rm $(INSTALLDIR)/bin/phreebird $(INSTALLDIR)/bin/phreeload $(INSTALLDIR)/bin/ldns_chase $(INSTALLDIR)/bin/unbound_trace
	rm $(INSTALLDIR)/lib/phreeload.so

clean:
	rm -rf bin
	rm -rf lib
