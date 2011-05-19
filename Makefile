VERSION=1.02
CC=gcc -Ldeps/lib -Ideps/include -O2 -g -DPB_VERSION="\"$(VERSION)\""
INSTALLDIR=/usr/local

all: phreebird phreeload ldns_chase unbound_trace

bin:
	mkdir bin

lib:
	mkdir lib
		
phreebird: bin
	$(CC) -o bin/phreebird phreebird.c -lldns -lcrypto -levent -lghthash

phreeload: bin lib
	$(CC) -D_GNU_SOURCE -lunbound -lcrypto -ldl -Wall -shared -fPIC -o lib/phreeload.so phreeload.c -I /usr/local/ssl/include
	cp phreeload bin

ldns_chase: bin
	$(CC) -o bin/ldns_chase ldns_chase.c -lldns -lcrypto

unbound_trace: bin
	$(CC) -o bin/unbound_trace unbound_trace.c -lunbound -lldns -lcrypto 
		
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
		
