all: mod_webfw2 testfilter 

# ~/sandbox/bin/apr-1-config --includes --cflags --libs --ldflags  --link-ld
APR_CONFIG   = /home/mthomas/sandbox/bin/apr-1-config
APR_INCLUDES = `$(APR_CONFIG) --includes`
APR_LIBS     = `$(APR_CONFIG) --libs`
APR_CFLAGS   = `$(APR_CONFIG) --cflags`
APR_LDFLAGS  = `$(APR_CONFIG) --ldflags`
APR_LINK     = `$(APR_CONFIG) --link-ld`


#APR_INCLUDES = -I../chad-libs/apr-1/include
#APR_LIBS     = -L../chad-libs/apr-1/.libs
APXS_BIN     = ~/sandbox/bin/apxs

THRASHER     = -DWITH_THRASHER
DFLAGS       =  -Wall -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 $(THRASHER)

libconfuse: 
	@if test -f confuse-2.5/src/libconfuse.la; then echo "[*] libconfuse already configured..."; else echo "[*] Configuring libconfuse..."; cd confuse-2.5 && ./configure CFLAGS=-fPIC --disable-nls 2>&1 >/dev/null; echo "[*] Making libconfuse";  make 2>&1 >/dev/null; fi

patricia.o: patricia.c 
	gcc $(DFLAGS) $(APR_INCLUDES) -fPIC -c -o patricia.o patricia.c -ggdb 

filter.o: filter.c 
	gcc $(DFLAGS) $(APR_INCLUDES) -I. -Iconfuse-2.5/src/ -fPIC -c -o filter.o filter.c -ggdb 

callbacks.o:
	gcc $(DFLAGS) $(APR_INCLUDES) -I. -fPIC -c -o callbacks.o callbacks.c -ggdb

testfilter: testfilter.c filter.c filter.o patricia.o libconfuse archives
	gcc $(DFLAGS) -I. -L. $(APR_INCLUDES) $(APR_LIBS) -Iconfuse-2.5/src/ testfilter.c -o testfilter -lfilter -lapr-1 -ggdb

filter: filter.c filter.o patricia.o libconfuse archives
	gcc  -DDEBUG -DTEST_FILTERCLOUD $(DFLAGS) -I. -L. $(APR_INCLUDES) $(APR_LIBS) -Iconfuse-2.5/src/ filter.c -o filter -lpatricia -lapr-1 -lconfuse -ggdb
 
archives: filter.c patricia.c filter.o patricia.o libconfuse 
	ar rcs libfilter.a filter.o patricia.o confuse-2.5/src/lexer.o confuse-2.5/src/confuse.o 

mod_webfw2: filter.c mod_webfw2.c archives callbacks.o 
	${APXS_BIN} -c -I. $(DFLAGS) -Iconfuse-2.5/src/ -L. mod_webfw2.c callbacks.o -lfilter -ggdb 2>&1 >/dev/null 
	${APXS_BIN} -i -a -n webfw2 mod_webfw2.la 2>&1 >/dev/null

distclean: clean
	cd confuse-2.5 && make distclean 2>&1 >/dev/null
	
clean:
	rm -rf *.o *.la *.slo *.lo *.a 
	rm -rf filter
	rm -rf testfilter
	rm -rf ./.libs/

