all: mod_webfw2 

APR_INCLUDES = -I../chad-libs/apr-1/include
APR_LIBS     = -L../chad-libs/apr-1/.libs
APXS_BIN     = ~/sandbox/bin/apxs
DFLAGS       = -Wall -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64

libconfuse: 
	@echo "  [*] Checking for libconfuse existance..."
	@if test -f confuse-2.5/src/libconfuse.la; then echo "  [*] libconfuse already configured..."; else echo "  [*] Configuring libconfuse..."; cd confuse-2.5 && ./configure CFLAGS=-fPIC --disable-nls 2>&1 >/dev/null; echo "  [*] Making libconfuse";  make 2>&1 >/dev/null; fi
	@cp confuse-2.5/src/.libs/libconfuse.a .

patricia.o: patricia.c 
	@echo "  [*] Compiling libpatricia..."
	@gcc $(DFLAGS) $(APR_INCLUDES) -fPIC -c -o patricia.o patricia.c -ggdb 

filtercloud.o: filtercloud.c 
	@echo "  [*] Compiling libfiltercloud..."
	@gcc $(DFLAGS) $(APR_INCLUDES) -I. -Iconfuse-2.5/src/ -fPIC -c -o filtercloud.o filtercloud.c -ggdb 
 

filtercloud: filtercloud.c patricia.o libconfuse archives
	@echo "  [*] Compiling test version of filtercloud..."
	@gcc  -DDEBUG -DTEST_FILTERCLOUD $(DFLAGS) -I. -L. $(APR_INCLUDES) $(APR_LIBS) -Iconfuse-2.5/src/ filtercloud.c -o filtercloud -lpatricia -lapr-1 -lconfuse -ggdb
 
archives:
	@echo "  [*] Creating libfiltercloud/libpatricia shared archives..."
	@ar rcs libfiltercloud.a  filtercloud.o
	@ar rcs libpatricia.a patricia.o

mod_webfw2: filtercloud.c mod_webfw2.c patricia.c filtercloud.o patricia.o libconfuse archives
	@echo "  [*] Creating Apache modules..."
	@${APXS_BIN} -c -I. -Iconfuse-2.5/src/ -L. mod_webfw2.c -ggdb -lfiltercloud -lpatricia -lconfuse -ggdb 2>&1 >/dev/null 
	@${APXS_BIN} -i -a -n webfw2 mod_webfw2.la 2>&1 >/dev/null

example_filtercloud_app:
	gcc $(DFLAGS) -I. -L. $(APR_INCLUDES) $(APR_LIBS) -Iconfuse-2.5/src/ example_filtercloud_app.c -o example_filtercloud_app -lapr-1 -lfiltercloud -lconfuse -lpatricia

distclean: clean
	@cd confuse-2.5 && make distclean 2>&1 >/dev/null
	
clean:
	@echo "  [*] Cleaning up..."
	@rm -rf *.o *.la *.slo *.lo *.a 
	@rm -rf filtercloud
	@rm -rf ./.libs/
	@rm -rf example_filtercloud_app

