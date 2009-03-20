
all: mod_webfw2 

libconfuse: 
	@echo "  [*] Checking for libconfuse existance..."
	@if test -f confuse-2.5/src/libconfuse.la; then echo "  [*] libconfuse already configured..."; else echo "  [*] Configuring libconfuse..."; cd confuse-2.5 && ./configure --enable-static 2>&1 >/dev/null; echo "  [*] Making libconfuse";  make 2>&1 >/dev/null; fi
	@cp confuse-2.5/src/.libs/libconfuse.a .

patricia.o: 
	@echo "  [*] Compiling libpatricia..."
	@gcc -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -I../chad-libs/apr-1/include -c -o patricia.o patricia.c -ggdb 

filtercloud.o: 
	@echo "  [*] Compiling libfiltercloud..."
	@gcc -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -I../chad-libs/apr-1/include -I. -Iconfuse-2.5/src/ -c -o filtercloud.o filtercloud.c -ggdb 

filtercloud: filtercloud.c patricia.o libconfuse archives
	@echo "  [*] Compiling test version of filtercloud..."
	@gcc  -DTEST_FILTERCLOUD -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -I. -L. -I../chad-libs/apr-1/include -L../chad-libs/apr-1/.libs  -Iconfuse-2.5/src/ filtercloud.c -o filtercloud -lpatricia -lapr-1 -lconfuse -ggdb
 
	 
archives:
	@echo "  [*] Creating libfiltercloud/libpatricia shared archives..."
	@ar rcs libfiltercloud.a  filtercloud.o
	@ar rcs libpatricia.a patricia.o

mod_webfw2: filtercloud.o patricia.o libconfuse archives
	@echo "  [*] Creating Apache modules..."
	@~/sandbox/bin/apxs -c -I. -Iconfuse-2.5/src/ -L. mod_webfw2.c -ggdb -D_REENTRANT -lfiltercloud -lpatricia -lconfuse -ggdb 2>&1 >/dev/null 
	@~/sandbox/bin/apxs -i -a -n webfw2 mod_webfw2.la 2>&1 >/dev/null

distclean: clean
	@cd confuse-2.5 && make distclean 2>&1 >/dev/null
	
clean:
	@echo "  [*] Cleaning up..."
	@rm -rf *.o *.la *.slo *.lo *.a 
	@rm -rf filtercloud
	@rm -rf ./.libs/
