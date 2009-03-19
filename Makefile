
all: mod_webfw2 

patricia.o: 
	gcc -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -I../chad-libs/apr-1/include -c -o patricia.o patricia.c 

filtercloud.o: 
	gcc -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -I../chad-libs/apr-1/include -c -o filtercloud.o filtercloud.c 

module: filtercloud.o patricia.o
	gcc -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -I../chad-libs/apr-1/include -L../chad-libs/apr-1/.libs  mod_webfw2.c -o mod_webfw2 filtercloud.o patricia.o -lapr-1 -ggdb 

mod_webfw2: filtercloud.o patricia.o
	ar rcs libfiltercloud.a  filtercloud.o
	ar rcs libpatricia.a patricia.o
	~/sandbox/bin/apxs -c -I. -L. mod_webfw2.c -ggdb -D_REENTRANT -lfiltercloud -lpatricia 
	~/sandbox/bin/apxs -i -a -n webfw2 mod_webfw2.la

clean:
	rm -rf *.o *.la *.slo *.lo *.a 
	rm -rf ./.libs/
