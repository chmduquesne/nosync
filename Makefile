all: libnosync.so

libnosync.so:
	gcc -g -Wall -fPIC -shared nosync.c -o libnosync.so

install: all
	install -m755 libnosync.so /lib/libnosync.so
	install -m644 nosync.conf /etc/nosync.conf
	echo "/lib/libnosync.so" >> /etc/ld.so.preload

clean:
	rm libnosync.so
