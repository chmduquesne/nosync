all: libnosync.so

libnosync.so:
	gcc -g -Wall -fPIC -shared nosync.c -o libnosync.so -ldl

install: all
	install -m755 libnosync.so /lib/libnosync.so
	install -m644 nosync.conf /etc/nosync.conf
	echo "/lib/libnosync.so" >> /etc/ld.so.preload

uninstall:
	sed -i "#/lib/libnosync.so##g" /etc/ld.so.preload
	rm -f /lib/libnosync.so
	rm -f /etc/nosync.conf

clean:
	rm libnosync.so
