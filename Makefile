all:
	gcc -g -Wall -fPIC -shared nosync.c -o libnosync.so
