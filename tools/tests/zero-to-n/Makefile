DEBUG=0
CC=/usr/bin/llvm-gcc-4.2

zn: zero-to-n.c
	$(CC) -Wall -arch i386 -arch x86_64 zero-to-n.c -o zn -DDEBUG=$(DEBUG) -ggdb
