#!/bin/ksh

cc -Os -c -arch i386 -arch x86_64 -I ../../../ ../gen/aescrypt.c -o aescrypt.o
cc -Os -c -arch i386 -arch x86_64 -I ../../../ ../gen/aeskey.c -o aeskey.o
cc -Os -c -arch i386 -arch x86_64 -I ../../../ ../gen/aestab.c -o aestab.o

cc -arch i386 -arch x86_64 -Os tstaes.c aescrypt.o aeskey.o aestab.o -o tstaesgenx86
rm -fr aescrypt.o aeskey.o aestab.o
