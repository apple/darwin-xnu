#!/bin/ksh

cc -c -Os -arch i386 -arch x86_64 ../i386/AES.s -o AES.o
cc -c -Os -arch i386 -arch x86_64 ../i386/aes_crypt_hw.s -o aes_crypt_hw.o
cc -c -Os -arch i386 -arch x86_64 ../i386/aes_key_hw.s -o aes_key_hw.o
cc -c -Os -arch i386 -arch x86_64 ../i386/aes_modes_asm.s -o aes_modes_asm.o
cc -c -Os -arch i386 -arch x86_64 ../i386/aes_modes_hw.s -o aes_modes_hw.o

cc -Os -arch i386 -arch x86_64 tstaes.c AES.o aes_crypt_hw.o aes_key_hw.o aes_modes_asm.o aes_modes_hw.o -o tstaesoptx86
rm -fr AES.o aes_crypt_hw.o aes_key_hw.o aes_modes_asm.o aes_modes_hw.o
