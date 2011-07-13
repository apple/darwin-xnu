
ARCHS=x86_64 i386
SDKROOT=/
CC=xcrun -sdk "$(SDKROOT)" cc
CFLAGS=$(patsubst %, -arch %,$(ARCHS)) -g -Wall -Os -isysroot $(SDKROOT)

all: jitter

timer_jitter.o: timer_jitter.c
	$(CC) -c -o $@ $< $(CFLAGS)

cpu_number.o: cpu_number.s
	$(CC) -c -o $@ $< $(CFLAGS)

jitter: timer_jitter.o cpu_number.o
	$(CC) -o $@ $^ $(CFLAGS)
