SDKROOT ?= /
ifeq "$(RC_TARGET_CONFIG)" "iPhone"
Embedded?=YES
else
Embedded?=$(shell echo $(SDKROOT) | grep -iq iphoneos && echo YES || echo NO)
endif

OBJROOT?=$(shell /bin/pwd)

CC:=$(shell xcrun -sdk "$(SDKROOT)" -find cc)

ifdef RC_ARCHS
    ARCHS:=$(RC_ARCHS)
  else
    ifeq "$(Embedded)" "YES"
      ARCHS:=armv7 armv7s arm64
    else
      ARCHS:=x86_64 i386
  endif
endif



DSTROOT?=$(shell /bin/pwd)

CFLAGS:=$(patsubst %, -arch %,$(ARCHS)) -g -Wall -Os $(ISYSROOT)

all: $(DSTROOT)/jitter

$(OBJROOT)/timer_jitter.o: timer_jitter.c
	$(CC) -c -o $@ $< $(CFLAGS)

$(OBJROOT)/cpu_number.o: cpu_number.s
	$(CC) -c -o $@ $< $(CFLAGS)

$(DSTROOT)/jitter: $(OBJROOT)/timer_jitter.o $(OBJROOT)/cpu_number.o
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f $(DSTROOT)/jitter $(OBJROOT)/*.o
