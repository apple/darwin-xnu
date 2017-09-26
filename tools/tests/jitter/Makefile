include ../Makefile.common

DSTROOT?=$(shell /bin/pwd)
SYMROOT?=$(shell /bin/pwd)
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


CFLAGS:=$(patsubst %, -arch %,$(ARCHS)) -g -Wall -Os -isysroot $(SDKROOT) -I$(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders

all: $(DSTROOT)/jitter

$(DSTROOT)/jitter: timer_jitter.c
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f $(DSTROOT)/jitter $(OBJROOT)/*.o
	rm -rf $(SYMROOT)/*.dSYM
