include ../Makefile.common

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

CFLAGS:=$(patsubst %, -arch %,$(ARCHS)) -g -Wall -Os -isysroot $(SDKROOT) -framework CoreFoundation

all: $(DSTROOT)/mktimer_test

$(DSTROOT)/mktimer_test: $(OBJROOT)/mktimer_test.c
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -rf $(DSTROOT)/mktimer_test $(DSTROOT)/mk_timer_test.dSYM
