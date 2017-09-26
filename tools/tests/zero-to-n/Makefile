include ../Makefile.common

CC:=$(shell xcrun -sdk "$(SDKROOT)" -find cc)

ifdef RC_ARCHS
    ARCHS:=$(RC_ARCHS)
  else
    ifeq "$(Embedded)" "YES"
      ARCHS:=armv7 armv7s arm64 armv7k
    else
      ARCHS:=x86_64 i386
  endif
endif

CFLAGS := -Os -g $(patsubst %, -arch %, $(ARCHS)) -isysroot $(SDKROOT) -isystem $(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders

DSTROOT?=$(shell /bin/pwd)
SYMROOT?=$(shell /bin/pwd)

DEBUG:=0

$(DSTROOT)/zn: zero-to-n.c
	$(CC) $(CFLAGS) -Wall zero-to-n.c -o $(SYMROOT)/$(notdir $@) -DDEBUG=$(DEBUG) -ggdb
	if [ ! -e $@ ]; then ditto $(SYMROOT)/$(notdir $@) $@; fi

clean:
	rm -rf $(DSTROOT)/zn $(SYMROOT)/*.dSYM $(SYMROOT)/zn
