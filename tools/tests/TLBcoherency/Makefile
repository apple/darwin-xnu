include ../Makefile.common

CC:=$(shell xcrun -sdk "$(SDKROOT)" -find cc)

ifdef RC_ARCHS
    ARCHS:=$(RC_ARCHS)
  else
    ifeq "$(Embedded)" "YES"
      ARCHS:=armv7 armv7s arm64 armv7k
    else
      ARCHS:=x86_64
  endif
endif

CFLAGS := -g $(patsubst %, -arch %, $(ARCHS)) -isysroot $(SDKROOT) -isystem $(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders

DSTROOT?=$(shell /bin/pwd)
SYMROOT?=$(shell /bin/pwd)

DEBUG:=0

$(DSTROOT)/tlbcoh: TLBcoherency.c
	$(CC) $(CFLAGS) -Wall TLBcoherency.c -o $(SYMROOT)/$(notdir $@) -DDEBUG=$(DEBUG) -g -Os
	if [ ! -e $@ ]; then ditto $(SYMROOT)/$(notdir $@) $@; fi

clean:
	rm -rf $(DSTROOT)/tlbcoh $(SYMROOT)/*.dSYM $(SYMROOT)/tlbcoh
