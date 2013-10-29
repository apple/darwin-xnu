SDKROOT ?= /
ifeq "$(RC_TARGET_CONFIG)" "iPhone"
Embedded?=YES
else
Embedded?=$(shell echo $(SDKROOT) | grep -iq iphoneos && echo YES || echo NO)
endif

CC:=xcrun -sdk "$(SDKROOT)" cc

ifdef RC_ARCHS
    ARCHS:=$(RC_ARCHS)
  else
    ifeq "$(Embedded)" "YES"
      ARCHS:=armv7 armv7s
    else
      ARCHS:=x86_64 i386
  endif
endif

CFLAGS := -g $(patsubst %, -arch %, $(ARCHS))

DSTROOT?=$(shell /bin/pwd)
SYMROOT?=$(shell /bin/pwd)

DEBUG:=0

$(DSTROOT)/zn: zero-to-n.c
	$(CC) $(CFLAGS) -Wall zero-to-n.c -o $(SYMROOT)/$(notdir $@) -DDEBUG=$(DEBUG) -ggdb
	if [ ! -e $@ ]; then ditto $(SYMROOT)/$(notdir $@) $@; fi

clean:
	rm -rf $(DSTROOT)/zn $(SYMROOT)/*.dSYM $(SYMROOT)/zn
