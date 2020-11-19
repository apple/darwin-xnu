include ../Makefile.common

CC:=$(shell xcrun -sdk "$(SDKROOT)" -find cc)

CFLAGS := -Os -g $(ARCH_FLAGS) -isysroot $(SDKROOT) -isystem $(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders
CFLAGS += -Wl,-sectcreate,__INFO_FILTER,__disable,/dev/null

DSTROOT?=$(shell /bin/pwd)
SYMROOT?=$(shell /bin/pwd)

DEBUG:=0

$(DSTROOT)/zn: zero-to-n.c
	$(CC) $(CFLAGS) -Wall zero-to-n.c -o $(SYMROOT)/$(notdir $@) -DDEBUG=$(DEBUG) -ggdb
	if [ ! -e $@ ]; then ditto $(SYMROOT)/$(notdir $@) $@; fi

clean:
	rm -rf $(DSTROOT)/zn $(SYMROOT)/*.dSYM $(SYMROOT)/zn
