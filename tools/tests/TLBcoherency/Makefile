include ../Makefile.common

CC:=$(shell xcrun -sdk "$(SDKROOT)" -find cc)

CFLAGS := -g $(ARCH_FLAGS) -isysroot $(SDKROOT) -isystem $(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders
CFLAGS += -Wl,-sectcreate,__INFO_FILTER,__disable,/dev/null

DSTROOT?=$(shell /bin/pwd)
SYMROOT?=$(shell /bin/pwd)

DEBUG:=0

$(DSTROOT)/tlbcoh: TLBcoherency.c
	$(CC) $(CFLAGS) -Wall TLBcoherency.c -o $(SYMROOT)/$(notdir $@) -DDEBUG=$(DEBUG) -g -Os
	if [ ! -e $@ ]; then ditto $(SYMROOT)/$(notdir $@) $@; fi

clean:
	rm -rf $(DSTROOT)/tlbcoh $(SYMROOT)/*.dSYM $(SYMROOT)/tlbcoh
