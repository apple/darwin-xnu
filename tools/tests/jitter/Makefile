include ../Makefile.common

DSTROOT?=$(shell /bin/pwd)
SYMROOT?=$(shell /bin/pwd)
OBJROOT?=$(shell /bin/pwd)

CC:=$(shell xcrun -sdk "$(SDKROOT)" -find cc)

CFLAGS:=$(ARCH_FLAGS) -g -Wall -Os -isysroot $(SDKROOT) -I$(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders
CFLAGS += -Wl,-sectcreate,__INFO_FILTER,__disable,/dev/null

all: $(DSTROOT)/jitter

$(DSTROOT)/jitter: timer_jitter.c
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f $(DSTROOT)/jitter $(OBJROOT)/*.o
	rm -rf $(SYMROOT)/*.dSYM
