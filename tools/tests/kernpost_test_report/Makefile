include ../Makefile.common

DSTROOT?=$(shell /bin/pwd)
SYMROOT?=$(shell /bin/pwd)
OBJROOT?=$(shell /bin/pwd)

CC:=$(shell xcrun -sdk "$(SDKROOT)" -find cc)

CFLAGS:=$(ARCH_FLAGS) -g -Wall -Os -isysroot $(SDKROOT) -I$(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders -lkdd -framework Foundation

all: $(DSTROOT)/kernpost_test_report

$(DSTROOT)/kernpost_test_report: kernpost_test_report.m
	$(CC) -o $@ $^ $(subst -arch i386,,$(CFLAGS))

clean:
	rm -f $(DSTROOT)/kernpost_test_report $(OBJROOT)/*.o
	rm -rf $(SYMROOT)/*.dSYM
