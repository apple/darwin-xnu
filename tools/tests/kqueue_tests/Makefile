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

CFLAGS	:=-g $(patsubst %, -arch %,$(ARCHS))

DSTROOT?=$(shell /bin/pwd)
SYMROOT?=$(shell /bin/pwd)

all: $(addprefix $(DSTROOT)/, file timer)

$(DSTROOT)/file:
	$(CC) $(CFLAGS) -o $(SYMROOT)/file_tests kqueue_file_tests.c
	if [ ! -e $(DSTROOT)/file_tests ]; then ditto $(SYMROOT)/file_tests $(DSTROOT)/file_tests; fi

$(DSTROOT)/timer:
	$(CC) $(CFLAGS) -o $(SYMROOT)/timer_tests kqueue_timer_tests.c
	if [ ! -e $(DSTROOT)/timer_tests ]; then ditto $(SYMROOT)/timer_tests $(DSTROOT)/timer_tests; fi

clean:
	rm -rf $(DSTROOT)/file_tests $(DSTROOT)/timer_tests $(SYMROOT)/*.dSYM $(SYMROOT)/file_tests $(SYMROOT)/timer_tests
