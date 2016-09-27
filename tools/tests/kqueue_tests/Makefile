include ../Makefile.common

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

CFLAGS	:=-g $(patsubst %, -arch %,$(ARCHS)) -isysroot $(SDKROOT)

DSTROOT?=$(shell /bin/pwd)
SYMROOT?=$(shell /bin/pwd)

all: $(addprefix $(DSTROOT)/, file_tests timer_tests)

$(DSTROOT)/file_tests: kqueue_file_tests.c
	$(CC) $(CFLAGS) -o $(SYMROOT)/file_tests kqueue_file_tests.c
	ditto $(SYMROOT)/file_tests $(DSTROOT)/file_tests

$(DSTROOT)/timer_tests: kqueue_timer_tests.c
	$(CC) $(CFLAGS) -o $(SYMROOT)/timer_tests kqueue_timer_tests.c
	ditto $(SYMROOT)/timer_tests $(DSTROOT)/timer_tests

clean:
	rm -rf $(DSTROOT)/file_tests $(DSTROOT)/timer_tests $(SYMROOT)/*.dSYM $(SYMROOT)/file_tests $(SYMROOT)/timer_tests
