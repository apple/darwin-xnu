include ../Makefile.common

DSTROOT?=$(shell /bin/pwd)
TARGETS := $(addprefix $(DSTROOT)/, measure_tlbs testsp)
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

CFLAGS += $(patsubst %, -arch %, $(ARCHS)) -isysroot $(SDKROOT)

all: $(TARGETS)

clean:
	rm -f $(TARGETS)

$(TARGETS): $(DSTROOT)/%: %.c
	$(CC) $(CFLAGS) -o $@ $<
