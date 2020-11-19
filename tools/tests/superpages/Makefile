include ../Makefile.common

DSTROOT?=$(shell /bin/pwd)
TARGETS := $(addprefix $(DSTROOT)/, measure_tlbs testsp)
CC:=$(shell xcrun -sdk "$(SDKROOT)" -find cc)

CFLAGS += $(ARCH_FLAGS) -isysroot $(SDKROOT)
CFLAGS += -Wl,-sectcreate,__INFO_FILTER,__disable,/dev/null

all: $(TARGETS)

clean:
	rm -f $(TARGETS)

$(TARGETS): $(DSTROOT)/%: %.c
	$(CC) $(CFLAGS) -o $@ $<
