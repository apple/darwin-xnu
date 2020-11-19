include ../Makefile.common

CC:=$(shell xcrun -sdk "$(SDKROOT)" -find cc)

SYMROOT?=$(shell /bin/pwd)

CFLAGS	:=-g -isysroot $(SDKROOT) -I$(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders
CFLAGS += -Wl,-sectcreate,__INFO_FILTER,__disable,/dev/null

DSTROOT?=$(shell /bin/pwd)
SRCROOT?=$(shell /bin/pwd)

SOURCES := sets.c pool.c tags.c
ARCH_32_TARGETS := $(addprefix $(DSTROOT)/, sets pool tags)
ARCH_64_TARGETS := $(addprefix $(DSTROOT)/, sets64 pool64 tags64)

TARGETS := $(if $(ARCH_CONFIGS_64), $(ARCH_64_TARGETS)) $(if $(ARCH_CONFIGS_32), $(ARCH_32_TARGETS))


all:	$(TARGETS)

$(ARCH_32_TARGETS): $(DSTROOT)/%: $(SRCROOT)/%.c
	$(CC) $(CFLAGS) $(ARCH_FLAGS_32) $< -o $(SYMROOT)/$(notdir $@) # 32-bit fat
	if [ ! -e $@ ]; then ditto $(SYMROOT)/$(notdir $@) $@; fi

.SECONDEXPANSION:
$(ARCH_64_TARGETS): $(DSTROOT)/%: $(SRCROOT)/$$(subst 64,,%).c
	$(CC) $(CFLAGS) $(ARCH_FLAGS_64) $< -o $(SYMROOT)/$(notdir $@) # 64-bit fat
	if [ ! -e $@ ]; then ditto $(SYMROOT)/$(notdir $@) $@; fi

clean:
	rm -f $(TARGETS)
	rm -rf $(SYMROOT)/*.dSYM
