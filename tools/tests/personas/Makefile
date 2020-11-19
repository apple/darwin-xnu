include ../Makefile.common

CC:=$(shell xcrun -sdk "$(SDKROOT)" -find cc)
CODESIGN:=$(shell xcrun -sdk "$(SDKROOT)" -find codesign)
CODESIGN_ALLOCATE:=$(shell xcrun -sdk "$(SDKROOT)" -find codesign_allocate)

SYMROOT?=$(shell /bin/pwd)

CFLAGS := -g -O2 -isysroot $(SDKROOT) -I$(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders
CFLAGS += -Wl,-sectcreate,__INFO_FILTER,__disable,/dev/null

# $(ARCH_CONFIGS) is set my Makefile.common
ARCH_FLAGS := $(if $(ARCH_CONFIGS_64), $(ARCH_FLAGS_64)) $(if $(ARCH_CONFIGS_32), $(ARCH_FLAGS_32))

DSTROOT?=$(shell /bin/pwd)

TARGETS := persona_mgr persona_spawn persona_test_run.sh persona_spawn_unentitled

all: $(addprefix $(DSTROOT)/, $(TARGETS))

$(DSTROOT)/persona_%: persona_%.c persona_test.h Makefile persona-entitlements.plist
	${CC} ${CFLAGS} ${ARCH_FLAGS} -o $(SYMROOT)/$(notdir $@) $<
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) \
	    $(CODESIGN) -s - --entitlements persona-entitlements.plist $(SYMROOT)/$(notdir $@)
	if [ ! -e $@ ]; then ditto $(SYMROOT)/$(notdir $@) $@; fi

$(DSTROOT)/persona_spawn_unentitled: persona_spawn.c persona_test.h Makefile
	${CC} ${CFLAGS} ${ARCH_FLAGS} -o $(SYMROOT)/$(notdir $@) $<
	if [ ! -e $@ ]; then ditto $(SYMROOT)/$(notdir $@) $@; fi

$(DSTROOT)/persona_test_run.sh: persona_test_run_src.sh
	cp $? $@
	chmod +x $@

clean:
	rm -rf $(addprefix $(DSTROOT)/,$(TARGETS)) $(addprefix $(SYMROOT)/,$(TARGETS)) $(SYMROOT)/*.dSYM
