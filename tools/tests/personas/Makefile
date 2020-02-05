include ../Makefile.common

CC:=$(shell xcrun -sdk "$(SDKROOT)" -find cc)
CODESIGN:=$(shell xcrun -sdk "$(SDKROOT)" -find codesign)
CODESIGN_ALLOCATE:=$(shell xcrun -sdk "$(SDKROOT)" -find codesign_allocate)

SYMROOT?=$(shell /bin/pwd)

CFLAGS := -g -O2 -isysroot $(SDKROOT) -I$(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders

ifdef RC_ARCHS
    ARCHS:=$(RC_ARCHS)
  else
    ifeq "$(Embedded)" "YES"
      ARCHS:=armv7 armv7s arm64
    else
      ARCHS:=x86_64 i386
  endif
endif

# These are convenience functions for filtering based on substrings, as the
# normal filter functions only accept one wildcard.
FILTER_OUT_SUBSTRING=$(strip $(foreach string,$(2),$(if $(findstring $(1),$(string)),,$(string))))
FILTER_SUBSTRING=$(strip $(foreach string,$(2),$(if $(findstring $(1),$(string)),$(string),)))

ARCH_32:=$(call FILTER_OUT_SUBSTRING,64,$(ARCHS))
ARCH_64:=$(call FILTER_SUBSTRING,64,$(ARCHS))

ARCH_32_FLAGS := $(patsubst %, -arch %, $(ARCH_32))
ARCH_64_FLAGS := $(patsubst %, -arch %, $(ARCH_64))
ARCH_FLAGS := $(if $(ARCH_64), $(ARCH_64_FLAGS)) $(if $(ARCH_32), $(ARCH_32_FLAGS))

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
