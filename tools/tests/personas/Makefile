include ../Makefile.common

CC:=$(shell xcrun -sdk "$(SDKROOT)" -find cc)

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

ARCH_32 := $(filter-out %64, $(ARCHS))
ARCH_64 := $(filter %64, $(ARCHS))

ARCH_32_FLAGS := $(patsubst %, -arch %, $(ARCH_32))
ARCH_64_FLAGS := $(patsubst %, -arch %, $(ARCH_64))
ARCH_FLAGS := $(if $(ARCH_64), $(ARCH_64_FLAGS)) $(if $(ARCH_32), $(ARCH_32_FLAGS))

DSTROOT?=$(shell /bin/pwd)

TARGETS := persona_mgr persona_spawn

all: $(addprefix $(DSTROOT)/, $(TARGETS))

$(DSTROOT)/persona_%: persona_%.c persona_test.h Makefile
	${CC} ${CFLAGS} ${ARCH_FLAGS} -o $(SYMROOT)/$(notdir $@) $<
	if [ ! -e $@ ]; then ditto $(SYMROOT)/$(notdir $@) $@; fi

clean:
	rm -rf $(addprefix $(DSTROOT)/,$(TARGETS)) $(addprefix $(SYMROOT)/,$(TARGETS)) $(SYMROOT)/*.dSYM
