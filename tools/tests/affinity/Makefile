include ../Makefile.common

CC:=$(shell xcrun -sdk "$(SDKROOT)" -find cc)

SYMROOT?=$(shell /bin/pwd)

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
ARCH_32_FLAGS := $(patsubst %, -arch %, $(ARCH_32))
ARCH_64 := $(filter %64, $(ARCHS))
ARCH_64_FLAGS := $(patsubst %, -arch %, $(ARCH_64))

CFLAGS 	:=-g -isysroot $(SDKROOT) -I$(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders

DSTROOT?=$(shell /bin/pwd)
SRCROOT?=$(shell /bin/pwd)

SOURCES := sets.c pool.c tags.c
ARCH_32_TARGETS := $(addprefix $(DSTROOT)/, sets pool tags)
ARCH_64_TARGETS := $(addprefix $(DSTROOT)/, sets64 pool64 tags64)

TARGETS := $(if $(ARCH_64), $(ARCH_64_TARGETS)) $(if $(ARCH_32), $(ARCH_32_TARGETS))


all:	$(TARGETS)

$(ARCH_32_TARGETS): $(DSTROOT)/%: $(SRCROOT)/%.c
	$(CC) $(CFLAGS) $(ARCH_32_FLAGS) $< -o $(SYMROOT)/$(notdir $@) # 32-bit fat 
	if [ ! -e $@ ]; then ditto $(SYMROOT)/$(notdir $@) $@; fi

.SECONDEXPANSION:
$(ARCH_64_TARGETS): $(DSTROOT)/%: $(SRCROOT)/$$(subst 64,,%).c
	$(CC) $(CFLAGS) $(ARCH_64_FLAGS) $< -o $(SYMROOT)/$(notdir $@) # 64-bit fat
	if [ ! -e $@ ]; then ditto $(SYMROOT)/$(notdir $@) $@; fi

clean:
	rm -f $(TARGETS) 
	rm -rf $(SYMROOT)/*.dSYM
