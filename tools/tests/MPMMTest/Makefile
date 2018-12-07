include ../Makefile.common

CC:=$(shell xcrun -sdk "$(SDKROOT)" -find cc)

SYMROOT?=$(shell /bin/pwd)

CFLAGS := -g -O2 -isysroot $(SDKROOT) -I$(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders
CFLAGS += -Wno-deprecated-declarations

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

DSTROOT?=$(shell /bin/pwd)

ARCH_32_TARGETS := MPMMtest KQMPMMtest KQMPMMtestD
ARCH_64_TARGETS := MPMMtest_64 KQMPMMtest_64 KQMPMMtest_64D
TARGETS := MPMMtest_perf.sh $(if $(ARCH_64), $(ARCH_64_TARGETS)) $(if $(ARCH_32), $(ARCH_32_TARGETS))

all:	$(addprefix $(DSTROOT)/, $(TARGETS))

$(DSTROOT)/MPMMtest: MPMMtest.c
	${CC} ${CFLAGS} ${ARCH_32_FLAGS} -o $(SYMROOT)/$(notdir $@) $?
	if [ ! -e $@ ]; then ditto $(SYMROOT)/$(notdir $@) $@; fi

$(DSTROOT)/MPMMtest_64: MPMMtest.c
	${CC} ${CFLAGS} ${ARCH_64_FLAGS} -o $(SYMROOT)/$(notdir $@) $?
	if [ ! -e $@ ]; then ditto $(SYMROOT)/$(notdir $@) $@; fi

$(DSTROOT)/KQMPMMtest: KQMPMMtest.c
	${CC} ${CFLAGS} ${ARCH_32_FLAGS} -o $(SYMROOT)/$(notdir $@) $?
	if [ ! -e $@ ]; then ditto $(SYMROOT)/$(notdir $@) $@; fi

$(DSTROOT)/KQMPMMtest_64: KQMPMMtest.c
	${CC} ${CFLAGS} ${ARCH_64_FLAGS} -o $(SYMROOT)/$(notdir $@) $?
	if [ ! -e $@ ]; then ditto $(SYMROOT)/$(notdir $@) $@; fi

$(DSTROOT)/KQMPMMtestD: KQMPMMtest.c
	${CC} ${CFLAGS} ${ARCH_32_FLAGS}  -DDIRECT_MSG_RCV=1 -o $(SYMROOT)/$(notdir $@) $?
	if [ ! -e $@ ]; then ditto $(SYMROOT)/$(notdir $@) $@; fi

$(DSTROOT)/KQMPMMtest_64D: KQMPMMtest.c
	${CC} ${CFLAGS} ${ARCH_64_FLAGS} -DDIRECT_MSG_RCV=1 -o $(SYMROOT)/$(notdir $@) $?
	if [ ! -e $@ ]; then ditto $(SYMROOT)/$(notdir $@) $@; fi

$(DSTROOT)/MPMMtest_perf.sh: MPMMtest_run.sh
	cp $? $@
	chmod +x $@

clean:
	rm -rf $(addprefix $(DSTROOT)/,$(TARGETS)) $(addprefix $(SYMROOT)/,$(TARGETS)) $(SYMROOT)/*.dSYM
