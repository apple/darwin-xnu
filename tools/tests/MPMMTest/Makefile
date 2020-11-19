include ../Makefile.common

CC:=$(shell xcrun -sdk "$(SDKROOT)" -find cc)

SYMROOT?=$(shell /bin/pwd)

CFLAGS := -g -O2 -isysroot $(SDKROOT) -I$(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders
CFLAGS += -Wno-deprecated-declarations
CFLAGS += -Wl,-sectcreate,__INFO_FILTER,__disable,/dev/null

# $(ARCH_CONFIGS) is set by Makefile.common

DSTROOT?=$(shell /bin/pwd)

ARCH_32_TARGETS := MPMMtest KQMPMMtest KQMPMMtestD
ARCH_64_TARGETS := MPMMtest_64 KQMPMMtest_64 KQMPMMtest_64D
TARGETS := MPMMtest_perf.sh $(if $(ARCH_CONFIGS_64), $(ARCH_64_TARGETS)) $(if $(ARCH_CONFIGS_32), $(ARCH_32_TARGETS))

all:	$(addprefix $(DSTROOT)/, $(TARGETS))

$(DSTROOT)/MPMMtest: MPMMtest.c
	${CC} ${CFLAGS} ${ARCH_FLAGS_32} -o $(SYMROOT)/$(notdir $@) $?
	if [ ! -e $@ ]; then ditto $(SYMROOT)/$(notdir $@) $@; fi

$(DSTROOT)/MPMMtest_64: MPMMtest.c
	${CC} ${CFLAGS} ${ARCH_FLAGS_64} -o $(SYMROOT)/$(notdir $@) $?
	if [ ! -e $@ ]; then ditto $(SYMROOT)/$(notdir $@) $@; fi

$(DSTROOT)/KQMPMMtest: KQMPMMtest.c
	${CC} ${CFLAGS} ${ARCH_FLAGS_32} -o $(SYMROOT)/$(notdir $@) $?
	if [ ! -e $@ ]; then ditto $(SYMROOT)/$(notdir $@) $@; fi

$(DSTROOT)/KQMPMMtest_64: KQMPMMtest.c
	${CC} ${CFLAGS} ${ARCH_FLAGS_64} -o $(SYMROOT)/$(notdir $@) $?
	if [ ! -e $@ ]; then ditto $(SYMROOT)/$(notdir $@) $@; fi

$(DSTROOT)/KQMPMMtestD: KQMPMMtest.c
	${CC} ${CFLAGS} ${ARCH_FLAGS_32}  -DDIRECT_MSG_RCV=1 -o $(SYMROOT)/$(notdir $@) $?
	if [ ! -e $@ ]; then ditto $(SYMROOT)/$(notdir $@) $@; fi

$(DSTROOT)/KQMPMMtest_64D: KQMPMMtest.c
	${CC} ${CFLAGS} ${ARCH_FLAGS_64} -DDIRECT_MSG_RCV=1 -o $(SYMROOT)/$(notdir $@) $?
	if [ ! -e $@ ]; then ditto $(SYMROOT)/$(notdir $@) $@; fi

$(DSTROOT)/MPMMtest_perf.sh: MPMMtest_run.sh
	cp $? $@
	chmod +x $@

clean:
	rm -rf $(addprefix $(DSTROOT)/,$(TARGETS)) $(addprefix $(SYMROOT)/,$(TARGETS)) $(SYMROOT)/*.dSYM
