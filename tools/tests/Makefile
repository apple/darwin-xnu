include Makefile.common

ifndef SRCROOT
export SRCROOT := $(shell /bin/pwd)
endif
ifndef OBJROOT
export OBJROOT = $(SRCROOT)/BUILD/obj
endif
ifndef DSTROOT
export DSTROOT = $(SRCROOT)/BUILD/dst
endif
ifndef SYMROOT
export SYMROOT = $(SRCROOT)/BUILD/sym
endif

ifdef RC_ProjectName
DSTSUBPATH = $(DSTROOT)/AppleInternal/CoreOS/tests/xnu
BATS_CONFIG_PATH = $(DSTROOT)/AppleInternal/CoreOS
else
DSTSUBPATH = $(DSTROOT)
BATS_CONFIG_PATH = $(DSTROOT)
endif

COMMON_TARGETS = unit_tests \
		MPMMTest		\
		packetdrill		\
		affinity		\
		execperf		\
		kqueue_tests		\
		superpages		\
		zero-to-n		\
		jitter			\
		perf_index		\
		darwintests		\
		unixconf

IPHONE_TARGETS =

MAC_TARGETS =

BATS_TARGET = $(BATS_CONFIG_PATH)/BATS

ifeq "$(Embedded)" "YES"
TARGETS =	$(addprefix $(DSTSUBPATH)/, $(COMMON_TARGETS) $(IPHONE_TARGETS))
else
TARGETS =	$(addprefix $(DSTSUBPATH)/, $(COMMON_TARGETS) $(MAC_TARGETS))
endif

all:	$(BATS_TARGET) $(TARGETS)

.PHONY: always

always:

$(DSTSUBPATH)/%: always
	$(_v)echo Building $@
	$(_v)mkdir -p $@
	$(_v)mkdir -p $(OBJROOT)/$(notdir $@)
	$(_v)mkdir -p $(SYMROOT)/$(notdir $@)
	$(_v)$(MAKE) -C $(SRCROOT)/$(notdir $@) SRCROOT=$(SRCROOT)/$(notdir $@) DSTROOT=$@ OBJROOT=$(OBJROOT)/$(notdir $@) SYMROOT=$(SYMROOT)/$(notdir $@) SDKROOT=$(SDKROOT) BASEDSTROOT=$(DSTROOT)

$(BATS_TARGET): $(TARGETS)
	$(_v)mkdir -p $@
	$(_v)mkdir -p $(OBJROOT)/$(notdir $@)
	$(_v)mkdir -p $(SYMROOT)
	$(_v)$(MAKE) -C $(SRCROOT)/$(notdir $@) SRCROOT=$(SRCROOT)/$(notdir $@) DSTROOT=$@ OBJROOT=$(OBJROOT)/$(notdir $@) SDKROOT=$(SDKROOT) BASEDSTROOT=$(DSTROOT)
