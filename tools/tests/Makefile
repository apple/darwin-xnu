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
		affinity		\
		execperf		\
		kqueue_tests		\
		superpages		\
		zero-to-n		\
		jitter			\
		perf_index

IPHONE_TARGETS = 

MAC_TARGETS = 


BATS_TARGET = $(BATS_CONFIG_PATH)/BATS

ifeq "$(Embedded)" "YES"
TARGETS = 	$(addprefix $(DSTSUBPATH)/, $(COMMON_TARGETS) $(IPHONE_TARGETS))
else
TARGETS = 	$(addprefix $(DSTSUBPATH)/, $(COMMON_TARGETS) $(MAC_TARGETS))
endif

all:	$(BATS_TARGET) $(TARGETS)

$(BATS_TARGET) $(DSTSUBPATH)/%:
	mkdir -p $@
	mkdir -p $(OBJROOT)/$(notdir $@) 
	mkdir -p $(SYMROOT)
	$(MAKE) -C $(SRCROOT)/$(notdir $@) SRCROOT=$(SRCROOT)/$(notdir $@) DSTROOT=$@ OBJROOT=$(OBJROOT)/$(notdir $@) SDKROOT=$(SDKROOT)
