ifdef RC_ProjectName
DSTSUBPATH = $(DSTROOT)/AppleInternal/CoreOS
else
DSTSUBPATH = $(DSTROOT)
endif

OBJROOT?=$(shell /bin/pwd)

ifeq "$(RC_TARGET_CONFIG)" "iPhone"
Embedded?=YES
else
Embedded?=$(shell echo $(SDKROOT) | grep -iq iphoneos && echo YES || echo NO)
endif

COMMON_TARGETS = xnu_quick_test		\
		MPMMTest		\
		affinity		\
		kqueue_tests		\
		superpages		\
		zero-to-n		\
		jitter			\
		perf_index		\
		unit_tests

IPHONE_TARGETS = memorystatus

MAC_TARGETS = 

ifeq "$(Embedded)" "YES"
TARGETS = 	$(addprefix $(DSTSUBPATH)/, $(COMMON_TARGETS) $(IPHONE_TARGETS))
else
TARGETS = 	$(addprefix $(DSTSUBPATH)/, $(COMMON_TARGETS) $(MAC_TARGETS))
endif

all:	$(TARGETS)

$(DSTSUBPATH)/%:
	mkdir -p $@
	mkdir -p $(OBJROOT)/$(notdir $@) 
	$(MAKE) -C $(SRCROOT)/$(notdir $@) SRCROOT=$(SRCROOT)/$(notdir $@) DSTROOT=$@ OBJROOT=$(OBJROOT)/$(notdir $@)
