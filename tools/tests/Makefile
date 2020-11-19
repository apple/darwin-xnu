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

DSTSUBPATH_KEXTS = $(DSTROOT)/System/AppleInternal/Library/AuxiliaryExtensions

COMMON_TARGETS = unit_tests \
		MPMMTest		\
		packetdrill		\
		affinity		\
		superpages		\
		zero-to-n		\
		jitter			\
		perf_index		\
		personas		\
		unixconf	 	\

KEXT_TARGETS = pgokext.kext

IPHONE_TARGETS =

MAC_TARGETS =

BATS_TARGET = $(BATS_CONFIG_PATH)/BATS

ifeq "$(Embedded)" "YES"
TARGETS =	$(addprefix $(DSTSUBPATH)/, $(COMMON_TARGETS) $(IPHONE_TARGETS)) $(addprefix $(DSTSUBPATH_KEXTS)/, $(KEXT_TARGETS))
else
TARGETS =	$(addprefix $(DSTSUBPATH)/, $(COMMON_TARGETS) $(MAC_TARGETS)) $(addprefix $(DSTSUBPATH_KEXTS)/, $(KEXT_TARGETS))
endif

all:	$(BATS_TARGET) $(TARGETS)

.PHONY: always

always:

# NOTE: RC_ARCHES nonsense is here because code signing will fail on kexts if we include a i386 slice
# <rdar://problem/29878263> CoreOSLobo: xnu_tests-4026 fails to codesign

$(DSTSUBPATH_KEXTS)/pgokext.kext: always
	xcodebuild -configuration Debug -project $(SRCROOT)/testkext/testkext.xcodeproj -target pgokext DSTROOT=$(DSTSUBPATH_KEXTS) SYMROOT=$(SYMROOT)/testkext SRCROOT=$(SRCROOT)/testkext OBJROOT=$(OBJROOT)/testkext SDKROOT=$(SDKROOT) RC_ARCHS="$(subst i386,,$(RC_ARCHS))" install

$(DSTSUBPATH)/%: always
	$(_v)echo Building $@
	$(_v)mkdir -p $@
	$(_v)mkdir -p $(OBJROOT)/$(notdir $@)
	$(_v)mkdir -p $(SYMROOT)/$(notdir $@)
	$(_v)$(MAKE) -C $(SRCROOT)/$(notdir $@) SRCROOT=$(SRCROOT)/$(notdir $@) DSTROOT=$@ OBJROOT=$(OBJROOT)/$(notdir $@) SYMROOT=$(SYMROOT)/$(notdir $@) SDKROOT=$(SDKROOT) BASEDSTROOT=$(DSTROOT)
	$(_v)find $@ -type d -name "*.dSYM" -exec cp -a {} $(SYMROOT)/ ';'

$(BATS_TARGET): $(TARGETS)
	$(_v)mkdir -p $@
	$(_v)mkdir -p $(OBJROOT)/$(notdir $@)
	$(_v)mkdir -p $(SYMROOT)
	$(_v)$(MAKE) -C $(SRCROOT)/$(notdir $@) SRCROOT=$(SRCROOT)/$(notdir $@) DSTROOT=$@ OBJROOT=$(OBJROOT)/$(notdir $@) SDKROOT=$(SDKROOT) BASEDSTROOT=$(DSTROOT) BASEDSTSUBPATH=$(DSTSUBPATH)
