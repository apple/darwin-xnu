#
# Copyright (C) 1999-2010 Apple Inc. All rights reserved.
#

ifndef VERSDIR
export VERSDIR := $(shell /bin/pwd)
endif

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

export MakeInc_top=${VERSDIR}/makedefs/MakeInc.top
export MakeInc_kernel=${VERSDIR}/makedefs/MakeInc.kernel
export MakeInc_cmd=${VERSDIR}/makedefs/MakeInc.cmd
export MakeInc_def=${VERSDIR}/makedefs/MakeInc.def
export MakeInc_rule=${VERSDIR}/makedefs/MakeInc.rule
export MakeInc_dir=${VERSDIR}/makedefs/MakeInc.dir

#
# Dispatch non-xnu build aliases to their own build
# systems. All xnu variants start with MakeInc_top.
#

ifeq ($(findstring Libsyscall,$(RC_ProjectName)),Libsyscall)

ifeq ($(RC_ProjectName),Libsyscall_headers_Sim)
TARGET=-target Libsyscall_headers_Sim
endif

default: install

installhdrs install:
	cd libsyscall ; \
		xcodebuild $@ $(TARGET)	\
			"SRCROOT=$(SRCROOT)/libsyscall"					\
			"OBJROOT=$(OBJROOT)" 						\
			"SYMROOT=$(SYMROOT)" 						\
			"DSTROOT=$(DSTROOT)"						\
			"SDKROOT=$(SDKROOT)"

clean:

installsrc:
	pax -rw . $(SRCROOT)

else ifeq ($(RC_ProjectName),libkxld)

default: install

installhdrs install clean:
	 $(MAKE) -C libkern/kxld $@ USE_APPLE_PB_SUPPORT=all

installsrc:
	pax -rw . $(SRCROOT)

else ifeq ($(RC_ProjectName),libkxld_host)

default: install

installhdrs install clean:
	 $(MAKE) -C libkern/kxld $@ USE_APPLE_PB_SUPPORT=all PRODUCT_TYPE=ARCHIVE

installsrc:
	pax -rw . $(SRCROOT)

else ifeq ($(RC_ProjectName),libkmod)

default: install

installhdrs install:
	cd libkern/kmod ; \
		xcodebuild $@ 	\
			"SRCROOT=$(SRCROOT)/libkern/kmod"				\
			"OBJROOT=$(OBJROOT)" 						\
			"SYMROOT=$(SYMROOT)" 						\
			"DSTROOT=$(DSTROOT)"						\
			"SDKROOT=$(SDKROOT)"

clean:

installsrc:
	pax -rw . $(SRCROOT)

else ifeq ($(RC_ProjectName),xnu_quick_test)

default: install

installhdrs:

install: xnu_quick_test

clean:

installsrc:
	pax -rw . $(SRCROOT)

else # all other RC_ProjectName

ifndef CURRENT_BUILD_CONFIG

# avoid having to include MakeInc.cmd
ifeq ($(RC_XBS),YES)
_v =
else ifeq ($(VERBOSE),YES)
_v =
else
_v = @
endif

#
# Setup for parallel sub-makes based on 2 times number of logical CPUs.
# If MAKEJOBS or -jN is passed on the make line, that takes precedence.
#
MAKEJOBS := --jobs=$(shell expr `/usr/sbin/sysctl -n hw.physicalcpu` \* 2)

TOP_TARGETS = clean installsrc installhdrs installhdrs_embedded installman exporthdrs setup build all all_embedded install install_embedded installopensource cscope tags help print_exports print_exports_first_build_config

.PHONY: $(TOP_TARGETS)

default: all

ifneq ($(REMOTEBUILD),)
$(TOP_TARGETS):
	$(_v)$(VERSDIR)/tools/remote_build.sh _REMOTEBUILD_TARGET=$@ _REMOTEBUILD_MAKE=$(MAKE) $(MAKEFLAGS)
else
$(TOP_TARGETS):
	$(_v)$(MAKE) -r $(if $(filter -j,$(MAKEFLAGS)),,$(MAKEJOBS)) -f $(MakeInc_top) $@
endif

else # CURRENT_BUILD_CONFIG

include $(MakeInc_cmd)
include $(MakeInc_def)

ALL_SUBDIRS = \
	bsd  \
	iokit \
	osfmk \
	pexpert \
	libkern \
	libsa \
	security \
	config

CONFIG_SUBDIRS = config tools

INSTINC_SUBDIRS = $(ALL_SUBDIRS) EXTERNAL_HEADERS
INSTINC_SUBDIRS_X86_64 = $(INSTINC_SUBDIRS)
INSTINC_SUBDIRS_ARM = $(INSTINC_SUBDIRS)

EXPINC_SUBDIRS = $(ALL_SUBDIRS)
EXPINC_SUBDIRS_X86_64 = $(EXPINC_SUBDIRS)
EXPINC_SUBDIRS_ARM = $(EXPINC_SUBDIRS)

SETUP_SUBDIRS = SETUP

COMP_SUBDIRS_X86_64 = $(ALL_SUBDIRS)
COMP_SUBDIRS_ARM = $(ALL_SUBDIRS)

INST_SUBDIRS =	\
	bsd	\
	config

INSTMAN_SUBDIRS = \
	bsd

include $(MakeInc_kernel)
include $(MakeInc_rule)
include $(MakeInc_dir)

endif # CURRENT_BUILD_CONFIG

endif # all other RC_ProjectName

# "xnu_quick_test" and "testbots" are targets that can be invoked via a standalone
# "make xnu_quick_test" or via buildit/XBS with the RC_ProjectName=xnu_quick_test.
# Define the target here in the outermost scope of the initial Makefile

xnu_quick_test:
	$(MAKE) -C $(SRCROOT)/tools/tests					\
		SRCROOT=$(SRCROOT)/tools/tests

# This target is defined to compile and run xnu_quick_test under testbots
testbots:
	$(MAKE) -C $(SRCROOT)/tools/tests/xnu_quick_test			\
		SRCROOT=$(SRCROOT)/tools/tests/xnu_quick_test			\
		MORECFLAGS="-DRUN_UNDER_TESTBOTS=1" 				\
		MAKE=$(MAKE)							\
		testbots
