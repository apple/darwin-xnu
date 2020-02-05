#
# Copyright (C) 1999-2016 Apple Inc. All rights reserved.
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
ifndef MallocNanoZone
export MallocNanoZone := 1
endif

# Avoid make default rules, make becomes faster
MAKEFLAGS+=r

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

include $(MakeInc_cmd)

ifneq ($(findstring Libsyscall_,$(RC_ProjectName)),)
TARGET=-target $(RC_ProjectName)
endif

default: install

# default to OS X
SDKROOT ?= macosx.internal

installhdrs install:
	cd libsyscall ; \
		xcodebuild $@ $(TARGET)	\
			$(MAKEOVERRIDES)	\
			"SRCROOT=$(SRCROOT)/libsyscall"					\
			"OBJROOT=$(OBJROOT)"						\
			"SYMROOT=$(SYMROOT)"						\
			"DSTROOT=$(DSTROOT)"						\
			"SDKROOT=$(SDKROOT)"

Libsyscall_driverkit: install

.PHONY: Libsyscall_driverkit

clean:

installsrc:
	pax -rw . $(SRCROOT)

else ifeq ($(RC_ProjectName),libkxld)

include $(MakeInc_cmd)

default: install

installhdrs install clean:
	 $(MAKE) -C libkern/kxld $@ USE_APPLE_PB_SUPPORT=all

installsrc:
	$(_v)$(MKDIR) $(SRCROOT)
	$(_v)$(FIND) -x . \! \( \( -name BUILD -o -name .svn -o -name .git -o -name cscope.\* -o -name \*~ \) -prune \) -print0 | $(PAX) -rw -p a -d0 $(SRCROOT)
	$(_v)$(CHMOD) -R go+rX $(SRCROOT)

else ifeq ($(RC_ProjectName),libkxld_host)

include $(MakeInc_cmd)

default: install

installhdrs install clean:
	 $(MAKE) -C libkern/kxld $@ USE_APPLE_PB_SUPPORT=all PRODUCT_TYPE=ARCHIVE

installsrc:
	$(_v)$(MKDIR) $(SRCROOT)
	$(_v)$(FIND) -x . \! \( \( -name BUILD -o -name .svn -o -name .git -o -name cscope.\* -o -name \*~ \) -prune \) -print0 | $(PAX) -rw -p a -d0 $(SRCROOT)
	$(_v)$(CHMOD) -R go+rX $(SRCROOT)

else ifeq ($(RC_ProjectName),libkmod)

default: install

installhdrs install:
	cd libkern/kmod ; \
		xcodebuild $@	\
			$(MAKEOVERRIDES)	\
			"SRCROOT=$(SRCROOT)/libkern/kmod"				\
			"OBJROOT=$(OBJROOT)"						\
			"SYMROOT=$(SYMROOT)"						\
			"DSTROOT=$(DSTROOT)"						\
			"SDKROOT=$(SDKROOT)"

clean:

installsrc:
	pax -rw . $(SRCROOT)

else ifeq ($(RC_ProjectName),xnu_tests)

export SYSCTL_HW_PHYSICALCPU := $(shell /usr/sbin/sysctl -n hw.physicalcpu)
export SYSCTL_HW_LOGICALCPU  := $(shell /usr/sbin/sysctl -n hw.logicalcpu)
MAKEJOBS := --jobs=$(shell expr $(SYSCTL_HW_LOGICALCPU) + 1)

default: install

installhdrs:

install: xnu_tests

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
# Setup for parallel sub-makes, taking into account physical and logical
# CPUs. If the system does not support SMT, use N+1.
# If MAKEJOBS or -jN is passed on the make line, that takes precedence.
#
export SYSCTL_HW_PHYSICALCPU := $(shell /usr/sbin/sysctl -n hw.physicalcpu)
export SYSCTL_HW_LOGICALCPU  := $(shell /usr/sbin/sysctl -n hw.logicalcpu)
MAKEJOBS := --jobs=$(shell expr $(SYSCTL_HW_LOGICALCPU) + 1)

TOP_TARGETS =								\
	clean								\
	installsrc							\
	exporthdrs							\
	all all_desktop all_embedded					\
	all_release_embedded all_development_embedded			\
	installhdrs installhdrs_desktop installhdrs_embedded		\
	installhdrs_release_embedded installhdrs_development_embedded	\
	install install_desktop install_embedded			\
	install_release_embedded install_development_embedded		\
	installopensource						\
	cscope tags TAGS checkstyle restyle check_uncrustify uncrustify				\
	help

DEFAULT_TARGET = all

# Targets for internal build system debugging
TOP_TARGETS +=						\
	print_exports print_exports_first_build_config	\
	setup						\
	build						\
	config						\
	install_textfiles				\
	install_config

ifeq ($(BUILD_JSON_COMPILATION_DATABASE),1)
MAKEARGS += -B
DEFAULT_TARGET := build
endif

.PHONY: $(TOP_TARGETS)

default: $(DEFAULT_TARGET)

ifneq ($(REMOTEBUILD),)
$(TOP_TARGETS):
	$(_v)$(VERSDIR)/tools/remote_build.sh _REMOTEBUILD_TARGET=$@ _REMOTEBUILD_MAKE=$(MAKE) $(if $(filter --,$(MAKEFLAGS)),-,)$(MAKEFLAGS)
else
$(TOP_TARGETS):
	$(_v)$(MAKE) $(MAKEARGS) -r $(if $(filter -j,$(MAKEFLAGS)),,$(MAKEJOBS)) -f $(MakeInc_top) $@
endif

else # CURRENT_BUILD_CONFIG

include $(MakeInc_cmd)
include $(MakeInc_def)

ALL_SUBDIRS = \
	security \
	bsd  \
	iokit \
	osfmk \
	pexpert \
	libkern \
	libsa \
	config \
	san

CONFIG_SUBDIRS = config tools san

INSTINC_SUBDIRS = $(ALL_SUBDIRS) EXTERNAL_HEADERS
INSTINC_SUBDIRS_X86_64 = $(INSTINC_SUBDIRS)
INSTINC_SUBDIRS_X86_64H = $(INSTINC_SUBDIRS)
INSTINC_SUBDIRS_ARM = $(INSTINC_SUBDIRS)
INSTINC_SUBDIRS_ARM64 = $(INSTINC_SUBDIRS)

EXPINC_SUBDIRS = $(ALL_SUBDIRS)
EXPINC_SUBDIRS_X86_64 = $(EXPINC_SUBDIRS)
EXPINC_SUBDIRS_X86_64H = $(EXPINC_SUBDIRS)
EXPINC_SUBDIRS_ARM = $(EXPINC_SUBDIRS)
EXPINC_SUBDIRS_ARM64 = $(EXPINC_SUBDIRS)

SETUP_SUBDIRS = SETUP san bsd

COMP_SUBDIRS_X86_64 = $(ALL_SUBDIRS)
COMP_SUBDIRS_X86_64H = $(ALL_SUBDIRS)
COMP_SUBDIRS_ARM = $(ALL_SUBDIRS)
COMP_SUBDIRS_ARM64 = $(ALL_SUBDIRS)

INSTTEXTFILES_SUBDIRS =	\
	bsd

include $(MakeInc_kernel)
include $(MakeInc_rule)
include $(MakeInc_dir)

endif # CURRENT_BUILD_CONFIG

endif # all other RC_ProjectName

installapi_libkdd installhdrs_libkdd install_libkdd:
	cd libkdd; \
		xcodebuild -target Default $(subst _libkdd,,$@)	\
			$(MAKEOVERRIDES)	\
			"SRCROOT=$(SRCROOT)/libkdd"		\
			"OBJROOT=$(OBJROOT)"			\
			"SYMROOT=$(SYMROOT)"			\
			"DSTROOT=$(DSTROOT)"			\
			"SDKROOT=$(SDKROOT)"


installapi_libkdd_tests installhdrs_libkdd_tests install_libkdd_tests:
	cd libkdd; \
		xcodebuild -target tests $(subst _libkdd_tests,,$@)	\
			$(MAKEOVERRIDES)	\
			"SRCROOT=$(SRCROOT)/libkdd"		\
			"OBJROOT=$(OBJROOT)"			\
			"SYMROOT=$(SYMROOT)"			\
			"DSTROOT=$(DSTROOT)"			\
			"SDKROOT=$(SDKROOT)"


installapi_libkdd_host installhdrs_libkdd_host install_libkdd_host:
	cd libkdd; \
		xcodebuild -configuration ReleaseHost -target kdd.framework $(subst _libkdd_host,,$@)	\
			$(MAKEOVERRIDES)	\
			"SRCROOT=$(SRCROOT)/libkdd"		\
			"OBJROOT=$(OBJROOT)"			\
			"SYMROOT=$(SYMROOT)"			\
			"DSTROOT=$(DSTROOT)"			\
			"SDKROOT=$(SDKROOT)"


# "xnu_tests" and "testbots" are targets that can be invoked via a standalone
# "make xnu_tests" or via buildit/XBS with the RC_ProjectName=xnu_tests.
# Define the target here in the outermost scope of the initial Makefile

xnu_tests:
	$(MAKE) -C $(SRCROOT)/tools/tests	$(if $(filter -j,$(MAKEFLAGS)),,$(MAKEJOBS)) \
		SRCROOT=$(SRCROOT)/tools/tests
	$(MAKE) -C $(SRCROOT)/tests	$(if $(filter -j,$(MAKEFLAGS)),,$(MAKEJOBS)) \
		SRCROOT=$(SRCROOT)/tests
