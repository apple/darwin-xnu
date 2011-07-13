ifndef VERSDIR
export VERSDIR=$(shell /bin/pwd)
endif
ifndef SRCROOT
export SRCROOT=$(shell /bin/pwd)
endif
ifndef OBJROOT
export OBJROOT=$(SRCROOT)/BUILD/obj/
endif
ifndef DSTROOT
export DSTROOT=$(SRCROOT)/BUILD/dst/
endif
ifndef SYMROOT
export SYMROOT=$(SRCROOT)/BUILD/sym/
endif

export MakeInc_cmd=${VERSDIR}/makedefs/MakeInc.cmd
export MakeInc_def=${VERSDIR}/makedefs/MakeInc.def
export MakeInc_rule=${VERSDIR}/makedefs/MakeInc.rule
export MakeInc_dir=${VERSDIR}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

ALL_SUBDIRS = \
	iokit \
	osfmk \
	bsd  \
	pexpert \
	libkern \
	libsa \
	security

CONFIG_SUBDIRS_I386 = config
CONFIG_SUBDIRS_X86_64 = config
CONFIG_SUBDIRS_ARM = config

INSTINC_SUBDIRS = $(ALL_SUBDIRS) EXTERNAL_HEADERS
INSTINC_SUBDIRS_I386 = $(INSTINC_SUBDIRS)
INSTINC_SUBDIRS_X86_64 = $(INSTINC_SUBDIRS)
INSTINC_SUBDIRS_ARM = $(INSTINC_SUBDIRS)

EXPINC_SUBDIRS = $(ALL_SUBDIRS)
EXPINC_SUBDIRS_I386 = $(EXPINC_SUBDIRS)
EXPINC_SUBDIRS_X86_64 = $(EXPINC_SUBDIRS)
EXPINC_SUBDIRS_ARM = $(EXPINC_SUBDIRS)

SETUP_SUBDIRS = SETUP

COMP_SUBDIRS_I386 = $(ALL_SUBDIRS)
COMP_SUBDIRS_X86_64 = $(ALL_SUBDIRS)
COMP_SUBDIRS_ARM = $(ALL_SUBDIRS)

INST_SUBDIRS =	\
	libkern	\
	libsa   \
	iokit	\
	osfmk	\
	bsd	\
	config	\
	security

INSTALL_KERNEL_FILE = mach_kernel

INSTALL_KERNEL_DIR = /


INSTMAN_SUBDIRS = \
	bsd

include $(MakeInc_rule)
include $(MakeInc_dir)

# This target is defined to compile and run xnu_quick_test under testbots
testbots:
	/usr/bin/make MORECFLAGS="-D RUN_UNDER_TESTBOTS=1" testbots -C ./tools/tests/xnu_quick_test/

