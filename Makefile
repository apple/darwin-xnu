ifndef VERSDIR
export VERSDIR=$(shell /bin/pwd)
endif
ifndef SRCROOT
export SRCROOT=$(shell /bin/pwd)
endif
ifndef OBJROOT
export OBJROOT=$(SRCROOT)/BUILD/obj
endif
ifndef DSTROOT
export DSTROOT=$(SRCROOT)/BUILD/dst
endif
ifndef SYMROOT
export SYMROOT=$(SRCROOT)/BUILD/sym
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
	libsa

INSTINC_SUBDIRS = $(ALL_SUBDIRS)

INSTINC_SUBDIRS_PPC = $(INSTINC_SUBDIRS)

INSTINC_SUBDIRS_I386 = $(INSTINC_SUBDIRS)

EXPINC_SUBDIRS = $(ALL_SUBDIRS)

EXPINC_SUBDIRS_PPC =  $(EXPINC_SUBDIRS)

EXPINC_SUBDIRS_I386 = $(EXPINC_SUBDIRS)

COMP_SUBDIRS = $(ALL_SUBDIRS)

INST_SUBDIRS =	\
	libkern	\
	libsa   \
	iokit	\
	osfmk	\
	bsd	\
	config

INSTALL_FILE_LIST= \
	mach_kernel

INSTALL_FILE_DIR= \
	/

INSTMAN_SUBDIRS = \
	bsd

include $(MakeInc_rule)
include $(MakeInc_dir)
