export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

IOKIT_FRAMEDIR = $(FRAMEDIR)/IOKit.framework/Versions/A
export INCDIR = $(IOKIT_FRAMEDIR)/Headers
export LCLDIR = $(IOKIT_FRAMEDIR)/PrivateHeaders

include $(MakeInc_cmd)
include $(MakeInc_def)

MD_DIR = i386
EXCLUDE_HEADERS = 

INSTINC_SUBDIRS =
INSTINC_SUBDIRS_PPC =
INSTINC_SUBDIRS_I386 =

EXPINC_SUBDIRS = ${INSTINC_SUBDIRS}
EXPINC_SUBDIRS_PPC = ${INSTINC_SUBDIRS_PPC}
EXPINC_SUBDIRS_I386 = ${INSTINC_SUBDIRS_I386}

ALL_HEADERS = $(shell (cd $(SOURCE); echo *.h))
HEADER_LIST = $(filter-out $(EXCLUDE_HEADERS), $(ALL_HEADERS))

INSTALL_MD_LIST	= ${HEADER_LIST}
INSTALL_MD_LCL_LIST = ""
INSTALL_MD_DIR = $(MD_DIR)

EXPORT_MD_LIST	= ${HEADER_LIST}
EXPORT_MD_DIR = IOKit/$(MD_DIR)

include $(MakeInc_rule)
include $(MakeInc_dir)
