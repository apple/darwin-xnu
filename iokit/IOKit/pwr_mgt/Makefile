export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

IOKIT_FRAMEDIR = $(FRAMEDIR)/IOKit.framework/Versions/A
INCDIR = $(IOKIT_FRAMEDIR)/Headers
LCLDIR = $(IOKIT_FRAMEDIR)/PrivateHeaders

include $(MakeInc_cmd)
include $(MakeInc_def)

MI_DIR = pwr_mgt
NOT_EXPORT_HEADERS = \
	IOPMinformee.h		\
	IOPMinformeeList.h	\
	IOPMlog.h		\
	IOPMPrivate.h

ALL_HEADERS = $(notdir $(wildcard $(SOURCE)*.h))

INSTALL_MI_LIST	= IOPMLibDefs.h IOPM.h
INSTALL_MI_LCL_LIST = IOPMPrivate.h
INSTALL_MI_DIR = $(MI_DIR)

EXPORT_MI_LIST	= $(filter-out $(NOT_EXPORT_HEADERS), $(ALL_HEADERS))
EXPORT_MI_DIR = IOKit/$(MI_DIR)

INSTALL_KF_MI_LCL_LIST = $(EXPORT_MI_LIST) IOPMPrivate.h

include $(MakeInc_rule)
include $(MakeInc_dir)
