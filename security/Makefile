export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES = \
	mac.h \
	mac_policy.h

PRIVATE_DATAFILES = \
	_label.h \
	mac_alloc.h \
	mac_data.h \
	mac_framework.h \
	mac_mach_internal.h \
	mac_internal.h

# Installed in /usr/include/security/
INSTALL_MI_LIST = ${DATAFILES} 

INSTALL_MI_DIR = security

EXPORT_MI_LIST = ${DATAFILES} ${PRIVATE_DATAFILES}

EXPORT_MI_DIR = security

# /System/Library/Frameworks/System.framework/PrivateHeaders
INSTALL_MI_LCL_LIST = ${DATAFILES} ${PRIVATE_DATAFILES}

# /System/Library/Frameworks/Kernel.framework/PrivateHeaders
INSTALL_KF_MI_LCL_LIST = ${DATAFILES} ${PRIVATE_DATAFILES}

COMP_SUBDIRS = conf

include $(MakeInc_rule)
include $(MakeInc_dir)
