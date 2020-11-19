export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

INCDIR=$(SDKHEADERSROOT)/usr/local/include

# Installs header file for user level -
#         $(DSTROOT)/System/Library/Frameworks/System.framework/PrivateHeaders
#         $(DSTROOT)/usr/(local/)include/
DATAFILES= \
	mac.h

# Installs header file for kernel extensions -
#         $(DSTROOT)/System/Library/Frameworks/Kernel.framework/Headers
#         $(DSTROOT)/System/Library/Frameworks/Kernel.framework/PrivateHeaders
KERNELFILES= \

# Installs header file for Apple internal use in user level -
#         $(DSTROOT)/System/Library/Frameworks/System.framework/PrivateHeaders
PRIVATE_DATAFILES = ${DATAFILES}

# Installs header file for Apple internal use for kernel extensions -
#         $(DSTROOT)/System/Library/Frameworks/Kernel.framework/PrivateHeaders
PRIVATE_KERNELFILES = \
	_label.h \
	mac.h \
	mac_data.h \
	mac_framework.h \
	mac_internal.h \
	mac_mach_internal.h \
	mac_policy.h

INSTALL_MI_LIST = ${DATAFILES}

# /System/Library/Frameworks/System.framework/PrivateHeaders
INSTALL_MI_LCL_LIST = ${PRIVATE_DATAFILES}

INSTALL_MI_DIR = security

EXPORT_MI_LIST = ${PRIVATE_KERNELFILES}

EXPORT_MI_DIR = ${INSTALL_MI_DIR}

# /System/Library/Frameworks/Kernel.framework/Headers
INSTALL_KF_MI_LIST = $(sort ${KERNELFILES})

# /System/Library/Frameworks/Kernel.framework/PrivateHeaders
INSTALL_KF_MI_LCL_LIST = $(sort ${KERNELFILES} ${PRIVATE_KERNELFILES})

COMP_SUBDIRS = conf

include $(MakeInc_rule)
include $(MakeInc_dir)
