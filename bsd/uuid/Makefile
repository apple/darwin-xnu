export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

# In both the framework PrivateHeader area and /usr/include/uuid
DATAFILES = \
	uuid.h

# KERNELFILES will appear only in the kernel framework
KERNELFILES = \
	uuid.h

INSTALL_MI_LIST	= ${DATAFILES}

INSTALL_MI_DIR = uuid

EXPORT_MI_LIST	= ${KERNELFILES}

EXPORT_MI_DIR = uuid

# /System/Library/Frameworks/Kernel.framework/PrivateHeaders

INSTALL_KF_MI_LCL_LIST =  ${KERNELFILES}

# /System/Library/Frameworks/Kernel.framework/Headers

INSTALL_KF_MI_LIST = ${KERNELFILES}

include $(MakeInc_rule)
include $(MakeInc_dir)
