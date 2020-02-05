export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES = \
	bsdthread_private.h \
	priority_private.h \
	workqueue_syscalls.h

PRIVATE_DATAFILES = \
	bsdthread_private.h \
	priority_private.h \
	workqueue_syscalls.h

KERNELFILES = \

PRIVATE_KERNELFILES = \

INTERNAL_KERNELFILES = \
	bsdthread_private.h \
	priority_private.h \
	workqueue_internal.h \
	workqueue_syscalls.h \
	workqueue_trace.h

INSTALL_MI_DIR = pthread

# /usr/local/include without PRIVATE stuff
# /System/Library/Frameworks/System.framework/PrivateHeaders
INCDIR = $(SDKHEADERSROOT)/usr/local/include
INSTALL_MI_LIST = ${DATAFILES}
INSTALL_MI_LCL_LIST = ${PRIVATE_DATAFILES}

# /System/Library/Frameworks/Kernel.framework/Headers
# /System/Library/Frameworks/Kernel.framework/PrivateHeaders
INSTALL_KF_MI_LIST = $(sort ${KERNELFILES})
INSTALL_KF_MI_LCL_LIST = $(sort ${KERNELFILES} ${PRIVATE_KERNELFILES})

EXPORT_MI_LIST = $(sort ${KERNELFILES} ${PRIVATE_KERNELFILES} ${INTERNAL_KERNELFILES})

EXPORT_MI_DIR = ${INSTALL_MI_DIR}

include $(MakeInc_rule)
include $(MakeInc_dir)
