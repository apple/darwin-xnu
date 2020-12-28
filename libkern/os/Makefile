export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

KERNELFILES = \
	base.h \
	object.h \
	log.h \
	trace.h \
	overflow.h \
	smart_ptr.h \
	cpp_util.h

PRIVATE_KERNELFILES = \
	hash.h \
	object_private.h \
	ptrtools.h \
	reason_private.h \
	refcnt.h \
	refcnt_internal.h

DATAFILES = \
	overflow.h

DRIVERKIT_DATAFILES = \
	base.h \
	overflow.h

PRIVATE_DATAFILES = \
	reason_private.h

INSTALL_MI_LIST = ${DATAFILES}

INSTALL_DRIVERKIT_MI_LIST = ${DRIVERKIT_DATAFILES}

INSTALL_MI_DIR = os

INSTALL_MI_LCL_LIST = ${PRIVATE_DATAFILES}

INSTALL_KF_MI_LIST = ${KERNELFILES}

INSTALL_KF_MI_LCL_LIST = ${KERNELFILES} ${PRIVATE_KERNELFILES}

EXPORT_MI_LIST = \
	${KERNELFILES} ${PRIVATE_KERNELFILES} log_private.h

EXPORT_MI_DIR = os

include $(MakeInc_rule)
include $(MakeInc_dir)
