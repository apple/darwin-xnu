export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES =

EXPORT_ONLY_FILES =	\
	ipc_types.h

EXPORT_PRIVATE_FILES =	\
	ipc_port.h

INSTALL_MI_LIST = ${DATAFILES}

INSTALL_MI_DIR = ipc

EXPORT_MI_LIST = ${DATAFILES} ${EXPORT_ONLY_FILES}

INSTALL_KF_MI_LCL_LIST = ${EXPORT_ONLY_FILES} ${EXPORT_PRIVATE_FILES} 

EXPORT_MI_DIR = ipc

include $(MakeInc_rule)
include $(MakeInc_dir)

