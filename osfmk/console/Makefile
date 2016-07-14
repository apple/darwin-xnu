export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES =

PRIVATE_DATAFILES = \
	video_console.h

INSTALL_MI_LCL_LIST = ${PRIVATE_DATAFILES}

INSTALL_KF_MI_LCL_LIST = ${PRIVATE_DATAFILES}

EXPORT_MI_LIST = ${PRIVATE_DATAFILES}

INSTALL_MI_DIR = console
EXPORT_MI_DIR = console

include $(MakeInc_rule)
include $(MakeInc_dir)


