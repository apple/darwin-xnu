export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES =

KERNELFILES = \
	routefs.h

INSTALL_MI_LIST	= ${DATAFILES}

INSTALL_MI_DIR = miscfs/routefs

INSTALL_KF_MI_LIST = ${DATAFILES}

INSTALL_KF_MI_LCL_LIST =

EXPORT_MI_LIST	=

EXPORT_MI_DIR =	miscfs/routefs

include $(MakeInc_rule)
include $(MakeInc_dir)
