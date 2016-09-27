export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

PRIVATE_DATAFILES = \
	rc4.h

INSTALL_MI_DIR = crypto

EXPORT_MI_DIR = ${INSTALL_MI_DIR}

INSTALL_KF_MI_LCL_LIST = ${PRIVATE_DATAFILES}

include $(MakeInc_rule)
include $(MakeInc_dir)
