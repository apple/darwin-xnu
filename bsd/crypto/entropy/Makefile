export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES = \
	diag_entropy_sysctl.h

INSTALL_MI_LIST =

EXPORT_MI_LIST = ${DATAFILES}

EXPORT_MI_DIR = crypto/entropy

include $(MakeInc_rule)
include $(MakeInc_dir)
