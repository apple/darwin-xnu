export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES = \
	copy.9	\
	fetch.9	\
	store.9	\
	style.9	\

INSTALL_MAN_LIST = ${DATAFILES}

INSTALL_MAN_DIR = man9

include $(MakeInc_rule)
include $(MakeInc_dir)

