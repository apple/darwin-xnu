export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES = \
	acct.5 \
	core.5 \
	dir.5 \
	dirent.5 \
	types.5

INSTALL_MAN_LIST = ${DATAFILES}

INSTALL_MAN_DIR = man5

include $(MakeInc_rule)
include $(MakeInc_dir)

