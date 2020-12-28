export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES = \
	AIC.h \
	board_config.h \
	boot.h \
	consistent_debug.h \
	dockchannel.h \
	PL192_VIC.h \
	protos.h \
	S3cUART.h \
	S7002.h \
	T8002.h

INSTALL_MD_LIST	= ${DATAFILES}

INSTALL_MD_DIR = pexpert/arm

EXPORT_MD_LIST	= ${DATAFILES}

EXPORT_MD_DIR = pexpert/arm

include $(MakeInc_rule)
include $(MakeInc_dir)
