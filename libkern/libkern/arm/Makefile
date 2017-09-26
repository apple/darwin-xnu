export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES = \
          OSByteOrder.h

INSTALL_MD_LIST	= ${DATAFILES}

INSTALL_MD_DIR = libkern/arm

EXPORT_MD_LIST	= ${DATAFILES}

EXPORT_MD_DIR = libkern/arm

include $(MakeInc_rule)
include $(MakeInc_dir)
