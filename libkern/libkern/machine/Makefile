export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES = \
          OSByteOrder.h

DRIVERKIT_DATAFILES = \
          OSByteOrder.h

INSTALL_MI_LIST	= ${DATAFILES}

INSTALL_DRIVERKIT_MI_LIST = ${DRIVERKIT_DATAFILES}

DRIVERKITINCDIR = $(DRIVERKITSDKHEADERSROOT)/usr/local/include

INSTALL_MI_DIR = libkern/machine

EXPORT_MI_LIST	= ${DATAFILES}

EXPORT_MI_DIR = libkern/machine

include $(MakeInc_rule)
include $(MakeInc_dir)
