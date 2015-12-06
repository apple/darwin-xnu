export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES = \
	keysock.h

PRIVATE_DATAFILES = \
	key_debug.h keydb.h key_var.h

PRIVATE_KERNELFILES = \
	 key.h

INSTALL_MI_LIST	= ${DATAFILES}

INSTALL_MI_DIR = netkey

EXPORT_MI_LIST	= ${DATAFILES}

EXPORT_MI_DIR = netkey

INSTALL_MI_LCL_LIST = ${PRIVATE_DATAFILES}

INSTALL_KF_MI_LCL_LIST = ${DATAFILES} ${PRIVATE_DATAFILES} ${PRIVATE_KERNELFILES}

include $(MakeInc_rule)
include $(MakeInc_dir)


