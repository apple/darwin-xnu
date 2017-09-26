export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES = \
	vfs_support.h

INSTALL_MI_LIST	= ${DATAFILES}

INSTALL_MI_DIR = vfs

INSTALL_KF_MI_LIST = ${DATAFILES}

EXPORT_MI_LIST	= ${DATAFILES} vfs_disk_conditioner.h

EXPORT_MI_DIR = vfs

include $(MakeInc_rule)
include $(MakeInc_dir)
