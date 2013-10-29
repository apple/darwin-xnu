export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES = \
	 hfs_encodings.h hfs_format.h hfs_mount.h hfs_unistr.h 

PRIVATE_DATAFILES = \
	hfs.h hfs_attrlist.h hfs_catalog.h hfs_cnode.h hfs_endian.h \
	hfs_fsctl.h hfs_macos_defs.h hfs_quota.h rangelist.h

INSTALL_MI_LIST	= ${DATAFILES}

INSTALL_MI_DIR = hfs

EXPORT_MI_LIST	= ${DATAFILES}

EXPORT_MI_DIR = hfs

INSTALL_MI_LCL_LIST = ${DATAFILES} ${PRIVATE_DATAFILES}

include $(MakeInc_rule)
include $(MakeInc_dir)


