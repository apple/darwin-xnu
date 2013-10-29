export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES = \
	audit_ioctl.h

INSTALL_MI_LIST	= ${DATAFILES}

INSTALL_MI_DIR = security/audit

INSTALL_KF_MI_LIST = ${DATAFILES}

EXPORT_MI_LIST	= ${DATAFILES} audit.h audit_bsd.h audit_private.h 

EXPORT_MI_DIR =	security/audit

include $(MakeInc_rule)
include $(MakeInc_dir)


