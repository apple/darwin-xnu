export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES = \
		kdp_callout.h \
		kdp_en_debugger.h

PRIVATE_KERNELFILES = processor_core.h

EXPORT_MI_LIST	= ${DATAFILES} kdp_dyld.h

INSTALL_KF_MI_LIST = ${DATAFILES}

INSTALL_KF_MI_LCL_LIST = ${DATAFILES} ${PRIVATE_KERNELFILES}

EXPORT_MI_DIR = kdp

include $(MakeInc_rule)
include $(MakeInc_dir)
