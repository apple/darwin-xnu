export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES =

EXPORT_ONLY_FILES = \
	vm_map.h \
	vm_kern.h \
	pmap.h

INSTALL_MI_LIST = ${DATAFILES}

INSTALL_MI_DIR = vm

EXPORT_MI_LIST = ${DATAFILES} ${EXPORT_ONLY_FILES}

EXPORT_MI_DIR = vm

include $(MakeInc_rule)
include $(MakeInc_dir)


