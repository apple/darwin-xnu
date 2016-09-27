export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)


EXPORT_ONLY_FILES = machine_kpc.h
EXPORT_MD_LIST = ${EXPORT_ONLY_FILES}
EXPORT_MD_DIR = x86_64

include $(MakeInc_rule)
include $(MakeInc_dir)
