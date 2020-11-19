export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

EXPINC_SUBDIRS = random

INSTTEXTFILES_SUBDIRS = dtrace

INSTTEXTFILES_SUBDIRS_X86_64 = dtrace
INSTTEXTFILES_SUBDIRS_X86_64H = dtrace
INSTTEXTFILES_SUBDIRS_ARM = dtrace
INSTTEXTFILES_SUBDIRS_ARM64 = dtrace

include $(MakeInc_rule)
include $(MakeInc_dir)
