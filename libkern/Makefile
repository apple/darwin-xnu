export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = \
	libkern
INSTINC_SUBDIRS_X86_64 = libkern
INSTINC_SUBDIRS_ARM = libkern

EXPINC_SUBDIRS = \
	libkern
EXPINC_SUBDIRS_X86_64 = libkern
EXPINC_SUBDIRS_ARM = libkern

COMP_SUBDIRS = conf

include $(MakeInc_rule)
include $(MakeInc_dir)
