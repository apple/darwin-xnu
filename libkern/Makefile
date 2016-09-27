export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = \
	libkern os firehose
INSTINC_SUBDIRS_X86_64 = libkern
INSTINC_SUBDIRS_X86_64H = libkern
INSTINC_SUBDIRS_ARM = libkern
INSTINC_SUBDIRS_ARM64 = libkern

EXPINC_SUBDIRS = \
	libkern os firehose
EXPINC_SUBDIRS_X86_64 = libkern
EXPINC_SUBDIRS_X86_64H = libkern
EXPINC_SUBDIRS_ARM = libkern
EXPINC_SUBDIRS_ARM64 = libkern

COMP_SUBDIRS = conf

include $(MakeInc_rule)
include $(MakeInc_dir)
