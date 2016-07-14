export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = \
	libkern os
INSTINC_SUBDIRS_X86_64 = libkern os
INSTINC_SUBDIRS_X86_64H = libkern os
INSTINC_SUBDIRS_ARM = libkern os
INSTINC_SUBDIRS_ARM64 = libkern os

EXPINC_SUBDIRS = \
	libkern os
EXPINC_SUBDIRS_X86_64 = libkern os
EXPINC_SUBDIRS_X86_64H = libkern os
EXPINC_SUBDIRS_ARM = libkern os
EXPINC_SUBDIRS_ARM64 = libkern os

COMP_SUBDIRS = conf

include $(MakeInc_rule)
include $(MakeInc_dir)
