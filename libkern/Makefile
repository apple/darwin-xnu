export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


export COMP_LDFLAGS_COMPONENT_PPC = -i_OSCompareAndSwap:_hw_compare_and_store

include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = libkern
INSTINC_SUBDIRS_PPC = ${INSTINC_SUBDIRS}
INSTINC_SUBDIRS_I386 = ${INSTINC_SUBDIRS}

EXPINC_SUBDIRS = libkern
EXPINC_SUBDIRS_PPC = ${EXPINC_SUBDIRS}
EXPINC_SUBDIRS_I386 = ${EXPINC_SUBDIRS}

SETUP_SUBDIRS = conf

COMP_SUBDIRS = conf

INST_SUBDIRS = kmod

include $(MakeInc_rule)
include $(MakeInc_dir)
