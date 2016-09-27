export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = \
	machine
INSTINC_SUBDIRS_X86_64 = \
	i386
INSTINC_SUBDIRS_X86_64H = \
	i386
INSTINC_SUBDIRS_ARM = \
	arm	\
	arm64
INSTINC_SUBDIRS_ARM64 = \
	arm	\
	arm64

EXPINC_SUBDIRS = ${INSTINC_SUBDIRS}
EXPINC_SUBDIRS_X86_64 = ${INSTINC_SUBDIRS_X86_64}
EXPINC_SUBDIRS_X86_64H = ${INSTINC_SUBDIRS_X86_64H}
EXPINC_SUBDIRS_ARM = ${INSTINC_SUBDIRS_ARM}
EXPINC_SUBDIRS_ARM64 = ${INSTINC_SUBDIRS_ARM64}

DATAFILES = \
        boot.h \
	protos.h \
	pexpert.h

PRIVATE_DATAFILES = \
	pexpert.h

INSTALL_MI_LIST	= ${DATAFILES}

INSTALL_MI_LCL_LIST = ${PRIVATE_DATAFILES}

INSTALL_MI_DIR = pexpert

EXPORT_MI_LIST	= ${DATAFILES} \
		    device_tree.h

EXPORT_MI_DIR = pexpert

include $(MakeInc_rule)
include $(MakeInc_dir)
