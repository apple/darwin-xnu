export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = \
	machine

INSTINC_SUBDIRS_PPC = \
	ppc

INSTINC_SUBDIRS_I386 = \
	i386

INSTINC_SUBDIRS_ARM = \
	arm

EXPINC_SUBDIRS = \
	machine

EXPINC_SUBDIRS_PPC = \
	ppc

EXPINC_SUBDIRS_I386 = \
	i386

EXPINC_SUBDIRS_ARM = \
	arm

MIG_DEFS =	\

MIG_HDRS = \

DATAFILES = \
	profile-internal.h profile-mk.h profile-kgmon.c \
	${MIG_DEFS}

MIGINCLUDES = \

INSTALL_MI_LIST	= ${DATAFILES} ${_MIG_HDRS_} ${MIGINCLUDES}

INSTALL_MI_DIR = profile

EXPORT_MI_LIST	= ${DATAFILES} ${_MIG_HDRS_} ${MIGINCLUDES}

EXPORT_MI_DIR = profile

.ORDER: ${_MIG_HDRS_} ${MIGINCLUDES}

include $(MakeInc_rule)
include $(MakeInc_dir)


