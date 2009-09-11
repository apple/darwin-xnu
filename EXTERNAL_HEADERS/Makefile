export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS =	\
	architecture	\
	mach-o

INSTINC_SUBDIRS_PPC = 	\
	architecture

INSTINC_SUBDIRS_I386 =	\
	architecture

INSTINC_SUBDIRS_X86_64 =	\
	architecture

INSTINC_SUBDIRS_ARM =	\
	architecture

EXPORT_FILES = \
	AppleSecureBootEpoch.h \
	ar.h		\
	stdarg.h	\
	stdbool.h	\
	stdint.h

INSTALL_MI_LIST = 

INSTALL_MI_DIR = .

EXPORT_MI_LIST = ${EXPORT_FILES}

EXPORT_MI_DIR = .

include $(MakeInc_rule)
include $(MakeInc_dir)
