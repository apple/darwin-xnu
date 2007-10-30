export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS =

INSTINC_SUBDIRS_PPC = 

INSTINC_SUBDIRS_I386 =

INSTINC_SUBDIRS_ARM =

EXPINC_SUBDIRS =

EXPINC_SUBDIRS_PPC =

EXPINC_SUBDIRS_I386 =

EXPINC_SUBDIRS_ARM =

MIG_TYPES = \
	UNDTypes.defs

MIG_DEFS = \
	UNDRequest.defs \
	UNDReply.defs

DATAFILES = \
	UNDTypes.h \
	${MIG_TYPES} \
	${MIG_DEFS}

INSTALL_MI_LIST =

INSTALL_MI_LCL_LIST	= ${DATAFILES} 

INSTALL_MI_GEN_LIST =

INSTALL_MI_DIR = UserNotification

EXPORT_MI_LIST	= \
	KUNCUserNotifications.h \
	${DATAFILES}

EXPORT_MI_GEN_LIST =

EXPORT_MI_DIR = UserNotification

#
# Build path
#       
INCFLAGS_MAKEFILE= -I..

MIGKSFLAGS	= -DMACH_KERNEL_PRIVATE -DKERNEL_SERVER=1
MIGKUFLAGS	= -DMACH_KERNEL_PRIVATE -DKERNEL_USER=1 -maxonstack 1024

MIG_KUHDRS = \
	UNDRequest.h

MIG_KUSRC = \
	UNDRequest.c

MIG_KSHDRS = \
	UNDReplyServer.h

MIG_KSSRC = \
	UNDReplyServer.c

COMP_FILES = ${MIG_KUSRC} ${MIG_KSSRC} 

${COMP_FILES} : ${MIG_TYPES}
        
${MIG_KUSRC} : \
	%.c : %.defs
	@echo MIG $@
	$(_v)${MIG} ${MIGFLAGS} ${MIGKUFLAGS}        \
		-user    $*.c              \
		-header  $*.h              \
		-server  /dev/null		\
		-sheader /dev/null		\
		$<

${MIG_KSSRC}: \
	%Server.c : %.defs
	@echo MIG $@
	$(_v)${MIG} ${MIGFLAGS} ${MIGKSFLAGS}        \
		-user    /dev/null              \
		-header  /dev/null              \
		-server  $*Server.c		\
		-sheader $*Server.h		\
		$<


include $(MakeInc_rule)
include $(MakeInc_dir)
