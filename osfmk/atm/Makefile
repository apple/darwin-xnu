export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

MIG_TYPES = \
	atm_types.defs

MIG_DEFS = \
	atm_notification.defs

MACH_PRIVATE_DEFS =

#
# MIG-generated headers that are traditionally used by user
# level code.
#
MIG_USHDRS =

MIG_UUHDRS =

MIGINCLUDES = ${MIG_UUHDRS} ${MIG_USHDRS}

DATAFILES = \
	atm_types.h \
	${MIG_TYPES} \
	${MIG_DEFS}

INSTALL_MI_LIST	= \
	${DATAFILES}

INSTALL_KF_MI_LIST = \
	${DATAFILES}

INSTALL_KF_MI_LCL_LIST = \
	${DATAFILES}

INSTALL_MI_GEN_LIST =

INSTALL_MI_DIR = atm

EXPORT_MI_LIST	= \
	${DATAFILES} atm_internal.h

EXPORT_MI_GEN_LIST = \
	${MIGINCLUDES}

EXPORT_MI_DIR = atm

${MIGINCLUDES} : ${MIG_TYPES}

${MIG_UUHDRS} : \
	%.h : %.defs
	@echo "$(ColorM)MIG$(Color0) $(ColorF)$@$(Color0)"
	$(_v)$(MIG) $(MIGFLAGS)		\
		-server /dev/null	\
		-user /dev/null		\
		-header $@		\
		$<

${MIG_USHDRS} : \
	%_server.h : %.defs
	@echo "$(ColorM)MIG$(Color0) $(ColorF)$@$(Color0)"
	$(_v)$(MIG) $(MIGFLAGS)		\
		-server /dev/null	\
		-user /dev/null		\
		-header /dev/null	\
		-sheader $@		\
		$<

#
# Build path
#

INCFLAGS_MAKEFILE= -I..

MIGKSFLAGS      = -DMACH_KERNEL_PRIVATE -DKERNEL_SERVER=1
MIGKUFLAGS      = -DMACH_KERNEL_PRIVATE -DKERNEL_USER=1 -maxonstack 1024
#
# MIG-generated headers that are traditionally used by kernel
# level code.
#
MIG_KUHDRS = \
	atm_notification.h

MIG_KUSRC = \
	atm_notification_user.c

MIG_KSHDRS =

MIG_KSSRC =

COMP_FILES = ${MIG_KUSRC} ${MIG_KSSRC}

do_build_all:: $(COMP_FILES)

${COMP_FILES} : ${MIG_TYPES}

${MIG_KUSRC} : \
	%_user.c : %.defs
	@echo "$(ColorM)MIG$(Color0) $(ColorF)$@$(Color0)"
	$(_v)${MIG} ${MIGFLAGS} ${MIGKUFLAGS}        \
		-user    $*_user.c              \
		-header  $*.h              \
		-server  /dev/null		\
		-sheader /dev/null		\
		$<

${MIG_KSSRC}: \
	%_server.c : %.defs
	@echo "$(ColorM)MIG$(Color0) $(ColorF)$@$(Color0)"
	$(_v)${MIG} ${MIGFLAGS} ${MIGKSFLAGS}        \
		-user    /dev/null              \
		-header  /dev/null              \
		-server  $*_server.c		\
		-sheader $*_server.h		\
		$<

include $(MakeInc_rule)
include $(MakeInc_dir)
