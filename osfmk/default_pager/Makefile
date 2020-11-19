export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

MIG_TYPES = \
	default_pager_types.defs

MIG_DEFS = \

MIG_USHDRS = \

MIG_UUHDRS = \

MIGINCLUDES = ${MIG_UUHDRS} ${MIG_USHDRS}

DATAFILES = \
	default_pager_types.h \
	${MIG_DEFS}

INSTALL_MI_LIST	= ${DATAFILES}

INSTALL_MI_GEN_LIST = ${MIGINCLUDES}

INSTALL_MI_DIR = default_pager

EXPORT_MI_LIST	= \
	${DATAFILES}

EXPORT_MI_GEN_LIST = \
	${MIGINCLUDES}

EXPORT_MI_DIR = default_pager

${MIGINCLUDES} : ${MIG_TYPES}

${MIG_UUHDRS} : \
	%.h : %.defs
	@$(LOG_MIG) $@
	$(_v)$(MIG) $(MIGFLAGS)		\
		-server /dev/null	\
		-user /dev/null		\
		-header $@		\
		$<

${MIG_USHDRS} : \
	%_server.h : %.defs
	@$(LOG_MIG) $@
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

MIGKSFLAGS	= -DMACH_KERNEL_PRIVATE -DKERNEL_SERVER=1
MIGKUFLAGS	= -DMACH_KERNEL_PRIVATE -DKERNEL_USER=1 -maxonstack 1024

#
# MIG-generated headers that are traditionally used by kernel
# level code.
#
MIG_KUHDRS = \

MIG_KUSRC = \

MIG_KSHDRS = \

MIG_KSSRC = \

#
# JMM -
# Since there are two generated header files with the same name, one for
# install and export, the other for internal use (and they are different)
# we can't explicitly list two rules for the same target.  So rules for
# generating internal headers will be handled implicitly by creating rules
# to generate the internal C sources, and the headers get created as a
# side-effect.
#
# This is all temporary scaffolding, as we are moving to a model where
# the MIG-generated code is identical in all environments.  At first, it
# will contain some environment-specific ifdefs, but over time should not
# even require that as we move towards making all the environments look
# the same.
#
COMP_FILES = ${MIG_KUSRC} ${MIG_KSSRC}

do_build_all:: $(COMP_FILES)

${COMP_FILES} : ${MIG_TYPES}

${MIG_KUSRC} : \
	%_user.c : %.defs
	@$(LOG_MIG) $@
	$(_v)${MIG} ${MIGFLAGS} ${MIGKUFLAGS}        \
		-user    $*_user.c              \
		-header  $*.h              \
		-server  /dev/null		\
		-sheader /dev/null		\
		$<

${MIG_KSSRC}: \
	%_server.c : %.defs
	@$(LOG_MIG) $@
	$(_v)${MIG} ${MIGFLAGS} ${MIGKSFLAGS}        \
		-user    /dev/null              \
		-header  /dev/null              \
		-server  $*_server.c		\
		-sheader $*_server.h		\
		$<

include $(MakeInc_rule)
include $(MakeInc_dir)
