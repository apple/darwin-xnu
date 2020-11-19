export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

MIG_DEFS = gssd_mach.defs

PRIVATE_DATAFILES = gssd_mach_types.h ${MIG_DEFS}

INSTALL_MI_LIST =

INSTALL_MI_LCL_LIST = ${PRIVATE_DATAFILES}

INSTALL_MI_GEN_LIST =

INSTALL_MI_DIR = gssd

EXPORT_MI_LIST	= \
	${PRIVATE_DATAFILES}

EXPORT_MI_GEN_LIST = gssd_mach.h

EXPORT_MI_DIR = gssd

#
# Build path
#
INCFLAGS_MAKEFILE= -I..

MIGKUFLAGS	= -DMACH_KERNEL_PRIVATE -DKERNEL_USER=1 -maxonstack 1024

MIG_KUHDRS = gssd_mach.h

MIG_KUSRC = gssd_mach.c gssd_mach.h

COMP_FILES = ${MIG_KUSRC}

do_build_all:: $(COMP_FILES)

${MIG_KUSRC} : gssd_mach.defs
	@$(LOG_MIG) "$@"
	$(_v)${MIG} ${MIGFLAGS} ${MIGKUFLAGS} \
		-user    gssd_mach.c              \
		-header  gssd_mach.h              \
		-server  /dev/null                \
		-sheader /dev/null                \
		$<

include $(MakeInc_rule)
include $(MakeInc_dir)
