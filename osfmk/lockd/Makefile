export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

MIG_DEFS = lockd_mach.defs

DATAFILES = lockd_mach_types.h ${MIG_DEFS}

PRIVATE_DATAFILES = lockd_mach_types.h ${MIG_DEFS}
KERNELFILES = ${PRIVATE_DATAFILES}

INSTALL_MI_LIST =
INSTALL_MI_LCL_LIST = ${PRIVATE_DATAFILES}

INSTALL_MI_GEN_LIST =

INSTALL_MI_DIR = lockd

EXPORT_MI_LIST = ${KERNELFILES}

EXPORT_MI_GEN_LIST = lockd_mach.h

EXPORT_MI_DIR = lockd

#
# Build path
#
INCFLAGS_MAKEFILE= -I..

MIGKUFLAGS	= -DMACH_KERNEL_PRIVATE -DKERNEL_USER=1 -maxonstack 1024

MIG_KUHDRS = lockd_mach.h

MIG_KUSRC = lockd_mach.c lockd_mach.h

COMP_FILES = ${MIG_KUSRC}

do_build_all:: $(COMP_FILES)

${MIG_KUSRC} : lockd_mach.defs
	@$(LOG_MIG) $@
	$(_v)${MIG} ${MIGFLAGS} ${MIGKUFLAGS}	\
		-user    lockd_mach.c		\
		-header  lockd_mach.h		\
		-server  /dev/null		\
		-sheader /dev/null		\
		$<

include $(MakeInc_rule)
include $(MakeInc_dir)
