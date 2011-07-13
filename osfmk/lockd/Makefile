export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS =

INSTINC_SUBDIRS_I386 =

EXPINC_SUBDIRS =

EXPINC_SUBDIRS_I386 =

MIG_DEFS = lockd_mach.defs

DATAFILES = lockd_mach_types.h ${MIG_DEFS}

INSTALL_MI_LIST =

INSTALL_MI_LCL_LIST	= ${DATAFILES} 

INSTALL_MI_GEN_LIST = 

INSTALL_MI_DIR = lockd

EXPORT_MI_LIST	= \
	${DATAFILES}

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

${COMP_FILES} : lockd_mach.defs

${MIG_KUSRC} : lockd_mach.defs
	@echo MIG $@
	$(_v)${MIG} ${MIGFLAGS} ${MIGKUFLAGS}	\
		-user    $*.c			\
		-header  $*.h			\
		-server  /dev/null		\
		-sheader /dev/null		\
		$<

include $(MakeInc_rule)
include $(MakeInc_dir)
