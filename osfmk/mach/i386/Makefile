export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

VPATH+=$(SOURCE)/../../i386:

MIG_DEFS = mach_i386.defs

MIGINCLUDES = mach_i386_server.h

DATAFILES = \
	boolean.h exception.h fp_reg.h flipc_dep.h \
	processor_info.h kern_return.h mach_i386_types.h ndr_def.h syscall_sw.h \
	thread_status.h thread_state.h vm_param.h \
	vm_types.h rpc.h \
	machine_types.defs ${MIG_DEFS} 

INSTALL_MD_LIST = ${DATAFILES}

INSTALL_MD_GEN_LIST = \
	asm.h \
	${MIGINCLUDES}

INSTALL_MD_DIR = mach/i386

EXPORT_MD_LIST = ${DATAFILES} 

EXPORT_MD_GEN_LIST = \
	asm.h \
	${MIGINCLUDES}

EXPORT_MD_DIR = mach/i386

.ORDER: ${MIG_HDRS} ${MIGINCLUDES}

COMP_FILES = mach_i386_server.h mach_i386_server.c

.ORDER: mach_i386_server.h mach_i386_server.c

MIGKSFLAGS = -DKERNEL_SERVER

mach_i386_server.h mach_i386_server.c: mach_i386.defs
	${MIG} ${MIGFLAGS} ${MIGKSFLAGS}	\
		-header /dev/null		\
		-user /dev/null			\
		-sheader mach_i386_server.h	\
		-server mach_i386_server.c	\
		$<

include $(MakeInc_rule)
include $(MakeInc_dir)


