export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

VPATH+=$(SOURCE)/../../ppc:

DATAFILES = \
	boolean.h exception.h kern_return.h ndr_def.h \
	processor_info.h rpc.h thread_state.h thread_status.h \
	vm_param.h vm_types.h machine_types.defs \
	syscall_sw.h 

INSTALL_MD_LIST = ${DATAFILES}

INSTALL_MD_GEN_LIST = \
	asm.h

INSTALL_MD_DIR = mach/ppc

EXPORT_MD_LIST = ${DATAFILES}

EXPORT_MD_GEN_LIST = \
	asm.h

EXPORT_MD_DIR = mach/ppc

include $(MakeInc_rule)
include $(MakeInc_dir)


