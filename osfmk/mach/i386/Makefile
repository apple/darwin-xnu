export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

VPATH := $(VPATH):$(SOURCE)/../../i386

DATAFILES = \
	boolean.h exception.h fp_reg.h \
	processor_info.h kern_return.h ndr_def.h syscall_sw.h \
	thread_status.h thread_state.h vm_param.h \
	vm_types.h rpc.h \
	_structs.h sdt_isa.h

PRIVATE_DATAFILES = \
	syscall_sw.h

INSTALL_MD_LIST = ${DATAFILES}

INSTALL_MD_LCL_LIST = ${PRIVATE_DATAFILES}

INSTALL_MD_GEN_LIST = \
	asm.h 

INSTALL_MD_DIR = mach/i386

EXPORT_MD_LIST = ${DATAFILES} 

EXPORT_MD_GEN_LIST = \
	asm.h

EXPORT_MD_DIR = mach/i386

include $(MakeInc_rule)
include $(MakeInc_dir)


