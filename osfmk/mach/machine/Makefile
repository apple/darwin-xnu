export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)


DATAFILES = \
	asm.h boolean.h exception.h kern_return.h ndr_def.h rpc.h \
	processor_info.h thread_state.h thread_status.h \
	vm_param.h vm_types.h machine_types.defs \
	syscall_sw.h

INSTALL_MI_LIST = ${DATAFILES}

INSTALL_MI_DIR = mach/machine

EXPORT_MI_LIST = ${DATAFILES}

EXPORT_MI_DIR = mach/machine

include $(MakeInc_rule)
include $(MakeInc_dir)


