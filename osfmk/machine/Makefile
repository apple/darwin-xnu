export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)


DATAFILES = \
	machlimits.h 	\
	ast.h	\
	ast_types.h	\
	commpage.h	\
	cpu_capabilities.h	\
	cpu_number.h	\
	db_machdep.h	\
	endian.h	\
	gdb_defs.h	\
	iobus.h	\
	io_map_entries.h \
	kgdb_defs.h	\
	kgdb_setjmp.h	\
	lock.h	\
	mach_param.h	\
	machine_routines.h	\
	machine_rpc.h	\
	machparam.h	\
	pmap.h	\
	setjmp.h	\
	spl.h	\
	task.h	\
	thread.h	\
	thread_act.h	\
	trap.h	\
	vm_tuning.h	\
	xpr.h		\
	hw_lock_types.h

INSTALL_MI_LCL_LIST = cpu_capabilities.h

INSTALL_MI_DIR = machine

EXPORT_MI_LIST = ${DATAFILES}

EXPORT_MI_DIR = machine

include $(MakeInc_rule)
include $(MakeInc_dir)


