export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)


EXPORT_ONLY_FILES = 		\
	asm.h 			\
	cpu_number.h		\
	cpu_capabilities.h	\
	Diagnostics.h		\
	io_map_entries.h	\
	lock.h			\
	locks.h			\
	pms.h			\
	proc_reg.h		\
	machine_routines.h	\
	mappings.h		\
	savearea.h		\
	simple_lock.h

INSTALL_MD_DIR = ppc

INSTALL_MD_LCL_LIST = cpu_capabilities.h

EXPORT_MD_LIST = ${EXPORT_ONLY_FILES}

EXPORT_MD_DIR = ppc

include $(MakeInc_rule)
include $(MakeInc_dir)


