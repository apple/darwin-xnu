export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)


DATAFILES = \
	asm.h machlimits.h 

EXPORT_ONLY_FILES = 		\
	asm.h 			\
	cpu_number.h		\
	lock.h			\
	hw_lock_types.h		\
	io_map_entries.h	\
	proc_reg.h		\
	machine_routines.h		\
	Diagnostics.h		\
	savearea.h		\
	mappings.h

INSTALL_MD_LIST = ${DATAFILES}

INSTALL_MD_DIR = ppc

EXPORT_MD_LIST = ${EXPORT_ONLY_FILES}

EXPORT_MD_DIR = ppc

include $(MakeInc_rule)
include $(MakeInc_dir)


