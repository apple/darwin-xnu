export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES = \
	asm.h eflags.h exec.h machlimits.h \
	endian.h trap.h soundcard.h

EXPORT_ONLY_FILES = cpu_number.h \
		    hw_lock_types.h \
		    io_map_entries.h \
		    lock.h \
		    machine_routines.h

INSTALL_MD_LIST = ${DATAFILES}

INSTALL_MD_DIR = i386

EXPORT_MD_LIST = ${EXPORT_ONLY_FILES}

EXPORT_MD_DIR = i386

include $(MakeInc_rule)
include $(MakeInc_dir)


