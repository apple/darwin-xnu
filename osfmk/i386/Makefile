export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

EXPORT_ONLY_FILES = 	\
		    apic.h \
		    cpu_number.h \
		    cpu_capabilities.h	\
		    cpuid.h \
		    io_map_entries.h \
		    lock.h \
		    locks.h \
		    machine_routines.h \
		    machine_cpu.h \
		    mtrr.h \
		    mp.h \
		    mp_desc.h \
		    mp_events.h \
		    proc_reg.h \
		    seg.h \
		    simple_lock.h \
		    tss.h

INSTALL_MD_DIR = i386

INSTALL_MD_LCL_LIST = cpu_capabilities.h

EXPORT_MD_LIST = ${EXPORT_ONLY_FILES}

EXPORT_MD_DIR = i386

include $(MakeInc_rule)
include $(MakeInc_dir)


