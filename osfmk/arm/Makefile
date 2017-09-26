export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

ARM_HEADER_FILES =	\
		arch.h \
		atomic.h \
		cpu_number.h \
		cpu_capabilities.h	\
		cpuid.h \
		cpuid_internal.h \
		dbgwrap.h \
		io_map_entries.h \
		lock.h \
		locks.h \
		machine_cpu.h \
		machine_cpuid.h \
		machine_routines.h \
		pal_routines.h \
		proc_reg.h \
		smp.h \
		thread.h \
		simple_lock.h


INSTALL_MD_DIR = arm

INSTALL_MD_LCL_LIST = arch.h cpu_capabilities.h

INSTALL_MD_LIST = arch.h

INSTALL_KF_MD_LIST = $(ARM_HEADER_FILES)

INSTALL_KF_MD_LCL_LIST = machine_kpc.h monotonic.h $(ARM_HEADER_FILES)

EXPORT_MD_LIST =	\
		caches_internal.h \
		machine_kpc.h \
		monotonic.h \
		${ARM_HEADER_FILES}

EXPORT_MD_DIR = arm

include $(MakeInc_rule)
include $(MakeInc_dir)
