export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

PRIVATE_DATAFILES = \
	cpu_capabilities.h

KERNELFILES = \
	atomic_impl.h	\
	atomic.h	\
	config.h		\
	cpu_capabilities.h	\
	cpu_number.h	\
	io_map_entries.h \
	lock.h	\
	locks.h	\
	machine_cpuid.h		\
	machine_remote_time.h \
	machine_routines.h	\
	machine_kpc.h		\
	memory_types.h		\
	monotonic.h \
	pal_routines.h		\
	pal_hibernate.h		\
	simple_lock.h		\
	smp.h

EXPORT_FILES = \
	machine_remote_time.h

INSTALL_MI_LCL_LIST = ${PRIVATE_DATAFILES}

INSTALL_KF_MD_LCL_LIST = ${EXPORT_FILES}

INSTALL_MI_DIR = machine

EXPORT_MI_LIST = ${KERNELFILES}

EXPORT_MI_DIR = machine

include $(MakeInc_rule)
include $(MakeInc_dir)
