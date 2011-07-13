export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

EXPORT_ONLY_FILES = 	\
		    apic.h \
		    asm.h \
		    cpu_number.h \
		    cpu_capabilities.h	\
		    cpu_data.h \
		    cpu_topology.h \
		    cpuid.h \
		    eflags.h \
		    io_map_entries.h \
		    lapic.h \
		    lock.h \
		    locks.h \
		    machine_routines.h \
		    machine_cpu.h \
		    mtrr.h \
		    mp.h \
		    mp_desc.h \
		    mp_events.h \
		    pal_native.h \
		    pal_routines.h \
		    pal_hibernate.h \
		    pmCPU.h \
		    pmap.h \
		    proc_reg.h \
		    rtclock_protos.h \
		    seg.h \
		    simple_lock.h \
		    tsc.h \
		    tss.h \
		    ucode.h \
		    vmx.h

INSTALL_MD_DIR = i386

INSTALL_MD_LIST = eflags.h user_ldt.h

INSTALL_MD_LCL_LIST = cpu_capabilities.h

INSTALL_KF_MD_LIST = asm.h cpuid.h eflags.h locks.h machine_routines.h proc_reg.h vmx.h

INSTALL_KF_MD_LCL_LIST = $(filter-out cpu_data.h pal_i386.h, $(EXPORT_ONLY_FILES))

EXPORT_MD_LIST = ${EXPORT_ONLY_FILES}

EXPORT_MD_DIR = i386

include $(MakeInc_rule)
include $(MakeInc_dir)


