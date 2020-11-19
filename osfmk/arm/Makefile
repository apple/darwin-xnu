export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

ifeq ($(PLATFORM),MacOSX)

ARM_HEADER_FILES =	\
		arch.h \
		atomic.h \
		cpu_number.h \
		cpu_capabilities.h	\
		cpu_x86_64_capabilities.h	\
		cpuid.h \
		cpuid_internal.h \
		io_map_entries.h \
		lock.h \
		locks.h \
		machine_cpuid.h \
		machine_routines.h \
		memory_types.h \
		pal_routines.h \
		simple_lock.h \
		thread.h \
		trap.h

INSTALL_MD_DIR = arm

# Headers installed into System.framework/PrivateHeaders (internal SDK only).
INSTALL_MD_LCL_LIST = arch.h cpu_capabilities.h

# Headers installed into /usr/include (public and internal SDKs).
INSTALL_MD_LIST = arch.h

# Headers installed in the public/internal SDKs for userspace DriverKit drivers.
INSTALL_DRIVERKIT_MD_LIST = arch.h

# Headers installed into Kernel.framework/Headers (public and internal SDKs).
INSTALL_KF_MD_LIST = $(ARM_HEADER_FILES)

# Headers installed into Kernel.framework/PrivateHeaders (internal SDK only).
INSTALL_KF_MD_LCL_LIST = \
		dbgwrap.h \
		machine_kpc.h \
		monotonic.h \
		pmap_public.h \
		proc_reg.h \
		smp.h \
		$(ARM_HEADER_FILES)

# TODO: consolidate INSTALL_KF_MD_LCL_LIST and EXPORT_MD_LIST? Only difference is caches_internal.h/machine_cpu.h
# Headers used to compile xnu
EXPORT_MD_LIST = \
		caches_internal.h \
		dbgwrap.h \
		machine_cpu.h \
		machine_kpc.h \
		monotonic.h \
		pmap_public.h \
		proc_reg.h \
		smp.h \
		${ARM_HEADER_FILES}

# These headers will be available with #include <arm/header_file.h>
EXPORT_MD_DIR = arm

else # $(PLATFORM),MacOSX

ARM_HEADER_FILES =	\
		arch.h \
		atomic.h \
		cpu_number.h \
		cpu_capabilities.h	\
		cpu_x86_64_capabilities.h	\
		cpuid.h \
		cpuid_internal.h \
		dbgwrap.h \
		io_map_entries.h \
		lock.h \
		locks.h \
		machine_cpu.h \
		machine_cpuid.h \
		machine_routines.h \
		memory_types.h \
		pal_routines.h \
		pmap_public.h \
		proc_reg.h \
		simple_lock.h \
		smp.h \
		thread.h \
		trap.h

INSTALL_MD_DIR = arm

INSTALL_MD_LCL_LIST = arch.h cpu_capabilities.h

INSTALL_MD_LIST = arch.h

INSTALL_DRIVERKIT_MD_LIST = arch.h

INSTALL_KF_MD_LIST = $(ARM_HEADER_FILES)

INSTALL_KF_MD_LCL_LIST = machine_kpc.h monotonic.h $(ARM_HEADER_FILES)

EXPORT_MD_LIST =	\
		caches_internal.h \
		machine_kpc.h \
		monotonic.h \
		${ARM_HEADER_FILES}

EXPORT_MD_DIR = arm

endif # $(PLATFORM),MacOSX

include $(MakeInc_rule)
include $(MakeInc_dir)
