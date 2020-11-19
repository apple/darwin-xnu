export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

ifeq ($(PLATFORM),MacOSX)


ARM_HEADER_FILES = \
	machine_cpuid.h		\
	machine_machdep.h	\

# Headers installed into Kernel.framework/Headers (public and internal SDKs).
INSTALL_KF_MD_LIST = $(ARM_HEADER_FILES)

# Headers installed into Kernel.framework/PrivateHeaders (internal SDK only).
INSTALL_KF_MD_LCL_LIST = \
	lowglobals.h \
	machine_kpc.h \
	machine_remote_time.h \
	monotonic.h \
	pgtrace.h \
	proc_reg.h \
	tlb.h \
	$(ARM_HEADER_FILES)

# TODO: Is there a reason that machine_machdep.h is not in this list? If not, these lists can be consolidated.
# Headers used to compile xnu
EXPORT_MD_LIST = \
	lowglobals.h \
	machine_cpuid.h \
	machine_kpc.h \
	machine_remote_time.h \
	monotonic.h \
	pgtrace.h \
	proc_reg.h \
	asm.h \
	tlb.h \
	pal_hibernate.h

# These headers will be available with #include <arm64/header_file.h>
EXPORT_MD_DIR = arm64

else # $(PLATFORM),MacOSX


ARM_HEADER_FILES = \
		lowglobals.h		\
		machine_cpuid.h		\
		machine_machdep.h	\
		proc_reg.h		\
		tlb.h			\

INSTALL_MD_DIR = arm64

INSTALL_MD_LCL_LIST =

INSTALL_MD_LIST =

INSTALL_KF_MD_LIST = $(ARM_HEADER_FILES)

INSTALL_KF_MD_LCL_LIST = machine_kpc.h machine_remote_time.h monotonic.h pgtrace.h $(ARM_HEADER_FILES)

EXPORT_MD_LIST = machine_cpuid.h machine_kpc.h machine_remote_time.h monotonic.h proc_reg.h pgtrace.h asm.h tlb.h pal_hibernate.h

EXPORT_MD_DIR = arm64

endif # $(PLATFORM),MacOSX

include $(MakeInc_rule)
include $(MakeInc_dir)
