export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

ARM_HEADER_FILES = \
		lowglobals.h		\
		machine_cpuid.h		\
		machine_machdep.h	\
		proc_reg.h

INSTALL_MD_DIR = arm64

INSTALL_MD_LCL_LIST =

INSTALL_MD_LIST =

INSTALL_KF_MD_LIST = $(ARM_HEADER_FILES)

INSTALL_KF_MD_LCL_LIST = machine_kpc.h monotonic.h pgtrace.h $(ARM_HEADER_FILES)

EXPORT_MD_LIST = machine_cpuid.h machine_kpc.h monotonic.h proc_reg.h pgtrace.h


EXPORT_MD_DIR = arm64

include $(MakeInc_rule)
include $(MakeInc_dir)
