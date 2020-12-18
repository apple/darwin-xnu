export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

ifeq ($(PLATFORM),MacOSX)

PRIVATE_DATAFILES = boot.h

PRIVATE_KERNELFILES = \
	AIC.h \
	apple_arm64_common.h \
	apple_arm64_regs.h \
	board_config.h \
	boot.h \
	S3c2410x.h \
	H7.h \
	H8.h \
	H9.h \
	H11.h \
	H13.h \
	BCM2837.h \
	spr_locks.h


# Headers installed into System.framework/PrivateHeaders (userspace internal SDK only).
INSTALL_MD_LCL_LIST = ${PRIVATE_DATAFILES}

# The userspace headers can be located in System.framework/PrivateHeaders/pexpert/arm64
INSTALL_MD_DIR = pexpert/arm64

# Ensure these files don't get auto-included into the public Kernel.framework/Headers.
INSTALL_KF_MD_LIST = ${EMPTY}

# Headers installed into Kernel.framework/PrivateHeaders (internal SDK only).
INSTALL_KF_MD_LCL_LIST = ${PRIVATE_KERNELFILES}

# Headers used to compile xnu
EXPORT_MD_LIST = ${PRIVATE_KERNELFILES}

# These headers will be available with #include <pexpert/arm64/header_file.h>
EXPORT_MD_DIR = pexpert/arm64

else # $(PLATFORM),MacOSX

DATAFILES = \
	AIC.h \
	apple_arm64_common.h \
	apple_arm64_regs.h \
	board_config.h \
	boot.h \
	S3c2410x.h \
	H7.h \
	H8.h \
	H9.h \
	H11.h \
	H13.h \
	BCM2837.h \
	spr_locks.h


INSTALL_MD_LIST	= ${DATAFILES}

INSTALL_MD_DIR = pexpert/arm64

EXPORT_MD_LIST	= ${DATAFILES}

EXPORT_MD_DIR = pexpert/arm64

endif # $(PLATFORM),MacOSX

include $(MakeInc_rule)
include $(MakeInc_dir)
