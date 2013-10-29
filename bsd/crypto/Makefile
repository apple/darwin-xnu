export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = \
	blowfish \
	cast128 \
	rc4 \

PRIVATE_DATAFILES = \
	sha1.h \
	sha2.h \
	des.h \
	aes.h aesxts.h \

INSTALL_MI_DIR = crypto

EXPORT_MI_DIR = ${INSTALL_MI_DIR}

INSTALL_KF_MI_LCL_LIST = ${PRIVATE_DATAFILES}

# We use this to install aesxts.h in Kernel.framework/PrivateHeaders 
# in addition to Kernel.framework/PrivateHeaders/crypto
# This should be removed once all clients are switched to include libkern/crypto/aesxts.h
INSTALL_KF_MD_LCL_LIST = aesxts.h

include $(MakeInc_rule)
include $(MakeInc_dir)


