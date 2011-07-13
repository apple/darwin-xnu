export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = \
	blowfish \
	cast128 \
	des	\
    rc4 \
	aes \
	sha2


INSTINC_SUBDIRS_I386 = \
	aes

INSTINC_SUBDIRS_X86_64 = \
	aes

INSTINC_SUBDIRS_ARM = \

EXPINC_SUBDIRS = ${INSTINC_SUBDIRS}

EXPINC_SUBDIRS_I386 = \

EXPINC_SUBDIRS_X86_64 = \

EXPINC_SUBDIRS_ARM = \

PRIVATE_DATAFILES = \
	sha1.h

INSTALL_MI_DIR = crypto

EXPORT_MI_DIR = ${INSTALL_MI_DIR}

INSTALL_KF_MI_LCL_LIST = ${PRIVATE_DATAFILES}

include $(MakeInc_rule)
include $(MakeInc_dir)


