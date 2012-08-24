export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS =

INSTINC_SUBDIRS_I386 =

EXPINC_SUBDIRS = ${INSTINC_SUBDIRS}

EXPINC_SUBDIRS_I386 = ${INSTINC_SUBDIRS_I386}

DATAFILES = md5.h sha1.h

PRIVATE_DATAFILES = register_crypto.h sha2.h des.h aes.h aesxts.h

INSTALL_KF_MI_LIST = ${DATAFILES}

INSTALL_KF_MI_LCL_LIST = ${PRIVATE_DATAFILES}

INSTALL_MI_DIR = libkern/crypto

EXPORT_MI_LIST	= ${DATAFILES} ${PRIVATE_DATAFILES} crypto_internal.h

EXPORT_MI_DIR = libkern/crypto

include $(MakeInc_rule)
include $(MakeInc_dir)


