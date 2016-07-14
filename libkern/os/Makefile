export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

LCLDIR = /usr/local/include

DATAFILES =

KERNELFILES = \
	${DATAFILES} \
	overflow.h

PRIVATE_KERNELFILES =

PRIVATE_DATAFILES = \
	${PRIVATE_KERNELFILES} \
	overflow.h

INSTALL_MI_LIST	= ${DATAFILES}

INSTALL_MI_DIR = os

INSTALL_MI_LCL_LIST =        \
	${PRIVATE_DATAFILES}

INSTALL_KF_MI_LIST = ${KERNELFILES}

INSTALL_KF_MI_LCL_LIST = ${KERNELFILES} ${PRIVATE_KERNELFILES}

EXPORT_MI_LIST = \
	$(sort ${KERNELFILES} ${PRIVATE_DATAFILES})

EXPORT_MI_GEN_LIST =

EXPORT_MI_DIR = os

include $(MakeInc_rule)
include $(MakeInc_dir)
