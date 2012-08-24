export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = \

INSTINC_SUBDIRS_PPC = \

INSTINC_SUBDIRS_I386 = \

EXPINC_SUBDIRS = \

EXPINC_SUBDIRS_PPC = \

EXPINC_SUBDIRS_I386 = \

DATAFILES= \

KERNELFILES= \

PRIVATE_DATAFILES = \
	altq.h altq_cbq.h altq_fairq.h altq_hfsc.h altq_priq.h altq_qfq.h

PRIVATE_KERNELFILES = ${KERNELFILES}

INSTALL_MI_LIST	= ${DATAFILES}

INSTALL_MI_DIR = net/altq

EXPORT_MI_LIST	= ${INSTALL_MI_LIST} ${KERNELFILES}

EXPORT_MI_DIR = ${INSTALL_MI_DIR}

INSTALL_MI_LCL_LIST = ${DATAFILES} ${PRIVATE_DATAFILES}

INSTALL_KF_MI_LCL_LIST = ${INSTALL_MI_LCL_LIST} ${PRIVATE_KERNELFILES}

include $(MakeInc_rule)
include $(MakeInc_dir)
