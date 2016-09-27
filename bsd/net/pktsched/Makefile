export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES= \

KERNELFILES= \

PRIVATE_DATAFILES = \
	pktsched.h pktsched_cbq.h pktsched_fairq.h pktsched_hfsc.h \
	pktsched_priq.h pktsched_tcq.h pktsched_rmclass.h pktsched_qfq.h \
	pktsched_fq_codel.h

PRIVATE_KERNELFILES = ${KERNELFILES}

INSTALL_MI_LIST	= ${DATAFILES}

INSTALL_MI_DIR = net/pktsched

EXPORT_MI_LIST	= ${INSTALL_MI_LIST} ${KERNELFILES}

EXPORT_MI_DIR = ${INSTALL_MI_DIR}

INSTALL_MI_LCL_LIST = ${PRIVATE_DATAFILES}

INSTALL_KF_MI_LCL_LIST = ${DATAFILES} ${PRIVATE_DATAFILES} ${PRIVATE_KERNELFILES}

include $(MakeInc_rule)
include $(MakeInc_dir)
