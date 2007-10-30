export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES = \
	 endian.h fasttrap_isa.h param.h profile.h \
	setjmp.h signal.h  \
	types.h vmparam.h _structs.h _types.h _param.h

KERNELFILES = \
	disklabel.h \
	 endian.h param.h profile.h \
	   signal.h  \
	 types.h  vmparam.h _structs.h _types.h _param.h

INSTALL_MD_LIST = ${DATAFILES}
INSTALL_MD_LCL_LIST = ${DATAFILES} disklabel.h

INSTALL_MD_DIR = ppc

EXPORT_MD_LIST = ${KERNELFILES}

EXPORT_MD_DIR = ppc

include $(MakeInc_rule)
include $(MakeInc_dir)


