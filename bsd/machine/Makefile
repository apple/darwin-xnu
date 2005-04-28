export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)


DATAFILES = \
	byte_order.h  endian.h \
	param.h  profile.h \
	setjmp.h signal.h  types.h\
	ucontext.h vmparam.h _types.h _limits.h
KERNELFILES = \
	byte_order.h  endian.h \
	param.h   profile.h \
	signal.h spl.h types.h \
	 vmparam.h _types.h _limits.h


INSTALL_MI_LIST = ${DATAFILES}
INSTALL_MI_LCL_LIST = ${DATAFILES} disklabel.h

INSTALL_MI_DIR = machine

EXPORT_MI_LIST = ${KERNELFILES}

EXPORT_MI_DIR = machine

include $(MakeInc_rule)
include $(MakeInc_dir)


