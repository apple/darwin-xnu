export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES = \
	byte_order.h  endian.h fasttrap_isa.h \
	limits.h param.h  profile.h \
	signal.h  types.h \
	vmparam.h _types.h _limits.h _param.h \
	_mcontext.h

DRIVERKIT_DATAFILES = \
	limits.h types.h _types.h endian.h

PRIVATE_DATAFILES = \
	disklabel.h

KERNELFILES = \
	disklabel.h \
	byte_order.h  endian.h \
	limits.h param.h   profile.h \
	signal.h types.h \
	vmparam.h _types.h _limits.h _param.h \
	_mcontext.h

MODULEMAP_INCDIR_FILES = \
	machine_types.modulemap

INSTALL_MODULEMAP_INCDIR_MI_LIST = ${MODULEMAP_INCDIR_FILES}

INSTALL_MI_LIST = ${DATAFILES}
INSTALL_DRIVERKIT_MI_LIST = ${DRIVERKIT_DATAFILES}
INSTALL_MI_LCL_LIST = ${PRIVATE_DATAFILES}

INSTALL_MI_DIR = machine

EXPORT_MI_LIST = ${KERNELFILES}

EXPORT_MI_DIR = machine

include $(MakeInc_rule)
include $(MakeInc_dir)
