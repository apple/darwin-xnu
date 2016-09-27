export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

MIG_DEFS =	\
	device.defs

MIG_HDRS = \

DATAFILES = \
	device_types.h device_port.h device_types.defs \
	${MIG_DEFS}

PRIVATE_DATAFILES = \
	device_types.h

MIGINCLUDES = \

INSTALL_MI_LIST	= ${DATAFILES} ${_MIG_HDRS_} ${MIGINCLUDES}

INSTALL_MI_LCL_LIST = ${PRIVATE_DATAFILES}

INSTALL_MI_DIR = device

EXPORT_MI_LIST	= ${DATAFILES} ${_MIG_HDRS_} ${MIGINCLUDES}

EXPORT_MI_DIR = device

#
# Build path
#
INCFLAGS_MAKEFILE= -I..

MIGKSFLAGS	= -DMACH_KERNEL_PRIVATE -DKERNEL_SERVER=1
MIGKUFLAGS	= -DMACH_KERNEL_PRIVATE -DKERNEL_USER=1

DEVICE_FILES    = device_server.h device_server.c

COMP_FILES	= ${DEVICE_FILES}

do_build_all:: $(COMP_FILES)

${DEVICE_FILES}: device.defs
	@echo "$(ColorM)MIG$(Color0) $(ColorF)$@$(Color0)"
	$(_v)${MIG} ${MIGFLAGS} ${MIGKSFLAGS}	\
	-header /dev/null			\
	-user /dev/null				\
	-sheader device_server.h		\
	-server device_server.c			\
	$<

include $(MakeInc_rule)
include $(MakeInc_dir)
