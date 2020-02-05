export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = \
    machine \
    c++ \
    crypto \
    img4
INSTINC_SUBDIRS_X86_64 = \
        i386
INSTINC_SUBDIRS_X86_64H = \
        i386
INSTINC_SUBDIRS_ARM = \
        arm
INSTINC_SUBDIRS_ARM64 = \
        arm

EXPINC_SUBDIRS = ${INSTINC_SUBDIRS}
EXPINC_SUBDIRS_X86_64 = ${INSTINC_SUBDIRS_X86_64}
EXPINC_SUBDIRS_X86_64H = ${INSTINC_SUBDIRS_X86_64H}
EXPINC_SUBDIRS_ARM = ${INSTINC_SUBDIRS_ARM}
EXPINC_SUBDIRS_ARM64 = ${INSTINC_SUBDIRS_ARM64}

DATAFILES = \
	OSByteOrder.h \
	_OSByteOrder.h \
	OSDebug.h \
	OSKextLib.h \
	OSReturn.h \
	OSTypes.h

DRIVERKIT_DATAFILES = \
	OSByteOrder.h \
	_OSByteOrder.h

KERNELFILES = \
	${DATAFILES} \
	OSAtomic.h \
	OSBase.h \
	OSMalloc.h \
	locks.h	\
	sysctl.h \
	tree.h \
	zconf.h	\
	zlib.h \
	crc.h \
	Block.h

PRIVATE_KERNELFILES = \
	OSKextLibPrivate.h \
	OSSerializeBinary.h \
	kext_request_keys.h \
	mkext.h \
	prelink.h \
	section_keywords.h \
	Block_private.h

PRIVATE_DATAFILES = \
	${PRIVATE_KERNELFILES} \
	tree.h

INSTALL_MI_LIST	= ${DATAFILES}

INSTALL_DRIVERKIT_MI_LIST = ${DRIVERKIT_DATAFILES}

DRIVERKITINCDIR = $(DRIVERKITSDKHEADERSROOT)/usr/local/include

INSTALL_MI_DIR = libkern

INSTALL_MI_LCL_LIST =        \
	${PRIVATE_DATAFILES} \
	kext_panic_report.h  \
	OSCrossEndian.h

INSTALL_KF_MI_LIST = ${KERNELFILES}

INSTALL_KF_MI_LCL_LIST = ${KERNELFILES} ${PRIVATE_KERNELFILES}

EXPORT_MI_LIST = \
	$(sort ${KERNELFILES} ${PRIVATE_DATAFILES}) \
	kernel_mach_header.h   \
	kxld.h                 \
	kxld_types.h           \
	stack_protector.h

EXPORT_MI_GEN_LIST = version.h

EXPORT_MI_DIR = libkern

version.h: version.h.template $(SRCROOT)/config/MasterVersion
	$(call makelog,[$(CMD_MC)] $(ColorH)GENERATING$(Color0) $(ColorLF)libkern/$@$(Color0) from $(ColorF)$<$(Color0))
	$(_v)install $(DATA_INSTALL_FLAGS) $< $@
	$(_v)$(NEWVERS) $@ > /dev/null

include $(MakeInc_rule)
include $(MakeInc_dir)
