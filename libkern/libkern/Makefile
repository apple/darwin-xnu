export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = \
        machine \
	c++ \
	crypto
INSTINC_SUBDIRS_X86_64 = \
        i386


EXPINC_SUBDIRS = ${INSTINC_SUBDIRS}
EXPINC_SUBDIRS_X86_64 = ${INSTINC_SUBDIRS_X86_64}

DATAFILES = \
	OSAtomic.h	\
        OSBase.h	\
        OSByteOrder.h	\
        _OSByteOrder.h	\
        OSDebug.h	\
	OSKextLib.h     \
        OSMalloc.h	\
        OSReturn.h	\
        OSTypes.h	\
	locks.h		\
	sysctl.h	\
	tree.h		\
	zconf.h		\
	zlib.h

PRIVATE_DATAFILES =         \
	OSKextLibPrivate.h  \
	kext_request_keys.h \
	mkext.h		    \
	prelink.h

INSTALL_MI_LIST	=       \
	OSByteOrder.h   \
	_OSByteOrder.h  \
	OSDebug.h       \
	OSKextLib.h     \
	OSReturn.h      \
	OSTypes.h

INSTALL_MI_DIR = libkern

INSTALL_MI_LCL_LIST =        \
	${INSTALL_MI_LIST}   \
	${PRIVATE_DATAFILES} \
	tree.h		     \
	kext_panic_report.h  \
	OSCrossEndian.h

INSTALL_KF_MI_LIST =       \
	${DATAFILES}

INSTALL_KF_MI_LCL_LIST =   \
	${DATAFILES}       \
	${PRIVATE_DATAFILES}

EXPORT_MI_LIST	=              \
	${DATAFILES}           \
	${PRIVATE_DATAFILES}   \
	kernel_mach_header.h   \
	kxld.h                 \
	kxld_types.h           \
	stack_protector.h

EXPORT_MI_GEN_LIST = version.h

EXPORT_MI_DIR = libkern

version.h: version.h.template $(SRCROOT)/config/MasterVersion
	@echo "Generating libkern/$@ from $<";
	$(_v)install $(DATA_INSTALL_FLAGS) $< $@
	$(_v)$(NEWVERS) $@ > /dev/null;

include $(MakeInc_rule)
include $(MakeInc_dir)
