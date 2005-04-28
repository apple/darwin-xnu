export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = \
        machine \
	c++

INSTINC_SUBDIRS_PPC = ${INSTINC_SUBDIRS} \
        ppc

INSTINC_SUBDIRS_I386 = ${INSTINC_SUBDIRS} \
        i386

EXPINC_SUBDIRS = ${INSTINC_SUBDIRS}
EXPINC_SUBDIRS_PPC = ${INSTINC_SUBDIRS_PPC}
EXPINC_SUBDIRS_I386 = ${INSTINC_SUBDIRS_I386}

DATAFILES = \
	OSAtomic.h	\
        OSBase.h	\
        OSByteOrder.h	\
        OSDebug.h	\
        OSMalloc.h	\
        OSReturn.h	\
        OSTypes.h	\
	locks.h		\
	sysctl.h

INSTALL_MI_LIST	= OSByteOrder.h OSDebug.h OSReturn.h OSTypes.h 

INSTALL_MI_DIR = libkern

EXPORT_MI_LIST	= ${DATAFILES}

EXPORT_MI_GEN_LIST = \
	 version.h

EXPORT_MI_DIR = libkern

NEWVERS = $(SRCROOT)/config/newvers.pl

version.h: version.h.template $(SRCROOT)/config/MasterVersion
	@echo "Generating libkern/$@ from $<";
	install $(DATA_INSTALL_FLAGS) $< $@
	$(NEWVERS) $@;

include $(MakeInc_rule)
include $(MakeInc_dir)


