export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS =

INSTINC_SUBDIRS_PPC = 	\
	ppc

INSTINC_SUBDIRS_I386 =	\
	i386

INSTINC_SUBDIRS_ARM =	\
	arm

EXPORT_FILES = 

INSTALL_MI_LIST = 

INSTALL_MI_DIR = architecture

EXPORT_MI_LIST = ${EXPORT_FILES}

EXPORT_MI_DIR = architecture

include $(MakeInc_rule)
include $(MakeInc_dir)


build_installhdrs_mi::
	$(MKDIR) $(DSTROOT)/$(KINCDIR)/$(EXPORT_MI_DIR)
	$(LN) ../../../../../../../../usr/include/architecture/byte_order.h $(DSTROOT)/$(KINCDIR)/$(EXPORT_MI_DIR)/byte_order.h 
