export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

CWARNFLAGS += -Wno-sign-compare

include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = \

INSTINC_SUBDIRS_PPC = \

INSTINC_SUBDIRS_I386 = \

EXPINC_SUBDIRS = \

EXPINC_SUBDIRS_PPC = \

EXPINC_SUBDIRS_I386 = \

SETUP_SUBDIRS = 	\

COMP_SUBDIRS = 	\

INST_SUBDIRS =	\

DATAFILES = appletalk.h atp.h asp.h aurp.h \
	    ddp.h ep.h lap.h nbp.h pap.h zip.h \
	    adsp.h at_pat.h  at_snmp.h at_aarp.h \
	    rtmp.h

PRIVATE_DATAFILES = \
	 debug.h routing_tables.h sysglue.h at_var.h

PRIVATE_KERNELFILES = \
	adsp_internal.h at_ddp_brt.h at_pcb.h
	

INSTALL_MI_LIST	= ${DATAFILES}

INSTALL_MI_DIR = netat

EXPORT_MI_LIST	= ${DATAFILES}

EXPORT_MI_DIR = netat

INSTALL_MI_LCL_LIST = ${DATAFILES} ${PRIVATE_DATAFILES}

INSTALL_KF_MI_LCL_LIST = ${INSTALL_MI_LCL_LIST} ${PRIVATE_KERNELFILES}

include $(MakeInc_rule)
include $(MakeInc_dir)


