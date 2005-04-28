export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS_PPC =

EXPORT_FILES = 		\
	asm_help.h	\
	basic_regs.h	\
	byte_order.h	\
	cframe.h	\
	fp_regs.h	\
	macro_help.h	\
	pseudo_inst.h	\
	reg_help.h


INSTALL_MD_LIST = 

INSTALL_MD_DIR = 

EXPORT_MD_LIST = ${EXPORT_FILES}

EXPORT_MD_DIR = architecture/ppc

include $(MakeInc_rule)
include $(MakeInc_dir)


