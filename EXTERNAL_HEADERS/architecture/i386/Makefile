export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

EXPORT_FILES = 		\
	asm_help.h	\
	cpu.h		\
	io.h		\
	pio.h		\
	sel.h		\
	tss.h		\
	desc.h		\
	reg_help.h	\
	table.h


INSTALL_MD_LIST = 

INSTALL_MD_DIR = 

EXPORT_MD_LIST = ${EXPORT_FILES}

EXPORT_MD_DIR = architecture/i386

include $(MakeInc_rule)
include $(MakeInc_dir)


