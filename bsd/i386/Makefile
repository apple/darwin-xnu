export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES = \
	cpu.h disklabel.h endian.h exec.h label_t.h param.h \
	profile.h psl.h ptrace.h  reboot.h setjmp.h signal.h \
	spl.h table.h types.h user.h vmparam.h


INSTALL_MD_LIST = ${DATAFILES}

INSTALL_MD_DIR = i386

EXPORT_MD_LIST = ${DATAFILES}

EXPORT_MD_DIR = i386

include $(MakeInc_rule)
include $(MakeInc_dir)


