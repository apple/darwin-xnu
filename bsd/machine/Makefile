export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)


DATAFILES = \
	ansi.h byte_order.h cons.h cpu.h disklabel.h endian.h exec.h \
	label_t.h param.h proc.h  profile.h psl.h ptrace.h reboot.h \
	reg.h setjmp.h signal.h spl.h table.h trap.h types.h unix_traps.h \
	user.h vmparam.h


INSTALL_MI_LIST = ${DATAFILES}

INSTALL_MI_DIR = machine

EXPORT_MI_LIST = ${DATAFILES}

EXPORT_MI_DIR = machine

include $(MakeInc_rule)
include $(MakeInc_dir)


