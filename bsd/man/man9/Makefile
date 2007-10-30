export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES = \
	copy.9		\
	copyin.9	\
	copyinstr.9	\
	copyout.9	\
	copystr.9	\
	fetch.9		\
	fubyte.9	\
	fuibyte.9	\
	fuiword.9	\
	fulong.9	\
	fuulong.9	\
	fuword.9	\
	store.9		\
	style.9		\
	subyte.9	\
	suibyte.9	\
	suiword.9	\
	sulong.9	\
	suulong.9	\
	suword.9	\
	intro.9

INSTALL_MAN_LIST = ${DATAFILES}

INSTALL_MAN_DIR = man9

include $(MakeInc_rule)
include $(MakeInc_dir)

