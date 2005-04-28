export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = \
	mach	\
	device \
	default_pager \
	mach_debug \
	kern \
	ipc \
	machine \
	UserNotification \
	vm \
	libsa

INSTINC_SUBDIRS_PPC = \
	mach \
	ppc

INSTINC_SUBDIRS_I386 = \
	mach	\
	i386

EXPINC_SUBDIRS = \
	mach	\
	device \
	default_pager \
	mach_debug \
	kern \
	kdp \
	ipc \
	machine \
	UserNotification \
	vm \
	libsa

EXPINC_SUBDIRS_PPC = \
	mach \
	ppc

EXPINC_SUBDIRS_I386 = \
	mach	\
	i386

SETUP_SUBDIRS = 	\
	conf

COMP_SUBDIRS = 	\
	conf

INST_SUBDIRS =	\


include $(MakeInc_rule)
include $(MakeInc_dir)


