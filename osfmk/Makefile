export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = \
	mach	\
	default_pager \
	device \
	mach_debug \
	profiling \
	UserNotification

INSTINC_SUBDIRS_PPC = \
	mach \
	profiling 

INSTINC_SUBDIRS_I386 = \
	mach	\
	profiling

EXPINC_SUBDIRS = \
	mach	\
	device \
	default_pager \
	mach_debug \
	profiling \
	ddb \
	kern \
	ipc \
	machine \
	UserNotification \
	vm \
	libsa

EXPINC_SUBDIRS_PPC = \
	mach \
	ppc \
	profiling 

EXPINC_SUBDIRS_I386 = \
	mach	\
	i386 \
	profiling

SETUP_SUBDIRS = 	\
	conf

COMP_SUBDIRS = 	\
	conf

INST_SUBDIRS =	\


include $(MakeInc_rule)
include $(MakeInc_dir)


