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
	gssd \
	kextd \
	lockd \
	vm \
	libsa \
	kdp \
	pmc \
	kperf
INSTINC_SUBDIRS_X86_64 = \
	mach	\
	i386	\
	x86_64

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
	gssd \
	kextd \
	lockd \
	vm \
	libsa \
	console \
	pmc \
	kperf

EXPINC_SUBDIRS_X86_64 = \
	mach	\
	i386	\
	x86_64

COMP_SUBDIRS = 	\
	conf

include $(MakeInc_rule)
include $(MakeInc_dir)
