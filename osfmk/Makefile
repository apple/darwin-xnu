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
	pmc
INSTINC_SUBDIRS_I386 = \
	mach	\
	i386
INSTINC_SUBDIRS_X86_64 = \
	mach	\
	i386	\
	x86_64
INSTINC_SUBDIRS_ARM = \
	mach	\
	arm

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
	kdp \
	pmc

EXPINC_SUBDIRS_I386 = \
	mach	\
	i386
EXPINC_SUBDIRS_X86_64 = \
	mach	\
	i386	\
	x86_64
EXPINC_SUBDIRS_ARM = \
	mach	\
	arm

SETUP_SUBDIRS =

COMP_SUBDIRS = 	\
	conf

INST_SUBDIRS =	\


include $(MakeInc_rule)
include $(MakeInc_dir)
