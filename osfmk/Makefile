export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)


INSTINC_SUBDIRS = \
	mach	\
	atm	\
	corpses	\
	bank \
	voucher \
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
	console \
	kperf \
	prng

INSTINC_SUBDIRS_X86_64 = \
	mach	\
	i386	\
	x86_64

INSTINC_SUBDIRS_X86_64H = \
	mach	\
	i386	\
	x86_64

INSTINC_SUBDIRS_ARM = \
	mach	\
	arm	\
	arm64

INSTINC_SUBDIRS_ARM64 = \
	mach	\
	arm	\
	arm64

EXPINC_SUBDIRS = \
	mach	\
	atm	\
	corpses	\
	bank \
	voucher \
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
	kperf \
	prng \
	tests


EXPINC_SUBDIRS_X86_64 = \
	mach	\
	i386	\
	x86_64
EXPINC_SUBDIRS_X86_64H = \
	mach	\
	i386	\
	x86_64
EXPINC_SUBDIRS_ARM = \
	mach	\
	arm	\
	arm64
EXPINC_SUBDIRS_ARM64 = \
	mach	\
	arm	\
	arm64

COMP_SUBDIRS =	\
	conf

include $(MakeInc_rule)
include $(MakeInc_dir)
