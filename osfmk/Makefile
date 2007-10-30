export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

export COMP_LDFLAGS_COMPONENT_PPC = -Wl,-i_OSCompareAndSwap:_hw_compare_and_store \
                                    -Wl,-i_OSDequeueAtomic:_hw_dequeue_atomic \
                                    -Wl,-i_OSEnqueueAtomic:_hw_queue_atomic

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
	lockd \
	vm \
	libsa \
	kdp

INSTINC_SUBDIRS_PPC = \
	mach \
	ppc

INSTINC_SUBDIRS_I386 = \
	mach	\
	i386

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
	lockd \
	vm \
	libsa \
	kdp

EXPINC_SUBDIRS_PPC = \
	mach \
	ppc

EXPINC_SUBDIRS_I386 = \
	mach	\
	i386

EXPINC_SUBDIRS_ARM = \
	mach	\
	arm

SETUP_SUBDIRS = 	\
	conf

COMP_SUBDIRS = 	\
	conf

INST_SUBDIRS =	\


include $(MakeInc_rule)
include $(MakeInc_dir)
