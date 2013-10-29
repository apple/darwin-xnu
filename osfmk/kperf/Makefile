export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

EXPORT_ONLY_FILES = 	\
			context.h	\
			timetrigger.h   \
			pet.h           \
			kperfbsd.h      \
			action.h        \
			kperf.h

EXPORT_MI_DIR = kperf

# Export our headers
EXPORT_MI_LIST = ${EXPORT_ONLY_FILES}

INSTALL_MI_DIR = kperf

INSTALL_MI_LIST = $(empty)

# Don't install in non-local, though
INSTALL_KF_MI_LIST = $(empty)

include $(MakeInc_rule)
include $(MakeInc_dir)


