export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = \
	devfs \
	fifofs \
	routefs \
	specfs \
	union \
	nullfs \
	bindfs

EXPINC_SUBDIRS = \
	devfs \
	fifofs \
	routefs \
	specfs \
	union \
	nullfs \
	bindfs

include $(MakeInc_rule)
include $(MakeInc_dir)
