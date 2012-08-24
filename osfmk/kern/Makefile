export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES =

EXPORT_ONLY_FILES = \
	affinity.h \
	assert.h \
	audit_sessionport.h \
	clock.h \
	cpu_number.h \
	cpu_data.h \
	debug.h \
	etimer.h \
	extmod_statistics.h \
	ipc_mig.h \
	ipc_misc.h \
	kalloc.h \
	kext_alloc.h \
	kern_types.h \
	ledger.h \
	lock.h \
	locks.h \
	host.h \
	mach_param.h \
	macro_help.h \
	page_decrypt.h \
	pms.h \
	processor.h \
	queue.h \
	sched_prim.h \
	simple_lock.h \
	startup.h \
	task.h \
	thread.h \
	thread_call.h \
	wait_queue.h \
	zalloc.h

INSTALL_MI_LIST = ${DATAFILES}

INSTALL_MI_DIR = kern

EXPORT_MI_LIST = ${DATAFILES} ${EXPORT_ONLY_FILES}

EXPORT_MI_DIR = kern

include $(MakeInc_rule)
include $(MakeInc_dir)


