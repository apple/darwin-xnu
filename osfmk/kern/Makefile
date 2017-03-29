export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES = \
	exc_resource.h \
	kern_cdata.h \
	kcdata.h

PRIVATE_DATAFILES = \
	debug.h \
	ecc.h \
	block_hint.h

EXPORT_FILES = \
	affinity.h \
	assert.h \
	audit_sessionport.h \
	backtrace.h \
	bits.h \
	call_entry.h \
	clock.h \
	coalition.h \
	cpu_number.h \
	cpu_data.h \
	energy_perf.h \
	extmod_statistics.h \
	hv_support.h \
	ipc_mig.h \
	ipc_misc.h \
	kalloc.h \
	kext_alloc.h \
	kern_types.h \
	kpc.h \
	ledger.h \
	lock.h \
	locks.h \
	host.h \
	mach_param.h \
	macro_help.h \
	page_decrypt.h \
	pms.h \
	policy_internal.h \
	processor.h \
	queue.h \
	sched_prim.h \
	sfi.h \
	simple_lock.h \
	startup.h \
	task.h \
	telemetry.h \
	thread.h \
	thread_call.h \
	timer_call.h \
	waitq.h \
	zalloc.h

PRIVATE_EXPORT_FILES = \
	build_config.h \
	mach_node_link.h

INSTALL_MI_LIST = ${DATAFILES}

INSTALL_MI_LCL_LIST = ${PRIVATE_DATAFILES}

INSTALL_KF_MI_LCL_LIST = ${DATAFILES} ${PRIVATE_DATAFILES} ${EXPORT_FILES} ${PRIVATE_EXPORT_FILES}

INSTALL_MI_DIR = kern

EXPORT_MI_LIST = ${DATAFILES} ${PRIVATE_DATAFILES} ${EXPORT_FILES}

EXPORT_MI_DIR = kern

include $(MakeInc_rule)
include $(MakeInc_dir)
