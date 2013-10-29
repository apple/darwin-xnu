/*
 * Copyright (c) 2012-2013 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
#include <mach/host_priv.h>
#include <mach/host_special_ports.h>
#include <mach/mach_types.h>
#include <mach/telemetry_notification_server.h>

#include <kern/assert.h>
#include <kern/clock.h>
#include <kern/debug.h>
#include <kern/host.h>
#include <kern/kalloc.h>
#include <kern/kern_types.h> 
#include <kern/locks.h> 
#include <kern/misc_protos.h> 
#include <kern/sched.h>
#include <kern/sched_prim.h>
#include <kern/telemetry.h>
#include <kern/timer_call.h>

#include <pexpert/pexpert.h>

#include <vm/vm_kern.h>
#include <vm/vm_shared_region.h>

#include <kperf/kperf.h>
#include <kperf/context.h>
#include <kperf/callstack.h>

#include <sys/kdebug.h>
#include <uuid/uuid.h>
#include <kdp/kdp_dyld.h>

#define TELEMETRY_DEBUG 0

extern int	proc_pid(void *);
extern char	*proc_name_address(void *p);
extern uint64_t proc_uniqueid(void *p);
extern uint64_t proc_was_throttled(void *p);
extern uint64_t proc_did_throttle(void *p);
extern uint64_t get_dispatchqueue_serialno_offset_from_proc(void *p);
extern int	proc_selfpid(void);

void telemetry_take_sample(thread_t thread, uint8_t microsnapshot_flags);

#define TELEMETRY_DEFAULT_SAMPLE_RATE (1) /* 1 sample every 1 second */
#define TELEMETRY_DEFAULT_BUFFER_SIZE (16*1024)
#define TELEMETRY_MAX_BUFFER_SIZE (64*1024)

#define	TELEMETRY_DEFAULT_NOTIFY_LEEWAY (4*1024) // Userland gets 4k of leeway to collect data after notification

uint32_t 			telemetry_sample_rate = 0;
volatile boolean_t 	telemetry_needs_record = FALSE;
volatile boolean_t 	telemetry_needs_timer_arming_record = FALSE;

/*
 * If TRUE, record micro-stackshot samples for all tasks.
 * If FALSE, only sample tasks which are marked for telemetry.
 */
boolean_t			telemetry_sample_all_tasks = FALSE;
uint32_t			telemetry_active_tasks = 0; // Number of tasks opted into telemetry

uint32_t			telemetry_timestamp = 0;

vm_offset_t			telemetry_buffer = 0;
uint32_t			telemetry_buffer_size = 0;
uint32_t			telemetry_buffer_current_position = 0;
uint32_t			telemetry_buffer_end_point = 0; // If we've wrapped, where does the last record end?
int					telemetry_bytes_since_last_mark = -1; // How much data since buf was last marked?
int					telemetry_buffer_notify_at = 0;

lck_grp_t       	telemetry_lck_grp;
lck_mtx_t       	telemetry_mtx;

#define TELEMETRY_LOCK() do { lck_mtx_lock(&telemetry_mtx); } while(0)
#define TELEMETRY_TRY_SPIN_LOCK() lck_mtx_try_lock_spin(&telemetry_mtx)
#define TELEMETRY_UNLOCK() do { lck_mtx_unlock(&telemetry_mtx); } while(0)

void telemetry_init(void)
{
	kern_return_t ret;
	uint32_t	  telemetry_notification_leeway;

	lck_grp_init(&telemetry_lck_grp, "telemetry group", LCK_GRP_ATTR_NULL);
	lck_mtx_init(&telemetry_mtx, &telemetry_lck_grp, LCK_ATTR_NULL);

	if (!PE_parse_boot_argn("telemetry_buffer_size", &telemetry_buffer_size, sizeof(telemetry_buffer_size))) {
		telemetry_buffer_size = TELEMETRY_DEFAULT_BUFFER_SIZE;
	}

	if (telemetry_buffer_size > TELEMETRY_MAX_BUFFER_SIZE)
		telemetry_buffer_size = TELEMETRY_MAX_BUFFER_SIZE;

	ret = kmem_alloc(kernel_map, &telemetry_buffer, telemetry_buffer_size);
	if (ret != KERN_SUCCESS) {
		kprintf("Telemetry: Allocation failed: %d\n", ret);
		return;
	}

	if (!PE_parse_boot_argn("telemetry_notification_leeway", &telemetry_notification_leeway, sizeof(telemetry_notification_leeway))) {
		/*
		 * By default, notify the user to collect the buffer when there is this much space left in the buffer.
		 */
		telemetry_notification_leeway = TELEMETRY_DEFAULT_NOTIFY_LEEWAY;
	}
	if (telemetry_notification_leeway >= telemetry_buffer_size) {
		printf("telemetry: nonsensical telemetry_notification_leeway boot-arg %d changed to %d\n",
		       telemetry_notification_leeway, TELEMETRY_DEFAULT_NOTIFY_LEEWAY);
		telemetry_notification_leeway = TELEMETRY_DEFAULT_NOTIFY_LEEWAY;
	}
	telemetry_buffer_notify_at = telemetry_buffer_size - telemetry_notification_leeway;

	if (!PE_parse_boot_argn("telemetry_sample_rate", &telemetry_sample_rate, sizeof(telemetry_sample_rate))) {
		telemetry_sample_rate = TELEMETRY_DEFAULT_SAMPLE_RATE;
	}

	/*
	 * To enable telemetry for all tasks, include "telemetry_sample_all_tasks=1" in boot-args.
	 */
	if (!PE_parse_boot_argn("telemetry_sample_all_tasks", &telemetry_sample_all_tasks, sizeof(telemetry_sample_all_tasks))) {

		telemetry_sample_all_tasks = TRUE;

	}

	kprintf("Telemetry: Sampling %stasks once per %u second%s\n",
		(telemetry_sample_all_tasks) ? "all " : "",
		telemetry_sample_rate, telemetry_sample_rate == 1 ? "" : "s");
}

/*
 * Enable or disable global microstackshots (ie telemetry_sample_all_tasks).
 *
 * enable_disable == 1: turn it on
 * enable_disable == 0: turn it off
 */
void
telemetry_global_ctl(int enable_disable) 
{
	if (enable_disable == 1) {
		telemetry_sample_all_tasks = TRUE;
	} else {
		telemetry_sample_all_tasks = FALSE;
	}
}

/*
 * Opt the given task into or out of the telemetry stream.
 *
 * Supported reasons (callers may use any or all of):
 *     TF_CPUMON_WARNING
 *     TF_WAKEMON_WARNING
 *
 * enable_disable == 1: turn it on
 * enable_disable == 0: turn it off
 */
void
telemetry_task_ctl(task_t task, uint32_t reasons, int enable_disable)
{
	task_lock(task);
	telemetry_task_ctl_locked(task, reasons, enable_disable);
	task_unlock(task);
}

void
telemetry_task_ctl_locked(task_t task, uint32_t reasons, int enable_disable)
{
	uint32_t origflags;

	assert((reasons != 0) && ((reasons | TF_TELEMETRY) == TF_TELEMETRY));

	task_lock_assert_owned(task);

	origflags = task->t_flags;

	if (enable_disable == 1) {
		task->t_flags |= reasons;
		if ((origflags & TF_TELEMETRY) == 0) {
			OSIncrementAtomic(&telemetry_active_tasks);
#if TELEMETRY_DEBUG			
			printf("%s: telemetry OFF -> ON (%d active)\n", proc_name_address(task->bsd_info), telemetry_active_tasks);
#endif			
		}
	} else {
		task->t_flags &= ~reasons;
		if (((origflags & TF_TELEMETRY) != 0) && ((task->t_flags & TF_TELEMETRY) == 0)) {
			/*
			 * If this task went from having at least one telemetry bit to having none,
			 * the net change was to disable telemetry for the task.
			 */
			OSDecrementAtomic(&telemetry_active_tasks);
#if TELEMETRY_DEBUG
			printf("%s: telemetry ON -> OFF (%d active)\n", proc_name_address(task->bsd_info), telemetry_active_tasks);
#endif
		}
	}
}

/*
 * Determine if the current thread is eligible for telemetry:
 *
 * telemetry_sample_all_tasks: All threads are eligible. This takes precedence.
 * telemetry_active_tasks: Count of tasks opted in.
 * task->t_flags & TF_TELEMETRY: This task is opted in.
 */
static boolean_t
telemetry_is_active(thread_t thread)
{
	if (telemetry_sample_all_tasks == TRUE) {
		return (TRUE);
	}

	if ((telemetry_active_tasks > 0) && ((thread->task->t_flags & TF_TELEMETRY) != 0)) {
		return (TRUE);
	}
 
	return (FALSE);
}

/*
 * Userland is arming a timer. If we are eligible for such a record,
 * sample now. No need to do this one at the AST because we're already at
 * a safe place in this system call.
 */
int telemetry_timer_event(__unused uint64_t deadline, __unused uint64_t interval, __unused uint64_t leeway)
{
	if (telemetry_needs_timer_arming_record == TRUE) {
		telemetry_needs_timer_arming_record = FALSE;
		telemetry_take_sample(current_thread(), kTimerArmingRecord | kUserMode);
	}

	return (0);
}

/*
 * Mark the current thread for an interrupt-based
 * telemetry record, to be sampled at the next AST boundary.
 */
void telemetry_mark_curthread(boolean_t interrupted_userspace)
{
	thread_t thread = current_thread();

	/*
	 * If telemetry isn't active for this thread, return and try
	 * again next time.
	 */
	if (telemetry_is_active(thread) == FALSE) {
		return;
	}

	telemetry_needs_record = FALSE;
	thread_ast_set(thread, interrupted_userspace ? AST_TELEMETRY_USER : AST_TELEMETRY_KERNEL);
	ast_propagate(thread->ast);
}

void compute_telemetry(void *arg __unused)
{
	if (telemetry_sample_all_tasks || (telemetry_active_tasks > 0)) {
		if ((++telemetry_timestamp) % telemetry_sample_rate == 0) {
			/*
			 * To avoid overloading the system with telemetry ASTs, make
			 * sure we don't add more requests while existing ones
			 * are in-flight.
			 */
			if (TELEMETRY_TRY_SPIN_LOCK()) {
				telemetry_needs_record = TRUE;
				telemetry_needs_timer_arming_record = TRUE;
				TELEMETRY_UNLOCK();
			}
		}
	}
}

/*
 * If userland has registered a port for telemetry notifications, send one now.
 */
static void
telemetry_notify_user(void)
{
	mach_port_t user_port;
	uint32_t	flags = 0;
	int			error;

	error = host_get_telemetry_port(host_priv_self(), &user_port);
	if ((error != KERN_SUCCESS) || !IPC_PORT_VALID(user_port)) {
		return;
	}

	telemetry_notification(user_port, flags);
}

void telemetry_ast(thread_t thread, boolean_t interrupted_userspace)
{
	uint8_t microsnapshot_flags = kInterruptRecord;

	if (interrupted_userspace)
		microsnapshot_flags |= kUserMode;

	telemetry_take_sample(thread, microsnapshot_flags);
}

void telemetry_take_sample(thread_t thread, uint8_t microsnapshot_flags)
{
	task_t task;
	void *p;
	struct kperf_context ctx;
	struct callstack cs;
	uint32_t btcount, bti;
	struct micro_snapshot *msnap;
	struct task_snapshot *tsnap;
	struct thread_snapshot *thsnap;
	clock_sec_t secs;
	clock_usec_t usecs;
	vm_size_t framesize;
	uint32_t current_record_start;
	uint32_t tmp = 0;
	boolean_t notify = FALSE;

	if (thread == THREAD_NULL)
		return;

	task = thread->task;
	if ((task == TASK_NULL) || (task == kernel_task))
		return;

	/* telemetry_XXX accessed outside of lock for instrumentation only */
	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_STACKSHOT, MICROSTACKSHOT_RECORD) | DBG_FUNC_START, microsnapshot_flags, telemetry_bytes_since_last_mark, 0, 0, 0);

	p = get_bsdtask_info(task);

	ctx.cur_thread = thread;
	ctx.cur_pid = proc_pid(p);

	/*
	 * Gather up the data we'll need for this sample. The sample is written into the kernel
	 * buffer with the global telemetry lock held -- so we must do our (possibly faulting)
	 * copies from userland here, before taking the lock.
	 */
	kperf_ucallstack_sample(&cs, &ctx);
	if (!(cs.flags & CALLSTACK_VALID))
		return;

	/*
	 * Find the actual [slid] address of the shared cache's UUID, and copy it in from userland.
	 */
	int		 					shared_cache_uuid_valid = 0;
	uint64_t					shared_cache_base_address;
	struct _dyld_cache_header	shared_cache_header;
	uint64_t					shared_cache_slide;

	/*
	 * Don't copy in the entire shared cache header; we only need the UUID. Calculate the
	 * offset of that one field.
	 */
	int sc_header_uuid_offset = (char *)&shared_cache_header.uuid - (char *)&shared_cache_header;
	vm_shared_region_t sr = vm_shared_region_get(task);
	if (sr != NULL) {
		if ((vm_shared_region_start_address(sr, &shared_cache_base_address) == KERN_SUCCESS) &&
			(copyin(shared_cache_base_address + sc_header_uuid_offset, (char *)&shared_cache_header.uuid,
	    	    sizeof (shared_cache_header.uuid)) == 0)) {
			shared_cache_uuid_valid = 1;
			shared_cache_slide = vm_shared_region_get_slide(sr);
		}
		// vm_shared_region_get() gave us a reference on the shared region.
		vm_shared_region_deallocate(sr);
	}

	/*
	 * Retrieve the array of UUID's for binaries used by this task.
	 * We reach down into DYLD's data structures to find the array.
	 *
	 * XXX - make this common with kdp?
	 */
	uint32_t			uuid_info_count = 0;
	mach_vm_address_t	uuid_info_addr = 0;
	if (task_has_64BitAddr(task)) {
		struct user64_dyld_all_image_infos task_image_infos;
		if (copyin(task->all_image_info_addr, (char *)&task_image_infos, sizeof(task_image_infos)) == 0) {
			uuid_info_count = (uint32_t)task_image_infos.uuidArrayCount;
			uuid_info_addr = task_image_infos.uuidArray;
		}
	} else {
		struct user32_dyld_all_image_infos task_image_infos;
		if (copyin(task->all_image_info_addr, (char *)&task_image_infos, sizeof(task_image_infos)) == 0) {
			uuid_info_count = task_image_infos.uuidArrayCount;
			uuid_info_addr = task_image_infos.uuidArray;
		}
	}

	/*
	 * If we get a NULL uuid_info_addr (which can happen when we catch dyld in the middle of updating
	 * this data structure), we zero the uuid_info_count so that we won't even try to save load info
	 * for this task.
	 */
	if (!uuid_info_addr) {
		uuid_info_count = 0;
	}

	uint32_t uuid_info_size = (uint32_t)(task_has_64BitAddr(thread->task) ? sizeof(struct user64_dyld_uuid_info) : sizeof(struct user32_dyld_uuid_info));
	uint32_t uuid_info_array_size = uuid_info_count * uuid_info_size;
	char	 *uuid_info_array = NULL;

	if (uuid_info_count > 0) {
		if ((uuid_info_array = (char *)kalloc(uuid_info_array_size)) == NULL) {
			return;
		}

		/*
		 * Copy in the UUID info array.
		 * It may be nonresident, in which case just fix up nloadinfos to 0 in the task snapshot.
		 */
		if (copyin(uuid_info_addr, uuid_info_array, uuid_info_array_size) != 0) {
			kfree(uuid_info_array, uuid_info_array_size);
			uuid_info_array = NULL;
			uuid_info_array_size = 0;
		}
	}

	/*
	 * Look for a dispatch queue serial number, and copy it in from userland if present.
	 */
	uint64_t dqserialnum = 0;
	int		 dqserialnum_valid = 0;

	uint64_t dqkeyaddr = thread_dispatchqaddr(thread);
	if (dqkeyaddr != 0) {
		uint64_t dqaddr = 0;
		uint64_t dq_serialno_offset = get_dispatchqueue_serialno_offset_from_proc(task->bsd_info);
		if ((copyin(dqkeyaddr, (char *)&dqaddr, (task_has_64BitAddr(task) ? 8 : 4)) == 0) &&
		    (dqaddr != 0) && (dq_serialno_offset != 0)) {
			uint64_t dqserialnumaddr = dqaddr + dq_serialno_offset;
			if (copyin(dqserialnumaddr, (char *)&dqserialnum, (task_has_64BitAddr(task) ? 8 : 4)) == 0) {
				dqserialnum_valid = 1;
			}
		}
	}

	clock_get_calendar_microtime(&secs, &usecs);

	TELEMETRY_LOCK();

	/*
	 * We do the bulk of the operation under the telemetry lock, on assumption that
	 * any page faults during execution will not cause another AST_TELEMETRY_ALL
	 * to deadlock; they will just block until we finish. This makes it easier
	 * to copy into the buffer directly. As soon as we unlock, userspace can copy
	 * out of our buffer.
	 */

copytobuffer:

	current_record_start = telemetry_buffer_current_position;

	if ((telemetry_buffer_size - telemetry_buffer_current_position) < sizeof(struct micro_snapshot)) {
		/*
		 * We can't fit a record in the space available, so wrap around to the beginning.
		 * Save the current position as the known end point of valid data.
		 */
		telemetry_buffer_end_point = current_record_start;
		telemetry_buffer_current_position = 0;
		goto copytobuffer;
	}

	msnap = (struct micro_snapshot *)(uintptr_t)(telemetry_buffer + telemetry_buffer_current_position);
	msnap->snapshot_magic = STACKSHOT_MICRO_SNAPSHOT_MAGIC;
	msnap->ms_flags = microsnapshot_flags;
	msnap->ms_opaque_flags = 0; /* namespace managed by userspace */
	msnap->ms_cpu = 0; /* XXX - does this field make sense for a micro-stackshot? */
	msnap->ms_time = secs;
	msnap->ms_time_microsecs = usecs;

	telemetry_buffer_current_position += sizeof(struct micro_snapshot);

	if ((telemetry_buffer_size - telemetry_buffer_current_position) < sizeof(struct task_snapshot)) {
		telemetry_buffer_end_point = current_record_start;
		telemetry_buffer_current_position = 0;
		goto copytobuffer;
	}

	tsnap = (struct task_snapshot *)(uintptr_t)(telemetry_buffer + telemetry_buffer_current_position);
	bzero(tsnap, sizeof(*tsnap));
	tsnap->snapshot_magic = STACKSHOT_TASK_SNAPSHOT_MAGIC;
	tsnap->pid = proc_pid(p);
	tsnap->uniqueid = proc_uniqueid(p);
	tsnap->user_time_in_terminated_threads = task->total_user_time;
	tsnap->system_time_in_terminated_threads = task->total_system_time;
	tsnap->suspend_count = task->suspend_count;
	tsnap->task_size = pmap_resident_count(task->map->pmap);
	tsnap->faults = task->faults;
	tsnap->pageins = task->pageins;
	tsnap->cow_faults = task->cow_faults;
	/*
	 * The throttling counters are maintained as 64-bit counters in the proc
	 * structure. However, we reserve 32-bits (each) for them in the task_snapshot
	 * struct to save space and since we do not expect them to overflow 32-bits. If we
	 * find these values overflowing in the future, the fix would be to simply 
	 * upgrade these counters to 64-bit in the task_snapshot struct
	 */
	tsnap->was_throttled = (uint32_t) proc_was_throttled(p);
	tsnap->did_throttle = (uint32_t) proc_did_throttle(p);
	
	if (task->t_flags & TF_TELEMETRY) {
		tsnap->ss_flags |= kTaskRsrcFlagged;
	}

	proc_get_darwinbgstate(task, &tmp);

	if (tmp & PROC_FLAG_DARWINBG) {
		tsnap->ss_flags |= kTaskDarwinBG;
	}
	if (tmp & PROC_FLAG_EXT_DARWINBG) {
		tsnap->ss_flags |= kTaskExtDarwinBG;
	}

	if (task->requested_policy.t_role == TASK_FOREGROUND_APPLICATION) {
		tsnap->ss_flags |= kTaskIsForeground;
	}

	if (tmp & PROC_FLAG_ADAPTIVE_IMPORTANT) {
		tsnap->ss_flags |= kTaskIsBoosted;
	}

	if (tmp & PROC_FLAG_SUPPRESSED) {
		tsnap->ss_flags |= kTaskIsSuppressed;
	}

	tsnap->latency_qos = task_grab_latency_qos(task);

	strlcpy(tsnap->p_comm, proc_name_address(p), sizeof(tsnap->p_comm));
	if (task_has_64BitAddr(thread->task)) {
		tsnap->ss_flags |= kUser64_p;
	}

	if (shared_cache_uuid_valid) {
		tsnap->shared_cache_slide = shared_cache_slide;
		bcopy(shared_cache_header.uuid, tsnap->shared_cache_identifier, sizeof (shared_cache_header.uuid));
	}

	telemetry_buffer_current_position += sizeof(struct task_snapshot);

	/*
	 * Directly after the task snapshot, place the array of UUID's corresponding to the binaries
	 * used by this task.
	 */
	if ((telemetry_buffer_size - telemetry_buffer_current_position) < uuid_info_array_size) {
		telemetry_buffer_end_point = current_record_start;
		telemetry_buffer_current_position = 0;
		goto copytobuffer;
	}

	/*
	 * Copy the UUID info array into our sample.
	 */
	if (uuid_info_array_size > 0) {
		bcopy(uuid_info_array, (char *)(telemetry_buffer + telemetry_buffer_current_position), uuid_info_array_size);
		tsnap->nloadinfos = uuid_info_count;
	}

	telemetry_buffer_current_position += uuid_info_array_size;

	/*
	 * After the task snapshot & list of binary UUIDs, we place a thread snapshot.
	 */

	if ((telemetry_buffer_size - telemetry_buffer_current_position) < sizeof(struct thread_snapshot)) {
		/* wrap and overwrite */
		telemetry_buffer_end_point = current_record_start;		
		telemetry_buffer_current_position = 0;
		goto copytobuffer;
	}

	thsnap = (struct thread_snapshot *)(uintptr_t)(telemetry_buffer + telemetry_buffer_current_position);
	bzero(thsnap, sizeof(*thsnap));

	thsnap->snapshot_magic = STACKSHOT_THREAD_SNAPSHOT_MAGIC;
	thsnap->thread_id = thread_tid(thread);
	thsnap->state = thread->state;
	thsnap->priority = thread->priority;
	thsnap->sched_pri = thread->sched_pri;
	thsnap->sched_flags = thread->sched_flags;
	thsnap->ss_flags |= kStacksPCOnly;

	if (thread->effective_policy.darwinbg) {
		thsnap->ss_flags |= kThreadDarwinBG;
	}

	thsnap->user_time = timer_grab(&thread->user_timer);

	uint64_t tval = timer_grab(&thread->system_timer);

	if (thread->precise_user_kernel_time) {
		thsnap->system_time = tval;
	} else {
		thsnap->user_time += tval;
		thsnap->system_time = 0;
	}

	telemetry_buffer_current_position += sizeof(struct thread_snapshot);

	/*
	 * If this thread has a dispatch queue serial number, include it here.
	 */
	if (dqserialnum_valid) {
		if ((telemetry_buffer_size - telemetry_buffer_current_position) < sizeof(dqserialnum)) {
			/* wrap and overwrite */
			telemetry_buffer_end_point = current_record_start;		
			telemetry_buffer_current_position = 0;
			goto copytobuffer;
		}

		thsnap->ss_flags |= kHasDispatchSerial;
		bcopy(&dqserialnum, (char *)telemetry_buffer + telemetry_buffer_current_position, sizeof (dqserialnum));
		telemetry_buffer_current_position += sizeof (dqserialnum);
	}

	if (task_has_64BitAddr(task)) {
		framesize = 8;
		thsnap->ss_flags |= kUser64_p;
	} else {
		framesize = 4;
	}

	btcount = cs.nframes;

	/*
	 * If we can't fit this entire stacktrace then cancel this record, wrap to the beginning,
	 * and start again there so that we always store a full record.
	 */
	if ((telemetry_buffer_size - telemetry_buffer_current_position)/framesize < btcount) {
		telemetry_buffer_end_point = current_record_start;
		telemetry_buffer_current_position = 0;
		goto copytobuffer;
	}

	for (bti=0; bti < btcount; bti++, telemetry_buffer_current_position += framesize) {
		if (framesize == 8) {
			*(uint64_t *)(uintptr_t)(telemetry_buffer + telemetry_buffer_current_position) = cs.frames[bti];
		} else {
			*(uint32_t *)(uintptr_t)(telemetry_buffer + telemetry_buffer_current_position) = (uint32_t)cs.frames[bti];
		}
	}

	if (telemetry_buffer_end_point < telemetry_buffer_current_position) {
		/*
		 * Each time the cursor wraps around to the beginning, we leave a
		 * differing amount of unused space at the end of the buffer. Make
		 * sure the cursor pushes the end point in case we're making use of
		 * more of the buffer than we did the last time we wrapped.
		 */
		telemetry_buffer_end_point = telemetry_buffer_current_position;
	}

	thsnap->nuser_frames = btcount;

	telemetry_bytes_since_last_mark += (telemetry_buffer_current_position - current_record_start);
	if (telemetry_bytes_since_last_mark > telemetry_buffer_notify_at) {
		notify = TRUE;
	}

	TELEMETRY_UNLOCK();

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_STACKSHOT, MICROSTACKSHOT_RECORD) | DBG_FUNC_END, notify, telemetry_bytes_since_last_mark, telemetry_buffer_current_position, telemetry_buffer_end_point, 0);

	if (notify) {
		telemetry_notify_user();
	}

	if (uuid_info_array != NULL) {
		kfree(uuid_info_array, uuid_info_array_size);
	}
}

#if TELEMETRY_DEBUG
static void
log_telemetry_output(vm_offset_t buf, uint32_t pos, uint32_t sz)
{
	struct micro_snapshot *p;
	uint32_t offset;
	
	printf("Copying out %d bytes of telemetry at offset %d\n", sz, pos);

	buf += pos;

	/*
	 * Find and log each timestamp in this chunk of buffer.
	 */
	for (offset = 0; offset < sz; offset++) {
		p = (struct micro_snapshot *)(buf + offset);
		if (p->snapshot_magic == STACKSHOT_MICRO_SNAPSHOT_MAGIC) {
			printf("telemetry timestamp: %lld\n", p->ms_time);
		}
	}
}
#endif

int telemetry_gather(user_addr_t buffer, uint32_t *length, boolean_t mark)
{
	int result = 0;
	uint32_t oldest_record_offset;

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_STACKSHOT, MICROSTACKSHOT_GATHER) | DBG_FUNC_START, mark, telemetry_bytes_since_last_mark, 0, 0, 0);

	TELEMETRY_LOCK();

	if (telemetry_buffer == 0) {
		*length = 0;		
		goto out;
	}

	if (*length < telemetry_buffer_size) {
		result = KERN_NO_SPACE;
		goto out;
	}

	/*
	 * Copy the ring buffer out to userland in order sorted by time: least recent to most recent.
	 * First, we need to search forward from the cursor to find the oldest record in our buffer.
	 */
	oldest_record_offset = telemetry_buffer_current_position;
	do {
		if ((oldest_record_offset == telemetry_buffer_size) ||
		    (oldest_record_offset == telemetry_buffer_end_point)) {

			if (*(uint32_t *)(uintptr_t)(telemetry_buffer) == 0) {
				/*
				 * There is no magic number at the start of the buffer, which means
				 * it's empty; nothing to see here yet.
				 */
				*length = 0;
				goto out;
			}
			/*
			 * We've looked through the end of the active buffer without finding a valid
			 * record; that means all valid records are in a single chunk, beginning at
			 * the very start of the buffer.
			 */

			oldest_record_offset = 0;
			assert(*(uint32_t *)(uintptr_t)(telemetry_buffer) == STACKSHOT_MICRO_SNAPSHOT_MAGIC);
			break;
		}

		if (*(uint32_t *)(uintptr_t)(telemetry_buffer + oldest_record_offset) == STACKSHOT_MICRO_SNAPSHOT_MAGIC)
			break;

		/*
		 * There are no alignment guarantees for micro-stackshot records, so we must search at each
		 * byte offset.
		 */
		oldest_record_offset++;
	} while (oldest_record_offset != telemetry_buffer_current_position);

	/*
	 * If needed, copyout in two chunks: from the oldest record to the end of the buffer, and then
	 * from the beginning of the buffer up to the current position.
	 */
	if (oldest_record_offset != 0) {
#if TELEMETRY_DEBUG
		log_telemetry_output(telemetry_buffer, oldest_record_offset,
		                     telemetry_buffer_end_point - oldest_record_offset);
#endif
		if ((result = copyout((void *)(telemetry_buffer + oldest_record_offset), buffer,
		    telemetry_buffer_end_point - oldest_record_offset)) != 0) {
			*length = 0;
			goto out;
		}
		*length = telemetry_buffer_end_point - oldest_record_offset;
	} else {
		*length = 0;
	}

#if TELEMETRY_DEBUG
	log_telemetry_output(telemetry_buffer, 0, telemetry_buffer_current_position);
#endif
	if ((result = copyout((void *)telemetry_buffer, buffer + *length,
	    telemetry_buffer_current_position)) != 0) {
		*length = 0;
		goto out;
	}
	*length += (uint32_t)telemetry_buffer_current_position;

out:

	if (mark && (*length > 0)) {
		telemetry_bytes_since_last_mark = 0;
	}

	TELEMETRY_UNLOCK();

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_STACKSHOT, MICROSTACKSHOT_GATHER) | DBG_FUNC_END, telemetry_buffer_current_position, *length, telemetry_buffer_end_point, 0, 0);

	return (result);
}

/************************/
/* BOOT PROFILE SUPPORT */
/************************/
/*
 * Boot Profiling
 *
 * The boot-profiling support is a mechanism to sample activity happening on the
 * system during boot. This mechanism sets up a periodic timer and on every timer fire,
 * captures a full backtrace into the boot profiling buffer. This buffer can be pulled
 * out and analyzed from user-space. It is turned on using the following boot-args:
 * "bootprofile_buffer_size" specifies the size of the boot profile buffer
 * "bootprofile_interval_ms" specifies the interval for the profiling timer
 *
 * Process Specific Boot Profiling
 *
 * The boot-arg "bootprofile_proc_name" can be used to specify a certain
 * process that needs to profiled during boot. Setting this boot-arg changes
 * the way stackshots are captured. At every timer fire, the code looks at the
 * currently running process and takes a stackshot only if the requested process
 * is on-core (which makes it unsuitable for MP systems).
 *
 */

#define BOOTPROFILE_MAX_BUFFER_SIZE (64*1024*1024) /* see also COPYSIZELIMIT_PANIC */

vm_offset_t			bootprofile_buffer = 0;
uint32_t			bootprofile_buffer_size = 0;
uint32_t			bootprofile_buffer_current_position = 0;
uint32_t			bootprofile_interval_ms = 0;
uint64_t			bootprofile_interval_abs = 0;
uint64_t			bootprofile_next_deadline = 0;
uint32_t			bootprofile_all_procs = 0;
char				bootprofile_proc_name[17];

lck_grp_t       	bootprofile_lck_grp;
lck_mtx_t       	bootprofile_mtx;

static timer_call_data_t	bootprofile_timer_call_entry;

#define BOOTPROFILE_LOCK() do { lck_mtx_lock(&bootprofile_mtx); } while(0)
#define BOOTPROFILE_TRY_SPIN_LOCK() lck_mtx_try_lock_spin(&bootprofile_mtx)
#define BOOTPROFILE_UNLOCK() do { lck_mtx_unlock(&bootprofile_mtx); } while(0)

static void bootprofile_timer_call(
	timer_call_param_t      param0,
	timer_call_param_t      param1);

extern int  
stack_snapshot_from_kernel(int pid, void *buf, uint32_t size, uint32_t flags, unsigned *retbytes);

void bootprofile_init(void)
{
	kern_return_t ret;

	lck_grp_init(&bootprofile_lck_grp, "bootprofile group", LCK_GRP_ATTR_NULL);
	lck_mtx_init(&bootprofile_mtx, &bootprofile_lck_grp, LCK_ATTR_NULL);

	if (!PE_parse_boot_argn("bootprofile_buffer_size", &bootprofile_buffer_size, sizeof(bootprofile_buffer_size))) {
		bootprofile_buffer_size = 0;
	}

	if (bootprofile_buffer_size > BOOTPROFILE_MAX_BUFFER_SIZE)
		bootprofile_buffer_size = BOOTPROFILE_MAX_BUFFER_SIZE;

	if (!PE_parse_boot_argn("bootprofile_interval_ms", &bootprofile_interval_ms, sizeof(bootprofile_interval_ms))) {
		bootprofile_interval_ms = 0;
	}

	if (!PE_parse_boot_argn("bootprofile_proc_name", &bootprofile_proc_name, sizeof(bootprofile_proc_name))) {
		bootprofile_all_procs = 1;
		bootprofile_proc_name[0] = '\0';
	}

	clock_interval_to_absolutetime_interval(bootprofile_interval_ms, NSEC_PER_MSEC, &bootprofile_interval_abs);

	/* Both boot args must be set to enable */
	if ((bootprofile_buffer_size == 0) || (bootprofile_interval_abs == 0)) {
		return;
	}

	ret = kmem_alloc(kernel_map, &bootprofile_buffer, bootprofile_buffer_size);
	if (ret != KERN_SUCCESS) {
		kprintf("Boot profile: Allocation failed: %d\n", ret);
		return;
	}

	kprintf("Boot profile: Sampling %s once per %u ms\n", bootprofile_all_procs ? "all procs" : bootprofile_proc_name,  bootprofile_interval_ms);

	timer_call_setup(&bootprofile_timer_call_entry,
					 bootprofile_timer_call,
					 NULL);

	bootprofile_next_deadline = mach_absolute_time() + bootprofile_interval_abs;
	timer_call_enter_with_leeway(&bootprofile_timer_call_entry,
								 NULL,
								 bootprofile_next_deadline,
								 0,
								 TIMER_CALL_SYS_NORMAL,
								 FALSE);
}

static void bootprofile_timer_call(
	timer_call_param_t      param0 __unused,
	timer_call_param_t      param1 __unused)
{
	unsigned retbytes = 0;
	int pid_to_profile = -1;

	if (!BOOTPROFILE_TRY_SPIN_LOCK()) {
		goto reprogram;
	}

	/* Check if process-specific boot profiling is turned on */
	if (!bootprofile_all_procs) {
		/*
		 * Since boot profiling initializes really early in boot, it is
		 * possible that at this point, the task/proc is not initialized.
		 * Nothing to do in that case.
		 */

		if ((current_task() != NULL) && (current_task()->bsd_info != NULL) &&
		    (0 == strncmp(bootprofile_proc_name, proc_name_address(current_task()->bsd_info), 17))) {
			pid_to_profile = proc_selfpid();
		}
		else {
			/*
			 * Process-specific boot profiling requested but the on-core process is
			 * something else. Nothing to do here.
			 */
			BOOTPROFILE_UNLOCK();
			goto reprogram;
		}
	}

	/* initiate a stackshot with whatever portion of the buffer is left */
	if (bootprofile_buffer_current_position < bootprofile_buffer_size) {
		stack_snapshot_from_kernel(
			pid_to_profile,
			(void *)(bootprofile_buffer + bootprofile_buffer_current_position),
			bootprofile_buffer_size - bootprofile_buffer_current_position,
			STACKSHOT_SAVE_LOADINFO | STACKSHOT_SAVE_KEXT_LOADINFO | STACKSHOT_GET_GLOBAL_MEM_STATS,
            &retbytes
			);

		bootprofile_buffer_current_position += retbytes;
	}

	BOOTPROFILE_UNLOCK();

	/* If we didn't get any data or have run out of buffer space, stop profiling */
	if ((retbytes == 0) || (bootprofile_buffer_current_position == bootprofile_buffer_size)) {
		return;
	}


reprogram:
	/* If the user gathered the buffer, no need to keep profiling */
	if (bootprofile_interval_abs == 0) {
		return;
	}

	clock_deadline_for_periodic_event(bootprofile_interval_abs,
									  mach_absolute_time(),
									  &bootprofile_next_deadline);
	timer_call_enter_with_leeway(&bootprofile_timer_call_entry,
								 NULL,
								 bootprofile_next_deadline,
								 0,
								 TIMER_CALL_SYS_NORMAL,
								 FALSE);
}

int bootprofile_gather(user_addr_t buffer, uint32_t *length)
{
	int result = 0;

	BOOTPROFILE_LOCK();

	if (bootprofile_buffer == 0) {
		*length = 0;		
		goto out;
	}

	if (*length < bootprofile_buffer_current_position) {
		result = KERN_NO_SPACE;
		goto out;
	}

	if ((result = copyout((void *)bootprofile_buffer, buffer,
	    bootprofile_buffer_current_position)) != 0) {
		*length = 0;
		goto out;
	}
	*length = bootprofile_buffer_current_position;

	/* cancel future timers */
	bootprofile_interval_abs = 0;

out:

	BOOTPROFILE_UNLOCK();

	return (result);
}
