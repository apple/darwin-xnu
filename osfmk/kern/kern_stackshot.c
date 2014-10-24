/*
 * Copyright (c) 2013 Apple Inc. All rights reserved.
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

#include <mach/mach_types.h>
#include <mach/vm_param.h>
#ifdef IMPORTANCE_INHERITANCE
#include <ipc/ipc_importance.h>
#endif
#include <sys/appleapiopts.h>
#include <kern/debug.h>
#include <uuid/uuid.h>

#include <kdp/kdp_dyld.h>
#include <kdp/kdp_en_debugger.h>

#include <libsa/types.h>
#include <libkern/version.h>

#include <string.h> /* bcopy */

#include <kern/processor.h>
#include <kern/thread.h>
#include <kern/clock.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_pageout.h>
#include <vm/vm_shared_region.h>
#include <libkern/OSKextLibPrivate.h>

extern unsigned int not_in_kdp;

/*
 * TODO: Even hackier than the other pieces.  This should really
 * be moved off of kdp_pmap, and we should probably separate
 * machine_trace_thread out of the kdp code.
 */
extern pmap_t kdp_pmap;
extern addr64_t kdp_vtophys(pmap_t pmap, addr64_t va);

int kdp_snapshot = 0;
static int stack_snapshot_ret = 0;
static unsigned stack_snapshot_bytes_traced = 0;

static void *stack_snapshot_buf;
static uint32_t stack_snapshot_bufsize;
int stack_snapshot_pid;
static uint32_t stack_snapshot_flags;
static uint32_t stack_snapshot_dispatch_offset;
static unsigned int old_debugger;

void 			do_stackshot(void);
void			kdp_snapshot_preflight(int pid, void * tracebuf, uint32_t tracebuf_size,
    				uint32_t flags, uint32_t dispatch_offset);
void			kdp_snapshot_postflight(void);
static int		kdp_stackshot(int pid, void *tracebuf, uint32_t tracebuf_size,
    				uint32_t flags, uint32_t dispatch_offset, uint32_t *pbytesTraced);
int			kdp_stack_snapshot_geterror(void);
int			kdp_stack_snapshot_bytes_traced(void);
int 			kdp_stackshot(int pid, void *tracebuf, uint32_t tracebuf_size, uint32_t trace_flags, uint32_t dispatch_offset, uint32_t *pbytesTraced);
static int 		pid_from_task(task_t task);
static uint64_t 	proc_uniqueid_from_task(task_t task);
static void		kdp_mem_and_io_snapshot(struct mem_and_io_snapshot *memio_snap);
static boolean_t	kdp_copyin(pmap_t p, uint64_t uaddr, void *dest, size_t size);
static uint64_t		proc_was_throttled_from_task(task_t task);

extern int		proc_pid(void *p);
extern uint64_t		proc_uniqueid(void *p);
extern uint64_t		proc_was_throttled(void *p);
extern uint64_t		proc_did_throttle(void *p);
static uint64_t		proc_did_throttle_from_task(task_t task);
extern void		proc_name_kdp(task_t  task, char *buf, int size);
extern int		proc_threadname_kdp(void *uth, char *buf, size_t size);
extern void		proc_starttime_kdp(void *p, uint64_t *tv_sec, uint64_t *tv_usec);

extern int 		count_busy_buffers(void);   /* must track with declaration in bsd/sys/buf_internal.h */
extern void 		bcopy_phys(addr64_t, addr64_t, vm_size_t);
extern int		machine_trace_thread(thread_t thread, char *tracepos, char *tracebound, int nframes, boolean_t user_p);
extern int		machine_trace_thread64(thread_t thread, char *tracepos, char *tracebound, int nframes, boolean_t user_p);

/* Validates that the given address is both a valid page and has
 * default caching attributes for the current kdp_pmap.  Returns
 * 0 if the address is invalid, and a kernel virtual address for
 * the given address if it is valid.
 */
vm_offset_t machine_trace_thread_get_kva(vm_offset_t cur_target_addr);

/* Clears caching information used by the above validation routine
 * (in case the kdp_pmap has been changed or cleared).
 */
void machine_trace_thread_clear_validation_cache(void);

#define MAX_FRAMES 1000

typedef struct thread_snapshot *thread_snapshot_t;
typedef struct task_snapshot *task_snapshot_t;

#if CONFIG_KDP_INTERACTIVE_DEBUGGING
extern kdp_send_t    kdp_en_send_pkt;
#endif 

/*
 * Globals to support machine_trace_thread_get_kva.
 */
static vm_offset_t prev_target_page = 0;
static vm_offset_t prev_target_kva = 0;
static boolean_t validate_next_addr = TRUE;


/* 
 * Method for grabbing timer values safely, in the sense that no infinite loop will occur 
 * Certain flavors of the timer_grab function, which would seem to be the thing to use,   
 * can loop infinitely if called while the timer is in the process of being updated.      
 * Unfortunately, it is (rarely) possible to get inconsistent top and bottom halves of    
 * the timer using this method. This seems insoluble, since stackshot runs in a context   
 * where the timer might be half-updated, and has no way of yielding control just long    
 * enough to finish the update.                                                           
 */

static uint64_t safe_grab_timer_value(struct timer *t)
{
#if   defined(__LP64__)
  return t->all_bits;
#else
  uint64_t time = t->high_bits;    /* endian independent grab */
  time = (time << 32) | t->low_bits;
  return time;
#endif
}

/* Cache stack snapshot parameters in preparation for a trace */
void
kdp_snapshot_preflight(int pid, void * tracebuf, uint32_t tracebuf_size, uint32_t flags, uint32_t dispatch_offset)
{
	stack_snapshot_pid = pid;
	stack_snapshot_buf = tracebuf;
	stack_snapshot_bufsize = tracebuf_size;
	stack_snapshot_flags = flags;
	stack_snapshot_dispatch_offset = dispatch_offset;
	kdp_snapshot++;
	/* Mark this debugger as active, since the polled mode driver that 
	 * ordinarily does this may not be enabled (yet), or since KDB may be
	 * the primary debugger.
	 */
	old_debugger = current_debugger;
	if (old_debugger != KDP_CUR_DB) {
		current_debugger = KDP_CUR_DB;
	}
}

void
kdp_snapshot_postflight(void)
{
	kdp_snapshot--;
#if CONFIG_KDP_INTERACTIVE_DEBUGGING
	if (
			(kdp_en_send_pkt == NULL) || (old_debugger == KDB_CUR_DB))
		current_debugger = old_debugger;
#else 
	current_debugger = old_debugger;
#endif 
}

int
kdp_stack_snapshot_geterror(void)
{
	return stack_snapshot_ret;
}

int
kdp_stack_snapshot_bytes_traced(void)
{
	return stack_snapshot_bytes_traced;
}

static int
kdp_stackshot(int pid, void *tracebuf, uint32_t tracebuf_size, uint32_t trace_flags, uint32_t dispatch_offset, uint32_t *pbytesTraced)
{
	char *tracepos = (char *) tracebuf;
	char *tracebound = tracepos + tracebuf_size;
	uint32_t tracebytes = 0;
	int error = 0, i;

	task_t task = TASK_NULL;
	thread_t thread = THREAD_NULL;
	unsigned framesize = 2 * sizeof(vm_offset_t);

	queue_head_t *task_list = &tasks;
	boolean_t is_active_list = TRUE;
	
	boolean_t dispatch_p = ((trace_flags & STACKSHOT_GET_DQ) != 0);
	boolean_t save_loadinfo_p = ((trace_flags & STACKSHOT_SAVE_LOADINFO) != 0);
	boolean_t save_kextloadinfo_p = ((trace_flags & STACKSHOT_SAVE_KEXT_LOADINFO) != 0);
	boolean_t save_userframes_p = ((trace_flags & STACKSHOT_SAVE_KERNEL_FRAMES_ONLY) == 0);
	boolean_t save_donating_pids_p = ((trace_flags & STACKSHOT_SAVE_IMP_DONATION_PIDS) != 0);

	if(trace_flags & STACKSHOT_GET_GLOBAL_MEM_STATS) {
	  if(tracepos + sizeof(struct mem_and_io_snapshot) > tracebound) {
	    error = -1;
	    goto error_exit;
	  }
	  kdp_mem_and_io_snapshot((struct mem_and_io_snapshot *)tracepos);
	  tracepos += sizeof(struct mem_and_io_snapshot);
	}
	

walk_list:
	queue_iterate(task_list, task, task_t, tasks) {
		if ((task == NULL) || !ml_validate_nofault((vm_offset_t) task, sizeof(struct task)))
			goto error_exit;

		int task_pid = pid_from_task(task);
		uint64_t task_uniqueid = proc_uniqueid_from_task(task);
		boolean_t task64 = task_has_64BitAddr(task);

		if (!task->active) {
			/* 
			 * Not interested in terminated tasks without threads, and
			 * at the moment, stackshot can't handle a task  without a name.
			 */
			if (queue_empty(&task->threads) || task_pid == -1) {
				continue;
			}
		}

		/* Trace everything, unless a process was specified */
		if ((pid == -1) || (pid == task_pid)) {
			task_snapshot_t task_snap;
			thread_snapshot_t tsnap = NULL;
			uint32_t uuid_info_count = 0;
			mach_vm_address_t uuid_info_addr = 0;
			boolean_t have_map = (task->map != NULL) && 
				(ml_validate_nofault((vm_offset_t)(task->map), sizeof(struct _vm_map)));
			boolean_t have_pmap = have_map && (task->map->pmap != NULL) &&
				(ml_validate_nofault((vm_offset_t)(task->map->pmap), sizeof(struct pmap)));
			uint64_t shared_cache_base_address = 0;

			if (have_pmap && task->active && save_loadinfo_p && task_pid > 0) {
				// Read the dyld_all_image_infos struct from the task memory to get UUID array count and location
				if (task64) {
					struct user64_dyld_all_image_infos task_image_infos;
					if (kdp_copyin(task->map->pmap, task->all_image_info_addr, &task_image_infos, sizeof(struct user64_dyld_all_image_infos))) {
						uuid_info_count = (uint32_t)task_image_infos.uuidArrayCount;
						uuid_info_addr = task_image_infos.uuidArray;
					}
				} else {
					struct user32_dyld_all_image_infos task_image_infos;
					if (kdp_copyin(task->map->pmap, task->all_image_info_addr, &task_image_infos, sizeof(struct user32_dyld_all_image_infos))) {
						uuid_info_count = task_image_infos.uuidArrayCount;
						uuid_info_addr = task_image_infos.uuidArray;
					}
				}

				// If we get a NULL uuid_info_addr (which can happen when we catch dyld in the middle of updating
				// this data structure), we zero the uuid_info_count so that we won't even try to save load info
				// for this task.
				if (!uuid_info_addr) {
					uuid_info_count = 0;
				}
			}

			if (have_pmap && save_kextloadinfo_p && task_pid == 0) {
				if (ml_validate_nofault((vm_offset_t)(gLoadedKextSummaries), sizeof(OSKextLoadedKextSummaryHeader))) {
					uuid_info_count = gLoadedKextSummaries->numSummaries + 1; /* include main kernel UUID */
				}
			}

			if (tracepos + sizeof(struct task_snapshot) > tracebound) {
				error = -1;
				goto error_exit;
			}

			task_snap = (task_snapshot_t) tracepos;
			task_snap->snapshot_magic = STACKSHOT_TASK_SNAPSHOT_MAGIC;
			task_snap->pid = task_pid;
			task_snap->uniqueid = task_uniqueid;
			task_snap->nloadinfos = uuid_info_count;
			task_snap->donating_pid_count = 0;

			/* Add the BSD process identifiers */
			if (task_pid != -1)
				proc_name_kdp(task, task_snap->p_comm, sizeof(task_snap->p_comm));
			else
				task_snap->p_comm[0] = '\0';
			task_snap->ss_flags = 0;
			if (task64)
				task_snap->ss_flags |= kUser64_p;
			if (task64 && task_pid == 0)
				task_snap->ss_flags |= kKernel64_p;
			if (!task->active) 
				task_snap->ss_flags |= kTerminatedSnapshot;
			if(task->pidsuspended) task_snap->ss_flags |= kPidSuspended;
			if(task->frozen) task_snap->ss_flags |= kFrozen;

			if (task->effective_policy.darwinbg == 1) {
				task_snap->ss_flags |= kTaskDarwinBG;
			}
			
			if (task->requested_policy.t_role == TASK_FOREGROUND_APPLICATION) {
				task_snap->ss_flags |= kTaskIsForeground;
			}

			if (task->requested_policy.t_boosted == 1) {
				task_snap->ss_flags |= kTaskIsBoosted;
			}

			if (task->effective_policy.t_sup_active == 1)
				task_snap->ss_flags |= kTaskIsSuppressed;
#if IMPORTANCE_INHERITANCE
			if (task->task_imp_base) {
				if (task->task_imp_base->iit_donor) {
					task_snap->ss_flags |= kTaskIsImpDonor;
}

				if (task->task_imp_base->iit_live_donor) {
					task_snap->ss_flags |= kTaskIsLiveImpDonor;
				}
			}
#endif

			task_snap->latency_qos = (task->effective_policy.t_latency_qos == LATENCY_QOS_TIER_UNSPECIFIED) ?
			                         LATENCY_QOS_TIER_UNSPECIFIED : ((0xFF << 16) | task->effective_policy.t_latency_qos);

			task_snap->suspend_count = task->suspend_count;
			task_snap->task_size = have_pmap ? pmap_resident_count(task->map->pmap) : 0;
			task_snap->faults = task->faults;
			task_snap->pageins = task->pageins;
			task_snap->cow_faults = task->cow_faults;

			task_snap->user_time_in_terminated_threads = task->total_user_time;
			task_snap->system_time_in_terminated_threads = task->total_system_time;
			/*
			 * The throttling counters are maintained as 64-bit counters in the proc
			 * structure. However, we reserve 32-bits (each) for them in the task_snapshot
			 * struct to save space and since we do not expect them to overflow 32-bits. If we
			 * find these values overflowing in the future, the fix would be to simply 
			 * upgrade these counters to 64-bit in the task_snapshot struct
			 */
			task_snap->was_throttled = (uint32_t) proc_was_throttled_from_task(task);
			task_snap->did_throttle = (uint32_t) proc_did_throttle_from_task(task);

			/* fetch some useful BSD info: */
			task_snap->p_start_sec = task_snap->p_start_usec = 0;
			proc_starttime_kdp(task->bsd_info, &task_snap->p_start_sec, &task_snap->p_start_usec);
			if (task->shared_region && ml_validate_nofault((vm_offset_t)task->shared_region,
														   sizeof(struct vm_shared_region))) {
				struct vm_shared_region *sr = task->shared_region;

				shared_cache_base_address = sr->sr_base_address + sr->sr_first_mapping;
			}
			if (!shared_cache_base_address
				|| !kdp_copyin(task->map->pmap, shared_cache_base_address + offsetof(struct _dyld_cache_header, uuid), task_snap->shared_cache_identifier, sizeof(task_snap->shared_cache_identifier))) {
				memset(task_snap->shared_cache_identifier, 0x0, sizeof(task_snap->shared_cache_identifier));
			}
			if (task->shared_region) {
				/*
				 * No refcounting here, but we are in debugger
				 * context, so that should be safe.
				 */
				task_snap->shared_cache_slide = task->shared_region->sr_slide_info.slide;
			} else {
				task_snap->shared_cache_slide = 0;
			}

			/* I/O Statistics */
			assert(IO_NUM_PRIORITIES == STACKSHOT_IO_NUM_PRIORITIES);

			if (task->task_io_stats) {
				task_snap->disk_reads_count = task->task_io_stats->disk_reads.count;
				task_snap->disk_reads_size = task->task_io_stats->disk_reads.size;
				task_snap->disk_writes_count = (task->task_io_stats->total_io.count - task->task_io_stats->disk_reads.count);
				task_snap->disk_writes_size = (task->task_io_stats->total_io.size - task->task_io_stats->disk_reads.size);
				for(i = 0; i < IO_NUM_PRIORITIES; i++) {
					task_snap->io_priority_count[i] = task->task_io_stats->io_priority[i].count;
					task_snap->io_priority_size[i] = task->task_io_stats->io_priority[i].size;
				}
				task_snap->paging_count = task->task_io_stats->paging.count;
				task_snap->paging_size = task->task_io_stats->paging.size;
				task_snap->non_paging_count = (task->task_io_stats->total_io.count - task->task_io_stats->paging.count);
				task_snap->non_paging_size = (task->task_io_stats->total_io.size - task->task_io_stats->paging.size);
				task_snap->metadata_count = task->task_io_stats->metadata.count;
				task_snap->metadata_size = task->task_io_stats->metadata.size;
				task_snap->data_count = (task->task_io_stats->total_io.count - task->task_io_stats->metadata.count);
				task_snap->data_size = (task->task_io_stats->total_io.size - task->task_io_stats->metadata.size);
			} else {
				/* zero from disk_reads_count to end of structure */
				memset(&task_snap->disk_reads_count, 0, offsetof(struct task_snapshot, metadata_size) - offsetof(struct task_snapshot, disk_reads_count)); 
			}
			tracepos += sizeof(struct task_snapshot);

			if (task_pid > 0 && uuid_info_count > 0) {
				uint32_t uuid_info_size = (uint32_t)(task64 ? sizeof(struct user64_dyld_uuid_info) : sizeof(struct user32_dyld_uuid_info));
				uint32_t uuid_info_array_size = uuid_info_count * uuid_info_size;

				if (tracepos + uuid_info_array_size > tracebound) {
					error = -1;
					goto error_exit;
				}

				// Copy in the UUID info array
				// It may be nonresident, in which case just fix up nloadinfos to 0 in the task_snap
				if (have_pmap && !kdp_copyin(task->map->pmap, uuid_info_addr, tracepos, uuid_info_array_size))
					task_snap->nloadinfos = 0;
				else
					tracepos += uuid_info_array_size;
			} else if (task_pid == 0 && uuid_info_count > 0) {
				uint32_t uuid_info_size = (uint32_t)sizeof(kernel_uuid_info);
				uint32_t uuid_info_array_size = uuid_info_count * uuid_info_size;
				kernel_uuid_info *output_uuids;

				if (tracepos + uuid_info_array_size > tracebound) {
					error = -1;
					goto error_exit;
				}

				output_uuids = (kernel_uuid_info *)tracepos;

				do {

					if (!kernel_uuid || !ml_validate_nofault((vm_offset_t)kernel_uuid, sizeof(uuid_t))) {
						/* Kernel UUID not found or inaccessible */
						task_snap->nloadinfos = 0;
						break;
					}

					output_uuids[0].imageLoadAddress = (uintptr_t)VM_KERNEL_UNSLIDE(vm_kernel_stext);
					memcpy(&output_uuids[0].imageUUID, kernel_uuid, sizeof(uuid_t));

					if (ml_validate_nofault((vm_offset_t)(&gLoadedKextSummaries->summaries[0]),
											gLoadedKextSummaries->entry_size * gLoadedKextSummaries->numSummaries)) {
						uint32_t kexti;

						for (kexti=0 ; kexti < gLoadedKextSummaries->numSummaries; kexti++) {
							output_uuids[1+kexti].imageLoadAddress = (uintptr_t)VM_KERNEL_UNSLIDE(gLoadedKextSummaries->summaries[kexti].address);
							memcpy(&output_uuids[1+kexti].imageUUID, &gLoadedKextSummaries->summaries[kexti].uuid, sizeof(uuid_t));
						}

						tracepos += uuid_info_array_size;
					} else {
						/* kext summary invalid, but kernel UUID was copied */
						task_snap->nloadinfos = 1;
						tracepos += uuid_info_size;
						break;
					}
				} while(0);
			}
			
			if (save_donating_pids_p) {
				task_snap->donating_pid_count = task_importance_list_pids(task, TASK_IMP_LIST_DONATING_PIDS, (int *)tracepos, (unsigned int)((tracebound - tracepos)/sizeof(int)));
				tracepos += sizeof(int) * task_snap->donating_pid_count;
			}

			queue_iterate(&task->threads, thread, thread_t, task_threads){
				uint64_t tval;

				if ((thread == NULL) || !ml_validate_nofault((vm_offset_t) thread, sizeof(struct thread)))
					goto error_exit;

				if (((tracepos + 4 * sizeof(struct thread_snapshot)) > tracebound)) {
					error = -1;
					goto error_exit;
				}
                if (!save_userframes_p && thread->kernel_stack == 0)
                    continue;

				/* Populate the thread snapshot header */
				tsnap = (thread_snapshot_t) tracepos;
				tsnap->thread_id = thread_tid(thread);
				tsnap->state = thread->state;
				tsnap->priority = thread->priority;
				tsnap->sched_pri = thread->sched_pri;
				tsnap->sched_flags = thread->sched_flags;
				tsnap->wait_event = VM_KERNEL_UNSLIDE_OR_PERM(thread->wait_event);
				tsnap->continuation = VM_KERNEL_UNSLIDE(thread->continuation);
				tval = safe_grab_timer_value(&thread->user_timer);
				tsnap->user_time = tval;
				tval = safe_grab_timer_value(&thread->system_timer);
				if (thread->precise_user_kernel_time) {
					tsnap->system_time = tval;
				} else {
					tsnap->user_time += tval;
					tsnap->system_time = 0;
				}
				tsnap->snapshot_magic = STACKSHOT_THREAD_SNAPSHOT_MAGIC;
				bzero(&tsnap->pth_name, STACKSHOT_MAX_THREAD_NAME_SIZE);
				proc_threadname_kdp(thread->uthread, &tsnap->pth_name[0], STACKSHOT_MAX_THREAD_NAME_SIZE);
				tracepos += sizeof(struct thread_snapshot);
				tsnap->ss_flags = 0;
				/* I/O Statistics */
				assert(IO_NUM_PRIORITIES == STACKSHOT_IO_NUM_PRIORITIES);
				if (thread->thread_io_stats) {
					tsnap->disk_reads_count = thread->thread_io_stats->disk_reads.count;
					tsnap->disk_reads_size = thread->thread_io_stats->disk_reads.size;
					tsnap->disk_writes_count = (thread->thread_io_stats->total_io.count - thread->thread_io_stats->disk_reads.count);
					tsnap->disk_writes_size = (thread->thread_io_stats->total_io.size - thread->thread_io_stats->disk_reads.size);
					for(i = 0; i < IO_NUM_PRIORITIES; i++) {
						tsnap->io_priority_count[i] = thread->thread_io_stats->io_priority[i].count;
						tsnap->io_priority_size[i] = thread->thread_io_stats->io_priority[i].size;
					}
					tsnap->paging_count = thread->thread_io_stats->paging.count;
					tsnap->paging_size = thread->thread_io_stats->paging.size;
					tsnap->non_paging_count = (thread->thread_io_stats->total_io.count - thread->thread_io_stats->paging.count);
					tsnap->non_paging_size = (thread->thread_io_stats->total_io.size - thread->thread_io_stats->paging.size);
					tsnap->metadata_count = thread->thread_io_stats->metadata.count;
					tsnap->metadata_size = thread->thread_io_stats->metadata.size;
					tsnap->data_count = (thread->thread_io_stats->total_io.count - thread->thread_io_stats->metadata.count);
					tsnap->data_size = (thread->thread_io_stats->total_io.size - thread->thread_io_stats->metadata.size);
				} else {
					/* zero from disk_reads_count to end of structure */
					memset(&tsnap->disk_reads_count, 0, 
						offsetof(struct thread_snapshot, metadata_size) - offsetof(struct thread_snapshot, disk_reads_count));
				}

				if (thread->effective_policy.darwinbg) {
					tsnap->ss_flags |= kThreadDarwinBG;
				}
				
				tsnap->io_tier = proc_get_effective_thread_policy(thread, TASK_POLICY_IO);
				if (proc_get_effective_thread_policy(thread, TASK_POLICY_PASSIVE_IO)) {
					tsnap->ss_flags |= kThreadIOPassive;
				}
				
				if (thread->suspend_count > 0) {
					tsnap->ss_flags |= kThreadSuspended;
				}
				if (IPC_VOUCHER_NULL != thread->ith_voucher) {
					tsnap->voucher_identifier = VM_KERNEL_ADDRPERM(thread->ith_voucher);
				}

				tsnap->ts_qos = thread->effective_policy.thep_qos;
				tsnap->total_syscalls = thread->syscalls_mach + thread->syscalls_unix;

				if (dispatch_p && (task != kernel_task) && (task->active) && have_pmap) {
					uint64_t dqkeyaddr = thread_dispatchqaddr(thread);
					if (dqkeyaddr != 0) {
						uint64_t dqaddr = 0;
						if (kdp_copyin(task->map->pmap, dqkeyaddr, &dqaddr, (task64 ? 8 : 4)) && (dqaddr != 0)) {
							uint64_t dqserialnumaddr = dqaddr + dispatch_offset;
							uint64_t dqserialnum = 0;
							if (kdp_copyin(task->map->pmap, dqserialnumaddr, &dqserialnum, (task64 ? 8 : 4))) {
								tsnap->ss_flags |= kHasDispatchSerial;
								*(uint64_t *)tracepos = dqserialnum;
								tracepos += 8;
							}
						}
					}
				}
/* Call through to the machine specific trace routines
 * Frames are added past the snapshot header.
 */
				tracebytes = 0;
				if (thread->kernel_stack != 0) {
#if defined(__LP64__)					
					tracebytes = machine_trace_thread64(thread, tracepos, tracebound, MAX_FRAMES, FALSE);
					tsnap->ss_flags |= kKernel64_p;
					framesize = 16;
#else
					tracebytes = machine_trace_thread(thread, tracepos, tracebound, MAX_FRAMES, FALSE);
					framesize = 8;
#endif
				}
				tsnap->nkern_frames = tracebytes/framesize;
				tracepos += tracebytes;
				tracebytes = 0;
				/* Trace user stack, if any */
				if (save_userframes_p && task->active && thread->task->map != kernel_map) {
					/* 64-bit task? */
					if (task_has_64BitAddr(thread->task)) {
						tracebytes = machine_trace_thread64(thread, tracepos, tracebound, MAX_FRAMES, TRUE);
						tsnap->ss_flags |= kUser64_p;
						framesize = 16;
					}
					else {
						tracebytes = machine_trace_thread(thread, tracepos, tracebound, MAX_FRAMES, TRUE);
						framesize = 8;
					}
				}
				tsnap->nuser_frames = tracebytes/framesize;
				tracepos += tracebytes;
				tracebytes = 0;
			}

            if (!save_userframes_p && tsnap == NULL) {
                /*
                 * No thread info is collected due to lack of kernel frames.
                 * Remove information about this task also
                 */
                tracepos = (char *)task_snap;
            }
		}
	}

	if (is_active_list) { 
		is_active_list = FALSE;
		task_list = &terminated_tasks;
		goto walk_list;
	}

error_exit:
	/* Release stack snapshot wait indicator */
	kdp_snapshot_postflight();

	*pbytesTraced = (uint32_t)(tracepos - (char *) tracebuf);

	return error;
}

static int pid_from_task(task_t task)
{
	int pid = -1;

	if (task->bsd_info)
		pid = proc_pid(task->bsd_info);

	return pid;
}

static uint64_t
proc_uniqueid_from_task(task_t task)
{
	uint64_t uniqueid = ~(0ULL);

	if (task->bsd_info)
		uniqueid = proc_uniqueid(task->bsd_info);

	return uniqueid;
}

static uint64_t
proc_was_throttled_from_task(task_t task)
{
	uint64_t was_throttled = 0;

	if (task->bsd_info)
		was_throttled = proc_was_throttled(task->bsd_info);
	
	return was_throttled;
}

static uint64_t
proc_did_throttle_from_task(task_t task)
{
	uint64_t did_throttle = 0;

	if (task->bsd_info)
		did_throttle = proc_did_throttle(task->bsd_info);
	
	return did_throttle;
}

static void
kdp_mem_and_io_snapshot(struct mem_and_io_snapshot *memio_snap)
{
	unsigned int pages_reclaimed;
	unsigned int pages_wanted;
	kern_return_t kErr;

	processor_t processor;
	vm_statistics64_t stat;
	vm_statistics64_data_t host_vm_stat;

	processor = processor_list;
	stat = &PROCESSOR_DATA(processor, vm_stat);
	host_vm_stat = *stat;

	if (processor_count > 1) {
		/*
		 * processor_list may be in the process of changing as we are
		 * attempting a stackshot.  Ordinarily it will be lock protected,
		 * but it is not safe to lock in the context of the debugger.
		 * Fortunately we never remove elements from the processor list,
		 * and only add to to the end of the list, so we SHOULD be able
		 * to walk it.  If we ever want to truly tear down processors,
		 * this will have to change.
		 */
		while ((processor = processor->processor_list) != NULL) {
			stat = &PROCESSOR_DATA(processor, vm_stat);
			host_vm_stat.compressions += stat->compressions;
			host_vm_stat.decompressions += stat->decompressions;
		}
	}

	memio_snap->snapshot_magic = STACKSHOT_MEM_AND_IO_SNAPSHOT_MAGIC;
	memio_snap->free_pages = vm_page_free_count;
	memio_snap->active_pages = vm_page_active_count;
	memio_snap->inactive_pages = vm_page_inactive_count;
	memio_snap->purgeable_pages = vm_page_purgeable_count;
	memio_snap->wired_pages = vm_page_wire_count;
	memio_snap->speculative_pages = vm_page_speculative_count;
	memio_snap->throttled_pages = vm_page_throttled_count;
	memio_snap->busy_buffer_count = count_busy_buffers();
	memio_snap->filebacked_pages = vm_page_pageable_external_count;
	memio_snap->compressions = (uint32_t)host_vm_stat.compressions;
	memio_snap->decompressions = (uint32_t)host_vm_stat.decompressions;
	memio_snap->compressor_size = VM_PAGE_COMPRESSOR_COUNT;
	kErr = mach_vm_pressure_monitor(FALSE, VM_PRESSURE_TIME_WINDOW, &pages_reclaimed, &pages_wanted);

	if ( ! kErr ) {
		memio_snap->pages_wanted = (uint32_t)pages_wanted;
		memio_snap->pages_reclaimed = (uint32_t)pages_reclaimed;
		memio_snap->pages_wanted_reclaimed_valid = 1;
	} else {
		memio_snap->pages_wanted = 0;
		memio_snap->pages_reclaimed = 0;
		memio_snap->pages_wanted_reclaimed_valid = 0;
	}
}

boolean_t
kdp_copyin(pmap_t p, uint64_t uaddr, void *dest, size_t size) 
{
	size_t rem = size;
	char *kvaddr = dest;

	while (rem) {
		ppnum_t upn = pmap_find_phys(p, uaddr);
		uint64_t phys_src = ptoa_64(upn) | (uaddr & PAGE_MASK);
		uint64_t phys_dest = kvtophys((vm_offset_t)kvaddr);
		uint64_t src_rem = PAGE_SIZE - (phys_src & PAGE_MASK);
		uint64_t dst_rem = PAGE_SIZE - (phys_dest & PAGE_MASK);
		size_t cur_size = (uint32_t) MIN(src_rem, dst_rem);
		cur_size = MIN(cur_size, rem);

		if (upn && pmap_valid_page(upn) && phys_dest) {
			bcopy_phys(phys_src, phys_dest, cur_size);
		}
		else
			break;
		uaddr += cur_size;
		kvaddr += cur_size;
		rem -= cur_size;	
	}
	return (rem == 0);
}

void
do_stackshot()
{
    stack_snapshot_ret = kdp_stackshot(stack_snapshot_pid,
	    stack_snapshot_buf, stack_snapshot_bufsize,
	    stack_snapshot_flags, stack_snapshot_dispatch_offset, 
		&stack_snapshot_bytes_traced);

}

/*
 * A fantastical routine that tries to be fast about returning
 * translations.  Caches the last page we found a translation
 * for, so that we can be quick about multiple queries to the
 * same page.  It turns out this is exactly the workflow
 * machine_trace_thread and its relatives tend to throw at us.
 *
 * Please zero the nasty global this uses after a bulk lookup;
 * this isn't safe across a switch of the kdp_pmap or changes
 * to a pmap.
 *
 * This also means that if zero is a valid KVA, we are
 * screwed.  Sucks to be us.  Fortunately, this should never
 * happen.
 */
vm_offset_t
machine_trace_thread_get_kva(vm_offset_t cur_target_addr)
{
	unsigned cur_wimg_bits;
	vm_offset_t cur_target_page;
	vm_offset_t cur_phys_addr;
	vm_offset_t kern_virt_target_addr;

	cur_target_page = atop(cur_target_addr);

	if ((cur_target_page != prev_target_page) || validate_next_addr) {
		/*
		 * Alright; it wasn't our previous page.  So
		 * we must validate that there is a page
		 * table entry for this address under the
		 * current kdp_pmap, and that it has default
		 * cache attributes (otherwise it may not be
		 * safe to access it).
		 */
		cur_phys_addr = kdp_vtophys(kdp_pmap ? kdp_pmap : kernel_pmap, cur_target_addr);

		if (!pmap_valid_page((ppnum_t) atop(cur_phys_addr))) {
			return 0;
		}

		cur_wimg_bits = pmap_cache_attributes((ppnum_t) atop(cur_phys_addr));

		if ((cur_wimg_bits & VM_WIMG_MASK) != VM_WIMG_DEFAULT) {
			return 0;
		}

#if __x86_64__
		kern_virt_target_addr = (vm_offset_t) PHYSMAP_PTOV(cur_phys_addr);
#else
#error Oh come on... we should really unify the physical -> kernel virtual interface
#endif
		prev_target_page = cur_target_page;
		prev_target_kva = (kern_virt_target_addr & ~PAGE_MASK);
		validate_next_addr = FALSE;
		return kern_virt_target_addr;
	} else {
		/* We found a translation, so stash this page */
		kern_virt_target_addr = prev_target_kva + (cur_target_addr & PAGE_MASK);
		return kern_virt_target_addr;
	}
}

void
machine_trace_thread_clear_validation_cache(void)
{
	validate_next_addr = TRUE;
}

