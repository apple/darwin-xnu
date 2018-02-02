/*
 * Copyright (c) 2013-2017 Apple Inc. All rights reserved.
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
#include <mach/mach_vm.h>
#include <mach/clock_types.h>
#include <sys/errno.h>
#include <sys/stackshot.h>
#ifdef IMPORTANCE_INHERITANCE
#include <ipc/ipc_importance.h>
#endif
#include <sys/appleapiopts.h>
#include <kern/debug.h>
#include <kern/block_hint.h>
#include <uuid/uuid.h>

#include <kdp/kdp_dyld.h>
#include <kdp/kdp_en_debugger.h>

#include <libsa/types.h>
#include <libkern/version.h>

#include <string.h> /* bcopy */

#include <kern/coalition.h>
#include <kern/processor.h>
#include <kern/thread.h>
#include <kern/thread_group.h>
#include <kern/task.h>
#include <kern/telemetry.h>
#include <kern/clock.h>
#include <kern/policy_internal.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_pageout.h>
#include <vm/vm_fault.h>
#include <vm/vm_shared_region.h>
#include <libkern/OSKextLibPrivate.h>

#if CONFIG_EMBEDDED
#include <pexpert/pexpert.h> /* For gPanicBase/gPanicBase */
#endif

#if MONOTONIC
#include <kern/monotonic.h>
#endif /* MONOTONIC */

#include <san/kasan.h>

extern unsigned int not_in_kdp;

#if CONFIG_EMBEDDED
uuid_t kernelcache_uuid;
#endif

/* indicate to the compiler that some accesses are unaligned */
typedef uint64_t unaligned_u64 __attribute__((aligned(1)));

extern addr64_t kdp_vtophys(pmap_t pmap, addr64_t va);
extern void * proc_get_uthread_uu_threadlist(void * uthread_v);

int kdp_snapshot                            = 0;
static kern_return_t stack_snapshot_ret     = 0;
static uint32_t stack_snapshot_bytes_traced = 0;

static kcdata_descriptor_t stackshot_kcdata_p = NULL;
static void *stack_snapshot_buf;
static uint32_t stack_snapshot_bufsize;
int stack_snapshot_pid;
static uint32_t stack_snapshot_flags;
static uint64_t stack_snapshot_delta_since_timestamp;
static boolean_t panic_stackshot;

static boolean_t stack_enable_faulting = FALSE;
static struct stackshot_fault_stats fault_stats;

static unaligned_u64 * stackshot_duration_outer;
static uint64_t stackshot_microsecs;

void * kernel_stackshot_buf   = NULL; /* Pointer to buffer for stackshots triggered from the kernel and retrieved later */
int kernel_stackshot_buf_size = 0;

void * stackshot_snapbuf = NULL; /* Used by stack_snapshot2 (to be removed) */

__private_extern__ void stackshot_init( void );
static boolean_t memory_iszero(void *addr, size_t size);
#if CONFIG_TELEMETRY
kern_return_t		stack_microstackshot(user_addr_t tracebuf, uint32_t tracebuf_size, uint32_t flags, int32_t *retval);
#endif
uint32_t		get_stackshot_estsize(uint32_t prev_size_hint);
kern_return_t		kern_stack_snapshot_internal(int stackshot_config_version, void *stackshot_config,
						size_t stackshot_config_size, boolean_t stackshot_from_user);
kern_return_t		do_stackshot(void *);
void			kdp_snapshot_preflight(int pid, void * tracebuf, uint32_t tracebuf_size, uint32_t flags, kcdata_descriptor_t data_p, uint64_t since_timestamp);
boolean_t               stackshot_thread_is_idle_worker_unsafe(thread_t thread);
static int		kdp_stackshot_kcdata_format(int pid, uint32_t trace_flags, uint32_t *pBytesTraced);
uint32_t		kdp_stack_snapshot_bytes_traced(void);
static void		kdp_mem_and_io_snapshot(struct mem_and_io_snapshot *memio_snap);
static boolean_t	kdp_copyin(vm_map_t map, uint64_t uaddr, void *dest, size_t size, boolean_t try_fault, uint32_t *kdp_fault_result);
static boolean_t	kdp_copyin_word(task_t task, uint64_t addr, uint64_t *result, boolean_t try_fault, uint32_t *kdp_fault_results);
static uint64_t		proc_was_throttled_from_task(task_t task);
static void		stackshot_thread_wait_owner_info(thread_t thread, thread_waitinfo_t * waitinfo);
static int		stackshot_thread_has_valid_waitinfo(thread_t thread);

#if CONFIG_COALITIONS
static void		stackshot_coalition_jetsam_count(void *arg, int i, coalition_t coal);
static void		stackshot_coalition_jetsam_snapshot(void *arg, int i, coalition_t coal);
#endif /* CONFIG_COALITIONS */


extern uint32_t workqueue_get_pwq_state_kdp(void *proc);

extern int		proc_pid(void *p);
extern uint64_t		proc_uniqueid(void *p);
extern uint64_t		proc_was_throttled(void *p);
extern uint64_t		proc_did_throttle(void *p);
static uint64_t proc_did_throttle_from_task(task_t task);
extern void proc_name_kdp(task_t task, char * buf, int size);
extern int proc_threadname_kdp(void * uth, char * buf, size_t size);
extern void proc_starttime_kdp(void * p, uint64_t * tv_sec, uint64_t * tv_usec, uint64_t * abstime);
extern int		memorystatus_get_pressure_status_kdp(void);
extern boolean_t memorystatus_proc_is_dirty_unsafe(void * v);

extern int count_busy_buffers(void); /* must track with declaration in bsd/sys/buf_internal.h */
extern void bcopy_phys(addr64_t, addr64_t, vm_size_t);

#if CONFIG_TELEMETRY
extern kern_return_t stack_microstackshot(user_addr_t tracebuf, uint32_t tracebuf_size, uint32_t flags, int32_t *retval);
#endif /* CONFIG_TELEMETRY */

extern kern_return_t kern_stack_snapshot_with_reason(char* reason);
extern kern_return_t kern_stack_snapshot_internal(int stackshot_config_version, void *stackshot_config, size_t stackshot_config_size, boolean_t stackshot_from_user);

/*
 * Validates that the given address is both a valid page and has
 * default caching attributes for the current map.  Returns
 * 0 if the address is invalid, and a kernel virtual address for
 * the given address if it is valid.
 */
vm_offset_t machine_trace_thread_get_kva(vm_offset_t cur_target_addr, vm_map_t map, uint32_t *thread_trace_flags);

#define KDP_FAULT_RESULT_PAGED_OUT   0x1 /* some data was unable to be retrieved */
#define KDP_FAULT_RESULT_TRIED_FAULT 0x2 /* tried to fault in data */
#define KDP_FAULT_RESULT_FAULTED_IN  0x4 /* successfully faulted in data */

/*
 * Looks up the physical translation for the given address in the target map, attempting
 * to fault data in if requested and it is not resident. Populates thread_trace_flags if requested
 * as well.
 */
vm_offset_t kdp_find_phys(vm_map_t map, vm_offset_t target_addr, boolean_t try_fault, uint32_t *kdp_fault_results);

static size_t stackshot_strlcpy(char *dst, const char *src, size_t maxlen);
static void stackshot_memcpy(void *dst, const void *src, size_t len);

/* Clears caching information used by the above validation routine
 * (in case the current map has been changed or cleared).
 */
void machine_trace_thread_clear_validation_cache(void);

#define MAX_FRAMES 1000
#define MAX_LOADINFOS 500
#define TASK_IMP_WALK_LIMIT 20

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
 * Stackshot locking and other defines.
 */
static lck_grp_t       *stackshot_subsys_lck_grp;
static lck_grp_attr_t  *stackshot_subsys_lck_grp_attr;
static lck_attr_t      *stackshot_subsys_lck_attr;
static lck_mtx_t	stackshot_subsys_mutex;

#define STACKSHOT_SUBSYS_LOCK() lck_mtx_lock(&stackshot_subsys_mutex)
#define STACKSHOT_SUBSYS_TRY_LOCK() lck_mtx_try_lock(&stackshot_subsys_mutex)
#define STACKSHOT_SUBSYS_UNLOCK() lck_mtx_unlock(&stackshot_subsys_mutex)

#define SANE_BOOTPROFILE_TRACEBUF_SIZE (64 * 1024 * 1024)
#define SANE_TRACEBUF_SIZE (8 * 1024 * 1024)

/*
 * We currently set a ceiling of 3 milliseconds spent in the kdp fault path
 * for non-panic stackshots where faulting is requested.
 */
#define KDP_FAULT_PATH_MAX_TIME_PER_STACKSHOT_NSECS (3 * NSEC_PER_MSEC)

#define STACKSHOT_SUPP_SIZE (16 * 1024) /* Minimum stackshot size */
#define TASK_UUID_AVG_SIZE (16 * sizeof(uuid_t)) /* Average space consumed by UUIDs/task */

/*
 * Initialize the mutex governing access to the stack snapshot subsystem
 * and other stackshot related bits.
 */
__private_extern__ void
stackshot_init( void )
{
	mach_timebase_info_data_t timebase;

	stackshot_subsys_lck_grp_attr = lck_grp_attr_alloc_init();

	stackshot_subsys_lck_grp = lck_grp_alloc_init("stackshot_subsys_lock", stackshot_subsys_lck_grp_attr);

	stackshot_subsys_lck_attr = lck_attr_alloc_init();

	lck_mtx_init(&stackshot_subsys_mutex, stackshot_subsys_lck_grp, stackshot_subsys_lck_attr);

	clock_timebase_info(&timebase);
	fault_stats.sfs_system_max_fault_time = ((KDP_FAULT_PATH_MAX_TIME_PER_STACKSHOT_NSECS * timebase.denom)/ timebase.numer);
}

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

/*
 * Called with interrupts disabled after stackshot context has been
 * initialized. Updates stack_snapshot_ret.
 */
static kern_return_t 
stackshot_trap()
{
	return DebuggerTrapWithState(DBOP_STACKSHOT, NULL, NULL, NULL, 0, FALSE, 0);
}


kern_return_t
stack_snapshot_from_kernel(int pid, void *buf, uint32_t size, uint32_t flags, uint64_t delta_since_timestamp, unsigned *bytes_traced)
{
	kern_return_t error = KERN_SUCCESS;
	boolean_t istate;

#if DEVELOPMENT || DEBUG
	if (kern_feature_override(KF_STACKSHOT_OVRD) == TRUE) {
		error = KERN_NOT_SUPPORTED;
		goto out;
	}
#endif
	if ((buf == NULL) || (size <= 0) || (bytes_traced == NULL)) {
		return KERN_INVALID_ARGUMENT;
	}

	/* cap in individual stackshot to SANE_TRACEBUF_SIZE */
	if (size > SANE_TRACEBUF_SIZE) {
		size = SANE_TRACEBUF_SIZE;
	}

	/* Serialize tracing */
	if (flags & STACKSHOT_TRYLOCK) {
		if (!STACKSHOT_SUBSYS_TRY_LOCK()) {
			return KERN_LOCK_OWNED;
		}
	} else {
		STACKSHOT_SUBSYS_LOCK();
	}

	struct kcdata_descriptor kcdata;
	uint32_t hdr_tag = (flags & STACKSHOT_COLLECT_DELTA_SNAPSHOT) ?
		KCDATA_BUFFER_BEGIN_DELTA_STACKSHOT : KCDATA_BUFFER_BEGIN_STACKSHOT;

	error = kcdata_memory_static_init(&kcdata, (mach_vm_address_t)buf, hdr_tag, size,
									  KCFLAG_USE_MEMCOPY | KCFLAG_NO_AUTO_ENDBUFFER);
	if (error) {
		goto out;
	}

	istate = ml_set_interrupts_enabled(FALSE);

	/* Preload trace parameters*/
	kdp_snapshot_preflight(pid, buf, size, flags, &kcdata, delta_since_timestamp);

	/*
	 * Trap to the debugger to obtain a coherent stack snapshot; this populates
	 * the trace buffer
	 */
	error = stackshot_trap();

	ml_set_interrupts_enabled(istate);

	*bytes_traced = kdp_stack_snapshot_bytes_traced();

out:
	stackshot_kcdata_p = NULL;
	STACKSHOT_SUBSYS_UNLOCK();
	return error;
}

#if CONFIG_TELEMETRY
kern_return_t
stack_microstackshot(user_addr_t tracebuf, uint32_t tracebuf_size, uint32_t flags, int32_t *retval)
{
	int error = KERN_SUCCESS;
	uint32_t bytes_traced = 0;

	*retval = -1;

	/*
	 * Control related operations
	 */
	if (flags & STACKSHOT_GLOBAL_MICROSTACKSHOT_ENABLE) {
		telemetry_global_ctl(1);
		*retval = 0;
		goto exit;
	} else if (flags & STACKSHOT_GLOBAL_MICROSTACKSHOT_DISABLE) {
		telemetry_global_ctl(0);
		*retval = 0;
		goto exit;
	}

	/*
	 * Data related operations
	 */
	*retval = -1;

	if ((((void*)tracebuf) == NULL) || (tracebuf_size == 0)) {
		error = KERN_INVALID_ARGUMENT;
		goto exit;
	}

	STACKSHOT_SUBSYS_LOCK();

	if (flags & STACKSHOT_GET_MICROSTACKSHOT) {
		if (tracebuf_size > SANE_TRACEBUF_SIZE) {
			error = KERN_INVALID_ARGUMENT;
			goto unlock_exit;
		}

		bytes_traced = tracebuf_size;
		error = telemetry_gather(tracebuf, &bytes_traced,
		                         (flags & STACKSHOT_SET_MICROSTACKSHOT_MARK) ? TRUE : FALSE);
		*retval = (int)bytes_traced;
		goto unlock_exit;
	}

	if (flags & STACKSHOT_GET_BOOT_PROFILE) {

		if (tracebuf_size > SANE_BOOTPROFILE_TRACEBUF_SIZE) {
			error = KERN_INVALID_ARGUMENT;
			goto unlock_exit;
		}

		bytes_traced = tracebuf_size;
		error = bootprofile_gather(tracebuf, &bytes_traced);
		*retval = (int)bytes_traced;
	}

unlock_exit:
	STACKSHOT_SUBSYS_UNLOCK();
exit:
	return error;
}
#endif /* CONFIG_TELEMETRY */

/*
 * Return the estimated size of a stackshot based on the
 * number of currently running threads and tasks.
 */
uint32_t
get_stackshot_estsize(uint32_t prev_size_hint)
{
	vm_size_t thread_total;
	vm_size_t task_total;
	uint32_t estimated_size;

	thread_total = (threads_count * sizeof(struct thread_snapshot));
	task_total = (tasks_count  * (sizeof(struct task_snapshot) + TASK_UUID_AVG_SIZE));

	estimated_size = (uint32_t) VM_MAP_ROUND_PAGE((thread_total + task_total + STACKSHOT_SUPP_SIZE), PAGE_MASK);
	if (estimated_size < prev_size_hint) {
		estimated_size = (uint32_t) VM_MAP_ROUND_PAGE(prev_size_hint, PAGE_MASK);
	}

	return estimated_size;
}

/*
 * stackshot_remap_buffer:	Utility function to remap bytes_traced bytes starting at stackshotbuf
 *				into the current task's user space and subsequently copy out the address
 *				at which the buffer has been mapped in user space to out_buffer_addr.
 *
 * Inputs:			stackshotbuf - pointer to the original buffer in the kernel's address space
 *				bytes_traced - length of the buffer to remap starting from stackshotbuf
 *				out_buffer_addr - pointer to placeholder where newly mapped buffer will be mapped.
 *				out_size_addr - pointer to be filled in with the size of the buffer
 *
 * Outputs:			ENOSPC if there is not enough free space in the task's address space to remap the buffer
 *				EINVAL for all other errors returned by task_remap_buffer/mach_vm_remap
 *				an error from copyout
 */
static kern_return_t
stackshot_remap_buffer(void *stackshotbuf, uint32_t bytes_traced, uint64_t out_buffer_addr, uint64_t out_size_addr)
{
	int 			error = 0;
	mach_vm_offset_t	stackshotbuf_user_addr = (mach_vm_offset_t)NULL;
	vm_prot_t		cur_prot, max_prot;

	error = mach_vm_remap_kernel(get_task_map(current_task()), &stackshotbuf_user_addr, bytes_traced, 0,
			VM_FLAGS_ANYWHERE, VM_KERN_MEMORY_NONE, kernel_map, (mach_vm_offset_t)stackshotbuf, FALSE, &cur_prot, &max_prot, VM_INHERIT_DEFAULT);
	/*
	 * If the call to mach_vm_remap fails, we return the appropriate converted error
	 */
	if (error == KERN_SUCCESS) {
		/*
		 * If we fail to copy out the address or size of the new buffer, we remove the buffer mapping that
		 * we just made in the task's user space.
		 */
		error = copyout(CAST_DOWN(void *, &stackshotbuf_user_addr), (user_addr_t)out_buffer_addr, sizeof(stackshotbuf_user_addr));
		if (error != KERN_SUCCESS) {
			mach_vm_deallocate(get_task_map(current_task()), stackshotbuf_user_addr, (mach_vm_size_t)bytes_traced);
			return error;
		}
		error = copyout(&bytes_traced, (user_addr_t)out_size_addr, sizeof(bytes_traced));
		if (error != KERN_SUCCESS) {
			mach_vm_deallocate(get_task_map(current_task()), stackshotbuf_user_addr, (mach_vm_size_t)bytes_traced);
			return error;
		}
	}
	return error;
}

kern_return_t
kern_stack_snapshot_internal(int stackshot_config_version, void *stackshot_config, size_t stackshot_config_size, boolean_t stackshot_from_user)
{
	int error = 0;
	boolean_t prev_interrupt_state;
	uint32_t bytes_traced = 0;
	uint32_t stackshotbuf_size = 0;
	void * stackshotbuf = NULL;
	kcdata_descriptor_t kcdata_p = NULL;

	void * buf_to_free = NULL;
	int size_to_free = 0;

	/* Parsed arguments */
	uint64_t		out_buffer_addr;
	uint64_t		out_size_addr;
	int			pid = -1;
	uint32_t		flags;
	uint64_t		since_timestamp;
	uint32_t		size_hint = 0;

	if(stackshot_config == NULL) {
		return 	KERN_INVALID_ARGUMENT;
	}
#if DEVELOPMENT || DEBUG
	/* TBD: ask stackshot clients to avoid issuing stackshots in this
	 * configuration in lieu of the kernel feature override.
	 */
	if (kern_feature_override(KF_STACKSHOT_OVRD) == TRUE) {
		return KERN_NOT_SUPPORTED;
	}
#endif

	switch (stackshot_config_version) {
		case STACKSHOT_CONFIG_TYPE:
			if (stackshot_config_size != sizeof(stackshot_config_t)) {
				return KERN_INVALID_ARGUMENT;
			}
			stackshot_config_t *config = (stackshot_config_t *) stackshot_config;
			out_buffer_addr = config->sc_out_buffer_addr;
			out_size_addr = config->sc_out_size_addr;
			pid = config->sc_pid;
			flags = config->sc_flags;
			since_timestamp = config->sc_delta_timestamp;
			if (config->sc_size <= SANE_TRACEBUF_SIZE) {
				size_hint = config->sc_size;
			}
			break;
		default:
			return KERN_NOT_SUPPORTED;
	    }

	    /*
	     * Currently saving a kernel buffer and trylock are only supported from the
	     * internal/KEXT API.
	     */
	    if (stackshot_from_user) {
		    if (flags & (STACKSHOT_TRYLOCK | STACKSHOT_SAVE_IN_KERNEL_BUFFER | STACKSHOT_FROM_PANIC)) {
			    return KERN_NO_ACCESS;
		    }
	    } else {
		if (!(flags & STACKSHOT_SAVE_IN_KERNEL_BUFFER)) {
			return KERN_NOT_SUPPORTED;
		}
	}

	if (!((flags & STACKSHOT_KCDATA_FORMAT) || (flags & STACKSHOT_RETRIEVE_EXISTING_BUFFER))) {
		return KERN_NOT_SUPPORTED;
	}

	/*
	 * If we're not saving the buffer in the kernel pointer, we need a place to copy into.
	 */
	if ((!out_buffer_addr || !out_size_addr) && !(flags & STACKSHOT_SAVE_IN_KERNEL_BUFFER)) {
		return KERN_INVALID_ARGUMENT;
	}

	if (since_timestamp != 0 && ((flags & STACKSHOT_COLLECT_DELTA_SNAPSHOT) == 0)) {
		return KERN_INVALID_ARGUMENT;
	}

#if MONOTONIC
	if (!mt_core_supported) {
		flags &= ~STACKSHOT_INSTRS_CYCLES;
	}
#else /* MONOTONIC */
	flags &= ~STACKSHOT_INSTRS_CYCLES;
#endif /* !MONOTONIC */

	STACKSHOT_SUBSYS_LOCK();

	if (flags & STACKSHOT_SAVE_IN_KERNEL_BUFFER) {
		/*
		 * Don't overwrite an existing stackshot
		 */
		if (kernel_stackshot_buf != NULL) {
			error = KERN_MEMORY_PRESENT;
			goto error_exit;
		}
	} else if (flags & STACKSHOT_RETRIEVE_EXISTING_BUFFER) {
		if ((kernel_stackshot_buf == NULL) || (kernel_stackshot_buf_size <= 0)) {
			error = KERN_NOT_IN_SET;
			goto error_exit;
		}
		error = stackshot_remap_buffer(kernel_stackshot_buf, kernel_stackshot_buf_size,
						out_buffer_addr, out_size_addr);
		/*
		 * If we successfully remapped the buffer into the user's address space, we 
		 * set buf_to_free and size_to_free so the prior kernel mapping will be removed
		 * and then clear the kernel stackshot pointer and associated size.
		 */
		if (error == KERN_SUCCESS) {
			buf_to_free = kernel_stackshot_buf;
			size_to_free = (int) VM_MAP_ROUND_PAGE(kernel_stackshot_buf_size, PAGE_MASK);
			kernel_stackshot_buf = NULL;
			kernel_stackshot_buf_size = 0;
		}
		
		goto error_exit;
	}

	if (flags & STACKSHOT_GET_BOOT_PROFILE) {
		void *bootprofile = NULL;
		uint32_t len = 0;
#if CONFIG_TELEMETRY
		bootprofile_get(&bootprofile, &len);
#endif
		if (!bootprofile || !len) {
			error = KERN_NOT_IN_SET;
			goto error_exit;
		}
		error = stackshot_remap_buffer(bootprofile, len, out_buffer_addr, out_size_addr);
		goto error_exit;
	}

	stackshotbuf_size = get_stackshot_estsize(size_hint);

	for (; stackshotbuf_size <= SANE_TRACEBUF_SIZE; stackshotbuf_size <<= 1) {
		if (kmem_alloc(kernel_map, (vm_offset_t *)&stackshotbuf, stackshotbuf_size, VM_KERN_MEMORY_DIAG) != KERN_SUCCESS) {
			error = KERN_RESOURCE_SHORTAGE;
			goto error_exit;
		}


		uint32_t hdr_tag = (flags & STACKSHOT_COLLECT_DELTA_SNAPSHOT) ? KCDATA_BUFFER_BEGIN_DELTA_STACKSHOT : KCDATA_BUFFER_BEGIN_STACKSHOT;
		kcdata_p = kcdata_memory_alloc_init((mach_vm_address_t)stackshotbuf, hdr_tag, stackshotbuf_size,
			                                    KCFLAG_USE_MEMCOPY | KCFLAG_NO_AUTO_ENDBUFFER);

		stackshot_duration_outer = NULL;
		uint64_t time_start      = mach_absolute_time();

		/*
		 * Disable interrupts and save the current interrupt state.
		 */
		prev_interrupt_state = ml_set_interrupts_enabled(FALSE);

		/*
		 * Load stackshot parameters.
		 */
		kdp_snapshot_preflight(pid, stackshotbuf, stackshotbuf_size, flags, kcdata_p, since_timestamp);

		error = stackshot_trap();

		ml_set_interrupts_enabled(prev_interrupt_state);

		/* record the duration that interupts were disabled */

		uint64_t time_end = mach_absolute_time();
		if (stackshot_duration_outer) {
			*stackshot_duration_outer = time_end - time_start;
		}

		if (error != KERN_SUCCESS) {
			if (kcdata_p != NULL) {
				kcdata_memory_destroy(kcdata_p);
				kcdata_p = NULL;
				stackshot_kcdata_p = NULL;
			}
			kmem_free(kernel_map, (vm_offset_t)stackshotbuf, stackshotbuf_size);
			stackshotbuf = NULL;
			if (error == KERN_INSUFFICIENT_BUFFER_SIZE) {
				/*
				 * If we didn't allocate a big enough buffer, deallocate and try again.
				 */
				continue;
			} else {
				goto error_exit;
			}
		}

		bytes_traced = kdp_stack_snapshot_bytes_traced();

		if (bytes_traced <= 0) {
			error = KERN_ABORTED;
			goto error_exit;
		}

		assert(bytes_traced <= stackshotbuf_size);
		if (!(flags & STACKSHOT_SAVE_IN_KERNEL_BUFFER)) {
			error = stackshot_remap_buffer(stackshotbuf, bytes_traced, out_buffer_addr, out_size_addr);
			goto error_exit;
		}

		/*
		 * Save the stackshot in the kernel buffer.
		 */
		kernel_stackshot_buf = stackshotbuf;
		kernel_stackshot_buf_size =  bytes_traced;
		/*
		 * Figure out if we didn't use all the pages in the buffer. If so, we set buf_to_free to the beginning of
		 * the next page after the end of the stackshot in the buffer so that the kmem_free clips the buffer and
		 * update size_to_free for kmem_free accordingly.
		 */
		size_to_free = stackshotbuf_size - (int) VM_MAP_ROUND_PAGE(bytes_traced, PAGE_MASK);

		assert(size_to_free >= 0);

		if (size_to_free != 0) {
			buf_to_free = (void *)((uint64_t)stackshotbuf + stackshotbuf_size - size_to_free);
		}

		stackshotbuf = NULL;
		stackshotbuf_size = 0;
		goto error_exit;
	}

	if (stackshotbuf_size > SANE_TRACEBUF_SIZE) {
		error = KERN_RESOURCE_SHORTAGE;
	}

error_exit:
	if (kcdata_p != NULL) {
		kcdata_memory_destroy(kcdata_p);
		kcdata_p = NULL;
		stackshot_kcdata_p = NULL;
	}

	if (stackshotbuf != NULL) {
		kmem_free(kernel_map, (vm_offset_t)stackshotbuf, stackshotbuf_size);
	}
	if (buf_to_free  != NULL) {
		kmem_free(kernel_map, (vm_offset_t)buf_to_free, size_to_free);
	}
	STACKSHOT_SUBSYS_UNLOCK();
	return error;
}

/*
 * Cache stack snapshot parameters in preparation for a trace.
 */
void
kdp_snapshot_preflight(int pid, void * tracebuf, uint32_t tracebuf_size, uint32_t flags,
					   kcdata_descriptor_t data_p, uint64_t since_timestamp)
{
	uint64_t microsecs = 0, secs = 0;
	clock_get_calendar_microtime((clock_sec_t *)&secs, (clock_usec_t *)&microsecs);

	stackshot_microsecs = microsecs + (secs * USEC_PER_SEC);
	stack_snapshot_pid = pid;
	stack_snapshot_buf = tracebuf;
	stack_snapshot_bufsize = tracebuf_size;
	stack_snapshot_flags = flags;
	stack_snapshot_delta_since_timestamp = since_timestamp;

	panic_stackshot = ((flags & STACKSHOT_FROM_PANIC) != 0);

	assert(data_p != NULL);
	assert(stackshot_kcdata_p == NULL);
	stackshot_kcdata_p = data_p;

	stack_snapshot_bytes_traced = 0;
}

void
panic_stackshot_reset_state()
{
	stackshot_kcdata_p = NULL;
}

boolean_t
stackshot_active()
{
	return (stackshot_kcdata_p != NULL);
}

uint32_t
kdp_stack_snapshot_bytes_traced(void)
{
	return stack_snapshot_bytes_traced;
}

static boolean_t memory_iszero(void *addr, size_t size)
{
	char *data = (char *)addr;
	for (size_t i = 0; i < size; i++){
		if (data[i] != 0)
			return FALSE;
	}
	return TRUE;
}

#define kcd_end_address(kcd) ((void *)((uint64_t)((kcd)->kcd_addr_begin) + kcdata_memory_get_used_bytes((kcd))))
#define kcd_max_address(kcd) ((void *)((kcd)->kcd_addr_begin + (kcd)->kcd_length))
/*
 * Use of the kcd_exit_on_error(action) macro requires a local
 * 'kern_return_t error' variable and 'error_exit' label.
 */
#define kcd_exit_on_error(action)                      \
	do {                                               \
		if (KERN_SUCCESS != (error = (action))) {      \
			if (error == KERN_RESOURCE_SHORTAGE) {     \
				error = KERN_INSUFFICIENT_BUFFER_SIZE; \
			}                                          \
			goto error_exit;                           \
		}                                              \
	} while (0); /* end kcd_exit_on_error */

static uint64_t
kcdata_get_task_ss_flags(task_t task)
{
	uint64_t ss_flags = 0;
	boolean_t task64 = task_has_64BitAddr(task);

	if (task64)
		ss_flags |= kUser64_p;
	if (!task->active || task_is_a_corpse(task))
		ss_flags |= kTerminatedSnapshot;
	if (task->pidsuspended)
		ss_flags |= kPidSuspended;
	if (task->frozen)
		ss_flags |= kFrozen;
	if (task->effective_policy.tep_darwinbg == 1)
		ss_flags |= kTaskDarwinBG;
	if (task->requested_policy.trp_role == TASK_FOREGROUND_APPLICATION)
		ss_flags |= kTaskIsForeground;
	if (task->requested_policy.trp_boosted == 1)
		ss_flags |= kTaskIsBoosted;
	if (task->effective_policy.tep_sup_active == 1)
		ss_flags |= kTaskIsSuppressed;
#if CONFIG_MEMORYSTATUS
	if (memorystatus_proc_is_dirty_unsafe(task->bsd_info))
		ss_flags |= kTaskIsDirty;
#endif

	ss_flags |= (0x7 & workqueue_get_pwq_state_kdp(task->bsd_info)) << 17;

#if IMPORTANCE_INHERITANCE
	if (task->task_imp_base) {
		if (task->task_imp_base->iit_donor)
			ss_flags |= kTaskIsImpDonor;
		if (task->task_imp_base->iit_live_donor)
			ss_flags |= kTaskIsLiveImpDonor;
	}
#endif

	return ss_flags;
}

static kern_return_t
kcdata_record_shared_cache_info(kcdata_descriptor_t kcd, task_t task, struct dyld_uuid_info_64_v2 *sys_shared_cache_loadinfo, unaligned_u64 *task_snap_ss_flags)
{
	kern_return_t error = KERN_SUCCESS;
	mach_vm_address_t out_addr = 0;

	uint64_t shared_cache_slide = 0;
	uint64_t shared_cache_base_address = 0;
	int task_pid = pid_from_task(task);
	uint32_t kdp_fault_results = 0;

	assert(task_snap_ss_flags != NULL);

	if (task->shared_region && ml_validate_nofault((vm_offset_t)task->shared_region, sizeof(struct vm_shared_region))) {
		struct vm_shared_region *sr = task->shared_region;
		shared_cache_base_address = sr->sr_base_address + sr->sr_first_mapping;
	} else {
		*task_snap_ss_flags |= kTaskSharedRegionInfoUnavailable;
		goto error_exit;
	}

	/* We haven't copied in the shared region UUID yet as part of setup */
	if (!shared_cache_base_address || !task->shared_region->sr_uuid_copied) {
		goto error_exit;
	}

	/*
	 * No refcounting here, but we are in debugger
	 * context, so that should be safe.
	 */
	shared_cache_slide = task->shared_region->sr_slide_info.slide;

	if (sys_shared_cache_loadinfo) {
		if (task_pid == 1) {
			/* save launchd's shared cache info as system level */
			stackshot_memcpy(sys_shared_cache_loadinfo->imageUUID, &task->shared_region->sr_uuid, sizeof(task->shared_region->sr_uuid));
			sys_shared_cache_loadinfo->imageLoadAddress = shared_cache_slide;
			sys_shared_cache_loadinfo->imageSlidBaseAddress = shared_cache_slide + task->shared_region->sr_base_address;

			goto error_exit;
		} else {
			if (shared_cache_slide == sys_shared_cache_loadinfo->imageLoadAddress &&
			    0 == memcmp(&task->shared_region->sr_uuid, sys_shared_cache_loadinfo->imageUUID,
			                sizeof(task->shared_region->sr_uuid))) {
				/* skip adding shared cache info. its same as system level one */
				goto error_exit;
			}
		}
	}

	kcd_exit_on_error(kcdata_get_memory_addr(kcd, STACKSHOT_KCTYPE_SHAREDCACHE_LOADINFO, sizeof(struct dyld_uuid_info_64_v2), &out_addr));
	struct dyld_uuid_info_64_v2 *shared_cache_data = (struct dyld_uuid_info_64_v2 *)out_addr;
	shared_cache_data->imageLoadAddress = shared_cache_slide;
	stackshot_memcpy(shared_cache_data->imageUUID, task->shared_region->sr_uuid, sizeof(task->shared_region->sr_uuid));
	shared_cache_data->imageSlidBaseAddress = shared_cache_base_address;

error_exit:
	if (kdp_fault_results & KDP_FAULT_RESULT_PAGED_OUT) {
		*task_snap_ss_flags |= kTaskUUIDInfoMissing;
	}

	if (kdp_fault_results & KDP_FAULT_RESULT_TRIED_FAULT) {
		*task_snap_ss_flags |= kTaskUUIDInfoTriedFault;
	}

	if (kdp_fault_results & KDP_FAULT_RESULT_FAULTED_IN) {
		*task_snap_ss_flags |= kTaskUUIDInfoFaultedIn;
	}

	return error;
}

static kern_return_t
kcdata_record_uuid_info(kcdata_descriptor_t kcd, task_t task, uint32_t trace_flags, boolean_t have_pmap, unaligned_u64 *task_snap_ss_flags)
{
	boolean_t save_loadinfo_p         = ((trace_flags & STACKSHOT_SAVE_LOADINFO) != 0);
	boolean_t save_kextloadinfo_p     = ((trace_flags & STACKSHOT_SAVE_KEXT_LOADINFO) != 0);
	boolean_t collect_delta_stackshot = ((trace_flags & STACKSHOT_COLLECT_DELTA_SNAPSHOT) != 0);
	boolean_t minimize_uuids          = collect_delta_stackshot && ((trace_flags & STACKSHOT_TAILSPIN) != 0);
	boolean_t should_fault            = (trace_flags & STACKSHOT_ENABLE_UUID_FAULTING);

	kern_return_t error        = KERN_SUCCESS;
	mach_vm_address_t out_addr = 0;

	uint32_t uuid_info_count         = 0;
	mach_vm_address_t uuid_info_addr = 0;
	uint64_t uuid_info_timestamp     = 0;
	uint32_t kdp_fault_results       = 0;

	assert(task_snap_ss_flags != NULL);

	int task_pid     = pid_from_task(task);
	boolean_t task64 = task_has_64BitAddr(task);

	if (save_loadinfo_p && have_pmap && task->active && task_pid > 0) {
		/* Read the dyld_all_image_infos struct from the task memory to get UUID array count and location */
		if (task64) {
			struct user64_dyld_all_image_infos task_image_infos;
			if (kdp_copyin(task->map, task->all_image_info_addr, &task_image_infos,
			               sizeof(struct user64_dyld_all_image_infos), should_fault, &kdp_fault_results)) {
				uuid_info_count = (uint32_t)task_image_infos.uuidArrayCount;
				uuid_info_addr = task_image_infos.uuidArray;
				if (task_image_infos.version >= DYLD_ALL_IMAGE_INFOS_TIMESTAMP_MINIMUM_VERSION) {
					uuid_info_timestamp = task_image_infos.timestamp;
				}
			}
		} else {
			struct user32_dyld_all_image_infos task_image_infos;
			if (kdp_copyin(task->map, task->all_image_info_addr, &task_image_infos,
			               sizeof(struct user32_dyld_all_image_infos), should_fault, &kdp_fault_results)) {
				uuid_info_count = task_image_infos.uuidArrayCount;
				uuid_info_addr = task_image_infos.uuidArray;
				if (task_image_infos.version >= DYLD_ALL_IMAGE_INFOS_TIMESTAMP_MINIMUM_VERSION) {
					uuid_info_timestamp = task_image_infos.timestamp;
				}
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
	}

	if (have_pmap && task_pid == 0) {
		if (save_kextloadinfo_p && ml_validate_nofault((vm_offset_t)(gLoadedKextSummaries), sizeof(OSKextLoadedKextSummaryHeader))) {
			uuid_info_count = gLoadedKextSummaries->numSummaries + 1; /* include main kernel UUID */
		} else {
			uuid_info_count = 1; /* include kernelcache UUID (embedded) or kernel UUID (desktop) */
		}
	}

	if (task_pid > 0 && uuid_info_count > 0 && uuid_info_count < MAX_LOADINFOS) {
		if (minimize_uuids && uuid_info_timestamp != 0 && uuid_info_timestamp < stack_snapshot_delta_since_timestamp)
			goto error_exit;

		uint32_t uuid_info_size       = (uint32_t)(task64 ? sizeof(struct user64_dyld_uuid_info) : sizeof(struct user32_dyld_uuid_info));
		uint32_t uuid_info_array_size = uuid_info_count * uuid_info_size;

		kcd_exit_on_error(kcdata_get_memory_addr_for_array(kcd, (task64 ? KCDATA_TYPE_LIBRARY_LOADINFO64 : KCDATA_TYPE_LIBRARY_LOADINFO),
									uuid_info_size, uuid_info_count, &out_addr));

		/* Copy in the UUID info array
		 * It may be nonresident, in which case just fix up nloadinfos to 0 in the task_snap
		 */
		if (have_pmap && !kdp_copyin(task->map, uuid_info_addr, (void *)out_addr, uuid_info_array_size, should_fault, &kdp_fault_results)) {
			bzero((void *)out_addr, uuid_info_array_size);
		}

	} else if (task_pid == 0 && uuid_info_count > 0 && uuid_info_count < MAX_LOADINFOS) {
		if (minimize_uuids && gLoadedKextSummaries != 0 && gLoadedKextSummariesTimestamp < stack_snapshot_delta_since_timestamp)
			goto error_exit;

		uintptr_t image_load_address;

		do {

#if CONFIG_EMBEDDED
			if (!save_kextloadinfo_p) {
				kcd_exit_on_error(kcdata_get_memory_addr(kcd, STACKSHOT_KCTYPE_KERNELCACHE_LOADINFO, sizeof(struct dyld_uuid_info_64), &out_addr));
				struct dyld_uuid_info_64 *kc_uuid = (struct dyld_uuid_info_64 *)out_addr;
				kc_uuid->imageLoadAddress = VM_MIN_KERNEL_AND_KEXT_ADDRESS;
				stackshot_memcpy(&kc_uuid->imageUUID, &kernelcache_uuid, sizeof(uuid_t));
				break;
			}
#endif /* CONFIG_EMBEDDED */

			if (!kernel_uuid || !ml_validate_nofault((vm_offset_t)kernel_uuid, sizeof(uuid_t))) {
				/* Kernel UUID not found or inaccessible */
				break;
			}

			kcd_exit_on_error(kcdata_get_memory_addr_for_array(
			    kcd, (sizeof(kernel_uuid_info) == sizeof(struct user64_dyld_uuid_info)) ? KCDATA_TYPE_LIBRARY_LOADINFO64
			                                                                            : KCDATA_TYPE_LIBRARY_LOADINFO,
			    sizeof(kernel_uuid_info), uuid_info_count, &out_addr));
			kernel_uuid_info *uuid_info_array = (kernel_uuid_info *)out_addr;
			image_load_address = (uintptr_t)VM_KERNEL_UNSLIDE(vm_kernel_stext);
			uuid_info_array[0].imageLoadAddress = image_load_address;
			stackshot_memcpy(&uuid_info_array[0].imageUUID, kernel_uuid, sizeof(uuid_t));

			if (save_kextloadinfo_p && 
				ml_validate_nofault((vm_offset_t)(gLoadedKextSummaries), sizeof(OSKextLoadedKextSummaryHeader)) &&
				ml_validate_nofault((vm_offset_t)(&gLoadedKextSummaries->summaries[0]),
									gLoadedKextSummaries->entry_size * gLoadedKextSummaries->numSummaries)) {
				uint32_t kexti;
				for (kexti=0 ; kexti < gLoadedKextSummaries->numSummaries; kexti++) {
					image_load_address = (uintptr_t)VM_KERNEL_UNSLIDE(gLoadedKextSummaries->summaries[kexti].address);
					uuid_info_array[kexti + 1].imageLoadAddress = image_load_address;
					stackshot_memcpy(&uuid_info_array[kexti + 1].imageUUID, &gLoadedKextSummaries->summaries[kexti].uuid, sizeof(uuid_t));
				}
			}
		} while(0);
	}

error_exit:
	if (kdp_fault_results & KDP_FAULT_RESULT_PAGED_OUT) {
		*task_snap_ss_flags |= kTaskUUIDInfoMissing;
	}

	if (kdp_fault_results & KDP_FAULT_RESULT_TRIED_FAULT) {
		*task_snap_ss_flags |= kTaskUUIDInfoTriedFault;
	}

	if (kdp_fault_results & KDP_FAULT_RESULT_FAULTED_IN) {
		*task_snap_ss_flags |= kTaskUUIDInfoFaultedIn;
	}

	return error;
}

static kern_return_t
kcdata_record_task_iostats(kcdata_descriptor_t kcd, task_t task)
{
	kern_return_t error = KERN_SUCCESS;
	mach_vm_address_t out_addr = 0;

	/* I/O Statistics if any counters are non zero */
	assert(IO_NUM_PRIORITIES == STACKSHOT_IO_NUM_PRIORITIES);
	if (task->task_io_stats && !memory_iszero(task->task_io_stats, sizeof(struct io_stat_info))) {
		kcd_exit_on_error(kcdata_get_memory_addr(kcd, STACKSHOT_KCTYPE_IOSTATS, sizeof(struct io_stats_snapshot), &out_addr));
		struct io_stats_snapshot *_iostat = (struct io_stats_snapshot *)out_addr;
		_iostat->ss_disk_reads_count = task->task_io_stats->disk_reads.count;
		_iostat->ss_disk_reads_size = task->task_io_stats->disk_reads.size;
		_iostat->ss_disk_writes_count = (task->task_io_stats->total_io.count - task->task_io_stats->disk_reads.count);
		_iostat->ss_disk_writes_size = (task->task_io_stats->total_io.size - task->task_io_stats->disk_reads.size);
		_iostat->ss_paging_count = task->task_io_stats->paging.count;
		_iostat->ss_paging_size = task->task_io_stats->paging.size;
		_iostat->ss_non_paging_count = (task->task_io_stats->total_io.count - task->task_io_stats->paging.count);
		_iostat->ss_non_paging_size = (task->task_io_stats->total_io.size - task->task_io_stats->paging.size);
		_iostat->ss_metadata_count = task->task_io_stats->metadata.count;
		_iostat->ss_metadata_size = task->task_io_stats->metadata.size;
		_iostat->ss_data_count = (task->task_io_stats->total_io.count - task->task_io_stats->metadata.count);
		_iostat->ss_data_size = (task->task_io_stats->total_io.size - task->task_io_stats->metadata.size);
		for(int i = 0; i < IO_NUM_PRIORITIES; i++) {
			_iostat->ss_io_priority_count[i] = task->task_io_stats->io_priority[i].count;
			_iostat->ss_io_priority_size[i] = task->task_io_stats->io_priority[i].size;
		}
	}

error_exit:
	return error;
}

static kern_return_t
kcdata_record_task_snapshot(kcdata_descriptor_t kcd, task_t task, uint32_t trace_flags, boolean_t have_pmap, unaligned_u64 **task_snap_ss_flags)
{
	boolean_t collect_delta_stackshot = ((trace_flags & STACKSHOT_COLLECT_DELTA_SNAPSHOT) != 0);
	boolean_t collect_iostats         = !collect_delta_stackshot && !(trace_flags & STACKSHOT_TAILSPIN) && !(trace_flags & STACKSHOT_NO_IO_STATS);
#if MONOTONIC
	boolean_t collect_instrs_cycles   = ((trace_flags & STACKSHOT_INSTRS_CYCLES) != 0);
#endif /* MONOTONIC */

	kern_return_t error                 = KERN_SUCCESS;
	mach_vm_address_t out_addr          = 0;
	struct task_snapshot_v2 * cur_tsnap = NULL;

	assert(task_snap_ss_flags != NULL);

	int task_pid           = pid_from_task(task);
	uint64_t task_uniqueid = get_task_uniqueid(task);
	uint64_t proc_starttime_secs = 0;

	kcd_exit_on_error(kcdata_get_memory_addr(kcd, STACKSHOT_KCTYPE_TASK_SNAPSHOT, sizeof(struct task_snapshot_v2), &out_addr));

	cur_tsnap = (struct task_snapshot_v2 *)out_addr;

	cur_tsnap->ts_unique_pid = task_uniqueid;
	cur_tsnap->ts_ss_flags = kcdata_get_task_ss_flags(task);
	*task_snap_ss_flags = (unaligned_u64 *)&cur_tsnap->ts_ss_flags;
	cur_tsnap->ts_user_time_in_terminated_threads = task->total_user_time;
	cur_tsnap->ts_system_time_in_terminated_threads = task->total_system_time;

	proc_starttime_kdp(task->bsd_info, &proc_starttime_secs, NULL, NULL);
	cur_tsnap->ts_p_start_sec = proc_starttime_secs;

#if CONFIG_EMBEDDED
	cur_tsnap->ts_task_size = have_pmap ? get_task_phys_footprint(task) : 0;
#else
	cur_tsnap->ts_task_size = have_pmap ? (pmap_resident_count(task->map->pmap) * PAGE_SIZE) : 0;
#endif
	cur_tsnap->ts_max_resident_size = get_task_resident_max(task);
	cur_tsnap->ts_suspend_count = task->suspend_count;
	cur_tsnap->ts_faults = task->faults;
	cur_tsnap->ts_pageins = task->pageins;
	cur_tsnap->ts_cow_faults = task->cow_faults;
	cur_tsnap->ts_was_throttled = (uint32_t) proc_was_throttled_from_task(task);
	cur_tsnap->ts_did_throttle = (uint32_t) proc_did_throttle_from_task(task);
	cur_tsnap->ts_latency_qos = (task->effective_policy.tep_latency_qos == LATENCY_QOS_TIER_UNSPECIFIED) ?
		LATENCY_QOS_TIER_UNSPECIFIED : ((0xFF << 16) | task->effective_policy.tep_latency_qos);
	cur_tsnap->ts_pid = task_pid;

	/* Add the BSD process identifiers */
	if (task_pid != -1 && task->bsd_info != NULL) {
		proc_name_kdp(task, cur_tsnap->ts_p_comm, sizeof(cur_tsnap->ts_p_comm));
#if CONFIG_COALITIONS
		if (trace_flags & STACKSHOT_SAVE_JETSAM_COALITIONS) {
			uint64_t jetsam_coal_id = coalition_id(task->coalition[COALITION_TYPE_JETSAM]);
			kcd_exit_on_error(kcdata_get_memory_addr(kcd, STACKSHOT_KCTYPE_JETSAM_COALITION, sizeof(jetsam_coal_id), &out_addr));
			stackshot_memcpy((void*)out_addr, &jetsam_coal_id, sizeof(jetsam_coal_id));
		}
#endif /* CONFIG_COALITIONS */
	}
	else {
		cur_tsnap->ts_p_comm[0] = '\0';
#if IMPORTANCE_INHERITANCE && (DEVELOPMENT || DEBUG)
		if (task->task_imp_base != NULL) {
			stackshot_strlcpy(cur_tsnap->ts_p_comm, &task->task_imp_base->iit_procname[0],
			        MIN((int)sizeof(task->task_imp_base->iit_procname), (int)sizeof(cur_tsnap->ts_p_comm)));
		}
#endif /* IMPORTANCE_INHERITANCE && (DEVELOPMENT || DEBUG) */
	}

	if (collect_iostats) {
		kcd_exit_on_error(kcdata_record_task_iostats(kcd, task));
	}

#if MONOTONIC
	if (collect_instrs_cycles) {
		uint64_t instrs = 0, cycles = 0;
		mt_stackshot_task(task, &instrs, &cycles);

		kcd_exit_on_error(kcdata_get_memory_addr(kcd, STACKSHOT_KCTYPE_INSTRS_CYCLES, sizeof(struct instrs_cycles_snapshot), &out_addr));
		struct instrs_cycles_snapshot *instrs_cycles = (struct instrs_cycles_snapshot *)out_addr;
		instrs_cycles->ics_instructions = instrs;
		instrs_cycles->ics_cycles = cycles;
	}
#endif /* MONOTONIC */

error_exit:
	return error;
}

static kern_return_t
kcdata_record_task_delta_snapshot(kcdata_descriptor_t kcd, task_t task, boolean_t have_pmap, unaligned_u64 **task_snap_ss_flags)
{
	kern_return_t error                       = KERN_SUCCESS;
	struct task_delta_snapshot_v2 * cur_tsnap = NULL;
	mach_vm_address_t out_addr                = 0;

	uint64_t task_uniqueid = get_task_uniqueid(task);
	assert(task_snap_ss_flags != NULL);

	kcd_exit_on_error(kcdata_get_memory_addr(kcd, STACKSHOT_KCTYPE_TASK_DELTA_SNAPSHOT, sizeof(struct task_delta_snapshot_v2), &out_addr));

	cur_tsnap = (struct task_delta_snapshot_v2 *)out_addr;

	cur_tsnap->tds_unique_pid = task_uniqueid;
	cur_tsnap->tds_ss_flags = kcdata_get_task_ss_flags(task);
	*task_snap_ss_flags = (unaligned_u64 *)&cur_tsnap->tds_ss_flags;

	cur_tsnap->tds_user_time_in_terminated_threads = task->total_user_time;
	cur_tsnap->tds_system_time_in_terminated_threads = task->total_system_time;

#if CONFIG_EMBEDDED
	cur_tsnap->tds_task_size = have_pmap ? get_task_phys_footprint(task) : 0;
#else
	cur_tsnap->tds_task_size = have_pmap ? (pmap_resident_count(task->map->pmap) * PAGE_SIZE) : 0;
#endif

	cur_tsnap->tds_max_resident_size = get_task_resident_max(task);
	cur_tsnap->tds_suspend_count = task->suspend_count;
	cur_tsnap->tds_faults            = task->faults;
	cur_tsnap->tds_pageins           = task->pageins;
	cur_tsnap->tds_cow_faults        = task->cow_faults;
	cur_tsnap->tds_was_throttled     = (uint32_t)proc_was_throttled_from_task(task);
	cur_tsnap->tds_did_throttle      = (uint32_t)proc_did_throttle_from_task(task);
	cur_tsnap->tds_latency_qos       = (task-> effective_policy.tep_latency_qos == LATENCY_QOS_TIER_UNSPECIFIED)
	                                 ? LATENCY_QOS_TIER_UNSPECIFIED
	                                 : ((0xFF << 16) | task-> effective_policy.tep_latency_qos);

error_exit:
	return error;
}

static kern_return_t
kcdata_record_thread_iostats(kcdata_descriptor_t kcd, thread_t thread)
{
	kern_return_t error = KERN_SUCCESS;
	mach_vm_address_t out_addr = 0;

	/* I/O Statistics */
	assert(IO_NUM_PRIORITIES == STACKSHOT_IO_NUM_PRIORITIES);
	if (thread->thread_io_stats && !memory_iszero(thread->thread_io_stats, sizeof(struct io_stat_info))) {
		kcd_exit_on_error(kcdata_get_memory_addr(kcd, STACKSHOT_KCTYPE_IOSTATS, sizeof(struct io_stats_snapshot), &out_addr));
		struct io_stats_snapshot *_iostat = (struct io_stats_snapshot *)out_addr;
		_iostat->ss_disk_reads_count = thread->thread_io_stats->disk_reads.count;
		_iostat->ss_disk_reads_size = thread->thread_io_stats->disk_reads.size;
		_iostat->ss_disk_writes_count = (thread->thread_io_stats->total_io.count - thread->thread_io_stats->disk_reads.count);
		_iostat->ss_disk_writes_size = (thread->thread_io_stats->total_io.size - thread->thread_io_stats->disk_reads.size);
		_iostat->ss_paging_count = thread->thread_io_stats->paging.count;
		_iostat->ss_paging_size = thread->thread_io_stats->paging.size;
		_iostat->ss_non_paging_count = (thread->thread_io_stats->total_io.count - thread->thread_io_stats->paging.count);
		_iostat->ss_non_paging_size = (thread->thread_io_stats->total_io.size - thread->thread_io_stats->paging.size);
		_iostat->ss_metadata_count = thread->thread_io_stats->metadata.count;
		_iostat->ss_metadata_size = thread->thread_io_stats->metadata.size;
		_iostat->ss_data_count = (thread->thread_io_stats->total_io.count - thread->thread_io_stats->metadata.count);
		_iostat->ss_data_size = (thread->thread_io_stats->total_io.size - thread->thread_io_stats->metadata.size);
		for(int i = 0; i < IO_NUM_PRIORITIES; i++) {
			_iostat->ss_io_priority_count[i] = thread->thread_io_stats->io_priority[i].count;
			_iostat->ss_io_priority_size[i] = thread->thread_io_stats->io_priority[i].size;
		}
	}

error_exit:
	return error;
}

static kern_return_t
kcdata_record_thread_snapshot(
    kcdata_descriptor_t kcd, thread_t thread, task_t task, uint32_t trace_flags, boolean_t have_pmap, boolean_t thread_on_core)
{
	boolean_t dispatch_p              = ((trace_flags & STACKSHOT_GET_DQ) != 0);
	boolean_t active_kthreads_only_p  = ((trace_flags & STACKSHOT_ACTIVE_KERNEL_THREADS_ONLY) != 0);
	boolean_t trace_fp_p              = false;
	boolean_t collect_delta_stackshot = ((trace_flags & STACKSHOT_COLLECT_DELTA_SNAPSHOT) != 0);
	boolean_t collect_iostats         = !collect_delta_stackshot && !(trace_flags & STACKSHOT_TAILSPIN) && !(trace_flags & STACKSHOT_NO_IO_STATS);
#if MONOTONIC
	boolean_t collect_instrs_cycles   = ((trace_flags & STACKSHOT_INSTRS_CYCLES) != 0);
#endif /* MONOTONIC */

	kern_return_t error        = KERN_SUCCESS;
	mach_vm_address_t out_addr = 0;
	int saved_count            = 0;

	struct thread_snapshot_v4 * cur_thread_snap = NULL;
	char cur_thread_name[STACKSHOT_MAX_THREAD_NAME_SIZE];
	uint64_t tval    = 0;
	boolean_t task64 = task_has_64BitAddr(task);

	kcd_exit_on_error(kcdata_get_memory_addr(kcd, STACKSHOT_KCTYPE_THREAD_SNAPSHOT, sizeof(struct thread_snapshot_v4), &out_addr));
	cur_thread_snap = (struct thread_snapshot_v4 *)out_addr;

	/* Populate the thread snapshot header */
	cur_thread_snap->ths_thread_id      = thread_tid(thread);
	cur_thread_snap->ths_wait_event = VM_KERNEL_UNSLIDE_OR_PERM(thread->wait_event);
	cur_thread_snap->ths_continuation = VM_KERNEL_UNSLIDE(thread->continuation);
	cur_thread_snap->ths_total_syscalls = thread->syscalls_mach + thread->syscalls_unix;

	if (IPC_VOUCHER_NULL != thread->ith_voucher)
		cur_thread_snap->ths_voucher_identifier = VM_KERNEL_ADDRPERM(thread->ith_voucher);
	else
		cur_thread_snap->ths_voucher_identifier = 0;

	cur_thread_snap->ths_dqserialnum = 0;
	if (dispatch_p && (task != kernel_task) && (task->active) && have_pmap) {
		uint64_t dqkeyaddr = thread_dispatchqaddr(thread);
		if (dqkeyaddr != 0) {
			uint64_t dqaddr = 0;
			boolean_t copyin_ok = kdp_copyin_word(task, dqkeyaddr, &dqaddr, FALSE, NULL);
			if (copyin_ok && dqaddr != 0) {
				uint64_t dqserialnumaddr = dqaddr + get_task_dispatchqueue_serialno_offset(task);
				uint64_t dqserialnum = 0;
				copyin_ok = kdp_copyin_word(task, dqserialnumaddr, &dqserialnum, FALSE, NULL);
				if (copyin_ok) {
					cur_thread_snap->ths_ss_flags |= kHasDispatchSerial;
					cur_thread_snap->ths_dqserialnum = dqserialnum;
				}
			}
		}
	}

	tval = safe_grab_timer_value(&thread->user_timer);
	cur_thread_snap->ths_user_time = tval;
	tval = safe_grab_timer_value(&thread->system_timer);

	if (thread->precise_user_kernel_time) {
		cur_thread_snap->ths_sys_time = tval;
	} else {
		cur_thread_snap->ths_user_time += tval;
		cur_thread_snap->ths_sys_time = 0;
	}

	cur_thread_snap->ths_ss_flags = 0;
	if (thread->thread_tag & THREAD_TAG_MAINTHREAD)
		cur_thread_snap->ths_ss_flags |= kThreadMain;
	if (thread->effective_policy.thep_darwinbg)
		cur_thread_snap->ths_ss_flags |= kThreadDarwinBG;
	if (proc_get_effective_thread_policy(thread, TASK_POLICY_PASSIVE_IO))
		cur_thread_snap->ths_ss_flags |= kThreadIOPassive;
	if (thread->suspend_count > 0)
		cur_thread_snap->ths_ss_flags |= kThreadSuspended;
	if (thread->options & TH_OPT_GLOBAL_FORCED_IDLE)
		cur_thread_snap->ths_ss_flags |= kGlobalForcedIdle;
	if (thread_on_core)
		cur_thread_snap->ths_ss_flags |= kThreadOnCore;
	if (stackshot_thread_is_idle_worker_unsafe(thread))
		cur_thread_snap->ths_ss_flags |= kThreadIdleWorker;

	/* make sure state flags defined in kcdata.h still match internal flags */
	static_assert(SS_TH_WAIT == TH_WAIT);
	static_assert(SS_TH_SUSP == TH_SUSP);
	static_assert(SS_TH_RUN == TH_RUN);
	static_assert(SS_TH_UNINT == TH_UNINT);
	static_assert(SS_TH_TERMINATE == TH_TERMINATE);
	static_assert(SS_TH_TERMINATE2 == TH_TERMINATE2);
	static_assert(SS_TH_IDLE == TH_IDLE);

	cur_thread_snap->ths_last_run_time           = thread->last_run_time;
	cur_thread_snap->ths_last_made_runnable_time = thread->last_made_runnable_time;
	cur_thread_snap->ths_state                   = thread->state;
	cur_thread_snap->ths_sched_flags             = thread->sched_flags;
	cur_thread_snap->ths_base_priority = thread->base_pri;
	cur_thread_snap->ths_sched_priority = thread->sched_pri;
	cur_thread_snap->ths_eqos = thread->effective_policy.thep_qos;
	cur_thread_snap->ths_rqos = thread->requested_policy.thrp_qos;
	cur_thread_snap->ths_rqos_override = thread->requested_policy.thrp_qos_override;
	cur_thread_snap->ths_io_tier = proc_get_effective_thread_policy(thread, TASK_POLICY_IO);
	cur_thread_snap->ths_thread_t = VM_KERNEL_UNSLIDE_OR_PERM(thread);

	static_assert(sizeof(thread->effective_policy) == sizeof(uint64_t));
	static_assert(sizeof(thread->requested_policy) == sizeof(uint64_t));
	cur_thread_snap->ths_requested_policy = *(unaligned_u64 *) &thread->requested_policy;
	cur_thread_snap->ths_effective_policy = *(unaligned_u64 *) &thread->effective_policy;

	/* if there is thread name then add to buffer */
	cur_thread_name[0] = '\0';
	proc_threadname_kdp(thread->uthread, cur_thread_name, STACKSHOT_MAX_THREAD_NAME_SIZE);
	if (strnlen(cur_thread_name, STACKSHOT_MAX_THREAD_NAME_SIZE) > 0) {
		kcd_exit_on_error(kcdata_get_memory_addr(kcd, STACKSHOT_KCTYPE_THREAD_NAME, sizeof(cur_thread_name), &out_addr));
		stackshot_memcpy((void *)out_addr, (void *)cur_thread_name, sizeof(cur_thread_name));
	}

	/* record system and user cpu times */
	time_value_t user_time;
	time_value_t system_time;
	thread_read_times(thread, &user_time, &system_time);
	kcd_exit_on_error(kcdata_get_memory_addr(kcd, STACKSHOT_KCTYPE_CPU_TIMES, sizeof(struct stackshot_cpu_times), &out_addr));
	struct stackshot_cpu_times * stackshot_cpu_times = (struct stackshot_cpu_times *)out_addr;
	stackshot_cpu_times->user_usec                   = ((uint64_t)user_time.seconds) * USEC_PER_SEC + user_time.microseconds;
	stackshot_cpu_times->system_usec                 = ((uint64_t)system_time.seconds) * USEC_PER_SEC + system_time.microseconds;

	/* Trace user stack, if any */
	if (!active_kthreads_only_p && task->active && thread->task->map != kernel_map) {
		uint32_t thread_snapshot_flags = 0;
		/* 64-bit task? */
		if (task64) {
			out_addr    = (mach_vm_address_t)kcd_end_address(kcd);
			saved_count = machine_trace_thread64(thread, (char *)out_addr, (char *)kcd_max_address(kcd), MAX_FRAMES, TRUE,
			                                     trace_fp_p, &thread_snapshot_flags);
			if (saved_count > 0) {
				int frame_size = trace_fp_p ? sizeof(struct stack_snapshot_frame64) : sizeof(uint64_t);
				kcd_exit_on_error(kcdata_get_memory_addr_for_array(kcd, trace_fp_p ? STACKSHOT_KCTYPE_USER_STACKFRAME64
				                                                                   : STACKSHOT_KCTYPE_USER_STACKLR64,
				                                                   frame_size, saved_count / frame_size, &out_addr));
				cur_thread_snap->ths_ss_flags |= kUser64_p;
			}
		} else {
			out_addr    = (mach_vm_address_t)kcd_end_address(kcd);
			saved_count = machine_trace_thread(thread, (char *)out_addr, (char *)kcd_max_address(kcd), MAX_FRAMES, TRUE, trace_fp_p,
			                                   &thread_snapshot_flags);
			if (saved_count > 0) {
				int frame_size = trace_fp_p ? sizeof(struct stack_snapshot_frame32) : sizeof(uint32_t);
				kcd_exit_on_error(kcdata_get_memory_addr_for_array(kcd, trace_fp_p ? STACKSHOT_KCTYPE_USER_STACKFRAME
				                                                                   : STACKSHOT_KCTYPE_USER_STACKLR,
				                                                   frame_size, saved_count / frame_size, &out_addr));
			}
		}

		if (thread_snapshot_flags != 0) {
			cur_thread_snap->ths_ss_flags |= thread_snapshot_flags;
		}
	}

	/* Call through to the machine specific trace routines
	 * Frames are added past the snapshot header.
	 */
	if (thread->kernel_stack != 0) {
		uint32_t thread_snapshot_flags = 0;
#if defined(__LP64__)
		out_addr    = (mach_vm_address_t)kcd_end_address(kcd);
		saved_count = machine_trace_thread64(thread, (char *)out_addr, (char *)kcd_max_address(kcd), MAX_FRAMES, FALSE, trace_fp_p,
		                                     &thread_snapshot_flags);
		if (saved_count > 0) {
			int frame_size = trace_fp_p ? sizeof(struct stack_snapshot_frame64) : sizeof(uint64_t);
			cur_thread_snap->ths_ss_flags |= kKernel64_p;
			kcd_exit_on_error(kcdata_get_memory_addr_for_array(kcd, trace_fp_p ? STACKSHOT_KCTYPE_KERN_STACKFRAME64
			                                                                   : STACKSHOT_KCTYPE_KERN_STACKLR64,
			                                                   frame_size, saved_count / frame_size, &out_addr));
		}
#else
		out_addr             = (mach_vm_address_t)kcd_end_address(kcd);
		saved_count = machine_trace_thread(thread, (char *)out_addr, (char *)kcd_max_address(kcd), MAX_FRAMES, FALSE, trace_fp_p,
		                                   &thread_snapshot_flags);
		if (saved_count > 0) {
			int frame_size = trace_fp_p ? sizeof(struct stack_snapshot_frame32) : sizeof(uint32_t);
			kcd_exit_on_error(
			    kcdata_get_memory_addr_for_array(kcd, trace_fp_p ? STACKSHOT_KCTYPE_KERN_STACKFRAME : STACKSHOT_KCTYPE_KERN_STACKLR,
			                                     frame_size, saved_count / frame_size, &out_addr));
		}
#endif
		if (thread_snapshot_flags != 0) {
			cur_thread_snap->ths_ss_flags |= thread_snapshot_flags;
		}
	}


	if (collect_iostats) {
		kcd_exit_on_error(kcdata_record_thread_iostats(kcd, thread));
	}

#if MONOTONIC
	if (collect_instrs_cycles) {
		uint64_t instrs = 0, cycles = 0;
		mt_stackshot_thread(thread, &instrs, &cycles);

		kcd_exit_on_error(kcdata_get_memory_addr(kcd, STACKSHOT_KCTYPE_INSTRS_CYCLES, sizeof(struct instrs_cycles_snapshot), &out_addr));
		struct instrs_cycles_snapshot *instrs_cycles = (struct instrs_cycles_snapshot *)out_addr;
		instrs_cycles->ics_instructions = instrs;
		instrs_cycles->ics_cycles = cycles;
	}
#endif /* MONOTONIC */

error_exit:
	return error;
}

static int
kcdata_record_thread_delta_snapshot(struct thread_delta_snapshot_v2 * cur_thread_snap, thread_t thread, boolean_t thread_on_core)
{
	cur_thread_snap->tds_thread_id = thread_tid(thread);
	if (IPC_VOUCHER_NULL != thread->ith_voucher)
		cur_thread_snap->tds_voucher_identifier  = VM_KERNEL_ADDRPERM(thread->ith_voucher);
	else
		cur_thread_snap->tds_voucher_identifier = 0;

	cur_thread_snap->tds_ss_flags = 0;
	if (thread->effective_policy.thep_darwinbg)
		cur_thread_snap->tds_ss_flags |= kThreadDarwinBG;
	if (proc_get_effective_thread_policy(thread, TASK_POLICY_PASSIVE_IO))
		cur_thread_snap->tds_ss_flags |= kThreadIOPassive;
	if (thread->suspend_count > 0)
		cur_thread_snap->tds_ss_flags |= kThreadSuspended;
	if (thread->options & TH_OPT_GLOBAL_FORCED_IDLE)
		cur_thread_snap->tds_ss_flags |= kGlobalForcedIdle;
	if (thread_on_core)
		cur_thread_snap->tds_ss_flags |= kThreadOnCore;
	if (stackshot_thread_is_idle_worker_unsafe(thread))
		cur_thread_snap->tds_ss_flags |= kThreadIdleWorker;

	cur_thread_snap->tds_last_made_runnable_time = thread->last_made_runnable_time;
	cur_thread_snap->tds_state                   = thread->state;
	cur_thread_snap->tds_sched_flags             = thread->sched_flags;
	cur_thread_snap->tds_base_priority           = thread->base_pri;
	cur_thread_snap->tds_sched_priority          = thread->sched_pri;
	cur_thread_snap->tds_eqos                    = thread->effective_policy.thep_qos;
	cur_thread_snap->tds_rqos                    = thread->requested_policy.thrp_qos;
	cur_thread_snap->tds_rqos_override           = thread->requested_policy.thrp_qos_override;
	cur_thread_snap->tds_io_tier                 = proc_get_effective_thread_policy(thread, TASK_POLICY_IO);

	return 0;
}

/*
 * Why 12?  12 strikes a decent balance between allocating a large array on
 * the stack and having large kcdata item overheads for recording nonrunable
 * tasks.
 */
#define UNIQUEIDSPERFLUSH 12

struct saved_uniqueids {
	uint64_t ids[UNIQUEIDSPERFLUSH];
	unsigned count;
};

static kern_return_t
flush_nonrunnable_tasks(struct saved_uniqueids * ids)
{
	if (ids->count == 0)
		return KERN_SUCCESS;
	mach_vm_address_t out_addr = 0;
	kern_return_t ret = kcdata_get_memory_addr_for_array(stackshot_kcdata_p, STACKSHOT_KCTYPE_NONRUNNABLE_TASKS, sizeof(uint64_t),
	                                                     ids->count, &out_addr);
	if (ret != KERN_SUCCESS) {
		return ret;
	}
	stackshot_memcpy((void *)out_addr, ids->ids, sizeof(uint64_t) * ids->count);
	ids->count = 0;
	return ret;
}

static kern_return_t
handle_nonrunnable_task(struct saved_uniqueids * ids, uint64_t pid)
{
	kern_return_t ret    = KERN_SUCCESS;
	ids->ids[ids->count] = pid;
	ids->count++;
	assert(ids->count <= UNIQUEIDSPERFLUSH);
	if (ids->count == UNIQUEIDSPERFLUSH)
		ret = flush_nonrunnable_tasks(ids);
	return ret;
}

enum thread_classification {
	tc_full_snapshot,  /* take a full snapshot */
	tc_delta_snapshot, /* take a delta snapshot */
	tc_nonrunnable,    /* only report id */
};

static enum thread_classification
classify_thread(thread_t thread, boolean_t * thread_on_core_p, uint32_t trace_flags)
{
	boolean_t collect_delta_stackshot = ((trace_flags & STACKSHOT_COLLECT_DELTA_SNAPSHOT) != 0);
	boolean_t minimize_nonrunnables   = ((trace_flags & STACKSHOT_TAILSPIN) != 0);

	processor_t last_processor = thread->last_processor;

	boolean_t thread_on_core =
	    (last_processor != PROCESSOR_NULL && last_processor->state == PROCESSOR_RUNNING && last_processor->active_thread == thread);

	*thread_on_core_p = thread_on_core;

	/* Capture the full thread snapshot if this is not a delta stackshot or if the thread has run subsequent to the
	 * previous full stackshot */
	if (!collect_delta_stackshot || thread_on_core || (thread->last_run_time > stack_snapshot_delta_since_timestamp)) {
		return tc_full_snapshot;
	} else {
		if (minimize_nonrunnables && !(thread->state & TH_RUN)) {
			return tc_nonrunnable;
		} else {
			return tc_delta_snapshot;
		}
	}
}

static kern_return_t
kdp_stackshot_kcdata_format(int pid, uint32_t trace_flags, uint32_t * pBytesTraced)
{
	kern_return_t error        = KERN_SUCCESS;
	mach_vm_address_t out_addr = 0;
	uint64_t abs_time = 0, abs_time_end = 0;
	uint64_t *abs_time_addr = NULL;
	uint64_t system_state_flags = 0;
	int saved_count = 0;
	task_t task = TASK_NULL;
	thread_t thread = THREAD_NULL;
	mach_timebase_info_data_t timebase = {0, 0};
	uint32_t length_to_copy = 0, tmp32 = 0;

	abs_time = mach_absolute_time();

	/* process the flags */
	boolean_t active_kthreads_only_p  = ((trace_flags & STACKSHOT_ACTIVE_KERNEL_THREADS_ONLY) != 0);
	boolean_t save_donating_pids_p    = ((trace_flags & STACKSHOT_SAVE_IMP_DONATION_PIDS) != 0);
	boolean_t collect_delta_stackshot = ((trace_flags & STACKSHOT_COLLECT_DELTA_SNAPSHOT) != 0);
	boolean_t minimize_nonrunnables   = ((trace_flags & STACKSHOT_TAILSPIN) != 0);
	boolean_t use_fault_path          = ((trace_flags & (STACKSHOT_ENABLE_UUID_FAULTING | STACKSHOT_ENABLE_BT_FAULTING)) != 0);
	boolean_t save_owner_info         = ((trace_flags & STACKSHOT_THREAD_WAITINFO) != 0);
	stack_enable_faulting = (trace_flags & (STACKSHOT_ENABLE_BT_FAULTING));

#if CONFIG_EMBEDDED
	/* KEXTs can't be described by just a base address on embedded */
	trace_flags &= ~(STACKSHOT_SAVE_KEXT_LOADINFO);
#endif

	struct saved_uniqueids saved_uniqueids = {.count = 0};

	if (use_fault_path) {
		fault_stats.sfs_pages_faulted_in = 0;
		fault_stats.sfs_time_spent_faulting = 0;
		fault_stats.sfs_stopped_faulting = (uint8_t) FALSE;
	}

	if (sizeof(void *) == 8)
		system_state_flags |= kKernel64_p;

	if (stackshot_kcdata_p == NULL || pBytesTraced == NULL) {
		error = KERN_INVALID_ARGUMENT;
		goto error_exit;
	}

	/* setup mach_absolute_time and timebase info -- copy out in some cases and needed to convert since_timestamp to seconds for proc start time */
	clock_timebase_info(&timebase);

	/* begin saving data into the buffer */
	*pBytesTraced = 0;
	kcd_exit_on_error(kcdata_add_uint32_with_description(stackshot_kcdata_p, trace_flags, "stackshot_in_flags"));
	kcd_exit_on_error(kcdata_add_uint32_with_description(stackshot_kcdata_p, (uint32_t)pid, "stackshot_in_pid"));
	kcd_exit_on_error(kcdata_add_uint64_with_description(stackshot_kcdata_p, system_state_flags, "system_state_flags"));

#if CONFIG_JETSAM
	tmp32 = memorystatus_get_pressure_status_kdp();
	kcd_exit_on_error(kcdata_get_memory_addr(stackshot_kcdata_p, STACKSHOT_KCTYPE_JETSAM_LEVEL, sizeof(uint32_t), &out_addr));
	stackshot_memcpy((void *)out_addr, &tmp32, sizeof(tmp32));
#endif

	if (!collect_delta_stackshot) {
		tmp32 = THREAD_POLICY_INTERNAL_STRUCT_VERSION;
		kcd_exit_on_error(kcdata_get_memory_addr(stackshot_kcdata_p, STACKSHOT_KCTYPE_THREAD_POLICY_VERSION, sizeof(uint32_t), &out_addr));
		stackshot_memcpy((void *)out_addr, &tmp32, sizeof(tmp32));

		tmp32 = PAGE_SIZE;
		kcd_exit_on_error(kcdata_get_memory_addr(stackshot_kcdata_p, STACKSHOT_KCTYPE_KERN_PAGE_SIZE, sizeof(uint32_t), &out_addr));
		stackshot_memcpy((void *)out_addr, &tmp32, sizeof(tmp32));

		/* save boot-args and osversion string */
		length_to_copy =  MIN((uint32_t)(strlen(version) + 1), OSVERSIZE);
		kcd_exit_on_error(kcdata_get_memory_addr(stackshot_kcdata_p, STACKSHOT_KCTYPE_OSVERSION, length_to_copy, &out_addr));
		stackshot_strlcpy((char*)out_addr, &version[0], length_to_copy);

		length_to_copy =  MIN((uint32_t)(strlen(PE_boot_args()) + 1), OSVERSIZE);
		kcd_exit_on_error(kcdata_get_memory_addr(stackshot_kcdata_p, STACKSHOT_KCTYPE_BOOTARGS, length_to_copy, &out_addr));
		stackshot_strlcpy((char*)out_addr, PE_boot_args(), length_to_copy);

		kcd_exit_on_error(kcdata_get_memory_addr(stackshot_kcdata_p, KCDATA_TYPE_TIMEBASE, sizeof(timebase), &out_addr));
		stackshot_memcpy((void *)out_addr, &timebase, sizeof(timebase));
	} else {
		kcd_exit_on_error(kcdata_get_memory_addr(stackshot_kcdata_p, STACKSHOT_KCTYPE_DELTA_SINCE_TIMESTAMP, sizeof(uint64_t), &out_addr));
		stackshot_memcpy((void*)out_addr, &stack_snapshot_delta_since_timestamp, sizeof(stack_snapshot_delta_since_timestamp));
	}

	kcd_exit_on_error(kcdata_get_memory_addr(stackshot_kcdata_p, KCDATA_TYPE_MACH_ABSOLUTE_TIME, sizeof(uint64_t), &out_addr));
	abs_time_addr = (uint64_t *)out_addr;
	stackshot_memcpy((void *)abs_time_addr, &abs_time, sizeof(uint64_t));

	kcd_exit_on_error(kcdata_get_memory_addr(stackshot_kcdata_p, KCDATA_TYPE_USECS_SINCE_EPOCH, sizeof(uint64_t), &out_addr));
	stackshot_memcpy((void *)out_addr, &stackshot_microsecs, sizeof(uint64_t));

	/* reserve space of system level shared cache load info */
	struct dyld_uuid_info_64_v2 * sys_shared_cache_loadinfo = NULL;
	if (!collect_delta_stackshot) {
		kcd_exit_on_error(kcdata_get_memory_addr(stackshot_kcdata_p, STACKSHOT_KCTYPE_SHAREDCACHE_LOADINFO,
		                                         sizeof(struct dyld_uuid_info_64_v2), &out_addr));
		sys_shared_cache_loadinfo = (struct dyld_uuid_info_64_v2 *)out_addr;
		bzero((void *)sys_shared_cache_loadinfo, sizeof(struct dyld_uuid_info_64_v2));
	}

	/* Add requested information first */
	if (trace_flags & STACKSHOT_GET_GLOBAL_MEM_STATS) {
		kcd_exit_on_error(kcdata_get_memory_addr(stackshot_kcdata_p, STACKSHOT_KCTYPE_GLOBAL_MEM_STATS, sizeof(struct mem_and_io_snapshot), &out_addr));
		kdp_mem_and_io_snapshot((struct mem_and_io_snapshot *)out_addr);
	}

#if CONFIG_COALITIONS
	int num_coalitions = 0;
	struct jetsam_coalition_snapshot *coalitions = NULL;
	/* Iterate over coalitions */
	if (trace_flags & STACKSHOT_SAVE_JETSAM_COALITIONS) {
		if (coalition_iterate_stackshot(stackshot_coalition_jetsam_count, &num_coalitions, COALITION_TYPE_JETSAM) != KERN_SUCCESS) {
			trace_flags &= ~(STACKSHOT_SAVE_JETSAM_COALITIONS);
		}
	}
	if (trace_flags & STACKSHOT_SAVE_JETSAM_COALITIONS) {
		if (num_coalitions > 0) {
			kcd_exit_on_error(kcdata_get_memory_addr_for_array(stackshot_kcdata_p, STACKSHOT_KCTYPE_JETSAM_COALITION_SNAPSHOT, sizeof(struct jetsam_coalition_snapshot), num_coalitions, &out_addr));
			coalitions = (struct jetsam_coalition_snapshot*)out_addr;
		}

		if (coalition_iterate_stackshot(stackshot_coalition_jetsam_snapshot, coalitions, COALITION_TYPE_JETSAM) != KERN_SUCCESS) {
			error = KERN_FAILURE;
			goto error_exit;
		}

	}
#else
	trace_flags &= ~(STACKSHOT_SAVE_JETSAM_COALITIONS);
#endif /* CONFIG_COALITIONS */

	trace_flags &= ~(STACKSHOT_THREAD_GROUP);

	/* Iterate over tasks */
	queue_head_t *task_list = &tasks;
	queue_iterate(task_list, task, task_t, tasks) {
		int task_pid                   = 0;
		uint64_t task_uniqueid         = 0;
		int num_delta_thread_snapshots = 0;
		int num_nonrunnable_threads    = 0;
		int num_waitinfo_threads       = 0;

		uint64_t task_start_abstime    = 0;
		boolean_t task_delta_stackshot = FALSE;
		boolean_t task64 = FALSE, have_map = FALSE, have_pmap = FALSE;
		boolean_t some_thread_ran = FALSE;
		unaligned_u64 *task_snap_ss_flags = NULL;

		if ((task == NULL) || !ml_validate_nofault((vm_offset_t)task, sizeof(struct task))) {
			error = KERN_FAILURE;
			goto error_exit;
		}

		have_map = (task->map != NULL) && (ml_validate_nofault((vm_offset_t)(task->map), sizeof(struct _vm_map)));
		have_pmap = have_map && (task->map->pmap != NULL) && (ml_validate_nofault((vm_offset_t)(task->map->pmap), sizeof(struct pmap)));

		task_pid = pid_from_task(task);
		task_uniqueid = get_task_uniqueid(task);
		task64 = task_has_64BitAddr(task);

		if (!task->active || task_is_a_corpse(task)) {
			/*
			 * Not interested in terminated tasks without threads, and
			 * at the moment, stackshot can't handle a task  without a name.
			 */
			if (queue_empty(&task->threads) || task_pid == -1) {
				continue;
			}
		}

		if (collect_delta_stackshot) {
			proc_starttime_kdp(task->bsd_info, NULL, NULL, &task_start_abstime);
		}

		/* Trace everything, unless a process was specified */
		if ((pid == -1) || (pid == task_pid)) {
#if DEBUG || DEVELOPMENT
			/* we might want to call kcdata_undo_add_container_begin(), which is
			 * only safe if we call it after kcdata_add_container_marker() but
			 * before adding any other kcdata items.  In development kernels,
			 * we'll remember where the buffer end was and confirm after calling
			 * kcdata_undo_add_container_begin() that it's in exactly the same
			 * place.*/
			mach_vm_address_t revert_addr = stackshot_kcdata_p->kcd_addr_end;
#endif

			/* add task snapshot marker */
			kcd_exit_on_error(kcdata_add_container_marker(stackshot_kcdata_p, KCDATA_TYPE_CONTAINER_BEGIN,
			                                              STACKSHOT_KCCONTAINER_TASK, task_uniqueid));

			if (!collect_delta_stackshot || (task_start_abstime == 0) ||
			    (task_start_abstime > stack_snapshot_delta_since_timestamp)) {
				kcd_exit_on_error(kcdata_record_task_snapshot(stackshot_kcdata_p, task, trace_flags, have_pmap, &task_snap_ss_flags));
			} else {
				task_delta_stackshot = TRUE;
				if (minimize_nonrunnables) {
					// delay taking the task snapshot.  If there are no runnable threads we'll skip it.
				} else {
					kcd_exit_on_error(kcdata_record_task_delta_snapshot(stackshot_kcdata_p, task, have_pmap, &task_snap_ss_flags));
				}
			}

			/* Iterate over task threads */
			queue_iterate(&task->threads, thread, thread_t, task_threads)
			{
				uint64_t thread_uniqueid;

				if ((thread == NULL) || !ml_validate_nofault((vm_offset_t)thread, sizeof(struct thread))) {
					error = KERN_FAILURE;
					goto error_exit;
				}

				if (active_kthreads_only_p && thread->kernel_stack == 0)
					continue;

				thread_uniqueid = thread_tid(thread);

				boolean_t thread_on_core;
				enum thread_classification thread_classification = classify_thread(thread, &thread_on_core, trace_flags);

				switch (thread_classification) {
				case tc_full_snapshot:
					/* add thread marker */
					kcd_exit_on_error(kcdata_add_container_marker(stackshot_kcdata_p, KCDATA_TYPE_CONTAINER_BEGIN,
					                                              STACKSHOT_KCCONTAINER_THREAD, thread_uniqueid));
					kcd_exit_on_error(
					    kcdata_record_thread_snapshot(stackshot_kcdata_p, thread, task, trace_flags, have_pmap, thread_on_core));

					/* mark end of thread snapshot data */
					kcd_exit_on_error(kcdata_add_container_marker(stackshot_kcdata_p, KCDATA_TYPE_CONTAINER_END,
					                                              STACKSHOT_KCCONTAINER_THREAD, thread_uniqueid));

					some_thread_ran = TRUE;
					break;

				case tc_delta_snapshot:
					num_delta_thread_snapshots++;
					break;

				case tc_nonrunnable:
					num_nonrunnable_threads++;
					break;
				}

				/* We want to report owner information regardless of whether a thread
				 * has changed since the last delta, whether it's a normal stackshot,
				 * or whether it's nonrunnable */
				if (save_owner_info && stackshot_thread_has_valid_waitinfo(thread))
					num_waitinfo_threads++;
			}

			if (task_delta_stackshot && minimize_nonrunnables) {
				if (some_thread_ran || num_delta_thread_snapshots > 0) {
					kcd_exit_on_error(kcdata_record_task_delta_snapshot(stackshot_kcdata_p, task, have_pmap, &task_snap_ss_flags));
				} else {
					kcd_exit_on_error(kcdata_undo_add_container_begin(stackshot_kcdata_p));

#if DEBUG || DEVELOPMENT
					mach_vm_address_t undo_addr = stackshot_kcdata_p->kcd_addr_end;
					if (revert_addr != undo_addr) {
						panic("tried to revert a container begin but we already moved past it. revert=%p undo=%p",
						      (void *)revert_addr, (void *)undo_addr);
					}
#endif
					kcd_exit_on_error(handle_nonrunnable_task(&saved_uniqueids, task_uniqueid));
					continue;
				}
			}

			struct thread_delta_snapshot_v2 * delta_snapshots = NULL;
			int current_delta_snapshot_index                  = 0;

			if (num_delta_thread_snapshots > 0) {
				kcd_exit_on_error(kcdata_get_memory_addr_for_array(stackshot_kcdata_p, STACKSHOT_KCTYPE_THREAD_DELTA_SNAPSHOT,
				                                                   sizeof(struct thread_delta_snapshot_v2),
				                                                   num_delta_thread_snapshots, &out_addr));
				delta_snapshots = (struct thread_delta_snapshot_v2 *)out_addr;
			}

			uint64_t * nonrunnable_tids   = NULL;
			int current_nonrunnable_index = 0;

			if (num_nonrunnable_threads > 0) {
				kcd_exit_on_error(kcdata_get_memory_addr_for_array(stackshot_kcdata_p, STACKSHOT_KCTYPE_NONRUNNABLE_TIDS,
				                                                   sizeof(uint64_t), num_nonrunnable_threads, &out_addr));
				nonrunnable_tids = (uint64_t *)out_addr;
			}

			thread_waitinfo_t *thread_waitinfo = NULL;
			int current_waitinfo_index         = 0;

			if (num_waitinfo_threads > 0) {
				kcd_exit_on_error(kcdata_get_memory_addr_for_array(stackshot_kcdata_p, STACKSHOT_KCTYPE_THREAD_WAITINFO,
									   sizeof(thread_waitinfo_t), num_waitinfo_threads, &out_addr));
				thread_waitinfo = (thread_waitinfo_t *)out_addr;
			}

			if (num_delta_thread_snapshots > 0 || num_nonrunnable_threads > 0 || num_waitinfo_threads > 0) {
				queue_iterate(&task->threads, thread, thread_t, task_threads)
				{
					if (active_kthreads_only_p && thread->kernel_stack == 0)
						continue;

					/* If we want owner info, we should capture it regardless of its classification */
					if (save_owner_info && stackshot_thread_has_valid_waitinfo(thread)) {
						stackshot_thread_wait_owner_info(
								thread,
								&thread_waitinfo[current_waitinfo_index++]);
					}

					boolean_t thread_on_core;
					enum thread_classification thread_classification = classify_thread(thread, &thread_on_core, trace_flags);

					switch (thread_classification) {
					case tc_full_snapshot:
						/* full thread snapshot captured above */
						continue;

					case tc_delta_snapshot:
						kcd_exit_on_error(kcdata_record_thread_delta_snapshot(&delta_snapshots[current_delta_snapshot_index++],
						                                                      thread, thread_on_core));
						break;

					case tc_nonrunnable:
						nonrunnable_tids[current_nonrunnable_index++] = thread_tid(thread);
						continue;
					}
				}

#if DEBUG || DEVELOPMENT
				if (current_delta_snapshot_index != num_delta_thread_snapshots) {
					panic("delta thread snapshot count mismatch while capturing snapshots for task %p. expected %d, found %d", task,
					      num_delta_thread_snapshots, current_delta_snapshot_index);
				}
				if (current_nonrunnable_index != num_nonrunnable_threads) {
					panic("nonrunnable thread count mismatch while capturing snapshots for task %p. expected %d, found %d", task,
					      num_nonrunnable_threads, current_nonrunnable_index);
				}
				if (current_waitinfo_index != num_waitinfo_threads) {
					panic("thread wait info count mismatch while capturing snapshots for task %p. expected %d, found %d", task,
					      num_waitinfo_threads, current_waitinfo_index);
				}
#endif
			}

#if IMPORTANCE_INHERITANCE
			if (save_donating_pids_p) {
				kcd_exit_on_error(
				    ((((mach_vm_address_t)kcd_end_address(stackshot_kcdata_p) + (TASK_IMP_WALK_LIMIT * sizeof(int32_t))) <
				      (mach_vm_address_t)kcd_max_address(stackshot_kcdata_p))
				         ? KERN_SUCCESS
				         : KERN_RESOURCE_SHORTAGE));
				saved_count = task_importance_list_pids(task, TASK_IMP_LIST_DONATING_PIDS,
				                                        (void *)kcd_end_address(stackshot_kcdata_p), TASK_IMP_WALK_LIMIT);
				if (saved_count > 0)
					kcd_exit_on_error(kcdata_get_memory_addr_for_array(stackshot_kcdata_p, STACKSHOT_KCTYPE_DONATING_PIDS,
					                                                   sizeof(int32_t), saved_count, &out_addr));
			}
#endif

			if (!collect_delta_stackshot || (num_delta_thread_snapshots != task->thread_count) || !task_delta_stackshot) {
				/*
				 * Collect shared cache info and UUID info in these scenarios
				 * 1) a full stackshot
				 * 2) a delta stackshot where the task started after the previous full stackshot OR
				 *    any thread from the task has run since the previous full stackshot
				 */

				kcd_exit_on_error(kcdata_record_shared_cache_info(stackshot_kcdata_p, task, sys_shared_cache_loadinfo, task_snap_ss_flags));
				kcd_exit_on_error(kcdata_record_uuid_info(stackshot_kcdata_p, task, trace_flags, have_pmap, task_snap_ss_flags));
			}
			/* mark end of task snapshot data */
			kcd_exit_on_error(kcdata_add_container_marker(stackshot_kcdata_p, KCDATA_TYPE_CONTAINER_END, STACKSHOT_KCCONTAINER_TASK,
			                                              task_uniqueid));
		}
	}

	if (minimize_nonrunnables) {
		flush_nonrunnable_tasks(&saved_uniqueids);
	}

	if (use_fault_path) {
		kcd_exit_on_error(kcdata_get_memory_addr(stackshot_kcdata_p, STACKSHOT_KCTYPE_STACKSHOT_FAULT_STATS,
								sizeof(struct stackshot_fault_stats), &out_addr));
		stackshot_memcpy((void*)out_addr, &fault_stats, sizeof(struct stackshot_fault_stats));
	}

	/* update timestamp of the stackshot */
	abs_time_end = mach_absolute_time();
#if DEVELOPMENT || DEBUG
	kcd_exit_on_error(kcdata_get_memory_addr(stackshot_kcdata_p, STACKSHOT_KCTYPE_STACKSHOT_DURATION,
	                                         sizeof(struct stackshot_duration), &out_addr));
	struct stackshot_duration * stackshot_duration = (struct stackshot_duration *)out_addr;
	stackshot_duration->stackshot_duration         = (abs_time_end - abs_time);
	stackshot_duration->stackshot_duration_outer   = 0;
	stackshot_duration_outer                       = (unaligned_u64 *)&stackshot_duration->stackshot_duration_outer;
#endif
	stackshot_memcpy((void *)abs_time_addr, &abs_time_end, sizeof(uint64_t));

	kcd_exit_on_error(kcdata_add_uint32_with_description(stackshot_kcdata_p, trace_flags, "stackshot_out_flags"));

	kcd_exit_on_error(kcdata_write_buffer_end(stackshot_kcdata_p));

	/*  === END of populating stackshot data === */

	*pBytesTraced = (uint32_t) kcdata_memory_get_used_bytes(stackshot_kcdata_p);
error_exit:

#if INTERRUPT_MASKED_DEBUG
	if (!panic_stackshot) {
		/*
		 * Try to catch instances where stackshot takes too long BEFORE returning from
		 * the debugger
		 */
		ml_check_interrupts_disabled_duration(current_thread());
	}
#endif

	stack_enable_faulting = FALSE;

	return error;
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

void
stackshot_memcpy(void *dst, const void *src, size_t len)
{
#if CONFIG_EMBEDDED
	if (panic_stackshot) {
		uint8_t *dest_bytes = (uint8_t *)dst;
		const uint8_t *src_bytes = (const uint8_t *)src;
		for (size_t i = 0; i < len; i++) {
			dest_bytes[i] = src_bytes[i];
		}
	} else
#endif
		memcpy(dst, src, len);
}

size_t
stackshot_strlcpy(char *dst, const char *src, size_t maxlen)
{
	const size_t srclen = strlen(src);

	if (srclen < maxlen) {
		stackshot_memcpy(dst, src, srclen+1);
	} else if (maxlen != 0) {
		stackshot_memcpy(dst, src, maxlen-1);
		dst[maxlen-1] = '\0';
	}

	return srclen;
}


/*
 * Returns the physical address of the specified map:target address,
 * using the kdp fault path if requested and the page is not resident.
 */
vm_offset_t
kdp_find_phys(vm_map_t map, vm_offset_t target_addr, boolean_t try_fault, uint32_t *kdp_fault_results)
{
	vm_offset_t cur_phys_addr;
	unsigned cur_wimg_bits;
	uint64_t fault_start_time = 0;

	if (map == VM_MAP_NULL) {
		return 0;
	}

	cur_phys_addr = kdp_vtophys(map->pmap, target_addr);
	if (!pmap_valid_page((ppnum_t) atop(cur_phys_addr))) {
		if (!try_fault || fault_stats.sfs_stopped_faulting) {
			if (kdp_fault_results)
				*kdp_fault_results |= KDP_FAULT_RESULT_PAGED_OUT;

			return 0;
		}

		/*
		 * The pmap doesn't have a valid page so we start at the top level
		 * vm map and try a lightweight fault. Update fault path usage stats.
		 */
		fault_start_time = mach_absolute_time();
		cur_phys_addr = kdp_lightweight_fault(map, (target_addr & ~PAGE_MASK));
		fault_stats.sfs_time_spent_faulting += (mach_absolute_time() - fault_start_time);

		if ((fault_stats.sfs_time_spent_faulting >= fault_stats.sfs_system_max_fault_time) && !panic_stackshot) {
			fault_stats.sfs_stopped_faulting = (uint8_t) TRUE;
		}

		cur_phys_addr += (target_addr & PAGE_MASK);

		if (!pmap_valid_page((ppnum_t) atop(cur_phys_addr))) {
			if (kdp_fault_results)
				*kdp_fault_results |= (KDP_FAULT_RESULT_TRIED_FAULT | KDP_FAULT_RESULT_PAGED_OUT);

			return 0;
		}

		if (kdp_fault_results)
			*kdp_fault_results |= KDP_FAULT_RESULT_FAULTED_IN;

		fault_stats.sfs_pages_faulted_in++;
	} else {
		/*
		 * This check is done in kdp_lightweight_fault for the fault path.
		 */
		cur_wimg_bits = pmap_cache_attributes((ppnum_t) atop(cur_phys_addr));

		if ((cur_wimg_bits & VM_WIMG_MASK) != VM_WIMG_DEFAULT) {
			return 0;
		}
	}

	return cur_phys_addr;
}

boolean_t
kdp_copyin_word(
	task_t task, uint64_t addr, uint64_t *result, boolean_t try_fault, uint32_t *kdp_fault_results)
{
	if (task_has_64BitAddr(task)) {
		return kdp_copyin(task->map, addr, result, sizeof(uint64_t), try_fault, kdp_fault_results);
	} else {
		uint32_t buf;
		boolean_t r = kdp_copyin(task->map, addr, &buf, sizeof(uint32_t), try_fault, kdp_fault_results);
		*result = buf;
		return r;
	}
}

boolean_t
kdp_copyin(vm_map_t map, uint64_t uaddr, void *dest, size_t size, boolean_t try_fault, uint32_t *kdp_fault_results)
{
	size_t rem = size;
	char *kvaddr = dest;

#if CONFIG_EMBEDDED
	/* Identify if destination buffer is in panic storage area */
	if (panic_stackshot && ((vm_offset_t)dest >= gPanicBase) && ((vm_offset_t)dest < (gPanicBase + gPanicSize))) {
		if (((vm_offset_t)dest + size) > (gPanicBase + gPanicSize)) {
			return FALSE;
		}
	}
#endif

	while (rem) {
		uint64_t phys_src = kdp_find_phys(map, uaddr, try_fault, kdp_fault_results);
		uint64_t phys_dest = kvtophys((vm_offset_t)kvaddr);
		uint64_t src_rem = PAGE_SIZE - (phys_src & PAGE_MASK);
		uint64_t dst_rem = PAGE_SIZE - (phys_dest & PAGE_MASK);
		size_t cur_size = (uint32_t) MIN(src_rem, dst_rem);
		cur_size = MIN(cur_size, rem);

		if (phys_src && phys_dest) {
#if CONFIG_EMBEDDED
			/*
			 * On embedded the panic buffer is mapped as device memory and doesn't allow
			 * unaligned accesses. To prevent these, we copy over bytes individually here.
			 */
			if (panic_stackshot)
				stackshot_memcpy(kvaddr, (const void *)phystokv(phys_src), cur_size);
			else
#endif /* CONFIG_EMBEDDED */
				bcopy_phys(phys_src, phys_dest, cur_size);
		} else {
			break;
		}

		uaddr += cur_size;
		kvaddr += cur_size;
		rem -= cur_size;
	}

	return (rem == 0);
}

kern_return_t
do_stackshot(void *context)
{
#pragma unused(context)
	kdp_snapshot++;

	stack_snapshot_ret = kdp_stackshot_kcdata_format(stack_snapshot_pid,
	    stack_snapshot_flags,
	    &stack_snapshot_bytes_traced);

	kdp_snapshot--;
	return stack_snapshot_ret;
}

/*
 * A fantastical routine that tries to be fast about returning
 * translations.  Caches the last page we found a translation
 * for, so that we can be quick about multiple queries to the
 * same page.  It turns out this is exactly the workflow
 * machine_trace_thread and its relatives tend to throw at us.
 *
 * Please zero the nasty global this uses after a bulk lookup;
 * this isn't safe across a switch of the map or changes
 * to a pmap.
 *
 * This also means that if zero is a valid KVA, we are
 * screwed.  Sucks to be us.  Fortunately, this should never
 * happen.
 */
vm_offset_t
machine_trace_thread_get_kva(vm_offset_t cur_target_addr, vm_map_t map, uint32_t *thread_trace_flags)
{
	vm_offset_t cur_target_page;
	vm_offset_t cur_phys_addr;
	vm_offset_t kern_virt_target_addr;
	uint32_t kdp_fault_results = 0;

	cur_target_page = atop(cur_target_addr);

	if ((cur_target_page != prev_target_page) || validate_next_addr) {

		/*
		 * Alright; it wasn't our previous page.  So
		 * we must validate that there is a page
		 * table entry for this address under the
		 * current pmap, and that it has default
		 * cache attributes (otherwise it may not be
		 * safe to access it).
		 */
		cur_phys_addr = kdp_find_phys(map, cur_target_addr, stack_enable_faulting, &kdp_fault_results);
		if (thread_trace_flags) {
			if (kdp_fault_results & KDP_FAULT_RESULT_PAGED_OUT) {
				*thread_trace_flags |= kThreadTruncatedBT;
			}

			if (kdp_fault_results & KDP_FAULT_RESULT_TRIED_FAULT) {
				*thread_trace_flags |= kThreadTriedFaultBT;
			}

			if (kdp_fault_results & KDP_FAULT_RESULT_FAULTED_IN) {
				*thread_trace_flags |= kThreadFaultedBT;
			}
		}

		if (cur_phys_addr == 0) {
			return 0;
		}
#if __x86_64__
		kern_virt_target_addr = (vm_offset_t) PHYSMAP_PTOV(cur_phys_addr);
#elif __arm__ || __arm64__
		kern_virt_target_addr = phystokv(cur_phys_addr);
#else
#error Oh come on... we should really unify the physical -> kernel virtual interface
#endif
		prev_target_page = cur_target_page;
		prev_target_kva = (kern_virt_target_addr & ~PAGE_MASK);
		validate_next_addr = FALSE;
	} else {
		/* We found a translation, so stash this page */
		kern_virt_target_addr = prev_target_kva + (cur_target_addr & PAGE_MASK);
	}

#if KASAN
	kasan_notify_address(kern_virt_target_addr, sizeof(uint64_t));
#endif
	return kern_virt_target_addr;
}

void
machine_trace_thread_clear_validation_cache(void)
{
	validate_next_addr = TRUE;
}

boolean_t
stackshot_thread_is_idle_worker_unsafe(thread_t thread)
{
	/* When the pthread kext puts a worker thread to sleep, it will
	 * set kThreadWaitParkedWorkQueue in the block_hint of the thread
	 * struct. See parkit() in kern/kern_support.c in libpthread.
	 */
	return (thread->state & TH_WAIT) &&
		(thread->block_hint == kThreadWaitParkedWorkQueue);
}

#if CONFIG_COALITIONS
static void
stackshot_coalition_jetsam_count(void *arg, int i, coalition_t coal)
{
#pragma unused(i, coal)
	unsigned int *coalition_count = (unsigned int*)arg;
	(*coalition_count)++;
}

static void
stackshot_coalition_jetsam_snapshot(void *arg, int i, coalition_t coal)
{
	if (coalition_type(coal) != COALITION_TYPE_JETSAM)
		return;

	struct jetsam_coalition_snapshot *coalitions = (struct jetsam_coalition_snapshot*)arg;
	struct jetsam_coalition_snapshot *jcs = &coalitions[i];
	task_t leader = TASK_NULL;
	jcs->jcs_id = coalition_id(coal);
	jcs->jcs_flags = 0;

	if (coalition_term_requested(coal))
		jcs->jcs_flags |= kCoalitionTermRequested;
	if (coalition_is_terminated(coal))
		jcs->jcs_flags |= kCoalitionTerminated;
	if (coalition_is_reaped(coal))
		jcs->jcs_flags |= kCoalitionReaped;
	if (coalition_is_privileged(coal))
		jcs->jcs_flags |= kCoalitionPrivileged;


	leader = kdp_coalition_get_leader(coal);
	if (leader)
		jcs->jcs_leader_task_uniqueid = get_task_uniqueid(leader);
	else
		jcs->jcs_leader_task_uniqueid = 0;
}
#endif /* CONFIG_COALITIONS */


/* Determine if a thread has waitinfo that stackshot can provide */
static int
stackshot_thread_has_valid_waitinfo(thread_t thread)
{
	if (!(thread->state & TH_WAIT))
		return 0;

	switch (thread->block_hint) {
		// If set to None or is a parked work queue, ignore it
		case kThreadWaitParkedWorkQueue:
		case kThreadWaitNone:
			return 0;
		// There is a short window where the pthread kext removes a thread
		// from its ksyn wait queue before waking the thread up
		case kThreadWaitPThreadMutex:
		case kThreadWaitPThreadRWLockRead:
		case kThreadWaitPThreadRWLockWrite:
		case kThreadWaitPThreadCondVar:
			return (kdp_pthread_get_thread_kwq(thread) != NULL);
		// All other cases are valid block hints if in a wait state
		default:
			return 1;
	}
}

static void
stackshot_thread_wait_owner_info(thread_t thread, thread_waitinfo_t *waitinfo)
{
	waitinfo->waiter    = thread_tid(thread);
	waitinfo->wait_type = thread->block_hint;
	switch (waitinfo->wait_type) {
		case kThreadWaitKernelMutex:
			kdp_lck_mtx_find_owner(thread->waitq, thread->wait_event, waitinfo);
			break;
		case kThreadWaitPortReceive:
			kdp_mqueue_recv_find_owner(thread->waitq, thread->wait_event, waitinfo);
			break;
		case kThreadWaitPortSend:
			kdp_mqueue_send_find_owner(thread->waitq, thread->wait_event, waitinfo);
			break;
		case kThreadWaitSemaphore:
			kdp_sema_find_owner(thread->waitq, thread->wait_event, waitinfo);
			break;
		case kThreadWaitUserLock:
			kdp_ulock_find_owner(thread->waitq, thread->wait_event, waitinfo);
			break;
		case kThreadWaitKernelRWLockRead:
		case kThreadWaitKernelRWLockWrite:
		case kThreadWaitKernelRWLockUpgrade:
			kdp_rwlck_find_owner(thread->waitq, thread->wait_event, waitinfo);
			break;
		case kThreadWaitPThreadMutex:
		case kThreadWaitPThreadRWLockRead:
		case kThreadWaitPThreadRWLockWrite:
		case kThreadWaitPThreadCondVar:
			kdp_pthread_find_owner(thread, waitinfo);
			break;
		case kThreadWaitWorkloopSyncWait:
			kdp_workloop_sync_wait_find_owner(thread, thread->wait_event, waitinfo);
			break;
		default:
			waitinfo->owner = 0;
			waitinfo->context = 0;
			break;
	}
}

