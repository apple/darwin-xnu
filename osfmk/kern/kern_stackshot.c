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
#include <mach/mach_vm.h>
#include <sys/errno.h>
#include <sys/stackshot.h>
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
#include <kern/telemetry.h>
#include <kern/clock.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_pageout.h>
#include <vm/vm_fault.h>
#include <vm/vm_shared_region.h>
#include <libkern/OSKextLibPrivate.h>

#if (defined(__arm64__) || defined(NAND_PANIC_DEVICE)) && !defined(LEGACY_PANIC_LOGS)
#include <pexpert/pexpert.h> /* For gPanicBase/gPanicBase */
#endif

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
static uint32_t stack_snapshot_bytes_traced = 0;

static kcdata_descriptor_t stackshot_kcdata_p = NULL;
static void *stack_snapshot_buf;
static uint32_t stack_snapshot_bufsize;
int stack_snapshot_pid;
static uint32_t stack_snapshot_flags;
static unsigned int old_debugger;
static boolean_t stack_enable_faulting;

void *kernel_stackshot_buf = NULL; /* Pointer to buffer for stackshots triggered from the kernel and retrieved later */
int kernel_stackshot_buf_size =  0;

void *stackshot_snapbuf = NULL; /* Used by stack_snapshot2 (to be removed) */

__private_extern__ void stackshot_lock_init( void );
static boolean_t memory_iszero(void *addr, size_t size);
kern_return_t		stack_snapshot2(int pid, user_addr_t tracebuf, uint32_t tracebuf_size, uint32_t flags, int32_t *retval);
kern_return_t		stack_snapshot_from_kernel_internal(int pid, void *buf, uint32_t size, uint32_t flags, unsigned *bytes_traced);
#if CONFIG_TELEMETRY
kern_return_t		stack_microstackshot(user_addr_t tracebuf, uint32_t tracebuf_size, uint32_t flags, int32_t *retval);
#endif
uint32_t		get_stackshot_estsize(uint32_t prev_size_hint);
kern_return_t		kern_stack_snapshot_internal(int stackshot_config_version, void *stackshot_config,
						size_t stackshot_config_size, boolean_t stackshot_from_user);
void 			do_stackshot(void);
void			kdp_snapshot_preflight(int pid, void * tracebuf, uint32_t tracebuf_size, uint32_t flags, kcdata_descriptor_t data_p, boolean_t enable_faulting);
void			kdp_snapshot_postflight(void);
static int		kdp_stackshot(int pid, void *tracebuf, uint32_t tracebuf_size, uint32_t flags, uint32_t *pbytesTraced);
static int		kdp_stackshot_kcdata_format(int pid, uint32_t trace_flags, uint32_t *pBytesTraced);
int			kdp_stack_snapshot_geterror(void);
uint32_t		kdp_stack_snapshot_bytes_traced(void);
int 			kdp_stackshot(int pid, void *tracebuf, uint32_t tracebuf_size, uint32_t trace_flags, uint32_t *pbytesTraced);
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
extern uint64_t		get_dispatchqueue_serialno_offset_from_proc(void *p);
static uint64_t		proc_dispatchqueue_serialno_offset_from_task(task_t task);
extern int		memorystatus_get_pressure_status_kdp(void);

extern int 		count_busy_buffers(void);   /* must track with declaration in bsd/sys/buf_internal.h */
extern void 		bcopy_phys(addr64_t, addr64_t, vm_size_t);
extern int		machine_trace_thread(thread_t thread, char *tracepos, char *tracebound, int nframes, boolean_t user_p, uint32_t *thread_trace_flags);
extern int		machine_trace_thread64(thread_t thread, char *tracepos, char *tracebound, int nframes, boolean_t user_p, uint32_t *thread_trace_flags);

/* Validates that the given address is both a valid page and has
 * default caching attributes for the current kdp_pmap.  Returns
 * 0 if the address is invalid, and a kernel virtual address for
 * the given address if it is valid.
 */
vm_offset_t machine_trace_thread_get_kva(vm_offset_t cur_target_addr, vm_map_t map, uint32_t *thread_trace_flags);

/* Clears caching information used by the above validation routine
 * (in case the kdp_pmap has been changed or cleared).
 */
void machine_trace_thread_clear_validation_cache(void);

#define MAX_FRAMES 1000
#define MAX_LOADINFOS 500
#define USECSPERSEC 1000000
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
#define STACKSHOT_SUBSYS_UNLOCK() lck_mtx_unlock(&stackshot_subsys_mutex)
#if defined(__i386__) || defined (__x86_64__)
#define TRAP_DEBUGGER __asm__ volatile("int3")
#else
#error No TRAP_DEBUGGER definition for this architecture
#endif

/* Initialize the mutex governing access to the stack snapshot subsystem */
__private_extern__ void
stackshot_lock_init( void )
{
	stackshot_subsys_lck_grp_attr = lck_grp_attr_alloc_init();

	stackshot_subsys_lck_grp = lck_grp_alloc_init("stackshot_subsys_lock", stackshot_subsys_lck_grp_attr);

	stackshot_subsys_lck_attr = lck_attr_alloc_init();

	lck_mtx_init(&stackshot_subsys_mutex, stackshot_subsys_lck_grp, stackshot_subsys_lck_attr);
}

#define SANE_BOOTPROFILE_TRACEBUF_SIZE (64 * 1024 * 1024)
#define SANE_TRACEBUF_SIZE (8 * 1024 * 1024)

#define STACKSHOT_SUPP_SIZE (16 * 1024) /* Minimum stackshot size */
#define TASK_UUID_AVG_SIZE (16 * sizeof(uuid_t)) /* Average space consumed by UUIDs/task */

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
 * Old, inefficient stackshot call. This will be removed in the next release and is being replaced with
 * two syscalls -- stack_snapshot_with_config and stack_microsnapshot.
 */
kern_return_t
stack_snapshot2(int pid, user_addr_t tracebuf, uint32_t tracebuf_size, uint32_t flags, int32_t *retval)
{
	boolean_t istate;
	int error = KERN_SUCCESS;
	unsigned bytesTraced = 0;

#if CONFIG_TELEMETRY
	if (flags & STACKSHOT_GLOBAL_MICROSTACKSHOT_ENABLE) {
		telemetry_global_ctl(1);
		*retval = 0;
		return (0);
	} else if (flags & STACKSHOT_GLOBAL_MICROSTACKSHOT_DISABLE) {
		telemetry_global_ctl(0);
		*retval = 0;
		return (0);
	}

	if (flags & STACKSHOT_WINDOWED_MICROSTACKSHOTS_ENABLE) {
		error = telemetry_enable_window();

		if (error != KERN_SUCCESS) {
			/* We are probably out of memory */
			*retval = -1;
			return KERN_RESOURCE_SHORTAGE;
		}

		*retval = 0;
		return (0);
	} else if (flags & STACKSHOT_WINDOWED_MICROSTACKSHOTS_DISABLE) {
		telemetry_disable_window();
		*retval = 0;
		return (0);
	}
#endif

	*retval = -1;
	/* Serialize tracing */
	STACKSHOT_SUBSYS_LOCK();

	if (tracebuf_size <= 0) {
		error = KERN_INVALID_ARGUMENT;
		goto error_exit;
	}

#if CONFIG_TELEMETRY
	if (flags & STACKSHOT_GET_MICROSTACKSHOT) {

		if (tracebuf_size > SANE_TRACEBUF_SIZE) {
			error = KERN_INVALID_ARGUMENT;
			goto error_exit;
		}

		bytesTraced = tracebuf_size;
		error = telemetry_gather(tracebuf, &bytesTraced,
		                         (flags & STACKSHOT_SET_MICROSTACKSHOT_MARK) ? TRUE : FALSE);
		*retval = (int)bytesTraced;
		goto error_exit;
	}

	if (flags & STACKSHOT_GET_WINDOWED_MICROSTACKSHOTS) {

		if (tracebuf_size > SANE_TRACEBUF_SIZE) {
			error = KERN_INVALID_ARGUMENT;
			goto error_exit;
		}

		bytesTraced = tracebuf_size;
		error = telemetry_gather_windowed(tracebuf, &bytesTraced);
		*retval = (int)bytesTraced;
		goto error_exit;
	}

	if (flags & STACKSHOT_GET_BOOT_PROFILE) {

		if (tracebuf_size > SANE_BOOTPROFILE_TRACEBUF_SIZE) {
			error = KERN_INVALID_ARGUMENT;
			goto error_exit;
		}

		bytesTraced = tracebuf_size;
		error = bootprofile_gather(tracebuf, &bytesTraced);
		*retval = (int)bytesTraced;
		goto error_exit;
	}
#endif

	if (tracebuf_size > SANE_TRACEBUF_SIZE) {
		error = KERN_INVALID_ARGUMENT;
		goto error_exit;
	}

	assert(stackshot_snapbuf == NULL);
	if (kmem_alloc_kobject(kernel_map, (vm_offset_t *)&stackshot_snapbuf, tracebuf_size, VM_KERN_MEMORY_DIAG) != KERN_SUCCESS) {
		error = KERN_RESOURCE_SHORTAGE;
		goto error_exit;
	}

	if (panic_active()) {
		error = KERN_RESOURCE_SHORTAGE;
		goto error_exit;
	}

	istate = ml_set_interrupts_enabled(FALSE);
	/* Preload trace parameters */
	kdp_snapshot_preflight(pid, stackshot_snapbuf, tracebuf_size, flags, NULL, FALSE);

	/* Trap to the debugger to obtain a coherent stack snapshot; this populates
	 * the trace buffer
	 */

	TRAP_DEBUGGER;

	ml_set_interrupts_enabled(istate);

	bytesTraced = kdp_stack_snapshot_bytes_traced();

	if (bytesTraced > 0) {
		if ((error = copyout(stackshot_snapbuf, tracebuf,
			((bytesTraced < tracebuf_size) ?
			    bytesTraced : tracebuf_size))))
			goto error_exit;
		*retval = bytesTraced;
	}
	else {
		error = KERN_NOT_IN_SET;
		goto error_exit;
	}

	error = kdp_stack_snapshot_geterror();
	if (error == -1) {
		error = KERN_NO_SPACE;
		*retval = -1;
		goto error_exit;
	}

error_exit:
	if (stackshot_snapbuf != NULL)
		kmem_free(kernel_map, (vm_offset_t) stackshot_snapbuf, tracebuf_size);
	stackshot_snapbuf = NULL;
	STACKSHOT_SUBSYS_UNLOCK();
	return error;
}

kern_return_t
stack_snapshot_from_kernel_internal(int pid, void *buf, uint32_t size, uint32_t flags, unsigned *bytes_traced)
{
	int error = 0;
	boolean_t istate;

	if ((buf == NULL) || (size <= 0) || (bytes_traced == NULL)) {
		return KERN_INVALID_ARGUMENT;
	}

	/* cap in individual stackshot to SANE_TRACEBUF_SIZE */
	if (size > SANE_TRACEBUF_SIZE) {
		size = SANE_TRACEBUF_SIZE;
	}

	/* Serialize tracing */
	STACKSHOT_SUBSYS_LOCK();
	istate = ml_set_interrupts_enabled(FALSE);


	/* Preload trace parameters*/
	kdp_snapshot_preflight(pid, buf, size, flags, NULL, FALSE);

	/* Trap to the debugger to obtain a coherent stack snapshot; this populates
	 * the trace buffer
	 */
	TRAP_DEBUGGER;

	ml_set_interrupts_enabled(istate);

	*bytes_traced = kdp_stack_snapshot_bytes_traced();

	error = kdp_stack_snapshot_geterror();

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

	if (flags & STACKSHOT_WINDOWED_MICROSTACKSHOTS_ENABLE) {
		error = telemetry_enable_window();

		if (error != KERN_SUCCESS) {
			/*
			 * We are probably out of memory
			 */
			*retval = -1;
			error = KERN_RESOURCE_SHORTAGE;
			goto exit;
		}

		*retval = 0;
		goto exit;
	} else if (flags & STACKSHOT_WINDOWED_MICROSTACKSHOTS_DISABLE) {
		telemetry_disable_window();
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

	if (flags & STACKSHOT_GET_WINDOWED_MICROSTACKSHOTS) {

		if (tracebuf_size > SANE_TRACEBUF_SIZE) {
			error = KERN_INVALID_ARGUMENT;
			goto unlock_exit;
		}

		bytes_traced = tracebuf_size;
		error = telemetry_gather_windowed(tracebuf, &bytes_traced);
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

	error = mach_vm_remap(get_task_map(current_task()), &stackshotbuf_user_addr, bytes_traced, 0,
			VM_FLAGS_ANYWHERE, kernel_map, (mach_vm_offset_t)stackshotbuf, FALSE, &cur_prot, &max_prot, VM_INHERIT_DEFAULT);
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
	boolean_t		enable_faulting = FALSE;
	uint32_t		size_hint = 0;

	if(stackshot_config == NULL) {
		return 	KERN_INVALID_ARGUMENT;
	}

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
			since_timestamp = config->sc_since_timestamp;
			if (config->sc_size <= SANE_TRACEBUF_SIZE) {
				size_hint = config->sc_size;
			}
			break;
		default:
			return KERN_NOT_SUPPORTED;
	}

	/*
	 * Currently saving a kernel buffer is only supported from the internal/KEXT API.
	 */
	if (stackshot_from_user) {
		if (flags & STACKSHOT_SAVE_IN_KERNEL_BUFFER) {
			return KERN_NO_ACCESS;
		}
	} else {
		if (!(flags & STACKSHOT_SAVE_IN_KERNEL_BUFFER)) {
			return KERN_NOT_SUPPORTED;
		}
	}

	if (flags & STACKSHOT_ENABLE_FAULTING) {
		return KERN_NOT_SUPPORTED;
	}

	/*
	 * If we're not saving the buffer in the kernel pointer, we need places to copy into.
	 */
	if ((!out_buffer_addr || !out_size_addr) && !(flags & STACKSHOT_SAVE_IN_KERNEL_BUFFER)) {
		return KERN_INVALID_ARGUMENT;
	}

	if (since_timestamp != 0) {
		return KERN_NOT_SUPPORTED;
	}

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

	stackshotbuf_size = get_stackshot_estsize(size_hint);

	for (; stackshotbuf_size <= SANE_TRACEBUF_SIZE; stackshotbuf_size <<= 1) {
		if (kmem_alloc(kernel_map, (vm_offset_t *)&stackshotbuf, stackshotbuf_size, VM_KERN_MEMORY_DIAG) != KERN_SUCCESS) {
			error = KERN_RESOURCE_SHORTAGE;
			goto error_exit;
		}

		/*
		 * If someone has panicked, don't try and enter the debugger
		 */
		if (panic_active()) {
			error = KERN_RESOURCE_SHORTAGE;
			goto error_exit;
		}

		if (flags & STACKSHOT_KCDATA_FORMAT) {
			kcdata_p = kcdata_memory_alloc_init((mach_vm_address_t)stackshotbuf, KCDATA_BUFFER_BEGIN_STACKSHOT, stackshotbuf_size, KCFLAG_USE_MEMCOPY);
		}


		/*
		 * Disable interrupts and save the current interrupt state.
		 */
		prev_interrupt_state = ml_set_interrupts_enabled(FALSE);

		/*
		 * Load stackshot parameters.
		 */
		kdp_snapshot_preflight(pid, stackshotbuf, stackshotbuf_size, flags, kcdata_p, enable_faulting);

		/*
		 * Trap to the debugger to obtain a stackshot (this will populate the buffer).
		 */
		TRAP_DEBUGGER;

		ml_set_interrupts_enabled(prev_interrupt_state);

		/*
		 * If we didn't allocate a big enough buffer, deallocate and try again.
		 */
		error = kdp_stack_snapshot_geterror();
		if (error == -1) {
			if (kcdata_p != NULL) {
				kcdata_memory_destroy(kcdata_p);
				kcdata_p = NULL;
				stackshot_kcdata_p = NULL;
			}
			kmem_free(kernel_map, (vm_offset_t)stackshotbuf, stackshotbuf_size);
			stackshotbuf = NULL;
			continue;
		}

		bytes_traced = kdp_stack_snapshot_bytes_traced();

		if (bytes_traced <= 0) {
			error = KERN_NOT_IN_SET;
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

/* Cache stack snapshot parameters in preparation for a trace */
void
kdp_snapshot_preflight(int pid, void * tracebuf, uint32_t tracebuf_size, uint32_t flags,
					   kcdata_descriptor_t data_p, boolean_t enable_faulting)
{
	stack_snapshot_pid = pid;
	stack_snapshot_buf = tracebuf;
	stack_snapshot_bufsize = tracebuf_size;
	stack_snapshot_flags = flags;
	stack_enable_faulting = enable_faulting;
	if (data_p != NULL) {
		stackshot_kcdata_p = data_p;
	}
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

static int
kdp_stackshot_kcdata_format(int pid, uint32_t trace_flags, uint32_t *pBytesTraced)
{
	/* convenience macros specific only for this function */
#define kcd_end_address(kcd) ((void *)((uint64_t)((kcd)->kcd_addr_begin) + kcdata_memory_get_used_bytes((kcd))))
#define kcd_max_address(kcd) ((void *)((kcd)->kcd_addr_begin + (kcd)->kcd_length))
#define kcd_exit_on_error(action)                                 \
	do {                                                      \
		if (KERN_SUCCESS != (error = (action))) {         \
			if (error == KERN_RESOURCE_SHORTAGE) {    \
				error = -1;                       \
			}                                         \
			goto error_exit;                          \
		}                                                 \
	} while (0); /* end kcd_exit_on_error */

	int error = 0;
	mach_vm_address_t out_addr = 0;
	uint64_t abs_time;
	struct task_snapshot_v2 *cur_tsnap;
	uint64_t system_state_flags = 0;
	int saved_count = 0;
	task_t task = TASK_NULL;
	thread_t thread = THREAD_NULL;
	mach_timebase_info_data_t timebase = {0, 0};
	uint64_t microsecs = 0, secs = 0;
	uint32_t length_to_copy, tmp32;

	abs_time = mach_absolute_time();
	clock_get_calendar_microtime((clock_sec_t*)&secs, (clock_usec_t*)&microsecs);

	/* process the flags */
	boolean_t dispatch_p = ((trace_flags & STACKSHOT_GET_DQ) != 0);
	boolean_t save_loadinfo_p = ((trace_flags & STACKSHOT_SAVE_LOADINFO) != 0);
	boolean_t save_kextloadinfo_p = ((trace_flags & STACKSHOT_SAVE_KEXT_LOADINFO) != 0);
	boolean_t save_userframes_p = ((trace_flags & STACKSHOT_SAVE_KERNEL_FRAMES_ONLY) == 0);
	boolean_t save_donating_pids_p = ((trace_flags & STACKSHOT_SAVE_IMP_DONATION_PIDS) != 0);

	if (sizeof(void *) == 8)
		system_state_flags |= kKernel64_p;

	if (stackshot_kcdata_p == NULL || pBytesTraced == NULL) {
		error = -1;
		goto error_exit;
	}

	/* begin saving data into the buffer */
	*pBytesTraced = 0;
	kcd_exit_on_error(kcdata_add_uint32_with_description(stackshot_kcdata_p, trace_flags, "stackshot_in_flags"));
	kcd_exit_on_error(kcdata_add_uint32_with_description(stackshot_kcdata_p, (uint32_t)pid, "stackshot_in_pid"));
	kcd_exit_on_error(kcdata_add_uint64_with_description(stackshot_kcdata_p, system_state_flags, "system_state_flags"));
	tmp32 = PAGE_SIZE;
	kcd_exit_on_error(kcdata_get_memory_addr(stackshot_kcdata_p, STACKSHOT_KCTYPE_KERN_PAGE_SIZE, sizeof(uint32_t), &out_addr));
	memcpy((void *)out_addr, &tmp32, sizeof(tmp32));

#if CONFIG_JETSAM
	tmp32 = memorystatus_get_pressure_status_kdp();
	kcd_exit_on_error(kcdata_get_memory_addr(stackshot_kcdata_p, STACKSHOT_KCTYPE_JETSAM_LEVEL, sizeof(uint32_t), &out_addr));
	memcpy((void *)out_addr, &tmp32, sizeof(tmp32));
#endif

	/* save boot-args and osversion string */
	length_to_copy =  MIN((uint32_t)(strlen(version) + 1), OSVERSIZE);
	kcd_exit_on_error(kcdata_get_memory_addr(stackshot_kcdata_p, STACKSHOT_KCTYPE_OSVERSION, length_to_copy, &out_addr));
	strlcpy((char*)out_addr, &version[0], length_to_copy);

	length_to_copy =  MIN((uint32_t)(strlen(PE_boot_args()) + 1), OSVERSIZE);
	kcd_exit_on_error(kcdata_get_memory_addr(stackshot_kcdata_p, STACKSHOT_KCTYPE_BOOTARGS, length_to_copy, &out_addr));
	strlcpy((char*)out_addr, PE_boot_args(), length_to_copy);

	/* setup mach_absolute_time and timebase info */
	clock_timebase_info(&timebase);
	kcd_exit_on_error(kcdata_get_memory_addr(stackshot_kcdata_p, KCDATA_TYPE_TIMEBASE, sizeof(timebase), &out_addr));
	memcpy((void *)out_addr, &timebase, sizeof(timebase));

	kcd_exit_on_error(kcdata_get_memory_addr(stackshot_kcdata_p, KCDATA_TYPE_MACH_ABSOLUTE_TIME, sizeof(uint64_t), &out_addr));
	memcpy((void *)out_addr, &abs_time, sizeof(uint64_t));

	microsecs = microsecs + (secs * USECSPERSEC);
	kcd_exit_on_error(kcdata_get_memory_addr(stackshot_kcdata_p, KCDATA_TYPE_USECS_SINCE_EPOCH, sizeof(uint64_t), &out_addr));
	memcpy((void *)out_addr, &microsecs, sizeof(uint64_t));

	/* reserve space of system level shared cache load info */
	struct dyld_uuid_info_64 *sys_shared_cache_loadinfo;
	kcd_exit_on_error(kcdata_get_memory_addr(stackshot_kcdata_p, STACKSHOT_KCTYPE_SHAREDCACHE_LOADINFO, sizeof(kernel_uuid_info), &out_addr));
	sys_shared_cache_loadinfo = (struct dyld_uuid_info_64 *)out_addr;
	bzero((void *)sys_shared_cache_loadinfo, sizeof(struct dyld_uuid_info_64));

	/* Add requested information first */
	if (trace_flags & STACKSHOT_GET_GLOBAL_MEM_STATS) {
		kcd_exit_on_error(kcdata_get_memory_addr(stackshot_kcdata_p, STACKSHOT_KCTYPE_GLOBAL_MEM_STATS, sizeof(struct mem_and_io_snapshot), &out_addr));
		kdp_mem_and_io_snapshot((struct mem_and_io_snapshot *)out_addr);
	}

	/* Iterate over tasks */
	queue_head_t *task_list = &tasks;
	queue_iterate(task_list, task, task_t, tasks) {
		int task_pid;
		if ((task == NULL) || !ml_validate_nofault((vm_offset_t) task, sizeof(struct task)))
			goto error_exit;

		task_pid = pid_from_task(task);
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

			uint64_t task_uniqueid = proc_uniqueid_from_task(task);
			boolean_t task64 = task_has_64BitAddr(task);
			boolean_t have_map = (task->map != NULL) && (ml_validate_nofault((vm_offset_t)(task->map), sizeof(struct _vm_map)));
			boolean_t have_pmap = have_map && (task->map->pmap != NULL) && (ml_validate_nofault((vm_offset_t)(task->map->pmap), sizeof(struct pmap)));

			/* add task snapshot marker */
			kcd_exit_on_error(kcdata_add_container_marker(stackshot_kcdata_p, KCDATA_TYPE_CONTAINER_BEGIN, STACKSHOT_KCCONTAINER_TASK, task_uniqueid));

			/* add task_snapshot_v2 struct data */
			kcd_exit_on_error(kcdata_get_memory_addr(stackshot_kcdata_p, STACKSHOT_KCTYPE_TASK_SNAPSHOT, sizeof(struct task_snapshot_v2), &out_addr));
			cur_tsnap = (struct task_snapshot_v2 *)out_addr;
			bzero(cur_tsnap, sizeof(struct task_snapshot_v2));

			cur_tsnap->ts_pid = task_pid;
			cur_tsnap->ts_unique_pid = task_uniqueid;

			/* Add the BSD process identifiers */
			if (task_pid != -1 && task->bsd_info != NULL)
				proc_name_kdp(task, cur_tsnap->ts_p_comm, sizeof(cur_tsnap->ts_p_comm));
			else {
				cur_tsnap->ts_p_comm[0] = '\0';
#if IMPORTANCE_INHERITANCE && (DEVELOPMENT || DEBUG)
				if (task->task_imp_base != NULL) {
					strlcpy(cur_tsnap->ts_p_comm, &task->task_imp_base->iit_procname[0],
					        MIN((int)sizeof(task->task_imp_base->iit_procname), (int)sizeof(cur_tsnap->ts_p_comm)));
				}
#endif
			}

			if (task64)
				cur_tsnap->ts_ss_flags |= kUser64_p;
			if (!task->active || task_is_a_corpse(task))
				cur_tsnap->ts_ss_flags |= kTerminatedSnapshot;
			if (task->pidsuspended)
				cur_tsnap->ts_ss_flags |= kPidSuspended;
			if (task->frozen)
				cur_tsnap->ts_ss_flags |= kFrozen;
			if (task->effective_policy.darwinbg == 1)
				cur_tsnap->ts_ss_flags |= kTaskDarwinBG;
			if (task->requested_policy.t_role == TASK_FOREGROUND_APPLICATION)
				cur_tsnap->ts_ss_flags |= kTaskIsForeground;
			if (task->requested_policy.t_boosted == 1)
				cur_tsnap->ts_ss_flags |= kTaskIsBoosted;
			if (task->effective_policy.t_sup_active == 1)
				cur_tsnap->ts_ss_flags |= kTaskIsSuppressed;

#if IMPORTANCE_INHERITANCE
			if (task->task_imp_base) {
				if (task->task_imp_base->iit_donor)
					cur_tsnap->ts_ss_flags |= kTaskIsImpDonor;
				if (task->task_imp_base->iit_live_donor)
					cur_tsnap->ts_ss_flags |= kTaskIsLiveImpDonor;
			}
#endif

			cur_tsnap->ts_latency_qos = (task->effective_policy.t_latency_qos == LATENCY_QOS_TIER_UNSPECIFIED) ?
				LATENCY_QOS_TIER_UNSPECIFIED : ((0xFF << 16) | task->effective_policy.t_latency_qos);
			cur_tsnap->ts_suspend_count = task->suspend_count;
			cur_tsnap->ts_p_start_sec = 0;
			proc_starttime_kdp(task->bsd_info, &cur_tsnap->ts_p_start_sec, NULL);

			cur_tsnap->ts_task_size = have_pmap ? (pmap_resident_count(task->map->pmap) * PAGE_SIZE) : 0;
			cur_tsnap->ts_max_resident_size = get_task_resident_max(task);
			cur_tsnap->ts_faults = task->faults;
			cur_tsnap->ts_pageins = task->pageins;
			cur_tsnap->ts_cow_faults = task->cow_faults;
			cur_tsnap->ts_user_time_in_terminated_threads = task->total_user_time;
			cur_tsnap->ts_system_time_in_terminated_threads = task->total_system_time;
			cur_tsnap->ts_was_throttled = (uint32_t) proc_was_throttled_from_task(task);
			cur_tsnap->ts_did_throttle = (uint32_t) proc_did_throttle_from_task(task);

			/* Check for shared cache information */
			do {
				uint8_t shared_cache_identifier[16];
				uint64_t shared_cache_slide;
				uint64_t shared_cache_base_address = 0;
				boolean_t found_shared_cache_info = TRUE;

				if (task->shared_region && ml_validate_nofault((vm_offset_t)task->shared_region, sizeof(struct vm_shared_region))) {
					struct vm_shared_region *sr = task->shared_region;
					shared_cache_base_address = sr->sr_base_address + sr->sr_first_mapping;
				}

				if (!shared_cache_base_address ||
						!kdp_copyin(task->map->pmap, shared_cache_base_address + offsetof(struct _dyld_cache_header, uuid), shared_cache_identifier, sizeof(shared_cache_identifier))
				   ) {
					found_shared_cache_info = FALSE;
				}

				if (task->shared_region) {
					/*
					 * No refcounting here, but we are in debugger
					 * context, so that should be safe.
					 */
					shared_cache_slide = task->shared_region->sr_slide_info.slide;
				} else {
					shared_cache_slide = 0;
				}

				if (found_shared_cache_info == FALSE)
					break;

				if (task_pid == 1) {
					/* save launchd's shared cache info as system level */
					bcopy(shared_cache_identifier, sys_shared_cache_loadinfo->imageUUID, sizeof(sys_shared_cache_loadinfo->imageUUID));
					sys_shared_cache_loadinfo->imageLoadAddress = shared_cache_slide;
					break;
				} else {
					if (shared_cache_slide == sys_shared_cache_loadinfo->imageLoadAddress &&
							0 == memcmp(shared_cache_identifier, sys_shared_cache_loadinfo->imageUUID, sizeof(sys_shared_cache_loadinfo->imageUUID))) {
						/* skip adding shared cache info. its same as system level one */
						break;
					}
				}

				kcd_exit_on_error(kcdata_get_memory_addr(stackshot_kcdata_p, STACKSHOT_KCTYPE_SHAREDCACHE_LOADINFO, sizeof(struct dyld_uuid_info_64), &out_addr));
				struct dyld_uuid_info_64 *shared_cache_data = (struct dyld_uuid_info_64 *)out_addr;
				shared_cache_data->imageLoadAddress = shared_cache_slide;
				bcopy(shared_cache_identifier, shared_cache_data->imageUUID, sizeof(shared_cache_data->imageUUID));

			} while(0);

			/* I/O Statistics if any counters are non zero */
			assert(IO_NUM_PRIORITIES == STACKSHOT_IO_NUM_PRIORITIES);
			if (task->task_io_stats && !memory_iszero(task->task_io_stats, sizeof(struct io_stat_info))) {
				kcd_exit_on_error(kcdata_get_memory_addr(stackshot_kcdata_p, STACKSHOT_KCTYPE_IOSTATS, sizeof(struct io_stats_snapshot), &out_addr));
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

#if IMPORTANCE_INHERITANCE
			if (save_donating_pids_p) {
				kcd_exit_on_error(((((mach_vm_address_t) kcd_end_address(stackshot_kcdata_p) + (TASK_IMP_WALK_LIMIT * sizeof(int32_t)))
							< (mach_vm_address_t) kcd_max_address(stackshot_kcdata_p)) ? KERN_SUCCESS : KERN_RESOURCE_SHORTAGE));
				saved_count = task_importance_list_pids(task, TASK_IMP_LIST_DONATING_PIDS, (void *)kcd_end_address(stackshot_kcdata_p), TASK_IMP_WALK_LIMIT);
				if (saved_count > 0)
					kcd_exit_on_error(kcdata_get_memory_addr_for_array(stackshot_kcdata_p, STASKSHOT_KCTYPE_DONATING_PIDS, sizeof(int32_t), saved_count, &out_addr));
			}
#endif

			/* place load info and libraries now */
			uint32_t uuid_info_count = 0;
			mach_vm_address_t uuid_info_addr = 0;
			if (save_loadinfo_p && have_pmap && task->active && task_pid > 0) {
				/* Read the dyld_all_image_infos struct from the task memory to get UUID array count and location */
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
					uuid_info_count = 1; /* atleast include kernel uuid */
				}
			}

			if (task_pid > 0 && uuid_info_count > 0 && uuid_info_count < MAX_LOADINFOS) {
				uint32_t uuid_info_size = (uint32_t)(task64 ? sizeof(struct user64_dyld_uuid_info) : sizeof(struct user32_dyld_uuid_info));
				uint32_t uuid_info_array_size = uuid_info_count * uuid_info_size;

				kcd_exit_on_error(kcdata_get_memory_addr_for_array(stackshot_kcdata_p,
							(task64 ? KCDATA_TYPE_LIBRARY_LOADINFO64 : KCDATA_TYPE_LIBRARY_LOADINFO),
							uuid_info_size,
							uuid_info_count,
							&out_addr));


				/* Copy in the UUID info array
				 * It may be nonresident, in which case just fix up nloadinfos to 0 in the task_snap
				 */
				if (have_pmap && !kdp_copyin(task->map->pmap, uuid_info_addr, (void *)out_addr, uuid_info_array_size)) {
					bzero((void *)out_addr, uuid_info_array_size);
				}

			} else if (task_pid == 0 && uuid_info_count > 0 && uuid_info_count < MAX_LOADINFOS) {
				uintptr_t image_load_address;

				do {
					if (!kernel_uuid || !ml_validate_nofault((vm_offset_t)kernel_uuid, sizeof(uuid_t))) {
						/* Kernel UUID not found or inaccessible */
						break;
					}
					kcd_exit_on_error(kcdata_get_memory_addr_for_array(stackshot_kcdata_p,
								(sizeof(kernel_uuid_info) == sizeof(struct user64_dyld_uuid_info))? KCDATA_TYPE_LIBRARY_LOADINFO64: KCDATA_TYPE_LIBRARY_LOADINFO,
								sizeof(kernel_uuid_info), uuid_info_count, &out_addr)
							);
					kernel_uuid_info *uuid_info_array = (kernel_uuid_info *)out_addr;
					image_load_address = (uintptr_t)VM_KERNEL_UNSLIDE(vm_kernel_stext);
					uuid_info_array[0].imageLoadAddress = image_load_address;
					memcpy(&uuid_info_array[0].imageUUID, kernel_uuid, sizeof(uuid_t));

					if (save_kextloadinfo_p && ml_validate_nofault((vm_offset_t)(&gLoadedKextSummaries->summaries[0]),
								gLoadedKextSummaries->entry_size * gLoadedKextSummaries->numSummaries)) {
						uint32_t kexti;
						for (kexti=0 ; kexti < gLoadedKextSummaries->numSummaries; kexti++) {
							image_load_address = (uintptr_t)VM_KERNEL_UNSLIDE(gLoadedKextSummaries->summaries[kexti].address);
							uuid_info_array[kexti + 1].imageLoadAddress = image_load_address;
							memcpy(&uuid_info_array[kexti + 1].imageUUID, &gLoadedKextSummaries->summaries[kexti].uuid, sizeof(uuid_t));
						}
					}
				} while(0);
			}

			/* Iterate over task threads */
			queue_iterate(&task->threads, thread, thread_t, task_threads){
				uint64_t tval;
				uint64_t thread_uniqueid = 0;
				char cur_thread_name[STACKSHOT_MAX_THREAD_NAME_SIZE];

				if ((thread == NULL) || !ml_validate_nofault((vm_offset_t) thread, sizeof(struct thread)))
					goto error_exit;

				if (!save_userframes_p && thread->kernel_stack == 0)
					continue;

				thread_uniqueid = thread_tid(thread);

				/* add thread marker */
				kcd_exit_on_error(kcdata_add_container_marker(stackshot_kcdata_p, KCDATA_TYPE_CONTAINER_BEGIN, STACKSHOT_KCCONTAINER_THREAD, thread_uniqueid));
				kcd_exit_on_error(kcdata_get_memory_addr(stackshot_kcdata_p, STACKSHOT_KCTYPE_THREAD_SNAPSHOT, sizeof(struct thread_snapshot_v2), &out_addr));
				struct thread_snapshot_v2 * cur_thread_snap = (struct thread_snapshot_v2 *)out_addr;

				/* Populate the thread snapshot header */
				cur_thread_snap->ths_thread_id = thread_uniqueid;
				cur_thread_snap->ths_state = thread->state;
				cur_thread_snap->ths_ss_flags = 0;
				cur_thread_snap->ths_base_priority = thread->base_pri;
				cur_thread_snap->ths_sched_priority = thread->sched_pri;
				cur_thread_snap->ths_sched_flags = thread->sched_flags;
				cur_thread_snap->ths_wait_event = VM_KERNEL_UNSLIDE_OR_PERM(thread->wait_event);
				cur_thread_snap->ths_continuation = VM_KERNEL_UNSLIDE(thread->continuation);
				cur_thread_snap->ths_last_run_time = thread->last_run_time;
				cur_thread_snap->ths_last_made_runnable_time = thread->last_made_runnable_time;
				cur_thread_snap->ths_io_tier = proc_get_effective_thread_policy(thread, TASK_POLICY_IO);
				cur_thread_snap->ths_eqos = thread->effective_policy.thep_qos;
				cur_thread_snap->ths_rqos = thread->requested_policy.thrp_qos;
				cur_thread_snap->ths_rqos_override = thread->requested_policy.thrp_qos_override;
				cur_thread_snap->ths_total_syscalls = thread->syscalls_mach + thread->syscalls_unix;
				cur_thread_snap->ths_dqserialnum = 0;

				tval = safe_grab_timer_value(&thread->user_timer);
				cur_thread_snap->ths_user_time = tval;
				tval = safe_grab_timer_value(&thread->system_timer);

				if (thread->precise_user_kernel_time) {
					cur_thread_snap->ths_sys_time = tval;
				} else {
					cur_thread_snap->ths_user_time += tval;
					cur_thread_snap->ths_sys_time = 0;
				}

				if (thread->effective_policy.darwinbg)
					cur_thread_snap->ths_ss_flags |= kThreadDarwinBG;
				if (proc_get_effective_thread_policy(thread, TASK_POLICY_PASSIVE_IO))
					cur_thread_snap->ths_ss_flags |= kThreadIOPassive;
				if (thread->suspend_count > 0)
					cur_thread_snap->ths_ss_flags |= kThreadSuspended;

				if (thread->options & TH_OPT_GLOBAL_FORCED_IDLE) {
					cur_thread_snap->ths_ss_flags |= kGlobalForcedIdle;
				}

				if (IPC_VOUCHER_NULL != thread->ith_voucher)
					cur_thread_snap->ths_voucher_identifier = VM_KERNEL_ADDRPERM(thread->ith_voucher);
				if (dispatch_p && (task != kernel_task) && (task->active) && have_pmap) {
					uint64_t dqkeyaddr = thread_dispatchqaddr(thread);
					if (dqkeyaddr != 0) {
						uint64_t dqaddr = 0;
						if (kdp_copyin(task->map->pmap, dqkeyaddr, &dqaddr, (task64 ? 8 : 4)) && (dqaddr != 0)) {
							uint64_t dqserialnumaddr = dqaddr + proc_dispatchqueue_serialno_offset_from_task(task);
							uint64_t dqserialnum = 0;
							if (kdp_copyin(task->map->pmap, dqserialnumaddr, &dqserialnum, (task64 ? 8 : 4))) {
								cur_thread_snap->ths_ss_flags |= kHasDispatchSerial;
								cur_thread_snap->ths_dqserialnum = dqserialnum;
							}
						}
					}
				}

				/* if there is thread name then add to buffer */
				cur_thread_name[0] = '\0';
				proc_threadname_kdp(thread->uthread, cur_thread_name, STACKSHOT_MAX_THREAD_NAME_SIZE);
				if (strnlen(cur_thread_name, STACKSHOT_MAX_THREAD_NAME_SIZE) > 0) {
					kcd_exit_on_error(kcdata_get_memory_addr(stackshot_kcdata_p, STACKSHOT_KCTYPE_THREAD_NAME, sizeof(cur_thread_name), &out_addr));
					bcopy((void *)cur_thread_name, (void *)out_addr, sizeof(cur_thread_name));
				}

				/* I/O Statistics */
				assert(IO_NUM_PRIORITIES == STACKSHOT_IO_NUM_PRIORITIES);
				if (thread->thread_io_stats && !memory_iszero(thread->thread_io_stats, sizeof(struct io_stat_info))) {
					kcd_exit_on_error(kcdata_get_memory_addr(stackshot_kcdata_p, STACKSHOT_KCTYPE_IOSTATS, sizeof(struct io_stats_snapshot), &out_addr));
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

				/* Trace user stack, if any */
				if (save_userframes_p && task->active && thread->task->map != kernel_map) {
					uint32_t thread_snapshot_flags = 0;
					/* 64-bit task? */
					if (task_has_64BitAddr(thread->task)) {
						out_addr = (mach_vm_address_t)kcd_end_address(stackshot_kcdata_p);
						saved_count = machine_trace_thread64(thread, (char *)out_addr, (char *)kcd_max_address(stackshot_kcdata_p), MAX_FRAMES, TRUE, &thread_snapshot_flags);
						if (saved_count > 0) {
							kcd_exit_on_error(kcdata_get_memory_addr_for_array(stackshot_kcdata_p,
									STACKSHOT_KCTYPE_USER_STACKFRAME64,
									sizeof(struct stack_snapshot_frame64),
									saved_count/sizeof(struct stack_snapshot_frame64),
									&out_addr));
							cur_thread_snap->ths_ss_flags |= kUser64_p;
						}
					}
					else {
						out_addr = (mach_vm_address_t)kcd_end_address(stackshot_kcdata_p);
						saved_count = machine_trace_thread(thread, (char *)out_addr, (char *)kcd_max_address(stackshot_kcdata_p), MAX_FRAMES, TRUE, &thread_snapshot_flags);
						if (saved_count > 0) {
							kcd_exit_on_error(kcdata_get_memory_addr_for_array(stackshot_kcdata_p,
										STACKSHOT_KCTYPE_USER_STACKFRAME,
										sizeof(struct stack_snapshot_frame32),
										saved_count/sizeof(struct stack_snapshot_frame32),
										&out_addr));
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
					out_addr = (mach_vm_address_t)kcd_end_address(stackshot_kcdata_p);
					saved_count = machine_trace_thread64(thread, (char *)out_addr, (char *)kcd_max_address(stackshot_kcdata_p), MAX_FRAMES, FALSE, &thread_snapshot_flags);
					if (saved_count > 0){
						cur_thread_snap->ths_ss_flags |= kKernel64_p;
						kcd_exit_on_error(kcdata_get_memory_addr_for_array(stackshot_kcdata_p,
									STACKSHOT_KCTYPE_KERN_STACKFRAME64,
									sizeof(struct stack_snapshot_frame64),
									saved_count/sizeof(struct stack_snapshot_frame64),
									&out_addr));
					}
#else
					out_addr = (mach_vm_address_t)kcd_end_address(stackshot_kcdata_p);
					saved_count = machine_trace_thread(thread, (char *)out_addr, (char *)kcd_max_address(stackshot_kcdata_p), MAX_FRAMES, FALSE, &thread_snapshot_flags);
					if (saved_count > 0) {
						kcd_exit_on_error(kcdata_get_memory_addr_for_array(stackshot_kcdata_p,
									STACKSHOT_KCTYPE_KERN_STACKFRAME,
									sizeof(struct stack_snapshot_frame32),
									saved_count/sizeof(struct stack_snapshot_frame32),
									&out_addr));
					}
#endif
					if (thread_snapshot_flags != 0) {
						cur_thread_snap->ths_ss_flags |= thread_snapshot_flags;
					}
				}
				/* mark end of thread snapshot data */
				kcd_exit_on_error(kcdata_add_container_marker(stackshot_kcdata_p, KCDATA_TYPE_CONTAINER_END, STACKSHOT_KCCONTAINER_THREAD, thread_uniqueid));
			}
			/* mark end of task snapshot data */
			kcd_exit_on_error(kcdata_add_container_marker(stackshot_kcdata_p, KCDATA_TYPE_CONTAINER_END, STACKSHOT_KCCONTAINER_TASK, task_uniqueid));
		}
	}

	/*  === END of populating stackshot data === */

	*pBytesTraced = (uint32_t) kcdata_memory_get_used_bytes(stackshot_kcdata_p);
error_exit:
	/* Release stack snapshot wait indicator */
	kdp_snapshot_postflight();

	return error;
}

static int
kdp_stackshot(int pid, void *tracebuf, uint32_t tracebuf_size, uint32_t trace_flags, uint32_t *pbytesTraced)
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

		if (!task->active || task_is_a_corpse(task)) {
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

			if (have_pmap && task_pid == 0) {
				if (save_kextloadinfo_p && ml_validate_nofault((vm_offset_t)(gLoadedKextSummaries), sizeof(OSKextLoadedKextSummaryHeader))) {
					uuid_info_count = gLoadedKextSummaries->numSummaries + 1; /* include main kernel UUID */
				}else {
					uuid_info_count = 1; /* atleast include kernel uuid */
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
			if (!task->active || task_is_a_corpse(task))
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
				uint32_t  uuid_offset = offsetof(kernel_uuid_info, imageUUID);
				uintptr_t image_load_address;

				if (tracepos + uuid_info_array_size > tracebound) {
					error = -1;
					goto error_exit;
				}

				do {

					if (!kernel_uuid || !ml_validate_nofault((vm_offset_t)kernel_uuid, sizeof(uuid_t))) {
						/* Kernel UUID not found or inaccessible */
						task_snap->nloadinfos = 0;
						break;
					}
					image_load_address = (uintptr_t)VM_KERNEL_UNSLIDE(vm_kernel_stext);
					memcpy(tracepos, &image_load_address, sizeof(uintptr_t));
					memcpy((tracepos + uuid_offset), kernel_uuid, sizeof(uuid_t));
					tracepos += uuid_info_size;

					if (save_kextloadinfo_p && ml_validate_nofault((vm_offset_t)(&gLoadedKextSummaries->summaries[0]),
											gLoadedKextSummaries->entry_size * gLoadedKextSummaries->numSummaries)) {
						uint32_t kexti;
						for (kexti=0 ; kexti < gLoadedKextSummaries->numSummaries; kexti++) {
							image_load_address = (uintptr_t)VM_KERNEL_UNSLIDE(gLoadedKextSummaries->summaries[kexti].address);
							memcpy(tracepos, &image_load_address, sizeof(uintptr_t));
							memcpy((tracepos + uuid_offset), &gLoadedKextSummaries->summaries[kexti].uuid, sizeof(uuid_t));
							tracepos += uuid_info_size;
						}
					} else {
						/* kext summary invalid, but kernel UUID was copied */
						task_snap->nloadinfos = 1;
						break;
					}
				} while(0);
			}
			
			if (save_donating_pids_p) {
				if (tracepos + (TASK_IMP_WALK_LIMIT * sizeof(int32_t)) > tracebound) {
					error = -1;
					goto error_exit;
				}

				task_snap->donating_pid_count = task_importance_list_pids(task, TASK_IMP_LIST_DONATING_PIDS, tracepos, TASK_IMP_WALK_LIMIT);
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
				tsnap->priority = thread->base_pri;
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

				if (thread->options & TH_OPT_GLOBAL_FORCED_IDLE) {
					tsnap->ss_flags |= kGlobalForcedIdle;
				}

				if (IPC_VOUCHER_NULL != thread->ith_voucher) {
					tsnap->voucher_identifier = VM_KERNEL_ADDRPERM(thread->ith_voucher);
				}

				tsnap->ts_qos = thread->effective_policy.thep_qos;
				tsnap->ts_rqos = thread->requested_policy.thrp_qos;
				tsnap->ts_rqos_override = thread->requested_policy.thrp_qos_override;
				/* zero out unused data. */
				tsnap->_reserved[0] = 0;
				tsnap->_reserved[1] = 0;
				tsnap->_reserved[2] = 0;
				tsnap->total_syscalls = thread->syscalls_mach + thread->syscalls_unix;

				if (dispatch_p && (task != kernel_task) && (task->active) && have_pmap) {
					uint64_t dqkeyaddr = thread_dispatchqaddr(thread);
					if (dqkeyaddr != 0) {
						uint64_t dqaddr = 0;
						if (kdp_copyin(task->map->pmap, dqkeyaddr, &dqaddr, (task64 ? 8 : 4)) && (dqaddr != 0)) {
							uint64_t dqserialnumaddr = dqaddr + proc_dispatchqueue_serialno_offset_from_task(task);
							uint64_t dqserialnum = 0;
							if (kdp_copyin(task->map->pmap, dqserialnumaddr, &dqserialnum, (task64 ? 8 : 4))) {
								tsnap->ss_flags |= kHasDispatchSerial;
								memcpy(tracepos, &dqserialnum, sizeof(dqserialnum));
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
					uint32_t thread_snapshot_flags = 0;
#if defined(__LP64__)					
					tracebytes = machine_trace_thread64(thread, tracepos, tracebound, MAX_FRAMES, FALSE, &thread_snapshot_flags);
					tsnap->ss_flags |= kKernel64_p;
					framesize = 16;
#else
					tracebytes = machine_trace_thread(thread, tracepos, tracebound, MAX_FRAMES, FALSE, &thread_snapshot_flags);
					framesize = 8;
#endif
					if (thread_snapshot_flags != 0) {
						tsnap->ss_flags |= thread_snapshot_flags;
					}
				}
				tsnap->nkern_frames = tracebytes/framesize;
				tracepos += tracebytes;
				tracebytes = 0;
				/* Trace user stack, if any */
				if (save_userframes_p && task->active && thread->task->map != kernel_map) {
					uint32_t thread_snapshot_flags = 0;
					/* 64-bit task? */
					if (task_has_64BitAddr(thread->task)) {
						tracebytes = machine_trace_thread64(thread, tracepos, tracebound, MAX_FRAMES, TRUE, &thread_snapshot_flags);
						tsnap->ss_flags |= kUser64_p;
						framesize = 16;
					}
					else {
						tracebytes = machine_trace_thread(thread, tracepos, tracebound, MAX_FRAMES, TRUE, &thread_snapshot_flags);
						framesize = 8;
					}
					if (thread_snapshot_flags != 0) {
						tsnap->ss_flags |= thread_snapshot_flags;
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

	if (task->bsd_info) {
		pid = proc_pid(task->bsd_info);
	} else {
		pid = task_pid(task);
	}

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

static uint64_t
proc_dispatchqueue_serialno_offset_from_task(task_t task)
{
	uint64_t dq_serialno_offset = 0;

	if (task->bsd_info) {
		dq_serialno_offset = get_dispatchqueue_serialno_offset_from_proc(task->bsd_info);
	}

	return dq_serialno_offset;
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

#if (defined(__arm64__) || defined(NAND_PANIC_DEVICE)) && !defined(LEGACY_PANIC_LOGS)
	/* Identify if destination buffer is in panic storage area */
	if ((vm_offset_t)dest >= gPanicBase && (vm_offset_t)dest < gPanicBase + gPanicSize) {
		if (((vm_offset_t)dest + size) >= (gPanicBase + gPanicSize)) {
			return FALSE;
		}
		ppnum_t upn = pmap_find_phys(p, uaddr);
		uint64_t phys_src = ptoa_64(upn) | (uaddr & PAGE_MASK);
		void *src_va = (void*)phystokv(phys_src);
		if (upn && pmap_valid_page(upn)) {
			bcopy(src_va, kvaddr, size);
			return TRUE;
		}
		return FALSE;
	}
#endif

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
    if (stack_snapshot_flags & STACKSHOT_KCDATA_FORMAT) {
        stack_snapshot_ret = kdp_stackshot_kcdata_format(stack_snapshot_pid,
	    stack_snapshot_flags,
	    &stack_snapshot_bytes_traced);
    }
    else {
        stack_snapshot_ret = kdp_stackshot(stack_snapshot_pid,
	    stack_snapshot_buf, stack_snapshot_bufsize,
	    stack_snapshot_flags, &stack_snapshot_bytes_traced);
    }
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
machine_trace_thread_get_kva(vm_offset_t cur_target_addr, vm_map_t map, uint32_t *thread_trace_flags)
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

			if (!stack_enable_faulting) {
				return 0;
			}

			/*
			 * The pmap doesn't have a valid page so we start at the top level
			 * vm map and try a lightweight fault.
			 */
			cur_phys_addr = kdp_lightweight_fault(map, (cur_target_addr & ~PAGE_MASK), thread_trace_flags);
			cur_phys_addr += (cur_target_addr & PAGE_MASK);

			if (!pmap_valid_page((ppnum_t) atop(cur_phys_addr)))
				return 0;
		} else {
			/*
			 * This check is done in kdp_lightweight_fault for the fault path.
			 */
			cur_wimg_bits = pmap_cache_attributes((ppnum_t) atop(cur_phys_addr));

			if ((cur_wimg_bits & VM_WIMG_MASK) != VM_WIMG_DEFAULT) {
				return 0;
			}
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

