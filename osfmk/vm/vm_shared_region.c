/*
 * Copyright (c) 2007-2020 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

/*
 * Shared region (... and comm page)
 *
 * This file handles the VM shared region and comm page.
 *
 */
/*
 * SHARED REGIONS
 * --------------
 *
 * A shared region is a submap that contains the most common system shared
 * libraries for a given environment which is defined by:
 * - cpu-type
 * - 64-bitness
 * - root directory
 * - Team ID - when we have pointer authentication.
 *
 * The point of a shared region is to reduce the setup overhead when exec'ing
 * a new process. A shared region uses a shared VM submap that gets mapped
 * automatically at exec() time, see vm_map_exec().  The first process of a given
 * environment sets up the shared region and all further processes in that
 * environment can re-use that shared region without having to re-create
 * the same mappings in their VM map.  All they need is contained in the shared
 * region.
 *
 * The region can also share a pmap (mostly for read-only parts but also for the
 * initial version of some writable parts), which gets "nested" into the
 * process's pmap.  This reduces the number of soft faults:  once one process
 * brings in a page in the shared region, all the other processes can access
 * it without having to enter it in their own pmap.
 *
 * When a process is being exec'ed, vm_map_exec() calls vm_shared_region_enter()
 * to map the appropriate shared region in the process's address space.
 * We look up the appropriate shared region for the process's environment.
 * If we can't find one, we create a new (empty) one and add it to the list.
 * Otherwise, we just take an extra reference on the shared region we found.
 *
 * The "dyld" runtime, mapped into the process's address space at exec() time,
 * will then use the shared_region_check_np() and shared_region_map_and_slide_np()
 * system calls to validate and/or populate the shared region with the
 * appropriate dyld_shared_cache file.
 *
 * The shared region is inherited on fork() and the child simply takes an
 * extra reference on its parent's shared region.
 *
 * When the task terminates, we release the reference on its shared region.
 * When the last reference is released, we destroy the shared region.
 *
 * After a chroot(), the calling process keeps using its original shared region,
 * since that's what was mapped when it was started.  But its children
 * will use a different shared region, because they need to use the shared
 * cache that's relative to the new root directory.
 */

/*
 * COMM PAGE
 *
 * A "comm page" is an area of memory that is populated by the kernel with
 * the appropriate platform-specific version of some commonly used code.
 * There is one "comm page" per platform (cpu-type, 64-bitness) but only
 * for the native cpu-type.  No need to overly optimize translated code
 * for hardware that is not really there !
 *
 * The comm pages are created and populated at boot time.
 *
 * The appropriate comm page is mapped into a process's address space
 * at exec() time, in vm_map_exec(). It is then inherited on fork().
 *
 * The comm page is shared between the kernel and all applications of
 * a given platform. Only the kernel can modify it.
 *
 * Applications just branch to fixed addresses in the comm page and find
 * the right version of the code for the platform.  There is also some
 * data provided and updated by the kernel for processes to retrieve easily
 * without having to do a system call.
 */

#include <debug.h>

#include <kern/ipc_tt.h>
#include <kern/kalloc.h>
#include <kern/thread_call.h>

#include <mach/mach_vm.h>

#include <vm/vm_map.h>
#include <vm/vm_shared_region.h>

#include <vm/vm_protos.h>

#include <machine/commpage.h>
#include <machine/cpu_capabilities.h>
#include <sys/random.h>

#if defined (__arm__) || defined(__arm64__)
#include <arm/cpu_data_internal.h>
#include <arm/misc_protos.h>
#endif

/*
 * the following codes are used in the  subclass
 * of the DBG_MACH_SHAREDREGION class
 */
#define PROCESS_SHARED_CACHE_LAYOUT 0x00

#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif /* __has_feature(ptrauth_calls) */

/* "dyld" uses this to figure out what the kernel supports */
int shared_region_version = 3;

/* trace level, output is sent to the system log file */
int shared_region_trace_level = SHARED_REGION_TRACE_ERROR_LVL;

/* should local (non-chroot) shared regions persist when no task uses them ? */
int shared_region_persistence = 0;      /* no by default */


/* delay in seconds before reclaiming an unused shared region */
TUNABLE_WRITEABLE(int, shared_region_destroy_delay, "vm_shared_region_destroy_delay", 120);

struct vm_shared_region *init_task_shared_region = NULL;

#ifndef CONFIG_EMBEDDED
/*
 * Only one cache gets to slide on Desktop, since we can't
 * tear down slide info properly today and the desktop actually
 * produces lots of shared caches.
 */
boolean_t shared_region_completed_slide = FALSE;
#endif

/* this lock protects all the shared region data structures */
static LCK_GRP_DECLARE(vm_shared_region_lck_grp, "vm shared region");
static LCK_MTX_DECLARE(vm_shared_region_lock, &vm_shared_region_lck_grp);

#define vm_shared_region_lock() lck_mtx_lock(&vm_shared_region_lock)
#define vm_shared_region_unlock() lck_mtx_unlock(&vm_shared_region_lock)
#define vm_shared_region_sleep(event, interruptible)                    \
	lck_mtx_sleep(&vm_shared_region_lock,                           \
	              LCK_SLEEP_DEFAULT,                                \
	              (event_t) (event),                                \
	              (interruptible))

/* the list of currently available shared regions (one per environment) */
queue_head_t    vm_shared_region_queue = QUEUE_HEAD_INITIALIZER(vm_shared_region_queue);
int             vm_shared_region_count = 0;
int             vm_shared_region_peak = 0;

/*
 * the number of times an event has forced the recalculation of the reslide
 * shared region slide.
 */
#if __has_feature(ptrauth_calls)
int                             vm_shared_region_reslide_count = 0;
#endif /* __has_feature(ptrauth_calls) */

static void vm_shared_region_reference_locked(vm_shared_region_t shared_region);
static vm_shared_region_t vm_shared_region_create(
	void                    *root_dir,
	cpu_type_t              cputype,
	cpu_subtype_t           cpu_subtype,
	boolean_t               is_64bit,
	boolean_t               reslide);
static void vm_shared_region_destroy(vm_shared_region_t shared_region);

static kern_return_t vm_shared_region_slide_sanity_check(vm_shared_region_slide_info_entry_t entry, mach_vm_size_t size);
static void vm_shared_region_timeout(thread_call_param_t param0,
    thread_call_param_t param1);
static kern_return_t vm_shared_region_slide_mapping(
	vm_shared_region_t sr,
	user_addr_t        slide_info_addr,
	mach_vm_size_t     slide_info_size,
	mach_vm_offset_t   start,
	mach_vm_size_t     size,
	mach_vm_offset_t   slid_mapping,
	uint32_t           slide,
	memory_object_control_t,
	vm_prot_t          prot); /* forward */

static int __commpage_setup = 0;
#if !CONFIG_EMBEDDED
static int __system_power_source = 1;   /* init to extrnal power source */
static void post_sys_powersource_internal(int i, int internal);
#endif

extern u_int32_t random(void);

/*
 * Retrieve a task's shared region and grab an extra reference to
 * make sure it doesn't disappear while the caller is using it.
 * The caller is responsible for consuming that extra reference if
 * necessary.
 */
vm_shared_region_t
vm_shared_region_get(
	task_t          task)
{
	vm_shared_region_t      shared_region;

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: -> get(%p)\n",
		(void *)VM_KERNEL_ADDRPERM(task)));

	task_lock(task);
	vm_shared_region_lock();
	shared_region = task->shared_region;
	if (shared_region) {
		assert(shared_region->sr_ref_count > 0);
		vm_shared_region_reference_locked(shared_region);
	}
	vm_shared_region_unlock();
	task_unlock(task);

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: get(%p) <- %p\n",
		(void *)VM_KERNEL_ADDRPERM(task),
		(void *)VM_KERNEL_ADDRPERM(shared_region)));

	return shared_region;
}

/*
 * Get the base address of the shared region.
 * That's the address at which it needs to be mapped in the process's address
 * space.
 * No need to lock since this data is set when the shared region is
 * created and is never modified after that.  The caller must hold an extra
 * reference on the shared region to prevent it from being destroyed.
 */
mach_vm_offset_t
vm_shared_region_base_address(
	vm_shared_region_t      shared_region)
{
	SHARED_REGION_TRACE_DEBUG(
		("shared_region: -> base_address(%p)\n",
		(void *)VM_KERNEL_ADDRPERM(shared_region)));
	assert(shared_region->sr_ref_count > 1);
	SHARED_REGION_TRACE_DEBUG(
		("shared_region: base_address(%p) <- 0x%llx\n",
		(void *)VM_KERNEL_ADDRPERM(shared_region),
		(long long)shared_region->sr_base_address));
	return shared_region->sr_base_address;
}

/*
 * Get the size of the shared region.
 * That's the size that needs to be mapped in the process's address
 * space.
 * No need to lock since this data is set when the shared region is
 * created and is never modified after that.  The caller must hold an extra
 * reference on the shared region to prevent it from being destroyed.
 */
mach_vm_size_t
vm_shared_region_size(
	vm_shared_region_t      shared_region)
{
	SHARED_REGION_TRACE_DEBUG(
		("shared_region: -> size(%p)\n",
		(void *)VM_KERNEL_ADDRPERM(shared_region)));
	assert(shared_region->sr_ref_count > 1);
	SHARED_REGION_TRACE_DEBUG(
		("shared_region: size(%p) <- 0x%llx\n",
		(void *)VM_KERNEL_ADDRPERM(shared_region),
		(long long)shared_region->sr_size));
	return shared_region->sr_size;
}

/*
 * Get the memory entry of the shared region.
 * That's the "memory object" that needs to be mapped in the process's address
 * space.
 * No need to lock since this data is set when the shared region is
 * created and is never modified after that.  The caller must hold an extra
 * reference on the shared region to prevent it from being destroyed.
 */
ipc_port_t
vm_shared_region_mem_entry(
	vm_shared_region_t      shared_region)
{
	SHARED_REGION_TRACE_DEBUG(
		("shared_region: -> mem_entry(%p)\n",
		(void *)VM_KERNEL_ADDRPERM(shared_region)));
	assert(shared_region->sr_ref_count > 1);
	SHARED_REGION_TRACE_DEBUG(
		("shared_region: mem_entry(%p) <- %p\n",
		(void *)VM_KERNEL_ADDRPERM(shared_region),
		(void *)VM_KERNEL_ADDRPERM(shared_region->sr_mem_entry)));
	return shared_region->sr_mem_entry;
}

vm_map_t
vm_shared_region_vm_map(
	vm_shared_region_t      shared_region)
{
	ipc_port_t              sr_handle;
	vm_named_entry_t        sr_mem_entry;
	vm_map_t                sr_map;

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: -> vm_map(%p)\n",
		(void *)VM_KERNEL_ADDRPERM(shared_region)));
	assert(shared_region->sr_ref_count > 1);

	sr_handle = shared_region->sr_mem_entry;
	sr_mem_entry = (vm_named_entry_t) ip_get_kobject(sr_handle);
	sr_map = sr_mem_entry->backing.map;
	assert(sr_mem_entry->is_sub_map);

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: vm_map(%p) <- %p\n",
		(void *)VM_KERNEL_ADDRPERM(shared_region),
		(void *)VM_KERNEL_ADDRPERM(sr_map)));
	return sr_map;
}

/*
 * Set the shared region the process should use.
 * A NULL new shared region means that we just want to release the old
 * shared region.
 * The caller should already have an extra reference on the new shared region
 * (if any).  We release a reference on the old shared region (if any).
 */
void
vm_shared_region_set(
	task_t                  task,
	vm_shared_region_t      new_shared_region)
{
	vm_shared_region_t      old_shared_region;

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: -> set(%p, %p)\n",
		(void *)VM_KERNEL_ADDRPERM(task),
		(void *)VM_KERNEL_ADDRPERM(new_shared_region)));

	task_lock(task);
	vm_shared_region_lock();

	old_shared_region = task->shared_region;
	if (new_shared_region) {
		assert(new_shared_region->sr_ref_count > 0);
	}

	task->shared_region = new_shared_region;

	vm_shared_region_unlock();
	task_unlock(task);

	if (old_shared_region) {
		assert(old_shared_region->sr_ref_count > 0);
		vm_shared_region_deallocate(old_shared_region);
	}

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: set(%p) <- old=%p new=%p\n",
		(void *)VM_KERNEL_ADDRPERM(task),
		(void *)VM_KERNEL_ADDRPERM(old_shared_region),
		(void *)VM_KERNEL_ADDRPERM(new_shared_region)));
}

/*
 * Lookup up the shared region for the desired environment.
 * If none is found, create a new (empty) one.
 * Grab an extra reference on the returned shared region, to make sure
 * it doesn't get destroyed before the caller is done with it.  The caller
 * is responsible for consuming that extra reference if necessary.
 */
vm_shared_region_t
vm_shared_region_lookup(
	void            *root_dir,
	cpu_type_t      cputype,
	cpu_subtype_t   cpu_subtype,
	boolean_t       is_64bit,
	boolean_t       reslide)
{
	vm_shared_region_t      shared_region;
	vm_shared_region_t      new_shared_region;

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: -> lookup(root=%p,cpu=<%d,%d>,64bit=%d,reslide=%d)\n",
		(void *)VM_KERNEL_ADDRPERM(root_dir),
		cputype, cpu_subtype, is_64bit, reslide));

	shared_region = NULL;
	new_shared_region = NULL;

	vm_shared_region_lock();
	for (;;) {
		queue_iterate(&vm_shared_region_queue,
		    shared_region,
		    vm_shared_region_t,
		    sr_q) {
			assert(shared_region->sr_ref_count > 0);
			if (shared_region->sr_cpu_type == cputype &&
#if !__has_feature(ptrauth_calls)                                 /* arm64e/arm64 use same region */
			    shared_region->sr_cpu_subtype == cpu_subtype &&
#endif /* !__has_feature(ptrauth_calls) */
			    shared_region->sr_root_dir == root_dir &&
			    shared_region->sr_64bit == is_64bit &&
#if __has_feature(ptrauth_calls)
			    shared_region->sr_reslide == reslide &&
#endif /* __has_feature(ptrauth_calls) */
			    !shared_region->sr_stale) {
				/* found a match ! */
				vm_shared_region_reference_locked(shared_region);
				goto done;
			}
		}
		if (new_shared_region == NULL) {
			/* no match: create a new one */
			vm_shared_region_unlock();
			new_shared_region = vm_shared_region_create(root_dir,
			    cputype,
			    cpu_subtype,
			    is_64bit,
			    reslide);
			/* do the lookup again, in case we lost a race */
			vm_shared_region_lock();
			continue;
		}
		/* still no match: use our new one */
		shared_region = new_shared_region;
		new_shared_region = NULL;
		queue_enter(&vm_shared_region_queue,
		    shared_region,
		    vm_shared_region_t,
		    sr_q);
		vm_shared_region_count++;
		if (vm_shared_region_count > vm_shared_region_peak) {
			vm_shared_region_peak = vm_shared_region_count;
		}
		break;
	}

done:
	vm_shared_region_unlock();

	if (new_shared_region) {
		/*
		 * We lost a race with someone else to create a new shared
		 * region for that environment. Get rid of our unused one.
		 */
		assert(new_shared_region->sr_ref_count == 1);
		new_shared_region->sr_ref_count--;
		vm_shared_region_destroy(new_shared_region);
		new_shared_region = NULL;
	}

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: lookup(root=%p,cpu=<%d,%d>,64bit=%d,reslide=%d) <- %p\n",
		(void *)VM_KERNEL_ADDRPERM(root_dir),
		cputype, cpu_subtype, is_64bit, reslide,
		(void *)VM_KERNEL_ADDRPERM(shared_region)));

	assert(shared_region->sr_ref_count > 0);
	return shared_region;
}

/*
 * Take an extra reference on a shared region.
 * The vm_shared_region_lock should already be held by the caller.
 */
static void
vm_shared_region_reference_locked(
	vm_shared_region_t      shared_region)
{
	LCK_MTX_ASSERT(&vm_shared_region_lock, LCK_MTX_ASSERT_OWNED);

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: -> reference_locked(%p)\n",
		(void *)VM_KERNEL_ADDRPERM(shared_region)));
	assert(shared_region->sr_ref_count > 0);
	shared_region->sr_ref_count++;
	assert(shared_region->sr_ref_count != 0);

	if (shared_region->sr_timer_call != NULL) {
		boolean_t cancelled;

		/* cancel and free any pending timeout */
		cancelled = thread_call_cancel(shared_region->sr_timer_call);
		if (cancelled) {
			thread_call_free(shared_region->sr_timer_call);
			shared_region->sr_timer_call = NULL;
			/* release the reference held by the cancelled timer */
			shared_region->sr_ref_count--;
		} else {
			/* the timer will drop the reference and free itself */
		}
	}

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: reference_locked(%p) <- %d\n",
		(void *)VM_KERNEL_ADDRPERM(shared_region),
		shared_region->sr_ref_count));
}

/*
 * Take a reference on a shared region.
 */
void
vm_shared_region_reference(vm_shared_region_t shared_region)
{
	SHARED_REGION_TRACE_DEBUG(
		("shared_region: -> reference(%p)\n",
		(void *)VM_KERNEL_ADDRPERM(shared_region)));

	vm_shared_region_lock();
	vm_shared_region_reference_locked(shared_region);
	vm_shared_region_unlock();

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: reference(%p) <- %d\n",
		(void *)VM_KERNEL_ADDRPERM(shared_region),
		shared_region->sr_ref_count));
}

/*
 * Release a reference on the shared region.
 * Destroy it if there are no references left.
 */
void
vm_shared_region_deallocate(
	vm_shared_region_t      shared_region)
{
	SHARED_REGION_TRACE_DEBUG(
		("shared_region: -> deallocate(%p)\n",
		(void *)VM_KERNEL_ADDRPERM(shared_region)));

	vm_shared_region_lock();

	assert(shared_region->sr_ref_count > 0);

	if (shared_region->sr_root_dir == NULL) {
		/*
		 * Local (i.e. based on the boot volume) shared regions
		 * can persist or not based on the "shared_region_persistence"
		 * sysctl.
		 * Make sure that this one complies.
		 *
		 * See comments in vm_shared_region_slide() for notes about
		 * shared regions we have slid (which are not torn down currently).
		 */
		if (shared_region_persistence &&
		    !shared_region->sr_persists) {
			/* make this one persistent */
			shared_region->sr_ref_count++;
			shared_region->sr_persists = TRUE;
		} else if (!shared_region_persistence &&
		    shared_region->sr_persists) {
			/* make this one no longer persistent */
			assert(shared_region->sr_ref_count > 1);
			shared_region->sr_ref_count--;
			shared_region->sr_persists = FALSE;
		}
	}

	assert(shared_region->sr_ref_count > 0);
	shared_region->sr_ref_count--;
	SHARED_REGION_TRACE_DEBUG(
		("shared_region: deallocate(%p): ref now %d\n",
		(void *)VM_KERNEL_ADDRPERM(shared_region),
		shared_region->sr_ref_count));

	if (shared_region->sr_ref_count == 0) {
		uint64_t deadline;

		/*
		 * Even though a shared region is unused, delay a while before
		 * tearing it down, in case a new app launch can use it.
		 */
		if (shared_region->sr_timer_call == NULL &&
		    shared_region_destroy_delay != 0 &&
		    !shared_region->sr_stale) {
			/* hold one reference for the timer */
			assert(!shared_region->sr_mapping_in_progress);
			shared_region->sr_ref_count++;

			/* set up the timer */
			shared_region->sr_timer_call = thread_call_allocate(
				(thread_call_func_t) vm_shared_region_timeout,
				(thread_call_param_t) shared_region);

			/* schedule the timer */
			clock_interval_to_deadline(shared_region_destroy_delay,
			    NSEC_PER_SEC,
			    &deadline);
			thread_call_enter_delayed(shared_region->sr_timer_call,
			    deadline);

			SHARED_REGION_TRACE_DEBUG(
				("shared_region: deallocate(%p): armed timer\n",
				(void *)VM_KERNEL_ADDRPERM(shared_region)));

			vm_shared_region_unlock();
		} else {
			/* timer expired: let go of this shared region */

			/*
			 * Remove it from the queue first, so no one can find
			 * it...
			 */
			queue_remove(&vm_shared_region_queue,
			    shared_region,
			    vm_shared_region_t,
			    sr_q);
			vm_shared_region_count--;
			vm_shared_region_unlock();

			/* ... and destroy it */
			vm_shared_region_destroy(shared_region);
			shared_region = NULL;
		}
	} else {
		vm_shared_region_unlock();
	}

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: deallocate(%p) <-\n",
		(void *)VM_KERNEL_ADDRPERM(shared_region)));
}

void
vm_shared_region_timeout(
	thread_call_param_t     param0,
	__unused thread_call_param_t    param1)
{
	vm_shared_region_t      shared_region;

	shared_region = (vm_shared_region_t) param0;

	vm_shared_region_deallocate(shared_region);
}


/*
 * Create a new (empty) shared region for a new environment.
 */
static vm_shared_region_t
vm_shared_region_create(
	void                    *root_dir,
	cpu_type_t              cputype,
	cpu_subtype_t           cpu_subtype,
	boolean_t               is_64bit,
#if !__has_feature(ptrauth_calls)
	__unused
#endif /* __has_feature(ptrauth_calls) */
	boolean_t               reslide)
{
	kern_return_t           kr;
	vm_named_entry_t        mem_entry;
	ipc_port_t              mem_entry_port;
	vm_shared_region_t      shared_region;
	vm_map_t                sub_map;
	mach_vm_offset_t        base_address, pmap_nesting_start;
	mach_vm_size_t          size, pmap_nesting_size;

	SHARED_REGION_TRACE_INFO(
		("shared_region: -> create(root=%p,cpu=<%d,%d>,64bit=%d,reslide=%d)\n",
		(void *)VM_KERNEL_ADDRPERM(root_dir),
		cputype, cpu_subtype, is_64bit, reslide));

	base_address = 0;
	size = 0;
	mem_entry = NULL;
	mem_entry_port = IPC_PORT_NULL;
	sub_map = VM_MAP_NULL;

	/* create a new shared region structure... */
	shared_region = kalloc(sizeof(*shared_region));
	if (shared_region == NULL) {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: create: couldn't allocate\n"));
		goto done;
	}

	/* figure out the correct settings for the desired environment */
	if (is_64bit) {
		switch (cputype) {
#if defined(__arm64__)
		case CPU_TYPE_ARM64:
			base_address = SHARED_REGION_BASE_ARM64;
			size = SHARED_REGION_SIZE_ARM64;
			pmap_nesting_start = SHARED_REGION_NESTING_BASE_ARM64;
			pmap_nesting_size = SHARED_REGION_NESTING_SIZE_ARM64;
			break;
#elif !defined(__arm__)
		case CPU_TYPE_I386:
			base_address = SHARED_REGION_BASE_X86_64;
			size = SHARED_REGION_SIZE_X86_64;
			pmap_nesting_start = SHARED_REGION_NESTING_BASE_X86_64;
			pmap_nesting_size = SHARED_REGION_NESTING_SIZE_X86_64;
			break;
		case CPU_TYPE_POWERPC:
			base_address = SHARED_REGION_BASE_PPC64;
			size = SHARED_REGION_SIZE_PPC64;
			pmap_nesting_start = SHARED_REGION_NESTING_BASE_PPC64;
			pmap_nesting_size = SHARED_REGION_NESTING_SIZE_PPC64;
			break;
#endif
		default:
			SHARED_REGION_TRACE_ERROR(
				("shared_region: create: unknown cpu type %d\n",
				cputype));
			kfree(shared_region, sizeof(*shared_region));
			shared_region = NULL;
			goto done;
		}
	} else {
		switch (cputype) {
#if defined(__arm__) || defined(__arm64__)
		case CPU_TYPE_ARM:
			base_address = SHARED_REGION_BASE_ARM;
			size = SHARED_REGION_SIZE_ARM;
			pmap_nesting_start = SHARED_REGION_NESTING_BASE_ARM;
			pmap_nesting_size = SHARED_REGION_NESTING_SIZE_ARM;
			break;
#else
		case CPU_TYPE_I386:
			base_address = SHARED_REGION_BASE_I386;
			size = SHARED_REGION_SIZE_I386;
			pmap_nesting_start = SHARED_REGION_NESTING_BASE_I386;
			pmap_nesting_size = SHARED_REGION_NESTING_SIZE_I386;
			break;
		case CPU_TYPE_POWERPC:
			base_address = SHARED_REGION_BASE_PPC;
			size = SHARED_REGION_SIZE_PPC;
			pmap_nesting_start = SHARED_REGION_NESTING_BASE_PPC;
			pmap_nesting_size = SHARED_REGION_NESTING_SIZE_PPC;
			break;
#endif
		default:
			SHARED_REGION_TRACE_ERROR(
				("shared_region: create: unknown cpu type %d\n",
				cputype));
			kfree(shared_region, sizeof(*shared_region));
			shared_region = NULL;
			goto done;
		}
	}

	/* create a memory entry structure and a Mach port handle */
	kr = mach_memory_entry_allocate(&mem_entry, &mem_entry_port);
	if (kr != KERN_SUCCESS) {
		kfree(shared_region, sizeof(*shared_region));
		shared_region = NULL;
		SHARED_REGION_TRACE_ERROR(
			("shared_region: create: "
			"couldn't allocate mem_entry\n"));
		goto done;
	}

#if     defined(__arm__) || defined(__arm64__)
	{
		struct pmap *pmap_nested;
		int pmap_flags = 0;
		pmap_flags |= is_64bit ? PMAP_CREATE_64BIT : 0;


		pmap_nested = pmap_create_options(NULL, 0, pmap_flags);
		if (pmap_nested != PMAP_NULL) {
			pmap_set_nested(pmap_nested);
			sub_map = vm_map_create(pmap_nested, 0, (vm_map_offset_t)size, TRUE);
#if defined(__arm64__)
			if (is_64bit ||
			    page_shift_user32 == SIXTEENK_PAGE_SHIFT) {
				/* enforce 16KB alignment of VM map entries */
				vm_map_set_page_shift(sub_map,
				    SIXTEENK_PAGE_SHIFT);
			}

#elif (__ARM_ARCH_7K__ >= 2)
			/* enforce 16KB alignment for watch targets with new ABI */
			vm_map_set_page_shift(sub_map, SIXTEENK_PAGE_SHIFT);
#endif /* __arm64__ */
		} else {
			sub_map = VM_MAP_NULL;
		}
	}
#else
	/* create a VM sub map and its pmap */
	sub_map = vm_map_create(pmap_create_options(NULL, 0, is_64bit), 0, size, TRUE);
#endif
	if (sub_map == VM_MAP_NULL) {
		ipc_port_release_send(mem_entry_port);
		kfree(shared_region, sizeof(*shared_region));
		shared_region = NULL;
		SHARED_REGION_TRACE_ERROR(("shared_region: create: couldn't allocate map\n"));
		goto done;
	}

	/* shared regions should always enforce code-signing */
	vm_map_cs_enforcement_set(sub_map, true);
	assert(vm_map_cs_enforcement(sub_map));
	assert(pmap_get_vm_map_cs_enforced(vm_map_pmap(sub_map)));

	assert(!sub_map->disable_vmentry_reuse);
	sub_map->is_nested_map = TRUE;

	/* make the memory entry point to the VM sub map */
	mem_entry->is_sub_map = TRUE;
	mem_entry->backing.map = sub_map;
	mem_entry->size = size;
	mem_entry->protection = VM_PROT_ALL;

	/* make the shared region point at the memory entry */
	shared_region->sr_mem_entry = mem_entry_port;

	/* fill in the shared region's environment and settings */
	shared_region->sr_base_address = base_address;
	shared_region->sr_size = size;
	shared_region->sr_pmap_nesting_start = pmap_nesting_start;
	shared_region->sr_pmap_nesting_size = pmap_nesting_size;
	shared_region->sr_cpu_type = cputype;
	shared_region->sr_cpu_subtype = cpu_subtype;
	shared_region->sr_64bit = (uint8_t)is_64bit;
	shared_region->sr_root_dir = root_dir;

	queue_init(&shared_region->sr_q);
	shared_region->sr_mapping_in_progress = FALSE;
	shared_region->sr_slide_in_progress = FALSE;
	shared_region->sr_persists = FALSE;
	shared_region->sr_stale = FALSE;
	shared_region->sr_timer_call = NULL;
	shared_region->sr_first_mapping = (mach_vm_offset_t) -1;

	/* grab a reference for the caller */
	shared_region->sr_ref_count = 1;

	shared_region->sr_slide = 0; /* not slid yet */

	/* Initialize UUID and other metadata */
	memset(&shared_region->sr_uuid, '\0', sizeof(shared_region->sr_uuid));
	shared_region->sr_uuid_copied = FALSE;
	shared_region->sr_images_count = 0;
	shared_region->sr_images = NULL;
#if __has_feature(ptrauth_calls)
	shared_region->sr_reslide = reslide;
	shared_region->sr_num_auth_section = 0;
	for (uint_t i = 0; i < NUM_SR_AUTH_SECTIONS; ++i) {
		shared_region->sr_auth_section[i] = NULL;
	}
	shared_region->sr_num_auth_section = 0;
#endif /* __has_feature(ptrauth_calls) */

done:
	if (shared_region) {
		SHARED_REGION_TRACE_INFO(
			("shared_region: create(root=%p,cpu=<%d,%d>,64bit=%d,reslide=%d"
			"base=0x%llx,size=0x%llx) <- "
			"%p mem=(%p,%p) map=%p pmap=%p\n",
			(void *)VM_KERNEL_ADDRPERM(root_dir),
			cputype, cpu_subtype, is_64bit, reslide,
			(long long)base_address,
			(long long)size,
			(void *)VM_KERNEL_ADDRPERM(shared_region),
			(void *)VM_KERNEL_ADDRPERM(mem_entry_port),
			(void *)VM_KERNEL_ADDRPERM(mem_entry),
			(void *)VM_KERNEL_ADDRPERM(sub_map),
			(void *)VM_KERNEL_ADDRPERM(sub_map->pmap)));
	} else {
		SHARED_REGION_TRACE_INFO(
			("shared_region: create(root=%p,cpu=<%d,%d>,64bit=%d,"
			"base=0x%llx,size=0x%llx) <- NULL",
			(void *)VM_KERNEL_ADDRPERM(root_dir),
			cputype, cpu_subtype, is_64bit,
			(long long)base_address,
			(long long)size));
	}
	return shared_region;
}

/*
 * Destroy a now-unused shared region.
 * The shared region is no longer in the queue and can not be looked up.
 */
static void
vm_shared_region_destroy(
	vm_shared_region_t      shared_region)
{
	vm_named_entry_t        mem_entry;
	vm_map_t                map;

	SHARED_REGION_TRACE_INFO(
		("shared_region: -> destroy(%p) (root=%p,cpu=<%d,%d>,64bit=%d)\n",
		(void *)VM_KERNEL_ADDRPERM(shared_region),
		(void *)VM_KERNEL_ADDRPERM(shared_region->sr_root_dir),
		shared_region->sr_cpu_type,
		shared_region->sr_cpu_subtype,
		shared_region->sr_64bit));

	assert(shared_region->sr_ref_count == 0);
	assert(!shared_region->sr_persists);

	mem_entry = (vm_named_entry_t) ip_get_kobject(shared_region->sr_mem_entry);
	assert(mem_entry->is_sub_map);
	assert(!mem_entry->internal);
	assert(!mem_entry->is_copy);
	map = mem_entry->backing.map;

	/*
	 * Clean up the pmap first.  The virtual addresses that were
	 * entered in this possibly "nested" pmap may have different values
	 * than the VM map's min and max offsets, if the VM sub map was
	 * mapped at a non-zero offset in the processes' main VM maps, which
	 * is usually the case, so the clean-up we do in vm_map_destroy() would
	 * not be enough.
	 */
	if (map->pmap) {
		pmap_remove(map->pmap,
		    (vm_map_offset_t)shared_region->sr_base_address,
		    (vm_map_offset_t)(shared_region->sr_base_address + shared_region->sr_size));
	}

	/*
	 * Release our (one and only) handle on the memory entry.
	 * This will generate a no-senders notification, which will be processed
	 * by ipc_kobject_notify(), which will release the one and only
	 * reference on the memory entry and cause it to be destroyed, along
	 * with the VM sub map and its pmap.
	 */
	mach_memory_entry_port_release(shared_region->sr_mem_entry);
	mem_entry = NULL;
	shared_region->sr_mem_entry = IPC_PORT_NULL;

	if (shared_region->sr_timer_call) {
		thread_call_free(shared_region->sr_timer_call);
	}

#if __has_feature(ptrauth_calls)
	/*
	 * Free the cached copies of slide_info for the AUTH regions.
	 */
	for (uint_t i = 0; i < shared_region->sr_num_auth_section; ++i) {
		vm_shared_region_slide_info_t si = shared_region->sr_auth_section[i];
		if (si != NULL) {
			vm_object_deallocate(si->si_slide_object);
			kheap_free(KHEAP_DATA_BUFFERS, si->si_slide_info_entry, si->si_slide_info_size);
			kfree(si, sizeof *si);
			shared_region->sr_auth_section[i] = NULL;
		}
	}
	shared_region->sr_num_auth_section = 0;
#endif /* __has_feature(ptrauth_calls) */

	/* release the shared region structure... */
	kfree(shared_region, sizeof(*shared_region));

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: destroy(%p) <-\n",
		(void *)VM_KERNEL_ADDRPERM(shared_region)));
	shared_region = NULL;
}

/*
 * Gets the address of the first (in time) mapping in the shared region.
 */
kern_return_t
vm_shared_region_start_address(
	vm_shared_region_t      shared_region,
	mach_vm_offset_t        *start_address)
{
	kern_return_t           kr;
	mach_vm_offset_t        sr_base_address;
	mach_vm_offset_t        sr_first_mapping;

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: -> start_address(%p)\n",
		(void *)VM_KERNEL_ADDRPERM(shared_region)));
	assert(shared_region->sr_ref_count > 1);

	vm_shared_region_lock();

	/*
	 * Wait if there's another thread establishing a mapping
	 * in this shared region right when we're looking at it.
	 * We want a consistent view of the map...
	 */
	while (shared_region->sr_mapping_in_progress) {
		/* wait for our turn... */
		assert(shared_region->sr_ref_count > 1);
		vm_shared_region_sleep(&shared_region->sr_mapping_in_progress,
		    THREAD_UNINT);
	}
	assert(!shared_region->sr_mapping_in_progress);
	assert(shared_region->sr_ref_count > 1);

	sr_base_address = shared_region->sr_base_address;
	sr_first_mapping = shared_region->sr_first_mapping;

	if (sr_first_mapping == (mach_vm_offset_t) -1) {
		/* shared region is empty */
		kr = KERN_INVALID_ADDRESS;
	} else {
		kr = KERN_SUCCESS;
		*start_address = sr_base_address + sr_first_mapping;
	}


	vm_shared_region_unlock();

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: start_address(%p) <- 0x%llx\n",
		(void *)VM_KERNEL_ADDRPERM(shared_region),
		(long long)shared_region->sr_base_address));

	return kr;
}

/*
 * Look up a pre-existing mapping in shared region, for replacement.
 * Takes an extra object reference if found.
 */
static kern_return_t
find_mapping_to_slide(vm_map_t map, vm_map_address_t addr, vm_map_entry_t entry)
{
	vm_map_entry_t found;

	/* find the shared region's map entry to slide */
	vm_map_lock_read(map);
	if (!vm_map_lookup_entry(map, addr, &found)) {
		/* no mapping there */
		vm_map_unlock(map);
		return KERN_INVALID_ARGUMENT;
	}

	*entry = *found;
	/* extra ref to keep object alive while map is unlocked */
	vm_object_reference(VME_OBJECT(found));
	vm_map_unlock_read(map);
	return KERN_SUCCESS;
}

#if __has_feature(ptrauth_calls)

/*
 * Determine if this task is actually using pointer signing.
 */
static boolean_t
task_sign_pointers(task_t task)
{
	if (task->map &&
	    task->map->pmap &&
	    !task->map->pmap->disable_jop) {
		return TRUE;
	}
	return FALSE;
}

/*
 * If the shared region contains mappings that are authenticated, then
 * remap them into the task private map.
 *
 * Failures are possible in this routine when jetsam kills a process
 * just as dyld is trying to set it up. The vm_map and task shared region
 * info get torn down w/o waiting for this thread to finish up.
 */
__attribute__((noinline))
kern_return_t
vm_shared_region_auth_remap(vm_shared_region_t sr)
{
	memory_object_t               sr_pager = MEMORY_OBJECT_NULL;
	task_t                        task = current_task();
	vm_shared_region_slide_info_t si;
	uint_t                        i;
	vm_object_t                   object;
	vm_map_t                      sr_map;
	struct vm_map_entry           tmp_entry_store = {0};
	vm_map_entry_t                tmp_entry = NULL;
	int                           vm_flags;
	vm_map_kernel_flags_t         vmk_flags;
	vm_map_offset_t               map_addr;
	kern_return_t                 kr = KERN_SUCCESS;
	boolean_t                     use_ptr_auth = task_sign_pointers(task);

	/*
	 * Don't do this more than once and avoid any race conditions in finishing it.
	 */
	vm_shared_region_lock();
	while (sr->sr_mapping_in_progress) {
		/* wait for our turn... */
		vm_shared_region_sleep(&sr->sr_mapping_in_progress, THREAD_UNINT);
	}
	assert(!sr->sr_mapping_in_progress);
	assert(sr->sr_ref_count > 1);

	/* Just return if already done. */
	if (task->shared_region_auth_remapped) {
		vm_shared_region_unlock();
		return KERN_SUCCESS;
	}

	/* let others know to wait while we're working in this shared region */
	sr->sr_mapping_in_progress = TRUE;
	vm_shared_region_unlock();

	/*
	 * Remap any sections with pointer authentications into the private map.
	 */
	for (i = 0; i < sr->sr_num_auth_section; ++i) {
		si = sr->sr_auth_section[i];
		assert(si != NULL);
		assert(si->si_ptrauth);

		/*
		 * We have mapping that needs to be private.
		 * Look for an existing slid mapping's pager with matching
		 * object, offset, slide info and shared_region_id to reuse.
		 */
		object = si->si_slide_object;
		sr_pager = shared_region_pager_match(object, si->si_start, si,
		    use_ptr_auth ? task->jop_pid : 0);
		if (sr_pager == MEMORY_OBJECT_NULL) {
			kr = KERN_FAILURE;
			goto done;
		}

		/*
		 * verify matching jop_pid for this task and this pager
		 */
		if (use_ptr_auth) {
			shared_region_pager_match_task_key(sr_pager, task);
		}

		sr_map = vm_shared_region_vm_map(sr);
		tmp_entry = NULL;

		kr = find_mapping_to_slide(sr_map, si->si_slid_address - sr->sr_base_address, &tmp_entry_store);
		if (kr != KERN_SUCCESS) {
			goto done;
		}
		tmp_entry = &tmp_entry_store;

		/*
		 * Check that the object exactly covers the region to slide.
		 */
		if (VME_OFFSET(tmp_entry) != si->si_start ||
		    tmp_entry->vme_end - tmp_entry->vme_start != si->si_end - si->si_start) {
			kr = KERN_FAILURE;
			goto done;
		}

		/*
		 * map the pager over the portion of the mapping that needs sliding
		 */
		vm_flags = VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE;
		vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;
		vmk_flags.vmkf_overwrite_immutable = TRUE;
		map_addr = si->si_slid_address;
		kr = vm_map_enter_mem_object(task->map,
		    &map_addr,
		    si->si_end - si->si_start,
		    (mach_vm_offset_t) 0,
		    vm_flags,
		    vmk_flags,
		    VM_KERN_MEMORY_NONE,
		    (ipc_port_t)(uintptr_t) sr_pager,
		    0,
		    TRUE,
		    tmp_entry->protection,
		    tmp_entry->max_protection,
		    tmp_entry->inheritance);
		memory_object_deallocate(sr_pager);
		sr_pager = MEMORY_OBJECT_NULL;
		if (kr != KERN_SUCCESS) {
			goto done;
		}
		assertf(map_addr == si->si_slid_address,
		    "map_addr=0x%llx si_slid_address=0x%llx tmp_entry=%p\n",
		    (uint64_t)map_addr,
		    (uint64_t)si->si_slid_address,
		    tmp_entry);

		/* Drop the ref count grabbed by find_mapping_to_slide */
		vm_object_deallocate(VME_OBJECT(tmp_entry));
		tmp_entry = NULL;
	}

done:
	if (tmp_entry) {
		/* Drop the ref count grabbed by find_mapping_to_slide */
		vm_object_deallocate(VME_OBJECT(tmp_entry));
		tmp_entry = NULL;
	}

	/*
	 * Drop any extra reference to the pager in case we're quitting due to an error above.
	 */
	if (sr_pager != MEMORY_OBJECT_NULL) {
		memory_object_deallocate(sr_pager);
	}

	/*
	 * Mark the region as having it's auth sections remapped.
	 */
	vm_shared_region_lock();
	task->shared_region_auth_remapped = TRUE;
	sr->sr_mapping_in_progress = FALSE;
	thread_wakeup((event_t)&sr->sr_mapping_in_progress);
	vm_shared_region_unlock();
	return kr;
}
#endif /* __has_feature(ptrauth_calls) */

void
vm_shared_region_undo_mappings(
	vm_map_t                 sr_map,
	mach_vm_offset_t         sr_base_address,
	struct _sr_file_mappings *srf_mappings,
	struct _sr_file_mappings *srf_mappings_current,
	unsigned int             srf_current_mappings_count)
{
	unsigned int             j = 0;
	vm_shared_region_t       shared_region = NULL;
	boolean_t                reset_shared_region_state = FALSE;
	struct _sr_file_mappings *srfmp;
	unsigned int             mappings_count;
	struct shared_file_mapping_slide_np *mappings;

	shared_region = vm_shared_region_get(current_task());
	if (shared_region == NULL) {
		printf("Failed to undo mappings because of NULL shared region.\n");
		return;
	}

	if (sr_map == NULL) {
		ipc_port_t              sr_handle;
		vm_named_entry_t        sr_mem_entry;

		vm_shared_region_lock();
		assert(shared_region->sr_ref_count > 1);

		while (shared_region->sr_mapping_in_progress) {
			/* wait for our turn... */
			vm_shared_region_sleep(&shared_region->sr_mapping_in_progress,
			    THREAD_UNINT);
		}
		assert(!shared_region->sr_mapping_in_progress);
		assert(shared_region->sr_ref_count > 1);
		/* let others know we're working in this shared region */
		shared_region->sr_mapping_in_progress = TRUE;

		vm_shared_region_unlock();

		reset_shared_region_state = TRUE;

		/* no need to lock because this data is never modified... */
		sr_handle = shared_region->sr_mem_entry;
		sr_mem_entry = (vm_named_entry_t) ip_get_kobject(sr_handle);
		sr_map = sr_mem_entry->backing.map;
		sr_base_address = shared_region->sr_base_address;
	}
	/*
	 * Undo the mappings we've established so far.
	 */
	for (srfmp = &srf_mappings[0];
	    srfmp <= srf_mappings_current;
	    srfmp++) {
		mappings = srfmp->mappings;
		mappings_count = srfmp->mappings_count;
		if (srfmp == srf_mappings_current) {
			mappings_count = srf_current_mappings_count;
		}

		for (j = 0; j < mappings_count; j++) {
			kern_return_t kr2;

			if (mappings[j].sms_size == 0) {
				/*
				 * We didn't establish this
				 * mapping, so nothing to undo.
				 */
				continue;
			}
			SHARED_REGION_TRACE_INFO(
				("shared_region: mapping[%d]: "
				"address:0x%016llx "
				"size:0x%016llx "
				"offset:0x%016llx "
				"maxprot:0x%x prot:0x%x: "
				"undoing...\n",
				j,
				(long long)mappings[j].sms_address,
				(long long)mappings[j].sms_size,
				(long long)mappings[j].sms_file_offset,
				mappings[j].sms_max_prot,
				mappings[j].sms_init_prot));
			kr2 = mach_vm_deallocate(
				sr_map,
				(mappings[j].sms_address -
				sr_base_address),
				mappings[j].sms_size);
			assert(kr2 == KERN_SUCCESS);
		}
	}

	if (reset_shared_region_state) {
		vm_shared_region_lock();
		assert(shared_region->sr_ref_count > 1);
		assert(shared_region->sr_mapping_in_progress);
		/* we're done working on that shared region */
		shared_region->sr_mapping_in_progress = FALSE;
		thread_wakeup((event_t) &shared_region->sr_mapping_in_progress);
		vm_shared_region_unlock();
		reset_shared_region_state = FALSE;
	}

	vm_shared_region_deallocate(shared_region);
}

/*
 * For now we only expect to see at most 2 regions to relocate/authenticate
 * per file. One that's VM_PROT_SLIDE and one VM_PROT_SLIDE | VM_PROT_NOAUTH.
 */
#define VMSR_NUM_SLIDES 2

/*
 * First part of vm_shared_region_map_file(). Split out to
 * avoid kernel stack overflow.
 */
__attribute__((noinline))
static kern_return_t
vm_shared_region_map_file_setup(
	vm_shared_region_t              shared_region,
	int                             sr_file_mappings_count,
	struct _sr_file_mappings        *sr_file_mappings,
	unsigned int                    *mappings_to_slide_cnt,
	struct shared_file_mapping_slide_np **mappings_to_slide,
	mach_vm_offset_t                *slid_mappings,
	memory_object_control_t         *slid_file_controls,
	mach_vm_offset_t                *first_mapping,
	mach_vm_offset_t                *file_first_mappings,
	mach_vm_offset_t                *sfm_min_address,
	mach_vm_offset_t                *sfm_max_address,
	vm_map_t                        *sr_map_ptr,
	vm_map_offset_t                 *lowest_unnestable_addr_ptr)
{
	kern_return_t           kr = KERN_SUCCESS;
	memory_object_control_t file_control;
	vm_object_t             file_object;
	ipc_port_t              sr_handle;
	vm_named_entry_t        sr_mem_entry;
	vm_map_t                sr_map;
	mach_vm_offset_t        sr_base_address;
	unsigned int            i = 0;
	mach_port_t             map_port;
	vm_map_offset_t         target_address;
	vm_object_t             object;
	vm_object_size_t        obj_size;
	vm_map_offset_t         lowest_unnestable_addr = 0;
	vm_map_kernel_flags_t   vmk_flags;
	mach_vm_offset_t        sfm_end;
	uint32_t                mappings_count;
	struct shared_file_mapping_slide_np *mappings;
	struct _sr_file_mappings *srfmp;
	unsigned int            current_file_index = 0;

	vm_shared_region_lock();
	assert(shared_region->sr_ref_count > 1);

	/*
	 * Make sure we handle only one mapping at a time in a given
	 * shared region, to avoid race conditions.  This should not
	 * happen frequently...
	 */
	while (shared_region->sr_mapping_in_progress) {
		/* wait for our turn... */
		vm_shared_region_sleep(&shared_region->sr_mapping_in_progress,
		    THREAD_UNINT);
	}
	assert(!shared_region->sr_mapping_in_progress);
	assert(shared_region->sr_ref_count > 1);
	/* let others know we're working in this shared region */
	shared_region->sr_mapping_in_progress = TRUE;

	vm_shared_region_unlock();

	/* no need to lock because this data is never modified... */
	sr_handle = shared_region->sr_mem_entry;
	sr_mem_entry = (vm_named_entry_t) ip_get_kobject(sr_handle);
	sr_map = sr_mem_entry->backing.map;
	sr_base_address = shared_region->sr_base_address;

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: -> map(%p)\n",
		(void *)VM_KERNEL_ADDRPERM(shared_region)));

	mappings_count = 0;
	mappings = NULL;
	srfmp = NULL;

	/* process all the files to be mapped */
	for (srfmp = &sr_file_mappings[0];
	    srfmp < &sr_file_mappings[sr_file_mappings_count];
	    srfmp++) {
		mappings_count = srfmp->mappings_count;
		mappings = srfmp->mappings;
		file_control = srfmp->file_control;

		if (mappings_count == 0) {
			/* no mappings here... */
			continue;
		}

		/*
		 * The code below can only correctly "slide" (perform relocations) for one
		 * value of the slide amount. So if a file has a non-zero slide, it has to
		 * match any previous value. A zero slide value is ok for things that are
		 * just directly mapped.
		 */
		if (shared_region->sr_slide == 0 && srfmp->slide != 0) {
			shared_region->sr_slide = srfmp->slide;
		} else if (shared_region->sr_slide != 0 &&
		    srfmp->slide != 0 &&
		    shared_region->sr_slide != srfmp->slide) {
			SHARED_REGION_TRACE_ERROR(
				("shared_region: more than 1 non-zero slide value amount "
				"slide 1:0x%x slide 2:0x%x\n ",
				shared_region->sr_slide, srfmp->slide));
			kr = KERN_INVALID_ARGUMENT;
			break;
		}

#if __arm64__
		if ((shared_region->sr_64bit ||
		    page_shift_user32 == SIXTEENK_PAGE_SHIFT) &&
		    ((srfmp->slide & SIXTEENK_PAGE_MASK) != 0)) {
			printf("FOURK_COMPAT: %s: rejecting mis-aligned slide 0x%x\n",
			    __FUNCTION__, srfmp->slide);
			kr = KERN_INVALID_ARGUMENT;
			break;
		}
#endif /* __arm64__ */

		/* get the VM object associated with the file to be mapped */
		file_object = memory_object_control_to_vm_object(file_control);
		assert(file_object);

		/* establish the mappings for that file */
		for (i = 0; i < mappings_count; i++) {
			SHARED_REGION_TRACE_INFO(
				("shared_region: mapping[%d]: "
				"address:0x%016llx size:0x%016llx offset:0x%016llx "
				"maxprot:0x%x prot:0x%x\n",
				i,
				(long long)mappings[i].sms_address,
				(long long)mappings[i].sms_size,
				(long long)mappings[i].sms_file_offset,
				mappings[i].sms_max_prot,
				mappings[i].sms_init_prot));

			if (mappings[i].sms_address < *sfm_min_address) {
				*sfm_min_address = mappings[i].sms_address;
			}

			if (os_add_overflow(mappings[i].sms_address,
			    mappings[i].sms_size,
			    &sfm_end) ||
			    (vm_map_round_page(sfm_end, VM_MAP_PAGE_MASK(sr_map)) <
			    mappings[i].sms_address)) {
				/* overflow */
				kr = KERN_INVALID_ARGUMENT;
				break;
			}
			if (sfm_end > *sfm_max_address) {
				*sfm_max_address = sfm_end;
			}

			if (mappings[i].sms_init_prot & VM_PROT_ZF) {
				/* zero-filled memory */
				map_port = MACH_PORT_NULL;
			} else {
				/* file-backed memory */
				__IGNORE_WCASTALIGN(map_port = (ipc_port_t) file_object->pager);
			}

			/*
			 * Remember which mappings need sliding.
			 */
			if (mappings[i].sms_max_prot & VM_PROT_SLIDE) {
				if (*mappings_to_slide_cnt == VMSR_NUM_SLIDES) {
					SHARED_REGION_TRACE_INFO(
						("shared_region: mapping[%d]: "
						"address:0x%016llx size:0x%016llx "
						"offset:0x%016llx "
						"maxprot:0x%x prot:0x%x "
						"too many mappings to slide...\n",
						i,
						(long long)mappings[i].sms_address,
						(long long)mappings[i].sms_size,
						(long long)mappings[i].sms_file_offset,
						mappings[i].sms_max_prot,
						mappings[i].sms_init_prot));
				} else {
					mappings_to_slide[*mappings_to_slide_cnt] = &mappings[i];
					*mappings_to_slide_cnt += 1;
				}
			}

			/* mapping's address is relative to the shared region base */
			target_address = (vm_map_offset_t)(mappings[i].sms_address - sr_base_address);

			vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;
			vmk_flags.vmkf_already = TRUE;
			/* no copy-on-read for mapped binaries */
			vmk_flags.vmkf_no_copy_on_read = 1;


			/* establish that mapping, OK if it's "already" there */
			if (map_port == MACH_PORT_NULL) {
				/*
				 * We want to map some anonymous memory in a shared region.
				 * We have to create the VM object now, so that it can be mapped "copy-on-write".
				 */
				obj_size = vm_map_round_page(mappings[i].sms_size, VM_MAP_PAGE_MASK(sr_map));
				object = vm_object_allocate(obj_size);
				if (object == VM_OBJECT_NULL) {
					kr = KERN_RESOURCE_SHORTAGE;
				} else {
					kr = vm_map_enter(
						sr_map,
						&target_address,
						vm_map_round_page(mappings[i].sms_size,
						VM_MAP_PAGE_MASK(sr_map)),
						0,
						VM_FLAGS_FIXED,
						vmk_flags,
						VM_KERN_MEMORY_NONE,
						object,
						0,
						TRUE,
						mappings[i].sms_init_prot & VM_PROT_ALL,
						mappings[i].sms_max_prot & VM_PROT_ALL,
						VM_INHERIT_DEFAULT);
				}
			} else {
				object = VM_OBJECT_NULL; /* no anonymous memory here */
				kr = vm_map_enter_mem_object(
					sr_map,
					&target_address,
					vm_map_round_page(mappings[i].sms_size,
					VM_MAP_PAGE_MASK(sr_map)),
					0,
					VM_FLAGS_FIXED,
					vmk_flags,
					VM_KERN_MEMORY_NONE,
					map_port,
					mappings[i].sms_file_offset,
					TRUE,
					mappings[i].sms_init_prot & VM_PROT_ALL,
					mappings[i].sms_max_prot & VM_PROT_ALL,
					VM_INHERIT_DEFAULT);
			}

			if (kr == KERN_SUCCESS) {
				/*
				 * Record the first (chronologically) successful
				 * mapping in this shared region.
				 * We're protected by "sr_mapping_in_progress" here,
				 * so no need to lock "shared_region".
				 */
				assert(current_file_index < VMSR_NUM_SLIDES);
				if (file_first_mappings[current_file_index] == (mach_vm_offset_t) -1) {
					file_first_mappings[current_file_index] = target_address;
				}

				if (*mappings_to_slide_cnt > 0 &&
				    mappings_to_slide[*mappings_to_slide_cnt - 1] == &mappings[i]) {
					slid_mappings[*mappings_to_slide_cnt - 1] = target_address;
					slid_file_controls[*mappings_to_slide_cnt - 1] = file_control;
				}

				/*
				 * Record the lowest writable address in this
				 * sub map, to log any unexpected unnesting below
				 * that address (see log_unnest_badness()).
				 */
				if ((mappings[i].sms_init_prot & VM_PROT_WRITE) &&
				    sr_map->is_nested_map &&
				    (lowest_unnestable_addr == 0 ||
				    (target_address < lowest_unnestable_addr))) {
					lowest_unnestable_addr = target_address;
				}
			} else {
				if (map_port == MACH_PORT_NULL) {
					/*
					 * Get rid of the VM object we just created
					 * but failed to map.
					 */
					vm_object_deallocate(object);
					object = VM_OBJECT_NULL;
				}
				if (kr == KERN_MEMORY_PRESENT) {
					/*
					 * This exact mapping was already there:
					 * that's fine.
					 */
					SHARED_REGION_TRACE_INFO(
						("shared_region: mapping[%d]: "
						"address:0x%016llx size:0x%016llx "
						"offset:0x%016llx "
						"maxprot:0x%x prot:0x%x "
						"already mapped...\n",
						i,
						(long long)mappings[i].sms_address,
						(long long)mappings[i].sms_size,
						(long long)mappings[i].sms_file_offset,
						mappings[i].sms_max_prot,
						mappings[i].sms_init_prot));
					/*
					 * We didn't establish this mapping ourselves;
					 * let's reset its size, so that we do not
					 * attempt to undo it if an error occurs later.
					 */
					mappings[i].sms_size = 0;
					kr = KERN_SUCCESS;
				} else {
					break;
				}
			}
		}

		if (kr != KERN_SUCCESS) {
			break;
		}

		++current_file_index;
	}

	if (file_first_mappings[0] != (mach_vm_offset_t)-1) {
		*first_mapping = file_first_mappings[0];
	}


	if (kr != KERN_SUCCESS) {
		/* the last mapping we tried (mappings[i]) failed ! */
		assert(i < mappings_count);
		SHARED_REGION_TRACE_ERROR(
			("shared_region: mapping[%d]: "
			"address:0x%016llx size:0x%016llx "
			"offset:0x%016llx "
			"maxprot:0x%x prot:0x%x failed 0x%x\n",
			i,
			(long long)mappings[i].sms_address,
			(long long)mappings[i].sms_size,
			(long long)mappings[i].sms_file_offset,
			mappings[i].sms_max_prot,
			mappings[i].sms_init_prot,
			kr));

		/*
		 * Respect the design of vm_shared_region_undo_mappings
		 * as we are holding the sr_mapping_in_progress == true here.
		 * So don't allow sr_map == NULL otherwise vm_shared_region_undo_mappings
		 * will be blocked at waiting sr_mapping_in_progress to be false.
		 */
		assert(sr_map != NULL);
		/* undo all the previous mappings */
		vm_shared_region_undo_mappings(sr_map, sr_base_address, sr_file_mappings, srfmp, i);
		return kr;
	}

	*lowest_unnestable_addr_ptr = lowest_unnestable_addr;
	*sr_map_ptr = sr_map;
	return KERN_SUCCESS;
}

/* forwared declaration */
__attribute__((noinline))
static void
vm_shared_region_map_file_final(
	vm_shared_region_t shared_region,
	vm_map_t           sr_map,
	mach_vm_offset_t   sfm_min_address,
	mach_vm_offset_t   sfm_max_address,
	mach_vm_offset_t   *file_first_mappings);

/*
 * Establish some mappings of a file in the shared region.
 * This is used by "dyld" via the shared_region_map_np() system call
 * to populate the shared region with the appropriate shared cache.
 *
 * One could also call it several times to incrementally load several
 * libraries, as long as they do not overlap.
 * It will return KERN_SUCCESS if the mappings were successfully established
 * or if they were already established identically by another process.
 */
__attribute__((noinline))
kern_return_t
vm_shared_region_map_file(
	vm_shared_region_t       shared_region,
	int                      sr_file_mappings_count,
	struct _sr_file_mappings *sr_file_mappings)
{
	kern_return_t           kr = KERN_SUCCESS;
	unsigned int            i;
	unsigned int            mappings_to_slide_cnt = 0;
	struct shared_file_mapping_slide_np *mappings_to_slide[VMSR_NUM_SLIDES] = {};
	mach_vm_offset_t        slid_mappings[VMSR_NUM_SLIDES];
	memory_object_control_t slid_file_controls[VMSR_NUM_SLIDES];
	mach_vm_offset_t        first_mapping = (mach_vm_offset_t)-1;
	mach_vm_offset_t        sfm_min_address = (mach_vm_offset_t)-1;
	mach_vm_offset_t        sfm_max_address = 0;
	vm_map_t                sr_map = NULL;
	vm_map_offset_t         lowest_unnestable_addr = 0;
	mach_vm_offset_t        file_first_mappings[VMSR_NUM_SLIDES] = {(mach_vm_offset_t) -1, (mach_vm_offset_t) -1};

	kr = vm_shared_region_map_file_setup(shared_region, sr_file_mappings_count, sr_file_mappings,
	    &mappings_to_slide_cnt, &mappings_to_slide[0], slid_mappings, slid_file_controls,
	    &first_mapping, &file_first_mappings[0],
	    &sfm_min_address, &sfm_max_address, &sr_map, &lowest_unnestable_addr);
	if (kr != KERN_SUCCESS) {
		vm_shared_region_lock();
		goto done;
	}

	/*
	 * The call above installed direct mappings to the shared cache file.
	 * Now we go back and overwrite the mappings that need relocation
	 * with a special shared region pager.
	 */
	for (i = 0; i < mappings_to_slide_cnt; ++i) {
		kr = vm_shared_region_slide(shared_region->sr_slide,
		    mappings_to_slide[i]->sms_file_offset,
		    mappings_to_slide[i]->sms_size,
		    mappings_to_slide[i]->sms_slide_start,
		    mappings_to_slide[i]->sms_slide_size,
		    slid_mappings[i],
		    slid_file_controls[i],
		    mappings_to_slide[i]->sms_max_prot);
		if (kr != KERN_SUCCESS) {
			SHARED_REGION_TRACE_ERROR(
				("shared_region: region_slide("
				"slide:0x%x start:0x%016llx "
				"size:0x%016llx) failed 0x%x\n",
				shared_region->sr_slide,
				(long long)mappings_to_slide[i]->sms_slide_start,
				(long long)mappings_to_slide[i]->sms_slide_size,
				kr));
			vm_shared_region_lock();
			goto done;
		}
	}

	assert(kr == KERN_SUCCESS);

	/* adjust the map's "lowest_unnestable_start" */
	lowest_unnestable_addr &= ~(pmap_shared_region_size_min(sr_map->pmap) - 1);
	if (lowest_unnestable_addr != sr_map->lowest_unnestable_start) {
		vm_map_lock(sr_map);
		sr_map->lowest_unnestable_start = lowest_unnestable_addr;
		vm_map_unlock(sr_map);
	}

	vm_shared_region_lock();
	assert(shared_region->sr_ref_count > 1);
	assert(shared_region->sr_mapping_in_progress);

	/* set "sr_first_mapping"; dyld uses it to validate the shared cache */
	if (shared_region->sr_first_mapping == (mach_vm_offset_t) -1) {
		shared_region->sr_first_mapping = first_mapping;
	}

	vm_shared_region_map_file_final(shared_region, sr_map, sfm_min_address, sfm_max_address,
	    &file_first_mappings[0]);

done:
	/*
	 * We're done working on that shared region.
	 * Wake up any waiting threads.
	 */
	shared_region->sr_mapping_in_progress = FALSE;
	thread_wakeup((event_t) &shared_region->sr_mapping_in_progress);
	vm_shared_region_unlock();

#if __has_feature(ptrauth_calls)
	if (kr == KERN_SUCCESS) {
		/*
		 * Since authenticated mappings were just added to the shared region,
		 * go back and remap them into private mappings for this task.
		 */
		kr = vm_shared_region_auth_remap(shared_region);
	}
#endif /* __has_feature(ptrauth_calls) */

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: map(%p) <- 0x%x \n",
		(void *)VM_KERNEL_ADDRPERM(shared_region), kr));
	return kr;
}

/*
 * Final part of vm_shared_region_map_file().
 * Kept in separate function to avoid blowing out the stack.
 */
__attribute__((noinline))
static void
vm_shared_region_map_file_final(
	vm_shared_region_t        shared_region,
	vm_map_t                  sr_map,
	mach_vm_offset_t          sfm_min_address,
	mach_vm_offset_t          sfm_max_address,
	__unused mach_vm_offset_t *file_first_mappings)
{
	struct _dyld_cache_header sr_cache_header;
	int                       error;
	size_t                    image_array_length;
	struct _dyld_cache_image_text_info *sr_image_layout;


	/*
	 * copy in the shared region UUID to the shared region structure.
	 * we do this indirectly by first copying in the shared cache header
	 * and then copying the UUID from there because we'll need to look
	 * at other content from the shared cache header.
	 */
	if (!shared_region->sr_uuid_copied) {
		error = copyin((user_addr_t)(shared_region->sr_base_address + shared_region->sr_first_mapping),
		    (char *)&sr_cache_header,
		    sizeof(sr_cache_header));
		if (error == 0) {
			memcpy(&shared_region->sr_uuid, &sr_cache_header.uuid, sizeof(shared_region->sr_uuid));
			shared_region->sr_uuid_copied = TRUE;
		} else {
#if DEVELOPMENT || DEBUG
			panic("shared_region: copyin shared_cache_header(sr_base_addr:0x%016llx sr_first_mapping:0x%016llx "
			    "offset:0 size:0x%016llx) failed with %d\n",
			    (long long)shared_region->sr_base_address,
			    (long long)shared_region->sr_first_mapping,
			    (long long)sizeof(sr_cache_header),
			    error);
#endif /* DEVELOPMENT || DEBUG */
			shared_region->sr_uuid_copied = FALSE;
		}
	}

	/*
	 * If the shared cache is associated with the init task (and is therefore the system shared cache),
	 * check whether it is a custom built shared cache and copy in the shared cache layout accordingly.
	 */
	boolean_t is_init_task = (task_pid(current_task()) == 1);
	if (shared_region->sr_uuid_copied && is_init_task) {
		/* Copy in the shared cache layout if we're running with a locally built shared cache */
		if (sr_cache_header.locallyBuiltCache) {
			KDBG((MACHDBG_CODE(DBG_MACH_SHAREDREGION, PROCESS_SHARED_CACHE_LAYOUT)) | DBG_FUNC_START);
			image_array_length = (size_t)(sr_cache_header.imagesTextCount * sizeof(struct _dyld_cache_image_text_info));
			sr_image_layout = kheap_alloc(KHEAP_DATA_BUFFERS, image_array_length, Z_WAITOK);
			error = copyin((user_addr_t)(shared_region->sr_base_address + shared_region->sr_first_mapping +
			    sr_cache_header.imagesTextOffset), (char *)sr_image_layout, image_array_length);
			if (error == 0) {
				shared_region->sr_images = kalloc((vm_size_t)(sr_cache_header.imagesTextCount * sizeof(struct dyld_uuid_info_64)));
				for (size_t index = 0; index < sr_cache_header.imagesTextCount; index++) {
					memcpy((char *)&shared_region->sr_images[index].imageUUID, (char *)&sr_image_layout[index].uuid,
					    sizeof(shared_region->sr_images[index].imageUUID));
					shared_region->sr_images[index].imageLoadAddress = sr_image_layout[index].loadAddress;
				}

				assert(sr_cache_header.imagesTextCount < UINT32_MAX);
				shared_region->sr_images_count = (uint32_t) sr_cache_header.imagesTextCount;
			} else {
#if DEVELOPMENT || DEBUG
				panic("shared_region: copyin shared_cache_layout(sr_base_addr:0x%016llx sr_first_mapping:0x%016llx "
				    "offset:0x%016llx size:0x%016llx) failed with %d\n",
				    (long long)shared_region->sr_base_address,
				    (long long)shared_region->sr_first_mapping,
				    (long long)sr_cache_header.imagesTextOffset,
				    (long long)image_array_length,
				    error);
#endif /* DEVELOPMENT || DEBUG */
			}
			KDBG((MACHDBG_CODE(DBG_MACH_SHAREDREGION, PROCESS_SHARED_CACHE_LAYOUT)) | DBG_FUNC_END, shared_region->sr_images_count);
			kheap_free(KHEAP_DATA_BUFFERS, sr_image_layout, image_array_length);
			sr_image_layout = NULL;
		}
		init_task_shared_region = shared_region;
	}

	/*
	 * If we succeeded, we know the bounds of the shared region.
	 * Trim our pmaps to only cover this range (if applicable to
	 * this platform).
	 */
	if (VM_MAP_PAGE_SHIFT(current_map()) == VM_MAP_PAGE_SHIFT(sr_map)) {
		pmap_trim(current_map()->pmap, sr_map->pmap, sfm_min_address, sfm_max_address - sfm_min_address);
	}
}

/*
 * Retrieve a task's shared region and grab an extra reference to
 * make sure it doesn't disappear while the caller is using it.
 * The caller is responsible for consuming that extra reference if
 * necessary.
 *
 * This also tries to trim the pmap for the shared region.
 */
vm_shared_region_t
vm_shared_region_trim_and_get(task_t task)
{
	vm_shared_region_t shared_region;
	ipc_port_t sr_handle;
	vm_named_entry_t sr_mem_entry;
	vm_map_t sr_map;

	/* Get the shared region and the map. */
	shared_region = vm_shared_region_get(task);
	if (shared_region == NULL) {
		return NULL;
	}

	sr_handle = shared_region->sr_mem_entry;
	sr_mem_entry = (vm_named_entry_t) ip_get_kobject(sr_handle);
	sr_map = sr_mem_entry->backing.map;

	/* Trim the pmap if possible. */
	if (VM_MAP_PAGE_SHIFT(task->map) == VM_MAP_PAGE_SHIFT(sr_map)) {
		pmap_trim(task->map->pmap, sr_map->pmap, 0, 0);
	}

	return shared_region;
}

/*
 * Enter the appropriate shared region into "map" for "task".
 * This involves looking up the shared region (and possibly creating a new
 * one) for the desired environment, then mapping the VM sub map into the
 * task's VM "map", with the appropriate level of pmap-nesting.
 */
kern_return_t
vm_shared_region_enter(
	struct _vm_map          *map,
	struct task             *task,
	boolean_t               is_64bit,
	void                    *fsroot,
	cpu_type_t              cpu,
	cpu_subtype_t           cpu_subtype,
	boolean_t               reslide)
{
	kern_return_t           kr;
	vm_shared_region_t      shared_region;
	vm_map_offset_t         sr_address, sr_offset, target_address;
	vm_map_size_t           sr_size, mapping_size;
	vm_map_offset_t         sr_pmap_nesting_start;
	vm_map_size_t           sr_pmap_nesting_size;
	ipc_port_t              sr_handle;
	vm_prot_t               cur_prot, max_prot;

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: -> "
		"enter(map=%p,task=%p,root=%p,cpu=<%d,%d>,64bit=%d)\n",
		(void *)VM_KERNEL_ADDRPERM(map),
		(void *)VM_KERNEL_ADDRPERM(task),
		(void *)VM_KERNEL_ADDRPERM(fsroot),
		cpu, cpu_subtype, is_64bit));

	/* lookup (create if needed) the shared region for this environment */
	shared_region = vm_shared_region_lookup(fsroot, cpu, cpu_subtype, is_64bit, reslide);
	if (shared_region == NULL) {
		/* this should not happen ! */
		SHARED_REGION_TRACE_ERROR(
			("shared_region: -> "
			"enter(map=%p,task=%p,root=%p,cpu=<%d,%d>,64bit=%d,reslide=%d): "
			"lookup failed !\n",
			(void *)VM_KERNEL_ADDRPERM(map),
			(void *)VM_KERNEL_ADDRPERM(task),
			(void *)VM_KERNEL_ADDRPERM(fsroot),
			cpu, cpu_subtype, is_64bit, reslide));
		//panic("shared_region_enter: lookup failed\n");
		return KERN_FAILURE;
	}

	kr = KERN_SUCCESS;
	/* no need to lock since this data is never modified */
	sr_address = (vm_map_offset_t)shared_region->sr_base_address;
	sr_size = (vm_map_size_t)shared_region->sr_size;
	sr_handle = shared_region->sr_mem_entry;
	sr_pmap_nesting_start = (vm_map_offset_t)shared_region->sr_pmap_nesting_start;
	sr_pmap_nesting_size = (vm_map_size_t)shared_region->sr_pmap_nesting_size;

	cur_prot = VM_PROT_READ;
	if (VM_MAP_POLICY_WRITABLE_SHARED_REGION(map)) {
		/*
		 * XXX BINARY COMPATIBILITY
		 * java6 apparently needs to modify some code in the
		 * dyld shared cache and needs to be allowed to add
		 * write access...
		 */
		max_prot = VM_PROT_ALL;
	} else {
		max_prot = VM_PROT_READ;
	}

	/*
	 * Start mapping the shared region's VM sub map into the task's VM map.
	 */
	sr_offset = 0;

	if (sr_pmap_nesting_start > sr_address) {
		/* we need to map a range without pmap-nesting first */
		target_address = sr_address;
		mapping_size = sr_pmap_nesting_start - sr_address;
		kr = vm_map_enter_mem_object(
			map,
			&target_address,
			mapping_size,
			0,
			VM_FLAGS_FIXED,
			VM_MAP_KERNEL_FLAGS_NONE,
			VM_KERN_MEMORY_NONE,
			sr_handle,
			sr_offset,
			TRUE,
			cur_prot,
			max_prot,
			VM_INHERIT_SHARE);
		if (kr != KERN_SUCCESS) {
			SHARED_REGION_TRACE_ERROR(
				("shared_region: enter(%p,%p,%p,%d,%d,%d): "
				"vm_map_enter(0x%llx,0x%llx,%p) error 0x%x\n",
				(void *)VM_KERNEL_ADDRPERM(map),
				(void *)VM_KERNEL_ADDRPERM(task),
				(void *)VM_KERNEL_ADDRPERM(fsroot),
				cpu, cpu_subtype, is_64bit,
				(long long)target_address,
				(long long)mapping_size,
				(void *)VM_KERNEL_ADDRPERM(sr_handle), kr));
			goto done;
		}
		SHARED_REGION_TRACE_DEBUG(
			("shared_region: enter(%p,%p,%p,%d,%d,%d): "
			"vm_map_enter(0x%llx,0x%llx,%p) error 0x%x\n",
			(void *)VM_KERNEL_ADDRPERM(map),
			(void *)VM_KERNEL_ADDRPERM(task),
			(void *)VM_KERNEL_ADDRPERM(fsroot),
			cpu, cpu_subtype, is_64bit,
			(long long)target_address, (long long)mapping_size,
			(void *)VM_KERNEL_ADDRPERM(sr_handle), kr));
		sr_offset += mapping_size;
		sr_size -= mapping_size;
	}
	/*
	 * We may need to map several pmap-nested portions, due to platform
	 * specific restrictions on pmap nesting.
	 * The pmap-nesting is triggered by the "vmkf_nested_pmap" flag...
	 */
	for (;
	    sr_pmap_nesting_size > 0;
	    sr_offset += mapping_size,
	    sr_size -= mapping_size,
	    sr_pmap_nesting_size -= mapping_size) {
		vm_map_kernel_flags_t vmk_flags;

		target_address = sr_address + sr_offset;
		mapping_size = sr_pmap_nesting_size;
		if (mapping_size > pmap_nesting_size_max(map->pmap)) {
			mapping_size = (vm_map_offset_t) pmap_nesting_size_max(map->pmap);
		}
		vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;
		vmk_flags.vmkf_nested_pmap = TRUE;
		kr = vm_map_enter_mem_object(
			map,
			&target_address,
			mapping_size,
			0,
			VM_FLAGS_FIXED,
			vmk_flags,
			VM_MEMORY_SHARED_PMAP,
			sr_handle,
			sr_offset,
			TRUE,
			cur_prot,
			max_prot,
			VM_INHERIT_SHARE);
		if (kr != KERN_SUCCESS) {
			SHARED_REGION_TRACE_ERROR(
				("shared_region: enter(%p,%p,%p,%d,%d,%d): "
				"vm_map_enter(0x%llx,0x%llx,%p) error 0x%x\n",
				(void *)VM_KERNEL_ADDRPERM(map),
				(void *)VM_KERNEL_ADDRPERM(task),
				(void *)VM_KERNEL_ADDRPERM(fsroot),
				cpu, cpu_subtype, is_64bit,
				(long long)target_address,
				(long long)mapping_size,
				(void *)VM_KERNEL_ADDRPERM(sr_handle), kr));
			goto done;
		}
		SHARED_REGION_TRACE_DEBUG(
			("shared_region: enter(%p,%p,%p,%d,%d,%d): "
			"nested vm_map_enter(0x%llx,0x%llx,%p) error 0x%x\n",
			(void *)VM_KERNEL_ADDRPERM(map),
			(void *)VM_KERNEL_ADDRPERM(task),
			(void *)VM_KERNEL_ADDRPERM(fsroot),
			cpu, cpu_subtype, is_64bit,
			(long long)target_address, (long long)mapping_size,
			(void *)VM_KERNEL_ADDRPERM(sr_handle), kr));
	}
	if (sr_size > 0) {
		/* and there's some left to be mapped without pmap-nesting */
		target_address = sr_address + sr_offset;
		mapping_size = sr_size;
		kr = vm_map_enter_mem_object(
			map,
			&target_address,
			mapping_size,
			0,
			VM_FLAGS_FIXED,
			VM_MAP_KERNEL_FLAGS_NONE,
			VM_KERN_MEMORY_NONE,
			sr_handle,
			sr_offset,
			TRUE,
			cur_prot,
			max_prot,
			VM_INHERIT_SHARE);
		if (kr != KERN_SUCCESS) {
			SHARED_REGION_TRACE_ERROR(
				("shared_region: enter(%p,%p,%p,%d,%d,%d): "
				"vm_map_enter(0x%llx,0x%llx,%p) error 0x%x\n",
				(void *)VM_KERNEL_ADDRPERM(map),
				(void *)VM_KERNEL_ADDRPERM(task),
				(void *)VM_KERNEL_ADDRPERM(fsroot),
				cpu, cpu_subtype, is_64bit,
				(long long)target_address,
				(long long)mapping_size,
				(void *)VM_KERNEL_ADDRPERM(sr_handle), kr));
			goto done;
		}
		SHARED_REGION_TRACE_DEBUG(
			("shared_region: enter(%p,%p,%p,%d,%d,%d): "
			"vm_map_enter(0x%llx,0x%llx,%p) error 0x%x\n",
			(void *)VM_KERNEL_ADDRPERM(map),
			(void *)VM_KERNEL_ADDRPERM(task),
			(void *)VM_KERNEL_ADDRPERM(fsroot),
			cpu, cpu_subtype, is_64bit,
			(long long)target_address, (long long)mapping_size,
			(void *)VM_KERNEL_ADDRPERM(sr_handle), kr));
		sr_offset += mapping_size;
		sr_size -= mapping_size;
	}
	assert(sr_size == 0);

done:
	if (kr == KERN_SUCCESS) {
		/* let the task use that shared region */
		vm_shared_region_set(task, shared_region);
	} else {
		/* drop our reference since we're not using it */
		vm_shared_region_deallocate(shared_region);
		vm_shared_region_set(task, NULL);
	}

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: enter(%p,%p,%p,%d,%d,%d) <- 0x%x\n",
		(void *)VM_KERNEL_ADDRPERM(map),
		(void *)VM_KERNEL_ADDRPERM(task),
		(void *)VM_KERNEL_ADDRPERM(fsroot),
		cpu, cpu_subtype, is_64bit,
		kr));
	return kr;
}

#define SANE_SLIDE_INFO_SIZE            (2560*1024) /*Can be changed if needed*/
struct vm_shared_region_slide_info      slide_info;

kern_return_t
vm_shared_region_sliding_valid(uint32_t slide)
{
	kern_return_t kr = KERN_SUCCESS;
	vm_shared_region_t sr = vm_shared_region_get(current_task());

	/* No region yet? we're fine. */
	if (sr == NULL) {
		return kr;
	}

	if (sr->sr_slide != 0 && slide != 0) {
		if (slide == sr->sr_slide) {
			/*
			 * Request for sliding when we've
			 * already done it with exactly the
			 * same slide value before.
			 * This isn't wrong technically but
			 * we don't want to slide again and
			 * so we return this value.
			 */
			kr = KERN_INVALID_ARGUMENT;
		} else {
			printf("Mismatched shared region slide\n");
			kr = KERN_FAILURE;
		}
	}
	vm_shared_region_deallocate(sr);
	return kr;
}

/*
 * Actually create (really overwrite) the mapping to part of the shared cache which
 * undergoes relocation.  This routine reads in the relocation info from dyld and
 * verifies it. It then creates a (or finds a matching) shared region pager which
 * handles the actual modification of the page contents and installs the mapping
 * using that pager.
 */
kern_return_t
vm_shared_region_slide_mapping(
	vm_shared_region_t      sr,
	user_addr_t             slide_info_addr,
	mach_vm_size_t          slide_info_size,
	mach_vm_offset_t        start,
	mach_vm_size_t          size,
	mach_vm_offset_t        slid_mapping,
	uint32_t                slide,
	memory_object_control_t sr_file_control,
	vm_prot_t               prot)
{
	kern_return_t           kr;
	vm_object_t             object = VM_OBJECT_NULL;
	vm_shared_region_slide_info_t si = NULL;
	vm_map_entry_t          tmp_entry = VM_MAP_ENTRY_NULL;
	struct vm_map_entry     tmp_entry_store;
	memory_object_t         sr_pager = MEMORY_OBJECT_NULL;
	vm_map_t                sr_map;
	int                     vm_flags;
	vm_map_kernel_flags_t   vmk_flags;
	vm_map_offset_t         map_addr;
	void                    *slide_info_entry = NULL;
	int                     error;

	assert(sr->sr_slide_in_progress);

	if (sr_file_control == MEMORY_OBJECT_CONTROL_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 * Copy in and verify the relocation information.
	 */
	if (slide_info_size < MIN_SLIDE_INFO_SIZE) {
		printf("Slide_info_size too small: %lx\n", (uintptr_t)slide_info_size);
		return KERN_FAILURE;
	}
	if (slide_info_size > SANE_SLIDE_INFO_SIZE) {
		printf("Slide_info_size too large: %lx\n", (uintptr_t)slide_info_size);
		return KERN_FAILURE;
	}

	slide_info_entry = kheap_alloc(KHEAP_DATA_BUFFERS, (vm_size_t)slide_info_size, Z_WAITOK);
	if (slide_info_entry == NULL) {
		return KERN_RESOURCE_SHORTAGE;
	}
	error = copyin(slide_info_addr, slide_info_entry, (size_t)slide_info_size);
	if (error) {
		printf("copyin of slide_info failed\n");
		kr = KERN_INVALID_ADDRESS;
		goto done;
	}

	if ((kr = vm_shared_region_slide_sanity_check(slide_info_entry, slide_info_size)) != KERN_SUCCESS) {
		printf("Sanity Check failed for slide_info\n");
		goto done;
	}

	/*
	 * Allocate and fill in a vm_shared_region_slide_info.
	 * This will either be used by a new pager, or used to find
	 * a pre-existing matching pager.
	 */
	object = memory_object_control_to_vm_object(sr_file_control);
	if (object == VM_OBJECT_NULL || object->internal) {
		object = VM_OBJECT_NULL;
		kr = KERN_INVALID_ADDRESS;
		goto done;
	}

	si = kalloc(sizeof(*si));
	if (si == NULL) {
		kr = KERN_RESOURCE_SHORTAGE;
		goto done;
	}
	vm_object_lock(object);

	vm_object_reference_locked(object);     /* for si->slide_object */
	object->object_is_shared_cache = TRUE;
	vm_object_unlock(object);

	si->si_slide_info_entry = slide_info_entry;
	si->si_slide_info_size = slide_info_size;

	assert(slid_mapping != (mach_vm_offset_t) -1);
	si->si_slid_address = slid_mapping + sr->sr_base_address;
	si->si_slide_object = object;
	si->si_start = start;
	si->si_end = si->si_start + size;
	si->si_slide = slide;
#if __has_feature(ptrauth_calls)
	/*
	 * If there is authenticated pointer data in this slid mapping,
	 * then just add the information needed to create new pagers for
	 * different shared_region_id's later.
	 */
	if (sr->sr_cpu_type == CPU_TYPE_ARM64 &&
	    sr->sr_cpu_subtype == CPU_SUBTYPE_ARM64E &&
	    !(prot & VM_PROT_NOAUTH)) {
		if (sr->sr_num_auth_section == NUM_SR_AUTH_SECTIONS) {
			printf("Too many auth/private sections for shared region!!\n");
			kr = KERN_INVALID_ARGUMENT;
			goto done;
		}
		si->si_ptrauth = TRUE;
		sr->sr_auth_section[sr->sr_num_auth_section++] = si;
		/*
		 * Remember the shared region, since that's where we'll
		 * stash this info for all auth pagers to share. Each pager
		 * will need to take a reference to it.
		 */
		si->si_shared_region = sr;
		kr = KERN_SUCCESS;
		goto done;
	}
	si->si_shared_region = NULL;
	si->si_ptrauth = FALSE;
#else /* __has_feature(ptrauth_calls) */
	(void)prot;     /* silence unused warning */
#endif /* __has_feature(ptrauth_calls) */

	/*
	 * find the pre-existing shared region's map entry to slide
	 */
	sr_map = vm_shared_region_vm_map(sr);
	kr = find_mapping_to_slide(sr_map, (vm_map_address_t)slid_mapping, &tmp_entry_store);
	if (kr != KERN_SUCCESS) {
		goto done;
	}
	tmp_entry = &tmp_entry_store;

	/*
	 * The object must exactly cover the region to slide.
	 */
	assert(VME_OFFSET(tmp_entry) == start);
	assert(tmp_entry->vme_end - tmp_entry->vme_start == size);

	/* create a "shared_region" sliding pager */
	sr_pager = shared_region_pager_setup(VME_OBJECT(tmp_entry), VME_OFFSET(tmp_entry), si, 0);
	if (sr_pager == MEMORY_OBJECT_NULL) {
		kr = KERN_RESOURCE_SHORTAGE;
		goto done;
	}

	/* map that pager over the portion of the mapping that needs sliding */
	vm_flags = VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE;
	vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;
	vmk_flags.vmkf_overwrite_immutable = TRUE;
	map_addr = tmp_entry->vme_start;
	kr = vm_map_enter_mem_object(sr_map,
	    &map_addr,
	    (tmp_entry->vme_end - tmp_entry->vme_start),
	    (mach_vm_offset_t) 0,
	    vm_flags,
	    vmk_flags,
	    VM_KERN_MEMORY_NONE,
	    (ipc_port_t)(uintptr_t) sr_pager,
	    0,
	    TRUE,
	    tmp_entry->protection,
	    tmp_entry->max_protection,
	    tmp_entry->inheritance);
	assertf(kr == KERN_SUCCESS, "kr = 0x%x\n", kr);
	assertf(map_addr == tmp_entry->vme_start,
	    "map_addr=0x%llx vme_start=0x%llx tmp_entry=%p\n",
	    (uint64_t)map_addr,
	    (uint64_t) tmp_entry->vme_start,
	    tmp_entry);

	/* success! */
	kr = KERN_SUCCESS;

done:
	if (sr_pager != NULL) {
		/*
		 * Release the sr_pager reference obtained by shared_region_pager_setup().
		 * The mapping, if it succeeded, is now holding a reference on the memory object.
		 */
		memory_object_deallocate(sr_pager);
		sr_pager = MEMORY_OBJECT_NULL;
	}
	if (tmp_entry != NULL) {
		/* release extra ref on tmp_entry's VM object */
		vm_object_deallocate(VME_OBJECT(tmp_entry));
		tmp_entry = VM_MAP_ENTRY_NULL;
	}

	if (kr != KERN_SUCCESS) {
		/* cleanup */
		if (si != NULL) {
			if (si->si_slide_object) {
				vm_object_deallocate(si->si_slide_object);
				si->si_slide_object = VM_OBJECT_NULL;
			}
			kfree(si, sizeof(*si));
			si = NULL;
		}
		if (slide_info_entry != NULL) {
			kheap_free(KHEAP_DATA_BUFFERS, slide_info_entry, (vm_size_t)slide_info_size);
			slide_info_entry = NULL;
		}
	}
	return kr;
}

static kern_return_t
vm_shared_region_slide_sanity_check_v2(
	vm_shared_region_slide_info_entry_v2_t s_info,
	mach_vm_size_t slide_info_size)
{
	if (slide_info_size < sizeof(struct vm_shared_region_slide_info_entry_v2)) {
		printf("%s bad slide_info_size: %lx\n", __func__, (uintptr_t)slide_info_size);
		return KERN_FAILURE;
	}
	if (s_info->page_size != PAGE_SIZE_FOR_SR_SLIDE) {
		return KERN_FAILURE;
	}

	/* Ensure that the slide info doesn't reference any data outside of its bounds. */

	uint32_t page_starts_count = s_info->page_starts_count;
	uint32_t page_extras_count = s_info->page_extras_count;
	mach_vm_size_t num_trailing_entries = page_starts_count + page_extras_count;
	if (num_trailing_entries < page_starts_count) {
		return KERN_FAILURE;
	}

	/* Scale by sizeof(uint16_t). Hard-coding the size simplifies the overflow check. */
	mach_vm_size_t trailing_size = num_trailing_entries << 1;
	if (trailing_size >> 1 != num_trailing_entries) {
		return KERN_FAILURE;
	}

	mach_vm_size_t required_size = sizeof(*s_info) + trailing_size;
	if (required_size < sizeof(*s_info)) {
		return KERN_FAILURE;
	}

	if (required_size > slide_info_size) {
		return KERN_FAILURE;
	}

	return KERN_SUCCESS;
}

static kern_return_t
vm_shared_region_slide_sanity_check_v3(
	vm_shared_region_slide_info_entry_v3_t s_info,
	mach_vm_size_t slide_info_size)
{
	if (slide_info_size < sizeof(struct vm_shared_region_slide_info_entry_v3)) {
		printf("%s bad slide_info_size: %lx\n", __func__, (uintptr_t)slide_info_size);
		return KERN_FAILURE;
	}
	if (s_info->page_size != PAGE_SIZE_FOR_SR_SLIDE) {
		printf("vm_shared_region_slide_sanity_check_v3: s_info->page_size != PAGE_SIZE_FOR_SR_SL 0x%llx != 0x%llx\n", (uint64_t)s_info->page_size, (uint64_t)PAGE_SIZE_FOR_SR_SLIDE);
		return KERN_FAILURE;
	}

	uint32_t page_starts_count = s_info->page_starts_count;
	mach_vm_size_t num_trailing_entries = page_starts_count;
	mach_vm_size_t trailing_size = num_trailing_entries << 1;
	mach_vm_size_t required_size = sizeof(*s_info) + trailing_size;
	if (required_size < sizeof(*s_info)) {
		printf("vm_shared_region_slide_sanity_check_v3: required_size != sizeof(*s_info) 0x%llx != 0x%llx\n", (uint64_t)required_size, (uint64_t)sizeof(*s_info));
		return KERN_FAILURE;
	}

	if (required_size > slide_info_size) {
		printf("vm_shared_region_slide_sanity_check_v3: required_size != slide_info_size 0x%llx != 0x%llx\n", (uint64_t)required_size, (uint64_t)slide_info_size);
		return KERN_FAILURE;
	}

	return KERN_SUCCESS;
}

static kern_return_t
vm_shared_region_slide_sanity_check_v4(
	vm_shared_region_slide_info_entry_v4_t s_info,
	mach_vm_size_t slide_info_size)
{
	if (slide_info_size < sizeof(struct vm_shared_region_slide_info_entry_v4)) {
		printf("%s bad slide_info_size: %lx\n", __func__, (uintptr_t)slide_info_size);
		return KERN_FAILURE;
	}
	if (s_info->page_size != PAGE_SIZE_FOR_SR_SLIDE) {
		return KERN_FAILURE;
	}

	/* Ensure that the slide info doesn't reference any data outside of its bounds. */

	uint32_t page_starts_count = s_info->page_starts_count;
	uint32_t page_extras_count = s_info->page_extras_count;
	mach_vm_size_t num_trailing_entries = page_starts_count + page_extras_count;
	if (num_trailing_entries < page_starts_count) {
		return KERN_FAILURE;
	}

	/* Scale by sizeof(uint16_t). Hard-coding the size simplifies the overflow check. */
	mach_vm_size_t trailing_size = num_trailing_entries << 1;
	if (trailing_size >> 1 != num_trailing_entries) {
		return KERN_FAILURE;
	}

	mach_vm_size_t required_size = sizeof(*s_info) + trailing_size;
	if (required_size < sizeof(*s_info)) {
		return KERN_FAILURE;
	}

	if (required_size > slide_info_size) {
		return KERN_FAILURE;
	}

	return KERN_SUCCESS;
}


static kern_return_t
vm_shared_region_slide_sanity_check(
	vm_shared_region_slide_info_entry_t s_info,
	mach_vm_size_t s_info_size)
{
	kern_return_t kr;

	switch (s_info->version) {
	case 2:
		kr = vm_shared_region_slide_sanity_check_v2(&s_info->v2, s_info_size);
		break;
	case 3:
		kr = vm_shared_region_slide_sanity_check_v3(&s_info->v3, s_info_size);
		break;
	case 4:
		kr = vm_shared_region_slide_sanity_check_v4(&s_info->v4, s_info_size);
		break;
	default:
		kr = KERN_FAILURE;
	}
	return kr;
}

static kern_return_t
rebase_chain_32(
	uint8_t *page_content,
	uint16_t start_offset,
	uint32_t slide_amount,
	vm_shared_region_slide_info_entry_v2_t s_info)
{
	const uint32_t last_page_offset = PAGE_SIZE_FOR_SR_SLIDE - sizeof(uint32_t);

	const uint32_t delta_mask = (uint32_t)(s_info->delta_mask);
	const uint32_t value_mask = ~delta_mask;
	const uint32_t value_add = (uint32_t)(s_info->value_add);
	const uint32_t delta_shift = __builtin_ctzll(delta_mask) - 2;

	uint32_t page_offset = start_offset;
	uint32_t delta = 1;

	while (delta != 0 && page_offset <= last_page_offset) {
		uint8_t *loc;
		uint32_t value;

		loc = page_content + page_offset;
		memcpy(&value, loc, sizeof(value));
		delta = (value & delta_mask) >> delta_shift;
		value &= value_mask;

		if (value != 0) {
			value += value_add;
			value += slide_amount;
		}
		memcpy(loc, &value, sizeof(value));
		page_offset += delta;
	}

	/* If the offset went past the end of the page, then the slide data is invalid. */
	if (page_offset > last_page_offset) {
		return KERN_FAILURE;
	}
	return KERN_SUCCESS;
}

static kern_return_t
rebase_chain_64(
	uint8_t *page_content,
	uint16_t start_offset,
	uint32_t slide_amount,
	vm_shared_region_slide_info_entry_v2_t s_info)
{
	const uint32_t last_page_offset = PAGE_SIZE_FOR_SR_SLIDE - sizeof(uint64_t);

	const uint64_t delta_mask = s_info->delta_mask;
	const uint64_t value_mask = ~delta_mask;
	const uint64_t value_add = s_info->value_add;
	const uint64_t delta_shift = __builtin_ctzll(delta_mask) - 2;

	uint32_t page_offset = start_offset;
	uint32_t delta = 1;

	while (delta != 0 && page_offset <= last_page_offset) {
		uint8_t *loc;
		uint64_t value;

		loc = page_content + page_offset;
		memcpy(&value, loc, sizeof(value));
		delta = (uint32_t)((value & delta_mask) >> delta_shift);
		value &= value_mask;

		if (value != 0) {
			value += value_add;
			value += slide_amount;
		}
		memcpy(loc, &value, sizeof(value));
		page_offset += delta;
	}

	if (page_offset + sizeof(uint32_t) == PAGE_SIZE_FOR_SR_SLIDE) {
		/* If a pointer straddling the page boundary needs to be adjusted, then
		 * add the slide to the lower half. The encoding guarantees that the upper
		 * half on the next page will need no masking.
		 *
		 * This assumes a little-endian machine and that the region being slid
		 * never crosses a 4 GB boundary. */

		uint8_t *loc = page_content + page_offset;
		uint32_t value;

		memcpy(&value, loc, sizeof(value));
		value += slide_amount;
		memcpy(loc, &value, sizeof(value));
	} else if (page_offset > last_page_offset) {
		return KERN_FAILURE;
	}

	return KERN_SUCCESS;
}

static kern_return_t
rebase_chain(
	boolean_t is_64,
	uint32_t pageIndex,
	uint8_t *page_content,
	uint16_t start_offset,
	uint32_t slide_amount,
	vm_shared_region_slide_info_entry_v2_t s_info)
{
	kern_return_t kr;
	if (is_64) {
		kr = rebase_chain_64(page_content, start_offset, slide_amount, s_info);
	} else {
		kr = rebase_chain_32(page_content, start_offset, slide_amount, s_info);
	}

	if (kr != KERN_SUCCESS) {
		printf("vm_shared_region_slide_page() offset overflow: pageIndex=%u, start_offset=%u, slide_amount=%u\n",
		    pageIndex, start_offset, slide_amount);
	}
	return kr;
}

static kern_return_t
vm_shared_region_slide_page_v2(vm_shared_region_slide_info_t si, vm_offset_t vaddr, uint32_t pageIndex)
{
	vm_shared_region_slide_info_entry_v2_t s_info = &si->si_slide_info_entry->v2;
	const uint32_t slide_amount = si->si_slide;

	/* The high bits of the delta_mask field are nonzero precisely when the shared
	 * cache is 64-bit. */
	const boolean_t is_64 = (s_info->delta_mask >> 32) != 0;

	const uint16_t *page_starts = (uint16_t *)((uintptr_t)s_info + s_info->page_starts_offset);
	const uint16_t *page_extras = (uint16_t *)((uintptr_t)s_info + s_info->page_extras_offset);

	uint8_t *page_content = (uint8_t *)vaddr;
	uint16_t page_entry;

	if (pageIndex >= s_info->page_starts_count) {
		printf("vm_shared_region_slide_page() did not find page start in slide info: pageIndex=%u, count=%u\n",
		    pageIndex, s_info->page_starts_count);
		return KERN_FAILURE;
	}
	page_entry = page_starts[pageIndex];

	if (page_entry == DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE) {
		return KERN_SUCCESS;
	}

	if (page_entry & DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA) {
		uint16_t chain_index = page_entry & DYLD_CACHE_SLIDE_PAGE_VALUE;
		uint16_t info;

		do {
			uint16_t page_start_offset;
			kern_return_t kr;

			if (chain_index >= s_info->page_extras_count) {
				printf("vm_shared_region_slide_page() out-of-bounds extras index: index=%u, count=%u\n",
				    chain_index, s_info->page_extras_count);
				return KERN_FAILURE;
			}
			info = page_extras[chain_index];
			page_start_offset = (uint16_t)((info & DYLD_CACHE_SLIDE_PAGE_VALUE) << DYLD_CACHE_SLIDE_PAGE_OFFSET_SHIFT);

			kr = rebase_chain(is_64, pageIndex, page_content, page_start_offset, slide_amount, s_info);
			if (kr != KERN_SUCCESS) {
				return KERN_FAILURE;
			}

			chain_index++;
		} while (!(info & DYLD_CACHE_SLIDE_PAGE_ATTR_END));
	} else {
		const uint16_t page_start_offset = (uint16_t)(page_entry << DYLD_CACHE_SLIDE_PAGE_OFFSET_SHIFT);
		kern_return_t kr;

		kr = rebase_chain(is_64, pageIndex, page_content, page_start_offset, slide_amount, s_info);
		if (kr != KERN_SUCCESS) {
			return KERN_FAILURE;
		}
	}

	return KERN_SUCCESS;
}


static kern_return_t
vm_shared_region_slide_page_v3(
	vm_shared_region_slide_info_t si,
	vm_offset_t vaddr,
	__unused mach_vm_offset_t uservaddr,
	uint32_t pageIndex,
#if !__has_feature(ptrauth_calls)
	__unused
#endif /* !__has_feature(ptrauth_calls) */
	uint64_t jop_key)
{
	vm_shared_region_slide_info_entry_v3_t s_info = &si->si_slide_info_entry->v3;
	const uint32_t slide_amount = si->si_slide;

	uint8_t *page_content = (uint8_t *)vaddr;
	uint16_t page_entry;

	if (pageIndex >= s_info->page_starts_count) {
		printf("vm_shared_region_slide_page() did not find page start in slide info: pageIndex=%u, count=%u\n",
		    pageIndex, s_info->page_starts_count);
		return KERN_FAILURE;
	}
	page_entry = s_info->page_starts[pageIndex];

	if (page_entry == DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE) {
		return KERN_SUCCESS;
	}

	uint8_t* rebaseLocation = page_content;
	uint64_t delta = page_entry;
	do {
		rebaseLocation += delta;
		uint64_t value;
		memcpy(&value, rebaseLocation, sizeof(value));
		delta = ((value & 0x3FF8000000000000) >> 51) * sizeof(uint64_t);

		// A pointer is one of :
		// {
		//	 uint64_t pointerValue : 51;
		//	 uint64_t offsetToNextPointer : 11;
		//	 uint64_t isBind : 1 = 0;
		//	 uint64_t authenticated : 1 = 0;
		// }
		// {
		//	 uint32_t offsetFromSharedCacheBase;
		//	 uint16_t diversityData;
		//	 uint16_t hasAddressDiversity : 1;
		//	 uint16_t hasDKey : 1;
		//	 uint16_t hasBKey : 1;
		//	 uint16_t offsetToNextPointer : 11;
		//	 uint16_t isBind : 1;
		//	 uint16_t authenticated : 1 = 1;
		// }

		bool isBind = (value & (1ULL << 62)) == 1;
		if (isBind) {
			return KERN_FAILURE;
		}

#if __has_feature(ptrauth_calls)
		uint16_t diversity_data = (uint16_t)(value >> 32);
		bool hasAddressDiversity = (value & (1ULL << 48)) != 0;
		ptrauth_key key = (ptrauth_key)((value >> 49) & 0x3);
#endif /* __has_feature(ptrauth_calls) */
		bool isAuthenticated = (value & (1ULL << 63)) != 0;

		if (isAuthenticated) {
			// The new value for a rebase is the low 32-bits of the threaded value plus the slide.
			value = (value & 0xFFFFFFFF) + slide_amount;
			// Add in the offset from the mach_header
			const uint64_t value_add = s_info->value_add;
			value += value_add;

#if __has_feature(ptrauth_calls)
			uint64_t discriminator = diversity_data;
			if (hasAddressDiversity) {
				// First calculate a new discriminator using the address of where we are trying to store the value
				uintptr_t pageOffset = rebaseLocation - page_content;
				discriminator = __builtin_ptrauth_blend_discriminator((void*)(((uintptr_t)uservaddr) + pageOffset), discriminator);
			}

			if (jop_key != 0 && si->si_ptrauth && !arm_user_jop_disabled()) {
				/*
				 * these pointers are used in user mode. disable the kernel key diversification
				 * so we can sign them for use in user mode.
				 */
				value = (uintptr_t)pmap_sign_user_ptr((void *)value, key, discriminator, jop_key);
			}
#endif /* __has_feature(ptrauth_calls) */
		} else {
			// The new value for a rebase is the low 51-bits of the threaded value plus the slide.
			// Regular pointer which needs to fit in 51-bits of value.
			// C++ RTTI uses the top bit, so we'll allow the whole top-byte
			// and the bottom 43-bits to be fit in to 51-bits.
			uint64_t top8Bits = value & 0x0007F80000000000ULL;
			uint64_t bottom43Bits = value & 0x000007FFFFFFFFFFULL;
			uint64_t targetValue = (top8Bits << 13) | bottom43Bits;
			value = targetValue + slide_amount;
		}

		memcpy(rebaseLocation, &value, sizeof(value));
	} while (delta != 0);

	return KERN_SUCCESS;
}

static kern_return_t
rebase_chainv4(
	uint8_t *page_content,
	uint16_t start_offset,
	uint32_t slide_amount,
	vm_shared_region_slide_info_entry_v4_t s_info)
{
	const uint32_t last_page_offset = PAGE_SIZE_FOR_SR_SLIDE - sizeof(uint32_t);

	const uint32_t delta_mask = (uint32_t)(s_info->delta_mask);
	const uint32_t value_mask = ~delta_mask;
	const uint32_t value_add = (uint32_t)(s_info->value_add);
	const uint32_t delta_shift = __builtin_ctzll(delta_mask) - 2;

	uint32_t page_offset = start_offset;
	uint32_t delta = 1;

	while (delta != 0 && page_offset <= last_page_offset) {
		uint8_t *loc;
		uint32_t value;

		loc = page_content + page_offset;
		memcpy(&value, loc, sizeof(value));
		delta = (value & delta_mask) >> delta_shift;
		value &= value_mask;

		if ((value & 0xFFFF8000) == 0) {
			// small positive non-pointer, use as-is
		} else if ((value & 0x3FFF8000) == 0x3FFF8000) {
			// small negative non-pointer
			value |= 0xC0000000;
		} else {
			// pointer that needs rebasing
			value += value_add;
			value += slide_amount;
		}
		memcpy(loc, &value, sizeof(value));
		page_offset += delta;
	}

	/* If the offset went past the end of the page, then the slide data is invalid. */
	if (page_offset > last_page_offset) {
		return KERN_FAILURE;
	}
	return KERN_SUCCESS;
}

static kern_return_t
vm_shared_region_slide_page_v4(vm_shared_region_slide_info_t si, vm_offset_t vaddr, uint32_t pageIndex)
{
	vm_shared_region_slide_info_entry_v4_t s_info = &si->si_slide_info_entry->v4;
	const uint32_t slide_amount = si->si_slide;

	const uint16_t *page_starts = (uint16_t *)((uintptr_t)s_info + s_info->page_starts_offset);
	const uint16_t *page_extras = (uint16_t *)((uintptr_t)s_info + s_info->page_extras_offset);

	uint8_t *page_content = (uint8_t *)vaddr;
	uint16_t page_entry;

	if (pageIndex >= s_info->page_starts_count) {
		printf("vm_shared_region_slide_page() did not find page start in slide info: pageIndex=%u, count=%u\n",
		    pageIndex, s_info->page_starts_count);
		return KERN_FAILURE;
	}
	page_entry = page_starts[pageIndex];

	if (page_entry == DYLD_CACHE_SLIDE4_PAGE_NO_REBASE) {
		return KERN_SUCCESS;
	}

	if (page_entry & DYLD_CACHE_SLIDE4_PAGE_USE_EXTRA) {
		uint16_t chain_index = page_entry & DYLD_CACHE_SLIDE4_PAGE_INDEX;
		uint16_t info;

		do {
			uint16_t page_start_offset;
			kern_return_t kr;

			if (chain_index >= s_info->page_extras_count) {
				printf("vm_shared_region_slide_page() out-of-bounds extras index: index=%u, count=%u\n",
				    chain_index, s_info->page_extras_count);
				return KERN_FAILURE;
			}
			info = page_extras[chain_index];
			page_start_offset = (uint16_t)((info & DYLD_CACHE_SLIDE4_PAGE_INDEX) << DYLD_CACHE_SLIDE_PAGE_OFFSET_SHIFT);

			kr = rebase_chainv4(page_content, page_start_offset, slide_amount, s_info);
			if (kr != KERN_SUCCESS) {
				return KERN_FAILURE;
			}

			chain_index++;
		} while (!(info & DYLD_CACHE_SLIDE4_PAGE_EXTRA_END));
	} else {
		const uint16_t page_start_offset = (uint16_t)(page_entry << DYLD_CACHE_SLIDE_PAGE_OFFSET_SHIFT);
		kern_return_t kr;

		kr = rebase_chainv4(page_content, page_start_offset, slide_amount, s_info);
		if (kr != KERN_SUCCESS) {
			return KERN_FAILURE;
		}
	}

	return KERN_SUCCESS;
}



kern_return_t
vm_shared_region_slide_page(
	vm_shared_region_slide_info_t si,
	vm_offset_t vaddr,
	mach_vm_offset_t uservaddr,
	uint32_t pageIndex,
	uint64_t jop_key)
{
	switch (si->si_slide_info_entry->version) {
	case 2:
		return vm_shared_region_slide_page_v2(si, vaddr, pageIndex);
	case 3:
		return vm_shared_region_slide_page_v3(si, vaddr, uservaddr, pageIndex, jop_key);
	case 4:
		return vm_shared_region_slide_page_v4(si, vaddr, pageIndex);
	default:
		return KERN_FAILURE;
	}
}

/******************************************************************************/
/* Comm page support                                                          */
/******************************************************************************/

ipc_port_t commpage32_handle = IPC_PORT_NULL;
ipc_port_t commpage64_handle = IPC_PORT_NULL;
vm_named_entry_t commpage32_entry = NULL;
vm_named_entry_t commpage64_entry = NULL;
vm_map_t commpage32_map = VM_MAP_NULL;
vm_map_t commpage64_map = VM_MAP_NULL;

ipc_port_t commpage_text32_handle = IPC_PORT_NULL;
ipc_port_t commpage_text64_handle = IPC_PORT_NULL;
vm_named_entry_t commpage_text32_entry = NULL;
vm_named_entry_t commpage_text64_entry = NULL;
vm_map_t commpage_text32_map = VM_MAP_NULL;
vm_map_t commpage_text64_map = VM_MAP_NULL;

user32_addr_t commpage_text32_location = 0;
user64_addr_t commpage_text64_location = 0;

#if defined(__i386__) || defined(__x86_64__)
/*
 * Create a memory entry, VM submap and pmap for one commpage.
 */
static void
_vm_commpage_init(
	ipc_port_t      *handlep,
	vm_map_size_t   size)
{
	kern_return_t           kr;
	vm_named_entry_t        mem_entry;
	vm_map_t                new_map;

	SHARED_REGION_TRACE_DEBUG(
		("commpage: -> _init(0x%llx)\n",
		(long long)size));

	kr = mach_memory_entry_allocate(&mem_entry,
	    handlep);
	if (kr != KERN_SUCCESS) {
		panic("_vm_commpage_init: could not allocate mem_entry");
	}
	new_map = vm_map_create(pmap_create_options(NULL, 0, 0), 0, size, PMAP_CREATE_64BIT);
	if (new_map == VM_MAP_NULL) {
		panic("_vm_commpage_init: could not allocate VM map");
	}
	mem_entry->backing.map = new_map;
	mem_entry->internal = TRUE;
	mem_entry->is_sub_map = TRUE;
	mem_entry->offset = 0;
	mem_entry->protection = VM_PROT_ALL;
	mem_entry->size = size;

	SHARED_REGION_TRACE_DEBUG(
		("commpage: _init(0x%llx) <- %p\n",
		(long long)size, (void *)VM_KERNEL_ADDRPERM(*handlep)));
}
#endif


/*
 * Initialize the comm text pages at boot time
 */
void
vm_commpage_text_init(void)
{
	SHARED_REGION_TRACE_DEBUG(
		("commpage text: ->init()\n"));
#if defined(__i386__) || defined(__x86_64__)
	/* create the 32 bit comm text page */
	unsigned int offset = (random() % _PFZ32_SLIDE_RANGE) << PAGE_SHIFT; /* restricting to 32bMAX-2PAGE */
	_vm_commpage_init(&commpage_text32_handle, _COMM_PAGE_TEXT_AREA_LENGTH);
	commpage_text32_entry = (vm_named_entry_t) ip_get_kobject(commpage_text32_handle);
	commpage_text32_map = commpage_text32_entry->backing.map;
	commpage_text32_location = (user32_addr_t) (_COMM_PAGE32_TEXT_START + offset);
	/* XXX if (cpu_is_64bit_capable()) ? */
	/* create the 64-bit comm page */
	offset = (random() % _PFZ64_SLIDE_RANGE) << PAGE_SHIFT; /* restricting sliding upto 2Mb range */
	_vm_commpage_init(&commpage_text64_handle, _COMM_PAGE_TEXT_AREA_LENGTH);
	commpage_text64_entry = (vm_named_entry_t) ip_get_kobject(commpage_text64_handle);
	commpage_text64_map = commpage_text64_entry->backing.map;
	commpage_text64_location = (user64_addr_t) (_COMM_PAGE64_TEXT_START + offset);
#endif

	commpage_text_populate();

	/* populate the routines in here */
	SHARED_REGION_TRACE_DEBUG(
		("commpage text: init() <-\n"));
}

/*
 * Initialize the comm pages at boot time.
 */
void
vm_commpage_init(void)
{
	SHARED_REGION_TRACE_DEBUG(
		("commpage: -> init()\n"));

#if defined(__i386__) || defined(__x86_64__)
	/* create the 32-bit comm page */
	_vm_commpage_init(&commpage32_handle, _COMM_PAGE32_AREA_LENGTH);
	commpage32_entry = (vm_named_entry_t) ip_get_kobject(commpage32_handle);
	commpage32_map = commpage32_entry->backing.map;

	/* XXX if (cpu_is_64bit_capable()) ? */
	/* create the 64-bit comm page */
	_vm_commpage_init(&commpage64_handle, _COMM_PAGE64_AREA_LENGTH);
	commpage64_entry = (vm_named_entry_t) ip_get_kobject(commpage64_handle);
	commpage64_map = commpage64_entry->backing.map;

#endif /* __i386__ || __x86_64__ */

	/* populate them according to this specific platform */
	commpage_populate();
	__commpage_setup = 1;
#if !CONFIG_EMBEDDED
	if (__system_power_source == 0) {
		post_sys_powersource_internal(0, 1);
	}
#endif

	SHARED_REGION_TRACE_DEBUG(
		("commpage: init() <-\n"));
}

/*
 * Enter the appropriate comm page into the task's address space.
 * This is called at exec() time via vm_map_exec().
 */
kern_return_t
vm_commpage_enter(
	vm_map_t        map,
	task_t          task,
	boolean_t       is64bit)
{
#if     defined(__arm__)
#pragma unused(is64bit)
	(void)task;
	(void)map;
	return KERN_SUCCESS;
#elif   defined(__arm64__)
#pragma unused(is64bit)
	(void)task;
	(void)map;
	pmap_insert_sharedpage(vm_map_pmap(map));
	return KERN_SUCCESS;
#else
	ipc_port_t              commpage_handle, commpage_text_handle;
	vm_map_offset_t         commpage_address, objc_address, commpage_text_address;
	vm_map_size_t           commpage_size, objc_size, commpage_text_size;
	int                     vm_flags;
	vm_map_kernel_flags_t   vmk_flags;
	kern_return_t           kr;

	SHARED_REGION_TRACE_DEBUG(
		("commpage: -> enter(%p,%p)\n",
		(void *)VM_KERNEL_ADDRPERM(map),
		(void *)VM_KERNEL_ADDRPERM(task)));

	commpage_text_size = _COMM_PAGE_TEXT_AREA_LENGTH;
	/* the comm page is likely to be beyond the actual end of the VM map */
	vm_flags = VM_FLAGS_FIXED;
	vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;
	vmk_flags.vmkf_beyond_max = TRUE;

	/* select the appropriate comm page for this task */
	assert(!(is64bit ^ vm_map_is_64bit(map)));
	if (is64bit) {
		commpage_handle = commpage64_handle;
		commpage_address = (vm_map_offset_t) _COMM_PAGE64_BASE_ADDRESS;
		commpage_size = _COMM_PAGE64_AREA_LENGTH;
		objc_size = _COMM_PAGE64_OBJC_SIZE;
		objc_address = _COMM_PAGE64_OBJC_BASE;
		commpage_text_handle = commpage_text64_handle;
		commpage_text_address = (vm_map_offset_t) commpage_text64_location;
	} else {
		commpage_handle = commpage32_handle;
		commpage_address =
		    (vm_map_offset_t)(unsigned) _COMM_PAGE32_BASE_ADDRESS;
		commpage_size = _COMM_PAGE32_AREA_LENGTH;
		objc_size = _COMM_PAGE32_OBJC_SIZE;
		objc_address = _COMM_PAGE32_OBJC_BASE;
		commpage_text_handle = commpage_text32_handle;
		commpage_text_address = (vm_map_offset_t) commpage_text32_location;
	}

	vm_tag_t tag = VM_KERN_MEMORY_NONE;
	if ((commpage_address & (pmap_commpage_size_min(map->pmap) - 1)) == 0 &&
	    (commpage_size & (pmap_commpage_size_min(map->pmap) - 1)) == 0) {
		/* the commpage is properly aligned or sized for pmap-nesting */
		tag = VM_MEMORY_SHARED_PMAP;
		vmk_flags.vmkf_nested_pmap = TRUE;
	}
	/* map the comm page in the task's address space */
	assert(commpage_handle != IPC_PORT_NULL);
	kr = vm_map_enter_mem_object(
		map,
		&commpage_address,
		commpage_size,
		0,
		vm_flags,
		vmk_flags,
		tag,
		commpage_handle,
		0,
		FALSE,
		VM_PROT_READ,
		VM_PROT_READ,
		VM_INHERIT_SHARE);
	if (kr != KERN_SUCCESS) {
		SHARED_REGION_TRACE_ERROR(
			("commpage: enter(%p,0x%llx,0x%llx) "
			"commpage %p mapping failed 0x%x\n",
			(void *)VM_KERNEL_ADDRPERM(map),
			(long long)commpage_address,
			(long long)commpage_size,
			(void *)VM_KERNEL_ADDRPERM(commpage_handle), kr));
	}

	/* map the comm text page in the task's address space */
	assert(commpage_text_handle != IPC_PORT_NULL);
	kr = vm_map_enter_mem_object(
		map,
		&commpage_text_address,
		commpage_text_size,
		0,
		vm_flags,
		vmk_flags,
		tag,
		commpage_text_handle,
		0,
		FALSE,
		VM_PROT_READ | VM_PROT_EXECUTE,
		VM_PROT_READ | VM_PROT_EXECUTE,
		VM_INHERIT_SHARE);
	if (kr != KERN_SUCCESS) {
		SHARED_REGION_TRACE_ERROR(
			("commpage text: enter(%p,0x%llx,0x%llx) "
			"commpage text %p mapping failed 0x%x\n",
			(void *)VM_KERNEL_ADDRPERM(map),
			(long long)commpage_text_address,
			(long long)commpage_text_size,
			(void *)VM_KERNEL_ADDRPERM(commpage_text_handle), kr));
	}

	/*
	 * Since we're here, we also pre-allocate some virtual space for the
	 * Objective-C run-time, if needed...
	 */
	if (objc_size != 0) {
		kr = vm_map_enter_mem_object(
			map,
			&objc_address,
			objc_size,
			0,
			VM_FLAGS_FIXED,
			vmk_flags,
			tag,
			IPC_PORT_NULL,
			0,
			FALSE,
			VM_PROT_ALL,
			VM_PROT_ALL,
			VM_INHERIT_DEFAULT);
		if (kr != KERN_SUCCESS) {
			SHARED_REGION_TRACE_ERROR(
				("commpage: enter(%p,0x%llx,0x%llx) "
				"objc mapping failed 0x%x\n",
				(void *)VM_KERNEL_ADDRPERM(map),
				(long long)objc_address,
				(long long)objc_size, kr));
		}
	}

	SHARED_REGION_TRACE_DEBUG(
		("commpage: enter(%p,%p) <- 0x%x\n",
		(void *)VM_KERNEL_ADDRPERM(map),
		(void *)VM_KERNEL_ADDRPERM(task), kr));
	return kr;
#endif
}

int
vm_shared_region_slide(
	uint32_t slide,
	mach_vm_offset_t        entry_start_address,
	mach_vm_size_t          entry_size,
	mach_vm_offset_t        slide_start,
	mach_vm_size_t          slide_size,
	mach_vm_offset_t        slid_mapping,
	memory_object_control_t sr_file_control,
	vm_prot_t               prot)
{
	vm_shared_region_t      sr;
	kern_return_t           error;

	SHARED_REGION_TRACE_DEBUG(
		("vm_shared_region_slide: -> slide %#x, entry_start %#llx, entry_size %#llx, slide_start %#llx, slide_size %#llx\n",
		slide, entry_start_address, entry_size, slide_start, slide_size));

	sr = vm_shared_region_get(current_task());
	if (sr == NULL) {
		printf("%s: no shared region?\n", __FUNCTION__);
		SHARED_REGION_TRACE_DEBUG(
			("vm_shared_region_slide: <- %d (no shared region)\n",
			KERN_FAILURE));
		return KERN_FAILURE;
	}

	/*
	 * Protect from concurrent access.
	 */
	vm_shared_region_lock();
	while (sr->sr_slide_in_progress) {
		vm_shared_region_sleep(&sr->sr_slide_in_progress, THREAD_UNINT);
	}

	sr->sr_slide_in_progress = TRUE;
	vm_shared_region_unlock();

	error = vm_shared_region_slide_mapping(sr,
	    (user_addr_t)slide_start,
	    slide_size,
	    entry_start_address,
	    entry_size,
	    slid_mapping,
	    slide,
	    sr_file_control,
	    prot);
	if (error) {
		printf("slide_info initialization failed with kr=%d\n", error);
	}

	vm_shared_region_lock();

	assert(sr->sr_slide_in_progress);
	sr->sr_slide_in_progress = FALSE;
	thread_wakeup(&sr->sr_slide_in_progress);

#ifndef CONFIG_EMBEDDED
	if (error == KERN_SUCCESS) {
		shared_region_completed_slide = TRUE;
	}
#endif
	vm_shared_region_unlock();

	vm_shared_region_deallocate(sr);

	SHARED_REGION_TRACE_DEBUG(
		("vm_shared_region_slide: <- %d\n",
		error));

	return error;
}

/*
 * Used during Authenticated Root Volume macOS boot.
 * Launchd re-execs itself and wants the new launchd to use
 * the shared cache from the new root volume. This call
 * makes all the existing shared caches stale to allow
 * that to happen.
 */
void
vm_shared_region_pivot(void)
{
	vm_shared_region_t      shared_region = NULL;

	vm_shared_region_lock();

	queue_iterate(&vm_shared_region_queue, shared_region, vm_shared_region_t, sr_q) {
		assert(shared_region->sr_ref_count > 0);
		shared_region->sr_stale = TRUE;
		if (shared_region->sr_timer_call) {
			/*
			 * We have a shared region ready to be destroyed
			 * and just waiting for a delayed timer to fire.
			 * Marking it stale cements its ineligibility to
			 * be used ever again. So let's shorten the timer
			 * aggressively down to 10 milliseconds and get rid of it.
			 * This is a single quantum and we don't need to go
			 * shorter than this duration. We want it to be short
			 * enough, however, because we could have an unmount
			 * of the volume hosting this shared region just behind
			 * us.
			 */
			uint64_t deadline;
			assert(shared_region->sr_ref_count == 1);

			/*
			 * Free the old timer call. Returns with a reference held.
			 * If the old timer has fired and is waiting for the vm_shared_region_lock
			 * lock, we will just return with an additional ref_count i.e. 2.
			 * The old timer will then fire and just drop the ref count down to 1
			 * with no other modifications.
			 */
			vm_shared_region_reference_locked(shared_region);

			/* set up the timer. Keep the reference from above for this timer.*/
			shared_region->sr_timer_call = thread_call_allocate(
				(thread_call_func_t) vm_shared_region_timeout,
				(thread_call_param_t) shared_region);

			/* schedule the timer */
			clock_interval_to_deadline(10, /* 10 milliseconds */
			    NSEC_PER_MSEC,
			    &deadline);
			thread_call_enter_delayed(shared_region->sr_timer_call,
			    deadline);

			SHARED_REGION_TRACE_DEBUG(
				("shared_region: pivot(%p): armed timer\n",
				(void *)VM_KERNEL_ADDRPERM(shared_region)));
		}
	}

	vm_shared_region_unlock();
}

/*
 * Routine to mark any non-standard slide shared cache region as stale.
 * This causes the next "reslide" spawn to create a new shared region.
 */
void
vm_shared_region_reslide_stale(void)
{
#if __has_feature(ptrauth_calls)
	vm_shared_region_t      shared_region = NULL;

	vm_shared_region_lock();

	queue_iterate(&vm_shared_region_queue, shared_region, vm_shared_region_t, sr_q) {
		assert(shared_region->sr_ref_count > 0);
		if (!shared_region->sr_stale && shared_region->sr_reslide) {
			shared_region->sr_stale = TRUE;
			vm_shared_region_reslide_count++;
		}
	}

	vm_shared_region_unlock();
#endif /* __has_feature(ptrauth_calls) */
}

/*
 * report if the task is using a reslide shared cache region.
 */
bool
vm_shared_region_is_reslide(__unused struct task *task)
{
	bool is_reslide = FALSE;
#if !XNU_TARGET_OS_OSX && __has_feature(ptrauth_calls)
	vm_shared_region_t sr = vm_shared_region_get(task);

	if (sr != NULL) {
		is_reslide = sr->sr_reslide;
		vm_shared_region_deallocate(sr);
	}
#endif /* !XNU_TARGET_OS_OSX && __has_feature(ptrauth_calls) */
	return is_reslide;
}

/*
 * This is called from powermanagement code to let kernel know the current source of power.
 * 0 if it is external source (connected to power )
 * 1 if it is internal power source ie battery
 */
void
#if !CONFIG_EMBEDDED
post_sys_powersource(int i)
#else
post_sys_powersource(__unused int i)
#endif
{
#if !CONFIG_EMBEDDED
	post_sys_powersource_internal(i, 0);
#endif
}


#if !CONFIG_EMBEDDED
static void
post_sys_powersource_internal(int i, int internal)
{
	if (internal == 0) {
		__system_power_source = i;
	}
}
#endif

void *
vm_shared_region_root_dir(
	struct vm_shared_region *sr)
{
	void *vnode;

	vm_shared_region_lock();
	vnode = sr->sr_root_dir;
	vm_shared_region_unlock();
	return vnode;
}
