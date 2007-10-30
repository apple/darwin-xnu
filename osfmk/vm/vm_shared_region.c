/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
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
 * libraries for a given environment.
 * An environment is defined by (cpu-type, 64-bitness, root directory).
 *
 * The point of a shared region is to reduce the setup overhead when exec'ing
 * a new process.
 * A shared region uses a shared VM submap that gets mapped automatically
 * at exec() time (see vm_map_exec()).  The first process of a given
 * environment sets up the shared region and all further processes in that
 * environment can re-use that shared region without having to re-create
 * the same mappings in their VM map.  All they need is contained in the shared
 * region.
 * It can also shared a pmap (mostly for read-only parts but also for the
 * initial version of some writable parts), which gets "nested" into the 
 * process's pmap.  This reduces the number of soft faults:  once one process
 * brings in a page in the shared region, all the other processes can access
 * it without having to enter it in their own pmap.
 *
 *
 * When a process is being exec'ed, vm_map_exec() calls vm_shared_region_enter()
 * to map the appropriate shared region in the process's address space.
 * We look up the appropriate shared region for the process's environment.
 * If we can't find one, we create a new (empty) one and add it to the list.
 * Otherwise, we just take an extra reference on the shared region we found.
 *
 * The "dyld" runtime (mapped into the process's address space at exec() time)
 * will then use the shared_region_check_np() and shared_region_map_np()
 * system call to validate and/or populate the shared region with the
 * appropriate dyld_shared_cache file.
 *
 * The shared region is inherited on fork() and the child simply takes an
 * extra reference on its parent's shared region.
 *
 * When the task terminates, we release a reference on its shared region.
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
 * at exec() time, in vm_map_exec().
 * It is then inherited on fork().
 *
 * The comm page is shared between the kernel and all applications of
 * a given platform.  Only the kernel can modify it.
 *
 * Applications just branch to fixed addresses in the comm page and find
 * the right version of the code for the platform.  There is also some
 * data provided and updated by the kernel for processes to retrieve easily
 * without having to do a system call.
 */

#include <debug.h>

#include <kern/ipc_tt.h>
#include <kern/kalloc.h>

#include <vm/vm_map.h>
#include <vm/vm_shared_region.h>

#include <vm/vm_protos.h>

#include <machine/commpage.h>
#include <machine/cpu_capabilities.h>

/* "dyld" uses this to figure out what the kernel supports */
int shared_region_version = 3;

/* should local (non-chroot) shared regions persist when no task uses them ? */
int shared_region_persistence = 1;	/* yes by default */

/* trace level, output is sent to the system log file */
int shared_region_trace_level = SHARED_REGION_TRACE_ERROR_LVL;

/* this lock protects all the shared region data structures */
lck_grp_t *vm_shared_region_lck_grp;
lck_mtx_t vm_shared_region_lock;

#define vm_shared_region_lock() lck_mtx_lock(&vm_shared_region_lock)
#define vm_shared_region_unlock() lck_mtx_unlock(&vm_shared_region_lock)
#define vm_shared_region_sleep(event, interruptible)			\
	lck_mtx_sleep(&vm_shared_region_lock,				\
		      LCK_SLEEP_DEFAULT,				\
		      (event_t) (event),				\
		      (interruptible))

/* the list of currently available shared regions (one per environment) */
queue_head_t	vm_shared_region_queue;

static void vm_shared_region_reference_locked(vm_shared_region_t shared_region);
static vm_shared_region_t vm_shared_region_create(
	void			*root_dir,
	cpu_type_t		cputype,
	boolean_t		is_64bit);
static void vm_shared_region_destroy(vm_shared_region_t shared_region);

/*
 * Initialize the module...
 */
void
vm_shared_region_init(void)
{
	SHARED_REGION_TRACE_DEBUG(
		("shared_region: -> init\n"));

	vm_shared_region_lck_grp = lck_grp_alloc_init("vm shared region",
						      LCK_GRP_ATTR_NULL);
	lck_mtx_init(&vm_shared_region_lock,
		     vm_shared_region_lck_grp,
		     LCK_ATTR_NULL);

	queue_init(&vm_shared_region_queue);

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: <- init\n"));
}

/*
 * Retrieve a task's shared region and grab an extra reference to 
 * make sure it doesn't disappear while the caller is using it.	
 * The caller is responsible for consuming that extra reference if
 * necessary.
 */
vm_shared_region_t
vm_shared_region_get(
	task_t		task)
{
	vm_shared_region_t	shared_region;

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: -> get(%p)\n",
		 task));

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
		 task, shared_region));

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
	vm_shared_region_t	shared_region)
{
	SHARED_REGION_TRACE_DEBUG(
		("shared_region: -> base_address(%p)\n",
		 shared_region));
	assert(shared_region->sr_ref_count > 1);
	SHARED_REGION_TRACE_DEBUG(
		("shared_region: base_address(%p) <- 0x%llx\n",
		 shared_region, (long long)shared_region->sr_base_address));
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
	vm_shared_region_t	shared_region)
{
	SHARED_REGION_TRACE_DEBUG(
		("shared_region: -> size(%p)\n",
		 shared_region));
	assert(shared_region->sr_ref_count > 1);
	SHARED_REGION_TRACE_DEBUG(
		("shared_region: size(%p) <- 0x%llx\n",
		 shared_region, (long long)shared_region->sr_size));
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
	vm_shared_region_t	shared_region)
{
	SHARED_REGION_TRACE_DEBUG(
		("shared_region: -> mem_entry(%p)\n",
		 shared_region));
	assert(shared_region->sr_ref_count > 1);
	SHARED_REGION_TRACE_DEBUG(
		("shared_region: mem_entry(%p) <- %p\n",
		 shared_region, shared_region->sr_mem_entry));
	return shared_region->sr_mem_entry;
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
	task_t			task,
	vm_shared_region_t	new_shared_region)
{
	vm_shared_region_t	old_shared_region;

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: -> set(%p, %p)\n",
		 task, new_shared_region));

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
		 task, old_shared_region, new_shared_region));
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
	void		*root_dir,
	cpu_type_t	cputype,
	boolean_t	is_64bit)
{
	vm_shared_region_t	shared_region;
	vm_shared_region_t	new_shared_region;

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: -> lookup(root=%p,cpu=%d,64bit=%d)\n",
		 root_dir, cputype, is_64bit));

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
			    shared_region->sr_root_dir == root_dir &&
			    shared_region->sr_64bit == is_64bit) {
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
								    is_64bit);
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
		break;
	}

done:
	vm_shared_region_unlock();

	if (new_shared_region) {
		/*
		 * We lost a race with someone else to create a new shared
		 * region for that environment.  Get rid of our unused one.
		 */
		assert(new_shared_region->sr_ref_count == 1);
		new_shared_region->sr_ref_count--;
		vm_shared_region_destroy(new_shared_region);
		new_shared_region = NULL;
	}

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: lookup(root=%p,cpu=%d,64bit=%d) <- %p\n",
		 root_dir, cputype, is_64bit, shared_region));

	assert(shared_region->sr_ref_count > 0);
	return shared_region;
}

/*
 * Take an extra reference on a shared region.
 * The vm_shared_region_lock should already be held by the caller.
 */
static void
vm_shared_region_reference_locked(
	vm_shared_region_t	shared_region)
{
#if DEBUG
	lck_mtx_assert(&vm_shared_region_lock, LCK_MTX_ASSERT_OWNED);
#endif

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: -> reference_locked(%p)\n",
		 shared_region));
	assert(shared_region->sr_ref_count > 0);
	shared_region->sr_ref_count++;
	SHARED_REGION_TRACE_DEBUG(
		("shared_region: reference_locked(%p) <- %d\n",
		 shared_region, shared_region->sr_ref_count));
}

/*
 * Release a reference on the shared region.
 * Destroy it if there are no references left.
 */
void
vm_shared_region_deallocate(
	vm_shared_region_t	shared_region)
{
	SHARED_REGION_TRACE_DEBUG(
		("shared_region: -> deallocate(%p)\n",
		 shared_region));

	vm_shared_region_lock();
	
	assert(shared_region->sr_ref_count > 0);

	if (shared_region->sr_root_dir == NULL) {
		/*
		 * Local (i.e. based on the boot volume) shared regions
		 * can persist or not based on the "shared_region_persistence"
		 * sysctl.
		 * Make sure that this one complies.
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
		 shared_region, shared_region->sr_ref_count));

	if (shared_region->sr_ref_count == 0) {
		assert(! shared_region->sr_mapping_in_progress);
		/* remove it from the queue first, so no one can find it... */
		queue_remove(&vm_shared_region_queue,
			     shared_region,
			     vm_shared_region_t,
			     sr_q);
		vm_shared_region_unlock();
		/* ... and destroy it */
		vm_shared_region_destroy(shared_region);
		shared_region = NULL;
	} else {
		vm_shared_region_unlock();
	}

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: deallocate(%p) <-\n",
		 shared_region));
}

/*
 * Create a new (empty) shared region for a new environment.
 */
static vm_shared_region_t
vm_shared_region_create(
	void			*root_dir,
	cpu_type_t		cputype,
	boolean_t		is_64bit)
{
	kern_return_t		kr;
	vm_named_entry_t	mem_entry;
	ipc_port_t		mem_entry_port;
	vm_shared_region_t	shared_region;
	vm_map_t		sub_map;
	mach_vm_offset_t	base_address, pmap_nesting_start;
	mach_vm_size_t		size, pmap_nesting_size;

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: -> create(root=%p,cpu=%d,64bit=%d)\n",
		 root_dir, cputype, is_64bit));

	base_address = 0;
	size = 0;
	mem_entry = NULL;
	mem_entry_port = IPC_PORT_NULL;
	sub_map = VM_MAP_NULL;

	/* create a new shared region structure... */
	shared_region = kalloc(sizeof (*shared_region));
	if (shared_region == NULL) {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: create: couldn't allocate\n"));
		goto done;
	}

	/* figure out the correct settings for the desired environment */
	if (is_64bit) {
		switch (cputype) {
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
		default:
			SHARED_REGION_TRACE_ERROR(
				("shared_region: create: unknown cpu type %d\n",
				 cputype));
			kfree(shared_region, sizeof (*shared_region));
			shared_region = NULL;
			goto done;
		}
	} else {
		switch (cputype) {
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
#ifdef CPU_TYPE_ARM
		case CPU_TYPE_ARM:
			base_address = SHARED_REGION_BASE_ARM;
			size = SHARED_REGION_SIZE_ARM;
			pmap_nesting_start = SHARED_REGION_NESTING_BASE_ARM;
			pmap_nesting_size = SHARED_REGION_NESTING_SIZE_ARM;
			break;
#endif /* CPU_TYPE_ARM */
		default:
			SHARED_REGION_TRACE_ERROR(
				("shared_region: create: unknown cpu type %d\n",
				 cputype));
			kfree(shared_region, sizeof (*shared_region));
			shared_region = NULL;
			goto done;
			
		}
	}

	/* create a memory entry structure and a Mach port handle */
	kr = mach_memory_entry_allocate(&mem_entry,
					&mem_entry_port);
	if (kr != KERN_SUCCESS) {
		kfree(shared_region, sizeof (*shared_region));
		shared_region = NULL;
		SHARED_REGION_TRACE_ERROR(
			("shared_region: create: "
			 "couldn't allocate mem_entry\n"));
		goto done;
	}

	/* create a VM sub map and its pmap */
	sub_map = vm_map_create(pmap_create(0, is_64bit),
				0, size,
				TRUE);
	if (sub_map == VM_MAP_NULL) {
		ipc_port_release_send(mem_entry_port);
		kfree(shared_region, sizeof (*shared_region));
		shared_region = NULL;
		SHARED_REGION_TRACE_ERROR(
			("shared_region: create: "
			 "couldn't allocate map\n"));
		goto done;
	}

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
	shared_region->sr_64bit = is_64bit;
	shared_region->sr_root_dir = root_dir;

	queue_init(&shared_region->sr_q);
	shared_region->sr_mapping_in_progress = FALSE;
	shared_region->sr_persists = FALSE;
	shared_region->sr_first_mapping = (mach_vm_offset_t) -1;

	/* grab a reference for the caller */
	shared_region->sr_ref_count = 1;

done:
	if (shared_region) {
		SHARED_REGION_TRACE_INFO(
			("shared_region: create(root=%p,cpu=%d,64bit=%d,"
			 "base=0x%llx,size=0x%llx) <- "
			 "%p mem=(%p,%p) map=%p pmap=%p\n",
			 root_dir, cputype, is_64bit, (long long)base_address,
			 (long long)size, shared_region,
			 mem_entry_port, mem_entry, sub_map, sub_map->pmap));
	} else {
		SHARED_REGION_TRACE_INFO(
			("shared_region: create(root=%p,cpu=%d,64bit=%d,"
			 "base=0x%llx,size=0x%llx) <- NULL",
			 root_dir, cputype, is_64bit, (long long)base_address,
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
	vm_shared_region_t	shared_region)
{
	vm_named_entry_t	mem_entry;
	vm_map_t		map;

	SHARED_REGION_TRACE_INFO(
		("shared_region: -> destroy(%p) (root=%p,cpu=%d,64bit=%d)\n",
		 shared_region,
		 shared_region->sr_root_dir,
		 shared_region->sr_cpu_type,
		 shared_region->sr_64bit));

	assert(shared_region->sr_ref_count == 0);
	assert(!shared_region->sr_persists);

	mem_entry = (vm_named_entry_t) shared_region->sr_mem_entry->ip_kobject;
	assert(mem_entry->is_sub_map);
	assert(!mem_entry->internal);
	assert(!mem_entry->is_pager);
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
			    shared_region->sr_base_address,
			    (shared_region->sr_base_address +
			     shared_region->sr_size));
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

	/* release the shared region structure... */
	kfree(shared_region, sizeof (*shared_region));
	SHARED_REGION_TRACE_DEBUG(
		("shared_region: destroy(%p) <-\n",
		 shared_region));
	shared_region = NULL;

}

/*
 * Gets the address of the first (in time) mapping in the shared region.
 */
kern_return_t
vm_shared_region_start_address(
	vm_shared_region_t	shared_region,
	mach_vm_offset_t	*start_address)
{
	kern_return_t		kr;
	mach_vm_offset_t	sr_base_address;
	mach_vm_offset_t	sr_first_mapping;

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: -> start_address(%p)\n",
		 shared_region));
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
	assert(! shared_region->sr_mapping_in_progress);
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
		 shared_region, (long long)shared_region->sr_base_address));

	return kr;
}
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
kern_return_t
vm_shared_region_map_file(
	vm_shared_region_t		shared_region,
	unsigned int			mappings_count,
	struct shared_file_mapping_np	*mappings,
	memory_object_control_t		file_control,
	memory_object_size_t		file_size,
	void				*root_dir)
{
	kern_return_t		kr;
	vm_object_t		file_object;
	ipc_port_t		sr_handle;
	vm_named_entry_t	sr_mem_entry;
	vm_map_t		sr_map;
	mach_vm_offset_t	sr_base_address;
	unsigned int		i;
	mach_port_t		map_port;
	mach_vm_offset_t	target_address;

	kr = KERN_SUCCESS;

	vm_shared_region_lock();
	assert(shared_region->sr_ref_count > 1);

	if (shared_region->sr_root_dir != root_dir) {
		/*
		 * This shared region doesn't match the current root
		 * directory of this process.  Deny the mapping to
		 * avoid tainting the shared region with something that	
		 * doesn't quite belong into it.
		 */
		vm_shared_region_unlock();
		kr = KERN_PROTECTION_FAILURE;
		goto done;
	}

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
	assert(! shared_region->sr_mapping_in_progress);
	assert(shared_region->sr_ref_count > 1);
	/* let others know we're working in this shared region */
	shared_region->sr_mapping_in_progress = TRUE;

	vm_shared_region_unlock();

	/* no need to lock because this data is never modified... */
	sr_handle = shared_region->sr_mem_entry;
	sr_mem_entry = (vm_named_entry_t) sr_handle->ip_kobject;
	sr_map = sr_mem_entry->backing.map;
	sr_base_address = shared_region->sr_base_address;

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: -> map(%p,%d,%p,%p,0x%llx)\n",
		 shared_region, mappings_count, mappings,
		 file_control, file_size));

	/* get the VM object associated with the file to be mapped */
	file_object = memory_object_control_to_vm_object(file_control);

	/* establish the mappings */
	for (i = 0; i < mappings_count; i++) {
		SHARED_REGION_TRACE_INFO(
			("shared_region: mapping[%d]: "
			 "address:0x%016llx size:0x%016llx offset:0x%016llx "
			 "maxprot:0x%x prot:0x%x\n",
			 i,
			 (long long)mappings[i].sfm_address,
			 (long long)mappings[i].sfm_size,
			 (long long)mappings[i].sfm_file_offset,
			 mappings[i].sfm_max_prot,
			 mappings[i].sfm_init_prot));

		if (mappings[i].sfm_init_prot & VM_PROT_ZF) {
			/* zero-filled memory */
			map_port = MACH_PORT_NULL;
		} else {
			/* file-backed memory */
			map_port = (ipc_port_t) file_object->pager;
		}

		/* mapping's address is relative to the shared region base */
		target_address =
			mappings[i].sfm_address - sr_base_address;

		/* establish that mapping, OK if it's to "already" there */
		kr = vm_map_enter_mem_object(
			sr_map,
			&target_address,
			vm_map_round_page(mappings[i].sfm_size),
			0,
			VM_FLAGS_FIXED | VM_FLAGS_ALREADY,
			map_port,
			mappings[i].sfm_file_offset,
			TRUE,
			mappings[i].sfm_init_prot & VM_PROT_ALL,
			mappings[i].sfm_max_prot & VM_PROT_ALL,
			VM_INHERIT_DEFAULT);
		if (kr == KERN_MEMORY_PRESENT) {
			/* this exact mapping was already there: that's fine */
			SHARED_REGION_TRACE_INFO(
				("shared_region: mapping[%d]: "
				 "address:0x%016llx size:0x%016llx "
				 "offset:0x%016llx "
				 "maxprot:0x%x prot:0x%x already mapped...\n",
				 i,
				 (long long)mappings[i].sfm_address,
				 (long long)mappings[i].sfm_size,
				 (long long)mappings[i].sfm_file_offset,
				 mappings[i].sfm_max_prot,
				 mappings[i].sfm_init_prot));
			kr = KERN_SUCCESS;
		} else if (kr != KERN_SUCCESS) {
			/* this mapping failed ! */
			SHARED_REGION_TRACE_ERROR(
				("shared_region: mapping[%d]: "
				 "address:0x%016llx size:0x%016llx "
				 "offset:0x%016llx "
				 "maxprot:0x%x prot:0x%x failed 0x%x\n",
				 i,
				 (long long)mappings[i].sfm_address,
				 (long long)mappings[i].sfm_size,
				 (long long)mappings[i].sfm_file_offset,
				 mappings[i].sfm_max_prot,
				 mappings[i].sfm_init_prot,
				 kr));
			break;
		}

		/* we're protected by "sr_mapping_in_progress" */
		if (shared_region->sr_first_mapping == (mach_vm_offset_t) -1) {
			shared_region->sr_first_mapping = target_address;
		}
	}

	vm_shared_region_lock();
	assert(shared_region->sr_ref_count > 1);
	assert(shared_region->sr_mapping_in_progress);
	/* we're done working on that shared region */
	shared_region->sr_mapping_in_progress = FALSE;
	thread_wakeup((event_t) &shared_region->sr_mapping_in_progress);
	vm_shared_region_unlock();

done:
	SHARED_REGION_TRACE_DEBUG(
		("shared_region: map(%p,%d,%p,%p,0x%llx) <- 0x%x \n",
		 shared_region, mappings_count, mappings,
		 file_control, file_size, kr));
	return kr;
}

/*
 * Enter the appropriate shared region into "map" for "task".
 * This involves looking up the shared region (and possibly creating a new
 * one) for the desired environment, then mapping the VM sub map into the
 * task's VM "map", with the appropriate level of pmap-nesting.
 */
kern_return_t
vm_shared_region_enter(
	struct _vm_map		*map,
	struct task		*task,
	void			*fsroot,
	cpu_type_t		cpu)
{
	kern_return_t		kr;
	vm_shared_region_t	shared_region;
	vm_map_offset_t		sr_address, sr_offset, target_address;
	vm_map_size_t		sr_size, mapping_size;
	vm_map_offset_t		sr_pmap_nesting_start;
	vm_map_size_t		sr_pmap_nesting_size;
	ipc_port_t		sr_handle;
	boolean_t		is_64bit;

	is_64bit = task_has_64BitAddr(task);

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: -> "
		 "enter(map=%p,task=%p,root=%p,cpu=%d,64bit=%d)\n",
		 map, task, fsroot, cpu, is_64bit));

	/* lookup (create if needed) the shared region for this environment */
	shared_region = vm_shared_region_lookup(fsroot, cpu, is_64bit);
	if (shared_region == NULL) {
		/* this should not happen ! */
		SHARED_REGION_TRACE_ERROR(
			("shared_region: -> "
			 "enter(map=%p,task=%p,root=%p,cpu=%d,64bit=%d): "
			 "lookup failed !\n",
			 map, task, fsroot, cpu, is_64bit));
		//panic("shared_region_enter: lookup failed\n");
		return KERN_FAILURE;
	}
	
	/* let the task use that shared region */
	vm_shared_region_set(task, shared_region);

	kr = KERN_SUCCESS;
	/* no need to lock since this data is never modified */
	sr_address = shared_region->sr_base_address;
	sr_size = shared_region->sr_size;
	sr_handle = shared_region->sr_mem_entry;
	sr_pmap_nesting_start = shared_region->sr_pmap_nesting_start;
	sr_pmap_nesting_size = shared_region->sr_pmap_nesting_size;

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
			sr_handle,
			sr_offset,
			TRUE,
			VM_PROT_READ,
			VM_PROT_ALL,
			VM_INHERIT_SHARE);
		if (kr != KERN_SUCCESS) {
			SHARED_REGION_TRACE_ERROR(
				("shared_region: enter(%p,%p,%p,%d,%d): "
				 "vm_map_enter(0x%llx,0x%llx,%p) error 0x%x\n",
				 map, task, fsroot, cpu, is_64bit,
				 (long long)target_address,
				 (long long)mapping_size, sr_handle, kr));
			goto done;
		}
		SHARED_REGION_TRACE_DEBUG(
			("shared_region: enter(%p,%p,%p,%d,%d): "
			 "vm_map_enter(0x%llx,0x%llx,%p) error 0x%x\n",
			 map, task, fsroot, cpu, is_64bit,
			 (long long)target_address, (long long)mapping_size,
			 sr_handle, kr));
		sr_offset += mapping_size;
		sr_size -= mapping_size;
	}
	/*
	 * We may need to map several pmap-nested portions, due to platform
	 * specific restrictions on pmap nesting.
	 * The pmap-nesting is triggered by the "VM_MEMORY_SHARED_PMAP" alias...
	 */
	for (;
	     sr_pmap_nesting_size > 0;
	     sr_offset += mapping_size,
		     sr_size -= mapping_size,
		     sr_pmap_nesting_size -= mapping_size) {
		target_address = sr_address + sr_offset;
		mapping_size = sr_pmap_nesting_size;
		if (mapping_size > pmap_nesting_size_max) {
			mapping_size = (vm_map_offset_t) pmap_nesting_size_max;
		}
		kr = vm_map_enter_mem_object(
			map,
			&target_address,
			mapping_size,
			0,
			(VM_FLAGS_FIXED | VM_MAKE_TAG(VM_MEMORY_SHARED_PMAP)),
			sr_handle,
			sr_offset,
			TRUE,
			VM_PROT_READ,
			VM_PROT_ALL,
			VM_INHERIT_SHARE);
		if (kr != KERN_SUCCESS) {
			SHARED_REGION_TRACE_ERROR(
				("shared_region: enter(%p,%p,%p,%d,%d): "
				 "vm_map_enter(0x%llx,0x%llx,%p) error 0x%x\n",
				 map, task, fsroot, cpu, is_64bit,
				 (long long)target_address,
				 (long long)mapping_size, sr_handle, kr));
			goto done;
		}
		SHARED_REGION_TRACE_DEBUG(
			("shared_region: enter(%p,%p,%p,%d,%d): "
			 "nested vm_map_enter(0x%llx,0x%llx,%p) error 0x%x\n",
			 map, task, fsroot, cpu, is_64bit,
			 (long long)target_address, (long long)mapping_size,
			 sr_handle, kr));
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
			sr_handle,
			sr_offset,
			TRUE,
			VM_PROT_READ,
			VM_PROT_ALL,
			VM_INHERIT_SHARE);
		if (kr != KERN_SUCCESS) {
			SHARED_REGION_TRACE_ERROR(
				("shared_region: enter(%p,%p,%p,%d,%d): "
				 "vm_map_enter(0x%llx,0x%llx,%p) error 0x%x\n",
				 map, task, fsroot, cpu, is_64bit,
				 (long long)target_address,
				 (long long)mapping_size, sr_handle, kr));
			goto done;
		}
		SHARED_REGION_TRACE_DEBUG(
			("shared_region: enter(%p,%p,%p,%d,%d): "
			 "vm_map_enter(0x%llx,0x%llx,%p) error 0x%x\n",
			 map, task, fsroot, cpu, is_64bit,
			 (long long)target_address, (long long)mapping_size,
			 sr_handle, kr));
		sr_offset += mapping_size;
		sr_size -= mapping_size;
	}
	assert(sr_size == 0);

done:
	SHARED_REGION_TRACE_DEBUG(
		("shared_region: enter(%p,%p,%p,%d,%d) <- 0x%x\n",
		 map, task, fsroot, cpu, is_64bit, kr));
	return kr;
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

/*
 * Create a memory entry, VM submap and pmap for one commpage.
 */
static void
_vm_commpage_init(
	ipc_port_t	*handlep,
	vm_map_size_t	size)
{
	kern_return_t		kr;
	vm_named_entry_t	mem_entry;
	vm_map_t		new_map;

	SHARED_REGION_TRACE_DEBUG(
		("commpage: -> _init(0x%llx)\n",
		 (long long)size));

	kr = mach_memory_entry_allocate(&mem_entry,
					handlep);
	if (kr != KERN_SUCCESS) {
		panic("_vm_commpage_init: could not allocate mem_entry");
	}
	new_map = vm_map_create(pmap_create(0, FALSE), 0, size, TRUE);
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
		 (long long)size, *handlep));
}

/*
 * Initialize the comm pages at boot time.
 */
void
vm_commpage_init(void)
{
	SHARED_REGION_TRACE_DEBUG(
		("commpage: -> init()\n"));

	/* create the 32-bit comm page */
	_vm_commpage_init(&commpage32_handle, _COMM_PAGE32_AREA_LENGTH);
	commpage32_entry = (vm_named_entry_t) commpage32_handle->ip_kobject;
	commpage32_map = commpage32_entry->backing.map;

	/* XXX if (cpu_is_64bit_capable()) ? */
	/* create the 64-bit comm page */
	_vm_commpage_init(&commpage64_handle, _COMM_PAGE64_AREA_LENGTH);
	commpage64_entry = (vm_named_entry_t) commpage64_handle->ip_kobject;
	commpage64_map = commpage64_entry->backing.map;

	/* populate them according to this specific platform */
	commpage_populate();

	SHARED_REGION_TRACE_DEBUG(
		("commpage: init() <-\n"));
}

/*
 * Enter the appropriate comm page into the task's address space.
 * This is called at exec() time via vm_map_exec().
 */
kern_return_t
vm_commpage_enter(
	vm_map_t	map,
	task_t		task)
{
	ipc_port_t		commpage_handle;
	vm_map_offset_t		commpage_address, objc_address;
	vm_map_size_t		commpage_size, objc_size;
	int			vm_flags;
	kern_return_t		kr;

	SHARED_REGION_TRACE_DEBUG(
		("commpage: -> enter(%p,%p)\n",
		 map, task));

	/* the comm page is likely to be beyond the actual end of the VM map */
	vm_flags = VM_FLAGS_FIXED | VM_FLAGS_BEYOND_MAX;

	/* select the appropriate comm page for this task */
	assert(! (task_has_64BitAddr(task) ^ vm_map_is_64bit(map)));
	if (task_has_64BitAddr(task)) {
#ifdef __ppc__
		/*
		 * PPC51: ppc64 is limited to 51-bit addresses.
		 * Memory above that limit is handled specially at the
		 * pmap level, so do not interfere.
		 */
		vm_flags |= VM_FLAGS_NO_PMAP_CHECK;
#endif /* __ppc__ */
		commpage_handle = commpage64_handle;
		commpage_address = (vm_map_offset_t) _COMM_PAGE64_BASE_ADDRESS;
		commpage_size = _COMM_PAGE64_AREA_LENGTH;
		objc_size = _COMM_PAGE64_OBJC_SIZE;
		objc_address = _COMM_PAGE64_OBJC_BASE;
	} else {
		commpage_handle = commpage32_handle;
		commpage_address =
			(vm_map_offset_t)(unsigned) _COMM_PAGE32_BASE_ADDRESS;
		commpage_size = _COMM_PAGE32_AREA_LENGTH;
		objc_size = _COMM_PAGE32_OBJC_SIZE;
		objc_address = _COMM_PAGE32_OBJC_BASE;
	}

	if ((commpage_address & (pmap_nesting_size_min - 1)) == 0 &&
	    (commpage_size & (pmap_nesting_size_min - 1)) == 0) {
		/* the commpage is properly aligned or sized for pmap-nesting */
		vm_flags |= VM_MAKE_TAG(VM_MEMORY_SHARED_PMAP);
	}

	/* map the comm page in the task's address space */
	assert(commpage_handle != IPC_PORT_NULL);
	kr = vm_map_enter_mem_object(
		map,
		&commpage_address,
		commpage_size,
		0,
		vm_flags,
		commpage_handle,
		0,
		FALSE,
		VM_PROT_READ|VM_PROT_EXECUTE,
		VM_PROT_READ|VM_PROT_EXECUTE,
		VM_INHERIT_SHARE);
	if (kr != KERN_SUCCESS) {
		SHARED_REGION_TRACE_ERROR(
			("commpage: enter(%p,0x%llx,0x%llx) "
			 "commpage %p mapping failed 0x%x\n",
			 map, (long long)commpage_address,
			 (long long)commpage_size, commpage_handle, kr));
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
			VM_FLAGS_FIXED | VM_FLAGS_BEYOND_MAX,
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
				 map, (long long)objc_address,
				 (long long)objc_size, kr));
		}
	}

	SHARED_REGION_TRACE_DEBUG(
		("commpage: enter(%p,%p) <- 0x%x\n",
		 map, task, kr));
	return kr;
}
