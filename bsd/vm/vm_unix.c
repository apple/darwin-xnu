/*
 * Copyright (c) 2006 Apple Computer, Inc. All Rights Reserved.
 * 
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1987 Carnegie-Mellon University
 * All rights reserved.  The CMU software License Agreement specifies
 * the terms and conditions for use and redistribution.
 */

/*
 */


#include <meta_features.h>

#include <kern/task.h>
#include <kern/thread.h>
#include <kern/debug.h>
#include <kern/lock.h>
#include <mach/mach_traps.h>
#include <mach/time_value.h>
#include <mach/vm_map.h>
#include <mach/vm_param.h>
#include <mach/vm_prot.h>
#include <mach/port.h>

#include <sys/file_internal.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/dir.h>
#include <sys/namei.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/vm.h>
#include <sys/file.h>
#include <sys/vnode_internal.h>
#include <sys/mount.h>
#include <sys/trace.h>
#include <sys/kernel.h>
#include <sys/ubc_internal.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/sysproto.h>
#include <sys/mman.h>

#include <bsm/audit_kernel.h>
#include <bsm/audit_kevents.h>

#include <kern/kalloc.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>

#include <machine/spl.h>

#include <mach/shared_memory_server.h>
#include <vm/vm_shared_memory_server.h>

#include <vm/vm_protos.h>


int
useracc(
	user_addr_t	addr,
	user_size_t	len,
	int	prot)
{
	return (vm_map_check_protection(
			current_map(),
			vm_map_trunc_page(addr), vm_map_round_page(addr+len),
			prot == B_READ ? VM_PROT_READ : VM_PROT_WRITE));
}

int
vslock(
	user_addr_t	addr,
	user_size_t	len)
{
	kern_return_t kret;
	kret = vm_map_wire(current_map(), vm_map_trunc_page(addr),
			vm_map_round_page(addr+len), 
			VM_PROT_READ | VM_PROT_WRITE ,FALSE);

	switch (kret) {
	case KERN_SUCCESS:
		return (0);
	case KERN_INVALID_ADDRESS:
	case KERN_NO_SPACE:
		return (ENOMEM);
	case KERN_PROTECTION_FAILURE:
		return (EACCES);
	default:
		return (EINVAL);
	}
}

int
vsunlock(
	user_addr_t addr,
	user_size_t len,
	__unused int dirtied)
{
#if FIXME  /* [ */
	pmap_t		pmap;
	vm_page_t	pg;
	vm_map_offset_t	vaddr;
	ppnum_t		paddr;
#endif  /* FIXME ] */
	kern_return_t kret;

#if FIXME  /* [ */
	if (dirtied) {
		pmap = get_task_pmap(current_task());
		for (vaddr = vm_map_trunc_page(addr);
		     vaddr < vm_map_round_page(addr+len);
				vaddr += PAGE_SIZE) {
			paddr = pmap_extract(pmap, vaddr);
			pg = PHYS_TO_VM_PAGE(paddr);
			vm_page_set_modified(pg);
		}
	}
#endif  /* FIXME ] */
#ifdef	lint
	dirtied++;
#endif	/* lint */
	kret = vm_map_unwire(current_map(), vm_map_trunc_page(addr),
				vm_map_round_page(addr+len), FALSE);
	switch (kret) {
	case KERN_SUCCESS:
		return (0);
	case KERN_INVALID_ADDRESS:
	case KERN_NO_SPACE:
		return (ENOMEM);
	case KERN_PROTECTION_FAILURE:
		return (EACCES);
	default:
		return (EINVAL);
	}
}

int
subyte(
	user_addr_t addr,
	int byte)
{
	char character;
	
	character = (char)byte;
	return (copyout((void *)&(character), addr, sizeof(char)) == 0 ? 0 : -1);
}

int
suibyte(
	user_addr_t addr,
	int byte)
{
	char character;
	
	character = (char)byte;
	return (copyout((void *)&(character), addr, sizeof(char)) == 0 ? 0 : -1);
}

int fubyte(user_addr_t addr)
{
	unsigned char byte;

	if (copyin(addr, (void *) &byte, sizeof(char)))
		return(-1);
	return(byte);
}

int fuibyte(user_addr_t addr)
{
	unsigned char byte;

	if (copyin(addr, (void *) &(byte), sizeof(char)))
		return(-1);
	return(byte);
}

int
suword(
	user_addr_t addr,
	long word)
{
	return (copyout((void *) &word, addr, sizeof(int)) == 0 ? 0 : -1);
}

long fuword(user_addr_t addr)
{
	long word;

	if (copyin(addr, (void *) &word, sizeof(int)))
		return(-1);
	return(word);
}

/* suiword and fuiword are the same as suword and fuword, respectively */

int
suiword(
	user_addr_t addr,
	long word)
{
	return (copyout((void *) &word, addr, sizeof(int)) == 0 ? 0 : -1);
}

long fuiword(user_addr_t addr)
{
	long word;

	if (copyin(addr, (void *) &word, sizeof(int)))
		return(-1);
	return(word);
}

/*
 * With a 32-bit kernel and mixed 32/64-bit user tasks, this interface allows the
 * fetching and setting of process-sized size_t and pointer values.
 */
int
sulong(user_addr_t addr, int64_t word)
{

	if (IS_64BIT_PROCESS(current_proc())) {
		return(copyout((void *)&word, addr, sizeof(word)) == 0 ? 0 : -1);
	} else {
		return(suiword(addr, (long)word));
	}
}

int64_t
fulong(user_addr_t addr)
{
	int64_t longword;

	if (IS_64BIT_PROCESS(current_proc())) {
		if (copyin(addr, (void *)&longword, sizeof(longword)) != 0)
			return(-1);
		return(longword);
	} else {
		return((int64_t)fuiword(addr));
	}
}

int
suulong(user_addr_t addr, uint64_t uword)
{

	if (IS_64BIT_PROCESS(current_proc())) {
		return(copyout((void *)&uword, addr, sizeof(uword)) == 0 ? 0 : -1);
	} else {
		return(suiword(addr, (u_long)uword));
	}
}

uint64_t
fuulong(user_addr_t addr)
{
	uint64_t ulongword;

	if (IS_64BIT_PROCESS(current_proc())) {
		if (copyin(addr, (void *)&ulongword, sizeof(ulongword)) != 0)
			return(-1ULL);
		return(ulongword);
	} else {
		return((uint64_t)fuiword(addr));
	}
}

int
swapon(__unused struct proc *procp, __unused struct swapon_args *uap, __unused int *retval)
{
	return(ENOTSUP);
}


kern_return_t
pid_for_task(
	struct pid_for_task_args *args)
{
	mach_port_name_t	t = args->t;
	user_addr_t		pid_addr  = args->pid;  
	struct proc * p;
	task_t		t1;
	int	pid = -1;
	kern_return_t	err = KERN_SUCCESS;
	boolean_t funnel_state;

	AUDIT_MACH_SYSCALL_ENTER(AUE_PIDFORTASK);
	AUDIT_ARG(mach_port1, t);

	funnel_state = thread_funnel_set(kernel_flock, TRUE);
	t1 = port_name_to_task(t);

	if (t1 == TASK_NULL) {
		err = KERN_FAILURE;
		goto pftout;
	} else {
		p = get_bsdtask_info(t1);
		if (p) {
			pid  = proc_pid(p);
			err = KERN_SUCCESS;
		} else {
			err = KERN_FAILURE;
		}
	}
	task_deallocate(t1);
pftout:
	AUDIT_ARG(pid, pid);
	(void) copyout((char *) &pid, pid_addr, sizeof(int));
	thread_funnel_set(kernel_flock, funnel_state);
	AUDIT_MACH_SYSCALL_EXIT(err);
	return(err);
}

/*
 *	Routine:	task_for_pid
 *	Purpose:
 *		Get the task port for another "process", named by its
 *		process ID on the same host as "target_task".
 *
 *		Only permitted to privileged processes, or processes
 *		with the same user ID.
 *
 * XXX This should be a BSD system call, not a Mach trap!!!
 */
kern_return_t
task_for_pid(
	struct task_for_pid_args *args)
{
	mach_port_name_t	target_tport = args->target_tport;
	int			pid = args->pid;
	user_addr_t		task_addr = args->t;
	struct uthread		*uthread;
	struct proc	*p;
	struct proc *p1;
	task_t		t1;
	mach_port_name_t	tret;
	void * sright;
	int error = 0;
	boolean_t funnel_state;

	AUDIT_MACH_SYSCALL_ENTER(AUE_TASKFORPID);
	AUDIT_ARG(pid, pid);
	AUDIT_ARG(mach_port1, target_tport);

	t1 = port_name_to_task(target_tport);
	if (t1 == TASK_NULL) {
		(void ) copyout((char *)&t1, task_addr, sizeof(mach_port_name_t));
		AUDIT_MACH_SYSCALL_EXIT(KERN_FAILURE);
		return(KERN_FAILURE);
	} 

	funnel_state = thread_funnel_set(kernel_flock, TRUE);

	p1 = get_bsdtask_info(t1);	/* XXX current proc */

	/*
	 * Delayed binding of thread credential to process credential, if we
	 * are not running with an explicitly set thread credential.
	 */
	uthread = get_bsdthread_info(current_thread());
	if (uthread->uu_ucred != p1->p_ucred &&
	    (uthread->uu_flag & UT_SETUID) == 0) {
		kauth_cred_t old = uthread->uu_ucred;
		proc_lock(p1);
		uthread->uu_ucred = p1->p_ucred;
		kauth_cred_ref(uthread->uu_ucred);
		proc_unlock(p1);
		if (old != NOCRED)
			kauth_cred_rele(old);
	}

	p = pfind(pid);
	AUDIT_ARG(process, p);

	if (
		(p != (struct proc *) 0)
		&& (p1 != (struct proc *) 0)
		&& (
			(p1 == p)
			|| !(suser(kauth_cred_get(), 0))
			 || ((kauth_cred_getuid(p->p_ucred) == kauth_cred_getuid(kauth_cred_get())) 
				&& (p->p_ucred->cr_ruid == kauth_cred_get()->cr_ruid)
				&& ((p->p_flag & P_SUGID) == 0))
		  )
		&& (p->p_stat != SZOMB)
		) {
			if (p->task != TASK_NULL) {
				task_reference(p->task);
				sright = (void *)convert_task_to_port(p->task);
				tret = ipc_port_copyout_send(
					sright, 
					get_task_ipcspace(current_task()));
			} else
				tret  = MACH_PORT_NULL;
			AUDIT_ARG(mach_port2, tret);
			(void ) copyout((char *)&tret, task_addr, sizeof(mach_port_name_t));
	        task_deallocate(t1);
			error = KERN_SUCCESS;
			goto tfpout;
	}
    task_deallocate(t1);
	tret = MACH_PORT_NULL;
	(void) copyout((char *) &tret, task_addr, sizeof(mach_port_name_t));
	error = KERN_FAILURE;
tfpout:
	thread_funnel_set(kernel_flock, funnel_state);
	AUDIT_MACH_SYSCALL_EXIT(error);
	return(error);
}


/*
 * shared_region_make_private_np:
 *
 * This system call is for "dyld" only.
 * 
 * It creates a private copy of the current process's "shared region" for
 * split libraries.  "dyld" uses this when the shared region is full or
 * it needs to load a split library that conflicts with an already loaded one
 * that this process doesn't need.  "dyld" specifies a set of address ranges
 * that it wants to keep in the now-private "shared region".  These cover
 * the set of split libraries that the process needs so far.  The kernel needs
 * to deallocate the rest of the shared region, so that it's available for 
 * more libraries for this process.
 */
int
shared_region_make_private_np(
	struct proc					*p,
	struct shared_region_make_private_np_args	*uap,
	__unused int					*retvalp)
{
	int				error;
	kern_return_t			kr;
	boolean_t			using_shared_regions;
	user_addr_t			user_ranges;
	unsigned int			range_count;
	vm_size_t			ranges_size;
	struct shared_region_range_np	*ranges;
	shared_region_mapping_t 	shared_region;
	struct shared_region_task_mappings	task_mapping_info;
	shared_region_mapping_t		next;

	ranges = NULL;

	range_count = uap->rangeCount;
	user_ranges = uap->ranges;
	ranges_size = (vm_size_t) (range_count * sizeof (ranges[0]));

	/* allocate kernel space for the "ranges" */
	if (range_count != 0) {
		if ((mach_vm_size_t) ranges_size !=
		    (mach_vm_size_t) range_count * sizeof (ranges[0])) {
			/* 32-bit integer overflow */
			error = EINVAL;
			goto done;
		}
		kr = kmem_alloc(kernel_map,
				(vm_offset_t *) &ranges,
				ranges_size);
		if (kr != KERN_SUCCESS) {
			error = ENOMEM;
			goto done;
		}

		/* copy "ranges" from user-space */
		error = copyin(user_ranges,
			       ranges,
			       ranges_size);
		if (error) {
			goto done;
		}
	}

	if (p->p_flag & P_NOSHLIB) {
		/* no split library has been mapped for this process so far */
		using_shared_regions = FALSE;
	} else {
		/* this process has already mapped some split libraries */
		using_shared_regions = TRUE;
	}

	/*
	 * Get a private copy of the current shared region.
	 * Do not chain it to the system-wide shared region, as we'll want
	 * to map other split libraries in place of the old ones.  We want
	 * to completely detach from the system-wide shared region and go our
	 * own way after this point, not sharing anything with other processes.
	 */
	error = clone_system_shared_regions(using_shared_regions,
					    FALSE, /* chain_regions */
					    ENV_DEFAULT_ROOT);
	if (error) {
		goto done;
	}

	/* get info on the newly allocated shared region */
	vm_get_shared_region(current_task(), &shared_region);
	task_mapping_info.self = (vm_offset_t) shared_region;
	shared_region_mapping_info(shared_region,
				   &(task_mapping_info.text_region),
				   &(task_mapping_info.text_size),
				   &(task_mapping_info.data_region),
				   &(task_mapping_info.data_size),
				   &(task_mapping_info.region_mappings),
				   &(task_mapping_info.client_base),
				   &(task_mapping_info.alternate_base),
				   &(task_mapping_info.alternate_next),
				   &(task_mapping_info.fs_base),
				   &(task_mapping_info.system),
				   &(task_mapping_info.flags),
				   &next);

	/*
	 * We now have our private copy of the shared region, as it was before
	 * the call to clone_system_shared_regions().  We now need to clean it
	 * up and keep only the memory areas described by the "ranges" array.
	 */
	kr = shared_region_cleanup(range_count, ranges, &task_mapping_info);
	switch (kr) {
	case KERN_SUCCESS:
		error = 0;
		break;
	default:
		error = EINVAL;
		goto done;
	}

done:
	if (ranges != NULL) {
		kmem_free(kernel_map,
			  (vm_offset_t) ranges,
			  ranges_size);
		ranges = NULL;
	}
	
	return error;
}


/*
 * shared_region_map_file_np:
 *
 * This system call is for "dyld" only.
 *
 * "dyld" wants to map parts of a split library in the shared region.
 * We get a file descriptor on the split library to be mapped and a set
 * of mapping instructions, describing which parts of the file to map in\
 * which areas of the shared segment and with what protection.
 * The "shared region" is split in 2 areas:
 * 0x90000000 - 0xa0000000 : read-only area (for TEXT and LINKEDIT sections), 
 * 0xa0000000 - 0xb0000000 : writable area (for DATA sections).
 *
 */
int
shared_region_map_file_np(
	struct proc				*p,
	struct shared_region_map_file_np_args	*uap,
	__unused int				*retvalp)
{
	int					error;
	kern_return_t				kr;
	int					fd;
	unsigned int				mapping_count;
	user_addr_t				user_mappings; /* 64-bit */
	user_addr_t				user_slide_p;  /* 64-bit */
	struct shared_file_mapping_np 		*mappings;
	vm_size_t				mappings_size;
	struct fileproc				*fp;
	mach_vm_offset_t 			slide;
	struct vnode				*vp;
	struct vfs_context 			context;
	memory_object_control_t 		file_control;
	memory_object_size_t			file_size;
	shared_region_mapping_t 		shared_region;
	struct shared_region_task_mappings	task_mapping_info;
	shared_region_mapping_t			next;
	shared_region_mapping_t			default_shared_region;
	boolean_t				using_default_region;
	unsigned int				j;
	vm_prot_t				max_prot;
	mach_vm_offset_t			base_offset, end_offset;
	mach_vm_offset_t			original_base_offset;
	boolean_t				mappings_in_segment;
#define SFM_MAX_STACK	6
	struct shared_file_mapping_np		stack_mappings[SFM_MAX_STACK];

	mappings_size = 0;
	mappings = NULL;
	mapping_count = 0;
	fp = NULL;
	vp = NULL;

	/* get file descriptor for split library from arguments */
	fd = uap->fd;

	/* get file structure from file descriptor */
	error = fp_lookup(p, fd, &fp, 0);
	if (error) {
		goto done;
	}

	/* make sure we're attempting to map a vnode */
	if (fp->f_fglob->fg_type != DTYPE_VNODE) {
		error = EINVAL;
		goto done;
	}

	/* we need at least read permission on the file */
	if (! (fp->f_fglob->fg_flag & FREAD)) {
		error = EPERM;
		goto done;
	}

	/* get vnode from file structure */
	error = vnode_getwithref((vnode_t)fp->f_fglob->fg_data);
	if (error) {
		goto done;
	}
	vp = (struct vnode *) fp->f_fglob->fg_data;

	/* make sure the vnode is a regular file */
	if (vp->v_type != VREG) {
		error = EINVAL;
		goto done;
	}

	/* get vnode size */
	{
		off_t	fs;
		
		context.vc_proc = p;
		context.vc_ucred = kauth_cred_get();
		if ((error = vnode_size(vp, &fs, &context)) != 0)
			goto done;
		file_size = fs;
	}

	/*
	 * Get the list of mappings the caller wants us to establish.
	 */
	mapping_count = uap->mappingCount; /* the number of mappings */
	mappings_size = (vm_size_t) (mapping_count * sizeof (mappings[0]));
	if (mapping_count == 0) {
		error = 0;	/* no mappings: we're done ! */
		goto done;
	} else if (mapping_count <= SFM_MAX_STACK) {
		mappings = &stack_mappings[0];
	} else {
		if ((mach_vm_size_t) mappings_size !=
		    (mach_vm_size_t) mapping_count * sizeof (mappings[0])) {
			/* 32-bit integer overflow */
			error = EINVAL;
			goto done;
		}
		kr = kmem_alloc(kernel_map,
				(vm_offset_t *) &mappings,
				mappings_size);
		if (kr != KERN_SUCCESS) {
			error = ENOMEM;
			goto done;
		}
	}

	user_mappings = uap->mappings;	   /* the mappings, in user space */
	error = copyin(user_mappings,
		       mappings,
		       mappings_size);
	if (error != 0) {
		goto done;
	}

	/*
	 * If the caller provides a "slide" pointer, it means they're OK
	 * with us moving the mappings around to make them fit.
	 */
	user_slide_p = uap->slide_p;

	/*
	 * Make each mapping address relative to the beginning of the
	 * shared region.  Check that all mappings are in the shared region.
	 * Compute the maximum set of protections required to tell the
	 * buffer cache how we mapped the file (see call to ubc_map() below).
	 */
	max_prot = VM_PROT_NONE;
	base_offset = -1LL;
	end_offset = 0;
	mappings_in_segment = TRUE;
	for (j = 0; j < mapping_count; j++) {
		mach_vm_offset_t segment;
		segment = (mappings[j].sfm_address &
			   GLOBAL_SHARED_SEGMENT_MASK);
		if (segment != GLOBAL_SHARED_TEXT_SEGMENT &&
		    segment != GLOBAL_SHARED_DATA_SEGMENT) {
			/* this mapping is not in the shared region... */
			if (user_slide_p == NULL) {
				/* ... and we can't slide it in: fail */
				error = EINVAL;
				goto done;
			}
			if (j == 0) {
				/* expect all mappings to be outside */
				mappings_in_segment = FALSE;
			} else if (mappings_in_segment != FALSE) {
				/* other mappings were not outside: fail */
				error = EINVAL;
				goto done;
			}
			/* we'll try and slide that mapping in the segments */
		} else {
			if (j == 0) {
				/* expect all mappings to be inside */
				mappings_in_segment = TRUE;
			} else if (mappings_in_segment != TRUE) {
				/* other mappings were not inside: fail */
				error = EINVAL;
				goto done;
			}
			/* get a relative offset inside the shared segments */
			mappings[j].sfm_address -= GLOBAL_SHARED_TEXT_SEGMENT;
		}
		if ((mappings[j].sfm_address & SHARED_TEXT_REGION_MASK)
		    < base_offset) {
			base_offset = (mappings[j].sfm_address &
				       SHARED_TEXT_REGION_MASK);
		}
		if ((mappings[j].sfm_address & SHARED_TEXT_REGION_MASK) +
		    mappings[j].sfm_size > end_offset) {
			end_offset =
				(mappings[j].sfm_address &
				 SHARED_TEXT_REGION_MASK) +
				mappings[j].sfm_size;
		}
		max_prot |= mappings[j].sfm_max_prot;
	}
	/* Make all mappings relative to the base_offset */
	base_offset = vm_map_trunc_page(base_offset);
	end_offset = vm_map_round_page(end_offset);
	for (j = 0; j < mapping_count; j++) {
		mappings[j].sfm_address -= base_offset;
	}
	original_base_offset = base_offset;
	if (mappings_in_segment == FALSE) {
		/*
		 * We're trying to map a library that was not pre-bound to
		 * be in the shared segments.  We want to try and slide it
		 * back into the shared segments but as far back as possible,
		 * so that it doesn't clash with pre-bound libraries.  Set
		 * the base_offset to the end of the region, so that it can't
		 * possibly fit there and will have to be slid.
		 */
		base_offset = SHARED_TEXT_REGION_SIZE - end_offset;
	}

	/* get the file's memory object handle */
	UBCINFOCHECK("shared_region_map_file_np", vp);
	file_control = ubc_getobject(vp, UBC_HOLDOBJECT);
	if (file_control == MEMORY_OBJECT_CONTROL_NULL) {
		error = EINVAL;
		goto done;
	}

	/*
	 * Get info about the current process's shared region.
	 * This might change if we decide we need to clone the shared region.
	 */
	vm_get_shared_region(current_task(), &shared_region);
	task_mapping_info.self = (vm_offset_t) shared_region;
	shared_region_mapping_info(shared_region,
				   &(task_mapping_info.text_region),
				   &(task_mapping_info.text_size),
				   &(task_mapping_info.data_region),
				   &(task_mapping_info.data_size),
				   &(task_mapping_info.region_mappings),
				   &(task_mapping_info.client_base),
				   &(task_mapping_info.alternate_base),
				   &(task_mapping_info.alternate_next),
				   &(task_mapping_info.fs_base),
				   &(task_mapping_info.system),
				   &(task_mapping_info.flags),
				   &next);

	/*
	 * Are we using the system's current shared region
	 * for this environment ?
	 */
	default_shared_region =
		lookup_default_shared_region(ENV_DEFAULT_ROOT,
					     task_mapping_info.system);
	if (shared_region == default_shared_region) {
		using_default_region = TRUE;
	} else {
		using_default_region = FALSE;
	}
	shared_region_mapping_dealloc(default_shared_region);

	if (vp->v_mount != rootvnode->v_mount &&
	    using_default_region) {
		/*
		 * The split library is not on the root filesystem.  We don't
		 * want to polute the system-wide ("default") shared region
		 * with it.
		 * Reject the mapping.  The caller (dyld) should "privatize"
		 * (via shared_region_make_private()) the shared region and
		 * try to establish the mapping privately for this process.
		 */
		error = EXDEV;
		goto done;
	}


	/*
	 * Map the split library.
	 */
	kr = map_shared_file(mapping_count,
			     mappings,
			     file_control,
			     file_size,
			     &task_mapping_info,
			     base_offset,
			     (user_slide_p) ? &slide : NULL);

	switch (kr) {
	case KERN_SUCCESS:
		/*
		 * The mapping was successful.  Let the buffer cache know
		 * that we've mapped that file with these protections.  This
		 * prevents the vnode from getting recycled while it's mapped.
		 */
		(void) ubc_map(vp, max_prot);
		error = 0;
		break;
	case KERN_INVALID_ADDRESS:
		error = EFAULT;
		goto done;
	case KERN_PROTECTION_FAILURE:
		error = EPERM;
		goto done;
	case KERN_NO_SPACE:
		error = ENOMEM;
		goto done;
	case KERN_FAILURE:
	case KERN_INVALID_ARGUMENT:
	default:
		error = EINVAL;
		goto done;
	}

	if (p->p_flag & P_NOSHLIB) {
		/* signal that this process is now using split libraries */
		p->p_flag &= ~P_NOSHLIB;
	}

	if (user_slide_p) {
		/*
		 * The caller provided a pointer to a "slide" offset.  Let
		 * them know by how much we slid the mappings.
		 */
		if (mappings_in_segment == FALSE) {
			/*
			 * We faked the base_offset earlier, so undo that
			 * and take into account the real base_offset.
			 */
			slide += SHARED_TEXT_REGION_SIZE - end_offset;
			slide -= original_base_offset;
			/*
			 * The mappings were slid into the shared segments
			 * and "slide" is relative to the beginning of the
			 * shared segments.  Adjust it to be absolute.
			 */
			slide += GLOBAL_SHARED_TEXT_SEGMENT;
		}
		error = copyout(&slide,
				user_slide_p,
				sizeof (int64_t));
	}

done:
	if (vp != NULL) {
		/*
		 * release the vnode...
		 * ubc_map() still holds it for us in the non-error case
		 */
		(void) vnode_put(vp);
		vp = NULL;
	}
	if (fp != NULL) {
		/* release the file descriptor */
		fp_drop(p, fd, fp, 0);
		fp = NULL;
	}
	if (mappings != NULL &&
	    mappings != &stack_mappings[0]) {
		kmem_free(kernel_map,
			  (vm_offset_t) mappings,
			  mappings_size);
	}
	mappings = NULL;

	return error;
}

int
load_shared_file(
	__unused struct proc *p,
	__unused struct load_shared_file_args *uap,
	__unused int *retval)
{
	return ENOSYS;
}

int
reset_shared_file(
	__unused struct proc *p,
	__unused struct reset_shared_file_args *uap,
	__unused int *retval)
{
	return ENOSYS;
}

int
new_system_shared_regions(
	__unused struct proc *p,
	__unused struct new_system_shared_regions_args *uap,
	__unused int *retval)
{
	return ENOSYS;
}



int
clone_system_shared_regions(
	int		shared_regions_active,
	int		chain_regions,
	int		base_vnode)
{
	shared_region_mapping_t	new_shared_region;
	shared_region_mapping_t	next;
	shared_region_mapping_t	old_shared_region;
	struct shared_region_task_mappings old_info;
	struct shared_region_task_mappings new_info;

	vm_get_shared_region(current_task(), &old_shared_region);
	old_info.self = (vm_offset_t)old_shared_region;
	shared_region_mapping_info(old_shared_region,
		&(old_info.text_region),   
		&(old_info.text_size),
		&(old_info.data_region),
		&(old_info.data_size),
		&(old_info.region_mappings),
		&(old_info.client_base),
		&(old_info.alternate_base),
		&(old_info.alternate_next), 
		&(old_info.fs_base),
		&(old_info.system),
		&(old_info.flags), &next);
	if ((shared_regions_active) ||
		(base_vnode == ENV_DEFAULT_ROOT)) {
	   if (shared_file_create_system_region(&new_shared_region))
		return (ENOMEM);
	} else {
	   new_shared_region = 
		lookup_default_shared_region(
			base_vnode, old_info.system);
	   if(new_shared_region == NULL) {
		shared_file_boot_time_init(
			base_vnode, old_info.system);
		vm_get_shared_region(current_task(), &new_shared_region);
	   } else {
		vm_set_shared_region(current_task(), new_shared_region);
	   }
	   if(old_shared_region)
		shared_region_mapping_dealloc(old_shared_region);
	}
	new_info.self = (vm_offset_t)new_shared_region;
	shared_region_mapping_info(new_shared_region,
		&(new_info.text_region),   
		&(new_info.text_size),
		&(new_info.data_region),
		&(new_info.data_size),
		&(new_info.region_mappings),
		&(new_info.client_base),
		&(new_info.alternate_base),
		&(new_info.alternate_next), 
		&(new_info.fs_base),
		&(new_info.system),
		&(new_info.flags), &next);
	if(shared_regions_active) {
	   if(vm_region_clone(old_info.text_region, new_info.text_region)) {
	   panic("clone_system_shared_regions: shared region mis-alignment 1");
		shared_region_mapping_dealloc(new_shared_region);
		return(EINVAL);
	   }
	   if (vm_region_clone(old_info.data_region, new_info.data_region)) {
	   panic("clone_system_shared_regions: shared region mis-alignment 2");
		shared_region_mapping_dealloc(new_shared_region);
		return(EINVAL);
	   }
	   if (chain_regions) {
		   /*
		    * We want a "shadowed" clone, a private superset of the old
		    * shared region.  The info about the old mappings is still
		    * valid for us.
		    */
		   shared_region_object_chain_attach(
			   new_shared_region, old_shared_region);
	   } else {
		   /*
		    * We want a completely detached clone with no link to
		    * the old shared region.  We'll be removing some mappings
		    * in our private, cloned, shared region, so the old mappings
		    * will become irrelevant to us.  Since we have a private
		    * "shared region" now, it isn't going to be shared with
		    * anyone else and we won't need to maintain mappings info.
		    */
		   shared_region_object_chain_detached(new_shared_region);
	   }
	}
	if (vm_map_region_replace(current_map(), old_info.text_region, 
			new_info.text_region, old_info.client_base, 
			old_info.client_base+old_info.text_size)) {
	panic("clone_system_shared_regions: shared region mis-alignment 3");
		shared_region_mapping_dealloc(new_shared_region);
		return(EINVAL);
	}
	if(vm_map_region_replace(current_map(), old_info.data_region, 
			new_info.data_region, 
			old_info.client_base + old_info.text_size, 
			old_info.client_base
				+ old_info.text_size + old_info.data_size)) {
	panic("clone_system_shared_regions: shared region mis-alignment 4");
		shared_region_mapping_dealloc(new_shared_region);
		return(EINVAL);
	}
	vm_set_shared_region(current_task(), new_shared_region);

	/* consume the reference which wasn't accounted for in object */
	/* chain attach */
	if (!shared_regions_active || !chain_regions)
		shared_region_mapping_dealloc(old_shared_region);

	return(0);

}

/* header for the profile name file.  The profiled app info is held */
/* in the data file and pointed to by elements in the name file     */

struct profile_names_header {
	unsigned int	number_of_profiles;
	unsigned int	user_id;
	unsigned int	version;
	off_t		element_array;
	unsigned int	spare1;
	unsigned int	spare2;
	unsigned int	spare3;
};

struct profile_element {
	off_t		addr;
	vm_size_t	size;
	unsigned int	mod_date;
	unsigned int	inode;
	char name[12];
};

struct global_profile {
	struct vnode	*names_vp;
	struct vnode	*data_vp;
	vm_offset_t	buf_ptr;
	unsigned int	user;
	unsigned int	age;
	unsigned int	busy;
};

struct global_profile_cache {
	int			max_ele;
	unsigned int		age;
	struct global_profile	profiles[3];
};

/* forward declarations */
int bsd_open_page_cache_files(unsigned int user,
			      struct global_profile **profile);
void bsd_close_page_cache_files(struct global_profile *profile);
int bsd_search_page_cache_data_base(
	struct	vnode			*vp,
	struct profile_names_header	*database,
	char				*app_name,
	unsigned int			mod_date,
	unsigned int			inode,
	off_t				*profile,
	unsigned int			*profile_size);

struct global_profile_cache global_user_profile_cache =
	{3, 0, {{NULL, NULL, 0, 0, 0, 0},
		    {NULL, NULL, 0, 0, 0, 0},
		    {NULL, NULL, 0, 0, 0, 0}} };

/* BSD_OPEN_PAGE_CACHE_FILES:                                 */
/* Caller provides a user id.  This id was used in            */
/* prepare_profile_database to create two unique absolute     */
/* file paths to the associated profile files.  These files   */
/* are either opened or bsd_open_page_cache_files returns an  */
/* error.  The header of the names file is then consulted.    */
/* The header and the vnodes for the names and data files are */
/* returned. */

int
bsd_open_page_cache_files(
	unsigned int	user,
	struct global_profile **profile)
{
	const char *cache_path = "/var/vm/app_profile/";
	struct proc	*p;
	int		error;
	vm_size_t	resid;
	off_t		resid_off;
	unsigned int	lru;
	vm_size_t	size;

	struct	vnode	*names_vp;
	struct  vnode	*data_vp;
	vm_offset_t	names_buf;
	vm_offset_t	buf_ptr;

	int		profile_names_length;
	int		profile_data_length;
	char		*profile_data_string;
	char		*profile_names_string;
	char		*substring;

	off_t		file_size;
	struct vfs_context  context;

	kern_return_t	ret;

	struct nameidata nd_names;
	struct nameidata nd_data;
	int		i;


	p = current_proc();

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

restart:
	for(i = 0; i<global_user_profile_cache.max_ele; i++) {
		if((global_user_profile_cache.profiles[i].user == user) 
			&&  (global_user_profile_cache.profiles[i].data_vp 
								!= NULL)) {
			*profile = &global_user_profile_cache.profiles[i];
			/* already in cache, we're done */
			if ((*profile)->busy) {
       				/*
       				* drop funnel and wait 
       				*/
				(void)tsleep((void *)
					*profile, 
					PRIBIO, "app_profile", 0);
				goto restart;
			}
			(*profile)->busy = 1;
			(*profile)->age = global_user_profile_cache.age;

			/*
			 * entries in cache are held with a valid
			 * usecount... take an iocount which will
			 * be dropped in "bsd_close_page_cache_files"
			 * which is called after the read or writes to
			 * these files are done
			 */
			if ( (vnode_getwithref((*profile)->data_vp)) ) {
			  
			        vnode_rele((*profile)->data_vp);
			        vnode_rele((*profile)->names_vp);

				(*profile)->data_vp = NULL;
				(*profile)->busy = 0;
				wakeup(*profile);

				goto restart;
			}
			if ( (vnode_getwithref((*profile)->names_vp)) ) {

			        vnode_put((*profile)->data_vp);
			        vnode_rele((*profile)->data_vp);
			        vnode_rele((*profile)->names_vp);

				(*profile)->data_vp = NULL;
				(*profile)->busy = 0;
				wakeup(*profile);

				goto restart;
			}
			global_user_profile_cache.age+=1;
			return 0;
		}
	}

	lru = global_user_profile_cache.age;
	*profile = NULL;
	for(i = 0; i<global_user_profile_cache.max_ele; i++) {
		/* Skip entry if it is in the process of being reused */
		if(global_user_profile_cache.profiles[i].data_vp ==
						(struct vnode *)0xFFFFFFFF)
			continue;
		/* Otherwise grab the first empty entry */
		if(global_user_profile_cache.profiles[i].data_vp == NULL) {
			*profile = &global_user_profile_cache.profiles[i];
			(*profile)->age = global_user_profile_cache.age;
			break;
		}
		/* Otherwise grab the oldest entry */
		if(global_user_profile_cache.profiles[i].age < lru) {
			lru = global_user_profile_cache.profiles[i].age;
			*profile = &global_user_profile_cache.profiles[i];
		}
	}

	/* Did we set it? */
	if (*profile == NULL) {
		/*
		 * No entries are available; this can only happen if all
		 * of them are currently in the process of being reused;
		 * if this happens, we sleep on the address of the first
		 * element, and restart.  This is less than ideal, but we
		 * know it will work because we know that there will be a
		 * wakeup on any entry currently in the process of being
		 * reused.
		 *
		 * XXX Reccomend a two handed clock and more than 3 total
		 * XXX cache entries at some point in the future.
		 */
       		/*
       		* drop funnel and wait 
       		*/
		(void)tsleep((void *)
		 &global_user_profile_cache.profiles[0],
			PRIBIO, "app_profile", 0);
		goto restart;
	}

	/*
	 * If it's currently busy, we've picked the one at the end of the
	 * LRU list, but it's currently being actively used.  We sleep on
	 * its address and restart.
	 */
	if ((*profile)->busy) {
       		/*
       		* drop funnel and wait 
       		*/
		(void)tsleep((void *)
			*profile, 
			PRIBIO, "app_profile", 0);
		goto restart;
	}
	(*profile)->busy = 1;
	(*profile)->user = user;

	/*
	 * put dummy value in for now to get competing request to wait
	 * above until we are finished
	 *
	 * Save the data_vp before setting it, so we can set it before
	 * we kmem_free() or vrele().  If we don't do this, then we
	 * have a potential funnel race condition we have to deal with.
	 */
	data_vp = (*profile)->data_vp;
	(*profile)->data_vp = (struct vnode *)0xFFFFFFFF;

	/*
	 * Age the cache here in all cases; this guarantees that we won't
	 * be reusing only one entry over and over, once the system reaches
	 * steady-state.
	 */
	global_user_profile_cache.age+=1;

	if(data_vp != NULL) {
		kmem_free(kernel_map, 
				(*profile)->buf_ptr, 4 * PAGE_SIZE);
		if ((*profile)->names_vp) {
			vnode_rele((*profile)->names_vp);
			(*profile)->names_vp = NULL;
		}
		vnode_rele(data_vp);
	}
	
	/* Try to open the appropriate users profile files */
	/* If neither file is present, try to create them  */
	/* If one file is present and the other not, fail. */
	/* If the files do exist, check them for the app_file */
	/* requested and read it in if present */

	ret = kmem_alloc(kernel_map,
		(vm_offset_t *)&profile_data_string, PATH_MAX);

	if(ret) {
		(*profile)->data_vp = NULL;
		(*profile)->busy = 0;
		wakeup(*profile);
		return ENOMEM;
	}

	/* Split the buffer in half since we know the size of */
	/* our file path and our allocation is adequate for   */
	/* both file path names */
	profile_names_string = profile_data_string + (PATH_MAX/2);


	strcpy(profile_data_string, cache_path);
	strcpy(profile_names_string, cache_path);
	profile_names_length = profile_data_length 
			= strlen(profile_data_string);
	substring = profile_data_string + profile_data_length;
	sprintf(substring, "%x_data", user);
	substring = profile_names_string + profile_names_length;
	sprintf(substring, "%x_names", user);

	/* We now have the absolute file names */

	ret = kmem_alloc(kernel_map,
       			(vm_offset_t *)&names_buf, 4 * PAGE_SIZE);
	if(ret) {
		kmem_free(kernel_map, 
				(vm_offset_t)profile_data_string, PATH_MAX);
		(*profile)->data_vp = NULL;
		(*profile)->busy = 0;
		wakeup(*profile);
		return ENOMEM;
	}

	NDINIT(&nd_names, LOOKUP, FOLLOW | LOCKLEAF, 
			UIO_SYSSPACE32, CAST_USER_ADDR_T(profile_names_string), &context);
	NDINIT(&nd_data, LOOKUP, FOLLOW | LOCKLEAF, 
			UIO_SYSSPACE32, CAST_USER_ADDR_T(profile_data_string), &context);

	if ( (error = vn_open(&nd_data, FREAD | FWRITE, 0)) ) {
#ifdef notdef
		printf("bsd_open_page_cache_files: CacheData file not found %s\n",
			profile_data_string);
#endif
		kmem_free(kernel_map, 
				(vm_offset_t)names_buf, 4 * PAGE_SIZE);
		kmem_free(kernel_map, 
			(vm_offset_t)profile_data_string, PATH_MAX);
		(*profile)->data_vp = NULL;
		(*profile)->busy = 0;
		wakeup(*profile);
		return error;
	}
	data_vp = nd_data.ni_vp;

	if ( (error = vn_open(&nd_names, FREAD | FWRITE, 0)) ) {
		printf("bsd_open_page_cache_files: NamesData file not found %s\n",
			profile_data_string);
		kmem_free(kernel_map, 
				(vm_offset_t)names_buf, 4 * PAGE_SIZE);
		kmem_free(kernel_map, 
			(vm_offset_t)profile_data_string, PATH_MAX);

		vnode_rele(data_vp);
		vnode_put(data_vp);

		(*profile)->data_vp = NULL;
		(*profile)->busy = 0;
		wakeup(*profile);
		return error;
	}
	names_vp = nd_names.ni_vp;

	if ((error = vnode_size(names_vp, &file_size, &context)) != 0) {
		printf("bsd_open_page_cache_files: Can't stat name file %s\n", profile_names_string);
		kmem_free(kernel_map, 
			(vm_offset_t)profile_data_string, PATH_MAX);
		kmem_free(kernel_map, 
			(vm_offset_t)names_buf, 4 * PAGE_SIZE);

		vnode_rele(names_vp);
		vnode_put(names_vp);
		vnode_rele(data_vp);
		vnode_put(data_vp);

		(*profile)->data_vp = NULL;
		(*profile)->busy = 0;
		wakeup(*profile);
		return error;
	}

	size = file_size;
	if(size > 4 * PAGE_SIZE) 
		size = 4 * PAGE_SIZE;
	buf_ptr = names_buf;
	resid_off = 0;

	while(size) {
		error = vn_rdwr(UIO_READ, names_vp, (caddr_t)buf_ptr, 
			size, resid_off,
			UIO_SYSSPACE32, IO_NODELOCKED, kauth_cred_get(), &resid, p);
		if((error) || (size == resid)) {
			if(!error) {
				error = EINVAL;
			}
			kmem_free(kernel_map, 
				(vm_offset_t)profile_data_string, PATH_MAX);
			kmem_free(kernel_map, 
				(vm_offset_t)names_buf, 4 * PAGE_SIZE);

			vnode_rele(names_vp);
			vnode_put(names_vp);
			vnode_rele(data_vp);
			vnode_put(data_vp);

			(*profile)->data_vp = NULL;
			(*profile)->busy = 0;
			wakeup(*profile);
			return error;
		}
		buf_ptr += size-resid;
		resid_off += size-resid;
		size = resid;
	}
	kmem_free(kernel_map, (vm_offset_t)profile_data_string, PATH_MAX);

	(*profile)->names_vp = names_vp;
	(*profile)->data_vp = data_vp;
	(*profile)->buf_ptr = names_buf;

	/*
	 * at this point, the both the names_vp and the data_vp have
	 * both a valid usecount and an iocount held
	 */
	return 0;

}

void
bsd_close_page_cache_files(
	struct global_profile *profile)
{
        vnode_put(profile->data_vp);
	vnode_put(profile->names_vp);

	profile->busy = 0;
	wakeup(profile);
}

int
bsd_read_page_cache_file(
	unsigned int	user,
	int		*fid,
	int		*mod,
	char		*app_name,
	struct vnode	*app_vp,
	vm_offset_t	*buffer,
	vm_offset_t	*bufsize)
{

	boolean_t	funnel_state;

	struct proc	*p;
	int		error;
	unsigned int	resid;

	off_t		profile;
	unsigned int	profile_size;

	vm_offset_t	names_buf;
	struct vnode_attr	va;
	struct vfs_context  context;

	kern_return_t	ret;

	struct	vnode	*names_vp;
	struct	vnode	*data_vp;

	struct global_profile *uid_files;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);

	/* Try to open the appropriate users profile files */
	/* If neither file is present, try to create them  */
	/* If one file is present and the other not, fail. */
	/* If the files do exist, check them for the app_file */
	/* requested and read it in if present */


	error = bsd_open_page_cache_files(user, &uid_files);
	if(error) {
		thread_funnel_set(kernel_flock, funnel_state);
		return EINVAL;
	}

	p = current_proc();

	names_vp = uid_files->names_vp;
	data_vp = uid_files->data_vp;
	names_buf = uid_files->buf_ptr;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	VATTR_INIT(&va);
	VATTR_WANTED(&va, va_fileid);
	VATTR_WANTED(&va, va_modify_time);
	
	if ((error = vnode_getattr(app_vp, &va, &context))) {
		printf("bsd_read_cache_file: Can't stat app file %s\n", app_name);
		bsd_close_page_cache_files(uid_files);
		thread_funnel_set(kernel_flock, funnel_state);
		return error;
	}

	*fid = (u_long)va.va_fileid;
	*mod = va.va_modify_time.tv_sec;
		
	if (bsd_search_page_cache_data_base(
		    names_vp,
		    (struct profile_names_header *)names_buf,
		    app_name, 
		    (unsigned int) va.va_modify_time.tv_sec,  
		    (u_long)va.va_fileid, &profile, &profile_size) == 0) {
		/* profile is an offset in the profile data base */
		/* It is zero if no profile data was found */
		
		if(profile_size == 0) {
			*buffer = 0;
			*bufsize = 0;
			bsd_close_page_cache_files(uid_files);
			thread_funnel_set(kernel_flock, funnel_state);
			return 0;
		}
		ret = (vm_offset_t)(kmem_alloc(kernel_map, buffer, profile_size));
		if(ret) {
			bsd_close_page_cache_files(uid_files);
			thread_funnel_set(kernel_flock, funnel_state);
			return ENOMEM;
		}
		*bufsize = profile_size;
		while(profile_size) {
			error = vn_rdwr(UIO_READ, data_vp, 
				(caddr_t) *buffer, profile_size, 
				profile, UIO_SYSSPACE32, IO_NODELOCKED, 
				kauth_cred_get(), &resid, p);
			if((error) || (profile_size == resid)) {
				bsd_close_page_cache_files(uid_files);
				kmem_free(kernel_map, (vm_offset_t)*buffer, profile_size);
				thread_funnel_set(kernel_flock, funnel_state);
				return EINVAL;
			}
		        profile += profile_size - resid;
			profile_size = resid;
		}
		bsd_close_page_cache_files(uid_files);
		thread_funnel_set(kernel_flock, funnel_state);
		return 0;
	} else {
		bsd_close_page_cache_files(uid_files);
		thread_funnel_set(kernel_flock, funnel_state);
		return EINVAL;
	}
	
}

int
bsd_search_page_cache_data_base(
	struct	vnode			*vp,
	struct profile_names_header	*database,
	char				*app_name,
	unsigned int			mod_date,
	unsigned int			inode,
	off_t				*profile,
	unsigned int			*profile_size)
{

	struct proc		*p;

	unsigned int 		i;
	struct profile_element	*element;
	unsigned int		ele_total;
	unsigned int		extended_list = 0;
	off_t			file_off = 0;
	unsigned int		size;
	off_t			resid_off;
	unsigned int		resid;
	vm_offset_t		local_buf = 0;

	int			error;
	kern_return_t		ret;

	p = current_proc();

	if(((vm_offset_t)database->element_array) !=
				sizeof(struct profile_names_header)) {
		return EINVAL;
	}
	element = (struct profile_element *)(
			(vm_offset_t)database->element_array + 
						(vm_offset_t)database);

	ele_total = database->number_of_profiles;
	
	*profile = 0;
	*profile_size = 0;
	while(ele_total) {
		/* note: code assumes header + n*ele comes out on a page boundary */
		if(((local_buf == 0) && (sizeof(struct profile_names_header) + 
			(ele_total * sizeof(struct profile_element))) 
					> (PAGE_SIZE * 4)) ||
			((local_buf != 0) && 
				(ele_total * sizeof(struct profile_element))
					 > (PAGE_SIZE * 4))) {
			extended_list = ele_total;
			if(element == (struct profile_element *)
				((vm_offset_t)database->element_array + 
						(vm_offset_t)database)) {
				ele_total = ((PAGE_SIZE * 4)/sizeof(struct profile_element)) - 1;
			} else {
				ele_total = (PAGE_SIZE * 4)/sizeof(struct profile_element);
			}
			extended_list -= ele_total;
		}
		for (i=0; i<ele_total; i++) {
			if((mod_date == element[i].mod_date) 
					&& (inode == element[i].inode)) {
				if(strncmp(element[i].name, app_name, 12) == 0) {
					*profile = element[i].addr;
					*profile_size = element[i].size;
					if(local_buf != 0) {
						kmem_free(kernel_map, local_buf, 4 * PAGE_SIZE);
					}
					return 0;
				}
			}
		}
		if(extended_list == 0)
			break;
		if(local_buf == 0) {
			ret = kmem_alloc(kernel_map, &local_buf, 4 * PAGE_SIZE);
			if(ret != KERN_SUCCESS) {
				return ENOMEM;
			}
		}
		element = (struct profile_element *)local_buf;
		ele_total = extended_list;
		extended_list = 0;
		file_off +=  4 * PAGE_SIZE;
		if((ele_total * sizeof(struct profile_element)) > 
							(PAGE_SIZE * 4)) {
			size = PAGE_SIZE * 4;
		} else {
			size = ele_total * sizeof(struct profile_element);
		}
		resid_off = 0;
		while(size) {
			error = vn_rdwr(UIO_READ, vp, 
				CAST_DOWN(caddr_t, (local_buf + resid_off)),
				size, file_off + resid_off, UIO_SYSSPACE32, 
				IO_NODELOCKED, kauth_cred_get(), &resid, p);
			if((error) || (size == resid)) {
				if(local_buf != 0) {
					kmem_free(kernel_map, local_buf, 4 * PAGE_SIZE);
				}
				return EINVAL;
			}
			resid_off += size-resid;
			size = resid;
		}
	}
	if(local_buf != 0) {
		kmem_free(kernel_map, local_buf, 4 * PAGE_SIZE);
	}
	return 0;
}

int
bsd_write_page_cache_file(
	unsigned int	user,
	char	 	*file_name,
	caddr_t		buffer,
	vm_size_t	size,
	int		mod,
	int		fid)
{
	struct proc		*p;
	int				resid;
	off_t			resid_off;
	int				error;
	boolean_t		funnel_state;
	off_t			file_size;
	struct vfs_context	context;
	off_t			profile;
	unsigned int	profile_size;

	vm_offset_t	names_buf;
	struct	vnode	*names_vp;
	struct	vnode	*data_vp;
	struct	profile_names_header *profile_header;
	off_t			name_offset;
	struct global_profile *uid_files;


	funnel_state = thread_funnel_set(kernel_flock, TRUE);


	error = bsd_open_page_cache_files(user, &uid_files);
	if(error) {
		thread_funnel_set(kernel_flock, funnel_state);
		return EINVAL;
	}

	p = current_proc();

	names_vp = uid_files->names_vp;
	data_vp = uid_files->data_vp;
	names_buf = uid_files->buf_ptr;

	/* Stat data file for size */

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	if ((error = vnode_size(data_vp, &file_size, &context)) != 0) {
		printf("bsd_write_page_cache_file: Can't stat profile data %s\n", file_name);
		bsd_close_page_cache_files(uid_files);
		thread_funnel_set(kernel_flock, funnel_state);
		return error;
	}
		
	if (bsd_search_page_cache_data_base(names_vp, 
			(struct profile_names_header *)names_buf, 
			file_name, (unsigned int) mod,  
			fid, &profile, &profile_size) == 0) {
		/* profile is an offset in the profile data base */
		/* It is zero if no profile data was found */
		
		if(profile_size == 0) {
			unsigned int	header_size;
			vm_offset_t	buf_ptr;

			/* Our Write case */

			/* read header for last entry */
			profile_header = 
				(struct profile_names_header *)names_buf;
			name_offset = sizeof(struct profile_names_header) + 
				(sizeof(struct profile_element) 
					* profile_header->number_of_profiles);
			profile_header->number_of_profiles += 1;

			if(name_offset < PAGE_SIZE * 4) {
				struct profile_element	*name;
				/* write new entry */
				name = (struct profile_element *)
					(names_buf + (vm_offset_t)name_offset);
				name->addr =  file_size;
				name->size = size;
				name->mod_date = mod;
				name->inode = fid;
				strncpy (name->name, file_name, 12);
			} else {
				unsigned int	ele_size;
				struct profile_element	name;
				/* write new entry */
				name.addr = file_size;
				name.size = size;
				name.mod_date = mod;
				name.inode = fid;
				strncpy (name.name, file_name, 12);
				/* write element out separately */
				ele_size = sizeof(struct profile_element);
				buf_ptr = (vm_offset_t)&name;
				resid_off = name_offset;

				while(ele_size) {
					error = vn_rdwr(UIO_WRITE, names_vp, 
						(caddr_t)buf_ptr, 
						ele_size, resid_off, 
						UIO_SYSSPACE32, IO_NODELOCKED, 
						kauth_cred_get(), &resid, p);
					if(error) {
						printf("bsd_write_page_cache_file: Can't write name_element %x\n", user);
						bsd_close_page_cache_files(
							uid_files);
						thread_funnel_set(
							kernel_flock, 
							funnel_state);
						return error;
					}
					buf_ptr += (vm_offset_t)
							ele_size-resid;
					resid_off += ele_size-resid;
					ele_size = resid;
				}
			}

			if(name_offset < PAGE_SIZE * 4) {
				header_size = name_offset + 
					sizeof(struct profile_element);
				
			} else {
				header_size = 
					sizeof(struct profile_names_header);
			}
			buf_ptr = (vm_offset_t)profile_header;
			resid_off = 0;

			/* write names file header */
			while(header_size) {
				error = vn_rdwr(UIO_WRITE, names_vp, 
					(caddr_t)buf_ptr, 
					header_size, resid_off, 
					UIO_SYSSPACE32, IO_NODELOCKED, 
					kauth_cred_get(), &resid, p);
				if(error) {
					printf("bsd_write_page_cache_file: Can't write header %x\n", user);
					bsd_close_page_cache_files(
						uid_files);
					thread_funnel_set(
						kernel_flock, funnel_state);
					return error;
				}
				buf_ptr += (vm_offset_t)header_size-resid;
				resid_off += header_size-resid;
				header_size = resid;
			}
			/* write profile to data file */
			resid_off = file_size;
			while(size) {
				error = vn_rdwr(UIO_WRITE, data_vp, 
					(caddr_t)buffer, size, resid_off, 
					UIO_SYSSPACE32, IO_NODELOCKED, 
					kauth_cred_get(), &resid, p);
				if(error) {
					printf("bsd_write_page_cache_file: Can't write header %x\n", user);
					bsd_close_page_cache_files(
						uid_files);
					thread_funnel_set(
						kernel_flock, funnel_state);
					return error;
				}
				buffer += size-resid;
				resid_off += size-resid;
				size = resid;
			}
			bsd_close_page_cache_files(uid_files);
			thread_funnel_set(kernel_flock, funnel_state);
			return 0;
		}
		/* Someone else wrote a twin profile before us */
		bsd_close_page_cache_files(uid_files);
		thread_funnel_set(kernel_flock, funnel_state);
		return 0;
	} else {		
		bsd_close_page_cache_files(uid_files);
		thread_funnel_set(kernel_flock, funnel_state);
		return EINVAL;
	}
	
}

int
prepare_profile_database(int	user)
{
	const char *cache_path = "/var/vm/app_profile/";
	struct proc	*p;
	int		error;
	int		resid;
	off_t		resid_off;
	vm_size_t	size;

	struct	vnode	*names_vp;
	struct  vnode	*data_vp;
	vm_offset_t	names_buf;
	vm_offset_t	buf_ptr;

	int		profile_names_length;
	int		profile_data_length;
	char		*profile_data_string;
	char		*profile_names_string;
	char		*substring;

	struct vnode_attr va;
	struct vfs_context context;

	struct	profile_names_header *profile_header;
	kern_return_t	ret;

	struct nameidata nd_names;
	struct nameidata nd_data;

	p = current_proc();

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	ret = kmem_alloc(kernel_map,
		(vm_offset_t *)&profile_data_string, PATH_MAX);

	if(ret) {
		return ENOMEM;
	}

	/* Split the buffer in half since we know the size of */
	/* our file path and our allocation is adequate for   */
	/* both file path names */
	profile_names_string = profile_data_string + (PATH_MAX/2);


	strcpy(profile_data_string, cache_path);
	strcpy(profile_names_string, cache_path);
	profile_names_length = profile_data_length 
			= strlen(profile_data_string);
	substring = profile_data_string + profile_data_length;
	sprintf(substring, "%x_data", user);
	substring = profile_names_string + profile_names_length;
	sprintf(substring, "%x_names", user);

	/* We now have the absolute file names */

	ret = kmem_alloc(kernel_map,
       			(vm_offset_t *)&names_buf, 4 * PAGE_SIZE);
	if(ret) {
		kmem_free(kernel_map, 
				(vm_offset_t)profile_data_string, PATH_MAX);
		return ENOMEM;
	}

	NDINIT(&nd_names, LOOKUP, FOLLOW, 
			UIO_SYSSPACE32, CAST_USER_ADDR_T(profile_names_string), &context);
	NDINIT(&nd_data, LOOKUP, FOLLOW,
			UIO_SYSSPACE32, CAST_USER_ADDR_T(profile_data_string), &context);

	if ( (error = vn_open(&nd_data, 
							O_CREAT | O_EXCL | FWRITE, S_IRUSR|S_IWUSR)) ) {
			kmem_free(kernel_map, 
					(vm_offset_t)names_buf, 4 * PAGE_SIZE);
			kmem_free(kernel_map, 
				(vm_offset_t)profile_data_string, PATH_MAX);
			
			return 0;
	}
	data_vp = nd_data.ni_vp;

	if ( (error = vn_open(&nd_names, 
							O_CREAT | O_EXCL | FWRITE, S_IRUSR|S_IWUSR)) ) {
			printf("prepare_profile_database: Can't create CacheNames %s\n",
				profile_data_string);
			kmem_free(kernel_map, 
					(vm_offset_t)names_buf, 4 * PAGE_SIZE);
			kmem_free(kernel_map, 
				(vm_offset_t)profile_data_string, PATH_MAX);

			vnode_rele(data_vp);
			vnode_put(data_vp);

			return error;
	}
	names_vp = nd_names.ni_vp;

	/* Write Header for new names file */

	profile_header = (struct profile_names_header *)names_buf;

	profile_header->number_of_profiles = 0;
	profile_header->user_id =  user;
	profile_header->version = 1;
	profile_header->element_array = 
				sizeof(struct profile_names_header);
	profile_header->spare1 = 0;
	profile_header->spare2 = 0;
	profile_header->spare3 = 0;

	size = sizeof(struct profile_names_header);
	buf_ptr = (vm_offset_t)profile_header;
	resid_off = 0;

	while(size) {
		error = vn_rdwr(UIO_WRITE, names_vp, 
				(caddr_t)buf_ptr, size, resid_off,
				UIO_SYSSPACE32, IO_NODELOCKED, 
				kauth_cred_get(), &resid, p);
		if(error) {
			printf("prepare_profile_database: Can't write header %s\n", profile_names_string);
			kmem_free(kernel_map, 
				(vm_offset_t)names_buf, 4 * PAGE_SIZE);
			kmem_free(kernel_map, 
				(vm_offset_t)profile_data_string, 
				PATH_MAX);

			vnode_rele(names_vp);
			vnode_put(names_vp);
			vnode_rele(data_vp);
			vnode_put(data_vp);

			return error;
		}
		buf_ptr += size-resid;
		resid_off += size-resid;
		size = resid;
	}
	VATTR_INIT(&va);
	VATTR_SET(&va, va_uid, user);

       	error = vnode_setattr(names_vp, &va, &context);
	if(error) {
		printf("prepare_profile_database: "
			"Can't set user %s\n", profile_names_string);
	}
	vnode_rele(names_vp);
	vnode_put(names_vp);
	
	VATTR_INIT(&va);
	VATTR_SET(&va, va_uid, user);
       	error = vnode_setattr(data_vp, &va, &context);
	if(error) {
		printf("prepare_profile_database: "
			"Can't set user %s\n", profile_data_string);
	}
	vnode_rele(data_vp);
	vnode_put(data_vp);

	kmem_free(kernel_map, 
			(vm_offset_t)profile_data_string, PATH_MAX);
	kmem_free(kernel_map, 
			(vm_offset_t)names_buf, 4 * PAGE_SIZE);
	return 0;

}
