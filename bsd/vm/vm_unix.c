/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
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
#include <mach/time_value.h>
#include <mach/vm_param.h>
#include <mach/vm_prot.h>
#include <mach/port.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/dir.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/vm.h>
#include <sys/file.h>
#include <sys/vnode.h>
#include <sys/buf.h>
#include <sys/mount.h>
#include <sys/trace.h>
#include <sys/kernel.h>
#include <sys/ubc.h>

#include <kern/kalloc.h>
#include <kern/parallel.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>

#include <machine/spl.h>
#include <mach/shared_memory_server.h>

useracc(addr, len, prot)
	caddr_t	addr;
	u_int	len;
	int	prot;
{
	return (vm_map_check_protection(
			current_map(),
			trunc_page(addr), round_page(addr+len),
			prot == B_READ ? VM_PROT_READ : VM_PROT_WRITE));
}

vslock(addr, len)
	caddr_t	addr;
	int	len;
{
	vm_map_wire(current_map(), trunc_page(addr),
			round_page(addr+len), 
			VM_PROT_READ | VM_PROT_WRITE ,FALSE);
}

vsunlock(addr, len, dirtied)
	caddr_t	addr;
	int	len;
	int dirtied;
{
	pmap_t		pmap;
#if FIXME  /* [ */
	vm_page_t	pg;
#endif  /* FIXME ] */
	vm_offset_t	vaddr, paddr;

#if FIXME  /* [ */
	if (dirtied) {
		pmap = get_task_pmap(current_task());
		for (vaddr = trunc_page(addr); vaddr < round_page(addr+len);
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
	vm_map_unwire(current_map(), trunc_page(addr),
				round_page(addr+len), FALSE);
}

#if	defined(sun) || BALANCE || defined(m88k)
#else	/*defined(sun) || BALANCE || defined(m88k)*/
subyte(addr, byte)
	void * addr;
	int byte;
{
	char character;
	
	character = (char)byte;
	return (copyout((void *)&(character), addr, sizeof(char)) == 0 ? 0 : -1);
}

suibyte(addr, byte)
	void * addr;
	int byte;
{
	char character;
	
	character = (char)byte;
	return (copyout((void *) &(character), addr, sizeof(char)) == 0 ? 0 : -1);
}

int fubyte(addr)
	void * addr;
{
	unsigned char byte;

	if (copyin(addr, (void *) &byte, sizeof(char)))
		return(-1);
	return(byte);
}

int fuibyte(addr)
	void * addr;
{
	unsigned char byte;

	if (copyin(addr, (void *) &(byte), sizeof(char)))
		return(-1);
	return(byte);
}

suword(addr, word)
	void * addr;
	long word;
{
	return (copyout((void *) &word, addr, sizeof(int)) == 0 ? 0 : -1);
}

long fuword(addr)
	void * addr;
{
	long word;

	if (copyin(addr, (void *) &word, sizeof(int)))
		return(-1);
	return(word);
}

/* suiword and fuiword are the same as suword and fuword, respectively */

suiword(addr, word)
	void * addr;
	long word;
{
	return (copyout((void *) &word, addr, sizeof(int)) == 0 ? 0 : -1);
}

long fuiword(addr)
	void * addr;
{
	long word;

	if (copyin(addr, (void *) &word, sizeof(int)))
		return(-1);
	return(word);
}
#endif	/* defined(sun) || BALANCE || defined(m88k) || defined(i386) */

int
swapon()
{
	return(EOPNOTSUPP);
}

thread_t
procdup(
	struct proc		*child,
	struct proc		*parent)
{
	thread_t		thread;
	task_t			task;
 	kern_return_t	result;

	if (parent->task == kernel_task)
		result = task_create_local(TASK_NULL, FALSE, FALSE, &task);
	else
		result = task_create_local(parent->task, TRUE, FALSE, &task);
	if (result != KERN_SUCCESS)
	    printf("fork/procdup: task_create failed. Code: 0x%x\n", result);
	child->task = task;
	/* task->proc = child; */
	set_bsdtask_info(task, child);
	result = thread_create(task, &thread);
	if (result != KERN_SUCCESS)
	    printf("fork/procdup: thread_create failed. Code: 0x%x\n", result);

#if FIXME /* [ */
	thread_deallocate(thread); // extra ref

	/*
	 *	Don't need to lock thread here because it can't
	 *	possibly execute and no one else knows about it.
	 */
	/* compute_priority(thread, FALSE); */
#endif /* ] */
	return(thread);
}

kern_return_t
pid_for_task(t, x)
	mach_port_t	t;
	int	*x;
{
	struct proc * p;
	task_t		t1;
	extern task_t port_name_to_task(mach_port_t t);
	int	pid = -1;
	kern_return_t	err;
	boolean_t funnel_state;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);
	t1 = port_name_to_task(t);

	if (t1 == TASK_NULL) {
		err = KERN_FAILURE;
	} else {
		p = get_bsdtask_info(t1);
		if (p) {
			pid  = p->p_pid;
			err = KERN_SUCCESS;
		} else {
			err = KERN_FAILURE;
		}
	}
	task_deallocate(t1);
	(void) copyout((char *) &pid, (char *) x, sizeof(*x));
pftout:
	thread_funnel_set(kernel_flock, funnel_state);
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
 */
kern_return_t
task_for_pid(target_tport, pid, t)
	mach_port_t	target_tport;
	int		pid;
	mach_port_t	*t;
{
	struct proc	*p;
	struct proc *p1;
	task_t		t1;
	mach_port_t	tret;
	extern task_t port_name_to_task(mach_port_t tp);
	void * sright;
	int error = 0;
	boolean_t funnel_state;

	t1 = port_name_to_task(target_tport);
	if (t1 == TASK_NULL) {
		(void ) copyout((char *)&t1, (char *)t, sizeof(mach_port_t));
		error = KERN_FAILURE;
		goto tfpout;
	} 

	funnel_state = thread_funnel_set(kernel_flock, TRUE);

 restart:
	p1 = get_bsdtask_info(t1);
	if (
		((p = pfind(pid)) != (struct proc *) 0)
		&& (p1 != (struct proc *) 0)
		&& ((p->p_ucred->cr_uid == p1->p_ucred->cr_uid)
		|| !(suser(p1->p_ucred, &p1->p_acflag)))
		&& (p->p_stat != SZOMB)
		) {
			if (p->task != TASK_NULL) {
				if (!task_reference_try(p->task)) {
					mutex_pause(); /* temp loss of funnel */
					goto restart;
				}
				sright = convert_task_to_port(p->task);
				tret = ipc_port_copyout_send(sright, get_task_ipcspace(current_task()));
			} else
				tret  = MACH_PORT_NULL;
			(void ) copyout((char *)&tret, (char *) t, sizeof(mach_port_t));
	        task_deallocate(t1);
			error = KERN_SUCCESS;
			goto tfpout;
	}
    task_deallocate(t1);
	tret = MACH_PORT_NULL;
	(void) copyout((char *) &tret, (char *) t, sizeof(mach_port_t));
	error = KERN_FAILURE;
tfpout:
	thread_funnel_set(kernel_flock, funnel_state);
	return(error);
}


struct load_shared_file_args {
		char		*filename;
		caddr_t		mfa;
		u_long		mfs;
		caddr_t		*ba;
		int		map_cnt;
		sf_mapping_t	*mappings;
		int		*flags;
};


int
load_shared_file(
	struct proc 		*p,
	struct load_shared_file_args *uap,
	register		*retval)
{
	caddr_t		mapped_file_addr=uap->mfa;
	u_long		mapped_file_size=uap->mfs;
	caddr_t		*base_address=uap->ba;
	int             map_cnt=uap->map_cnt;
	sf_mapping_t       *mappings=uap->mappings;
	char            *filename=uap->filename;
	int             *flags=uap->flags;
	struct vnode		*vp = 0; 
	struct nameidata 	nd, *ndp;
	char			*filename_str;
	register int		error;
	kern_return_t		kr;

	struct vattr	vattr;
	void 		*object;
	void		*file_object;
        sf_mapping_t    *map_list;
        caddr_t		local_base;
	int		local_flags;
	int		caller_flags;
	int		i;
	vm_size_t	dummy;
	kern_return_t	kret;

	shared_region_mapping_t shared_region;
	struct shared_region_task_mappings	task_mapping_info;
	shared_region_mapping_t	next;

	ndp = &nd;

	unix_master();

	/* Retrieve the base address */
	if (error = copyin(base_address, &local_base, sizeof (caddr_t))) {
			goto lsf_bailout;
        }
	if (error = copyin(flags, &local_flags, sizeof (int))) {
			goto lsf_bailout;
        }
	caller_flags = local_flags;
	kret = kmem_alloc(kernel_map, (vm_offset_t *)&filename_str,
			(vm_size_t)(MAXPATHLEN));
		if (kret != KERN_SUCCESS) {
			error = ENOMEM;
			goto lsf_bailout;
		}
	kret = kmem_alloc(kernel_map, (vm_offset_t *)&map_list,
			(vm_size_t)(map_cnt*sizeof(sf_mapping_t)));
		if (kret != KERN_SUCCESS) {
			kmem_free(kernel_map, (vm_offset_t)filename_str, 
				(vm_size_t)(MAXPATHLEN));
			error = ENOMEM;
			goto lsf_bailout;
		}

	if (error = 
		copyin(mappings, map_list, (map_cnt*sizeof(sf_mapping_t)))) {
		goto lsf_bailout_free;
	}

	if (error = copyinstr(filename, 
			filename_str, MAXPATHLEN, (size_t *)&dummy)) {
		goto lsf_bailout_free;
	}

	/*
	 * Get a vnode for the target file
	 */
	NDINIT(ndp, LOOKUP, FOLLOW | LOCKLEAF, UIO_SYSSPACE,
	    filename_str, p);

	if ((error = namei(ndp))) {
		goto lsf_bailout_free;
	}

	vp = ndp->ni_vp;

	if (vp->v_type != VREG) {
		error = EINVAL;
		goto lsf_bailout_free_vput;
	}

	UBCINFOCHECK("load_shared_file", vp);

	if (error = VOP_GETATTR(vp, &vattr, p->p_ucred, p)) {
		goto lsf_bailout_free_vput;
	}


	file_object = ubc_getobject(vp, (UBC_NOREACTIVATE|UBC_HOLDOBJECT));
	if (file_object == (void *)NULL) {
		error = EINVAL;
		goto lsf_bailout_free_vput;
	}

#ifdef notdef
	if(vattr.va_size != mapped_file_size) {
		error = EINVAL;
		goto lsf_bailout_free_vput;
	}
#endif

	vm_get_shared_region(current_task(), &shared_region);
	task_mapping_info.self = (vm_offset_t)shared_region;

	shared_region_mapping_info(shared_region, 
			&(task_mapping_info.text_region), 
			&(task_mapping_info.text_size),
			&(task_mapping_info.data_region), 
			&(task_mapping_info.data_size), 
			&(task_mapping_info.region_mappings),
			&(task_mapping_info.client_base), 
			&(task_mapping_info.alternate_base),
			&(task_mapping_info.alternate_next), 
			&(task_mapping_info.flags), &next);

	/*  This is a work-around to allow executables which have been */
	/*  built without knowledge of the proper shared segment to    */
	/*  load.  This code has been architected as a shared region   */
	/*  handler, the knowledge of where the regions are loaded is  */
	/*  problematic for the extension of shared regions as it will */
	/*  not be easy to know what region an item should go into.    */
	/*  The code below however will get around a short term problem */
	/*  with executables which believe they are loading at zero.   */

	{
		if (((unsigned int)local_base & 
			(~(task_mapping_info.text_size - 1))) != 
			task_mapping_info.client_base) {
			if(local_flags & ALTERNATE_LOAD_SITE) {
				local_base = (caddr_t)(
					(unsigned int)local_base & 
					   (task_mapping_info.text_size - 1));
				local_base = (caddr_t)((unsigned int)local_base
					   | task_mapping_info.client_base);
			} else {
				error = EINVAL;
				goto lsf_bailout_free_vput;
			}
		}
	}

	/* load alternate regions if the caller has requested.  */
	/* Note: the new regions are "clean slates" */
	   
	if (local_flags & NEW_LOCAL_SHARED_REGIONS) {

		shared_region_mapping_t	new_shared_region;
		shared_region_mapping_t	old_shared_region;
		struct shared_region_task_mappings old_info;
		struct shared_region_task_mappings new_info;

		if(shared_file_create_system_region(&new_shared_region)) {
			error = ENOMEM;
			goto lsf_bailout_free_vput;
		}
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
			&(old_info.flags), &next);
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
			&(new_info.flags), &next);
		if (vm_map_region_replace(current_map(), old_info.text_region, 
				new_info.text_region, old_info.client_base, 
				old_info.client_base+old_info.text_size)) {
			panic("load_shared_file: shared region mis-alignment");
			shared_region_mapping_dealloc(new_shared_region);
			error = EINVAL;
			goto lsf_bailout_free_vput;
		}
		if(vm_map_region_replace(current_map(), old_info.data_region, 
				new_info.data_region, 
				old_info.client_base + old_info.text_size, 
				old_info.client_base
				+ old_info.text_size + old_info.data_size)) {
			panic("load_shared_file: shared region mis-alignment 1");
			shared_region_mapping_dealloc(new_shared_region);
			error = EINVAL;
			goto lsf_bailout_free_vput;
		}
		vm_set_shared_region(current_task(), new_shared_region);
		task_mapping_info = new_info;
		shared_region_mapping_dealloc(old_shared_region);
	}

	if((kr = copyin_shared_file((vm_offset_t)mapped_file_addr, 
			mapped_file_size, 
			(vm_offset_t *)&local_base,
			map_cnt, map_list, file_object, 
			&task_mapping_info, &local_flags))) {
		switch (kr) {
			case KERN_FAILURE:
				error = EINVAL;
				break;
			case KERN_INVALID_ARGUMENT:
				error = EINVAL;
				break;
			case KERN_INVALID_ADDRESS:
				error = EACCES;
				break;
			case KERN_PROTECTION_FAILURE:
				/* save EAUTH for authentication in this */
				/* routine */
				error = EPERM;
				break;
			case KERN_NO_SPACE:
				error = ENOMEM;
				break;
			default:
				error = EINVAL;
		};
		if((caller_flags & ALTERNATE_LOAD_SITE) && systemLogDiags) {
			printf("load_shared_file:  Failed to load shared file! error: 0x%x, Base_address: 0x%x, number of mappings: %d, file_object 0x%x\n", error, local_base, map_cnt, file_object);
			for(i=0; i<map_cnt; i++) {
				printf("load_shared_file: Mapping%d, mapping_offset: 0x%x, size: 0x%x, file_offset: 0x%x, protection: 0x%x\n"
					, i, map_list[i].mapping_offset, 
					map_list[i].size, 
					map_list[i].file_offset, 
					map_list[i].protection);
			}
		}
	} else {
		if(!(error = copyout(&local_flags, flags, sizeof (int)))) {
			error = copyout(&local_base, 
				base_address, sizeof (caddr_t));
		}
	}

lsf_bailout_free_vput:
	vput(vp);

lsf_bailout_free:
	kmem_free(kernel_map, (vm_offset_t)filename_str, 
				(vm_size_t)(MAXPATHLEN));
	kmem_free(kernel_map, (vm_offset_t)map_list, 
				(vm_size_t)(map_cnt*sizeof(sf_mapping_t)));

lsf_bailout:
	unix_release();
	return error;
}

struct reset_shared_file_args {
		caddr_t		*ba;
		int		map_cnt;
		sf_mapping_t	*mappings;
};

int
reset_shared_file(
	struct proc 		*p,
	struct reset_shared_file_args *uap,
	register		*retval)
{
        caddr_t		*base_address=uap->ba;
        int             map_cnt=uap->map_cnt;
        sf_mapping_t       *mappings=uap->mappings;
	register int		error;
	kern_return_t		kr;

        sf_mapping_t    *map_list;
        caddr_t		local_base;
	vm_offset_t	map_address;
	int		i;
	kern_return_t	kret;




	unix_master();

	/* Retrieve the base address */
	if (error = copyin(base_address, &local_base, sizeof (caddr_t))) {
			goto rsf_bailout;
        }

	if (((unsigned int)local_base & GLOBAL_SHARED_SEGMENT_MASK) 
					!= GLOBAL_SHARED_TEXT_SEGMENT) {
		error = EINVAL;
		goto rsf_bailout;
	}

	kret = kmem_alloc(kernel_map, (vm_offset_t *)&map_list,
			(vm_size_t)(map_cnt*sizeof(sf_mapping_t)));
		if (kret != KERN_SUCCESS) {
			error = ENOMEM;
			goto rsf_bailout;
		}

	if (error = 
		copyin(mappings, map_list, (map_cnt*sizeof(sf_mapping_t)))) {

		kmem_free(kernel_map, (vm_offset_t)map_list, 
				(vm_size_t)(map_cnt*sizeof(sf_mapping_t)));
		goto rsf_bailout;
	}
	for (i = 0; i<map_cnt; i++) {
		if((map_list[i].mapping_offset 
				& GLOBAL_SHARED_SEGMENT_MASK) == 0x10000000) {
			map_address = (vm_offset_t)
				(local_base + map_list[i].mapping_offset);
			vm_deallocate(current_map(), 
				map_address,
				map_list[i].size);
			vm_map(current_map(), &map_address,
				map_list[i].size, 0, SHARED_LIB_ALIAS,
				shared_data_region_handle, 
				((unsigned int)local_base 
				   & SHARED_DATA_REGION_MASK) +
					(map_list[i].mapping_offset 
					& SHARED_DATA_REGION_MASK),
				TRUE, VM_PROT_READ, 
				VM_PROT_READ, VM_INHERIT_SHARE);
		}
	}

	kmem_free(kernel_map, (vm_offset_t)map_list, 
				(vm_size_t)(map_cnt*sizeof(sf_mapping_t)));

rsf_bailout:
	unix_release();
	return error;
}




int
clone_system_shared_regions()
{
	shared_region_mapping_t	new_shared_region;
	shared_region_mapping_t	next;
	shared_region_mapping_t	old_shared_region;
	struct shared_region_task_mappings old_info;
	struct shared_region_task_mappings new_info;

	if (shared_file_create_system_region(&new_shared_region))
		return (ENOMEM);
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
		&(old_info.flags), &next);
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
		&(new_info.flags), &next);
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
	shared_region_object_chain_attach(new_shared_region, old_shared_region);
	return(0);

}
