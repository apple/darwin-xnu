/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
#include <sys/stat.h>

#include <kern/kalloc.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>

#include <machine/spl.h>

#include <mach/shared_memory_server.h>
#include <vm/vm_shared_memory_server.h>


extern zone_t lsf_zone;

useracc(addr, len, prot)
	caddr_t	addr;
	u_int	len;
	int	prot;
{
	return (vm_map_check_protection(
			current_map(),
			trunc_page_32((unsigned int)addr), round_page_32((unsigned int)(addr+len)),
			prot == B_READ ? VM_PROT_READ : VM_PROT_WRITE));
}

vslock(addr, len)
	caddr_t	addr;
	int	len;
{
kern_return_t kret;
	kret = vm_map_wire(current_map(), trunc_page_32((unsigned int)addr),
			round_page_32((unsigned int)(addr+len)), 
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
	kern_return_t kret;

#if FIXME  /* [ */
	if (dirtied) {
		pmap = get_task_pmap(current_task());
		for (vaddr = trunc_page((unsigned int)(addr)); vaddr < round_page((unsigned int)(addr+len));
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
	kret = vm_map_unwire(current_map(), trunc_page_32((unsigned int)(addr)),
				round_page_32((unsigned int)(addr+len)), FALSE);
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


kern_return_t
pid_for_task(t, x)
	mach_port_t	t;
	int	*x;
{
	struct proc * p;
	task_t		t1;
	extern task_t port_name_to_task(mach_port_t t);
	int	pid = -1;
	kern_return_t	err = KERN_SUCCESS;
	boolean_t funnel_state;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);
	t1 = port_name_to_task(t);

	if (t1 == TASK_NULL) {
		err = KERN_FAILURE;
		goto pftout;
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
pftout:
	(void) copyout((char *) &pid, (char *) x, sizeof(*x));
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
		return(KERN_FAILURE);
	} 

	funnel_state = thread_funnel_set(kernel_flock, TRUE);

 restart:
	p1 = get_bsdtask_info(t1);
	if (
		((p = pfind(pid)) != (struct proc *) 0)
		&& (p1 != (struct proc *) 0)
		&& (((p->p_ucred->cr_uid == p1->p_ucred->cr_uid) && 
			((p->p_cred->p_ruid == p1->p_cred->p_ruid)))
		|| !(suser(p1->p_ucred, &p1->p_acflag)))
		&& (p->p_stat != SZOMB)
		) {
			if (p->task != TASK_NULL) {
				if (!task_reference_try(p->task)) {
					mutex_pause(); /* temp loss of funnel */
					goto restart;
				}
				sright = (void *)convert_task_to_port(p->task);
				tret = (void *)
					ipc_port_copyout_send(sright, 
					   get_task_ipcspace(current_task()));
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

int	ws_disabled = 1;

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
	memory_object_control_t file_control;
        sf_mapping_t    *map_list;
        caddr_t		local_base;
	int		local_flags;
	int		caller_flags;
	int		i;
	int		default_regions = 0;
	vm_size_t	dummy;
	kern_return_t	kret;

	shared_region_mapping_t shared_region;
	struct shared_region_task_mappings	task_mapping_info;
	shared_region_mapping_t	next;

	ndp = &nd;


	/* Retrieve the base address */
	if (error = copyin(base_address, &local_base, sizeof (caddr_t))) {
			goto lsf_bailout;
        }
	if (error = copyin(flags, &local_flags, sizeof (int))) {
			goto lsf_bailout;
        }

	if(local_flags & QUERY_IS_SYSTEM_REGION) {
			shared_region_mapping_t	default_shared_region;
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
					&(task_mapping_info.fs_base),
					&(task_mapping_info.system),
					&(task_mapping_info.flags), &next);

			default_shared_region =
				lookup_default_shared_region(
					ENV_DEFAULT_ROOT, 
					task_mapping_info.system);
			if (shared_region == default_shared_region) {
				local_flags = SYSTEM_REGION_BACKED;
			} else {
				local_flags = 0;
			}
			shared_region_mapping_dealloc(default_shared_region);
			error = 0;
			error = copyout(&local_flags, flags, sizeof (int));
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


	file_control = ubc_getobject(vp, UBC_HOLDOBJECT);
	if (file_control == MEMORY_OBJECT_CONTROL_NULL) {
		error = EINVAL;
		goto lsf_bailout_free_vput;
	}

#ifdef notdef
	if(vattr.va_size != mapped_file_size) {
		error = EINVAL;
		goto lsf_bailout_free_vput;
	}
#endif
	if(p->p_flag & P_NOSHLIB) {
		p->p_flag = p->p_flag & ~P_NOSHLIB;
	}

	/* load alternate regions if the caller has requested.  */
	/* Note: the new regions are "clean slates" */
	if (local_flags & NEW_LOCAL_SHARED_REGIONS) {
		error = clone_system_shared_regions(FALSE, ENV_DEFAULT_ROOT);
		if (error) {
			goto lsf_bailout_free_vput;
		}
	}

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
			&(task_mapping_info.fs_base),
			&(task_mapping_info.system),
			&(task_mapping_info.flags), &next);

	{
		shared_region_mapping_t	default_shared_region;
		default_shared_region =
			lookup_default_shared_region(
				ENV_DEFAULT_ROOT, 
				task_mapping_info.system);
		if(shared_region == default_shared_region) {
			default_regions = 1;
		}
		shared_region_mapping_dealloc(default_shared_region);
	}
	/* If we are running on a removable file system we must not */
	/* be in a set of shared regions or the file system will not */
	/* be removable. */
	if(((vp->v_mount != rootvnode->v_mount) && (default_regions)) 
		&& (lsf_mapping_pool_gauge() < 75)) {
				/* We don't want to run out of shared memory */
				/* map entries by starting too many private versions */
				/* of the shared library structures */
		int	error;
       		if(p->p_flag & P_NOSHLIB) {
				error = clone_system_shared_regions(FALSE, ENV_DEFAULT_ROOT);
       		} else {
				error = clone_system_shared_regions(TRUE, ENV_DEFAULT_ROOT);
       		}
		if (error) {
			goto lsf_bailout_free_vput;
		}
		local_flags = local_flags & ~NEW_LOCAL_SHARED_REGIONS;
		vm_get_shared_region(current_task(), &shared_region);
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
			&(task_mapping_info.flags), &next);
	}

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


	if((kr = copyin_shared_file((vm_offset_t)mapped_file_addr, 
			mapped_file_size, 
			(vm_offset_t *)&local_base,
			map_cnt, map_list, file_control, 
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
			printf("load_shared_file:  Failed to load shared file! error: 0x%x, Base_address: 0x%x, number of mappings: %d, file_control 0x%x\n", error, local_base, map_cnt, file_control);
			for(i=0; i<map_cnt; i++) {
				printf("load_shared_file: Mapping%d, mapping_offset: 0x%x, size: 0x%x, file_offset: 0x%x, protection: 0x%x\n"
					, i, map_list[i].mapping_offset, 
					map_list[i].size, 
					map_list[i].file_offset, 
					map_list[i].protection);
			}
		}
	} else {
		if(default_regions)
			local_flags |= SYSTEM_REGION_BACKED;
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
	return error;
}

struct new_system_shared_regions_args {
	int dummy;
};

int
new_system_shared_regions(
	struct proc 		*p,
	struct new_system_shared_regions_args *uap,
	register		*retval)
{
	shared_region_mapping_t	regions;
	shared_region_mapping_t	new_regions;

	if(!(is_suser())) {
	 	*retval = EINVAL;
		return EINVAL;
	}

	/* clear all of our existing defaults */
	remove_all_shared_regions();

	*retval = 0;
	return 0;
}



int
clone_system_shared_regions(shared_regions_active, base_vnode)
{
	shared_region_mapping_t	new_shared_region;
	shared_region_mapping_t	next;
	shared_region_mapping_t	old_shared_region;
	struct shared_region_task_mappings old_info;
	struct shared_region_task_mappings new_info;

	struct proc	*p;

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
	   shared_region_object_chain_attach(
				new_shared_region, old_shared_region);
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
	if(!shared_regions_active)
		shared_region_mapping_dealloc(old_shared_region);

	return(0);

}

extern vm_map_t bsd_pageable_map;

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

struct global_profile_cache global_user_profile_cache =
	{3, 0, NULL, NULL, NULL, 0, 0, 0,
		NULL, NULL, NULL, 0, 0, 0,
		NULL, NULL, NULL, 0, 0, 0 };

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
	char		*cache_path = "/var/vm/app_profile/";
	struct proc	*p;
	int		error;
	int		resid;
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

	struct vattr	vattr;

	struct	profile_names_header *profile_header;
	kern_return_t	ret;

	struct nameidata nd_names;
	struct nameidata nd_data;

	int		i;


	p = current_proc();

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
			vrele((*profile)->names_vp);
			(*profile)->names_vp = NULL;
		}
		vrele(data_vp);
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
			UIO_SYSSPACE, profile_names_string, p);
	NDINIT(&nd_data, LOOKUP, FOLLOW | LOCKLEAF, 
			UIO_SYSSPACE, profile_data_string, p);
	if (error = vn_open(&nd_data, FREAD | FWRITE, 0)) {
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
	VOP_UNLOCK(data_vp, 0, p);

	if (error = vn_open(&nd_names, FREAD | FWRITE, 0)) {
		printf("bsd_open_page_cache_files: NamesData file not found %s\n",
			profile_data_string);
		kmem_free(kernel_map, 
				(vm_offset_t)names_buf, 4 * PAGE_SIZE);
		kmem_free(kernel_map, 
			(vm_offset_t)profile_data_string, PATH_MAX);
		vrele(data_vp);
		(*profile)->data_vp = NULL;
		(*profile)->busy = 0;
		wakeup(*profile);
		return error;
	}
	names_vp = nd_names.ni_vp;

	if(error = VOP_GETATTR(names_vp, &vattr, p->p_ucred, p)) {
		printf("bsd_open_page_cache_files: Can't stat name file %s\n", profile_names_string);
		kmem_free(kernel_map, 
			(vm_offset_t)profile_data_string, PATH_MAX);
		kmem_free(kernel_map, 
			(vm_offset_t)names_buf, 4 * PAGE_SIZE);
		vput(names_vp);
		vrele(data_vp);
		(*profile)->data_vp = NULL;
		(*profile)->busy = 0;
		wakeup(*profile);
		return error;
	}

	size = vattr.va_size;
	if(size > 4 * PAGE_SIZE) 
		size = 4 * PAGE_SIZE;
	buf_ptr = names_buf;
	resid_off = 0;

	while(size) {
		error = vn_rdwr(UIO_READ, names_vp, (caddr_t)buf_ptr, 
			size, resid_off,
			UIO_SYSSPACE, IO_NODELOCKED, p->p_ucred, &resid, p);
		if((error) || (size == resid)) {
			if(!error) {
				error = EINVAL;
			}
			kmem_free(kernel_map, 
				(vm_offset_t)profile_data_string, PATH_MAX);
			kmem_free(kernel_map, 
				(vm_offset_t)names_buf, 4 * PAGE_SIZE);
			vput(names_vp);
			vrele(data_vp);
			(*profile)->data_vp = NULL;
			(*profile)->busy = 0;
			wakeup(*profile);
			return error;
		}
		buf_ptr += size-resid;
		resid_off += size-resid;
		size = resid;
	}
	
	VOP_UNLOCK(names_vp, 0, p);
	kmem_free(kernel_map, (vm_offset_t)profile_data_string, PATH_MAX);
	(*profile)->names_vp = names_vp;
	(*profile)->data_vp = data_vp;
	(*profile)->buf_ptr = names_buf;
	return 0;

}

void
bsd_close_page_cache_files(
	struct global_profile *profile)
{
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
	vm_offset_t	*buf_size)
{

	boolean_t		funnel_state;

	struct proc	*p;
	int		error;
	int		resid;
	vm_size_t	size;

	off_t		profile;
	unsigned int	profile_size;

	vm_offset_t	names_buf;
	struct vattr	vattr;

	kern_return_t	ret;

	struct	vnode	*names_vp;
	struct	vnode	*data_vp;
	struct	vnode	*vp1;
	struct	vnode	*vp2;

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


	/* 
	 * Get locks on both files, get the vnode with the lowest address first
	 */

	if((unsigned int)names_vp < (unsigned int)data_vp) {
		vp1 = names_vp;
		vp2 = data_vp;
	} else {
		vp1 = data_vp;
		vp2 = names_vp;
	}
	error = vn_lock(vp1, LK_EXCLUSIVE | LK_RETRY, p);
	if(error) {
		printf("bsd_read_page_cache_file: Can't lock profile names %x\n", user);
		bsd_close_page_cache_files(uid_files);
		thread_funnel_set(kernel_flock, funnel_state);
		return error;
	}
	error = vn_lock(vp2, LK_EXCLUSIVE | LK_RETRY, p);
	if(error) {
		printf("bsd_read_page_cache_file: Can't lock profile data %x\n", user);
		VOP_UNLOCK(vp1, 0, p);
		bsd_close_page_cache_files(uid_files);
		thread_funnel_set(kernel_flock, funnel_state);
		return error;
	}

	if(error = VOP_GETATTR(app_vp, &vattr, p->p_ucred, p)) {
		VOP_UNLOCK(names_vp, 0, p);
		VOP_UNLOCK(data_vp, 0, p);
		printf("bsd_read_cache_file: Can't stat app file %s\n", app_name);
		bsd_close_page_cache_files(uid_files);
		thread_funnel_set(kernel_flock, funnel_state);
		return error;
	}

	*fid = vattr.va_fileid;
	*mod = vattr.va_mtime.tv_sec;
		

	if (bsd_search_page_cache_data_base(names_vp, names_buf, app_name, 
			(unsigned int) vattr.va_mtime.tv_sec,  
			vattr.va_fileid, &profile, &profile_size) == 0) {
		/* profile is an offset in the profile data base */
		/* It is zero if no profile data was found */
		
		if(profile_size == 0) {
			*buffer = NULL;
			*buf_size = 0;
			VOP_UNLOCK(names_vp, 0, p);
			VOP_UNLOCK(data_vp, 0, p);
			bsd_close_page_cache_files(uid_files);
			thread_funnel_set(kernel_flock, funnel_state);
			return 0;
		}
		ret = (vm_offset_t)(kmem_alloc(kernel_map, buffer, profile_size));
		if(ret) {
			VOP_UNLOCK(names_vp, 0, p);
			VOP_UNLOCK(data_vp, 0, p);
			bsd_close_page_cache_files(uid_files);
			thread_funnel_set(kernel_flock, funnel_state);
			return ENOMEM;
		}
		*buf_size = profile_size;
		while(profile_size) {
			error = vn_rdwr(UIO_READ, data_vp, 
				(caddr_t) *buffer, profile_size, 
				profile, UIO_SYSSPACE, IO_NODELOCKED, 
				p->p_ucred, &resid, p);
			if((error) || (profile_size == resid)) {
				VOP_UNLOCK(names_vp, 0, p);
				VOP_UNLOCK(data_vp, 0, p);
				bsd_close_page_cache_files(uid_files);
				kmem_free(kernel_map, (vm_offset_t)*buffer, profile_size);
				thread_funnel_set(kernel_flock, funnel_state);
				return EINVAL;
			}
		        profile += profile_size - resid;
			profile_size = resid;
		}
		VOP_UNLOCK(names_vp, 0, p);
		VOP_UNLOCK(data_vp, 0, p);
		bsd_close_page_cache_files(uid_files);
		thread_funnel_set(kernel_flock, funnel_state);
		return 0;
	} else {
		VOP_UNLOCK(names_vp, 0, p);
		VOP_UNLOCK(data_vp, 0, p);
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
	int			resid;
	vm_offset_t		local_buf = NULL;

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
					if(local_buf != NULL) {
						kmem_free(kernel_map, 
							(vm_offset_t)local_buf, 4 * PAGE_SIZE);
					}
					return 0;
				}
			}
		}
		if(extended_list == 0)
			break;
		if(local_buf == NULL) {
			ret = kmem_alloc(kernel_map,
               	 		(vm_offset_t *)&local_buf, 4 * PAGE_SIZE);
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
				size, file_off + resid_off, UIO_SYSSPACE, 
				IO_NODELOCKED, p->p_ucred, &resid, p);
			if((error) || (size == resid)) {
				if(local_buf != NULL) {
					kmem_free(kernel_map, 
						(vm_offset_t)local_buf, 
						4 * PAGE_SIZE);
				}
				return EINVAL;
			}
			resid_off += size-resid;
			size = resid;
		}
	}
	if(local_buf != NULL) {
		kmem_free(kernel_map, 
			(vm_offset_t)local_buf, 4 * PAGE_SIZE);
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
	struct nameidata	nd;
	struct vnode		*vp = 0; 
	int			resid;
	off_t			resid_off;
	int			error;
	boolean_t		funnel_state;
	struct vattr		vattr;
	struct vattr		data_vattr;

	off_t				profile;
	unsigned int			profile_size;

	vm_offset_t	names_buf;
	struct	vnode	*names_vp;
	struct	vnode	*data_vp;
	struct	vnode	*vp1;
	struct	vnode	*vp2;

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

	/* 
	 * Get locks on both files, get the vnode with the lowest address first
	 */

	if((unsigned int)names_vp < (unsigned int)data_vp) {
		vp1 = names_vp;
		vp2 = data_vp;
	} else {
		vp1 = data_vp;
		vp2 = names_vp;
	}

	error = vn_lock(vp1, LK_EXCLUSIVE | LK_RETRY, p);
	if(error) {
		printf("bsd_write_page_cache_file: Can't lock profile names %x\n", user);
		bsd_close_page_cache_files(uid_files);
		thread_funnel_set(kernel_flock, funnel_state);
		return error;
	}
	error = vn_lock(vp2, LK_EXCLUSIVE | LK_RETRY, p);
	if(error) {
		printf("bsd_write_page_cache_file: Can't lock profile data %x\n", user);
		VOP_UNLOCK(vp1, 0, p);
		bsd_close_page_cache_files(uid_files);
		thread_funnel_set(kernel_flock, funnel_state);
		return error;
	}

	/* Stat data file for size */

	if(error = VOP_GETATTR(data_vp, &data_vattr, p->p_ucred, p)) {
		VOP_UNLOCK(names_vp, 0, p);
		VOP_UNLOCK(data_vp, 0, p);
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
				name->addr =  data_vattr.va_size;
				name->size = size;
				name->mod_date = mod;
				name->inode = fid;
				strncpy (name->name, file_name, 12);
			} else {
				unsigned int	ele_size;
				struct profile_element	name;
				/* write new entry */
				name.addr = data_vattr.va_size;
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
						UIO_SYSSPACE, IO_NODELOCKED, 
						p->p_ucred, &resid, p);
					if(error) {
						printf("bsd_write_page_cache_file: Can't write name_element %x\n", user);
						VOP_UNLOCK(names_vp, 0, p);
						VOP_UNLOCK(data_vp, 0, p);
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
					UIO_SYSSPACE, IO_NODELOCKED, 
					p->p_ucred, &resid, p);
				if(error) {
					VOP_UNLOCK(names_vp, 0, p);
					VOP_UNLOCK(data_vp, 0, p);
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
			resid_off = data_vattr.va_size;
			while(size) {
				error = vn_rdwr(UIO_WRITE, data_vp, 
					(caddr_t)buffer, size, resid_off, 
					UIO_SYSSPACE, IO_NODELOCKED, 
					p->p_ucred, &resid, p);
				if(error) {
					VOP_UNLOCK(names_vp, 0, p);
					VOP_UNLOCK(data_vp, 0, p);
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
			VOP_UNLOCK(names_vp, 0, p);
			VOP_UNLOCK(data_vp, 0, p);
			bsd_close_page_cache_files(uid_files);
			thread_funnel_set(kernel_flock, funnel_state);
			return 0;
		}
		/* Someone else wrote a twin profile before us */
		VOP_UNLOCK(names_vp, 0, p);
		VOP_UNLOCK(data_vp, 0, p);
		bsd_close_page_cache_files(uid_files);
		thread_funnel_set(kernel_flock, funnel_state);
		return 0;
	} else {		
		VOP_UNLOCK(names_vp, 0, p);
		VOP_UNLOCK(data_vp, 0, p);
		bsd_close_page_cache_files(uid_files);
		thread_funnel_set(kernel_flock, funnel_state);
		return EINVAL;
	}
	
}

int
prepare_profile_database(int	user)
{
	char		*cache_path = "/var/vm/app_profile/";
	struct proc	*p;
	int		error;
	int		resid;
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

	struct vattr	vattr;

	struct	profile_names_header *profile_header;
	kern_return_t	ret;

	struct nameidata nd_names;
	struct nameidata nd_data;

	int		i;

	p = current_proc();

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
			UIO_SYSSPACE, profile_names_string, p);
	NDINIT(&nd_data, LOOKUP, FOLLOW,
			UIO_SYSSPACE, profile_data_string, p);

	if (error = vn_open(&nd_data, 
			O_CREAT | O_EXCL | FWRITE, S_IRUSR|S_IWUSR)) {
			kmem_free(kernel_map, 
					(vm_offset_t)names_buf, 4 * PAGE_SIZE);
			kmem_free(kernel_map, 
				(vm_offset_t)profile_data_string, PATH_MAX);
			return 0;
	}

	data_vp = nd_data.ni_vp;
	VOP_UNLOCK(data_vp, 0, p);

	if (error = vn_open(&nd_names, 
			O_CREAT | O_EXCL | FWRITE, S_IRUSR|S_IWUSR)) {
			printf("prepare_profile_database: Can't create CacheNames %s\n",
				profile_data_string);
			kmem_free(kernel_map, 
					(vm_offset_t)names_buf, 4 * PAGE_SIZE);
			kmem_free(kernel_map, 
				(vm_offset_t)profile_data_string, PATH_MAX);
			vrele(data_vp);
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
				UIO_SYSSPACE, IO_NODELOCKED, 
				p->p_ucred, &resid, p);
		if(error) {
			printf("prepare_profile_database: Can't write header %s\n", profile_names_string);
			kmem_free(kernel_map, 
				(vm_offset_t)names_buf, 4 * PAGE_SIZE);
			kmem_free(kernel_map, 
				(vm_offset_t)profile_data_string, 
				PATH_MAX);
			vput(names_vp);
			vrele(data_vp);
			return error;
		}
		buf_ptr += size-resid;
		resid_off += size-resid;
		size = resid;
	}

	VATTR_NULL(&vattr);
	vattr.va_uid = user;
       	error = VOP_SETATTR(names_vp, &vattr, p->p_cred->pc_ucred, p);
	if(error) {
		printf("prepare_profile_database: "
			"Can't set user %s\n", profile_names_string);
	}
	vput(names_vp);
	
	error = vn_lock(data_vp, LK_EXCLUSIVE | LK_RETRY, p);
	if(error) {
		vrele(data_vp);
		printf("prepare_profile_database: cannot lock data file %s\n",
			profile_data_string);
		kmem_free(kernel_map, 
			(vm_offset_t)profile_data_string, PATH_MAX);
		kmem_free(kernel_map, 
			(vm_offset_t)names_buf, 4 * PAGE_SIZE);
	}
	VATTR_NULL(&vattr);
	vattr.va_uid = user;
       	error = VOP_SETATTR(data_vp, &vattr, p->p_cred->pc_ucred, p);
	if(error) {
		printf("prepare_profile_database: "
			"Can't set user %s\n", profile_data_string);
	}
	
	vput(data_vp);
	kmem_free(kernel_map, 
			(vm_offset_t)profile_data_string, PATH_MAX);
	kmem_free(kernel_map, 
			(vm_offset_t)names_buf, 4 * PAGE_SIZE);
	return 0;

}
