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
 *	Copyright (C) 1988, 1989,  NeXT, Inc.
 *
 *	File:	kern/mach_loader.c
 *	Author:	Avadis Tevanian, Jr.
 *
 *	Mach object file loader (kernel version, for now).
 *
 * 21-Jul-88  Avadis Tevanian, Jr. (avie) at NeXT
 *	Started.
 */
#include <sys/param.h>
#include <sys/vnode.h>
#include <sys/uio.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/fcntl.h>
#include <sys/ubc.h>

#include <ufs/ufs/lockf.h>
#include <ufs/ufs/quota.h>
#include <ufs/ufs/inode.h>

#include <mach/mach_types.h>

#include <kern/mach_loader.h>

#include <mach-o/fat.h>
#include <mach-o/loader.h>

#include <kern/cpu_number.h>

#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_pager.h>
#include <vm/vnode_pager.h>
#include <mach/shared_memory_server.h>
#include <mach/vm_statistics.h>

/*
 * Prototypes of static functions.
 */
static
load_return_t
parse_machfile(
	struct vnode		*vp,
	vm_map_t		map,
	struct mach_header	*header,
	unsigned long		file_offset,
	unsigned long		macho_size,
	int			depth,
	unsigned long		*lib_version,
	load_result_t		*result
),
load_segment(
	struct segment_command	*scp,
	void * 			pager,
	unsigned long		pager_offset,
	unsigned long		macho_size,
	unsigned long		end_of_file,
	vm_map_t		map,
	load_result_t		*result
),
load_unixthread(
	struct thread_command	*tcp,
	load_result_t		*result
),
load_thread(
	struct thread_command	*tcp,
	load_result_t		*result
),
load_threadstate(
	thread_t	thread,
	unsigned long	*ts,
	unsigned long	total_size
),
load_threadstack(
	thread_t	thread,
	unsigned long	*ts,
	unsigned long	total_size,
	vm_offset_t	*user_stack
),
load_threadentry(
	thread_t	thread,
	unsigned long	*ts,
	unsigned long	total_size,
	vm_offset_t	*entry_point
),
load_fvmlib(
	struct fvmlib_command	*lcp,
	vm_map_t		map,
	int			depth
),
load_idfvmlib(
	struct fvmlib_command	*lcp,
	unsigned long		*version
),
load_dylinker(
	struct dylinker_command	*lcp,
	vm_map_t		map,
	int			depth,
	load_result_t		*result
),
get_macho_vnode(
	char			*path,
	struct mach_header	*mach_header,
	unsigned long		*file_offset,
	unsigned long		*macho_size,
	struct vnode		**vpp
);

load_return_t
load_machfile(
	struct vnode		*vp,
	struct mach_header	*header,
	unsigned long		file_offset,
	unsigned long		macho_size,
	load_result_t		*result
)
{
	pmap_t			pmap;
	vm_map_t		map;
	vm_map_t		old_map;
	load_result_t		myresult;
	kern_return_t		kret;
	load_return_t		lret;

	old_map = current_map();
#ifdef i386
	pmap = get_task_pmap(current_task());
	pmap_reference(pmap);
#else
	pmap = pmap_create((vm_size_t) 0);
#endif
	map = vm_map_create(pmap,
			get_map_min(old_map),
			get_map_max(old_map),
			TRUE); /**** FIXME ****/

	if (!result)
		result = &myresult;

	*result = (load_result_t) { 0 };

	lret = parse_machfile(vp, map, header, file_offset, macho_size,
			     0, (unsigned long *)0, result);

	if (lret != LOAD_SUCCESS) {
		vm_map_deallocate(map);	/* will lose pmap reference too */
		return(lret);
	}
	/*
	 *	Commit to new map.  First make sure that the current
	 *	users of the task get done with it, and that we clean
	 *	up the old contents of IPC and memory.  The task is
	 *	guaranteed to be single threaded upon return (us).
	 *
	 *	Swap the new map for the old at the task level and at
	 *	our activation.  The latter consumes our new map reference
	 *	but each leaves us responsible for the old_map reference.
	 *	That lets us get off the pmap associated with it, and
	 *	then we can release it.
	 */
	task_halt(current_task());

	old_map = swap_task_map(current_task(), map);
	vm_map_deallocate(old_map);

	old_map = swap_act_map(current_act(), map);

#ifndef i386
	pmap_switch(pmap);	/* Make sure we are using the new pmap */
#endif

	vm_map_deallocate(old_map);
	return(LOAD_SUCCESS);
}

int	dylink_test = 1;
extern	vm_offset_t	system_shared_region;

static
load_return_t
parse_machfile(
	struct vnode		*vp,
	vm_map_t		map,
	struct mach_header	*header,
	unsigned long		file_offset,
	unsigned long		macho_size,
	int			depth,
	unsigned long		*lib_version,
	load_result_t		*result
)
{
	struct machine_slot	*ms;
	int			ncmds;
	struct load_command	*lcp, *next;
	struct dylinker_command	*dlp = 0;
	void *			pager;
	load_return_t		ret;
	vm_offset_t		addr, kl_addr;
	vm_size_t		size,kl_size;
	int			offset;
	int			pass;
	struct proc *p = current_proc();		/* XXXX */
	int			error;
	int resid=0;

	/*
	 *	Break infinite recursion
	 */
	if (depth > 6)
		return(LOAD_FAILURE);
	depth++;

	/*
	 *	Check to see if right machine type.
	 */
	ms = &machine_slot[cpu_number()];
	if ((header->cputype != ms->cpu_type) ||
	    !check_cpu_subtype(header->cpusubtype))
		return(LOAD_BADARCH);
		
	switch (header->filetype) {
	
	case MH_OBJECT:
	case MH_EXECUTE:
	case MH_PRELOAD:
		if (depth != 1)
			return (LOAD_FAILURE);
		break;
		
	case MH_FVMLIB:
	case MH_DYLIB:
		if (depth == 1)
			return (LOAD_FAILURE);
		break;

	case MH_DYLINKER:
		if (depth != 2)
			return (LOAD_FAILURE);
		break;
		
	default:
		return (LOAD_FAILURE);
	}

	/*
	 *	Get the pager for the file.
	 */
	UBCINFOCHECK("parse_machfile", vp);
	pager = (void *) ubc_getpager(vp);

	/*
	 *	Map portion that must be accessible directly into
	 *	kernel's map.
	 */
	if ((sizeof (struct mach_header) + header->sizeofcmds) > macho_size)
		return(LOAD_BADMACHO);

	/*
	 *	Round size of Mach-O commands up to page boundry.
	 */
	size = round_page(sizeof (struct mach_header) + header->sizeofcmds);
	if (size <= 0)
		return(LOAD_BADMACHO);

	/*
	 * Map the load commands into kernel memory.
	 */
	addr = 0;
#if 0 /* [
#if FIXME
	ret = vm_allocate_with_pager(kernel_map, &addr, size, TRUE, pager,
				     file_offset);
#else
	ret = vm_map(kernel_map,&addr,size,0,TRUE, pager, file_offset, FALSE,
			VM_PROT_DEFAULT, VM_PROT_ALL, VM_INHERIT_DEFAULT);
#endif /* FIXME */
	if (ret != KERN_SUCCESS) {
		return(LOAD_NOSPACE);
	}
	ubc_map(vp);
#else /* 0 ][ */
	kl_size = size;
	kl_addr = kalloc(size);
	addr = kl_addr;
	if (addr == NULL)  {
		printf("No space to readin load commands\n");
		return(LOAD_NOSPACE);
	}
	if(error = vn_rdwr(UIO_READ, vp, addr, size, file_offset,
	    UIO_SYSSPACE, 0, p->p_ucred, &resid, p)) {
		printf("Load command read over nfs failed\n");
		if (kl_addr ) kfree(kl_addr,kl_size);
		return(EIO);
	}
	/* ubc_map(vp); */ /* NOT HERE */
	
#endif /* 0 ] */
	/*
	 *	Scan through the commands, processing each one as necessary.
	 */
	for (pass = 1; pass <= 2; pass++) {
		offset = sizeof(struct mach_header);
		ncmds = header->ncmds;
		while (ncmds--) {
			/*
			 *	Get a pointer to the command.
			 */
			lcp = (struct load_command *)(addr + offset);
			offset += lcp->cmdsize;

			/*
			 *	Check for valid lcp pointer by checking
			 *	next offset.
			 */
			if (offset > header->sizeofcmds
					+ sizeof(struct mach_header)) {
#if 0
				vm_map_remove(kernel_map, addr, addr + size);
#endif
				if (kl_addr ) kfree(kl_addr,kl_size);
				return(LOAD_BADMACHO);
			}

			/*
			 *	Check for valid command.
			 */
			switch(lcp->cmd) {
			case LC_SEGMENT:
				if (pass != 1)
					break;
				ret = load_segment(
					       (struct segment_command *) lcp,
						   pager, file_offset,
						   macho_size,
						   (unsigned long)ubc_getsize(vp),
						   map,
						   result);
				break;
			case LC_THREAD:
				if (pass != 2)
					break;
				ret = load_thread((struct thread_command *)lcp,
						  result);
				break;
			case LC_UNIXTHREAD:
				if (pass != 2)
					break;
				ret = load_unixthread(
						 (struct thread_command *) lcp,
						 result);
				break;
			case LC_LOADFVMLIB:
				if (pass != 1)
					break;
				ret = load_fvmlib((struct fvmlib_command *)lcp,
						  map, depth);
				break;
			case LC_IDFVMLIB:
				if (pass != 1)
					break;
				if (lib_version) {
					ret = load_idfvmlib(
						(struct fvmlib_command *)lcp,
						lib_version);
				}
				break;
			case LC_LOAD_DYLINKER:
				if (pass != 2)
					break;
				if (depth == 1 || dlp == 0)
					dlp = (struct dylinker_command *)lcp;
				else
					ret = LOAD_FAILURE;
				break;
			default:
				ret = KERN_SUCCESS;/* ignore other stuff */
			}
			if (ret != LOAD_SUCCESS)
				break;
		}
		if (ret != LOAD_SUCCESS)
			break;
	}
	if (ret == LOAD_SUCCESS && dlp != 0) {
		vm_offset_t addr;
		shared_region_mapping_t shared_region;
		struct shared_region_task_mappings	map_info;
		shared_region_mapping_t next;

RedoLookup:
		vm_get_shared_region(current_task(), &shared_region);
		map_info.self = (vm_offset_t)shared_region;
		shared_region_mapping_info(shared_region,
			&(map_info.text_region),   
			&(map_info.text_size),
			&(map_info.data_region),
			&(map_info.data_size),
			&(map_info.region_mappings),
			&(map_info.client_base),
			&(map_info.alternate_base),
			&(map_info.alternate_next), 
			&(map_info.flags), &next);

		if((map_info.flags & SHARED_REGION_FULL) &&
			(map_info.flags & SHARED_REGION_SYSTEM)) {
			if(map_info.self != (vm_offset_t)system_shared_region) {
				shared_region_mapping_ref(system_shared_region);
				vm_set_shared_region(current_task(), 
							system_shared_region);
				shared_region_mapping_dealloc(
					(shared_region_mapping_t)map_info.self);
				goto RedoLookup;
			}
		}


		if (dylink_test) {
			addr = map_info.client_base;
			vm_map(map, &addr, map_info.text_size, 0, 
				(VM_MEMORY_SHARED_PMAP << 24) 
						| SHARED_LIB_ALIAS,
				map_info.text_region, 0, FALSE,
				VM_PROT_READ, VM_PROT_READ, VM_INHERIT_SHARE);
			addr = map_info.client_base + map_info.text_size;
			vm_map(map, &addr, map_info.data_size, 
				0, SHARED_LIB_ALIAS,
				map_info.data_region, 0, TRUE,
				VM_PROT_READ, VM_PROT_READ, VM_INHERIT_SHARE);
		}
		ret = load_dylinker(dlp, map, depth, result);
	}

	if (kl_addr ) kfree(kl_addr,kl_size);
#if 0
	vm_map_remove(kernel_map, addr, addr + size);
#endif
	if ((ret == LOAD_SUCCESS) && (depth == 1) &&
				(result->thread_count == 0))
		ret = LOAD_FAILURE;
	if (ret == LOAD_SUCCESS)
		ubc_map(vp);
		
	return(ret);
}

static
load_return_t
load_segment(
	struct segment_command	*scp,
	void *			pager,
	unsigned long		pager_offset,
	unsigned long		macho_size,
	unsigned long		end_of_file,
	vm_map_t		map,
	load_result_t		*result
)
{
	kern_return_t		ret;
	vm_offset_t		map_addr, map_offset;
	vm_size_t		map_size, seg_size, delta_size;
	caddr_t			tmp;
	vm_prot_t 		initprot;
	vm_prot_t		maxprot;
#if 1
	extern int print_map_addr;
#endif /* 1 */

	/*
	 * Make sure what we get from the file is really ours (as specified
	 * by macho_size).
	 */
	if (scp->fileoff + scp->filesize > macho_size)
		return (LOAD_BADMACHO);

	seg_size = round_page(scp->vmsize);
	if (seg_size == 0)
		return(KERN_SUCCESS);

	/*
	 *	Round sizes to page size.
	 */
	map_size = round_page(scp->filesize);
	map_addr = trunc_page(scp->vmaddr);

	map_offset = pager_offset + scp->fileoff;

	if (map_size > 0) {
		initprot = (scp->initprot) & VM_PROT_ALL;
		maxprot = (scp->maxprot) & VM_PROT_ALL;
		/*
		 *	Map a copy of the file into the address space.
		 */
		ret = vm_map(map,
				&map_addr, map_size, (vm_offset_t)0, FALSE,
				pager, map_offset, TRUE,
				initprot, maxprot,
				VM_INHERIT_DEFAULT);
		if (ret != KERN_SUCCESS)
			return(LOAD_NOSPACE);
	
#if 1
		if (print_map_addr)
			printf("LSegment: Mapped addr= %x; size = %x\n", map_addr, map_size);
#endif /* 1 */
		/*
		 *	If the file didn't end on a page boundary,
		 *	we need to zero the leftover.
		 */
		delta_size = map_size - scp->filesize;
#if FIXME
		if (delta_size > 0) {
			vm_offset_t	tmp;
	
			ret = vm_allocate(kernel_map, &tmp, delta_size, TRUE);
			if (ret != KERN_SUCCESS)
				return(LOAD_RESOURCE);
	
			if (copyout(tmp, map_addr + scp->filesize,
								delta_size)) {
				(void) vm_deallocate(
						kernel_map, tmp, delta_size);
				return(LOAD_FAILURE);
			}
			
			(void) vm_deallocate(kernel_map, tmp, delta_size);
		}
#endif /* FIXME */
	}

	/*
	 *	If the virtual size of the segment is greater
	 *	than the size from the file, we need to allocate
	 *	zero fill memory for the rest.
	 */
	delta_size = seg_size - map_size;
	if (delta_size > 0) {
		vm_offset_t	tmp = map_addr + map_size;

		ret = vm_allocate(map, &tmp, delta_size, FALSE);
		if (ret != KERN_SUCCESS)
			return(LOAD_NOSPACE);
	}

	/*
	 *	Set protection values. (Note: ignore errors!)
	 */

	if (scp->maxprot != VM_PROT_DEFAULT) {
		(void) vm_protect(map,
					map_addr, seg_size,
					TRUE, scp->maxprot);
	}
	if (scp->initprot != VM_PROT_DEFAULT) {
		(void) vm_protect(map,
				      map_addr, seg_size,
				      FALSE, scp->initprot);
	}
	if ( (scp->fileoff == 0) && (scp->filesize != 0) )
		result->mach_header = map_addr;
	return(LOAD_SUCCESS);
}

static
load_return_t
load_unixthread(
	struct thread_command	*tcp,
	load_result_t		*result
)
{
	thread_t	thread = current_thread();
	load_return_t	ret;
	
	if (result->thread_count != 0)
		return (LOAD_FAILURE);
	
	ret = load_threadstack(thread,
		       (unsigned long *)(((vm_offset_t)tcp) + 
		       		sizeof(struct thread_command)),
		       tcp->cmdsize - sizeof(struct thread_command),
		       &result->user_stack);
	if (ret != LOAD_SUCCESS)
		return(ret);

	ret = load_threadentry(thread,
		       (unsigned long *)(((vm_offset_t)tcp) + 
		       		sizeof(struct thread_command)),
		       tcp->cmdsize - sizeof(struct thread_command),
		       &result->entry_point);
	if (ret != LOAD_SUCCESS)
		return(ret);

	ret = load_threadstate(thread,
		       (unsigned long *)(((vm_offset_t)tcp) + 
		       		sizeof(struct thread_command)),
		       tcp->cmdsize - sizeof(struct thread_command));
	if (ret != LOAD_SUCCESS)
		return (ret);

	result->unixproc = TRUE;
	result->thread_count++;

	return(LOAD_SUCCESS);
}

static
load_return_t
load_thread(
	struct thread_command	*tcp,
	load_result_t		*result
)
{
	thread_t	thread;
	kern_return_t	kret;
	load_return_t	lret;

	if (result->thread_count == 0)
		thread = current_thread();
	else {
		kret = thread_create(current_task(), &thread);
		if (kret != KERN_SUCCESS)
			return(LOAD_RESOURCE);
		thread_deallocate(thread);
	}

	lret = load_threadstate(thread,
		       (unsigned long *)(((vm_offset_t)tcp) + 
		       		sizeof(struct thread_command)),
		       tcp->cmdsize - sizeof(struct thread_command));
	if (lret != LOAD_SUCCESS)
		return (lret);

	if (result->thread_count == 0) {
		lret = load_threadstack(current_thread(),
				(unsigned long *)(((vm_offset_t)tcp) + 
					sizeof(struct thread_command)),
				tcp->cmdsize - sizeof(struct thread_command),
				&result->user_stack);
		if (lret != LOAD_SUCCESS)
			return(lret);

		lret = load_threadentry(current_thread(),
				(unsigned long *)(((vm_offset_t)tcp) + 
					sizeof(struct thread_command)),
				tcp->cmdsize - sizeof(struct thread_command),
				&result->entry_point);
		if (lret != LOAD_SUCCESS)
			return(lret);
	}
	/*
	 *	Resume thread now, note that this means that the thread
	 *	commands should appear after all the load commands to
	 *	be sure they don't reference anything not yet mapped.
	 */
	else
		thread_resume(thread);
		
	result->thread_count++;

	return(LOAD_SUCCESS);
}

static
load_return_t
load_threadstate(
	thread_t	thread,
	unsigned long	*ts,
	unsigned long	total_size
)
{
	kern_return_t	ret;
	unsigned long	size;
	int		flavor;

	/*
	 *	Set the thread state.
	 */

	while (total_size > 0) {
		flavor = *ts++;
		size = *ts++;
		total_size -= (size+2)*sizeof(unsigned long);
		if (total_size < 0)
			return(LOAD_BADMACHO);
		ret = thread_setstatus(getact_thread(thread), flavor, ts, size);
		if (ret != KERN_SUCCESS)
			return(LOAD_FAILURE);
		ts += size;	/* ts is a (unsigned long *) */
	}
	return(LOAD_SUCCESS);
}

static
load_return_t
load_threadstack(
	thread_t	thread,
	unsigned long	*ts,
	unsigned long	total_size,
	vm_offset_t	*user_stack
)
{
	kern_return_t	ret;
	unsigned long	size;
	int		flavor;

	/*
	 *	Set the thread state.
	 */
	*user_stack = 0;
	while (total_size > 0) {
		flavor = *ts++;
		size = *ts++;
		total_size -= (size+2)*sizeof(unsigned long);
		if (total_size < 0)
			return(LOAD_BADMACHO);
		ret = thread_userstack(thread, flavor, ts, size, user_stack);
		if (ret != KERN_SUCCESS)
			return(LOAD_FAILURE);
		ts += size;	/* ts is a (unsigned long *) */
	}
	return(LOAD_SUCCESS);
}

static
load_return_t
load_threadentry(
	thread_t	thread,
	unsigned long	*ts,
	unsigned long	total_size,
	vm_offset_t	*entry_point
)
{
	kern_return_t	ret;
	unsigned long	size;
	int		flavor;

	/*
	 *	Set the thread state.
	 */
	*entry_point = 0;
	while (total_size > 0) {
		flavor = *ts++;
		size = *ts++;
		total_size -= (size+2)*sizeof(unsigned long);
		if (total_size < 0)
			return(LOAD_BADMACHO);
		ret = thread_entrypoint(thread, flavor, ts, size, entry_point);
		if (ret != KERN_SUCCESS)
			return(LOAD_FAILURE);
		ts += size;	/* ts is a (unsigned long *) */
	}
	return(LOAD_SUCCESS);
}

static
load_return_t
load_fvmlib(
	struct fvmlib_command	*lcp,
	vm_map_t		map,
	int			depth
)
{
	char			*name;
	char			*p;
	struct vnode		*vp;
	struct mach_header	header;
	unsigned long		file_offset;
	unsigned long		macho_size;
	unsigned long		lib_version;
	load_result_t		myresult;
	kern_return_t		ret;

	name = (char *)lcp + lcp->fvmlib.name.offset;
	/*
	 *	Check for a proper null terminated string.
	 */
	p = name;
	do {
		if (p >= (char *)lcp + lcp->cmdsize)
			return(LOAD_BADMACHO);
	} while (*p++);

	ret = get_macho_vnode(name, &header, &file_offset, &macho_size, &vp);
	if (ret)
		return (ret);
		
	myresult = (load_result_t) { 0 };

	/*
	 *	Load the Mach-O.
	 */
	ret = parse_machfile(vp, map, &header,
				file_offset, macho_size,
				depth, &lib_version, &myresult);

	if ((ret == LOAD_SUCCESS) &&
	    (lib_version < lcp->fvmlib.minor_version))
		ret = LOAD_SHLIB;

	vrele(vp);
	return(ret);
}

static
load_return_t
load_idfvmlib(
	struct fvmlib_command	*lcp,
	unsigned long		*version
)
{
	*version = lcp->fvmlib.minor_version;
	return(LOAD_SUCCESS);
}

static
load_return_t
load_dylinker(
	struct dylinker_command	*lcp,
	vm_map_t		map,
	int			depth,
	load_result_t		*result
)
{
	char			*name;
	char			*p;
	struct vnode		*vp;
	struct mach_header	header;
	unsigned long		file_offset;
	unsigned long		macho_size;
	vm_map_t		copy_map;
	load_result_t		myresult;
	kern_return_t		ret;
	vm_map_copy_t	tmp;
	vm_offset_t	dyl_start, map_addr;
	vm_size_t	dyl_length;

	name = (char *)lcp + lcp->name.offset;
	/*
	 *	Check for a proper null terminated string.
	 */
	p = name;
	do {
		if (p >= (char *)lcp + lcp->cmdsize)
			return(LOAD_BADMACHO);
	} while (*p++);

	ret = get_macho_vnode(name, &header, &file_offset, &macho_size, &vp);
	if (ret)
		return (ret);
			
	myresult = (load_result_t) { 0 };

	/*
	 *	Load the Mach-O.
	 */
		
	copy_map = vm_map_create(pmap_create(macho_size),
			get_map_min(map), get_map_max( map), TRUE);

	ret = parse_machfile(vp, copy_map, &header,
				file_offset, macho_size,
				depth, 0, &myresult);

	if (ret)
		goto out;

	if (get_map_nentries(copy_map) > 0) {

		dyl_start = get_map_start(copy_map);
		dyl_length = get_map_end(copy_map) - dyl_start;

		map_addr = dyl_start;
		ret = vm_allocate(map, &map_addr, dyl_length, FALSE);
		if (ret != KERN_SUCCESS)  {
			ret = vm_allocate(map, &map_addr, dyl_length, TRUE);
		}

		if (ret != KERN_SUCCESS) {
			ret = LOAD_NOSPACE;
			goto out;
		
		}
		ret = vm_map_copyin(copy_map, dyl_start, dyl_length, TRUE,
				&tmp);
		if (ret != KERN_SUCCESS) {
			(void) vm_map_remove(map,
					     map_addr,
					     map_addr + dyl_length,
					     VM_MAP_NO_FLAGS);
			goto out;
		}

		ret = vm_map_copy_overwrite(map, map_addr, tmp, FALSE);
		if (ret != KERN_SUCCESS) {
				vm_map_copy_discard(tmp);
				(void) vm_map_remove(map,
						     map_addr,
						     map_addr + dyl_length,
						     VM_MAP_NO_FLAGS);
				goto out;		}

		if (map_addr != dyl_start)
			myresult.entry_point += (map_addr - dyl_start);
	} else
		ret = LOAD_FAILURE;
	
	if (ret == LOAD_SUCCESS) {		
		result->dynlinker = TRUE;
		result->entry_point = myresult.entry_point;
		ubc_map(vp);
	}
out:
	vm_map_deallocate(copy_map);
	
	vrele(vp);
	return (ret);

}

static
load_return_t
get_macho_vnode(
	char			*path,
	struct mach_header	*mach_header,
	unsigned long		*file_offset,
	unsigned long		*macho_size,
	struct vnode		**vpp
)
{
	struct vnode		*vp;
	struct vattr attr, *atp;
	struct nameidata nid, *ndp;
	struct proc *p = current_proc();		/* XXXX */
	boolean_t		is_fat;
	struct fat_arch		fat_arch;
	int			error;
	int resid;
	union {
		struct mach_header	mach_header;
		struct fat_header	fat_header;
		char	pad[512];
	} header;
	error = KERN_SUCCESS;
	
	ndp = &nid;
	atp = &attr;
	
	/* init the namei data to point the file user's program name */
	NDINIT(ndp, LOOKUP, FOLLOW | LOCKLEAF | SAVENAME, UIO_SYSSPACE, path, p);

	if (error = namei(ndp))
		return(error);
	
	vp = ndp->ni_vp;
	
	/* check for regular file */
	if (vp->v_type != VREG) {
		error = EACCES;
		goto bad1;
	}

	/* get attributes */
	if (error = VOP_GETATTR(vp, &attr, p->p_ucred, p))
		goto bad1;

	/* Check mount point */
	if (vp->v_mount->mnt_flag & MNT_NOEXEC) {
		error = EACCES;
		goto bad1;
	}

	if ((vp->v_mount->mnt_flag & MNT_NOSUID) || (p->p_flag & P_TRACED))
		atp->va_mode &= ~(VSUID | VSGID);

		/* check access.  for root we have to see if any exec bit on */
	if (error = VOP_ACCESS(vp, VEXEC, p->p_ucred, p))
		goto bad1;
	if ((atp->va_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0) {
		error = EACCES;
		goto bad1;
	}

	/* try to open it */
	if (error = VOP_OPEN(vp, FREAD, p->p_ucred, p))
		goto bad1;
	if(error = vn_rdwr(UIO_READ, vp, (caddr_t)&header, sizeof(header), 0,
	    UIO_SYSSPACE, IO_NODELOCKED, p->p_ucred, &resid, p))
		goto bad2;

/* XXXX WMG - we should check for a short read of the header here */
	
	if (header.mach_header.magic == MH_MAGIC)
	    is_fat = FALSE;
	else if (header.fat_header.magic == FAT_MAGIC ||
		 header.fat_header.magic == FAT_CIGAM)
	    is_fat = TRUE;
	else {
	    error = LOAD_BADMACHO;
	    goto bad2;
	}

	if (is_fat) {
		/*
		 * Look up our architecture in the fat file.
		 */
		error = fatfile_getarch(vp, (vm_offset_t)(&header.fat_header), &fat_arch);
		if (error != LOAD_SUCCESS) {
			goto bad2;
		}
		/*
		 *	Read the Mach-O header out of it
		 */
		error = vn_rdwr(UIO_READ, vp, &header.mach_header,
				sizeof(header.mach_header), fat_arch.offset,
				UIO_SYSSPACE, IO_NODELOCKED, p->p_ucred, &resid, p);
		if (error) {
			error = LOAD_FAILURE;
			goto bad2;
		}

		/*
		 *	Is this really a Mach-O?
		 */
		if (header.mach_header.magic != MH_MAGIC) {
			error = LOAD_BADMACHO;
			goto bad2;
		}
		
		*mach_header = header.mach_header;
		*file_offset = fat_arch.offset;
		*macho_size = fat_arch.size;
		*vpp = vp;
		/* leaks otherwise - A.R */
		FREE_ZONE(ndp->ni_cnd.cn_pnbuf, ndp->ni_cnd.cn_pnlen, M_NAMEI);
		
 		/* i_lock exclusive panics, otherwise during pageins */
		VOP_UNLOCK(vp, 0, p);
		return (error);
	} else {
	
		*mach_header = header.mach_header;
		*file_offset = 0;
		if (UBCISVALID(vp))
			ubc_setsize(vp, attr.va_size);	/* XXX why? */
		*macho_size =  attr.va_size;
		*vpp = vp;
		/* leaks otherwise - A.R */
		FREE_ZONE(ndp->ni_cnd.cn_pnbuf, ndp->ni_cnd.cn_pnlen, M_NAMEI);

		/* i_lock exclusive panics, otherwise during pageins */
        VOP_UNLOCK(vp, 0, p);
		return (error);
	}

bad2:
	/*
	 * unlock and close the vnode, restore the old one, free the
	 * pathname buf, and punt.
	 */
	VOP_UNLOCK(vp, 0, p);
	vn_close(vp, FREAD, p->p_ucred, p);
	FREE_ZONE(ndp->ni_cnd.cn_pnbuf, ndp->ni_cnd.cn_pnlen, M_NAMEI);
	return (error);
bad1:
	/*
	 * free the namei pathname buffer, and put the vnode
	 * (which we don't yet have open).
	 */
	FREE_ZONE(ndp->ni_cnd.cn_pnbuf, ndp->ni_cnd.cn_pnlen, M_NAMEI);
	vput(vp);
	return(error);
}
