/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
#include <sys/vnode_internal.h>
#include <sys/uio.h>
#include <sys/namei.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/stat.h>
#include <sys/malloc.h>
#include <sys/mount_internal.h>
#include <sys/fcntl.h>
#include <sys/ubc_internal.h>
#include <sys/imgact.h>

#include <mach/mach_types.h>
#include <mach/vm_map.h>	/* vm_allocate() */
#include <mach/mach_vm.h>	/* mach_vm_allocate() */
#include <mach/vm_statistics.h>
#include <mach/task.h>
#include <mach/thread_act.h>

#include <machine/vmparam.h>
#include <machine/exec.h>

#include <kern/kern_types.h>
#include <kern/cpu_number.h>
#include <kern/mach_loader.h>
#include <kern/kalloc.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/page_decrypt.h>

#include <mach-o/fat.h>
#include <mach-o/loader.h>

#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_pager.h>
#include <vm/vnode_pager.h>
#include <vm/vm_protos.h> 

/*
 * XXX vm/pmap.h should not treat these prototypes as MACH_KERNEL_PRIVATE
 * when KERNEL is defined.
 */
extern pmap_t	pmap_create(vm_map_size_t size, boolean_t is_64bit);
extern void	pmap_switch(pmap_t);

/*
 * XXX kern/thread.h should not treat these prototypes as MACH_KERNEL_PRIVATE
 * when KERNEL is defined.
 */
extern kern_return_t	thread_setstatus(thread_t thread, int flavor,
				thread_state_t tstate,
				mach_msg_type_number_t count);

extern kern_return_t    thread_state_initialize(thread_t thread);


/* XXX should have prototypes in a shared header file */
extern int	get_map_nentries(vm_map_t);
extern kern_return_t	thread_userstack(thread_t, int, thread_state_t,
				unsigned int, mach_vm_offset_t *, int *);
extern kern_return_t	thread_entrypoint(thread_t, int, thread_state_t,
				unsigned int, mach_vm_offset_t *);

extern kern_return_t	memory_object_signed(memory_object_control_t control,
					     boolean_t is_signed);

/* An empty load_result_t */
static load_result_t load_result_null = {
	.mach_header = MACH_VM_MIN_ADDRESS,
	.entry_point = MACH_VM_MIN_ADDRESS,
	.user_stack = MACH_VM_MIN_ADDRESS,
	.thread_count = 0,
	.unixproc = 0,
	.dynlinker = 0,
	.customstack = 0,
	.csflags = 0
};

/*
 * Prototypes of static functions.
 */
static load_return_t
parse_machfile(
	struct vnode		*vp,
	vm_map_t		map,
	thread_t		thread,
	struct mach_header	*header,
	off_t			file_offset,
	off_t			macho_size,
	int			depth,
	load_result_t		*result
);

static load_return_t
load_segment(
	struct segment_command	*scp,
	void * 					pager,
	off_t				pager_offset,
	off_t				macho_size,
	off_t				end_of_file,
	vm_map_t				map,
	load_result_t			*result
);

static load_return_t
load_segment_64(
	struct segment_command_64	*scp64,
	void				*pager,
	off_t				pager_offset,
	off_t				macho_size,
	off_t				end_of_file,
	vm_map_t			map,
	load_result_t			*result
);

int load_code_signature(
	struct linkedit_data_command	*lcp,
	struct vnode			*vp,
	off_t				macho_offset,
	off_t				macho_size,
	cpu_type_t			cputype,
	load_result_t			*result);
	
#if CONFIG_CODE_DECRYPTION
static load_return_t
set_code_unprotect(
	struct encryption_info_command	*lcp,
	caddr_t				addr,
	vm_map_t			map,
	struct vnode			*vp);
#endif

static load_return_t
load_unixthread(
	struct thread_command	*tcp,
	thread_t			thread,
	load_result_t			*result
);

static load_return_t
load_thread(
	struct thread_command	*tcp,
	thread_t			thread,
	load_result_t			*result
);

static load_return_t
load_threadstate(
	thread_t		thread,
	unsigned long	*ts,
	unsigned long	total_size
);

static load_return_t
load_threadstack(
	thread_t		thread,
	unsigned long	*ts,
	unsigned long	total_size,
	user_addr_t	*user_stack,
	int				*customstack
);

static load_return_t
load_threadentry(
	thread_t		thread,
	unsigned long	*ts,
	unsigned long	total_size,
	mach_vm_offset_t	*entry_point
);

static load_return_t
load_dylinker(
	struct dylinker_command	*lcp,
	integer_t		archbits,
	vm_map_t				map,
	thread_t			thread,
	int						depth,
	load_result_t			*result,
	boolean_t			is_64bit
);

static load_return_t
get_macho_vnode(
	char				*path,
	integer_t		archbits,
	struct mach_header	*mach_header,
	off_t			*file_offset,
	off_t			*macho_size,
	struct vnode		**vpp
);

load_return_t
load_machfile(
	struct image_params	*imgp,
	struct mach_header	*header,
	thread_t 		thread,
	vm_map_t 		new_map,
	load_result_t		*result
)
{
	struct vnode		*vp = imgp->ip_vp;
	off_t			file_offset = imgp->ip_arch_offset;
	off_t			macho_size = imgp->ip_arch_size;
	
	pmap_t			pmap = 0;	/* protected by create_map */
	vm_map_t		map;
	vm_map_t		old_map;
	load_result_t		myresult;
	load_return_t		lret;
	boolean_t create_map = TRUE;

	if (new_map != VM_MAP_NULL) {
		create_map = FALSE;
	}

	if (create_map) {
		old_map = current_map();
		pmap = pmap_create((vm_map_size_t) 0, (imgp->ip_flags & IMGPF_IS_64BIT));
		map = vm_map_create(pmap,
				0,
				vm_compute_max_offset((imgp->ip_flags & IMGPF_IS_64BIT)),
				TRUE);
	} else
		map = new_map;

	if ( (header->flags & MH_ALLOW_STACK_EXECUTION) )
	        vm_map_disable_NX(map);
		
	if (!result)
		result = &myresult;

	*result = load_result_null;

	lret = parse_machfile(vp, map, thread, header, file_offset, macho_size,
			      0, result);

	if (lret != LOAD_SUCCESS) {
		if (create_map) {
			vm_map_deallocate(map);	/* will lose pmap reference too */
		}
		return(lret);
	}

	/*
	 * For 64-bit users, check for presence of a 4GB page zero
	 * which will enable the kernel to share the user's address space
	 * and hence avoid TLB flushes on kernel entry/exit
	 */ 
	if ((imgp->ip_flags & IMGPF_IS_64BIT) &&
	     vm_map_has_4GB_pagezero(map))
		vm_map_set_4GB_pagezero(map);

	/*
	 *	Commit to new map.  First make sure that the current
	 *	users of the task get done with it, and that we clean
	 *	up the old contents of IPC and memory.  The task is
	 *	guaranteed to be single threaded upon return (us).
	 *
	 *	Swap the new map for the old, which  consumes our new map
	 *	reference but each leaves us responsible for the old_map reference.
	 *	That lets us get off the pmap associated with it, and
	 *	then we can release it.
	 */

	 if (create_map) {
		task_halt(current_task());

		old_map = swap_task_map(current_task(), map);
		vm_map_clear_4GB_pagezero(old_map);
		pmap_switch(pmap);	/* Make sure we are using the new pmap */
		vm_map_deallocate(old_map);
	}
	return(LOAD_SUCCESS);
}

/*
 * The file size of a mach-o file is limited to 32 bits; this is because
 * this is the limit on the kalloc() of enough bytes for a mach_header and
 * the contents of its sizeofcmds, which is currently constrained to 32
 * bits in the file format itself.  We read into the kernel buffer the
 * commands section, and then parse it in order to parse the mach-o file
 * format load_command segment(s).  We are only interested in a subset of
 * the total set of possible commands.
 */
static
load_return_t
parse_machfile(
	struct vnode 		*vp,       
	vm_map_t		map,
	thread_t		thread,
	struct mach_header	*header,
	off_t			file_offset,
	off_t			macho_size,
	int			depth,
	load_result_t		*result
)
{
	uint32_t		ncmds;
	struct load_command	*lcp;
	struct dylinker_command	*dlp = 0;
	integer_t		dlarchbits = 0;
	void *			pager;
	load_return_t		ret = LOAD_SUCCESS;
	caddr_t			addr;
	void *			kl_addr;
	vm_size_t		size,kl_size;
	size_t			offset;
	size_t			oldoffset;	/* for overflow check */
	int			pass;
	proc_t			p = current_proc();		/* XXXX */
	int			error;
	int resid=0;
	task_t task;
	size_t			mach_header_sz = sizeof(struct mach_header);
	boolean_t		abi64;
	boolean_t		got_code_signatures = FALSE;

	if (header->magic == MH_MAGIC_64 ||
	    header->magic == MH_CIGAM_64) {
	    	mach_header_sz = sizeof(struct mach_header_64);
	}

	/*
	 *	Break infinite recursion
	 */
	if (depth > 6) {
		return(LOAD_FAILURE);
	}

	task = (task_t)get_threadtask(thread);

	depth++;

	/*
	 *	Check to see if right machine type.
	 */
	if (((cpu_type_t)(header->cputype & ~CPU_ARCH_MASK) != cpu_type()) ||
	    !grade_binary(header->cputype, 
	    	header->cpusubtype & ~CPU_SUBTYPE_MASK))
		return(LOAD_BADARCH);
		
	abi64 = ((header->cputype & CPU_ARCH_ABI64) == CPU_ARCH_ABI64);
		
	switch (header->filetype) {
	
	case MH_OBJECT:
	case MH_EXECUTE:
	case MH_PRELOAD:
		if (depth != 1) {
			return (LOAD_FAILURE);
		}
		break;
		
	case MH_FVMLIB:
	case MH_DYLIB:
		if (depth == 1) {
			return (LOAD_FAILURE);
		}
		break;

	case MH_DYLINKER:
		if (depth != 2) {
			return (LOAD_FAILURE);
		}
		break;
		
	default:
		return (LOAD_FAILURE);
	}

	/*
	 *	Get the pager for the file.
	 */
	pager = (void *) ubc_getpager(vp);

	/*
	 *	Map portion that must be accessible directly into
	 *	kernel's map.
	 */
	if ((mach_header_sz + header->sizeofcmds) > macho_size)
		return(LOAD_BADMACHO);

	/*
	 *	Round size of Mach-O commands up to page boundry.
	 */
	size = round_page(mach_header_sz + header->sizeofcmds);
	if (size <= 0)
		return(LOAD_BADMACHO);

	/*
	 * Map the load commands into kernel memory.
	 */
	addr = 0;
	kl_size = size;
	kl_addr = kalloc(size);
	addr = (caddr_t)kl_addr;
	if (addr == NULL)
		return(LOAD_NOSPACE);

	error = vn_rdwr(UIO_READ, vp, addr, size, file_offset,
	    UIO_SYSSPACE32, 0, kauth_cred_get(), &resid, p);
	if (error) {
		if (kl_addr )
			kfree(kl_addr, kl_size);
		return(LOAD_IOERROR);
	}
	
	/*
	 *	Scan through the commands, processing each one as necessary.
	 */
	for (pass = 1; pass <= 2; pass++) {
		/*
		 * Loop through each of the load_commands indicated by the
		 * Mach-O header; if an absurd value is provided, we just
		 * run off the end of the reserved section by incrementing
		 * the offset too far, so we are implicitly fail-safe.
		 */
		offset = mach_header_sz;
		ncmds = header->ncmds;
		while (ncmds--) {
			/*
			 *	Get a pointer to the command.
			 */
			lcp = (struct load_command *)(addr + offset);
			oldoffset = offset;
			offset += lcp->cmdsize;

			/*
			 * Perform prevalidation of the struct load_command
			 * before we attempt to use its contents.  Invalid
			 * values are ones which result in an overflow, or
			 * which can not possibly be valid commands, or which
			 * straddle or exist past the reserved section at the
			 * start of the image.
			 */
			if (oldoffset > offset ||
			    lcp->cmdsize < sizeof(struct load_command) ||
			    offset > header->sizeofcmds + mach_header_sz) {
				ret = LOAD_BADMACHO;
				break;
			}

			/*
			 * Act on struct load_command's for which kernel
			 * intervention is required.
			 */
			switch(lcp->cmd) {
			case LC_SEGMENT_64:
				if (pass != 1)
					break;
				ret = load_segment_64(
					       (struct segment_command_64 *)lcp,
						   pager,
						   file_offset,
						   macho_size,
						   ubc_getsize(vp),
						   map,
						   result);
				break;
			case LC_SEGMENT:
				if (pass != 1)
					break;
				ret = load_segment(
					       (struct segment_command *) lcp,
						   pager,
						   file_offset,
						   macho_size,
						   ubc_getsize(vp),
						   map,
						   result);
				break;
			case LC_THREAD:
				if (pass != 2)
					break;
				ret = load_thread((struct thread_command *)lcp,
						   thread,
						  result);
				break;
			case LC_UNIXTHREAD:
				if (pass != 2)
					break;
				ret = load_unixthread(
						 (struct thread_command *) lcp,
						   thread,
						 result);
				break;
			case LC_LOAD_DYLINKER:
				if (pass != 2)
					break;
				if ((depth == 1) && (dlp == 0)) {
					dlp = (struct dylinker_command *)lcp;
					dlarchbits = (header->cputype & CPU_ARCH_MASK);
				} else {
					ret = LOAD_FAILURE;
				}
				break;
			case LC_CODE_SIGNATURE:
				/* CODE SIGNING */
				if (pass != 2)
					break;
				/* pager -> uip ->
				   load signatures & store in uip
				   set VM object "signed_pages"
				*/
				ret = load_code_signature(
					(struct linkedit_data_command *) lcp,
					vp,
					file_offset,
					macho_size,
					header->cputype,
					(depth == 1) ? result : NULL);
				if (ret != LOAD_SUCCESS) {
					printf("proc %d: load code signature error %d "
					       "for file \"%s\"\n",
					       p->p_pid, ret, vp->v_name);
					ret = LOAD_SUCCESS; /* ignore error */
				} else {
					got_code_signatures = TRUE;
				}
				break;
#if CONFIG_CODE_DECRYPTION
			case LC_ENCRYPTION_INFO:
				if (pass != 2)
					break;
				ret = set_code_unprotect(
					(struct encryption_info_command *) lcp,
					addr, map, vp);
				if (ret != LOAD_SUCCESS) {
					printf("proc %d: set_code_unprotect() error %d "
					       "for file \"%s\"\n",
					       p->p_pid, ret, vp->v_name);
					/* Don't let the app run if it's 
					 * encrypted but we failed to set up the
					 * decrypter */
					 psignal(p, SIGKILL);
				}
				break;
#endif
			default:
				/* Other commands are ignored by the kernel */
				ret = LOAD_SUCCESS;
				break;
			}
			if (ret != LOAD_SUCCESS)
				break;
		}
		if (ret != LOAD_SUCCESS)
			break;
	}
	if (ret == LOAD_SUCCESS) { 
	    if (! got_code_signatures) {
		    struct cs_blob *blob;
		    /* no embedded signatures: look for detached ones */
		    blob = ubc_cs_blob_get(vp, -1, file_offset);
		    if (blob != NULL) {
			    /* get flags to be applied to the process */
			    result->csflags |= blob->csb_flags;
		    }
	    }

	    if (dlp != 0)
			ret = load_dylinker(dlp, dlarchbits, map, thread, depth, result, abi64);

	    if(depth == 1) {
		if (result->thread_count == 0) {
			ret = LOAD_FAILURE;
		} else if ( abi64 ) {
#ifdef __ppc__
			/* Map in 64-bit commpage */
			/* LP64todo - make this clean */
			/*
			 * PPC51: ppc64 is limited to 51-bit addresses.
			 * Memory above that limit is handled specially
			 * at the pmap level.
			 */
			pmap_map_sharedpage(current_task(), get_map_pmap(map));
#endif /* __ppc__ */
		}
	    }
	}

	if (kl_addr )
		kfree(kl_addr, kl_size);

	return(ret);
}

#if CONFIG_CODE_DECRYPTION

#define	APPLE_UNPROTECTED_HEADER_SIZE	(3 * PAGE_SIZE_64)

static load_return_t
unprotect_segment_64(
	uint64_t	file_off,
	uint64_t	file_size,
	vm_map_t	map,
	vm_map_offset_t	map_addr,
	vm_map_size_t	map_size)
{
	kern_return_t	kr;

	/*
	 * The first APPLE_UNPROTECTED_HEADER_SIZE bytes (from offset 0 of
	 * this part of a Universal binary) are not protected...
	 * The rest needs to be "transformed".
	 */
	if (file_off <= APPLE_UNPROTECTED_HEADER_SIZE &&
	    file_off + file_size <= APPLE_UNPROTECTED_HEADER_SIZE) {
		/* it's all unprotected, nothing to do... */
		kr = KERN_SUCCESS;
	} else {
		if (file_off <= APPLE_UNPROTECTED_HEADER_SIZE) {
			/*
			 * We start mapping in the unprotected area.
			 * Skip the unprotected part...
			 */
			vm_map_offset_t	delta;

			delta = APPLE_UNPROTECTED_HEADER_SIZE;
			delta -= file_off;
			map_addr += delta;
			map_size -= delta;
		}
		/* ... transform the rest of the mapping. */
		struct pager_crypt_info crypt_info;
		crypt_info.page_decrypt = dsmos_page_transform;
		crypt_info.crypt_ops = NULL;
		crypt_info.crypt_end = NULL;
		kr = vm_map_apple_protected(map,
					    map_addr,
					    map_addr + map_size,
					    &crypt_info);
	}

	if (kr != KERN_SUCCESS) {
		return LOAD_FAILURE;
	}
	return LOAD_SUCCESS;
}
#else	/* CONFIG_CODE_DECRYPTION */
#define unprotect_segment_64(file_off, file_size, map, map_addr, map_size) \
	LOAD_SUCCESS
#endif	/* CONFIG_CODE_DECRYPTION */

static
load_return_t
load_segment(
	struct segment_command	*scp,
	void *			pager,
	off_t			pager_offset,
	off_t			macho_size,
	__unused off_t		end_of_file,
	vm_map_t		map,
	load_result_t		*result
)
{
	kern_return_t		ret;
	vm_offset_t		map_addr, map_offset;
	vm_size_t		map_size, seg_size, delta_size;
	vm_prot_t 		initprot;
	vm_prot_t		maxprot;

	/*
	 * Make sure what we get from the file is really ours (as specified
	 * by macho_size).
	 */
	if (scp->fileoff + scp->filesize > macho_size)
		return (LOAD_BADMACHO);
	/*
	 * Make sure the segment is page-aligned in the file.
	 */
	if ((scp->fileoff & PAGE_MASK) != 0)
		return LOAD_BADMACHO;

	seg_size = round_page(scp->vmsize);
	if (seg_size == 0)
		return(KERN_SUCCESS);

	/*
	 *	Round sizes to page size.
	 */
	map_size = round_page(scp->filesize);
	map_addr = trunc_page(scp->vmaddr);

#if 0	/* XXX (4596982) this interferes with Rosetta */
	if (map_addr == 0 &&
	    map_size == 0 &&
	    seg_size != 0 &&
	    (scp->initprot & VM_PROT_ALL) == VM_PROT_NONE &&
	    (scp->maxprot & VM_PROT_ALL) == VM_PROT_NONE) {
		/*
		 * This is a "page zero" segment:  it starts at address 0,
		 * is not mapped from the binary file and is not accessible.
		 * User-space should never be able to access that memory, so
		 * make it completely off limits by raising the VM map's
		 * minimum offset.
		 */
		ret = vm_map_raise_min_offset(map, (vm_map_offset_t) seg_size);
		if (ret != KERN_SUCCESS) {
			return LOAD_FAILURE;
		}
		return LOAD_SUCCESS;
	}
#endif

	map_offset = pager_offset + scp->fileoff;

	if (map_size > 0) {
		initprot = (scp->initprot) & VM_PROT_ALL;
		maxprot = (scp->maxprot) & VM_PROT_ALL;
		/*
		 *	Map a copy of the file into the address space.
		 */
		ret = vm_map(map,
				&map_addr, map_size, (vm_offset_t)0,
			        VM_FLAGS_FIXED,	pager, map_offset, TRUE,
				initprot, maxprot,
				VM_INHERIT_DEFAULT);
		if (ret != KERN_SUCCESS)
			return(LOAD_NOSPACE);
	
		/*
		 *	If the file didn't end on a page boundary,
		 *	we need to zero the leftover.
		 */
		delta_size = map_size - scp->filesize;
#if FIXME
		if (delta_size > 0) {
			vm_offset_t	tmp;
	
			ret = vm_allocate(kernel_map, &tmp, delta_size, VM_FLAGS_ANYWHERE);
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

		ret = vm_map(map, &tmp, delta_size, 0, VM_FLAGS_FIXED,
			     NULL, 0, FALSE,
			     scp->initprot, scp->maxprot,
			     VM_INHERIT_DEFAULT);
		if (ret != KERN_SUCCESS)
			return(LOAD_NOSPACE);
	}

	if ( (scp->fileoff == 0) && (scp->filesize != 0) )
		result->mach_header = map_addr;

	if (scp->flags & SG_PROTECTED_VERSION_1) {
		ret = unprotect_segment_64((uint64_t) scp->fileoff,
					   (uint64_t) scp->filesize,
					   map,
					   (vm_map_offset_t) map_addr,
					   (vm_map_size_t) map_size);
	} else {
		ret = LOAD_SUCCESS;
	}

	return ret;
}

static
load_return_t
load_segment_64(
	struct segment_command_64	*scp64,
	void *				pager,
	off_t				pager_offset,
	off_t				macho_size,
	__unused off_t			end_of_file,
	vm_map_t			map,
	load_result_t		*result
)
{
	kern_return_t		ret;
	mach_vm_offset_t	map_addr, map_offset;
	mach_vm_size_t		map_size, seg_size, delta_size;
	vm_prot_t 		initprot;
	vm_prot_t		maxprot;
	
	/*
	 * Make sure what we get from the file is really ours (as specified
	 * by macho_size).
	 */
	if (scp64->fileoff + scp64->filesize > (uint64_t)macho_size)
		return (LOAD_BADMACHO);
	/*
	 * Make sure the segment is page-aligned in the file.
	 */
	if ((scp64->fileoff & PAGE_MASK_64) != 0)
		return LOAD_BADMACHO;

	seg_size = round_page_64(scp64->vmsize);
	if (seg_size == 0)
		return(KERN_SUCCESS);

	/*
	 *	Round sizes to page size.
	 */
	map_size = round_page_64(scp64->filesize);	/* limited to 32 bits */
	map_addr = round_page_64(scp64->vmaddr);

	if (map_addr == 0 &&
	    map_size == 0 &&
	    seg_size != 0 &&
	    (scp64->initprot & VM_PROT_ALL) == VM_PROT_NONE &&
	    (scp64->maxprot & VM_PROT_ALL) == VM_PROT_NONE) {
		/*
		 * This is a "page zero" segment:  it starts at address 0,
		 * is not mapped from the binary file and is not accessible.
		 * User-space should never be able to access that memory, so
		 * make it completely off limits by raising the VM map's
		 * minimum offset.
		 */
		ret = vm_map_raise_min_offset(map, seg_size);
		if (ret != KERN_SUCCESS) {
			return LOAD_FAILURE;
		}
		return LOAD_SUCCESS;
	}

	map_offset = pager_offset + scp64->fileoff;	/* limited to 32 bits */

	if (map_size > 0) {
		initprot = (scp64->initprot) & VM_PROT_ALL;
		maxprot = (scp64->maxprot) & VM_PROT_ALL;
		/*
		 *	Map a copy of the file into the address space.
		 */
		ret = mach_vm_map(map,
				&map_addr, map_size, (mach_vm_offset_t)0,
			        VM_FLAGS_FIXED,	pager, map_offset, TRUE,
				initprot, maxprot,
				VM_INHERIT_DEFAULT);
		if (ret != KERN_SUCCESS)
			return(LOAD_NOSPACE);
	
		/*
		 *	If the file didn't end on a page boundary,
		 *	we need to zero the leftover.
		 */
		delta_size = map_size - scp64->filesize;
#if FIXME
		if (delta_size > 0) {
			mach_vm_offset_t	tmp;
	
			ret = vm_allocate(kernel_map, &tmp, delta_size, VM_FLAGS_ANYWHERE);
			if (ret != KERN_SUCCESS)
				return(LOAD_RESOURCE);
	
			if (copyout(tmp, map_addr + scp64->filesize,
								delta_size)) {
				(void) vm_deallocate(
						kernel_map, tmp, delta_size);
				return (LOAD_FAILURE);
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
		mach_vm_offset_t tmp = map_addr + map_size;

		ret = mach_vm_map(map, &tmp, delta_size, 0, VM_FLAGS_FIXED,
				  NULL, 0, FALSE,
				  scp64->initprot, scp64->maxprot,
				  VM_INHERIT_DEFAULT);
		if (ret != KERN_SUCCESS)
			return(LOAD_NOSPACE);
	}

	if ( (scp64->fileoff == 0) && (scp64->filesize != 0) )
		result->mach_header = map_addr;

	if (scp64->flags & SG_PROTECTED_VERSION_1) {
		ret = unprotect_segment_64(scp64->fileoff,
					   scp64->filesize,
					   map,
					   map_addr,
					   map_size);
	} else {
		ret = LOAD_SUCCESS;
	}

	return ret;
}

static
load_return_t
load_thread(
	struct thread_command	*tcp,
	thread_t			thread,
	load_result_t		*result
)
{
	kern_return_t	kret;
	load_return_t	lret;
	task_t			task;
	int customstack=0;

	task = get_threadtask(thread);

	/* if count is 0; same as thread */
	if (result->thread_count != 0) {
		kret = thread_create(task, &thread);
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
		lret = load_threadstack(thread,
				(unsigned long *)(((vm_offset_t)tcp) + 
					sizeof(struct thread_command)),
				tcp->cmdsize - sizeof(struct thread_command),
				&result->user_stack,
				&customstack);
		if (customstack)
				result->customstack = 1;
		else
				result->customstack = 0;
			
		if (lret != LOAD_SUCCESS)
			return(lret);

		lret = load_threadentry(thread,
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
load_unixthread(
	struct thread_command	*tcp,
	thread_t		thread,
	load_result_t		*result
)
{
	load_return_t	ret;
	int customstack =0;
	
	if (result->thread_count != 0) {
printf("load_unixthread: already have a thread!");
		return (LOAD_FAILURE);
	}
	
	ret = load_threadstack(thread,
		       (unsigned long *)(((vm_offset_t)tcp) + 
		       		sizeof(struct thread_command)),
		       tcp->cmdsize - sizeof(struct thread_command),
		       &result->user_stack,
			   &customstack);
	if (ret != LOAD_SUCCESS)
		return(ret);

	if (customstack)
			result->customstack = 1;
	else
			result->customstack = 0;
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
load_threadstate(
	thread_t	thread,
	unsigned long	*ts,
	unsigned long	total_size
)
{
	kern_return_t	ret;
	unsigned long	size;
	int		flavor;
	unsigned long	thread_size;

    ret = thread_state_initialize( thread );
    if (ret != KERN_SUCCESS) {
        return(LOAD_FAILURE);
    }
    
	/*
	 *	Set the new thread state; iterate through the state flavors in
     *  the mach-o file.
	 */
	while (total_size > 0) {
		flavor = *ts++;
		size = *ts++;
		thread_size = (size+2)*sizeof(unsigned long);
		if (thread_size > total_size)
			return(LOAD_BADMACHO);
		total_size -= thread_size;
		/*
		 * Third argument is a kernel space pointer; it gets cast
		 * to the appropriate type in machine_thread_set_state()
		 * based on the value of flavor.
		 */
		ret = thread_setstatus(thread, flavor, (thread_state_t)ts, size);
		if (ret != KERN_SUCCESS) {
			return(LOAD_FAILURE);
		}
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
	user_addr_t	*user_stack,
	int *customstack
)
{
	kern_return_t	ret;
	unsigned long	size;
	int		flavor;
	unsigned long	stack_size;

	while (total_size > 0) {
		flavor = *ts++;
		size = *ts++;
		stack_size = (size+2)*sizeof(unsigned long);
		if (stack_size > total_size)
			return(LOAD_BADMACHO);
		total_size -= stack_size;

		/*
		 * Third argument is a kernel space pointer; it gets cast
		 * to the appropriate type in thread_userstack() based on
		 * the value of flavor.
		 */
		ret = thread_userstack(thread, flavor, (thread_state_t)ts, size, user_stack, customstack);
		if (ret != KERN_SUCCESS) {
			return(LOAD_FAILURE);
		}
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
	mach_vm_offset_t	*entry_point
)
{
	kern_return_t	ret;
	unsigned long	size;
	int		flavor;
	unsigned long	entry_size;

	/*
	 *	Set the thread state.
	 */
	*entry_point = MACH_VM_MIN_ADDRESS;
	while (total_size > 0) {
		flavor = *ts++;
		size = *ts++;
		entry_size = (size+2)*sizeof(unsigned long);
		if (entry_size > total_size)
			return(LOAD_BADMACHO);
		total_size -= entry_size;
		/*
		 * Third argument is a kernel space pointer; it gets cast
		 * to the appropriate type in thread_entrypoint() based on
		 * the value of flavor.
		 */
		ret = thread_entrypoint(thread, flavor, (thread_state_t)ts, size, entry_point);
		if (ret != KERN_SUCCESS) {
			return(LOAD_FAILURE);
		}
		ts += size;	/* ts is a (unsigned long *) */
	}
	return(LOAD_SUCCESS);
}


static
load_return_t
load_dylinker(
	struct dylinker_command	*lcp,
	integer_t		archbits,
	vm_map_t		map,
	thread_t	thread,
	int			depth,
	load_result_t		*result,
	boolean_t		is_64bit
)
{
	char			*name;
	char			*p;
	struct vnode		*vp = NULLVP;	/* set by get_macho_vnode() */
	struct mach_header	header;
	off_t			file_offset = 0; /* set by get_macho_vnode() */
	off_t			macho_size = 0;	/* set by get_macho_vnode() */
	vm_map_t		copy_map;
	load_result_t		myresult;
	kern_return_t		ret;
	vm_map_copy_t	tmp;
	mach_vm_offset_t	dyl_start, map_addr;
	mach_vm_size_t		dyl_length;

	name = (char *)lcp + lcp->name.offset;
	/*
	 *	Check for a proper null terminated string.
	 */
	p = name;
	do {
		if (p >= (char *)lcp + lcp->cmdsize)
			return(LOAD_BADMACHO);
	} while (*p++);

	ret = get_macho_vnode(name, archbits, &header, &file_offset, &macho_size, &vp);
	if (ret)
		return (ret);
			
	myresult = load_result_null;

	/*
	 *	First try to map dyld in directly.  This should work most of
	 *	the time since there shouldn't normally be something already
	 *	mapped to its address.
	 */

	ret = parse_machfile(vp, map, thread, &header, file_offset, macho_size,
				depth, &myresult);

	/*
	 *	If it turned out something was in the way, then we'll take
	 *	take this longer path to map dyld into a temporary map and
	 *	copy it into destination map at a different address.
	 */

	if (ret == LOAD_NOSPACE) {

		/*
		 *	Load the Mach-O.
		 *	Use a temporary map to do the work.
		 */
		copy_map = vm_map_create(pmap_create(vm_map_round_page(macho_size),
						     is_64bit),
					 get_map_min(map), get_map_max(map), TRUE);
		if (VM_MAP_NULL == copy_map) {
			ret = LOAD_RESOURCE;
			goto out;
		}
	
		myresult = load_result_null;

		ret = parse_machfile(vp, copy_map, thread, &header,
					file_offset, macho_size,
					depth, &myresult);
	
		if (ret) {
			vm_map_deallocate(copy_map);
			goto out;
		}
	
		if (get_map_nentries(copy_map) > 0) {
	
			dyl_start = mach_get_vm_start(copy_map);
			dyl_length = mach_get_vm_end(copy_map) - dyl_start;
	
			map_addr = dyl_start;
			ret = mach_vm_allocate(map, &map_addr, dyl_length, VM_FLAGS_ANYWHERE);
	
			if (ret != KERN_SUCCESS) {
				vm_map_deallocate(copy_map);
				ret = LOAD_NOSPACE;
				goto out;
			
			}

			ret = vm_map_copyin(copy_map,
					    (vm_map_address_t)dyl_start,
					    (vm_map_size_t)dyl_length,
					    TRUE, &tmp);
			if (ret != KERN_SUCCESS) {
				(void) vm_map_remove(map,
					     vm_map_trunc_page(map_addr),
					     vm_map_round_page(map_addr + dyl_length),
					     VM_MAP_NO_FLAGS);
				vm_map_deallocate(copy_map);
				goto out;
			}
	
			ret = vm_map_copy_overwrite(map,
					     (vm_map_address_t)map_addr,
					     tmp, FALSE);
			if (ret != KERN_SUCCESS) {
				vm_map_copy_discard(tmp);
				(void) vm_map_remove(map,
					     vm_map_trunc_page(map_addr),
					     vm_map_round_page(map_addr + dyl_length),
					     VM_MAP_NO_FLAGS);
				vm_map_deallocate(copy_map);
				goto out;
			}
	
			if (map_addr != dyl_start)
				myresult.entry_point += (map_addr - dyl_start);
		} else {
			ret = LOAD_FAILURE;
		}

		vm_map_deallocate(copy_map);
	}
	
	if (ret == LOAD_SUCCESS) {		
		result->dynlinker = TRUE;
		result->entry_point = myresult.entry_point;
	}
out:
	vnode_put(vp);
	return (ret);

}

int
load_code_signature(
	struct linkedit_data_command	*lcp,
	struct vnode			*vp,
	off_t				macho_offset,
	off_t				macho_size,
	cpu_type_t			cputype,
	load_result_t			*result)
{
	int		ret;
	kern_return_t	kr;
	vm_offset_t	addr;
	int		resid;
	struct cs_blob	*blob;
	int		error;
	vm_size_t	blob_size;

	addr = 0;
	blob = NULL;

	if (lcp->cmdsize != sizeof (struct linkedit_data_command) ||
	    lcp->dataoff + lcp->datasize > macho_size) {
		ret = LOAD_BADMACHO;
		goto out;
	}

	blob = ubc_cs_blob_get(vp, cputype, -1);
	if (blob != NULL) {
		/* we already have a blob for this vnode and cputype */
		if (blob->csb_cpu_type == cputype &&
		    blob->csb_base_offset == macho_offset &&
		    blob->csb_mem_size == lcp->datasize) {
			/* it matches the blob we want here: we're done */
			ret = LOAD_SUCCESS;
		} else {
			/* the blob has changed for this vnode: fail ! */
			ret = LOAD_BADMACHO;
		}
		goto out;
	}

	blob_size = lcp->datasize;
	kr = ubc_cs_blob_allocate(&addr, &blob_size);
	if (kr != KERN_SUCCESS) {
		ret = LOAD_NOSPACE;
		goto out;
	}
	
	resid = 0;
	error = vn_rdwr(UIO_READ,
			vp,
			(caddr_t) addr,
			lcp->datasize,
			macho_offset + lcp->dataoff,
			UIO_SYSSPACE32,
			0,
			kauth_cred_get(),
			&resid,
			current_proc());
	if (error || resid != 0) {
		ret = LOAD_IOERROR;
		goto out;
	}

	if (ubc_cs_blob_add(vp,
			    cputype,
			    macho_offset,
			    addr,
			    lcp->datasize)) {
		ret = LOAD_FAILURE;
		goto out;
	} else {
		/* ubc_cs_blob_add() has consumed "addr" */
		addr = 0;
	}
		
	blob = ubc_cs_blob_get(vp, cputype, -1);

	ret = LOAD_SUCCESS;
out:
	if (result && ret == LOAD_SUCCESS) {
		result->csflags |= blob->csb_flags;
	}
	if (addr != 0) {
		ubc_cs_blob_deallocate(addr, blob_size);
		addr = 0;
	}

	return ret;
}


#if CONFIG_CODE_DECRYPTION

static load_return_t
set_code_unprotect(
		   struct encryption_info_command *eip,
		   caddr_t addr, 	
		   vm_map_t map,
		   struct vnode	*vp)
{
	int result, len;
	char vpath[MAXPATHLEN];
	pager_crypt_info_t crypt_info;
	const char * cryptname = 0;
	
	size_t offset;
	struct segment_command_64 *seg64;
	struct segment_command *seg32;
	vm_map_offset_t map_offset, map_size;
	kern_return_t kr;
	
	switch(eip->cryptid) {
		case 0:
			/* not encrypted, just an empty load command */
			return LOAD_SUCCESS;
		case 1:
			cryptname="com.apple.unfree";
			break;
		case 0x10:	
			/* some random cryptid that you could manually put into
			 * your binary if you want NULL */
			cryptname="com.apple.null";
			break;
		default:
			return LOAD_BADMACHO;
	}
	
	len = MAXPATHLEN;
	result = vn_getpath(vp, vpath, &len);
	if(result) return result;
	
	/* set up decrypter first */
	if(NULL==text_crypter_create) return LOAD_FAILURE;
	kr=text_crypter_create(&crypt_info, cryptname, (void*)vpath);
	
	if(kr) {
		printf("set_code_unprotect: unable to create decrypter %s, kr=%d\n",
		       cryptname, kr);
		return LOAD_RESOURCE;
	}
	
	/* this is terrible, but we have to rescan the load commands to find the
	 * virtual address of this encrypted stuff. This code is gonna look like
	 * the dyld source one day... */
	struct mach_header *header = (struct mach_header *)addr;
	size_t mach_header_sz = sizeof(struct mach_header);
	if (header->magic == MH_MAGIC_64 ||
	    header->magic == MH_CIGAM_64) {
	    	mach_header_sz = sizeof(struct mach_header_64);
	}
	offset = mach_header_sz;
	uint32_t ncmds = header->ncmds;
	while (ncmds--) {
		/*
		 *	Get a pointer to the command.
		 */
		struct load_command *lcp = (struct load_command *)(addr + offset);
		offset += lcp->cmdsize;
		
		switch(lcp->cmd) {
			case LC_SEGMENT_64:
				seg64 = (struct segment_command_64 *)lcp;
				if ((seg64->fileoff <= eip->cryptoff) &&
				    (seg64->fileoff+seg64->filesize >= 
				     eip->cryptoff+eip->cryptsize)) {
					map_offset = seg64->vmaddr + eip->cryptoff - seg64->fileoff;
					map_size = eip->cryptsize;
					goto remap_now;
				}
			case LC_SEGMENT:
				seg32 = (struct segment_command *)lcp;
				if ((seg32->fileoff <= eip->cryptoff) &&
				    (seg32->fileoff+seg32->filesize >= 
				     eip->cryptoff+eip->cryptsize)) {
					map_offset = seg32->vmaddr + eip->cryptoff - seg32->fileoff;
					map_size = eip->cryptsize;
					goto remap_now;
				}
		}
	}
	
	/* if we get here, did not find anything */
	return LOAD_BADMACHO;
	
remap_now:
	/* now remap using the decrypter */
	kr = vm_map_apple_protected(map, map_offset, map_offset+map_size, &crypt_info);
	if(kr) {
		printf("set_code_unprotect(): mapping failed with %x\n", kr);
		crypt_info.crypt_end(crypt_info.crypt_ops);
		return LOAD_PROTECT;
	}
	
	return LOAD_SUCCESS;
}

#endif

/*
 * This routine exists to support the load_dylinker().
 *
 * This routine has its own, separate, understanding of the FAT file format,
 * which is terrifically unfortunate.
 */
static
load_return_t
get_macho_vnode(
	char			*path,
	integer_t		archbits,
	struct mach_header	*mach_header,
	off_t			*file_offset,
	off_t			*macho_size,
	struct vnode		**vpp
)
{
	struct vnode		*vp;
	vfs_context_t		ctx = vfs_context_current();
	proc_t			p = vfs_context_proc(ctx);
	kauth_cred_t		kerncred;
	struct nameidata nid, *ndp;
	boolean_t		is_fat;
	struct fat_arch		fat_arch;
	int			error = LOAD_SUCCESS;
	int resid;
	union {
		struct mach_header	mach_header;
		struct fat_header	fat_header;
		char	pad[512];
	} header;
	off_t fsize = (off_t)0;
	int err2;
	
	/*
	 * Capture the kernel credential for use in the actual read of the
	 * file, since the user doing the execution may have execute rights
	 * but not read rights, but to exec something, we have to either map
	 * or read it into the new process address space, which requires
	 * read rights.  This is to deal with lack of common credential
	 * serialization code which would treat NOCRED as "serialize 'root'".
	 */
	kerncred = vfs_context_ucred(vfs_context_kernel());

	ndp = &nid;
	
	/* init the namei data to point the file user's program name */
	NDINIT(ndp, LOOKUP, FOLLOW | LOCKLEAF, UIO_SYSSPACE32, CAST_USER_ADDR_T(path), ctx);

	if ((error = namei(ndp)) != 0) {
		if (error == ENOENT) {
			error = LOAD_ENOENT;
		} else {
			error = LOAD_FAILURE;
		}
		return(error);
	}
	nameidone(ndp);
	vp = ndp->ni_vp;
	
	/* check for regular file */
	if (vp->v_type != VREG) {
		error = LOAD_PROTECT;
		goto bad1;
	}

	/* get size */
	if ((error = vnode_size(vp, &fsize, ctx)) != 0) {
		error = LOAD_FAILURE;
		goto bad1;
	}

	/* Check mount point */
	if (vp->v_mount->mnt_flag & MNT_NOEXEC) {
		error = LOAD_PROTECT;
		goto bad1;
	}

	/* check access */
	if ((error = vnode_authorize(vp, NULL, KAUTH_VNODE_EXECUTE, ctx)) != 0) {
		error = LOAD_PROTECT;
		goto bad1;
	}

	/* try to open it */
	if ((error = VNOP_OPEN(vp, FREAD, ctx)) != 0) {
		error = LOAD_PROTECT;
		goto bad1;
	}

	if ((error = vn_rdwr(UIO_READ, vp, (caddr_t)&header, sizeof(header), 0,
	    UIO_SYSSPACE32, IO_NODELOCKED, kerncred, &resid, p)) != 0) {
		error = LOAD_IOERROR;
		goto bad2;
	}
	
	if (header.mach_header.magic == MH_MAGIC ||
	    header.mach_header.magic == MH_MAGIC_64)
	    is_fat = FALSE;
	else if (header.fat_header.magic == FAT_MAGIC ||
		 header.fat_header.magic == FAT_CIGAM)
	    is_fat = TRUE;
	else {
	    error = LOAD_BADMACHO;
	    goto bad2;
	}

	if (is_fat) {
		/* Look up our architecture in the fat file. */
		error = fatfile_getarch_with_bits(vp, archbits, (vm_offset_t)(&header.fat_header), &fat_arch);
		if (error != LOAD_SUCCESS)
			goto bad2;

		/* Read the Mach-O header out of it */
		error = vn_rdwr(UIO_READ, vp, (caddr_t)&header.mach_header,
				sizeof(header.mach_header), fat_arch.offset,
				UIO_SYSSPACE32, IO_NODELOCKED, kerncred, &resid, p);
		if (error) {
			error = LOAD_IOERROR;
			goto bad2;
		}

		/* Is this really a Mach-O? */
		if (header.mach_header.magic != MH_MAGIC &&
		    header.mach_header.magic != MH_MAGIC_64) {
			error = LOAD_BADMACHO;
			goto bad2;
		}

		*file_offset = fat_arch.offset;
		*macho_size = fat_arch.size;
	} else {
		/*
		 * Force get_macho_vnode() to fail if the architecture bits
		 * do not match the expected architecture bits.  This in
		 * turn causes load_dylinker() to fail for the same reason,
		 * so it ensures the dynamic linker and the binary are in
		 * lock-step.  This is potentially bad, if we ever add to
		 * the CPU_ARCH_* bits any bits that are desirable but not
		 * required, since the dynamic linker might work, but we will
		 * refuse to load it because of this check.
		 */
		if ((cpu_type_t)(header.mach_header.cputype & CPU_ARCH_MASK) != archbits)
			return(LOAD_BADARCH);

		*file_offset = 0;
		*macho_size = fsize;
	}

	*mach_header = header.mach_header;
	*vpp = vp;

	ubc_setsize(vp, fsize);
	
	return (error);

bad2:
	err2 = VNOP_CLOSE(vp, FREAD, ctx);
	vnode_put(vp);
	return (error);

bad1:
	vnode_put(vp);
	return(error);
}
