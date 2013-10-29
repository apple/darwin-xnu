/*
 * Copyright (c) 2000-2010 Apple Inc. All rights reserved.
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
#include <sys/codesign.h>

#include <mach/mach_types.h>
#include <mach/vm_map.h>	/* vm_allocate() */
#include <mach/mach_vm.h>	/* mach_vm_allocate() */
#include <mach/vm_statistics.h>
#include <mach/task.h>
#include <mach/thread_act.h>

#include <machine/vmparam.h>
#include <machine/exec.h>
#include <machine/pal_routines.h>

#include <kern/kern_types.h>
#include <kern/cpu_number.h>
#include <kern/mach_loader.h>
#include <kern/mach_fat.h>
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
#include <IOKit/IOReturn.h>	/* for kIOReturnNotPrivileged */

/*
 * XXX vm/pmap.h should not treat these prototypes as MACH_KERNEL_PRIVATE
 * when KERNEL is defined.
 */
extern pmap_t	pmap_create(ledger_t ledger, vm_map_size_t size,
				boolean_t is_64bit);

/* XXX should have prototypes in a shared header file */
extern int	get_map_nentries(vm_map_t);

extern kern_return_t	memory_object_signed(memory_object_control_t control,
					     boolean_t is_signed);

/* An empty load_result_t */
static load_result_t load_result_null = {
	.mach_header = MACH_VM_MIN_ADDRESS,
	.entry_point = MACH_VM_MIN_ADDRESS,
	.user_stack = MACH_VM_MIN_ADDRESS,
	.user_stack_size = 0,
	.all_image_info_addr = MACH_VM_MIN_ADDRESS,
	.all_image_info_size = 0,
	.thread_count = 0,
	.unixproc = 0,
	.dynlinker = 0,
	.needs_dynlinker = 0,
	.prog_allocated_stack = 0,
	.prog_stack_size = 0,
	.validentry = 0,
	.csflags = 0,
	.uuid = { 0 },
	.min_vm_addr = MACH_VM_MAX_ADDRESS,
	.max_vm_addr = MACH_VM_MIN_ADDRESS
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
	int64_t			slide,
	int64_t			dyld_slide,	
	load_result_t		*result
);

static load_return_t
load_segment(
	struct load_command		*lcp,
	uint32_t			filetype,
	void				*control,
	off_t				pager_offset,
	off_t				macho_size,
	struct vnode			*vp,
	vm_map_t			map,
	int64_t				slide,
	load_result_t			*result
);

static load_return_t
load_uuid(
	struct uuid_command		*uulp,
	char				*command_end,
	load_result_t			*result
);

static load_return_t
load_code_signature(
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
	int64_t				slide,
	struct vnode		*vp,
	cpu_type_t			cputype,
	cpu_subtype_t		cpusubtype);
#endif

static
load_return_t
load_main(
	struct entry_point_command	*epc,
	thread_t		thread,
	int64_t				slide,
	load_result_t		*result
);

static load_return_t
load_unixthread(
	struct thread_command	*tcp,
	thread_t			thread,
	int64_t				slide,
	load_result_t			*result
);

static load_return_t
load_threadstate(
	thread_t		thread,
	uint32_t	*ts,
	uint32_t	total_size
);

static load_return_t
load_threadstack(
	thread_t		thread,
	uint32_t	*ts,
	uint32_t	total_size,
	mach_vm_offset_t	*user_stack,
	int				*customstack
);

static load_return_t
load_threadentry(
	thread_t		thread,
	uint32_t	*ts,
	uint32_t	total_size,
	mach_vm_offset_t	*entry_point
);

static load_return_t
load_dylinker(
	struct dylinker_command	*lcp,
	integer_t		archbits,
	vm_map_t				map,
	thread_t			thread,
	int						depth,
	int64_t			slide,
	load_result_t			*result
);

struct macho_data;

static load_return_t
get_macho_vnode(
	char				*path,
	integer_t		archbits,
	struct mach_header	*mach_header,
	off_t			*file_offset,
	off_t			*macho_size,
	struct macho_data	*macho_data,
	struct vnode		**vpp
);

static inline void
widen_segment_command(const struct segment_command *scp32,
    struct segment_command_64 *scp)
{
	scp->cmd = scp32->cmd;
	scp->cmdsize = scp32->cmdsize;
	bcopy(scp32->segname, scp->segname, sizeof(scp->segname));
	scp->vmaddr = scp32->vmaddr;
	scp->vmsize = scp32->vmsize;
	scp->fileoff = scp32->fileoff;
	scp->filesize = scp32->filesize;
	scp->maxprot = scp32->maxprot;
	scp->initprot = scp32->initprot;
	scp->nsects = scp32->nsects;
	scp->flags = scp32->flags;
}

static void
note_all_image_info_section(const struct segment_command_64 *scp,
    boolean_t is64, size_t section_size, const void *sections,
    int64_t slide, load_result_t *result)
{
	const union {
		struct section s32;
		struct section_64 s64;
	} *sectionp;
	unsigned int i;

	if (strncmp(scp->segname, "__DATA", sizeof(scp->segname)) != 0)
		return;
	for (i = 0; i < scp->nsects; ++i) {
		sectionp = (const void *)
		    ((const char *)sections + section_size * i);
		if (0 == strncmp(sectionp->s64.sectname, "__all_image_info",
		    sizeof(sectionp->s64.sectname))) {
			result->all_image_info_addr =
			    is64 ? sectionp->s64.addr : sectionp->s32.addr;
			result->all_image_info_addr += slide;
			result->all_image_info_size =
			    is64 ? sectionp->s64.size : sectionp->s32.size;
			return;
		}
	}
}

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
	off_t			file_size = imgp->ip_vattr->va_data_size;
	
	pmap_t			pmap = 0;	/* protected by create_map */
	vm_map_t		map;
	vm_map_t		old_map;
	task_t			old_task = TASK_NULL; /* protected by create_map */
	load_result_t		myresult;
	load_return_t		lret;
	boolean_t create_map = FALSE;
	int spawn = (imgp->ip_flags & IMGPF_SPAWN);
	task_t task = current_task();
	proc_t p = current_proc();
	mach_vm_offset_t	aslr_offset = 0;
	mach_vm_offset_t	dyld_aslr_offset = 0;
	kern_return_t 		kret;

	if (macho_size > file_size) {
		return(LOAD_BADMACHO);
	}

	if (new_map == VM_MAP_NULL) {
		create_map = TRUE;
		old_task = current_task();
	}

	/*
	 * If we are spawning, we have created backing objects for the process
	 * already, which include non-lazily creating the task map.  So we
	 * are going to switch out the task map with one appropriate for the
	 * bitness of the image being loaded.
	 */
	if (spawn) {
		create_map = TRUE;
		old_task = get_threadtask(thread);
	}

	if (create_map) {
		pmap = pmap_create(get_task_ledger(task), (vm_map_size_t) 0,
				(imgp->ip_flags & IMGPF_IS_64BIT));
		pal_switch_pmap(thread, pmap, imgp->ip_flags & IMGPF_IS_64BIT);
		map = vm_map_create(pmap,
				0,
				vm_compute_max_offset((imgp->ip_flags & IMGPF_IS_64BIT)),
				TRUE);
	} else
		map = new_map;

#ifndef	CONFIG_ENFORCE_SIGNED_CODE
	/* This turns off faulting for executable pages, which allows
	 * to circumvent Code Signing Enforcement. The per process
	 * flag (CS_ENFORCEMENT) is not set yet, but we can use the
	 * global flag.
	 */
	if ( !cs_enforcement(NULL) && (header->flags & MH_ALLOW_STACK_EXECUTION) )
	        vm_map_disable_NX(map);
#endif

	/* Forcibly disallow execution from data pages on even if the arch
	 * normally permits it. */
	if ((header->flags & MH_NO_HEAP_EXECUTION) && !(imgp->ip_flags & IMGPF_ALLOW_DATA_EXEC))
		vm_map_disallow_data_exec(map);
	
	/*
	 * Compute a random offset for ASLR, and an independent random offset for dyld.
	 */
	if (!(imgp->ip_flags & IMGPF_DISABLE_ASLR)) {
		uint64_t max_slide_pages;

		max_slide_pages = vm_map_get_max_aslr_slide_pages(map);

		aslr_offset = random();
		aslr_offset %= max_slide_pages;
		aslr_offset <<= vm_map_page_shift(map);

		dyld_aslr_offset = random();
		dyld_aslr_offset %= max_slide_pages;
		dyld_aslr_offset <<= vm_map_page_shift(map);
	}
	
	if (!result)
		result = &myresult;

	*result = load_result_null;

	lret = parse_machfile(vp, map, thread, header, file_offset, macho_size,
	                      0, (int64_t)aslr_offset, (int64_t)dyld_aslr_offset, result);

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
	     vm_map_has_4GB_pagezero(map)) {
		vm_map_set_4GB_pagezero(map);
	}
	/*
	 *	Commit to new map.
	 *
	 *	Swap the new map for the old, which  consumes our new map
	 *	reference but each leaves us responsible for the old_map reference.
	 *	That lets us get off the pmap associated with it, and
	 *	then we can release it.
	 */

	 if (create_map) {
		/*
		 * If this is an exec, then we are going to destroy the old
		 * task, and it's correct to halt it; if it's spawn, the
		 * task is not yet running, and it makes no sense.
		 */
	 	if (!spawn) {
			/*
			 * Mark the task as halting and start the other
			 * threads towards terminating themselves.  Then
			 * make sure any threads waiting for a process
			 * transition get informed that we are committed to
			 * this transition, and then finally complete the
			 * task halting (wait for threads and then cleanup
			 * task resources).
			 *
			 * NOTE: task_start_halt() makes sure that no new
			 * threads are created in the task during the transition.
			 * We need to mark the workqueue as exiting before we
			 * wait for threads to terminate (at the end of which
			 * we no longer have a prohibition on thread creation).
			 * 
			 * Finally, clean up any lingering workqueue data structures
			 * that may have been left behind by the workqueue threads
			 * as they exited (and then clean up the work queue itself).
			 */
			kret = task_start_halt(task);
			if (kret != KERN_SUCCESS) {
				return(kret);		
			}
			proc_transcommit(p, 0);
			workqueue_mark_exiting(p);
			task_complete_halt(task);
			workqueue_exit(p);
		}
		old_map = swap_task_map(old_task, thread, map, !spawn);
		vm_map_clear_4GB_pagezero(old_map);
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
 * the total set of possible commands. If "map"==VM_MAP_NULL or
 * "thread"==THREAD_NULL, do not make permament VM modifications,
 * just preflight the parse.
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
	int64_t			aslr_offset,
	int64_t			dyld_aslr_offset,
	load_result_t		*result
)
{
	uint32_t		ncmds;
	struct load_command	*lcp;
	struct dylinker_command	*dlp = 0;
	integer_t		dlarchbits = 0;
	void *			control;
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
	size_t			mach_header_sz = sizeof(struct mach_header);
	boolean_t		abi64;
	boolean_t		got_code_signatures = FALSE;
	int64_t			slide = 0;

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

	depth++;

	/*
	 *	Check to see if right machine type.
	 */
	if (((cpu_type_t)(header->cputype & ~CPU_ARCH_MASK) != (cpu_type() & ~CPU_ARCH_MASK)) ||
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
	control = ubc_getobject(vp, UBC_FLAGS_NONE);

	/*
	 *	Map portion that must be accessible directly into
	 *	kernel's map.
	 */
	if ((off_t)(mach_header_sz + header->sizeofcmds) > macho_size)
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
	    UIO_SYSSPACE, 0, kauth_cred_get(), &resid, p);
	if (error) {
		if (kl_addr )
			kfree(kl_addr, kl_size);
		return(LOAD_IOERROR);
	}

	/*
	 *	For PIE and dyld, slide everything by the ASLR offset.
	 */
	if ((header->flags & MH_PIE) || (header->filetype == MH_DYLINKER)) {
		slide = aslr_offset;
	}

	 /*
	 *  Scan through the commands, processing each one as necessary.
	 *  We parse in three passes through the headers:
	 *  1: thread state, uuid, code signature
	 *  2: segments
	 *  3: dyld, encryption, check entry point
	 */
	
	for (pass = 1; pass <= 3; pass++) {

		/*
		 * Check that the entry point is contained in an executable segments
		 */ 
		if ((pass == 3) && (result->validentry == 0)) {
			thread_state_initialize(thread);
			ret = LOAD_FAILURE;
			break;
		}

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
			case LC_SEGMENT:
				if (pass != 2)
					break;

				if (abi64) {
					/*
					 * Having an LC_SEGMENT command for the
					 * wrong ABI is invalid <rdar://problem/11021230>
					 */
					ret = LOAD_BADMACHO;
					break;
				}

				ret = load_segment(lcp,
				                   header->filetype,
				                   control,
				                   file_offset,
				                   macho_size,
				                   vp,
				                   map,
				                   slide,
				                   result);
				break;
			case LC_SEGMENT_64:
				if (pass != 2)
					break;

				if (!abi64) {
					/*
					 * Having an LC_SEGMENT_64 command for the
					 * wrong ABI is invalid <rdar://problem/11021230>
					 */
					ret = LOAD_BADMACHO;
					break;
				}

				ret = load_segment(lcp,
				                   header->filetype,
				                   control,
				                   file_offset,
				                   macho_size,
				                   vp,
				                   map,
				                   slide,
				                   result);
				break;
			case LC_UNIXTHREAD:
				if (pass != 1)
					break;
				ret = load_unixthread(
						 (struct thread_command *) lcp,
						 thread,
						 slide,
						 result);
				break;
			case LC_MAIN:
				if (pass != 1)
					break;
				if (depth != 1)
					break;
				ret = load_main(
						 (struct entry_point_command *) lcp,
						 thread,
						 slide,
						 result);
				break;
			case LC_LOAD_DYLINKER:
				if (pass != 3)
					break;
				if ((depth == 1) && (dlp == 0)) {
					dlp = (struct dylinker_command *)lcp;
					dlarchbits = (header->cputype & CPU_ARCH_MASK);
				} else {
					ret = LOAD_FAILURE;
				}
				break;
			case LC_UUID:
				if (pass == 1 && depth == 1) {
					ret = load_uuid((struct uuid_command *) lcp,
							(char *)addr + mach_header_sz + header->sizeofcmds,
							result);
				}
				break;
			case LC_CODE_SIGNATURE:
				/* CODE SIGNING */
				if (pass != 1)
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
			case LC_ENCRYPTION_INFO_64:
				if (pass != 3)
					break;
				ret = set_code_unprotect(
					(struct encryption_info_command *) lcp,
					addr, map, slide, vp,
					header->cputype, header->cpusubtype);
				if (ret != LOAD_SUCCESS) {
					printf("proc %d: set_code_unprotect() error %d "
					       "for file \"%s\"\n",
					       p->p_pid, ret, vp->v_name);
					/* 
					 * Don't let the app run if it's 
					 * encrypted but we failed to set up the
					 * decrypter. If the keys are missing it will
					 * return LOAD_DECRYPTFAIL.
					 */
					 if (ret == LOAD_DECRYPTFAIL) {
						/* failed to load due to missing FP keys */
						proc_lock(p);
						p->p_lflag |= P_LTERM_DECRYPTFAIL;
						proc_unlock(p);
					}
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

		/* Make sure if we need dyld, we got it */
		if (result->needs_dynlinker && !dlp) {
			ret = LOAD_FAILURE;
		}

	    if ((ret == LOAD_SUCCESS) && (dlp != 0)) {
		/*
		 * load the dylinker, and slide it by the independent DYLD ASLR
		 * offset regardless of the PIE-ness of the main binary.
		 */

		ret = load_dylinker(dlp, dlarchbits, map, thread, depth,
		                    dyld_aslr_offset, result);
	    }

	    if((ret == LOAD_SUCCESS) && (depth == 1)) {
			if (result->thread_count == 0) {
				ret = LOAD_FAILURE;
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
unprotect_segment(
	uint64_t	file_off,
	uint64_t	file_size,
	struct vnode	*vp,
	off_t		macho_offset,
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
#pragma unused(vp, macho_offset)
		crypt_info.crypt_ops = (void *)0x2e69cf40;
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
static load_return_t
unprotect_segment(
	__unused	uint64_t	file_off,
	__unused	uint64_t	file_size,
	__unused	struct vnode	*vp,
	__unused	off_t		macho_offset,
	__unused	vm_map_t	map,
	__unused	vm_map_offset_t	map_addr,
	__unused	vm_map_size_t	map_size)
{
	return LOAD_SUCCESS;
}
#endif	/* CONFIG_CODE_DECRYPTION */

static
load_return_t
load_segment(
	struct load_command		*lcp,
	uint32_t			filetype,
	void *				control,
	off_t				pager_offset,
	off_t				macho_size,
	struct vnode			*vp,
	vm_map_t			map,
	int64_t				slide,
	load_result_t		*result
)
{
	struct segment_command_64 segment_command, *scp;
	kern_return_t		ret;
	vm_map_offset_t		map_addr, map_offset;
	vm_map_size_t		map_size, seg_size, delta_size;
	vm_prot_t 		initprot;
	vm_prot_t		maxprot;
	size_t			segment_command_size, total_section_size,
				single_section_size;
	boolean_t		prohibit_pagezero_mapping = FALSE;
	
	if (LC_SEGMENT_64 == lcp->cmd) {
		segment_command_size = sizeof(struct segment_command_64);
		single_section_size  = sizeof(struct section_64);
	} else {
		segment_command_size = sizeof(struct segment_command);
		single_section_size  = sizeof(struct section);
	}
	if (lcp->cmdsize < segment_command_size)
		return (LOAD_BADMACHO);
	total_section_size = lcp->cmdsize - segment_command_size;

	if (LC_SEGMENT_64 == lcp->cmd)
		scp = (struct segment_command_64 *)lcp;
	else {
		scp = &segment_command;
		widen_segment_command((struct segment_command *)lcp, scp);
	}

	/*
	 * Make sure what we get from the file is really ours (as specified
	 * by macho_size).
	 */
	if (scp->fileoff + scp->filesize < scp->fileoff ||
	    scp->fileoff + scp->filesize > (uint64_t)macho_size)
		return (LOAD_BADMACHO);
	/*
	 * Ensure that the number of sections specified would fit
	 * within the load command size.
	 */
	if (total_section_size / single_section_size < scp->nsects)
		return (LOAD_BADMACHO);
	/*
	 * Make sure the segment is page-aligned in the file.
	 */
	if ((scp->fileoff & PAGE_MASK_64) != 0)
		return (LOAD_BADMACHO);

	/*
	 *	Round sizes to page size.
	 */
	seg_size = round_page_64(scp->vmsize);
	map_size = round_page_64(scp->filesize);
	map_addr = trunc_page_64(scp->vmaddr); /* JVXXX note that in XNU TOT this is round instead of trunc for 64 bits */

	seg_size = vm_map_round_page(seg_size, vm_map_page_mask(map));
	map_size = vm_map_round_page(map_size, vm_map_page_mask(map));

	if (seg_size == 0)
		return (KERN_SUCCESS);
	if (map_addr == 0 &&
	    map_size == 0 &&
	    seg_size != 0 &&
	    (scp->initprot & VM_PROT_ALL) == VM_PROT_NONE &&
	    (scp->maxprot & VM_PROT_ALL) == VM_PROT_NONE) {
		/*
		 * For PIE, extend page zero rather than moving it.  Extending
		 * page zero keeps early allocations from falling predictably
		 * between the end of page zero and the beginning of the first
		 * slid segment.
		 */
		seg_size += slide;
		slide = 0;
		/* XXX (4596982) this interferes with Rosetta, so limit to 64-bit tasks */
		if (scp->cmd == LC_SEGMENT_64) {
		        prohibit_pagezero_mapping = TRUE;
		}
		
		if (prohibit_pagezero_mapping) {
			/*
			 * This is a "page zero" segment:  it starts at address 0,
			 * is not mapped from the binary file and is not accessible.
			 * User-space should never be able to access that memory, so
			 * make it completely off limits by raising the VM map's
			 * minimum offset.
			 */
			ret = vm_map_raise_min_offset(map, seg_size);
			if (ret != KERN_SUCCESS) {
				return (LOAD_FAILURE);
			}
			return (LOAD_SUCCESS);
		}
	}

	/* If a non-zero slide was specified by the caller, apply now */
	map_addr += slide;

	if (map_addr < result->min_vm_addr)
		result->min_vm_addr = map_addr;
	if (map_addr+seg_size > result->max_vm_addr)
		result->max_vm_addr = map_addr+seg_size;

	if (map == VM_MAP_NULL)
		return (LOAD_SUCCESS);

	map_offset = pager_offset + scp->fileoff;	/* limited to 32 bits */

	if (map_size > 0) {
		initprot = (scp->initprot) & VM_PROT_ALL;
		maxprot = (scp->maxprot) & VM_PROT_ALL;
		/*
		 *	Map a copy of the file into the address space.
		 */
		ret = vm_map_enter_mem_object_control(map,
				&map_addr, map_size, (mach_vm_offset_t)0,
			        VM_FLAGS_FIXED,	control, map_offset, TRUE,
				initprot, maxprot,
				VM_INHERIT_DEFAULT);
		if (ret != KERN_SUCCESS) {
			return (LOAD_NOSPACE);
		}
	
		/*
		 *	If the file didn't end on a page boundary,
		 *	we need to zero the leftover.
		 */
		delta_size = map_size - scp->filesize;
#if FIXME
		if (delta_size > 0) {
			mach_vm_offset_t	tmp;
	
			ret = mach_vm_allocate(kernel_map, &tmp, delta_size, VM_FLAGS_ANYWHERE);
			if (ret != KERN_SUCCESS)
				return(LOAD_RESOURCE);
	
			if (copyout(tmp, map_addr + scp->filesize,
								delta_size)) {
				(void) mach_vm_deallocate(
						kernel_map, tmp, delta_size);
				return (LOAD_FAILURE);
			}
	
			(void) mach_vm_deallocate(kernel_map, tmp, delta_size);
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
				  scp->initprot, scp->maxprot,
				  VM_INHERIT_DEFAULT);
		if (ret != KERN_SUCCESS)
			return(LOAD_NOSPACE);
	}

	if ( (scp->fileoff == 0) && (scp->filesize != 0) )
		result->mach_header = map_addr;

	if (scp->flags & SG_PROTECTED_VERSION_1) {
		ret = unprotect_segment(scp->fileoff,
					scp->filesize,
					vp,
					pager_offset,
					map,
					map_addr,
					map_size);
	} else {
		ret = LOAD_SUCCESS;
	}
	if (LOAD_SUCCESS == ret && filetype == MH_DYLINKER &&
	    result->all_image_info_addr == MACH_VM_MIN_ADDRESS)
		note_all_image_info_section(scp,
		    LC_SEGMENT_64 == lcp->cmd, single_section_size,
		    (const char *)lcp + segment_command_size, slide, result);

	if ((result->entry_point >= map_addr) && (result->entry_point < (map_addr + map_size)))
		result->validentry = 1;

	return ret;
}

static
load_return_t
load_uuid(
	struct uuid_command	*uulp,
	char			*command_end,
	load_result_t		*result
)
{
		/*
		 * We need to check the following for this command:
		 * - The command size should be atleast the size of struct uuid_command
		 * - The UUID part of the command should be completely within the mach-o header
		 */

		if ((uulp->cmdsize < sizeof(struct uuid_command)) ||
		    (((char *)uulp + sizeof(struct uuid_command)) > command_end)) {
			return (LOAD_BADMACHO);
		}
		
		memcpy(&result->uuid[0], &uulp->uuid[0], sizeof(result->uuid));
		return (LOAD_SUCCESS);
}

static
load_return_t
load_main(
	struct entry_point_command	*epc,
	thread_t		thread,
	int64_t				slide,
	load_result_t		*result
)
{
	mach_vm_offset_t addr;
	kern_return_t	ret;
	
	if (epc->cmdsize < sizeof(*epc))
		return (LOAD_BADMACHO);
	if (result->thread_count != 0) {
		printf("load_main: already have a thread!");
		return (LOAD_FAILURE);
	}

	if (thread == THREAD_NULL)
		return (LOAD_SUCCESS);
	
	/* LC_MAIN specifies stack size but not location */
	if (epc->stacksize) {
		result->prog_stack_size = 1;
		result->user_stack_size = epc->stacksize;
	} else {
		result->prog_stack_size = 0;
		result->user_stack_size = MAXSSIZ;
	}
	result->prog_allocated_stack = 0;

	/* use default location for stack */
	ret = thread_userstackdefault(thread, &addr);
	if (ret != KERN_SUCCESS)
		return(LOAD_FAILURE);

	/* The stack slides down from the default location */
	result->user_stack = addr;
	result->user_stack -= slide;

	/* kernel does *not* use entryoff from LC_MAIN.	 Dyld uses it. */
	result->needs_dynlinker = TRUE;
	result->validentry = TRUE;

	ret = thread_state_initialize( thread );
	if (ret != KERN_SUCCESS) {
		return(LOAD_FAILURE);
	}

	result->unixproc = TRUE;
	result->thread_count++;

	return(LOAD_SUCCESS);
}


static
load_return_t
load_unixthread(
	struct thread_command	*tcp,
	thread_t		thread,
	int64_t				slide,
	load_result_t		*result
)
{
	load_return_t	ret;
	int customstack =0;
	mach_vm_offset_t addr;
	
	if (tcp->cmdsize < sizeof(*tcp))
		return (LOAD_BADMACHO);
	if (result->thread_count != 0) {
		printf("load_unixthread: already have a thread!");
		return (LOAD_FAILURE);
	}

	if (thread == THREAD_NULL)
		return (LOAD_SUCCESS);
	
	ret = load_threadstack(thread,
		       (uint32_t *)(((vm_offset_t)tcp) + 
		       		sizeof(struct thread_command)),
		       tcp->cmdsize - sizeof(struct thread_command),
		       &addr,
			   &customstack);
	if (ret != LOAD_SUCCESS)
		return(ret);

	/* LC_UNIXTHREAD optionally specifies stack size and location */
    
	if (customstack) {
		result->prog_stack_size = 0;	/* unknown */
		result->prog_allocated_stack = 1;
	} else {
		result->prog_allocated_stack = 0;
		result->prog_stack_size = 0;
		result->user_stack_size = MAXSSIZ;
	}

	/* The stack slides down from the default location */
	result->user_stack = addr;
	result->user_stack -= slide;

	ret = load_threadentry(thread,
		       (uint32_t *)(((vm_offset_t)tcp) + 
		       		sizeof(struct thread_command)),
		       tcp->cmdsize - sizeof(struct thread_command),
		       &addr);
	if (ret != LOAD_SUCCESS)
		return(ret);

	result->entry_point = addr;
	result->entry_point += slide;

	ret = load_threadstate(thread,
		       (uint32_t *)(((vm_offset_t)tcp) + 
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
	uint32_t	*ts,
	uint32_t	total_size
)
{
	kern_return_t	ret;
	uint32_t	size;
	int		flavor;
	uint32_t	thread_size;

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
		if (UINT32_MAX-2 < size ||
		    UINT32_MAX/sizeof(uint32_t) < size+2)
			return (LOAD_BADMACHO);
		thread_size = (size+2)*sizeof(uint32_t);
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
		ts += size;	/* ts is a (uint32_t *) */
	}
	return(LOAD_SUCCESS);
}

static
load_return_t
load_threadstack(
	thread_t	thread,
	uint32_t	*ts,
	uint32_t	total_size,
	mach_vm_offset_t	*user_stack,
	int *customstack
)
{
	kern_return_t	ret;
	uint32_t	size;
	int		flavor;
	uint32_t	stack_size;

	while (total_size > 0) {
		flavor = *ts++;
		size = *ts++;
		if (UINT32_MAX-2 < size ||
		    UINT32_MAX/sizeof(uint32_t) < size+2)
			return (LOAD_BADMACHO);
		stack_size = (size+2)*sizeof(uint32_t);
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
		ts += size;	/* ts is a (uint32_t *) */
	}
	return(LOAD_SUCCESS);
}

static
load_return_t
load_threadentry(
	thread_t	thread,
	uint32_t	*ts,
	uint32_t	total_size,
	mach_vm_offset_t	*entry_point
)
{
	kern_return_t	ret;
	uint32_t	size;
	int		flavor;
	uint32_t	entry_size;

	/*
	 *	Set the thread state.
	 */
	*entry_point = MACH_VM_MIN_ADDRESS;
	while (total_size > 0) {
		flavor = *ts++;
		size = *ts++;
		if (UINT32_MAX-2 < size ||
		    UINT32_MAX/sizeof(uint32_t) < size+2)
			return (LOAD_BADMACHO);
		entry_size = (size+2)*sizeof(uint32_t);
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
		ts += size;	/* ts is a (uint32_t *) */
	}
	return(LOAD_SUCCESS);
}

struct macho_data {
	struct nameidata	__nid;
	union macho_vnode_header {
		struct mach_header	mach_header;
		struct fat_header	fat_header;
		char	__pad[512];
	} __header;
};

static load_return_t
load_dylinker(
	struct dylinker_command	*lcp,
	integer_t		archbits,
	vm_map_t		map,
	thread_t	thread,
	int			depth,
	int64_t			slide,
	load_result_t		*result
)
{
	char			*name;
	char			*p;
	struct vnode		*vp = NULLVP;	/* set by get_macho_vnode() */
	struct mach_header	*header;
	off_t			file_offset = 0; /* set by get_macho_vnode() */
	off_t			macho_size = 0;	/* set by get_macho_vnode() */
	load_result_t		*myresult;
	kern_return_t		ret;
	struct macho_data	*macho_data;
	struct {
		struct mach_header	__header;
		load_result_t		__myresult;
		struct macho_data	__macho_data;
	} *dyld_data;

	if (lcp->cmdsize < sizeof(*lcp))
		return (LOAD_BADMACHO);

	name = (char *)lcp + lcp->name.offset;
	/*
	 *	Check for a proper null terminated string.
	 */
	p = name;
	do {
		if (p >= (char *)lcp + lcp->cmdsize)
			return(LOAD_BADMACHO);
	} while (*p++);

	/* Allocate wad-of-data from heap to reduce excessively deep stacks */

	MALLOC(dyld_data, void *, sizeof (*dyld_data), M_TEMP, M_WAITOK);
	header = &dyld_data->__header;
	myresult = &dyld_data->__myresult;
	macho_data = &dyld_data->__macho_data;

	ret = get_macho_vnode(name, archbits, header,
	    &file_offset, &macho_size, macho_data, &vp);
	if (ret)
		goto novp_out;

	*myresult = load_result_null;

	/*
	 *	First try to map dyld in directly.  This should work most of
	 *	the time since there shouldn't normally be something already
	 *	mapped to its address.
	 */

	ret = parse_machfile(vp, map, thread, header, file_offset,
	                     macho_size, depth, slide, 0, myresult);

	/*
	 *	If it turned out something was in the way, then we'll take
	 *	take this longer path to preflight dyld's vm ranges, then
	 *	map it at a free location in the address space.
	 */

	if (ret == LOAD_NOSPACE) {
		mach_vm_offset_t	dyl_start, map_addr;
		mach_vm_size_t	dyl_length;
		int64_t			slide_amount;

		*myresult = load_result_null;

		/*
		 * Preflight parsing the Mach-O file with a NULL
		 * map, which will return the ranges needed for a
		 * subsequent map attempt (with a slide) in "myresult"
		 */
		ret = parse_machfile(vp, VM_MAP_NULL, THREAD_NULL, header,
		                     file_offset, macho_size, depth,
		                     0 /* slide */, 0, myresult);

		if (ret != LOAD_SUCCESS) {
			goto out;
		}

		dyl_start = myresult->min_vm_addr;
		dyl_length = myresult->max_vm_addr - myresult->min_vm_addr;

		dyl_length += slide;

		/* To find an appropriate load address, do a quick allocation */
		map_addr = dyl_start;
		ret = mach_vm_allocate(map, &map_addr, dyl_length, VM_FLAGS_ANYWHERE);
		if (ret != KERN_SUCCESS) {
			ret = LOAD_NOSPACE;
			goto out;
		}

		ret = mach_vm_deallocate(map, map_addr, dyl_length);
		if (ret != KERN_SUCCESS) {
			ret = LOAD_NOSPACE;
			goto out;
		}
		
		if (map_addr < dyl_start)
			slide_amount = -(int64_t)(dyl_start - map_addr);
		else
			slide_amount = (int64_t)(map_addr - dyl_start);

		slide_amount += slide;

		*myresult = load_result_null;

		ret = parse_machfile(vp, map, thread, header,
		                     file_offset, macho_size, depth,
		                     slide_amount, 0, myresult);

		if (ret) {
			goto out;
		}
	}

	if (ret == LOAD_SUCCESS) {		
		result->dynlinker = TRUE;
		result->entry_point = myresult->entry_point;
		result->validentry = myresult->validentry;
		result->all_image_info_addr = myresult->all_image_info_addr;
		result->all_image_info_size = myresult->all_image_info_size;
	}
out:
	vnode_put(vp);
novp_out:
	FREE(dyld_data, M_TEMP);
	return (ret);

}

static load_return_t
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
	if (blob != NULL &&
	    blob->csb_cpu_type == cputype &&
	    blob->csb_base_offset == macho_offset &&
	    blob->csb_blob_offset == lcp->dataoff &&
	    blob->csb_mem_size == lcp->datasize) {
		/* 
		 * we already have a blob for this vnode and cputype
		 * and its at the same offset in Mach-O.  Optimize to
		 * not reload, revalidate, and compare the blob hashes.
		 * Security will not be compromised, but we might miss
		 * out on some messagetracer info about the differences
		 * in blob content.
		 */
		ret = LOAD_SUCCESS;
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
			UIO_SYSSPACE,
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
			    lcp->dataoff,
			    lcp->datasize)) {
		ret = LOAD_FAILURE;
		goto out;
	} else {
		/* ubc_cs_blob_add() has consumed "addr" */
		addr = 0;
	}

#if CHECK_CS_VALIDATION_BITMAP
	ubc_cs_validation_bitmap_allocate( vp );
#endif
		
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
		   int64_t slide,
		   struct vnode	*vp,
		   cpu_type_t cputype,
		   cpu_subtype_t cpusubtype)
{
	int result, len;
	pager_crypt_info_t crypt_info;
	const char * cryptname = 0;
	char *vpath;
	
	size_t offset;
	struct segment_command_64 *seg64;
	struct segment_command *seg32;
	vm_map_offset_t map_offset, map_size;
	kern_return_t kr;

	if (eip->cmdsize < sizeof(*eip)) return LOAD_BADMACHO;
	
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
	
	if (map == VM_MAP_NULL) return (LOAD_SUCCESS);
	if (NULL == text_crypter_create) return LOAD_FAILURE;

	MALLOC_ZONE(vpath, char *, MAXPATHLEN, M_NAMEI, M_WAITOK);
	if(vpath == NULL) return LOAD_FAILURE;
	
	len = MAXPATHLEN;
	result = vn_getpath(vp, vpath, &len);
	if(result) {
		FREE_ZONE(vpath, MAXPATHLEN, M_NAMEI);
		return LOAD_FAILURE;
	}
	
	/* set up decrypter first */
	crypt_file_data_t crypt_data = {
		.filename = vpath,
		.cputype = cputype,
		.cpusubtype = cpusubtype};
	kr=text_crypter_create(&crypt_info, cryptname, (void*)&crypt_data);
	FREE_ZONE(vpath, MAXPATHLEN, M_NAMEI);
	
	if(kr) {
		printf("set_code_unprotect: unable to create decrypter %s, kr=%d\n",
		       cryptname, kr);
		if (kr == kIOReturnNotPrivileged) {
			/* text encryption returned decryption failure */
			return(LOAD_DECRYPTFAIL);
		 }else
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
					map_offset = seg64->vmaddr + eip->cryptoff - seg64->fileoff + slide;
					map_size = eip->cryptsize;
					goto remap_now;
				}
			case LC_SEGMENT:
				seg32 = (struct segment_command *)lcp;
				if ((seg32->fileoff <= eip->cryptoff) &&
				    (seg32->fileoff+seg32->filesize >= 
				     eip->cryptoff+eip->cryptsize)) {
					map_offset = seg32->vmaddr + eip->cryptoff - seg32->fileoff + slide;
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
	struct macho_data	*data,
	struct vnode		**vpp
)
{
	struct vnode		*vp;
	vfs_context_t		ctx = vfs_context_current();
	proc_t			p = vfs_context_proc(ctx);
	kauth_cred_t		kerncred;
	struct nameidata	*ndp = &data->__nid;
	boolean_t		is_fat;
	struct fat_arch		fat_arch;
	int			error;
	int resid;
	union macho_vnode_header *header = &data->__header;
	off_t fsize = (off_t)0;

	/*
	 * Capture the kernel credential for use in the actual read of the
	 * file, since the user doing the execution may have execute rights
	 * but not read rights, but to exec something, we have to either map
	 * or read it into the new process address space, which requires
	 * read rights.  This is to deal with lack of common credential
	 * serialization code which would treat NOCRED as "serialize 'root'".
	 */
	kerncred = vfs_context_ucred(vfs_context_kernel());

	/* init the namei data to point the file user's program name */
	NDINIT(ndp, LOOKUP, OP_OPEN, FOLLOW | LOCKLEAF, UIO_SYSSPACE, CAST_USER_ADDR_T(path), ctx);

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
	if ((error = vnode_authorize(vp, NULL, KAUTH_VNODE_EXECUTE | KAUTH_VNODE_READ_DATA, ctx)) != 0) {
		error = LOAD_PROTECT;
		goto bad1;
	}

	/* try to open it */
	if ((error = VNOP_OPEN(vp, FREAD, ctx)) != 0) {
		error = LOAD_PROTECT;
		goto bad1;
	}

	if ((error = vn_rdwr(UIO_READ, vp, (caddr_t)header, sizeof (*header), 0,
	    UIO_SYSSPACE, IO_NODELOCKED, kerncred, &resid, p)) != 0) {
		error = LOAD_IOERROR;
		goto bad2;
	}

	if (header->mach_header.magic == MH_MAGIC ||
	    header->mach_header.magic == MH_MAGIC_64) {
		is_fat = FALSE;
	} else if (header->fat_header.magic == FAT_MAGIC ||
	    header->fat_header.magic == FAT_CIGAM) {
		is_fat = TRUE;
	} else {
		error = LOAD_BADMACHO;
		goto bad2;
	}

	if (is_fat) {
		/* Look up our architecture in the fat file. */
		error = fatfile_getarch_with_bits(vp, archbits,
		    (vm_offset_t)(&header->fat_header), &fat_arch);
		if (error != LOAD_SUCCESS)
			goto bad2;

		/* Read the Mach-O header out of it */
		error = vn_rdwr(UIO_READ, vp, (caddr_t)&header->mach_header,
		    sizeof (header->mach_header), fat_arch.offset,
		    UIO_SYSSPACE, IO_NODELOCKED, kerncred, &resid, p);
		if (error) {
			error = LOAD_IOERROR;
			goto bad2;
		}

		/* Is this really a Mach-O? */
		if (header->mach_header.magic != MH_MAGIC &&
		    header->mach_header.magic != MH_MAGIC_64) {
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
		if ((cpu_type_t)(header->mach_header.cputype & CPU_ARCH_MASK) != archbits) {
			error = LOAD_BADARCH;
			goto bad2;
		}

		*file_offset = 0;
		*macho_size = fsize;
	}

	*mach_header = header->mach_header;
	*vpp = vp;

	ubc_setsize(vp, fsize);
	return (error);

bad2:
	(void) VNOP_CLOSE(vp, FREAD, ctx);
bad1:
	vnode_put(vp);
	return(error);
}
