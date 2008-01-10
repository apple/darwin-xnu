/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
/* Copyright (c) 1991 NeXT Computer, Inc.  All rights reserved.
 *
 *	File:	bsd/kern/kern_core.c
 *
 *	This file contains machine independent code for performing core dumps.
 *
 */

#include <mach/vm_param.h>
#include <mach/thread_status.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/signalvar.h>
#include <sys/resourcevar.h>
#include <sys/namei.h>
#include <sys/vnode_internal.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/timeb.h>
#include <sys/times.h>
#include <sys/acct.h>
#include <sys/file_internal.h>
#include <sys/uio.h>
#include <sys/kernel.h>
#include <sys/stat.h>

#include <mach-o/loader.h>
#include <mach/vm_region.h>
#include <mach/vm_statistics.h>

#include <vm/vm_kern.h>
#include <vm/vm_protos.h> /* last */
#include <vm/vm_map.h>		/* current_map() */
#include <mach/mach_vm.h>	/* mach_vm_region_recurse() */
#include <mach/task.h>		/* task_suspend() */
#include <kern/task.h>		/* get_task_numacts() */

typedef struct {
	int	flavor;			/* the number for this flavor */
	int	count;			/* count of ints in this flavor */
} mythread_state_flavor_t;

#if defined (__ppc__)

mythread_state_flavor_t thread_flavor_array[]={
		{PPC_THREAD_STATE , PPC_THREAD_STATE_COUNT},
		{PPC_FLOAT_STATE, PPC_FLOAT_STATE_COUNT}, 
		{PPC_EXCEPTION_STATE, PPC_EXCEPTION_STATE_COUNT},
		{PPC_VECTOR_STATE, PPC_VECTOR_STATE_COUNT}
		};
int mynum_flavors=4;
#elif defined (__i386__)
mythread_state_flavor_t thread_flavor_array [] = { 
		{x86_THREAD_STATE, x86_THREAD_STATE_COUNT},
		{x86_FLOAT_STATE, x86_FLOAT_STATE_COUNT},
		{x86_EXCEPTION_STATE, x86_EXCEPTION_STATE_COUNT},
		};
int mynum_flavors=3;

#else
#error architecture not supported
#endif


typedef struct {
	vm_offset_t header; 
	int  hoffset;
	mythread_state_flavor_t *flavors;
	int tstate_size;
} tir_t;

/* XXX should be static */
void collectth_state(thread_t th_act, void *tirp);

/* XXX not in a Mach header anywhere */
kern_return_t thread_getstatus(register thread_t act, int flavor,
	thread_state_t tstate, mach_msg_type_number_t *count);
void task_act_iterate_wth_args(task_t, void(*)(thread_t, void *), void *);


__private_extern__ int do_coredump = 1;	/* default: dump cores */
__private_extern__ int sugid_coredump = 0; /* default: but not SGUID binaries */

void
collectth_state(thread_t th_act, void *tirp)
{
	vm_offset_t	header;
	int  hoffset, i ;
	mythread_state_flavor_t *flavors;
	struct thread_command	*tc;
	tir_t *t = (tir_t *)tirp;

		/*
		 *	Fill in thread command structure.
		 */
		header = t->header;
		hoffset = t->hoffset;
		flavors = t->flavors;
	
		tc = (struct thread_command *) (header + hoffset);
		tc->cmd = LC_THREAD;
		tc->cmdsize = sizeof(struct thread_command)
				+ t->tstate_size;
		hoffset += sizeof(struct thread_command);
		/*
		 * Follow with a struct thread_state_flavor and
		 * the appropriate thread state struct for each
		 * thread state flavor.
		 */
		for (i = 0; i < mynum_flavors; i++) {
			*(mythread_state_flavor_t *)(header+hoffset) =
			  flavors[i];
			hoffset += sizeof(mythread_state_flavor_t);
			thread_getstatus(th_act, flavors[i].flavor,
					(thread_state_t)(header+hoffset),
					&flavors[i].count);
			hoffset += flavors[i].count*sizeof(int);
		}

		t->hoffset = hoffset;
}

/*
 * Create a core image on the file "core".
 */
#define	MAX_TSTATE_FLAVORS	10
int
coredump(struct proc *p)
{
	int error=0;
	kauth_cred_t cred = kauth_cred_get();
	struct vnode_attr va;
	struct vfs_context context;
	vm_map_t	map;
	int		thread_count, segment_count;
	int		command_size, header_size, tstate_size;
	int		hoffset;
	off_t		foffset;
	vm_map_offset_t	vmoffset;
	vm_offset_t	header;
	vm_map_size_t	vmsize;
	vm_prot_t	prot;
	vm_prot_t	maxprot;
	vm_inherit_t	inherit;
	int		error1;
	task_t		task;
	char		core_name[MAXCOMLEN+6];
	char		*name;
	mythread_state_flavor_t flavors[MAX_TSTATE_FLAVORS];
	vm_size_t	mapsize;
	int		i;
	int nesting_depth = 0;
	kern_return_t	kret;
	struct vm_region_submap_info_64 vbr;
	int vbrcount=0;
	tir_t tir1;
	struct vnode * vp;
	struct mach_header	*mh;
	struct mach_header_64	*mh64;
	int		is_64 = 0;
	size_t		mach_header_sz = sizeof(struct mach_header);
	size_t		segment_command_sz = sizeof(struct segment_command);

	if (do_coredump == 0 ||		/* Not dumping at all */
	    ( (sugid_coredump == 0) &&	/* Not dumping SUID/SGID binaries */
	      ( (cred->cr_svuid != cred->cr_ruid) ||
	        (cred->cr_svgid != cred->cr_rgid)))) {
	    
		return (EFAULT);
	}

	if (IS_64BIT_PROCESS(p)) {
		is_64 = 1;
		mach_header_sz = sizeof(struct mach_header_64);
		segment_command_sz = sizeof(struct segment_command_64);
	}

	task = current_task();
	map = current_map();
	mapsize = get_vmmap_size(map);

	if (mapsize >=  p->p_rlimit[RLIMIT_CORE].rlim_cur)
		return (EFAULT);
	(void) task_suspend(task);

	/* create name according to sysctl'able format string */
	name = proc_core_name(p->p_comm, kauth_cred_getuid(cred), p->p_pid);

	/* if name creation fails, fall back to historical behaviour... */
	if (name == NULL) {
		sprintf(core_name, "/cores/core.%d", p->p_pid);
		name = core_name;
	}
	context.vc_proc = p;
	context.vc_ucred = cred;

	if ((error = vnode_open(name, (O_CREAT | FWRITE | O_NOFOLLOW), S_IRUSR, VNODE_LOOKUP_NOFOLLOW, &vp, &context)))
	        return (error);

	VATTR_INIT(&va);
	VATTR_WANTED(&va, va_nlink);
	/* Don't dump to non-regular files or files with links. */
	if (vp->v_type != VREG ||
	    vnode_getattr(vp, &va, &context) || va.va_nlink != 1) {
		error = EFAULT;
		goto out;
	}

	VATTR_INIT(&va);	/* better to do it here than waste more stack in vnode_setsize */
	VATTR_SET(&va, va_data_size, 0);
	vnode_setattr(vp, &va, &context);
	p->p_acflag |= ACORE;

	/*
	 *	If the task is modified while dumping the file
	 *	(e.g., changes in threads or VM, the resulting
	 *	file will not necessarily be correct.
	 */

	thread_count = get_task_numacts(task);
	segment_count = get_vmmap_entries(map);	/* XXX */
	bcopy(thread_flavor_array,flavors,sizeof(thread_flavor_array));
	tstate_size = 0;
	for (i = 0; i < mynum_flavors; i++)
		tstate_size += sizeof(mythread_state_flavor_t) +
		  (flavors[i].count * sizeof(int));

	command_size = segment_count * segment_command_sz +
	  thread_count*sizeof(struct thread_command) +
	  tstate_size*thread_count;

	header_size = command_size + mach_header_sz;

	(void) kmem_alloc(kernel_map,
				    (vm_offset_t *)&header,
				    (vm_size_t)header_size);

	/*
	 *	Set up Mach-O header.
	 */
	if (is_64) {
		mh64 = (struct mach_header_64 *)header;
		mh64->magic = MH_MAGIC_64;
		mh64->cputype = cpu_type();
		mh64->cpusubtype = cpu_subtype();
		mh64->filetype = MH_CORE;
		mh64->ncmds = segment_count + thread_count;
		mh64->sizeofcmds = command_size;
		mh64->reserved = 0;		/* 8 byte alignment */
	} else {
		mh = (struct mach_header *)header;
		mh->magic = MH_MAGIC;
		mh->cputype = cpu_type();
		mh->cpusubtype = cpu_subtype();
		mh->filetype = MH_CORE;
		mh->ncmds = segment_count + thread_count;
		mh->sizeofcmds = command_size;
	}

	hoffset = mach_header_sz;	/* offset into header */
	foffset = round_page(header_size);	/* offset into file */
	vmoffset = MACH_VM_MIN_ADDRESS;		/* offset into VM */

	/*
	 * We use to check for an error, here, now we try and get 
	 * as much as we can
	 */
	while (segment_count > 0) {
		struct segment_command		*sc;
		struct segment_command_64	*sc64;

		/*
		 *	Get region information for next region.
		 */
		
		while (1) {
			vbrcount = VM_REGION_SUBMAP_INFO_COUNT_64;
			if((kret = mach_vm_region_recurse(map, 
					&vmoffset, &vmsize, &nesting_depth, 
					(vm_region_recurse_info_t)&vbr,
					&vbrcount)) != KERN_SUCCESS) {
				break;
			}
			/*
			 * If we get a valid mapping back, but we're dumping
			 * a 32 bit process,  and it's over the allowable
			 * address space of a 32 bit process, it's the same
			 * as if mach_vm_region_recurse() failed.
			 */
			if (!(is_64) &&
			    (vmoffset + vmsize > VM_MAX_ADDRESS)) {
			    	kret = KERN_INVALID_ADDRESS;
				break;
			}
			if(vbr.is_submap) {
				nesting_depth++;
				continue;
			} else {
				break;
			}
		}
		if(kret != KERN_SUCCESS)
			break;

		prot = vbr.protection;
		maxprot = vbr.max_protection;
		inherit = vbr.inheritance;
		/*
		 *	Fill in segment command structure.
		 */
		if (is_64) {
			sc64 = (struct segment_command_64 *)(header + hoffset);
			sc64->cmd = LC_SEGMENT_64;
			sc64->cmdsize = sizeof(struct segment_command_64);
			/* segment name is zeroed by kmem_alloc */
			sc64->segname[0] = 0;
			sc64->vmaddr = vmoffset;
			sc64->vmsize = vmsize;
			sc64->fileoff = foffset;
			sc64->filesize = vmsize;
			sc64->maxprot = maxprot;
			sc64->initprot = prot;
			sc64->nsects = 0;
		} else  {
			sc = (struct segment_command *) (header + hoffset);
			sc->cmd = LC_SEGMENT;
			sc->cmdsize = sizeof(struct segment_command);
			/* segment name is zeroed by kmem_alloc */
			sc->segname[0] = 0;
			sc->vmaddr = CAST_DOWN(vm_offset_t,vmoffset);
			sc->vmsize = CAST_DOWN(vm_size_t,vmsize);
			sc->fileoff = CAST_DOWN(uint32_t,foffset);
			sc->filesize = CAST_DOWN(uint32_t,vmsize);
			sc->maxprot = maxprot;
			sc->initprot = prot;
			sc->nsects = 0;
		}

		/*
		 *	Write segment out.  Try as hard as possible to
		 *	get read access to the data.
		 */
		if ((prot & VM_PROT_READ) == 0) {
			mach_vm_protect(map, vmoffset, vmsize, FALSE,
					   prot|VM_PROT_READ);
		}
		/*
		 *	Only actually perform write if we can read.
		 *	Note: if we can't read, then we end up with
		 *	a hole in the file.
		 */
		if ((maxprot & VM_PROT_READ) == VM_PROT_READ
			&& vbr.user_tag != VM_MEMORY_IOKIT
			&& coredumpok(map,vmoffset)) {
			vm_map_size_t	tmp_vmsize = vmsize;
			off_t		xfer_foffset = foffset;

			//LP64todo - works around vn_rdwr_64() 2G limit
			while (tmp_vmsize > 0) {
				vm_map_size_t	xfer_vmsize = tmp_vmsize;
				if (xfer_vmsize > INT_MAX)
					xfer_vmsize = INT_MAX;
				error = vn_rdwr_64(UIO_WRITE, vp,
						vmoffset, xfer_vmsize, xfer_foffset,
					(IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32), 
					IO_NODELOCKED|IO_UNIT, cred, (int *) 0, p);
				tmp_vmsize -= xfer_vmsize;
				xfer_foffset += xfer_vmsize;
			}
		}

		hoffset += segment_command_sz;
		foffset += vmsize;
		vmoffset += vmsize;
		segment_count--;
	}

	/*
	 * If there are remaining segments which have not been written
	 * out because break in the loop above, then they were not counted
	 * because they exceed the real address space of the executable
	 * type: remove them from the header's count.  This is OK, since
	 * we are allowed to have a sparse area following the segments.
	 */
	if (is_64) {
		mh64->ncmds -= segment_count;
	} else {
		mh->ncmds -= segment_count;
	}

	tir1.header = header;
	tir1.hoffset = hoffset;
	tir1.flavors = flavors;
	tir1.tstate_size = tstate_size;
	task_act_iterate_wth_args(task, collectth_state,&tir1);

	/*
	 *	Write out the Mach header at the beginning of the
	 *	file.  OK to use a 32 bit write for this.
	 */
	error = vn_rdwr(UIO_WRITE, vp, (caddr_t)header, header_size, (off_t)0,
			UIO_SYSSPACE32, IO_NODELOCKED|IO_UNIT, cred, (int *) 0, p);
	kmem_free(kernel_map, header, header_size);
out:
	error1 = vnode_close(vp, FWRITE, &context);
	if (error == 0)
		error = error1;

	return (error);
}
