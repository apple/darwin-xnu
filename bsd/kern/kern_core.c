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
/* Copyright (c) 1991 NeXT Computer, Inc.  All rights reserved.
 *
 *	File:	bsd/kern/kern_core.c
 *
 *	This file contains machine independent code for performing core dumps.
 *
 * HISTORY
 * 16-Feb-91  Mike DeMoney (mike@next.com)
 *	Massaged into MI form from m68k/core.c.
 */

#include <mach/vm_param.h>
#include <mach/thread_status.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/signalvar.h>
#include <sys/resourcevar.h>
#include <sys/namei.h>
#include <sys/vnode.h>
#include <sys/proc.h>
#include <sys/timeb.h>
#include <sys/times.h>
#include <sys/buf.h>
#include <sys/acct.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/kernel.h>
#include <sys/stat.h>

#include <mach-o/loader.h>
#include <mach/vm_region.h>

#include <vm/vm_kern.h>

typedef struct {
	int	flavor;			/* the number for this flavor */
	int	count;			/* count of ints in this flavor */
} mythread_state_flavor_t;

#if defined (__ppc__)

mythread_state_flavor_t thread_flavor_array[]={
		{PPC_THREAD_STATE , PPC_THREAD_STATE_COUNT},
		{PPC_FLOAT_STATE, PPC_FLOAT_STATE_COUNT}, 
		{PPC_EXCEPTION_STATE, PPC_EXCEPTION_STATE_COUNT}
		};
int mynum_flavors=3;
#elif defined (__i386__)
mythread_state_flavor_t thread_flavor_array [] = { 
		{i386_THREAD_STATE, i386_THREAD_STATE_COUNT},
		{i386_THREAD_FPSTATE, i386_THREAD_FPSTATE_COUNT},
		{i386_THREAD_EXCEPTSTATE, i386_THREAD_EXCEPTSTATE_COUNT},
		{i386_THREAD_CTHREADSTATE, i386_THREAD_CTHREADSTATE_COUNT},
		{i386_NEW_THREAD_STATE, i386_NEW_THREAD_STATE_COUNT},
		{i386_FLOAT_STATE, i386_FLOAT_STATE_COUNT},
		{i386_ISA_PORT_MAP_STATE, i386_ISA_PORT_MAP_STATE_COUNT},
		{i386_V86_ASSIST_STATE, i386_V86_ASSIST_STATE_COUNT},
		{THREAD_SYSCALL_STATE, i386_THREAD_SYSCALL_STATE_COUNT}
		};
int mynum_flavors=9;

#else
#error architecture not supported
#endif


typedef struct {
	vm_offset_t header; 
	int  hoffset;
	mythread_state_flavor_t *flavors;
	int tstate_size;
} tir_t;

collectth_state(thread_act_t th_act, tir_t *t)
{
	vm_offset_t	header;
	int  hoffset, i ;
	mythread_state_flavor_t *flavors;
	struct thread_command	*tc;
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
					(thread_state_t *)(header+hoffset),
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
coredump(p)
	register struct proc *p;
{
	int error=0;
	register struct pcred *pcred = p->p_cred;
	register struct ucred *cred = pcred->pc_ucred;
	struct nameidata nd;
	struct vattr	vattr;
	vm_map_t	map;
	int		thread_count, segment_count;
	int		command_size, header_size, tstate_size;
	int		hoffset, foffset, vmoffset;
	vm_offset_t	header;
	struct machine_slot	*ms;
	struct mach_header	*mh;
	struct segment_command	*sc;
	struct thread_command	*tc;
	vm_size_t	size;
	vm_prot_t	prot;
	vm_prot_t	maxprot;
	vm_inherit_t	inherit;
	vm_offset_t	offset;
	int		error1;
	task_t		task;
	char		core_name[MAXCOMLEN+6];
	mythread_state_flavor_t flavors[MAX_TSTATE_FLAVORS];
	vm_size_t	nflavors,mapsize;
	int		i;
	int nesting_depth = 0;
	kern_return_t	kret;
	struct vm_region_submap_info_64 vbr;
	int vbrcount=0;
	tir_t tir1;
	struct vnode * vp;


	if (pcred->p_svuid != pcred->p_ruid || pcred->p_svgid != pcred->p_rgid)
		return (EFAULT);

	task = current_task();
	map = current_map();
	mapsize = get_vmmap_size(map);

	if (mapsize >=  p->p_rlimit[RLIMIT_CORE].rlim_cur)
		return (EFAULT);
	(void) task_suspend(task);

	/*
	 *	Make sure all registers, etc. are in pcb so they get
	 *	into core file.
	 */
#if defined (__ppc__)
	fpu_save();
#endif
	sprintf(core_name, "/cores/core.%d", p->p_pid);
	NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE, core_name, p);
	if(error = vn_open(&nd, O_CREAT | FWRITE, S_IRUSR ))
		return (error);
	vp = nd.ni_vp;
	
	/* Don't dump to non-regular files or files with links. */
	if (vp->v_type != VREG ||
	    VOP_GETATTR(vp, &vattr, cred, p) || vattr.va_nlink != 1) {
		error = EFAULT;
		goto out;
	}

	VATTR_NULL(&vattr);
	vattr.va_size = 0;
	VOP_LEASE(vp, p, cred, LEASE_WRITE);
	VOP_SETATTR(vp, &vattr, cred, p);
	p->p_acflag |= ACORE;

	/*
	 *	If the task is modified while dumping the file
	 *	(e.g., changes in threads or VM, the resulting
	 *	file will not necessarily be correct.
	 */

	thread_count = get_task_numacts(task);
	segment_count = get_vmmap_entries(map);	/* XXX */
	/*
	 * nflavors here is really the number of ints in flavors
	 * to meet the thread_getstatus() calling convention
	 */
#if 0
	nflavors = sizeof(flavors)/sizeof(int);
	if (thread_getstatus(current_thread(), THREAD_STATE_FLAVOR_LIST,
				(thread_state_t)(flavors),
				 &nflavors) != KERN_SUCCESS)
	    panic("core flavor list");
	/* now convert to number of flavors */
	nflavors /= sizeof(mythread_state_flavor_t)/sizeof(int);
#else
	nflavors = mynum_flavors;
	bcopy(thread_flavor_array,flavors,sizeof(thread_flavor_array));
#endif
	tstate_size = 0;
	for (i = 0; i < nflavors; i++)
		tstate_size += sizeof(mythread_state_flavor_t) +
		  (flavors[i].count * sizeof(int));

	command_size = segment_count*sizeof(struct segment_command) +
	  thread_count*sizeof(struct thread_command) +
	  tstate_size*thread_count;

	header_size = command_size + sizeof(struct mach_header);

	(void) kmem_alloc_wired(kernel_map,
				    (vm_offset_t *)&header,
				    (vm_size_t)header_size);

	/*
	 *	Set up Mach-O header.
	 */
	mh = (struct mach_header *) header;
	ms = &machine_slot[cpu_number()];
	mh->magic = MH_MAGIC;
	mh->cputype = ms->cpu_type;
	mh->cpusubtype = ms->cpu_subtype;
	mh->filetype = MH_CORE;
	mh->ncmds = segment_count + thread_count;
	mh->sizeofcmds = command_size;

	hoffset = sizeof(struct mach_header);	/* offset into header */
	foffset = round_page(header_size);	/* offset into file */
	vmoffset = VM_MIN_ADDRESS;		/* offset into VM */
	/* We use to check for an error, here, now we try and get 
	 * as much as we can
	 */
	while (segment_count > 0){
		/*
		 *	Get region information for next region.
		 */
		
		while (1) {
			vbrcount = VM_REGION_SUBMAP_INFO_COUNT_64;
			if((kret = vm_region_recurse_64(map, 
					&vmoffset, &size, &nesting_depth, 
					&vbr, &vbrcount)) != KERN_SUCCESS) {
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
		sc = (struct segment_command *) (header + hoffset);
		sc->cmd = LC_SEGMENT;
		sc->cmdsize = sizeof(struct segment_command);
		/* segment name is zerod by kmem_alloc */
		sc->vmaddr = vmoffset;
		sc->vmsize = size;
		sc->fileoff = foffset;
		sc->filesize = size;
		sc->maxprot = maxprot;
		sc->initprot = prot;
		sc->nsects = 0;

		/*
		 *	Write segment out.  Try as hard as possible to
		 *	get read access to the data.
		 */
		if ((prot & VM_PROT_READ) == 0) {
			vm_protect(map, vmoffset, size, FALSE,
				   prot|VM_PROT_READ);
		}
		/*
		 *	Only actually perform write if we can read.
		 *	Note: if we can't read, then we end up with
		 *	a hole in the file.
		 */
		if ((maxprot & VM_PROT_READ) == VM_PROT_READ) {
			error = vn_rdwr(UIO_WRITE, vp, (caddr_t)vmoffset, size, foffset,
				UIO_USERSPACE, IO_NODELOCKED|IO_UNIT, cred, (int *) 0, p);
		}

		hoffset += sizeof(struct segment_command);
		foffset += size;
		vmoffset += size;
		segment_count--;
	}

#if 0 /* [ */
	task_lock(task);
	thread = (thread_t) queue_first(&task->thread_list);
	while (thread_count > 0) {
		/*
		 *	Fill in thread command structure.
		 */
		tc = (struct thread_command *) (header + hoffset);
		tc->cmd = LC_THREAD;
		tc->cmdsize = sizeof(struct thread_command)
				+ tstate_size;
		hoffset += sizeof(struct thread_command);
		/*
		 * Follow with a struct thread_state_flavor and
		 * the appropriate thread state struct for each
		 * thread state flavor.
		 */
		for (i = 0; i < nflavors; i++) {
			*(mythread_state_flavor_t *)(header+hoffset) =
			  flavors[i];
			hoffset += sizeof(mythread_state_flavor_t);
			thread_getstatus(thread, flavors[i].flavor,
					(thread_state_t *)(header+hoffset),
					&flavors[i].count);
			hoffset += flavors[i].count*sizeof(int);
		}
		thread = (thread_t) queue_next(&thread->thread_list);
		thread_count--;
	}
	task_unlock(task);
#else /* /* 0 ][ */
	tir1.header = header;
	tir1.hoffset = hoffset;
	tir1.flavors = flavors;
	tir1.tstate_size = tstate_size;
	task_act_iterate_wth_args(task, collectth_state,&tir1);

#endif /* 0 ] */
	/*
	 *	Write out the Mach header at the beginning of the
	 *	file.
	 */
	error = vn_rdwr(UIO_WRITE, vp, (caddr_t)header, header_size, (off_t)0,
			UIO_SYSSPACE, IO_NODELOCKED|IO_UNIT, cred, (int *) 0, p);
	kmem_free(kernel_map, header, header_size);
out:
	VOP_UNLOCK(vp, 0, p);
	error1 = vn_close(vp, FWRITE, cred, p);
	if (error == 0)
		error = error1;
}
