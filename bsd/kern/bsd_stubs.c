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
#include <sys/time.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <mach/mach_types.h>
#include <mach/vm_prot.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/proc_internal.h>
#include <sys/buf.h>	/* for SET */
#include <sys/user.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>

/* Just to satisfy pstat command */
int     dmmin, dmmax, dmtext;

vm_offset_t
kmem_mb_alloc(vm_map_t  mbmap, int size) 
{
        vm_offset_t addr;
	if (kernel_memory_allocate(mbmap, &addr, size,
   		0,
		KMA_NOPAGEWAIT|KMA_KOBJECT|KMA_LOMEM) == KERN_SUCCESS)
   			return(addr);
	else
		return(0);
		
}

/*
 * XXX this function only exists to be exported and do nothing.
 */
void
pcb_synch(void)
{
}

struct proc *
current_proc(void)
{
	/* Never returns a NULL */
	struct uthread * ut;
	struct proc *p; 
	thread_t thr_act = current_thread();

	ut = (struct uthread *)get_bsdthread_info(thr_act); 
	if (ut &&  (ut->uu_flag & UT_VFORK) && ut->uu_proc) {
		p = ut->uu_proc;
		if ((p->p_flag & P_INVFORK) == 0) 
			panic("returning child proc not under vfork");
		if (p->p_vforkact != (void *)thr_act) 
			panic("returning child proc which is not cur_act");
		return(p);
	}

	p = (struct proc *)get_bsdtask_info(current_task());

	if (p == NULL)
		return (kernproc);

	return (p);
}

/* Device switch add delete routines */

extern int nblkdev, nchrdev;

struct bdevsw nobdev = NO_BDEVICE;
struct cdevsw nocdev = NO_CDEVICE;
/* 
 *	if index is -1, return a free slot if avaliable
 *	  else see whether the index is free
 *	return the major number that is free else -1
 *
 */
int
bdevsw_isfree(int index)
{
	struct bdevsw *devsw;
	if (index == -1) {
	    devsw = bdevsw;
	    for(index=0; index < nblkdev; index++, devsw++) {
		if(memcmp((char *)devsw, 
			    (char *)&nobdev, 
			    sizeof(struct bdevsw)) == 0)
		    break;
	    }
	} else {
		/* NB: Not used below unless index is in range */
		devsw = &bdevsw[index];
	}

	if ((index < 0) || (index >= nblkdev) ||
	    (memcmp((char *)devsw, 
		          (char *)&nobdev, 
			  sizeof(struct bdevsw)) != 0)) {
		return(-1);
	}
	return(index);
}

/* 
 *	if index is -1, find a free slot to add
 *	  else see whether the slot is free
 *	return the major number that is used else -1
 */
int
bdevsw_add(int index, struct bdevsw * bsw) 
{
	struct bdevsw *devsw;

	if (index == -1) {
	    devsw = &bdevsw[1];		/* Start at slot 1 - this is a hack to fix the index=1 hack */
	    /* yes, start at 1 to avoid collision with volfs (Radar 2842228) */
	    for(index=1; index < nblkdev; index++, devsw++) {
		if(memcmp((char *)devsw, 
			    (char *)&nobdev, 
			    sizeof(struct bdevsw)) == 0)
		    break;
	    }
	}
	devsw = &bdevsw[index];
	if ((index < 0) || (index >= nblkdev) ||
	    (memcmp((char *)devsw, 
		          (char *)&nobdev, 
			  sizeof(struct bdevsw)) != 0)) {
		return(-1);
	}
	bdevsw[index] = *bsw;
	return(index);
}
/* 
 *	if the slot has the same bsw, then remove
 *	else -1
 */
int
bdevsw_remove(int index, struct bdevsw * bsw) 
{
	struct bdevsw *devsw;

	devsw = &bdevsw[index];
	if ((index < 0) || (index >= nblkdev) ||
	    (memcmp((char *)devsw, 
		          (char *)bsw, 
			  sizeof(struct bdevsw)) != 0)) {
		return(-1);
	}
	bdevsw[index] = nobdev;
	return(index);
}

/* 
 *	if index is -1, return a free slot if avaliable
 *	  else see whether the index is free
 *	return the major number that is free else -1
 */
int
cdevsw_isfree(int index)
{
	struct cdevsw *devsw;

	if (index == -1) {
	    devsw = cdevsw;
	    for(index=0; index < nchrdev; index++, devsw++) {
		if(memcmp((char *)devsw, 
			    (char *)&nocdev, 
			    sizeof(struct cdevsw)) == 0)
		    break;
	    }
	}
	devsw = &cdevsw[index];
	if ((index < 0) || (index >= nchrdev) ||
	    (memcmp((char *)devsw, 
		          (char *)&nocdev, 
			  sizeof(struct cdevsw)) != 0)) {
		return(-1);
	}
	return(index);
}

/* 
 *	if index is -1, find a free slot to add
 *	  else see whether the slot is free
 *	return the major number that is used else -1
 */
int
cdevsw_add(int index, struct cdevsw * csw) 
{
	struct cdevsw *devsw;

	if (index == -1) {
	    devsw = cdevsw;
	    for(index=0; index < nchrdev; index++, devsw++) {
		if(memcmp((char *)devsw, 
			    (char *)&nocdev, 
			    sizeof(struct cdevsw)) == 0)
		    break;
	    }
	}
	devsw = &cdevsw[index];
	if ((index < 0) || (index >= nchrdev) ||
	    (memcmp((char *)devsw, 
		          (char *)&nocdev, 
			  sizeof(struct cdevsw)) != 0)) {
		return(-1);
	}
	cdevsw[index] = *csw;
	return(index);
}
/*
 *	if the index has the same bsw, then remove
 *	else -1
 */
int
cdevsw_remove(int index, struct cdevsw * csw) 
{
	struct cdevsw *devsw;

	devsw = &cdevsw[index];
	if ((index < 0) || (index >= nchrdev) ||
	    (memcmp((char *)devsw, 
		          (char *)csw, 
			  sizeof(struct cdevsw)) != 0)) {
		return(-1);
	}
	cdevsw[index] = nocdev;
	return(index);
}

static int
cdev_set_bdev(int cdev, int bdev)
{
	extern int chrtoblk_add(int cdev, int bdev);

	return (chrtoblk_set(cdev, bdev));
}

int  
cdevsw_add_with_bdev(int index, struct cdevsw * csw, int bdev)
{
	index = cdevsw_add(index, csw);
	if (index < 0) {
		return (index);
	}
	if (cdev_set_bdev(index, bdev) < 0) {
		cdevsw_remove(index, csw);
		return (-1);
	}
	return (index);
}

issingleuser(void)
{
	char namep[16];


	if (PE_parse_boot_arg("-s", namep)) {
		return(1);
	} else {
		return(0);
	}
}

void *
tbeproc(void *procp)
{
	struct proc *p = procp;

	if (p)
		SET(p->p_flag, P_TBE);
	return;
}


/* 
 * WARNING - this is a temporary workaround for binary compatibility issues
 * with anti-piracy software that relies on patching ptrace (3928003).
 * This KPI will be removed in the system release after Tiger.
 */
uintptr_t temp_patch_ptrace(uintptr_t new_ptrace)
{
	struct sysent *		callp;
	sy_call_t *			old_ptrace;
#ifndef __ppc__
	boolean_t	funnel_state;
#endif

	if (new_ptrace == 0)
		return(0);
		
#ifdef __ppc__
	enter_funnel_section(kernel_flock);
#else
	funnel_state = thread_funnel_set(kernel_flock, TRUE);
#endif
	callp = &sysent[26];
	old_ptrace = callp->sy_call;
	
	/* only allow one patcher of ptrace */
	if (old_ptrace == (sy_call_t *) ptrace) {
		callp->sy_call = (sy_call_t *) new_ptrace;
	}
	else {
		old_ptrace = NULL;
	}
#ifdef __ppc__
	exit_funnel_section( );
#else
	(void)thread_funnel_set(kernel_flock, funnel_state);
#endif
	
	return((uintptr_t)old_ptrace);
}

void temp_unpatch_ptrace(void)
{
	struct sysent *		callp;
#ifndef __ppc__
	boolean_t	funnel_state;
#endif
		
#ifdef __ppc__
	enter_funnel_section(kernel_flock);
#else
	funnel_state = thread_funnel_set(kernel_flock, TRUE);
#endif
	callp = &sysent[26];
	callp->sy_call = (sy_call_t *) ptrace;
#ifdef __ppc__
	exit_funnel_section( );
#else
	(void)thread_funnel_set(kernel_flock, funnel_state);
#endif
	
	return;
}
