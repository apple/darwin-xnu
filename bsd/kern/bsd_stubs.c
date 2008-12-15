/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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

/* XXX these should be in a common header somwhere, but aren't */
extern int chrtoblk_set(int, int);
extern vm_offset_t kmem_mb_alloc(vm_map_t, int);

/* XXX most of these just exist to export; there's no good header for them*/
void	pcb_synch(void);
int	issingleuser(void);
void	tbeproc(void *);


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
	thread_t thread = current_thread();

	ut = (struct uthread *)get_bsdthread_info(thread); 
	if (ut &&  (ut->uu_flag & UT_VFORK) && ut->uu_proc) {
		p = ut->uu_proc;
		if ((p->p_lflag & P_LINVFORK) == 0) 
			panic("returning child proc not under vfork");
		if (p->p_vforkact != (void *)thread) 
			panic("returning child proc which is not cur_act");
		return(p);
	}

	p = (struct proc *)get_bsdtask_info(current_task());

	if (p == NULL)
		return (kernproc);

	return (p);
}

/* Device switch add delete routines */

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
 *
 * NOTE:	In practice, -1 is unusable, since there are kernel internal
 *		devices that call this function with absolute index values,
 *		which will stomp on free-slot based assignments that happen
 *		before them.  Therefore, if index is negative, we start
 *		looking for a free slot at the absolute value of index,
 *		instead of starting at 0 (lets out slot 1, but that's one
 *		of the problem slots down low - the vndevice).  -12 is
 *		currently a safe starting point.
 */
int
cdevsw_add(int index, struct cdevsw * csw) 
{
	struct cdevsw *devsw;

	if (index < 0) {
	    if (index == -1)
	    	index = 0;	/* historical behaviour; XXX broken */
	    else
	        index = -index;	/* start at least this far up in the table */
	    devsw = &cdevsw[index];
	    for(; index < nchrdev; index++, devsw++) {
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

#include <pexpert/pexpert.h>	/* for PE_parse_boot_arg */

/*
 * Notes:	This function is used solely by UFS, apparently in an effort
 *		to work around an issue with single user mounts.
 *
 *		It's not technically correct to reference PE_parse_boot_arg()
 *		from this file.
 */
int
issingleuser(void)
{
	char namep[16];

	if (PE_parse_boot_argn("-s", namep, sizeof(namep))) {
		return(1);
	} else {
		return(0);
	}
}

void
tbeproc(void *procp)
{
	struct proc *p = procp;

	if (p)
		OSBitOrAtomic(P_TBE, (UInt32 *)&p->p_flag);
	return;
}

