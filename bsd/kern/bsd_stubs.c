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
#include <sys/stat.h>
#include <vm/vm_map.h>
#include <sys/systm.h>
#include <kern/assert.h>
#include <sys/conf.h>
#include <sys/proc_internal.h>
#include <sys/buf.h> /* for SET */
#include <sys/kernel.h>
#include <sys/user.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>

/* XXX these should be in a common header somwhere, but aren't */
extern int chrtoblk_set(int, int);
extern vm_offset_t kmem_mb_alloc(vm_map_t, int, int);

/* XXX most of these just exist to export; there's no good header for them*/
void pcb_synch(void);

TAILQ_HEAD(, devsw_lock) devsw_locks;
lck_mtx_t devsw_lock_list_mtx;
lck_grp_t * devsw_lock_grp;

/* Just to satisfy pstat command */
int dmmin, dmmax, dmtext;

vm_offset_t
kmem_mb_alloc(vm_map_t mbmap, int size, int physContig)
{
	vm_offset_t addr = 0;
	kern_return_t kr = KERN_SUCCESS;

	if (!physContig)
		kr = kernel_memory_allocate(mbmap, &addr, size, 0, KMA_NOPAGEWAIT | KMA_KOBJECT | KMA_LOMEM, VM_KERN_MEMORY_MBUF);
	else
		kr = kmem_alloc_contig(mbmap, &addr, size, PAGE_MASK, 0xfffff, 0, KMA_NOPAGEWAIT | KMA_KOBJECT | KMA_LOMEM, VM_KERN_MEMORY_MBUF);

	if (kr != KERN_SUCCESS)
		addr = 0;

	return addr;
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
	struct proc * p;
	thread_t thread = current_thread();

	ut = (struct uthread *)get_bsdthread_info(thread);
	if (ut && (ut->uu_flag & UT_VFORK) && ut->uu_proc) {
		p = ut->uu_proc;
		if ((p->p_lflag & P_LINVFORK) == 0)
			panic("returning child proc not under vfork");
		if (p->p_vforkact != (void *)thread)
			panic("returning child proc which is not cur_act");
		return (p);
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
 *	if index is negative, we start
 *	looking for a free slot at the absolute value of index,
 *	instead of starting at 0
 */
int
bdevsw_isfree(int index)
{
	struct bdevsw * devsw;

	if (index < 0) {
		if (index == -1)
			index = 1; /* start at 1 to avoid collision with volfs (Radar 2842228) */
		else
			index = -index; /* start at least this far up in the table */
		devsw = &bdevsw[index];
		for (; index < nblkdev; index++, devsw++) {
			if (memcmp((char *)devsw, (char *)&nobdev, sizeof(struct bdevsw)) == 0)
				break;
		}
	}

	if (index < 0 || index >= nblkdev)
		return (-1);

	devsw = &bdevsw[index];
	if ((memcmp((char *)devsw, (char *)&nobdev, sizeof(struct bdevsw)) != 0)) {
		return (-1);
	}
	return (index);
}

/*
 *	if index is -1, find a free slot to add
 *	  else see whether the slot is free
 *	return the major number that is used else -1
 *
 *	if index is negative, we start
 *	looking for a free slot at the absolute value of index,
 *	instead of starting at 0
 */
int
bdevsw_add(int index, struct bdevsw * bsw)
{
	index = bdevsw_isfree(index);
	if (index < 0) {
		return (-1);
	}
	bdevsw[index] = *bsw;
	return (index);
}
/*
 *	if the slot has the same bsw, then remove
 *	else -1
 */
int
bdevsw_remove(int index, struct bdevsw * bsw)
{
	struct bdevsw * devsw;

	if (index < 0 || index >= nblkdev)
		return (-1);

	devsw = &bdevsw[index];
	if ((memcmp((char *)devsw, (char *)bsw, sizeof(struct bdevsw)) != 0)) {
		return (-1);
	}
	bdevsw[index] = nobdev;
	return (index);
}

/*
 *	if index is -1, return a free slot if avaliable
 *	  else see whether the index is free
 *	return the major number that is free else -1
 *
 *	if index is negative, we start
 *	looking for a free slot at the absolute value of index,
 *	instead of starting at 0
 */
int
cdevsw_isfree(int index)
{
	struct cdevsw * devsw;

	if (index < 0) {
		if (index == -1)
			index = 0;
		else
			index = -index; /* start at least this far up in the table */
		devsw = &cdevsw[index];
		for (; index < nchrdev; index++, devsw++) {
			if (memcmp((char *)devsw, (char *)&nocdev, sizeof(struct cdevsw)) == 0)
				break;
		}
	}

	if (index < 0 || index >= nchrdev)
		return (-1);

	devsw = &cdevsw[index];
	if ((memcmp((char *)devsw, (char *)&nocdev, sizeof(struct cdevsw)) != 0)) {
		return (-1);
	}
	return (index);
}

/*
 *	if index is -1, find a free slot to add
 *	  else see whether the slot is free
 *	return the major number that is used else -1
 *
 *	if index is negative, we start
 *	looking for a free slot at the absolute value of index,
 *	instead of starting at 0
 *
 * NOTE:	In practice, -1 is unusable, since there are kernel internal
 *		devices that call this function with absolute index values,
 *		which will stomp on free-slot based assignments that happen
 *		before them.  -24 is currently a safe starting point.
 */
int
cdevsw_add(int index, struct cdevsw * csw)
{
	index = cdevsw_isfree(index);
	if (index < 0) {
		return (-1);
	}
	cdevsw[index] = *csw;
	return (index);
}
/*
 *	if the slot has the same csw, then remove
 *	else -1
 */
int
cdevsw_remove(int index, struct cdevsw * csw)
{
	struct cdevsw * devsw;

	if (index < 0 || index >= nchrdev)
		return (-1);

	devsw = &cdevsw[index];
	if ((memcmp((char *)devsw, (char *)csw, sizeof(struct cdevsw)) != 0)) {
		return (-1);
	}
	cdevsw[index] = nocdev;
	cdevsw_flags[index] = 0;
	return (index);
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

int
cdevsw_setkqueueok(int index, struct cdevsw * csw, int use_offset)
{
	struct cdevsw * devsw;
	uint64_t flags = CDEVSW_SELECT_KQUEUE;

	if (index < 0 || index >= nchrdev)
		return (-1);

	devsw = &cdevsw[index];
	if ((memcmp((char *)devsw, (char *)csw, sizeof(struct cdevsw)) != 0)) {
		return (-1);
	}

	if (use_offset) {
		flags |= CDEVSW_USE_OFFSET;
	}

	cdevsw_flags[index] = flags;
	return 0;
}

#include <pexpert/pexpert.h> /* for PE_parse_boot_arg */

/*
 * Copy the "hostname" variable into a caller-provided buffer
 * Returns: 0 for success, ENAMETOOLONG for insufficient buffer space.
 * On success, "len" will be set to the number of characters preceding
 * the NULL character in the hostname.
 */
int
bsd_hostname(char * buf, int bufsize, int * len)
{
	/*
	 * "hostname" is null-terminated, and "hostnamelen" is equivalent to strlen(hostname).
	 */
	if (hostnamelen < bufsize) {
		strlcpy(buf, hostname, bufsize);
		*len = hostnamelen;
		return 0;
	} else {
		return ENAMETOOLONG;
	}
}

void
devsw_lock(dev_t dev, int mode)
{
	devsw_lock_t newlock, tmplock;
	int res;

	assert(0 <= major(dev) && major(dev) < nchrdev);
	assert(mode == S_IFCHR || mode == S_IFBLK);

	MALLOC(newlock, devsw_lock_t, sizeof(struct devsw_lock), M_TEMP, M_WAITOK | M_ZERO);
	newlock->dl_dev = dev;
	newlock->dl_thread = current_thread();
	newlock->dl_mode = mode;

	lck_mtx_lock_spin(&devsw_lock_list_mtx);
retry:
	TAILQ_FOREACH(tmplock, &devsw_locks, dl_list)
	{
		if (tmplock->dl_dev == dev && tmplock->dl_mode == mode) {
			res = msleep(tmplock, &devsw_lock_list_mtx, PVFS, "devsw_lock", NULL);
			assert(res == 0);
			goto retry;
		}
	}

	TAILQ_INSERT_TAIL(&devsw_locks, newlock, dl_list);
	lck_mtx_unlock(&devsw_lock_list_mtx);
}
void
devsw_unlock(dev_t dev, int mode)
{
	devsw_lock_t tmplock;

	assert(0 <= major(dev) && major(dev) < nchrdev);

	lck_mtx_lock_spin(&devsw_lock_list_mtx);

	TAILQ_FOREACH(tmplock, &devsw_locks, dl_list)
	{
		if (tmplock->dl_dev == dev && tmplock->dl_mode == mode) {
			break;
		}
	}

	if (tmplock == NULL) {
		panic("Trying to unlock, and couldn't find lock.");
	}

	if (tmplock->dl_thread != current_thread()) {
		panic("Trying to unlock, but I don't hold the lock.");
	}

	wakeup(tmplock);
	TAILQ_REMOVE(&devsw_locks, tmplock, dl_list);

	lck_mtx_unlock(&devsw_lock_list_mtx);

	FREE(tmplock, M_TEMP);
}

void
devsw_init()
{
	devsw_lock_grp = lck_grp_alloc_init("devsw", NULL);
	assert(devsw_lock_grp != NULL);

	lck_mtx_init(&devsw_lock_list_mtx, devsw_lock_grp, NULL);
	TAILQ_INIT(&devsw_locks);
}
