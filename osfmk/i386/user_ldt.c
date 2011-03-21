/*
 * Copyright (c) 2000-2009 Apple Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon 
 * the rights to redistribute these changes.
 */

/*
 */

/*
 * User LDT management.
 * Each task may have its own LDT.
 */

#include <kern/kalloc.h>
#include <kern/thread.h>
#include <kern/misc_protos.h>

#include <vm/vm_kern.h>

#include <i386/machdep_call.h>
#include <i386/user_ldt.h>
#include <i386/mp.h>
#include <i386/machine_routines.h>
#include <i386/proc_reg.h>
#include <i386/mp_desc.h>
#include <i386/seg.h>
#include <i386/thread.h>

#include <sys/errno.h>

static void user_ldt_set_action(void *);

/*
 * Add the descriptors to the LDT, starting with
 * the descriptor for 'first_selector'.
 */

int
i386_set_ldt(
	uint32_t		*retval,
	uint32_t		start_sel,
	uint32_t		descs,	/* out */
	uint32_t		num_sels)
{
	user_ldt_t	new_ldt, old_ldt;
	struct real_descriptor *dp;
	unsigned int	i;
	unsigned int	min_selector = LDTSZ_MIN;	/* do not allow the system selectors to be changed */
	task_t		task = current_task();
	unsigned int	ldt_count;
	kern_return_t err;

	if (start_sel != LDT_AUTO_ALLOC
	    && (start_sel != 0 || num_sels != 0)
	    && (start_sel < min_selector || start_sel >= LDTSZ))
	    return EINVAL;
	if (start_sel != LDT_AUTO_ALLOC
	    && (uint64_t)start_sel + (uint64_t)num_sels > LDTSZ) /* cast to uint64_t to detect wrap-around */
	    return EINVAL;

	task_lock(task);
	
	old_ldt = task->i386_ldt;

	if (start_sel == LDT_AUTO_ALLOC) {
	    if (old_ldt) {
		unsigned int null_count;
		struct real_descriptor null_ldt;
		
		bzero(&null_ldt, sizeof(null_ldt));

		/*
		 * Look for null selectors among the already-allocated
		 * entries.
		 */
		null_count = 0;
		i = 0;
		while (i < old_ldt->count)
		{
		    if (!memcmp(&old_ldt->ldt[i++], &null_ldt, sizeof(null_ldt))) {
			null_count++;
			if (null_count == num_sels)
			    break;  /* break out of while loop */
		    } else {
			null_count = 0;
		    }
		}

		/*
		 * If we broke out of the while loop, i points to the selector
		 * after num_sels null selectors.  Otherwise it points to the end
		 * of the old LDTs, and null_count is the number of null selectors
		 * at the end. 
		 *
		 * Either way, there are null_count null selectors just prior to
		 * the i-indexed selector, and either null_count >= num_sels,
		 * or we're at the end, so we can extend.
		 */
		start_sel = old_ldt->start + i - null_count;
	    } else {
		start_sel = LDTSZ_MIN;
	    }
		
	    if ((uint64_t)start_sel + (uint64_t)num_sels > LDTSZ) {
		task_unlock(task);
		return ENOMEM;
	    }
	}

	if (start_sel == 0 && num_sels == 0) {
	    new_ldt = NULL;
	} else {
	    /*
	     * Allocate new LDT
	     */

	    unsigned int    begin_sel = start_sel;
	    unsigned int    end_sel = begin_sel + num_sels;
	    
	    if (old_ldt != NULL) {
		if (old_ldt->start < begin_sel)
		    begin_sel = old_ldt->start;
		if (old_ldt->start + old_ldt->count > end_sel)
		    end_sel = old_ldt->start + old_ldt->count;
	    }

	    ldt_count = end_sel - begin_sel;
	    /* XXX allocation under task lock */
	    new_ldt = (user_ldt_t)kalloc(sizeof(struct user_ldt) + (ldt_count * sizeof(struct real_descriptor)));
	    if (new_ldt == NULL) {
		task_unlock(task);
		return ENOMEM;
	    }

	    new_ldt->start = begin_sel;
	    new_ldt->count = ldt_count;

	    /*
	     * Have new LDT.  If there was a an old ldt, copy descriptors
	     * from old to new.
	     */
	    if (old_ldt) {
		bcopy(&old_ldt->ldt[0],
		      &new_ldt->ldt[old_ldt->start - begin_sel],
		      old_ldt->count * sizeof(struct real_descriptor));

		/*
		 * If the old and new LDTs are non-overlapping, fill the 
		 * center in with null selectors.
		 */
		 		 
		if (old_ldt->start + old_ldt->count < start_sel)
		    bzero(&new_ldt->ldt[old_ldt->count],
			  (start_sel - (old_ldt->start + old_ldt->count)) * sizeof(struct real_descriptor));
		else if (old_ldt->start > start_sel + num_sels)
		    bzero(&new_ldt->ldt[num_sels],
			  (old_ldt->start - (start_sel + num_sels)) * sizeof(struct real_descriptor));
	    }

	    /*
	     * Install new descriptors.
	     */
	    if (descs != 0) {
		    /* XXX copyin under task lock */
		err = copyin(descs, (char *)&new_ldt->ldt[start_sel - begin_sel],
			     num_sels * sizeof(struct real_descriptor));
		if (err != 0)
		{
		    task_unlock(task);
		    user_ldt_free(new_ldt);
		    return err;
		}
	    } else {
		bzero(&new_ldt->ldt[start_sel - begin_sel], num_sels * sizeof(struct real_descriptor));
	    }

	    /*
	     * Validate descriptors.
	     * Only allow descriptors with user privileges.
	     */
	    for (i = 0, dp = (struct real_descriptor *) &new_ldt->ldt[start_sel - begin_sel];
		 i < num_sels;
		 i++, dp++)
	    {
		switch (dp->access & ~ACC_A) {
		    case 0:
		    case ACC_P:
			/* valid empty descriptor, clear Present preemptively */
			dp->access &= ~ACC_P;
			break;
		    case ACC_P | ACC_PL_U | ACC_DATA:
		    case ACC_P | ACC_PL_U | ACC_DATA_W:
		    case ACC_P | ACC_PL_U | ACC_DATA_E:
		    case ACC_P | ACC_PL_U | ACC_DATA_EW:
		    case ACC_P | ACC_PL_U | ACC_CODE:
		    case ACC_P | ACC_PL_U | ACC_CODE_R:
		    case ACC_P | ACC_PL_U | ACC_CODE_C:
		    case ACC_P | ACC_PL_U | ACC_CODE_CR:
			break;
		    default:
			task_unlock(task);
			user_ldt_free(new_ldt);
			return EACCES;
		}
	    }
	}

	task->i386_ldt = new_ldt; /* new LDT for task */

	/*
	 * Switch to new LDT.  We need to do this on all CPUs, since
	 * another thread in this same task may be currently running,
	 * and we need to make sure the new LDT is in place
	 * throughout the task before returning to the user.
	 */
	mp_broadcast(user_ldt_set_action, task);

	task_unlock(task);

	/* free old LDT.  We can't do this until after we've
	 * rendezvoused with all CPUs, in case another thread
	 * in this task was in the process of context switching.
	 */
	if (old_ldt)
	    user_ldt_free(old_ldt);

	*retval = start_sel;

	return 0;
}

int
i386_get_ldt(
	uint32_t		*retval,
	uint32_t		start_sel,
	uint32_t		descs,	/* out */
	uint32_t		num_sels)
{
	user_ldt_t	user_ldt;
	task_t		task = current_task();
	unsigned int	ldt_count;
	kern_return_t	err;

	if (start_sel >= 8192)
	    return EINVAL;
	if ((uint64_t)start_sel + (uint64_t)num_sels > 8192)
	    return EINVAL;
	if (descs == 0)
	    return EINVAL;

	task_lock(task);

	user_ldt = task->i386_ldt;
	err = 0;

	/*
	 * copy out the descriptors
	 */

	if (user_ldt != 0)
	    ldt_count = user_ldt->start + user_ldt->count;
	else
	    ldt_count = LDTSZ_MIN;


	if (start_sel < ldt_count)
	{
	    unsigned int copy_sels = num_sels;

	    if (start_sel + num_sels > ldt_count)
		copy_sels = ldt_count - start_sel;

	    err = copyout((char *)(current_ldt() + start_sel),
			  descs, copy_sels * sizeof(struct real_descriptor));
	}

	task_unlock(task);

	*retval = ldt_count;

	return err;
}

void
user_ldt_free(
	user_ldt_t	user_ldt)
{
	kfree(user_ldt, sizeof(struct user_ldt) + (user_ldt->count * sizeof(struct real_descriptor)));
}

user_ldt_t
user_ldt_copy(
	user_ldt_t	user_ldt)
{
	if (user_ldt != NULL) {
	    size_t	size = sizeof(struct user_ldt) + (user_ldt->count * sizeof(struct real_descriptor));
	    user_ldt_t	new_ldt = (user_ldt_t)kalloc(size);
	    if (new_ldt != NULL)
		bcopy(user_ldt, new_ldt, size);
	    return new_ldt;
	}
	
	return 0;
}

void
user_ldt_set_action(
	void *arg)
{
	task_t		arg_task = (task_t)arg;

	if (arg_task == current_task())	{
	    user_ldt_set(current_thread());
	}
}

/*
 * Set the LDT for the given thread on the current CPU.  Should be invoked
 * with interrupts disabled.
 */
void
user_ldt_set(
	thread_t thread)
{
        task_t		task = thread->task;
	user_ldt_t	user_ldt;

	user_ldt = task->i386_ldt;

	if (user_ldt != 0) {
	    struct real_descriptor *ldtp = (struct real_descriptor *)current_ldt();

	    if (user_ldt->start > LDTSZ_MIN) {
		bzero(&ldtp[LDTSZ_MIN],
		      sizeof(struct real_descriptor) * (user_ldt->start - LDTSZ_MIN));
	    }
	    
	    bcopy(user_ldt->ldt, &ldtp[user_ldt->start],
		  sizeof(struct real_descriptor) * (user_ldt->count));

	    gdt_desc_p(USER_LDT)->limit_low = (sizeof(struct real_descriptor) * (user_ldt->start + user_ldt->count)) - 1;

	    ml_cpu_set_ldt(USER_LDT);
	} else {
	    ml_cpu_set_ldt(KERNEL_LDT);
	}
}
