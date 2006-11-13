/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
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
 * Each thread in a task may have its own LDT.
 */

#include <kern/kalloc.h>
#include <kern/thread.h>
#include <kern/misc_protos.h>

#include <vm/vm_kern.h>

#include <i386/seg.h>
#include <i386/thread.h>
#include <i386/user_ldt.h>

char	acc_type[8][3] = {
    /*	code	stack	data */
    {	0,	0,	1	},	/* data */
    {	0,	1,	1	},	/* data, writable */
    {	0,	0,	1	},	/* data, expand-down */
    {	0,	1,	1	},	/* data, writable, expand-down */
    {	1,	0,	0	},	/* code */
    {	1,	0,	1	},	/* code, readable */
    {	1,	0,	0	},	/* code, conforming */
    {	1,	0,	1	},	/* code, readable, conforming */
};

#if 0
/* Forward */

extern boolean_t	selector_check(
				thread_t		thread,
				int			sel,
				int			type);

boolean_t
selector_check(
	thread_t		thread,
	int			sel,
	int			type)
{
	struct user_ldt	*ldt;
	int	access;

	ldt = thread->machine.pcb->ims.ldt;
	if (ldt == 0) {
	    switch (type) {
		case S_CODE:
		    return sel == USER_CS;
		case S_STACK:
		    return sel == USER_DS;
		case S_DATA:
		    return sel == 0 ||
			   sel == USER_CS ||
			   sel == USER_DS;
	    }
	}

	if (type != S_DATA && sel == 0)
	    return FALSE;
	if ((sel & (SEL_LDTS|SEL_PL)) != (SEL_LDTS|SEL_PL_U)
	  || sel > ldt->desc.limit_low)
		return FALSE;

	access = ldt->ldt[sel_idx(sel)].access;
	
	if ((access & (ACC_P|ACC_PL|ACC_TYPE_USER))
		!= (ACC_P|ACC_PL_U|ACC_TYPE_USER))
	    return FALSE;
		/* present, pl == pl.user, not system */

	return acc_type[(access & 0xe)>>1][type];
}

/*
 * Add the descriptors to the LDT, starting with
 * the descriptor for 'first_selector'.
 */

kern_return_t
i386_set_ldt(
	thread_t		thr_act,
	int			first_selector,
	descriptor_list_t	desc_list,
	mach_msg_type_number_t	count)
{
	user_ldt_t	new_ldt, old_ldt, temp;
	struct real_descriptor *dp;
	int		i;
	int		min_selector = 0;
	pcb_t		pcb;
	vm_size_t	ldt_size_needed;
	int		first_desc = sel_idx(first_selector);
	vm_map_copy_t	old_copy_object;
	thread_t		thread;

	if (first_desc < min_selector || first_desc > 8191)
	    return KERN_INVALID_ARGUMENT;
	if (first_desc + count >= 8192)
	    return KERN_INVALID_ARGUMENT;
	if (thr_act == THREAD_NULL)
	    return KERN_INVALID_ARGUMENT;
	if ((thread = act_lock_thread(thr_act)) == THREAD_NULL) {
		act_unlock_thread(thr_act);
	    return KERN_INVALID_ARGUMENT;
	}
	if (thread == current_thread())
		min_selector = LDTSZ;
	act_unlock_thread(thr_act);

	/*
	 * We must copy out desc_list to the kernel map, and wire
	 * it down (we touch it while the PCB is locked).
	 *
	 * We make a copy of the copyin object, and clear
	 * out the old one, so that the MIG stub will have a
	 * a empty (but valid) copyin object to discard.
	 */
	{
	    kern_return_t	kr;
	    vm_map_offset_t	dst_addr;

	    old_copy_object = (vm_map_copy_t) desc_list;

	    kr = vm_map_copyout(ipc_kernel_map, &dst_addr,
				vm_map_copy_copy(old_copy_object));
	    if (kr != KERN_SUCCESS)
		return kr;

	    (void) vm_map_wire(ipc_kernel_map,
			vm_map_trunc_page(dst_addr),
			vm_map_round_page(dst_addr + 
				count * sizeof(struct real_descriptor)),
			VM_PROT_READ|VM_PROT_WRITE, FALSE);
	    desc_list = CAST_DOWN(descriptor_list_t, dst_addr);
	}

	for (i = 0, dp = (struct real_descriptor *) desc_list;
	     i < count;
	     i++, dp++)
	{
	    switch (dp->access & ~ACC_A) {
		case 0:
		case ACC_P:
		    /* valid empty descriptor */
		    break;
		case ACC_P | ACC_CALL_GATE:
		    /* Mach kernel call */
		    *dp = *(struct real_descriptor *)
				&ldt[sel_idx(USER_SCALL)];
		    break;
		case ACC_P | ACC_PL_U | ACC_DATA:
		case ACC_P | ACC_PL_U | ACC_DATA_W:
		case ACC_P | ACC_PL_U | ACC_DATA_E:
		case ACC_P | ACC_PL_U | ACC_DATA_EW:
		case ACC_P | ACC_PL_U | ACC_CODE:
		case ACC_P | ACC_PL_U | ACC_CODE_R:
		case ACC_P | ACC_PL_U | ACC_CODE_C:
		case ACC_P | ACC_PL_U | ACC_CODE_CR:
		case ACC_P | ACC_PL_U | ACC_CALL_GATE_16:
		case ACC_P | ACC_PL_U | ACC_CALL_GATE:
		    break;
		default:
		    (void) vm_map_remove(ipc_kernel_map, 
					 vm_map_trunc_page(desc_list),
					 vm_map_round_page(&desc_list[count]),
					 VM_MAP_REMOVE_KUNWIRE);
		    return KERN_INVALID_ARGUMENT;
	    }
	}
	ldt_size_needed = sizeof(struct real_descriptor)
			* (first_desc + count);

	pcb = thr_act->machine.pcb;
	new_ldt = 0;
    Retry:
	simple_lock(&pcb->lock);
	old_ldt = pcb->ims.ldt;
	if (old_ldt == 0 ||
	    old_ldt->desc.limit_low + 1 < ldt_size_needed)
	{
	    /*
	     * No old LDT, or not big enough
	     */
	    if (new_ldt == 0) {
		simple_unlock(&pcb->lock);

		new_ldt = (user_ldt_t) kalloc(ldt_size_needed
					      + sizeof(struct real_descriptor));
		new_ldt->desc.limit_low   = ldt_size_needed - 1;
		new_ldt->desc.limit_high  = 0;
		new_ldt->desc.base_low    = 
				((vm_offset_t)&new_ldt->ldt[0]) & 0xffff;
		new_ldt->desc.base_med    = 
				(((vm_offset_t)&new_ldt->ldt[0]) >> 16)
						 & 0xff;
		new_ldt->desc.base_high   = 
				((vm_offset_t)&new_ldt->ldt[0]) >> 24;
		new_ldt->desc.access      = ACC_P | ACC_LDT;
		new_ldt->desc.granularity = 0;

		goto Retry;
	    }

	    /*
	     * Have new LDT.  If there was a an old ldt, copy descriptors
	     * from old to new.  Otherwise copy the default ldt.
	     */
	    if (old_ldt) {
		bcopy((char *)&old_ldt->ldt[0],
		      (char *)&new_ldt->ldt[0],
		      old_ldt->desc.limit_low + 1);
	    }
	    else if (thr_act == current_thread()) {
		struct real_descriptor template = {0, 0, 0, ACC_P, 0, 0 ,0};

		for (dp = &new_ldt->ldt[0], i = 0; i < first_desc; i++, dp++) {
		    if (i < LDTSZ)
		    	*dp = *(struct real_descriptor *) &ldt[i];
		    else
			*dp = template;
		}
	    }

	    temp = old_ldt;
	    old_ldt = new_ldt;	/* use new LDT from now on */
	    new_ldt = temp;	/* discard old LDT */

	    pcb->ims.ldt = old_ldt;	/* new LDT for thread */
	}

	/*
	 * Install new descriptors.
	 */
	bcopy((char *)desc_list,
	      (char *)&old_ldt->ldt[first_desc],
	      count * sizeof(struct real_descriptor));

	simple_unlock(&pcb->lock);

	if (new_ldt)
	    kfree((vm_offset_t)new_ldt,
		  new_ldt->desc.limit_low+1+sizeof(struct real_descriptor));

	/*
	 * Free the descriptor list.
	 */
	(void) vm_map_remove(ipc_kernel_map, vm_map_trunc_page(desc_list),
			     vm_map_round_page(&desc_list[count]),
			     VM_MAP_REMOVE_KUNWIRE);
	return KERN_SUCCESS;
}

kern_return_t
i386_get_ldt(
	thread_t		thr_act,
	int			first_selector,
	int			selector_count,	/* number wanted */
	descriptor_list_t	*desc_list,	/* in/out */
	mach_msg_type_number_t	*count)		/* in/out */
{
	struct user_ldt *user_ldt;
	pcb_t		pcb = thr_act->machine.pcb;
	int		first_desc = sel_idx(first_selector);
	unsigned int	ldt_count;
	vm_size_t	ldt_size;
	vm_size_t	size, size_needed;
	vm_offset_t	addr;
	thread_t		thread;

	if (thr_act == THREAD_NULL)
	    return KERN_INVALID_ARGUMENT;

	if (first_desc < 0 || first_desc > 8191)
	    return KERN_INVALID_ARGUMENT;
	if (first_desc + selector_count >= 8192)
	    return KERN_INVALID_ARGUMENT;

	addr = 0;
	size = 0;

	for (;;) {
	    simple_lock(&pcb->lock);
	    user_ldt = pcb->ims.ldt;
	    if (user_ldt == 0) {
		simple_unlock(&pcb->lock);
		if (addr)
		    kmem_free(ipc_kernel_map, addr, size);
		*count = 0;
		return KERN_SUCCESS;
	    }

	    /*
	     * Find how many descriptors we should return.
	     */
	    ldt_count = (user_ldt->desc.limit_low + 1) /
			sizeof (struct real_descriptor);
	    ldt_count -= first_desc;
	    if (ldt_count > selector_count)
		ldt_count = selector_count;

	    ldt_size = ldt_count * sizeof(struct real_descriptor);

	    /*
	     * Do we have the memory we need?
	     */
	    if (ldt_count <= *count)
		break;		/* fits in-line */

	    size_needed = round_page(ldt_size);
	    if (size_needed <= size)
		break;

	    /*
	     * Unlock the pcb and allocate more memory
	     */
	    simple_unlock(&pcb->lock);

	    if (size != 0)
		kmem_free(ipc_kernel_map, addr, size);

	    size = size_needed;

	    if (kmem_alloc(ipc_kernel_map, &addr, size)
			!= KERN_SUCCESS)
		return KERN_RESOURCE_SHORTAGE;
	}

	/*
	 * copy out the descriptors
	 */
	bcopy((char *)&user_ldt->ldt[first_desc],
	      (char *)addr,
	      ldt_size);
	*count = ldt_count;
	simple_unlock(&pcb->lock);

	if (addr) {
	    vm_size_t		size_used, size_left;
	    vm_map_copy_t	memory;

	    /*
	     * Free any unused memory beyond the end of the last page used
	     */
	    size_used = round_page(ldt_size);
	    if (size_used != size)
		kmem_free(ipc_kernel_map,
			addr + size_used, size - size_used);

	    /*
	     * Zero the remainder of the page being returned.
	     */
	    size_left = size_used - ldt_size;
	    if (size_left > 0)
		bzero((char *)addr + ldt_size, size_left);

	    /*
	     * Unwire the memory and make it into copyin form.
	     */
	    (void) vm_map_unwire(ipc_kernel_map, vm_map_trunc_page(addr),
				 vm_map_round_page(addr + size_used), FALSE);
	    (void) vm_map_copyin(ipc_kernel_map, (vm_map_address_t)addr, 
				 (vm_map_size_t)size_used, TRUE, &memory);
	    *desc_list = (descriptor_list_t) memory;
	}

	return KERN_SUCCESS;
}

#endif 
void
user_ldt_free(
	user_ldt_t	user_ldt)
{
	kfree(user_ldt,
		user_ldt->desc.limit_low+1+sizeof(struct real_descriptor));
}
