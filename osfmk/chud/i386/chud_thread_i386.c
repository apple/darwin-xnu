/*
 * Copyright (c) 2003-2007 Apple Inc. All rights reserved.
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

#include <mach/mach_types.h>
#include <mach/task.h>
#include <mach/thread_act.h>
#include <machine/thread.h>

#include <kern/kern_types.h>
#include <kern/processor.h>
#include <kern/thread.h>

#include <vm/vm_map.h>
#include <vm/pmap.h>

#include <chud/chud_xnu.h>
#include <chud/chud_xnu_private.h>

#include <i386/proc_reg.h>
#include <i386/mp_desc.h>
#include <i386/misc_protos.h>

#if 0
#pragma mark **** thread state ****
#endif

__private_extern__ kern_return_t
chudxnu_thread_get_state(
						 thread_t	 	thread, 
						 thread_flavor_t	 	flavor,
						 thread_state_t	 	tstate,
						 mach_msg_type_number_t	*count,
						 boolean_t	 	user_only)
{
	if (user_only) {
		/* We can't get user state for kernel threads */
		if (thread->task == kernel_task)
			return KERN_FAILURE;
		/* this properly handles deciding whether or not the thread is 64 bit or not */
		return machine_thread_get_state(thread, flavor, tstate, count);
	} else {
		// i386 machine_thread_get_kern_state() is different from the PPC version which returns
		// the previous save area - user or kernel - rather than kernel or NULL if no kernel
		// interrupt state available
		
		// the real purpose of this branch is the following:
		// the user doesn't care if the thread states are user or kernel, he
		// just wants the thread state, so we need to determine the proper one
		// to return, kernel or user, for the given thread.
		if(thread == current_thread() && current_cpu_datap()->cpu_int_state) {
			// the above are conditions where we possibly can read the kernel
			// state. we still need to determine if this interrupt happened in
			// kernel or user context
			if(USER_STATE(thread) == current_cpu_datap()->cpu_int_state &&
			   current_cpu_datap()->cpu_interrupt_level == 1) {
				// interrupt happened in user land
				return machine_thread_get_state(thread, flavor, tstate, count);
			} else {
				// kernel interrupt.
				return machine_thread_get_kern_state(thread, flavor, tstate, count);
			}
		} else {
            // get the user-mode thread state
			return machine_thread_get_state(thread, flavor, tstate, count);
		}
	}
}

__private_extern__ kern_return_t
chudxnu_thread_set_state(
						 thread_t		thread, 
						 thread_flavor_t		flavor,
						 thread_state_t		tstate,
						 mach_msg_type_number_t	count,
						 boolean_t 		user_only)
{
#pragma unused (user_only)
	return machine_thread_set_state(thread, flavor, tstate, count);
}

#if 0
#pragma mark **** task memory read/write ****
#endif

__private_extern__ kern_return_t
chudxnu_task_read(
				  task_t		task,
				  void		*kernaddr,
				  uint64_t	usraddr,
				  vm_size_t	size)
{
	kern_return_t ret = KERN_SUCCESS;
	boolean_t old_level;
	
	if(ml_at_interrupt_context()) {
		return KERN_FAILURE; // Can't look at tasks on interrupt stack
	}

	/*
	 * pmap layer requires interrupts to be on
	 */
	old_level = ml_set_interrupts_enabled(TRUE);
	
	if(current_task()==task) {	
		
		if(copyin(usraddr, kernaddr, size)) {
			ret = KERN_FAILURE;
		}
	} else {
		vm_map_t map = get_task_map(task);
		ret = vm_map_read_user(map, usraddr, kernaddr, size);
	}
    
	ml_set_interrupts_enabled(old_level);

	return ret;
}

__private_extern__ kern_return_t
chudxnu_task_write(
				   task_t		task,
				   uint64_t	useraddr,
				   void		*kernaddr,
				   vm_size_t	size)
{
	kern_return_t ret = KERN_SUCCESS;
	boolean_t old_level;
	
	if(ml_at_interrupt_context()) {
		return KERN_FAILURE; // can't poke into tasks on interrupt stack
	}

	/*
	 * pmap layer requires interrupts to be on
	 */
	old_level = ml_set_interrupts_enabled(TRUE);
	
	if(current_task()==task) {    
		
		if(copyout(kernaddr, useraddr, size)) {
			ret = KERN_FAILURE;
		}
	} else {
		vm_map_t map = get_task_map(task);
		ret = vm_map_write_user(map, kernaddr, useraddr, size);
	}		
	
	ml_set_interrupts_enabled(old_level);

	return ret;
}

__private_extern__ kern_return_t
chudxnu_kern_read(void *dstaddr, vm_offset_t srcaddr, vm_size_t size)
{
	return (ml_nofault_copy(srcaddr, (vm_offset_t) dstaddr, size) == size ?
			KERN_SUCCESS: KERN_FAILURE);
}

__private_extern__ kern_return_t
chudxnu_kern_write(
				   vm_offset_t	dstaddr,
				   void		*srcaddr,
				   vm_size_t	size)
{
	return (ml_nofault_copy((vm_offset_t) srcaddr, dstaddr, size) == size ?
			KERN_SUCCESS: KERN_FAILURE);
}

#define VALID_STACK_ADDRESS(supervisor, addr, minKernAddr, maxKernAddr)   (supervisor ? (addr>=minKernAddr && addr<=maxKernAddr) : TRUE)
// don't try to read in the hole
#define VALID_STACK_ADDRESS64(supervisor, addr, minKernAddr, maxKernAddr) \
(supervisor ? ((uint64_t)addr >= minKernAddr && (uint64_t)addr <= maxKernAddr) : \
((uint64_t)addr != 0ULL && ((uint64_t)addr <= 0x00007FFFFFFFFFFFULL || (uint64_t)addr >= 0xFFFF800000000000ULL)))

typedef struct _cframe64_t {
	uint64_t	prevFP;		// can't use a real pointer here until we're a 64 bit kernel
	uint64_t	caller;
	uint64_t	args[0];
}cframe64_t;


typedef struct _cframe_t {
	uint32_t		prev;	// this is really a user32-space pointer to the previous frame
	uint32_t		caller;
	uint32_t		args[0];
} cframe_t;

extern void * find_user_regs(thread_t);
extern x86_saved_state32_t *find_kern_regs(thread_t);

static kern_return_t do_backtrace32(
	task_t task,
	thread_t thread,
	x86_saved_state32_t *regs, 
	uint64_t *frames,
	mach_msg_type_number_t *start_idx,
	mach_msg_type_number_t max_idx,
	boolean_t supervisor)
{
	uint32_t tmpWord = 0UL;
	uint64_t currPC = (uint64_t) regs->eip;
	uint64_t currFP = (uint64_t) regs->ebp;
	uint64_t prevPC = 0ULL;
	uint64_t prevFP = 0ULL;
	uint64_t kernStackMin = thread->kernel_stack;
    uint64_t kernStackMax = kernStackMin + kernel_stack_size;
	mach_msg_type_number_t ct = *start_idx;
	kern_return_t kr = KERN_FAILURE;

	if(ct >= max_idx)
		return KERN_RESOURCE_SHORTAGE;	// no frames traced
	
	frames[ct++] = chudxnu_vm_unslide(currPC, supervisor);

	// build a backtrace of this 32 bit state.
	while(VALID_STACK_ADDRESS(supervisor, currFP, kernStackMin, kernStackMax)) {
		cframe_t *fp = (cframe_t *) (uintptr_t) currFP;

        if(!currFP) {
            currPC = 0;
            break;
        }

        if(ct >= max_idx) {
			*start_idx = ct;
            return KERN_RESOURCE_SHORTAGE;
        }

		/* read our caller */
		if(supervisor) {
			kr = chudxnu_kern_read(&tmpWord, (vm_offset_t) &fp->caller, sizeof(uint32_t));
		} else {
			kr = chudxnu_task_read(task, &tmpWord, (vm_offset_t) &fp->caller, sizeof(uint32_t));
		}

		if(kr != KERN_SUCCESS) {
			currPC = 0ULL;
			break;
		}

		currPC = (uint64_t) tmpWord;    // promote 32 bit address

        /* 
         * retrive contents of the frame pointer and advance to the next stack
         * frame if it's valid 
         */
        prevFP = 0;
		if(supervisor) {
			kr = chudxnu_kern_read(&tmpWord, (vm_offset_t)&fp->prev, sizeof(uint32_t));
		} else {
			kr = chudxnu_task_read(task, &tmpWord, (vm_offset_t)&fp->prev, sizeof(uint32_t));
		}
		prevFP = (uint64_t) tmpWord;    // promote 32 bit address

        if(prevFP) {
            frames[ct++] = chudxnu_vm_unslide(currPC, supervisor);
            prevPC = currPC;
        }
        if(prevFP < currFP) {
            break;
        } else {
            currFP = prevFP;
        }	
	}

	*start_idx = ct;
	return KERN_SUCCESS;
}

static kern_return_t do_backtrace64(
	task_t task,
	thread_t thread,
	x86_saved_state64_t *regs, 
	uint64_t *frames,
	mach_msg_type_number_t *start_idx,
	mach_msg_type_number_t max_idx,
	boolean_t supervisor)
{
	uint64_t currPC = regs->isf.rip;
	uint64_t currFP = regs->rbp;
	uint64_t prevPC = 0ULL;
	uint64_t prevFP = 0ULL;
	uint64_t kernStackMin = (uint64_t)thread->kernel_stack;
    uint64_t kernStackMax = (uint64_t)kernStackMin + kernel_stack_size;
	mach_msg_type_number_t ct = *start_idx;
	kern_return_t kr = KERN_FAILURE;

	if(*start_idx >= max_idx)
		return KERN_RESOURCE_SHORTAGE;	// no frames traced
	
	frames[ct++] = chudxnu_vm_unslide(currPC, supervisor);

	// build a backtrace of this 32 bit state.
	while(VALID_STACK_ADDRESS64(supervisor, currFP, kernStackMin, kernStackMax)) {
		// this is the address where caller lives in the user thread
		uint64_t caller = currFP + sizeof(uint64_t);

        if(!currFP) {
            currPC = 0;
            break;
        }

        if(ct >= max_idx) {
			*start_idx = ct;
            return KERN_RESOURCE_SHORTAGE;
        }

		/* read our caller */
		if(supervisor) {
			kr = chudxnu_kern_read(&currPC, (vm_offset_t)caller, sizeof(uint64_t));
		} else {
			kr = chudxnu_task_read(task, &currPC, caller, sizeof(uint64_t));
		}

		if(kr != KERN_SUCCESS) {
			currPC = 0ULL;
			break;
		}

        /* 
         * retrive contents of the frame pointer and advance to the next stack
         * frame if it's valid 
         */
        prevFP = 0;
		if(supervisor) {
			kr = chudxnu_kern_read(&prevFP, (vm_offset_t)currFP, sizeof(uint64_t));
		} else {
			kr = chudxnu_task_read(task, &prevFP, currFP, sizeof(uint64_t));
		}

        if(VALID_STACK_ADDRESS64(supervisor, prevFP, kernStackMin, kernStackMax)) {
            frames[ct++] = chudxnu_vm_unslide(currPC, supervisor);
            prevPC = currPC;
        }
        if(prevFP < currFP) {
            break;
        } else {
            currFP = prevFP;
        }	
	}

	*start_idx = ct;
	return KERN_SUCCESS;
}

static kern_return_t do_kernel_backtrace(
	thread_t thread,
	struct x86_kernel_state *regs, 
	uint64_t *frames,
	mach_msg_type_number_t *start_idx,
	mach_msg_type_number_t max_idx)
{
	uint64_t kernStackMin = (uint64_t)thread->kernel_stack;
    uint64_t kernStackMax = (uint64_t)kernStackMin + kernel_stack_size;
	mach_msg_type_number_t ct = *start_idx;
	kern_return_t kr = KERN_FAILURE;

#if __LP64__
	uint64_t currPC = 0ULL;
	uint64_t currFP = 0ULL;
	uint64_t prevPC = 0ULL;
	uint64_t prevFP = 0ULL;
	if(KERN_SUCCESS != chudxnu_kern_read(&currPC, (vm_offset_t)&(regs->k_rip), sizeof(uint64_t))) {
		return KERN_FAILURE;
	}
	if(KERN_SUCCESS != chudxnu_kern_read(&currFP, (vm_offset_t)&(regs->k_rbp), sizeof(uint64_t))) {
		return KERN_FAILURE;
	}
#else
	uint32_t currPC = 0U;
	uint32_t currFP = 0U;
	uint32_t prevPC = 0U;
	uint32_t prevFP = 0U;
	if(KERN_SUCCESS != chudxnu_kern_read(&currPC, (vm_offset_t)&(regs->k_eip), sizeof(uint32_t))) {
		return KERN_FAILURE;
	}
	if(KERN_SUCCESS != chudxnu_kern_read(&currFP, (vm_offset_t)&(regs->k_ebp), sizeof(uint32_t))) {
		return KERN_FAILURE;
	}
#endif

	if(*start_idx >= max_idx)
		return KERN_RESOURCE_SHORTAGE;	// no frames traced
	
	if(!currPC) {
		return KERN_FAILURE;
	}

	frames[ct++] = chudxnu_vm_unslide((uint64_t)currPC, 1);

	// build a backtrace of this kernel state
#if __LP64__
	while(VALID_STACK_ADDRESS64(TRUE, currFP, kernStackMin, kernStackMax)) {
		// this is the address where caller lives in the user thread
		uint64_t caller = currFP + sizeof(uint64_t);
#else
	while(VALID_STACK_ADDRESS(TRUE, currFP, kernStackMin, kernStackMax)) {
		uint32_t caller = (uint32_t)currFP + sizeof(uint32_t);
#endif

        if(!currFP || !currPC) {
            currPC = 0;
            break;
        }

        if(ct >= max_idx) {
			*start_idx = ct;
            return KERN_RESOURCE_SHORTAGE;
        }

		/* read our caller */
		kr = chudxnu_kern_read(&currPC, (vm_offset_t)caller, sizeof(currPC));

		if(kr != KERN_SUCCESS || !currPC) {
			currPC = 0UL;
			break;
		}

        /* 
         * retrive contents of the frame pointer and advance to the next stack
         * frame if it's valid 
         */
        prevFP = 0;
		kr = chudxnu_kern_read(&prevFP, (vm_offset_t)currFP, sizeof(currPC));

#if __LP64__
        if(VALID_STACK_ADDRESS64(TRUE, prevFP, kernStackMin, kernStackMax)) {
#else
        if(VALID_STACK_ADDRESS(TRUE, prevFP, kernStackMin, kernStackMax)) {
#endif
            frames[ct++] = chudxnu_vm_unslide((uint64_t)currPC, 1);
            prevPC = currPC;
        }
        if(prevFP <= currFP) {
            break;
        } else {
            currFP = prevFP;
        }	
	}

	*start_idx = ct;
	return KERN_SUCCESS;
}

static
kern_return_t chudxnu_thread_get_callstack64_internal(
	thread_t		thread,
	uint64_t		*callstack,
	mach_msg_type_number_t	*count,
	boolean_t		user_only,
	boolean_t		kern_only)
{
	kern_return_t kr = KERN_FAILURE;
    task_t task = thread->task;
    uint64_t currPC = 0ULL;
	boolean_t supervisor = FALSE;
    mach_msg_type_number_t bufferIndex = 0;
    mach_msg_type_number_t bufferMaxIndex = *count;
	x86_saved_state_t *tagged_regs = NULL;		// kernel register state
	x86_saved_state64_t *regs64 = NULL;
	x86_saved_state32_t *regs32 = NULL;
	x86_saved_state32_t *u_regs32 = NULL;
	x86_saved_state64_t *u_regs64 = NULL;
	struct x86_kernel_state *kregs = NULL;

	if(ml_at_interrupt_context()) {
		
		if(user_only) {
			/* can't backtrace user state on interrupt stack. */
			return KERN_FAILURE;
		}

		/* backtracing at interrupt context? */
		 if(thread == current_thread() && current_cpu_datap()->cpu_int_state) {
			/* 
			 * Locate the registers for the interrupted thread, assuming it is
			 * current_thread(). 
			 */
			tagged_regs = current_cpu_datap()->cpu_int_state;
			
			if(is_saved_state64(tagged_regs)) {
				/* 64 bit registers */
				regs64 = saved_state64(tagged_regs);
				supervisor = ((regs64->isf.cs & SEL_PL) != SEL_PL_U);
			} else {
				/* 32 bit registers */
				regs32 = saved_state32(tagged_regs);
				supervisor = ((regs32->cs & SEL_PL) != SEL_PL_U);
			}
		} 
	}

	if(!ml_at_interrupt_context() && kernel_task == task) {

		if(!thread->kernel_stack) {
			return KERN_FAILURE;
		}

		// Kernel thread not at interrupt context
		kregs = (struct x86_kernel_state *)NULL;

		// nofault read of the thread->kernel_stack pointer
		if(KERN_SUCCESS != chudxnu_kern_read(&kregs, (vm_offset_t)&(thread->kernel_stack), sizeof(void *))) {
			return KERN_FAILURE;
		}

		// Adjust to find the saved kernel state
		kregs = STACK_IKS((vm_offset_t)(uintptr_t)kregs);

		supervisor = TRUE;
	} else if(!tagged_regs) {
		/* 
		 * not at interrupt context, or tracing a different thread than
		 * current_thread() at interrupt context 
		 */
		tagged_regs = USER_STATE(thread);
		if(is_saved_state64(tagged_regs)) {
			/* 64 bit registers */
			regs64 = saved_state64(tagged_regs);
			supervisor = ((regs64->isf.cs & SEL_PL) != SEL_PL_U); 
		} else {
			/* 32 bit registers */
			regs32 = saved_state32(tagged_regs);
			supervisor = ((regs32->cs & SEL_PL) != SEL_PL_U);
		}
	}

	*count = 0; 

	if(supervisor) {
		// the caller only wants a user callstack.
		if(user_only) {
			// bail - we've only got kernel state
			return KERN_FAILURE;
		}
	} else {
		// regs32(64) is not in supervisor mode.
		u_regs32 = regs32;
		u_regs64 = regs64;
		regs32 = NULL;
		regs64 = NULL;
	}

	if (user_only) {
		/* we only want to backtrace the user mode */
		if(!(u_regs32 || u_regs64)) {
			/* no user state to look at */
			return KERN_FAILURE;
		}
	}

	/* 
	 * Order of preference for top of stack:
	 * 64 bit kernel state (not likely)
	 * 32 bit kernel state
	 * 64 bit user land state
	 * 32 bit user land state
	 */

	if(kregs) {
		/*
		 * nofault read of the registers from the kernel stack (as they can
		 * disappear on the fly).
		 */

#if __LP64__
		if(KERN_SUCCESS != chudxnu_kern_read(&currPC, (vm_offset_t)&(kregs->k_rip), sizeof(uint64_t))) {
			return KERN_FAILURE;
		}
#else
		uint32_t tmp;
		if(KERN_SUCCESS != chudxnu_kern_read(&tmp, (vm_offset_t)&(kregs->k_eip), sizeof(uint32_t))) {
			return KERN_FAILURE;
		}
		currPC = (uint64_t)tmp;
#endif
	} else if(regs64) {
		currPC = regs64->isf.rip;
	} else if(regs32) {
		currPC = (uint64_t) regs32->eip;
	} else if(u_regs64) {
		currPC = u_regs64->isf.rip;
	} else if(u_regs32) {
		currPC = (uint64_t) u_regs32->eip;
	}
	
	if(!currPC) {
		/* no top of the stack, bail out */
		return KERN_FAILURE;
	}

	bufferIndex = 0;
		
	if(bufferMaxIndex < 1) {
		*count = 0;
		return KERN_RESOURCE_SHORTAGE;
	}

	/* backtrace kernel */
	if(kregs) {
		addr64_t address = 0ULL;
		size_t size = 0UL;

		// do the backtrace
		kr = do_kernel_backtrace(thread, kregs, callstack, &bufferIndex, bufferMaxIndex);

		// and do a nofault read of (r|e)sp
#if __LP64__
		uint64_t rsp = 0ULL;
		size = sizeof(uint64_t);
		
		if(KERN_SUCCESS != chudxnu_kern_read(&address, (vm_offset_t)&(kregs->k_rsp), size)) {
			address = 0ULL;
		}
#else
		uint32_t rsp = 0ULL, tmp = 0ULL;
		size = sizeof(uint32_t);

		if(KERN_SUCCESS != chudxnu_kern_read(&tmp, (vm_offset_t)&(kregs->k_esp), size)) {
			address = 0ULL;
		} else {
			address = (addr64_t)tmp;
		}
#endif

		if(address && KERN_SUCCESS == chudxnu_kern_read(&rsp, (vm_offset_t)address, size) && bufferIndex < bufferMaxIndex) {
			callstack[bufferIndex++] = (uint64_t)rsp;
		}
	} else if(regs64) {
		uint64_t rsp = 0ULL;

		// backtrace the 64bit side.
		kr = do_backtrace64(task, thread, regs64, callstack, &bufferIndex, 
			bufferMaxIndex, TRUE);

		if(KERN_SUCCESS == chudxnu_kern_read(&rsp, (vm_offset_t) regs64->isf.rsp, sizeof(uint64_t)) && 
			bufferIndex < bufferMaxIndex) {
			callstack[bufferIndex++] = rsp;
		}

	} else if(regs32) {
		uint32_t esp = 0UL;

		// backtrace the 32bit side.
		kr = do_backtrace32(task, thread, regs32, callstack, &bufferIndex, 
			bufferMaxIndex, TRUE);
		
		if(KERN_SUCCESS == chudxnu_kern_read(&esp, (vm_offset_t) regs32->uesp, sizeof(uint32_t)) && 
			bufferIndex < bufferMaxIndex) {
			callstack[bufferIndex++] = (uint64_t) esp;
		}
	} else if(u_regs64 && !kern_only) {
		/* backtrace user land */
		uint64_t rsp = 0ULL;
		
		kr = do_backtrace64(task, thread, u_regs64, callstack, &bufferIndex, 
			bufferMaxIndex, FALSE);

		if(KERN_SUCCESS == chudxnu_task_read(task, &rsp, (addr64_t) u_regs64->isf.rsp, sizeof(uint64_t)) && 
			bufferIndex < bufferMaxIndex) {
			callstack[bufferIndex++] = rsp;
		}

	} else if(u_regs32 && !kern_only) {
		uint32_t esp = 0UL;
		
		kr = do_backtrace32(task, thread, u_regs32, callstack, &bufferIndex, 
			bufferMaxIndex, FALSE);

		if(KERN_SUCCESS == chudxnu_task_read(task, &esp, (addr64_t) u_regs32->uesp, sizeof(uint32_t)) && 
			bufferIndex < bufferMaxIndex) {
			callstack[bufferIndex++] = (uint64_t) esp;
		}
	}

    *count = bufferIndex;
    return kr;
}

__private_extern__
kern_return_t chudxnu_thread_get_callstack64_kperf(
	thread_t		thread,
	uint64_t		*callstack,
	mach_msg_type_number_t	*count,
	boolean_t		is_user)
{
	return chudxnu_thread_get_callstack64_internal(thread, callstack, count, is_user, !is_user);
}

__private_extern__
kern_return_t chudxnu_thread_get_callstack64(
	thread_t		thread,
	uint64_t		*callstack,
	mach_msg_type_number_t	*count,
	boolean_t		user_only)
{
	return chudxnu_thread_get_callstack64_internal(thread, callstack, count, user_only, 0);
}

