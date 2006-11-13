/*
 * Copyright (c) 2003-2004 Apple Computer, Inc. All rights reserved.
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

#include <mach/mach_types.h>
#include <mach/task.h>
#include <mach/thread_act.h>

#include <kern/kern_types.h>
#include <kern/processor.h>
#include <kern/thread.h>

#include <vm/vm_map.h>
#include <vm/pmap.h>

#include <chud/chud_xnu.h>
#include <chud/chud_xnu_private.h>

#include <i386/misc_protos.h>
#include <i386/proc_reg.h>
#include <i386/mp_desc.h>

#pragma mark **** thread state ****

__private_extern__ kern_return_t
chudxnu_thread_user_state_available(thread_t thread)
{
#pragma unused (thread)
	return KERN_SUCCESS;
}

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

#pragma mark **** task memory read/write ****
    
__private_extern__ kern_return_t
chudxnu_task_read(
	task_t		task,
	void		*kernaddr,
	uint64_t	usraddr,
	vm_size_t	size)
{
	kern_return_t ret = KERN_SUCCESS;
    
	if(current_task()==task) {
		if(ml_at_interrupt_context()) {
			return KERN_FAILURE; // can't do copyin on interrupt stack
		}
	
		if(copyin(usraddr, kernaddr, size)) {
			ret = KERN_FAILURE;
		}
	} else {
		vm_map_t map = get_task_map(task);
		ret = vm_map_read_user(map, usraddr, kernaddr, size);
	}
    
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
    
	if(current_task()==task) {    
		if(ml_at_interrupt_context()) {
			return KERN_FAILURE; // can't do copyout on interrupt stack
		}
	
		if(copyout(kernaddr, useraddr, size)) {
			ret = KERN_FAILURE;
		}
	} else {
		vm_map_t map = get_task_map(task);
		ret = vm_map_write_user(map, kernaddr, useraddr, size);
	}		
    
	return ret;
}

__private_extern__ kern_return_t
chudxnu_kern_read(void *dstaddr, vm_offset_t srcaddr, vm_size_t size)
{
    while(size>0) {
		ppnum_t pp;
		addr64_t phys_addr;    
		
		/* Get the page number */
		pp = pmap_find_phys(kernel_pmap, srcaddr);
		if(!pp) {
			return KERN_FAILURE;	/* Not mapped... */
		}
		
		/* Shove in the page offset */
		phys_addr = ((addr64_t)pp << 12) |
				(srcaddr & 0x0000000000000FFFULL);
		if(phys_addr >= mem_actual) {
			return KERN_FAILURE;	/* out of range */
		}
		
		if((phys_addr&0x1) || size==1) {
			*((uint8_t *)dstaddr) =
				ml_phys_read_byte_64(phys_addr);
			dstaddr = ((uint8_t *)dstaddr) + 1;
			srcaddr += sizeof(uint8_t);
			size -= sizeof(uint8_t);
		} else if((phys_addr&0x3) || size<=2) {
			*((uint16_t *)dstaddr) =
				ml_phys_read_half_64(phys_addr);
			dstaddr = ((uint16_t *)dstaddr) + 1;
			srcaddr += sizeof(uint16_t);
			size -= sizeof(uint16_t);
		} else {
			*((uint32_t *)dstaddr) =
				ml_phys_read_word_64(phys_addr);
			dstaddr = ((uint32_t *)dstaddr) + 1;
			srcaddr += sizeof(uint32_t);
			size -= sizeof(uint32_t);
		}
    }
    return KERN_SUCCESS;
}

__private_extern__ kern_return_t
chudxnu_kern_write(
	vm_offset_t	dstaddr,
	void		*srcaddr,
	vm_size_t	size)
{
	while(size>0) {
		ppnum_t pp;
		addr64_t phys_addr;    
		
		/* Get the page number */
		pp = pmap_find_phys(kernel_pmap, dstaddr);
		if(!pp) {
			return KERN_FAILURE;	/* Not mapped... */
		}
		
		/* Shove in the page offset */
		phys_addr = ((addr64_t)pp << 12) |
				(dstaddr & 0x0000000000000FFFULL);
		if(phys_addr > mem_actual) {
			return KERN_FAILURE;	/* out of range */
		}
		
		if((phys_addr&0x1) || size==1) {
			ml_phys_write_byte_64(phys_addr, *((uint8_t *)srcaddr));
			srcaddr = ((uint8_t *)srcaddr) + 1;
			dstaddr += sizeof(uint8_t);
			size -= sizeof(uint8_t);
		} else if((phys_addr&0x3) || size<=2) {
			ml_phys_write_half_64(phys_addr, *((uint16_t *)srcaddr));
			srcaddr = ((uint16_t *)srcaddr) + 1;
			dstaddr += sizeof(uint16_t);
			size -= sizeof(uint16_t);
		} else {
			ml_phys_write_word_64(phys_addr, *((uint32_t *)srcaddr));
			srcaddr = ((uint32_t *)srcaddr) + 1;
			dstaddr += sizeof(uint32_t);
			size -= sizeof(uint32_t);
		}
    }
    
    return KERN_SUCCESS;
}

#define VALID_STACK_ADDRESS(supervisor, addr, minKernAddr, maxKernAddr)   (supervisor ? (addr>=minKernAddr && addr<=maxKernAddr) : TRUE)
// don't try to read in the hole
#define VALID_STACK_ADDRESS64(supervisor, addr, minKernAddr, maxKernAddr) \
	(supervisor ? (addr >= minKernAddr && addr <= maxKernAddr) : \
		(addr != 0 && (addr <= 0x00007FFFFFFFFFFFULL || addr >= 0xFFFF800000000000ULL)))

typedef struct _cframe64_t {
	uint64_t	prevFP;		// can't use a real pointer here until we're a 64 bit kernel
	uint64_t	caller;
	uint64_t	args[0];
}cframe64_t;


typedef struct _cframe_t {
	struct _cframe_t	*prev;	// when we go 64 bits, this needs to be capped at 32 bits
	uint32_t		caller;
	uint32_t		args[0];
} cframe_t;

__private_extern__
kern_return_t chudxnu_thread_get_callstack64(
	thread_t		thread,
	uint64_t		*callstack,
	mach_msg_type_number_t	*count,
	boolean_t		user_only)
{
    kern_return_t kr = KERN_FAILURE;
	kern_return_t ret = KERN_SUCCESS;
    task_t task = thread->task;
    uint64_t currPC = 0;
	uint64_t prevPC = 0;
    uint64_t currFP = 0;
    uint64_t prevFP = 0;
    uint64_t rsp = 0;
    uint64_t kernStackMin = min_valid_stack_address();
    uint64_t kernStackMax = max_valid_stack_address();
    uint64_t *buffer = callstack;
    int bufferIndex = 0;
    int bufferMaxIndex = *count;
    boolean_t supervisor = FALSE;
	boolean_t is64bit = FALSE;
	void * t_regs;
	
	if (user_only) {
		/* We can't get user state for kernel threads */
		if (task == kernel_task) {
			return KERN_FAILURE;
		}
        t_regs = USER_STATE(thread);
		
		if(is_saved_state64(t_regs)) {
			void *int_state = current_cpu_datap()->cpu_int_state;
			x86_saved_state64_t *s64 = saved_state64(t_regs);
			
			if(int_state) {	// are we on an interrupt that happened in user land
				supervisor = !(t_regs == int_state && current_cpu_datap()->cpu_interrupt_level == 1);
			} else {
				if(s64) {
					supervisor = ((s64->isf.cs & SEL_PL) != SEL_PL_U);
				} else {
					// assume 32 bit kernel
					supervisor = FALSE;	
				}
			}
			is64bit = TRUE;
		} else {
			x86_saved_state32_t *regs;

			regs = saved_state32(t_regs);
			
			// find out if we're in supervisor mode
			supervisor = ((regs->cs & SEL_PL) != SEL_PL_U);
			is64bit = FALSE;
		}
    } else {
    	t_regs = current_cpu_datap()->cpu_int_state;
		x86_saved_state32_t *regs;

        regs = saved_state32(t_regs);
		
		// find out if we're in supervisor mode
        supervisor = ((regs->cs & SEL_PL) != SEL_PL_U);
		is64bit = FALSE;
    }
	
	if(is64bit) {
		x86_saved_state64_t *regs = saved_state64(t_regs);
		
		if(user_only) {
			/* cant get user state for kernel threads */
			if(task == kernel_task) {
				return KERN_FAILURE;
			}
			regs = USER_REGS64(thread);
		} 
		
		currPC = regs->isf.rip;
		currFP = regs->rbp;
		
		if(!currPC)
		{
			*count = 0;
			return KERN_FAILURE;
		}
		
		bufferIndex = 0;
		
		//allot space for saving %rsp on the 
		//bottom of the stack for user callstacks
		if(!supervisor)
			bufferMaxIndex = bufferMaxIndex - 1;    
			
		if(bufferMaxIndex < 1) {
			*count = 0;
			return KERN_RESOURCE_SHORTAGE;
		}
		buffer[bufferIndex++] = currPC; // save RIP on the top of the stack

		// now make a 64bit back trace
		while (VALID_STACK_ADDRESS64(supervisor, currFP, kernStackMin, kernStackMax))
		{
			// this is the address where caller lives in the user thread
			uint64_t caller = currFP + sizeof(uint64_t);
			if(!currFP) {
				currPC = 0;
				break;
			}
			
			if(bufferIndex >= bufferMaxIndex) {
				*count = bufferMaxIndex;
				return KERN_RESOURCE_SHORTAGE;
			}

			/* read our caller */
			kr = chudxnu_task_read(task, &currPC, caller, sizeof(uint64_t));    
			
			if(kr != KERN_SUCCESS) {
				currPC = 0;
				break;
			}
			
			/* 
			 * retrive contents of the frame pointer and advance to the next stack
			 * frame if it's valid 
			 */
			prevFP = 0;
			kr = chudxnu_task_read(task, &prevFP, currFP, sizeof(uint64_t));
			
			if(kr != KERN_SUCCESS) {
				currPC = 0;
				break;
			}
	
			if(VALID_STACK_ADDRESS64(supervisor, prevFP, kernStackMin, kernStackMax)) {
				buffer[bufferIndex++] = currPC;
				prevPC = currPC;
			}
			if(prevFP < currFP) {
				break;
			} else {
				currFP = prevFP;
			}
		}

		// append (rsp) on the bottom of the callstack
		kr = chudxnu_task_read(task, &rsp, (addr64_t) regs->isf.rsp, sizeof(uint64_t));
		if(kr == KERN_SUCCESS) {
			buffer[bufferIndex++] = rsp;
		}
    } else {
		/* !thread_is_64bit() */
		/* we grab 32 bit frames and silently promote them to 64 bits */
		uint32_t tmpWord = 0;
		x86_saved_state32_t *regs = NULL;
		
		if(user_only) {
			/* cant get user state for kernel threads */
			if(task == kernel_task || supervisor) {
				return 0x11;
			}
			regs = USER_REGS32(thread);
		} else {
			regs = saved_state32(current_cpu_datap()->cpu_int_state);
		}
		
		if(regs == NULL) {
			*count = 0;
			return 0x12;
		}

		currPC = (uint64_t) regs->eip;
		currFP = (uint64_t) regs->ebp;
		
		bufferIndex = 0;
		//if(!supervisor)
		//	bufferMaxIndex = bufferMaxIndex - 1;    //allot space for saving %rsp on the stack for user callstacks
		if(bufferMaxIndex < 1) {
			*count = 0;
			return KERN_RESOURCE_SHORTAGE;
		}
		buffer[bufferIndex++] = currPC; // save EIP on the top of the stack

		// now make a 64bit back trace from 32 bit stack frames
		while (VALID_STACK_ADDRESS(supervisor, currFP, kernStackMin, kernStackMax))
		{
			cframe_t *fp = (cframe_t *) (uint32_t) currFP;

			if(bufferIndex >= bufferMaxIndex) {
				*count = bufferMaxIndex;
				return KERN_RESOURCE_SHORTAGE;
			}

			/* read the next frame */
			if(supervisor) {
				kr = chudxnu_kern_read(&tmpWord, (vm_offset_t) &fp->caller, sizeof(uint32_t));
			} else {
				kr = chudxnu_task_read(task, &tmpWord, (vm_offset_t) &fp->caller, sizeof(uint32_t));    
			}
			
			if(kr != KERN_SUCCESS) {
				currPC = 0;
				break;
			}
			
			currPC = (uint64_t) tmpWord;	// promote 32 bit address
			
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
			prevFP = (uint64_t) tmpWord;	// promote 32 bit address
			
			if(prevFP) {
				buffer[bufferIndex++] = currPC;
				prevPC = currPC;
			}
			if(prevFP < currFP) {
				break;
			} else {
				currFP = prevFP;
			}
		}

		// append (esp) on the bottom of the callstack
		if(!supervisor) {
			kr = chudxnu_task_read(task, &tmpWord, regs->uesp, sizeof(uint32_t));
			if(kr == KERN_SUCCESS) {
				rsp = (uint64_t) tmpWord;	// promote 32 bit address
				buffer[bufferIndex++] = rsp;
			}
		}
    }
    
    *count = bufferIndex;
    return ret;
}

__private_extern__ kern_return_t
chudxnu_thread_get_callstack(
	thread_t		thread, 
	uint32_t		*callStack,
	mach_msg_type_number_t	*count,
	boolean_t		user_only)
{
	kern_return_t   kr;
	task_t          task = thread->task;
	uint32_t        currPC;
	uint32_t        currFP;
	uint32_t        prevFP = 0;
	uint32_t        prevPC = 0;
    uint32_t        esp = 0;
	uint32_t        kernStackMin = min_valid_stack_address();
	uint32_t        kernStackMax = max_valid_stack_address();
	uint32_t       *buffer = callStack;
	int             bufferIndex = 0;
	int             bufferMaxIndex = *count;
	boolean_t       supervisor;
	x86_saved_state32_t *regs = NULL;

    if (user_only) {
		/* We can't get user state for kernel threads */
		if (task == kernel_task) {
			return KERN_FAILURE;
		}
        regs = USER_REGS32(thread);
    } else {
    	regs = saved_state32(current_cpu_datap()->cpu_int_state);
    }

    if (regs == NULL) {
        *count = 0;
		return KERN_FAILURE;
    }
	
	supervisor = ((regs->cs & SEL_PL) != SEL_PL_U);
	
	currPC = regs->eip;
	currFP = regs->ebp;
	
	bufferIndex = 0;
    if(!supervisor)
        bufferMaxIndex -= 1;    // allot space for saving userland %esp on stack
	if (bufferMaxIndex < 1) {
		*count = 0;
		return KERN_RESOURCE_SHORTAGE;
	}
	buffer[bufferIndex++] = currPC; //save PC in position 0.

	// Now, fill buffer with stack backtraces.
	while (VALID_STACK_ADDRESS(supervisor, currFP, kernStackMin, kernStackMax)) {
		cframe_t	*fp = (cframe_t *) currFP;

		if (bufferIndex >= bufferMaxIndex) {
			*count = bufferMaxIndex;
			return KERN_RESOURCE_SHORTAGE;
		}

		if (supervisor) {
			kr = chudxnu_kern_read(
					&currPC,
					(vm_offset_t) &fp->caller,
					sizeof(currPC));
		} else {
			kr = chudxnu_task_read(
					task,
					&currPC,
					(vm_offset_t) &fp->caller,
					sizeof(currPC));
		}
		if (kr != KERN_SUCCESS)
			break;

		//retrieve the contents of the frame pointer
		// and advance to the prev stack frame if it's valid
		prevFP = 0;
		if (supervisor) {
			kr = chudxnu_kern_read(
					&prevFP,
					(vm_offset_t) &fp->prev,
					sizeof(prevFP));
		} else {
			kr = chudxnu_task_read(
					task,
					&prevFP,
					(vm_offset_t) &fp->prev,
					sizeof(prevFP));
		}
		if (prevFP) {
			buffer[bufferIndex++] = currPC;
			prevPC = currPC;
		}
		if (prevFP < currFP) {
			break;
		} else {
			currFP = prevFP;
		}
	}

	// put the stack pointer on the bottom of the backtrace
    if(!supervisor) {
        kr = chudxnu_task_read(task, &esp, regs->uesp, sizeof(uint32_t));
        if(kr == KERN_SUCCESS) {
            buffer[bufferIndex++] = esp;
        }
    }

	*count = bufferIndex;
	return KERN_SUCCESS;
}


#pragma mark **** DEPRECATED ****

// DEPRECATED
__private_extern__
kern_return_t chudxnu_bind_current_thread(int cpu)
{
	return chudxnu_bind_thread(current_thread(), cpu);
}

// DEPRECATED
kern_return_t chudxnu_unbind_current_thread(void)
{
	return chudxnu_unbind_thread(current_thread());
}

// DEPRECATED
__private_extern__
kern_return_t chudxnu_current_thread_get_callstack(
	uint32_t		*callStack,
	mach_msg_type_number_t	*count,
	boolean_t		user_only)
{
	return chudxnu_thread_get_callstack(
			current_thread(), callStack, count, user_only);
}

// DEPRECATED
__private_extern__
thread_t chudxnu_current_act(void)
{
	return chudxnu_current_thread();
}
