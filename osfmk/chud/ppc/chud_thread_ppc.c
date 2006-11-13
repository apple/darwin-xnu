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
#include <kern/ipc_tt.h>

#include <vm/vm_map.h>
#include <vm/pmap.h>

#include <chud/chud_xnu.h>
#include <chud/chud_xnu_private.h>

#include <ppc/misc_protos.h>
#include <ppc/proc_reg.h>
#include <ppc/machine_routines.h>
#include <ppc/fpu_protos.h>

// forward declarations
extern kern_return_t machine_thread_get_kern_state( thread_t                thread,
													thread_flavor_t         flavor,
													thread_state_t          tstate,
													mach_msg_type_number_t  *count);


#pragma mark **** thread state ****

__private_extern__
kern_return_t chudxnu_copy_savearea_to_threadstate(thread_flavor_t flavor, thread_state_t tstate, mach_msg_type_number_t *count, struct savearea *sv)
{
    struct ppc_thread_state *ts;
    struct ppc_thread_state64 *xts;

    switch(flavor) {
    case PPC_THREAD_STATE:
        if(*count < PPC_THREAD_STATE_COUNT) { /* Is the count ok? */
            *count = 0;
            return KERN_INVALID_ARGUMENT;
        }
        ts = (struct ppc_thread_state *) tstate;
        if(sv) {
            ts->r0	= (unsigned int)sv->save_r0;
            ts->r1	= (unsigned int)sv->save_r1;
            ts->r2	= (unsigned int)sv->save_r2;
            ts->r3	= (unsigned int)sv->save_r3;
            ts->r4	= (unsigned int)sv->save_r4;
            ts->r5	= (unsigned int)sv->save_r5;
            ts->r6	= (unsigned int)sv->save_r6;
            ts->r7	= (unsigned int)sv->save_r7;
            ts->r8	= (unsigned int)sv->save_r8;
            ts->r9	= (unsigned int)sv->save_r9;
            ts->r10	= (unsigned int)sv->save_r10;
            ts->r11	= (unsigned int)sv->save_r11;
            ts->r12	= (unsigned int)sv->save_r12;
            ts->r13	= (unsigned int)sv->save_r13;
            ts->r14	= (unsigned int)sv->save_r14;
            ts->r15	= (unsigned int)sv->save_r15;
            ts->r16	= (unsigned int)sv->save_r16;
            ts->r17	= (unsigned int)sv->save_r17;
            ts->r18	= (unsigned int)sv->save_r18;
            ts->r19	= (unsigned int)sv->save_r19;
            ts->r20	= (unsigned int)sv->save_r20;
            ts->r21	= (unsigned int)sv->save_r21;
            ts->r22	= (unsigned int)sv->save_r22;
            ts->r23	= (unsigned int)sv->save_r23;
            ts->r24	= (unsigned int)sv->save_r24;
            ts->r25	= (unsigned int)sv->save_r25;
            ts->r26	= (unsigned int)sv->save_r26;
            ts->r27	= (unsigned int)sv->save_r27;
            ts->r28	= (unsigned int)sv->save_r28;
            ts->r29	= (unsigned int)sv->save_r29;
            ts->r30	= (unsigned int)sv->save_r30;
            ts->r31	= (unsigned int)sv->save_r31;
            ts->cr	= (unsigned int)sv->save_cr;
            ts->xer	= (unsigned int)sv->save_xer;
            ts->lr	= (unsigned int)sv->save_lr;
            ts->ctr	= (unsigned int)sv->save_ctr;
            ts->srr0 	= (unsigned int)sv->save_srr0;
            ts->srr1 	= (unsigned int)sv->save_srr1;
            ts->mq	= 0;
            ts->vrsave	= (unsigned int)sv->save_vrsave;
        } else {
            bzero((void *)ts, sizeof(struct ppc_thread_state));
        }
            *count = PPC_THREAD_STATE_COUNT; /* Pass back the amount we actually copied */
        return KERN_SUCCESS;
        break;
    case PPC_THREAD_STATE64:
        if(*count < PPC_THREAD_STATE64_COUNT) { /* Is the count ok? */
            return KERN_INVALID_ARGUMENT;
        }
        xts = (struct ppc_thread_state64 *) tstate;
        if(sv) {
            xts->r0	= sv->save_r0;
            xts->r1	= sv->save_r1;
            xts->r2	= sv->save_r2;
            xts->r3	= sv->save_r3;
            xts->r4	= sv->save_r4;
            xts->r5	= sv->save_r5;
            xts->r6	= sv->save_r6;
            xts->r7	= sv->save_r7;
            xts->r8	= sv->save_r8;
            xts->r9	= sv->save_r9;
            xts->r10	= sv->save_r10;
            xts->r11	= sv->save_r11;
            xts->r12	= sv->save_r12;
            xts->r13	= sv->save_r13;
            xts->r14	= sv->save_r14;
            xts->r15	= sv->save_r15;
            xts->r16	= sv->save_r16;
            xts->r17	= sv->save_r17;
            xts->r18	= sv->save_r18;
            xts->r19	= sv->save_r19;
            xts->r20	= sv->save_r20;
            xts->r21	= sv->save_r21;
            xts->r22	= sv->save_r22;
            xts->r23	= sv->save_r23;
            xts->r24	= sv->save_r24;
            xts->r25	= sv->save_r25;
            xts->r26	= sv->save_r26;
            xts->r27	= sv->save_r27;
            xts->r28	= sv->save_r28;
            xts->r29	= sv->save_r29;
            xts->r30	= sv->save_r30;
            xts->r31	= sv->save_r31;
            xts->cr	= sv->save_cr;
            xts->xer	= sv->save_xer;
            xts->lr	= sv->save_lr;
            xts->ctr	= sv->save_ctr;
            xts->srr0 	= sv->save_srr0;
            xts->srr1 	= sv->save_srr1;
            xts->vrsave	= sv->save_vrsave;
        } else {
            bzero((void *)xts, sizeof(struct ppc_thread_state64));
        }
        *count = PPC_THREAD_STATE64_COUNT; /* Pass back the amount we actually copied */
        return KERN_SUCCESS;
        break;
    default:
        *count = 0;
        return KERN_INVALID_ARGUMENT;
        break;
    }
}

__private_extern__
kern_return_t chudxnu_copy_threadstate_to_savearea(struct savearea *sv, thread_flavor_t flavor, thread_state_t tstate, mach_msg_type_number_t *count)
{
    struct ppc_thread_state *ts;
    struct ppc_thread_state64 *xts;

    switch(flavor) {
    case PPC_THREAD_STATE:
        if(*count < PPC_THREAD_STATE_COUNT) { /* Is the count ok? */
            return KERN_INVALID_ARGUMENT;
        }
        ts = (struct ppc_thread_state *) tstate;
        if(sv) {
            sv->save_r0		= (uint64_t)ts->r0;
            sv->save_r1		= (uint64_t)ts->r1;
            sv->save_r2		= (uint64_t)ts->r2;
            sv->save_r3		= (uint64_t)ts->r3;
            sv->save_r4		= (uint64_t)ts->r4;
            sv->save_r5		= (uint64_t)ts->r5;
            sv->save_r6		= (uint64_t)ts->r6;
            sv->save_r7		= (uint64_t)ts->r7;
            sv->save_r8		= (uint64_t)ts->r8;
            sv->save_r9		= (uint64_t)ts->r9;
            sv->save_r10	= (uint64_t)ts->r10;
            sv->save_r11	= (uint64_t)ts->r11;
            sv->save_r12	= (uint64_t)ts->r12;
            sv->save_r13	= (uint64_t)ts->r13;
            sv->save_r14	= (uint64_t)ts->r14;
            sv->save_r15	= (uint64_t)ts->r15;
            sv->save_r16	= (uint64_t)ts->r16;
            sv->save_r17	= (uint64_t)ts->r17;
            sv->save_r18	= (uint64_t)ts->r18;
            sv->save_r19	= (uint64_t)ts->r19;
            sv->save_r20	= (uint64_t)ts->r20;
            sv->save_r21	= (uint64_t)ts->r21;
            sv->save_r22	= (uint64_t)ts->r22;
            sv->save_r23	= (uint64_t)ts->r23;
            sv->save_r24	= (uint64_t)ts->r24;
            sv->save_r25	= (uint64_t)ts->r25;
            sv->save_r26	= (uint64_t)ts->r26;
            sv->save_r27	= (uint64_t)ts->r27;
            sv->save_r28	= (uint64_t)ts->r28;
            sv->save_r29	= (uint64_t)ts->r29;
            sv->save_r30	= (uint64_t)ts->r30;
            sv->save_r31	= (uint64_t)ts->r31;
            sv->save_cr		= ts->cr;
            sv->save_xer	= (uint64_t)ts->xer;
            sv->save_lr		= (uint64_t)ts->lr;
            sv->save_ctr	= (uint64_t)ts->ctr;
            sv->save_srr0	= (uint64_t)ts->srr0;
            sv->save_srr1	= (uint64_t)ts->srr1;
            sv->save_vrsave	= ts->vrsave;
            return KERN_SUCCESS;
        }
            break;
    case PPC_THREAD_STATE64:
        if(*count < PPC_THREAD_STATE64_COUNT) { /* Is the count ok? */
            return KERN_INVALID_ARGUMENT;
        }
        xts = (struct ppc_thread_state64 *) tstate;
        if(sv) {
            sv->save_r0		= xts->r0;
            sv->save_r1		= xts->r1;
            sv->save_r2		= xts->r2;
            sv->save_r3		= xts->r3;
            sv->save_r4		= xts->r4;
            sv->save_r5		= xts->r5;
            sv->save_r6		= xts->r6;
            sv->save_r7		= xts->r7;
            sv->save_r8		= xts->r8;
            sv->save_r9		= xts->r9;
            sv->save_r10	= xts->r10;
            sv->save_r11	= xts->r11;
            sv->save_r12	= xts->r12;
            sv->save_r13	= xts->r13;
            sv->save_r14	= xts->r14;
            sv->save_r15	= xts->r15;
            sv->save_r16	= xts->r16;
            sv->save_r17	= xts->r17;
            sv->save_r18	= xts->r18;
            sv->save_r19	= xts->r19;
            sv->save_r20	= xts->r20;
            sv->save_r21	= xts->r21;
            sv->save_r22	= xts->r22;
            sv->save_r23	= xts->r23;
            sv->save_r24	= xts->r24;
            sv->save_r25	= xts->r25;
            sv->save_r26	= xts->r26;
            sv->save_r27	= xts->r27;
            sv->save_r28	= xts->r28;
            sv->save_r29	= xts->r29;
            sv->save_r30	= xts->r30;
            sv->save_r31	= xts->r31;
            sv->save_cr		= xts->cr;
            sv->save_xer	= xts->xer;
            sv->save_lr		= xts->lr;
            sv->save_ctr	= xts->ctr;
            sv->save_srr0	= xts->srr0;
            sv->save_srr1	= xts->srr1;
            sv->save_vrsave	= xts->vrsave;
            return KERN_SUCCESS;
        }
    }
    return KERN_FAILURE;
}

__private_extern__
kern_return_t chudxnu_thread_user_state_available(thread_t thread)
{
    if(find_user_regs(thread)) {
	return KERN_SUCCESS;
    } else {
	return KERN_FAILURE;
    }
}

__private_extern__
kern_return_t chudxnu_thread_get_state(thread_t thread, 
				    thread_flavor_t flavor,
                                    thread_state_t tstate,
                                    mach_msg_type_number_t *count,
                                    boolean_t user_only)
{
    if(flavor==PPC_THREAD_STATE || flavor==PPC_THREAD_STATE64) { // machine_thread_get_state filters out some bits
		struct savearea *sv;
		if(user_only) {
			sv = find_user_regs(thread);
		} else {
			sv = find_kern_regs(thread);
		}
		return chudxnu_copy_savearea_to_threadstate(flavor, tstate, count, sv);
    } else {
		if(user_only) {
			return machine_thread_get_state(thread, flavor, tstate, count);
		} else {
			// doesn't do FP or VMX
			return machine_thread_get_kern_state(thread, flavor, tstate, count);
		}    
    }
}

__private_extern__
kern_return_t chudxnu_thread_set_state(thread_t thread, 
					thread_flavor_t flavor,
					thread_state_t tstate,
					mach_msg_type_number_t count,
					boolean_t user_only)
{
    if(flavor==PPC_THREAD_STATE || flavor==PPC_THREAD_STATE64) { // machine_thread_set_state filters out some bits
		struct savearea *sv;
		if(user_only) {
			sv = find_user_regs(thread);
		} else {
			sv = find_kern_regs(thread);
		}
		return chudxnu_copy_threadstate_to_savearea(sv, flavor, tstate, &count);
    } else {
		return machine_thread_set_state(thread, flavor, tstate, count); // always user
    }
}

#pragma mark **** task memory read/write ****
    
__private_extern__
kern_return_t chudxnu_task_read(task_t task, void *kernaddr, uint64_t usraddr, vm_size_t size)
{
    kern_return_t ret = KERN_SUCCESS;
    
	if(!chudxnu_is_64bit_task(task)) { // clear any cruft out of upper 32-bits for 32-bit tasks
		usraddr &= 0x00000000FFFFFFFFULL;
	}

    if(current_task()==task) {
		thread_t      cur_thr = current_thread();
		vm_offset_t   recover_handler = cur_thr->recover; 
		
		if(ml_at_interrupt_context()) {
			return KERN_FAILURE; // can't do copyin on interrupt stack
		}
	
		if(copyin(usraddr, kernaddr, size)) {
			ret = KERN_FAILURE;
		}
		cur_thr->recover = recover_handler;
    } else {
		vm_map_t map = get_task_map(task);
		ret = vm_map_read_user(map, usraddr, kernaddr, size);
    }
    
    return ret;
}
			
__private_extern__
kern_return_t chudxnu_task_write(task_t task, uint64_t useraddr, void *kernaddr, vm_size_t size)
{
    kern_return_t ret = KERN_SUCCESS;
    
	if(!chudxnu_is_64bit_task(task)) { // clear any cruft out of upper 32-bits for 32-bit tasks
		useraddr &= 0x00000000FFFFFFFFULL;
	}

    if(current_task()==task) {    
		thread_t      cur_thr = current_thread();
		vm_offset_t   recover_handler = cur_thr->recover; 
					
		if(ml_at_interrupt_context()) {
			return KERN_FAILURE; // can't do copyout on interrupt stack
		}
	
		if(copyout(kernaddr, useraddr, size)) {
			ret = KERN_FAILURE;
		}
		cur_thr->recover = recover_handler;
    } else {
		vm_map_t map = get_task_map(task);
		ret = vm_map_write_user(map, kernaddr, useraddr, size);
    }		
    
    return ret;
}

__private_extern__
kern_return_t chudxnu_kern_read(void *dstaddr, vm_offset_t srcaddr, vm_size_t size)
{
    while(size>0) {
		ppnum_t pp;
		addr64_t phys_addr;    
		
		pp = pmap_find_phys(kernel_pmap, srcaddr);			/* Get the page number */
		if(!pp) {
			return KERN_FAILURE;					/* Not mapped... */
		}
		
		phys_addr = ((addr64_t)pp << 12) | (srcaddr & 0x0000000000000FFFULL);	/* Shove in the page offset */
		if(phys_addr >= mem_actual) {
			return KERN_FAILURE;					/* out of range */
		}
		
		if((phys_addr&0x1) || size==1) {
			*((uint8_t *)dstaddr) = ml_phys_read_byte_64(phys_addr);
			((uint8_t *)dstaddr)++;
			srcaddr += sizeof(uint8_t);
			size -= sizeof(uint8_t);
		} else if((phys_addr&0x3) || size<=2) {
			*((uint16_t *)dstaddr) = ml_phys_read_half_64(phys_addr);
			((uint16_t *)dstaddr)++;
			srcaddr += sizeof(uint16_t);
			size -= sizeof(uint16_t);
		} else {
			*((uint32_t *)dstaddr) = ml_phys_read_word_64(phys_addr);
			((uint32_t *)dstaddr)++;
			srcaddr += sizeof(uint32_t);
			size -= sizeof(uint32_t);
		}
    }
    return KERN_SUCCESS;
}

__private_extern__
kern_return_t chudxnu_kern_write(vm_offset_t dstaddr, void *srcaddr, vm_size_t size)
{
    while(size>0) {
		ppnum_t pp;
		addr64_t phys_addr;    
		
		pp = pmap_find_phys(kernel_pmap, dstaddr);			/* Get the page number */
		if(!pp) {
			return KERN_FAILURE;					/* Not mapped... */
		}
		
		phys_addr = ((addr64_t)pp << 12) | (dstaddr & 0x0000000000000FFFULL);	/* Shove in the page offset */
		if(phys_addr >= mem_actual) {
			return KERN_FAILURE;					/* out of range */
		}
		
		if((phys_addr&0x1) || size==1) {
			ml_phys_write_byte_64(phys_addr, *((uint8_t *)srcaddr));
			((uint8_t *)srcaddr)++;
			dstaddr += sizeof(uint8_t);
			size -= sizeof(uint8_t);
		} else if((phys_addr&0x3) || size<=2) {
			ml_phys_write_half_64(phys_addr, *((uint16_t *)srcaddr));
			((uint16_t *)srcaddr)++;
			dstaddr += sizeof(uint16_t);
			size -= sizeof(uint16_t);
		} else {
			ml_phys_write_word_64(phys_addr, *((uint32_t *)srcaddr));
			((uint32_t *)srcaddr)++;
			dstaddr += sizeof(uint32_t);
			size -= sizeof(uint32_t);
		}
    }
    
    return KERN_SUCCESS;
}

// chudxnu_thread_get_callstack gathers a raw callstack along with any information needed to
// fix it up later (in case we stopped program as it was saving values into prev stack frame, etc.)
// after sampling has finished.
//
// For an N-entry callstack:
//
// [0]      current pc
// [1..N-3] stack frames (including current one)
// [N-2]    current LR (return value if we're in a leaf function)
// [N-1]    current r0 (in case we've saved LR in r0)
//

#define FP_LINK_OFFSET 			2
#define STACK_ALIGNMENT_MASK	0xF // PPC stack frames are supposed to be 16-byte aligned
#define INST_ALIGNMENT_MASK		0x3 // Instructions are always 4-bytes wide

#ifndef USER_MODE
#define USER_MODE(msr) ((msr) & MASK(MSR_PR) ? TRUE : FALSE)
#endif

#ifndef SUPERVISOR_MODE
#define SUPERVISOR_MODE(msr) ((msr) & MASK(MSR_PR) ? FALSE : TRUE)
#endif

#define VALID_STACK_ADDRESS(addr)   (addr>=0x1000ULL &&			 \
				     (addr&STACK_ALIGNMENT_MASK)==0x0 && \
				     (supervisor ?			 \
					 (addr>=kernStackMin &&		 \
					  addr<=kernStackMax) :		 \
					 TRUE))


__private_extern__
kern_return_t chudxnu_thread_get_callstack64(	thread_t thread,
						uint64_t *callStack,
						mach_msg_type_number_t *count,
						boolean_t user_only)
{
    kern_return_t kr;
    task_t task = get_threadtask(thread);
    uint64_t nextFramePointer = 0;
    uint64_t currPC, currLR, currR0;
    uint64_t framePointer;
    uint64_t prevPC = 0;
    uint64_t kernStackMin = min_valid_stack_address();
    uint64_t kernStackMax = max_valid_stack_address();
    uint64_t *buffer = callStack;
    uint32_t tmpWord;
    int bufferIndex = 0;
    int bufferMaxIndex = *count;
    boolean_t supervisor;
    boolean_t is64Bit;
    struct savearea *sv;

    if(user_only) {
        sv = find_user_regs(thread);
    } else {
        sv = find_kern_regs(thread);
    }

    if(!sv) {
        *count = 0;
        return KERN_FAILURE;
    }

    supervisor = SUPERVISOR_MODE(sv->save_srr1);
    if(supervisor) {
#warning assuming kernel task is always 32-bit
		is64Bit = FALSE;
    } else {
		is64Bit = chudxnu_is_64bit_task(task);
    }

    bufferMaxIndex = bufferMaxIndex - 2; // allot space for saving the LR and R0 on the stack at the end.
    if(bufferMaxIndex<2) {
        *count = 0;
        return KERN_RESOURCE_SHORTAGE;
    }

    currPC = sv->save_srr0;
    framePointer = sv->save_r1; /* r1 is the stack pointer (no FP on PPC)  */
    currLR = sv->save_lr;
    currR0 = sv->save_r0;

    bufferIndex = 0;  // start with a stack of size zero
    buffer[bufferIndex++] = currPC; // save PC in position 0.

    // Now, fill buffer with stack backtraces.
    while(bufferIndex<bufferMaxIndex && VALID_STACK_ADDRESS(framePointer)) {
        uint64_t pc = 0;
        // Above the stack pointer, the following values are saved:
        // saved LR
        // saved CR
        // saved SP
        //-> SP
        // Here, we'll get the lr from the stack.
        uint64_t fp_link;

		if(is64Bit) {
			fp_link = framePointer + FP_LINK_OFFSET*sizeof(uint64_t);
		} else {
			fp_link = framePointer + FP_LINK_OFFSET*sizeof(uint32_t);
		}

        // Note that we read the pc even for the first stack frame (which, in theory,
        // is always empty because the callee fills it in just before it lowers the
        // stack.  However, if we catch the program in between filling in the return
        // address and lowering the stack, we want to still have a valid backtrace.
        // FixupStack correctly disregards this value if necessary.

        if(supervisor) {
			if(is64Bit) {
				kr = chudxnu_kern_read(&pc, fp_link, sizeof(uint64_t));
			} else {
				kr = chudxnu_kern_read(&tmpWord, fp_link, sizeof(uint32_t));
				pc = tmpWord;
			}    
        } else {
			if(is64Bit) {
				kr = chudxnu_task_read(task, &pc, fp_link, sizeof(uint64_t));
			} else {
				kr = chudxnu_task_read(task, &tmpWord, fp_link, sizeof(uint32_t));
				pc = tmpWord;
	    	}
		}
        if(kr!=KERN_SUCCESS) {
            pc = 0;
            break;
        }

        // retrieve the contents of the frame pointer and advance to the next stack frame if it's valid
        if(supervisor) {
			if(is64Bit) {
				kr = chudxnu_kern_read(&nextFramePointer, framePointer, sizeof(uint64_t));
			} else {
				kr = chudxnu_kern_read(&tmpWord, framePointer, sizeof(uint32_t));
				nextFramePointer = tmpWord;
			}  
        } else {
			if(is64Bit) {
				kr = chudxnu_task_read(task, &nextFramePointer, framePointer, sizeof(uint64_t));
			} else {
				kr = chudxnu_task_read(task, &tmpWord, framePointer, sizeof(uint32_t));
				nextFramePointer = tmpWord;
			}
		}
        if(kr!=KERN_SUCCESS) {
            nextFramePointer = 0;
        }

        if(nextFramePointer) {
            buffer[bufferIndex++] = pc;
            prevPC = pc;
        }
    
        if(nextFramePointer<framePointer) {
            break;
        } else {
	    	framePointer = nextFramePointer;
		}
    }

    if(bufferIndex>=bufferMaxIndex) {
        *count = 0;
        return KERN_RESOURCE_SHORTAGE;
    }

    // Save link register and R0 at bottom of stack (used for later fixup).
    buffer[bufferIndex++] = currLR;
    buffer[bufferIndex++] = currR0;

    *count = bufferIndex;
    return KERN_SUCCESS;
}

__private_extern__
kern_return_t chudxnu_thread_get_callstack( thread_t thread, 
					    uint32_t *callStack,
					    mach_msg_type_number_t *count,
					    boolean_t user_only)
{
    kern_return_t kr;
    task_t task = get_threadtask(thread);
    uint64_t nextFramePointer = 0;
    uint64_t currPC, currLR, currR0;
    uint64_t framePointer;
    uint64_t prevPC = 0;
    uint64_t kernStackMin = min_valid_stack_address();
    uint64_t kernStackMax = max_valid_stack_address();
    uint32_t *buffer = callStack;
    uint32_t tmpWord;
    int bufferIndex = 0;
    int bufferMaxIndex = *count;
    boolean_t supervisor;
    boolean_t is64Bit;
    struct savearea *sv;

    if(user_only) {
        sv = find_user_regs(thread);
    } else {
        sv = find_kern_regs(thread);
    }

    if(!sv) {
        *count = 0;
        return KERN_FAILURE;
    }

    supervisor = SUPERVISOR_MODE(sv->save_srr1);
    if(supervisor) {
#warning assuming kernel task is always 32-bit
		is64Bit = FALSE;
    } else {
		is64Bit = chudxnu_is_64bit_task(task);
    }

    bufferMaxIndex = bufferMaxIndex - 2; // allot space for saving the LR and R0 on the stack at the end.
    if(bufferMaxIndex<2) {
        *count = 0;
        return KERN_RESOURCE_SHORTAGE;
    }

    currPC = sv->save_srr0;
    framePointer = sv->save_r1; /* r1 is the stack pointer (no FP on PPC)  */
    currLR = sv->save_lr;
    currR0 = sv->save_r0;

    bufferIndex = 0;  // start with a stack of size zero
    buffer[bufferIndex++] = currPC; // save PC in position 0.

    // Now, fill buffer with stack backtraces.
    while(bufferIndex<bufferMaxIndex && VALID_STACK_ADDRESS(framePointer)) {
        uint64_t pc = 0;
        // Above the stack pointer, the following values are saved:
        // saved LR
        // saved CR
        // saved SP
        //-> SP
        // Here, we'll get the lr from the stack.
        uint64_t fp_link;

		if(is64Bit) {
			fp_link = framePointer + FP_LINK_OFFSET*sizeof(uint64_t);
		} else {
			fp_link = framePointer + FP_LINK_OFFSET*sizeof(uint32_t);
		}

        // Note that we read the pc even for the first stack frame (which, in theory,
        // is always empty because the callee fills it in just before it lowers the
        // stack.  However, if we catch the program in between filling in the return
        // address and lowering the stack, we want to still have a valid backtrace.
        // FixupStack correctly disregards this value if necessary.

        if(supervisor) {
			if(is64Bit) {
				kr = chudxnu_kern_read(&pc, fp_link, sizeof(uint64_t));
			} else {
				kr = chudxnu_kern_read(&tmpWord, fp_link, sizeof(uint32_t));
				pc = tmpWord;
			}    
        } else {
			if(is64Bit) {
				kr = chudxnu_task_read(task, &pc, fp_link, sizeof(uint64_t));
			} else {
				kr = chudxnu_task_read(task, &tmpWord, fp_link, sizeof(uint32_t));
				pc = tmpWord;
			}
        }
        if(kr!=KERN_SUCCESS) {
            pc = 0;
            break;
        }

        // retrieve the contents of the frame pointer and advance to the next stack frame if it's valid
        if(supervisor) {
			if(is64Bit) {
				kr = chudxnu_kern_read(&nextFramePointer, framePointer, sizeof(uint64_t));
			} else {
				kr = chudxnu_kern_read(&tmpWord, framePointer, sizeof(uint32_t));
				nextFramePointer = tmpWord;
			}  
        } else {
			if(is64Bit) {
				kr = chudxnu_task_read(task, &nextFramePointer, framePointer, sizeof(uint64_t));
			} else {
				kr = chudxnu_task_read(task, &tmpWord, framePointer, sizeof(uint32_t));
				nextFramePointer = tmpWord;
			}
        }
        if(kr!=KERN_SUCCESS) {
            nextFramePointer = 0;
        }

        if(nextFramePointer) {
            buffer[bufferIndex++] = pc;
            prevPC = pc;
        }
    
        if(nextFramePointer<framePointer) {
            break;
        } else {
	    	framePointer = nextFramePointer;
		}
    }

    if(bufferIndex>=bufferMaxIndex) {
        *count = 0;
        return KERN_RESOURCE_SHORTAGE;
    }

    // Save link register and R0 at bottom of stack (used for later fixup).
    buffer[bufferIndex++] = currLR;
    buffer[bufferIndex++] = currR0;

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
kern_return_t chudxnu_current_thread_get_callstack(	uint32_t *callStack,
													mach_msg_type_number_t *count,
													boolean_t user_only)
{
	return chudxnu_thread_get_callstack(current_thread(), callStack, count, user_only);
}

// DEPRECATED
__private_extern__
thread_t chudxnu_current_act(void)
{
	return chudxnu_current_thread();
}
