/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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

#include <ppc/chud/chud_xnu.h>
#include <kern/processor.h>
#include <kern/thread.h>
#include <kern/thread_act.h>
#include <kern/ipc_tt.h>
#include <ppc/proc_reg.h>
#include <ppc/machine_routines.h>

__private_extern__
kern_return_t chudxnu_bind_current_thread(int cpu)
{
    if(cpu>=0 && cpu<chudxnu_avail_cpu_count()) { /* make sure cpu # is sane */
        thread_bind(current_thread(), processor_ptr[cpu]);
        thread_block((void (*)(void)) 0);
        return KERN_SUCCESS;
    } else {
        return KERN_FAILURE;
    }
}

__private_extern__
kern_return_t chudxnu_unbind_current_thread(void)
{
    thread_bind(current_thread(), PROCESSOR_NULL);
    return KERN_SUCCESS;
}

static savearea *chudxnu_private_get_regs(void)
{
    return current_act()->mact.pcb; // take the top savearea (user or kernel)
}

static savearea *chudxnu_private_get_user_regs(void)
{
    return find_user_regs(current_act()); // take the top user savearea (skip any kernel saveareas)
}

static savearea_fpu *chudxnu_private_get_fp_regs(void)
{
    fpu_save(current_act()->mact.curctx); // just in case it's live, save it
    return current_act()->mact.curctx->FPUsave; // take the top savearea (user or kernel)
}

static savearea_fpu *chudxnu_private_get_user_fp_regs(void)
{
    return find_user_fpu(current_act()); // take the top user savearea (skip any kernel saveareas)
}

static savearea_vec *chudxnu_private_get_vec_regs(void)
{
    vec_save(current_act()->mact.curctx); // just in case it's live, save it
    return current_act()->mact.curctx->VMXsave; // take the top savearea (user or kernel)
}

static savearea_vec *chudxnu_private_get_user_vec_regs(void)
{
    return find_user_vec(current_act()); // take the top user savearea (skip any kernel saveareas)
}

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
        } else {
            return KERN_FAILURE;
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
        } else {
            return KERN_FAILURE;
        }
    }
}

__private_extern__
kern_return_t chudxnu_thread_get_state(thread_act_t thr_act, 
									thread_flavor_t flavor,
                                    thread_state_t tstate,
                                    mach_msg_type_number_t *count,
                                    boolean_t user_only)
{
	if(thr_act==current_act()) {
		if(flavor==PPC_THREAD_STATE || flavor==PPC_THREAD_STATE64) {
			struct savearea *sv;
			if(user_only) {
				sv = chudxnu_private_get_user_regs();
			} else {
				sv = chudxnu_private_get_regs();
			}
			return chudxnu_copy_savearea_to_threadstate(flavor, tstate, count, sv);
		} else if(flavor==PPC_FLOAT_STATE && user_only) {
#warning chudxnu_thread_get_state() does not yet support supervisor FP
			return machine_thread_get_state(current_act(), flavor, tstate, count);
		} else if(flavor==PPC_VECTOR_STATE && user_only) {
#warning chudxnu_thread_get_state() does not yet support supervisor VMX
			return machine_thread_get_state(current_act(), flavor, tstate, count);
		} else {
			*count = 0;
			return KERN_INVALID_ARGUMENT;
		}
	} else {
		return machine_thread_get_state(thr_act, flavor, tstate, count);
	}
}

__private_extern__
kern_return_t chudxnu_thread_set_state(thread_act_t thr_act, 
									thread_flavor_t flavor,
                                    thread_state_t tstate,
                                    mach_msg_type_number_t count,
                                    boolean_t user_only)
{
	if(thr_act==current_act()) {
		if(flavor==PPC_THREAD_STATE || flavor==PPC_THREAD_STATE64) {
			struct savearea *sv;
			if(user_only) {
				sv = chudxnu_private_get_user_regs();
			} else {
				sv = chudxnu_private_get_regs();
			}
			return chudxnu_copy_threadstate_to_savearea(sv, flavor, tstate, &count);
		} else if(flavor==PPC_FLOAT_STATE && user_only) {
#warning chudxnu_thread_set_state() does not yet support supervisor FP
			return machine_thread_set_state(current_act(), flavor, tstate, count);
		} else if(flavor==PPC_VECTOR_STATE && user_only) {
#warning chudxnu_thread_set_state() does not yet support supervisor VMX
			return machine_thread_set_state(current_act(), flavor, tstate, count);
		} else {
			return KERN_INVALID_ARGUMENT;
		}
	} else {
		return machine_thread_set_state(thr_act, flavor, tstate, count);
	}
}

static inline kern_return_t chudxnu_private_task_read_bytes(task_t task, vm_offset_t addr, int size, void *data)
{
    
    kern_return_t ret;
    
    if(task==kernel_task) {
        if(size==sizeof(unsigned int)) {
            addr64_t phys_addr;
            ppnum_t pp;

			pp = pmap_find_phys(kernel_pmap, addr);			/* Get the page number */
			if(!pp) return KERN_FAILURE;					/* Not mapped... */
			
			phys_addr = ((addr64_t)pp << 12) | (addr & 0x0000000000000FFFULL);	/* Shove in the page offset */
			
            if(phys_addr < mem_actual) {					/* Sanity check: is it in memory? */
                *((uint32_t *)data) = ml_phys_read_64(phys_addr);
                return KERN_SUCCESS;
            }
        } else {
            return KERN_FAILURE;
        }
    } else {
        
		ret = KERN_SUCCESS;									/* Assume everything worked */
		if(copyin((void *)addr, data, size)) ret = KERN_FAILURE;	/* Get memory, if non-zero rc, it didn't work */
		return ret;
    }
}

// chudxnu_current_thread_get_callstack gathers a raw callstack along with any information needed to
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

#define VALID_STACK_ADDRESS(addr)	(addr>=0x1000 && (addr&STACK_ALIGNMENT_MASK)==0x0 && (supervisor ? (addr>=kernStackMin && addr<=kernStackMax) : TRUE))

__private_extern__
kern_return_t chudxnu_current_thread_get_callstack(uint32_t *callStack,
                                                   mach_msg_type_number_t *count,
                                                   boolean_t user_only)
{
    kern_return_t kr;
    vm_address_t nextFramePointer = 0;
    vm_address_t currPC, currLR, currR0;
    vm_address_t framePointer;
    vm_address_t prevPC = 0;
    vm_address_t kernStackMin = min_valid_stack_address();
    vm_address_t kernStackMax = max_valid_stack_address();
    unsigned int *buffer = callStack;
    int bufferIndex = 0;
    int bufferMaxIndex = *count;
    boolean_t supervisor;
    struct savearea *sv;

    if(user_only) {
        sv = chudxnu_private_get_user_regs();
    } else {
        sv = chudxnu_private_get_regs();
    }

    if(!sv) {
        *count = 0;
        return KERN_FAILURE;
    }

    supervisor = SUPERVISOR_MODE(sv->save_srr1);

    if(!supervisor && ml_at_interrupt_context()) { // can't do copyin() if on interrupt stack
        *count = 0;
        return KERN_FAILURE;
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
        vm_address_t pc = 0;
        // Above the stack pointer, the following values are saved:
        // saved LR
        // saved CR
        // saved SP
        //-> SP
        // Here, we'll get the lr from the stack.
        volatile vm_address_t fp_link = (vm_address_t)(((unsigned *)framePointer)+FP_LINK_OFFSET);

        // Note that we read the pc even for the first stack frame (which, in theory,
        // is always empty because the callee fills it in just before it lowers the
        // stack.  However, if we catch the program in between filling in the return
        // address and lowering the stack, we want to still have a valid backtrace.
        // FixupStack correctly disregards this value if necessary.

        if(supervisor) {
            kr = chudxnu_private_task_read_bytes(kernel_task, fp_link, sizeof(unsigned int), &pc);
        } else {
            kr = chudxnu_private_task_read_bytes(current_task(), fp_link, sizeof(unsigned int), &pc);
        }
        if(kr!=KERN_SUCCESS) {
            //        IOLog("task_read_callstack: unable to read framePointer: %08x\n",framePointer);
            pc = 0;
            break;
        }

        // retrieve the contents of the frame pointer and advance to the next stack frame if it's valid

        if(supervisor) {
            kr = chudxnu_private_task_read_bytes(kernel_task, framePointer, sizeof(unsigned int), &nextFramePointer);
        } else {
            kr = chudxnu_private_task_read_bytes(current_task(), framePointer, sizeof(unsigned int), &nextFramePointer);
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

    // Save link register and R0 at bottom of stack.  This means that we won't worry
    // about these values messing up stack compression.  These end up being used
    // by FixupStack.
    buffer[bufferIndex++] = currLR;
    buffer[bufferIndex++] = currR0;

    *count = bufferIndex;
    return KERN_SUCCESS;
}

__private_extern__
int chudxnu_task_threads(task_t task,
			 			thread_act_array_t *thr_act_list,
			 			mach_msg_type_number_t *count)
{
    mach_msg_type_number_t task_thread_count = 0;
    kern_return_t kr;

    kr = task_threads(current_task(), thr_act_list, count);
    if(kr==KERN_SUCCESS) {
        thread_act_t thr_act;
        int i, state_count;
        for(i=0; i<(*count); i++) {
            thr_act = convert_port_to_act(((ipc_port_t *)(*thr_act_list))[i]);
	    	/* undo the mig conversion task_threads does */
	   	 	thr_act_list[i] = thr_act;
		}
    }
    return kr;
}

__private_extern__
thread_act_t chudxnu_current_act(void)
{
	return current_act();
}

__private_extern__
task_t chudxnu_current_task(void)
{
	return current_task();
}

__private_extern__
kern_return_t chudxnu_thread_info(thread_act_t thr_act,
        						thread_flavor_t flavor,
        						thread_info_t thread_info_out,
        						mach_msg_type_number_t *thread_info_count)
{
	return thread_info(thr_act, flavor, thread_info_out, thread_info_count);
}
