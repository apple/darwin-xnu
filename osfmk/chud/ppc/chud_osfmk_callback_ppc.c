/*
 * Copyright (c) 2003-2004 Apple Computer, Inc. All rights reserved.
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

#include <stdint.h>
#include <mach/boolean.h>
#include <mach/mach_types.h>

#include <kern/kern_types.h>
#include <kern/processor.h>
#include <kern/thread_call.h>
#include <kern/kalloc.h>
#include <kern/thread.h>

#include <ppc/machine_routines.h>
#include <ppc/cpu_data.h>
#include <ppc/cpu_internal.h>
#include <ppc/exception.h>
#include <ppc/thread.h>
#include <ppc/trap.h>

#include <chud/chud_xnu.h>
#include <chud/chud_xnu_private.h>

__private_extern__
void chudxnu_cancel_all_callbacks(void)
{
    chudxnu_cpu_timer_callback_cancel_all();
    chudxnu_trap_callback_cancel();
    chudxnu_interrupt_callback_cancel();
    chudxnu_perfmon_ast_callback_cancel();
    chudxnu_cpusig_callback_cancel();
    chudxnu_kdebug_callback_cancel();
    chudxnu_thread_timer_callback_cancel();
	chudxnu_syscall_callback_cancel();
}

static chudcpu_data_t chudcpu_boot_cpu;

void *chudxnu_per_proc_alloc(boolean_t boot_processor)
{
	chudcpu_data_t	*chud_proc_info;

	if (boot_processor) {
		chud_proc_info = &chudcpu_boot_cpu;
	} else {
		chud_proc_info = (chudcpu_data_t *)kalloc(sizeof(chudcpu_data_t));
		if (chud_proc_info == (chudcpu_data_t *)NULL) {
			return (void *)NULL;
		}
	}
	bzero((char *)chud_proc_info, sizeof(chudcpu_data_t));
	chud_proc_info->t_deadline = 0xFFFFFFFFFFFFFFFFULL;
	return (void *)chud_proc_info;
}

void chudxnu_per_proc_free(void *per_proc_chud)
{
	if (per_proc_chud == (void *)&chudcpu_boot_cpu) {
		return;
	} else {
		kfree(per_proc_chud,sizeof(chudcpu_data_t));
	}
}

static void chudxnu_private_cpu_timer_callback(timer_call_param_t param0, timer_call_param_t param1)
{
    chudcpu_data_t	*chud_proc_info;
    boolean_t oldlevel;
    struct ppc_thread_state64 state;
    mach_msg_type_number_t count;
    chudxnu_cpu_timer_callback_func_t fn = NULL;

    oldlevel = ml_set_interrupts_enabled(FALSE);
    chud_proc_info = (chudcpu_data_t *)(getPerProc()->pp_chud);

    count = PPC_THREAD_STATE64_COUNT;
    if(chudxnu_thread_get_state(current_thread(), PPC_THREAD_STATE64, (thread_state_t)&state, &count, FALSE)==KERN_SUCCESS) {
        fn = chud_proc_info->cpu_timer_callback_fn;
        if(fn) {
            (fn)(PPC_THREAD_STATE64, (thread_state_t)&state, count);
        }
    }

    ml_set_interrupts_enabled(oldlevel);
}

__private_extern__
kern_return_t chudxnu_cpu_timer_callback_enter(chudxnu_cpu_timer_callback_func_t func, uint32_t time, uint32_t units)
{
    chudcpu_data_t	*chud_proc_info;
    boolean_t oldlevel;

    oldlevel = ml_set_interrupts_enabled(FALSE);
    chud_proc_info = (chudcpu_data_t *)(getPerProc()->pp_chud);

    timer_call_cancel(&(chud_proc_info->cpu_timer_call)); // cancel any existing callback for this cpu

    chud_proc_info->cpu_timer_callback_fn = func;

    clock_interval_to_deadline(time, units, &(chud_proc_info->t_deadline));
    timer_call_setup(&(chud_proc_info->cpu_timer_call), chudxnu_private_cpu_timer_callback, NULL);
    timer_call_enter(&(chud_proc_info->cpu_timer_call), chud_proc_info->t_deadline);

    ml_set_interrupts_enabled(oldlevel);
    return KERN_SUCCESS;
}

__private_extern__
kern_return_t chudxnu_cpu_timer_callback_cancel(void)
{
    chudcpu_data_t	*chud_proc_info;
    boolean_t oldlevel;

    oldlevel = ml_set_interrupts_enabled(FALSE);
    chud_proc_info = (chudcpu_data_t *)(getPerProc()->pp_chud);

    timer_call_cancel(&(chud_proc_info->cpu_timer_call));
    chud_proc_info->t_deadline = chud_proc_info->t_deadline | ~(chud_proc_info->t_deadline); // set to max value
    chud_proc_info->cpu_timer_callback_fn = NULL;

    ml_set_interrupts_enabled(oldlevel);
    return KERN_SUCCESS;
}

__private_extern__
kern_return_t chudxnu_cpu_timer_callback_cancel_all(void)
{
    unsigned int cpu;
    chudcpu_data_t	*chud_proc_info;

    for(cpu=0; cpu<real_ncpus; cpu++) {
    	if ((PerProcTable[cpu].ppe_vaddr == 0)
    	    || (PerProcTable[cpu].ppe_vaddr->pp_chud == 0))
			continue;
    	chud_proc_info = (chudcpu_data_t *)PerProcTable[cpu].ppe_vaddr->pp_chud;
        timer_call_cancel(&(chud_proc_info->cpu_timer_call));
        chud_proc_info->t_deadline = chud_proc_info->t_deadline | ~(chud_proc_info->t_deadline); // set to max value
        chud_proc_info->cpu_timer_callback_fn = NULL;
    }
    return KERN_SUCCESS;
}

#pragma mark **** trap ****
static chudxnu_trap_callback_func_t trap_callback_fn = NULL;

#define TRAP_ENTRY_POINT(t) ((t==T_RESET) ? 0x100 : \
                             (t==T_MACHINE_CHECK) ? 0x200 : \
                             (t==T_DATA_ACCESS) ? 0x300 : \
                             (t==T_DATA_SEGMENT) ? 0x380 : \
                             (t==T_INSTRUCTION_ACCESS) ? 0x400 : \
                             (t==T_INSTRUCTION_SEGMENT) ? 0x480 : \
                             (t==T_INTERRUPT) ? 0x500 : \
                             (t==T_ALIGNMENT) ? 0x600 : \
                             (t==T_PROGRAM) ? 0x700 : \
                             (t==T_FP_UNAVAILABLE) ? 0x800 : \
                             (t==T_DECREMENTER) ? 0x900 : \
                             (t==T_IO_ERROR) ? 0xa00 : \
                             (t==T_RESERVED) ? 0xb00 : \
                             (t==T_SYSTEM_CALL) ? 0xc00 : \
                             (t==T_TRACE) ? 0xd00 : \
                             (t==T_FP_ASSIST) ? 0xe00 : \
                             (t==T_PERF_MON) ? 0xf00 : \
                             (t==T_VMX) ? 0xf20 : \
                             (t==T_INVALID_EXCP0) ? 0x1000 : \
                             (t==T_INVALID_EXCP1) ? 0x1100 : \
                             (t==T_INVALID_EXCP2) ? 0x1200 : \
                             (t==T_INSTRUCTION_BKPT) ? 0x1300 : \
                             (t==T_SYSTEM_MANAGEMENT) ? 0x1400 : \
                             (t==T_SOFT_PATCH) ? 0x1500 : \
                             (t==T_ALTIVEC_ASSIST) ? 0x1600 : \
                             (t==T_THERMAL) ? 0x1700 : \
                             (t==T_ARCHDEP0) ? 0x1800 : \
                             (t==T_INSTRUMENTATION) ? 0x2000 : \
                             0x0)

static kern_return_t chudxnu_private_trap_callback(int trapno, struct savearea *ssp, unsigned int dsisr, unsigned int dar)
{
    boolean_t oldlevel = ml_set_interrupts_enabled(FALSE);
    kern_return_t retval = KERN_FAILURE;
    uint32_t trapentry = TRAP_ENTRY_POINT(trapno);
    chudxnu_trap_callback_func_t fn = trap_callback_fn;

    if(trapentry!=0x0) {
        if(fn) {
            struct ppc_thread_state64 state;
            mach_msg_type_number_t count = PPC_THREAD_STATE64_COUNT;
            chudxnu_copy_savearea_to_threadstate(PPC_THREAD_STATE64, (thread_state_t)&state, &count, ssp);
            retval = (fn)(trapentry, PPC_THREAD_STATE64, (thread_state_t)&state, count);
        }
    }

    ml_set_interrupts_enabled(oldlevel);

    return retval;
}

__private_extern__
kern_return_t chudxnu_trap_callback_enter(chudxnu_trap_callback_func_t func)
{
    trap_callback_fn = func;
    perfTrapHook = chudxnu_private_trap_callback;
    __asm__ volatile("eieio");	/* force order */
    __asm__ volatile("sync");	/* force to memory */
    return KERN_SUCCESS;
}

__private_extern__
kern_return_t chudxnu_trap_callback_cancel(void)
{
    trap_callback_fn = NULL;
        perfTrapHook = NULL;
    __asm__ volatile("eieio");	/* force order */
    __asm__ volatile("sync");	/* force to memory */
    return KERN_SUCCESS;
}

#pragma mark **** ast ****
static chudxnu_perfmon_ast_callback_func_t perfmon_ast_callback_fn = NULL;

static kern_return_t chudxnu_private_chud_ast_callback(int trapno, struct savearea *ssp, unsigned int dsisr, unsigned int dar)
{
    boolean_t oldlevel = ml_set_interrupts_enabled(FALSE);
    ast_t *myast = ast_pending();
    kern_return_t retval = KERN_FAILURE;
    chudxnu_perfmon_ast_callback_func_t fn = perfmon_ast_callback_fn;
    
	if(*myast & AST_CHUD_URGENT) {
		*myast &= ~(AST_CHUD_URGENT | AST_CHUD);
		if((*myast & AST_PREEMPTION) != AST_PREEMPTION) *myast &= ~(AST_URGENT);
		retval = KERN_SUCCESS;
	} else if(*myast & AST_CHUD) {
		*myast &= ~(AST_CHUD);
		retval = KERN_SUCCESS;
	}

    if(fn) {
		struct ppc_thread_state64 state;
		mach_msg_type_number_t count;
		count = PPC_THREAD_STATE64_COUNT;
		
		if(chudxnu_thread_get_state(current_thread(), PPC_THREAD_STATE64, (thread_state_t)&state, &count, FALSE)==KERN_SUCCESS) {
			(fn)(PPC_THREAD_STATE64, (thread_state_t)&state, count);
		}
    }
    
#if 0
    // ASTs from ihandler go through thandler and are made to look like traps
    // always handle AST_CHUD_URGENT if there's a callback
    // only handle AST_CHUD if it's the only AST pending
    if(perfmon_ast_callback_fn && ((*myast & AST_CHUD_URGENT) || ((*myast & AST_CHUD) && !(*myast & AST_URGENT)))) {
        struct ppc_thread_state64 state;
        mach_msg_type_number_t count = PPC_THREAD_STATE64_COUNT;
        chudxnu_copy_savearea_to_threadstate(PPC_THREAD_STATE64, (thread_state_t)&state, &count, ssp);
        if(*myast & AST_CHUD_URGENT) {
            *myast &= ~(AST_CHUD_URGENT | AST_CHUD);
            if((*myast & AST_PREEMPTION) != AST_PREEMPTION) *myast &= ~(AST_URGENT);
			retval = KERN_SUCCESS;
        } else if(*myast & AST_CHUD) {
            *myast &= ~(AST_CHUD);
			retval = KERN_SUCCESS;
        }
        (perfmon_ast_callback_fn)(PPC_THREAD_STATE64, (thread_state_t)&state, count);
    }
#endif

    ml_set_interrupts_enabled(oldlevel);
	return retval;
}

__private_extern__
kern_return_t chudxnu_perfmon_ast_callback_enter(chudxnu_perfmon_ast_callback_func_t func)
{
    perfmon_ast_callback_fn = func;
    perfASTHook = chudxnu_private_chud_ast_callback;
    __asm__ volatile("eieio");	/* force order */
    __asm__ volatile("sync");	/* force to memory */
    return KERN_SUCCESS;
}

__private_extern__
kern_return_t chudxnu_perfmon_ast_callback_cancel(void)
{
    perfmon_ast_callback_fn = NULL;
    perfASTHook = NULL;
    __asm__ volatile("eieio");	/* force order */
    __asm__ volatile("sync");	/* force to memory */
    return KERN_SUCCESS;
}

__private_extern__
kern_return_t chudxnu_perfmon_ast_send_urgent(boolean_t urgent)
{
    boolean_t oldlevel = ml_set_interrupts_enabled(FALSE);
	ast_t *myast = ast_pending();

    if(urgent) {
        *myast |= (AST_CHUD_URGENT | AST_URGENT);
    } else {
        *myast |= (AST_CHUD);
    }

    ml_set_interrupts_enabled(oldlevel);
    return KERN_SUCCESS;
}

__private_extern__
kern_return_t chudxnu_perfmon_ast_send(void)
{
    return chudxnu_perfmon_ast_send_urgent(TRUE);
}

#pragma mark **** interrupt ****
static chudxnu_interrupt_callback_func_t interrupt_callback_fn = NULL;
//extern perfCallback perfIntHook; /* function hook into interrupt() */

static kern_return_t chudxnu_private_interrupt_callback(int trapno, struct savearea *ssp, unsigned int dsisr, unsigned int dar)
{
    chudxnu_interrupt_callback_func_t fn = interrupt_callback_fn;
    
    if(fn) {
        struct ppc_thread_state64 state;
        mach_msg_type_number_t count = PPC_THREAD_STATE64_COUNT;
        chudxnu_copy_savearea_to_threadstate(PPC_THREAD_STATE64, (thread_state_t)&state, &count, ssp);
        return (fn)(TRAP_ENTRY_POINT(trapno), PPC_THREAD_STATE64, (thread_state_t)&state, count);
    } else {
        return KERN_FAILURE;
    }
}

__private_extern__
kern_return_t chudxnu_interrupt_callback_enter(chudxnu_interrupt_callback_func_t func)
{
    interrupt_callback_fn = func;
    perfIntHook = chudxnu_private_interrupt_callback;
    __asm__ volatile("eieio");	/* force order */
    __asm__ volatile("sync");	/* force to memory */
    return KERN_SUCCESS;
}

__private_extern__
kern_return_t chudxnu_interrupt_callback_cancel(void)
{
    interrupt_callback_fn = NULL;
    perfIntHook = NULL;
    __asm__ volatile("eieio");	/* force order */
    __asm__ volatile("sync");	/* force to memory */
    return KERN_SUCCESS;
}

#pragma mark **** cpu signal ****
static chudxnu_cpusig_callback_func_t cpusig_callback_fn = NULL;
extern perfCallback perfCpuSigHook; /* function hook into cpu_signal_handler() */

static kern_return_t chudxnu_private_cpu_signal_handler(int request, struct savearea *ssp, unsigned int arg0, unsigned int arg1)
{
    chudxnu_cpusig_callback_func_t fn = cpusig_callback_fn;
    
    if(fn) {
        struct ppc_thread_state64 state;
        mach_msg_type_number_t count = PPC_THREAD_STATE64_COUNT;
        chudxnu_copy_savearea_to_threadstate(PPC_THREAD_STATE64, (thread_state_t)&state, &count, ssp);
        (fn)(request, PPC_THREAD_STATE64, (thread_state_t)&state, count);
    }
    return KERN_SUCCESS; // ignored
}

__private_extern__
kern_return_t chudxnu_cpusig_callback_enter(chudxnu_cpusig_callback_func_t func)
{
    cpusig_callback_fn = func;
    perfCpuSigHook = chudxnu_private_cpu_signal_handler;
    __asm__ volatile("eieio");	/* force order */
    __asm__ volatile("sync");	/* force to memory */
    return KERN_SUCCESS;
}

__private_extern__
kern_return_t chudxnu_cpusig_callback_cancel(void)
{
    cpusig_callback_fn = NULL;
    perfCpuSigHook = NULL;
    __asm__ volatile("eieio");	/* force order */
    __asm__ volatile("sync");	/* force to memory */
    return KERN_SUCCESS;
}

__private_extern__
kern_return_t chudxnu_cpusig_send(int otherCPU, uint32_t request)
{
    int thisCPU;
    kern_return_t retval = KERN_FAILURE;
    int retries = 0;
    boolean_t oldlevel;
    uint32_t temp[2];

    oldlevel = ml_set_interrupts_enabled(FALSE);
    thisCPU = cpu_number();

    if(thisCPU!=otherCPU) {
        temp[0] = 0xFFFFFFFF;		/* set sync flag */
        temp[1] = request;			/* set request */
        __asm__ volatile("eieio");	/* force order */
        __asm__ volatile("sync");	/* force to memory */

        do {
            retval=cpu_signal(otherCPU, SIGPcpureq, CPRQchud, (uint32_t)&temp);
        } while(retval!=KERN_SUCCESS && (retries++)<16);
    
        if(retries>=16) {
            retval = KERN_FAILURE;
        } else {
            retval = hw_cpu_sync(temp, LockTimeOut); /* wait for the other processor */
            if(!retval) {
                retval = KERN_FAILURE;
            } else {
                retval = KERN_SUCCESS;
            }
        }
    } else {
        retval = KERN_INVALID_ARGUMENT;
    }

    ml_set_interrupts_enabled(oldlevel);
    return retval;
}
