/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
 */

#include <stdint.h>
#include <mach/boolean.h>
#include <mach/mach_types.h>

#include <ppc/machine_routines.h>
#include <ppc/exception.h>
#include <kern/ast.h>
#include <kern/timer_call.h>
#include <kern/kern_types.h>

extern kern_return_t chud_copy_savearea_to_threadstate(thread_flavor_t flavor, thread_state_t tstate, mach_msg_type_number_t *count, struct savearea *sv);
extern kern_return_t chud_copy_threadstate_to_savearea(struct savearea *sv, thread_flavor_t flavor, thread_state_t tstate, mach_msg_type_number_t *count);

__private_extern__
void chudxnu_cancel_all_callbacks(void)
{
    extern void chudxnu_exit_callback_cancel(void);
    extern void chudxnu_thread_timer_callback_cancel(void);

    chudxnu_cpu_timer_callback_cancel_all();
    chudxnu_trap_callback_cancel();
    chudxnu_interrupt_callback_cancel();
    chudxnu_perfmon_ast_callback_cancel();
    chudxnu_cpusig_callback_cancel();
    chudxnu_kdebug_callback_cancel();
    chudxnu_exit_callback_cancel();
    chudxnu_thread_timer_callback_cancel();
}

#pragma mark **** cpu timer ****
static timer_call_data_t cpu_timer_call[NCPUS] = {{0}, {0}};
static uint64_t t_deadline[NCPUS] = {0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL};

typedef void (*chudxnu_cpu_timer_callback_func_t)(thread_flavor_t flavor, thread_state_t tstate,  mach_msg_type_number_t count);
static chudxnu_cpu_timer_callback_func_t cpu_timer_callback_fn[NCPUS] = {NULL, NULL};

static void chudxnu_private_cpu_timer_callback(timer_call_param_t param0, timer_call_param_t param1)
{
    int cpu;
    boolean_t oldlevel;
    struct ppc_thread_state64 state;
    mach_msg_type_number_t count;

    oldlevel = ml_set_interrupts_enabled(FALSE);
    cpu = cpu_number();

    count = PPC_THREAD_STATE64_COUNT;
    if(chudxnu_thread_get_state(current_act(), PPC_THREAD_STATE64, (thread_state_t)&state, &count, FALSE)==KERN_SUCCESS) {
        if(cpu_timer_callback_fn[cpu]) {
            (cpu_timer_callback_fn[cpu])(PPC_THREAD_STATE64, (thread_state_t)&state, count);
        }
    }

    ml_set_interrupts_enabled(oldlevel);
}

__private_extern__
kern_return_t chudxnu_cpu_timer_callback_enter(chudxnu_cpu_timer_callback_func_t func, uint32_t time, uint32_t units)
{
    int cpu;
    boolean_t oldlevel;

    oldlevel = ml_set_interrupts_enabled(FALSE);
    cpu = cpu_number();

    timer_call_cancel(&(cpu_timer_call[cpu])); // cancel any existing callback for this cpu

    cpu_timer_callback_fn[cpu] = func;

    clock_interval_to_deadline(time, units, &(t_deadline[cpu]));
    timer_call_setup(&(cpu_timer_call[cpu]), chudxnu_private_cpu_timer_callback, NULL);
    timer_call_enter(&(cpu_timer_call[cpu]), t_deadline[cpu]);

    ml_set_interrupts_enabled(oldlevel);
    return KERN_SUCCESS;
}

__private_extern__
kern_return_t chudxnu_cpu_timer_callback_cancel(void)
{
    int cpu;
    boolean_t oldlevel;

    oldlevel = ml_set_interrupts_enabled(FALSE);
    cpu = cpu_number();

    timer_call_cancel(&(cpu_timer_call[cpu]));
    t_deadline[cpu] = t_deadline[cpu] | ~(t_deadline[cpu]); // set to max value
    cpu_timer_callback_fn[cpu] = NULL;

    ml_set_interrupts_enabled(oldlevel);
    return KERN_SUCCESS;
}

__private_extern__
kern_return_t chudxnu_cpu_timer_callback_cancel_all(void)
{
    int cpu;

    for(cpu=0; cpu<NCPUS; cpu++) {
        timer_call_cancel(&(cpu_timer_call[cpu]));
        t_deadline[cpu] = t_deadline[cpu] | ~(t_deadline[cpu]); // set to max value
        cpu_timer_callback_fn[cpu] = NULL;
    }
    return KERN_SUCCESS;
}

#pragma mark **** trap and ast ****
typedef kern_return_t (*chudxnu_trap_callback_func_t)(uint32_t trapentry, thread_flavor_t flavor, thread_state_t tstate, mach_msg_type_number_t count);
static chudxnu_trap_callback_func_t trap_callback_fn = NULL;

typedef kern_return_t (*perfTrap)(int trapno, struct savearea *ssp, unsigned int dsisr, unsigned int dar);
extern perfTrap perfTrapHook; /* function hook into trap() */

typedef void (*chudxnu_perfmon_ast_callback_func_t)(thread_flavor_t flavor, thread_state_t tstate,  mach_msg_type_number_t count);
static chudxnu_perfmon_ast_callback_func_t perfmon_ast_callback_fn = NULL;

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
    int cpu = cpu_number();

    kern_return_t retval = KERN_FAILURE;
    uint32_t trapentry = TRAP_ENTRY_POINT(trapno);

    // ASTs from ihandler go through thandler and are made to look like traps
    if(perfmon_ast_callback_fn && (need_ast[cpu] & AST_PPC_CHUD)) {
        struct ppc_thread_state64 state;
        mach_msg_type_number_t count = PPC_THREAD_STATE64_COUNT;
        chudxnu_copy_savearea_to_threadstate(PPC_THREAD_STATE64, (thread_state_t)&state, &count, ssp);
        (perfmon_ast_callback_fn)(PPC_THREAD_STATE64, (thread_state_t)&state, count);
        need_ast[cpu] &= ~(AST_PPC_CHUD);
    }

    if(trapentry!=0x0) {
        if(trap_callback_fn) {
            struct ppc_thread_state64 state;
            mach_msg_type_number_t count = PPC_THREAD_STATE64_COUNT;
            chudxnu_copy_savearea_to_threadstate(PPC_THREAD_STATE64, (thread_state_t)&state, &count, ssp);
            retval = (trap_callback_fn)(trapentry, PPC_THREAD_STATE64, (thread_state_t)&state, count);
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
    if(!perfmon_ast_callback_fn) {
        perfTrapHook = NULL;
    }
    __asm__ volatile("eieio");	/* force order */
    __asm__ volatile("sync");	/* force to memory */
    return KERN_SUCCESS;
}

__private_extern__
kern_return_t chudxnu_perfmon_ast_callback_enter(chudxnu_perfmon_ast_callback_func_t func)
{
    perfmon_ast_callback_fn = func;
    perfTrapHook = chudxnu_private_trap_callback;
    __asm__ volatile("eieio");	/* force order */
    __asm__ volatile("sync");	/* force to memory */
    return KERN_SUCCESS;
}

__private_extern__
kern_return_t chudxnu_perfmon_ast_callback_cancel(void)
{
    perfmon_ast_callback_fn = NULL;
    if(!trap_callback_fn) {
        perfTrapHook = NULL;
    }
    __asm__ volatile("eieio");	/* force order */
    __asm__ volatile("sync");	/* force to memory */
    return KERN_SUCCESS;
}

__private_extern__
kern_return_t chudxnu_perfmon_ast_send(void)
{
    int cpu;
    boolean_t oldlevel;

    oldlevel = ml_set_interrupts_enabled(FALSE);
    cpu = cpu_number();

    need_ast[cpu] |= (AST_PPC_CHUD | AST_URGENT);

    ml_set_interrupts_enabled(oldlevel);
    return KERN_SUCCESS;
}

#pragma mark **** interrupt ****
typedef kern_return_t (*chudxnu_interrupt_callback_func_t)(uint32_t trapentry, thread_flavor_t flavor, thread_state_t tstate,  mach_msg_type_number_t count);
static chudxnu_interrupt_callback_func_t interrupt_callback_fn = NULL;

extern perfTrap perfIntHook; /* function hook into interrupt() */

static kern_return_t chudxnu_private_interrupt_callback(int trapno, struct savearea *ssp, unsigned int dsisr, unsigned int dar)
{
    if(interrupt_callback_fn) {
        struct ppc_thread_state64 state;
        mach_msg_type_number_t count = PPC_THREAD_STATE64_COUNT;
        chudxnu_copy_savearea_to_threadstate(PPC_THREAD_STATE64, (thread_state_t)&state, &count, ssp);
        return (interrupt_callback_fn)(TRAP_ENTRY_POINT(trapno), PPC_THREAD_STATE64, (thread_state_t)&state, count);
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
typedef kern_return_t (*chudxnu_cpusig_callback_func_t)(int request, thread_flavor_t flavor, thread_state_t tstate, mach_msg_type_number_t count);
static chudxnu_cpusig_callback_func_t cpusig_callback_fn = NULL;

extern perfTrap perfCpuSigHook; /* function hook into cpu_signal_handler() */

static kern_return_t chudxnu_private_cpu_signal_handler(int request, struct savearea *ssp, unsigned int arg0, unsigned int arg1)
{
    if(cpusig_callback_fn) {
        struct ppc_thread_state64 state;
        mach_msg_type_number_t count = PPC_THREAD_STATE64_COUNT;
        chudxnu_copy_savearea_to_threadstate(PPC_THREAD_STATE64, (thread_state_t)&state, &count, ssp);
        (cpusig_callback_fn)(request, PPC_THREAD_STATE64, (thread_state_t)&state, count);
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

#pragma mark **** thread timer ****

static thread_call_t thread_timer_call = NULL;

typedef void (*chudxnu_thread_timer_callback_func_t)(uint32_t arg);
static chudxnu_thread_timer_callback_func_t thread_timer_callback_fn = NULL;

static void chudxnu_private_thread_timer_callback(thread_call_param_t param0, thread_call_param_t param1)
{
    if(thread_timer_call) {
        thread_call_free(thread_timer_call);
        thread_timer_call = NULL;

        if(thread_timer_callback_fn) {
            (thread_timer_callback_fn)((uint32_t)param0);
        }
    }
}

__private_extern__
kern_return_t chudxnu_thread_timer_callback_enter(chudxnu_thread_timer_callback_func_t func, uint32_t arg, uint32_t time, uint32_t units)
{
    if(!thread_timer_call) {
        uint64_t t_delay;
        thread_timer_callback_fn = func;
        thread_timer_call = thread_call_allocate((thread_call_func_t)chudxnu_private_thread_timer_callback, (thread_call_param_t)arg);
        clock_interval_to_deadline(time, units, &t_delay);
        thread_call_enter_delayed(thread_timer_call, t_delay);
        return KERN_SUCCESS;
    } else {
        return KERN_FAILURE; // thread timer call already pending
    }
}

__private_extern__
kern_return_t chudxnu_thread_timer_callback_cancel(void)
{
    if(thread_timer_call) {
        thread_call_free(thread_timer_call);
        thread_timer_call = NULL;
    }
    thread_timer_callback_fn = NULL;
    return KERN_SUCCESS;
}
