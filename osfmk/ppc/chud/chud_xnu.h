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

#ifndef _PPC_CHUD_XNU_H_
#define _PPC_CHUD_XNU_H_


#include <stdint.h>
#include <mach/boolean.h>
#include <mach/mach_types.h>

#pragma mark **** process ****
// ********************************************************************************
// process
// ********************************************************************************
int chudxnu_pid_for_task(task_t task);
task_t chudxnu_task_for_pid(int pid);
int chudxnu_current_pid(void);

#pragma mark **** thread ****
// ********************************************************************************
// thread
// ********************************************************************************
kern_return_t chudxnu_bind_current_thread(int cpu);

kern_return_t chudxnu_unbind_current_thread(void);

kern_return_t chudxnu_thread_get_state(thread_act_t thr_act, 
						thread_flavor_t flavor,
					    thread_state_t tstate,
					    mach_msg_type_number_t *count,
					    boolean_t user_only);

kern_return_t chudxnu_thread_set_state(thread_act_t thr_act, 
						thread_flavor_t flavor,
					    thread_state_t tstate,
					    mach_msg_type_number_t count,
					    boolean_t user_only);

kern_return_t chudxnu_current_thread_get_callstack(uint32_t *callStack,
						mach_msg_type_number_t *count,
						boolean_t user_only);

task_t chudxnu_current_task(void);

thread_act_t chudxnu_current_act(void);

int chudxnu_task_threads(task_t task,
			 			thread_act_array_t *thr_act_list,
			 			mach_msg_type_number_t *count);

kern_return_t chudxnu_thread_info(thread_act_t thr_act,
        				thread_flavor_t flavor,
        				thread_info_t thread_info_out,
        				mach_msg_type_number_t *thread_info_count);

#pragma mark **** memory ****
// ********************************************************************************
// memory
// ********************************************************************************

uint64_t chudxnu_avail_memory_size(void);
uint64_t chudxnu_phys_memory_size(void);

vm_offset_t chudxnu_io_map(uint64_t phys_addr, vm_size_t size);

uint32_t chudxnu_phys_addr_wimg(uint64_t phys_addr);

#pragma mark **** cpu ****
// ********************************************************************************
// cpu
// ********************************************************************************
int chudxnu_avail_cpu_count(void);
int chudxnu_phys_cpu_count(void);
int chudxnu_cpu_number(void);

kern_return_t chudxnu_enable_cpu(int cpu, boolean_t enable);

kern_return_t chudxnu_enable_cpu_nap(int cpu, boolean_t enable);
boolean_t chudxnu_cpu_nap_enabled(int cpu);

boolean_t chudxnu_get_interrupts_enabled(void);
boolean_t chudxnu_set_interrupts_enabled(boolean_t enable);
boolean_t chudxnu_at_interrupt_context(void);
void chudxnu_cause_interrupt(void);

kern_return_t chudxnu_set_shadowed_spr(int cpu, int spr, uint32_t val);
kern_return_t chudxnu_set_shadowed_spr64(int cpu, int spr, uint64_t val);

uint32_t chudxnu_get_orig_cpu_l2cr(int cpu);
uint32_t chudxnu_get_orig_cpu_l3cr(int cpu);

void chudxnu_flush_caches(void);
void chudxnu_enable_caches(boolean_t enable);

kern_return_t chudxnu_perfmon_acquire_facility(task_t);
kern_return_t chudxnu_perfmon_release_facility(task_t);

uint32_t * chudxnu_get_branch_trace_buffer(uint32_t *entries);

typedef struct {
    uint32_t hwResets;
    uint32_t hwMachineChecks;
    uint32_t hwDSIs;
    uint32_t hwISIs;
    uint32_t hwExternals;
    uint32_t hwAlignments;
    uint32_t hwPrograms;
    uint32_t hwFloatPointUnavailable;
    uint32_t hwDecrementers;
    uint32_t hwIOErrors;
    uint32_t hwSystemCalls;
    uint32_t hwTraces;
    uint32_t hwFloatingPointAssists;
    uint32_t hwPerformanceMonitors;
    uint32_t hwAltivecs;
    uint32_t hwInstBreakpoints;
    uint32_t hwSystemManagements;
    uint32_t hwAltivecAssists;
    uint32_t hwThermal;
    uint32_t hwSoftPatches;
    uint32_t hwMaintenances;
    uint32_t hwInstrumentations;
} rupt_counters_t;

kern_return_t chudxnu_get_cpu_rupt_counters(int cpu, rupt_counters_t *rupts);
kern_return_t chudxnu_clear_cpu_rupt_counters(int cpu);

kern_return_t chudxnu_passup_alignment_exceptions(boolean_t enable);

#pragma mark **** callbacks ****
// ********************************************************************************
// callbacks
// ********************************************************************************

void chudxnu_cancel_all_callbacks(void);

// cpu timer - each cpu has its own callback 
typedef kern_return_t (*chudxnu_cpu_timer_callback_func_t)(thread_flavor_t flavor, thread_state_t tstate,  mach_msg_type_number_t count);
kern_return_t chudxnu_cpu_timer_callback_enter(chudxnu_cpu_timer_callback_func_t func, uint32_t time, uint32_t units); // callback is entered on current cpu
kern_return_t chudxnu_cpu_timer_callback_cancel(void); // callback is cleared on current cpu
kern_return_t chudxnu_cpu_timer_callback_cancel_all(void); // callback is cleared on all cpus

// trap callback - one callback for system
typedef kern_return_t (*chudxnu_trap_callback_func_t)(uint32_t trapentry, thread_flavor_t flavor, thread_state_t tstate,  mach_msg_type_number_t count);
kern_return_t chudxnu_trap_callback_enter(chudxnu_trap_callback_func_t func);
kern_return_t chudxnu_trap_callback_cancel(void);

// interrupt callback - one callback for system
typedef kern_return_t (*chudxnu_interrupt_callback_func_t)(uint32_t trapentry, thread_flavor_t flavor, thread_state_t tstate,  mach_msg_type_number_t count);
kern_return_t chudxnu_interrupt_callback_enter(chudxnu_interrupt_callback_func_t func);
kern_return_t chudxnu_interrupt_callback_cancel(void);

// ast callback - one callback for system
typedef kern_return_t (*chudxnu_perfmon_ast_callback_func_t)(thread_flavor_t flavor, thread_state_t tstate,  mach_msg_type_number_t count);
kern_return_t chudxnu_perfmon_ast_callback_enter(chudxnu_perfmon_ast_callback_func_t func);
kern_return_t chudxnu_perfmon_ast_callback_cancel(void);
kern_return_t chudxnu_perfmon_ast_send(void);

// cpusig callback - one callback for system
typedef kern_return_t (*chudxnu_cpusig_callback_func_t)(int request, thread_flavor_t flavor, thread_state_t tstate, mach_msg_type_number_t count);
kern_return_t chudxnu_cpusig_callback_enter(chudxnu_cpusig_callback_func_t func);
kern_return_t chudxnu_cpusig_callback_cancel(void);
kern_return_t chudxnu_cpusig_send(int otherCPU, uint32_t request);

// kdebug callback - one callback for system
typedef kern_return_t (*chudxnu_kdebug_callback_func_t)(uint32_t debugid, uint32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4);
kern_return_t chudxnu_kdebug_callback_enter(chudxnu_kdebug_callback_func_t func);
kern_return_t chudxnu_kdebug_callback_cancel(void);

// task exit callback - one callback for system
typedef kern_return_t (*chudxnu_exit_callback_func_t)(int pid);
kern_return_t chudxnu_exit_callback_enter(chudxnu_exit_callback_func_t func);
kern_return_t chudxnu_exit_callback_cancel(void);

// thread timer callback - one callback for system
typedef kern_return_t (*chudxnu_thread_timer_callback_func_t)(uint32_t arg);
kern_return_t chudxnu_thread_timer_callback_enter(chudxnu_thread_timer_callback_func_t func, uint32_t arg, uint32_t time, uint32_t units);
kern_return_t chudxnu_thread_timer_callback_cancel(void);


#endif /* _PPC_CHUD_XNU_H_ */
