/*
 * Copyright (c) 2003-2009 Apple Inc. All rights reserved.
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

#include <stdint.h>
#include <mach/boolean.h>
#include <mach/mach_types.h>

#include <kern/kern_types.h>
#include <kern/processor.h>
#include <kern/timer_call.h>
#include <kern/thread_call.h>
#include <kern/kalloc.h>
#include <kern/thread.h>

#include <libkern/OSAtomic.h>

#include <machine/machine_routines.h>
#include <machine/cpu_data.h>
#include <machine/trap.h>

#include <chud/chud_xnu.h>
#include <chud/chud_xnu_private.h>

#include <i386/misc_protos.h>
#include <i386/lapic.h>
#include <i386/mp.h>
#include <i386/machine_cpu.h>

#include <sys/kdebug.h>
#define CHUD_TIMER_CALLBACK_CANCEL	0
#define CHUD_TIMER_CALLBACK_ENTER	1
#define CHUD_TIMER_CALLBACK		2
#define CHUD_AST_SEND			3
#define CHUD_AST_CALLBACK		4
#define CHUD_CPUSIG_SEND		5
#define CHUD_CPUSIG_CALLBACK		6

__private_extern__
void chudxnu_cancel_all_callbacks(void)
{
    chudxnu_cpusig_callback_cancel();
    chudxnu_cpu_timer_callback_cancel_all();
    chudxnu_interrupt_callback_cancel();
    chudxnu_perfmon_ast_callback_cancel();
}

static lck_grp_t	chud_request_lck_grp;
static lck_grp_attr_t	chud_request_lck_grp_attr;
static lck_attr_t	chud_request_lck_attr;


static chudcpu_data_t chudcpu_boot_cpu;
void *
chudxnu_cpu_alloc(boolean_t boot_processor)
{
	chudcpu_data_t	*chud_proc_info;

	if (boot_processor) {
		chud_proc_info = &chudcpu_boot_cpu;

		lck_attr_setdefault(&chud_request_lck_attr);
		lck_grp_attr_setdefault(&chud_request_lck_grp_attr);
		lck_grp_init(&chud_request_lck_grp, "chud_request", &chud_request_lck_grp_attr);

	} else {
		chud_proc_info = (chudcpu_data_t *)
					kalloc(sizeof(chudcpu_data_t));
		if (chud_proc_info == (chudcpu_data_t *)NULL) {
			return (void *)NULL;
		}
	}
	bzero((char *)chud_proc_info, sizeof(chudcpu_data_t));
	chud_proc_info->t_deadline = 0xFFFFFFFFFFFFFFFFULL;

	mpqueue_init(&chud_proc_info->cpu_request_queue, &chud_request_lck_grp, &chud_request_lck_attr);

	/* timer_call_cancel() can be called before first usage, so init here: <rdar://problem/9320202> */
	timer_call_setup(&(chud_proc_info->cpu_timer_call), NULL, NULL);


	return (void *)chud_proc_info;
}

void
chudxnu_cpu_free(void *cp)
{
	if (cp == NULL || cp == (void *)&chudcpu_boot_cpu) {
		return;
	} else {
		kfree(cp,sizeof(chudcpu_data_t));
	}
}

static void
chudxnu_private_cpu_timer_callback(
	timer_call_param_t param0,
	timer_call_param_t param1)
{
#pragma unused (param0)
#pragma unused (param1)
	chudcpu_data_t			*chud_proc_info;
	boolean_t			oldlevel;
	x86_thread_state_t 		state;
	mach_msg_type_number_t		count;
	chudxnu_cpu_timer_callback_func_t fn;

	oldlevel = ml_set_interrupts_enabled(FALSE);
	chud_proc_info = (chudcpu_data_t *)(current_cpu_datap()->cpu_chud);

	count = x86_THREAD_STATE_COUNT;
	if (chudxnu_thread_get_state(current_thread(),
				     x86_THREAD_STATE,
				     (thread_state_t)&state,
				     &count,
				     FALSE) == KERN_SUCCESS) {
			fn = chud_proc_info->cpu_timer_callback_fn;
       		if (fn) {
       			(fn)(
				x86_THREAD_STATE,
				(thread_state_t)&state,
				count);
       		} 
	} 
	
	ml_set_interrupts_enabled(oldlevel);
}

__private_extern__ kern_return_t
chudxnu_cpu_timer_callback_enter(
	chudxnu_cpu_timer_callback_func_t	func,
	uint32_t				time,
	uint32_t				units)
{
	chudcpu_data_t	*chud_proc_info;
	boolean_t	oldlevel;

	oldlevel = ml_set_interrupts_enabled(FALSE);
	chud_proc_info = (chudcpu_data_t *)(current_cpu_datap()->cpu_chud);

	// cancel any existing callback for this cpu
	timer_call_cancel(&(chud_proc_info->cpu_timer_call));

	chud_proc_info->cpu_timer_callback_fn = func;

	clock_interval_to_deadline(time, units, &(chud_proc_info->t_deadline));
	timer_call_setup(&(chud_proc_info->cpu_timer_call),
			 chudxnu_private_cpu_timer_callback, NULL);
	timer_call_enter(&(chud_proc_info->cpu_timer_call),
			 chud_proc_info->t_deadline,
			 TIMER_CALL_SYS_CRITICAL|TIMER_CALL_LOCAL);

	ml_set_interrupts_enabled(oldlevel);
	return KERN_SUCCESS;
}

__private_extern__ kern_return_t
chudxnu_cpu_timer_callback_cancel(void)
{
	chudcpu_data_t	*chud_proc_info;
	boolean_t	oldlevel;

	oldlevel = ml_set_interrupts_enabled(FALSE);
	chud_proc_info = (chudcpu_data_t *)(current_cpu_datap()->cpu_chud);

	timer_call_cancel(&(chud_proc_info->cpu_timer_call));

	// set to max value:
	chud_proc_info->t_deadline |= ~(chud_proc_info->t_deadline);
	chud_proc_info->cpu_timer_callback_fn = NULL;

	ml_set_interrupts_enabled(oldlevel);
 	return KERN_SUCCESS;
}

__private_extern__ kern_return_t
chudxnu_cpu_timer_callback_cancel_all(void)
{
	unsigned int	cpu;
	chudcpu_data_t	*chud_proc_info;

	for(cpu=0; cpu < real_ncpus; cpu++) {
		chud_proc_info = (chudcpu_data_t *) cpu_data_ptr[cpu]->cpu_chud;
		if (chud_proc_info == NULL)
			continue;
		timer_call_cancel(&(chud_proc_info->cpu_timer_call));
		chud_proc_info->t_deadline |= ~(chud_proc_info->t_deadline);
		chud_proc_info->cpu_timer_callback_fn = NULL;
	}
	return KERN_SUCCESS;
}

#if 0
#pragma mark **** ast ****
#endif
static kern_return_t chud_null_ast(thread_flavor_t flavor, thread_state_t tstate,  
	mach_msg_type_number_t count);
static chudxnu_perfmon_ast_callback_func_t perfmon_ast_callback_fn = chud_null_ast;

static kern_return_t chud_null_ast(thread_flavor_t flavor __unused,
	thread_state_t tstate __unused,  mach_msg_type_number_t count __unused) {
	return KERN_FAILURE;
}

static kern_return_t
chudxnu_private_chud_ast_callback(ast_t reasons, ast_t *myast)
{	
	boolean_t oldlevel = ml_set_interrupts_enabled(FALSE);
	kern_return_t retval = KERN_FAILURE;
	chudxnu_perfmon_ast_callback_func_t fn = perfmon_ast_callback_fn;
	
	if (fn) {
		if ((*myast & AST_CHUD_URGENT) && (reasons & (AST_URGENT | AST_CHUD_URGENT))) { // Only execute urgent callbacks if reasons specifies an urgent context.
			*myast &= ~AST_CHUD_URGENT;
			
			if (AST_URGENT == *myast) { // If the only flag left is AST_URGENT, we can clear it; we know that we set it, but if there are also other bits set in reasons then someone else might still need AST_URGENT, so we'll leave it set.  The normal machinery in ast_taken will ensure it gets cleared eventually, as necessary.
				*myast = AST_NONE;
			}
			
			retval = KERN_SUCCESS;
		}
		
		if ((*myast & AST_CHUD) && (reasons & AST_CHUD)) { // Only execute non-urgent callbacks if reasons actually specifies AST_CHUD.  This implies non-urgent callbacks since the only time this'll happen is if someone either calls ast_taken with AST_CHUD explicitly (not done at time of writing, but possible) or with AST_ALL, which of course includes AST_CHUD.
			*myast &= ~AST_CHUD;
			retval = KERN_SUCCESS;
		}
	
		if (KERN_SUCCESS == retval) {
			x86_thread_state_t state;
			mach_msg_type_number_t count = x86_THREAD_STATE_COUNT;
			thread_t thread = current_thread();
			
			if (KERN_SUCCESS == chudxnu_thread_get_state(thread,
														 x86_THREAD_STATE,
														 (thread_state_t)&state,
														 &count,
														 (thread->task != kernel_task))) {
				(fn)(x86_THREAD_STATE, (thread_state_t)&state, count);
			}
		}
	}
    
	ml_set_interrupts_enabled(oldlevel);
	return retval;
}

volatile perfASTCallback perfASTHook;

__private_extern__ kern_return_t
chudxnu_perfmon_ast_callback_enter(chudxnu_perfmon_ast_callback_func_t func)
{
	if(OSCompareAndSwapPtr(NULL, chudxnu_private_chud_ast_callback,
		(void * volatile *)&perfASTHook)) {
		chudxnu_perfmon_ast_callback_func_t old = perfmon_ast_callback_fn;

		while(!OSCompareAndSwapPtr(old, func,
			(void * volatile *)&perfmon_ast_callback_fn)) {
			old = perfmon_ast_callback_fn;
		}

		return KERN_SUCCESS;
	}
	return KERN_FAILURE;
}

__private_extern__ kern_return_t
chudxnu_perfmon_ast_callback_cancel(void)
{
	if(OSCompareAndSwapPtr(chudxnu_private_chud_ast_callback, NULL,
		(void * volatile *)&perfASTHook)) {
		chudxnu_perfmon_ast_callback_func_t old = perfmon_ast_callback_fn;

		while(!OSCompareAndSwapPtr(old, chud_null_ast,
			(void * volatile *)&perfmon_ast_callback_fn)) {
			old = perfmon_ast_callback_fn;
		}

		return KERN_SUCCESS;
	}
	return KERN_FAILURE;
}

__private_extern__ kern_return_t
chudxnu_perfmon_ast_send_urgent(boolean_t urgent)
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

#if 0
#pragma mark **** interrupt ****
#endif
static kern_return_t chud_null_int(uint32_t trapentry, thread_flavor_t flavor, 
	thread_state_t tstate,  mach_msg_type_number_t count);
static chudxnu_interrupt_callback_func_t interrupt_callback_fn = chud_null_int;

static kern_return_t chud_null_int(uint32_t trapentry __unused, thread_flavor_t flavor __unused,
	thread_state_t tstate __unused,  mach_msg_type_number_t count __unused) {
	return KERN_FAILURE;
}

static void
chudxnu_private_interrupt_callback(void *foo) __attribute__((used));

static void
chudxnu_private_interrupt_callback(void *foo)
{
#pragma unused (foo)
	chudxnu_interrupt_callback_func_t fn = interrupt_callback_fn;

	if(fn) {
		boolean_t			oldlevel;
		x86_thread_state_t		state;
		mach_msg_type_number_t		count;

		oldlevel = ml_set_interrupts_enabled(FALSE);

		count = x86_THREAD_STATE_COUNT;
		if(chudxnu_thread_get_state(current_thread(),
					    x86_THREAD_STATE,
					    (thread_state_t)&state,
					    &count,
					    FALSE) == KERN_SUCCESS) {
			(fn)(
				X86_INTERRUPT_PERFMON,
				x86_THREAD_STATE,
				(thread_state_t)&state,
				count);
		}
		ml_set_interrupts_enabled(oldlevel);
	}
}

__private_extern__ kern_return_t
chudxnu_interrupt_callback_enter(chudxnu_interrupt_callback_func_t func)
{
	if(OSCompareAndSwapPtr(chud_null_int, func, 
		(void * volatile *)&interrupt_callback_fn)) {
		lapic_set_pmi_func((i386_intr_func_t)chudxnu_private_interrupt_callback);
		return KERN_SUCCESS;
	}
    return KERN_FAILURE;
}

__private_extern__ kern_return_t
chudxnu_interrupt_callback_cancel(void)
{
	chudxnu_interrupt_callback_func_t old = interrupt_callback_fn;

	while(!OSCompareAndSwapPtr(old, chud_null_int,
		(void * volatile *)&interrupt_callback_fn)) {
		old = interrupt_callback_fn;
	}

    lapic_set_pmi_func(NULL);
    return KERN_SUCCESS;
}

#if 0
#pragma mark **** cpu signal ****
#endif
static chudxnu_cpusig_callback_func_t cpusig_callback_fn = NULL;

static          kern_return_t
chudxnu_private_cpu_signal_handler(int request)
{
	chudxnu_cpusig_callback_func_t fn = cpusig_callback_fn;
	
	if (fn) {
	x86_thread_state_t  state;
		mach_msg_type_number_t count = x86_THREAD_STATE_COUNT;

		if (chudxnu_thread_get_state(current_thread(),
					     x86_THREAD_STATE,
					     (thread_state_t) &state, &count,
					     FALSE) == KERN_SUCCESS) {
			return (fn)(
					request, x86_THREAD_STATE,
					(thread_state_t) &state, count);
		} else {
			return KERN_FAILURE;
		}
	}
	return KERN_SUCCESS; //ignored
}
/*
 * chudxnu_cpu_signal_handler() is called from the IPI handler
 * when a CHUD signal arrives from another processor.
 */
__private_extern__ void
chudxnu_cpu_signal_handler(void)
{
	chudcpu_signal_request_t	*reqp;
	chudcpu_data_t			*chudinfop;

	chudinfop = (chudcpu_data_t *) current_cpu_datap()->cpu_chud;

	mpdequeue_head(&(chudinfop->cpu_request_queue),
		       (queue_entry_t *) &reqp);
	while (reqp != NULL) {
		chudxnu_private_cpu_signal_handler(reqp->req_code);
		reqp->req_sync = 0;
		mpdequeue_head(&(chudinfop->cpu_request_queue),
			       (queue_entry_t *) &reqp);
	}
}

__private_extern__ kern_return_t
chudxnu_cpusig_callback_enter(chudxnu_cpusig_callback_func_t func)
{
	if(OSCompareAndSwapPtr(NULL, func, 
		(void * volatile *)&cpusig_callback_fn)) {
		return KERN_SUCCESS;
	}
	return KERN_FAILURE;
}

__private_extern__ kern_return_t
chudxnu_cpusig_callback_cancel(void)
{
	chudxnu_cpusig_callback_func_t old = cpusig_callback_fn;

	while(!OSCompareAndSwapPtr(old, NULL,
		(void * volatile *)&cpusig_callback_fn)) {
		old = cpusig_callback_fn;
	}

	return KERN_SUCCESS;
}

__private_extern__ kern_return_t
chudxnu_cpusig_send(int otherCPU, uint32_t request_code)
{
	int				thisCPU;
	kern_return_t			retval = KERN_FAILURE;
	chudcpu_signal_request_t	request;
	uint64_t			deadline;
	chudcpu_data_t			*target_chudp;
	boolean_t old_level;

	disable_preemption();
	// force interrupts on for a cross CPU signal.
	old_level = chudxnu_set_interrupts_enabled(TRUE);
	thisCPU = cpu_number();

	if ((unsigned) otherCPU < real_ncpus &&
	    thisCPU != otherCPU &&
	    cpu_data_ptr[otherCPU]->cpu_running) {

		target_chudp = (chudcpu_data_t *)
					cpu_data_ptr[otherCPU]->cpu_chud;

		/* Fill out request */
		request.req_sync = 0xFFFFFFFF;		/* set sync flag */
		//request.req_type = CPRQchud;		/* set request type */
		request.req_code = request_code;	/* set request */

		/*
		 * Insert the new request in the target cpu's request queue
		 * and signal target cpu.
		 */
		mpenqueue_tail(&target_chudp->cpu_request_queue,
			       &request.req_entry);
		i386_signal_cpu(otherCPU, MP_CHUD, ASYNC);

		/* Wait for response or timeout */
		deadline = mach_absolute_time() + LockTimeOut;
		while (request.req_sync != 0) {
			if (mach_absolute_time() > deadline) {
				panic("chudxnu_cpusig_send(%d,%d) timed out\n",
					otherCPU, request_code);
			}
			cpu_pause();
		}
		retval = KERN_SUCCESS;
	} else {
		retval = KERN_INVALID_ARGUMENT;
	}

	chudxnu_set_interrupts_enabled(old_level);
	enable_preemption();
	return retval;
}
