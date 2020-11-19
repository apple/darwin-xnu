/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
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
 * Copyright (c) 1991,1990 Carnegie Mellon University
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

#include <mach_debug.h>
#include <mach_ldebug.h>

#include <sys/kdebug.h>

#include <mach/kern_return.h>
#include <mach/thread_status.h>
#include <mach/vm_param.h>

#include <kern/counters.h>
#include <kern/kalloc.h>
#include <kern/mach_param.h>
#include <kern/processor.h>
#include <kern/cpu_data.h>
#include <kern/cpu_number.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <kern/misc_protos.h>
#include <kern/assert.h>
#include <kern/spl.h>
#include <kern/machine.h>
#include <kern/kpc.h>
#include <ipc/ipc_port.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/pmap.h>
#include <vm/vm_protos.h>

#include <i386/cpu_data.h>
#include <i386/cpu_number.h>
#include <i386/eflags.h>
#include <i386/proc_reg.h>
#include <i386/fpu.h>
#include <i386/misc_protos.h>
#include <i386/mp_desc.h>
#include <i386/thread.h>
#include <i386/machine_routines.h>
#include <i386/lapic.h> /* LAPIC_PMC_SWI_VECTOR */
#include <i386/seg.h>

#if HYPERVISOR
#include <kern/hv_support.h>
#endif

/*
 * Maps state flavor to number of words in the state:
 */
unsigned int _MachineStateCount[] = {
	[x86_THREAD_STATE32]            = x86_THREAD_STATE32_COUNT,
	[x86_THREAD_STATE64]            = x86_THREAD_STATE64_COUNT,
	[x86_THREAD_FULL_STATE64]       = x86_THREAD_FULL_STATE64_COUNT,
	[x86_THREAD_STATE]              = x86_THREAD_STATE_COUNT,
	[x86_FLOAT_STATE32]             = x86_FLOAT_STATE32_COUNT,
	[x86_FLOAT_STATE64]             = x86_FLOAT_STATE64_COUNT,
	[x86_FLOAT_STATE]               = x86_FLOAT_STATE_COUNT,
	[x86_EXCEPTION_STATE32]         = x86_EXCEPTION_STATE32_COUNT,
	[x86_EXCEPTION_STATE64]         = x86_EXCEPTION_STATE64_COUNT,
	[x86_EXCEPTION_STATE]           = x86_EXCEPTION_STATE_COUNT,
	[x86_DEBUG_STATE32]             = x86_DEBUG_STATE32_COUNT,
	[x86_DEBUG_STATE64]             = x86_DEBUG_STATE64_COUNT,
	[x86_DEBUG_STATE]               = x86_DEBUG_STATE_COUNT,
	[x86_AVX_STATE32]               = x86_AVX_STATE32_COUNT,
	[x86_AVX_STATE64]               = x86_AVX_STATE64_COUNT,
	[x86_AVX_STATE]                 = x86_AVX_STATE_COUNT,
	[x86_AVX512_STATE32]            = x86_AVX512_STATE32_COUNT,
	[x86_AVX512_STATE64]            = x86_AVX512_STATE64_COUNT,
	[x86_AVX512_STATE]              = x86_AVX512_STATE_COUNT,
	[x86_PAGEIN_STATE]              = x86_PAGEIN_STATE_COUNT
};

ZONE_DECLARE(iss_zone, "x86_64 saved state",
    sizeof(x86_saved_state_t), ZC_NONE);

ZONE_DECLARE(ids_zone, "x86_64 debug state",
    sizeof(x86_debug_state64_t), ZC_NONE);

/* Forward */

extern void             Thread_continue(void);
extern void             Load_context(
	thread_t                        thread) __attribute__((noreturn));

static void
get_exception_state32(thread_t thread, x86_exception_state32_t *es);

static void
get_exception_state64(thread_t thread, x86_exception_state64_t *es);

static void
get_thread_state32(thread_t thread, x86_thread_state32_t *ts);

static void
get_thread_state64(thread_t thread, void *ts, boolean_t full);

static int
set_thread_state32(thread_t thread, x86_thread_state32_t *ts);

static int
set_thread_state64(thread_t thread, void *ts, boolean_t full);

#if HYPERVISOR
static inline void
ml_hv_cswitch(thread_t old, thread_t new)
{
	if (old->hv_thread_target) {
		hv_callbacks.preempt(old->hv_thread_target);
	}

	if (new->hv_thread_target) {
		hv_callbacks.dispatch(new->hv_thread_target);
	}
}
#endif

/*
 * Don't let an illegal value for the lower 32-bits of dr7 get set.
 * Specifically, check for undefined settings.  Setting these bit patterns
 * result in undefined behaviour and can lead to an unexpected
 * TRCTRAP.
 */
static boolean_t
dr7d_is_valid(uint32_t *dr7d)
{
	int i;
	uint32_t mask1, mask2;

	/*
	 * If the DE bit is set in CR4, R/W0-3 can be pattern
	 * "10B" to indicate i/o reads and write
	 */
	if (!(get_cr4() & CR4_DE)) {
		for (i = 0, mask1 = 0x3 << 16, mask2 = 0x2 << 16; i < 4;
		    i++, mask1 <<= 4, mask2 <<= 4) {
			if ((*dr7d & mask1) == mask2) {
				return FALSE;
			}
		}
	}

	/*
	 * if we are doing an instruction execution break (indicated
	 * by r/w[x] being "00B"), then the len[x] must also be set
	 * to "00B"
	 */
	for (i = 0; i < 4; i++) {
		if (((((*dr7d >> (16 + i * 4))) & 0x3) == 0) &&
		    ((((*dr7d >> (18 + i * 4))) & 0x3) != 0)) {
			return FALSE;
		}
	}

	/*
	 * Intel docs have these bits fixed.
	 */
	*dr7d |= 0x1 << 10; /* set bit 10 to 1 */
	*dr7d &= ~(0x1 << 11); /* set bit 11 to 0 */
	*dr7d &= ~(0x1 << 12); /* set bit 12 to 0 */
	*dr7d &= ~(0x1 << 14); /* set bit 14 to 0 */
	*dr7d &= ~(0x1 << 15); /* set bit 15 to 0 */

	/*
	 * We don't allow anything to set the global breakpoints.
	 */

	if (*dr7d & 0x2) {
		return FALSE;
	}

	if (*dr7d & (0x2 << 2)) {
		return FALSE;
	}

	if (*dr7d & (0x2 << 4)) {
		return FALSE;
	}

	if (*dr7d & (0x2 << 6)) {
		return FALSE;
	}

	return TRUE;
}

extern void set_64bit_debug_regs(x86_debug_state64_t *ds);

boolean_t
debug_state_is_valid32(x86_debug_state32_t *ds)
{
	if (!dr7d_is_valid(&ds->dr7)) {
		return FALSE;
	}

	return TRUE;
}

boolean_t
debug_state_is_valid64(x86_debug_state64_t *ds)
{
	if (!dr7d_is_valid((uint32_t *)&ds->dr7)) {
		return FALSE;
	}

	/*
	 * Don't allow the user to set debug addresses above their max
	 * value
	 */
	if (ds->dr7 & 0x1) {
		if (ds->dr0 >= VM_MAX_PAGE_ADDRESS) {
			return FALSE;
		}
	}

	if (ds->dr7 & (0x1 << 2)) {
		if (ds->dr1 >= VM_MAX_PAGE_ADDRESS) {
			return FALSE;
		}
	}

	if (ds->dr7 & (0x1 << 4)) {
		if (ds->dr2 >= VM_MAX_PAGE_ADDRESS) {
			return FALSE;
		}
	}

	if (ds->dr7 & (0x1 << 6)) {
		if (ds->dr3 >= VM_MAX_PAGE_ADDRESS) {
			return FALSE;
		}
	}

	/* For x86-64, we must ensure the upper 32-bits of DR7 are clear */
	ds->dr7 &= 0xffffffffULL;

	return TRUE;
}


static kern_return_t
set_debug_state32(thread_t thread, x86_debug_state32_t *ds)
{
	x86_debug_state32_t *new_ids;
	pcb_t pcb;

	pcb = THREAD_TO_PCB(thread);

	if (debug_state_is_valid32(ds) != TRUE) {
		return KERN_INVALID_ARGUMENT;
	}

	if (pcb->ids == NULL) {
		new_ids = zalloc(ids_zone);
		bzero(new_ids, sizeof *new_ids);

		simple_lock(&pcb->lock, LCK_GRP_NULL);
		/* make sure it wasn't already alloc()'d elsewhere */
		if (pcb->ids == NULL) {
			pcb->ids = new_ids;
			simple_unlock(&pcb->lock);
		} else {
			simple_unlock(&pcb->lock);
			zfree(ids_zone, new_ids);
		}
	}


	copy_debug_state32(ds, pcb->ids, FALSE);

	return KERN_SUCCESS;
}

static kern_return_t
set_debug_state64(thread_t thread, x86_debug_state64_t *ds)
{
	x86_debug_state64_t *new_ids;
	pcb_t pcb;

	pcb = THREAD_TO_PCB(thread);

	if (debug_state_is_valid64(ds) != TRUE) {
		return KERN_INVALID_ARGUMENT;
	}

	if (pcb->ids == NULL) {
		new_ids = zalloc(ids_zone);
		bzero(new_ids, sizeof *new_ids);

#if HYPERVISOR
		if (thread->hv_thread_target) {
			hv_callbacks.volatile_state(thread->hv_thread_target,
			    HV_DEBUG_STATE);
		}
#endif

		simple_lock(&pcb->lock, LCK_GRP_NULL);
		/* make sure it wasn't already alloc()'d elsewhere */
		if (pcb->ids == NULL) {
			pcb->ids = new_ids;
			simple_unlock(&pcb->lock);
		} else {
			simple_unlock(&pcb->lock);
			zfree(ids_zone, new_ids);
		}
	}

	copy_debug_state64(ds, pcb->ids, FALSE);

	return KERN_SUCCESS;
}

static void
get_debug_state32(thread_t thread, x86_debug_state32_t *ds)
{
	x86_debug_state32_t *saved_state;

	saved_state = thread->machine.ids;

	if (saved_state) {
		copy_debug_state32(saved_state, ds, TRUE);
	} else {
		bzero(ds, sizeof *ds);
	}
}

static void
get_debug_state64(thread_t thread, x86_debug_state64_t *ds)
{
	x86_debug_state64_t *saved_state;

	saved_state = (x86_debug_state64_t *)thread->machine.ids;

	if (saved_state) {
		copy_debug_state64(saved_state, ds, TRUE);
	} else {
		bzero(ds, sizeof *ds);
	}
}

/*
 * consider_machine_collect:
 *
 *	Try to collect machine-dependent pages
 */
void
consider_machine_collect(void)
{
}

void
consider_machine_adjust(void)
{
}

/*
 * Switch to the first thread on a CPU.
 */
void
machine_load_context(
	thread_t                new)
{
	new->machine.specFlags |= OnProc;
	act_machine_switch_pcb(NULL, new);
	Load_context(new);
}

static inline void
pmap_switch_context(thread_t ot, thread_t nt, int cnum)
{
	pmap_assert(ml_get_interrupts_enabled() == FALSE);
	vm_map_t nmap = nt->map, omap = ot->map;
	if ((omap != nmap) || (nmap->pmap->pagezero_accessible)) {
		PMAP_DEACTIVATE_MAP(omap, ot, cnum);
		PMAP_ACTIVATE_MAP(nmap, nt, cnum);
	}
}

/*
 * Switch to a new thread.
 * Save the old thread`s kernel state or continuation,
 * and return it.
 */
thread_t
machine_switch_context(
	thread_t                        old,
	thread_continue_t       continuation,
	thread_t                        new)
{
	assert(current_cpu_datap()->cpu_active_stack == old->kernel_stack);

#if KPC
	kpc_off_cpu(old);
#endif /* KPC */

	/*
	 *	Save FP registers if in use.
	 */
	fpu_switch_context(old, new);

	old->machine.specFlags &= ~OnProc;
	new->machine.specFlags |= OnProc;

	/*
	 * Monitor the stack depth and report new max,
	 * not worrying about races.
	 */
	vm_offset_t     depth = current_stack_depth();
	if (depth > kernel_stack_depth_max) {
		kernel_stack_depth_max = depth;
		KERNEL_DEBUG_CONSTANT(
			MACHDBG_CODE(DBG_MACH_SCHED, MACH_STACK_DEPTH),
			(long) depth, 0, 0, 0, 0);
	}

	/*
	 *	Switch address maps if need be, even if not switching tasks.
	 *	(A server activation may be "borrowing" a client map.)
	 */
	pmap_switch_context(old, new, cpu_number());

	/*
	 *	Load the rest of the user state for the new thread
	 */
	act_machine_switch_pcb(old, new);

#if HYPERVISOR
	ml_hv_cswitch(old, new);
#endif

	return Switch_context(old, continuation, new);
}

boolean_t
machine_thread_on_core(thread_t thread)
{
	return thread->machine.specFlags & OnProc;
}

thread_t
machine_processor_shutdown(
	thread_t        thread,
	void            (*doshutdown)(processor_t),
	processor_t     processor)
{
#if CONFIG_VMX
	vmx_suspend();
#endif
	fpu_switch_context(thread, NULL);
	pmap_switch_context(thread, processor->idle_thread, cpu_number());
	return Shutdown_context(thread, doshutdown, processor);
}


/*
 * This is where registers that are not normally specified by the mach-o
 * file on an execve would be nullified, perhaps to avoid a covert channel.
 */
kern_return_t
machine_thread_state_initialize(
	thread_t thread)
{
	/*
	 * If there's an fpu save area, free it.
	 * The initialized state will then be lazily faulted-in, if required.
	 * And if we're target, re-arm the no-fpu trap.
	 */
	if (thread->machine.ifps) {
		(void) fpu_set_fxstate(thread, NULL, x86_FLOAT_STATE64);

		if (thread == current_thread()) {
			clear_fpu();
		}
	}

	if (thread->machine.ids) {
		zfree(ids_zone, thread->machine.ids);
		thread->machine.ids = NULL;
	}

	return KERN_SUCCESS;
}

uint32_t
get_eflags_exportmask(void)
{
	return EFL_USER_SET;
}

/*
 * x86_SAVED_STATE32	 - internal save/restore general register state on 32/64 bit processors
 *			   for 32bit tasks only
 * x86_SAVED_STATE64	 - internal save/restore general register state on 64 bit processors
 *			   for 64bit tasks only
 * x86_THREAD_STATE32	 - external set/get general register state on 32/64 bit processors
 *			   for 32bit tasks only
 * x86_THREAD_STATE64	 - external set/get general register state on 64 bit processors
 *			   for 64bit tasks only
 * x86_SAVED_STATE	 - external set/get general register state on 32/64 bit processors
 *			   for either 32bit or 64bit tasks
 * x86_FLOAT_STATE32	 - internal/external save/restore float and xmm state on 32/64 bit processors
 *			   for 32bit tasks only
 * x86_FLOAT_STATE64	 - internal/external save/restore float and xmm state on 64 bit processors
 *			   for 64bit tasks only
 * x86_FLOAT_STATE	 - external save/restore float and xmm state on 32/64 bit processors
 *			   for either 32bit or 64bit tasks
 * x86_EXCEPTION_STATE32 - external get exception state on 32/64 bit processors
 *			   for 32bit tasks only
 * x86_EXCEPTION_STATE64 - external get exception state on 64 bit processors
 *			   for 64bit tasks only
 * x86_EXCEPTION_STATE   - external get exception state on 323/64 bit processors
 *			   for either 32bit or 64bit tasks
 */


static void
get_exception_state64(thread_t thread, x86_exception_state64_t *es)
{
	x86_saved_state64_t *saved_state;

	saved_state = USER_REGS64(thread);

	es->trapno = saved_state->isf.trapno;
	es->cpu = saved_state->isf.cpu;
	es->err = (typeof(es->err))saved_state->isf.err;
	es->faultvaddr = saved_state->cr2;
}

static void
get_exception_state32(thread_t thread, x86_exception_state32_t *es)
{
	x86_saved_state32_t *saved_state;

	saved_state = USER_REGS32(thread);

	es->trapno = saved_state->trapno;
	es->cpu = saved_state->cpu;
	es->err = saved_state->err;
	es->faultvaddr = saved_state->cr2;
}


static int
set_thread_state32(thread_t thread, x86_thread_state32_t *ts)
{
	x86_saved_state32_t     *saved_state;

	pal_register_cache_state(thread, DIRTY);

	saved_state = USER_REGS32(thread);

	/*
	 * Scrub segment selector values:
	 */
	ts->cs = USER_CS;
	/*
	 * On a 64 bit kernel, we always override the data segments,
	 * as the actual selector numbers have changed. This also
	 * means that we don't support setting the data segments
	 * manually any more.
	 */
	ts->ss = USER_DS;
	ts->ds = USER_DS;
	ts->es = USER_DS;

	/* Set GS to CTHREAD only if's been established */
	ts->gs = thread->machine.cthread_self ? USER_CTHREAD : NULL_SEG;

	/* Check segment selectors are safe */
	if (!valid_user_segment_selectors(ts->cs,
	    ts->ss,
	    ts->ds,
	    ts->es,
	    ts->fs,
	    ts->gs)) {
		return KERN_INVALID_ARGUMENT;
	}

	saved_state->eax = ts->eax;
	saved_state->ebx = ts->ebx;
	saved_state->ecx = ts->ecx;
	saved_state->edx = ts->edx;
	saved_state->edi = ts->edi;
	saved_state->esi = ts->esi;
	saved_state->ebp = ts->ebp;
	saved_state->uesp = ts->esp;
	saved_state->efl = (ts->eflags & ~EFL_USER_CLEAR) | EFL_USER_SET;
	saved_state->eip = ts->eip;
	saved_state->cs = ts->cs;
	saved_state->ss = ts->ss;
	saved_state->ds = ts->ds;
	saved_state->es = ts->es;
	saved_state->fs = ts->fs;
	saved_state->gs = ts->gs;

	/*
	 * If the trace trap bit is being set,
	 * ensure that the user returns via iret
	 * - which is signaled thusly:
	 */
	if ((saved_state->efl & EFL_TF) && saved_state->cs == SYSENTER_CS) {
		saved_state->cs = SYSENTER_TF_CS;
	}

	return KERN_SUCCESS;
}

static int
set_thread_state64(thread_t thread, void *state, int full)
{
	x86_thread_state64_t *ts;
	x86_saved_state64_t     *saved_state;

	if (full == TRUE) {
		ts = &((x86_thread_full_state64_t *)state)->ss64;
		if (!valid_user_code_selector(((x86_thread_full_state64_t *)ts)->ss64.cs)) {
			return KERN_INVALID_ARGUMENT;
		}
	} else {
		ts = (x86_thread_state64_t *)state;
		// In this case, ts->cs exists but is ignored, and
		// CS is always set to USER_CS below instead.
	}

	pal_register_cache_state(thread, DIRTY);

	saved_state = USER_REGS64(thread);

	if (!IS_USERADDR64_CANONICAL(ts->rsp) ||
	    !IS_USERADDR64_CANONICAL(ts->rip)) {
		return KERN_INVALID_ARGUMENT;
	}

	saved_state->r8 = ts->r8;
	saved_state->r9 = ts->r9;
	saved_state->r10 = ts->r10;
	saved_state->r11 = ts->r11;
	saved_state->r12 = ts->r12;
	saved_state->r13 = ts->r13;
	saved_state->r14 = ts->r14;
	saved_state->r15 = ts->r15;
	saved_state->rax = ts->rax;
	saved_state->rbx = ts->rbx;
	saved_state->rcx = ts->rcx;
	saved_state->rdx = ts->rdx;
	saved_state->rdi = ts->rdi;
	saved_state->rsi = ts->rsi;
	saved_state->rbp = ts->rbp;
	saved_state->isf.rsp = ts->rsp;
	saved_state->isf.rflags = (ts->rflags & ~EFL_USER_CLEAR) | EFL_USER_SET;
	saved_state->isf.rip = ts->rip;

	if (full == FALSE) {
		saved_state->isf.cs = USER64_CS;
	} else {
		saved_state->isf.cs = ((x86_thread_full_state64_t *)ts)->ss64.cs;
		saved_state->isf.ss = ((x86_thread_full_state64_t *)ts)->ss;
		saved_state->ds = (uint32_t)((x86_thread_full_state64_t *)ts)->ds;
		saved_state->es = (uint32_t)((x86_thread_full_state64_t *)ts)->es;
		machine_thread_set_tsd_base(thread,
		    ((x86_thread_full_state64_t *)ts)->gsbase);
	}

	saved_state->fs = (uint32_t)ts->fs;
	saved_state->gs = (uint32_t)ts->gs;

	return KERN_SUCCESS;
}



static void
get_thread_state32(thread_t thread, x86_thread_state32_t *ts)
{
	x86_saved_state32_t     *saved_state;

	pal_register_cache_state(thread, VALID);

	saved_state = USER_REGS32(thread);

	ts->eax = saved_state->eax;
	ts->ebx = saved_state->ebx;
	ts->ecx = saved_state->ecx;
	ts->edx = saved_state->edx;
	ts->edi = saved_state->edi;
	ts->esi = saved_state->esi;
	ts->ebp = saved_state->ebp;
	ts->esp = saved_state->uesp;
	ts->eflags = saved_state->efl;
	ts->eip = saved_state->eip;
	ts->cs = saved_state->cs;
	ts->ss = saved_state->ss;
	ts->ds = saved_state->ds;
	ts->es = saved_state->es;
	ts->fs = saved_state->fs;
	ts->gs = saved_state->gs;
}


static void
get_thread_state64(thread_t thread, void *state, boolean_t full)
{
	x86_thread_state64_t    *ts;
	x86_saved_state64_t     *saved_state;

	if (full == TRUE) {
		ts = &((x86_thread_full_state64_t *)state)->ss64;
	} else {
		ts = (x86_thread_state64_t *)state;
	}

	pal_register_cache_state(thread, VALID);

	saved_state = USER_REGS64(thread);

	ts->r8 = saved_state->r8;
	ts->r9 = saved_state->r9;
	ts->r10 = saved_state->r10;
	ts->r11 = saved_state->r11;
	ts->r12 = saved_state->r12;
	ts->r13 = saved_state->r13;
	ts->r14 = saved_state->r14;
	ts->r15 = saved_state->r15;
	ts->rax = saved_state->rax;
	ts->rbx = saved_state->rbx;
	ts->rcx = saved_state->rcx;
	ts->rdx = saved_state->rdx;
	ts->rdi = saved_state->rdi;
	ts->rsi = saved_state->rsi;
	ts->rbp = saved_state->rbp;
	ts->rsp = saved_state->isf.rsp;
	ts->rflags = saved_state->isf.rflags;
	ts->rip = saved_state->isf.rip;
	ts->cs = saved_state->isf.cs;

	if (full == TRUE) {
		((x86_thread_full_state64_t *)state)->ds = saved_state->ds;
		((x86_thread_full_state64_t *)state)->es = saved_state->es;
		((x86_thread_full_state64_t *)state)->ss = saved_state->isf.ss;
		((x86_thread_full_state64_t *)state)->gsbase =
		    thread->machine.cthread_self;
	}

	ts->fs = saved_state->fs;
	ts->gs = saved_state->gs;
}

kern_return_t
machine_thread_state_convert_to_user(
	__unused thread_t thread,
	__unused thread_flavor_t flavor,
	__unused thread_state_t tstate,
	__unused mach_msg_type_number_t *count)
{
	// No conversion to userspace representation on this platform
	return KERN_SUCCESS;
}

kern_return_t
machine_thread_state_convert_from_user(
	__unused thread_t thread,
	__unused thread_flavor_t flavor,
	__unused thread_state_t tstate,
	__unused mach_msg_type_number_t count)
{
	// No conversion from userspace representation on this platform
	return KERN_SUCCESS;
}

kern_return_t
machine_thread_siguctx_pointer_convert_to_user(
	__unused thread_t thread,
	__unused user_addr_t *uctxp)
{
	// No conversion to userspace representation on this platform
	return KERN_SUCCESS;
}

kern_return_t
machine_thread_function_pointers_convert_from_user(
	__unused thread_t thread,
	__unused user_addr_t *fptrs,
	__unused uint32_t count)
{
	// No conversion from userspace representation on this platform
	return KERN_SUCCESS;
}

/*
 *	act_machine_set_state:
 *
 *	Set the status of the specified thread.
 */

kern_return_t
machine_thread_set_state(
	thread_t thr_act,
	thread_flavor_t flavor,
	thread_state_t tstate,
	mach_msg_type_number_t count)
{
	switch (flavor) {
	case x86_SAVED_STATE32:
	{
		x86_saved_state32_t     *state;
		x86_saved_state32_t     *saved_state;

		if (count < x86_SAVED_STATE32_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		state = (x86_saved_state32_t *) tstate;

		/*
		 * Refuse to allow 64-bit processes to set
		 * 32-bit state.
		 */
		if (thread_is_64bit_addr(thr_act)) {
			return KERN_INVALID_ARGUMENT;
		}

		/* Check segment selectors are safe */
		if (!valid_user_segment_selectors(state->cs,
		    state->ss,
		    state->ds,
		    state->es,
		    state->fs,
		    state->gs)) {
			return KERN_INVALID_ARGUMENT;
		}

		pal_register_cache_state(thr_act, DIRTY);

		saved_state = USER_REGS32(thr_act);

		/*
		 * General registers
		 */
		saved_state->edi = state->edi;
		saved_state->esi = state->esi;
		saved_state->ebp = state->ebp;
		saved_state->uesp = state->uesp;
		saved_state->ebx = state->ebx;
		saved_state->edx = state->edx;
		saved_state->ecx = state->ecx;
		saved_state->eax = state->eax;
		saved_state->eip = state->eip;

		saved_state->efl = (state->efl & ~EFL_USER_CLEAR) | EFL_USER_SET;

		/*
		 * If the trace trap bit is being set,
		 * ensure that the user returns via iret
		 * - which is signaled thusly:
		 */
		if ((saved_state->efl & EFL_TF) && state->cs == SYSENTER_CS) {
			state->cs = SYSENTER_TF_CS;
		}

		/*
		 * User setting segment registers.
		 * Code and stack selectors have already been
		 * checked.  Others will be reset by 'iret'
		 * if they are not valid.
		 */
		saved_state->cs = state->cs;
		saved_state->ss = state->ss;
		saved_state->ds = state->ds;
		saved_state->es = state->es;
		saved_state->fs = state->fs;
		saved_state->gs = state->gs;

		break;
	}

	case x86_SAVED_STATE64:
	{
		x86_saved_state64_t     *state;
		x86_saved_state64_t     *saved_state;

		if (count < x86_SAVED_STATE64_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		if (!thread_is_64bit_addr(thr_act)) {
			return KERN_INVALID_ARGUMENT;
		}

		state = (x86_saved_state64_t *) tstate;

		/* Verify that the supplied code segment selector is
		 * valid. In 64-bit mode, the FS and GS segment overrides
		 * use the FS.base and GS.base MSRs to calculate
		 * base addresses, and the trampolines don't directly
		 * restore the segment registers--hence they are no
		 * longer relevant for validation.
		 */
		if (!valid_user_code_selector(state->isf.cs)) {
			return KERN_INVALID_ARGUMENT;
		}

		/* Check pc and stack are canonical addresses */
		if (!IS_USERADDR64_CANONICAL(state->isf.rsp) ||
		    !IS_USERADDR64_CANONICAL(state->isf.rip)) {
			return KERN_INVALID_ARGUMENT;
		}

		pal_register_cache_state(thr_act, DIRTY);

		saved_state = USER_REGS64(thr_act);

		/*
		 * General registers
		 */
		saved_state->r8 = state->r8;
		saved_state->r9 = state->r9;
		saved_state->r10 = state->r10;
		saved_state->r11 = state->r11;
		saved_state->r12 = state->r12;
		saved_state->r13 = state->r13;
		saved_state->r14 = state->r14;
		saved_state->r15 = state->r15;
		saved_state->rdi = state->rdi;
		saved_state->rsi = state->rsi;
		saved_state->rbp = state->rbp;
		saved_state->rbx = state->rbx;
		saved_state->rdx = state->rdx;
		saved_state->rcx = state->rcx;
		saved_state->rax = state->rax;
		saved_state->isf.rsp = state->isf.rsp;
		saved_state->isf.rip = state->isf.rip;

		saved_state->isf.rflags = (state->isf.rflags & ~EFL_USER_CLEAR) | EFL_USER_SET;

		/*
		 * User setting segment registers.
		 * Code and stack selectors have already been
		 * checked.  Others will be reset by 'sys'
		 * if they are not valid.
		 */
		saved_state->isf.cs = state->isf.cs;
		saved_state->isf.ss = state->isf.ss;
		saved_state->fs = state->fs;
		saved_state->gs = state->gs;

		break;
	}

	case x86_FLOAT_STATE32:
	case x86_AVX_STATE32:
	case x86_AVX512_STATE32:
	{
		if (count != _MachineStateCount[flavor]) {
			return KERN_INVALID_ARGUMENT;
		}

		if (thread_is_64bit_addr(thr_act)) {
			return KERN_INVALID_ARGUMENT;
		}

		return fpu_set_fxstate(thr_act, tstate, flavor);
	}

	case x86_FLOAT_STATE64:
	case x86_AVX_STATE64:
	case x86_AVX512_STATE64:
	{
		if (count != _MachineStateCount[flavor]) {
			return KERN_INVALID_ARGUMENT;
		}

		if (!thread_is_64bit_addr(thr_act)) {
			return KERN_INVALID_ARGUMENT;
		}

		return fpu_set_fxstate(thr_act, tstate, flavor);
	}

	case x86_FLOAT_STATE:
	{
		x86_float_state_t       *state;

		if (count != x86_FLOAT_STATE_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		state = (x86_float_state_t *)tstate;
		if (state->fsh.flavor == x86_FLOAT_STATE64 && state->fsh.count == x86_FLOAT_STATE64_COUNT &&
		    thread_is_64bit_addr(thr_act)) {
			return fpu_set_fxstate(thr_act, (thread_state_t)&state->ufs.fs64, x86_FLOAT_STATE64);
		}
		if (state->fsh.flavor == x86_FLOAT_STATE32 && state->fsh.count == x86_FLOAT_STATE32_COUNT &&
		    !thread_is_64bit_addr(thr_act)) {
			return fpu_set_fxstate(thr_act, (thread_state_t)&state->ufs.fs32, x86_FLOAT_STATE32);
		}
		return KERN_INVALID_ARGUMENT;
	}

	case x86_AVX_STATE:
	case x86_AVX512_STATE:
	{
		x86_avx_state_t       *state;

		if (count != _MachineStateCount[flavor]) {
			return KERN_INVALID_ARGUMENT;
		}

		state = (x86_avx_state_t *)tstate;
		/* Flavors are defined to have sequential values: 32-bit, 64-bit, non-specific */
		/* 64-bit flavor? */
		if (state->ash.flavor == (flavor - 1) &&
		    state->ash.count == _MachineStateCount[flavor - 1] &&
		    thread_is_64bit_addr(thr_act)) {
			return fpu_set_fxstate(thr_act,
			           (thread_state_t)&state->ufs.as64,
			           flavor - 1);
		}
		/* 32-bit flavor? */
		if (state->ash.flavor == (flavor - 2) &&
		    state->ash.count == _MachineStateCount[flavor - 2] &&
		    !thread_is_64bit_addr(thr_act)) {
			return fpu_set_fxstate(thr_act,
			           (thread_state_t)&state->ufs.as32,
			           flavor - 2);
		}
		return KERN_INVALID_ARGUMENT;
	}

	case x86_THREAD_STATE32:
	{
		if (count != x86_THREAD_STATE32_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		if (thread_is_64bit_addr(thr_act)) {
			return KERN_INVALID_ARGUMENT;
		}

		return set_thread_state32(thr_act, (x86_thread_state32_t *)tstate);
	}

	case x86_THREAD_STATE64:
	{
		if (count != x86_THREAD_STATE64_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		if (!thread_is_64bit_addr(thr_act)) {
			return KERN_INVALID_ARGUMENT;
		}

		return set_thread_state64(thr_act, tstate, FALSE);
	}

	case x86_THREAD_FULL_STATE64:
	{
		if (count != x86_THREAD_FULL_STATE64_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		if (!thread_is_64bit_addr(thr_act)) {
			return KERN_INVALID_ARGUMENT;
		}

		/* If this process does not have a custom LDT, return failure */
		if (thr_act->task->i386_ldt == 0) {
			return KERN_INVALID_ARGUMENT;
		}

		return set_thread_state64(thr_act, tstate, TRUE);
	}

	case x86_THREAD_STATE:
	{
		x86_thread_state_t      *state;

		if (count != x86_THREAD_STATE_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		state = (x86_thread_state_t *)tstate;

		if (state->tsh.flavor == x86_THREAD_STATE64 &&
		    state->tsh.count == x86_THREAD_STATE64_COUNT &&
		    thread_is_64bit_addr(thr_act)) {
			return set_thread_state64(thr_act, &state->uts.ts64, FALSE);
		} else if (state->tsh.flavor == x86_THREAD_FULL_STATE64 &&
		    state->tsh.count == x86_THREAD_FULL_STATE64_COUNT &&
		    thread_is_64bit_addr(thr_act) && thr_act->task->i386_ldt != 0) {
			return set_thread_state64(thr_act, &state->uts.ts64, TRUE);
		} else if (state->tsh.flavor == x86_THREAD_STATE32 &&
		    state->tsh.count == x86_THREAD_STATE32_COUNT &&
		    !thread_is_64bit_addr(thr_act)) {
			return set_thread_state32(thr_act, &state->uts.ts32);
		} else {
			return KERN_INVALID_ARGUMENT;
		}
	}
	case x86_DEBUG_STATE32:
	{
		x86_debug_state32_t *state;
		kern_return_t ret;

		if (thread_is_64bit_addr(thr_act)) {
			return KERN_INVALID_ARGUMENT;
		}

		state = (x86_debug_state32_t *)tstate;

		ret = set_debug_state32(thr_act, state);

		return ret;
	}
	case x86_DEBUG_STATE64:
	{
		x86_debug_state64_t *state;
		kern_return_t ret;

		if (!thread_is_64bit_addr(thr_act)) {
			return KERN_INVALID_ARGUMENT;
		}

		state = (x86_debug_state64_t *)tstate;

		ret = set_debug_state64(thr_act, state);

		return ret;
	}
	case x86_DEBUG_STATE:
	{
		x86_debug_state_t *state;
		kern_return_t ret = KERN_INVALID_ARGUMENT;

		if (count != x86_DEBUG_STATE_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		state = (x86_debug_state_t *)tstate;
		if (state->dsh.flavor == x86_DEBUG_STATE64 &&
		    state->dsh.count == x86_DEBUG_STATE64_COUNT &&
		    thread_is_64bit_addr(thr_act)) {
			ret = set_debug_state64(thr_act, &state->uds.ds64);
		} else if (state->dsh.flavor == x86_DEBUG_STATE32 &&
		    state->dsh.count == x86_DEBUG_STATE32_COUNT &&
		    !thread_is_64bit_addr(thr_act)) {
			ret = set_debug_state32(thr_act, &state->uds.ds32);
		}
		return ret;
	}
	default:
		return KERN_INVALID_ARGUMENT;
	}

	return KERN_SUCCESS;
}

mach_vm_address_t
machine_thread_pc(thread_t thr_act)
{
	if (thread_is_64bit_addr(thr_act)) {
		return (mach_vm_address_t)USER_REGS64(thr_act)->isf.rip;
	} else {
		return (mach_vm_address_t)USER_REGS32(thr_act)->eip;
	}
}

void
machine_thread_reset_pc(thread_t thr_act, mach_vm_address_t pc)
{
	pal_register_cache_state(thr_act, DIRTY);

	if (thread_is_64bit_addr(thr_act)) {
		if (!IS_USERADDR64_CANONICAL(pc)) {
			pc = 0;
		}
		USER_REGS64(thr_act)->isf.rip = (uint64_t)pc;
	} else {
		USER_REGS32(thr_act)->eip = (uint32_t)pc;
	}
}


/*
 *	thread_getstatus:
 *
 *	Get the status of the specified thread.
 */

kern_return_t
machine_thread_get_state(
	thread_t thr_act,
	thread_flavor_t flavor,
	thread_state_t tstate,
	mach_msg_type_number_t *count)
{
	switch (flavor) {
	case THREAD_STATE_FLAVOR_LIST:
	{
		if (*count < 3) {
			return KERN_INVALID_ARGUMENT;
		}

		tstate[0] = i386_THREAD_STATE;
		tstate[1] = i386_FLOAT_STATE;
		tstate[2] = i386_EXCEPTION_STATE;

		*count = 3;
		break;
	}

	case THREAD_STATE_FLAVOR_LIST_NEW:
	{
		if (*count < 4) {
			return KERN_INVALID_ARGUMENT;
		}

		tstate[0] = x86_THREAD_STATE;
		tstate[1] = x86_FLOAT_STATE;
		tstate[2] = x86_EXCEPTION_STATE;
		tstate[3] = x86_DEBUG_STATE;

		*count = 4;
		break;
	}

	case THREAD_STATE_FLAVOR_LIST_10_9:
	{
		if (*count < 5) {
			return KERN_INVALID_ARGUMENT;
		}

		tstate[0] = x86_THREAD_STATE;
		tstate[1] = x86_FLOAT_STATE;
		tstate[2] = x86_EXCEPTION_STATE;
		tstate[3] = x86_DEBUG_STATE;
		tstate[4] = x86_AVX_STATE;

		*count = 5;
		break;
	}

	case THREAD_STATE_FLAVOR_LIST_10_13:
	{
		if (*count < 6) {
			return KERN_INVALID_ARGUMENT;
		}

		tstate[0] = x86_THREAD_STATE;
		tstate[1] = x86_FLOAT_STATE;
		tstate[2] = x86_EXCEPTION_STATE;
		tstate[3] = x86_DEBUG_STATE;
		tstate[4] = x86_AVX_STATE;
		tstate[5] = x86_AVX512_STATE;

		*count = 6;
		break;
	}

	case THREAD_STATE_FLAVOR_LIST_10_15:
	{
		if (*count < 7) {
			return KERN_INVALID_ARGUMENT;
		}

		tstate[0] = x86_THREAD_STATE;
		tstate[1] = x86_FLOAT_STATE;
		tstate[2] = x86_EXCEPTION_STATE;
		tstate[3] = x86_DEBUG_STATE;
		tstate[4] = x86_AVX_STATE;
		tstate[5] = x86_AVX512_STATE;
		tstate[6] = x86_PAGEIN_STATE;

		*count = 7;
		break;
	}

	case x86_SAVED_STATE32:
	{
		x86_saved_state32_t     *state;
		x86_saved_state32_t     *saved_state;

		if (*count < x86_SAVED_STATE32_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		if (thread_is_64bit_addr(thr_act)) {
			return KERN_INVALID_ARGUMENT;
		}

		state = (x86_saved_state32_t *) tstate;
		saved_state = USER_REGS32(thr_act);

		/*
		 * First, copy everything:
		 */
		*state = *saved_state;
		state->ds = saved_state->ds & 0xffff;
		state->es = saved_state->es & 0xffff;
		state->fs = saved_state->fs & 0xffff;
		state->gs = saved_state->gs & 0xffff;

		*count = x86_SAVED_STATE32_COUNT;
		break;
	}

	case x86_SAVED_STATE64:
	{
		x86_saved_state64_t     *state;
		x86_saved_state64_t     *saved_state;

		if (*count < x86_SAVED_STATE64_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		if (!thread_is_64bit_addr(thr_act)) {
			return KERN_INVALID_ARGUMENT;
		}

		state = (x86_saved_state64_t *)tstate;
		saved_state = USER_REGS64(thr_act);

		/*
		 * First, copy everything:
		 */
		*state = *saved_state;
		state->ds = saved_state->ds & 0xffff;
		state->es = saved_state->es & 0xffff;
		state->fs = saved_state->fs & 0xffff;
		state->gs = saved_state->gs & 0xffff;

		*count = x86_SAVED_STATE64_COUNT;
		break;
	}

	case x86_FLOAT_STATE32:
	{
		if (*count < x86_FLOAT_STATE32_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		if (thread_is_64bit_addr(thr_act)) {
			return KERN_INVALID_ARGUMENT;
		}

		*count = x86_FLOAT_STATE32_COUNT;

		return fpu_get_fxstate(thr_act, tstate, flavor);
	}

	case x86_FLOAT_STATE64:
	{
		if (*count < x86_FLOAT_STATE64_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		if (!thread_is_64bit_addr(thr_act)) {
			return KERN_INVALID_ARGUMENT;
		}

		*count = x86_FLOAT_STATE64_COUNT;

		return fpu_get_fxstate(thr_act, tstate, flavor);
	}

	case x86_FLOAT_STATE:
	{
		x86_float_state_t       *state;
		kern_return_t           kret;

		if (*count < x86_FLOAT_STATE_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		state = (x86_float_state_t *)tstate;

		/*
		 * no need to bzero... currently
		 * x86_FLOAT_STATE64_COUNT == x86_FLOAT_STATE32_COUNT
		 */
		if (thread_is_64bit_addr(thr_act)) {
			state->fsh.flavor = x86_FLOAT_STATE64;
			state->fsh.count  = x86_FLOAT_STATE64_COUNT;

			kret = fpu_get_fxstate(thr_act, (thread_state_t)&state->ufs.fs64, x86_FLOAT_STATE64);
		} else {
			state->fsh.flavor = x86_FLOAT_STATE32;
			state->fsh.count  = x86_FLOAT_STATE32_COUNT;

			kret = fpu_get_fxstate(thr_act, (thread_state_t)&state->ufs.fs32, x86_FLOAT_STATE32);
		}
		*count = x86_FLOAT_STATE_COUNT;

		return kret;
	}

	case x86_AVX_STATE32:
	case x86_AVX512_STATE32:
	{
		if (*count != _MachineStateCount[flavor]) {
			return KERN_INVALID_ARGUMENT;
		}

		if (thread_is_64bit_addr(thr_act)) {
			return KERN_INVALID_ARGUMENT;
		}

		*count = _MachineStateCount[flavor];

		return fpu_get_fxstate(thr_act, tstate, flavor);
	}

	case x86_AVX_STATE64:
	case x86_AVX512_STATE64:
	{
		if (*count != _MachineStateCount[flavor]) {
			return KERN_INVALID_ARGUMENT;
		}

		if (!thread_is_64bit_addr(thr_act)) {
			return KERN_INVALID_ARGUMENT;
		}

		*count = _MachineStateCount[flavor];

		return fpu_get_fxstate(thr_act, tstate, flavor);
	}

	case x86_AVX_STATE:
	case x86_AVX512_STATE:
	{
		x86_avx_state_t         *state;
		thread_state_t          fstate;

		if (*count < _MachineStateCount[flavor]) {
			return KERN_INVALID_ARGUMENT;
		}

		*count = _MachineStateCount[flavor];
		state = (x86_avx_state_t *)tstate;

		bzero((char *)state, *count * sizeof(int));

		if (thread_is_64bit_addr(thr_act)) {
			flavor -= 1;         /* 64-bit flavor */
			fstate = (thread_state_t) &state->ufs.as64;
		} else {
			flavor -= 2;         /* 32-bit flavor */
			fstate = (thread_state_t) &state->ufs.as32;
		}
		state->ash.flavor = flavor;
		state->ash.count  = _MachineStateCount[flavor];

		return fpu_get_fxstate(thr_act, fstate, flavor);
	}

	case x86_THREAD_STATE32:
	{
		if (*count < x86_THREAD_STATE32_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		if (thread_is_64bit_addr(thr_act)) {
			return KERN_INVALID_ARGUMENT;
		}

		*count = x86_THREAD_STATE32_COUNT;

		get_thread_state32(thr_act, (x86_thread_state32_t *)tstate);
		break;
	}

	case x86_THREAD_STATE64:
	{
		if (*count < x86_THREAD_STATE64_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		if (!thread_is_64bit_addr(thr_act)) {
			return KERN_INVALID_ARGUMENT;
		}

		*count = x86_THREAD_STATE64_COUNT;

		get_thread_state64(thr_act, tstate, FALSE);
		break;
	}

	case x86_THREAD_FULL_STATE64:
	{
		if (*count < x86_THREAD_FULL_STATE64_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		if (!thread_is_64bit_addr(thr_act)) {
			return KERN_INVALID_ARGUMENT;
		}

		/* If this process does not have a custom LDT, return failure */
		if (thr_act->task->i386_ldt == 0) {
			return KERN_INVALID_ARGUMENT;
		}

		*count = x86_THREAD_FULL_STATE64_COUNT;

		get_thread_state64(thr_act, tstate, TRUE);
		break;
	}

	case x86_THREAD_STATE:
	{
		x86_thread_state_t      *state;

		if (*count < x86_THREAD_STATE_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		state = (x86_thread_state_t *)tstate;

		bzero((char *)state, sizeof(x86_thread_state_t));

		if (thread_is_64bit_addr(thr_act)) {
			state->tsh.flavor = x86_THREAD_STATE64;
			state->tsh.count  = x86_THREAD_STATE64_COUNT;

			get_thread_state64(thr_act, &state->uts.ts64, FALSE);
		} else {
			state->tsh.flavor = x86_THREAD_STATE32;
			state->tsh.count  = x86_THREAD_STATE32_COUNT;

			get_thread_state32(thr_act, &state->uts.ts32);
		}
		*count = x86_THREAD_STATE_COUNT;

		break;
	}


	case x86_EXCEPTION_STATE32:
	{
		if (*count < x86_EXCEPTION_STATE32_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		if (thread_is_64bit_addr(thr_act)) {
			return KERN_INVALID_ARGUMENT;
		}

		*count = x86_EXCEPTION_STATE32_COUNT;

		get_exception_state32(thr_act, (x86_exception_state32_t *)tstate);
		/*
		 * Suppress the cpu number for binary compatibility
		 * of this deprecated state.
		 */
		((x86_exception_state32_t *)tstate)->cpu = 0;
		break;
	}

	case x86_EXCEPTION_STATE64:
	{
		if (*count < x86_EXCEPTION_STATE64_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		if (!thread_is_64bit_addr(thr_act)) {
			return KERN_INVALID_ARGUMENT;
		}

		*count = x86_EXCEPTION_STATE64_COUNT;

		get_exception_state64(thr_act, (x86_exception_state64_t *)tstate);
		/*
		 * Suppress the cpu number for binary compatibility
		 * of this deprecated state.
		 */
		((x86_exception_state64_t *)tstate)->cpu = 0;
		break;
	}

	case x86_EXCEPTION_STATE:
	{
		x86_exception_state_t   *state;

		if (*count < x86_EXCEPTION_STATE_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		state = (x86_exception_state_t *)tstate;

		bzero((char *)state, sizeof(x86_exception_state_t));

		if (thread_is_64bit_addr(thr_act)) {
			state->esh.flavor = x86_EXCEPTION_STATE64;
			state->esh.count  = x86_EXCEPTION_STATE64_COUNT;

			get_exception_state64(thr_act, &state->ues.es64);
		} else {
			state->esh.flavor = x86_EXCEPTION_STATE32;
			state->esh.count  = x86_EXCEPTION_STATE32_COUNT;

			get_exception_state32(thr_act, &state->ues.es32);
		}
		*count = x86_EXCEPTION_STATE_COUNT;

		break;
	}
	case x86_DEBUG_STATE32:
	{
		if (*count < x86_DEBUG_STATE32_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		if (thread_is_64bit_addr(thr_act)) {
			return KERN_INVALID_ARGUMENT;
		}

		get_debug_state32(thr_act, (x86_debug_state32_t *)tstate);

		*count = x86_DEBUG_STATE32_COUNT;

		break;
	}
	case x86_DEBUG_STATE64:
	{
		if (*count < x86_DEBUG_STATE64_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		if (!thread_is_64bit_addr(thr_act)) {
			return KERN_INVALID_ARGUMENT;
		}

		get_debug_state64(thr_act, (x86_debug_state64_t *)tstate);

		*count = x86_DEBUG_STATE64_COUNT;

		break;
	}
	case x86_DEBUG_STATE:
	{
		x86_debug_state_t   *state;

		if (*count < x86_DEBUG_STATE_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		state = (x86_debug_state_t *)tstate;

		bzero(state, sizeof *state);

		if (thread_is_64bit_addr(thr_act)) {
			state->dsh.flavor = x86_DEBUG_STATE64;
			state->dsh.count  = x86_DEBUG_STATE64_COUNT;

			get_debug_state64(thr_act, &state->uds.ds64);
		} else {
			state->dsh.flavor = x86_DEBUG_STATE32;
			state->dsh.count  = x86_DEBUG_STATE32_COUNT;

			get_debug_state32(thr_act, &state->uds.ds32);
		}
		*count = x86_DEBUG_STATE_COUNT;
		break;
	}

	case x86_PAGEIN_STATE:
	{
		if (*count < x86_PAGEIN_STATE_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		x86_pagein_state_t *state = (void *)tstate;

		state->__pagein_error = thr_act->t_pagein_error;

		*count = x86_PAGEIN_STATE_COUNT;
		break;
	}

	case x86_INSTRUCTION_STATE:
	{
		if (*count < x86_INSTRUCTION_STATE_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		x86_instruction_state_t *state = (void *)tstate;
		x86_instruction_state_t *src_state = THREAD_TO_PCB(thr_act)->insn_state;

		if (src_state != 0 && (src_state->insn_stream_valid_bytes > 0 || src_state->out_of_synch)) {
#if DEVELOPMENT || DEBUG
			extern int insnstream_force_cacheline_mismatch;
#endif
			size_t byte_count = (src_state->insn_stream_valid_bytes > x86_INSTRUCTION_STATE_MAX_INSN_BYTES)
			    ? x86_INSTRUCTION_STATE_MAX_INSN_BYTES : src_state->insn_stream_valid_bytes;
			if (byte_count > 0) {
				bcopy(src_state->insn_bytes, state->insn_bytes, byte_count);
			}
			state->insn_offset = src_state->insn_offset;
			state->insn_stream_valid_bytes = byte_count;
#if DEVELOPMENT || DEBUG
			state->out_of_synch = src_state->out_of_synch || insnstream_force_cacheline_mismatch;
			insnstream_force_cacheline_mismatch = 0;        /* One-shot, reset after use */

			if (state->out_of_synch) {
				bcopy(&src_state->insn_cacheline[0], &state->insn_cacheline[0],
				    x86_INSTRUCTION_STATE_CACHELINE_SIZE);
			} else {
				bzero(&state->insn_cacheline[0], x86_INSTRUCTION_STATE_CACHELINE_SIZE);
			}
#else
			state->out_of_synch = src_state->out_of_synch;
#endif
			*count = x86_INSTRUCTION_STATE_COUNT;
		} else {
			*count = 0;
		}
		break;
	}

	case x86_LAST_BRANCH_STATE:
	{
		boolean_t istate;

		if (!last_branch_support_enabled || *count < x86_LAST_BRANCH_STATE_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		istate = ml_set_interrupts_enabled(FALSE);
		/* If the current thread is asking for its own LBR data, synch the LBRs first */
		if (thr_act == current_thread()) {
			i386_lbr_synch(thr_act);
		}
		ml_set_interrupts_enabled(istate);

		if (i386_lbr_native_state_to_mach_thread_state(THREAD_TO_PCB(thr_act), (last_branch_state_t *)tstate) < 0) {
			*count = 0;
			return KERN_INVALID_ARGUMENT;
		}

		*count = x86_LAST_BRANCH_STATE_COUNT;
		break;
	}

	default:
		return KERN_INVALID_ARGUMENT;
	}

	return KERN_SUCCESS;
}

kern_return_t
machine_thread_get_kern_state(
	thread_t                thread,
	thread_flavor_t         flavor,
	thread_state_t          tstate,
	mach_msg_type_number_t  *count)
{
	x86_saved_state_t       *int_state = current_cpu_datap()->cpu_int_state;

	/*
	 * This works only for an interrupted kernel thread
	 */
	if (thread != current_thread() || int_state == NULL) {
		return KERN_FAILURE;
	}

	switch (flavor) {
	case x86_THREAD_STATE32: {
		x86_thread_state32_t *state;
		x86_saved_state32_t *saved_state;

		if (!is_saved_state32(int_state) ||
		    *count < x86_THREAD_STATE32_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		state = (x86_thread_state32_t *) tstate;

		saved_state = saved_state32(int_state);
		/*
		 * General registers.
		 */
		state->eax = saved_state->eax;
		state->ebx = saved_state->ebx;
		state->ecx = saved_state->ecx;
		state->edx = saved_state->edx;
		state->edi = saved_state->edi;
		state->esi = saved_state->esi;
		state->ebp = saved_state->ebp;
		state->esp = saved_state->uesp;
		state->eflags = saved_state->efl;
		state->eip = saved_state->eip;
		state->cs = saved_state->cs;
		state->ss = saved_state->ss;
		state->ds = saved_state->ds & 0xffff;
		state->es = saved_state->es & 0xffff;
		state->fs = saved_state->fs & 0xffff;
		state->gs = saved_state->gs & 0xffff;

		*count = x86_THREAD_STATE32_COUNT;

		return KERN_SUCCESS;
	}

	case x86_THREAD_STATE64: {
		x86_thread_state64_t    *state;
		x86_saved_state64_t     *saved_state;

		if (!is_saved_state64(int_state) ||
		    *count < x86_THREAD_STATE64_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		state = (x86_thread_state64_t *) tstate;

		saved_state = saved_state64(int_state);
		/*
		 * General registers.
		 */
		state->rax = saved_state->rax;
		state->rbx = saved_state->rbx;
		state->rcx = saved_state->rcx;
		state->rdx = saved_state->rdx;
		state->rdi = saved_state->rdi;
		state->rsi = saved_state->rsi;
		state->rbp = saved_state->rbp;
		state->rsp = saved_state->isf.rsp;
		state->r8 = saved_state->r8;
		state->r9 = saved_state->r9;
		state->r10 = saved_state->r10;
		state->r11 = saved_state->r11;
		state->r12 = saved_state->r12;
		state->r13 = saved_state->r13;
		state->r14 = saved_state->r14;
		state->r15 = saved_state->r15;

		state->rip = saved_state->isf.rip;
		state->rflags = saved_state->isf.rflags;
		state->cs = saved_state->isf.cs;
		state->fs = saved_state->fs & 0xffff;
		state->gs = saved_state->gs & 0xffff;
		*count = x86_THREAD_STATE64_COUNT;

		return KERN_SUCCESS;
	}

	case x86_THREAD_STATE: {
		x86_thread_state_t *state = NULL;

		if (*count < x86_THREAD_STATE_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		state = (x86_thread_state_t *) tstate;

		if (is_saved_state32(int_state)) {
			x86_saved_state32_t *saved_state = saved_state32(int_state);

			state->tsh.flavor = x86_THREAD_STATE32;
			state->tsh.count = x86_THREAD_STATE32_COUNT;

			/*
			 * General registers.
			 */
			state->uts.ts32.eax = saved_state->eax;
			state->uts.ts32.ebx = saved_state->ebx;
			state->uts.ts32.ecx = saved_state->ecx;
			state->uts.ts32.edx = saved_state->edx;
			state->uts.ts32.edi = saved_state->edi;
			state->uts.ts32.esi = saved_state->esi;
			state->uts.ts32.ebp = saved_state->ebp;
			state->uts.ts32.esp = saved_state->uesp;
			state->uts.ts32.eflags = saved_state->efl;
			state->uts.ts32.eip = saved_state->eip;
			state->uts.ts32.cs = saved_state->cs;
			state->uts.ts32.ss = saved_state->ss;
			state->uts.ts32.ds = saved_state->ds & 0xffff;
			state->uts.ts32.es = saved_state->es & 0xffff;
			state->uts.ts32.fs = saved_state->fs & 0xffff;
			state->uts.ts32.gs = saved_state->gs & 0xffff;
		} else if (is_saved_state64(int_state)) {
			x86_saved_state64_t *saved_state = saved_state64(int_state);

			state->tsh.flavor = x86_THREAD_STATE64;
			state->tsh.count = x86_THREAD_STATE64_COUNT;

			/*
			 * General registers.
			 */
			state->uts.ts64.rax = saved_state->rax;
			state->uts.ts64.rbx = saved_state->rbx;
			state->uts.ts64.rcx = saved_state->rcx;
			state->uts.ts64.rdx = saved_state->rdx;
			state->uts.ts64.rdi = saved_state->rdi;
			state->uts.ts64.rsi = saved_state->rsi;
			state->uts.ts64.rbp = saved_state->rbp;
			state->uts.ts64.rsp = saved_state->isf.rsp;
			state->uts.ts64.r8 = saved_state->r8;
			state->uts.ts64.r9 = saved_state->r9;
			state->uts.ts64.r10 = saved_state->r10;
			state->uts.ts64.r11 = saved_state->r11;
			state->uts.ts64.r12 = saved_state->r12;
			state->uts.ts64.r13 = saved_state->r13;
			state->uts.ts64.r14 = saved_state->r14;
			state->uts.ts64.r15 = saved_state->r15;

			state->uts.ts64.rip = saved_state->isf.rip;
			state->uts.ts64.rflags = saved_state->isf.rflags;
			state->uts.ts64.cs = saved_state->isf.cs;
			state->uts.ts64.fs = saved_state->fs & 0xffff;
			state->uts.ts64.gs = saved_state->gs & 0xffff;
		} else {
			panic("unknown thread state");
		}

		*count = x86_THREAD_STATE_COUNT;
		return KERN_SUCCESS;
	}
	}
	return KERN_FAILURE;
}


void
machine_thread_switch_addrmode(thread_t thread)
{
	/*
	 * We don't want to be preempted until we're done
	 * - particularly if we're switching the current thread
	 */
	disable_preemption();

	/*
	 * Reset the state saveareas. As we're resetting, we anticipate no
	 * memory allocations in this path.
	 */
	machine_thread_create(thread, thread->task);

	/* Adjust FPU state */
	fpu_switch_addrmode(thread, task_has_64Bit_addr(thread->task));

	/* If we're switching ourselves, reset the pcb addresses etc. */
	if (thread == current_thread()) {
		boolean_t istate = ml_set_interrupts_enabled(FALSE);
		act_machine_switch_pcb(NULL, thread);
		ml_set_interrupts_enabled(istate);
	}
	enable_preemption();
}



/*
 * This is used to set the current thr_act/thread
 * when starting up a new processor
 */
void
machine_set_current_thread(thread_t thread)
{
	current_cpu_datap()->cpu_active_thread = thread;
}


/*
 * Perform machine-dependent per-thread initializations
 */
void
machine_thread_init(void)
{
	fpu_module_init();
}

/*
 * machine_thread_template_init: Initialize machine-specific portion of
 * the thread template.
 */
void
machine_thread_template_init(thread_t thr_template)
{
	assert(fpu_default != UNDEFINED);

	THREAD_TO_PCB(thr_template)->xstate = fpu_default;
}

user_addr_t
get_useraddr(void)
{
	thread_t thr_act = current_thread();

	if (thread_is_64bit_addr(thr_act)) {
		x86_saved_state64_t     *iss64;

		iss64 = USER_REGS64(thr_act);

		return iss64->isf.rip;
	} else {
		x86_saved_state32_t     *iss32;

		iss32 = USER_REGS32(thr_act);

		return iss32->eip;
	}
}

/*
 * detach and return a kernel stack from a thread
 */

vm_offset_t
machine_stack_detach(thread_t thread)
{
	vm_offset_t     stack;

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_STACK_DETACH),
	    (uintptr_t)thread_tid(thread), thread->priority,
	    thread->sched_pri, 0,
	    0);

	stack = thread->kernel_stack;
	thread->kernel_stack = 0;

	return stack;
}

/*
 * attach a kernel stack to a thread and initialize it
 */

void
machine_stack_attach(
	thread_t                thread,
	vm_offset_t             stack)
{
	struct x86_kernel_state *statep;

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_STACK_ATTACH),
	    (uintptr_t)thread_tid(thread), thread->priority,
	    thread->sched_pri, 0, 0);

	assert(stack);
	thread->kernel_stack = stack;
	thread_initialize_kernel_state(thread);

	statep = STACK_IKS(stack);

	/*
	 * Reset the state of the thread to resume from a continuation,
	 * including resetting the stack and frame pointer to avoid backtracers
	 * seeing this temporary state and attempting to walk the defunct stack.
	 */
	statep->k_rbp = (uint64_t) 0;
	statep->k_rip = (uint64_t) Thread_continue;
	statep->k_rbx = (uint64_t) thread_continue;
	statep->k_rsp = (uint64_t) STACK_IKS(stack);

	return;
}

/*
 * move a stack from old to new thread
 */

void
machine_stack_handoff(thread_t old,
    thread_t new)
{
	vm_offset_t     stack;

	assert(new);
	assert(old);

	kpc_off_cpu(old);

	stack = old->kernel_stack;
	if (stack == old->reserved_stack) {
		assert(new->reserved_stack);
		old->reserved_stack = new->reserved_stack;
		new->reserved_stack = stack;
	}
	old->kernel_stack = 0;
	/*
	 * A full call to machine_stack_attach() is unnecessry
	 * because old stack is already initialized.
	 */
	new->kernel_stack = stack;

	fpu_switch_context(old, new);

	old->machine.specFlags &= ~OnProc;
	new->machine.specFlags |= OnProc;

	pmap_switch_context(old, new, cpu_number());
	act_machine_switch_pcb(old, new);

#if HYPERVISOR
	ml_hv_cswitch(old, new);
#endif

	machine_set_current_thread(new);
	thread_initialize_kernel_state(new);

	return;
}




struct x86_act_context32 {
	x86_saved_state32_t ss;
	x86_float_state32_t fs;
	x86_debug_state32_t ds;
};

struct x86_act_context64 {
	x86_saved_state64_t ss;
	x86_float_state64_t fs;
	x86_debug_state64_t ds;
};



void *
act_thread_csave(void)
{
	kern_return_t kret;
	mach_msg_type_number_t val;
	thread_t thr_act = current_thread();

	if (thread_is_64bit_addr(thr_act)) {
		struct x86_act_context64 *ic64;

		ic64 = (struct x86_act_context64 *)kalloc(sizeof(struct x86_act_context64));

		if (ic64 == (struct x86_act_context64 *)NULL) {
			return (void *)0;
		}

		val = x86_SAVED_STATE64_COUNT;
		kret = machine_thread_get_state(thr_act, x86_SAVED_STATE64,
		    (thread_state_t) &ic64->ss, &val);
		if (kret != KERN_SUCCESS) {
			kfree(ic64, sizeof(struct x86_act_context64));
			return (void *)0;
		}
		val = x86_FLOAT_STATE64_COUNT;
		kret = machine_thread_get_state(thr_act, x86_FLOAT_STATE64,
		    (thread_state_t) &ic64->fs, &val);
		if (kret != KERN_SUCCESS) {
			kfree(ic64, sizeof(struct x86_act_context64));
			return (void *)0;
		}

		val = x86_DEBUG_STATE64_COUNT;
		kret = machine_thread_get_state(thr_act,
		    x86_DEBUG_STATE64,
		    (thread_state_t)&ic64->ds,
		    &val);
		if (kret != KERN_SUCCESS) {
			kfree(ic64, sizeof(struct x86_act_context64));
			return (void *)0;
		}
		return ic64;
	} else {
		struct x86_act_context32 *ic32;

		ic32 = (struct x86_act_context32 *)kalloc(sizeof(struct x86_act_context32));

		if (ic32 == (struct x86_act_context32 *)NULL) {
			return (void *)0;
		}

		val = x86_SAVED_STATE32_COUNT;
		kret = machine_thread_get_state(thr_act, x86_SAVED_STATE32,
		    (thread_state_t) &ic32->ss, &val);
		if (kret != KERN_SUCCESS) {
			kfree(ic32, sizeof(struct x86_act_context32));
			return (void *)0;
		}
		val = x86_FLOAT_STATE32_COUNT;
		kret = machine_thread_get_state(thr_act, x86_FLOAT_STATE32,
		    (thread_state_t) &ic32->fs, &val);
		if (kret != KERN_SUCCESS) {
			kfree(ic32, sizeof(struct x86_act_context32));
			return (void *)0;
		}

		val = x86_DEBUG_STATE32_COUNT;
		kret = machine_thread_get_state(thr_act,
		    x86_DEBUG_STATE32,
		    (thread_state_t)&ic32->ds,
		    &val);
		if (kret != KERN_SUCCESS) {
			kfree(ic32, sizeof(struct x86_act_context32));
			return (void *)0;
		}
		return ic32;
	}
}


void
act_thread_catt(void *ctx)
{
	thread_t thr_act = current_thread();
	kern_return_t kret;

	if (ctx == (void *)NULL) {
		return;
	}

	if (thread_is_64bit_addr(thr_act)) {
		struct x86_act_context64 *ic64;

		ic64 = (struct x86_act_context64 *)ctx;

		kret = machine_thread_set_state(thr_act, x86_SAVED_STATE64,
		    (thread_state_t) &ic64->ss, x86_SAVED_STATE64_COUNT);
		if (kret == KERN_SUCCESS) {
			machine_thread_set_state(thr_act, x86_FLOAT_STATE64,
			    (thread_state_t) &ic64->fs, x86_FLOAT_STATE64_COUNT);
		}
		kfree(ic64, sizeof(struct x86_act_context64));
	} else {
		struct x86_act_context32 *ic32;

		ic32 = (struct x86_act_context32 *)ctx;

		kret = machine_thread_set_state(thr_act, x86_SAVED_STATE32,
		    (thread_state_t) &ic32->ss, x86_SAVED_STATE32_COUNT);
		if (kret == KERN_SUCCESS) {
			(void) machine_thread_set_state(thr_act, x86_FLOAT_STATE32,
			    (thread_state_t) &ic32->fs, x86_FLOAT_STATE32_COUNT);
		}
		kfree(ic32, sizeof(struct x86_act_context32));
	}
}


void
act_thread_cfree(__unused void *ctx)
{
	/* XXX - Unused */
}

/*
 * Duplicate one x86_debug_state32_t to another.  "all" parameter
 * chooses whether dr4 and dr5 are copied (they are never meant
 * to be installed when we do machine_task_set_state() or
 * machine_thread_set_state()).
 */
void
copy_debug_state32(
	x86_debug_state32_t *src,
	x86_debug_state32_t *target,
	boolean_t all)
{
	if (all) {
		target->dr4 = src->dr4;
		target->dr5 = src->dr5;
	}

	target->dr0 = src->dr0;
	target->dr1 = src->dr1;
	target->dr2 = src->dr2;
	target->dr3 = src->dr3;
	target->dr6 = src->dr6;
	target->dr7 = src->dr7;
}

/*
 * Duplicate one x86_debug_state64_t to another.  "all" parameter
 * chooses whether dr4 and dr5 are copied (they are never meant
 * to be installed when we do machine_task_set_state() or
 * machine_thread_set_state()).
 */
void
copy_debug_state64(
	x86_debug_state64_t *src,
	x86_debug_state64_t *target,
	boolean_t all)
{
	if (all) {
		target->dr4 = src->dr4;
		target->dr5 = src->dr5;
	}

	target->dr0 = src->dr0;
	target->dr1 = src->dr1;
	target->dr2 = src->dr2;
	target->dr3 = src->dr3;
	target->dr6 = src->dr6;
	target->dr7 = src->dr7;
}
