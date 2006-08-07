/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1992-1990 Carnegie Mellon University
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

#include <platforms.h>

#include <mach/exception_types.h>
#include <mach/i386/thread_status.h>
#include <mach/i386/fp_reg.h>

#include <kern/mach_param.h>
#include <kern/processor.h>
#include <kern/thread.h>
#include <kern/zalloc.h>
#include <kern/misc_protos.h>
#include <kern/spl.h>
#include <kern/assert.h>

#include <i386/thread.h>
#include <i386/fpu.h>
#include <i386/trap.h>
#include <architecture/i386/pio.h>
#include <i386/cpuid.h>
#include <i386/misc_protos.h>
#include <i386/proc_reg.h>

int		fp_kind = FP_NO;	/* not inited */
zone_t		ifps_zone;		/* zone for FPU save area */

#define ALIGNED(addr,size)	(((unsigned)(addr)&((size)-1))==0)

/* Forward */

extern void		fpinit(void);
extern void		fp_save(
				thread_t	thr_act);
extern void		fp_load(
				thread_t	thr_act);

static void configure_mxcsr_capability_mask(struct x86_fpsave_state *ifps);

struct x86_fpsave_state starting_fp_state;


/* Global MXCSR capability bitmask */
static unsigned int mxcsr_capability_mask;

/*
 * Determine the MXCSR capability mask, which allows us to mask off any
 * potentially unsafe "reserved" bits before restoring the FPU context.
 * *Not* per-cpu, assumes symmetry.
 */
static void
configure_mxcsr_capability_mask(struct x86_fpsave_state *ifps)
{
	/* FXSAVE requires a 16 byte aligned store */
	assert(ALIGNED(ifps,16));
	/* Clear, to prepare for the diagnostic FXSAVE */
	bzero(ifps, sizeof(*ifps));
	/* Disable FPU/SSE Device Not Available exceptions */
	clear_ts();

	__asm__ volatile("fxsave %0" : "=m" (ifps->fx_save_state));
	mxcsr_capability_mask = ifps->fx_save_state.fx_MXCSR_MASK;

	/* Set default mask value if necessary */
	if (mxcsr_capability_mask == 0)
		mxcsr_capability_mask = 0xffbf;
	
	/* Re-enable FPU/SSE DNA exceptions */
	set_ts();
}

/*
 * Allocate and initialize FP state for current thread.
 * Don't load state.
 */
static struct x86_fpsave_state *
fp_state_alloc(void)
{
	struct x86_fpsave_state *ifps;

	ifps = (struct x86_fpsave_state *)zalloc(ifps_zone);
	assert(ALIGNED(ifps,16));
	bzero((char *)ifps, sizeof *ifps);

	return ifps;
}

static inline void
fp_state_free(struct x86_fpsave_state *ifps)
{
	zfree(ifps_zone, ifps);
}


/*
 * Look for FPU and initialize it.
 * Called on each CPU.
 */
void
init_fpu(void)
{
	unsigned short	status, control;

	/*
	 * Check for FPU by initializing it,
	 * then trying to read the correct bit patterns from
	 * the control and status registers.
	 */
	set_cr0((get_cr0() & ~(CR0_EM|CR0_TS)) | CR0_NE);	/* allow use of FPU */

	fninit();
	status = fnstsw();
	fnstcw(&control);

	if ((status & 0xff) == 0 &&
	    (control & 0x103f) == 0x3f) 
        {
	    /* Use FPU save/restore instructions if available */
		if (cpuid_features() & CPUID_FEATURE_FXSR) {
		        fp_kind = FP_FXSR;
			set_cr4(get_cr4() | CR4_FXS);
			printf("Enabling XMM register save/restore");
			/* And allow SIMD instructions if present */
			if (cpuid_features() & CPUID_FEATURE_SSE) {
		    	printf(" and SSE/SSE2");
		    	set_cr4(get_cr4() | CR4_XMM);
			}
			printf(" opcodes\n");
	    } else
			panic("fpu is not FP_FXSR");

	    /*
	     * initialze FPU to normal starting 
	     * position so that we can take a snapshot
	     * of that state and store it for future use
	     * when we're asked for the FPU state of a 
	     * thread, and it hasn't initiated any yet
	     */
	     fpinit();
	     fxsave(&starting_fp_state.fx_save_state);

	     /*
	      * Trap wait instructions.  Turn off FPU for now.
	      */
	     set_cr0(get_cr0() | CR0_TS | CR0_MP);
	}
	else
	{
	    /*
	     * NO FPU.
	     */
		panic("fpu is not FP_FXSR");
	}
}

/*
 * Initialize FP handling.
 */
void
fpu_module_init(void)
{
	struct x86_fpsave_state *new_ifps;
	
	ifps_zone = zinit(sizeof(struct x86_fpsave_state),
			  THREAD_MAX * sizeof(struct x86_fpsave_state),
			  THREAD_CHUNK * sizeof(struct x86_fpsave_state),
			  "x86 fpsave state");
	new_ifps = fp_state_alloc();
	/* Determine MXCSR reserved bits */
	configure_mxcsr_capability_mask(new_ifps);
	fp_state_free(new_ifps);
}

/*
 * Free a FPU save area.
 * Called only when thread terminating - no locking necessary.
 */
void
fpu_free(fps)
	struct x86_fpsave_state *fps;
{
	fp_state_free(fps);
}

/*
 * Set the floating-point state for a thread based 
 * on the FXSave formatted data. This is basically  
 * the same as fpu_set_state except it uses the 
 * expanded data structure. 
 * If the thread is not the current thread, it is
 * not running (held).  Locking needed against
 * concurrent fpu_set_state or fpu_get_state.
 */
kern_return_t
fpu_set_fxstate(
	thread_t	thr_act,
	thread_state_t	tstate)
{
	struct x86_fpsave_state	*ifps;
	struct x86_fpsave_state *new_ifps;
	x86_float_state64_t	*state;
	pcb_t	pcb;

	if (fp_kind == FP_NO)
	        return KERN_FAILURE;

	state = (x86_float_state64_t *)tstate;

	assert(thr_act != THREAD_NULL);
	pcb = thr_act->machine.pcb;

	if (state == NULL) {
	        /*
		 * new FPU state is 'invalid'.
		 * Deallocate the fp state if it exists.
		 */
	        simple_lock(&pcb->lock);

		ifps = pcb->ifps;
		pcb->ifps = 0;

		simple_unlock(&pcb->lock);

		if (ifps != 0)
		        fp_state_free(ifps);
	} else {
	        /*
		 * Valid state.  Allocate the fp state if there is none.
		 */
	        new_ifps = 0;
	Retry:
		simple_lock(&pcb->lock);

		ifps = pcb->ifps;
		if (ifps == 0) {
		        if (new_ifps == 0) {
			        simple_unlock(&pcb->lock);
				new_ifps = fp_state_alloc();
				goto Retry;
			}
			ifps = new_ifps;
			new_ifps = 0;
			pcb->ifps = ifps;
		}
		/*
		 * now copy over the new data.
		 */
		bcopy((char *)&state->fpu_fcw,
		      (char *)&ifps->fx_save_state, sizeof(struct x86_fx_save));

		/* XXX The layout of the state set from user-space may need to be
		 * validated for consistency.
		 */
		ifps->fp_save_layout = thread_is_64bit(thr_act) ? FXSAVE64 : FXSAVE32;
		/* Mark the thread's floating point status as non-live. */
		ifps->fp_valid = TRUE;
		/*
		 * Clear any reserved bits in the MXCSR to prevent a GPF
		 * when issuing an FXRSTOR.
		 */
		ifps->fx_save_state.fx_MXCSR &= mxcsr_capability_mask;

		simple_unlock(&pcb->lock);

		if (new_ifps != 0)
		        fp_state_free(new_ifps);
	}
	return KERN_SUCCESS;
}

/*
 * Get the floating-point state for a thread.
 * If the thread is not the current thread, it is
 * not running (held).  Locking needed against
 * concurrent fpu_set_state or fpu_get_state.
 */
kern_return_t
fpu_get_fxstate(
	thread_t	thr_act,
	thread_state_t	tstate)
{
	struct x86_fpsave_state	*ifps;
	x86_float_state64_t	*state;
	kern_return_t	ret = KERN_FAILURE;
	pcb_t	pcb;

	if (fp_kind == FP_NO)
	    return KERN_FAILURE;

	state = (x86_float_state64_t *)tstate;

	assert(thr_act != THREAD_NULL);
	pcb = thr_act->machine.pcb;

	simple_lock(&pcb->lock);

	ifps = pcb->ifps;
	if (ifps == 0) {
	        /*
		 * No valid floating-point state.
		 */
	        bcopy((char *)&starting_fp_state.fx_save_state,
		      (char *)&state->fpu_fcw, sizeof(struct x86_fx_save));

		simple_unlock(&pcb->lock);

		return KERN_SUCCESS;
	}
	/*
	 * Make sure we`ve got the latest fp state info
	 * If the live fpu state belongs to our target
	 */
	if (thr_act == current_thread())
	{
	        boolean_t	intr;

		intr = ml_set_interrupts_enabled(FALSE);

		clear_ts();
		fp_save(thr_act);
		clear_fpu();

		(void)ml_set_interrupts_enabled(intr);
	}
	if (ifps->fp_valid) {
        	bcopy((char *)&ifps->fx_save_state,
	      	      (char *)&state->fpu_fcw, sizeof(struct x86_fx_save));
		ret = KERN_SUCCESS;
	}
	simple_unlock(&pcb->lock);

	return ret;
}


/*
 * the child thread is 'stopped' with the thread
 * mutex held and is currently not known by anyone
 * so no way for fpu state to get manipulated by an
 * outside agency -> no need for pcb lock
 */

void
fpu_dup_fxstate(
	thread_t	parent,
	thread_t	child)
{
	struct x86_fpsave_state *new_ifps = NULL;
        boolean_t	intr;
	pcb_t		ppcb;

	ppcb = parent->machine.pcb;

	if (ppcb->ifps == NULL)
	        return;

        if (child->machine.pcb->ifps)
	        panic("fpu_dup_fxstate: child's ifps non-null");

	new_ifps = fp_state_alloc();

	simple_lock(&ppcb->lock);

	if (ppcb->ifps != NULL) {
	        /*
		 * Make sure we`ve got the latest fp state info
		 */
	        intr = ml_set_interrupts_enabled(FALSE);

		clear_ts();
		fp_save(parent);
		clear_fpu();

		(void)ml_set_interrupts_enabled(intr);

		if (ppcb->ifps->fp_valid) {
		        child->machine.pcb->ifps = new_ifps;

			bcopy((char *)&(ppcb->ifps->fx_save_state),
			      (char *)&(child->machine.pcb->ifps->fx_save_state), sizeof(struct x86_fx_save));

			new_ifps->fp_save_layout = ppcb->ifps->fp_save_layout;
			/* Mark the new fp saved state as non-live. */
			new_ifps->fp_valid = TRUE;
			/*
			 * Clear any reserved bits in the MXCSR to prevent a GPF
			 * when issuing an FXRSTOR.
			 */
			new_ifps->fx_save_state.fx_MXCSR &= mxcsr_capability_mask;
			new_ifps = NULL;
		}
	}
	simple_unlock(&ppcb->lock);

	if (new_ifps != NULL)
	        fp_state_free(new_ifps);
}


/*
 * Initialize FPU.
 *
 */
void
fpinit(void)
{
	unsigned short	control;

	clear_ts();
	fninit();
	fnstcw(&control);
	control &= ~(FPC_PC|FPC_RC); /* Clear precision & rounding control */
	control |= (FPC_PC_64 |		/* Set precision */ 
			FPC_RC_RN | 	/* round-to-nearest */
			FPC_ZE |	/* Suppress zero-divide */
			FPC_OE |	/*  and overflow */
			FPC_UE |	/*  underflow */
			FPC_IE |	/* Allow NaNQs and +-INF */
			FPC_DE |	/* Allow denorms as operands  */
			FPC_PE);	/* No trap for precision loss */
	fldcw(control);

	/* Initialize SSE/SSE2 */
	__builtin_ia32_ldmxcsr(0x1f80);
}

/*
 * Coprocessor not present.
 */

void
fpnoextflt(void)
{
	boolean_t	intr;

	intr = ml_set_interrupts_enabled(FALSE);

	clear_ts();			/*  Enable FPU use */

	if (get_interrupt_level()) {
		/*
		 * Save current coprocessor context if valid
		 * Initialize coprocessor live context
		 */
		fp_save(current_thread());
		fpinit();
	} else {
		/*
		 * Load this thread`s state into coprocessor live context.
		 */
		fp_load(current_thread());
	}

	(void)ml_set_interrupts_enabled(intr);
}

/*
 * FPU overran end of segment.
 * Re-initialize FPU.  Floating point state is not valid.
 */

void
fpextovrflt(void)
{
	thread_t	thr_act = current_thread();
	pcb_t		pcb;
	struct x86_fpsave_state *ifps;
	boolean_t	intr;

	intr = ml_set_interrupts_enabled(FALSE);

	if (get_interrupt_level())
		panic("FPU segment overrun exception at interrupt context\n");
	if (current_task() == kernel_task)
		panic("FPU segment overrun exception in kernel thread context\n");

	/*
	 * This is a non-recoverable error.
	 * Invalidate the thread`s FPU state.
	 */
	pcb = thr_act->machine.pcb;
	simple_lock(&pcb->lock);
	ifps = pcb->ifps;
	pcb->ifps = 0;
	simple_unlock(&pcb->lock);

	/*
	 * Re-initialize the FPU.
	 */
	clear_ts();
	fninit();

	/*
	 * And disable access.
	 */
	clear_fpu();

	(void)ml_set_interrupts_enabled(intr);

	if (ifps)
	    zfree(ifps_zone, ifps);

	/*
	 * Raise exception.
	 */
	i386_exception(EXC_BAD_ACCESS, VM_PROT_READ|VM_PROT_EXECUTE, 0);
	/*NOTREACHED*/
}

/*
 * FPU error. Called by AST.
 */

void
fpexterrflt(void)
{
	thread_t	thr_act = current_thread();
	struct x86_fpsave_state *ifps = thr_act->machine.pcb->ifps;
	boolean_t	intr;

	intr = ml_set_interrupts_enabled(FALSE);

	if (get_interrupt_level())
		panic("FPU error exception at interrupt context\n");
	if (current_task() == kernel_task)
		panic("FPU error exception in kernel thread context\n");

	/*
	 * Save the FPU state and turn off the FPU.
	 */
	fp_save(thr_act);

	(void)ml_set_interrupts_enabled(intr);

	/*
	 * Raise FPU exception.
	 * Locking not needed on pcb->ifps,
	 * since thread is running.
	 */
	i386_exception(EXC_ARITHMETIC,
		       EXC_I386_EXTERR,
		       ifps->fx_save_state.fx_status);

	/*NOTREACHED*/
}

/*
 * Save FPU state.
 *
 * Locking not needed:
 * .	if called from fpu_get_state, pcb already locked.
 * .	if called from fpnoextflt or fp_intr, we are single-cpu
 * .	otherwise, thread is running.
 * N.B.: Must be called with interrupts disabled
 */

void
fp_save(
	thread_t	thr_act)
{
	pcb_t pcb = thr_act->machine.pcb;
	struct x86_fpsave_state *ifps = pcb->ifps;

	if (ifps != 0 && !ifps->fp_valid) {
		assert((get_cr0() & CR0_TS) == 0);
		/* registers are in FPU */
		ifps->fp_valid = TRUE;

		if (!thread_is_64bit(thr_act)) {
			/* save the compatibility/legacy mode XMM+x87 state */
			fxsave(&ifps->fx_save_state);
			ifps->fp_save_layout = FXSAVE32;
		}
		else {
			fxsave64(&ifps->fx_save_state);
			ifps->fp_save_layout = FXSAVE64;
		}
	}
}

/*
 * Restore FPU state from PCB.
 *
 * Locking not needed; always called on the current thread.
 */

void
fp_load(
	thread_t	thr_act)
{
	pcb_t pcb = thr_act->machine.pcb;
	struct x86_fpsave_state *ifps;

	ifps = pcb->ifps;
	if (ifps == 0 || ifps->fp_valid == FALSE) {
		if (ifps == 0) {
			/* FIXME: This allocation mechanism should be revised
			 * for scenarios where interrupts are disabled.
			 */
			ifps = fp_state_alloc();
			pcb->ifps = ifps;
		}
		fpinit();
	} else {
		assert(ifps->fp_save_layout == FXSAVE32 || ifps->fp_save_layout == FXSAVE64);
		if (ifps->fp_save_layout == FXSAVE32) {
			/* Restore the compatibility/legacy mode XMM+x87 state */
			fxrstor(&ifps->fx_save_state);
		}
		else if (ifps->fp_save_layout == FXSAVE64) {
			fxrstor64(&ifps->fx_save_state);
		}
	}
	ifps->fp_valid = FALSE;		/* in FPU */
}



/*
 * fpflush(thread_t)
 *	Flush the current act's state, if needed
 *	(used by thread_terminate_self to ensure fp faults
 *	aren't satisfied by overly general trap code in the
 *	context of the reaper thread)
 */
void
fpflush(__unused thread_t thr_act)
{
	/* not needed on MP x86s; fp not lazily evaluated */
}

/*
 * SSE arithmetic exception handling code.
 * Basically the same as the x87 exception handler with a different subtype
 */

void
fpSSEexterrflt(void)
{
	thread_t	thr_act = current_thread();
	struct x86_fpsave_state *ifps = thr_act->machine.pcb->ifps;
	boolean_t	intr;

	intr = ml_set_interrupts_enabled(FALSE);

	if (get_interrupt_level())
		panic("SSE exception at interrupt context\n");
	if (current_task() == kernel_task)
		panic("SSE exception in kernel thread context\n");

	/*
	 * Save the FPU state and turn off the FPU.
	 */
	fp_save(thr_act);

	(void)ml_set_interrupts_enabled(intr);
	/*
	 * Raise FPU exception.
	 * Locking not needed on pcb->ifps,
	 * since thread is running.
	 */
	assert(ifps->fp_save_layout == FXSAVE32 || ifps->fp_save_layout == FXSAVE64);
	i386_exception(EXC_ARITHMETIC,
		       EXC_I386_SSEEXTERR,
		       ifps->fx_save_state.fx_status);
	/*NOTREACHED*/
}


void
fp_setvalid(boolean_t value) {
        thread_t	thr_act = current_thread();
	struct x86_fpsave_state *ifps = thr_act->machine.pcb->ifps;

	if (ifps) {
	        ifps->fp_valid = value;

		if (value == TRUE)
		        clear_fpu();
	}
}
