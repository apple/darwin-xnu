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
#include <i386/pio.h>
#include <i386/cpuid.h>
#include <i386/misc_protos.h>

#if 0
#include <i386/ipl.h>
extern int curr_ipl;
#define ASSERT_IPL(L) \
{ \
      if (curr_ipl != L) { \
	      printf("IPL is %d, expected %d\n", curr_ipl, L); \
	      panic("fpu: wrong ipl"); \
      } \
}
#else
#define ASSERT_IPL(L)
#endif

int		fp_kind = FP_387;	/* 80387 present */
zone_t		ifps_zone;		/* zone for FPU save area */

#define	clear_fpu() \
    { \
	set_ts(); \
    }

#define ALIGNED(addr,size)	(((unsigned)(addr)&((size)-1))==0)

/* Forward */

extern void		fpinit(void);
extern void		fp_save(
				thread_t	thr_act);
extern void		fp_load(
				thread_t	thr_act);

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
            fp_kind = FP_387;	/* assume we have a 387 compatible instruction set */
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
	    }

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
	    fp_kind = FP_NO;
	    set_cr0(get_cr0() | CR0_EM);
	}
}

/*
 * Initialize FP handling.
 */
void
fpu_module_init(void)
{
	ifps_zone = zinit(sizeof(struct i386_fpsave_state),
			  THREAD_MAX * sizeof(struct i386_fpsave_state),
			  THREAD_CHUNK * sizeof(struct i386_fpsave_state),
			  "i386 fpsave state");
}

/*
 * Free a FPU save area.
 * Called only when thread terminating - no locking necessary.
 */
void
fpu_free(fps)
	struct i386_fpsave_state *fps;
{
ASSERT_IPL(SPL0);
	zfree(ifps_zone, fps);
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
	thread_t		thr_act,
	struct i386_float_state	*state)
{
	register pcb_t	pcb;
	register struct i386_fpsave_state *ifps;
	register struct i386_fpsave_state *new_ifps;

ASSERT_IPL(SPL0);
	if (fp_kind == FP_NO)
	    return KERN_FAILURE;

        if (state->fpkind != FP_FXSR) {
            /* strange if this happens, but in case someone builds one of these manually... */
            return fpu_set_state(thr_act, state);
        }
        
	assert(thr_act != THREAD_NULL);
	pcb = thr_act->machine.pcb;

	if (state->initialized == 0) {
	    /*
	     * new FPU state is 'invalid'.
	     * Deallocate the fp state if it exists.
	     */
	    simple_lock(&pcb->lock);
	    ifps = pcb->ims.ifps;
	    pcb->ims.ifps = 0;
	    simple_unlock(&pcb->lock);

	    if (ifps != 0) {
		zfree(ifps_zone, ifps);
	    }
	}
	else {
	    /*
	     * Valid state.  Allocate the fp state if there is none.
	     */

	    new_ifps = 0;
	Retry:
	    simple_lock(&pcb->lock);
	    ifps = pcb->ims.ifps;
	    if (ifps == 0) {
		if (new_ifps == 0) {
		    simple_unlock(&pcb->lock);
		    new_ifps = (struct i386_fpsave_state *) zalloc(ifps_zone);
		    assert(ALIGNED(new_ifps,16));
		    goto Retry;
		}
		ifps = new_ifps;
		new_ifps = 0;
                bzero((char *)ifps, sizeof *ifps);
		pcb->ims.ifps = ifps;
	    }

	    /*
	     * now copy over the new data.
	     */
            bcopy((char *)&state->hw_state[0], (char *)&ifps->fx_save_state, sizeof(struct i386_fx_save));
            ifps->fp_save_flavor = FP_FXSR;
	    simple_unlock(&pcb->lock);
	    if (new_ifps != 0)
		zfree(ifps_zone, ifps);
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
	thread_t				thr_act,
	register struct i386_float_state	*state)
{
	register pcb_t	pcb;
	register struct i386_fpsave_state *ifps;

ASSERT_IPL(SPL0);
	if (fp_kind == FP_NO) {
	    return KERN_FAILURE;
	} else if (fp_kind == FP_387) {
	    return fpu_get_state(thr_act, state);
	}

	assert(thr_act != THREAD_NULL);
	pcb = thr_act->machine.pcb;

	simple_lock(&pcb->lock);
	ifps = pcb->ims.ifps;
	if (ifps == 0) {
	    /*
	     * No valid floating-point state.
	     */
	    simple_unlock(&pcb->lock);
	    bzero((char *)state, sizeof(struct i386_float_state));
	    return KERN_SUCCESS;
	}

	/* Make sure we`ve got the latest fp state info */
	/* If the live fpu state belongs to our target */
	if (thr_act == current_thread())
	{
	    clear_ts();
	    fp_save(thr_act);
	    clear_fpu();
	}

	state->fpkind = fp_kind;
	state->exc_status = 0;
        state->initialized = ifps->fp_valid;
        bcopy( (char *)&ifps->fx_save_state, (char *)&state->hw_state[0], sizeof(struct i386_fx_save));

	simple_unlock(&pcb->lock);

	return KERN_SUCCESS;
}

/*
 * Set the floating-point state for a thread.
 * If the thread is not the current thread, it is
 * not running (held).  Locking needed against
 * concurrent fpu_set_state or fpu_get_state.
 */
kern_return_t
fpu_set_state(
	thread_t		thr_act,
	struct i386_float_state	*state)
{
	register pcb_t	pcb;
	register struct i386_fpsave_state *ifps;
	register struct i386_fpsave_state *new_ifps;

ASSERT_IPL(SPL0);
	if (fp_kind == FP_NO)
	    return KERN_FAILURE;

	assert(thr_act != THREAD_NULL);
	pcb = thr_act->machine.pcb;

	if (state->initialized == 0) {
	    /*
	     * new FPU state is 'invalid'.
	     * Deallocate the fp state if it exists.
	     */
	    simple_lock(&pcb->lock);
	    ifps = pcb->ims.ifps;
	    pcb->ims.ifps = 0;
	    simple_unlock(&pcb->lock);

	    if (ifps != 0) {
		zfree(ifps_zone, ifps);
	    }
	}
	else {
	    /*
	     * Valid state.  Allocate the fp state if there is none.
	     */
	    register struct i386_fp_save *user_fp_state;
	    register struct i386_fp_regs *user_fp_regs;

	    user_fp_state = (struct i386_fp_save *) &state->hw_state[0];
	    user_fp_regs  = (struct i386_fp_regs *)
			&state->hw_state[sizeof(struct i386_fp_save)];

	    new_ifps = 0;
	Retry:
	    simple_lock(&pcb->lock);
	    ifps = pcb->ims.ifps;
	    if (ifps == 0) {
		if (new_ifps == 0) {
		    simple_unlock(&pcb->lock);
		    new_ifps = (struct i386_fpsave_state *) zalloc(ifps_zone);
		    assert(ALIGNED(new_ifps,16));
		    goto Retry;
		}
		ifps = new_ifps;
		new_ifps = 0;
                bzero((char *)ifps, sizeof *ifps); // zero ALL fields first
		pcb->ims.ifps = ifps;
	    }

	    /*
	     * Ensure that reserved parts of the environment are 0.
	     */
	    bzero((char *)&ifps->fp_save_state, sizeof(struct i386_fp_save));

	    ifps->fp_save_state.fp_control = user_fp_state->fp_control;
	    ifps->fp_save_state.fp_status  = user_fp_state->fp_status;
	    ifps->fp_save_state.fp_tag     = user_fp_state->fp_tag;
	    ifps->fp_save_state.fp_eip     = user_fp_state->fp_eip;
	    ifps->fp_save_state.fp_cs      = user_fp_state->fp_cs;
	    ifps->fp_save_state.fp_opcode  = user_fp_state->fp_opcode;
	    ifps->fp_save_state.fp_dp      = user_fp_state->fp_dp;
	    ifps->fp_save_state.fp_ds      = user_fp_state->fp_ds;
	    ifps->fp_regs = *user_fp_regs;
            ifps->fp_save_flavor = FP_387;
	    simple_unlock(&pcb->lock);
	    if (new_ifps != 0)
		zfree(ifps_zone, ifps);
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
fpu_get_state(
	thread_t				thr_act,
	register struct i386_float_state	*state)
{
	register pcb_t	pcb;
	register struct i386_fpsave_state *ifps;

ASSERT_IPL(SPL0);
	if (fp_kind == FP_NO)
	    return KERN_FAILURE;

	assert(thr_act != THREAD_NULL);
	pcb = thr_act->machine.pcb;

	simple_lock(&pcb->lock);
	ifps = pcb->ims.ifps;
	if (ifps == 0) {
	    /*
	     * No valid floating-point state.
	     */
	    simple_unlock(&pcb->lock);
	    bzero((char *)state, sizeof(struct i386_float_state));
	    return KERN_SUCCESS;
	}

	/* Make sure we`ve got the latest fp state info */
	/* If the live fpu state belongs to our target */
	if (thr_act == current_thread())
	{
	    clear_ts();
	    fp_save(thr_act);
	    clear_fpu();
	}

	state->fpkind = fp_kind;
	state->exc_status = 0;

	{
	    register struct i386_fp_save *user_fp_state;
	    register struct i386_fp_regs *user_fp_regs;

	    state->initialized = ifps->fp_valid;

	    user_fp_state = (struct i386_fp_save *) &state->hw_state[0];
	    user_fp_regs  = (struct i386_fp_regs *)
			&state->hw_state[sizeof(struct i386_fp_save)];

	    /*
	     * Ensure that reserved parts of the environment are 0.
	     */
	    bzero((char *)user_fp_state,  sizeof(struct i386_fp_save));

	    user_fp_state->fp_control = ifps->fp_save_state.fp_control;
	    user_fp_state->fp_status  = ifps->fp_save_state.fp_status;
	    user_fp_state->fp_tag     = ifps->fp_save_state.fp_tag;
	    user_fp_state->fp_eip     = ifps->fp_save_state.fp_eip;
	    user_fp_state->fp_cs      = ifps->fp_save_state.fp_cs;
	    user_fp_state->fp_opcode  = ifps->fp_save_state.fp_opcode;
	    user_fp_state->fp_dp      = ifps->fp_save_state.fp_dp;
	    user_fp_state->fp_ds      = ifps->fp_save_state.fp_ds;
	    *user_fp_regs = ifps->fp_regs;
	}
	simple_unlock(&pcb->lock);

	return KERN_SUCCESS;
}

/*
 * Initialize FPU.
 *
 * Raise exceptions for:
 *	invalid operation
 *	divide by zero
 *	overflow
 *
 * Use 53-bit precision.
 */
void
fpinit(void)
{
	unsigned short	control;

ASSERT_IPL(SPL0);
	clear_ts();
	fninit();
	fnstcw(&control);
	control &= ~(FPC_PC|FPC_RC); /* Clear precision & rounding control */
	control |= (FPC_PC_53 |		/* Set precision */ 
			FPC_RC_RN | 	/* round-to-nearest */
			FPC_ZE |	/* Suppress zero-divide */
			FPC_OE |	/*  and overflow */
			FPC_UE |	/*  underflow */
			FPC_IE |	/* Allow NaNQs and +-INF */
			FPC_DE |	/* Allow denorms as operands  */
			FPC_PE);	/* No trap for precision loss */
	fldcw(control);
}

/*
 * Coprocessor not present.
 */

void
fpnoextflt(void)
{
	/*
	 * Enable FPU use.
	 */
ASSERT_IPL(SPL0);
	clear_ts();

	/*
	 * Load this thread`s state into the FPU.
	 */
	fp_load(current_thread());
}

/*
 * FPU overran end of segment.
 * Re-initialize FPU.  Floating point state is not valid.
 */

void
fpextovrflt(void)
{
	register thread_t	thr_act = current_thread();
	register pcb_t		pcb;
	register struct i386_fpsave_state *ifps;

	/*
	 * This is a non-recoverable error.
	 * Invalidate the thread`s FPU state.
	 */
	pcb = thr_act->machine.pcb;
	simple_lock(&pcb->lock);
	ifps = pcb->ims.ifps;
	pcb->ims.ifps = 0;
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
	register thread_t	thr_act = current_thread();

ASSERT_IPL(SPL0);
	/*
	 * Save the FPU state and turn off the FPU.
	 */
	fp_save(thr_act);

	/*
	 * Raise FPU exception.
	 * Locking not needed on pcb->ims.ifps,
	 * since thread is running.
	 */
	i386_exception(EXC_ARITHMETIC,
		       EXC_I386_EXTERR,
		       thr_act->machine.pcb->ims.ifps->fp_save_state.fp_status);
	/*NOTREACHED*/
}

/*
 * Save FPU state.
 *
 * Locking not needed:
 * .	if called from fpu_get_state, pcb already locked.
 * .	if called from fpnoextflt or fp_intr, we are single-cpu
 * .	otherwise, thread is running.
 */
void
fp_save(
	thread_t	thr_act)
{
	register pcb_t pcb = thr_act->machine.pcb;
	register struct i386_fpsave_state *ifps = pcb->ims.ifps;
	if (ifps != 0 && !ifps->fp_valid) {
	    /* registers are in FPU */
	    ifps->fp_valid = TRUE;
            ifps->fp_save_flavor = FP_387;
            if (FXSAFE()) {
                fxsave(&ifps->fx_save_state);	// save the SSE2/Fp state in addition is enabled
                ifps->fp_save_flavor = FP_FXSR;
            }
	    fnsave(&ifps->fp_save_state);  // also update the old save area for now...
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
	register pcb_t pcb = thr_act->machine.pcb;
	register struct i386_fpsave_state *ifps;

ASSERT_IPL(SPL0);
	ifps = pcb->ims.ifps;
	if (ifps == 0) {
	    ifps = (struct i386_fpsave_state *) zalloc(ifps_zone);
	    assert(ALIGNED(ifps,16));
	    bzero((char *)ifps, sizeof *ifps);
	    pcb->ims.ifps = ifps;
	    fpinit();
#if 1
/* 
 * I'm not sure this is needed. Does the fpu regenerate the interrupt in
 * frstor or not? Without this code we may miss some exceptions, with it
 * we might send too many exceptions.
 */
	} else if (ifps->fp_valid == 2) {
		/* delayed exception pending */

		ifps->fp_valid = TRUE;
		clear_fpu();
		/*
		 * Raise FPU exception.
		 * Locking not needed on pcb->ims.ifps,
		 * since thread is running.
		 */
		i386_exception(EXC_ARITHMETIC,
		       EXC_I386_EXTERR,
		       thr_act->machine.pcb->ims.ifps->fp_save_state.fp_status);
		/*NOTREACHED*/
#endif
	} else {
            if (ifps->fp_save_flavor == FP_FXSR) fxrstor(&ifps->fx_save_state);
	    else frstor(ifps->fp_save_state);
	}
	ifps->fp_valid = FALSE;		/* in FPU */
}


/*
 * Allocate and initialize FP state for current thread.
 * Don't load state.
 *
 * Locking not needed; always called on the current thread.
 */
void
fp_state_alloc(void)
{
	pcb_t	pcb = current_thread()->machine.pcb;
	struct i386_fpsave_state *ifps;

	ifps = (struct i386_fpsave_state *)zalloc(ifps_zone);
	assert(ALIGNED(ifps,16));
	bzero((char *)ifps, sizeof *ifps);
	pcb->ims.ifps = ifps;

	ifps->fp_valid = TRUE;
	ifps->fp_save_state.fp_control = (0x037f
			& ~(FPC_IM|FPC_ZM|FPC_OM|FPC_PC))
			| (FPC_PC_53|FPC_IC_AFF);
	ifps->fp_save_state.fp_status = 0;
	ifps->fp_save_state.fp_tag = 0xffff;	/* all empty */
        ifps->fx_save_state.fx_control = ifps->fp_save_state.fp_control;
        ifps->fx_save_state.fx_status = ifps->fp_save_state.fp_status;
        ifps->fx_save_state.fx_tag = 0x00;
        ifps->fx_save_state.fx_MXCSR = 0x1f80;
        
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
 *	Handle a coprocessor error interrupt on the AT386.
 *	This comes in on line 5 of the slave PIC at SPL1.
 */

void
fpintr(void)
{
	spl_t	s;
	thread_t thr_act = current_thread();

ASSERT_IPL(SPL1);
	/*
	 * Turn off the extended 'busy' line.
	 */
	outb(0xf0, 0);

	/*
	 * Save the FPU context to the thread using it.
	 */
	clear_ts();
	fp_save(thr_act);
	fninit();
	clear_fpu();

	/*
	 * Since we are running on the interrupt stack, we must
	 * signal the thread to take the exception when we return
	 * to user mode.  Use an AST to do this.
	 *
	 * Don`t set the thread`s AST field.  If the thread is
	 * descheduled before it takes the AST, it will notice
	 * the FPU error when it reloads its FPU state.
	 */
	s = splsched();
	mp_disable_preemption();
	ast_on(AST_I386_FP);
	mp_enable_preemption();
	splx(s);
}
