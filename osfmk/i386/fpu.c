/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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

#include <cpus.h>
#include <platforms.h>

#include <mach/exception_types.h>
#include <mach/i386/thread_status.h>
#include <mach/i386/fp_reg.h>

#include <kern/mach_param.h>
#include <kern/thread.h>
#include <kern/zalloc.h>
#include <kern/misc_protos.h>
#include <kern/spl.h>
#include <kern/assert.h>

#include <i386/thread.h>
#include <i386/fpu.h>
#include <i386/trap.h>
#include <i386/pio.h>
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

#if	NCPUS == 1
volatile thread_act_t	fp_act = THR_ACT_NULL;
				    /* thread whose state is in FPU */
				    /* always THR_ACT_NULL if emulating FPU */
volatile thread_act_t	fp_intr_act = THR_ACT_NULL;


#define	clear_fpu() \
    { \
	set_ts(); \
	fp_act = THR_ACT_NULL; \
    }

#else	/* NCPUS > 1 */
#define	clear_fpu() \
    { \
	set_ts(); \
    }

#endif

/* Forward */

extern void		fpinit(void);
extern void		fp_save(
				thread_act_t	thr_act);
extern void		fp_load(
				thread_act_t	thr_act);

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
	set_cr0(get_cr0() & ~(CR0_EM|CR0_TS));	/* allow use of FPU */

	fninit();
	status = fnstsw();
	fnstcw(&control);

	if ((status & 0xff) == 0 &&
	    (control & 0x103f) == 0x3f)
	{
#if 0
	    /*
	     * We have a FPU of some sort.
	     * Compare -infinity against +infinity
	     * to check whether we have a 287 or a 387.
	     */
	    volatile double fp_infinity, fp_one, fp_zero;
	    fp_one = 1.0;
	    fp_zero = 0.0;
	    fp_infinity = fp_one / fp_zero;
	    if (fp_infinity == -fp_infinity) {
		/*
		 * We have an 80287.
		 */
		fp_kind = FP_287;
		__asm__ volatile(".byte 0xdb; .byte 0xe4");	/* fnsetpm */
	    }
	    else
#endif
		 {
		/*
		 * We have a 387.
		 */
		fp_kind = FP_387;
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
fp_free(fps)
	struct i386_fpsave_state *fps;
{
ASSERT_IPL(SPL0);
#if	NCPUS == 1
	if ((fp_act != THR_ACT_NULL) && (fp_act->mact.pcb->ims.ifps == fps)) {
		/* 
		 * Make sure we don't get FPU interrupts later for
		 * this thread
		 */
		fwait();

		/* Mark it free and disable access */
	    clear_fpu();
	}
#endif	/* NCPUS == 1 */
	zfree(ifps_zone, (vm_offset_t) fps);
}

/*
 * Set the floating-point state for a thread.
 * If the thread is not the current thread, it is
 * not running (held).  Locking needed against
 * concurrent fpu_set_state or fpu_get_state.
 */
kern_return_t
fpu_set_state(
	thread_act_t		thr_act,
	struct i386_float_state	*state)
{
	register pcb_t	pcb;
	register struct i386_fpsave_state *ifps;
	register struct i386_fpsave_state *new_ifps;

ASSERT_IPL(SPL0);
	if (fp_kind == FP_NO)
	    return KERN_FAILURE;

	assert(thr_act != THR_ACT_NULL);
	pcb = thr_act->mact.pcb;

#if	NCPUS == 1

	/*
	 * If this thread`s state is in the FPU,
	 * discard it; we are replacing the entire
	 * FPU state.
	 */
	if (fp_act == thr_act) {
	    fwait();			/* wait for possible interrupt */
	    clear_fpu();		/* no state in FPU */
	}
#endif

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
		zfree(ifps_zone, (vm_offset_t) ifps);
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
		    goto Retry;
		}
		ifps = new_ifps;
		new_ifps = 0;
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

	    simple_unlock(&pcb->lock);
	    if (new_ifps != 0)
		zfree(ifps_zone, (vm_offset_t) ifps);
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
	thread_act_t				thr_act,
	register struct i386_float_state	*state)
{
	register pcb_t	pcb;
	register struct i386_fpsave_state *ifps;

ASSERT_IPL(SPL0);
	if (fp_kind == FP_NO)
	    return KERN_FAILURE;

	assert(thr_act != THR_ACT_NULL);
	pcb = thr_act->mact.pcb;

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
#if	NCPUS == 1
	if (thr_act == fp_act)
#else
	if (thr_act == current_act())
#endif
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
#if	NCPUS == 1

	/*
	 * If this thread`s state is in the FPU, we are done.
	 */
	if (fp_act == current_act())
	    return;

	/* Make sure we don't do fpsave() in fp_intr while doing fpsave()
	 * here if the current fpu instruction generates an error.
	 */
	fwait();
	/*
	 * If another thread`s state is in the FPU, save it.
	 */
	if (fp_act != THR_ACT_NULL) {
	    fp_save(fp_act);
	}

	/*
	 * Give this thread the FPU.
	 */
	fp_act = current_act();

#endif	/* NCPUS == 1 */

	/*
	 * Load this thread`s state into the FPU.
	 */
	fp_load(current_act());
}

/*
 * FPU overran end of segment.
 * Re-initialize FPU.  Floating point state is not valid.
 */

void
fpextovrflt(void)
{
	register thread_act_t	thr_act = current_act();
	register pcb_t		pcb;
	register struct i386_fpsave_state *ifps;

#if	NCPUS == 1

	/*
	 * Is exception for the currently running thread?
	 */
	if (fp_act != thr_act) {
	    /* Uh oh... */
	    panic("fpextovrflt");
	}
#endif

	/*
	 * This is a non-recoverable error.
	 * Invalidate the thread`s FPU state.
	 */
	pcb = thr_act->mact.pcb;
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
	    zfree(ifps_zone, (vm_offset_t) ifps);

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
	register thread_act_t	thr_act = current_act();

ASSERT_IPL(SPL0);
#if	NCPUS == 1
	/*
	 * Since FPU errors only occur on ESC or WAIT instructions,
	 * the current thread should own the FPU.  If it didn`t,
	 * we should have gotten the task-switched interrupt first.
	 */
	if (fp_act != THR_ACT_NULL) {
	    panic("fpexterrflt");
		return;
	}

	/*
	 * Check if we got a context switch between the interrupt and the AST
	 * This can happen if the interrupt arrived after the FPU AST was
	 * checked. In this case, raise the exception in fp_load when this
	 * thread next time uses the FPU. Remember exception condition in
	 * fp_valid (extended boolean 2).
	 */
	if (fp_intr_act != thr_act) {
		if (fp_intr_act == THR_ACT_NULL) {
			panic("fpexterrflt: fp_intr_act == THR_ACT_NULL");
			return;
		}
		fp_intr_act->mact.pcb->ims.ifps->fp_valid = 2;
		fp_intr_act = THR_ACT_NULL;
		return;
	}
	fp_intr_act = THR_ACT_NULL;
#else	/* NCPUS == 1 */
	/*
	 * Save the FPU state and turn off the FPU.
	 */
	fp_save(thr_act);
#endif	/* NCPUS == 1 */

	/*
	 * Raise FPU exception.
	 * Locking not needed on pcb->ims.ifps,
	 * since thread is running.
	 */
	i386_exception(EXC_ARITHMETIC,
		       EXC_I386_EXTERR,
		       thr_act->mact.pcb->ims.ifps->fp_save_state.fp_status);
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
	thread_act_t	thr_act)
{
	register pcb_t pcb = thr_act->mact.pcb;
	register struct i386_fpsave_state *ifps = pcb->ims.ifps;

	if (ifps != 0 && !ifps->fp_valid) {
	    /* registers are in FPU */
	    ifps->fp_valid = TRUE;
	    fnsave(&ifps->fp_save_state);
	}
}

/*
 * Restore FPU state from PCB.
 *
 * Locking not needed; always called on the current thread.
 */

void
fp_load(
	thread_act_t	thr_act)
{
	register pcb_t pcb = thr_act->mact.pcb;
	register struct i386_fpsave_state *ifps;

ASSERT_IPL(SPL0);
	ifps = pcb->ims.ifps;
	if (ifps == 0) {
	    ifps = (struct i386_fpsave_state *) zalloc(ifps_zone);
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
		       thr_act->mact.pcb->ims.ifps->fp_save_state.fp_status);
		/*NOTREACHED*/
#endif
	} else {
	    frstor(ifps->fp_save_state);
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
	pcb_t	pcb = current_act()->mact.pcb;
	struct i386_fpsave_state *ifps;

	ifps = (struct i386_fpsave_state *)zalloc(ifps_zone);
	bzero((char *)ifps, sizeof *ifps);
	pcb->ims.ifps = ifps;

	ifps->fp_valid = TRUE;
	ifps->fp_save_state.fp_control = (0x037f
			& ~(FPC_IM|FPC_ZM|FPC_OM|FPC_PC))
			| (FPC_PC_53|FPC_IC_AFF);
	ifps->fp_save_state.fp_status = 0;
	ifps->fp_save_state.fp_tag = 0xffff;	/* all empty */
}


/*
 * fpflush(thread_act_t)
 *	Flush the current act's state, if needed
 *	(used by thread_terminate_self to ensure fp faults
 *	aren't satisfied by overly general trap code in the
 *	context of the reaper thread)
 */
void
fpflush(thread_act_t thr_act)
{
#if	NCPUS == 1
	if (fp_act && thr_act == fp_act) {
	    clear_ts();
	    fwait();
	    clear_fpu();
	}
#else
	/* not needed on MP x86s; fp not lazily evaluated */
#endif
}


/*
 *	Handle a coprocessor error interrupt on the AT386.
 *	This comes in on line 5 of the slave PIC at SPL1.
 */

void
fpintr(void)
{
	spl_t	s;
	thread_act_t thr_act = current_act();

ASSERT_IPL(SPL1);
	/*
	 * Turn off the extended 'busy' line.
	 */
	outb(0xf0, 0);

	/*
	 * Save the FPU context to the thread using it.
	 */
#if	NCPUS == 1
	if (fp_act == THR_ACT_NULL) {
		printf("fpintr: FPU not belonging to anyone!\n");
		clear_ts();
		fninit();
		clear_fpu();
		return;
	}

	if (fp_act != thr_act) {
	    /*
	     * FPU exception is for a different thread.
	     * When that thread again uses the FPU an exception will be
	     * raised in fp_load. Remember the condition in fp_valid (== 2).
	     */
	    clear_ts();
	    fp_save(fp_act);
	    fp_act->mact.pcb->ims.ifps->fp_valid = 2;
	    fninit();
	    clear_fpu();
	    /* leave fp_intr_act THR_ACT_NULL */
	    return;
	}
	if (fp_intr_act != THR_ACT_NULL)
	    panic("fp_intr: already caught intr");
	fp_intr_act = thr_act;
#endif	/* NCPUS == 1 */

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
