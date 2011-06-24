/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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

#include <libkern/OSAtomic.h>

#include <architecture/i386/pio.h>
#include <i386/cpuid.h>
#include <i386/fpu.h>
#include <i386/proc_reg.h>
#include <i386/misc_protos.h>
#include <i386/thread.h>
#include <i386/trap.h>

int		fp_kind = FP_NO;	/* not inited */
zone_t		ifps_zone;		/* zone for FPU save area */

#define ALIGNED(addr,size)	(((uintptr_t)(addr)&((size)-1))==0)

/* Forward */

extern void		fpinit(void);
extern void		fp_save(
				thread_t	thr_act);
extern void		fp_load(
				thread_t	thr_act);

static void configure_mxcsr_capability_mask(struct x86_avx_thread_state *fps);

struct x86_avx_thread_state initial_fp_state __attribute((aligned(64)));


/* Global MXCSR capability bitmask */
static unsigned int mxcsr_capability_mask;

#define	fninit() \
	__asm__ volatile("fninit")

#define	fnstcw(control) \
	__asm__("fnstcw %0" : "=m" (*(unsigned short *)(control)))

#define	fldcw(control) \
	__asm__ volatile("fldcw %0" : : "m" (*(unsigned short *) &(control)) )

#define	fnclex() \
	__asm__ volatile("fnclex")

#define	fnsave(state)  \
	__asm__ volatile("fnsave %0" : "=m" (*state))

#define	frstor(state) \
	__asm__ volatile("frstor %0" : : "m" (state))

#define fwait() \
    	__asm__("fwait");

#define fxrstor(addr)           __asm__ __volatile__("fxrstor %0" : : "m" (*(addr)))     
#define fxsave(addr)            __asm__ __volatile__("fxsave %0" : "=m" (*(addr)))

static uint32_t	fp_register_state_size = 0;
static uint32_t fpu_YMM_present	= FALSE;
static uint32_t	cpuid_reevaluated = 0;

static void fpu_store_registers(void *, boolean_t);
static void fpu_load_registers(void *);

extern	void xsave64o(void);
extern	void xrstor64o(void);

#define XMASK ((uint32_t) (XFEM_X87 | XFEM_SSE | XFEM_YMM))

/* DRK: TODO replace opcodes with mnemonics when assembler support available */

static inline void xsetbv(uint32_t mask_hi, uint32_t mask_lo) {
	__asm__ __volatile__(".short 0x010F\n\t.byte 0xD1" :: "a"(mask_lo), "d"(mask_hi), "c" (XCR0));
}

static inline void xsave(void *a) {
	/* MOD 0x4, operand ECX 0x1 */
	__asm__ __volatile__(".short 0xAE0F\n\t.byte 0x21" :: "a"(XMASK), "d"(0), "c" (a));
}

static inline void xrstor(void *a) {
	/* MOD 0x5, operand ECX 0x1 */
	__asm__ __volatile__(".short 0xAE0F\n\t.byte 0x29" :: "a"(XMASK), "d"(0), "c" (a));
}

static inline void xsave64(void *a) {
	/* Out of line call that executes in 64-bit mode on K32 */
	__asm__ __volatile__("call _xsave64o" :: "a"(XMASK), "d"(0), "c" (a));
}

static inline void xrstor64(void *a) {
	/* Out of line call that executes in 64-bit mode on K32 */
	__asm__ __volatile__("call _xrstor64o" :: "a"(XMASK), "d"(0), "c" (a));
}

static inline unsigned short
fnstsw(void)
{
	unsigned short status;
	__asm__ volatile("fnstsw %0" : "=ma" (status));
	return(status);
}

/*
 * Configure the initial FPU state presented to new threads.
 * Determine the MXCSR capability mask, which allows us to mask off any
 * potentially unsafe "reserved" bits before restoring the FPU context.
 * *Not* per-cpu, assumes symmetry.
 */

static void
configure_mxcsr_capability_mask(struct x86_avx_thread_state *fps)
{
	/* XSAVE requires a 64 byte aligned store */
	assert(ALIGNED(fps, 64));
	/* Clear, to prepare for the diagnostic FXSAVE */
	bzero(fps, sizeof(*fps));

	fpinit();
	fpu_store_registers(fps, FALSE);

	mxcsr_capability_mask = fps->fx_MXCSR_MASK;

	/* Set default mask value if necessary */
	if (mxcsr_capability_mask == 0)
		mxcsr_capability_mask = 0xffbf;
	
	/* Clear vector register store */
	bzero(&fps->fx_XMM_reg[0][0], sizeof(fps->fx_XMM_reg));
	bzero(&fps->x_YMMH_reg[0][0], sizeof(fps->x_YMMH_reg));

	fps->fp_valid = TRUE;
	fps->fp_save_layout = fpu_YMM_present ? XSAVE32: FXSAVE32;
	fpu_load_registers(fps);

	/* Poison values to trap unsafe usage */
	fps->fp_valid = 0xFFFFFFFF;
	fps->fp_save_layout = FP_UNUSED;

	/* Re-enable FPU/SSE DNA exceptions */
	set_ts();
}


/*
 * Look for FPU and initialize it.
 * Called on each CPU.
 */
void
init_fpu(void)
{
#if	DEBUG	
	unsigned short	status;
	unsigned short 	control;
#endif
	/*
	 * Check for FPU by initializing it,
	 * then trying to read the correct bit patterns from
	 * the control and status registers.
	 */
	set_cr0((get_cr0() & ~(CR0_EM|CR0_TS)) | CR0_NE);	/* allow use of FPU */
	fninit();
#if	DEBUG	
	status = fnstsw();
	fnstcw(&control);
	
	assert(((status & 0xff) == 0) && ((control & 0x103f) == 0x3f));
#endif
	/* Advertise SSE support */
	if (cpuid_features() & CPUID_FEATURE_FXSR) {
		fp_kind = FP_FXSR;
		set_cr4(get_cr4() | CR4_OSFXS);
		/* And allow SIMD exceptions if present */
		if (cpuid_features() & CPUID_FEATURE_SSE) {
			set_cr4(get_cr4() | CR4_OSXMM);
		}
		fp_register_state_size = sizeof(struct x86_fx_thread_state);

	} else
		panic("fpu is not FP_FXSR");

	/* Configure the XSAVE context mechanism if the processor supports
	 * AVX/YMM registers
	 */
	if (cpuid_features() & CPUID_FEATURE_XSAVE) {
		cpuid_xsave_leaf_t *xsp = &cpuid_info()->cpuid_xsave_leaf;
		if (xsp->extended_state[0] & (uint32_t)XFEM_YMM) {
			assert(xsp->extended_state[0] & (uint32_t) XFEM_SSE);
			/* XSAVE container size for all features */
			assert(xsp->extended_state[2] == sizeof(struct x86_avx_thread_state));
			fp_register_state_size = sizeof(struct x86_avx_thread_state);
			fpu_YMM_present = TRUE;
			set_cr4(get_cr4() | CR4_OSXSAVE);
			xsetbv(0, XMASK);
			/* Re-evaluate CPUID, once, to reflect OSXSAVE */
			if (OSCompareAndSwap(0, 1, &cpuid_reevaluated))
				cpuid_set_info();
			/* DRK: consider verifying AVX offset with cpuid(d, ECX:2) */
		}
	}
	else
		fpu_YMM_present = FALSE;

	fpinit();

	/*
	 * Trap wait instructions.  Turn off FPU for now.
	 */
	set_cr0(get_cr0() | CR0_TS | CR0_MP);
}

/*
 * Allocate and initialize FP state for current thread.
 * Don't load state.
 */
static void *
fp_state_alloc(void)
{
	void *ifps = zalloc(ifps_zone);

#if	DEBUG	
	if (!(ALIGNED(ifps,64))) {
		panic("fp_state_alloc: %p, %u, %p, %u", ifps, (unsigned) ifps_zone->elem_size, (void *) ifps_zone->free_elements, (unsigned) ifps_zone->alloc_size);
	}
#endif
	return ifps;
}

static inline void
fp_state_free(void *ifps)
{
	zfree(ifps_zone, ifps);
}

void clear_fpu(void)
{
	set_ts();
}


static void fpu_load_registers(void *fstate) {
	struct x86_fx_thread_state *ifps = fstate;
	fp_save_layout_t layout = ifps->fp_save_layout;

	assert(layout == FXSAVE32 || layout == FXSAVE64 || layout == XSAVE32 || layout == XSAVE64);
	assert(ALIGNED(ifps, 64));
	assert(ml_get_interrupts_enabled() == FALSE);

#if	DEBUG	
	if (layout == XSAVE32 || layout == XSAVE64) {
		struct x86_avx_thread_state *iavx = fstate;
		unsigned i;
		/* Verify reserved bits in the XSAVE header*/
		if (iavx->_xh.xsbv & ~7)
			panic("iavx->_xh.xsbv: 0x%llx", iavx->_xh.xsbv);
		for (i = 0; i < sizeof(iavx->_xh.xhrsvd); i++)
			if (iavx->_xh.xhrsvd[i])
				panic("Reserved bit set");
	}
	if (fpu_YMM_present) {
		if (layout != XSAVE32 && layout != XSAVE64)
			panic("Inappropriate layout: %u\n", layout);
	}
#endif	/* DEBUG */

#if defined(__i386__)
	if (layout == FXSAVE32) {
		/* Restore the compatibility/legacy mode XMM+x87 state */
		fxrstor(ifps);
	}
	else if (layout == FXSAVE64) {
		fxrstor64(ifps);
	}
	else if (layout == XSAVE32) {
		xrstor(ifps);
	}
	else if (layout == XSAVE64) {
		xrstor64(ifps);
	}
#elif defined(__x86_64__)
	if ((layout == XSAVE64) || (layout == XSAVE32))
		xrstor(ifps);
	else
		fxrstor(ifps);
#endif
}

static void fpu_store_registers(void *fstate, boolean_t is64) {
	struct x86_fx_thread_state *ifps = fstate;
	assert(ALIGNED(ifps, 64));
#if defined(__i386__)
	if (!is64) {
		if (fpu_YMM_present) {
			xsave(ifps);
			ifps->fp_save_layout = XSAVE32;
		}
		else {
			/* save the compatibility/legacy mode XMM+x87 state */
			fxsave(ifps);
			ifps->fp_save_layout = FXSAVE32;
		}
	}
	else {
		if (fpu_YMM_present) {
			xsave64(ifps);
			ifps->fp_save_layout = XSAVE64;
		}
		else {
			fxsave64(ifps);
			ifps->fp_save_layout = FXSAVE64;
		}
	}
#elif defined(__x86_64__)
	if (fpu_YMM_present) {
		xsave(ifps);
		ifps->fp_save_layout = is64 ? XSAVE64 : XSAVE32;
	}
	else {
		fxsave(ifps);
		ifps->fp_save_layout = is64 ? FXSAVE64 : FXSAVE32;
	}
#endif
}

/*
 * Initialize FP handling.
 */

void
fpu_module_init(void)
{
	if ((fp_register_state_size != sizeof(struct x86_fx_thread_state)) &&
	    (fp_register_state_size != sizeof(struct x86_avx_thread_state)))
		panic("fpu_module_init: incorrect savearea size %u\n", fp_register_state_size);

	assert(fpu_YMM_present != 0xFFFFFFFF);

	/* We explicitly choose an allocation size of 64
	 * to eliminate waste for the 832 byte sized
	 * AVX XSAVE register save area.
	 */
	ifps_zone = zinit(fp_register_state_size,
			  thread_max * fp_register_state_size,
			  64 * fp_register_state_size,
			  "x86 fpsave state");

#if	ZONE_DEBUG
	/* To maintain the required alignment, disable
	 * zone debugging for this zone as that appends
	 * 16 bytes to each element.
	 */
	zone_debug_disable(ifps_zone);
#endif	
	/* Determine MXCSR reserved bits and configure initial FPU state*/
	configure_mxcsr_capability_mask(&initial_fp_state);
}

/*
 * Save thread`s FPU context.
 */
void
fpu_save_context(thread_t thread)
{
	struct x86_fx_thread_state *ifps;

	assert(ml_get_interrupts_enabled() == FALSE);
	ifps = (thread)->machine.pcb->ifps;
#if	DEBUG
	if (ifps && ((ifps->fp_valid != FALSE) && (ifps->fp_valid != TRUE))) {
		panic("ifps->fp_valid: %u\n", ifps->fp_valid);
	}
#endif
	if (ifps != 0 && (ifps->fp_valid == FALSE)) {
		/* Clear CR0.TS in preparation for the FP context save. In
		 * theory, this shouldn't be necessary since a live FPU should
		 * indicate that TS is clear. However, various routines
		 * (such as sendsig & sigreturn) manipulate TS directly.
		 */
		clear_ts();
		/* registers are in FPU - save to memory */
		fpu_store_registers(ifps, (thread_is_64bit(thread) && is_saved_state64(thread->machine.pcb->iss)));
		ifps->fp_valid = TRUE;
	}
	set_ts();
}


/*
 * Free a FPU save area.
 * Called only when thread terminating - no locking necessary.
 */
void
fpu_free(void *fps)
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
	thread_state_t	tstate,
	thread_flavor_t f)
{
	struct x86_fx_thread_state *ifps;
	struct x86_fx_thread_state *new_ifps;
	x86_float_state64_t	*state;
	pcb_t	pcb;
	size_t	state_size = (((f == x86_AVX_STATE32) || (f == x86_AVX_STATE64)) && (fpu_YMM_present == TRUE)) ? sizeof(struct x86_avx_thread_state) : sizeof(struct x86_fx_thread_state);
	boolean_t	old_valid;
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
	    old_valid = ifps->fp_valid;

#if	DEBUG	    
	    if ((old_valid == FALSE) && (thr_act != current_thread())) {
		    panic("fpu_set_fxstate inconsistency, thread: %p not stopped", thr_act);
	    }
#endif

	    bcopy((char *)&state->fpu_fcw, (char *)ifps, state_size);

	    if (fpu_YMM_present) {
		struct x86_avx_thread_state *iavx = (void *) ifps;
		iavx->fp_save_layout = thread_is_64bit(thr_act) ? XSAVE64 : XSAVE32;
		/* Sanitize XSAVE header */
		bzero(&iavx->_xh.xhrsvd[0], sizeof(iavx->_xh.xhrsvd));
		if (state_size == sizeof(struct x86_avx_thread_state))
			iavx->_xh.xsbv = (XFEM_YMM | XFEM_SSE | XFEM_X87);
		else
			iavx->_xh.xsbv = (XFEM_SSE | XFEM_X87);
	    }
	    else
		ifps->fp_save_layout = thread_is_64bit(thr_act) ? FXSAVE64 : FXSAVE32;
	    ifps->fp_valid = old_valid;

	    if (old_valid == FALSE) {
		    boolean_t istate = ml_set_interrupts_enabled(FALSE);
		    ifps->fp_valid = TRUE;
		    set_ts();
		    ml_set_interrupts_enabled(istate);
	    }
		/*
		 * Clear any reserved bits in the MXCSR to prevent a GPF
		 * when issuing an FXRSTOR.
		 */
	    ifps->fx_MXCSR &= mxcsr_capability_mask;

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
	thread_state_t	tstate,
	thread_flavor_t f)
{
	struct x86_fx_thread_state	*ifps;
	x86_float_state64_t	*state;
	kern_return_t	ret = KERN_FAILURE;
	pcb_t	pcb;
	size_t	state_size = (((f == x86_AVX_STATE32) || (f == x86_AVX_STATE64)) && (fpu_YMM_present == TRUE)) ? sizeof(struct x86_avx_thread_state) : sizeof(struct x86_fx_thread_state);

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

		bcopy((char *)&initial_fp_state, (char *)&state->fpu_fcw,
		    state_size);

		simple_unlock(&pcb->lock);

		return KERN_SUCCESS;
	}
	/*
	 * Make sure we`ve got the latest fp state info
	 * If the live fpu state belongs to our target
	 */
	if (thr_act == current_thread()) {
		boolean_t	intr;

		intr = ml_set_interrupts_enabled(FALSE);

		clear_ts();
		fp_save(thr_act);
		clear_fpu();

		(void)ml_set_interrupts_enabled(intr);
	}
	if (ifps->fp_valid) {
        	bcopy((char *)ifps, (char *)&state->fpu_fcw, state_size);
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
	struct x86_fx_thread_state *new_ifps = NULL;
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
		struct x86_fx_thread_state *ifps = ppcb->ifps;
	        /*
		 * Make sure we`ve got the latest fp state info
		 */
	        intr = ml_set_interrupts_enabled(FALSE);
		assert(current_thread() == parent);
		clear_ts();
		fp_save(parent);
		clear_fpu();

		(void)ml_set_interrupts_enabled(intr);

		if (ifps->fp_valid) {
			child->machine.pcb->ifps = new_ifps;
			assert((fp_register_state_size == sizeof(struct x86_fx_thread_state)) ||
			    (fp_register_state_size == sizeof(struct x86_avx_thread_state)));
			bcopy((char *)(ppcb->ifps),
			    (char *)(child->machine.pcb->ifps), fp_register_state_size);

			/* Mark the new fp saved state as non-live. */
			/* Temporarily disabled: radar 4647827
			 * new_ifps->fp_valid = TRUE;
			 */

			/*
			 * Clear any reserved bits in the MXCSR to prevent a GPF
			 * when issuing an FXRSTOR.
			 */
			new_ifps->fx_MXCSR &= mxcsr_capability_mask;
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
	thread_t	thr_act;
	pcb_t		pcb;
	struct x86_fx_thread_state *ifps = 0;

	thr_act = current_thread();
	pcb = thr_act->machine.pcb;

	assert(fp_register_state_size != 0);

	if (pcb->ifps == 0 && !get_interrupt_level()) {
	        ifps = fp_state_alloc();
		bcopy((char *)&initial_fp_state, (char *)ifps,
		    fp_register_state_size);
		if (!thread_is_64bit(thr_act)) {
			ifps->fp_save_layout = fpu_YMM_present ? XSAVE32 : FXSAVE32;
		}
		else
			ifps->fp_save_layout = fpu_YMM_present ? XSAVE64 : FXSAVE64;
		ifps->fp_valid = TRUE;
	}
	intr = ml_set_interrupts_enabled(FALSE);

	clear_ts();			/*  Enable FPU use */

	if (get_interrupt_level()) {
		/*
		 * Save current coprocessor context if valid
		 * Initialize coprocessor live context
		 */
		fp_save(thr_act);
		fpinit();
	} else {
	        if (pcb->ifps == 0) {
		        pcb->ifps = ifps;
			ifps = 0;
		}
		/*
		 * Load this thread`s state into coprocessor live context.
		 */
		fp_load(thr_act);
	}
	(void)ml_set_interrupts_enabled(intr);

	if (ifps)
	        fp_state_free(ifps);
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
	struct x86_fx_thread_state *ifps;
	boolean_t	intr;

	intr = ml_set_interrupts_enabled(FALSE);

	if (get_interrupt_level())
		panic("FPU segment overrun exception  at interrupt context\n");
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
	struct x86_fx_thread_state *ifps = thr_act->machine.pcb->ifps;
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
		       ifps->fx_status);

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
	struct x86_fx_thread_state *ifps = pcb->ifps;

	assert(ifps != 0);
	if (ifps != 0 && !ifps->fp_valid) {
		assert((get_cr0() & CR0_TS) == 0);
		/* registers are in FPU */
		ifps->fp_valid = TRUE;
		fpu_store_registers(ifps, thread_is_64bit(thr_act));
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
	struct x86_fx_thread_state *ifps = pcb->ifps;

	assert(ifps);
	assert(ifps->fp_valid == FALSE || ifps->fp_valid == TRUE);

	if (ifps->fp_valid == FALSE) {
		fpinit();
	} else {
		fpu_load_registers(ifps);
	}
	ifps->fp_valid = FALSE;		/* in FPU */
}

/*
 * SSE arithmetic exception handling code.
 * Basically the same as the x87 exception handler with a different subtype
 */

void
fpSSEexterrflt(void)
{
	thread_t	thr_act = current_thread();
	struct x86_fx_thread_state *ifps = thr_act->machine.pcb->ifps;
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
		       ifps->fx_MXCSR);
	/*NOTREACHED*/
}

void
fp_setvalid(boolean_t value) {
        thread_t	thr_act = current_thread();
	struct x86_fx_thread_state *ifps = thr_act->machine.pcb->ifps;

	if (ifps) {
	        ifps->fp_valid = value;

		if (value == TRUE) {
			boolean_t istate = ml_set_interrupts_enabled(FALSE);
		        clear_fpu();
			ml_set_interrupts_enabled(istate);
		}
	}
}

boolean_t
ml_fpu_avx_enabled(void) {
	return (fpu_YMM_present == TRUE);
}
