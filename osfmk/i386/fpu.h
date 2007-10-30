/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1991 Carnegie Mellon University
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

#ifndef	_I386_FPU_H_
#define	_I386_FPU_H_

/*
 * Macro definitions for routines to manipulate the
 * floating-point processor.
 */
#include <kern/thread.h>
#include <i386/thread.h>
#include <kern/kern_types.h>
#include <mach/i386/kern_return.h>
#include <mach/i386/thread_status.h>
#include <i386/proc_reg.h>

extern int		fp_kind;

extern void		init_fpu(void);
extern void		fpu_module_init(void);
extern void		fpu_free(
				struct x86_fpsave_state	* fps);
extern kern_return_t	fpu_set_fxstate(
				thread_t	thr_act,
				thread_state_t	state);
extern kern_return_t	fpu_get_fxstate(
				thread_t	thr_act,
				thread_state_t	state);
extern void		fpu_dup_fxstate(
				thread_t	parent,
				thread_t	child);
extern void		fpnoextflt(void);
extern void		fpextovrflt(void);
extern void		fpexterrflt(void);
extern void		fpSSEexterrflt(void);
extern void		fpflush(thread_t);
extern void		fp_setvalid(boolean_t);
extern void		fxsave64(struct x86_fx_save *);
extern void		fxrstor64(struct x86_fx_save *);

/*
 * FPU instructions.
 */
#define	fninit() \
	__asm__ volatile("fninit")

#define	fnstcw(control) \
	__asm__("fnstcw %0" : "=m" (*(unsigned short *)(control)))

#define	fldcw(control) \
	__asm__ volatile("fldcw %0" : : "m" (*(unsigned short *) &(control)) )

extern unsigned short		fnstsw(void);

extern __inline__ unsigned short fnstsw(void)
{
	unsigned short status;
	__asm__ volatile("fnstsw %0" : "=ma" (status));
	return(status);
}

#define	fnclex() \
	__asm__ volatile("fnclex")

#define	fnsave(state)  \
	__asm__ volatile("fnsave %0" : "=m" (*state))

#define	frstor(state) \
	__asm__ volatile("frstor %0" : : "m" (state))

#define fwait() \
    	__asm__("fwait");

#define fxrstor(addr)           __asm("fxrstor %0" : : "m" (*(addr)))     
#define fxsave(addr)            __asm __volatile("fxsave %0" : "=m" (*(addr)))

#define FXSAFE() (fp_kind == FP_FXSR)


static inline void clear_fpu(void)
{
	set_ts();
}

/*
 * Save thread`s FPU context.
 */

static inline void fpu_save_context(thread_t thread)
{
	struct x86_fpsave_state *ifps;

	assert(ml_get_interrupts_enabled() == FALSE);
	ifps = (thread)->machine.pcb->ifps;
	if (ifps != 0 && !ifps->fp_valid) {
		/* Clear CR0.TS in preparation for the FP context save. In
		 * theory, this shouldn't be necessary since a live FPU should
		 * indicate that TS is clear. However, various routines
		 * (such as sendsig & sigreturn) manipulate TS directly.
		 */
		clear_ts();
		/* registers are in FPU - save to memory */
		ifps->fp_valid = TRUE;
		if (!thread_is_64bit(thread) || is_saved_state32(thread->machine.pcb->iss)) {
			/* save the compatibility/legacy mode XMM+x87 state */
			fxsave(&ifps->fx_save_state);
			ifps->fp_save_layout = FXSAVE32;
		}
		else {
			/* Execute a brief jump to 64-bit mode to save the 64
			 * bit state
			 */
			fxsave64(&ifps->fx_save_state);
			ifps->fp_save_layout = FXSAVE64;
		}
	}
	set_ts();
}

#endif	/* _I386_FPU_H_ */
