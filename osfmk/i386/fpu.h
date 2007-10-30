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

#include <i386/proc_reg.h>
#include <i386/thread.h>
#include <kern/kern_types.h>
#include <mach/i386/kern_return.h>
#include <mach/i386/thread_status.h>

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

#define	fpu_load_context(pcb)

/*
 * Save thread`s FPU context.
 * If only one CPU, we just set the task-switched bit,
 * to keep the new thread from using the coprocessor.
 * If multiple CPUs, we save the entire state.
 * NOTE: in order to provide backwards compatible support in the kernel. When saving SSE2 state, we also save the
 * FP state in it's old location. Otherwise fpu_get_state() and fpu_set_state() will stop working
 */
#define	fpu_save_context(thread) \
    { \
	register struct i386_fpsave_state *ifps; \
	ifps = (thread)->machine.pcb->ims.ifps; \
	if (ifps != 0 && !ifps->fp_valid) { \
	    /* registers are in FPU - save to memory */ \
	    ifps->fp_valid = TRUE; \
            ifps->fp_save_flavor = FP_387; \
            if (FXSAFE()) { \
		fxsave(&ifps->fx_save_state); \
                ifps->fp_save_flavor = FP_FXSR; \
	    } \
            fnsave(&ifps->fp_save_state); \
	} \
	set_ts(); \
    }
	    


extern int	fp_kind;

extern void		init_fpu(void);
extern void		fpu_module_init(void);
extern void		fpu_free(
				struct i386_fpsave_state	* fps);
extern kern_return_t	fpu_set_state(
				thread_t			thr_act,
				struct i386_float_state		* st);
extern kern_return_t	fpu_get_state(
				thread_t			thr_act,
				struct i386_float_state		* st);
extern kern_return_t	fpu_set_fxstate(
				thread_t			thr_act,
				struct i386_float_state		* st);
extern kern_return_t	fpu_get_fxstate(
				thread_t			thr_act,
				struct i386_float_state		* st);
extern void		fpnoextflt(void);
extern void		fpextovrflt(void);
extern void		fpexterrflt(void);
extern void		fp_state_alloc(void);
extern void		fpintr(void);
extern void		fpflush(thread_t);

#endif	/* _I386_FPU_H_ */
