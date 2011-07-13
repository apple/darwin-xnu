/*
 * Copyright (c) 2004-2010 Apple Inc. All rights reserved.
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
 * @APPLE_FREE_COPYRIGHT@
 */
/*
 *	File:		rtclock_asm.h
 *	Purpose:	Assembly routines for handling the machine dependent
 *				real-time clock.
 */

#ifndef _I386_RTCLOCK_H_
#define _I386_RTCLOCK_H_

#include <i386/pal_rtclock_asm.h>

#if defined(__i386__)

/*
 * Nanotime returned in %edx:%eax.
 * Computed from tsc based on the scale factor
 * and an implicit 32 bit shift.
 *
 * Uses %eax, %ebx, %ecx, %edx, %esi, %edi.
 */
#define NANOTIME							  \
	mov	%gs:CPU_NANOTIME,%edi					; \
	PAL_RTC_NANOTIME_READ_FAST()


/*
 * Add 64-bit delta in register dreg : areg to timer pointed to by register treg.
 */
#define TIMER_UPDATE(treg,dreg,areg,offset)				       \
	addl	(TIMER_LOW+(offset))(treg),areg		/* add low bits */   ; \
	adcl	dreg,(TIMER_HIGH+(offset))(treg)	/* carry high bits */; \
	movl	areg,(TIMER_LOW+(offset))(treg)		/* updated low bit */; \
	movl	(TIMER_HIGH+(offset))(treg),dreg	/* copy high bits */ ; \
	movl	dreg,(TIMER_HIGHCHK+(offset))(treg)	/* to high check */

/*
 * Add time delta to old timer and start new.
 */
#define TIMER_EVENT(old,new)						       \
	NANOTIME				/* edx:eax nanosecs */       ; \
	movl	%eax,%esi			/* save timestamp */	     ; \
	movl	%edx,%edi			/* save timestamp */	     ; \
	movl	%gs:CPU_ACTIVE_THREAD,%ecx	/* get current thread */     ; \
	subl	(old##_TIMER)+TIMER_TSTAMP(%ecx),%eax   /* elapsed */	     ; \
	sbbl	(old##_TIMER)+TIMER_TSTAMP+4(%ecx),%edx	/* time */	     ; \
	TIMER_UPDATE(%ecx,%edx,%eax,old##_TIMER)  /* update timer */	     ; \
	movl	%esi,(new##_TIMER)+TIMER_TSTAMP(%ecx)   /* set timestamp */  ; \
	movl	%edi,(new##_TIMER)+TIMER_TSTAMP+4(%ecx)	 /* set timestamp */ ; \
	leal	(new##_TIMER)(%ecx), %ecx   /* compute new timer pointer */  ; \
	movl	%gs:CPU_PROCESSOR,%ebx		/* get current processor */  ; \
	movl	%ecx,THREAD_TIMER(%ebx)		/* set current timer */	     ; \
	movl	%esi,%eax			/* restore timestamp */	     ; \
	movl	%edi,%edx			/* restore timestamp */	     ; \
	subl	(old##_STATE)+TIMER_TSTAMP(%ebx),%eax	 /* elapsed */	     ; \
	sbbl	(old##_STATE)+TIMER_TSTAMP+4(%ebx),%edx	 /* time */	     ; \
	TIMER_UPDATE(%ebx,%edx,%eax,old##_STATE)/* update timer */	     ; \
	leal	(new##_STATE)(%ebx),%ecx	/* new state pointer */      ; \
	movl	%ecx,CURRENT_STATE(%ebx)	/* set current state */	     ; \
	movl	%esi,TIMER_TSTAMP(%ecx)		/* set timestamp */          ; \
	movl	%edi,TIMER_TSTAMP+4(%ecx)	/* set timestamp */

/*
 * Update time on user trap entry.
 * Uses %eax,%ebx,%ecx,%edx,%esi,%edi.
 */
#define	TIME_TRAP_UENTRY			TIMER_EVENT(USER,SYSTEM)

/*
 * update time on user trap exit.
 * Uses %eax,%ebx,%ecx,%edx,%esi,%edi.
 */
#define	TIME_TRAP_UEXIT				TIMER_EVENT(SYSTEM,USER)

/*
 * update time on interrupt entry.
 * Uses %eax,%ebx,%ecx,%edx,%esi,%edi.
 * Saves processor state info on stack.
 */
#define	TIME_INT_ENTRY							       \
	NANOTIME				/* edx:eax nanosecs */	     ; \
	movl	%eax,%gs:CPU_INT_EVENT_TIME	/* save in cpu data */	     ; \
	movl	%edx,%gs:CPU_INT_EVENT_TIME+4	/* save in cpu data */	     ; \
	movl	%eax,%esi			/* save timestamp */	     ; \
	movl	%edx,%edi			/* save timestamp */	     ; \
	movl	%gs:CPU_PROCESSOR,%ebx		/* get current processor */  ; \
	movl 	THREAD_TIMER(%ebx),%ecx		/* get current timer */	     ; \
	subl	TIMER_TSTAMP(%ecx),%eax		/* compute elapsed time */   ; \
	sbbl	TIMER_TSTAMP+4(%ecx),%edx	/* compute elapsed time */   ; \
	TIMER_UPDATE(%ecx,%edx,%eax,0)		/* update timer */	     ; \
	movl	KERNEL_TIMER(%ebx),%ecx		/* point to kernel timer */  ; \
	movl	%esi,TIMER_TSTAMP(%ecx)		/* set timestamp */	     ; \
	movl	%edi,TIMER_TSTAMP+4(%ecx)	/* set timestamp */	     ; \
	movl	%esi,%eax			/* restore timestamp */	     ; \
	movl	%edi,%edx			/* restore timestamp */	     ; \
	movl	CURRENT_STATE(%ebx),%ecx	/* get current state */	     ; \
	pushl	%ecx				/* save state */	     ; \
	subl	TIMER_TSTAMP(%ecx),%eax		/* compute elapsed time */   ; \
	sbbl	TIMER_TSTAMP+4(%ecx),%edx	/* compute elapsed time */   ; \
	TIMER_UPDATE(%ecx,%edx,%eax,0)		/* update timer */	     ; \
	leal	IDLE_STATE(%ebx),%eax		/* get idle state */	     ; \
	cmpl	%eax,%ecx			/* compare current state */  ; \
	je	0f				/* skip if equal */	     ; \
	leal	SYSTEM_STATE(%ebx),%ecx		/* get system state */	     ; \
	movl	%ecx,CURRENT_STATE(%ebx)	/* set current state */	     ; \
0:	movl	%esi,TIMER_TSTAMP(%ecx)		/* set timestamp */	     ; \
	movl	%edi,TIMER_TSTAMP+4(%ecx)	/* set timestamp */

/*
 * update time on interrupt exit.
 * Uses %eax,%ebx,%ecx,%edx,%esi,%edi.
 * Restores processor state info from stack.
 */
#define	TIME_INT_EXIT							       \
	NANOTIME				/* edx:eax nanosecs */       ; \
	movl	%eax,%gs:CPU_INT_EVENT_TIME	/* save in cpu data */	     ; \
	movl	%edx,%gs:CPU_INT_EVENT_TIME+4	/* save in cpu data */	     ; \
	movl	%eax,%esi			/* save timestamp */	     ; \
	movl	%edx,%edi			/* save timestamp */	     ; \
	movl	%gs:CPU_PROCESSOR,%ebx		/* get current processor */  ; \
	movl	KERNEL_TIMER(%ebx),%ecx		/* point to kernel timer */  ; \
	subl	TIMER_TSTAMP(%ecx),%eax		/* compute elapsed time */   ; \
	sbbl	TIMER_TSTAMP+4(%ecx),%edx	/* compute elapsed time */   ; \
	TIMER_UPDATE(%ecx,%edx,%eax,0)		/* update timer */	     ; \
	movl	THREAD_TIMER(%ebx),%ecx		/* interrupted timer */	     ; \
	movl	%esi,TIMER_TSTAMP(%ecx)		/* set timestamp */	     ; \
	movl	%edi,TIMER_TSTAMP+4(%ecx)	/* set timestamp */	     ; \
	movl	%esi,%eax			/* restore timestamp */	     ; \
	movl	%edi,%edx			/* restore timestamp */	     ; \
	movl	CURRENT_STATE(%ebx),%ecx	/* get current state */	     ; \
	subl	TIMER_TSTAMP(%ecx),%eax		/* compute elapsed time */   ; \
	sbbl	TIMER_TSTAMP+4(%ecx),%edx	/* compute elapsed time */   ; \
	TIMER_UPDATE(%ecx,%edx,%eax,0)		/* update timer */	     ; \
	popl	%ecx				/* restore state */	     ; \
	movl	%ecx,CURRENT_STATE(%ebx)	/* set current state */	     ; \
	movl	%esi,TIMER_TSTAMP(%ecx)		/* set timestamp */	     ; \
	movl	%edi,TIMER_TSTAMP+4(%ecx)	/* set timestamp */

#elif defined(__x86_64__)

/*
 * Nanotime returned in %rax.
 * Computed from tsc based on the scale factor and an implicit 32 bit shift.
 * This code must match what _rtc_nanotime_read does in
 * machine_routines_asm.s.  Failure to do so can
 * result in "weird" timing results.
 *
 * Uses: %rsi, %rdi, %rdx, %rcx
 */
#define NANOTIME							       \
	movq	%gs:CPU_NANOTIME,%rdi					     ; \
	PAL_RTC_NANOTIME_READ_FAST()

/*
 * Add 64-bit delta in register reg to timer pointed to by register treg.
 */
#define TIMER_UPDATE(treg,reg,offset)					       \
	addq	reg,(offset)+TIMER_ALL(treg)		/* add timer */

/*
 * Add time delta to old timer and start new.
 * Uses: %rsi, %rdi, %rdx, %rcx, %rax
 */
#define TIMER_EVENT(old,new)						       \
	NANOTIME				/* %rax := nanosecs */       ; \
	movq	%rax,%rsi			/* save timestamp */	     ; \
	movq	%gs:CPU_ACTIVE_THREAD,%rcx	/* get thread */	     ; \
	subq	(old##_TIMER)+TIMER_TSTAMP(%rcx),%rax	/* compute elapsed */; \
	TIMER_UPDATE(%rcx,%rax,old##_TIMER)	/* update timer */	     ; \
	leaq	(new##_TIMER)(%rcx),%rcx	/* point to new timer */     ; \
	movq	%rsi,TIMER_TSTAMP(%rcx)		/* set timestamp */	     ; \
	movq	%gs:CPU_PROCESSOR,%rdx		/* get processor */	     ; \
	movq	%rcx,THREAD_TIMER(%rdx)		/* set current timer */	     ; \
	movq	%rsi,%rax			/* restore timestamp */	     ; \
	subq	(old##_STATE)+TIMER_TSTAMP(%rdx),%rax	/* compute elapsed */; \
	TIMER_UPDATE(%rdx,%rax,old##_STATE)	/* update timer */	     ; \
	leaq	(new##_STATE)(%rdx),%rcx 	/* point to new state */     ; \
	movq	%rcx,CURRENT_STATE(%rdx)	/* set current state */	     ; \
	movq	%rsi,TIMER_TSTAMP(%rcx)		/* set timestamp */

/*
 * Update time on user trap entry.
 * Uses: %rsi, %rdi, %rdx, %rcx, %rax
 */
#define	TIME_TRAP_UENTRY	TIMER_EVENT(USER,SYSTEM)

/*
 * update time on user trap exit.
 * Uses: %rsi, %rdi, %rdx, %rcx, %rax
 */
#define	TIME_TRAP_UEXIT		TIMER_EVENT(SYSTEM,USER)

/*
 * update time on interrupt entry.
 * Uses: %rsi, %rdi, %rdx, %rcx, %rax
 * Saves processor state info on stack.
 */
#define	TIME_INT_ENTRY							       \
	NANOTIME				/* %rax := nanosecs */	     ; \
	movq	%rax,%gs:CPU_INT_EVENT_TIME	/* save in cpu data */	     ; \
	movq	%rax,%rsi			/* save timestamp */	     ; \
	movq	%gs:CPU_PROCESSOR,%rdx		/* get processor */	     ; \
	movq 	THREAD_TIMER(%rdx),%rcx		/* get current timer */	     ; \
	subq	TIMER_TSTAMP(%rcx),%rax		/* compute elapsed */	     ; \
	TIMER_UPDATE(%rcx,%rax,0)		/* update timer */	     ; \
	movq	KERNEL_TIMER(%rdx),%rcx		/* get kernel timer */	     ; \
	movq	%rsi,TIMER_TSTAMP(%rcx)		/* set timestamp */	     ; \
	movq	%rsi,%rax			/* restore timestamp */	     ; \
	movq	CURRENT_STATE(%rdx),%rcx	/* get current state */	     ; \
	pushq	%rcx				/* save state */	     ; \
	subq	TIMER_TSTAMP(%rcx),%rax		/* compute elapsed */	     ; \
	TIMER_UPDATE(%rcx,%rax,0)		/* update timer */	     ; \
	leaq	IDLE_STATE(%rdx),%rax		/* get idle state */	     ; \
	cmpq	%rax,%rcx			/* compare current */	     ; \
	je	0f				/* skip if equal */	     ; \
	leaq	SYSTEM_STATE(%rdx),%rcx		/* get system state */	     ; \
	movq	%rcx,CURRENT_STATE(%rdx)	/* set current state */	     ; \
0:	movq	%rsi,TIMER_TSTAMP(%rcx)		/* set timestamp */

/*
 * update time on interrupt exit.
 * Uses: %rsi, %rdi, %rdx, %rcx, %rax
 * Restores processor state info from stack.
 */
#define	TIME_INT_EXIT							       \
	NANOTIME				/* %rax := nanosecs */	     ; \
	movq	%rax,%gs:CPU_INT_EVENT_TIME	/* save in cpu data */	     ; \
	movq	%rax,%rsi			/* save timestamp */	     ; \
	movq	%gs:CPU_PROCESSOR,%rdx		/* get processor */	     ; \
	movq	KERNEL_TIMER(%rdx),%rcx		/* get kernel timer */	     ; \
	subq	TIMER_TSTAMP(%rcx),%rax		/* compute elapsed */        ; \
	TIMER_UPDATE(%rcx,%rax,0)		/* update timer */	     ; \
	movq	THREAD_TIMER(%rdx),%rcx		/* interrupted timer */	     ; \
	movq	%rsi,TIMER_TSTAMP(%rcx)		/* set timestamp */	     ; \
	movq	%rsi,%rax			/* restore timestamp */	     ; \
	movq	CURRENT_STATE(%rdx),%rcx	/* get current state */	     ; \
	subq	TIMER_TSTAMP(%rcx),%rax		/* compute elapsed */	     ; \
	TIMER_UPDATE(%rcx,%rax,0)		/* update timer */	     ; \
	popq	%rcx				/* restore state */	     ; \
	movq	%rcx,CURRENT_STATE(%rdx)	/* set current state */	     ; \
	movq	%rsi,TIMER_TSTAMP(%rcx)		/* set timestamp */

#endif

/*
 * Check for vtimers for task.
 *   task_reg   is register pointing to current task
 *   thread_reg is register pointing to current thread
 */
#define TASK_VTIMER_CHECK(task_reg,thread_reg)				       \
	cmpl	$0,TASK_VTIMERS(task_reg)				     ; \
	jz	1f							     ; \
	orl	$(AST_BSD),%gs:CPU_PENDING_AST	/* Set pending AST */	     ; \
	lock								     ; \
	orl	$(AST_BSD),TH_AST(thread_reg)	/* Set thread AST  */	     ; \
1:									     ; \

#endif /* _I386_RTCLOCK_H_ */
