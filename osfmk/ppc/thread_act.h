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
 * 
 */

#ifndef	_PPC_THREAD_ACT_H_
#define	_PPC_THREAD_ACT_H_

#include <mach_kgdb.h>
#include <mach/boolean.h>
#include <mach/ppc/vm_types.h>
#include <mach/thread_status.h>
#include <kern/lock.h>
#include <kern/clock.h>
#include <ppc/savearea.h>

/*
 * Kernel state structure
 *
 * This holds the kernel state that is saved and restored across context
 * switches. 
 */

/*
 * PPC process control block
 *
 * The PCB holds normal context.  It does not contain vector or floating point 
 * registers.
 *
 */

typedef struct savearea pcb;
typedef struct savearea *pcb_t;

struct facility_context {

	savearea_fpu	*FPUsave;		/* The floating point savearea */
	savearea		*FPUlevel;		/* The floating point context level */
	unsigned int	FPUcpu;			/* The last processor to enable floating point */
	unsigned int	FPUsync;		/* Sync lock */
	savearea_vec	*VMXsave;		/* The VMX savearea */
	savearea		*VMXlevel;		/* The VMX context level */
	unsigned int	VMXcpu;			/* The last processor to enable vector */
	unsigned int	VMXsync;		/* Sync lock */
	struct thread_activation *facAct;	/* Activation associated with context */
};

typedef struct facility_context facility_context;

/*
 * Maps state flavor to number of words in the state:
 */
extern unsigned int state_count[];

#define USER_REGS(ThrAct)	((ThrAct)->mact.pcb)

#define	user_pc(ThrAct)		((ThrAct)->mact.pcb->save_srr0)

#define act_machine_state_ptr(ThrAct)	(thread_state_t)USER_REGS(ThrAct)

typedef struct MachineThrAct {
	/*
	 * pointer to process control block control blocks.  Potentially
	 * one for each active facility context.  They may point to the
	 * same saveareas.
	 */
	savearea		*pcb;			/* The "normal" savearea */
	savearea		*upcb;			/* The "normal" user savearea */
	facility_context *curctx;		/* Current facility context */
	facility_context *deferctx;		/* Deferred facility context */
	facility_context facctx;		/* "Normal" facility context */
	struct vmmCntrlEntry *vmmCEntry;	/* Pointer current emulation context or 0 */
	struct vmmCntrlTable *vmmControl;	/* Pointer to virtual machine monitor control table */
	uint64_t		qactTimer;		/* Time thread needs to interrupt. This is a single-shot timer. Zero is unset */
	unsigned int	cioSpace;		/* Address space ID for in progress copyin/out */
#define	cioSwitchAway 0x80000000	/* Context switched away from thread since MapUserAddressSpace */
#define cioSwitchAwayb 0
	addr64_t		cioRelo;		/* Relocation value for in progress copyin/out */
	unsigned int	ksp;			/* points to TOP OF STACK or zero */
	unsigned int	preemption_count;	/* preemption count */
	unsigned int	bbDescAddr;		/* Points to Blue Box Trap descriptor area in kernel (page aligned) */
	unsigned int	bbUserDA;		/* Points to Blue Box Trap descriptor area in user (page aligned) */
	unsigned int	bbTableStart;	/* Points to Blue Box Trap dispatch area in user */
	unsigned int	emPendRupts;	/* Number of pending emulated interruptions */
	unsigned int	bbTaskID;		/* Opaque task ID for Blue Box threads */
	unsigned int	bbTaskEnv;		/* Opaque task data reference for Blue Box threads */
	unsigned int	specFlags;		/* Special flags */
    unsigned int    pmcovfl[8];     /* PMC overflow count */
    unsigned int    perfmonFlags;   /* Perfmon facility flags */
    unsigned int	bbTrap;			/* Blue Box trap vector */
    unsigned int	bbSysCall;		/* Blue Box syscall vector */
    unsigned int	bbInterrupt;	/* Blue Box interrupt vector */
    unsigned int	bbPending;		/* Blue Box pending interrupt vector */

/* special flags bits */

#define ignoreZeroFaultbit		0
#define floatUsedbit			1
#define vectorUsedbit			2
#define runningVMbit			4
#define floatCngbit				5
#define vectorCngbit			6
#define timerPopbit				7
#define userProtKeybit			8
#define FamVMenabit		 	    11
#define FamVMmodebit			12
#define perfMonitorbit          13
#define OnProcbit				14
/*	NOTE: Do not move or assign bit 31 without changing exception vector ultra fast path code */
#define bbThreadbit				28
#define bbNoMachSCbit	 		29
#define bbPreemptivebit			30
#define spfReserved1			31	/* See note above */

#define ignoreZeroFault		0x80000000  /* (1<<(31-ignoreZeroFaultbit)) */
#define floatUsed			0x40000000  /* (1<<(31-floatUsedbit)) */
#define vectorUsed			0x20000000  /* (1<<(31-vectorUsedbit)) */

#define runningVM			0x08000000  /* (1<<(31-runningVMbit)) */
#define floatCng			0x04000000  /* (1<<(31-floatCngbit)) */
#define vectorCng			0x02000000  /* (1<<(31-vectorCngbit)) */
#define timerPop			0x01000000  /* (1<<(31-timerPopbit)) */

#define userProtKey			0x00800000  /* (1<<(31-userProtKeybit)) */

#define	FamVMena			0x00100000  /* (1<<(31-FamVMenabit)) */
#define	FamVMmode			0x00080000  /* (1<<(31-FamVMmodebit)) */
#define perfMonitor         0x00040000  /* (1<<(31-perfMonitorbit)) */
#define	OnProc				0x00020000  /* (1<<(31-OnProcbit)) */

#define bbThread			0x00000008  /* (1<<(31-bbThreadbit)) */
#define bbNoMachSC			0x00000004  /* (1<<(31-bbNoMachSCbit)) */
#define bbPreemptive		0x00000002  /* (1<<(31-bbPreemptivebit)) */

#define fvChkb 0
#define fvChk 0x80000000

#ifdef	MACH_BSD
	unsigned long	cthread_self;	/* for use of cthread package */
#endif

} MachineThrAct, *MachineThrAct_t;

extern struct savearea *find_user_regs(thread_act_t act);
extern struct savearea *get_user_regs(thread_act_t);
extern struct savearea_fpu *find_user_fpu(thread_act_t act);
extern struct savearea_vec *find_user_vec(thread_act_t act);
extern struct savearea_vec *find_user_vec_curr(void);
extern int thread_enable_fpe(thread_act_t act, int onoff);

extern struct savearea *find_kern_regs(thread_act_t act);

extern void *act_thread_csave(void);
extern void act_thread_catt(void *ctx);
extern void act_thread_cfree(void *ctx);

#define	current_act_fast()	current_act()

#endif	/* _PPC_THREAD_ACT_H_ */
