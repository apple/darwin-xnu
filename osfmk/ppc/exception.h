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

/* Miscellaneous constants and structures used by the exception
 * handlers
 */

#ifndef _PPC_EXCEPTION_H_
#define _PPC_EXCEPTION_H_

#ifndef ASSEMBLER

#include <cpus.h>
#include <mach_kdb.h>
#include <mach_kdp.h>

#include <mach/machine/vm_types.h>
#include <mach/boolean.h>
#include <pexpert/pexpert.h>
#include <IOKit/IOInterrupts.h>
#include <ppc/machine_routines.h>

/*	Per processor CPU features */
struct procFeatures {
	unsigned int	Available;
#define pfFloat		0x80000000
#define pfFloatb	0
#define pfAltivec	0x40000000
#define pfAltivecb	1
#define pfAvJava	0x20000000
#define pfAvJavab	2
#define pfSMPcap	0x10000000
#define pfSMPcapb	3
#define pfCanSleep	0x08000000
#define pfCanSleepb	4
#define pfCanNap	0x04000000
#define pfCanNapb	5
#define pfCanDoze	0x02000000
#define pfCanDozeb	6
#define pfThermal	0x01000000
#define pfThermalb	7
#define pfThermInt	0x00800000
#define pfThermIntb	8
#define pfL23lck	0x00001000
#define pfL23lckb	19
#define pfWillNap	0x00000800
#define pfWillNapb	20
#define pfNoMSRir	0x00000400
#define pfNoMSRirb	21
#define pfL1nnc		0x00000200
#define pfL1nncb	22
#define pfL1i		0x00000100
#define pfL1ib		23
#define pfL1d		0x00000080
#define pfL1db		24
#define pfL1fa		0x00000040
#define pfL1fab		25
#define pfL2		0x00000020
#define pfL2b		26
#define pfL2fa		0x00000010
#define pfL2fab		27
#define pfL2i		0x00000008
#define pfL2ib		28
#define pfL3		0x00000004
#define pfL3b		29
#define pfL3fa		0x00000002
#define pfL3fab		30
#define pfValid		0x00000001
#define pfValidb	31
	unsigned short	rptdProc;
	unsigned short	lineSize;
	unsigned int	l1iSize;
	unsigned int	l1dSize;
	unsigned int	l2cr;
	unsigned int	l2Size;
	unsigned int	l3cr;
	unsigned int	l3Size;
	unsigned int	pfHID0;
	unsigned int	pfHID1;
	unsigned int	pfHID2;
	unsigned int	pfHID3;
	unsigned int	pfMSSCR0;
	unsigned int	pfMSSCR1;
	unsigned int	pfICTRL;
	unsigned int	pfLDSTCR;
};

typedef struct procFeatures procFeatures;

struct thrmControl {
	unsigned int	maxTemp;			/* Maximum temprature before damage */
	unsigned int	throttleTemp;		/* Temprature at which to throttle down */
	unsigned int	lowTemp;			/* Interrupt when temprature drops below */
	unsigned int	highTemp;			/* Interrupt when temprature exceeds this */
	unsigned int	thrm3val;			/* Value for thrm3 register */
	unsigned int	rsvd[3];			/* Pad to cache line */
};

typedef struct thrmControl thrmControl;

/* When an exception is taken, this info is accessed via sprg0 */
/* We should always have this one on a cache line boundary */
struct per_proc_info {
	unsigned short	cpu_number;
	unsigned short	cpu_flags;			/* Various low-level flags */
	vm_offset_t  	istackptr;
	vm_offset_t  	intstack_top_ss;

#if	MACH_KDP || MACH_KDB
	vm_offset_t  	debstackptr;
	vm_offset_t  	debstack_top_ss;
#else
	unsigned int	ppigas1[2];			/* Take up some space if no KDP or KDB */
#endif

	unsigned int	tempwork1;			/* Temp work area - monitor use carefully */
	unsigned int	save_exception_type;
	unsigned int	old_thread;

	/* PPC cache line boundary here - 020 */

	unsigned int	active_kloaded;		/* pointer to active_kloaded[CPU_NO] */
	unsigned int	cpu_data;			/* pointer to cpu_data[CPU_NO] */
	unsigned int	need_ast;			/* pointer to need_ast[CPU_NO] */
/*
 *	Note: the following two pairs of words need to stay in order and each pair must
 *	be in the same reservation (line) granule 
 */
	unsigned int	FPU_thread;			/* Thread owning the FPU on this cpu.*/
	unsigned int	FPU_vmmCtx;			/* Owing virtual machine context */
	unsigned int 	VMX_thread;			/* Thread owning the VMX on this cpu */
	unsigned int 	VMX_vmmCtx;			/* Owing virtual machine context */
	unsigned int	active_stacks;		/* pointer to active_stacks[CPU_NO] */

	/* PPC cache line boundary here - 040 */
	unsigned int 	quickfret;			/* Pointer to savearea for exception exit to free */
	unsigned int 	Lastpmap;			/* Last user pmap loaded  */
	unsigned int	userspace;			/* Last loaded user memory space ID  */
	unsigned int	userpmap;			/* User pmap - real address */
	unsigned int 	liveVRSave;			/* VRSave assiciated with live vector registers */
	unsigned int 	spcFlags;			/* Special thread flags */
	unsigned int	liveFPSCR;			/* FPSCR which is for the live context */
	unsigned int	ppigas05C;			/* Reserved area */

	/* PPC cache line boundary here - 060 */
	boolean_t		(*set_interrupts_enabled)(boolean_t);
	boolean_t		(*get_interrupts_enabled)(void);
	IOInterruptHandler	interrupt_handler;
	void *			interrupt_nub;
	unsigned int	interrupt_source;
	void *			interrupt_target;
	void *			interrupt_refCon;
	unsigned int	savedSave;			/* Savearea saved across sleep - must be 0 at boot */

	/* PPC cache line boundary here - 080 */
	unsigned int	MPsigpStat;			/* Signal Processor status (interlocked update for this one) */
#define MPsigpMsgp		0xC0000000		/* Message pending (busy + pass) */
#define MPsigpBusy		0x80000000		/* Processor area busy, i.e., locked */
#define MPsigpPass		0x40000000		/* Busy lock passed to receiving processor */
#define MPsigpSrc		0x000000FF		/* Processor that owns busy, i.e., the ID of */
										/*   whomever set busy. When a busy is passed, */
										/*   this is the requestor of the function. */
#define MPsigpFunc		0x0000FF00		/* Current function */
#define MPsigpIdle		0x00			/* No function pending */
#define MPsigpSigp		0x04			/* Signal a processor */
#define SIGPast		0					/* Requests an ast on target processor */
#define SIGPcpureq	1					/* Requests CPU specific function */
#define SIGPdebug	2					/* Requests a debugger entry */
#define SIGPwake	3					/* Wake up a sleeping processor */
#define CPRQtemp	0					/* Get temprature of processor */
#define CPRQtimebase	1					/* Get timebase of processor */
	unsigned int	MPsigpParm0;		/* SIGP parm 0 */
	unsigned int	MPsigpParm1;		/* SIGP parm 1 */
	unsigned int	MPsigpParm2;		/* SIGP parm 2 */
	cpu_id_t		cpu_id;
	vm_offset_t		start_paddr;
	unsigned int	ruptStamp[2];		/* Timebase at last interruption */

	/* PPC cache line boundary here - 0A0 */
	procFeatures 	pf;					/* Processor features */
	
	/* PPC cache line boundary here - 0E0 */
	thrmControl		thrm;				/* Thermal controls */
	
	/* PPC cache line boundary here - 100 */
	unsigned int	napStamp[2];		/* Time base when we napped */
	unsigned int	napTotal[2];		/* Total nap time in ticks */
	unsigned int	numSIGPast;			/* Number of SIGP asts recieved */
	unsigned int	numSIGPcpureq;		/* Number of SIGP cpu requests recieved */
	unsigned int	numSIGPdebug;		/* Number of SIGP debugs recieved */
	unsigned int	numSIGPwake;		/* Number of SIGP wakes recieved */
	
	/* PPC cache line boundary here - 120 */
	unsigned int	spcTRc;				/* Special trace count */
	unsigned int	spcTRp;				/* Special trace buffer pointer */
	unsigned int 	Uassist;			/* User Assist Word */
	unsigned int	rsrvd12C[5];		/* Reserved slots */
	
	/* PPC cache line boundary here - 140 */
	time_base_enable_t	time_base_enable;
	unsigned int	rsrvd140[7];		/* Reserved slots */
	
	/* PPC cache line boundary here - 160 */
	unsigned int	rsrvd160[8];		/* Reserved slots */
	
	/* PPC cache line boundary here - 180 */
	unsigned int	rsrvd180[8];		/* Reserved slots */
	
	/* PPC cache line boundary here - 1A0 */
	unsigned int	rsrvd1A0[8];		/* Reserved slots */
	
	/* PPC cache line boundary here - 1C0 */
	unsigned int	rsrvd1C0[8];		/* Reserved slots */
	
	/* PPC cache line boundary here - 1E0 */
	double			emfp0;				/* Copies of floating point registers */
	double			emfp1;				/* Used for emulation purposes */
	double			emfp2;
	double			emfp3;

	double			emfp4;				
	double			emfp5;
	double			emfp6;
	double			emfp7;

	double			emfp8;
	double			emfp9;
	double			emfp10;
	double			emfp11;
	
	double			emfp12;
	double			emfp13;
	double			emfp14;
	double			emfp15;
	
	double			emfp16;
	double			emfp17;
	double			emfp18;
	double			emfp19;

	double			emfp20;
	double			emfp21;
	double			emfp22;
	double			emfp23;
	
	double			emfp24;
	double			emfp25;
	double			emfp26;
	double			emfp27;
	
	double			emfp28;
	double			emfp29;
	double			emfp30;
	double			emfp31;

/*								   - 2E0 */
	unsigned int 	emfpscr_pad;
	unsigned int 	emfpscr;
	unsigned int	empadfp[6];
	
/*								   - 300 */
	unsigned int	emvr0[4];			/* Copies of vector registers used both */
	unsigned int	emvr1[4];			/* for full vector emulation or */
	unsigned int	emvr2[4];			/* as saveareas while assisting denorms */
	unsigned int	emvr3[4];
	unsigned int	emvr4[4];
	unsigned int	emvr5[4];
	unsigned int	emvr6[4];
	unsigned int	emvr7[4];
	unsigned int	emvr8[4];
	unsigned int	emvr9[4];
	unsigned int	emvr10[4];
	unsigned int	emvr11[4];
	unsigned int	emvr12[4];
	unsigned int	emvr13[4];
	unsigned int	emvr14[4];
	unsigned int	emvr15[4];
	unsigned int	emvr16[4];
	unsigned int	emvr17[4];
	unsigned int	emvr18[4];
	unsigned int	emvr19[4];
	unsigned int	emvr20[4];
	unsigned int	emvr21[4];
	unsigned int	emvr22[4];
	unsigned int	emvr23[4];
	unsigned int	emvr24[4];
	unsigned int	emvr25[4];
	unsigned int	emvr26[4];
	unsigned int	emvr27[4];
	unsigned int	emvr28[4];
	unsigned int	emvr29[4];
	unsigned int	emvr30[4];
	unsigned int	emvr31[4];
	unsigned int	emvscr[4];			
	unsigned int	empadvr[4];			
/*								   - 520 */

	unsigned int	patcharea[56];
/*								   - 600 */

};


extern struct per_proc_info per_proc_info[NCPUS];

typedef struct savearea {

/*	The following area corresponds to ppc_saved_state and ppc_thread_state */

/*										offset 0x0000 */
	unsigned int 	save_srr0;
	unsigned int 	save_srr1;
	unsigned int 	save_r0;
	unsigned int 	save_r1;
	unsigned int 	save_r2;
	unsigned int 	save_r3;
	unsigned int 	save_r4;
	unsigned int 	save_r5;

	unsigned int 	save_r6;
	unsigned int 	save_r7;
	unsigned int 	save_r8;
	unsigned int 	save_r9;
	unsigned int 	save_r10;
	unsigned int 	save_r11;
	unsigned int 	save_r12;
	unsigned int 	save_r13;

	unsigned int 	save_r14;
	unsigned int 	save_r15;
	unsigned int 	save_r16;
	unsigned int 	save_r17;
	unsigned int 	save_r18;
	unsigned int 	save_r19;
	unsigned int 	save_r20;
	unsigned int 	save_r21;

	unsigned int 	save_r22;
	unsigned int 	save_r23;
	unsigned int 	save_r24;
	unsigned int 	save_r25;
	unsigned int 	save_r26;	
	unsigned int 	save_r27;
	unsigned int 	save_r28;
	unsigned int 	save_r29;

	unsigned int 	save_r30;
	unsigned int 	save_r31;
	unsigned int 	save_cr;		
	unsigned int 	save_xer;
	unsigned int 	save_lr;
	unsigned int 	save_ctr;
	unsigned int	save_mq;				
	unsigned int	save_vrsave;
	
	unsigned int	save_sr_copyin;
	unsigned int	save_space;
	unsigned int	save_xfpscrpad;
	unsigned int	save_xfpscr;
	unsigned int	save_pad2[4];


/*	The following corresponds to ppc_exception_state */

/*										offset 0x00C0 */
	unsigned int 	save_dar;
	unsigned int 	save_dsisr;
	unsigned int	save_exception;
	unsigned int	save_pad3[5];

/*	The following corresponds to ppc_float_state */

/*										offset 0x00E0 */
	double			save_fp0;
	double			save_fp1;
	double			save_fp2;
	double			save_fp3;

	double			save_fp4;
	double			save_fp5;
	double			save_fp6;
	double			save_fp7;

	double			save_fp8;
	double			save_fp9;
	double			save_fp10;
	double			save_fp11;
	
	double			save_fp12;
	double			save_fp13;
	double			save_fp14;
	double			save_fp15;
	
	double			save_fp16;
	double			save_fp17;
	double			save_fp18;
	double			save_fp19;

	double			save_fp20;
	double			save_fp21;
	double			save_fp22;
	double			save_fp23;
	
	double			save_fp24;
	double			save_fp25;
	double			save_fp26;
	double			save_fp27;
	
	double			save_fp28;
	double			save_fp29;
	double			save_fp30;
	double			save_fp31;

	unsigned int 	save_fpscr_pad;
	unsigned int 	save_fpscr;
	unsigned int	save_pad4[6];
	
/*	The following is the save area for the VMX registers */

/*										offset 0x0200 */
	unsigned int	save_vr0[4];
	unsigned int	save_vr1[4];
	unsigned int	save_vr2[4];
	unsigned int	save_vr3[4];
	unsigned int	save_vr4[4];
	unsigned int	save_vr5[4];
	unsigned int	save_vr6[4];
	unsigned int	save_vr7[4];
	unsigned int	save_vr8[4];
	unsigned int	save_vr9[4];
	unsigned int	save_vr10[4];
	unsigned int	save_vr11[4];
	unsigned int	save_vr12[4];
	unsigned int	save_vr13[4];
	unsigned int	save_vr14[4];
	unsigned int	save_vr15[4];
	unsigned int	save_vr16[4];
	unsigned int	save_vr17[4];
	unsigned int	save_vr18[4];
	unsigned int	save_vr19[4];
	unsigned int	save_vr20[4];
	unsigned int	save_vr21[4];
	unsigned int	save_vr22[4];
	unsigned int	save_vr23[4];
	unsigned int	save_vr24[4];
	unsigned int	save_vr25[4];
	unsigned int	save_vr26[4];
	unsigned int	save_vr27[4];
	unsigned int	save_vr28[4];
	unsigned int	save_vr29[4];
	unsigned int	save_vr30[4];
	unsigned int	save_vr31[4];
	unsigned int	save_vscr[4];			/* Note that this is always valid if VMX has been used */
	unsigned int	save_pad5[4];			/* Insures that vrvalid is on a cache line */
	unsigned int	save_vrvalid;			/* VRs that have been saved */
	unsigned int	save_pad6[7];
	
/*	The following is the save area for the segment registers */

/*										offset 0x0440 */

	unsigned int 	save_sr0;
	unsigned int 	save_sr1;
	unsigned int 	save_sr2;
	unsigned int 	save_sr3;
	unsigned int 	save_sr4;
	unsigned int 	save_sr5;
	unsigned int 	save_sr6;
	unsigned int 	save_sr7;

	unsigned int 	save_sr8;
	unsigned int 	save_sr9;
	unsigned int 	save_sr10;
	unsigned int 	save_sr11;
	unsigned int 	save_sr12;
	unsigned int 	save_sr13;
	unsigned int 	save_sr14;
	unsigned int 	save_sr15;

/* The following are the control area for this save area */

/*										offset 0x0480 */

	struct savearea	*save_prev;				/* The address of the previous normal savearea */
	struct savearea	*save_prev_float;		/* The address of the previous floating point savearea */
	struct savearea	*save_prev_vector;		/* The address of the previous vector savearea */
	struct savearea	*save_qfret;			/* The "quick release" chain */
	struct savearea	*save_phys;				/* The physical address of this savearea */
	struct thread_activation	*save_act;	/* Pointer to the associated activation */
	unsigned int	save_flags;				/* Various flags */
#define save_perm	0x80000000				/* Permanent area, cannot be released */
	unsigned int	save_level_fp;			/* Level that floating point state belongs to */
	unsigned int	save_level_vec;			/* Level that vector state belongs to */

} savearea;

typedef struct savectl {					/* Savearea control */
	
	unsigned int	*sac_next;				/* Points to next savearea page that has a free slot  - real */
	unsigned int	sac_vrswap;				/* XOR mask to swap V to R or vice versa */
	unsigned int	sac_alloc;				/* Bitmap of allocated slots */
	unsigned int	sac_flags;				/* Various flags */
} savectl;

struct Saveanchor {
	unsigned int	savelock;				/* Lock word for savearea manipulation */
	int				savecount;				/* The total number of save areas allocated */
	int				saveinuse;				/* Number of areas in use */
	int				savemin;				/* We abend if lower than this */
	int				saveneghyst;			/* The negative hysteresis value */
	int				savetarget;				/* The target point for free save areas */
	int				saveposhyst;			/* The positive hysteresis value */
	unsigned int	savefree;				/* Anchor for the freelist queue */
											/* Cache line (32-byte) boundary */
	int				savextnd;				/* Free list extention count */
	int				saveneed;				/* Number of savearea's needed.  So far, we assume we need 3 per activation */
	int				savemaxcount;
	int				savespare[5];			/* Spare */
};


extern char *trap_type[];

#endif /* ndef ASSEMBLER */

#define sac_empty	0xC0000000				/* Mask with all entries empty */
#define sac_cnt		2						/* Number of entries per page */
#define sac_busy	0x80000000				/* This page is busy - used during initial allocation */
#define sac_perm	0x40000000				/* Page permanently assigned */

#define SAVattach	0x80000000				/* Savearea is attached to a thread */
#define SAVfpuvalid	0x40000000				/* Savearea contains FPU context */
#define SAVvmxvalid	0x20000000				/* Savearea contains VMX context */
#define SAVinuse	0xE0000000				/* Save area is inuse */
#define SAVrststk	0x00010000				/* Indicates that the current stack should be reset to empty */
#define SAVsyscall	0x00020000				/* Indicates that the savearea is associated with a syscall */
#define SAVredrive	0x00040000				/* Indicates that the low-level fault handler associated */
											/* with this savearea should be redriven */

/* cpu_flags defs */
#define SIGPactive	0x8000
#define needSRload	0x4000
#define turnEEon	0x2000
#define traceBE     0x1000					/* user mode BE tracing in enabled */
#define traceBEb    3						/* bit number for traceBE */
#define BootDone	0x0100
#define loadMSR		0x7FF4

#define T_VECTOR_SIZE	4					/* function pointer size */
#define InitialSaveMin		4				/* The initial value for the minimum number of saveareas */
#define InitialNegHysteresis	5			/* The number off from target before we adjust upwards */
#define InitialPosHysteresis	10			/* The number off from target before we adjust downwards */
#define InitialSaveTarget	20				/* The number of saveareas for an initial target */
#define	InitialSaveAreas	20				/* The number of saveareas to allocate at boot */
#define	InitialSaveBloks	(InitialSaveAreas+sac_cnt-1)/sac_cnt	/* The number of savearea blocks to allocate at boot */

/* Hardware exceptions */

#define T_IN_VAIN				(0x00 * T_VECTOR_SIZE)
#define T_RESET					(0x01 * T_VECTOR_SIZE)
#define T_MACHINE_CHECK			(0x02 * T_VECTOR_SIZE)
#define T_DATA_ACCESS			(0x03 * T_VECTOR_SIZE)
#define T_INSTRUCTION_ACCESS	(0x04 * T_VECTOR_SIZE)
#define T_INTERRUPT				(0x05 * T_VECTOR_SIZE)
#define T_ALIGNMENT				(0x06 * T_VECTOR_SIZE)
#define T_PROGRAM				(0x07 * T_VECTOR_SIZE)
#define T_FP_UNAVAILABLE		(0x08 * T_VECTOR_SIZE)
#define T_DECREMENTER			(0x09 * T_VECTOR_SIZE)
#define T_IO_ERROR				(0x0a * T_VECTOR_SIZE)
#define T_RESERVED				(0x0b * T_VECTOR_SIZE)
#define T_SYSTEM_CALL			(0x0c * T_VECTOR_SIZE)
#define T_TRACE					(0x0d * T_VECTOR_SIZE)
#define T_FP_ASSIST				(0x0e * T_VECTOR_SIZE)
#define T_PERF_MON				(0x0f * T_VECTOR_SIZE)
#define T_VMX					(0x10 * T_VECTOR_SIZE)
#define T_INVALID_EXCP0			(0x11 * T_VECTOR_SIZE)
#define T_INVALID_EXCP1			(0x12 * T_VECTOR_SIZE)
#define T_INVALID_EXCP2			(0x13 * T_VECTOR_SIZE)
#define T_INSTRUCTION_BKPT		(0x14 * T_VECTOR_SIZE)
#define T_SYSTEM_MANAGEMENT		(0x15 * T_VECTOR_SIZE)
#define T_ALTIVEC_ASSIST		(0x16 * T_VECTOR_SIZE)
#define T_THERMAL				(0x17 * T_VECTOR_SIZE)
#define T_INVALID_EXCP5			(0x18 * T_VECTOR_SIZE)
#define T_INVALID_EXCP6			(0x19 * T_VECTOR_SIZE)
#define T_INVALID_EXCP7			(0x1A * T_VECTOR_SIZE)
#define T_INVALID_EXCP8			(0x1B * T_VECTOR_SIZE)
#define T_INVALID_EXCP9			(0x1C * T_VECTOR_SIZE)
#define T_INVALID_EXCP10		(0x1D * T_VECTOR_SIZE)
#define T_INVALID_EXCP11		(0x1E * T_VECTOR_SIZE)
#define T_INVALID_EXCP12		(0x1F * T_VECTOR_SIZE)
#define T_INVALID_EXCP13		(0x20 * T_VECTOR_SIZE)

#define T_RUNMODE_TRACE			(0x21 * T_VECTOR_SIZE) /* 601 only */

#define T_SIGP					(0x22 * T_VECTOR_SIZE)
#define T_PREEMPT				(0x23 * T_VECTOR_SIZE)
#define T_CSWITCH				(0x24 * T_VECTOR_SIZE)
#define T_SHUTDOWN				(0x25 * T_VECTOR_SIZE)

#define T_AST					(0x100 * T_VECTOR_SIZE) 
#define T_MAX					T_SHUTDOWN		 /* Maximum exception no */

#define	EXCEPTION_VECTOR(exception)	(exception * 0x100 /T_VECTOR_SIZE )

#ifndef ASSEMBLER

typedef struct resethandler {
	unsigned int	type;
	vm_offset_t	call_paddr;
	vm_offset_t	arg__paddr;
} resethandler_t;

extern resethandler_t ResetHandler;

#endif

#define	RESET_HANDLER_NULL	0x0
#define	RESET_HANDLER_START	0x1

#endif /* _PPC_EXCEPTION_H_ */
