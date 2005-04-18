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

#include <ppc/savearea.h>

#ifndef ASSEMBLER

#include <cpus.h>
#include <mach_kdb.h>
#include <mach_kdp.h>

#include <mach/machine/vm_types.h>
#include <mach/boolean.h>
#include <kern/cpu_data.h>
#include <pexpert/pexpert.h>
#include <IOKit/IOInterrupts.h>
#include <ppc/machine_routines.h>

/*	Per processor CPU features */
#pragma pack(4)							/* Make sure the structure stays as we defined it */
struct procFeatures {
	unsigned int	Available;			/* 0x000 */
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
#define pfSlowNap	0x00400000
#define pfSlowNapb	9
#define pfNoMuMMCK	0x00200000
#define pfNoMuMMCKb	10
#define pfNoL2PFNap	0x00100000
#define pfNoL2PFNapb	11
#define pfSCOMFixUp	0x00080000
#define pfSCOMFixUpb	12
#define	pfHasDcba	0x00040000
#define	pfHasDcbab	13
#define	pfL1fa		0x00010000
#define	pfL1fab		15
#define pfL2		0x00008000
#define pfL2b		16
#define pfL2fa		0x00004000
#define pfL2fab		17
#define pfL2i		0x00002000
#define pfL2ib		18
#define pfLClck		0x00001000
#define pfLClckb	19
#define pfWillNap	0x00000800
#define pfWillNapb	20
#define pfNoMSRir	0x00000400
#define pfNoMSRirb	21
#define pfL3pdet	0x00000200
#define pfL3pdetb	22
#define	pf128Byte	0x00000080
#define	pf128Byteb	24
#define	pf32Byte	0x00000020
#define	pf32Byteb	26
#define	pf64Bit		0x00000010
#define	pf64Bitb	27
#define pfL3		0x00000004
#define pfL3b		29
#define pfL3fa		0x00000002
#define pfL3fab		30
#define pfValid		0x00000001
#define pfValidb	31
	unsigned short	rptdProc;			/* 0x004 */
	unsigned short	lineSize;			/* 0x006 */
	unsigned int	l1iSize;			/* 0x008 */
	unsigned int	l1dSize;			/* 0x00C */
	unsigned int	l2cr;				/* 0x010 */
	unsigned int	l2Size;				/* 0x014 */
	unsigned int	l3cr;				/* 0x018 */
	unsigned int	l3Size;				/* 0x01C */
	unsigned int	pfMSSCR0;			/* 0x020 */
	unsigned int	pfMSSCR1;			/* 0x024 */
	unsigned int	pfICTRL;			/* 0x028 */
	unsigned int	pfLDSTCR;			/* 0x02C */
	unsigned int	pfLDSTDB;			/* 0x030 */
	unsigned int	pfMaxVAddr;			/* 0x034 */
	unsigned int	pfMaxPAddr;			/* 0x038 */
	unsigned int	pfPTEG;				/* 0x03C */
	uint64_t		pfHID0;				/* 0x040 */
	uint64_t		pfHID1;				/* 0x048 */
	uint64_t		pfHID2;				/* 0x050 */
	uint64_t		pfHID3;				/* 0x058 */
	uint64_t		pfHID4;				/* 0x060 */
	uint64_t		pfHID5;				/* 0x068 */
	unsigned int	l2crOriginal;		/* 0x070 */
	unsigned int	l3crOriginal;		/* 0x074 */
	unsigned int	pfBootConfig;		/* 0x078 */
	unsigned int	pfPowerModes;		/* 0x07C */
#define pmDPLLVmin		0x00010000
#define pmDPLLVminb		15
#define pmPowerTune		0x00000004
#define pmPowerTuneb	29
#define pmDFS			0x00000002
#define pmDFSb			30
#define pmDualPLL		0x00000001
#define pmDualPLLb		31
	unsigned int	pfPowerTune0;		/* 0x080 */
	unsigned int	pfPowerTune1;		/* 0x084 */
	unsigned int	rsrvd88[6];			/* 0x088 */
};
#pragma pack()

typedef struct procFeatures procFeatures;


/*
 *
 *		Various performance counters
 */
#pragma pack(4)							/* Make sure the structure stays as we defined it */
struct hwCtrs {	

	unsigned int	hwInVains; 				/* In vain */
	unsigned int	hwResets;				/* Reset */
	unsigned int	hwMachineChecks;		/* Machine check */
	unsigned int	hwDSIs; 				/* DSIs */
	unsigned int	hwISIs; 				/* ISIs */
	unsigned int	hwExternals; 			/* Externals */
	unsigned int	hwAlignments; 			/* Alignment */
	unsigned int	hwPrograms; 			/* Program */
	unsigned int	hwFloatPointUnavailable;	/* Floating point */
	unsigned int	hwDecrementers; 		/* Decrementer */
	unsigned int	hwIOErrors; 			/* I/O error */
	unsigned int	hwrsvd0; 				/* Reserved */
	unsigned int	hwSystemCalls; 			/* System call */
	unsigned int	hwTraces; 				/* Trace */
	unsigned int	hwFloatingPointAssists; /* Floating point assist */
	unsigned int	hwPerformanceMonitors; 	/* Performance monitor */
	unsigned int	hwAltivecs; 			/* VMX */
	unsigned int	hwrsvd1; 				/* Reserved */
	unsigned int	hwrsvd2; 				/* Reserved */
	unsigned int	hwrsvd3; 				/* Reserved */
	unsigned int	hwInstBreakpoints; 		/* Instruction breakpoint */
	unsigned int	hwSystemManagements; 	/* System management */
	unsigned int	hwAltivecAssists; 		/* Altivec Assist */
	unsigned int	hwThermal;				/* Thermals */
	unsigned int	hwrsvd5; 				/* Reserved */
	unsigned int	hwrsvd6; 				/* Reserved */
	unsigned int	hwrsvd7; 				/* Reserved */
	unsigned int	hwrsvd8;				/* Reserved */
	unsigned int	hwrsvd9; 				/* Reserved */
	unsigned int	hwrsvd10; 				/* Reserved */
	unsigned int	hwrsvd11; 				/* Reserved */
	unsigned int	hwrsvd12; 				/* Reserved */
	unsigned int	hwrsvd13; 				/* Reserved */
	unsigned int	hwTrace601;				/* Trace */
	unsigned int	hwSIGPs; 				/* SIGP */
	unsigned int	hwPreemptions; 			/* Preemption */
	unsigned int	hwContextSwitchs;		/* Context switch */
	unsigned int	hwShutdowns;			/* Shutdowns */
	unsigned int	hwChokes;				/* System ABENDs */
	unsigned int	hwDataSegments;			/* Data Segment Interruptions */
	unsigned int	hwInstructionSegments;	/* Instruction Segment Interruptions */
	unsigned int	hwSoftPatches;			/* Soft Patch interruptions */
	unsigned int	hwMaintenances;			/* Maintenance interruptions */
	unsigned int	hwInstrumentations;		/* Instrumentation interruptions */
	unsigned int	hwrsvd14;				/* Reserved */
	unsigned int 	hwhdec;					/* 0B4 Hypervisor decrementer */

	unsigned int	hwspare0[11];			/* 0B8 Reserved */
	unsigned int	hwspare0a;				/* 0E4 Reserved */
	unsigned int	hwspare0b;				/* 0E8 Reserved */
	unsigned int	hwspare0c;				/* 0EC Reserved */
	unsigned int	hwspare0d;				/* 0F0 Reserved */
	unsigned int	hwIgnored;				/* 0F4 Interruptions ignored */
	unsigned int	hwRedrives;				/* 0F8 Number of redriven interrupts */
	unsigned int	hwSteals;				/* 0FC Steals */
/*											   100 */

	unsigned int 	hwMckHang;				/* ? */
	unsigned int 	hwMckSLBPE;				/* ? */
	unsigned int 	hwMckTLBPE;				/* ? */
	unsigned int 	hwMckERCPE;				/* ? */
	unsigned int	hwMckL1DPE;				/* ? */
	unsigned int	hwMckL1TPE;				/* ? */
	unsigned int 	hwMckUE;				/* ? */
	unsigned int 	hwMckIUE;				/* ? */
	unsigned int 	hwMckIUEr;				/* ? */
	unsigned int 	hwMckDUE;				/* ? */
	unsigned int 	hwMckDTW;				/* ? */
	unsigned int 	hwMckUnk;				/* ? */
	unsigned int 	hwMckExt;				/* ? */
	unsigned int 	hwMckICachePE;			/* ? */
	unsigned int 	hwMckITagPE;			/* ? */
	unsigned int 	hwMckIEratPE;			/* ? */
	unsigned int 	hwMckDEratPE;			/* ? */
	unsigned int	hwspare2[15];			/* Pad to next 128 bndry */
/*											0x180 */

	unsigned int	napStamp[2];			/* Time base when we napped */
	unsigned int	napTotal[2];			/* Total nap time in ticks */
	unsigned int	numSIGPast;				/* Number of SIGP asts recieved */
	unsigned int	numSIGPcpureq;			/* Number of SIGP cpu requests recieved */
	unsigned int	numSIGPdebug;			/* Number of SIGP debugs recieved */
	unsigned int	numSIGPwake;			/* Number of SIGP wakes recieved */
	unsigned int	numSIGPtimo;			/* Number of SIGP send timeouts */
	unsigned int	numSIGPmast;			/* Number of SIGPast messages merged */
	unsigned int	numSIGPmwake;			/* Number of SIGPwake messages merged */
	unsigned int	numSIGPcall;			/* Number of SIGPcall messages received */
	
	unsigned int	hwspare3[20];			/* Pad to 512 */
	
};
#pragma pack()

typedef struct hwCtrs hwCtrs;

struct patch_entry {
	unsigned int	*addr;
	unsigned int	data;
	unsigned int	type;
	unsigned int	value;
};

typedef struct patch_entry patch_entry_t;

#define	PATCH_INVALID		0
#define	PATCH_PROCESSOR		1
#define	PATCH_FEATURE		2

#define PATCH_TABLE_SIZE	12

#define PatchExt32		0x80000000
#define PatchExt32b		0
#define PatchLwsync		0x40000000
#define PatchLwsyncb	1

/* When an exception is taken, this info is accessed via sprg0 */
/* We should always have this one on a cache line boundary */

#pragma pack(4)							/* Make sure the structure stays as we defined it */
struct per_proc_info {
	unsigned short	cpu_number;
	unsigned short	cpu_flags;			/* Various low-level flags */
	vm_offset_t  	istackptr;
	vm_offset_t  	intstack_top_ss;

	vm_offset_t  	debstackptr;
	vm_offset_t  	debstack_top_ss;

	unsigned int 	spcFlags;			/* Special thread flags */
	unsigned int 	Uassist;			/* User Assist Word */
	unsigned int	old_thread;

	/* PPC cache line boundary here - 020 */

	uint64_t		rtcPop;				/* Real Time Clock pop */
	unsigned int	need_ast;			/* pointer to need_ast[CPU_NO] */
/*
 *	Note: the following two pairs of words need to stay in order and each pair must
 *	be in the same reservation (line) granule 
 */
	struct facility_context	*FPU_owner;	/* Owner of the FPU on this cpu */
	unsigned int 	liveVRSave;			/* VRSave assiciated with live vector registers */
	struct facility_context	*VMX_owner;	/* Owner of the VMX on this cpu */
	unsigned int 	holdQFret;			/* Hold off releasing quickfret list */
	unsigned int 	save_exception_type;

	/* PPC cache line boundary here - 040 */
	addr64_t		quickfret;			/* List of saveareas to release */
	addr64_t		lclfree;			/* Pointer to local savearea list */
	unsigned int	lclfreecnt;			/* Entries in local savearea list */
	unsigned int	spcTRc;				/* Special trace count */
	unsigned int	spcTRp;				/* Special trace buffer pointer */
	unsigned int	ppbbTaskEnv;		/* BlueBox Task Environment */

	/* PPC cache line boundary here - 060 */
	boolean_t		interrupts_enabled;
	IOInterruptHandler	interrupt_handler;
	void *			interrupt_nub;
	unsigned int	interrupt_source;
	void *			interrupt_target;
	void *			interrupt_refCon;
	uint64_t		next_savearea;			/* pointer to the next savearea */

	/* PPC cache line boundary here - 080 */
	unsigned int	MPsigpStat;			/* Signal Processor status (interlocked update for this one) */
#define MPsigpMsgp		0xC0000000		/* Message pending (busy + pass ) */
#define MPsigpBusy		0x80000000		/* Processor area busy, i.e., locked */
#define MPsigpPass		0x40000000		/* Busy lock passed to receiving processor */
#define MPsigpAck		0x20000000		/* Ack Busy lock passed to receiving processor */
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
#define SIGPcall	4					/* Call a function on a processor */

#define CPRQtemp	0					/* Get temprature of processor */
#define CPRQtimebase	1				/* Get timebase of processor */
#define CPRQsegload	2					/* Segment registers reload */
#define CPRQscom	3					/* SCOM */
#define CPRQchud	4					/* CHUD perfmon */
#define CPRQsps		5					/* Set Processor Speed */

	unsigned int	MPsigpParm0;		/* SIGP parm 0 */
	unsigned int	MPsigpParm1;		/* SIGP parm 1 */
	unsigned int	MPsigpParm2;		/* SIGP parm 2 */
	cpu_id_t		cpu_id;
	vm_offset_t		start_paddr;
	unsigned int	ruptStamp[2];		/* Timebase at last interruption */

	/* PPC cache line boundary here - 0A0 */
	procFeatures 	pf;					/* Processor features */
	
	/* PPC cache line boundary here - 140 */
	unsigned int	ppRsvd140[8];		/* Reserved */
	
	/* PPC cache line boundary here - 160 */
	time_base_enable_t	time_base_enable;
	unsigned int	ppRsvd164[4];		/* Reserved */
	cpu_data_t		pp_cpu_data;		/* cpu data info */
	
	/* PPC cache line boundary here - 180 */
	unsigned int	ppRsvd180[2];		/* Reserved */
	uint64_t		validSegs;			/* Valid SR/STB slots */
	addr64_t		ppUserPmap;			/* Current user state pmap (physical address) */
	unsigned int	ppUserPmapVirt;		/* Current user state pmap (virtual address) */
	unsigned int	ppMapFlags;			/* Mapping flags */
	
	/* PPC cache line boundary here - 1A0 */
	unsigned short	ppInvSeg;			/* Forces complete invalidate of SRs/SLB (this must stay with ppInvSeg) */
	unsigned short	ppCurSeg;			/* Set to 1 if user segments, 0 if kernel (this must stay with ppInvSeg) */
	unsigned int	ppSegSteal;			/* Count of segment slot steals */
	ppnum_t			VMMareaPhys;		/* vmm state page physical addr */
	unsigned int	VMMXAFlgs;			/* vmm extended flags */
	unsigned int	FAMintercept;		/* vmm FAM Exceptions to intercept */
	unsigned int	rsrvd1B4[3];		/* Reserved slots */
	
	/* PPC cache line boundary here - 1C0 */
	unsigned int	ppCIOmp[16];		/* Linkage mapping for copyin/out - 64 bytes */
	
	/* PPC cache line boundary here - 200 */
	uint64_t		tempr0;				/* temporary savearea */
	uint64_t		tempr1;			
	uint64_t		tempr2;
	uint64_t		tempr3;

	uint64_t		tempr4;				
	uint64_t		tempr5;
	uint64_t		tempr6;
	uint64_t		tempr7;

	uint64_t		tempr8;
	uint64_t		tempr9;
	uint64_t		tempr10;
	uint64_t		tempr11;
	
	uint64_t		tempr12;
	uint64_t		tempr13;
	uint64_t		tempr14;
	uint64_t		tempr15;
	
	uint64_t		tempr16;
	uint64_t		tempr17;
	uint64_t		tempr18;
	uint64_t		tempr19;

	uint64_t		tempr20;
	uint64_t		tempr21;
	uint64_t		tempr22;
	uint64_t		tempr23;
	
	uint64_t		tempr24;
	uint64_t		tempr25;
	uint64_t		tempr26;
	uint64_t		tempr27;
	
	uint64_t		tempr28;
	uint64_t		tempr29;
	uint64_t		tempr30;
	uint64_t		tempr31;


	/* PPC cache line boundary here - 300 */
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

/*								   - 400 */
	unsigned int 	emfpscr_pad;
	unsigned int 	emfpscr;
	unsigned int	empadfp[6];
	
/*								   - 420 */
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
/*								   - 640 */
/* note implicit dependence on kSkipListMaxLists, which must be <= 28 */
    addr64_t		skipListPrev[28];	/* prev ptrs saved as side effect of calling mapSearchFull() */
    
/*								   - 720 */

	unsigned int	patcharea[56];
/*								   - 800 */

	hwCtrs			hwCtr;					/* Hardware exception counters */
/*								   - A00 */

	unsigned int	pppadpage[384];			/* Pad to end of page */
/*								   - 1000 */


};

#define	pp_preemption_count	pp_cpu_data.preemption_level
#define	pp_simple_lock_count	pp_cpu_data.simple_lock_count
#define	pp_interrupt_level	pp_cpu_data.interrupt_level

#pragma pack()


extern struct per_proc_info per_proc_info[NCPUS];


extern char *trap_type[];

#endif /* ndef ASSEMBLER */											/* with this savearea should be redriven */

/* cpu_flags defs */
#define SIGPactive	0x8000
#define needSRload	0x4000
#define turnEEon	0x2000
#define traceBE     0x1000					/* user mode BE tracing in enabled */
#define traceBEb    3						/* bit number for traceBE */
#define SleepState	0x0800
#define SleepStateb	4
#define mcountOff	0x0400
#define SignalReady	0x0200
#define BootDone	0x0100
#define loadMSR		0x7FF4

#define T_VECTOR_SIZE	4					/* function pointer size */

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
#define T_EMULATE				(0x20 * T_VECTOR_SIZE)

#define T_RUNMODE_TRACE			(0x21 * T_VECTOR_SIZE) /* 601 only */

#define T_SIGP					(0x22 * T_VECTOR_SIZE)
#define T_PREEMPT				(0x23 * T_VECTOR_SIZE)
#define T_CSWITCH				(0x24 * T_VECTOR_SIZE)
#define T_SHUTDOWN				(0x25 * T_VECTOR_SIZE)
#define T_CHOKE					(0x26 * T_VECTOR_SIZE)

#define T_DATA_SEGMENT			(0x27 * T_VECTOR_SIZE)
#define T_INSTRUCTION_SEGMENT	(0x28 * T_VECTOR_SIZE)

#define T_SOFT_PATCH			(0x29 * T_VECTOR_SIZE)
#define T_MAINTENANCE			(0x2A * T_VECTOR_SIZE)
#define T_INSTRUMENTATION		(0x2B * T_VECTOR_SIZE)
#define T_ARCHDEP0				(0x2C * T_VECTOR_SIZE)
#define T_HDEC					(0x2D * T_VECTOR_SIZE)

#define T_AST					(0x100 * T_VECTOR_SIZE) 
#define T_MAX					T_CHOKE		 /* Maximum exception no */

#define	T_FAM					0x00004000

#define	EXCEPTION_VECTOR(exception)	(exception * 0x100 / T_VECTOR_SIZE )

/*
 *		System choke (failure) codes 
 */
 
#define failDebug 0
#define failStack 1
#define failMapping 2
#define failContext 3
#define failNoSavearea 4
#define failSaveareaCorr 5
#define failBadLiveContext 6
#define	failSkipLists 7
#define	failUnalignedStk 8

/* Always must be last - update failNames table in model_dep.c as well */
#define failUnknown 9

#ifndef ASSEMBLER

#pragma pack(4)							/* Make sure the structure stays as we defined it */
typedef struct resethandler {
	unsigned int	type;
	vm_offset_t	call_paddr;
	vm_offset_t	arg__paddr;
} resethandler_t;
#pragma pack()

extern resethandler_t ResetHandler;

#endif

#define	RESET_HANDLER_NULL	0x0
#define	RESET_HANDLER_START	0x1
#define	RESET_HANDLER_BUPOR	0x2
#define	RESET_HANDLER_IGNORE	0x3

#endif /* _PPC_EXCEPTION_H_ */
