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
 * @OSF_FREE_COPYRIGHT@
 */
/*
 * @APPLE_FREE_COPYRIGHT@
 */

/*
	MPPlugIn.h

	Herein we find all the global MP plugin stuff

	Lovingly crafted by Bill Angell using traditional methods

*/


/*
 *	External hook completion codes
 *
 *	The MP plugin's external interrupt hook returns one of these codes
 */

#define kMPVainInterrupt 0							/* Interruption in vain -- ignore it */
#define kMPIOInterruptPending 1						/* This is an I/O interruption -- handle it */
#define kMPSignalPending 2							/* This is a pending signal -- handle it */


/* ***********************************************************************
 * Entry point jump table entry numbers
 * *********************************************************************** */

#define kCountProcessors 		0
#define kStartProcessor 		1					/* ->cpu address, ->start address, ->pass-thru parm */
#define kResumeProcessor 		2					/* ->cpu address */
#define kStopProcessor 			3					/* ->cpu address */
#define kResetProcessor 		4					/* ->cpu address */
#define kSignalProcessor 		5					/* ->cpu address */
#define kStoreProcessorStatus 	6					/* ->cpu address, ->status area address */
#define kSynchClock 			7					/* ->cpu address */
#define kExternalHook 			8					/* no parms */
#define kProcessorState 		9					/* ->cpu address */
#define kRunSIGPRun 			10					/* no parms */
#define kPhoneyFirmware			11					/* Dummy kernel for alternate processors */
	
#define kMPPlugInMaxCall 		11					/* set MPPlugInMaxCall to the highest-numbered call */


/* ***********************************************************************
 *	MP Plug-In specification
 *
 *	The address of this area is passed to the MP plugin by the initialization code. If the
 *	version ID and the installed hardware match the MP plugin, it returns its memory
 *	requirements and a table of offsets to its entry points.
 * *********************************************************************** */

#define kMPPlugInVersionID		1

#define kSIGPUninitializedState	0
#define kSIGPResetState			1
#define kSIGPStoppedState		2
#define kSIGPOperatingState		3
#define kSIGPErrorState			4

#define kSIGPnoErr				0
#define kSIGPInvalidStateErr	-3999
#define kSIGPInterfaceBusyErr	-3998
#define kSIGPPrivilegeErr		-3997
#define kSIGPNoPlugInErr		-3996
#define kTimeBaseSynchronizationErr		-3995
#define kSIGPTargetAddrErr		-3994
#define kSIGPInvalidStatusErr	-3993

#define kMPPlugInInstallFailed	-4999
#define kMPPlugInInternalError	-4998

/* 
 * ***********************************************************************
 *	Signal processor request codes
 * ***********************************************************************
 */

#define SIGPast					0					/* Requests an ast on target processor */
#define SIGPptlb				1					/* Requests a total purge of the TLB */
#define SIGPkdb					2					/* Requests a KDB entry */

/* 
 * ***********************************************************************
 *	Temporary debugging error codes (well, at least as temporary as the income tax)
 * ***********************************************************************
 */
#define kMPPHairyPalms			-10002
#define kMPPOffline				-10003
#define kMPPBadState			-10004
#define kMPPInvalCPU			-10005
#define kMPPCantLock			-10006
#define kMPPNotReady			-10007
#define kMPPNotStopped			-10008
#define kMPPBadCPU				-10009
#define kMPPOnly1CPU			-10010
#define kMPPBadVers				-10011
#define kMPPNotRunning			-10012
#define kMPPTimeOut				-10013
#define kMPPInitTO1				-10014
#define kMPPInitTO2				-10015
#define kMPPInitTO3				-10016


/* 
 * ***********************************************************************
 *	Let's define some hardware stuff
 * ***********************************************************************
 */
 
#define Bandit1			0xF2000000
#define PCI1AdrReg		0xF2800000
#define GrandCentral	0xF3000000
#define EtherNetROM		0xF3019000
#define HammerHead		0xF8000000
#define ArbConfig		0x0090
#define TwoCPU			0x02
#define WhoAmI			0x00B0
#define PriCPU			0x10
#define SecCPU			0x08
#define IntReg			0x00C0
#define SecInt			0x80


/* 
 * ***********************************************************************
 *	Let's define the flags for MPPInterface
 * ***********************************************************************
 */

#define SpinTimeOut		30000000

#define MPPICmsgp		0xc0000000					/* Message pending (busy + pass) */
#define MPPICBusy		0x80000000					/* Processor area busy, i.e., locked */
#define MPPICPass		0x40000000					/* Busy lock passed to receiving processor */
#define MPPICOnline		0x20000000					/* Processor is online */
#define MPPICReady		0x10000000					/* Processor is ready, i.e., started, not reset */
#define MPPICStop		0x08000000					/* Processor is stopped */
#define MPPICBset		0x000000FF					/* Processor that owns busy, i.e., the ID of */
													/*   whomever set busy. When a busy is passed, */
													/*   this is the requestor of the function. */
#define MPPICfunc		0x0000FF00					/* Current function */
#define MPPICfIdle		0x00						/* No function pending */
#define MPPICfStrt		0x01						/* Start the processor, physical address in  */
													/*   MPPIParm0 */
#define MPPICfResm		0x02						/* Resume a stopped processor */
#define MPPICfStop		0x03						/* Stop a processor */
#define MPPICfSigp		0x04						/* Signal a processor */
#define MPPICfStat		0x05						/* Store the processor machine state -  */
													/*   physical address of response in MPPIParm0 */
#define MPPICfTBsy		0x06						/* Synchronize timebase - */
													/*   TB image in MPPIParm0 and MPPIParm1 */
#define MPPICfReset		0x07						/* Reset the processor */
#define MPPICfTBsy1		0x81						/* TB sync, phase 1 */
#define MPPICfTBsy2		0x82						/* TB sync, phase 2 */
#define MPPICSigp		0x80000000					/* Processor has signal pending (keep signal status when stopped) */
#define MPPICXRun		0x40000000					/* Explicit SIGP run call */


                       
#ifndef __ASSEMBLER__

typedef unsigned char	CPUState;
typedef unsigned int	CPUNotification;

struct MPPlugInSpec {								/* This is MPSxxxx for assembler */
		unsigned int 		versionID;				/* Version ID, must match */
		unsigned int		*areaAddr;				/* Virtual address of area to be */
													/*  relocated to physical memory */
		unsigned int 		areaSize;				/* Size of area to be relocated */
		unsigned int 		*offsetTableAddr;		/* Virtual address of table of entry offsets */
		unsigned int		*baseAddr;				/* Common base area - used for debugging */
		unsigned int		*dataArea;				/* Pointer to the MP workarea - used for debugging */
		unsigned int		*CPUArea;				/* Pointer to the CPU workarea - used for debugging */
		unsigned int		*SIGPhandler;			/* Physical address of signal interrupt filter */
};

typedef struct MPPlugInSpec MPPlugInSpec;
typedef MPPlugInSpec *MPPlugInSpecPtr;

struct MPEntryPts {	
		unsigned int		EntAddr[kMPPlugInMaxCall+1];	/* Real addresses of all plugin entry points */
};

typedef struct MPEntryPts MPEntryPts;

struct SystemRegister {
		unsigned int		regno;
		unsigned int		contents;
};

typedef struct SystemRegister SystemRegister;

typedef struct FPRegs {
		unsigned int		lo;
		unsigned int		hi;
} FPRegs;

struct BATregs {
		unsigned int		upper;
		unsigned int		lower;
};

typedef struct BATregs BATregs;


#define kSysRegCount 16
		
struct CPUStatusArea {								/*  0000 This is CSAxxxxx for assembler */

/*
 *		Note that this guy always has to be in one-to-one mapped area contiguously
 */
 
		CPUState			state;					/*  0000 */
		unsigned char		regsAreValid;			/*  0001 */
		unsigned char		filler[2];				/*  0002 */
		unsigned int		gpr[32];				/*  0004 */
		FPRegs				fpr[32];				/*  0084 */
		unsigned int		cr;						/*  0184 */
		unsigned int		fpscr;					/*  0188 */
		unsigned int		xer;					/*  018C */
		unsigned int		lr;						/*  0190 */
		unsigned int		ctr;					/*  0194 */
		unsigned int		tbu;					/*  0198 This is rtcu on 601. */
		unsigned int		tbl;					/*  019C This is rtcl on 601. */
		unsigned int		pvr;					/*  01A0 */
		BATregs				ibat[4];				/*  01A4 */
		BATregs				dbat[4];				/*  01E4 */
		unsigned int		sdr1;					/*  0224 */
		unsigned int		sr[16];					/*  0228 */
		unsigned int		dar;					/*  0268 */
		unsigned int		dsisr;					/*  026C */
		unsigned int		sprg[4];				/*  0270 */
		unsigned int		srr0;					/*  0280 */
		unsigned int		srr1;					/*  0284 */
		unsigned int		dec;					/*  0288 */
		unsigned int		dabr;					/*  028C */
		unsigned int		iabr;					/*  0290 */
		unsigned int		ear;					/*  0294 */
		unsigned int		hid[16];				/*  0298 */
		unsigned int		mmcr[2];				/*  02D8 */
		unsigned int		pmc[4];					/*  02E0 */
		unsigned int		pir;					/*  02F0 */
		unsigned int		sda;					/*  02F4 */
		unsigned int		sia;					/*  02F8 */
		unsigned int		mq;						/*  02FC */
		
		unsigned int		msr;					/*  0300 */
		unsigned int		pc;						/*  0304 */
		
		SystemRegister		sysregs[kSysRegCount];	/*  0308 */
		
		unsigned int		filler2[6];				/*  0388  Always pad up to 32-byte boundary */
													/*  03A0 */
};

typedef struct CPUStatusArea CPUStatusArea;
typedef CPUStatusArea *CPUStatusAreaPtr;

extern CPUStatusArea CSA[NCPUS];

struct SenseInfo {
	CPUNotification		notification;
	CPUState			state;
};

typedef struct SenseInfo SenseInfo;
typedef SenseInfo *SenseInfoPtr;


struct MPPInterface {

	unsigned int			MPPICStat;						/* Processor status (interlocked update for this one) */
	unsigned int			MPPICParm0;			/* SIGP parm 0 */
	unsigned int			MPPICParm1;			/* SIGP parm 1 */
	unsigned int			MPPICParm2;			/* SIGP parm 2 */
	unsigned int			MPPICspare0;		/* unused */
	unsigned int			MPPICspare1;		/* unused */
	unsigned int			MPPICParm0BU;		/* Parm 0 backed up here at 'rupt time for safe keeping */
	unsigned int			MPPICPriv;			/* Processor status (interlocked update for this one) */
};

typedef struct MPPInterface MPPInterface;
typedef MPPInterface *MPPInterfacePtr;

extern MPPInterface MPPICPUs[];


/* ***********************************************************************
 *	Function prototypes and data areas
 * *********************************************************************** */

extern unsigned int	MPgetProcCount	(void);
extern unsigned int	MPstart			(unsigned int cpu, unsigned int sadr, unsigned int parm);
extern unsigned int	MPexternalHook	(void);
extern unsigned int	MPsignal		(unsigned int cpu, unsigned int	SIGPparm);
extern unsigned int	MPstop			(unsigned int cpu);
#if 0
extern unsigned int	MPCPUAddress	(void);
extern unsigned int	MPresume		(unsigned int cpu);
extern unsigned int	MPreset			(unsigned int cpu);
extern unsigned int	MPSense			(unsigned int cpu, unsigned int	*info);
extern unsigned int	MPstoreStatus	(unsigned int cpu, unsigned int	*statusArea);
extern unsigned int	MPSetStatus		(unsigned int cpu, unsigned int	*statusArea);
extern unsigned int	MPgetSignal		(void);
extern unsigned int	MPsyncTB		(void);
extern unsigned int	MPcheckPending	(void);
#endif
extern int MPinstall		(unsigned int physAddr, unsigned int band1, unsigned int hammerh, unsigned int grandc,
								unsigned int pci1ar, unsigned int enetr);
extern unsigned int MPprobe	(MPPlugInSpecPtr spec, unsigned int hammerh);

extern void start_secondary	(void);
extern void mp_intr	(void);


extern MPPlugInSpec	MPspec;							/* An area for the MP interfaces */
extern MPEntryPts	MPEntries;						/* Real addresses of plugin routines */

#endif /* ndef __ASSEMBLER */
