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
	File:		PseudoKernelPriv.h

	Contains:	Interfaces for Classic environment's PseudoKernel

	Copyright:	(c) 2000 Apple Computer, Inc. All rights reserved.
*/

#include <ppc/exception.h>

/* Support firmware PseudoKernel FastTrap architectural extension */

#define bbMaxTrap (16 * sizeof(long))
#define bbRFITrap bbMaxTrap

extern int bb_enable_bluebox(struct savearea *);
extern int bb_disable_bluebox(struct savearea *);
extern int bb_settaskenv(struct savearea *);

struct BlueExceptionDataArea {
	UInt32				srr0;					// OUT PC at time of exception, IN return address
	UInt32				srr1;					// OUT/IN msr FE0, BE, SE and FE1 bits to restore on exit
	UInt32				sprg0;					// OUT R1 set to this value
	UInt32				sprg1;					// OUT/IN R1 restored to this value
};
typedef struct BlueExceptionDataArea * BlueExceptionDataAreaPtr;
typedef struct BlueExceptionDataArea BEDA_t;

/*
	The Blue Thread, which is running MacOS, needs to be able to handle Traps, SCs and interrupts.
*/
struct BlueThreadTrapDescriptor {
	UInt32				TrapVector;				// 0=Trap
	UInt32				SysCallVector;			// 1=SysCall
	UInt32				InterruptVector;		// 2=Interrupt
	UInt32				PendingIntVector;		// 3=Pending interrupt
	BEDA_t				exceptionInfo;			// Save registers at time of exception (trap/syscall)
	UInt32				InterruptControlWord;	// Holds context state and backup CR2 bits
	UInt32				NewExitState;			// New run state when exiting PseudoKernel
	UInt32				testIntMask;			// Mask for a pending alternate context interrupt in backup CR2
	UInt32				postIntMask;			// Mask to post an interrupt
};
typedef struct BlueThreadTrapDescriptor * BlueThreadTrapDescriptorPtr;
typedef struct BlueThreadTrapDescriptor BTTD_t;
	
enum {
	// The following define the UInt32 gInterruptState
	kInUninitialized	=	0,			// State not yet initialized
	kInPseudoKernel		=	1,			// Currently executing within pseudo kernel
	kInSystemContext	=	2,			// Currently executing within the system (emulator) context
	kInAlternateContext	=	3,			// Currently executing within an alternate (native) context
	kInExceptionHandler	=	4,			// Currently executing an exception handler
	kOutsideBlue		=	5,			// Currently executing outside of the Blue thread
	kNotifyPending		=	6,			// Pending Notify Interrupt

	kInterruptStateMask	=	0x000F0000,	// Mask to extract interrupt state from gInterruptState
	kInterruptStateShift	=	16,		// Shift count to align interrupt state

	kBackupCR2Mask		=	0x0000000F,	// Mask to extract backup CR2 from gInterruptState
	kCR2ToBackupShift	=	31-11,		// Shift count to align CR2 into the backup CR2 of gInterruptState
										//  (and vice versa)
	kCR2Mask			=	0x00F00000	// Mask to extract CR2 from the PPC CR register 
};

struct bbRupt {
	struct ReturnHandler	rh;			/* Return handler address */
};
typedef struct bbRupt bbRupt;
