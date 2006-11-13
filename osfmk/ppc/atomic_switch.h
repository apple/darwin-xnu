/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
 * http://www.opensource.apple.com/apsl/ and read it before using this 
 * file.
 *
 * The Original Code and all software distributed under the License are 
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, 
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. 
 * Please see the License for the specific language governing rights and 
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
typedef unsigned char	UInt8;
typedef unsigned short	UInt16;
typedef unsigned long	UInt32;


/* Support firmware CallPseudoKernel architectural extension */

struct CallPseudoKernelDescriptor {
	UInt32				pc;
	UInt32				gpr0;
	UInt32				intControlAddr;
	UInt32				newState;
	UInt32				intStateMask;
	UInt32				intCR2Mask;
	UInt32				intCR2Shift;
	UInt32				sysContextState;
};
typedef struct CallPseudoKernelDescriptor CallPseudoKernelDescriptor;
typedef CallPseudoKernelDescriptor * CallPseudoKernelDescriptorPtr;
typedef CallPseudoKernelDescriptor CPKD_t;



/* Support firmware ExitPseudoKernel architectural extension */

struct ExitPseudoKernelDescriptor {
	UInt32				pc;
	UInt32				sp;
	UInt32				gpr0;
	UInt32				gpr3;
	UInt32				cr;
	UInt32				intControlAddr;
	UInt32				newState;
	UInt32				intStateMask;
	UInt32				intCR2Mask;
	UInt32				intCR2Shift;
	UInt32				sysContextState;
	UInt32				intPendingMask;
	UInt32				intPendingPC;
	UInt32				msrUpdate;
};
typedef struct ExitPseudoKernelDescriptor ExitPseudoKernelDescriptor;
typedef ExitPseudoKernelDescriptor * ExitPseudoKernelDescriptorPtr;
typedef ExitPseudoKernelDescriptor EPKD_t;


struct EmulatorDescriptor {
	UInt8		regMap[16];		// table mapping 68K D0..D7, A0..A7 register to PowerPC registers
	UInt32		bootstrapVersionOffset;	// offset within emulator data page of the bootstrap version string
	UInt32		ecbOffset;		// offset within emulator data page of the ECB
	UInt32		intModeLevelOffset;	// offset within emulator data page of the interrupt mode level
	UInt32		entryAddress;		// offset within text of the emulator's main entry point
	UInt32		kcallTrapTableOffset;	// offset within text of the nanokernel(!) call trap table
	UInt32		postIntMask;		// post interrupt mask
	UInt32		clearIntMask;		// clear interrupt mask
	UInt32		testIntMask;		// test interrupt mask
	UInt32		codeSize;		// total size of emulator object code (interpretive + DR)
	UInt32		hashTableSize;		// size of DR emulator's hash table
	UInt32		drCodeStartOffset;	// offset within text of the DR emulator's object code
	UInt32		drInitOffset;		// offset within DR emulator of its initialization entry point
	UInt32		drAllocateCache;	// offset within DR emulator of its cache allocation entry point
	UInt32		dispatchTableOffset;	// offset within text of the encoded instruction dispatch table 
};
typedef struct EmulatorDescriptor EmulatorDescriptor;
typedef EmulatorDescriptor *EmulatorDescriptorPtr;

	
enum {
											// The following define the UInt32 gInterruptState
	kInUninitialized	=	0,			// State not yet initialized
	kInPseudoKernel		=	1,			// Currently executing within pseudo kernel
	kInSystemContext	=	2,			// Currently executing within the system (emulator) context
	kInAlternateContext	=	3,			// Currently executing within an alternate (native) context
	kInExceptionHandler	=	4,			// Currently executing an exception handler
	kOutsideMain		=	5,			// Currently executing outside of the main thread
	kNotifyPending		=	6,			// Pending Notify Interrupt

	kInterruptStateMask	=	0x000F0000,	// Mask to extract interrupt state from gInterruptState
	kInterruptStateShift	=	16,			// Shift count to align interrupt state

	kBackupCR2Mask		=	0x0000000F,	// Mask to extract backup CR2 from gInterruptState
	kCR2ToBackupShift	=	31-11,		// Shift count to align CR2 into the backup CR2 of gInterruptState
											//  (and vice versa)
	kCR2Mask		=	0x00F00000  // Mask to extract CR2 from the PPC CR register 
};


enum {
	kcReturnFromException		= 0,	
	kcRunAlternateContext		= 1,
	kcResetSystem				= 2,
	kcVMDispatch				= 3,
	kcPrioritizeInterrupts		= 4,
	kcPowerDispatch				= 5,
	kcRTASDispatch				= 6,
	kcGetAdapterProcPtrsPPC		= 12,
	kcGetAdapterProcPtrs		= 13,
	kcCallAdapterProc			= 14,
	kcSystemCrash				= 15
};

#define bbMaxCode 16

