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
 
#ifdef ASSEMBLER

#ifdef _FIRMWARECALLS_H_
#error Hey! You can only include FirmwareCalls.h in one assembler file, dude. And it should be Firmware.s!
#else /* _FIRMWARECALLS_H_ */

/*
 *			Entries for all firmware calls are in here (except for call 0x80000000 - CutTrace
 */

#define _FIRMWARECALLS_H_

#define	fwCallEnt(name, entrypt) 									\
			.globl	name								__ASMNL__	\
 			.set	name,(.-EXT(FWtable))/4|0x80000000	__ASMNL__	\
			.long	EXT(entrypt)						__ASMNL__
			
/*
 *
 */
 
			fwCallEnt(dbgDispCall, dbgDispLL)				/* Write stuff to printer or modem port */
			fwCallEnt(dbgCkptCall, dbgCkptLL)				/* Save 128 bytes from r3 to 0x380 V=R mapping */
			fwCallEnt(StoreRealCall, StoreRealLL)			/* Save one word in real storage */
			fwCallEnt(ClearRealCall, ClearRealLL)			/* Clear physical pages */
			fwCallEnt(LoadDBATsCall, xLoadDBATsLL)			/* Load all DBATs */
			fwCallEnt(LoadIBATsCall, xLoadIBATsLL)			/* Load all IBATs */
			fwCallEnt(DoPreemptCall, DoPreemptLL)			/* Preempt if need be */
			fwCallEnt(CreateFakeIOCall, CreateFakeIOLL)		/* Make a fake I/O interruption */
			fwCallEnt(SwitchContextCall, SwitchContextLL)	/* Switch context */
			fwCallEnt(Choke, DoChokeLL)						/* Choke (system crash) */
			fwCallEnt(dbgRegsCall, dbgRegsLL)				/* Dumps all registers */
			fwCallEnt(CreateFakeDECCall, CreateFakeDECLL)	/* Make a fake decrementer interruption */
			fwCallEnt(CreateShutdownCTXCall, CreateShutdownCTXLL)	/* create a shutdown context */
#if PERF_HIST
			fwCallEnt(PerfCtlCall, PerfCtlLL)				/* Control performance monitor */
#endif

#endif	/* _FIRMWARECALLS_H_ */

#else /* ASSEMBLER */
	
/*
 *			The firmware function headers
 */
extern void			CutTrace		(unsigned int item1, ...);

#endif /* ASSEMBLER */
