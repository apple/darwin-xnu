/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1997 Apple Computer, Inc.
 *
 *
 * HISTORY
 *
 * Simon Douglas  10 Nov 97
 * - first checked in, mostly from MacOS DBDMA.i, machdep/ppc/dbdma.h
 *	but use byte reverse ops.
 */

#ifndef _IODBDMA_H_
#define _IODBDMA_H_

#include <IOKit/IOTypes.h>
#include <libkern/OSByteOrder.h>


/* DBDMA definitions */

struct IODBDMAChannelRegisters {
    volatile unsigned long 	channelControl;
    volatile unsigned long 	channelStatus;
    volatile unsigned long 	commandPtrHi;		/* implementation optional*/
    volatile unsigned long 	commandPtrLo;
    volatile unsigned long 	interruptSelect;	/* implementation optional*/
    volatile unsigned long 	branchSelect;		/* implementation optional*/
    volatile unsigned long 	waitSelect;		/* implementation optional*/
    volatile unsigned long 	transferModes;		/* implementation optional*/
    volatile unsigned long 	data2PtrHi;		/* implementation optional*/
    volatile unsigned long 	data2PtrLo;		/* implementation optional*/

    volatile unsigned long 	reserved1;
    volatile unsigned long 	addressHi;		/* implementation optional*/
    volatile unsigned long 	reserved2[4];
    volatile unsigned long 	unimplemented[16];

/* This structure must remain fully padded to 256 bytes.*/
    volatile unsigned long 	undefined[32];
};
typedef struct IODBDMAChannelRegisters IODBDMAChannelRegisters;

/* These constants define the DB-DMA channel control words and status flags.*/

enum {
	kdbdmaRun	= 0x00008000,
	kdbdmaPause	= 0x00004000,
	kdbdmaFlush	= 0x00002000,
	kdbdmaWake	= 0x00001000,
	kdbdmaDead	= 0x00000800,
	kdbdmaActive	= 0x00000400,
	kdbdmaBt	= 0x00000100,
	kdbdmaS7	= 0x00000080,
	kdbdmaS6	= 0x00000040,
	kdbdmaS5	= 0x00000020,
	kdbdmaS4	= 0x00000010,
	kdbdmaS3	= 0x00000008,
	kdbdmaS2	= 0x00000004,
	kdbdmaS1	= 0x00000002,
	kdbdmaS0	= 0x00000001
};


#define	IOSetDBDMAChannelControlBits(mask)	( ((mask) | (mask) << 16) )
#define	IOClearDBDMAChannelControlBits(mask)	( (mask) << 16)


/* This structure defines the DB-DMA channel command descriptor.*/

/*
   *** WARNING:	Endian-ness issues must be considered when performing load/store! ***
*/

struct IODBDMADescriptor {
	unsigned long            operation;   /* cmd || key || i || b || w || reqCount*/
	unsigned long            address;
	volatile unsigned long   cmdDep;
	volatile unsigned long   result;      /* xferStatus || resCount*/
};
typedef struct IODBDMADescriptor IODBDMADescriptor;

/* These constants define the DB-DMA channel command operations and modifiers.*/


enum {
/* Command.cmd operations*/
	kdbdmaOutputMore	= 0,
	kdbdmaOutputLast	= 1,
	kdbdmaInputMore		= 2,
	kdbdmaInputLast		= 3,
	kdbdmaStoreQuad		= 4,
	kdbdmaLoadQuad		= 5,
	kdbdmaNop		= 6,
	kdbdmaStop		= 7
};


enum {
/* Command.key modifiers (choose one for INPUT, OUTPUT, LOAD, and STORE)*/
	kdbdmaKeyStream0	= 0,	/* default modifier*/
	kdbdmaKeyStream1	= 1,
	kdbdmaKeyStream2	= 2,
	kdbdmaKeyStream3	= 3,
	kdbdmaKeyRegs		= 5,
	kdbdmaKeySystem		= 6,
	kdbdmaKeyDevice		= 7,

	kdbdmaIntNever		= 0,	/* default modifier*/
	kdbdmaIntIfTrue		= 1,
	kdbdmaIntIfFalse	= 2,
	kdbdmaIntAlways		= 3,

	kdbdmaBranchNever	= 0,	/* default modifier*/
	kdbdmaBranchIfTrue	= 1,
	kdbdmaBranchIfFalse	= 2,
	kdbdmaBranchAlways	= 3,

	kdbdmaWaitNever		= 0,	/* default modifier*/
	kdbdmaWaitIfTrue	= 1,
	kdbdmaWaitIfFalse	= 2,
	kdbdmaWaitAlways	= 3,

	kdbdmaCommandMask	= (long)0xFFFF0000,
	kdbdmaReqCountMask	= 0x0000FFFF
};


/* These constants define the DB-DMA channel command results.*/

enum {
	/* result masks*/
	kdbdmaStatusRun		= kdbdmaRun << 16,
	kdbdmaStatusPause	= kdbdmaPause << 16,
	kdbdmaStatusFlush	= kdbdmaFlush << 16,
	kdbdmaStatusWake	= kdbdmaWake << 16,
	kdbdmaStatusDead	= kdbdmaDead << 16,
	kdbdmaStatusActive	= kdbdmaActive << 16,
	kdbdmaStatusBt		= kdbdmaBt << 16,
	kdbdmaStatusS7		= kdbdmaS7 << 16,
	kdbdmaStatusS6		= kdbdmaS6 << 16,
	kdbdmaStatusS5		= kdbdmaS5 << 16,
	kdbdmaStatusS4		= kdbdmaS4 << 16,
	kdbdmaStatusS3		= kdbdmaS3 << 16,
	kdbdmaStatusS2		= kdbdmaS2 << 16,
	kdbdmaStatusS1		= kdbdmaS1 << 16,
	kdbdmaStatusS0		= kdbdmaS0 << 16,
	kdbdmaResCountMask	= 0x0000FFFF,
	kdbdmaXferStatusMask	= 0xFFFF0000
};


/*  These macros are are IODBDMAChannelRegisters accessor functions. */

#define IOSetDBDMAChannelRegister(registerSetPtr,field,value)	\
OSWriteSwapInt32(registerSetPtr,offsetof(IODBDMAChannelRegisters,field),value)

#define IOGetDBDMAChannelRegister(registerSetPtr, field)	\
OSReadSwapInt32(registerSetPtr,offsetof(IODBDMAChannelRegisters, field))


/* 	void IOSetDBDMAChannelControl (IODBDMAChannelRegisters *registerSetPtr, unsigned long ctlValue); */

#define IOSetDBDMAChannelControl(registerSetPtr,ctlValue)		\
do {									\
    eieio();								\
    IOSetDBDMAChannelRegister(registerSetPtr,channelControl,ctlValue);	\
    eieio();								\
} while(0)

/* 	unsigned long IOGetDBDMAChannelStatus (IODBDMAChannelRegisters *registerSetPtr); */

#define IOGetDBDMAChannelStatus(registerSetPtr)		\
	IOGetDBDMAChannelRegister(registerSetPtr,channelStatus)

/* 	unsigned long IOGetDBDMACommandPtr (IODBDMAChannelRegisters *registerSetPtr); */

#define IOGetDBDMACommandPtr(registerSetPtr)			\
	IOGetDBDMAChannelRegister(registerSetPtr,commandPtrLo)

/* 	void IOSetDBDMACommandPtr (IODBDMAChannelRegisters *registerSetPtr, unsigned long cclPtr); */

#define IOSetDBDMACommandPtr(registerSetPtr,cclPtr)			\
do {									\
    IOSetDBDMAChannelRegister(registerSetPtr,commandPtrHi,0);		\
    eieio();								\
    IOSetDBDMAChannelRegister(registerSetPtr,commandPtrLo,cclPtr);	\
    eieio();								\
} while(0)


/* 	unsigned long IOGetDBDMAInterruptSelect (IODBDMAChannelRegisters *registerSetPtr); */

#define IOGetDBDMAInterruptSelect(registerSetPtr)		\
        IOGetDBDMAChannelRegister(registerSetPtr,interruptSelect)

/* 	void IOSetDBDMAInterruptSelect (IODBDMAChannelRegisters *registerSetPtr, unsigned long intSelValue); */

#define IOSetDBDMAInterruptSelect(registerSetPtr,intSelValue)		   \
do {									   \
    IOSetDBDMAChannelRegister(registerSetPtr,interruptSelect,intSelValue); \
    eieio();								   \
} while(0)

/* 	unsigned long IOGetDBDMABranchSelect (IODBDMAChannelRegisters *registerSetPtr); */

#define IOGetDBDMABranchSelect(registerSetPtr)				\
	IOGetDBDMAChannelRegister(registerSetPtr,branchSelect)

/* 	void IOSetDBDMABranchSelect (IODBDMAChannelRegisters *registerSetPtr, unsigned long braSelValue); */

#define IOSetDBDMABranchSelect(registerSetPtr,braSelValue)		\
do {									\
    IOSetDBDMAChannelRegister(registerSetPtr,branchSelect,braSelValue);	\
    eieio();								\
} while(0)

/* 	unsigned long IOGetDBDMAWaitSelect (IODBDMAChannelRegisters *registerSetPtr); */

#define IOGetDBDMAWaitSelect(registerSetPtr)				\
	IOGetDBDMAChannelRegister(registerSetPtr,waitSelect)

/* 	void IOSetDBDMAWaitSelect (IODBDMAChannelRegisters *registerSetPtr, unsigned long waitSelValue); */

#define IOSetDBDMAWaitSelect(registerSetPtr,waitSelValue)		\
do {									\
    IOSetDBDMAChannelRegister(registerSetPtr,waitSelect,waitSelValue);	\
    eieio();								\
} while(0)


/*  These macros are IODBDMADescriptor accessor functions. */

#define IOSetDBDMADescriptor(descPtr,field,value)		\
OSWriteSwapInt32( descPtr, offsetof( IODBDMADescriptor, field), value)

#define IOGetDBDMADescriptor(descPtr,field)	\
OSReadSwapInt32( descPtr, offsetof( IODBDMADescriptor, field))

#define	IOMakeDBDMAOperation(cmd,key,interrupt,branch,wait,count)	\
    ( ((cmd) << 28) | ((key) << 24) | ((interrupt) << 20)		\
      | ((branch) << 18) | ( (wait) << 16) | (count) )

/* void  IOMakeDBDMADescriptor (IODBDMADescriptor *descPtr,
				unsigned long cmd,
				unsigned long key,
				unsigned long interrupt,
				unsigned long branch,
				unsigned long wait,
				unsigned long count,
				unsigned long addr); */

#define IOMakeDBDMADescriptor(descPtr,cmd,key,interrupt,branch,wait,count,addr)\
do {									       \
    IOSetDBDMADescriptor(descPtr, address, addr);			       \
    IOSetDBDMADescriptor(descPtr, cmdDep,  0);				       \
    IOSetDBDMADescriptor(descPtr, result,  0);				       \
    eieio();								       \
    IOSetDBDMADescriptor(descPtr, operation,				       \
        IOMakeDBDMAOperation(cmd,key,interrupt,branch,wait,count));	       \
    eieio();								       \
} while(0)

/* void IOMakeDBDMADescriptorDep (IODBDMADescriptor *descPtr,
				unsigned long cmd,
				unsigned long key,
				unsigned long interrupt,
				unsigned long branch,
				unsigned long wait,
				unsigned long count,
				unsigned long addr,
				unsigned long dep); */

#define IOMakeDBDMADescriptorDep(descPtr,cmd,key,interrupt,branch,wait,count,addr,dep) \
do {									       \
    IOSetDBDMADescriptor(descPtr, address, addr);			       \
    IOSetDBDMADescriptor(descPtr, cmdDep, dep);				       \
    IOSetDBDMADescriptor(descPtr, result, 0);				       \
    eieio();								       \
    IOSetDBDMADescriptor(descPtr, operation,				       \
        IOMakeDBDMAOperation(cmd, key, interrupt, branch, wait, count));       \
    eieio();								       \
} while(0)

/*	Field accessors - NOTE: unsynchronized */

/* 	unsigned long IOGetDBDMAOperation (IODBDMADescriptor *descPtr) */

#define IOGetCCOperation(descPtr)				\
	IOGetDBDMADescriptor(descPtr,operation)

/* 	void IOSetCCOperation (IODBDMADescriptor *descPtr, unsigned long operationValue) */

#define IOSetCCOperation(descPtr,operationValue)		\
	IOSetDBDMADescriptor(descPtr,operation,operationValue)

/* 	unsigned long IOGetCCAddress (IODBDMADescriptor *descPtr) */

#define IOGetCCAddress(descPtr)				\
	IOGetDBDMADescriptor(descPtr,address)

/* 	void IOSetCCAddress (IODBDMADescriptor *descPtr, unsigned long addressValue) */

#define IOSetCCAddress(descPtr,addressValue)		\
	IOSetDBDMADescriptor(descPtr,address, addressValue)

/* 	unsigned long IOGetCCCmdDep (IODBDMADescriptor *descPtr) */

#define IOGetCCCmdDep(descPtr)				\
	IOGetDBDMADescriptor(descPtr,cmdDep)

/* 	void IOSetCCCmdDep (IODBDMADescriptor *descPtr, unsigned long cmdDepValue) */

#define IOSetCCCmdDep(descPtr,cmdDepValue)		\
	IOSetDBDMADescriptor(descPtr,cmdDep,cmdDepValue)

/* 	unsigned long IOGetCCResult (IODBDMADescriptor *descPtr) */

#define IOGetCCResult(descPtr)				\
	IOGetDBDMADescriptor(descPtr,result)

/* 	void IOSetCCResult (IODBDMADescriptor *descPtr, unsigned long resultValue) */

#define IOSetCCResult(descPtr,resultValue)		\
	IOSetDBDMADescriptor(descPtr,result,resultValue)


/* DBDMA routines */

extern void	IODBDMAStart( volatile IODBDMAChannelRegisters *registerSetPtr, volatile IODBDMADescriptor *physicalDescPtr);
extern void	IODBDMAStop( volatile IODBDMAChannelRegisters *registerSetPtr);
extern void	IODBDMAFlush( volatile IODBDMAChannelRegisters *registerSetPtr);
extern void	IODBDMAReset( volatile IODBDMAChannelRegisters *registerSetPtr);
extern void	IODBDMAContinue( volatile IODBDMAChannelRegisters *registerSetPtr);
extern void	IODBDMAPause( volatile IODBDMAChannelRegisters *registerSetPtr);

extern IOReturn	IOAllocatePhysicallyContiguousMemory( unsigned int size, unsigned int options,
				     IOVirtualAddress * logical, IOPhysicalAddress * physical );
extern IOReturn IOFreePhysicallyContiguousMemory( IOVirtualAddress * logical, unsigned int size);

#endif /* !defined(_IODBDMA_H_) */
