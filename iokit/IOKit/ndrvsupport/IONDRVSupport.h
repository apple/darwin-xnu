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

#ifndef __IONDRVSUPPORT__
#define __IONDRVSUPPORT__

#include <libkern/OSTypes.h>

#pragma options align=mac68k

#ifdef __cplusplus
extern "C" {
#endif

#define kIONDRVIgnoreKey	"AAPL,iokit-ignore-ndrv"
#define kIONDRVForXKey		"AAPL,iokit-ndrv"

struct IOTVector {
    void *	pc;
    UInt32	toc;
};
typedef struct IOTVector IOTVector;

struct IONDRVInterruptSetMember {
	void * 		setID;
	UInt32	 	member;
};
typedef struct IONDRVInterruptSetMember IONDRVInterruptSetMember;

typedef SInt32	(*IONDRVInterruptHandler)( IONDRVInterruptSetMember setMember, void *refCon, UInt32 theIntCount);
typedef void    (*IONDRVInterruptEnabler)( IONDRVInterruptSetMember setMember, void *refCon);
typedef Boolean (*IONDRVInterruptDisabler)( IONDRVInterruptSetMember setMember, void *refCon);

enum {
    kIONDRVFirstMemberNumber			= 1,
    kIONDRVIsrIsComplete			= 0,
    kIONDRVIsrIsNotComplete			= -1,
    kIONDRVMemberNumberParent			= -2
};

enum {
    kIONDRVReturnToParentWhenComplete		= 0x00000001,
    kIONDRVReturnToParentWhenNotComplete	= 0x00000002
};

enum {
    kIONDRVISTChipInterruptSource		= 0,
    kIONDRVISTOutputDMAInterruptSource 		= 1,
    kIONDRVISTInputDMAInterruptSource		= 2,
    kIONDRVISTPropertyMemberCount		= 3
};

#define kIONDRVISTPropertyName	"driver-ist" 

IOReturn
IONDRVInstallInterruptFunctions(void *	setID,
                                UInt32	member,
                                void *	refCon,
                                IOTVector * handler,
                                IOTVector * enabler,
                                IOTVector * disabler );

typedef const IOTVector * (*IONDRVUndefinedSymbolHandler)( void * self, 
                            const char * libraryName, const char * symbolName );

#pragma options align=reset

#ifdef __cplusplus
}
#endif

#endif /* __IONDRVSUPPORT__ */
