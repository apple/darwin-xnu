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
 * sdouglas  22 Oct 97 - first checked in.
 * sdouglas  21 July 98 - start IOKit
 * sdouglas  21 July 98 - start IOKit
 */


#ifndef _IOKIT_IOPEFLOADER_H
#define _IOKIT_IOPEFLOADER_H


#include <IOKit/ndrvsupport/IOMacOSTypes.h>
#include <IOKit/ndrvsupport/IONDRVSupport.h>

#ifdef __cplusplus
extern "C" {
#endif


enum {
    cfragFirstErrCode           = -2800,   /* The first value in the range of CFM errors.*/
    cfragContextIDErr           = -2800,   /* The context ID was not valid.*/
    cfragConnectionIDErr        = -2801,   /* The connection ID was not valid.*/
    cfragNoSymbolErr            = -2802,   /* The specified symbol was not found.*/
    cfragNoSectionErr           = -2803,   /* The specified section was not found.*/
    cfragNoLibraryErr           = -2804,   /* The named library was not found.*/
    cfragDupRegistrationErr     = -2805,   /* The registration name was already in use.*/
    cfragFragmentFormatErr      = -2806,   /* A fragment's container format is unknown.*/
    cfragUnresolvedErr          = -2807,   /* A fragment had "hard" unresolved imports.*/
    cfragNoPositionErr          = -2808,   /* The registration insertion point was not found.*/
    cfragNoPrivateMemErr        = -2809,   /* Out of memory for internal bookkeeping.*/
    cfragNoClientMemErr         = -2810,   /* Out of memory for fragment mapping or section instances.*/
    cfragNoIDsErr               = -2811,   /* No more CFM IDs for contexts, connections, etc.*/
    cfragInitOrderErr           = -2812,   /* */
    cfragImportTooOldErr        = -2813,   /* An import library was too old for a client.*/
    cfragImportTooNewErr        = -2814,   /* An import library was too new for a client.*/
    cfragInitLoopErr            = -2815,   /* Circularity in required initialization order.*/
    cfragInitAtBootErr          = -2816,   /* A boot library has an initialization function.  (System 7 only)*/
    cfragLibConnErr             = -2817,   /* */
    cfragCFMStartupErr          = -2818,   /* Internal error during CFM initialization.*/
    cfragCFMInternalErr         = -2819,   /* An internal inconstistancy has been detected.*/
    cfragFragmentCorruptErr     = -2820,   /* A fragment's container was corrupt (known format).*/
    cfragInitFunctionErr        = -2821,   /* A fragment's initialization routine returned an error.*/
    cfragNoApplicationErr       = -2822,   /* No application member found in the cfrg resource.*/
    cfragArchitectureErr        = -2823,   /* A fragment has an unacceptable architecture.*/
    cfragFragmentUsageErr       = -2824,   /* A semantic error in usage of the fragment.*/
    cfragFileSizeErr            = -2825,   /* A file was too large to be mapped.*/
    cfragNotClosureErr          = -2826,   /* The closure ID was actually a connection ID.*/
    cfragNoRegistrationErr      = -2827,   /* The registration name was not found.*/
    cfragContainerIDErr         = -2828,   /* The fragment container ID was not valid.*/
    cfragClosureIDErr           = -2829,   /* The closure ID was not valid.*/
    cfragAbortClosureErr        = -2830    /* Used by notification handlers to abort a closure.*/
};

enum {
    paramErr            = -50,
    unimpErr            = -4
};


typedef UInt32 CFragVersionNumber;
enum {
    kNullCFragVersion           = 0,
    kWildcardCFragVersion       = 0xFFFFFFFF
};

typedef UInt8 CFragSymbolClass;
enum {
    kCodeCFragSymbol            = 0,
    kDataCFragSymbol            = 1,
    kTVectorCFragSymbol         = 2,
    kTOCCFragSymbol             = 3,
    kGlueCFragSymbol            = 4
};

enum {
    kUnresolvedCFragSymbolAddress = 0
};

typedef UInt32 CFragShortVersionPair;
#define ComposeCFragShortVersionPair(current,older) (current << 16 | older)
#define GetCFragShortVersionCurrent(version)        (version >> 16)
#define GetCFragShortVersionOlder(version)          (version & 0xFFFF)


enum {
    kMainCFragSymbolIndex       = -1,
    kInitCFragSymbolIndex       = -2,
    kTermCFragSymbolIndex       = -3
};

typedef void * PCodeInstance;

OSStatus
PCodeOpen( LogicalAddress container, ByteCount containerSize, PCodeInstance * instance );
OSStatus
PCodeClose( PCodeInstance instance );
OSStatus
PCodeInstantiate( PCodeInstance instance,
                    IONDRVUndefinedSymbolHandler handler, void * self );
OSStatus
PCodeFindExport( PCodeInstance instance, const char * symbolName, LogicalAddress * address, CFragSymbolClass * symbolClass );
OSStatus
PCodeFindMain( PCodeInstance instance, LogicalAddress * mainAddress );

static __inline__ unsigned int get_R2(void)
{
    unsigned int result;
    __asm__ volatile("mr %0,	r2" : "=r" (result));
    return result;
}

static __inline__ void set_R2(unsigned int val)
{
    __asm__ volatile("mr r2,%0" : : "r" (val));
    return;
}

#ifdef __cplusplus
}
#endif

#endif /* ! _IOKIT_IOPEFLOADER_H */

