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
	File:		HFSInstrumentation.h

	Contains:	xxx put contents here xxx

	Version:	xxx put version here xxx

	Copyright:	© 1997 by Apple Computer, Inc., all rights reserved.

	File Ownership:

		DRI:				xxx put dri here xxx

		Other Contact:		xxx put other contact here xxx

		Technology:			xxx put technology here xxx

	Writers:

		(DSH)	Deric Horn
		(djb)	Don Brady

	Change History (most recent first):

	   <CS6>	 10/1/97	djb		Add kGetCatalogIterator
	   <CS5>	  9/4/97	djb		Add kTraceRelString, kHeuristicHint.
	   <CS4>	 7/24/97	djb		Add summary traces for GetNode, RelNode, and BasicIO.
	   <CS3>	 7/21/97	djb		Redefine LogStartTime/LogEndTime macros.
	   <CS2>	 7/16/97	DSH		FilesInternal.i renamed FileMgrInternal.i to avoid name
									collision
	   <CS1>	  5/9/97	djb		first checked in
*/

#include "../../hfs_macos_defs.h"
#include "FileMgrInternal.h"


//
// Instrumentation summary trace indicies
//
enum {
	// Unicode routines
	kTraceUnicodeToPString,
	kTracePStringToUnicode,
	kTraceUnicodeCompare,
	
	kTraceRelString,

	// B-tree routines
	kTraceOpenBTree,
	kTraceCloseBTree,
	kTraceFlushBTree,
	kTraceSearchBTree,
	kTraceGetBTreeRecord,
	kTraceInsertBTreeRecord,
	kTraceDeleteBTreeRecord,
	kTraceReplaceBTreeRecord,
	
	// Misc routines
	kTraceMapFileBlock,
	kTraceBlockAllocate,

	kTraceGetNode,
	kTraceReleaseNode,
	kTraceBasicIO,
	kTraceFSRead,
	kHeuristicHint,
	kGetCatalogIterator,

	
	kSummaryTraceRefs	// number of summary trace references
};


void STLogStartTime(UInt32 selector);
void STLogEndTime(UInt32 selector, OSErr error);


/*
MACRO
	LogStartTime(selector)

DESCRIPTION
	If summary traces are enabled then LogStartTime will record the starting time for
	the routine associated with the selector. Otherwise LogStartTime does nothing.

*/

#if hasSummaryTraces

#define	LogStartTime(selector)			STLogStartTime( (selector) )

#else

#define	LogStartTime(selector)			((void) 0)

#endif



/*
MACRO
	LogEndTime(selector, error)

DESCRIPTION
	If summary traces are enabled then InsLogEndTime will record the ending time for
	the routine associated with the selector. Otherwise LogEndTime does nothing.

*/

#if hasSummaryTraces

#define LogEndTime(selector,error)		STLogEndTime( (selector), (error) )

#else

#define LogEndTime(selector,error)		((void) 0)

#endif
