/*
 * Copyright (c) 1996-2002 Apple Computer, Inc. All rights reserved.
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
 *
 *	@(#)BTreeScanner.h
 */

#ifndef	_BTREESCANNER_H_
#define _BTREESCANNER_H_

#include <sys/time.h>

#include "FileMgrInternal.h"
#include "BTreesPrivate.h"

// amount of time we are allowed to process a catalog search (in µ secs)
// NOTE - code assumes kMaxMicroSecsInKernel is less than 1,000,000
// jertodo - what should we set this to?
enum { kMaxMicroSecsInKernel = (1000 * 100) };	// 1 tenth of a second

// btree node scanner buffer size.  at 32K we get 8 nodes.  this is the size used
// in Mac OS 9
enum { kCatSearchBufferSize = (32 * 1024) };


/*
 * ============ W A R N I N G ! ============
 * DO NOT INCREASE THE SIZE OF THIS STRUCT!
 * It must be less than or equal to the size of 
 * the opaque searchstate struct (in sys/attr.h).
 */
/* Private description used in hfs_search */
struct CatPosition 
{
  u_int32_t		writeCount;    	/* The BTree's write count (to see if the catalog writeCount */
                              	/* changed since the last search).  If 0, the rest */
                             	/* of the record is invalid, start from beginning. */
  u_int32_t     nextNode;     	/* node number to resume search */
  u_int32_t   	nextRecord;  	/* record number to resume search */
  u_int32_t   	recordsFound; 	/* number of leaf records seen so far */
};
typedef struct CatPosition              CatPosition;


/*
	BTScanState - This structure is used to keep track of the current state
	of a BTree scan.  It contains both the dynamic state information (like
	the current node number and record number) and information that is static
	for the duration of a scan (such as buffer pointers).
	
	NOTE: recordNum may equal or exceed the number of records in the node
	number nodeNum.  If so, then the next attempt to get a record will move
	to a new node number.
*/
struct BTScanState 
{
	//	The following fields are set up once at initialization time.
	//	They are not changed during a scan.
	u_int32_t			bufferSize;
	struct buf *		bufferPtr;
	BTreeControlBlock *	btcb;
	
	//	The following fields are the dynamic state of the current scan.
	u_int32_t			nodeNum;			// zero is first node
	u_int32_t			recordNum;			// zero is first record
	BTNodeDescriptor *	currentNodePtr;		// points to current node within buffer
	u_int32_t			nodesLeftInBuffer;	// number of valid nodes still in the buffer
	u_int32_t			recordsFound;		// number of leaf records seen so far
	struct timeval		startTime;			// time we started catalog search
};
typedef struct BTScanState BTScanState;


/* *********************** PROTOTYPES *********************** */

int	BTScanInitialize(	const FCB *		btreeFile,
						u_int32_t		startingNode,
						u_int32_t		startingRecord,
						u_int32_t		recordsFound,
						u_int32_t		bufferSize,
						BTScanState	*	scanState     );
							
int BTScanNextRecord(	BTScanState *	scanState,
						Boolean			avoidIO,
						void * *		key,
						void * *		data,
						u_int32_t *		dataSize  );

int	BTScanTerminate(	BTScanState *	scanState,
						u_int32_t *		startingNode,
						u_int32_t *		startingRecord,
						u_int32_t *		recordsFound	);

#endif /* !_BTREESCANNER_H_ */
