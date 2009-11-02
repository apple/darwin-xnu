/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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
 * @APPLE_FREE_COPYRIGHT@
 */

/*
 * Here be the instrumentaion page layout
 * Lovingly crafted by Bill Angell using traditional methods
*/

#ifndef _INSTRUMENTATION_H_
#define _INSTRUMENTATION_H_

#define INTRUMENTATION 1


#define inBase 0x6000

#define inEntry 0
#define inAtGetTb 1
#define inBeforeTrace 2
#define inAfterSAAlloc 3
#define inBeforeFilter 4
#define inEatRuptQfret 5
#define inEatRuptSAfree 6
#define inPassupSwtchSeg 7
#define inExceptionExit 8
#define inMiddleOfSC 9
#define inEatRuptSwtchSeg 10
#define inPassup 11
#define inCopyout 12
#define inMUASbefore 13
#define inMUAS

#endif /* _INSTRUMENTATION_H_ */
