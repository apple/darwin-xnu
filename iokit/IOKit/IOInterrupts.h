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
 * Copyright (c) 1999 Apple Computer, Inc.  All rights reserved. 
 *
 *  DRI: Josh de Cesare
 *
 */


#ifndef _IOKIT_IOINTERRUPTS_H
#define _IOKIT_IOINTERRUPTS_H

#define kIOInterruptTypeEdge  (0)
#define kIOInterruptTypeLevel (1)

#ifdef __cplusplus

class OSData;
class IOInterruptController;

struct IOInterruptSource {
  IOInterruptController *interruptController;
  OSData                *vectorData;
};
typedef struct IOInterruptSource IOInterruptSource;

#endif /* __cplusplus */

typedef void (*IOInterruptHandler)(void *target, void *refCon,
				   void *nub, int source);

#endif /* ! _IOKIT_IOINTERRUPTS_H */
