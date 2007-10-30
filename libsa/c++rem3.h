/*
 * Copyright (c) 2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/*
 * History:
 *  2002-02-26 	gvdl	Initial implementation of the gcc 2.95 -> gcc 3.x
 *			symbol remangler.
 */

#include <sys/cdefs.h>

typedef enum Rem3Return {
    kR3NotRemangled = 0,	// Wasn't a 2.95 C++ symbol but otherwise OK
    kR3Remangled,		// Was sucessfully remangled from 2.95 -> 3.x
    kR3InternalNotRemangled,	// Symbol is too big to be parsed
    kR3BufferTooSmallRemangled,	// Is 2.95 symbol but insufficent output space
    kR3BadArgument,		// One of the pointers are NULL
} Rem3Return;

__BEGIN_DECLS

extern Rem3Return
rem3_remangle_name(char *gcc3, int *gcc3size, const char *gcc295);

__END_DECLS
