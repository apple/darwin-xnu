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
 * Copyright (c) 1992 NeXT Computer, Inc.
 *
 * Intel386 Family:	Segment selector.
 *
 * HISTORY
 *
 * 29 March 1992 ? at NeXT
 *	Created.
 */

/*
 * Segment selector.
 */

#ifndef __XNU_ARCH_I386_SEL_H
#define __XNU_ARCH_I386_SEL_H

typedef struct sel {
    unsigned short	rpl	:2,
#define KERN_PRIV	0
#define USER_PRIV	3
			ti	:1,
#define SEL_GDT		0
#define SEL_LDT		1
			index	:13;
} sel_t;

#define NULL_SEL	((sel_t) { 0, 0, 0 } )

#endif /* __XNU_ARCH_I386_SEL_H */
