/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
 * Intel386 Family:	User registers for U**X.
 *
 */
 
#ifdef	KERNEL_PRIVATE

#ifndef _BSD_I386_REG_H_
#define _BSD_I386_REG_H_

/* FIXME - should include mach/i386/thread_status.h and 
  construct the values from i386_saved_state
 */
#define	EDX	9
#define	ECX	10
#define	EAX	11
#define	EIP	14
#define	EFL	16
#define	ESP	7
#define	UESP	17
#define	PS	EFL
#define	PC	EIP
#define	SP	UESP



#endif	/* _BSD_I386_REG_H_ */

#endif	/* KERNEL_PRIVATE */
