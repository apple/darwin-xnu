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
 * @OSF_COPYRIGHT@
 */
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:31  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:46  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.10.2  1994/09/23  02:44:05  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:43:34  ezf]
 *
 * Revision 1.1.10.1  1994/08/07  20:50:20  bolinger
 * 	Import colo_shared revision into NMK18.
 * 	[1994/08/02  16:41:42  bolinger]
 * 
 * Revision 1.1.8.1  1994/07/08  20:09:11  dwm
 * 	mk6 CR227 - bring vm_behavior constants up to spec.
 * 	[1994/07/08  20:02:37  dwm]
 * 
 * Revision 1.1.4.3  1993/09/17  21:35:31  robert
 * 	change marker to OSF_FREE_COPYRIGHT
 * 	[1993/09/17  21:28:53  robert]
 * 
 * Revision 1.1.4.2  1993/06/04  15:14:02  jeffc
 * 	CR9193 - MK5.0 merge.
 * 	[1993/06/04  13:54:38  jeffc]
 * 
 * Revision 3.0  92/12/31  22:14:09  ede
 * 	Initial revision for OSF/1 R1.3
 * 
 * $EndLog$
 */
/*
 *	File:	mach/vm_behavior.h
 *
 *	Virtual memory map behavior definitions.
 *
 */

#ifndef	_MACH_VM_BEHAVIOR_H_
#define _MACH_VM_BEHAVIOR_H_

/*
 *	Types defined:
 *
 *	vm_behavior_t	behavior codes.
 */

typedef int		vm_behavior_t;

/*
 *	Enumeration of valid values for vm_behavior_t.
 *	These describe expected page reference behavior for 
 *	for a given range of virtual memory.  For implementation 
 *	details see vm/vm_fault.c
 */


#define VM_BEHAVIOR_DEFAULT	((vm_behavior_t) 0)	/* default */
#define VM_BEHAVIOR_RANDOM	((vm_behavior_t) 1)	/* random */
#define VM_BEHAVIOR_SEQUENTIAL	((vm_behavior_t) 2)	/* forward sequential */
#define VM_BEHAVIOR_RSEQNTL	((vm_behavior_t) 3)	/* reverse sequential */

#endif	/*_MACH_VM_BEHAVIOR_H_*/
