/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
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
 * Revision 1.2  1998/04/29 17:36:36  mburg
 * MK7.3 merger
 *
 * Revision 1.2.22.1  1998/02/03  09:32:55  gdt
 * 	Merge up to MK7.3
 * 	[1998/02/03  09:17:02  gdt]
 *
 * Revision 1.2.20.1  1997/06/17  03:00:55  devrcs
 * 	RPC Enhancements.
 * 	Added new definition of the rpc_return_trap.
 * 	[1996/04/26  21:53:51  yfei]
 * 
 * Revision 1.2.17.2  1996/02/16  00:07:27  yfei
 * 	Merged NSWC based RPC enhancements into MK7_MAIN.
 * 
 * Revision 1.2.12.2  1994/09/23  02:37:42  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:40:17  ezf]
 * 
 * Revision 1.2.12.1  1994/08/26  20:48:44  watkins
 * 	Merge with rt2_shared.
 * 	[1994/08/26  18:38:55  watkins]
 * 
 * Revision 1.2.9.1  1994/07/18  22:03:32  burke
 * 	Check-in for merge.
 * 	[1994/07/15  21:04:49  burke]
 * 
 * Revision 1.2.7.3  1994/07/05  14:28:23  watkins
 * 	Merge with rpc.
 * 	[1994/07/05  14:27:30  watkins]
 * 
 * Revision 1.2.6.1  1994/05/18  21:18:29  watkins
 * 	Add macro for rpc call gate.
 * 	[1994/05/18  21:16:19  watkins]
 * 
 * Revision 1.2.2.2  1993/06/09  02:40:45  gm
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:16:24  jeffc]
 * 
 * Revision 1.2  1993/04/19  16:34:14  devrcs
 * 	Fixes for ANSI C
 * 	[1993/02/26  13:35:10  sp]
 * 
 * Revision 1.1  1992/09/30  02:30:50  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.5  91/05/14  16:52:22  mrt
 * 	Correcting copyright
 * 
 * Revision 2.4  91/02/05  17:32:17  mrt
 * 	Changed to new Mach copyright
 * 	[91/02/01  17:10:01  mrt]
 * 
 * Revision 2.3  90/12/05  23:46:16  af
 * 	Made GNU preproc happy.
 * 
 * Revision 2.2  90/05/03  15:48:01  dbg
 * 	Created.
 * 	[90/04/30  16:36:25  dbg]
 * 
 * Revision 1.3.1.1  89/12/22  22:22:03  rvb
 * 	Use asm.h
 * 	[89/12/22            rvb]
 * 
 * Revision 1.3  89/03/09  20:19:53  rpd
 * 	More cleanup.
 * 
 * Revision 1.2  89/02/26  13:01:00  gm0w
 * 	Changes for cleanup.
 * 
 * 31-Dec-88  Robert Baron (rvb) at Carnegie-Mellon University
 *	Derived from MACH2.0 vax release.
 *
 *  1-Sep-86  Michael Young (mwyoung) at Carnegie-Mellon University
 *	Created from mach_syscalls.h in the user library sources.
 *
 */
/* CMU_ENDHIST */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */

#ifndef	_MACH_I386_SYSCALL_SW_H_
#define _MACH_I386_SYSCALL_SW_H_

#include <architecture/i386/asm_help.h>

#define MACHCALLSEL     $0x07
#define RPCCALLSEL 	$0x0f

#define kernel_trap(trap_name,trap_number,number_args) \
LEAF(_##trap_name,0) ;\
	movl	$##trap_number,%eax   ;\
        lcall   MACHCALLSEL, $0 ;\
END(_##trap_name)

#define rpc_trap(trap_name,trap_number,number_args) \
LEAF(_##trap_name,0) ;\
        movl    $##trap_number,%eax; \
        lcall   RPCCALLSEL, $0 ;\
END(_##trap_name)

#define rpc_return_trap(trap_name,trap_number,number_args) \
LEAF(_##trap_name,0) ;\
	movl    %eax, %ecx; \
        movl    $##trap_number,%eax; \
        lcall   RPCCALLSEL, $0 ;\
END(_##trap_name)

#endif	/* _MACH_I386_SYSCALL_SW_H_ */
