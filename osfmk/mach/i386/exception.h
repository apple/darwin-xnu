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
 * Revision 1.1.1.1  1998/03/07 02:25:47  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.2.8.5  1995/04/07  19:05:14  barbou
 * 	Backed out previous submission.
 * 	[95/03/29            barbou]
 *
 * Revision 1.2.8.4  1995/03/15  17:19:29  bruel
 * 	EXC_TYPES_COUNT is machine independant.
 * 	(the machine exception type is given in the code argument).
 * 	[95/03/06            bruel]
 * 
 * Revision 1.2.8.3  1995/01/10  05:16:18  devrcs
 * 	mk6 CR801 - merge up from nmk18b4 to nmk18b7
 * 	* Rev 1.2.6.3  1994/11/08  21:53:17  rkc
 * 	  Incremented the number of exception types to reflect the addition
 * 	  of the alert exception.
 * 	[1994/12/09  21:11:21  dwm]
 * 
 * Revision 1.2.8.1  1994/09/23  02:36:53  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:39:53  ezf]
 * 
 * Revision 1.2.2.2  1993/06/09  02:40:25  gm
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:16:07  jeffc]
 * 
 * Revision 1.2  1993/04/19  16:33:44  devrcs
 * 	changes for EXC_MACH_SYSCALL
 * 	[1993/04/05  12:06:25  david]
 * 
 * 	make endif tags ansi compliant/include files
 * 	[1993/02/20  21:44:18  david]
 * 
 * 	Updated to new exception interface.
 * 	[1992/12/23  13:05:21  david]
 * 
 * Revision 1.1  1992/09/30  02:30:41  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.4  91/05/14  16:52:05  mrt
 * 	Correcting copyright
 * 
 * Revision 2.3  91/02/05  17:32:08  mrt
 * 	Changed to new Mach copyright
 * 	[91/02/01  17:09:45  mrt]
 * 
 * Revision 2.2  90/05/03  15:47:38  dbg
 * 	First checkin.
 * 
 * Revision 1.3  89/03/09  20:19:42  rpd
 * 	More cleanup.
 * 
 * Revision 1.2  89/02/26  13:00:47  gm0w
 * 	Changes for cleanup.
 * 
 * 31-Dec-88  Robert Baron (rvb) at Carnegie-Mellon University
 *	Derived from MACH2.0 vax release.
 *
 *  2-Nov-87  David Golub (dbg) at Carnegie-Mellon University
 *	Created.
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

#ifndef	_MACH_I386_EXCEPTION_H_
#define _MACH_I386_EXCEPTION_H_

/*
 * No machine dependent types for the 80386
 */

#define	EXC_TYPES_COUNT	10	/* incl. illegal exception 0 */

/*
 *	Codes and subcodes for 80386 exceptions.
 */

#define EXCEPTION_CODE_MAX	2	/* currently code and subcode */

/*
 *	EXC_BAD_INSTRUCTION
 */

#define EXC_I386_INVOP			1

/*
 *	EXC_ARITHMETIC
 */

#define EXC_I386_DIV			1
#define EXC_I386_INTO			2
#define EXC_I386_NOEXT			3
#define EXC_I386_EXTOVR			4
#define EXC_I386_EXTERR			5
#define EXC_I386_EMERR			6
#define EXC_I386_BOUND			7

/*
 *	EXC_SOFTWARE
 *	Note: 0x10000-0x10003 in use for unix signal
 */

/*
 *	EXC_BAD_ACCESS
 */

/*
 *	EXC_BREAKPOINT
 */

#define EXC_I386_SGL			1
#define EXC_I386_BPT			2

#define EXC_I386_DIVERR		0	/* divide by 0 eprror		*/
#define EXC_I386_SGLSTP		1	/* single step			*/
#define EXC_I386_NMIFLT		2	/* NMI				*/
#define EXC_I386_BPTFLT		3	/* breakpoint fault		*/
#define EXC_I386_INTOFLT	4	/* INTO overflow fault		*/
#define EXC_I386_BOUNDFLT	5	/* BOUND instruction fault	*/
#define EXC_I386_INVOPFLT	6	/* invalid opcode fault		*/
#define EXC_I386_NOEXTFLT	7	/* extension not available fault*/
#define EXC_I386_DBLFLT		8	/* double fault			*/
#define EXC_I386_EXTOVRFLT	9	/* extension overrun fault	*/
#define EXC_I386_INVTSSFLT	10	/* invalid TSS fault		*/
#define EXC_I386_SEGNPFLT	11	/* segment not present fault	*/
#define EXC_I386_STKFLT		12	/* stack fault			*/
#define EXC_I386_GPFLT		13	/* general protection fault	*/
#define EXC_I386_PGFLT		14	/* page fault			*/
#define EXC_I386_EXTERRFLT	16	/* extension error fault	*/
#define	EXC_I386_ALIGNFLT	17	/* Alignment fault */
#define EXC_I386_ENDPERR	33	/* emulated extension error flt	*/
#define EXC_I386_ENOEXTFLT	32	/* emulated ext not present	*/


/*
 *	machine dependent exception masks
 */
#define	EXC_MASK_MACHINE	0


#endif	/* _MACH_I386_EXCEPTION_H_ */
