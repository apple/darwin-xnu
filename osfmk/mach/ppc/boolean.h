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
 * Revision 1.1.1.1  1998/03/07 02:25:46  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.8.1  1996/12/09  16:50:03  stephen
 * 	nmklinux_1.0b3_shared into pmk1.1
 * 	[1996/12/09  10:50:49  stephen]
 *
 * Revision 1.1.6.1  1996/04/11  11:19:44  emcmanus
 * 	Copied from mainline.ppc.
 * 	[1996/04/10  16:56:37  emcmanus]
 * 
 * Revision 1.1.4.1  1995/11/23  17:36:42  stephen
 * 	first powerpc checkin to mainline.ppc
 * 	[1995/11/23  16:44:33  stephen]
 * 
 * Revision 1.1.2.1  1995/08/25  06:49:32  stephen
 * 	Initial checkin of files for PowerPC port
 * 	[1995/08/23  16:27:03  stephen]
 * 
 * 	Initial checkin of files for PowerPC port
 * 	[1995/08/23  15:03:41  stephen]
 * 
 * Revision 1.2.6.1  1994/09/23  02:36:44  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:39:49  ezf]
 * 
 * Revision 1.2.2.2  1993/06/09  02:40:19  gm
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:16:03  jeffc]
 * 
 * Revision 1.2  1993/04/19  16:33:37  devrcs
 * 	ansi C conformance changes
 * 	[1993/02/02  18:55:53  david]
 * 
 * Revision 1.1  1992/09/30  02:30:40  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.4  91/05/14  16:51:56  mrt
 * 	Correcting copyright
 * 
 * Revision 2.3  91/02/05  17:32:04  mrt
 * 	Changed to new Mach copyright
 * 	[91/02/01  17:09:33  mrt]
 * 
 * Revision 2.2  90/05/03  15:47:26  dbg
 * 	First checkin.
 * 
 * Revision 1.3  89/03/09  20:19:36  rpd
 * 	More cleanup.
 * 
 * Revision 1.2  89/02/26  13:00:41  gm0w
 * 	Changes for cleanup.
 * 
 * 24-Sep-86  Michael Young (mwyoung) at Carnegie-Mellon University
 *	Created.
 */
/* CMU_ENDHIST */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
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

/*
 *	File:	boolean.h
 *
 *	Boolean type, for ppc.
 */

#ifndef	_MACH_PPC_BOOLEAN_H_
#define _MACH_PPC_BOOLEAN_H_

typedef int		boolean_t;

#endif	/* _MACH_PPC_BOOLEAN_H_ */
