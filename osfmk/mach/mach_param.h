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
 * Revision 1.1.1.1  1998/09/22 21:05:30  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:45  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.2.16.2  1994/09/23  02:38:50  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:40:58  ezf]
 *
 * Revision 1.2.16.1  1994/06/13  20:49:40  dlb
 * 	Merge MK6 and NMK17
 * 	[1994/06/13  20:47:55  dlb]
 * 
 * Revision 1.2.7.1  1994/03/11  15:26:48  bernadat
 * 	Do not account exception ports as registered ports.
 * 	[94/03/11            bernadat]
 * 
 * Revision 1.2.2.4  1993/08/05  19:09:19  jeffc
 * 	CR9508 - Delete dead code. Remove MACH_IPC_COMPAT
 * 	[1993/08/03  17:09:06  jeffc]
 * 
 * Revision 1.2.2.3  1993/08/03  18:29:29  gm
 * 	CR9596: Change KERNEL to MACH_KERNEL.
 * 	[1993/08/02  18:04:55  gm]
 * 
 * Revision 1.2.2.2  1993/06/09  02:41:29  gm
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:16:53  jeffc]
 * 
 * Revision 1.2  1993/04/19  16:35:13  devrcs
 * 	Fixes for ANSI C
 * 	[1993/02/26  13:30:09  sp]
 * 
 * 	Updated to new exception interface.
 * 	[1992/12/23  13:09:02  david]
 * 
 * Revision 1.1  1992/09/30  02:31:14  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.4.2.1  92/03/03  16:22:03  jeffreyh
 * 	Changes from TRUNK
 * 	[92/02/26  12:02:58  jeffreyh]
 * 
 * Revision 2.5  92/01/15  13:44:51  rpd
 * 	Changed MACH_IPC_COMPAT conditionals to default to not present.
 * 
 * Revision 2.4  91/05/14  16:54:40  mrt
 * 	Correcting copyright
 * 
 * Revision 2.3  91/02/05  17:33:28  mrt
 * 	Changed to new Mach copyright
 * 	[91/02/01  17:18:01  mrt]
 * 
 * Revision 2.2  90/06/02  14:58:21  rpd
 * 	Created.
 * 	[90/03/26  23:56:39  rpd]
 * 
 *
 * Condensed history:
 *	Moved implementation constants elsewhere (rpd).
 *	Added SET_MAX (rpd).
 *	Added KERN_MSG_SMALL_SIZE (mwyoung).
 *	Added PORT_BACKLOG_MAX (mwyoung).
 *	Added PORT_BACKLOG_MAX (mwyoung).
 *	Added TASK_PORT_REGISTER_MAX (mwyoung).
 *	Created (mwyoung).
 */
/* CMU_ENDHIST */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
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
 *	File:	mach/mach_param.h
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1986
 *
 *	Mach system sizing parameters
 */

#ifndef	_MACH_MACH_PARAM_H_
#define _MACH_MACH_PARAM_H_

/* Number of "registered" ports */

#define TASK_PORT_REGISTER_MAX	3

#endif	/* _MACH_MACH_PARAM_H_ */
