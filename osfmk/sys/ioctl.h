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
 * Revision 1.1.1.1  1998/09/22 21:05:48  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:59  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.2.10.1  1996/11/29  16:59:52  stephen
 * 	nmklinux_1.0b3_shared into pmk1.1
 * 	Moved contents to mach/mach_ioctl.h.
 * 	[96/09/18            barbou]
 *
 * Revision 1.2.6.1  1994/09/23  03:12:49  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:58:45  ezf]
 * 
 * Revision 1.2.2.2  1993/06/09  02:55:17  gm
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:30:51  jeffc]
 * 
 * Revision 1.2  1993/04/19  17:16:43  devrcs
 * 	Fixes for ANSI C
 * 	[1993/02/26  14:02:24  sp]
 * 
 * Revision 1.1  1992/09/30  02:36:52  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.5  91/10/09  16:18:46  af
 * 	 Revision 2.4.1.1  91/09/01  15:53:00  af
 * 	 	Upgraded to BSD 4.4.
 * 	 	[91/09/01            af]
 * 
 * Revision 2.4.1.1  91/09/01  15:53:00  af
 * 	Upgraded to BSD 4.4.
 * 	[91/09/01            af]
 * 
 * Revision 2.4  91/05/14  17:40:04  mrt
 * 	Correcting copyright
 * 
 * Revision 2.3  91/03/16  15:01:35  rpd
 * 	Fixed the definitions for ANSI C.
 * 	[91/02/20            rpd]
 * 
 * Revision 2.2  91/02/14  15:04:02  mrt
 * 	Changed to new Mach copyright
 * 
 * 
 */
/* CMU_ENDHIST */
/*
 * Mach Operating System
 * Copyright (c) 1991 Carnegie Mellon University
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
 * any improvements or extensions that they make and grant Carnegie Mellon rights
 * to redistribute these changes.
 */
/*
 */
/*
 * Format definitions for 'ioctl' commands in device definitions.
 *
 * From BSD4.4.
 */

#ifndef _SYS_IOCTL_H_
#define _SYS_IOCTL_H_

#include <mach/mach_ioctl.h>

#endif	 /* _SYS_IOCTL_H_ */
