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
 * Mach Operating System
 * Copyright (c) 1991,1990 Carnegie Mellon University
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
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:39  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:40  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.2.6.1  1994/09/23  01:45:53  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:19:54  ezf]
 *
 * Revision 1.2.2.2  1993/06/09  02:27:00  gm
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:02:53  jeffc]
 * 
 * Revision 1.2  1993/04/19  16:12:08  devrcs
 * 	Fixed Copyrights
 * 	[92/12/16            bernadat]
 * 
 * 	Changed MP_GDT from 1200 to 1100 to save unused space.
 * 	[92/12/08            bernadat]
 * 
 * Revision 1.1  1992/09/30  02:27:14  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.1.3.1  92/04/30  11:57:14  bernadat
 * 	Moved from cbus to here, applies to both Corollary
 * 	and SystemPro
 * 	[92/04/08            bernadat]
 * 
 * Revision 2.1.9.1  92/02/18  18:34:14  jeffreyh
 * 	Created
 * 	[91/06/27  05:00:05  bernadat]
 * 
 */
/* CMU_ENDHIST */

/*
 * Define where to store boot code for slaves
 */

#define MP_BOOT		0x1000		/* address where slave boots load */
#define MP_BOOTSEG	0x100	
#define MP_GDT		0x1100		/* temporary gdt address for boot */
#define MP_BOOTSTACK	0x800		/* stack for boot */
#define MP_MACH_START	MP_BOOTSTACK	/* contains address where to jump
					   after boot */
#define MP_FIRST_ADDR	0x3000		/* 2 extra pages reserved */
