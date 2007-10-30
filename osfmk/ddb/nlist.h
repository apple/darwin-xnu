/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
 */
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:48  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:26:09  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.11.2  1995/01/06  19:11:11  devrcs
 * 	mk6 CR668 - 1.3b26 merge
 * 	Add padding for alpha, make n_other unsigned,
 * 	fix erroneous def of N_FN.
 * 	[1994/10/14  03:40:03  dwm]
 *
 * Revision 1.1.11.1  1994/09/23  01:23:37  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:11:49  ezf]
 * 
 * Revision 1.1.4.3  1993/07/27  18:28:42  elliston
 * 	Add ANSI prototypes.  CR #9523.
 * 	[1993/07/27  18:13:44  elliston]
 * 
 * Revision 1.1.4.2  1993/06/02  23:13:34  jeffc
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  20:58:08  jeffc]
 * 
 * Revision 1.1  1992/09/30  02:24:29  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.4  91/05/14  15:38:20  mrt
 * 	Correcting copyright
 * 
 * Revision 2.3  91/02/05  17:07:42  mrt
 * 	Changed to new Mach copyright
 * 	[91/01/31  16:20:26  mrt]
 * 
 * 11-Aug-88  David Golub (dbg) at Carnegie-Mellon University
 *	Added n_un, n_strx definitions for kernel debugger (from
 *	a.out.h).
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
 * any improvements or extensions that they make and grant Carnegie Mellon 
 * the rights to redistribute these changes.
 */
/*
 */
/*
 *  nlist.h - symbol table entry  structure for an a.out file
 *  derived from FSF's a.out.gnu.h
 *
 */

#ifndef _DDB_NLIST_H_
#define _DDB_NLIST_H_

struct	nlist {
	union n_un {
	    char	*n_name;	/* symbol name */
	    long	n_strx;		/* index into file string table */
	} n_un;
	unsigned char n_type;	/* type flag, i.e. N_TEXT etc; see below */
	unsigned char n_other;	/* unused */
	short	n_desc;		/* see <stab.h> */
#if	defined(__alpha)
	int	n_pad;		/* alignment, used to carry framesize info */
#endif
	vm_offset_t n_value;	/* value of this symbol (or sdb offset) */
};

/*
 * Simple values for n_type.
 */
#define	N_UNDF	0		/* undefined */
#define	N_ABS	2		/* absolute */
#define	N_TEXT	4		/* text */
#define	N_DATA	6		/* data */
#define	N_BSS	8		/* bss */
#define	N_FN	0x1e		/* file name symbol */
#define	N_EXT	1		/* external bit, or'ed in */
#define	N_TYPE	0x1e		/* mask for all the type bits */
#define	N_STAB	0xe0		/* if any of these bits set, a SDB entry */

#endif	/* !_DDB_NLIST_H_ */
