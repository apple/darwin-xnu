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
 * Revision 1.1.1.1  1998/09/22 21:05:45  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:26:17  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.2.10.2  1995/01/06  19:52:35  devrcs
 * 	mk6 CR668 - 1.3b26 merge
 * 	64bit cleanup
 * 	[1994/10/14  03:43:33  dwm]
 *
 * Revision 1.2.10.1  1994/09/23  02:45:09  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:44:01  ezf]
 * 
 * Revision 1.2.3.2  1993/06/09  02:44:38  gm
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:19:01  jeffc]
 * 
 * Revision 1.2  1993/04/19  16:41:12  devrcs
 * 	ansi C conformance changes
 * 	[1993/02/02  18:56:42  david]
 * 
 * Revision 1.1  1992/09/30  02:32:32  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.4  91/05/14  17:03:21  mrt
 * 	Correcting copyright
 * 
 * Revision 2.3  91/02/05  17:37:46  mrt
 * 	Changed to new Mach copyright
 * 	[91/02/01  17:28:22  mrt]
 * 
 * Revision 2.2  91/01/08  15:18:59  rpd
 * 	Created.
 * 	[91/01/02            rpd]
 * 
 */
/* CMU_ENDHIST */
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
 */

#ifndef	_MACH_DEBUG_HASH_INFO_H_
#define _MACH_DEBUG_HASH_INFO_H_

/*
 *	Remember to update the mig type definitions
 *	in mach_debug_types.defs when adding/removing fields.
 */

typedef struct hash_info_bucket {
	natural_t	hib_count;	/* number of records in bucket */
} hash_info_bucket_t;

typedef hash_info_bucket_t *hash_info_bucket_array_t;

#endif	/* _MACH_DEBUG_HASH_INFO_H_ */
