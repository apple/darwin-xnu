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
 * Revision 1.2.9.2  1998/02/02  09:22:22  gdt
 * 	Add new function "MATTR_VAL_GET_INFO" to get shared/resident information
 * 	about a page.  This lets Linux display better statistics (e.g. 'top').
 * 	[1998/02/02  09:21:30  gdt]
 *
 * Revision 1.2.9.1  1997/09/12  17:16:06  stephen
 * 	Add new MATTR_VAL_CACHE_SYNC which
 * 	syncs I+D caches without necessarily
 * 	flushing them.
 * 	[1997/09/12  16:32:45  stephen]
 * 
 * Revision 1.2.6.1  1994/09/23  02:43:58  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:43:31  ezf]
 * 
 * Revision 1.2.2.2  1993/06/09  02:44:08  gm
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:18:41  jeffc]
 * 
 * Revision 1.2  1993/04/19  16:40:21  devrcs
 * 	ansi C conformance changes
 * 	[1993/02/02  18:55:22  david]
 * 
 * Revision 1.1  1992/09/30  02:32:22  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.4  91/05/14  17:02:37  mrt
 * 	Correcting copyright
 * 
 * Revision 2.3  91/02/05  17:37:24  mrt
 * 	Changed to new Mach copyright
 * 	[91/02/01  17:22:17  mrt]
 * 
 * Revision 2.2  90/01/22  23:05:53  af
 * 	Created.
 * 	[89/12/08            af]
 * 
 *
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
 *	File:	mach/vm_attributes.h
 *	Author:	Alessandro Forin
 *
 *	Virtual memory attributes definitions.
 *
 *	These definitions are in addition to the machine-independent
 *	ones (e.g. protection), and are only selectively supported
 *	on specific machine architectures.
 *
 */

#ifndef	VM_ATTRIBUTES_H_
#define	VM_ATTRIBUTES_H_

/*
 *	Types of machine-dependent attributes
 */
typedef unsigned int	vm_machine_attribute_t;

#define	MATTR_CACHE		1	/* cachability */
#define MATTR_MIGRATE		2	/* migrability */
#define	MATTR_REPLICATE		4	/* replicability */

/*
 *	Values for the above, e.g. operations on attribute
 */
typedef int		vm_machine_attribute_val_t;

#define MATTR_VAL_OFF		0	/* (generic) turn attribute off */
#define MATTR_VAL_ON		1	/* (generic) turn attribute on */
#define MATTR_VAL_GET		2	/* (generic) return current value */

#define MATTR_VAL_CACHE_FLUSH	6	/* flush from all caches */
#define MATTR_VAL_DCACHE_FLUSH	7	/* flush from data caches */
#define MATTR_VAL_ICACHE_FLUSH	8	/* flush from instruction caches */
#define MATTR_VAL_CACHE_SYNC	9	/* sync I+D caches */
#define MATTR_VAL_CACHE_SYNC	9	/* sync I+D caches */

#define MATTR_VAL_GET_INFO	10	/* get page info (stats) */

#endif	/* VM_ATTRIBUTES_H_ */
