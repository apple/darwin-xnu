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
 * Revision 1.1.1.1  1998/09/22 21:05:45  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:26:17  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.6.1  1994/09/23  02:45:56  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:44:21  ezf]
 *
 * Revision 1.1.2.3  1993/07/28  18:01:46  jeffc
 * 	CR9523 - Add prototypes to kernel. Protect this file
 * 	against multiple inclusion
 * 	[1993/07/28  12:23:48  jeffc]
 * 
 * Revision 1.1.2.2  1993/06/02  23:50:21  jeffc
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:19:13  jeffc]
 * 
 * Revision 1.1  1992/09/30  02:32:37  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.4  91/05/14  17:04:01  mrt
 * 	Correcting copyright
 * 
 * Revision 2.3  91/02/05  17:38:10  mrt
 * 	Changed to new Mach copyright
 * 	[91/02/01  17:29:22  mrt]
 * 
 * Revision 2.2  90/05/03  15:48:58  dbg
 * 	Created.
 * 	[90/04/06            dbg]
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
#ifndef MACH_DEBUG_PAGE_INFO_H 
#define MACH_DEBUG_PAGE_INFO_H 

#include <mach/machine/vm_types.h>

typedef	vm_offset_t	*page_address_array_t;
#endif	/* MACH_DEBUG_PAGE_INFO_H */
