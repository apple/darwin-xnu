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
 * Revision 1.1.1.1  1998/09/22 21:05:49  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:59  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.6.1  1994/09/23  03:13:55  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:59:11  ezf]
 *
 * Revision 1.1.2.2  1993/06/03  00:18:34  jeffc
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:31:15  jeffc]
 * 
 * Revision 1.1  1992/09/30  02:37:07  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.4  91/05/14  17:40:52  mrt
 * 	Correcting copyright
 * 
 * Revision 2.3  91/02/05  17:57:18  mrt
 * 	Changed to new Mach copyright
 * 	[91/02/01  17:49:58  mrt]
 * 
 * Revision 2.2  90/01/19  14:35:31  rwd
 * 	Set version to 3.0 and set include version to 0
 * 	[89/12/10            rwd]
 * 
 * Revision 2.1  89/08/03  16:10:14  rwd
 * Created.
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
 * any improvements or extensions that they make and grant Carnegie Mellon rights
 * to redistribute these changes.
 */
/*
 */

/*
 *	Each kernel has a major and minor version number.  Changes in
 *	the major number in general indicate a change in exported features.
 *	Changes in minor number usually correspond to internal-only
 *	changes that the user need not be aware of (in general).  These
 *	values are stored at boot time in the machine_info strucuture and
 *	can be obtained by user programs with the host_info kernel call.
 *	This mechanism is intended to be the formal way for Mach programs
 *	to provide for backward compatibility in future releases.
 *
 *	[ This needs to be reconciled somehow with the major/minor version
 *	  number stuffed into the version string - mja, 5/8/87 ]
 *
 *	Following is an informal history of the numbers:
 *
 *	25-March-87  Avadis Tevanian, Jr.
 *		Created version numbering scheme.  Started with major 1,
 *		minor 0.
 */

#define KERNEL_MAJOR_VERSION	3
#define KERNEL_MINOR_VERSION	0

/* 
 *  Version number of the kernel include files.
 *
 *  This number must be changed whenever an incompatible change is made to one
 *  or more of our include files which are used by application programs that
 *  delve into kernel memory.  The number should normally be simply incremented
 *  but may actually be changed in any manner so long as it differs from the
 *  numbers previously assigned to any other versions with which the current
 *  version is incompatible.  It is used at boot time to determine which
 *  versions of the system programs to install.
 *
 *  Note that the symbol _INCLUDE_VERSION must be set to this in the symbol
 *  table.  On the VAX for example, this is done in locore.s.
 */

/*
 * Current allocation strategy: bump either branch by 2, until non-MACH is
 * excised from the CSD environment.
 */
#define	INCLUDE_VERSION	0
