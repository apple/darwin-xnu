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
 * Revision 1.1.1.1  1998/09/22 21:05:29  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:45  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.2.10.2  1995/02/23  17:51:15  alanl
 * 	Merge with DIPC2_SHARED.
 * 	[1995/01/03  21:49:04  alanl]
 *
 * Revision 1.2.10.1  1994/09/23  02:35:28  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:39:26  ezf]
 * 
 * Revision 1.2.8.1  1994/08/04  02:27:36  mmp
 * 	NOTE: file was moved back to b11 version for dipc2_shared.
 * 	Added DIPC error system.
 * 	[1994/05/11  17:36:37  alanl]
 * 
 * Revision 1.2.2.3  1993/08/12  21:59:50  jvs
 * 	Correctly prototype mach_error_fn_t typedef.  9523
 * 	[1993/08/12  21:57:56  jvs]
 * 
 * Revision 1.2.2.2  1993/06/09  02:39:58  gm
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:15:47  jeffc]
 * 
 * Revision 1.2  1993/04/19  16:33:02  devrcs
 * 	make endif tags ansi compliant/include files
 * 	[1993/02/20  21:44:37  david]
 * 
 * Revision 1.1  1992/09/30  02:30:35  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.4  91/05/14  16:51:24  mrt
 * 	Correcting copyright
 * 
 * Revision 2.3  91/02/05  17:31:48  mrt
 * 	Changed to new Mach copyright
 * 	[91/02/01  17:16:50  mrt]
 * 
 * Revision 2.2  90/06/02  14:57:47  rpd
 * 	Added err_mach_ipc for new IPC.
 * 	[90/03/26  22:28:42  rpd]
 * 
 * Revision 2.1  89/08/03  16:02:07  rwd
 * Created.
 * 
 * Revision 2.4  89/02/25  18:13:18  gm0w
 * 	Changes for cleanup.
 * 
 * Revision 2.3  89/02/07  00:51:57  mwyoung
 * Relocated from sys/error.h
 * 
 * Revision 2.2  88/10/18  00:37:31  mwyoung
 * 	Added {system,sub and code}_emask 
 * 	[88/10/17  17:06:58  mrt]
 * 
 *	Added {system,sub and code}_emask 
 *
 *  12-May-88 Mary Thompson (mrt) at Carnegie Mellon
 *	Changed mach_error_t from unsigned int to kern_return_t
 *	which is a 32 bit integer regardless of machine type.
 *      insigned int was incompatible with old usages of mach_error.
 *
 *  10-May-88 Douglas Orr (dorr) at Carnegie-Mellon University
 *	Missing endif replaced
 *
 *   5-May-88 Mary Thompson (mrt) at Carnegie Mellon
 *	Changed typedef of mach_error_t from long to unsigned int
 *	to keep our Camelot users happy. Also moved the nonkernel
 *	function declarations from here to mach_error.h.
 *
 *  10-Feb-88 Douglas Orr (dorr) at Carnegie-Mellon University
 *	Created.
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
 * File:	mach/error.h
 * Purpose:
 *	error module definitions
 *
 */

#ifndef	ERROR_H_
#define ERROR_H_
#include <mach/kern_return.h>

/*
 *	error number layout as follows:
 *
 *	hi		 		       lo
 *	| system(6) | subsystem(12) | code(14) |
 */


#define	err_none		(mach_error_t)0
#define ERR_SUCCESS		(mach_error_t)0
#define	ERR_ROUTINE_NIL		(mach_error_fn_t)0


#define	err_system(x)		(((x)&0x3f)<<26)
#define err_sub(x)		(((x)&0xfff)<<14)

#define err_get_system(err)	(((err)>>26)&0x3f)
#define err_get_sub(err)	(((err)>>14)&0xfff)
#define err_get_code(err)	((err)&0x3fff)

#define system_emask		(err_system(0x3f))
#define sub_emask		(err_sub(0xfff))
#define code_emask		(0x3fff)


/*	major error systems	*/
#define	err_kern		err_system(0x0)		/* kernel */
#define	err_us			err_system(0x1)		/* user space library */
#define	err_server		err_system(0x2)		/* user space servers */
#define	err_ipc			err_system(0x3)		/* old ipc errors */
#define err_mach_ipc		err_system(0x4)		/* mach-ipc errors */
#define	err_dipc		err_system(0x7)		/* distributed ipc */
#define err_local		err_system(0x3e)	/* user defined errors */
#define	err_ipc_compat		err_system(0x3f)	/* (compatibility) mach-ipc errors */

#define	err_max_system		0x3f


/*	unix errors get lumped into one subsystem  */
#define	unix_err(errno)		(err_kern|err_sub(3)|errno)

typedef	kern_return_t	mach_error_t;
typedef mach_error_t	(* mach_error_fn_t)( void );

#endif	/* ERROR_H_ */
