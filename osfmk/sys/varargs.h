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
 * Revision 1.2.28.1  1996/11/29  16:59:53  stephen
 * 	nmklinux_1.0b3_shared into pmk1.1
 * 	Added powerpc special case
 * 	[1996/11/29  16:34:18  stephen]
 *
 * Revision 1.2.15.2  1996/01/09  19:23:16  devrcs
 * 	Added alpha varargs.h
 * 	[1995/12/01  20:39:10  jfraser]
 * 
 * 	Merged '64-bit safe' changes from DEC alpha port.
 * 	[1995/11/21  18:10:39  jfraser]
 * 
 * Revision 1.2.15.1  1994/09/23  03:13:46  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:59:07  ezf]
 * 
 * Revision 1.2.4.3  1993/08/03  18:30:40  gm
 * 	CR9596: Change KERNEL to MACH_KERNEL.
 * 	[1993/08/02  19:03:10  gm]
 * 
 * Revision 1.2.4.2  1993/06/09  02:55:42  gm
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:31:11  jeffc]
 * 
 * Revision 1.2  1993/04/19  17:17:26  devrcs
 * 	correct endif tags for ansi
 * 	[1993/02/25  17:56:02  david]
 * 
 * Revision 1.1  1992/09/30  02:37:05  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.10  91/12/10  16:32:53  jsb
 * 	Fixes from Intel
 * 	[91/12/10  15:52:01  jsb]
 * 
 * Revision 2.9  91/09/12  16:54:22  debo
 * 	Added mac2.
 * 	[91/09/11  17:22:52  debo]
 * 
 * Revision 2.8  91/07/09  23:23:50  danner
 * 	Added luna88k support.
 * 	[91/06/24            danner]
 * 
 * Revision 2.7  91/06/18  20:53:02  jsb
 * 	Moved i860 varargs code here from i860/i860_varargs.h, thanks to
 * 	new copyright from Intel.
 * 	[91/06/18  19:15:02  jsb]
 * 
 * Revision 2.6  91/05/14  17:40:46  mrt
 * 	Correcting copyright
 * 
 * Revision 2.5  91/02/05  17:57:12  mrt
 * 	Changed to new Mach copyright
 * 	[91/02/01  17:49:51  mrt]
 * 
 * Revision 2.4  90/11/25  17:48:50  jsb
 * 	Added i860 support.
 * 	[90/11/25  16:54:09  jsb]
 * 
 * Revision 2.3  90/05/03  15:51:29  dbg
 * 	Added i386.
 * 	[90/02/08            dbg]
 * 
 * Revision 2.2  89/11/29  14:16:44  af
 * 	RCS-ed, added mips case.  Mips also needs it in Mach standalone
 * 	programs.
 * 	[89/10/28  10:39:14  af]
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

#ifndef _SYS_VARARGS_H_
#define _SYS_VARARGS_H_

#if	defined(vax) || defined(sun3) || defined(mips) || defined(i386) || defined(mac2)
#define	va_dcl	int	va_alist;
typedef	char *	va_list;

#define	va_start(pvar)	(pvar) = (va_list)&va_alist
#define	va_end(pvar)
#ifdef	mips
# define va_arg(pvar, type) ((type *)(pvar = \
		(va_list) (sizeof(type) > 4 ? ((int)pvar + 2*8 - 1) & -8 \
				   : ((int)pvar + 2*4 - 1) & -4)))[-1]
#else	/* mips */
#define	va_arg(pvar,type)	(		\
		(pvar) += ((sizeof(type)+3) & ~0x3),	\
		*((type *)((pvar) - ((sizeof(type)+3) & ~0x3))) )
#endif	/* mips */
#endif	/* vax */

/*
 * Try to make varargs work for the Multimax so that _doprnt can be
 * declared as
 *	_doprnt(file, fmt, list)
 *	FILE	*file;
 *	char	*fmt;
 *	va_list *list;
 * and use
 *
 *	n = va_arg(*list, type)
 *
 * without needing to drag in extra declarations
 *
 * and printf becomes
 *
 * printf(fmt, va_alist)
 *	char	*fmt;
 *	va_dcl
 * {
 *	va_list listp;
 *	va_start(listp);
 *	_doprnt((FILE *)0, fmt, &listp);
 *	va_end(listp);
 * }
 */

#if	defined(multimax) && defined(MACH_KERNEL)

/*
 * the vararglist pointer is an elaborate structure (ecch)
 */
typedef struct va_list {
	char	*va_item;	/* current item */
	int	*va_ptr1,	/* arglist pointers for 1, 2, n */
		*va_ptr2,
		*va_ptrn;
	int	va_ct;		/* current argument number */
} va_list;

#define	va_alist	va_arg1, va_arg2, va_argn
#define	va_dcl		int	va_arg1, va_arg2, va_argn;

#define	va_start(pvar)	(		\
	(pvar).va_ptr1 = &va_arg1,	\
	(pvar).va_ptr2 = &va_arg2,	\
	(pvar).va_ptrn = &va_argn,	\
	(pvar).va_ct = 0 )

#define	va_end(pvar)

#define	va_arg(pvar, type)	(	\
	(pvar).va_ct++,			\
	(pvar).va_item = (char *)	\
	  ( ((pvar).va_ct == 1)		\
	    ? (pvar).va_ptr1		\
	    : ((pvar).va_ct == 2)	\
	      ? (pvar).va_ptr2		\
	      : (pvar).va_ptrn++ ) ,	\
	*((type *)((pvar).va_item)) )

/* what a mess! */
#endif	/* defined(multimax) && defined(MACH_KERNEL) */

#if i860
#include <i860/varargs.h>	/* PGI vs. Greenhills */
#endif

#ifdef luna88k
#include <luna88k/varargs.h> /* How nice */
#endif

#if defined (__PPC__) && defined (_CALL_SYSV)
#include <ppc/va-ppc.h>	/* care of gcc compiler - TEMPORARY 2.7.1 TODO NMGS*/
#endif

#if defined(__alpha)
#  include <varargs.h>
#endif /* defined(__alpha) */

#endif /* _SYS_VARARGS_H_ */
