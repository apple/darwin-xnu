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
 * Revision 1.1.1.1  1998/09/22 21:05:32  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:57  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.12.5  1995/02/24  15:22:46  alanl
 * 	Add XPR definition to trace generic XMM activities.
 * 	[95/01/31            alanl]
 *
 * Revision 1.1.14.3  1994/11/02  18:37:35  dwm
 * 	mk6 CR668 - 1.3b26 merge
 * 	Add MOR token, update XPR names for locks, vm_maps.
 * 	now only a single XPR(...) macro, 5 args always.
 * 	[1994/11/02  18:17:33  dwm]
 * 
 * Revision 1.1.12.3  1994/09/23  02:32:50  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:38:33  ezf]
 * 
 * Revision 1.1.12.2  1994/09/10  21:46:57  bolinger
 * 	Merge up to NMK17.3
 * 	[1994/09/08  19:57:50  bolinger]
 * 
 * Revision 1.1.12.1  1994/06/14  17:13:10  bolinger
 * 	Merge up to NMK17.2.
 * 	[1994/06/14  16:55:44  bolinger]
 * 
 * Revision 1.1.7.2  1994/05/30  07:37:07  bernadat
 * 	Added missing ')' to XPR5.
 * 	[94/05/25            bernadat]
 * 
 * Revision 1.1.7.1  1994/03/24  15:29:18  paire
 * 	Set up correct XPR and XPR[1-5] macros.
 * 	Added XPR_SIMPLE_LOCK define.
 * 	[94/03/08            paire]
 * 
 * Revision 1.1.2.5  1993/08/03  18:29:24  gm
 * 	CR9596: Change KERNEL to MACH_KERNEL.
 * 	[1993/08/02  17:41:44  gm]
 * 
 * Revision 1.1.2.4  1993/07/27  18:09:08  rod
 * 	Add ANSI prototypes.  CR #9523.
 * 	[1993/07/27  10:42:04  rod]
 * 
 * Revision 1.1.2.3  1993/06/07  22:15:39  jeffc
 * 	CR9176 - ANSI C violations: trailing tokens on CPP
 * 	directives, extra semicolons after decl_ ..., asm keywords
 * 	[1993/06/07  19:07:55  jeffc]
 * 
 * Revision 1.1.2.2  1993/06/02  23:42:14  jeffc
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:15:17  jeffc]
 * 
 * Revision 1.1  1992/09/30  02:30:28  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.3  91/05/14  16:50:21  mrt
 * 	Correcting copyright
 * 
 * Revision 2.2  91/02/05  17:31:18  mrt
 * 	MACH_KERNEL: removed conditionals.
 * 	[88/12/19            dbg]
 * 
 * Revision 2.1  89/08/03  15:57:39  rwd
 * Created.
 * 
 * Revision 2.5  88/12/19  02:51:59  mwyoung
 * 	Added VM system tags.
 * 	[88/11/22            mwyoung]
 * 
 * Revision 2.4  88/08/24  02:55:54  mwyoung
 * 	Adjusted include file references.
 * 	[88/08/17  02:29:56  mwyoung]
 * 
 *
 *  9-Apr-88  Daniel Julin (dpj) at Carnegie-Mellon University
 *	Added flags for TCP and MACH_NP debugging.
 *
 *  6-Jan-88  Michael Young (mwyoung) at Carnegie-Mellon University
 *	Make the event structure smaller to make it easier to read from
 *	kernel debuggers.
 *
 * 16-Mar-87  Mike Accetta (mja) at Carnegie-Mellon University
 *	MACH:  made XPR_DEBUG definition conditional on MACH
 *	since the routines invoked under it won't link without MACH.
 *	[ V5.1(F7) ]
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
 * Include file for xpr circular buffer silent tracing.  
 *
 */
/*
 * If the kernel flag XPRDEBUG is set, the XPR macro is enabled.  The 
 * macro should be invoked something like the following:
 *	XPR(XPR_SYSCALLS, "syscall: %d, 0x%x\n", syscallno, arg1, 0,0,0);
 * which will expand into the following code:
 *	if (xprflags & XPR_SYSCALLS)
 *		xpr("syscall: %d, 0x%x\n", syscallno, arg1, 0,0,0);
 * Xpr will log the pointer to the printf string and up to 5 arguements,
 * along with a timestamp and cpuinfo (for multi-processor systems), into
 * a circular buffer.  The actual printf processing is delayed until after
 * the buffer has been collected.  It is assumed that the text/data segments
 * of the kernel can easily be reconstructed in a post-processor which
 * performs the printf processing.
 *
 * If the XPRDEBUG compilation switch is not set, the XPR macro expands 
 * to nothing.
 */

#ifndef	_KERN_XPR_H_
#define _KERN_XPR_H_

#ifdef	MACH_KERNEL
#include <xpr_debug.h>
#else	/* MACH_KERNEL */
#include <sys/features.h>
#endif	/* MACH_KERNEL */

#include <machine/xpr.h>

#if	XPR_DEBUG

#define XPR(flags, msg, arg1, arg2, arg3, arg4, arg5) 		\
MACRO_BEGIN							\
	if (xprflags & (flags)) {				\
		xpr((msg), (long)(arg1), (long)(arg2),		\
		    (long)(arg3), (long)(arg4), (long)(arg5));	\
	}							\
MACRO_END

extern int xprflags;

/*
 * flags for message types.
 */
#define XPR_TRAPS		(1 << 1)
#define XPR_SCHED		(1 << 2)
#define	XPR_LOCK		(1 << 3)
#define	XPR_SLOCK		(1 << 4)
#define XPR_PMAP		(1 << 6)
#define XPR_VM_MAP		(1 << 7)
#define	XPR_VM_OBJECT		(1 << 8)
#define	XPR_VM_OBJECT_CACHE	(1 << 9)
#define	XPR_VM_PAGE		(1 << 10)
#define	XPR_VM_PAGEOUT		(1 << 11)
#define	XPR_MEMORY_OBJECT	(1 << 12)
#define	XPR_VM_FAULT		(1 << 13)
#define	XPR_VM_OBJECT_REP	(1 << 14)
#define	XPR_DEFAULT_PAGER	(1 << 15)
#define	XPR_INODE_PAGER		(1 << 16)
#define	XPR_INODE_PAGER_DATA	(1 << 17)
#define	XPR_XMM			(1 << 18)

#else	/* XPR_DEBUG */
#define XPR(flags, msg, arg1, arg2, arg3, arg4, arg5)
#endif	/* XPR_DEBUG */

struct xprbuf {
	char 	*msg;
	long	arg1,arg2,arg3,arg4,arg5;
	int	timestamp;
	int	cpuinfo;
};

/* Bootstrap XPR facility */
extern void xprbootstrap(void);

/* Enable XPR facility */
extern void xprinit(void);

/* Log an XPR message */
extern void xpr(
	char	*msg,
	long	arg1,
	long	arg2,
	long	arg3,
	long	arg4,
	long	arg5);

#endif /* _KERN_XPR_H_ */
