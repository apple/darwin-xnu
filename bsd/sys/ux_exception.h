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
 * Mach Operating System
 * Copyright (c) 1989 Carnegie-Mellon University
 * Copyright (c) 1988 Carnegie-Mellon University
 * Copyright (c) 1987 Carnegie-Mellon University
 * All rights reserved.  The CMU software License Agreement specifies
 * the terms and conditions for use and redistribution.
 */
/*
 * HISTORY
 *
 * Revision 1.2.32.1  1998/11/11 21:54:39  aramesh
 * Atlas merge
 *
 * Revision 1.1.1.1  1997/09/30 02:42:22  wsanchez
 * Import of kernel from umeshv/kernel
 *
 * Revision 2.7  89/10/03  19:23:14  rpd
 * 	Change from NeXT:  added EXC_UNIX_ABORT.
 * 	[89/08/20  23:16:13  rpd]
 * 
 * Revision 2.6  89/03/09  19:35:07  rpd
 * 	More cleanup.
 * 
 * Revision 2.5  89/02/25  15:01:07  gm0w
 * 	Changes for cleanup.
 * 
 * Revision 2.4  89/02/07  01:01:10  mwyoung
 * Relocated from uxkern/ux_exception.h
 * 
 * Revision 2.3  89/01/15  16:35:44  rpd
 * 	Use decl_simple_lock_data.
 * 	[89/01/15  15:19:58  rpd]
 * 
 * Revision 2.2  88/08/24  02:52:12  mwyoung
 * 	Adjusted include file references.
 * 	[88/08/17  02:27:27  mwyoung]
 *
 * 29-Sep-87  David Black (dlb) at Carnegie-Mellon University
 *	Created.
 *
 */

/*
 *	Codes for Unix software exceptions under EXC_SOFTWARE.
 */

#ifndef	_SYS_UX_EXCEPTION_H_
#define _SYS_UX_EXCEPTION_H_

#define EXC_UNIX_BAD_SYSCALL	0x10000		/* SIGSYS */

#define EXC_UNIX_BAD_PIPE	0x10001		/* SIGPIPE */

#define EXC_UNIX_ABORT		0x10002		/* SIGABRT */

#ifdef	KERNEL
/*
 *	Kernel data structures for Unix exception handler.
 */

#include <mach/port.h>

extern mach_port_name_t			ux_exception_port;

#endif /* KERNEL */

#endif	/* _SYS_UX_EXCEPTION_H_ */
