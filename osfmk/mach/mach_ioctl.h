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
 * Revision 1.1.1.1  1998/09/22 21:05:30  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:45  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.4.2  1997/02/07  12:12:35  barbou
 * 	Fixed the defines (some were missing the "MACH_" prefixes).
 * 	[1997/02/07  12:06:38  barbou]
 *
 * Revision 1.1.4.1  1996/11/29  16:59:20  stephen
 * 	nmklinux_1.0b3_shared into pmk1.1
 * 	     Contents of sys/ioctl.h. Prefixed the definitions with "MACH" to avoid
 * 	     conflicts with UNIX servers.
 * 	     [96/09/18            barbou]
 * 	[1996/11/29  16:33:15  stephen]
 * 
 * $EndLog$
 */
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
CS.CMU.EDU
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
 * Format definitions for 'ioctl' commands in device definitions.
 *
 * From BSD4.4.
 */

#ifndef _MACH_MACH_IOCTL_H_
#define _MACH_MACH_IOCTL_H_

/*
 * Ioctl's have the command encoded in the lower word, and the size of
 * any in or out parameters in the upper word.  The high 3 bits of the
 * upper word are used to encode the in/out status of the parameter.
 */
#define MACH_IOCPARM_MASK       0x1fff  /* parameter length, at most 13 bits */
#define MACH_IOC_VOID   0x20000000      /* no parameters */
#define MACH_IOC_OUT            0x40000000      /* copy out parameters */
#define MACH_IOC_IN             0x80000000      /* copy in parameters */
#define MACH_IOC_INOUT  (MACH_IOC_IN|MACH_IOC_OUT)

#define _MACH_IOC(inout,group,num,len) \
        (inout | ((len & MACH_IOCPARM_MASK) << 16) | ((group) << 8) | (num))
#define _MACH_IO(g,n)   	_MACH_IOC(MACH_IOC_VOID,  (g), (n), 0)
#define _MACH_IOR(g,n,t)        _MACH_IOC(MACH_IOC_OUT,   (g), (n), sizeof(t))
#define _MACH_IOW(g,n,t)        _MACH_IOC(MACH_IOC_IN,    (g), (n), sizeof(t))
#define _MACH_IOWR(g,n,t)       _MACH_IOC(MACH_IOC_INOUT, (g), (n), sizeof(t))

#ifdef  MACH_KERNEL
     /*
      * to avoid changing the references in the micro-kernel sources...
      */
#define IOCPARM_MASK    MACH_IOCPARM_MASK
#define IOC_VOID        MACH_IOC_VOID
#define IOC_OUT         MACH_IOC_OUT
#define IOC_IN          MACH_IOC_IN
#define IOC_INOUT       MACH_IOC_INOUT
#define _IOC            _MACH_IOC
#define _IO             _MACH_IO
#define _IOR            _MACH_IOR
#define _IOW            _MACH_IOW
#define _IOWR           _MACH_IOWR
#endif  /* MACH_KERNEL */

#endif   /* _MACH_MACH_IOCTL_H_ */
