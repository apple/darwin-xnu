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
 * Revision 1.1.1.1  1998/09/22 21:05:36  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:37  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.7.1  1994/09/23  01:54:13  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:22:49  ezf]
 *
 * Revision 1.1.2.3  1993/09/17  21:35:16  robert
 * 	change marker to OSF_FREE_COPYRIGHT
 * 	[1993/09/17  21:28:26  robert]
 * 
 * Revision 1.1.2.2  1993/08/09  19:39:51  dswartz
 * 	Add ANSI prototypes - CR#9523
 * 	[1993/08/06  17:44:52  dswartz]
 * 
 * $EndLog$
 */

extern void		hardclock(struct i386_interrupt_state	*regs);
extern void		delayed_clock(void);
