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
 * Revision 1.1.1.1  1998/09/22 21:05:30  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:45  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.5.1  1995/01/06  19:50:20  devrcs
 * 	mk6 CR668 - 1.3b26 merge
 * 	new file for mk6
 * 	[1994/10/12  22:25:10  dwm]
 *
 * Revision 1.1.2.2  1993/10/20  19:09:29  gm
 * 	CR9913: Replacement for <sys/reboot.h> flags used in host_reboot()
 * 	calls.
 * 	[1993/10/13  17:21:14  gm]
 * 
 * $EndLog$
 */

#define HOST_REBOOT_HALT	0x8
#define	HOST_REBOOT_DEBUGGER	0x1000
