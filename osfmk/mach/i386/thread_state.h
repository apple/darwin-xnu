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
 * Revision 1.1.1.1  1998/09/22 21:05:31  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:47  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.6.3  1995/01/10  05:16:26  devrcs
 * 	mk6 CR801 - copyright marker not FREE_
 * 	[1994/12/01  19:25:21  dwm]
 *
 * Revision 1.1.6.1  1994/08/07  20:48:54  bolinger
 * 	Merge up to colo_b7.
 * 	[1994/08/01  21:01:26  bolinger]
 * 
 * Revision 1.1.4.1  1994/06/25  03:47:07  dwm
 * 	mk6 CR98 - new file to hold MD THREAD_STATE_MAX
 * 	[1994/06/24  21:54:48  dwm]
 * 
 * $EndLog$
 */
#ifndef _MACH_I386_THREAD_STATE_H_
#define _MACH_I386_THREAD_STATE_H_

#define I386_THREAD_STATE_MAX	144

#if defined (__i386__)
#define THREAD_STATE_MAX	I386_THREAD_STATE_MAX
#endif

#endif	/* _MACH_I386_THREAD_STATE_H_ */
