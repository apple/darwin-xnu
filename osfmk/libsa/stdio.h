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
 * 
 */
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:51  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:35  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.2.3  1996/10/04  11:36:05  emcmanus
 * 	Added fprintf_stderr() prototype, for use by Mach libraries and like
 * 	that might end up being linked with either libc or libsa_mach.
 * 	[1996/10/04  11:31:53  emcmanus]
 *
 * Revision 1.1.2.2  1996/10/03  17:53:45  emcmanus
 * 	Define NULL.  This is currently also (questionably) defined in stdlib.h,
 * 	string.h, and types.h.
 * 	[1996/10/03  16:17:55  emcmanus]
 * 
 * Revision 1.1.2.1  1996/09/17  16:56:18  bruel
 * 	created from standalone mach servers.
 * 	[96/09/17            bruel]
 * 
 * $EndLog$
 */

#ifndef _MACH_STDIO_H_
#define _MACH_STDIO_H_

#include <stdarg.h>

#ifndef NULL
#define NULL ((void *) 0)
#endif

extern int	sprintf(char *, const char *, ...); 
extern int	printf(const char *, ...); 
extern int	vprintf(const char *, va_list );
extern int	vsprintf(char *, const char *, va_list );

extern int 	getchar(void);

extern int	fprintf_stderr(const char *, ...);

#endif /* _MACH_STDIO_H_ */
