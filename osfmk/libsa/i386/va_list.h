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
 * 
 */
/*
 * HISTORY
 * 
 * Revision 1.2  1998/09/30 21:21:00  wsanchez
 * Merged in IntelMerge1 (mburg: Intel support)
 *
 * Revision 1.1.2.1  1998/09/30 18:19:50  mburg
 * Changes for Intel port
 *
 * Revision 1.1.1.1  1998/03/07 02:25:36  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.2.1  1996/09/17  16:56:30  bruel
 * 	created from standalone mach servers
 * 	[1996/09/17  16:18:09  bruel]
 *
 * $EndLog$
 */

#ifndef _MACHINE_VALIST_H
#define _MACHINE_VALIST_H

/*
 * Four possible situations:
 * 	- We are being included by {var,std}args.h (or anyone) before stdio.h.
 * 	  define real type.
 *
 * 	- We are being included by stdio.h before {var,std}args.h.
 * 	  define hidden type for prototypes in stdio, don't pollute namespace.
 * 
 * 	- We are being included by {var,std}args.h after stdio.h.
 * 	  define real type to match hidden type.  no longer use hidden type.
 * 
 * 	- We are being included again after defining the real va_list.
 * 	  do nothing.
 * 
 */

#if	!defined(_HIDDEN_VA_LIST) && !defined(_VA_LIST)
#define _VA_LIST
typedef	char *va_list;

#elif	defined(_HIDDEN_VA_LIST) && !defined(_VA_LIST)
#define _VA_LIST
typedef char *__va_list;

#elif	defined(_HIDDEN_VA_LIST) && defined(_VA_LIST)
#undef _HIDDEN_VA_LIST
typedef __va_list va_list;

#endif

#endif /* _MACHINE_VALIST_H */

