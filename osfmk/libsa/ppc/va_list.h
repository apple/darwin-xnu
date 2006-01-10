/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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
#if !defined(APPLE) && !defined(NeXT)
/*
 * @OSF_COPYRIGHT@
 */
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:51  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:36  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.2.1  1996/12/09  16:59:07  stephen
 * 	nmklinux_1.0b3_shared into pmk1.1
 * 	[1996/12/09  11:18:59  stephen]
 *
 * Revision 1.1.4.1  1996/04/11  14:37:05  emcmanus
 * 	Copied from mainline.ppc.
 * 	[1996/04/11  14:36:22  emcmanus]
 * 
 * Revision 1.1.2.1  1995/12/28  16:37:24  barbou
 * 	Self-Contained Mach Distribution:
 * 	created.
 * 	[95/12/28            barbou]
 * 
 * $EndLog$
 */

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

/* Define __gnuc_va_list. */

#ifndef __GNUC_VA_LIST
/*
 * If this is for internal libc use, don't define
 * anything but __gnuc_va_list.
 */
#define __GNUC_VA_LIST
typedef struct {
  char gpr;			/* index into the array of 8 GPRs stored in the
				   register save area gpr=0 corresponds to r3,
				   gpr=1 to r4, etc. */
  char fpr;			/* index into the array of 8 FPRs stored in the
				   register save area fpr=0 corresponds to f1,
				   fpr=1 to f2, etc. */
  char *overflow_arg_area;	/* location on stack that holds the next
				   overflow argument */
  char *reg_save_area;		/* where r3:r10 and f1:f8, if saved are stored */
} __gnuc_va_list[1];

#endif /* not __GNUC_VA_LIST */

#define _VA_LIST
typedef struct {
  char gpr;			/* index into the array of 8 GPRs stored in the
				   register save area gpr=0 corresponds to r3,
				   gpr=1 to r4, etc. */
  char fpr;			/* index into the array of 8 FPRs stored in the
				   register save area fpr=0 corresponds to f1,
				   fpr=1 to f2, etc. */
  char *overflow_arg_area;	/* location on stack that holds the next
				   overflow argument */
  char *reg_save_area;		/* where r3:r10 and f1:f8, if saved are stored */
} va_list[1];

#elif	defined(_HIDDEN_VA_LIST) && !defined(_VA_LIST)

#define _VA_LIST
typedef struct {
  char gpr;			/* index into the array of 8 GPRs stored in the
				   register save area gpr=0 corresponds to r3,
				   gpr=1 to r4, etc. */
  char fpr;			/* index into the array of 8 FPRs stored in the
				   register save area fpr=0 corresponds to f1,
				   fpr=1 to f2, etc. */
  char *overflow_arg_area;	/* location on stack that holds the next
				   overflow argument */
  char *reg_save_area;		/* where r3:r10 and f1:f8, if saved are stored */
} __va_list[1];

#elif	defined(_HIDDEN_VA_LIST) && defined(_VA_LIST)

#undef _HIDDEN_VA_LIST
typedef __va_list va_list;

#endif

#endif
