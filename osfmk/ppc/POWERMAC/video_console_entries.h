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
 * @OSF_FREE_COPYRIGHT@
 * 
 */
/*
 * @APPLE_FREE_COPYRIGHT@
 */
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:43  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:26:05  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.10.1  1996/12/09  16:52:54  stephen
 * 	nmklinux_1.0b3_shared into pmk1.1
 * 	[1996/12/09  10:57:17  stephen]
 *
 * Revision 1.1.8.2  1996/06/14  08:40:48  emcmanus
 * 	Added prototype for vc_putchar().
 * 	[1996/05/07  09:35:43  emcmanus]
 * 
 * Revision 1.1.8.1  1996/06/07  16:04:24  stephen
 * 	Added video_scroll_up and video_scroll_down prototypes
 * 	[1996/06/07  15:43:59  stephen]
 * 
 * Revision 1.1.4.3  1996/05/03  17:26:10  stephen
 * 	Added APPLE_FREE_COPYRIGHT
 * 	[1996/05/03  17:20:12  stephen]
 * 
 * Revision 1.1.4.2  1996/04/27  15:23:46  emcmanus
 * 	Added vcputc() and vcgetc() prototypes so these functions can be
 * 	used in the console switch.
 * 	[1996/04/27  15:03:38  emcmanus]
 * 
 * Revision 1.1.4.1  1996/04/11  09:06:51  emcmanus
 * 	Copied from mainline.ppc.
 * 	[1996/04/10  17:01:38  emcmanus]
 * 
 * Revision 1.1.2.3  1996/03/14  12:58:27  stephen
 * 	no change
 * 	[1996/03/14  12:56:24  stephen]
 * 
 * Revision 1.1.2.2  1996/01/30  13:29:09  stephen
 * 	Added vcmmap
 * 	[1996/01/30  13:27:11  stephen]
 * 
 * Revision 1.1.2.1  1996/01/12  16:15:06  stephen
 * 	First revision
 * 	[1996/01/12  14:41:47  stephen]
 * 
 * $EndLog$
 */
#include <device/device_types.h>

extern int		vcputc(
				int			l,
				int			u,
				int			c);
extern int		vcgetc(
				int			l,
				int			u,
				boolean_t		wait,
				boolean_t		raw);

extern void video_scroll_up(unsigned long start,
			    unsigned long end,
			    unsigned long dest);

extern void video_scroll_down(unsigned long start,  /* HIGH addr */
			      unsigned long end,    /* LOW addr */
			      unsigned long dest);  /* HIGH addr */
