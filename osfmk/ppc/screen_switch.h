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
/*
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
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
 *	File: screen_switch.h
 * 	Author: Alessandro Forin, Carnegie Mellon University
 *	Date:	10/90
 *
 *	Definitions of things that must be tailored to
 *	specific hardware boards for the Generic Screen Driver.
 */

#ifndef	SCREEN_SWITCH_H
#define	SCREEN_SWITCH_H	1

#include <mach/boolean.h>

/*
 *	List of probe routines, scanned at cold-boot time
 *	to see which, if any, graphic display is available.
 *	This is done before autoconf, so that printing on
 *	the console works early on.  The alloc routine is
 *	called only on the first device that answers.
 *	Ditto for the setup routine, called later on.
 */
struct screen_probe_vector {
	int		(*probe)(void);
	unsigned int	(*alloc)(void);
	int		(*setup)(int, user_info_t);
};

/*
 *	Low-level operations on the graphic device, used
 *	by the otherwise device-independent interface code
 */

/* Forward declaration of screen_softc_t */
typedef struct screen_softc *screen_softc_t;

struct screen_switch {
	int	(*graphic_open)(void);			/* when X11 opens */
	int	(*graphic_close)(screen_softc_t);	/* .. or closes */
	int	(*set_status)(screen_softc_t,
			      dev_flavor_t,
			      dev_status_t,
			      natural_t);		/* dev-specific ops */
	int	(*get_status)(screen_softc_t,
			      dev_flavor_t,
			      dev_status_t,
			      natural_t*);		/* dev-specific ops */
	int	(*char_paint)(screen_softc_t,
			      int,
			      int,
			      int);			/* blitc */
	int	(*pos_cursor)(void*,
			      int,
			      int);			/* cursor positioning*/
	int	(*insert_line)(screen_softc_t,
			       short);			/* ..and scroll down */
	int	(*remove_line)(screen_softc_t,
			       short);			/* ..and scroll up */
	int	(*clear_bitmap)(screen_softc_t);	/* blank screen */
	int	(*video_on)(void*,
			    user_info_t*);		/* screen saver */
	int	(*video_off)(void*,
			     user_info_t*);
	int	(*intr_enable)(void*,
			       boolean_t);
	int	(*map_page)(screen_softc_t,
			    vm_offset_t,
			    int);			/* user-space mapping*/
};

/*
 *	Each graphic device needs page-aligned memory
 *	to be mapped in user space later (for events
 *	and such).  Size and content of this memory
 *	is unfortunately device-dependent, even if
 *	it did not need to (puns).
 */
extern char  *screen_data;

extern struct screen_probe_vector screen_probe_vector[];

extern int screen_noop(void), screen_find(void);

#endif	/* SCREEN_SWITCH_H */
