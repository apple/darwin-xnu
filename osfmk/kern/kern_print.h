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
 * Revision 1.1.1.1  1998/09/22 21:05:34  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:55  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.5.1  1995/01/06  19:47:13  devrcs
 * 	mk6 CR668 - 1.3b26 merge
 * 	new file for mk6
 * 	[1994/10/12  22:19:25  dwm]
 *
 * Revision 1.1.2.1  1993/11/22  20:14:46  jeffc
 * 	Modularized declarations of ddb print functions.
 * 	[1993/11/22  19:03:03  jeffc]
 * 
 * $EndLog$
 */

#ifndef	KERN_PRINT_H_
#define	KERN_PRINT_H_

#include <ddb/db_expr.h>

extern void 	db_show_all_slocks(void);


extern void	db_show_one_zone(
			        db_expr_t       addr,
			        int		have_addr,
			        db_expr_t	count,
			        char *          modif);

extern void	db_show_all_zones(
			        db_expr_t	addr,
			        int		have_addr,
			        db_expr_t	count,
			        char *		modif);

#endif	/* KERN_PRINT_H_ */
