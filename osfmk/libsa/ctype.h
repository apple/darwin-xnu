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
 * Revision 1.1.1.1  1998/09/22 21:05:51  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:35  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.2.1  1996/09/17  16:56:20  bruel
 * 	created from standalone mach servers.
 * 	[96/09/17            bruel]
 *
 * $EndLog$
 */

#ifndef _CTYPE_H_
#define _CTYPE_H_

extern int	isalpha(int);
extern int	isalnum(int);
extern int	iscntrl(int);
extern int	isdigit(int);
extern int	isgraph(int);
extern int	islower(int);
extern int	isprint(int);
extern int	ispunct(int);
extern int	isspace(int);
extern int	isupper(int);
extern int	isxdigit(int);
extern int	toupper(int);
extern int	tolower(int);

extern int	isascii(int);
extern int	toascii(int);

extern int	(_toupper)(int);
extern int	(_tolower)(int);

#endif /* _CTYPE_H_ */
