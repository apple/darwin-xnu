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
 * Revision 1.1.1.1  1998/09/22 21:05:51  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:35  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.4.1  1997/02/21  15:43:21  barbou
 * 	Removed "size_t" definition, include "types.h" instead.
 * 	[1997/02/21  15:36:54  barbou]
 *
 * Revision 1.1.2.4  1996/10/10  14:13:33  emcmanus
 * 	Added memmove() prototype.
 * 	[1996/10/10  14:11:51  emcmanus]
 * 
 * Revision 1.1.2.3  1996/10/07  07:20:26  paire
 * 	Added strncat() prototype, since it is defined in libsa_mach.
 * 	[96/10/07            paire]
 * 
 * Revision 1.1.2.2  1996/10/04  11:36:07  emcmanus
 * 	Added strspn() prototype, since it is defined in libsa_mach.
 * 	[1996/10/04  11:31:57  emcmanus]
 * 
 * Revision 1.1.2.1  1996/09/17  16:56:15  bruel
 * 	created for standalone mach servers.
 * 	[96/09/17            bruel]
 * 
 * $EndLog$
 */

#ifndef	_MACH_STRING_H_
#define	_MACH_STRING_H_	1

#ifdef MACH_KERNEL_PRIVATE
#include <types.h>
#else
#include <sys/types.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef	NULL
#define NULL	0
#endif

extern void	*memcpy(void *, const void *, size_t);
extern void	*memmove(void *, const void *, size_t);
extern void	*memset(void *, int, size_t);

extern size_t	strlen(const char *);
extern char	*strcpy(char *, const char *);
extern char	*strncpy(char *, const char *, size_t);
extern char	*strcat(char *, const char *);
extern char	*strncat(char *, const char *, size_t);
extern int	strcmp(const char *, const char *);
extern int	strncmp(const char *,const char *, size_t);
extern char	*strchr(const char *s, int c);
extern size_t	strspn(const char *, const char *);

#ifdef __cplusplus
}
#endif

#endif	/* _MACH_STRING_H_ */
