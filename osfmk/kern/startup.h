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
 * Revision 1.1.1.1  1998/09/22 21:05:32  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:56  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.7.1  1994/09/23  02:26:54  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:36:18  ezf]
 *
 * Revision 1.1.2.3  1993/08/16  18:08:47  bernard
 * 	Clean up MP configuration warnings - CR#9523
 * 	[1993/08/13  15:29:52  bernard]
 * 
 * Revision 1.1.2.2  1993/08/11  18:04:28  bernard
 * 	Fixed to use machine include file ANSI prototypes - CR#9523
 * 	[1993/08/11  16:28:27  bernard]
 * 
 * 	Second pass fixes for ANSI prototypes - CR#9523
 * 	[1993/08/11  14:20:54  bernard]
 * 
 * $EndLog$
 */

#ifndef	_KERN_STARTUP_H_
#define	_KERN_STARTUP_H_

#include <cpus.h>

/*
 * Kernel and machine startup declarations
 */

/* Initialize kernel */
extern void	setup_main(void);

/* Initialize machine dependent stuff */
extern void	machine_init(void);

#if	NCPUS > 1

extern void	slave_main(void);

/*
 * The following must be implemented in machine dependent code.
 */

/* Slave cpu initialization */
extern void	slave_machine_init(void);

/* Start slave processors */
extern void	start_other_cpus(void);

#endif	/* NCPUS > 1 */
#endif	/* _KERN_STARTUP_H_ */
