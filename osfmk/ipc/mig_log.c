/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:29  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:26:16  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.2.6.1  1994/09/23  02:14:23  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:31:33  ezf]
 *
 * Revision 1.2.2.4  1993/08/03  18:29:18  gm
 * 	CR9596: Change KERNEL to MACH_KERNEL.
 * 	[1993/08/02  16:11:07  gm]
 * 
 * Revision 1.2.2.3  1993/07/22  16:18:15  rod
 * 	Add ANSI prototypes.  CR #9523.
 * 	[1993/07/22  13:34:22  rod]
 * 
 * Revision 1.2.2.2  1993/06/09  02:33:38  gm
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:11:41  jeffc]
 * 
 * Revision 1.2  1993/04/19  16:23:26  devrcs
 * 	Untyped ipc merge:
 * 	Support for logging and tracing within the MIG stubs
 * 	[1993/02/24  14:49:29  travos]
 * 
 * $EndLog$
 */

#ifdef MACH_KERNEL
#include <mig_debug.h>
#endif

#include <mach/message.h>
#include <mach/mig_log.h>

int mig_tracing, mig_errors, mig_full_tracing;

/*
 * Tracing facilities for MIG generated stubs.
 *
 * At the moment, there is only a printf, which is
 * activated through the runtime switch:
 * 	mig_tracing to call MigEventTracer
 * 	mig_errors to call MigEventErrors
 * For this to work, MIG has to run with the -L option, 
 * and the mig_debug flags has to be selected
 *
 * In the future, it will be possible to collect infos
 * on the use of MACH IPC with an application similar
 * to netstat.
 * 
 * A new option will be generated accordingly to the
 * kernel configuration rules, e.g
 *	#include <mig_log.h>
 */ 

void
MigEventTracer(
	mig_who_t		who,
	mig_which_event_t	what,
	mach_msg_id_t		msgh_id,
	unsigned int		size,
	unsigned int		kpd,
	unsigned int		retcode,
	unsigned int		ports,
	unsigned int		oolports,
	unsigned int		ool,
	char			*file,
	unsigned int		line)
{
    printf("%d|%d|%d", who, what, msgh_id); 
    if (mig_full_tracing)
	printf(" -- sz%d|kpd%d|ret(0x%x)|p%d|o%d|op%d|%s, %d", 
	    size, kpd, retcode, ports, oolports, ool, file, line); 
    printf("\n");
}

void
MigEventErrors(
	mig_who_t		who,
	mig_which_error_t	what,
	void			*par,
	char			*file,
	unsigned int		line)
{
    if (what == MACH_MSG_ERROR_UNKNOWN_ID)
	printf("%d|%d|%d -- %s %d\n", who, what, *(int *)par, file, line); 
    else
	printf("%d|%d|%s -- %s %d\n", who, what, (char *)par, file, line); 
}
