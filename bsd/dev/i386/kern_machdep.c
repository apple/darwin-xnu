/*
 * Copyright (c) 2000-2013 Apple Inc. All rights reserved.
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
 *	Copyright (C) 1990,  NeXT, Inc.
 *
 *	File:	next/kern_machdep.c
 *	Author:	John Seamons
 *
 *	Machine-specific kernel routines.
 */

#include        <sys/types.h>
#include        <mach/machine.h>
#include        <kern/cpu_number.h>
#include        <machine/exec.h>
#include        <machine/machine_routines.h>

#if __x86_64__
extern int bootarg_no32exec;    /* bsd_init.c */
#endif

/**********************************************************************
* Routine:	grade_binary()
*
* Function:	Say OK to CPU types that we can actually execute on the given
*		system. 64-bit binaries have the highest preference, followed
*		by 32-bit binaries. 0 means unsupported.
**********************************************************************/
int
grade_binary(cpu_type_t exectype, cpu_subtype_t execsubtype, cpu_subtype_t execfeatures __unused, bool allow_simulator_binary __unused)
{
	cpu_subtype_t hostsubtype = cpu_subtype();

	switch (exectype) {
	case CPU_TYPE_X86_64:           /* native 64-bit */
		switch (hostsubtype) {
		case CPU_SUBTYPE_X86_64_H:      /* x86_64h can execute anything */
			switch (execsubtype) {
			case CPU_SUBTYPE_X86_64_H:
				return 3;
			case CPU_SUBTYPE_X86_64_ALL:
				return 2;
			}
			break;
		case CPU_SUBTYPE_X86_ARCH1:     /* generic systems can only execute ALL subtype */
			switch (execsubtype) {
			case CPU_SUBTYPE_X86_64_ALL:
				return 2;
			}
			break;
		}
		break;
	case CPU_TYPE_X86:              /* native */
#if __x86_64__
		if (bootarg_no32exec && !allow_simulator_binary) {
			return 0;
		}
#endif
		return 1;
	}

	return 0;
}
