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
 *	Copyright (C) 1990,  NeXT, Inc.
 *
 *	File:	next/kern_machdep.c
 *	Author:	John Seamons
 *
 *	Machine-specific kernel routines.
 */

#include	<sys/types.h>
#include	<mach/machine.h>
#include	<kern/cpu_number.h>

extern int grade_binary(cpu_type_t exectype, cpu_subtype_t execsubtype);

/**********************************************************************
 * Routine:	grade_binary()
 *
 * Function:	Return a relative preference for exectypes and
 *		execsubtypes in fat executable files.  The higher the
 *		grade, the higher the preference.  A grade of 0 means
 *		not acceptable.
 **********************************************************************/
int
grade_binary(__unused cpu_type_t exectype, cpu_subtype_t execsubtype)
{
	int		cpusubtype = cpu_subtype();

	switch (cpusubtype) {
	    case CPU_SUBTYPE_386:
		switch (execsubtype) {
		    case CPU_SUBTYPE_386:
			return 1;
		    default:
			return 0;
		}

	    case CPU_SUBTYPE_486:
		switch (execsubtype) {
		    case CPU_SUBTYPE_386:
			return 1;

		    case CPU_SUBTYPE_486SX:
			return 2;

		    case CPU_SUBTYPE_486:
			return 3;

		    default:
			return 0;
		}

	    case CPU_SUBTYPE_486SX:
		switch (execsubtype) {
		    case CPU_SUBTYPE_386:
			return 1;

		    case CPU_SUBTYPE_486:
			return 2;

		    case CPU_SUBTYPE_486SX:
			return 3;

		    default:
			return 0;
		}

	    case CPU_SUBTYPE_586:
		switch (execsubtype) {
		    case CPU_SUBTYPE_386:
			return 1;

		    case CPU_SUBTYPE_486SX:
			return 2;

		    case CPU_SUBTYPE_486:
			return 3;

		    case CPU_SUBTYPE_586:
			return 4;

		    default:
			return 0;
		}

	    default:
		if (	CPU_SUBTYPE_INTEL_MODEL(execsubtype) ==
		    	CPU_SUBTYPE_INTEL_MODEL_ALL) {
		    if (	CPU_SUBTYPE_INTEL_FAMILY(cpusubtype) >=
				CPU_SUBTYPE_INTEL_FAMILY(execsubtype))
			return CPU_SUBTYPE_INTEL_FAMILY_MAX - 
			    CPU_SUBTYPE_INTEL_FAMILY(cpusubtype) -
			    CPU_SUBTYPE_INTEL_FAMILY(execsubtype);
		}
		else {
		    if (	cpusubtype == execsubtype)
			return CPU_SUBTYPE_INTEL_FAMILY_MAX + 1;
		}
		return 0;
	}
}

extern void md_prepare_for_shutdown(int, int, char *);

void
md_prepare_for_shutdown(
	__unused int paniced,
	__unused int howto,
	__unused char * command)
{
}
