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
 *	Copyright (C) 1990,  NeXT, Inc.
 *
 *	File:	next/kern_machdep.c
 *	Author:	John Seamons
 *
 *	Machine-specific kernel routines.
 *
 *  8-Dec-91  Peter King (king) at NeXT
 *	Added grade_cpu_subtype().
 *	FIXME: Do we want to merge this with check_cpu_subtype()?
 *
 *  5-Mar-90  John Seamons (jks) at NeXT
 *	Created.
 */

#include	<sys/types.h>
#include	<mach/machine.h>
#include	<kern/cpu_number.h>

check_cpu_subtype (cpu_subtype)
	cpu_subtype_t cpu_subtype;
{
	struct machine_slot *ms = &machine_slot[cpu_number()];
	
	switch (ms->cpu_subtype) {
	    case CPU_SUBTYPE_386:
		if (cpu_subtype == CPU_SUBTYPE_386)
		    return (TRUE);
		break;

	    case CPU_SUBTYPE_486:
	    case CPU_SUBTYPE_486SX:
		if (	cpu_subtype == CPU_SUBTYPE_486		||
			cpu_subtype == CPU_SUBTYPE_486SX	||
			cpu_subtype == CPU_SUBTYPE_386		)
		    return (TRUE);
		break;

	    case CPU_SUBTYPE_586:
		if (	cpu_subtype == CPU_SUBTYPE_586		||
			cpu_subtype == CPU_SUBTYPE_486		||
			cpu_subtype == CPU_SUBTYPE_486SX	||
			cpu_subtype == CPU_SUBTYPE_386		)
		    return (TRUE);
		break;

	    default:
		if (	CPU_SUBTYPE_INTEL_MODEL(cpu_subtype) ==
			CPU_SUBTYPE_INTEL_MODEL_ALL) {
		    if (	CPU_SUBTYPE_INTEL_FAMILY(ms->cpu_subtype) >=
				CPU_SUBTYPE_INTEL_FAMILY(cpu_subtype))
			return (TRUE);
		}
		else {
		    if (	ms->cpu_subtype == cpu_subtype)
			return (TRUE);
		}
		break;
	}

	return (FALSE);
}

/**********************************************************************
 * Routine:	grade_cpu_subtype()
 *
 * Function:	Return a relative preference for cpu_subtypes in fat
 *		executable files.  The higher the grade, the higher the
 *		preference.  A grade of 0 means not acceptable.
 **********************************************************************/
grade_cpu_subtype (cpu_subtype)
	cpu_subtype_t		cpu_subtype;
{
	struct machine_slot	*ms = &machine_slot[cpu_number()];

	switch (ms->cpu_subtype) {
	    case CPU_SUBTYPE_386:
		switch (cpu_subtype) {
		    case CPU_SUBTYPE_386:
			return 1;
		    default:
			return 0;
		}

	    case CPU_SUBTYPE_486:
		switch (cpu_subtype) {
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
		switch (cpu_subtype) {
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
		switch (cpu_subtype) {
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
		if (	CPU_SUBTYPE_INTEL_MODEL(cpu_subtype) ==
		    	CPU_SUBTYPE_INTEL_MODEL_ALL) {
		    if (	CPU_SUBTYPE_INTEL_FAMILY(ms->cpu_subtype) >=
				CPU_SUBTYPE_INTEL_FAMILY(cpu_subtype))
			return CPU_SUBTYPE_INTEL_FAMILY_MAX - 
			    CPU_SUBTYPE_INTEL_FAMILY(ms->cpu_subtype) -
			    CPU_SUBTYPE_INTEL_FAMILY(cpu_subtype);
		}
		else {
		    if (	ms->cpu_subtype == cpu_subtype)
			return CPU_SUBTYPE_INTEL_FAMILY_MAX + 1;
		}
		return 0;
	}
}
