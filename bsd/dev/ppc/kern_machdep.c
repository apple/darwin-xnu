/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
 *	Copyright (C) 1990, 1993  NeXT, Inc.
 *	Copyright (C) 1997  Apple Computer, Inc.
 *
 *	File:	next/kern_machdep.c
 *	Author:	John Seamons
 *
 *	Machine-specific kernel routines.
 *
 * HISTORY
 *  8-Dec-91  Peter King (king) at NeXT
 *	Added grade_cpu_subtype().
 *	FIXME: Do we want to merge this with check_cpu_subtype()?
 *
 *  5-Mar-90  John Seamons (jks) at NeXT
 *	Created.
 */

#include	<sys/types.h>
#include	<sys/param.h>
#include	<mach/machine.h>
#include	<mach/boolean.h>
#include	<mach/vm_param.h>
#include	<kern/cpu_number.h>

int
check_cpu_subtype(cpu_subtype_t cpu_subtype)
{
	struct machine_slot *ms = &machine_slot[cpu_number()];

	if (cpu_subtype == ms->cpu_subtype)
		return (TRUE);

	switch (cpu_subtype) {
		case CPU_SUBTYPE_POWERPC_970:
				/* Do not allow a 970 binary to run on non-970 systems */
				if (ms->cpu_subtype != CPU_SUBTYPE_POWERPC_970)
				break;
		case CPU_SUBTYPE_POWERPC_7450:
		case CPU_SUBTYPE_POWERPC_7400:
		case CPU_SUBTYPE_POWERPC_750:
		case CPU_SUBTYPE_POWERPC_ALL:
			return (TRUE);
	}

	return (FALSE);
}

/*
 * Routine: grade_cpu_subtype()
 *
 * Function:
 *	Return a relative preference for cpu_subtypes in fat executable files.
 *	The higher the grade, the higher the preference.
 *	A grade of 0 means not acceptable.
 */

int
grade_cpu_subtype(cpu_subtype_t cpu_subtype)
{
	struct machine_slot *ms = &machine_slot[cpu_number()];

	/*
	 * This code should match cpusubtype_findbestarch() in best_arch.c in the
	 * cctools project.  As of 2/16/98 this is what has been agreed upon for
	 * the PowerPC subtypes.  If an exact match is not found the subtype will
	 * be picked from the following order:
	 *		970(but only on 970), 7450, 7400, 750, ALL
	 * Note the 601 is NOT in the list above.  It is only picked via an exact
	 * match. For details see Radar 2213821.
	 *
	 * To implement this function to follow what was agreed upon above, we use
	 * the fact there are currently 4 different subtypes.  Exact matches return
	 * the value 6, and the values 5 thru 1 are returned for the
	 * subtypes listed in the order above.
	 */
	if (ms->cpu_subtype == cpu_subtype)
		return 6;
	switch (cpu_subtype) {
		case CPU_SUBTYPE_POWERPC_970:
				/* Do not allow a 970 binary to run on non-970 systems */		
				if (ms->cpu_subtype != CPU_SUBTYPE_POWERPC_970)
					break;
			return 5;
		case CPU_SUBTYPE_POWERPC_7450:
			return 4;
		case CPU_SUBTYPE_POWERPC_7400:
			return 3;
		case CPU_SUBTYPE_POWERPC_750:
			return 2;
		case CPU_SUBTYPE_POWERPC_ALL:
			return 1;
	}
	/*
	 * If we get here it is because it is a cpusubtype we don't support
	 * or a new cpusubtype that was added since this code was written.  Both
	 * will be considered unacceptable.
	 */
	return 0;
}

boolean_t
kernacc(
    off_t 	start,
    size_t	len
)
{
	off_t base;
	off_t end;
    
	base = trunc_page_64(start);
	end = start + len;
	
	while (base < end) {
		if(kvtophys((vm_offset_t)base) == NULL)
			return(FALSE);
		base += page_size;
	}   

	return (TRUE);
}
