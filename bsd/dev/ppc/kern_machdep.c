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
 *	Copyright (C) 1990, 1993  NeXT, Inc.
 *	Copyright (C) 1997  Apple Computer, Inc.
 *
 *	File:	next/kern_machdep.c
 *	Author:	John Seamons
 *
 *	Machine-specific kernel routines.
 */

#include	<sys/types.h>
#include	<sys/param.h>
#include	<mach/machine.h>
#include	<mach/boolean.h>
#include	<mach/vm_param.h>
#include	<kern/cpu_number.h>

int grade_binary(cpu_type_t exectype, cpu_subtype_t execsubtype);

/*
 * Routine: grade_binary()
 *
 * Function:
 *	Return a relative preference for exectypes and execsubtypes in fat
 *	executable files.  The higher the grade, the higher the preference.
 *	A grade of 0 means not acceptable.
 *
 * Note:	We really don't care about the real cpu_type() here,
 *		because machines can only have one type.
 */
int
grade_binary(cpu_type_t exectype, cpu_subtype_t execsubtype)
{
	int		cpusubtype = cpu_subtype();

	/*
	 * This code should match cpusubtype_findbestarch() in best_arch.c
	 * in the cctools project.  As of 2/16/98 this is what has been
	 * agreed upon for the PowerPC subtypes.  If an exact match is not
	 * found the subtype will be picked from the following order:
	 *		970(but only on 970), 7450, 7400, 750, ALL
	 * Note the 601 is NOT in the list above.  It is only picked via
	 * an exact match. For details see Radar 2213821.
	 */

	switch (cpusubtype) {
	case CPU_SUBTYPE_POWERPC_970:
		switch(exectype) {
		case CPU_TYPE_POWERPC64:	/* CPU_IS64BIT | CPU_POWERPC */
			switch(execsubtype) {
			/*
			 * Prefer 64 bit architecture specific binaries; note
			 * that this value does not mean the same thing here
			 * as it does below.
			 */
			case CPU_SUBTYPE_POWERPC_970:
				return 8;
			/* Prefer generic binaries */
			case CPU_SUBTYPE_POWERPC_ALL:
				return 7;
			default:
				return 0;
			}
			/* NOTREACHED */

		case CPU_TYPE_POWERPC:
			switch(execsubtype) {
			/*
			 * Prefer 32 bit binaries with 64 bit leaf functions;
			 * this is actually bogus use of the subtype to encode
			 * CPU feature bits.
			 */
			case CPU_SUBTYPE_POWERPC_970:
				return 6;
			case CPU_SUBTYPE_POWERPC_7450:
				return 4;
			case CPU_SUBTYPE_POWERPC_7400:
				return 3;
			case CPU_SUBTYPE_POWERPC_750:
				return 2;
			case CPU_SUBTYPE_POWERPC_ALL:
				return 1;
			default:
				return 0;
			}
			/* NOTREACHED */

		default:
			return 0;
		}
		/* NOTREACHED */

	case CPU_SUBTYPE_POWERPC_7450:
		switch(exectype) {
		case CPU_TYPE_POWERPC64:	/* CPU_IS64BIT | CPU_POWERPC */
			return 0;

		case CPU_TYPE_POWERPC:
			switch(execsubtype) {
			case CPU_SUBTYPE_POWERPC_7450:
				return 6;
			case CPU_SUBTYPE_POWERPC_7400:
				return 4;
			case CPU_SUBTYPE_POWERPC_750:
				return 3;
			case CPU_SUBTYPE_POWERPC_ALL:
				return 1;
			default:
				return 0;
			}
			/* NOTREACHED */

		default:
			return 0;
		}
		/* NOTREACHED */

	case CPU_SUBTYPE_POWERPC_7400:
		switch(exectype) {
		case CPU_TYPE_POWERPC64:	/* CPU_IS64BIT | CPU_POWERPC */
			return 0;

		case CPU_TYPE_POWERPC:
			switch(execsubtype) {
			case CPU_SUBTYPE_POWERPC_7400:
				return 6;
			case CPU_SUBTYPE_POWERPC_7450:
				return 4;
			case CPU_SUBTYPE_POWERPC_750:
				return 3;
			case CPU_SUBTYPE_POWERPC_ALL:
				return 1;
			default:
				return 0;
			}
			/* NOTREACHED */

		default:
			return 0;
		}
		/* NOTREACHED */

	case CPU_SUBTYPE_POWERPC_750:
		switch(exectype) {
		case CPU_TYPE_POWERPC64:	/* CPU_IS64BIT | CPU_POWERPC */
			return 0;

		case CPU_TYPE_POWERPC:
			switch(execsubtype) {
			case CPU_SUBTYPE_POWERPC_750:
				return 6;
#ifndef ADDRESS_RADAR_2678019
			/*
			 * Currently implemented because dropping this would
			 * turn the executable subtype into a "has Altivec"
			 * flag, which we do not want to permit.  It could
			 * also break working third party applications
			 * already in use in the field.
			 */
			case CPU_SUBTYPE_POWERPC_7400:
				return 4;
			case CPU_SUBTYPE_POWERPC_7450:
				return 3;
#endif	/* ADDRESS_RADAR_2678019 */
			case CPU_SUBTYPE_POWERPC_ALL:
				return 1;
			default:
				return 0;
			}
			/* NOTREACHED */

		default:
			return 0;
		}
		/* NOTREACHED */

	default:
		switch(exectype) {
		case CPU_TYPE_POWERPC64:	/* CPU_IS64BIT | CPU_POWERPC */
			return 0;

		case CPU_TYPE_POWERPC:
			/* Special case for PPC601 */
			if (cpusubtype == execsubtype)
				return 6;
			/*
			 * If we get here it is because it is a cpusubtype we
			 * don't support or a new cpusubtype that was added
			 * since this code was written.  Both will be
			 * considered unacceptable.
			 */
			return 0;
			/* NOTREACHED */

		default:
			return 0;
		}
		/* NOTREACHED */
	}
	/* NOTREACHED */
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

void
md_prepare_for_shutdown(int paniced, int howto, char * command);

extern void IOSystemShutdownNotification(void);

void
md_prepare_for_shutdown(__unused int paniced, __unused int howto,
			__unused char * command)
{

    /*
     * Temporary hack to notify the power management root domain
     * that the system will shut down.
     */
    IOSystemShutdownNotification();
}
