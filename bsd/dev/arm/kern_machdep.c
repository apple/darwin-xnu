/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
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
#include        <libkern/libkern.h>
#include        <machine/exec.h>
#include        <pexpert/arm64/board_config.h>

#if __arm64__
static cpu_subtype_t cpu_subtype32(void);
#endif /* __arm64__ */

#if __arm64__
/*
 * When an arm64 CPU is executing an arm32 binary, we need to map from the
 * host's 64-bit subtype to the appropriate 32-bit subtype.
 */
static cpu_subtype_t
cpu_subtype32()
{
	switch (cpu_subtype()) {
	case CPU_SUBTYPE_ARM64_V8:
		return CPU_SUBTYPE_ARM_V8;
	default:
		return 0;
	}
}

#endif /* __arm64__ */

/**********************************************************************
* Routine:	grade_binary()
*
* Function:	Return a relative preference for exectypes and
*		execsubtypes in fat executable files.  The higher the
*		grade, the higher the preference.  A grade of 0 means
*		not acceptable.
**********************************************************************/
int
grade_binary(cpu_type_t exectype, cpu_subtype_t execsubtype, cpu_subtype_t execfeatures __unused, bool allow_simulator_binary __unused)
{
#if __arm64__
	cpu_subtype_t hostsubtype =
	    (exectype & CPU_ARCH_ABI64) ? cpu_subtype() : cpu_subtype32();
#else
	cpu_subtype_t hostsubtype = cpu_subtype();
#endif /* __arm64__ */

	switch (exectype) {
#if __arm64__
	case CPU_TYPE_ARM64:
		switch (hostsubtype) {
		case CPU_SUBTYPE_ARM64_V8:
			switch (execsubtype) {
			case CPU_SUBTYPE_ARM64_V8:
				return 10;
			case CPU_SUBTYPE_ARM64_ALL:
				return 9;
			}
			break;

		} /* switch (hostsubtype) */
		break;

#else /* __arm64__ */

	case CPU_TYPE_ARM:
		switch (hostsubtype) {
		/*
		 * For 32-bit ARMv8, try the ARMv8 slice before falling back to Swift.
		 */
		case CPU_SUBTYPE_ARM_V8:
			switch (execsubtype) {
			case CPU_SUBTYPE_ARM_V8:
				return 7;
			}
			goto v7s;

			/*
			 * For Swift and later, we prefer to run a swift slice, but fall back
			 * to v7 as Cortex A9 errata should not apply
			 */
v7s:
		case CPU_SUBTYPE_ARM_V7S:
			switch (execsubtype) {
			case CPU_SUBTYPE_ARM_V7S:
				return 6;
			}
			goto v7;

		/*
		 * For Cortex A7, accept v7k only due to differing ABI
		 */
		case CPU_SUBTYPE_ARM_V7K:
			switch (execsubtype) {
			case CPU_SUBTYPE_ARM_V7K:
				return 6;
			}
			break;

		/*
		 * For Cortex A9, we prefer the A9 slice, but will run v7 albeit
		 * under the risk of hitting the NEON load/store errata
		 */
		case CPU_SUBTYPE_ARM_V7F:
			switch (execsubtype) {
			case CPU_SUBTYPE_ARM_V7F:
				return 6;
			}
			goto v7;

v7:
		case CPU_SUBTYPE_ARM_V7:
			switch (execsubtype) {
			case CPU_SUBTYPE_ARM_V7:
				return 5;
			}
		// fall through...

		case CPU_SUBTYPE_ARM_V6:
			switch (execsubtype) {
			case CPU_SUBTYPE_ARM_V6:
				return 4;
			}
		// fall through...

		case CPU_SUBTYPE_ARM_V5TEJ:
			switch (execsubtype) {
			case CPU_SUBTYPE_ARM_V5TEJ:
				return 3;
			}
		// fall through

		case CPU_SUBTYPE_ARM_V4T:
			switch (execsubtype) {
			case CPU_SUBTYPE_ARM_V4T:
				return 2;
			case CPU_SUBTYPE_ARM_ALL:
				return 1;
			}
			break;

		case CPU_SUBTYPE_ARM_XSCALE:
			switch (execsubtype) {
			case CPU_SUBTYPE_ARM_XSCALE:
				return 4;
			case CPU_SUBTYPE_ARM_V5TEJ:
				return 3;
			case CPU_SUBTYPE_ARM_V4T:
				return 2;
			case CPU_SUBTYPE_ARM_ALL:
				return 1;
			}
			break;
		}
#endif /* __arm64__ */
	}

	return 0;
}
