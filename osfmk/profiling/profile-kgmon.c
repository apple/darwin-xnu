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
 * Revision 1.1.1.1  1998/09/22 21:05:49  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:26:08  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.5.1  1995/01/06  19:54:04  devrcs
 * 	mk6 CR668 - 1.3b26 merge
 * 	new file for mk6
 * 	[1994/10/12  22:25:34  dwm]
 *
 * Revision 1.1.2.1  1994/04/08  17:52:05  meissner
 * 	Add callback function to _profile_kgmon.
 * 	[1994/02/16  22:38:31  meissner]
 * 
 * 	_profile_kgmon now returns pointer to area, doesn't do move itself.
 * 	[1994/02/11  16:52:17  meissner]
 * 
 * 	Move all printfs into if (pv->debug) { ... } blocks.
 * 	Add debug printfs protected by if (pv->debug) for all error conditions.
 * 	Add code to reset profiling information.
 * 	Add code to get/set debug flag.
 * 	Expand copyright.
 * 	[1994/02/07  12:41:14  meissner]
 * 
 * 	Add support to copy arbitrary regions.
 * 	Delete several of the KGMON_GET commands, now that arb. regions are supported.
 * 	Explicitly call _profile_update_stats before dumping vars or stats.
 * 	[1994/02/03  00:59:05  meissner]
 * 
 * 	Combine _profile_{vars,stats,md}; Allow more than one _profile_vars.
 * 	[1994/02/01  12:04:09  meissner]
 * 
 * 	CR 10198 - Initial version.
 * 	[1994/01/28  23:33:37  meissner]
 * 
 * $EndLog$
 */

#include <profiling/profile-internal.h>

#ifdef MACH_KERNEL
#include <profiling/machine/profile-md.h>
#endif

#ifndef PROFILE_VARS
#define PROFILE_VARS(cpu) (&_profile_vars)
#endif

/*
 * Kgmon interface.  This returns the count of bytes moved if everything was ok,
 * or -1 if there were errors.
 */

long
_profile_kgmon(int write,
	       size_t count,
	       long indx,
	       int max_cpus,
	       void **p_ptr,
	       void (*control_func)(kgmon_control_t))
{
	kgmon_control_t kgmon;
	int cpu;
	int error = 0;
	int i;
	struct profile_vars *pv;
	static struct callback dummy_callback;

	*p_ptr = (void *)0;

	/*
	 * If the number passed is not within bounds, just copy the data directly.
	 */

	if (!LEGAL_KGMON(indx)) {
		*p_ptr = (void *)indx;
		if (!write) {
			if (PROFILE_VARS(0)->debug) {
				printf("_profile_kgmon: copy %5ld bytes, from 0x%lx\n",
				       (long)count,
				       (long)indx);
			}

		} else {
			if (PROFILE_VARS(0)->debug) {
				printf("_profile_kgmon: copy %5ld bytes, to 0x%lx\n",
				       (long)count,
				       (long)indx);
			}
		}			

		return count;
	}

	/*
	 * Decode the record number into the component pieces.
	 */

	DECODE_KGMON(indx, kgmon, cpu);

	if (PROFILE_VARS(0)->debug) {
		printf("_profile_kgmon: start: kgmon control = %2d, cpu = %d, count = %ld\n",
		       kgmon, cpu, (long)count);
	}

	/* Validate the CPU number */
	if (cpu < 0 || cpu >= max_cpus) {
		if (PROFILE_VARS(0)->debug) {
			printf("KGMON, bad cpu %d\n", cpu);
		}

		return -1;

	} else {
		pv = PROFILE_VARS(cpu);

		if (!write) {
			switch (kgmon) {
			default:
				if (PROFILE_VARS(0)->debug) {
					printf("Unknown KGMON read command\n");
				}

				error = -1;
				break;

			case KGMON_GET_STATUS:		/* return whether or not profiling is active */
				if (cpu != 0) {
					if (PROFILE_VARS(0)->debug) {
						printf("KGMON_GET_STATUS: cpu = %d\n", cpu);
					}

					error = -1;
					break;
				}

				if (count != sizeof(pv->active)) {
					if (PROFILE_VARS(0)->debug) {
						printf("KGMON_GET_STATUS: count = %ld, should be %ld\n",
						       (long)count,
						       (long)sizeof(pv->active));
					}

					error = -1;
					break;
				}

				*p_ptr = (void *)&pv->active;
				break;

			case KGMON_GET_DEBUG:		/* return whether or not debugging is active */
				if (cpu != 0) {
					if (PROFILE_VARS(0)->debug) {
						printf("KGMON_GET_DEBUG: cpu = %d\n", cpu);
					}

					error = -1;
					break;
				}

				if (count != sizeof(pv->debug)) {
					if (PROFILE_VARS(0)->debug) {
						printf("KGMON_GET_DEBUG: count = %ld, should be %ld\n",
						       (long)count,
						       (long)sizeof(pv->active));
					}

					error = -1;
					break;
				}

				*p_ptr = (void *)&pv->debug;
				break;

			case KGMON_GET_PROFILE_VARS:	/* return the _profile_vars structure */
				if (count != sizeof(struct profile_vars)) {
					if (PROFILE_VARS(0)->debug) {
						printf("KGMON_GET_PROFILE_VARS: count = %ld, should be %ld\n",
						       (long)count,
						       (long)sizeof(struct profile_vars));
					}

					error = -1;
					break;
				}

				_profile_update_stats(pv);
				*p_ptr = (void *)pv;
				break;

			case KGMON_GET_PROFILE_STATS:	/* return the _profile_stats structure */
				if (count != sizeof(struct profile_stats)) {
					if (PROFILE_VARS(0)->debug) {
						printf("KGMON_GET_PROFILE_STATS: count = %ld, should be = %ld\n",
						       (long)count,
						       (long)sizeof(struct profile_stats));
					}

					error = -1;
					break;
				}

				_profile_update_stats(pv);
				*p_ptr = (void *)&pv->stats;
				break;
			}

		} else {
			switch (kgmon) {
			default:
				if (PROFILE_VARS(0)->debug) {
					printf("Unknown KGMON write command\n");
				}

				error = -1;
				break;

			case KGMON_SET_PROFILE_ON:	/* turn on profiling */
				if (cpu != 0) {
					if (PROFILE_VARS(0)->debug) {
						printf("KGMON_SET_PROFILE_ON, cpu = %d\n", cpu);
					}

					error = -1;
					break;
				}

				if (!PROFILE_VARS(0)->active) {
					for (i = 0; i < max_cpus; i++) {
						PROFILE_VARS(i)->active = 1;
					}

					if (control_func) {
						(*control_func)(kgmon);
					}

					_profile_md_start();
				}

				count = 0;
				break;

			case KGMON_SET_PROFILE_OFF:	/* turn off profiling */
				if (cpu != 0) {
					if (PROFILE_VARS(0)->debug) {
						printf("KGMON_SET_PROFILE_OFF, cpu = %d\n", cpu);
					}

					error = -1;
					break;
				}

				if (PROFILE_VARS(0)->active) {
					for (i = 0; i < max_cpus; i++) {
						PROFILE_VARS(i)->active = 0;
					}

					_profile_md_stop();

					if (control_func) {
						(*control_func)(kgmon);
					}
				}

				count = 0;
				break;

			case KGMON_SET_PROFILE_RESET:	/* reset profiling */
				if (cpu != 0) {
					if (PROFILE_VARS(0)->debug) {
						printf("KGMON_SET_PROFILE_RESET, cpu = %d\n", cpu);
					}

					error = -1;
					break;
				}

				for (i = 0; i < max_cpus; i++) {
					_profile_reset(PROFILE_VARS(i));
				}

				if (control_func) {
					(*control_func)(kgmon);
				}

				count = 0;
				break;

			case KGMON_SET_DEBUG_ON:	/* turn on profiling */
				if (cpu != 0) {
					if (PROFILE_VARS(0)->debug) {
						printf("KGMON_SET_DEBUG_ON, cpu = %d\n", cpu);
					}

					error = -1;
					break;
				}

				if (!PROFILE_VARS(0)->debug) {
					for (i = 0; i < max_cpus; i++) {
						PROFILE_VARS(i)->debug = 1;
					}

					if (control_func) {
						(*control_func)(kgmon);
					}
				}

				count = 0;
				break;

			case KGMON_SET_DEBUG_OFF:	/* turn off profiling */
				if (cpu != 0) {
					if (PROFILE_VARS(0)->debug) {
						printf("KGMON_SET_DEBUG_OFF, cpu = %d\n", cpu);
					}

					error = -1;
					break;
				}

				if (PROFILE_VARS(0)->debug) {
					for (i = 0; i < max_cpus; i++) {
						PROFILE_VARS(i)->debug = 0;
					}

					if (control_func) {
						(*control_func)(kgmon);
					}
				}

				count = 0;
				break;
			}
		}
	}

	if (error) {
		if (PROFILE_VARS(0)->debug) {
			printf("_profile_kgmon: done:  kgmon control = %2d, cpu = %d, error = %d\n",
			       kgmon, cpu, error);
		}

		return -1;
	}

	if (PROFILE_VARS(0)->debug) {
		printf("_profile_kgmon: done:  kgmon control = %2d, cpu = %d, count = %ld\n",
		       kgmon, cpu, (long)count);
	}

	return count;
}
