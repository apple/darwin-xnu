/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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
 *  This is a simplifed version of the commpage support from 10.3.
 *  The supported feature is the tuning of _cpu_capabilities.
 *  There is no shared page for user processes.
 */

#include <mach/mach_types.h>
#include <mach/machine.h>
#include <ppc/exception.h>
#include <ppc/machine_routines.h>
#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>

int		_cpu_capabilities = 0;			// define the capability vector

/* Determine number of CPUs on this system.  We cannot rely on
 * machine_info.max_cpus this early in the boot.
 */
static int
commpage_cpus( void )
{
    int		cpus;
    
    cpus = ml_get_max_cpus();			// NB: this call can block
    
    if (cpus == 0)
        panic("commpage cpus==0");
    if (cpus > 0xFF)
        cpus = 0xFF;
    
    return	cpus;
}


/* Initialize kernel version of _cpu_capabilities vector (used by KEXTs.) */

static void
commpage_init_cpu_capabilities( void )
{
    struct per_proc_info *pp;
    procFeatures	*pfp;
    int	cpus;
    int	available;

    pp = per_proc_info;					// use CPU 0's per-proc
    pfp = &pp->pf;						// point to features in per-proc
    available = pfp->Available;

    // If AltiVec is disabled make sure it is not reported as available.
    if ((available & pfAltivec) == 0) {
        _cpu_capabilities &= ~kHasAltivec;
    }

    if (_cpu_capabilities & kDcbaAvailable) { 		// if this processor has DCBA, time it...
        _cpu_capabilities |= commpage_time_dcba();	// ...and set kDcbaRecomended if it helps.
    }

    cpus = commpage_cpus();				// how many CPUs do we have
    if (cpus == 1) _cpu_capabilities |= kUP;
    _cpu_capabilities |= (cpus << kNumCPUsShift);
}


/* Fill in commpage: called once, during kernel initialization, from the
 * startup thread before user-mode code is running.
 * See the top of this file for a list of what you have to do to add
 * a new routine to the commpage.
 */  
void
commpage_populate( void )
{
    commpage_init_cpu_capabilities();
}
