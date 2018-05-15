/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
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

#include <IOKit/rtc/IORTCController.h>

#define super IOService

OSDefineMetaClassAndAbstractStructors(IORTC, IOService);

void IORTC::getUTCTimeOfDay( clock_sec_t * secs, clock_nsec_t * nsecs )
{
    *nsecs = 0;
    *secs = getGMTTimeOfDay();
}

void IORTC::setUTCTimeOfDay( clock_sec_t secs, clock_nsec_t nsecs )
{
    setGMTTimeOfDay(secs);
}

IOReturn IORTC::getMonotonicClockOffset( int64_t * usecs )
{
    return kIOReturnUnsupported;
}

IOReturn IORTC::setMonotonicClockOffset( int64_t usecs )
{
    return kIOReturnUnsupported;
}

IOReturn IORTC::getMonotonicClockAndTimestamp( uint64_t * usecs, uint64_t *mach_absolute_time )
{
    return kIOReturnUnsupported;
}

OSMetaClassDefineReservedUnused(IORTC, 0);
OSMetaClassDefineReservedUnused(IORTC, 1);
OSMetaClassDefineReservedUnused(IORTC, 2);
OSMetaClassDefineReservedUnused(IORTC, 3);
OSMetaClassDefineReservedUnused(IORTC, 4);
OSMetaClassDefineReservedUnused(IORTC, 5);
OSMetaClassDefineReservedUnused(IORTC, 6);
OSMetaClassDefineReservedUnused(IORTC, 7);
