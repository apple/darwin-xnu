/*
 * Copyright (c) 2006-2009 Apple Inc. All rights reserved.
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

#include <IOKit/IOService.h>
#include <IOKit/IOPolledInterface.h>

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSDefineMetaClassAndAbstractStructors(IOPolledInterface, OSObject);

OSMetaClassDefineReservedUnused(IOPolledInterface, 0);
OSMetaClassDefineReservedUnused(IOPolledInterface, 1);
OSMetaClassDefineReservedUnused(IOPolledInterface, 2);
OSMetaClassDefineReservedUnused(IOPolledInterface, 3);
OSMetaClassDefineReservedUnused(IOPolledInterface, 4);
OSMetaClassDefineReservedUnused(IOPolledInterface, 5);
OSMetaClassDefineReservedUnused(IOPolledInterface, 6);
OSMetaClassDefineReservedUnused(IOPolledInterface, 7);
OSMetaClassDefineReservedUnused(IOPolledInterface, 8);
OSMetaClassDefineReservedUnused(IOPolledInterface, 9);
OSMetaClassDefineReservedUnused(IOPolledInterface, 10);
OSMetaClassDefineReservedUnused(IOPolledInterface, 11);
OSMetaClassDefineReservedUnused(IOPolledInterface, 12);
OSMetaClassDefineReservedUnused(IOPolledInterface, 13);
OSMetaClassDefineReservedUnused(IOPolledInterface, 14);
OSMetaClassDefineReservedUnused(IOPolledInterface, 15);

#if !HIBERNATION
/* KPI stub if hibernate is configured off */
IOReturn
IOPolledInterface::checkAllForWork(void)
{
  IOReturn	err = kIOReturnNotReady;

  return err;
}
#endif /* !HIBERNATION */
