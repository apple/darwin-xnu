/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/* IOArray.h created by rsulack on Thu 11-Sep-1997 */

#include <libkern/OSDebug.h>

#include <libkern/c++/OSCollection.h>
#include <libkern/c++/OSDictionary.h>

#include <IOKit/IOKitDebug.h>

#define super OSObject

OSDefineMetaClassAndAbstractStructors(OSCollection, OSObject)


OSMetaClassDefineReservedUsed(OSCollection, 0);
OSMetaClassDefineReservedUsed(OSCollection, 1);
OSMetaClassDefineReservedUnused(OSCollection, 2);
OSMetaClassDefineReservedUnused(OSCollection, 3);
OSMetaClassDefineReservedUnused(OSCollection, 4);
OSMetaClassDefineReservedUnused(OSCollection, 5);
OSMetaClassDefineReservedUnused(OSCollection, 6);
OSMetaClassDefineReservedUnused(OSCollection, 7);

bool OSCollection::init()
{
    if (!super::init())
        return false;

    updateStamp = 0;

    return true;
}

void OSCollection::haveUpdated()
{
    if ( (gIOKitDebug & kOSLogRegistryMods) && (fOptions & kImmutable) )
	OSReportWithBacktrace("Trying to change a collection in the registry");

    updateStamp++;
}

unsigned OSCollection::setOptions(unsigned options, unsigned mask, void *)
{
    unsigned old = fOptions;

    if (mask)
	fOptions = (old & ~mask) | (options & mask);

    return old;
}

OSCollection *  OSCollection::copyCollection(OSDictionary *cycleDict)
{
    if (cycleDict) {
	OSObject *obj = cycleDict->getObject((const OSSymbol *) this);
	if (obj)
	    obj->retain();

	return reinterpret_cast<OSCollection *>(obj);
    }
    else {
	// If we are here it means that there is a collection subclass that
	// hasn't overridden the copyCollection method.  In which case just
	// return a reference to ourselves.  
	// Hopefully this collection will not be inserted into the registry
	retain();
	return this;
    }
}
