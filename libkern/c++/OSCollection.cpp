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
/* IOArray.h created by rsulack on Thu 11-Sep-1997 */

#include <libkern/c++/OSCollection.h>
#include <libkern/c++/OSArray.h>

#define super OSObject

OSDefineMetaClassAndAbstractStructors(OSCollection, OSObject)
OSMetaClassDefineReservedUnused(OSCollection, 0);
OSMetaClassDefineReservedUnused(OSCollection, 1);
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
