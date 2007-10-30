/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
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

#ifndef _IOPOLLEDINTERFACE_H_
#define _IOPOLLEDINTERFACE_H_

#include <libkern/c++/OSObject.h>

#define kIOPolledInterfaceSupportKey "IOPolledInterface"

enum
{
    kIOPolledPreflightState   = 1,
    kIOPolledBeforeSleepState = 2,
    kIOPolledAfterSleepState  = 3,
    kIOPolledPostflightState  = 4
};

enum
{
    kIOPolledWrite = 1,
    kIOPolledRead  = 2
};

typedef void (*IOPolledCompletionAction)( void *   target,
                                          void *   parameter,
                                          IOReturn status,
                                          uint64_t actualByteCount);
struct IOPolledCompletion
{
    void *                    target;
    IOPolledCompletionAction  action;
    void *                    parameter;
};

class IOPolledInterface : public OSObject
{
    OSDeclareAbstractStructors(IOPolledInterface);

protected:
    struct ExpansionData { };
    ExpansionData * reserved;

public:
    virtual IOReturn probe(IOService * target) = 0;

    virtual IOReturn open( IOOptionBits state, IOMemoryDescriptor * buffer) = 0;
    virtual IOReturn close(IOOptionBits state) = 0;

    virtual IOReturn startIO(uint32_t 	        operation,
                             uint32_t           bufferOffset,
                             uint64_t	        deviceOffset,
                             uint64_t	        length,
                             IOPolledCompletion completion) = 0;

    virtual IOReturn checkForWork(void) = 0;

    static IOReturn checkAllForWork(void);

    OSMetaClassDeclareReservedUnused(IOPolledInterface, 0);
    OSMetaClassDeclareReservedUnused(IOPolledInterface, 1);
    OSMetaClassDeclareReservedUnused(IOPolledInterface, 2);
    OSMetaClassDeclareReservedUnused(IOPolledInterface, 3);
    OSMetaClassDeclareReservedUnused(IOPolledInterface, 4);
    OSMetaClassDeclareReservedUnused(IOPolledInterface, 5);
    OSMetaClassDeclareReservedUnused(IOPolledInterface, 6);
    OSMetaClassDeclareReservedUnused(IOPolledInterface, 7);
    OSMetaClassDeclareReservedUnused(IOPolledInterface, 8);
    OSMetaClassDeclareReservedUnused(IOPolledInterface, 9);
    OSMetaClassDeclareReservedUnused(IOPolledInterface, 10);
    OSMetaClassDeclareReservedUnused(IOPolledInterface, 11);
    OSMetaClassDeclareReservedUnused(IOPolledInterface, 12);
    OSMetaClassDeclareReservedUnused(IOPolledInterface, 13);
    OSMetaClassDeclareReservedUnused(IOPolledInterface, 14);
    OSMetaClassDeclareReservedUnused(IOPolledInterface, 15);
};

#endif /* _IOPOLLEDINTERFACE_H_ */
