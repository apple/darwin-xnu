/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
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

