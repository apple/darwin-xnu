/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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
#ifndef _IOSYNCER_H
#define _IOSYNCER_H

#include <libkern/c++/OSObject.h>
#include <IOKit/IOTypes.h>
#include <IOKit/IOLocks.h>

class IOSyncer : public OSObject
{
    OSDeclareDefaultStructors(IOSyncer)

private:
    // The spin lock that is used to guard the 'threadMustStop' variable. 
    IOSimpleLock *guardLock;
    volatile bool threadMustStop;
    IOReturn fResult;
    virtual void free();
    virtual void privateSignal();

public:

    static IOSyncer * create(bool twoRetains = true);

    virtual bool init(bool twoRetains);
    virtual void reinit();
    virtual IOReturn wait(bool autoRelease = true);
    virtual void signal(IOReturn res = kIOReturnSuccess,
					bool autoRelease = true);
};

#endif /* !_IOSYNCER */

