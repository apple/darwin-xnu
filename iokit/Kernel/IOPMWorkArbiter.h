/*
 * Copyright (c) 2001-2002 Apple Computer, Inc. All rights reserved.
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
 
#ifndef _IOPMWorkArbiter_H_
#define _IOPMWorkArbiter_H_
 
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOEventSource.h>
#include <IOKit/IOService.h>
extern "C" {
    #include <kern/queue.h>
}

class IOPMWorkArbiter : public IOEventSource
{
    OSDeclareDefaultStructors(IOPMWorkArbiter);

private:
    enum {
        kAllAcked = 0,
        kDriverAcked,
        kRootDomainClamshellChanged
    };

    // Queue of requested states
    struct PMEventEntry 
    {
        void                    *next;
        IOService               *target;
        uint16_t                actionType;
        uint32_t                intArgument;
    };

    IOPMrootDomain              *fRootDomain;

    void                        *events;
    IOLock                      *tmpLock;

protected:
    virtual bool checkForWork(void);

public:
    IOLock              *arbiterLock;

    //typedef void (*Action)(IOService *target, unsigned long state);

    virtual bool init(OSObject *owner, Action action = 0);

    // static initialiser
    static IOPMWorkArbiter *pmWorkArbiter(IOPMrootDomain *owner);
      
    /* IOPMrootDomain work */
    bool clamshellStateChangeOccurred(uint32_t messageValue);
 };
 
 
 #endif /* _IOPMWorkArbiter_H_ */
 
