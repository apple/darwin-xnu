/*
 * Copyright (c) 2001-2002 Apple Computer, Inc. All rights reserved.
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
      
    // thread launcher
    static void checkForWorkThreadFunc(void *refcon);
      
    /* IOServicePM work */
    bool allAckedOccurred(IOService *inTarget);    
    bool driverAckedOccurred(IOService *inTarget);

    /* IOPMrootDomain work */
    bool clamshellStateChangeOccurred(uint32_t messageValue);
 };
 
 
/*
class PMWorkUnit : public OSObject
{
    friend class IOService:
    OSDeclareDefaultStructors(PMWorkUnit)
public:
    uint16_t        type;
    IOService       *who;
}

class PMWorkerThread : public OSObject
{
    friend class IOService;
    OSDeclareDefaultStructors(PMWorkerThread)

public:
    virtual void free();

    static PMWorkerThread *workerThread( void );
    static void main( PMWorkerThread * self );
};
*/
 
 #endif /* _IOPMWorkArbiter_H_ */
 
