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
#ifndef _IOKIT_ROOTDOMAIN_H
#define _IOKIT_ROOTDOMAIN_H

#include <IOKit/IOService.h>
#include <IOKit/pwr_mgt/IOPM.h>

class RootDomainUserClient;

#define number_of_power_states 2
#define powerOn 1


class IOPMrootDomain: public IOService
{
OSDeclareDefaultStructors(IOPMrootDomain)
    
public:

    virtual  bool start( IOService * provider );
    virtual IOReturn newUserClient ( task_t,  void *, UInt32, IOUserClient ** );
    virtual IOReturn setAggressiveness ( unsigned long, unsigned long );
    virtual IOReturn getAggressiveness ( unsigned long, unsigned long * );


private:

    unsigned long current_values[kMaxType+1];			// current values of aggressiveness factors
    UInt16   serialNumber;					// used to identify sleep/wake notification cycle
    OSArray* responseFlags;					// points to array of responses from apps
    bool     doNotSleep;					// true if an application vetos sleep notification
    
    virtual  IOReturn setPowerState ( long, IOService* );
    virtual  unsigned long maxCapabilityForDomainState ( IOPMPowerFlags );
    virtual  unsigned long powerStateForDomainState ( IOPMPowerFlags );
    virtual  void notifyApps ( void );
    virtual  bool responseValid ( unsigned long refcon );
    virtual  void checkForDone ( void );
    unsigned long initialPowerStateForDomainState ( IOPMPowerFlags);
    void command_received ( void *, void * , void * , void *);

};

#endif /*  _IOKIT_ROOTDOMAIN_H */
