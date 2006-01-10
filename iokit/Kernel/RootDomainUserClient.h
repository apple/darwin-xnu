/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * Copyright (c) 1999 Apple Computer, Inc.  All rights reserved. 
 *
 * HISTORY
 *
 */


#ifndef _IOKIT_ROOTDOMAINUSERCLIENT_H
#define _IOKIT_ROOTDOMAINUSERCLIENT_H

#include <IOKit/IOUserClient.h>
#include <IOKit/pwr_mgt/IOPM.h>
#include <IOKit/pwr_mgt/RootDomain.h>
#include <IOKit/pwr_mgt/IOPMLibDefs.h>


class RootDomainUserClient : public IOUserClient
{
    OSDeclareDefaultStructors(RootDomainUserClient)

private:
    IOPMrootDomain *	fOwner;
    task_t              fOwningTask;

    IOReturn            secureSleepSystem( int *return_code );
    IOReturn            secureSetAggressiveness( unsigned long type, unsigned long newLevel, int *return_code );

public:

    virtual IOReturn clientClose( void );
    
    virtual IOExternalMethod * getTargetAndMethodForIndex( IOService ** targetP, UInt32 index );

    virtual bool start( IOService * provider );

    virtual bool initWithTask(task_t owningTask, void *security_id, UInt32);

    void setPreventative(UInt32 on_off, UInt32 types_of_sleep);

};

#endif /* ! _IOKIT_ROOTDOMAINUSERCLIENT_H */

