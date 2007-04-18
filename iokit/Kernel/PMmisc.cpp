/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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
#include <IOKit/pwr_mgt/IOPM.h>
#include <IOKit/IOService.h>

extern "C" {
extern void kprintf(const char *, ...);
}

static char rootDomain[ ] = "IOPMrootDomain";
static char displayDevice[ ] = "IODisplayWrangler";
static bool rootRegistered;
static bool displayRegistered;
static IOService * root;
static IOService * display;

void IOPMLog(const char * who,unsigned long event,unsigned long param1, unsigned long param2)
{
//    kprintf("%s %02d %08x %08x\n",who,event,param1,param2);
}


void IOPMRegisterDevice(const char * who, IOService * theDevice)
{

    if ( strcmp(rootDomain,who) == 0 ) {			// root power domain is registering
        theDevice->youAreRoot();
        rootRegistered = true;
        root = theDevice;
        if ( displayRegistered ) {
            root->addChild ( display );
        }
    }
    else{
        if ( strcmp(displayDevice,who) == 0 ) {			// somebody else is registering
            displayRegistered = true;				// save pointer to display wrangler
            display = theDevice;
        }
        if ( rootRegistered ) {					// if not root domain, then it's
            root->addChild ( theDevice );				// one of its children
        }
    }
}

