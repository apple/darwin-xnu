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

