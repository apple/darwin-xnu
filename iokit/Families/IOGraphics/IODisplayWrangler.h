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
/*
 * Copyright (c) 1999 Apple Computer, Inc.
 *
 *
 * HISTORY
 *
 */

#ifndef _IOKIT_IODISPLAYWRANGLER_H
#define _IOKIT_IODISPLAYWRANGLER_H

#include <IOKit/IOService.h>
#include <IOKit/graphics/IOFramebuffer.h>
#include <IOKit/graphics/IODisplay.h>

class IOWorkLoop;
class IOCommandQueue;

class IODisplayWrangler : public IOService
{
    OSDeclareDefaultStructors( IODisplayWrangler );

private:
    bool		fOpen;
    IOLock *		fMatchingLock;
    OSSet *		fFramebuffers;
    OSSet *		fDisplays;
    // true: we have informed displays to assume lowest usable state
    bool		emergency_informed;
    // from control panel: number of idle minutes before dimming
    unsigned long	mins_to_dim;
    // false: use mins_to_dim unless in emergency situation
    bool		use_general_aggressiveness;

    virtual void initForPM ( void );
    virtual IOReturn setAggressiveness ( unsigned long, unsigned long );
    virtual bool activityTickle ( unsigned long, unsigned long );
    virtual IOReturn setPowerState ( unsigned long powerStateOrdinal, IOService* whatDevice );
    virtual void makeDisplaysUsable ( void );
    virtual void idleDisplays ( void );
      
    static bool _displayHandler( void * target, void * ref,
                            IOService * newService );
    static bool _displayConnectHandler( void * target, void * ref,
                            IOService * newService );

    virtual bool displayHandler( OSSet * set, IODisplay * newDisplay);
    virtual bool displayConnectHandler( void * ref, IODisplayConnect * connect);

    virtual bool makeDisplayConnects( IOFramebuffer * fb );

    virtual IODisplayConnect * getDisplayConnect(
		IOFramebuffer * fb, IOIndex connect );

    virtual IOReturn getConnectFlagsForDisplayMode(
		IODisplayConnect * connect,
		IODisplayModeID mode, UInt32 * flags );

    virtual IOReturn getDefaultMode( IOFramebuffer * fb,
                        IODisplayModeID * mode, IOIndex * depth );

    virtual IOReturn findStartupMode( IOFramebuffer * fb );

public:

    IOService *	rootDomain;			// points to Root Power Domain
    
    virtual bool start(IOService * provider);

    static IOReturn clientStart( IOFramebuffer * fb );

    static IOReturn getFlagsForDisplayMode(
		IOFramebuffer * fb,
		IODisplayModeID mode, UInt32 * flags );
    
};

#endif /* _IOKIT_IODISPLAYWRANGLER_H */
