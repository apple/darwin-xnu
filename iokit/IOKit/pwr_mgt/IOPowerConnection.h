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
 * Copyright (c) 1998 Apple Computer, Inc.  All rights reserved.
 *
 * HISTORY
 *
 */


#ifndef _IOKIT_IOPOWERCONNECTION_H
#define _IOKIT_IOPOWERCONNECTION_H

#include <IOKit/IOService.h>
#include <IOKit/pwr_mgt/IOPM.h>

class IOPowerConnection : public IOService
{
    OSDeclareDefaultStructors(IOPowerConnection)

protected:
    /*! @field parentKnowsState	true: parent knows state of its domain
					used by child */
    bool		stateKnown;
    /*! @field currentPowerFlags	power flags which describe  the current state of the power domain
					used by child */
    IOPMPowerFlags 	currentPowerFlags;
    /*! @field desiredDomainState	state number which corresponds to the child's desire
					used by parent */
    unsigned long	desiredDomainState;

public:
        /*! @function setParentKnowsState
            @abstract Sets the stateKnown variable.
            @discussion Called by the parent when the object is created and called by the child when it discovers that the parent now knows its state. */
    void setParentKnowsState (bool );

    /*! @function setParentCurrentPowerFlags
        @abstract Sets the currentPowerFlags variable.
        @discussion Called by the parent when the object is created and called by the child when it discovers that the parent state is changing. */
    void setParentCurrentPowerFlags (IOPMPowerFlags );

    /*! @function parentKnowsState
        @abstract Returns the stateKnown variable. */
    bool parentKnowsState (void );

    /*! @function parentCurrentPowerFlags
        @abstract Returns the currentPowerFlags variable. */
    IOPMPowerFlags parentCurrentPowerFlags (void );

    /*! @function setDesiredDomainState
        @abstract Sets the desiredDomainState variable.
        @discussion Called by the child. */
    void setDesiredDomainState (unsigned long );

    /*! @function getDesiredDomainState
        @abstract Returns the desiredDomainState variable.
    @discussion Called by the child. */
    unsigned long getDesiredDomainState ( void );
};

#endif /* ! _IOKIT_IOPOWERCONNECTION_H */

