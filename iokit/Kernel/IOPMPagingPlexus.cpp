/*
 * Copyright (c) 1998-2001 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
 * Copyright (c) 1998 Apple Computer, Inc.  All rights reserved. 
 *
 * HISTORY
 * 9 May 01 suurballe.
 */
 
#include <IOKit/pwr_mgt/IOPMPagingPlexus.h>
#include <IOKit/pwr_mgt/IOPM.h>
#include <IOKit/pwr_mgt/RootDomain.h>
#include <IOKit/pwr_mgt/IOPowerConnection.h>
#include <IOKit/IOLib.h>

extern char rootdevice[];

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define super IOService
OSDefineMetaClassAndStructors(IOPMPagingPlexus,IOService)


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// stub driver has two power states, off and on

enum { kIOPlexusPowerStateCount = 2 };

static const IOPMPowerState powerStates[ kIOPlexusPowerStateCount ] = {
    { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 1, 0, IOPMPagingAvailable, IOPMPowerOn, 0, 0, 0, 0, 0, 0, 0, 0 }
};

//* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
// initialize
//
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool IOPMPagingPlexus::start ( IOService * provider )
{
    super::start(provider);

    ourLock = IOLockAlloc();
    systemBooting = true;

    PMinit();   			 // initialize superclass variables
    
    registerPowerDriver(this,(IOPMPowerState *)powerStates,kIOPlexusPowerStateCount);
    
    return true;
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
// setAggressiveness
//
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn IOPMPagingPlexus::setAggressiveness ( unsigned long type, unsigned long )
{
    OSDictionary *	dict;
    OSIterator *	iter;
    OSObject *		next;
    IOService *		candidate = 0;
    IOService *		pagingProvider;

    if( type != kPMMinutesToSleep)
        return IOPMNoErr;
    
    IOLockLock(ourLock);
    if ( systemBooting ) {
        systemBooting = false;
        IOLockUnlock(ourLock);
        dict = IOBSDNameMatching(rootdevice);
        if ( dict ) {
            iter = getMatchingServices(dict);
            if ( iter ) {
                while ( (next = iter->getNextObject()) ) {
                    if ( (candidate = OSDynamicCast(IOService,next)) ) {
                        break;
                    }
                }
                iter->release();
            }
        }
        if ( candidate ) {
            pagingProvider = findProvider(candidate);
            if ( pagingProvider ) {
                processSiblings(pagingProvider);
                pagingProvider->addPowerChild(this);
                getPMRootDomain()->removePowerChild(((IOPowerConnection *)getParentEntry(gIOPowerPlane)));
                processChildren();
            }
        }
    }
    else {
        IOLockUnlock(ourLock);
    }
    return IOPMNoErr;
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
// findProvider
//
// Climb upward in the power tree from the node pointed to by the parameter.
// Return a pointer to the first power-managed entity encountered.
// This is the provider of paging services (the root device disk driver).
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOService * IOPMPagingPlexus::findProvider ( IOService * mediaObject )
{
    IORegistryEntry * node = mediaObject;
    
    if ( mediaObject == NULL ) {
        return NULL;
    }
    
    while ( node ) {
        if ( node->inPlane(gIOPowerPlane) ) {
            return (IOService *)node;
        }
        node = node->getParentEntry(gIOServicePlane);
    }
    return NULL;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
// processSiblings
//
// Climb upward in the power tree from the node pointed to by the parameter.
// "Other" children of each ancestor (not the nodes in our upward path) are
// made children of this plexus, so they get paging services from here.
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void IOPMPagingPlexus::processSiblings ( IOService * aNode )
{
    OSIterator *	parentIterator;
    IORegistryEntry *	nextNub;
    IORegistryEntry *	nextParent;
    OSIterator *	siblingIterator;
    IORegistryEntry *	nextSibling;

    parentIterator = aNode->getParentIterator(gIOPowerPlane);		// iterate parents of this node

    if ( parentIterator ) {
        while ( true ) {
            if ( ! (nextNub = (IORegistryEntry *)(parentIterator->getNextObject())) ) {
                parentIterator->release();
                break;
            }
            if ( OSDynamicCast(IOPowerConnection,nextNub) ) {
                nextParent = nextNub->getParentEntry(gIOPowerPlane);
                if ( nextParent == getPMRootDomain() ) {
                    continue;				// plexus already has root's children
                }
                if ( nextParent == this ) {
                    parentIterator->release();
                    removePowerChild((IOPowerConnection *)nextNub);
                    break;
                }
                siblingIterator = nextParent->getChildIterator(gIOPowerPlane);
                                                                                // iterate children of this parent
                if ( siblingIterator ) {
                    while ( (nextSibling = (IORegistryEntry *)(siblingIterator->getNextObject())) ) {
                        if ( OSDynamicCast(IOPowerConnection,nextSibling) ) {
                            nextSibling = nextSibling->getChildEntry(gIOPowerPlane);
                            if ( nextSibling != aNode ) {			// non-ancestor of driver gets
                                addPowerChild((IOService *)nextSibling);	// plexus as parent
                            }
                        }
                    }
                    siblingIterator->release();
                }
                processSiblings((IOService *)nextParent);			// do the same thing to this parent
            }
   	}
    }
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
// processChildren
//
// Now invent the need for paging services:  alter our children's arrays
// to show that they need paging.
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void IOPMPagingPlexus::processChildren ( void )
{
    OSIterator *	childIterator;
    IOPowerConnection *	nextChildNub;
    IORegistryEntry *	nextChild;
    IOService *		child;
    unsigned int	i;
    
    childIterator = getChildIterator(gIOPowerPlane);

    if ( childIterator ) {
        while ( (nextChild = (IORegistryEntry *)(childIterator->getNextObject())) ) {
            if ( (nextChildNub = OSDynamicCast(IOPowerConnection,nextChild)) ) {
                child = (IOService *)nextChild->getChildEntry(gIOPowerPlane);
                if ( child->pm_vars->theControllingDriver ) {
                    for ( i = 1; i < child->pm_vars->theNumberOfPowerStates; i++ ) {
                        child->pm_vars->thePowerStates[i].inputPowerRequirement |= IOPMPagingAvailable;
                    }
                }
                if ( child->pm_vars->myCurrentState ) {
                    nextChildNub->setDesiredDomainState(kIOPlexusPowerStateCount-1);
                }
            }
        }
        childIterator->release();
    }
}
