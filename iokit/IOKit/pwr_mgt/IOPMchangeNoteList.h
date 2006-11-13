/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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
#include <libkern/c++/OSObject.h>
#include <IOKit/IOReturn.h>

class IOPowerConnection;

// This is a list of State Changes which are in progress.  Its purpose is to keep track of the
// notifications and acknowledgements caused by state change.  A change is added to the list
// when either our parent notifies us that the power domain is changing state or when we decide
// to change power to our device or domain.
//
// A change is removed from the list when all interested parties have been informed of the upcoming
// change, all of them have acknowledged the notification, the change has been made, all interested
// parties have been informed that the change was made, and all of them have acknowledged.
//
// The list is strictly first-in, first-out.  It is implemented as a circular list in a linear
// array.  There are two pointers into the array.  The circular list is empty when these two
// pointers are equal.

// More specifically, a change note is put into the array when one of these things happens:
//   the device decides it is idle and needs to reduce power. (changePowerStateTo)
//   the device decides it is not idle and needs to increase power. (changePowerStateTo)
//   the controlling driver requests a state change. (changePowerStateTo)
//   some client needs to use the device but it is powered down. (makeUsable)
//   the parent says the domain power is changing. (powerStateWillChangeTo)
//   a child says it no longer needs power, and all other children are similarly idle. (requestDomainState)
//.  a child wants more power in the domain so it can raise its power state. (requestDomainState)
//
// A change note is removed from the array when all interested drivers and power domain
// children have acknowledged the change.

// Each change note contains:
// A flag field which describes the change.
// Which power state the device will be in after the change.
// The power flags which describe the result of this change.

struct changeNoteItem{
unsigned long		flags;
unsigned long		newStateNumber;
IOPMPowerFlags		outputPowerCharacter;
IOPMPowerFlags		inputPowerRequirement;
IOPMPowerFlags		domainState;
IOPowerConnection *	parent;
IOPMPowerFlags		singleParentState;
IOPMPowerFlags		capabilityFlags;
};

typedef struct changeNoteItem changeNoteItem;


					// flags field
	
#define IOPMParentInitiated		1		// this power change initiated by our  parent
#define IOPMWeInitiated		2		// this power change initiated by this device (not parent)
#define IOPMNotDone		4		// we couldn't make this change
#define IOPMNotInUse		8		// this list element not currently in use
#define IOPMDomainWillChange	16		// parent change started by PowerDomainWillChangeTo
#define IOPMDomainDidChange	32		// parent change started by PowerDomainDidChangeTo


// Length of change note list is maximum 5.  There cannot be two adjacent device-initiated change notes unless
// one is currently being actioned, because two adjacent in-active device-initiated changes are always collapsed
// into one, and there cannot be more than two parent-initiated change notes in the queue (from one parent),
// because the parent does not
// initiate a change (by calling domainStateWillChange) until everybody has acknowledged the previous one
// (by calling domainStateDidChange), although if we are the last to send that acknowledgement, the change we
// are acknowledging will still be in the queue as we acknowledge, and at that point the parent can give us another
// (by callingdomainStateWillChange).  So we need room for two parent changes, two non-adjacent device changes,
// one more per additional parent, say two more,
// and room for one more device change to get into the queue before collapsing it with its neighbor.  In this case, seven
// entryies suffices.  Or, we need
// room for two adjacent device changes (one in progress), a parent change, another device change, another parent change,
// another device change, another parent change, another device change, plus
// one more device change to get into the queue before collapsing it with its neighbor.  Nine entries in this case. 
// I'm not sure what irrationallity causes me to code for twenty entries in the queue.
#define IOPMMaxChangeNotes 20

class IOPMchangeNoteList :public OSObject
{
OSDeclareDefaultStructors(IOPMchangeNoteList)
    
private:
    unsigned long		firstInList;		// points to oldest active change note in list
    unsigned long		firstUnused;		// points just beyond newest change note in list

public:

        changeNoteItem		changeNote[IOPMMaxChangeNotes];
    

void initialize ( void );

long createChangeNote ( void );

long currentChange ( void );

long latestChange ( void );

IOReturn releaseHeadChangeNote ( void );

IOReturn releaseTailChangeNote ( void );

bool changeNoteInUse ( unsigned long ordinal );

long nextChangeNote ( unsigned long ordinal );

unsigned long increment (unsigned long ordinal );

unsigned long decrement (unsigned long ordinal );

long previousChangeNote (unsigned long ordinal );

bool listEmpty ( void );

};
