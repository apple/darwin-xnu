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

extern "C" {
#include <kern/thread_call.h>
}

#include <libkern/c++/OSObject.h>
#include <IOKit/IOLocks.h>
class IOPMinformee;
class IOPMinformeeList;
class IOPMchangeNoteList;
class IOPMpmChild;
class IOWorkLoop;
class IOCommandQueue;
class IOCommandGate;
class IOTimerEventSource;
class IOPlatformExpert;

#include <IOKit/pwr_mgt/IOPM.h>


/*!
@defined ACK_TIMER_PERIOD
@discussion When an IOService is waiting for acknowledgement to a power state change
notification from an interested driver or the controlling driver its ack timer is ticking every tenth of a second.
(100000000 nanoseconds are one tenth of a second).
*/
 #define ACK_TIMER_PERIOD 100000000



/*!
@class IOPMpriv : public OSObject
@abstract Private power management private instance variables for IOService objects.
*/
class IOPMpriv : public OSObject
{
    friend class IOService;

    OSDeclareDefaultStructors(IOPMpriv)

    public:

/*! @field we_are_root 		TRUE if this device is the root power domain */
    bool			we_are_root;
    
    /*! @field interestedDrivers	 list of interested drivers */
    IOPMinformeeList *	interestedDrivers;
    
    /*! @field children		 list of power domain children */
    IOPMinformeeList *	children;
    
    /*! @field changeList		list of pending power state changes */
    IOPMchangeNoteList *	changeList;
    
    /*! @field driver_timer		timeout on waiting for controlling driver to acknowledgeSetPowerState */
    IOReturn			driver_timer;
    
    /*! @field ackTimer									*/
    thread_call_t		ackTimer;

    /*! @field settleTimer								*/
    thread_call_t		settleTimer;

    /*! @field machine_state		state number of state machine processing current change note */
    unsigned long		machine_state;
    
    /*! @field settle_time		settle timer after changing power state */
    unsigned long		settle_time;
    
    /*! @field head_note		ordinal of change note currently being processed */
    long			head_note;
    
    /*! @field head_note_flags	copy of flags field in change note currently being processed*/
    unsigned long		head_note_flags;

    /*! @field head_note_state	copy of newStateNumberfield in change note currently being  processed */
    unsigned long		head_note_state;

    /*! @field head_note_outputFlags	 outputPowerCharacter field from change note currently being processed */
    unsigned long		head_note_outputFlags;

    /*! @field head_note_domainState		power domain flags from parent... (only on parent change) */
    unsigned long		head_note_domainState;

    /*! @field head_note_parent		pointer to initiating parent... (only on parent change) */
    IOPowerConnection * 	head_note_parent;
    
    /*! @field head_note_capabilityFlags	copy of capabilityFlags field in change note currently being processed */
    unsigned long		head_note_capabilityFlags;

    /*! @field head_note_pendingAcks	number of acks we are waiting for during notification */
    unsigned long		head_note_pendingAcks;

    /*! @field our_lock			used to control access to head_note_pendingAcks and driver_timer */
    IOLock	*		our_lock;

    /*! @field flags_lock		used to control access to response flags array */
    IOLock	*		flags_lock;

    /*! @field initial_change			true forces first state to be broadcast even if it isn't a change */
    bool			initial_change;

    /*! @field need_to_become_usable	someone called makeUsable before we had a controlling driver */
    bool			need_to_become_usable;

    /*! @field device_overrides		state changes are made based only on subclass's desire */
    bool			device_overrides;

    /*! @field clampOn		domain is clamped on till first child registers */
    bool			clampOn;

    /*! @field owner			points to object which made this struct.  Used for debug output only */
    IOService * 		owner;

    /*! @field activityLock			used to protect activity flag */
    IOLock *		activityLock;

    /*! @field timerEventSrc		an idle timer */
    IOTimerEventSource * 	timerEventSrc;

    /*! @field idle_timer_period		its period in seconds */
    unsigned long		idle_timer_period;
   
    /*! @field clampTimerEventSrc    timer for clamping power on */
    IOTimerEventSource *        clampTimerEventSrc;

    /*! @field device_active			true: there has been device activity since last idle timer expiration  */
    bool			device_active;

    /*! @field device_active_timestamp    time in ticks of last activity */
    AbsoluteTime                device_active_timestamp;

    /*! @field driverDesire
This is the power state desired by our controlling driver.  It is initialized to myCurrentState and is changed
when the controlling driver calls changePowerStateTo.   A change in driverDesire may cause a change in ourDesiredPowerState.
*/
    unsigned long		driverDesire;



    /*! @field deviceDesire
This is the power state desired by a subclassed device object.  It is initialized to myCurrentState and is changed
when the subclassed object calls changePowerStateToPriv.  A change in deviceDesire may cause a change in ourDesiredPowerState.
*/
    unsigned long		deviceDesire;



    /*! @field ourDesiredPowerState
This is the power state we desire currently.  If equal to myCurrentState, we're happy.
Otherwise, we're waiting for the parent to raise the power domain to at least this level.
    
If this is a power domain, this is the maximum of all our children's desires, driverDesire, and deviceDesire.
It increases when:
a child asks for more power via requestDomainState,
the controlling driver asks for more power via changePowerStateTo

It decreases when:
we lose a child and the child had the highest power need of all our children,
the child with the highest power need suggests a lower power domain state,
the controlling driver asks for lower power for some reason via changePowerStateTo

If this is not a power domain, ourDesiredPowerState represents the greater of driverDesire and deviceDesire.
It increases when:
the controlling driver asks for more power via changePowerStateTo
some driver calls makeUsable
a subclassed object asks for more power via changePowerStateToPriv

It decreases when:
the controlling driver asks for lower power for some reason via changePowerStateTo
a subclassed object asks for lower power for some reason via changePowerStateToPriv
*/
    unsigned long		ourDesiredPowerState;


    /*! @field previousRequest
This is a reminder of what our parent thinks our need is.  Whenever it changes,
we call requestDomainState in the parent to keep it current.  It is usually equal to ourDesiredPowerState
except while a power change is in progress.
*/
    unsigned long		previousRequest;


    /*! @field askingFor
Used by activityTickle so it doesn't try to raise the device to a lower state than
what it may have previously requested.
*/
    unsigned long		askingFor;		 


    /*! @field imminentState
Usually the same as myCurrentState, except right after calling powerStateWillChangeTo.
*/
    unsigned long		imminentState;

    /*! @function serialize
Serialize private instance variables for debug output (IORegistryDumper).
*/
    virtual bool serialize(OSSerialize *s) const;

};




/*!
@class IOPMprot : public OSObject
@abstract Protected power management instance variables for IOService objects.
*/
class IOPMprot : public OSObject //management
{
    friend class IOService;
    
    OSDeclareDefaultStructors(IOPMprot)

    public:

        /*! @field ourName			from getName(), used in logging */
    const char *		ourName;

    /*! @field thePlatform			from getPlatform, used in logging and registering */
    IOPlatformExpert * 	thePlatform;

    /*! @field theNumberOfPowerStates	the number of states in the array */
    unsigned long		theNumberOfPowerStates;			// the number of states in the array

    /*! @field thePowerStates		the array */
    IOPMPowerState	thePowerStates[IOPMMaxPowerStates];

    /*! @field theControllingDriver		points to the controlling driver */
    IOService * 		theControllingDriver;

    /*! @field aggressiveness		current value of power management aggressiveness */
    unsigned long		aggressiveness;

    /*! @field current_aggressiveness_values    array of aggressiveness values */
    unsigned long               current_aggressiveness_values [kMaxType+1];

    /*! @field current_aggressiveness_validity    true for values that are currently valid */
    bool	               current_aggressiveness_valid [kMaxType+1];

    /*! @field myCurrentState		the ordinal of our current power state */
    unsigned long		myCurrentState;

    /*! @field parentsKnowState	true if all our parents know the state of their power domain */
    bool		parentsKnowState;

    /*! @field parentsCurrentPowerFlags	logical OR of power flags for the current state of each power domainparent */
    IOPMPowerFlags	parentsCurrentPowerFlags;

    /*! @field maxCapability			ordinal of highest state we can achieve in current power domain state */
    unsigned long		maxCapability;

    /*! @field PMworkloop			points to the single power management workloop */
    IOWorkLoop *		PMworkloop;

    /*! @field commandQueue		used to serialize idle-power-down and busy-power-up */
    IOCommandQueue * 	commandQueue;

    /*! @field PMcommandGate		used to serialize timer expirations and incoming acknowledgements */
    IOCommandGate *	PMcommandGate;

    /*! @field myCharacterFlags		logical OR of all output power character flags in the array */
    IOPMPowerFlags  		myCharacterFlags;

    /*! @field serialNumber		used to uniquely identify power management notification to apps and clients */
    UInt16   serialNumber;

    /*! @field responseFlags		points to an OSArray which manages responses from notified apps and clients */
    OSArray* responseFlags;
    
    /*! @field doNotPowerDown		keeps track of any negative responses from notified apps and clients */
    bool	doNotPowerDown;
    
    /*! @function serialize
Serialize protected instance variables for debug output (IORegistryDumper).
*/
    virtual bool serialize(OSSerialize *s) const;

};

