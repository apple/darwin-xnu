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
@class IOPMpriv
@abstract Private power management private instance variables for IOService objects.
*/
class IOPMpriv : public OSObject
{
    friend class IOService;

    OSDeclareDefaultStructors(IOPMpriv)

    public:

/*! @var we_are_root 
    TRUE if this device is the root power domain.
*/
    bool			we_are_root;
    
    /*! @var interestedDrivers 
        List of interested drivers.
    */
    IOPMinformeeList *	interestedDrivers;
    
    /*! @var children
        List of power domain children.
    */
    IOPMinformeeList *	children;
    
    /*! @var changeList
        List of pending power state changes.
    */
    IOPMchangeNoteList *	changeList;
    
    /*! @var driver_timer
        Timeout on waiting for controlling driver to acknowledgeSetPowerState.
    */
    IOReturn			driver_timer;
    
    /*! @var ackTimer									*/
    thread_call_t		ackTimer;

    /*! @var settleTimer								*/
    thread_call_t		settleTimer;

    /*! @var machine_state
        State number of state machine processing current change note.
    */
    unsigned long		machine_state;
    
    /*! @var settle_time
        Settle timer after changing power state.
    */
    unsigned long		settle_time;
    
    /*! @var head_note
        Ordinal of change note currently being processed.
    */
    long			head_note;
    
    /*! @var head_note_flags
        Copy of flags field in change note currently being processed.
    */
    unsigned long		head_note_flags;

    /*! @var head_note_state
        Copy of newStateNumberfield in change note currently being  processed.
    */
    unsigned long		head_note_state;

    /*! @var head_note_outputFlags
    OutputPowerCharacter field from change note currently being processed.
    */
    unsigned long		head_note_outputFlags;

    /*! @var head_note_domainState
    Power domain flags from parent... (only on parent change).
    */
    unsigned long		head_note_domainState;

    /*! @var head_note_parent
        Pointer to initiating parent... (only on parent change).
    */
    IOPowerConnection * 	head_note_parent;
    
    /*! @var head_note_capabilityFlags
        Copy of capabilityFlags field in change note currently being processed.
    */
    unsigned long		head_note_capabilityFlags;

    /*! @var head_note_pendingAcks
        Number of acks we are waiting for during notification.
    */
    unsigned long		head_note_pendingAcks;

    /*! @var our_lock
        Used to control access to head_note_pendingAcks and driver_timer.
    */
    IOLock	*		our_lock;

    /*! @var flags_lock
        Used to control access to response flags array.
    */
    IOLock	*		flags_lock;

    /*! @var queue_lock
        Used to control access to change note queue.
    */
    IOLock	*		queue_lock;

    /*! @var initial_change
        True forces first state to be broadcast even if it isn't a change.
    */
    bool			initial_change;

    /*! @var need_to_become_usable
        Someone called makeUsable before we had a controlling driver.
    */
    bool			need_to_become_usable;

    /*! @var device_overrides
        State changes are made based only on subclass's desire.
    */
    bool			device_overrides;

    /*! @var clampOn
        Domain is clamped on till first child registers.
    */
    bool			clampOn;

    /*! @var owner
        Points to object which made this struct.  Used for debug output only.
    */
    IOService * 		owner;

    /*! @var activityLock
        Used to protect activity flag.
    */
    IOLock *		activityLock;

    /*! @var timerEventSrc
        An idle timer.
    */
    IOTimerEventSource * 	timerEventSrc;

    /*! @var idle_timer_period
        Timer's period in seconds.
    */
    unsigned long		idle_timer_period;
   
    /*! @var clampTimerEventSrc
        Timer for clamping power on.
    */
    IOTimerEventSource *        clampTimerEventSrc;

    /*! @var device_active
        True: there has been device activity since last idle timer expiration.
    */
    bool			device_active;

    /*! @var device_active_timestamp
        Time in ticks of last activity.
    */
    AbsoluteTime                device_active_timestamp;

    /*! @var driverDesire
    This is the power state desired by our controlling driver.  It is initialized to myCurrentState and is changed
    when the controlling driver calls changePowerStateTo.   A change in driverDesire may cause a change in ourDesiredPowerState.
*/
    unsigned long		driverDesire;



    /*! @var deviceDesire
    This is the power state desired by a subclassed device object.  It is initialized to myCurrentState and is changed when the subclassed object calls changePowerStateToPriv.  A change in deviceDesire may cause a change in ourDesiredPowerState.
*/
    unsigned long		deviceDesire;



    /*! @var ourDesiredPowerState
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


    /*! @var previousRequest
This is a reminder of what our parent thinks our need is.  Whenever it changes,
we call requestDomainState in the parent to keep it current.  It is usually equal to ourDesiredPowerState
except while a power change is in progress.
*/
    unsigned long		previousRequest;


    /*! @var askingFor
        Not used.
*/
    unsigned long		askingFor;		 


    /*! @var imminentState
        Usually the same as myCurrentState, except right after calling powerStateWillChangeTo.
*/
    unsigned long		imminentState;

    /*! @function serialize
        Serialize private instance variables for debug output (IORegistryDumper).
*/
    virtual bool serialize(OSSerialize *s) const;

};




/*!
@class IOPMprott
@abstract Protected power management instance variables for IOService objects.
*/
class IOPMprot : public OSObject //management
{
    friend class IOService;
    
    OSDeclareDefaultStructors(IOPMprot)

    public:

        /*! @var ourName
            From getName(), used in logging.
        */
    const char *		ourName;

    /*! @var thePlatform
        From getPlatform, used in logging and registering.
    */
    IOPlatformExpert * 	thePlatform;

    /*! @var theNumberOfPowerStates
        The number of states in the array.
    */
    unsigned long		theNumberOfPowerStates;			// the number of states in the array

    /*! @var thePowerStates
        The array.
    */
    IOPMPowerState	thePowerStates[IOPMMaxPowerStates];

    /*! @var theControllingDriver
        Points to the controlling driver.
    */
    IOService * 		theControllingDriver;

    /*! @var aggressiveness
        Current value of power management aggressiveness.
    */
    unsigned long		aggressiveness;

    /*! @var current_aggressiveness_values
        Array of aggressiveness values.
    */
    unsigned long               current_aggressiveness_values [kMaxType+1];

    /*! @var current_aggressiveness_validity
        True for values that are currently valid.
    */
    bool	               current_aggressiveness_valid [kMaxType+1];

    /*! @var myCurrentState
        The ordinal of our current power state.
    */
    unsigned long		myCurrentState;

    /*! @var parentsKnowState
        True if all our parents know the state of their power domain.
    */
    bool		parentsKnowState;

    /*! @var parentsCurrentPowerFlags
        Logical OR of power flags for the current state of each power domainparent.
    */
    IOPMPowerFlags	parentsCurrentPowerFlags;

    /*! @var maxCapability
        Ordinal of highest state we can achieve in current power domain state.
    */
    unsigned long		maxCapability;

    /*! @var PMworkloop
        Points to the single power management workloop.
    */
    IOWorkLoop *		PMworkloop;

    /*! @var commandQueue
        Used to serialize idle-power-down and busy-power-up.
    */
    IOCommandQueue * 	commandQueue;

    /*! @var PMcommandGate
        Used to serialize timer expirations and incoming acknowledgements.
    */
    IOCommandGate *	PMcommandGate;

    /*! @var myCharacterFlags
        Logical OR of all output power character flags in the array.
    */
    IOPMPowerFlags  		myCharacterFlags;

    /*! @var serialNumber
        Used to uniquely identify power management notification to apps and clients.
    */
    UInt16   serialNumber;

    /*! @var responseFlags
        Points to an OSArray which manages responses from notified apps and clients.
    */
    OSArray* responseFlags;
    
    /*! @var doNotPowerDown
        Keeps track of any negative responses from notified apps and clients.
    */
    bool	doNotPowerDown;
    
    /*! @var childLock
        Used to serialize scanning the children.
    */
    IOLock	*		childLock;

    /*! @var parentLock
        Used to serialize scanning the parents.
    */
    IOLock	*		parentLock;

    /*! @var outofbandparameter
        Used to communicate desired function to tellClientsWithResponse().
        This is used because it avoids changing the signatures of the affected virtual methods. 
    */
    int				outofbandparameter;

    /*! @function serialize
Serialize protected instance variables for debug output (IORegistryDumper).
*/
    virtual bool serialize(OSSerialize *s) const;

};

