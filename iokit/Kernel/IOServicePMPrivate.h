/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
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

#ifndef _IOKIT_IOSERVICEPMPRIVATE_H
#define _IOKIT_IOSERVICEPMPRIVATE_H

/* Binary compatibility with drivers that access pm_vars */
#define PM_VARS_SUPPORT     1

/*! @class IOServicePM
    @abstract Power management class.
*/
class IOServicePM : public OSObject
{
    friend class IOService;

    OSDeclareDefaultStructors( IOServicePM )

private:
    /*! @var Owner
        Points to object that called PMinit().  Used only for debugging.
    */
    IOService *             Owner;

    /*! @var InterestedDrivers
        List of interested drivers.
    */
    IOPMinformeeList *      InterestedDrivers;

    /*! @var DriverTimer
        How long to wait for controlling driver to acknowledge.
    */
    IOReturn                DriverTimer;

    /*! @var AckTimer */
    thread_call_t           AckTimer;

    /*! @var SettleTimer */
    thread_call_t           SettleTimer;

    /*! @var MachineState
        Current power management machine state.
    */
    unsigned long           MachineState;

    /*! @var SettleTimeUS
        Settle time after changing power state.
    */
    unsigned long           SettleTimeUS;

    /*! @var HeadNoteFlags
        The flags field for the current change note.
    */
    unsigned long           HeadNoteFlags;

    /*! @var HeadNoteState
        The newStateNumber field for the current change note.
    */
    unsigned long           HeadNoteState;

    /*! @var HeadNoteOutputFlags
        The outputPowerCharacter field for the current change note.
    */
    unsigned long           HeadNoteOutputFlags;

    /*! @var HeadNoteDomainState
        Power domain flags from parent. (only on parent change).
    */
    unsigned long           HeadNoteDomainState;

    /*! @var HeadNoteParent
        Pointer to initiating parent. (only on parent change).
    */
    IOPowerConnection *     HeadNoteParent;
    
    /*! @var HeadNoteCapabilityFlags
        The capabilityFlags field for the current change note.
    */
    unsigned long           HeadNoteCapabilityFlags;

    /*! @var HeadNotePendingAcks
        Number of acks we are waiting for.
    */
    unsigned long           HeadNotePendingAcks;

    /*! @var PMLock
        PM state lock.
    */
    IOLock	*               PMLock;

    /*! @var WeAreRoot
        True if our owner is the root of the power tree.
    */
    bool                    WeAreRoot;

    /*! @var InitialChange
        Initialized to true, then set to false after the initial power change.
    */
    bool                    InitialChange;

    /*! @var NeedToBecomeUsable
        Someone has called makeUsable before we had a controlling driver.
    */
    bool                    NeedToBecomeUsable;

    /*! @var DeviceOverrides
        Ignore children and driver desires if true.
    */
    bool                    DeviceOverrides;

    /*! @var ClampOn
        Domain is clamped on until the first power child is added.
    */
    bool                    ClampOn;

    /*! @var DeviceActive
        True if device was active since last idle timer expiration.
    */
    bool                    DeviceActive;

    /*! @var DoNotPowerDown
        Keeps track of any negative responses from notified apps and clients.
    */
    bool					DoNotPowerDown;

    /*! @var ParentsKnowState
        True if all our parents know the state of their power domain.
    */
    bool					ParentsKnowState;

    /*! @var DeviceActiveTimestamp
        Time of last device activity.
    */
    AbsoluteTime            DeviceActiveTimestamp;

    /*! @var ActivityLock
        Used to protect activity flag.
    */
    IOLock *                ActivityLock;

    /*! @var IdleTimerEventSource
        An idle timer event source.
    */
    IOTimerEventSource *    IdleTimerEventSource;

    /*! @var IdleTimerPeriod
        Idle timer's period in seconds.
    */
    unsigned long           IdleTimerPeriod;

    /*! @var DriverDesire
        Power state desired by our controlling driver.
    */
    unsigned long           DriverDesire;

    /*! @var DeviceDesire
        Power state desired by a subclassed device object.
    */
    unsigned long           DeviceDesire;

    /*! @var ChildrenDesire
        Power state desired by all children.
    */
    unsigned long           ChildrenDesire;

    /*! @var DesiredPowerState
        This is the power state we desire currently.
    */
    unsigned long           DesiredPowerState;

    /*! @var PreviousRequest
        This is what our parent thinks our need is.
    */
    unsigned long           PreviousRequest;

	/*! @var Name
		Cache result from getName(), used in logging.
	*/
    const char *            Name;

    /*! @var Platform
        Cache result from getPlatform(), used in logging and registering.
    */
    IOPlatformExpert *      Platform;

    /*! @var NumberOfPowerStates
        Number of power states in the power array.
    */
    unsigned long           NumberOfPowerStates;

    /*! @var PowerStates
        Power state array.
    */
    IOPMPowerState *		PowerStates;

    /*! @var ControllingDriver
        The controlling driver.
    */
    IOService *				ControllingDriver;

    /*! @var AggressivenessValues
        Array of aggressiveness values.
    */
    unsigned long			AggressivenessValue[ kMaxType + 1 ];

    /*! @var AggressivenessValid
        True for aggressiveness values that are currently valid.
    */
    bool					AggressivenessValid[ kMaxType + 1 ];

    /*! @var CurrentPowerState
        The ordinal of our current power state.
    */
    unsigned long			CurrentPowerState;

    /*! @var ParentsCurrentPowerFlags
        Logical OR of power flags for each power domain parent.
    */
    IOPMPowerFlags			ParentsCurrentPowerFlags;

    /*! @var MaxCapability
        Ordinal of highest power state we can achieve in current power domain.
    */
    unsigned long			MaxCapability;

    /*! @var OutputPowerCharacterFlags
        Logical OR of all output power character flags in the array.
    */
    IOPMPowerFlags			OutputPowerCharacterFlags;

    /*! @var SerialNumber
        Used to uniquely identify power management notification to apps and clients.
    */
    UInt16					SerialNumber;

    /*! @var ResponseArray
        OSArray which manages responses from notified apps and clients.
    */
    OSArray *				ResponseArray;

    /*! @var OutOfBandParameter
        Used to communicate desired function to tellClientsWithResponse().
        This is used because it avoids changing the signatures of the affected virtual methods. 
    */
    int						OutOfBandParameter;

    AbsoluteTime            DriverCallStartTime;
    IOPMPowerFlags          CurrentCapabilityFlags;
    unsigned long           CurrentPowerConsumption;
    unsigned long           TempClampPowerState;
    unsigned long           TempClampCount;
    IOPMWorkQueue *			PMWorkQueue;
    IOPMRequest *			PMRequest;
    OSSet *					InsertInterestSet;
    OSSet *					RemoveInterestSet;
    OSArray *				NotifyChildArray;
    unsigned long			WaitReason;
    unsigned long			NextMachineState;
    thread_call_t			DriverCallEntry;
    void *					DriverCallParamPtr;
    IOItemCount				DriverCallParamCount;
    IOItemCount				DriverCallParamSlots;
    IOOptionBits			DriverCallReason;
    long                    ActivityTicklePowerState;
    bool					StrictTreeOrder;
    bool					DriverCallBusy;
    bool					ActivityTimerStopped;
    bool					WillAdjustPowerState;
    bool					WillPMStop;

#if PM_VARS_SUPPORT
    IOPMprot *				PMVars;
#endif

    /*! @function serialize
        Serialize IOServicePM state for debug output.
    */
    virtual bool serialize( OSSerialize * s ) const;
};

#define fWeAreRoot                  pwrMgt->WeAreRoot
#define fInterestedDrivers          pwrMgt->InterestedDrivers
#define fDriverTimer                pwrMgt->DriverTimer
#define fAckTimer                   pwrMgt->AckTimer
#define fSettleTimer                pwrMgt->SettleTimer
#define fMachineState               pwrMgt->MachineState
#define fSettleTimeUS               pwrMgt->SettleTimeUS
#define fHeadNoteFlags              pwrMgt->HeadNoteFlags
#define fHeadNoteState              pwrMgt->HeadNoteState
#define fHeadNoteOutputFlags        pwrMgt->HeadNoteOutputFlags
#define fHeadNoteDomainState        pwrMgt->HeadNoteDomainState
#define fHeadNoteParent             pwrMgt->HeadNoteParent
#define fHeadNoteCapabilityFlags    pwrMgt->HeadNoteCapabilityFlags
#define fHeadNotePendingAcks        pwrMgt->HeadNotePendingAcks
#define fPMLock                     pwrMgt->PMLock
#define fInitialChange              pwrMgt->InitialChange
#define fNeedToBecomeUsable         pwrMgt->NeedToBecomeUsable
#define fDeviceOverrides            pwrMgt->DeviceOverrides
#define fClampOn                    pwrMgt->ClampOn
#define fOwner                      pwrMgt->Owner
#define fActivityLock               pwrMgt->ActivityLock
#define fIdleTimerEventSource       pwrMgt->IdleTimerEventSource
#define fIdleTimerPeriod            pwrMgt->IdleTimerPeriod
#define fDeviceActive               pwrMgt->DeviceActive
#define fDeviceActiveTimestamp      pwrMgt->DeviceActiveTimestamp
#define fDriverDesire               pwrMgt->DriverDesire
#define fDeviceDesire               pwrMgt->DeviceDesire
#define fChildrenDesire             pwrMgt->ChildrenDesire
#define fDesiredPowerState          pwrMgt->DesiredPowerState
#define fPreviousRequest            pwrMgt->PreviousRequest
#define fName                       pwrMgt->Name
#define fPlatform                   pwrMgt->Platform
#define fNumberOfPowerStates        pwrMgt->NumberOfPowerStates
#define fPowerStates                pwrMgt->PowerStates
#define fControllingDriver          pwrMgt->ControllingDriver
#define fAggressivenessValue        pwrMgt->AggressivenessValue
#define fAggressivenessValid        pwrMgt->AggressivenessValid
#define fCurrentPowerState          pwrMgt->CurrentPowerState
#define fParentsKnowState           pwrMgt->ParentsKnowState
#define fParentsCurrentPowerFlags   pwrMgt->ParentsCurrentPowerFlags
#define fMaxCapability              pwrMgt->MaxCapability
#define fOutputPowerCharacterFlags  pwrMgt->OutputPowerCharacterFlags
#define fSerialNumber               pwrMgt->SerialNumber
#define fResponseArray              pwrMgt->ResponseArray
#define fDoNotPowerDown             pwrMgt->DoNotPowerDown
#define fOutOfBandParameter         pwrMgt->OutOfBandParameter
#define fDriverCallStartTime        pwrMgt->DriverCallStartTime
#define fCurrentCapabilityFlags     pwrMgt->CurrentCapabilityFlags
#define fCurrentPowerConsumption    pwrMgt->CurrentPowerConsumption
#define fTempClampPowerState        pwrMgt->TempClampPowerState
#define fTempClampCount             pwrMgt->TempClampCount
#define fPMWorkQueue                pwrMgt->PMWorkQueue
#define fPMRequest                  pwrMgt->PMRequest
#define fWaitReason                 pwrMgt->WaitReason
#define fNextMachineState           pwrMgt->NextMachineState
#define fDriverCallReason           pwrMgt->DriverCallReason
#define fDriverCallEntry            pwrMgt->DriverCallEntry
#define fDriverCallParamPtr         pwrMgt->DriverCallParamPtr
#define fDriverCallParamCount       pwrMgt->DriverCallParamCount
#define fDriverCallParamSlots       pwrMgt->DriverCallParamSlots
#define fDriverCallBusy             pwrMgt->DriverCallBusy
#define fWillPMStop                 pwrMgt->WillPMStop
#define fActivityTickled            pwrMgt->ActivityTickled
#define fInsertInterestSet          pwrMgt->InsertInterestSet
#define fRemoveInterestSet          pwrMgt->RemoveInterestSet
#define fStrictTreeOrder            pwrMgt->StrictTreeOrder
#define fNotifyChildArray           pwrMgt->NotifyChildArray
#define fWillAdjustPowerState       pwrMgt->WillAdjustPowerState
#define fActivityTimerStopped       pwrMgt->ActivityTimerStopped
#define fActivityTicklePowerState   pwrMgt->ActivityTicklePowerState
#define fPMVars                     pwrMgt->PMVars

/*!
@defined ACK_TIMER_PERIOD
@discussion When an IOService is waiting for acknowledgement to a power change
notification from an interested driver or the controlling driver its ack timer
is ticking every tenth of a second.
(100000000 nanoseconds are one tenth of a second).
*/
#define ACK_TIMER_PERIOD 100000000

#define IOPMParentInitiated     1   // this power change initiated by our  parent
#define IOPMWeInitiated         2   // this power change initiated by this device
#define IOPMNotDone             4   // we couldn't make this change
#define IOPMNotInUse            8   // this list element not currently in use
#define IOPMDomainWillChange    16  // change started by PowerDomainWillChangeTo
#define IOPMDomainDidChange     32  // change started by PowerDomainDidChangeTo

struct changeNoteItem {
    unsigned long       flags;
    unsigned long       newStateNumber;
    IOPMPowerFlags      outputPowerCharacter;
    IOPMPowerFlags      inputPowerRequirement;
    IOPMPowerFlags      domainState;
    IOPowerConnection * parent;
    IOPMPowerFlags      singleParentState;
    IOPMPowerFlags      capabilityFlags;
};

enum {
    kDriverCallInformPreChange,
    kDriverCallInformPostChange,
    kDriverCallSetPowerState
};

struct DriverCallParam {
    OSObject *  Target;
    IOReturn    Result;
};

// values of outofbandparameter
enum {
    kNotifyApps,
    kNotifyPriority
};

// used for applyToInterested
struct context {
    OSArray *      responseFlags;
    UInt16         serialNumber;
    UInt16         counter;
    UInt32         maxTimeRequested;
    int            msgType;
    IOService *    us;
    unsigned long  stateNumber;
    IOPMPowerFlags stateFlags;
    const char * errorLog;
};

//*********************************************************************************
// PM command types
//*********************************************************************************

enum {
    /* Command Types */
    kIOPMRequestTypeInvalid                = 0x00,
    kIOPMRequestTypePMStop                 = 0x01,
    kIOPMRequestTypeAddPowerChild1         = 0x02,
    kIOPMRequestTypeAddPowerChild2         = 0x03,
    kIOPMRequestTypeAddPowerChild3         = 0x04,
    kIOPMRequestTypeRegisterPowerDriver    = 0x05,
    kIOPMRequestTypeAdjustPowerState       = 0x06,
    kIOPMRequestTypeMakeUsable             = 0x07,
    kIOPMRequestTypeTemporaryPowerClamp    = 0x08,
    kIOPMRequestTypePowerDomainWillChange  = 0x09,
    kIOPMRequestTypePowerDomainDidChange   = 0x0A,
    kIOPMRequestTypeChangePowerStateTo     = 0x0B,
    kIOPMRequestTypeChangePowerStateToPriv = 0x0C,
    kIOPMRequestTypePowerOverrideOnPriv    = 0x0D,
    kIOPMRequestTypePowerOverrideOffPriv   = 0x0E,
    kIOPMRequestTypeActivityTickle         = 0x0F,
    /* Reply Types */
    kIOPMRequestTypeReplyStart             = 0x80,
    kIOPMRequestTypeAckPowerChange         = 0x81,
    kIOPMRequestTypeAckSetPowerState       = 0x82,
    kIOPMRequestTypeAllowPowerChange       = 0x83,
    kIOPMRequestTypeCancelPowerChange      = 0x84,
    kIOPMRequestTypeInterestChanged        = 0x85
};

//*********************************************************************************
// PM Helper Classes
//*********************************************************************************

class IOPMRequest : public IOCommand
{
    OSDeclareDefaultStructors( IOPMRequest )

protected:
    IOOptionBits        fType;          // request type
    IOService *         fTarget;        // request target
    IOPMRequest *       fParent;        // parent request
    IOItemCount         fChildCount;    // wait if non-zero

public:
    void *              fArg0;
    void *              fArg1;
    void *              fArg2;

    inline bool         hasChildRequest( void ) const
    {
        return (fChildCount != 0);
    }

    inline bool         hasParentRequest( void ) const
    {
        return (fParent != 0);
    }

    inline void         setParentRequest( IOPMRequest * parent )
    {
        if (!fParent)
        {
            fParent = parent;
            fParent->fChildCount++;
        }
    }

    inline IOOptionBits getType( void ) const
    {
        return fType;
    }

    inline bool         isReply( void ) const
    {
        return (fType > kIOPMRequestTypeReplyStart);
    }

    inline IOService *  getTarget( void ) const
    {
        return fTarget;
    }

    static IOPMRequest *create( void );

    void    reset( void );

    bool    init( IOService * owner, IOOptionBits type );
};

class IOPMRequestQueue : public IOEventSource
{
    OSDeclareDefaultStructors( IOPMRequestQueue )

public:
    typedef bool (*Action)( IOService *, IOPMRequest *, IOPMRequestQueue * );

protected:
    queue_head_t    fQueue;
    IOLock *        fLock;

    virtual bool checkForWork( void );
    virtual void free( void );
    virtual bool init( IOService * inOwner, Action inAction );

public:
    static  IOPMRequestQueue * create( IOService * inOwner, Action inAction );
    void    queuePMRequest( IOPMRequest * request );
    void    queuePMRequestChain( IOPMRequest ** requests, IOItemCount count );
    void    signalWorkAvailable( void );
};

class IOPMWorkQueue : public IOEventSource
{
    OSDeclareDefaultStructors( IOPMWorkQueue )

public:
    typedef bool (*Action)( IOService *, IOPMRequest *, IOPMWorkQueue * );

protected:
    queue_head_t    fWorkQueue;
    Action          fWorkAction;
    Action          fRetireAction;

    virtual bool checkForWork( void );
    virtual bool init( IOService * inOwner, Action work, Action retire );

public:
    static IOPMWorkQueue * create( IOService * inOwner, Action work, Action retire );
    void   queuePMRequest( IOPMRequest * request );
};

#endif /* !_IOKIT_IOSERVICEPMPRIVATE_H */
