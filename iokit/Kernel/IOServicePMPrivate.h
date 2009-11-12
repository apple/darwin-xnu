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

/*! @class IOServicePM
    @abstract Power management class.
*/
class IOServicePM : public OSObject
{
    friend class IOService;

    OSDeclareDefaultStructors( IOServicePM )

private:
    // List of interested drivers.
    IOPMinformeeList *      InterestedDrivers;

    // How long to wait for controlling driver to acknowledge.
    IOReturn                DriverTimer;

    // Current power management machine state.
    uint32_t                MachineState;

    thread_call_t           AckTimer;
    thread_call_t           SettleTimer;

    // Settle time after changing power state.
    unsigned long           SettleTimeUS;

    // The flags describing current change note.
    unsigned long           HeadNoteFlags;

    // The new power state number being changed to.
    unsigned long           HeadNotePowerState;

    // Points to the entry in the power state array.
    IOPMPowerState *        HeadNotePowerArrayEntry;

    // Power flags supplied by all parents (domain).
    unsigned long           HeadNoteDomainFlags;

    // Power flags supplied by domain accounting for parent changes.
    IOPMPowerFlags          HeadNoteDomainTargetFlags;

    // Connection attached to the changing parent.
    IOPowerConnection *     HeadNoteParentConnection;
    
    // Power flags supplied by the changing parent.
    unsigned long           HeadNoteParentFlags;

    // Number of acks still outstanding.
    unsigned long           HeadNotePendingAcks;

    // PM state lock.
    IOLock	*               PMLock;

    // Initialized to true, then set to false after the initial power change.
    bool                    InitialChange;

    // Ignore children and driver desires if true.
    bool                    DeviceOverrides;

    // True if device was active since last idle timer expiration.
    bool                    DeviceActive;

    // Keeps track of any negative responses from notified apps and clients.
    bool					DoNotPowerDown;

    // True if all our parents know the state of their power domain.
    bool					ParentsKnowState;

    bool					StrictTreeOrder;
    bool					IdleTimerStopped;
	bool					AdjustPowerScheduled;

    // Time of last device activity.
    AbsoluteTime            DeviceActiveTimestamp;

    // Used to protect activity flag.
    IOLock *                ActivityLock;

    // Idle timer event source.
    IOTimerEventSource *    IdleTimerEventSource;

    // Idle timer's period in seconds.
    unsigned long           IdleTimerPeriod;
    unsigned long           IdleTimerMinPowerState;
    AbsoluteTime            IdleTimerStartTime;

    // Power state desired by a subclassed device object.
    unsigned long           DeviceDesire;

    // This is the power state we desire currently.
    unsigned long           DesiredPowerState;

    // This is what our parent thinks our need is.
    unsigned long           PreviousRequest;

    // Cache result from getName(), used in logging.
    const char *            Name;

    // Number of power states in the power array.
    unsigned long           NumberOfPowerStates;

    // Power state array.
    IOPMPowerState *		PowerStates;

    // The controlling driver.
    IOService *				ControllingDriver;

    // Our current power state.
    unsigned long			CurrentPowerState;

    // Logical OR of power flags for each power domain parent.
    IOPMPowerFlags			ParentsCurrentPowerFlags;

    // The highest power state we can achieve in current power domain.
    unsigned long			MaxCapability;

    // Logical OR of all output power character flags in the array.
    IOPMPowerFlags			OutputPowerCharacterFlags;

    // OSArray which manages responses from notified apps and clients.
    OSArray *				ResponseArray;
    OSArray *               NotifyClientArray;

    // Used to uniquely identify power management notification to apps and clients.
    UInt16					SerialNumber;

    // Used to communicate desired function to tellClientsWithResponse().
    // This is used because it avoids changing the signatures of the affected virtual methods.
    int						OutOfBandParameter;

    AbsoluteTime            DriverCallStartTime;
    IOPMPowerFlags          CurrentCapabilityFlags;
    long                    ActivityTicklePowerState;
    unsigned long           CurrentPowerConsumption;
    unsigned long           TempClampPowerState;
    IOPMWorkQueue *			PMWorkQueue;
    OSSet *					InsertInterestSet;
    OSSet *					RemoveInterestSet;
    OSArray *				NotifyChildArray;
    OSDictionary *          PowerClients;
    thread_call_t			DriverCallEntry;
    void *					DriverCallParamPtr;
    IOItemCount				DriverCallParamCount;
    IOItemCount				DriverCallParamSlots;
    uint32_t                DriverCallReason;
    uint32_t                TempClampCount;
    uint32_t                OverrideMaxPowerState;
    uint32_t                ActivityTickleCount;
    uint32_t                WaitReason;
    uint32_t                NextMachineState;
    uint32_t                RootDomainState;
    uint32_t                ThreadAssertionCount;

    // Protected by PMLock
    struct {
        uint32_t            DriverCallBusy : 1;
        uint32_t            PMStop         : 1;
    } LockedFlags;

    thread_t                ThreadAssertionThread;

#if PM_VARS_SUPPORT
    IOPMprot *				PMVars;
#endif

    // Serialize IOServicePM state for debug output.
    IOReturn gatedSerialize( OSSerialize * s );
    virtual bool serialize( OSSerialize * s ) const;
};

#define fInterestedDrivers          pwrMgt->InterestedDrivers
#define fDriverTimer                pwrMgt->DriverTimer
#define fAckTimer                   pwrMgt->AckTimer
#define fSettleTimer                pwrMgt->SettleTimer
#define fMachineState               pwrMgt->MachineState
#define fSettleTimeUS               pwrMgt->SettleTimeUS
#define fHeadNoteFlags              pwrMgt->HeadNoteFlags
#define fHeadNotePowerState         pwrMgt->HeadNotePowerState
#define fHeadNotePowerArrayEntry    pwrMgt->HeadNotePowerArrayEntry
#define fHeadNoteDomainFlags        pwrMgt->HeadNoteDomainFlags
#define fHeadNoteDomainTargetFlags  pwrMgt->HeadNoteDomainTargetFlags
#define fHeadNoteParentConnection   pwrMgt->HeadNoteParentConnection
#define fHeadNoteParentFlags        pwrMgt->HeadNoteParentFlags
#define fHeadNotePendingAcks        pwrMgt->HeadNotePendingAcks
#define fPMLock                     pwrMgt->PMLock
#define fInitialChange              pwrMgt->InitialChange
#define fDeviceOverrides            pwrMgt->DeviceOverrides
#define fActivityLock               pwrMgt->ActivityLock
#define fIdleTimerEventSource       pwrMgt->IdleTimerEventSource
#define fIdleTimerPeriod            pwrMgt->IdleTimerPeriod
#define fIdleTimerMinPowerState     pwrMgt->IdleTimerMinPowerState
#define fDeviceActive               pwrMgt->DeviceActive
#define fIdleTimerStartTime         pwrMgt->IdleTimerStartTime
#define fDeviceActiveTimestamp      pwrMgt->DeviceActiveTimestamp
#define fActivityTickleCount        pwrMgt->ActivityTickleCount
#define fDeviceDesire               pwrMgt->DeviceDesire
#define fDesiredPowerState          pwrMgt->DesiredPowerState
#define fPreviousRequest            pwrMgt->PreviousRequest
#define fName                       pwrMgt->Name
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
#define fNotifyClientArray          pwrMgt->NotifyClientArray
#define fDoNotPowerDown             pwrMgt->DoNotPowerDown
#define fOutOfBandParameter         pwrMgt->OutOfBandParameter
#define fDriverCallStartTime        pwrMgt->DriverCallStartTime
#define fCurrentCapabilityFlags     pwrMgt->CurrentCapabilityFlags
#define fCurrentPowerConsumption    pwrMgt->CurrentPowerConsumption
#define fTempClampPowerState        pwrMgt->TempClampPowerState
#define fTempClampCount             pwrMgt->TempClampCount
#define fOverrideMaxPowerState      pwrMgt->OverrideMaxPowerState
#define fPMWorkQueue                pwrMgt->PMWorkQueue
#define fWaitReason                 pwrMgt->WaitReason
#define fNextMachineState           pwrMgt->NextMachineState
#define fDriverCallReason           pwrMgt->DriverCallReason
#define fDriverCallEntry            pwrMgt->DriverCallEntry
#define fDriverCallParamPtr         pwrMgt->DriverCallParamPtr
#define fDriverCallParamCount       pwrMgt->DriverCallParamCount
#define fDriverCallParamSlots       pwrMgt->DriverCallParamSlots
#define fActivityTickled            pwrMgt->ActivityTickled
#define fInsertInterestSet          pwrMgt->InsertInterestSet
#define fRemoveInterestSet          pwrMgt->RemoveInterestSet
#define fStrictTreeOrder            pwrMgt->StrictTreeOrder
#define fNotifyChildArray           pwrMgt->NotifyChildArray
#define fIdleTimerStopped           pwrMgt->IdleTimerStopped
#define fAdjustPowerScheduled       pwrMgt->AdjustPowerScheduled
#define fActivityTicklePowerState   pwrMgt->ActivityTicklePowerState
#define fPMVars                     pwrMgt->PMVars
#define fPowerClients               pwrMgt->PowerClients
#define fRootDomainState            pwrMgt->RootDomainState
#define fThreadAssertionCount       pwrMgt->ThreadAssertionCount
#define fThreadAssertionThread      pwrMgt->ThreadAssertionThread
#define fLockedFlags                pwrMgt->LockedFlags

/*
When an IOService is waiting for acknowledgement to a power change
notification from an interested driver or the controlling driver,
the ack timer is ticking every tenth of a second.
(100000000 nanoseconds are one tenth of a second).
*/
#define ACK_TIMER_PERIOD            100000000

#define kIOPMParentInitiated        0x01    // this power change initiated by our  parent
#define kIOPMWeInitiated            0x02    // this power change initiated by this device
#define kIOPMNotDone                0x04    // we couldn't make this change
#define kIOPMDomainWillChange       0x08    // change started by PowerDomainWillChangeTo
#define kIOPMDomainDidChange        0x10    // change started by PowerDomainDidChangeTo
#define kIOPMDomainPowerDrop        0x20    // Domain is lowering power
#define kIOPMSynchronize            0x40    // change triggered by power tree re-sync

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

typedef bool (*IOPMMessageFilter)(OSObject * object, void * context);

// used for applyToInterested
struct IOPMInterestContext {
    OSArray *           responseFlags;
    OSArray *           notifyClients;
    UInt16              serialNumber;
    UInt16              counter;
    UInt32              maxTimeRequested;
    int                 msgType;
    IOService *         us;
    unsigned long       stateNumber;
    IOPMPowerFlags      stateFlags;
    const char *        errorLog;
    IOPMMessageFilter   filterFunc;
};

//*********************************************************************************
// PM Statistics & Diagnostics
//*********************************************************************************

extern const OSSymbol *gIOPMStatsApplicationResponseTimedOut;
extern const OSSymbol *gIOPMStatsApplicationResponseCancel;
extern const OSSymbol *gIOPMStatsApplicationResponseSlow;

//*********************************************************************************
// PM command types
//*********************************************************************************

enum {
    /* Command Types */
    kIOPMRequestTypeInvalid                     = 0x00,
    kIOPMRequestTypePMStop                      = 0x01,
    kIOPMRequestTypeAddPowerChild1              = 0x02,
    kIOPMRequestTypeAddPowerChild2              = 0x03,
    kIOPMRequestTypeAddPowerChild3              = 0x04,
    kIOPMRequestTypeRegisterPowerDriver         = 0x05,
    kIOPMRequestTypeAdjustPowerState            = 0x06,
    kIOPMRequestTypePowerDomainWillChange       = 0x07,
    kIOPMRequestTypePowerDomainDidChange        = 0x08,
    kIOPMRequestTypePowerOverrideOnPriv         = 0x09,
    kIOPMRequestTypePowerOverrideOffPriv        = 0x0A,
    kIOPMRequestTypeActivityTickle              = 0x0B,
    kIOPMRequestTypeRequestPowerState           = 0x0C,
    kIOPMRequestTypeSynchronizePowerTree        = 0x0D,
    kIOPMRequestTypeRequestPowerStateOverride   = 0x0E,
    kIOPMRequestTypeSetIdleTimerPeriod          = 0x0F,

    /* Reply Types */
    kIOPMRequestTypeReplyStart                  = 0x80,
    kIOPMRequestTypeAckPowerChange              = 0x81,
    kIOPMRequestTypeAckSetPowerState            = 0x82,
    kIOPMRequestTypeAllowPowerChange            = 0x83,
    kIOPMRequestTypeCancelPowerChange           = 0x84,
    kIOPMRequestTypeInterestChanged             = 0x85,
    kIOPMRequestTypeIdleCancel                  = 0x86
};

//*********************************************************************************
// IOServicePM internal helper classes
//*********************************************************************************

typedef void (*IOPMCompletionAction)(void * target, void * param, IOReturn status);

class IOPMRequest : public IOCommand
{
    OSDeclareDefaultStructors( IOPMRequest )

protected:
    IOService *          fTarget;        // request target
    IOPMRequest *        fRequestNext;   // the next request in the chain
    IOPMRequest *        fRequestRoot;   // the root request in the issue tree
    IOItemCount          fWorkWaitCount; // execution blocked if non-zero
    IOItemCount          fFreeWaitCount; // completion blocked if non-zero
    uint32_t             fType;          // request type

    IOPMCompletionAction fCompletionAction;
    void *               fCompletionTarget;
    void *               fCompletionParam;
    IOReturn             fCompletionStatus;

public:
    void *               fArg0;
    void *               fArg1;
    void *               fArg2;

    inline bool          isWorkBlocked( void ) const
    {
        return (fWorkWaitCount != 0);
    }

    inline bool          isFreeBlocked( void ) const
    {
        return (fFreeWaitCount != 0);
    }

    inline IOPMRequest * getNextRequest( void ) const
    {
        return fRequestNext;
    }

    inline IOPMRequest * getRootRequest( void ) const
    {
        if (fRequestRoot) return fRequestRoot;
        if (fCompletionAction) return (IOPMRequest *) this;
        return 0;
    }

    inline uint32_t      getType( void ) const
    {
        return fType;
    }

    inline bool          isReplyType( void ) const
    {
        return (fType > kIOPMRequestTypeReplyStart);
    }

    inline IOService *   getTarget( void ) const
    {
        return fTarget;
    }

    inline bool          isCompletionInstalled( void )
    {
        return (fCompletionAction != 0);
    }

    inline void          installCompletionAction(
                            IOPMCompletionAction action,
                            void *               target,
                            void *               param )
    {
        fCompletionAction = action;
        fCompletionTarget = target;
        fCompletionParam  = param;
    }

    static IOPMRequest * create( void );
    bool   init( IOService * owner, IOOptionBits type );
    void   reset( void );
    void   attachNextRequest( IOPMRequest * next );
    void   detachNextRequest( void );
    void   attachRootRequest( IOPMRequest * root );
    void   detachRootRequest( void );
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
    static  IOPMWorkQueue * create( IOService * inOwner, Action work, Action retire );
    void    queuePMRequest( IOPMRequest * request );
};

class IOPMCompletionQueue : public IOEventSource
{
    OSDeclareDefaultStructors( IOPMCompletionQueue )

public:
    typedef bool (*Action)( IOService *, IOPMRequest *, IOPMCompletionQueue * );

protected:
    queue_head_t    fQueue;

    virtual bool checkForWork( void );
    virtual bool init( IOService * inOwner, Action inAction );

public:
    static  IOPMCompletionQueue * create( IOService * inOwner, Action inAction );
    void    queuePMRequest( IOPMRequest * request );
};

#endif /* !_IOKIT_IOSERVICEPMPRIVATE_H */
