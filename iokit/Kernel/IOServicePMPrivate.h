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

#include <IOKit/IOCommand.h>
#include <IOKit/IOEventSource.h>

//******************************************************************************
// PM command types
//******************************************************************************

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
    kIOPMRequestTypeIdleCancel                  = 0x86,
    kIOPMRequestTypeChildNotifyDelayCancel      = 0x87
};

//******************************************************************************
// PM actions - For root domain only
//******************************************************************************

struct IOPMActions;

typedef void
(*IOPMActionPowerChangeStart)(
    void *          target,
    IOService *     service,
    IOPMActions *   actions, 
    uint32_t        powerState,
    uint32_t *      changeFlags );

typedef void
(*IOPMActionPowerChangeDone)(
    void *          target,
    IOService *     service,
    IOPMActions *   actions, 
    uint32_t        powerState,
    uint32_t        changeFlags );

typedef void
(*IOPMActionPowerChangeOverride)(
    void *          target,
    IOService *     service,
    IOPMActions *   actions, 
    unsigned long * powerState,
    uint32_t *      changeFlags );

typedef void
(*IOPMActionActivityTickle)(
    void *          target,
    IOService *     service,
    IOPMActions *   actions );

struct IOPMActions {
    void *                          target;
    uint32_t                        parameter;
    IOPMActionPowerChangeStart      actionPowerChangeStart;
    IOPMActionPowerChangeDone       actionPowerChangeDone;
    IOPMActionPowerChangeOverride   actionPowerChangeOverride;
    IOPMActionActivityTickle        actionActivityTickle;
};

//******************************************************************************

enum {
	kIOPMEventClassSystemEvent			= 0x00,
	kIOPMEventClassDriverEvent			= 0x1
};

class PMEventDetails : public OSObject 
{
    OSDeclareDefaultStructors( PMEventDetails );
    friend class IOServicePM;
    friend class IOPMrootDomain;
    friend class IOPMTimeline;
public:  
  static PMEventDetails *eventDetails(uint32_t   type,
                                      const char *ownerName,
                                      uintptr_t  ownerUnique,
                                      const char *interestName,
                                      uint8_t    oldState,
                                      uint8_t    newState,
                                      uint32_t   result,
                                      uint32_t   elapsedTimeUS);

  static PMEventDetails *eventDetails(uint32_t   type,
                                      const char *uuid,
                                      uint32_t   reason,
                                      uint32_t   result);
private:
  uint8_t		  eventClassifier;
  uint32_t        eventType;
  const char      *ownerName;
  uintptr_t       ownerUnique;
  const char      *interestName;
  uint8_t         oldState;
  uint8_t         newState;
  uint32_t        result;
  uint32_t        elapsedTimeUS;
  
  const char      *uuid;
  uint32_t        reason;
};

// Internal concise representation of IOPMPowerState
struct IOPMPSEntry
{
    IOPMPowerFlags	capabilityFlags;
    IOPMPowerFlags	outputPowerFlags;
    IOPMPowerFlags	inputPowerFlags;
    uint32_t        staticPower;
    uint32_t        settleUpTime;
    uint32_t        settleDownTime;
};

//******************************************************************************
// IOServicePM
//******************************************************************************

class IOServicePM : public OSObject
{
    friend class IOService;
    friend class IOPMWorkQueue;

    OSDeclareDefaultStructors( IOServicePM )

private:
    // Link IOServicePM objects on IOPMWorkQueue.
    queue_chain_t           WorkChain;
    
    // Queue of IOPMRequest objects.
    queue_head_t            RequestHead;

    // IOService creator and owner.
    IOService *             Owner;

    // List of interested drivers (protected by PMLock).
    IOPMinformeeList *      InterestedDrivers;

    // How long to wait for controlling driver to acknowledge.
    IOReturn                DriverTimer;

    // Current power management machine state.
    uint32_t                MachineState;

    thread_call_t           AckTimer;
    thread_call_t           SettleTimer;
    thread_call_t           IdleTimer;

    // Settle time after changing power state.
    uint32_t                SettleTimeUS;

    // The flags describing current change note.
    IOPMPowerChangeFlags    HeadNoteChangeFlags;

    // The new power state number being changed to.
    IOPMPowerStateIndex     HeadNotePowerState;

    // Points to the entry in the power state array.
    IOPMPSEntry *           HeadNotePowerArrayEntry;

    // Power flags supplied by all parents (domain).
    IOPMPowerFlags          HeadNoteDomainFlags;

    // Power flags supplied by domain accounting for parent changes.
    IOPMPowerFlags          HeadNoteDomainTargetFlags;

    // Connection attached to the changing parent.
    IOPowerConnection *     HeadNoteParentConnection;
    
    // Power flags supplied by the changing parent.
    IOPMPowerFlags          HeadNoteParentFlags;

    // Number of acks still outstanding.
    uint32_t                HeadNotePendingAcks;

    // PM state lock.
    IOLock *                PMLock;

    unsigned int            InitialPowerChange:1;
    unsigned int            InitialSetPowerState:1;
    unsigned int            DeviceOverrideEnabled:1;
    unsigned int            DeviceWasActive:1;
    unsigned int            DoNotPowerDown:1;
    unsigned int            ParentsKnowState:1;
    unsigned int            StrictTreeOrder:1;
    unsigned int            IdleTimerStopped:1;
    unsigned int            AdjustPowerScheduled:1;
    unsigned int            IsPreChange:1;
    unsigned int            DriverCallBusy:1;
    unsigned int            PCDFunctionOverride:1;

    // Time of last device activity.
    AbsoluteTime            DeviceActiveTimestamp;

    // Used to protect activity flag.
    IOLock *                ActivityLock;

    // Idle timer's period in seconds.
    unsigned long           IdleTimerPeriod;
    unsigned long           IdleTimerMinPowerState;
    AbsoluteTime            IdleTimerStartTime;

    // Power state desired by a subclassed device object.
    IOPMPowerStateIndex     DeviceDesire;

    // This is the power state we desire currently.
    IOPMPowerStateIndex     DesiredPowerState;

    // This is what our parent thinks our need is.
    IOPMPowerFlags          PreviousRequestPowerFlags;

    // Cache result from getName(), used in logging.
    const char *            Name;

    // Number of power states in the power array.
    IOPMPowerStateIndex     NumberOfPowerStates;

    // Power state array.
    IOPMPSEntry *           PowerStates;

    // The controlling driver.
    IOService *             ControllingDriver;

    // Our current power state.
    IOPMPowerStateIndex     CurrentPowerState;

    // Logical OR of power flags for each power domain parent.
    IOPMPowerFlags          ParentsCurrentPowerFlags;

    // The highest power state we can achieve in current power domain.
    IOPMPowerStateIndex     MaxPowerState;

    // Logical OR of all output power character flags in the array.
    IOPMPowerFlags          OutputPowerCharacterFlags;

    // OSArray which manages responses from notified apps and clients.
    OSArray *               ResponseArray;
    OSArray *               NotifyClientArray;

    // Used to uniquely identify power management notification to apps and clients.
    UInt16                  SerialNumber;

    // Used to communicate desired function to tellClientsWithResponse().
    // This is used because it avoids changing the signatures of the affected virtual methods.
    int                     OutOfBandParameter;

    AbsoluteTime            DriverCallStartTime;
    IOPMPowerFlags          CurrentCapabilityFlags;
    long                    ActivityTicklePowerState;
    unsigned long           CurrentPowerConsumption;
    IOPMPowerStateIndex     TempClampPowerState;
    OSArray *               NotifyChildArray;
    OSDictionary *          PowerClients;
    thread_call_t           DriverCallEntry;
    void *                  DriverCallParamPtr;
    IOItemCount             DriverCallParamCount;
    IOItemCount             DriverCallParamSlots;
    uint32_t                DriverCallReason;
    uint32_t                OutOfBandMessage;
    uint32_t                TempClampCount;
    uint32_t                OverrideMaxPowerState;
    uint32_t                ActivityTickleCount;
    uint32_t                WaitReason;
    uint32_t                SavedMachineState;
    uint32_t                RootDomainState;

    // Protected by PMLock - BEGIN
    struct {
        uint32_t            PMStop              : 1;
        uint32_t            PMDriverCallWait    : 1;
    } LockedFlags;

    queue_head_t            PMDriverCallQueue;
    OSSet *                 InsertInterestSet;
    OSSet *                 RemoveInterestSet;
    // Protected by PMLock - END

#if PM_VARS_SUPPORT
    IOPMprot *              PMVars;
#endif

    IOPMActions             PMActions;

    // Serialize IOServicePM state for debug output.
    IOReturn gatedSerialize( OSSerialize * s );
    virtual bool serialize( OSSerialize * s ) const;
};

#define fOwner                      pwrMgt->Owner
#define fInterestedDrivers          pwrMgt->InterestedDrivers
#define fDriverTimer                pwrMgt->DriverTimer
#define fMachineState               pwrMgt->MachineState
#define fAckTimer                   pwrMgt->AckTimer
#define fSettleTimer                pwrMgt->SettleTimer
#define fIdleTimer                  pwrMgt->IdleTimer
#define fSettleTimeUS               pwrMgt->SettleTimeUS
#define fHeadNoteChangeFlags        pwrMgt->HeadNoteChangeFlags
#define fHeadNotePowerState         pwrMgt->HeadNotePowerState
#define fHeadNotePowerArrayEntry    pwrMgt->HeadNotePowerArrayEntry
#define fHeadNoteDomainFlags        pwrMgt->HeadNoteDomainFlags
#define fHeadNoteDomainTargetFlags  pwrMgt->HeadNoteDomainTargetFlags
#define fHeadNoteParentConnection   pwrMgt->HeadNoteParentConnection
#define fHeadNoteParentFlags        pwrMgt->HeadNoteParentFlags
#define fHeadNotePendingAcks        pwrMgt->HeadNotePendingAcks
#define fPMLock                     pwrMgt->PMLock
#define fInitialPowerChange         pwrMgt->InitialPowerChange
#define fInitialSetPowerState       pwrMgt->InitialSetPowerState
#define fDeviceOverrideEnabled      pwrMgt->DeviceOverrideEnabled
#define fDeviceWasActive            pwrMgt->DeviceWasActive
#define fDoNotPowerDown             pwrMgt->DoNotPowerDown
#define fParentsKnowState           pwrMgt->ParentsKnowState
#define fStrictTreeOrder            pwrMgt->StrictTreeOrder
#define fIdleTimerStopped           pwrMgt->IdleTimerStopped
#define fAdjustPowerScheduled       pwrMgt->AdjustPowerScheduled
#define fIsPreChange                pwrMgt->IsPreChange
#define fDriverCallBusy             pwrMgt->DriverCallBusy
#define fPCDFunctionOverride        pwrMgt->PCDFunctionOverride
#define fDeviceActiveTimestamp      pwrMgt->DeviceActiveTimestamp
#define fActivityLock               pwrMgt->ActivityLock
#define fIdleTimerPeriod            pwrMgt->IdleTimerPeriod
#define fIdleTimerMinPowerState     pwrMgt->IdleTimerMinPowerState
#define fIdleTimerStartTime         pwrMgt->IdleTimerStartTime
#define fDeviceDesire               pwrMgt->DeviceDesire
#define fDesiredPowerState          pwrMgt->DesiredPowerState
#define fPreviousRequestPowerFlags  pwrMgt->PreviousRequestPowerFlags
#define fName                       pwrMgt->Name
#define fNumberOfPowerStates        pwrMgt->NumberOfPowerStates
#define fPowerStates                pwrMgt->PowerStates
#define fControllingDriver          pwrMgt->ControllingDriver
#define fCurrentPowerState          pwrMgt->CurrentPowerState
#define fParentsCurrentPowerFlags   pwrMgt->ParentsCurrentPowerFlags
#define fMaxPowerState              pwrMgt->MaxPowerState
#define fOutputPowerCharacterFlags  pwrMgt->OutputPowerCharacterFlags
#define fResponseArray              pwrMgt->ResponseArray
#define fNotifyClientArray          pwrMgt->NotifyClientArray
#define fSerialNumber               pwrMgt->SerialNumber
#define fOutOfBandParameter         pwrMgt->OutOfBandParameter
#define fDriverCallStartTime        pwrMgt->DriverCallStartTime
#define fCurrentCapabilityFlags     pwrMgt->CurrentCapabilityFlags
#define fActivityTicklePowerState   pwrMgt->ActivityTicklePowerState
#define fCurrentPowerConsumption    pwrMgt->CurrentPowerConsumption
#define fTempClampPowerState        pwrMgt->TempClampPowerState
#define fNotifyChildArray           pwrMgt->NotifyChildArray
#define fPowerClients               pwrMgt->PowerClients
#define fDriverCallEntry            pwrMgt->DriverCallEntry
#define fDriverCallParamPtr         pwrMgt->DriverCallParamPtr
#define fDriverCallParamCount       pwrMgt->DriverCallParamCount
#define fDriverCallParamSlots       pwrMgt->DriverCallParamSlots
#define fDriverCallReason           pwrMgt->DriverCallReason
#define fOutOfBandMessage           pwrMgt->OutOfBandMessage
#define fTempClampCount             pwrMgt->TempClampCount
#define fOverrideMaxPowerState      pwrMgt->OverrideMaxPowerState
#define fActivityTickleCount        pwrMgt->ActivityTickleCount
#define fWaitReason                 pwrMgt->WaitReason
#define fSavedMachineState          pwrMgt->SavedMachineState
#define fRootDomainState            pwrMgt->RootDomainState
#define fLockedFlags                pwrMgt->LockedFlags
#define fPMDriverCallQueue          pwrMgt->PMDriverCallQueue
#define fInsertInterestSet          pwrMgt->InsertInterestSet
#define fRemoveInterestSet          pwrMgt->RemoveInterestSet
#define fPMVars                     pwrMgt->PMVars
#define fPMActions                  pwrMgt->PMActions

/*
When an IOService is waiting for acknowledgement to a power change
notification from an interested driver or the controlling driver,
the ack timer is ticking every tenth of a second.
(100000000 nanoseconds are one tenth of a second).
*/
#define ACK_TIMER_PERIOD            100000000

// Max wait time in microseconds for kernel priority and capability clients
// with async message handlers to acknowledge.
// 
#define kPriorityClientMaxWait      (90 * 1000 * 1000)
#define kCapabilityClientMaxWait    (240 * 1000 * 1000)

// Attributes describing a power state change.
// See IOPMPowerChangeFlags data type.
//
#define kIOPMParentInitiated        0x0001  // this power change initiated by our  parent
#define kIOPMSelfInitiated          0x0002  // this power change initiated by this device
#define kIOPMNotDone                0x0004  // we couldn't make this change
#define kIOPMDomainWillChange       0x0008  // change started by PowerDomainWillChangeTo
#define kIOPMDomainDidChange        0x0010  // change started by PowerDomainDidChangeTo
#define kIOPMDomainPowerDrop        0x0020  // Domain is lowering power
#define kIOPMIgnoreChildren         0x0040  // Ignore children and driver power desires
#define kIOPMSkipAskPowerDown       0x0080  // skip the ask app phase
#define kIOPMSynchronize            0x0100  // change triggered by power tree re-sync
#define kIOPMSyncNoChildNotify      0x0200  // sync root domain only, not entire tree
#define kIOPMSyncTellPowerDown      0x0400  // send the ask/will power off messages
#define kIOPMSyncCancelPowerDown    0x0800  // sleep cancel for maintenance wake
#define kIOPMPowerSuppressed        0x1000  // power suppressed for dark wake

enum {
    kDriverCallInformPreChange,
    kDriverCallInformPostChange,
    kDriverCallSetPowerState
};

struct DriverCallParam {
    OSObject *  Target;
    IOReturn    Result;
};

// values of OutOfBandParameter
enum {
    kNotifyApps,
    kNotifyPriority,
    kNotifyCapabilityChangeApps,
    kNotifyCapabilityChangePriority
};

typedef bool (*IOPMMessageFilter)(
        void * target, void * object, void * arg1, void * arg2, void * arg3 );

// used for applyToInterested
struct IOPMInterestContext {
    OSArray *               responseArray;
    OSArray *               notifyClients;
    uint16_t                serialNumber;
    uint8_t                 isPreChange;
    uint8_t                 enableTracing;
    uint32_t                maxTimeRequested;
    uint32_t                messageType;
    uint32_t                notifyType;
    IOService *             us;
    IOPMPowerStateIndex     stateNumber;
    IOPMPowerFlags          stateFlags;
    IOPMPowerChangeFlags    changeFlags;
    const char *            errorLog;
    IOPMMessageFilter       messageFilter;
};

// assertPMDriverCall() options
enum {
    kIOPMADC_NoInactiveCheck = 1
};

//******************************************************************************
// PM Statistics & Diagnostics
//******************************************************************************

extern const OSSymbol *gIOPMStatsApplicationResponseTimedOut;
extern const OSSymbol *gIOPMStatsApplicationResponseCancel;
extern const OSSymbol *gIOPMStatsApplicationResponseSlow;

//******************************************************************************
// IOPMRequest
//******************************************************************************

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
    bool   attachNextRequest( IOPMRequest * next );
    bool   detachNextRequest( void );
    bool   attachRootRequest( IOPMRequest * root );
    bool   detachRootRequest( void );
};

//******************************************************************************
// IOPMRequestQueue
//******************************************************************************

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
};

//******************************************************************************
// IOPMWorkQueue
//******************************************************************************

#define WORK_QUEUE_STATS    1

class IOPMWorkQueue : public IOEventSource
{
    OSDeclareDefaultStructors( IOPMWorkQueue )

public:
    typedef bool (*Action)( IOService *, IOPMRequest *, IOPMWorkQueue * );

#if WORK_QUEUE_STATS
    uint64_t            fStatCheckForWork;
    uint64_t            fStatScanEntries;
    uint64_t            fStatQueueEmpty;
    uint64_t            fStatNoWorkDone;
#endif

protected:
    queue_head_t        fWorkQueue;
    Action              fWorkAction;
    Action              fRetireAction;
    uint32_t            fQueueLength;
    uint32_t            fConsumerCount;
    volatile uint32_t   fProducerCount;

    virtual bool checkForWork( void );
    virtual bool init( IOService * inOwner, Action work, Action retire );
    bool    checkRequestQueue( queue_head_t * queue, bool * empty );

public:
    static  IOPMWorkQueue * create( IOService * inOwner, Action work, Action retire );
    bool    queuePMRequest( IOPMRequest * request, IOServicePM * pwrMgt );
    void    signalWorkAvailable( void );
    void    incrementProducerCount( void );
};

//******************************************************************************
// IOPMCompletionQueue
//******************************************************************************

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
    bool    queuePMRequest( IOPMRequest * request );
};

#endif /* !_IOKIT_IOSERVICEPMPRIVATE_H */
