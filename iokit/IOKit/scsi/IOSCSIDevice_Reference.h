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
 

/*! 
@header IOSCSIDevice_Reference.h

This header defines the IOSCSIDevice class.

The SCSI framework creates instances of this class to
represent each valid SCSI device (target/lun) detected during
SCSI bus scanning. When an instance of this class is registered with
IOKit, the instance will be presented to clients which
'match' the IOSCSIDevice class.
*/

/*!
@typedef SCSITargetParms
Parameter structure for get/setTargetParms
@field transferPeriodpS 
Minimum SCSI synchronous transfer period allowed
for this target in picoseconds (10E-12). For asynchronous data transfer,
set this field to 0.
@field transferOffset 
Maximum SCSI synchronous transfer offset allowed for this target in
bytes. For asynchronous data transfer, set this field to 0.
@field transferWidth 
Maximum SCSI bus width in bytes. Note: must be a
power of 2.
@field enableTagQueuing
Setting enableTagQueuing to true enables tag queuing for SCSI Commands
issued to the target.
@field disableParity 
Set to (true) to disable parity checking on the
SCSI bus for this target.
*/
typedef struct SCSITargetParms {
    UInt32		transferPeriodpS;
    UInt32		transferOffset;
    UInt32		transferWidth;
    
    bool		enableTagQueuing;
    bool		disableParity;
    
    UInt32	    reserved[16];

} SCSITargetParms;


/*!
@typedef SCSILunParms
Parameter structure for get/setLunParms
@field disableDisconnect
Setting disableDisconnect to true disables SCSI disconnect for SCSI
Commands issued to the target/lun pair.
*/
typedef struct SCSILunParms {
    bool	disableDisconnect;
    
    UInt32	reserved[16];

} SCSILunParms;


/*!
@enum SCSIClientMessage
@discussion
IOSCSIDevice notifies its client of significant 'events' by the IOService::message()
api. When possible the client is notified of the event prior to any action taken. The
client is responsible for managing the device queue for the IOSCSIDevice
via the holdQueue(), releaseQueue(), flushQueue() and notifyIdle() api's. The client is also
notified at the end of an 'event' by the corresponding message id with or'd with
kClientMsgDone.
@constant kClientMsgDeviceAbort
A client initiated device abort is beginning.
@constant kClientMsgDeviceReset
A client initiated device reset is beginning.
@constant kClientMsgBusReset
An unsolicited bus reset has occurred.
@constant kClientMsgDone
This constant is or'd with one of the above message ids to indicate the
client should complete processing of the corresponding event.
*/
enum SCSIClientMessage {
    kClientMsgDeviceAbort	 	=  0x00005000,
    kClientMsgDeviceReset,
    kClientMsgBusReset,		

    kClientMsgDone			= 0x80000000,
};


/*!
@class IOSCSIDevice : public IOCDBDevice
@abstract 
Class that describes a SCSI device (target/lun pair).
@discussion 
The IOSCSIDevice class provides basic services 
to initialize and supervise a SCSI device. Once the device is
initialized, the client will normally use the allocCommand() member
function to create IOSCSICommand(s) to send SCSI CDBs to the target/lun.
*/
class IOSCSIDevice : public IOCDBDevice
{
public:
     
/*!
@function allocCommand
@abstract 
Allocates a IOSCSICommand object for this device.
@discussion 
The client uses the allocCommand() member function to allocate IOSCSICommand(s)
for a IOSCSIDevice. The client then uses the member functions of 
the IOSCSICommand to initialize it and send it to the device. A completed IOSCSICommand
may be reused for subsequent I/O requests or returned to the SCSI Family.
@param scsiDevice
Always specify kIOSCSIDevice.
@param clientDataSize
The client may indicate the size of a per-command data area for its own
use.

Note: The amount of per-command storage allowed is under review. We
anticipate that typical SCSI clients will need not more than 1024 bytes
per command.
*/
IOSCSICommand *allocCommand( IOSCSIDevice *scsiDevice, UInt32 clientDataSize = 0 );


/*!
@function setTargetParms
@abstract 
Sets SCSI parameters that apply to all luns on a SCSI target device.
@discussion 
This function will block until we attempt to set the
requested parameters. It may not be called from the device's workloop context.

The SCSI Family will serialize accesses to the SCSI
target so as not to disrupt commands in progress prior to processing a
change of target parameters.
@param targetParms 
Pointer to structure of type SCSITargetParms.
*/
bool setTargetParms( SCSITargetParms *targetParms );


/*!
@function getTargetParms
@abstract 
Gets the current target parameters.
@discussion 
Returns the parameters currently in effect for the SCSI target.
See setTargetParms().
@param targetParms 
Pointer to structure of type SCSITargetParms.
*/
void getTargetParms( SCSITargetParms *targetParms );


/*!
@function setLunParms
@abstract 
Sets the logical unit parameters for this device.
@discussion 
This function will block until we attempt to set the
requested parameters. It may not be called from the device's workloop context.

The SCSI Family will serialize accesses to the SCSI
target/lun so as not to disrupt commands in progress prior to processing a
change of lun parameters.
@param lunParms 
Pointer to structure of type SCSILunParms
*/
bool setLunParms( SCSILunParms *lunParms );


/*!
@function getLunParms
@abstract 
Gets the current logical unit parameters.
@discussion 
Returns the parameters currently in effect for the SCSI target/lun.
@param lunParms
Pointer to structure of type SCSITargetParms
*/
void getLunParms( SCSILunParms *lunParms );


/*!
@function abort
@abstract 
Aborts all outstanding requests for the target/lun pair.
@discussion 
If any I/O requests are currently active for the target/lun, an abort
command is sent to the device and any active requests are completed.

Prior to abort processing beginning, the client will be notified via:

message( kClientMsgDeviceAbort );

When abort processing is completed, the client will be notified via:

message( kClientMsgDeviceAbort | kClientMsgDone );

The client is responsible for managing the pending work queue for
the device when an abort request occurs. See holdQueue(), flushQueue(),
notifyIdle() functions.
*/
void abort();


/*!
@function reset
@abstract 
Resets the SCSI target. 
@discussion  
Since a SCSI target may have multiple logical units (lun(s)) the
reset() function may affect multiple IOSCSIDevice instances. Processing for
each lun is similar. 

Prior to reset processing beginning, the client will be notified via:

message( kClientMsgDeviceReset );

When reset processing is completed, the client will be notified via:

message( kClientMsgDeviceReset | kClientMsgDone );

The client is responsible for managing the pending work queue for
the device when an abort request occurs. See holdQueue(), flushQueue(),
notifyIdle() functions.
*/
void reset();


/*!
@function getInquiryData
@abstract Returns SCSI Inquiry data for the IOSCSIDevice. 
@discussion
Inquiry data returned is from the results of the last SCSI bus probe.
@param inquiryBuffer
Pointer to a buffer to receive the Inquiry data.
@param inquiryBufSize
Size of the buffer supplied.
@param inquiryDataSize
Pointer to a UInt32 to receive the size of the Inquiry data actually 
returned.
*/
void getInquiryData( void *inquiryBuffer, UInt32 inquiryBufSize, UInt32 *inquiryDataSize );


/*!
@function message
@abstract 
IOService message function.
@discussion
IOSCSIDevice notifies its client of significant 'events' by the IOService::message()
api. When possible the client is notified of the event prior to any action taken. The
client is responsible for managing the device queue for the IOSCSIDevice
via the holdQueue(), releaseQueue(), flushQueue() and notifyIdle() api's. 

Any return codes provided by the client are ignored.
@param message-id
Message id's for IOSCSIDevice are defined by enum SCSIClientMessage
@param provider
Pointer to the IOSCSIDevice reporting the event.
@param argument
Unused.
*/
IOReturn message( UInt32 type, IOService * provider, void * argument = 0 );


/*!
@function open
@abstract
IOService open function
@discussion
A client should open a IOSCSIDevice prior to accessing it. Only one open is allowed
per device.
@param client
Pointer to the IOSCSI device the client is opening.
@param options
There are currently no options defined by the SCSI Family.
@param arg
Unused. Omit or specify 0.
*/
bool open( IOService *client, IOOptionBits options = 0, void *arg = 0 );


/*!
@function close
@abstract
IOService close function
@discussion
A client must close a IOSCSIDevice if the client plans no further accesses to it.
@param client
Pointer to the IOSCSI device the client is closing.
@param options
There are currently no options defined by the SCSI Family.
*/
void close( IOService *client, IOOptionBits	options = 0 );


/*!
@function holdQueue
@abstract 
Suspends sending additional IOSCSICommands to the target/lun.
@discussion
holdQueue() may only be called from the IOSCSIDevice workloop. The client
is guaranteed to be running in this context during a message() notification.

holdQueue() has no effect on commands already passed to the host adapter. One
or more commands may complete after the queue is held. See notifyIdle()
@param queueType
Perform action on the indicated queue. See enum SCSIQueueType in IOSCSICommand.
*/
holdQueue( UInt32 queueType );


/*!
@function flushQueue
@abstract 
Returns any commands on the IOSCSIDevice's pending work queue.
@discussion
flushQueue() may only be called from the IOSCSIDevice workloop. This is 
guaranteed to be the case after a IOSCSICommand completion of after a 
message() notification.

All pending command are completed prior to flushQueue() returning to the caller.

flushQueue() has no effect on commands already passed to the host adapter. One
or more commands may complete after the queue is flushed. See notifyIdle().
@param queueType
Perform action on the indicated queue. See enum SCSIQueueType in IOSCSICommand.
@param rc
The return code of any flushed commands is set to (rc).
*/
void flushQueue( UInt32 queueType, IOReturn rc );


/*!
@function notifyIdle
@abstract
Notifies the client when all active commands on a SCSI device have completed.
@discussion
notifyIdle() may only be called from the IOSCSIDevice workloop. This is guaranteed
to be the case after a IOSCSICommand completion of after a message() notification.

Only one notifyIdle() call may be active. Any outstanding notifyIdle() calls may
be cancelled by calling notifyIdle() with no parameters.
@param target
Object to receive the notification. Normally the client's (this) pointer.
@param callback
Pointer to a callback routine of type CallbackFn.
@param refcon
Pointer to client's private data.
*/
void notifyIdle( void *target, Callback callback, void *refcon );


/*!
@function releaseQueue
@abstract
Resumes sending IOSCSICommands to the IOSCSIDevice. 
@discussion
If the device queue was not held, releaseQueue() has no effect.

releaseQueue() may only be called from the IOSCSIDevice workloop. This is guaranteed
to be the case after a IOSCSICommand completion of after a message() notification.
@param queueType
Perform action on the indicated queue. See enum SCSIQueueType in IOSCSICommand.
*/
void releaseQueue( UInt32 queueType );


/*!
@function getWorkLoop
@abstract
Returns the IOWorkLoop object that services this IOSCSIDevice.
*/
IOWorkloop *getWorkLoop();

}
