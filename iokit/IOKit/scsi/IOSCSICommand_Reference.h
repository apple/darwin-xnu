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
@header IOSCSICommand_Reference.h 

This header defines the IOSCSICommand class.

This class encapsulates a SCSI Command. The client driver allocates a
command using IOSCSIDevice::allocCommand() and initializes it using
functions of this class. The client can then submit the command to
the SCSI stack by invoking the execute() function.
*/


/*!
@enum SCSICDBFlags
Defines values for the cdbFlags field in the SCSICDBInfo structure.
@constant kCDBFNoDisconnect
Set by the IOSCSIDevice client to indicate the target may not disconnect
during the execution of this IOSCSICommand.
@constant kCDBFlagsDisableParity
Set by the IOSCSIController class to tell the host adapter driver to disable
parity checking during the execution of this CDB.
@constant kCDBFlagsNoDisconnect
Set by the IOSCSIController class to tell the host adapter driver that the 
target may not disconnect during the execution of this IOSCSICommand.
@constant kCDBFlagsNegotiateSDTR
Set by the IOSCSIController class to tell the host adapter driver that it
should initiate synchronous data transfer negotiation during this IOSCSICommand.
@constant kCDBFlagsNegotiateWDTR
Set by the IOSCSIController class to tell the host adapter driver that it
should initiate wide data transfer negotiation during this IOSCSICommand.
*/
enum SCSICDBFlags {
    kCDBFNoDisconnect		= 0x00000001,

/*
 *  Note: These flags are for IOSCSIController subclasses only
 */
    kCDBFlagsDisableParity	= 0x08000000,
    kCDBFlagsNoDisconnect	= 0x10000000,
    kCDBFlagsNegotiateSDTR	= 0x20000000,
    kCDBFlagsNegotiateWDTR	= 0x40000000,
};


/*!
@enum SCSIAdapterStatus
Defines the values of the adapterStatus field of the SCSIResults structure.
@constant kSCSIAdapterStatusSuccess
Request completed with no adapter reported errors.
@constant kSCSIAdapterStatusProtocolError
Violation of SCSI protocol detected by host adapter.
@constant kSCSIAdapterStatusSelectionTimeout
Target device did not respond to selection.
@constant kSCSIAdapterStatusMsgReject
Adapter received a msg reject from the target device.
@constant kSCSIAdapterStatusParityError
Adapter detected, or target reported a parity error during the
IOSCSICommand.
@constant kSCSIAdapterStatusOverrun
Target device requested more data than supplied by host.
*/
enum SCSIAdapterStatus {
    kSCSIAdapterStatusSuccess	    = 0,
    kSCSIAdapterStatusProtocolError,
    kSCSIAdapterStatusSelectionTimeout,
    kSCSIAdapterStatusMsgReject,
    kSCSIAdapterStatusParityError,
    kSCSIAdapterStatusOverrun,
};


/*!
@typedef SCSICDBInfo
@discussion
Fields specified here are set by IOSCSIDevice client, while others
are set by the IOSCSIController class for use by the host adapter
driver. The client should zero all fields of the structure prior
to use.
@field cdbFlags
See enum SCSICDBFlags for flag definitions.
@field cdbTagMsg 
This field should be set to zero by the IOSCSIDevice client. If the
SCSI device supports tag queuing then the IOSCSIController class
will set this field to select simple (unordered) tags. 
@field cdbTag
This field is set by the IOSCSIController class to tell the host 
adapter driver the SCSI tag value to assign to this IOSCSICommand.
@field cdbLength
Set by the IOSCSIDevice client to the length of the Command Descriptor
Block (CDB).
@field cdb
Set by the IOSCSIDevice client to command descriptor block the client
wishes the target to execute.
*/
typedef struct SCSICDBInfo {
	
    UInt32      cdbFlags;

    UInt32	cdbTagMsg;
    UInt32	cdbTag;

    UInt32	cdbAbortMsg;

    UInt32	cdbLength;
    UInt8	cdb[16];
    
    UInt32	reserved[16];
} SCSICDBInfo;


/*!
@typedef SCSIResults
@field returnCode
The overall return code for the command. See iokit/iokit/IOReturn.h.
This value is also returned as the getResults() return value.

Note: The SCSI Family will automatically generate standard return codes
based on the values in the adapterStatus and scsiStatus fields. Unless 
the IOSCSIController subclass needs set a specific return code, it should
leave this field set to zero.
@field bytesTransferred
The total number of bytes transferred to/from the target device.
@field adapterStatus
The IOSCSIController subclass must fill-in this field as appropriate.
See enum SCSIAdapterStatus. 
@field scsiStatus
The SCSI Status byte returned from the target device.
@field requestSenseDone
A boolean indicating whether sense data was obtained from the target
device.
@field requestSenseLength
The number of sense data bytes returned from the target device.
*/
typedef struct SCSIResults {
    IOReturn			returnCode;
    
    UInt32			bytesTransferred;

    enum SCSIAdapterStatus	adapterStatus;	
    UInt8			scsiStatus;
    
    bool			requestSenseDone;
    UInt32			requestSenseLength;
} SCSIResults;


/*!
@enum SCSIQueueType
Each IOSCSIDevice has two queues, a normal Q and a bypass Q. The treatment of the
queues is essentially identical except that the bypass Q is given preference whenever
it has commands available. 

Usually, the client will use the normal Q for regular I/O commands and the bypass Q
to send error recovery commands to the device.
@constant kQTypeNormalQ
Indicates command applies to the normal IOSCSIDevice queue.
@constant kQTypeBypassQ
Indicates command applies to the bypass IOSCSIDevice queue.
*/
enum SCSIQueueType {
    kQTypeNormalQ	= 0,
    kQTypeBypassQ	= 1,
};


/*!
@enum SCSIQueuePosition
Indicates whether a IOSCSICommand should be added to the head or tail
of the queue selected.
@constant kQPositionTail
Queue request at the tail (end) of the selected queue.
@constant kQPositionHead
Queue request at the head (front) of the selected queue.
*/
enum SCSIQueuePosition {
    kQPositionTail	= 0,
    kQPositionHead	= 1,
};


/*!
@struct SCSITargetLun
@field target
The SCSI Id for the SCSI device being selected.
@field lun
The SCSI Lun for the SCSI device being selected.
*/ 
typedef struct SCSITargetLun {
    UInt8   target;
    UInt8   lun;
    UInt8   reserved[2];
} SCSITargetLun;

/*!
@class IOSCSICommand : public IOCDBCommand
@abstract 
Class that describes a SCSI device (target/lun pair).
@discussion 
This class encapsulates a SCSI Command. The client driver allocates a
command using IOSCSIDevice::allocCommand() and initializes it using
functions of this class. The client can then submit the command to
the SCSI stack by invoking the execute() function.
*/
class IOSCSICommand : public IOCDBCommand
{
public:


/*!
@function setPointers
@abstract
Sets the data buffer component of a SCSI Command.
@discussion
The client provides an IOMemoryDescriptor object to corresponding
to the client's data or request sense buffer, the maximum data transfer count
and data transfer direction.
@param desc
Pointer to a IOMemoryDescriptor describing the client's I/O buffer.
@param transferCount
Maximum data transfer count in bytes.
@param isWrite
Data transfer direction. (Defined with respect to the device, i.e. isWrite = true
indicates the host is writing to the device.
@param isSense
If isSense is set to false, the IOSCSICommand's data buffer information is set. Otherwise,
the IOSCSICommand's request sense buffer information is set
*/
void setPointers( IOMemoryDescriptor *desc, UInt32 transferCount, bool isWrite, bool isSense=false );


/*!
@function getPointers
@abstract
Gets the data buffer component of a SCSI Command.
@discussion
The client provides a set of pointers to fields to receive the IOSCSICommand's
data/request sense buffer pointers.
@param desc
Pointer to a field (IOMemoryDescriptor *) to receive the IOSCSICommand's IOMemoryDescriptor pointer.
@param transferCount
Pointer to a field (UInt32) to receive the IOSCSICommand's maximum transfer count.
@param isWrite 
Pointer to a field (bool) to receive the IOSCSICommand's transfer direction.
@param isSense
If isSense is set to true, the IOSCSICommand's data buffer information is returned. Otherwise,
the IOSCSICommand's request sense buffer information is returned.
*/
void getPointers( IOMemoryDescriptor **desc, UInt32 *transferCount, bool *isWrite, bool isSense = false );

/*!
@function setTimeout
@abstract
Sets the timeout for the command in milliseconds.
@discussion
The IOSCSIController class will abort a command which does not
complete with in the time interval specified. The client should
set the timeout parameter to zero if they want to suppress
timing.
@param timeout
Command timeout in milliseconds.
*/
void setTimeout( UInt32 timeoutmS );	    

/*!
@function getTimeout
@abstract
Gets the timeout for the command in milliseconds.
@discussion
This function returns the command timeout previously set by setTimeout().
@param timeout
Command timeout in milliseconds.
*/
UInt32	    getTimeout();


/*!
@function setCallback
@abstract
Sets the callback routine to be invoked when the SCSI Command completes.
@param target
Pointer to the object to be passed to the callback routine. This would usually
be the client's (this) pointer.
@param callback
Pointer to the client's function to process the completed command
@param refcon
Pointer to the information required by the client's callback routine to process
the completed command.
*/
void setCallback( void *target = 0, CallbackFn callback = 0, void *refcon = 0 );


/*!
@function getClientData
@abstract
Returns a pointer to the SCSI Command's client data area.
@discussion
The client may allocate storage in the SCSI Command for its own use.
See IOSCSIDevice::allocateCmd().
*/
void	    *getClientData();

/*
@function getCommandData
@abstract
Returns a pointer to the SCSI Command's controller data area
@discussion
This area is allocated for use by the IOSCSIController subclass (host adapter
driver). The client should not normally access this area.
*/
void	    *getCommandData();


/*!
@function setCDB
@abstract
Sets the CDB component of a SCSI Command. 
@param scsiCDB
Pointer to a SCSICDBInfo structure.
*/
void setCDB( SCSICDBInfo *scsiCmd );


/*!
@function getCDB
@abstract
Gets the CDB component of a SCSI Command. 
@param scsiCDB
Pointer to a SCSICDBInfo structure to receive the SCSI Command's cdb information.
*/
void getCDB( SCSICDBInfo *scsiCmd );


/*!
@function getResults
@abstract
Gets results from a completed SCSI Command.
@discussion
The getResults() function returns the value of the returnCode field of the command results. If
the client is only interested in a pass/fail indication for the command, the client 
can pass (SCSIResult *)0 as a parameter.
@param results
Pointer to a SCSIResults structure to receive the SCSI Commands completion information.
*/
IOReturn getResults( SCSIResults *results );

/*!
@function setResults
@abstract
Sets the results component of a SCSI Command.
@discussion
The setResults() function is used by the IOSCSIController subclass (host
adapter driver) return results for a SCSI Command about to be completed.
@param scsiResults Pointer to a SCSIResults structure containing
completion information for the SCSI Command.

Completion information is copied into the command, so the caller may
release the SCSIResults structure provided when this function returns.
*/
void setResults( SCSIResults *results );


/*!
@function getDevice
@abstract 
Returns the IOSCSIDevice this command is targeted to.
@param deviceType
The caller should use value kIOSCSIDeviceType.
@discussion
In some cases a IOSCSICommand is not associated with a specific target/lun. This
would be the case for a SCSI Bus Reset. In this case getDevice() returns 0.
*/
IOSCSIDevice *getDevice( IOSCSIDevice *deviceType );


/*!
@function getTargetLun
@abstract 
Returns the target/lun for the IOSCSIDevice this command is associated with.
@param targetLun
Pointer to a SCSITargetLun structure to receive the target/lun information.
*/
void getTargetLun( SCSITargetLun *targetLun );


/*!
@function execute
@abstract 
Submits a SCSI command to be executed.
@discussion
Once the execute() function is called, the client should not
invoke any further functions on the SCSI Command with the
exception of abort().

The execute() function optionally returns sets a unique sequence
number token for the command. If the client intends to use the abort()
method they must retain this sequence number token.
@param sequenceNumber
Pointer to field (UInt32) to receive the sequence number assigned to the SCSI
Command.
*/
bool execute( UInt32 *sequenceNumber = 0 );

/*!
@function abort
@abstract
Aborts an executing SCSI Command.
@discussion
The client may invoke the abort() method to force the completion of an
executing SCSI Command. The client must pass the sequence number
provided when the execute() function was invoked.

Note: The abort function provides no status on whether or not a
command has been successfully aborted. The client should wait for the
command to actually complete to determine whether the abort completed
successfully.
@param sequenceNumber
The client must pass the sequence number assigned to the command when
the client called the execute() function.
*/
void abort( UInt32 sequenceNumber );

/*!
@function complete
@abstract
Indicates the IOSCSIController subclass (host adapter driver) has completed a SCSI command.
@discussion
Once the complete() function is called, the controller
subclass should make no further accesses to the IOSCSICommand
being completed.

A IOSCSIDevice client would not normally call this function.
*/
void complete();


/*!
@function getSequenceNumber
@abstract
Returns the sequence number assigned to an executing command.
@discussion
The caller should check the sequence number for 0. This indicates that
the command has completed or has not been processed to the point where
a sequence number has been assigned.
*/
UInt32 getSequenceNumber();


/*!
@function setQueueInfo
@abstract
Sets queuing information for the SCSI Command.
@discussion
Each IOSCSIDevice has two queues, a normal Q and a bypass Q. The treatment of the
queues is esentially identical except that the bypass Q is given preference whenever
it has commands available. 

Usually, the client will use the normal Q for regular I/O commands and the bypass Q
to send error recovery commands to the device.
@param queueType
Set to kQTypeNormalQ or kQTypeBypassQ to indicate which IOSCSIDevice queue the 
SCSI Command should be routed to.
@param queuePosition
Set to kQPositionTail or kQPositionHead to indicate whether the SCSI Command should
be added to the head to tail for the selected IOSCSIDevice queue.
*/
void setQueueInfo(  UInt32 queueType = kQTypeNormalQ, UInt32 queuePosition = kQPositionTail );


/*!
@function getQueueInfo
@abstract
Gets queuing information for the SCSI Command.
@param queueType
Pointer to a field (UInt32) to receive the queue type previously set for this SCSI Command.
@param queuePosition
Pointer to a field (UInt32) to receive the queue position previously set for this SCSI Command.
*/
void getQueueInfo(  UInt32 *queueType, UInt32 *queuePosition = 0 );


/*!
@function getCmdType
@abstract
Obtains the underlying 'intent' of a SCSI Command.
@discussion
This function provides information on the intent of a SCSI
Command. For example, since Aborts, Request Sense and normal Execute commands are
all sent to the executeCommand() function, invoking getCmdType()
will indicate whether a Request Sense, Abort or Normal I/O request is
being processed.

It this information is not normally meaningful to IOSCSIDevice clients.
*/
UInt32	    getCmdType();


/*!
@function getOriginalCmd
@abstract
Obtains a 'related' SCSI Command.
@discussion
In cases where a SCSI command is related to a previous command, this
function will return the original command. For example, if a
Request Sense command  (CmdType = kSCSICommandReqSense)is processed,
then this function can be used to obtain the original command that
caused the check condition. If an Abort command (CmdType =
kSCSICommandAbort) then this function can be used to obtain the original
command the abort was issued against.


It this information is not normally meaningful to IOSCSIDevice clients.
*/
IOSCSICommand	*getOriginalCmd();    

};
