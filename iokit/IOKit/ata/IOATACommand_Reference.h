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
@header IOATACommand_Reference.h 

This header defines the IOATACommand class.

This class encapsulates an ATA/ATAPI Command. The client driver allocates a
command using IOATADevice::allocCommand() and initializes it using
functions of this class. The client can then submit the command to
the ATA/ATAPI stack by invoking the execute() function.
*/

/*!
@typedef ATATaskfile
@discussion
The ATATaskfile structure provides information to be read/written into an IOATACommand. This
information includes the ATA taskfile register settings and the protocol the transport driver
is to use when the corresponding IOATACommand is executed.
@field protocol
Indicates the type of protocol the ATA Controller driver is to use when executing this command.
See enum ATAProtocol in IOATADevice_Reference for allowable values for this field.
@field tagType
Indicates whether an ATA command requires a tag. This field is only used when the protocol
selected for the command supports the Overlap feature set.
@field tag
This field is set by the IOATAController class to tell the host 
adapter driver the tag value to assign to this IOATACommand.
@field resultmask
This field is set by the IOATADevice client and is a bit mask indicating the registers to be 
returned when the IOATACommand completes. Clients should use ATARegToMask() convert ATA register
index values to bit mask values.
@field regmask
This field is set by the IOATADevice client and is a bit mask indicating the registers to be written
when an IOATACommand is executed. Clients should use ATARegToMask() convert ATA register
index values to bit mask values.
@field ataRegs
This array contains the ATA taskfile register values to be written when an IOATACommand is executed.
The index values for ATA taskfile registers is specified by enum ATARegs.
*/
typedef struct ATATaskfile {

    ATAProtocol		protocol;
   
    UInt32		flags;
  
    UInt8		tagType;
    UInt32		tag;

    UInt32		resultmask;

    UInt32		regmask;
    UInt32              ataRegs[kMaxATARegs];
    
} ATATaskfile;

/*!
@typedef ATACDBInfo
@discussion
The ATACDBInfo structure provides cdb information to be read/written into an IOATACommand.
@field cdbFlags
Indicates flags to applicable to the CDB to be executed. There are currently no flags defined for
IOATADevice clients.
@field cdbLength
Set by the IOATADevice client to the length of the Command Descriptor
Block (CDB).
@field cdb
Set by the IOATADevice client to command descriptor block the client
wishes the ATAPI device to execute.
*/
typedef struct ATACDBInfo {

    UInt32		cdbFlags;

    UInt32		cdbLength;
    UInt8		cdb[16];
    
    UInt32              reserved[16];
    
} ATACDBInfo;

/*!
@typedef ATAResults
@discussion
The ATAResults structure provides completion information for an IOATACommand. 
@field returnCode
The overall return code for the command. See iokit/iokit/IOReturn.h.
This value is also returned as the getResults() return value.
@field bytesTransferred
The total number of bytes transferred to/from the ATA device.
Note: Some ATA controllers are not capable of returning accurate byte counts when
operating in bus-master mode. Clients should use some caution in interpreting the
contents of this field.
@field adapterStatus
This field contains the low-level ATA Controller status for a completed IOATACommand. 
Values for this field are defined by enum ATAReturnCode.
@field requestSenseDone
A boolean indicating whether sense data was obtained from the ATAPI
device.
@field requestSenseLength
The number of sense data bytes returned from the ATAPI device.
@field ataRegs
This array contains the ATA taskfile register values to be returned when an IOATACommand completes.
The index values for ATA taskfile registers is specified by enum ATARegs. Registers to be returned 
are indicated by the bit mask resultmask. See structure ATATaskfile.
*/
typedef struct ATAResults {

    IOReturn		returnCode;
 
    UInt32		bytesTransferred;

    ATAReturnCode       adapterStatus;

    bool		requestSenseDone;
    UInt32		requestSenseLength;

    UInt32              ataRegs[kMaxATARegs];
    
    UInt32              reserved[16];
    
} ATAResults;



class IOATACommand : public IOCDBCommand
{
public:


/*!
@function setPointers
@abstract
Sets the data buffer component of an ATA/ATAPI Command.
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
If isSense is set to false, the IOATACommand's data buffer information is set. If isSense is
set to true, the IOATACommand's request sense buffer information is set.
*/
     void 			setPointers( IOMemoryDescriptor 	*desc, 
					     UInt32 			transferCount, 
                                             bool 			isWrite, 
					     bool 			isSense = false );
/*!
@function getPointers
@abstract
Gets the data buffer component of an ATA/ATAPI Command.
@discussion
The client provides a set of pointers to fields to receive the IOATACommand's
data/request sense buffer pointers.
@param desc
Pointer to a field (IOMemoryDescriptor *) to receive the IOATACommand's IOMemoryDescriptor pointer.
@param transferCount
Pointer to a field (UInt32) to receive the IOATACommand's maximum transfer count.
@param isWrite 
Pointer to a field (bool) to receive the IOATACommand's transfer direction.
@param isSense
If isSense is set to true, the IOATACommand's data buffer information is returned. Otherwise,
the IOATACommand's request sense buffer information is returned.
*/
     void 			getPointers( IOMemoryDescriptor 	**desc, 
					     UInt32 			*transferCount, 
					     bool 			*isWrite, 
					     bool 			isSense = false );
/*!
@function setTimeout
@abstract
Sets the timeout for the command in milliseconds.
@discussion
The IOATAController class will abort a command which does not
complete with in the time interval specified. The client should
set the timeout parameter to zero if they want to suppress
timing.
@param timeout
Command timeout in milliseconds.
*/
     void 			setTimeout( UInt32  timeoutmS );
     
/*!
@function getTimeout
@abstract
Gets the timeout for the command in milliseconds.
@discussion
This function returns the command timeout previously set by setTimeout().
@param timeout
Command timeout in milliseconds.
*/		
     UInt32 			getTimeout();

/*!
@function setCallback
@abstract
Sets the callback routine to be invoked when the ATA/ATAPI Command completes.
@param target
Pointer to the object to be passed to the callback routine. This would usually
be the client's (this) pointer.
@param callback
Pointer to the client's function to process the completed command
@param refcon
Pointer to the information required by the client's callback routine to process
the completed command.
*/
     void 			setCallback( void *target = 0, CallbackFn callback = 0, void *refcon = 0 );

/*!
@function execute
@abstract 
Submits a ATA/ATAPI command to be executed.
@discussion
Once the execute() function is called, the client should not
invoke any further functions on the ATA/ATAPI Command with the
exception of abort().

The execute() function optionally returns sets a unique sequence
number token for the command. If the client intends to use the abort()
method they must retain this sequence number token.
@param sequenceNumber
Pointer to field (UInt32) to receive the sequence number assigned to the ATA/ATAPI
Command.
*/
     bool 			execute( UInt32 *sequenceNumber = 0 );

/*!
@function abort
@abstract
Aborts an executing ATA/ATAPI Command.
@discussion
The client may invoke the abort() method to force the completion of an
executing ATA/ATAPI Command. The client must pass the sequence number
provided when the execute() function was invoked.

Note: The abort function provides no status on whether or not a
command has been successfully aborted. The client should wait for the
command to actually complete to determine whether the abort completed
successfully.
@param sequenceNumber
The client must pass the sequence number assigned to the command when
the client called the execute() function.
*/
     void			abort( UInt32 sequenceNumber );

/*!
@function complete
@abstract
Indicates the IOATAController subclass (host adapter driver) has completed an ATA/ATAPI command.
@discussion
Once the complete() function is called, the controller
subclass should make no further accesses to the IOATACommand
being completed.

A IOATADevice client would not normally call this function.
*/
     void	 		complete();

/*!
@function getClientData
@abstract
Returns a pointer to the ATA/ATAPI Command's client data area.
@discussion
The client may allocate storage in the ATA/ATAPI Command for its own use.
See IOATADevice::allocateCmd().
*/
     void			*getClientData();
     
/*
@function getCommandData
@abstract
Returns a pointer to the ATA Command's controller data area
@discussion
This area is allocated for use by the IOATAController subclass (host adapter
driver). The client should not normally access this area.
*/
     
          void			*getCommandData();

/*!
@function getSequenceNumber
@abstract
Returns the sequence number assigned to an executing command.
@discussion
The caller should check the sequence number for 0. This indicates that
the command has completed or has not been processed to the point where
a sequence number has been assigned.
*/
    UInt32			getSequenceNumber();

/*!
@function setTaskfile
@abstract
Sets the ATA taskfile register information and ATA/ATAPI protocol for the IOATACommand.
@discussion 
See struct ATATaskfile additional information.
@param ATATaskfile
Pointer to an ATATaskfile structure.
*/
    void 			setTaskfile( ATATaskfile *taskfile );
    
/*!
@function getTaskfile
@abstract
Sets the ATA taskfile register information and ATA/ATAPI protocol for the IOATACommand.
@param ATATaskfile
Pointer to an ATATaskfile structure.
*/    						
    void 			getTaskfile( ATATaskfile *taskfile ); 	
    
/*!
@function getProtocol
@abstract
Returns the protocol specified for the ATA/ATAPI Command. 
@discussion
The protocol returned is specified by the client in the ATATaskfile structure. See setTaskfile().
This function is normally used by subclasses of IOATAController to obtain information about the
ATA command being executed.
*/    						
    ATAProtocol			getProtocol();
    
/*!
@function getResultMask
@abstract
Returns the resultMask specified for the ATA/ATAPI Command.
@discussion
The resultMask is specified by the client in the ATATaskfile structure and indicates the ATA taskfile registers
to be returned when the ATA/ATAPI command completes. See setTaskfile(). This function is normally used by 
subclasses of IOATAController to obtain information about the ATA command being executed.
*/    						
    UInt32			getResultMask();
    
/*!
@function getFlags
@abstract
Returns the flags specified for the ATA/ATAPI Command.
@discussion
The flags are specified by the client in the ATATaskfile structure.  See setTaskfile(). This function is 
normally used by subclasses of IOATAController to obtain information about the ATA command being executed.
*/    						    
    UInt32			getFlags();

/*!
@function setCDB
@abstract
Sets the CDB component of a ATA/ATAPI Command. 
@param ataCDB
Pointer to a ATACDBInfo structure.
*/     
     void 			setCDB( ATACDBInfo *ataCmd );
     
/*!
@function getCDB
@abstract
Gets the CDB component of a ATA/ATAPI Command. 
@param ataCDB
Pointer to an ATACDBInfo structure to receive the ATA/ATAPI Command's cdb information.
*/
     
     void			getCDB( ATACDBInfo *ataCmd );

/*!
@function getResults
@abstract
Gets results from a completed ATA/ATAPI Command.
@discussion
The getResults() function returns the value of the returnCode field of the command results. If
the client is only interested in a pass/fail indication for the command, the client 
can pass (ATAResults *)0 as a parameter.
@param results
Pointer to a ATAResults structure to receive the ATA/ATAPI Command's completion information.
*/     
     IOReturn			getResults( ATAResults *results );
     
/*!
@function setResults
@abstract
Sets the results component of a ATA/ATAPI Command.
@discussion
The setResults() function is used by the IOATAController subclass (host
adapter driver) return results for a ATA/ATAPI Command about to be completed.
@param ataResults Pointer to a ATAResults structure containing
completion information for the ATA/ATAPI Command.

Completion information is copied into the command, so the caller may
release the ATAResults structure provided when this function returns.
*/     
     void			setResults( ATAResults *results );

/*!
@function getDevice
@abstract 
Returns the IOATADevice this command is targeted to.
@param deviceType
The caller should use value kIOATADeviceType. 
@discussion
In some cases a IOATACommand is not associated with a specific ATA Unit. This
would be the case for a ATA Bus Reset. In this case getDevice() returns 0.
*/
     IOATADevice 	*getDevice( IOATAStandardDevice *deviceType );

/*!
@function getUnit
@abstract 
Returns the unit number for the IOATADevice this command is associated with.
*/
     ATAUnit			getUnit();

/*!
@function setQueueInfo
@abstract
Sets queuing information for the ATA/ATAPI Command.
@discussion
Each IOATADevice has two queues, a normal Q and a bypass Q. The treatment of the
queues is essentially identical except that the bypass Q is given preference whenever
it has commands available. 

Usually, the client will use the normal Q for regular I/O commands and the bypass Q
to send error recovery commands to the device.
@param queueType
Set to kATAQTypeNormalQ or kATAQTypeBypassQ to indicate which IOATADevice queue the 
ATA/ATAPI Command should be routed to.
@param queuePosition
Set to kATAQPositionTail or kATAQPositionHead to indicate whether the ATA/ATAPI Command should
be added to the head to tail for the selected IOATADevice queue.
*/
    void			setQueueInfo(  UInt32 forQueueType = kATAQTypeNormalQ, UInt32 forQueuePosition = kATAQPositionTail );
    
/*!
@function getQueueInfo
@abstract
Gets queuing information for the ATA Command.
@param queueType
Pointer to a field (UInt32) to receive the queue type previously set for this ATA Command.
@param queuePosition
Pointer to a field (UInt32) to receive the queue position previously set for this ATA Command.
*/    
    void			getQueueInfo(  UInt32 *forQueueType, UInt32 *forQueuePosition = 0 );

/*!
@function getCmdType
@abstract
Obtains the underlying 'intent' of an ATA/ATAPI Command.
@discussion
This function provides information on the intent of a ATA/ATAPI
Command. For example, since Aborts, Request Sense and normal Execute commands are
all sent to the executeCommand() function, invoking getCmdType()
will indicate whether a Request Sense, Abort or Normal I/O request is
being processed.

This information is not normally meaningful to IOATADevice clients.
*/
     UInt32			getCmdType();
     
/*!
@function getOriginalCmd
@abstract
Obtains a 'related' ATA/ATAPI Command.
@discussion
In cases where a ATA command is related to a previous command, this
function will return the original command. For example, if a
Request Sense command  (CmdType = kATACommandReqSense)is processed,
then this function can be used to obtain the original command that
caused the check condition. If an Abort command (CmdType =
kATACommandAbort) then this function can be used to obtain the original
command the abort was issued against.

It this information is not normally meaningful to IOATADevice clients.
*/

     IOATAStandardCommand	*getOriginalCmd();    

};

