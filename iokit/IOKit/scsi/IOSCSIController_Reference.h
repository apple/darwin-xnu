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
@header IOSCSIController_Reference.h

This header defines the IOSCSIController class.

IOSCSIController provides the superclass for SCSI host
adapter drivers. 

Drivers are instantiated based on their 'personality' entry matching
their adapter's OpenFirmware device tree entry. When a match occurs,
the driver's class is instantiated. Since the driver is written as a
subclass of IOSCSIController, an instance of the SCSI Family is automatically
instantiated.
*/


/*!
@typedef SCSIControllerInfo
Parameter structure passed for configure() function.
@field initiatorId
The SCSI address of your host adapter. Usually 7 (decimal).
@field maxTargetsSupported
The number of targets you controller supports. Typically 8 or 16.
@field maxLunsSupported
The number of logical units per target your controller supports.
Typically 8.
@field minTransferPeriodpS
The minimum synchronous data transfer period in picoseconds your
controller supports.
@field maxTransferOffset
The maximum synchronous data offset your controller supports in bytes.
@field maxTransferWidth
The maximum data SCSI bus width your controller supports in bytes. Must
be a power of 2.
@field maxCommandsPerController
The maximum number of outstanding commands your controller supports
across all targets and luns. Set to 0 if there is no controller limit in
this category.
@field maxCommandsPerTarget
The maximum number of outstanding commands your controller supports on a
given target. Set to 0 if there is no controller limit in this category.
@field maxCommandsPerLun
The maximum number of outstanding commands your controller supports on a
given lun. Set to 0 if there is no controller limit in this category.
@field tagAllocationMethod
Controls whether tags are allocated on a per Lun, per Target or per
Controller basis. See enum SCSITagAllocation.
@field maxTags
The maximum number of tags allocated to each Lun, Target or Controller
depending on the tagAllocationMethod setting.
@field targetPrivateDataSize
IOSCSIController will optionally allocate per-target storage for your
driver based on the setting of this field. The amount of storage needed
is specified in bytes.
@field lunPrivateDataSize
IOSCSIController will optionally allocate per-lun storage for your
driver based on the setting of this field. The amount of storage needed
is specified in bytes.
@field commandPrivateDataSize
IOSCSIController will optionally allocate per-command storage for your
driver based on the setting of this field. The amount of storage needed
is specified in bytes.

Note: The amount of per-command storage allowed is under review. We
anticipate that typical SCSI controllers will need not more than 1024
bytes per command.
@field disableCancelCommands
Subclasses of IOSCSIController which do their own management of
aborts/resets can set this field to true to avoid receiving
cancelCommand() requests.
*/
typedef struct SCSIControllerInfo {
    UInt32      initiatorId;

    UInt32	maxTargetsSupported;
    UInt32	maxLunsSupported;

    UInt32	minTransferPeriodpS;
    UInt32	maxTransferOffset;
    UInt32	maxTransferWidth; 
 
    UInt32	maxCommandsPerController;
    UInt32	maxCommandsPerTarget;
    UInt32	maxCommandsPerLun;

    UInt32	tagAllocationMethod;
    UInt32	maxTags;

    UInt32	targetPrivateDataSize;
    UInt32	lunPrivateDataSize;
    UInt32	commandPrivateDataSize;

    bool	disableCancelCommands;

    UInt32	reserved[64];

} SCSIControllerInfo;


/*!
@enum SCSITagAllocation
@discussion
This enum defines how SCSI tags are allocated.
@constant kTagAllocationNone
This controller does not support tag queuing.
@constant kTagAllocationPerLun
Each SCSI Lun has its own private tag pool containing
(maxTags) SCSI tags.
@constant kTagAllocationPerTarget
Each SCSI Target has its own private tag pool contain
(maxTags) SCSI tags. Luns connected to this target
allocate tags from this pool.
@constant kTagAllocationPerController
The controller has a global tag pool containing (maxTags)
SCSI tags. This pool is shared by all Luns connected to
this controller.
*/ 
enum {
    kTagAllocationNone			= 0,
    kTagAllocationPerLun,
    kTagAllocationPerTarget,    
    kTagAllocationPerController,
};


/*!
@class IOSCSIController : public IOService
@abstract 
Superclass for SCSI host adapter drivers
@discussion 
The IOSCSIController class provides a number of services to simplify
writing a driver for your host adapter.

Specifically, the class provides the following features:

1. Complete request scheduling semantics.

The IOSCSIController class manages request queues on behalf of its
subclasses. It tracks all requests submitted to its subclasses,
including managing timeouts, aborts and request cancellations.

2. Request Sense scheduling

Subclasses of IOSCSIController do not need to implement
auto-request-sense functionality. Your driver can use the default
handling in the super class.

3. Storage management.

The IOSCSIController subclass provides per-request private storage areas
for your subclass.

4. Resource management.

The IOSCSIController subclass will manage the number of outstanding
commands submitted to your subclass on a per-controller and per-lun
basis.
*/
@class IOSCSIController : public IOService
{
public:
 
     
/*!
@function configure
@abstract 
Driver configuration/initialization request.
@discussion 
The configure() member function is the first call your subclass will
receive. You should provide the information requested in the
SCSIControllerInfo structure and enable your hardware for operation.
If your driver initialized successfully, you should return true, otherwise,
your driver should return false.
@param provider
Pointer to an object (usually IOPCIDevice) which represents the bus of
your device is attached to . Typically your driver will use functions
supplied by this object to access PCI space on your hardware. See
IOPCIDevice for a description of PCI services.
@param controllerInfo
Pointer to a SCSIControllerInfo structure. Your driver should provide
the information requested in this structure prior to returning from
the configure() call.
*/
bool configure( IOService *provider, SCSIControllerInfo *controllerInfo );


/*!
@function executeCommand
@abstract
Execute a IOSCSICommand.
@discussion
The executeCommand() function is called for all 'routine' I/O requests
including abort requests. The driver is passed a pointer to an 
IOSCSICommand object. The driver obtains information about the I/O
request by using function calls provided by the IOSCSICommand
class.
@param scsiCommand
Pointer to a IOSCSICommand. See IOSCSICommand for more information.
*/
void executeCommand( IOSCSICommand *scsiCommand );


/*!
@function cancelCommand
@abstract
Cancels a IOSCSICommand previously submitted to the driver.
@discussion
The cancelCommand() function is called to inform your subclass to force
completion of a SCSI command.

Your subclass should call the getOriginalCmd() to determine the command
to complete.

After calling complete() on the original command, you should complete
the IOSCSICommand passed to the cancelCommand() function

Note: When a cancelCommand is issued, your subclass may presume that any
activity to remove an active command from the SCSI Target, i.e. (abort
tag/abort) has already occurred.
@param scsiCommand
Pointer to a IOSCSICommand. See IOSCSICommand for more information.
*/
void cancelCommand( IOSCSICommand *scsiCommand );
 
 
/*!
@function resetCommand
@abstract
Request the driver issue a SCSI Bus reset.
@discussion
The resetCommand() function indicates you should do a SCSI Bus Reset.
After issuing the reset you should complete to IOSCSICommand passed.

Note: After you report the IOSCSICommand Reset complete, you will
receive cancelCommand() requests for all outstanding commands.
@param scsiCommand
Pointer to a IOSCSICommand. See IOSCSICommand for more information.
*/
void resetCommand( IOSCSICommand *scsiCommand );    


/*!
@function resetOccurred
@abstract
Inform the IOSCSIController class of an unsolicited SCSI Bus reset.
@discussion 
Your subclass should call this function if
you detect a target initiated bus reset, or need to do an unplanned SCSI
Bus Reset as part of adapter error recovery.

Note: After you call the resetOccurred() function, you will receive
cancelCommand() requests for all outstanding IOSCSICommand(s).
*/
void resetOccurred();

/*!
@function rescheduleCommand
@abstract
Return a IOSCSICommand for rescheduling.
@discussion
If your subclass function cannot start processing an otherwise
acceptable IOSCSICommand due to resource constraints, i.e. MailBox full,
lost SCSI Bus arbitration, you may have the IOSCSICommand rescheduled by
calling rescheduleCommand(). A IOSCSICommand passed to this function
should be treated as 'complete', i.e. you should make no further
accesses to it.

Note: If you cannot process further commands, you should call the
disableCommands() function to prevent receiving additional commands
until you are ready to accept them.
@param scsiCommand
Pointer to IOSCSICommand your driver needs to reschedule.
*/
void rescheduleCommand( IOSCSICommand *scsiCommand );


/*!
@function disableCommands
@abstract
Suspend sending I/O commands to your driver.
@discussion
In cases where your executeCommand() member function cannot accept
commands, you may disable further calls by invoking disableCommands().
Use enableCommands() to resume receiving commands.

Note: The resetCommand() and cancelCommands() entry points are not
affected by the use of this function.

Note: The default timeout for disableCommands() is 5s. If this timeout
is exceeded the IOSCSIController class will call your driver's 
disableTimeoutOccurred() function. The default action of this function
is to issue a SCSI Bus Reset by calling your driver's resetCommand()
function.
@param timeoutmS
Your driver may override the default timeout 
by specifying a timeout value in milliseconds.
*/
void disableCommands( UInt32 timeoutmS );


/*!
@function enableCommands
@abstract
Resume sending I/O commands to your driver.
@discussion
Resumes sending I/O commands to your driver that were previously suspended
by calling disableCommands().
*/
void enableCommands();

/*!
@function disableTimeoutOccurred
@abstract
Indicates your driver has suspended commands too long.
@discussion
The IOSCSIController superclass will timeout disableCommand() requests
to preclude the possibility of a hung SCSI bus. If a timeout occurs,
then disableTimeoutOccurred() will be called. The default action of this
routine is to do a SCSI Bus Reset by calling resetCommand(). Your
subclass may choose to modify the default behavior of this routine to do
additional adapter specific error recovery.
*/
void disableTimeoutOccurred();


/*!
@function findCommandWithNexus
@abstract
Locate an active IOSCSICommand using target/lun/tag values.
@discussion
Your subclass can use this function to search for an active
IOSCSICommand by providing the target/lun/tag values for the command. In
the case of a non-tagged command the second parameter must either be
omitted or set to -1.

An unsuccessful search will return 0.
@param targetLun
Structure of type SCSITargetLun, initialized to the target/lun value you
wish to search for.
@param tagValue
Optional tag value you wish to search for. 
*/
IOSCSICommand *findCommandWithNexus( SCSITargetLun targetLun, UInt32 tagValue = (UInt32) -1 );

/*!
@function allocateTarget
@abstract
Notifies driver of allocation of per-Target resources.
@discussion
Your driver will be called at its allocateTarget() function when a target is about
to be probed. The your driver should initialize its per-target data at this time.
If the subclass wishes to prevent probing of this target, it should return false
as the result of this function call.

This is an optional function. Your driver is not required to implement it.
@param targetLun
SCSITargetLun structure containing the SCSI Id of the target that is about to be
allocated.
*/
bool allocateTarget( SCSITargetLun targetLun );


/*!
@function deallocateTarget
@abstract
Notifies driver that target resources will be deallocated.
@discussion
Your driver will be called at its deallocateTarget() function when a target is about
deallocated. The your driver must insure that there will be no further access to
the per-target data allocated to this target.

This is an optional function. Your driver is not required to implement it.
@param targetLun
SCSITargetLun structure containing the SCSI Id of the target that is about to be
deallocated.
*/
bool deallocateTarget( SCSITargetLun targetLun );


/*!
@function allocateLun
@abstract
Notifies driver of allocation of per-Lun resources.
@discussion
Your driver will be called at its allocateLun() function when a Lun is about
to be probed. The your driver should initialize its per-lun data at this time.
If the subclass wishes to prevent probing of this lun, it should return false
as the result of this function call.

This is an optional function. Your driver is not required to implement it.
@param targetLun
SCSITargetLun structure containing the SCSI Id of the target/lun that is about to be
allocated.
*/
bool allocateLun( SCSITargetLun targetLun );


/*!
@function deallocateLun
@abstract
Notifies driver of deallocation of per-Lun resources.
@discussion
Your driver will be called at its deallocateLun() function when a Lun is about
deallocated. The your driver must insure that there will be no further access to
the per-lun data allocated to this lun.

This is an optional function. Your driver is not required to implement it.
@param targetLun
SCSITargetLun structure containing the SCSI Id of the target/lun that is about to be
deallocated.
*/
bool allocateLun( SCSITargetLun targetLun );


/*!
@function getTargetData
@abstract
Obtains a pointer to per-Target data allocated by IOSCSIController.
@discussion
This function returns a pointer to per-Target workarea allocated for 
your driver's use. The size of this area must be specified in the 
during the configure() function. See struct SCSIControllerInfo, 
field targetDataSize.
@param targetLun
SCSITargetLun structure containing the SCSI Id of the target who's
workarea you are requesting a pointer to. 
*/
void *getTargetData( SCSITargetLun targetLun );


/*!
@function getLunData
@abstract
Obtains a pointer to per-Lun data allocated by IOSCSIController.
@discussion
This function returns a pointer to per-Lun workarea allocated for 
your driver's use. The size of this area must be specified  
during the configure() function. See struct SCSIControllerInfo, 
field lunDataSize.
*/
void *getLunData( SCSITargetLun targetLun );


/*!
@function getWorkLoop
@abstract
Returns the IOWorkLoop object that services your driver.
*/
IOWorkloop *getWorkLoop();


}
