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
@header IOATAController_Reference.h

This header defines the IOATAController class.

IOATAController provides the superclass for the ATA Family. In most
cases, actual controller drivers should be implemented to IOATAStandardDriver
which converts the relatively high-level commands produced by this class
to low-level ATA register commands.

This class may be useful in cases where the actual ATA device is connected
by some intermediate bus and it would be more efficient for family for that
bus to deal with high-level commands rather than low-level ATA register I/O.
*/

class IOATAStandardController : public IOService
{

public:

/*!
@function reset
@abstract
Perform an ATA bus reset.
@discussion
This function requests the IOATAController class to perform an ATA Bus reset. 

The IOATAController class will convert this request into a reset command and
will call the resetCommand() function.

The reset() function is synchronous, i.e. it will wait for the reset to complete.
*/
    IOReturn			reset();

protected:

/*!
@function enableCommands
@abstract
Resume sending I/O commands to your driver.
@discussion
Resumes sending I/O commands to your driver that were previously suspended
by calling disableCommands().
*/
    void			enableCommands();
    
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
is exceeded the IOATAController class will call your driver's 
disableTimeoutOccurred() function. The default action of this function
is to issue a ATA Bus Reset by calling your driver's resetCommand()
function.
@param timeoutmS
Your driver may override the default timeout 
by specifying a timeout value in milliseconds.
*/
    void			disableCommands( UInt32 disableTimeoutmS );
    
/*!
@function rescheduleCommand
@abstract
Return a IOATACommand for rescheduling.
@discussion
If your subclass function cannot start processing an otherwise
acceptable IOATACommand, you may have the IOATACommand rescheduled by
calling rescheduleCommand(). A IOATACommand passed to this function
should be treated as 'complete', i.e. you should make no further
accesses to it.

Note: If you cannot process further commands, you should call the
disableCommands() function to prevent receiving additional commands
until you are ready to accept them.
@param ataCommand
Pointer to IOATACommand your driver needs to reschedule.
*/
    void			rescheduleCommand( IOATAStandardCommand *forATACmd );

    void			resetStarted();
    void 			resetOccurred();


/*!
@function findCommandWithNexus
@abstract
Locate an active IOATACommand using device/tag values.
@discussion
Your subclass can use this function to search for an active
IOATACommand by providing the device/tag values for the command. In
the case of a non-tagged command the second parameter must either be
omitted or set to -1.

An unsuccessful search will return 0.
@param forDevice
Pointer to an IOATADevice. 
wish to search for.
@param tagValue
Optional tag value you wish to search for. 
*/
    IOATAStandardCommand	*findCommandWithNexus( IOATAStandardDevice *forDevice, UInt32 tagValue = (UInt32)-1 );

/*!
@function getDeviceData
@abstract
Obtains a pointer to per-device data allocated by IOATAController.
@discussion
This function returns a pointer to per-device workarea allocated for 
your driver's use. The size of this area must be specified in the 
during the configure() function. See struct ATAControllerInfo, 
field devicePrivateDataSize.
@param forUnit
The unit number of the ata device.
*/
    void 			*getDeviceData( ATAUnit forUnit );
    
/*!
@function getWorkLoop
@abstract
Returns/provides the IOWorkLoop object that services your driver.
@discussion
If your driver wishes to create its own workloop, you should implement this
function and return the IOWorkLoop for your subclass. Otherwise, if you
return 0, the IOATAController class will create a workloop for your driver.
*/
    virtual IOWorkLoop  	*getWorkLoop() const;

/*!
@function getCommandCount
@abstract
Returns the current active command count for your driver.
@discussion
This indicates the number of executeCommands that have been sent to your
driver and have not been completed.
*/
    UInt32			getCommandCount();
    
/*!
@function setCommandLimit
@abstract
Modifies command limit indicated for the IOATADevice device.
@discussion
If the device currently has more than commands outstanding than the new command limit,
additional commands will not be sent to the device. If the command limit is increased,
the additional commands will be sent until the command limit is met.
@param device
Pointer to an IOATADevice.
@param commandLimit
New limit on outstanding executeCommands.
*/     
    void			setCommandLimit( IOATAStandardDevice *device, UInt32 commandLimit );			

/*!
@function suspendDevice
@abstract
Stops sending executeCommands to the indicated device.
@discussion
This function causes the IOATAController class to stop sending executeCommands to the
indicated device.
@param forATADevice
Pointer to an IOATADevice for which executeCommand delivery is to be suspended.
*/
    void			suspendDevice( IOATAStandardDevice *forATADevice );
    
/*!
@function resumeDevice
@abstract
Resumes sending executeCommands to the indicated device.
@discussion
This function causes the IOATAController class to resume sending executeCommands to an
IOATADevice that was previously suspended. If the IOATADevice was not previously
suspended, then this call has no effect.
@param forATADevice
Pointer to an IOATADevice for which executeCommand delivery is to be resumed.
*/    
    void			resumeDevice( IOATAStandardDevice *forATADevice );
    
/*!
@function selectDevice
@abstract
Returns a pointer to the IOATADevice device that was suspended the for the 
longest amount of time.
@discussion
This function returns a 'hint' as which device to resume to implement fairness
in servicing IOATADevice contending for access to the ATA bus.
*/    
    IOATAStandardDevice		*selectDevice();

protected:

/*!
@function configure
@abstract 
Driver configuration/initialization request.
@discussion 
The configure() member function is the first call your subclass will
receive. You should provide the information requested in the
ATAControllerInfo structure and enable your hardware for operation.
If your driver initialized successfully, you should return true, otherwise,
your driver should return false.
@param provider
Pointer to an object (usually IOPCIDevice) which represents the bus of
your device is attached to . Typically your driver will use functions
supplied by this object to access PCI space on your hardware. See
IOPCIDevice for a description of PCI services.
@param controllerInfo
Pointer to a ATAControllerInfo structure. Your driver should provide
the information requested in this structure prior to returning from
the configure() call.
*/
    virtual bool 		configure( IOService *provider, ATAControllerInfo *controllerInfo ) = 0;
    
/*!
@function getProtocolSupported
@abstract 
Returns a bit mask of transport protocols this IOATADevice supports.
@discussion
The subclass of IOATAController must return a bit-mask of transport protocols supported.
@param protocolsSupported
Pointer to a (UInt32) to receive a bit mask of transport protocols supported. See enum
ATAProtocol of a list of transport protocols.
*/
    virtual bool        	getProtocolsSupported( ATAProtocol *protocolsSupported ) = 0;

/*!
@function executeCommand
@abstract
Execute an IOATACommand.
@discussion
The executeCommand() function is called for all 'routine' I/O requests. 
The driver is passed a pointer to an 
IOATACommand object. The driver obtains information about the I/O
request by using function calls provided by the IOATACommand
class.
@param ataCommand
Pointer to an IOATACommand. See IOATACommand_Reference for more information.
*/
    virtual void		executeCommand( IOATAStandardCommand *forATACmd ) = 0;
    
/*!
@function cancelCommand
@abstract
Cancels a IOATACommand previously submitted.
@discussion
The cancelCommand() function is called to inform your subclass to force
completion of an ATA command.

Your subclass should call the getOriginalCmd() to determine the command
to complete.

After calling complete() on the original command, you should complete
the IOATACommand passed to the cancelCommand() function

Note: When a cancelCommand is issued, your subclass may presume that any
activity to remove an active command has already occurred.
@param ataCommand
Pointer to a IOATACommand. See IOATACommand for more information.
*/    
    virtual void		cancelCommand(  IOATAStandardCommand *forATACmd ) = 0;
    
/*!
@function resetCommand
@abstract
Request the IOATAController subclass issue an ATA Bus reset.
@discussion
The resetCommand() function indicates you should do an ATA Bus Reset.
After issuing the reset you should complete to IOATACommand passed.

Note: After you report the IOATACommand Reset complete, you will
receive cancelCommand() requests for all outstanding commands.
@param ataCommand
Pointer to a IOATACommand. See IOATACommand for more information.
*/
    virtual void		resetCommand(   IOATAStandardCommand *forATACmd ) = 0; 
    
/*!
@function abortCommand
@abstract 
Requests the IOATAController subclass abort a currently executing command.

Note: In most cases ATA does not provide semantics to cleanly abort an executing
command. In these cases, the subclass may reset the ATA bus to implement this
function.
@param forATACmd
Pointer to an active IOATACommand to be aborted.
*/       
    virtual void		abortCommand(   IOATAStandardCommand *forATACmd ) = 0;    

/*!
@function calculateTiming
Convert ATA timing parameters to controller register settings.
@discussion 
The IOATAController subclass is presented with proposed timings. If the subclass
can support the provided timing parameters, it should calculate the corresponding
controller register settings and make them available for future lookup indexed
by the timingProtocol field of the ATATiming structure. If the controller driver
cannot support the indicated timing it should return false as the calculateTiming()
result.
@param deviceNum
The unit number (0/1) of the IOATADevice the timing is to apply to.
@param timing
A pointer to a ATATiming structure containing the parameters for the selected
timing.
*/
    virtual bool 		calculateTiming( UInt32 deviceNum,  ATATiming *timing )	= 0;


/*!
@function allocateDevice
@abstract
The IOATAController class informs its subclass of allocation of an ATA device.
@discussion
The IOATAController subclass will be called at its allocateDevice() function when an
ATA device is about to be probed. The subclass should initialize its per-device data at 
this time. If the subclass wishes to prevent probing of this device, it should return false
as the result of this function call.

Note: This is an optional function. Your driver is not required to implement it.
@param unit
The ATA unit number of the device about to be allocated.
*/
    virtual bool		allocateDevice( ATAUnit unit );
    
/*!
@function deallocateDevice
@abstract
The IOATAController class informs its subclass of deallocation of an ATA device.
@discussion
The IOATAController subclass will be called at its deallocateDevice() function when 
an ATA device is about to be deallocated. The subclass must insure that there will 
be no further access to the per-device data allocated to this device.

Note: This is an optional function. Your driver is not required to implement it.
@param unit
The ATA unit number of the device about to be deallocated.
*/    
    virtual void		deallocateDevice( ATAUnit unit );

/*!
@function disableTimeoutOccurred
@abstract
Indicates the IOATAController subclass has suspended commands too long.
@discussion
The IOATAController class will timeout disableCommand() requests
to preclude the possibility of a hung ATA bus. If a timeout occurs,
then disableTimeoutOccurred() will be called. The default action of this
routine is to do a ATA Bus Reset by calling resetCommand(). Your
subclass may choose to modify the default behavior of this routine to do
additional adapter specific error recovery.
*/
    virtual void		disableTimeoutOccurred();
    
/*!
@function enableControllerInterrupts
@abstract
Indicates the IOATAController subclass should enables its controller interrupt.
@discussion
The default implementation of this function enables all interrupt sources
associated with the current workloop. If the subclass needs more precise
control of its interrupt sources it should replace the implementation of
this function with its own.
*/    	
    virtual void		enableControllerInterrupts();
    
/*!
@function disableControllerInterrupts
@abstract
Indicates the IOATAController subclass should disable its controller interrupt.
@discussion
The default implementation of this function disables all interrupt sources
associated with the current workloop. If the subclass needs more precise
control of its interrupt sources it should replace the implementation of
this function with its own.
*/    	    
    virtual void		disableControllerInterrupts();

};

