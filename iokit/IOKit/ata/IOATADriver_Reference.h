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
@header IOATAStandardDriver_Reference.h

This header defines the IOATAStandardDriver class.

This class provides a standard ATA/ATAPI driver implementation. 

In most cases ATA controller drivers should be implemented to this class since
it relieves the controller driver writer from having to implement most of the ATA/ATAPI
protocol. 
*/

/*!
@typedef ATAControllerInfo
Parameter structure passed for configure() function.
@field maxDevicesSupported
Maximum ATA devices supported per bus. Normally set to (2).
@field devicePrivateDataSize
Size of per unit storage (in bytes) available to the controller driver. See getDeviceData.
@field commandPrivateDataSize
Size of per command storage (in bytes) available to the controller driver. See getCommandData.
@field disableCancelCommands
Normally set to false by the controller driver.
*/
typedef struct ATAControllerInfo {

    UInt32	maxDevicesSupported;
 
    UInt32	devicePrivateDataSize;
    UInt32	commandPrivateDataSize;

    bool	disableCancelCommands;

    UInt32	reserved[64];

} ATAControllerInfo;
 
class IOATAStandardDriver : public IOATAStandardController
{
protected:

/*!
@function writeATAReg
@abstract
ATA taskfile register write function.
@discussion
The controller driver must implement this function by writing the indicated 
ATA register.
@param regIndex
Register index values are defined by enum ATARegs. See IOATADevice_Reference.
@param regValue
Register value. For the ATA Data Register this is a 16-bit value. For other registers,
this is an 8-bit value.
*/
    virtual void		writeATAReg( UInt32 regIndex, UInt32 regValue ) 	= 0;
    
/*!
@function readATAReg
ATA taskfile register read function.
@discussion
The controller driver must implement this function by reading the indicated ATA register and returning the register value as a (UInt32).
@param regIndex
Register index values are defined by enum ATARegs. See IOATADevice_Reference.
*/   
    virtual UInt32		readATAReg(  UInt32 regIndex ) 				= 0;

/*!
@function selectTiming
Select ATA timing parameters.
@discussion
The controller driver will be called at this entry point to indicate the timing to use
the next time the indicated device is selected. See newDeviceSelected(). 
@param deviceNum
The unit number (0/1) of the IOATADevice the timing is to apply to.
@param timingProtocol
The timing protocol to use the next time the device is selected. See enum ATATimingProtocol in
IOATADevice_Reference. 

Note:The controller driver should have calculated and cached the necessary
controller register settings when the timing parameters were presented by the 
calculateTiming() function.
*/
    virtual bool 		selectTiming( ATAUnit deviceNum, ATATimingProtocol timingProtocol ) = 0;

/*!
@function calculateTiming
Convert ATA timing parameters to controller register settings.
@discussion 
The controller driver is presented with proposed timings. If the controller driver
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
    virtual bool 		calculateTiming( UInt32 deviceNum,  ATATiming *timing )			= 0;

/*!
@function programDMA
Program the controller DMA hardware.
@discussion
The controller driver is presented with an IOATACommand and should use the 
IOATACommand's getPointers() function to obtain the command's IOMemoryDescriptor,
transfer length and transfer direction. The controller driver then should
use IOMemoryCursor functions to obtain the physical transfer list for 
the data buffer.
@param cmd
Pointer to an IOATACommand.
*/  
    virtual bool		programDma( IOATAStandardCommand *cmd );
    
/*!
@function startDma
Start the controller DMA hardware.
@discussion
The controller driver should start the controller's DMA hardware with settings 
corresponding to the last programDma() function call.
@param cmd
Pointer to an IOATACommand. This will normally be the same command that was previously
presented during the programDma() call.
*/   
    virtual bool		startDma( IOATAStandardCommand *cmd );
    
/*!
@function stopDma
Stop the controller DMA hardware.
@discussion
The controller driver should stop the controller's DMA hardware and return the
current transfer count.
@param cmd
Pointer to an IOATACommand. This will normally be the same command that was previously
presented during the programDma() call.
*/    
    virtual bool		stopDma( IOATAStandardCommand *cmd, UInt32 *transferCount );
    
/*!
@function resetDma
Reset the controller DMA hardware.
@discussion
The controller driver should unconditionally stop the controller's DMA hardware.
*/    
    virtual bool		resetDma();
    
/*!
@function checkDmaActive
Return the state of the controller's DMA hardware.
@discussion
This function should return true if the controller's DMA channel is active, i.e. there
is a non-zero transfer count and false if the transfer count has been met.
*/    
    virtual bool		checkDmaActive();

/*!
@function newDeviceSelected
Indicates that a new ATA unit is to be selected.
@discussion
The controller driver should do any controller operation associated with selecting
a new ata unit.
*/  
    virtual void		newDeviceSelected( IOATAStandardDevice *newDevice );
    
/*!
@function interruptOccurred
Indicates that a controller interrupt occurred.
@discussion
This function will be called prior to the ATA standard driver begins processing
the interrupt event. A controller which 'latches' interrupt events should clear
the interrupting condition and then call the ATA standard driver interrupt handler
by calling super::interruptOccurred().
*/
    virtual void		interruptOccurred();
   
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

};  

