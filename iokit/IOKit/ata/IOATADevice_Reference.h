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
@header IOATADevice_Reference.h

This header defines the IOATADevice class.

The ATA/ATAPI framework creates instances of this class to
represent each valid ATA/ATAPI device detected during
ATA bus scanning. When an instance of this class is registered with
IOKit, the instance will be presented to clients which
'match' the IOATADevice class.
*/

/*!
@enum ATADeviceType
Defines ATA/ATAPI Device types.
@constant kATADeviceNone
Indicates no device installed. 
@constant kATADeviceATA
Indicates ATA type device, i.e. packet protocols not supported.
@constant kATADeviceATAPI
Indicates ATAPI type device, i.e. packet protocols supported.
*/
enum ATADeviceType {

    kATADeviceNone,
    kATADeviceATA,
    kATADeviceATAPI,
    
};

/*!
@enum ATATimingProtocol
Defines supported transport timing. See getTimingsSupported(), selectTiming().
@constant kATATimingPIO
Indicates transport timing is for Programmed I/O.
@constant kATATimingDMA
Indicates transport timing is for DMA.
@constant kATATimingDMA33
Indicates transport timing is for Ultra DMA/33.
@constant kATATimingDMA66
Indicates transport timing is for Ultra DMA/66.
@constant kATAMaxTimings
Indicates number of timing protocols defined.
*/        
enum ATATimingProtocol
{
    kATATimingPIO		= (1 << 0),
    kATATimingDMA     		= (1 << 1),
    kATATimingUltraDMA33	= (1 << 2),
    kATATimingUltraDMA66	= (1 << 3),
    kATAMaxTimings		= 4,

};

/*!
@enum ATAProtocol
Defines supported transport protocols. See getProtocolsSupported().
@constant kATAProtocolNone
Indicates no transport protocol defined.
@constant kATAProtocolSetRegs
Indicates the transport driver should do a Set ATA Registers operation. For this 
protocol, the transport driver sets the requested taskfile registers as indicated 
in the ATATaskfile structure and then reads back the taskfile registers requested.
The transport presumes the device will not generate an interrupt as a result
of this operation.
@constant kATAProtocolPIO
Indicates the transport driver should do a Programmed I/O operation. For this 
protocol, the transport driver sets the requested taskfile registers, and transfers
data to/from the IOATADevice via Programmed I/O operations. The IOATADevice client
can control the direction/amount data transferred by using setPointers() function.
The client can indicate a zero data transfer length to implement non-data transfer
commands such as power-management and set features.
@constant kATAProtocolDMA
Indicates the transport driver should do a DMA I/O operation to the device. For this 
protocol, the transport driver sets the requested taskfile registers, and transfers
data to/from the IOATADevice via DMA operations.
@constant kATAProtocolDMAQueued
Indicates the transport driver should do DMA Queued I/O operations. In this case,
the driver will queue multiple I/O operations at the IOATADevice. Both the device
and the transport driver must support this protocol.
@constant kATAProtocolDMAQueueRelease
Indicates the transport driver should do DMA Queued I/O operations with bus release. 
In this case, the driver will queue multiple I/O operations at the IOATADevice. In
addition this protocol allows Overlap between both devices on the ATA Bus.
@constant kATAProtocolATAPIPIO
Indicates the transport driver should send an use ATAPI packet protocol and transfer
data to/from the device via PIO cycles.
@constant kATAProtocolATAPIDMA
Indicates the transport driver should send an use ATAPI packet protocol and transfer
data to/from the device via DMA cycles.
*/
enum ATAProtocol {

   kATAProtocolNone		= 0,
   kATAProtocolSetRegs		= (1 << 0),
   kATAProtocolPIO		= (1 << 1),
   kATAProtocolDMA		= (1 << 2),
   kATAProtocolDMAQueued	= (1 << 3),
   kATAProtocolDMAQueuedRelease	= (1 << 4),

   kATAProtocolATAPIPIO		= (1 << 16),
   kATAProtocolATAPIDMA		= (1 << 17),
   
};

/*!
@typedef ATATiming
@abstract
Provides the low-level cycle times for the transport timing indicated.
@discussion
See enum ATATimingProtocols for a list of transport timing protocols.
@field timingProtocol
Indicates transport timing the structure refers to. See enum ATATimingProtocol
for a list of transport timings.
@field mode
Indicates the ATA DMA/PIO mode supported. The mode is a number indicating preset
timings for a particular set of timings as defined by the ATA specification.
@field minDataAccess
The minimum time (in nS) that IOW-/IOR- indicates that the data is valid for 16-bit
data transfers. This field does not apply for Ultra/33 and Ultra/66 timings.
@field minDataCycle
The minimum time (in nS) that a full 16-bit data transfer will take, i.e. the time
between consecutive assertions of IOW-/IOR-. For Ultra/33 and Ultra/66 timings
this field indicates the average single cycle time.
@field minCmdAccess
The minimum time (in nS) that IOW-/IOR- indicates that the data is valid for 8-bit
pio command transfers.
@field minCmdCycle
The minimum time (in nS) that a full 8-bit pio data transfer will take, i.e. the time
between consecutive assertions of IOW-/IOR-.
*/
typedef struct ATATiming {

    ATATimingProtocol	timingProtocol;

    UInt32		featureSetting;

    UInt32		mode;
    UInt32		minDataAccess;
    UInt32		minDataCycle;
    UInt32		minCmdAccess;
    UInt32		minCmdCycle;
    UInt32		reserved_3[9];
    
} ATATiming;
 
class IOATAStandardDevice : public IOATADevice
{
public:

/*!
@function allocCommand
@abstract 
Allocates an IOATACommand object for this device.
@discussion 
The client uses the allocCommand() member function to allocate IOATACommand(s)
for an IOATADevice. The client then uses the member functions of 
the IOATACommand to initialize it and send it to the device. A completed IOATACommand
may be reused for subsequent I/O requests or returned to the ATA/ATAPI Family.
@param deviceType
Always specify kIOATADevice.
@param clientDataSize
The client may indicate the size of a per-command data area for its own
use.
*/
     IOATACommand	*allocCommand( IOATADevice *deviceType, UInt32 clientDataSize = 0 );

/*!
@function getUnit
@abstract
Returns the ATA unit number corresponding to this device.
*/
    ATAUnit			getUnit();
    
/*!
@function getDeviceType
@abstract
Returns the type of the corresponding ATA/ATAPI device.
@discussion 
See enum ATADeviceType for return values for this function. 
*/   
    ATADeviceType		getDeviceType();
    
/*!
@function getIdentifyData
@abstract 
Returns the ATA/ATAPI Identify data for the IOATADevice
@discussion
Identify data is from the results of the last ATA bus probe.
@param identifyBuffer
Pointer to a 512-byte data buffer to receive the ATA/ATAPI Identify data.
*/  
    bool			getIdentifyData( ATAIdentify *identifyBuffer );
    
/*!
@function getInquiryData
@abstract 
Returns ATAPI Inquiry data for the IOATADevice. 
@discussion
Inquiry data returned is from the results of the last ATA bus probe.
@param inquiryBufSize
Size of the buffer supplied.
@param inquiryBuffer
Pointer to a buffer to receive the Inquiry data.
*/
    bool			getInquiryData( UInt32 inquiryBufSize, ATAPIInquiry *inquiryBuffer );
    
/*!
@function getDeviceCapacity
@abstract 
Returns the block count and block size of the ATA/ATAPI device. 
@discussion
This function returns the capacity as returned by the ATA Identify command for ATA devices,
and the Read Device Capacity for ATAPI devices. The client should use caution in interpreting
the results of this function since the results are based on the last ATA bus scan.
@param blockMax
Pointer to a (UInt32) to receive the maximum addressable block on the device. Note: The device
block count is one greater than the maximum addressable block number.
@param blockSize
Pointer to a (UInt32) to receive the block size of the device in bytes.
*/    
    bool 			getDeviceCapacity( UInt32 *blockMax, UInt32 *blockSize );
    
    
/*!
@function getProtocolSupported
@abstract 
Returns a bit mask of transport protocols this IOATADevice supports.
@discussion
There is no guarantee that a particular device/driver combination will support
all transport protocols defined. The IOATADevice client must use this function
to determine which ATAProtocol values are valid for this device.
@param protocolsSupported
Pointer to a (UInt32) to receive a bit mask of transport protocols supported. See enum
ATAProtocol of a list of transport protocols.
*/
    bool			getProtocolsSupported( ATAProtocol *protocolsSupported );
    
/*!
@function getTimingsSupported
@abstract
Returns a bit mask of transport timings this IOATADevice supports
@discussion
There is no guarantee that a particular device/driver combination will support
all transport timings defined. The IOATADevice client must use this function
to determine which ATATimingProtocol values are valid for this device.
@param protocolsSupported
Pointer to a (UInt32) to receive a bit mask of transport timings supported. See enum
ATATimingProtocol of a list of transport timings.
*/
    bool 			getTimingsSupported( ATATimingProtocol *timingsSupported );
    
/*!
@function getTimingSelected
@abstract
Returns the last transport timing selected for the device
@param timingProtocol
Pointer to a (UInt32) to receive the current timing protocol selected. See enum ATATimingProtocol
for a list of transport timing protocols.
*/    
    bool			getTimingSelected( ATATimingProtocol *timingProtocol );
    
/*!
@function getTiming
@abstract
Returns the parameters for the transport timing indicated.
@discussion
If the transport/device combination does not support the transport timing
indicated, then this function will return false. See getTimingsSupported()
to obtain a bit mask of supported timings.
@param timingProtocol
Pointer to a (UInt32) which the client has set to the timing protocol whose parameters are
to be obtained.
@param timing
Pointer to a (struct ATATiming) to receive the parameters (cycle timings) for the requested
timing.
*/    
    bool			getTiming( ATATimingProtocol *timingProtocol, ATATiming *timing );
    
/*!    
@function getATAPIPktInt
@abstract
Returns whether the an ATAPI device will generate an Interrupt prior to signal it is ready
to request a command packet.
@discussion
A return value of (true) will indicates the device will generate a packet transfer interrupt. 
This function would not normally need to be used by the IOATADevice client. It is for use
by the transport driver.
*/
    bool			getATAPIPktInt();

/*!
@function selectTiming
@abstract
Selects the transport timing to be used for this IOATADevice.
@discussion
The IOATADevice client must issue the selectTiming() function when initializing an IOATADevice and
after an ATA Bus Reset event. 
@param timingProtocol
The transport timing to be selected for the device. See getTimingsSupported() for transport timings
supported by the transport/device combination.
@param fNotifyMsg
If fNotifyMsg is set to false, selectTiming() operates a synchronous call, i.e. it blocks the
client until it completes. If the client needs to call this function during an event such as
an ATA Bus Reset, it must use the asynchronous version of this function by setting fNotifyMsg
to true. In this case the client will be notified via a message when this function has
completed.
*/
    bool 			selectTiming( ATATimingProtocol timingProtocol, bool fNotifyMsg = false );
    
/*!
@function holdQueue
@abstract 
Suspends sending additional IOATACommand to this device.
@discussion
holdQueue() may only be called from the IOATADevice workloop. The client
is guaranteed to be running in this context during a message() notification.

holdQueue() has no effect on commands already passed to the host adapter. One
or more commands may complete after the queue is held. See notifyIdle()
@param queueType
Perform action on the indicated queue. See enum ATAQueueType in IOATACommand.
*/
    void			holdQueue( UInt32 queueType );
    
/*!
@function releaseQueue
@abstract
Resumes sending IOATACommands to the IOATADevice. 
@discussion
If the device queue was not held, releaseQueue() has no effect.

releaseQueue() may only be called from the IOATADevice workloop. This is guaranteed
to be the case after a IOATACommand completion of after a message() notification.
@param queueType
Perform action on the indicated queue. See enum ATAQueueType in IOATACommand.
*/    
    void			releaseQueue( UInt32 queueType );
    
/*!
@function flushQueue
@abstract 
Returns any commands on the IOATADevice's pending work queue.
@discussion
flushQueue() may only be called from the IOATADevice workloop. This is 
guaranteed to be the case after a IOATACommand completion of after a 
message() notification.

All pending command are completed prior to flushQueue() returning to the caller.

flushQueue() has no effect on commands already passed to the host adapter. One
or more commands may complete after the queue is flushed. See notifyIdle().
@param queueType
Perform action on the indicated queue. See enum ATAQueueType in IOATACommand.
@param rc
The return code of any flushed commands is set to (rc).
*/    
    void			flushQueue( UInt32 queueType, IOReturn rc );
    
/*!
@function notifyIdle
@abstract
Notifies the client when all active commands on an ATA device have completed.
@discussion
notifyIdle() may only be called from the IOATADevice workloop. This is guaranteed
to be the case after a IOATACommand completion of after a message() notification.

Only one notifyIdle() call may be active. Any outstanding notifyIdle() calls may
be cancelled by calling notifyIdle() with no parameters.
@param target
Object to receive the notification. Normally the client's (this) pointer.
@param callback
Pointer to a callback routine of type CallbackFn.
@param refcon
Pointer to client's private data.
*/   
    void			notifyIdle(  void *target = 0, CallbackFn callback = 0, void *refcon = 0 );

/*!
@function getWorkLoop
@abstract
Returns the IOWorkLoop object that services this IOATADevice.
*/
IOWorkloop *getWorkLoop();

};
