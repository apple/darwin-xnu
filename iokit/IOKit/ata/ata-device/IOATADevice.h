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
/*
 *
 *	IOATADevice.h
 *
 *
 *	Methods in this header provide information about the ATA device 
 *      the device client driver is submitting the ATACommand(s) to.
 *
 * 	Note: ATACommand(s) are allocated and freed by methods in this class. 
 *            The remaining methods to setup and submit ATACommands are defined in
 *            IOATACommand.h
 */

#ifndef _IOATADEVICE_H
#define _IOATADEVICE_H

class IOATACommand;

class IOATADevice : public IOCDBDevice
{
    OSDeclareAbstractStructors(IOATADevice)

/*------------------Methods provided to IOCDBDevice clients-----------------------*/
public:

    /*
     * Allocate a CDB Command
     */
    virtual IOCDBCommand 	*allocCommand( IOCDBDevice *cdbDevice, UInt32 clientDataSize = 0 ) = 0;

    /*
     * Abort all outstanding commands on this device
     */
    virtual void		abort() = 0;
    
    /*
     * Reset device (also aborts all outstanding commands)
     */
    virtual void		reset() = 0;

    /*
     * Obtain information about this device
     */
    virtual void		getInquiryData( void    *inquiryBuffer, 
                                                UInt32  inquiryBufSize, 
                                                UInt32  *inquiryDataSize ) = 0;

/*------------------Additional methods provided to IOATADevice clients-----------------------*/
public:
    /*
     * Allocate a ATACommand
     */
    virtual IOATACommand	*allocCommand( IOATADevice *scsiDevice, UInt32 clientDataSize = 0 ) = 0;

    /*
     * Obtain information about this device
     */
    virtual ATAUnit		getUnit() = 0;
    virtual ATADeviceType	getDeviceType() = 0;
    virtual bool		getIdentifyData( ATAIdentify *identifyBuffer ) = 0;
    virtual bool		getInquiryData( UInt32 inquiryBufSize, ATAPIInquiry *inquiryBuffer ) = 0;
    virtual bool 		getDeviceCapacity( UInt32 *blockMax, UInt32 *blockSize ) = 0;
    virtual bool		getProtocolsSupported( ATAProtocol *protocolsSupported ) = 0;
    virtual bool 		getTimingsSupported( ATATimingProtocol *timingsSupported ) = 0;
    virtual bool		getTimingSelected( ATATimingProtocol *timingProtocol ) = 0;
    virtual bool		getTiming( ATATimingProtocol *timingProtocol, ATATiming *timing ) = 0;
    virtual bool		getATAPIPktInt() = 0;

    /*
     * Select default device timing for this device
     */
    virtual bool 		selectTiming( ATATimingProtocol timingProtocol, bool fNotifyMsg = false ) = 0;

    /* 
     * Queue management commands
     */
    virtual void		holdQueue( UInt32 queueType )    = 0;
    virtual void		releaseQueue( UInt32 queueType ) = 0;
    virtual void		flushQueue( UInt32 queueType, IOReturn rc ) = 0;
    virtual void		notifyIdle(  void *target = 0, CallbackFn callback = 0, void *refcon = 0 ) = 0;

};

#define kIOATADevice		((IOATADevice *)0)

#endif
