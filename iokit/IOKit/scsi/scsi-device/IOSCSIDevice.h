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
 *	IOSCSIDevice.h
 *
 *
 *	Methods in this header provide information about the SCSI device 
 *      the device client driver is submitting the SCSICommand(s) to.
 *
 * 	Note: SCSICommand(s) are allocated and freed by methods in this class. 
 *            The remaining methods to setup and submit SCSICommands are defined in
 *            IOSCSICommand.h
 */

#ifndef _IOSCSIDEVICE_H
#define _IOSCSIDEVICE_H

class IOSCSICommand;

class IOSCSIDevice : public IOCDBDevice
{
    OSDeclareAbstractStructors(IOSCSIDevice)

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

/*------------------Additional methods provided to IOSCSIDevice clients-----------------------*/
public:
    /*
     * Allocate a SCSICommand
     */
    virtual IOSCSICommand	*allocCommand( IOSCSIDevice *scsiDevice, UInt32 clientDataSize = 0 ) = 0;

    /*
     * Target management commands
     */
    virtual bool                setTargetParms( SCSITargetParms *targetParms ) = 0;
    virtual void                getTargetParms( SCSITargetParms *targetParms ) = 0;

    /* 
     * Lun management commands
     */
    virtual bool		setLunParms( SCSILunParms *lunParms ) = 0;
    virtual void		getLunParms( SCSILunParms *lunParms ) = 0;

    /* 
     * Queue management commands
     */
    virtual void		holdQueue( UInt32 queueType )    = 0;
    virtual void		releaseQueue( UInt32 queueType ) = 0;
    virtual void		flushQueue( UInt32 queueType, IOReturn rc ) = 0;
    virtual void		notifyIdle(  void *target = 0, CallbackFn callback = 0, void *refcon = 0 ) = 0;

};

#define kIOSCSIDevice		((IOSCSIDevice *)0)

#endif
