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
 *	IOCDBDevice.h
 *
 *
 *
 * 	Note: CDBCommand(s) are allocated and freed by methods in this class. 
 *            The remaining methods to setup and submit CDBCommands are defined in
 *            IOCDBCommand.h
 */
#ifndef _IOCDBDEVICE_H
#define _IOCDBDEVICE_H

class IOCDBCommand;

class IOCDBDevice : public IOService
{
    OSDeclareAbstractStructors(IOCDBDevice)

/*------------------Methods provided to IOCDBDevice clients-----------------------*/
public:
    /*
     * Allocate a CDB Command
     */
    virtual IOCDBCommand 	*allocCommand( IOCDBDevice *deviceType, UInt32 clientDataSize = 0 ) = 0;

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
};

#define kIOCDBDevice		((IOCDBDevice *)0)


#endif
