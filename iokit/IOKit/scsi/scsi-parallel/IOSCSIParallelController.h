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
 *	IOSCSIController.h
 *
 *	Methods in this header list the methods an SCSI controller driver must implement. 
 */
#ifndef _IOSCSIPARALLELCONTROLLER_H
#define _IOSCSIPARALLELCONTROLLER_H

#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IOTimerEventSource.h>
#include <libkern/OSByteOrder.h>
#include <IOKit/IOMemoryCursor.h>

class IOSCSIParallelDevice;
class IOSCSIParallelCommand;

class IOSCSIParallelController : public IOService
{
    OSDeclareDefaultStructors(IOSCSIParallelController)

    friend class IOSCSIParallelCommand;
    friend class IOSCSIParallelDevice;

/*------------------Methods provided by IOSCSIParallelController---------------------------------*/
public:
    bool			probeTarget( SCSITargetLun targetLun );
    void			reset();

protected:
    void			resetOccurred();

    void			enableCommands();
    void			disableCommands();
    void			disableCommands( UInt32 disableTimeoutmS );

    void			rescheduleCommand( IOSCSIParallelCommand *forSCSICmd );

    IOSCSIParallelDevice        *findDeviceWithTargetLun( SCSITargetLun targetLun );
    IOSCSIParallelCommand       *findCommandWithNexus( SCSITargetLun targetLun, UInt32 tagValue = (UInt32)-1 );

    void 			*getTargetData( SCSITargetLun targetLun );
    void 			*getLunData( SCSITargetLun targetLun );

    virtual IOWorkLoop  	*getWorkLoop() const;

    void			setCommandLimit( UInt32 commandLimit );			// temp


/*------------------Methods the controller subclass must implement-----------------------*/
protected:
    /*
     *   Initialize controller hardware.
     *
     *   Note: The controller driver's configure() method will be called prior to any other
     *         methods. If the controller driver returns successfully from this method it
     *         should be ready to accept any other method call listed.
     */
    virtual bool 		configure( IOService *provider, SCSIControllerInfo *controllerInfo ) = 0;

    /*
     *	Bus/target commands
     *
     */
    virtual void		executeCommand( IOSCSIParallelCommand *forSCSICmd ) = 0;
    virtual void		cancelCommand(  IOSCSIParallelCommand *forSCSICmd ) = 0;
    virtual void		resetCommand(   IOSCSIParallelCommand *forSCSICmd ) = 0;    

/*------------------Optional methods the controller subclass may implement-----------------------*/
protected:
    /*
     *    These methods notify the IOSCSIParallelController subclass, that a target or lun is about to be
     *    probed. The subclass should initialize its per-target or per-lun data when called at these
     *    methods. If the subclass (for some reason) wants to prevent probing of a target or lun, it
     *    can return false to the corresponding allocate*() call.
     */    
    virtual bool		allocateTarget( SCSITargetLun targetLun );
    virtual void		deallocateTarget( SCSITargetLun targetLun );

    virtual bool		allocateLun( SCSITargetLun targetLun );
    virtual void		deallocateLun( SCSITargetLun targetLun );

    virtual void		disableTimeoutOccurred();	


/*------------------Methods private to the IOSCSIParallelController class----------------------*/

public:
    bool 			start( IOService *provider );
    void 			free();

private:
    IOSCSIParallelDevice 	*createDevice();

    void			initQueues();
    bool 			scanSCSIBus();

    bool 			initTarget( SCSITargetLun targetLun );
    bool 			initTargetGated( SCSITargetLun *targetLun );
    void			releaseTarget( SCSITargetLun targetLun );
    void			releaseTargetGated( SCSITargetLun *targetLun );
    bool			initDevice( IOSCSIParallelDevice *device );
    bool			initDeviceGated( IOSCSIParallelDevice *device );
    void 			releaseDevice( IOSCSIParallelDevice *device );
    void 			releaseDeviceGated( IOSCSIParallelDevice *device );


    void 			addDevice( IOSCSIParallelDevice *forDevice );
    void 			deleteDevice( IOSCSIParallelDevice *forDevice );

    void			timer( IOTimerEventSource *);

    void			dispatchRequest();
    void			dispatch();

    bool			checkBusReset();
    
    void			completeCommand( IOSCSIParallelCommand *forSCSICmd );

    bool 			createWorkLoop();
    bool 			configureController();

    IOSCSIParallelCommand 	*allocCommand( UInt32 clientDataSize );

private:
    
    UInt32			sequenceNumber;

    UInt32			commandCount;
    UInt32			commandLimit;
    UInt32			commandLimitSave;

    UInt32			disableTimer;
    bool			commandDisable;

    UInt32			tagArraySize;
    UInt32			*tagArray;
    
    UInt32			busResetState;
    IOSCSIParallelCommand	*resetCmd;
    UInt32			resetTimer;

    IOSCSIParallelCommand	*noDisconnectCmd;

    SCSIControllerInfo		controllerInfo;
    SCSITarget  		*targets;
    
    IOWorkLoop			*workLoop;
    IOTimerEventSource		*timerEvent;
    IOInterruptEventSource	*dispatchEvent;

    IOCommandGate		*controllerGate;

    IOService			*provider;
};

#endif
