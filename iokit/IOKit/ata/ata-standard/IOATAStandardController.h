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
 *	IOATAController.h
 *
 *	Methods in this header list the methods an ATA controller driver must implement. 
 */
#ifndef _IOATASTANDARDCONTROLLER_H
#define _IOATASTANDARDCONTROLLER_H

#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IOTimerEventSource.h>
#include <libkern/OSByteOrder.h>
#include <IOKit/IOMemoryCursor.h>

class IOATAStandardDevice;
class IOATAStandardCommand;
class IOATAStandardDriver;

class IOATAStandardController : public IOService
{
    OSDeclareDefaultStructors(IOATAStandardController)

    friend class IOATAStandardCommand;
    friend class IOATAStandardDevice;
    friend class IOATAStandardDriver;

/*------------------Methods provided by IOATAStandardController---------------------------------*/
public:
    IOReturn			reset();

protected:
    void			enableCommands();
    void			disableCommands();
    void			disableCommands( UInt32 disableTimeoutmS );

    void			rescheduleCommand( IOATAStandardCommand *forATACmd );

    void			resetStarted();
    void 			resetOccurred();

    IOATAStandardCommand	*findCommandWithNexus( IOATAStandardDevice *forDevice, UInt32 tagValue = (UInt32)-1 );

    void 			*getDeviceData( ATAUnit forUnit );

    virtual IOWorkLoop  	*getWorkLoop() const;

    UInt32			getCommandCount();
    void			setCommandLimit( IOATAStandardDevice *device, UInt32 commandLimit );			

    void			suspendDevice( IOATAStandardDevice *forATADevice );
    void			resumeDevice( IOATAStandardDevice *forATADevice );
    IOATAStandardDevice		*selectDevice();

    bool			getTiming( ATAUnit unit, ATATimingProtocol *timingProtocol );


/*------------------Methods the controller subclass must implement-----------------------*/
protected:
    /*
     *   Initialize controller hardware.
     *
     *   Note: The controller driver's configure() method will be called prior to any other
     *         methods. If the controller driver returns successfully from this method it
     *         should be ready to accept any other method call listed.
     */
    virtual bool 		configure( IOService *provider, ATAControllerInfo *controllerInfo ) = 0;
    
    /*
     *  Driver must indicate which ATA protocols it supports. 
     */
    virtual bool        	getProtocolsSupported( ATAProtocol *protocolsSupported ) = 0;

    /*
     *	Bus/target commands
     *
     */
    virtual void		executeCommand( IOATAStandardCommand *forATACmd ) = 0;
    virtual void		cancelCommand(  IOATAStandardCommand *forATACmd ) = 0;
    virtual void		resetCommand(   IOATAStandardCommand *forATACmd ) = 0;    
    virtual void		abortCommand(   IOATAStandardCommand *forATACmd ) = 0;    

    /*
     *  Methods to set timing for individual devices
     */	
    virtual bool 		calculateTiming( UInt32 deviceNum,  ATATiming *timing )			= 0;

/*------------------Optional methods the controller subclass may implement-----------------------*/
protected:
    /*
     *    These methods notify the IOATAStandardController subclass, that a target or lun is about to be
     *    probed. The subclass should initialize its per-target or per-lun data when called at these
     *    methods. If the subclass (for some reason) wants to prevent probing of a target or lun, it
     *    can return false to the corresponding allocate*() call.
     */    
    virtual bool		allocateDevice( ATAUnit unit );
    virtual void		deallocateDevice( ATAUnit unit );

    virtual void		disableTimeoutOccurred();	

    /*
     *
     */
    virtual void		enableControllerInterrupts();
    virtual void		disableControllerInterrupts();

/*------------------Methods private to the IOATAStandardController class----------------------*/

public:
    bool 			start( IOService *provider );
    void 			free();

private:
    void			initQueues();
    bool 			scanATABus();
    void			resetATABus();

    bool 			createDeviceNubs();
    bool 			probeDeviceNubs();
    bool 			registerDeviceNubs();
    bool 			initTimings();
    bool 			matchNubWithPropertyTable( IOService *nub, OSDictionary *table );

    bool 			resetBus();


    bool			initDevice( IOATAStandardDevice *device );
    void 			releaseDevice( IOATAStandardDevice *device );

    bool 			workLoopRequest( WorkLoopReqType type, UInt32 p1=0, UInt32 p2=0, UInt32 p3=0 );
    void                	workLoopProcessRequest( WorkLoopRequest *workLoopReq, void *p1, void *p2, void *p3 );

    void 			addDevice( IOATAStandardDevice *forDevice );
    void 			deleteDevice( IOATAStandardDevice *forDevice );

    void			timer( IOTimerEventSource *);

    void			dispatchRequest();
    void			dispatch();

    bool			checkBusReset();
    
    void			completeCommand( IOATAStandardCommand *forATACmd );

    bool 			createWorkLoop();
    bool 			configureController();

    IOATAStandardCommand 	*allocCommand( UInt32 clientDataSize );

private:
    
    UInt32			sequenceNumber;

    UInt32			commandCount;
    UInt32			commandLimit;
    UInt32			commandLimitSave;

    UInt32			disableTimer;
    bool			commandDisable;

    UInt32			busResetState;
    IOATAStandardCommand	*resetCmd;
    UInt32			resetTimer;

    IOATAStandardCommand	*noDisconnectCmd;

    ATAControllerInfo		controllerInfo;
    ATATarget  			*targets;
    
    IOWorkLoop			*workLoop;
    IOTimerEventSource		*timerEvent;
    IOInterruptEventSource	*dispatchEvent;
    IOCommandGate		*workLoopReqGate;

    IOService			*provider;
};

#endif
