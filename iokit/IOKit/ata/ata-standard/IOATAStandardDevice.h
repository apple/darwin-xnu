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
 *	IOATAStandardDevice.h
 *
 *
 *	Methods in this header provide information about the ATA device 
 *      the device client driver is submitting the ATACommand(s) to.
 *
 * 	Note: ATACommand(s) are allocated and freed by methods in this class. 
 *            The remaining methods to setup and submit ATACommands are defined in
 *            IOATACommand.h
 */
 
#ifndef _IOATASTANDARDDEVICE_H
#define _IOATASTANDARDDEVICE_H

class IOATAStandardController;
 
class IOATAStandardDevice : public IOATADevice
{
    OSDeclareDefaultStructors(IOATAStandardDevice)
    
    friend class IOATAStandardCommand;
    friend class IOATAStandardController;

/*------------------Methods provided to IOCDBDevice clients-----------------------*/
public:

    /*
     * Allocate a CDB Command
     */
     IOCDBCommand 		*allocCommand( IOCDBDevice *deviceType, UInt32 clientDataSize = 0 );

    /*
     * Abort all outstanding commands on this device
     */
     void			abort();
    
    /*
     * Reset device (also aborts all outstanding commands)
     */
     void			reset();

    /*
     * Obtain information about this device
     */
     void			getInquiryData( void    *inquiryBuffer, 
                                                UInt32  inquiryBufSize, 
                                                UInt32  *inquiryDataSize );

/*------------------Additional methods provided to IOATADevice clients-----------------------*/
public:
    /*
     * Allocate a ATACommand
     */
     IOATAStandardCommand	*allocCommand( IOATAStandardDevice *deviceType, UInt32 clientDataSize = 0 );

    /*
     * Obtain information about this device
     */
    ATAUnit			getUnit();
    ATADeviceType		getDeviceType();
    bool			getIdentifyData( ATAIdentify *identifyBuffer );
    bool			getInquiryData( UInt32 inquiryBufSize, ATAPIInquiry *inquiryBuffer );
    bool 			getDeviceCapacity( UInt32 *blockMax, UInt32 *blockSize );
    bool			getProtocolsSupported( ATAProtocol *protocolsSupported );
    bool 			getTimingsSupported( ATATimingProtocol *timingsSupported );
    bool			getTimingSelected( ATATimingProtocol *timingProtocol );
    bool			getTiming( ATATimingProtocol *timingProtocol, ATATiming *timing );
    bool			getATAPIPktInt();

    /*
     * Select default device timing for this device
     */
    bool 			selectTiming( ATATimingProtocol timingProtocol, bool fNotifyMsg = false );

    /* 
     * Queue management commands
     */
    void			holdQueue( UInt32 queueType );
    void			releaseQueue( UInt32 queueType );
    void			flushQueue( UInt32 queueType, IOReturn rc );
    void			notifyIdle(  void *target = 0, CallbackFn callback = 0, void *refcon = 0 );

    /* 
     *
     */
     IOWorkLoop			*getWorkLoop() const; 

/*------------------Methods private to the IOATADevice class----------------*/
public:
    bool			open(  IOService *forClient, IOOptionBits options, void *arg );
    void			close( IOService *forClient, IOOptionBits options );
    bool 			init( IOATAStandardController *forController, ATAUnit forUnit );
    void			free();

    bool 			matchPropertyTable( OSDictionary * table );
    IOService 			*matchLocation( IOService * client );

     IOATACommand		*allocCommand( IOATADevice *deviceType, UInt32 clientDataSize = 0 );

private:
    void			submitCommand(  UInt32 cmdType, IOATAStandardCommand *ataCmd, UInt32 cmdSequenceNumber = 0 );
    void 			receiveCommand( UInt32 cmdType, IOATAStandardCommand *ataCmd, UInt32 cmdSequenceNumber, void *p3 );

    IOReturn	 		probeDevice();
    ATADeviceType		probeDeviceType();

    IOReturn 			doSpinUp();
    IOReturn			doIdentify( void **dataPtr );
    IOReturn			doSectorCommand( ATACommand ataCmd, UInt32 ataLBA, UInt32 ataCount, void **dataPtr );
    IOReturn			doInquiry( void **dataPtr );
    IOReturn			doTestUnitReady();
    IOReturn			doReadCapacity( void *data );

    bool			getATATimings();

    void 			selectTimingDone( IOATAStandardCommand *ataCmd );

    void			setupTarget();

    void 			dispatchRequest();
    bool			dispatch( UInt32 *dispatchAction );

    void			abortAllCommands( ATACommandType abortCmdType );

    IOATAStandardCommand       *findCommandWithNexus( UInt32 tagValue );

    void			abortCommand( IOATAStandardCommand *ataCmd, UInt32 cmdSequenceNumber );
    void      	          	completeCommand( IOATAStandardCommand *cmd );

    void			checkIdleNotify();

    void			executeCommandDone(  IOATAStandardCommand *ataCmd );
    void			executeReqSenseDone( IOATAStandardCommand *ataCmd );
    void 			abortCommandDone(    IOATAStandardCommand *ataCmd );
    void			cancelCommandDone(   IOATAStandardCommand *ataCmd );
    void			finishCommand(       IOATAStandardCommand *ataCmd );

    OSDictionary 		*createProperties();
    bool 			addToRegistry( OSDictionary *propTable, OSObject *regObj, char *key, bool doRelease = true );
    void 			stripBlanks( char *d, char *s, UInt32 l );

    void 			endianConvertData( void *data, void *endianTable );

    bool			checkDeviceQueue( UInt32 *dispatchAction );
    void			checkNegotiate( IOATAStandardCommand *ataCmd );
    bool			checkTag( IOATAStandardCommand *ataCmd );
    bool			checkReqSense();
    bool			checkAbortQueue();
    void			checkCancelQueue();

    bool 			allocTag( UInt32 *tagId );
    void 			freeTag( UInt32 tagId );
    
    void			timer();
    
    void			resetOccurred( ATAClientMessage clientMsg = kATAClientMsgNone );
    void			resetComplete();

    void			rescheduleCommand( IOATAStandardCommand *ataCmd );

    void 			suspend();
    void 			resume();

    void 			addCommand( queue_head_t *list, IOATAStandardCommand *ataCmd );
    void 			stackCommand( queue_head_t *list, IOATAStandardCommand *ataCmd );
    void 			deleteCommand( queue_head_t *list, IOATAStandardCommand *ataCmd, IOReturn rc = kIOReturnSuccess );
    IOATAStandardCommand 	*checkCommand( queue_head_t *list );
    IOATAStandardCommand 	*getCommand( queue_head_t *list );
    void 			moveCommand(    queue_head_t 		*fromList, 
						queue_head_t 		*toList, 
						IOATAStandardCommand 	*ataCmd, 
						IOReturn 		rc = kIOReturnSuccess );
    void 			moveAllCommands( queue_head_t *fromList, queue_head_t *toList, IOReturn rc = kIOReturnSuccess );
    bool 			findCommand( queue_head_t *list, IOATAStandardCommand *findATACmd );
    void 			purgeAllCommands( queue_head_t *list, IOReturn rc );

private:
    ATAUnit			unit;
    ATATarget			*target;

    IOATAStandardController	*controller;
    IOCommandGate               *deviceGate;    

    IOService			*client;
    IORWLock *			clientSem;

    queue_head_t	      	deviceList;
    queue_head_t		bypassList;
    queue_head_t		activeList;
    queue_head_t		abortList;
    queue_head_t		cancelList;
    
    ATACommandType		abortCmdPending;

    UInt32			reqSenseState;
    UInt32			abortState;
    UInt32			cancelState;
    UInt32			negotiateState;
    
    IOATAStandardCommand	*reqSenseOrigCmd;

    IOATAStandardCommand	*reqSenseCmd;
    IOATAStandardCommand	*abortCmd;
    IOATAStandardCommand	*cancelCmd;
    IOATAStandardCommand       	*probeCmd;

    UInt32			normalQHeld;
    UInt32			bypassQHeld;

    bool			idleNotifyActive;
    CallbackFn			idleNotifyCallback;
    void			*idleNotifyTarget;
    void			*idleNotifyRefcon;
    
    bool			isSuspended;
    AbsoluteTime		suspendTime;

    UInt32			commandCount;
    UInt32			commandLimit;
    UInt32			commandLimitSave;

    UInt32			maxTags;
    UInt32			tagArraySize;
    UInt32			*tagArray;

    ATADeviceType		deviceType;

    UInt32			protocolsSupported;
    UInt32			atapiPktInt;

    ATAIdentify			*identifyData;

    ATAInquiry			*inquiryData;
    UInt32			inquiryDataSize;
  
    ATATimingProtocol		currentTiming;

    UInt32			numTimings;
    ATATiming			ataTimings[kATAMaxTimings];

    void			*devicePrivateData;
};

#define kIOATAStandardDevice	((IOATAStandardDevice *)0)

#endif
