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
 *	IOSCSIParallelDevice.h
 *
 *
 *	Methods in this header provide information about the SCSI device 
 *      the device client driver is submitting the SCSICommand(s) to.
 *
 * 	Note: SCSICommand(s) are allocated and freed by methods in this class. 
 *            The remaining methods to setup and submit SCSICommands are defined in
 *            IOSCSICommand.h
 */
 
#ifndef _IOSCSIPARALLELDEVICE_H
#define _IOSCSIPARALLELDEVICE_H

class IOSCSIParallelController;
 
class IOSCSIParallelDevice : public IOSCSIDevice
{
    OSDeclareDefaultStructors(IOSCSIParallelDevice)
    
    friend class IOSCSIParallelCommand;
    friend class IOSCSIParallelController;

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

/*------------------Additional methods provided to IOSCSIDevice clients-----------------------*/
public:
    /*
     * Allocate a SCSICommand
     */
     IOSCSIParallelCommand	*allocCommand( IOSCSIParallelDevice *deviceType, UInt32 clientDataSize = 0 );

    /*
     * Target management commands
     */
     bool                	setTargetParms( SCSITargetParms *targetParms );
     void               	getTargetParms( SCSITargetParms *targetParms );

    /* 
     * Lun management commands
     */
     bool			setLunParms( SCSILunParms *lunParms );
     void			getLunParms( SCSILunParms *lunParms );

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

/*------------------Methods private to the IOSCSIDevice class----------------*/
public:
    bool			open(  IOService *forClient, IOOptionBits options = 0, void *arg = 0 );
    void			close( IOService *forClient, IOOptionBits options = 0 );
    IOReturn 			message( UInt32 clientMsg, IOService *forProvider, void *forArg = 0 );
    bool 			init( IOSCSIParallelController *forController, SCSITargetLun forTargetLun );
    void			free();

    bool 			matchPropertyTable( OSDictionary * table );
    IOService 			*matchLocation( IOService * client );

    IOSCSICommand		*allocCommand( IOSCSIDevice *deviceType, UInt32 clientDataSize = 0 );

private:
    void			submitCommand(  UInt32 cmdType, IOSCSIParallelCommand *scsiCmd, UInt32 cmdSequenceNumber = 0 );
    void 			receiveCommand( UInt32 cmdType, IOSCSIParallelCommand *scsiCmd, UInt32 cmdSequenceNumber, void *p3 );

    IOReturn	 		probeTargetLun();
    bool			checkCmdQueEnabled();
    void			setupTarget();

    void 			dispatchRequest();
    bool			dispatch( UInt32 *dispatchAction );

    void			abortAllCommands( SCSICommandType abortCmdType );

    IOSCSIParallelCommand       *findCommandWithNexus( UInt32 tagValue );

    void			abortCommand( IOSCSIParallelCommand *scsiCmd, UInt32 cmdSequenceNumber );
    void      	          	completeCommand( IOSCSIParallelCommand *cmd );

    void			checkIdleNotify();

    void			executeCommandDone(  IOSCSIParallelCommand *scsiCmd );
    void			executeReqSenseDone( IOSCSIParallelCommand *scsiCmd );
    void 			abortCommandDone(    IOSCSIParallelCommand *scsiCmd );
    void			cancelCommandDone(   IOSCSIParallelCommand *scsiCmd );
    void			finishCommand(       IOSCSIParallelCommand *scsiCmd );

    OSDictionary 		*createProperties();
    bool 			addToRegistry( OSDictionary *propTable, OSObject *regObj, char *key, bool doRelease = true );
    void 			stripBlanks( char *d, char *s, UInt32 l );

    bool			checkDeviceQueue( UInt32 *dispatchAction );
    void			checkNegotiate( IOSCSIParallelCommand *scsiCmd );
    bool			checkTag( IOSCSIParallelCommand *scsiCmd );
    bool			checkReqSense();
    bool			checkAbortQueue();
    void			checkCancelQueue();

    void			negotiationComplete();

    bool 			allocTag( UInt32 *tagId );
    void 			freeTag( UInt32 tagId );
    
    void			timer();
    
    void			resetOccurred( SCSIClientMessage clientMsg );
    void			resetComplete();

    void			rescheduleCommand( IOSCSIParallelCommand *scsiCmd );

    void 			addCommand( queue_head_t *list, IOSCSIParallelCommand *scsiCmd );
    void 			stackCommand( queue_head_t *list, IOSCSIParallelCommand *scsiCmd );
    void 			deleteCommand( queue_head_t *list, IOSCSIParallelCommand *scsiCmd, IOReturn rc = kIOReturnSuccess );
    IOSCSIParallelCommand 	*checkCommand( queue_head_t *list );
    IOSCSIParallelCommand 	*getCommand( queue_head_t *list );
    void 			moveCommand(    queue_head_t 		*fromList, 
						queue_head_t 		*toList, 
						IOSCSIParallelCommand 	*scsiCmd, 
						IOReturn 		rc = kIOReturnSuccess );
    void 			moveAllCommands( queue_head_t *fromList, queue_head_t *toList, IOReturn rc = kIOReturnSuccess );
    bool 			findCommand( queue_head_t *list, IOSCSIParallelCommand *findScsiCmd );
    void 			purgeAllCommands( queue_head_t *list, IOReturn rc );

private:
    queue_chain_t		nextDevice;

    SCSITargetLun		targetLun;
    
    SCSITarget			*target;

    IOSCSIParallelController	*controller;
    IOCommandGate               *deviceGate;    

    IOService			*client;
    IORWLock *			clientSem;

    queue_head_t	      	deviceList;
    queue_head_t		bypassList;
    queue_head_t		activeList;
    queue_head_t		abortList;
    queue_head_t		cancelList;
    
    SCSICommandType		abortCmdPending;

    UInt32			reqSenseState;
    UInt32			abortState;
    UInt32			cancelState;
    UInt32			negotiateState;
    
    IOSCSIParallelCommand	*reqSenseOrigCmd;

    IOSCSIParallelCommand	*reqSenseCmd;
    IOSCSIParallelCommand	*abortCmd;
    IOSCSIParallelCommand	*cancelCmd;
    IOSCSIParallelCommand       *probeCmd;

    bool			normalQHeld;
    bool			bypassQHeld;

    bool			idleNotifyActive;
    CallbackFn			idleNotifyCallback;
    void			*idleNotifyTarget;
    void			*idleNotifyRefcon;    

    UInt32			commandCount;
    UInt32			commandLimit;
    UInt32			commandLimitSave;

    bool			disableDisconnect;

    bool			lunAllocated;

    OSNumber			*regObjTransferPeriod;
    OSNumber			*regObjTransferOffset;
    OSNumber			*regObjTransferWidth;
    OSNumber			*regObjTransferOptions;
    OSNumber			*regObjCmdQueue;

    UInt32			*tagArray;

    SCSILunParms		lunParmsNew;
    
    SCSIInquiry			*inquiryData;
    UInt32			inquiryDataSize;

    void			*devicePrivateData;
};

#define kIOSCSIParallelDevice	((IOSCSIParallelDevice *)0)

#endif
