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
 *	IOATACommand.h
 *
 */
#ifndef _IOATASTANDARDCOMMAND_H
#define _IOATASTANDARDCOMMAND_H

class IOATAStandardDevice;
class IOATAStandardCommand;
class IOSyncer;
class IOATAStandardDriver;

class IOATAStandardCommand : public IOATACommand
{
    OSDeclareDefaultStructors(IOATAStandardCommand)

    friend class IOATAStandardController;
    friend class IOATAStandardDevice;
    friend class IOATAStandardDriver;

/*------------------Methods provided to IOCDBCommand users -------------------------*/
public:  
    /*
     * Set/Get IOMemoryDescriptor object to I/O data buffer or sense data buffer.
     */
     void 			setPointers( IOMemoryDescriptor 	*desc, 
					     UInt32 			transferCount, 
                                             bool 			isWrite, 
					     bool 			isSense = false );

     void 			getPointers( IOMemoryDescriptor 	**desc, 
					     UInt32 			*transferCount, 
					     bool 			*isWrite, 
					     bool 			isSense = false );
    /*
     * Set/Get command timeout (mS)
     */	 	
     void 			setTimeout( UInt32  timeoutmS );		
     UInt32 			getTimeout();

    /*
     * Set async callback routine. Specifying no parameters indicates synchronous call.
     */
     void 			setCallback( void *target = 0, CallbackFn callback = 0, void *refcon = 0 );

    /*
     * Set/Get CDB information. (Generic CDB version)
     */	
     void 			setCDB( CDBInfo *cdbInfo );
     void 			getCDB( CDBInfo *cdbInfo );

    /*
     * Get CDB results. (Generic CDB version)
     */      
     IOReturn			getResults( CDBResults *cdbResults );

    /*
     * Get CDB Device this command is directed to.
     */
     IOCDBDevice 		*getDevice( IOCDBDevice *deviceType );
//  #define kIOCDBDevice	((IOCDBDevice *)0)

    /*
     * Command verbs
     */ 
     bool 			execute( UInt32 *sequenceNumber = 0 );
     void			abort( UInt32 sequenceNumber );
     void	 		complete();

    /*
     * Get pointers to client and command data.
     */
     void			*getCommandData();
     void			*getClientData();

    /*
     * Get unique sequence number assigned to command.
     */
    UInt32			getSequenceNumber();

/*------------------ Additional methods provided to IOATACommand users -------------------------*/
public:
    /*
     * Set/Get ATA taskfile information.
     */	
    void 			setTaskfile( ATATaskfile *taskfile );						
    void 			getTaskfile( ATATaskfile *taskfile ); 			
    ATAProtocol			getProtocol();
    UInt32			getResultMask();
    UInt32			getFlags();

    /*
     * Set/Get CDB information. (ATA specific version).
     */	
     void 			setCDB( ATACDBInfo *ataCmd );
     void			getCDB( ATACDBInfo *ataCmd );

    /*
     * Get/Set CDB results. (ATA specific version).
     */      
     IOReturn			getResults( ATAResults *results );
     void			setResults( ATAResults *results );

    /*
     * Get ATA Device this command is directed to.
     */
     IOATAStandardDevice 	*getDevice( IOATAStandardDevice *deviceType );
//   #define kIOATADevice	((IOATADevice *)0)


    /*
     * Get ATA Target/Lun for this command.
     */
     ATAUnit			getUnit();

    /*
     * Get/Set queue routing for this command.
     */
    void			setQueueInfo(  UInt32 forQueueType = kATAQTypeNormalQ, UInt32 forQueuePosition = kATAQPositionTail );
    void			getQueueInfo(  UInt32 *forQueueType, UInt32 *forQueuePosition = 0 );

    /*
     * Get command type / Get original command. 
     *
     * These methods are provided for the controller class to identify and relate commands.
     * They are not usually of interest to the client side.
     */     
     UInt32			getCmdType();
     IOATAStandardCommand	*getOriginalCmd();    

/*------------------Methods private to the IOATACommand class-------------------------*/
public:
    IOATADevice			*getDevice( IOATADevice *deviceType );
    void 			free();

private:
    ATACommandType		cmdType;

    IOATAStandardController    	*controller;
    IOATAStandardDevice		*device;

    queue_head_t		*list;
    queue_chain_t		nextCommand;
 
    ATATaskfile			taskfile;

    ATAResults			results;

    ATACDBInfo			ataCmd;

    UInt32			timeout;    
    UInt32			timer;

    UInt8			queueType;
    UInt8			queuePosition;
    
    IOMemoryDescriptor		*xferDesc;
    UInt32			xferCount;
    UInt32			xferDirection;

    UInt32			senseLength;
    IOMemoryDescriptor		*senseData;

    IOATAStandardCommand	*origCommand;

    union
    {
        struct
        {
            UInt32		reserved;
            IOSyncer *		lock;
        } sync;
        struct
        {
	    CallbackFn 		callback;
    	    void		*target;
    	    void		*refcon;
        } async;
     } completionInfo;

    UInt32			dataSize;
    void                	*dataArea;
    void			*commandPrivateData;
    void			*clientData;	
    
    UInt32			sequenceNumber;	  
};

#endif
