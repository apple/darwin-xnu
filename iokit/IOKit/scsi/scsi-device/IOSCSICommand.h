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
 *	IOSCSICommand.h
 *
 */
#ifndef _IOSCSICOMMAND_H
#define _IOSCSICOMMAND_H

class IOSCSIDevice;
class IOSCSICommand;

class IOSCSICommand : public IOCDBCommand
{
    OSDeclareAbstractStructors(IOSCSICommand)

/*------------------Methods provided to IOCDBCommand users -------------------------*/
public:  
    /*
     * Set/Get IOMemoryDescriptor object to I/O data buffer or sense data buffer.
     */
    virtual void 		setPointers( IOMemoryDescriptor 	*desc, 
					     UInt32 			transferCount, 
                                             bool 			isWrite, 
					     bool 			isSense = false ) = 0;

    virtual void 		getPointers( IOMemoryDescriptor 	**desc, 
					     UInt32 			*transferCount, 
					     bool 			*isWrite, 
					     bool 			isSense = false ) = 0;
    /*
     * Set/Get command timeout (mS)
     */	 	
    virtual void 		setTimeout( UInt32  timeoutmS ) = 0;		
    virtual UInt32 		getTimeout() = 0;

    /*
     * Set async callback routine. Specifying no parameters indicates synchronous call.
     */
    virtual void 		setCallback( void *target = 0, CallbackFn callback = 0, void *refcon = 0 ) = 0;

    /*
     * Set/Get CDB information. (Generic CDB version)
     */	
    virtual void 		setCDB( CDBInfo *cdbInfo ) = 0;
    virtual void 		getCDB( CDBInfo *cdbInfo ) = 0;

    /*
     * Get CDB results. (Generic CDB version)
     */      
    virtual IOReturn		getResults( CDBResults *cdbResults ) = 0;

    /*
     * Get CDB Device this command is directed to.
     */
    virtual IOCDBDevice 	*getDevice( IOCDBDevice *deviceType ) = 0;

    /*
     * Command verbs
     */ 
    virtual bool 		execute( UInt32 *sequenceNumber = 0 ) = 0;
    virtual void		abort( UInt32 sequenceNumber ) = 0;
    virtual void	 	complete() = 0;

    /*
     * Get pointers to client and command data.
     */
    virtual void		*getCommandData() = 0;
    virtual void		*getClientData() = 0;

    /*
     * Get unique sequence number assigned to command.
     */
    virtual UInt32		getSequenceNumber() = 0;

/*------------------ Additional methods provided to IOSCSICommand users -------------------------*/
public:
    /*
     * Set/Get CDB information. (SCSI specific version).
     */	
    virtual void 		setCDB( SCSICDBInfo *scsiCmd ) = 0;
    virtual void		getCDB( SCSICDBInfo *scsiCmd ) = 0;

    /*
     * Get/Set CDB results. (SCSI specific version).
     */      
    virtual IOReturn		getResults( SCSIResults *results ) = 0;
    virtual void		setResults( SCSIResults *results ) = 0;

    /*
     * Get SCSI Device this command is directed to.
     */
    virtual IOSCSIDevice 	*getDevice( IOSCSIDevice *deviceType ) = 0;

    /*
     * Get SCSI Target/Lun for this command.
     */
    virtual void		getTargetLun( SCSITargetLun *targetLun ) = 0;

    /*
     * Get/Set queue routing for this command.
     */
    virtual void		setQueueInfo(  UInt32 forQueueType = kQTypeNormalQ, UInt32 forQueuePosition = kQPositionTail ) = 0;
    virtual void		getQueueInfo(  UInt32 *forQueueType, UInt32 *forQueuePosition = 0 ) = 0;

    /*
     * Set to blank state, call prior to re-use of this object.
     */	
     virtual void 			zeroCommand() = 0;  
};

#endif
