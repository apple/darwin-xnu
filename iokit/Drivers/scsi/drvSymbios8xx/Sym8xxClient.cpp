/*
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
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

/* Sym8xxClient.m created by russb2 on Sat 30-May-1998 */

#include "Sym8xxController.h"

extern pmap_t 	        kernel_pmap;


/*-----------------------------------------------------------------------------*
 *
 *-----------------------------------------------------------------------------*/
void Sym8xxSCSIController::executeCommand( IOSCSIParallelCommand *scsiCommand )
{
    SRB				*srb = NULL;
    SCSICDBInfo			scsiCDB;
    SCSITargetLun               targetLun;
    Nexus                       *nexus;
    Nexus                       *nexusPhys;  
    UInt32                      len;  
    bool                        isWrite;                

    srb = (SRB *) scsiCommand->getCommandData();
    bzero( srb, sizeof(SRB) );

    srb->srbPhys = (SRB *) pmap_extract( kernel_pmap, (vm_offset_t) srb );
    srb->scsiCommand = scsiCommand;

    scsiCommand->getCDB( &scsiCDB );
    scsiCommand->getTargetLun( &targetLun );

    nexus            = &srb->nexus;
    nexusPhys        = &srb->srbPhys->nexus;
    
    srb->target      = targetLun.target;
    srb->lun         = targetLun.lun;
    srb->srbCDBFlags = scsiCDB.cdbFlags;

    /*
     * Setup the Nexus struct. This part of the SRB is read/written both by the
     * script and the driver.
     */
    nexus->targetParms.target    = srb->target;

//    printf( "SCSI(Symbios8xx): executeCommand: T/L = %d:%d Cmd = %08x CmdType = %d\n\r", 
//                        targetLun.target, targetLun.lun, (int)scsiCommand, scsiCommand->getCmdType() );
    
    switch ( scsiCommand->getCmdType() )
    {
        case kSCSICommandAbort:
        case kSCSICommandAbortAll:
        case kSCSICommandDeviceReset:
            Sym8xxAbortCommand( scsiCommand );
            return;

        default:
            ;
    }
    
    /*
     * Set client data buffer pointers in the SRB
     */
    scsiCommand->getPointers( &srb->xferDesc, &srb->xferCount, &isWrite );
    
    srb->directionMask = (isWrite) ? 0x00000000 :0x01000000;    
    
    nexus->cdb.ppData = OSSwapHostToLittleInt32((UInt32)&nexusPhys->cdbData);

    len = scsiCDB.cdbLength;

    nexus->cdb.length = OSSwapHostToLittleInt32( len );
    nexus->cdbData    = scsiCDB.cdb;

    Sym8xxCalcMsgs( scsiCommand );
    
    /*
     * Setup initial data transfer list (SGList) 
     */
    nexus->ppSGList   = (SGEntry *)OSSwapHostToLittleInt32((UInt32)&nexusPhys->sgListData[2]);
    Sym8xxUpdateSGList( srb );

    Sym8xxStartSRB( srb );
}


/*-----------------------------------------------------------------------------*
 * This routine queues an SRB to reset the SCSI Bus
 *
 *-----------------------------------------------------------------------------*/
void Sym8xxSCSIController::resetCommand( IOSCSIParallelCommand *scsiCommand )
{
    SRB		*srb;

//    printf( "SCSI(Symbios8xx): resetCommand\n\r" ); 

    srb = (SRB *) scsiCommand->getCommandData();
    bzero( srb, sizeof(SRB) );

    srb->srbPhys = (SRB *) pmap_extract( kernel_pmap, (vm_offset_t) srb );
    srb->scsiCommand = scsiCommand;

    Sym8xxSCSIBusReset( srb );
}

/*-----------------------------------------------------------------------------*
 *
 *-----------------------------------------------------------------------------*/
void Sym8xxSCSIController::cancelCommand( IOSCSIParallelCommand *scsiCommand )
{
    IOSCSIParallelCommand	*origCommand;
    SRB				*srb;
    SCSITargetLun		targetLun;
    SCSIResults         	scsiResults;

    origCommand = scsiCommand->getOriginalCmd();
    srb  = (SRB *)origCommand->getCommandData();

    switch ( origCommand->getCmdType() )
    {
        case kSCSICommandAbort:
        case kSCSICommandAbortAll:
        case kSCSICommandDeviceReset:
            if ( abortSRB == srb )
            {
                SCRIPT_VAR(R_ld_AbortBdr_mailbox) = 0;
                abortSRB = 0;

                origCommand->complete();                
            }
            break;

        default:

            if ( adapter->nexusPtrsVirt[srb->nexus.tag] == &srb->nexus )
            {
                adapter->nexusPtrsVirt[srb->nexus.tag] = (Nexus *) -1;
                adapter->nexusPtrsPhys[srb->nexus.tag] = (Nexus *) -1;

                origCommand->complete();                
            }
            else
            {
                origCommand->getTargetLun( &targetLun );
                origCommand->complete();                

                IOLog( "SCSI(Symbios8xx): Aborted SRB not found - T/L = %d:%d\n\r", targetLun.target, targetLun.lun );
            }              
    }

    bzero( &scsiResults, sizeof(scsiResults) );    
    scsiCommand->setResults( &scsiResults );
    scsiCommand->complete();
}
      
/*-----------------------------------------------------------------------------*
 *
 *
 *
 *
 *-----------------------------------------------------------------------------*/
void Sym8xxSCSIController::Sym8xxAbortCommand( IOSCSIParallelCommand *scsiCommand )
{
    SRB				*srb;
    SCSICDBInfo                 scsiCDB;
    SCSITargetLun		targetLun;


    scsiCommand->getTargetLun( &targetLun );

    switch ( scsiCommand->getCmdType() )
    {
        case kSCSICommandAbort:
            srb = (SRB *)scsiCommand->getOriginalCmd()->getCommandData();
            Sym8xxCancelMailBox( &srb->srbPhys->nexus );
            break;

        case kSCSICommandAbortAll:
            Sym8xxCancelMailBox( targetLun.target, targetLun.lun, false );
            break;
      
        case kSCSICommandDeviceReset:
            Sym8xxCancelMailBox( targetLun.target, (UInt32) -1, false );
            break;

        default:
            ;
    }

    if ( abortSRB )
    {
        abortReqPending = true;
        
        rescheduleCommand( scsiCommand );
        disableCommands();
        return;
    }

    scsiCommand->getCDB( &scsiCDB );

    srb = (SRB *) scsiCommand->getCommandData();
    
    srb->nexus.msgData[0] = srb->lun | ((srb->srbCDBFlags & kCDBFlagsNoDisconnect ) ? 0x80 : 0xC0);
        
    if ( scsiCDB.cdbTagMsg != 0 )
    {
        srb->nexus.tag        = scsiCDB.cdbTag + 128;
        srb->nexus.msgData[1] = srb->nexus.tag;
    }
    else
    {    
        srb->nexus.tag        = ((UInt32)srb->target << 3) | srb->lun;
        srb->nexus.msgData[1] = 0;
    }       
    srb->tag = srb->nexus.tag;

    srb->nexus.msgData[2] = scsiCDB.cdbAbortMsg;
    
    Sym8xxAbortBdr( srb );
}    

         
/*-----------------------------------------------------------------------------*
 * This routine creates SCSI messages to send during the initial connection
 * to the target. It is called during client request processing and also by
 * the I/O thread when a request sense operation is required.
 *
 * Outbound messages are setup in the MsgOut buffer in the Nexus structure of
 * the SRB.
 *
 *-----------------------------------------------------------------------------*/
void Sym8xxSCSIController::Sym8xxCalcMsgs( IOSCSIParallelCommand *scsiCommand ) 
{
    SRB			*srb;
    Nexus		*nexus;
    Nexus		*nexusPhys;
    UInt32		msgIndex;
    SCSICDBInfo		scsiCDB;
    SCSITargetParms	targetParms;
    UInt32		i;
    UInt32		tw;


    srb       = (SRB *)scsiCommand->getCommandData();
    nexus     = &srb->nexus;
    nexusPhys = &srb->srbPhys->nexus;

    scsiCommand->getCDB( &scsiCDB );

    /*
     * Setup Identify message 
     */
    msgIndex = 0;
    nexus->msg.ppData = OSSwapHostToLittleInt32((UInt32)&nexusPhys->msgData);
    nexus->msgData[msgIndex++] = srb->lun | (( scsiCDB.cdbFlags & kCDBFlagsNoDisconnect ) ? 0x80 : 0xC0);

    /*
     * Allocate tag for request.
     *
     * For non-tagged requests a pseudo-tag is created consisting of target*16+lun. For tagged
     * requests a tag in the range 128-255 is allocated.
     *
     * If a pseudo-tag is inuse for a non-tagged command or there are no tags available for
     * a tagged request, then the command is blocked until a tag becomes available.
     *
     * Note: If we are being called during request sense processing (srbState != ksrbStateCDBDone)
     *       then a tag has already been allocated to the request.
     */
    if ( scsiCDB.cdbTagMsg != 0 )
    {
        nexus->msgData[msgIndex++] = scsiCDB.cdbTagMsg;
        nexus->msgData[msgIndex++] = srb->tag = srb->nexus.tag = scsiCDB.cdbTag + 128;
    }
    else
    {
        srb->tag = srb->nexus.tag = ((UInt32)srb->target << 3) | srb->lun;
    }   
    /*
     * Setup to negotiate for Wide (16-bit) data transfers
     *
     * Note: There is no provision to negotiate back to narrow transfers although
     *       SCSI does support this.
     */
        
    scsiCommand->getDevice(kIOSCSIParallelDevice)->getTargetParms( &targetParms );

    if ( scsiCDB.cdbFlags & (kCDBFlagsNegotiateWDTR | kCDBFlagsNegotiateSDTR) )
    {
        negotiateWDTRComplete = negotiateSDTRComplete = false;
    }

    if ( scsiCDB.cdbFlags & kCDBFlagsNegotiateWDTR )
    {
        nexus->msgData[msgIndex++] = kSCSIMsgExtended;
        nexus->msgData[msgIndex++] = 2;
        nexus->msgData[msgIndex++] = kSCSIMsgWideDataXferReq;

        for ( tw = targetParms.transferWidth, i = (UInt32)-1; 
              tw; 
              tw >>= 1, i++ )
          ;

        nexus->msgData[msgIndex++] = i;
    }

    /*
     * Setup to negotiate for Synchronous data transfers.
     *
     * Note: We can negotiate back to async based on the flags in the command. 
     */

    if ( scsiCDB.cdbFlags & kCDBFlagsNegotiateSDTR )
    {
        nexus->msgData[msgIndex++] = kSCSIMsgExtended;
        nexus->msgData[msgIndex++] = 3;
        nexus->msgData[msgIndex++] = kSCSIMsgSyncXferReq;
        if ( targetParms.transferOffset != 0 )
        {
            nexus->msgData[msgIndex++] = targetParms.transferPeriodpS / 4000;
            nexus->msgData[msgIndex++] = targetParms.transferOffset;
        }
        else
        {
            nexus->msgData[msgIndex++] = 0;
            nexus->msgData[msgIndex++] = 0;
        }        
            
    }

    /*
     * If we are negotiating for both Sync and Wide data transfers, we setup both messages
     * in the Nexus msgOut buffer. However, after each message the script needs to wait for
     * a reply message from the target. In this case, we set the msgOut length to include
     * bytes upto the end of the Wide message. When we get the reply from the target, the
     * routine handling the WDTR will setup the Nexus pointers/counts to send the remaining
     * message bytes. See Sym8xxExecute.m(Sym8xxNegotiateWDTR).
     */
    srb->srbMsgLength = msgIndex;

    if ((scsiCDB.cdbFlags & (kCDBFlagsNegotiateWDTR | kCDBFlagsNegotiateSDTR)) 
                                                       == (kCDBFlagsNegotiateWDTR | kCDBFlagsNegotiateSDTR))
    {
        msgIndex -= 5;
    }

    nexus->msg.length = OSSwapHostToLittleInt32( msgIndex );

    srb->srbCDBFlags = scsiCDB.cdbFlags;
}

/*-----------------------------------------------------------------------------*
 * This routine sets up the data transfer SG list for the client's buffer in the
 * Nexus structure.
 *
 * The SGList actually consists of script instructions. The script will branch
 * to the SGList when the target enters data transfer phase. When the SGList completes
 * it will either execute a script INT instruction if there are more segments of the
 * user buffer that need to be transferred or will execute a script RETURN instruction
 * to return to the script.
 *
 * The first two slots in the SGList are reserved for partial data transfers. See
 * Sym8xxExecute.m(Sym8xxAdjustDataPtrs).
 * 
 *-----------------------------------------------------------------------------*/


/*-----------------------------------------------------------------------------*
 * Build SG list based on an IOMemoryDescriptor object.
 *
 *-----------------------------------------------------------------------------*/
bool Sym8xxSCSIController::Sym8xxUpdateSGList( SRB *srb )
{
    IOPhysicalSegment 		range;
    UInt32			actRanges;
    UInt32			offset;
    UInt32			bytesLeft;
    UInt32			i;
    IOReturn			rc = true;

    offset    = srb->xferOffset;
    bytesLeft = srb->xferCount - srb->xferOffset;

    if ( bytesLeft == 0 ) return rc;

    i         = 2;

    while ( (bytesLeft > 0) && (i < MAX_SGLIST_ENTRIES-1))
    {
        actRanges = memoryCursor->getPhysicalSegments( srb->xferDesc,
                                                       offset,
						       &range,
                                                       1 );
			     
        if ( actRanges != 1 )
        {
            rc = false;
            break;
        }

        /*
         * Note: The script instruction(s) to transfer data to/from the scsi bus
         *       have the same format as a typical SGList with the transfer length 
         *       as the first word and the physical transfer address as the second. 
         *       The data transfer direction is specified by a bit or'd into the
         *       high byte of the SG entry's length field.
         */
        srb->nexus.sgListData[i].physAddr = OSSwapHostToLittleInt32( (UInt32)range.location );
        srb->nexus.sgListData[i].length   = OSSwapHostToLittleInt32( range.length | srb->directionMask );

        bytesLeft -= range.length;
        offset    += range.length;
        i++;
    }

    if ( !bytesLeft )
    {
        srb->nexus.sgListData[i].length   = OSSwapHostToLittleInt32( 0x90080000 );
        srb->nexus.sgListData[i].physAddr = OSSwapHostToLittleInt32( 0x00000000 );
    }
    else
    {
        srb->nexus.sgListData[i].length   = OSSwapHostToLittleInt32( 0x98080000 );
        srb->nexus.sgListData[i].physAddr = OSSwapHostToLittleInt32( A_sglist_complete );
    }

    srb->xferOffsetPrev = srb->xferOffset;
    srb->xferOffset     = offset;

    return rc;
}

