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

/* Sym8xxExecute.m created by russb2 on Sat 30-May-1998 */

#include "Sym8xxController.h"

extern "C"
{
    unsigned int ml_phys_read( vm_offset_t paddr );
};

#if 0
static UInt32 dropInt = 0;
#endif

void Sym8xxSCSIController::Sym8xxStartSRB( SRB *srb )
{

    srb->nexus.targetParms.scntl3Reg = adapter->targetClocks[srb->target].scntl3Reg;
    srb->nexus.targetParms.sxferReg  = adapter->targetClocks[srb->target].sxferReg;

    adapter->nexusPtrsVirt[srb->nexus.tag] = &srb->nexus;
    adapter->nexusPtrsPhys[srb->nexus.tag] = (Nexus *)OSSwapHostToLittleInt32( (UInt32)&srb->srbPhys->nexus );
    adapter->schedMailBox[mailBoxIndex++]  = (Nexus *)OSSwapHostToLittleInt32 ( (UInt32)&srb->srbPhys->nexus );

    Sym8xxSignalScript( srb );
}
             

/*-----------------------------------------------------------------------------*
 * Interrupts from the Symbios chipset are dispatched here at task time under the
 * IOThread's context.
 *-----------------------------------------------------------------------------*/
void Sym8xxSCSIController::interruptOccurred( IOInterruptEventSource *ies, int intCount )
{
    do
    {
        /* 
         * The chipset's ISTAT reg gives us the general interrupting condiditions,
         * with DSTAT and SIST providing more detailed information.
         */
        istatReg = Sym8xxReadRegs( chipBaseAddr, ISTAT, ISTAT_SIZE );

        /* The INTF bit in ISTAT indicates that the script is signalling the driver
         * that its IODone mailbox is full and that we should process a completed
         * request. The script continues to run after posting this interrupt unlike 
         * other chipset interrupts which require the driver to restart the script
         * engine.
         */
        if ( istatReg & INTF )
        {
            Sym8xxWriteRegs( chipBaseAddr, ISTAT, ISTAT_SIZE, istatReg );
#if 0
            if ( dropInt++ > 100 )
            {
                dropInt = 0;
                SCRIPT_VAR(R_ld_IOdone_mailbox)       = 0;
                continue;
            }
#endif
            Sym8xxProcessIODone();
        }

        /*
         * Handle remaining interrupting conditions
         */  
        if ( istatReg & (SIP | DIP) )
        {
            Sym8xxProcessInterrupt();    
        }
    }
    while ( istatReg & (SIP | DIP | INTF) );

    getWorkLoop()->enableAllInterrupts();

}

/*-----------------------------------------------------------------------------*
 * Process a request posted in the script's IODone mailbox.
 *
 *-----------------------------------------------------------------------------*/
void Sym8xxSCSIController::Sym8xxProcessIODone()
{
    SRB				*srb;
    Nexus			*nexus;
    IODoneMailBox		*pMailBox;
    
 
    /*
     * The IODone mailbox contains an index into our Nexus pointer tables.
     *
     * The Nexus struct is part of the SRB so we can get our SRB address
     * by subtracting the offset of the Nexus struct in the SRB.
     */
    pMailBox = (IODoneMailBox *)&SCRIPT_VAR(R_ld_IOdone_mailbox);
    nexus = adapter->nexusPtrsVirt[pMailBox->nexus];        
    srb   = (SRB *)((UInt32)nexus - offsetof(SRB, nexus));    

    srb->srbSCSIStatus = pMailBox->status;

    if ( srb->srbSCSIStatus == kSCSIStatusCheckCondition )
    {
        Sym8xxCheckRequestSense( srb );
    }
    
    Sym8xxUpdateXferOffset( srb );

    /* 
     * Clear the completed Nexus pointer from our tables and clear the
     * IODone mailbox.
     */
    adapter->nexusPtrsVirt[pMailBox->nexus] = (Nexus *) -1;
    adapter->nexusPtrsPhys[pMailBox->nexus] = (Nexus *) -1;
    SCRIPT_VAR(R_ld_IOdone_mailbox)       = 0;

    /*
     * Wake up the client's thread to do post-processing
     */
    Sym8xxCompleteSRB( srb );

    scriptRestartAddr = (UInt32) &chipRamAddrPhys[Ent_select_phase];
}
/*-----------------------------------------------------------------------------*
 *
 *
 *-----------------------------------------------------------------------------*/
void Sym8xxSCSIController::Sym8xxCompleteSRB( SRB *srb )
{
    IOSCSIParallelCommand	*scsiCommand;
    SCSIResults			scsiResults;
    SCSINegotiationResults	negotiationResult, *negResult;
    

    scsiCommand = srb->scsiCommand;
    
    bzero( &scsiResults, sizeof(scsiResults) );    
    
    scsiResults.adapterStatus = srb->srbAdapterStatus;
    scsiResults.returnCode    = srb->srbReturnCode;

    
    if ( srb == abortSRB )
    {
        abortSRB = 0;
        if ( abortReqPending == true )
        {
            abortReqPending = false;
            enableCommands();
        }
    }    
    else
    {
        scsiResults.bytesTransferred = srb->xferDone; 
        scsiResults.scsiStatus       = srb->srbSCSIStatus;
    }

    negResult = 0;

    if ( (srb->srbCDBFlags & kCDBFlagsNegotiateSDTR) || (srb->srbCDBFlags & kCDBFlagsNegotiateWDTR) )
    {
        bzero( &negotiationResult, sizeof(struct SCSINegotiationResults) );

        if ( ((srb->srbCDBFlags & kCDBFlagsNegotiateSDTR) && srb->negotiateSDTRComplete == false) ||
             ((srb->srbCDBFlags & kCDBFlagsNegotiateWDTR) && srb->negotiateWDTRComplete == false)     )
        {
            negotiationResult.returnCode = kIOReturnIOError;
        }
       
        negotiationResult.transferPeriodpS = transferPeriod;
        negotiationResult.transferOffset   = transferOffset;
        negotiationResult.transferWidth    = transferWidth;
        negotiationResult.transferOptions  = 0;

        negResult = &negotiationResult;
    }
    
    scsiCommand->setResults( &scsiResults, negResult );
    scsiCommand->complete();
}
   
/*-----------------------------------------------------------------------------*
 * General script interrupt processing
 *
 *-----------------------------------------------------------------------------*/
void Sym8xxSCSIController::Sym8xxProcessInterrupt()
{
    SRB			*srb 		= NULL;
    Nexus		*nexus 		= NULL;
    UInt32		nexusIndex;
    UInt32		scriptPhase;
    UInt32		fifoCnt 	= 0;
    UInt32		dspsReg 	= 0;
    UInt32		dspReg  	= 0;


    /*
     * Read DSTAT/SIST regs to determine why the script stopped.
     */
    dstatReg = Sym8xxReadRegs( chipBaseAddr,  DSTAT, DSTAT_SIZE );
    IODelay(5);
    sistReg =  Sym8xxReadRegs( chipBaseAddr,  SIST,  SIST_SIZE );

//    printf( "SCSI(Symbios8xx): SIST = %04x DSTAT = %02x\n\r", sistReg, dstatReg  );

    /*
     * This Script var tells us what the script thinks it was doing when the interrupt occurred.
     */
    scriptPhase = OSSwapHostToLittleInt32( SCRIPT_VAR(R_ld_phase_flag) );

    /*
     * SCSI Bus reset detected 
     *
     * Clean up the carnage.     
     * Note: This may be either an adapter or target initiated reset.
     */
    if ( sistReg & RSTI )
    {
        Sym8xxProcessSCSIBusReset();
        return;
    }

    /*
     * Calculate our current SRB/Nexus.
     *
     * Read a script var to determine the index of the nexus it was processing
     * when the interrupt occurred. The script will invalidate the index if there
     * is no target currently connected or the script cannot determine which target
     * has reconnected.
     */
    nexusIndex = OSSwapHostToLittleInt32(SCRIPT_VAR(R_ld_nexus_index));
    if ( nexusIndex >= MAX_SCSI_TAG )
    {
        Sym8xxProcessNoNexus();
        return;
    }
    nexus  = adapter->nexusPtrsVirt[nexusIndex];        
    if ( nexus == (Nexus *) -1 )
    {
        Sym8xxProcessNoNexus();
        return;
    }
    srb = (SRB *)((UInt32)nexus - offsetof(SRB, nexus));  

    scriptRestartAddr = (UInt32) &chipRamAddrPhys[Ent_phase_handler];
   
    /*   
     * Parity and SCSI Gross Errors.
     *
     * Abort the current connection. The abort completion will trigger
     * clean-up of the current SRB/Nexus.
     */
    if ( sistReg & PAR )
    {  
         srb->srbAdapterStatus = kSCSIAdapterStatusParityError;
         Sym8xxAbortCurrent( srb );
    }

    else if ( sistReg & SGE )
    {
         srb->srbAdapterStatus = kSCSIAdapterStatusProtocolError;
         Sym8xxAbortCurrent( srb );
    }
       
    /*
     * Unexpected disconnect. 
     *
     * If we were currently trying to abort this connection then mark the abort
     * as completed. For all cases clean-up and wake-up the client thread.
     */ 
    else if ( sistReg & UDC )
    {
        if ( srb->srbAdapterStatus == kSCSIAdapterStatusSuccess )
        {
            srb->srbAdapterStatus = kSCSIAdapterStatusProtocolError;
        }
        adapter->nexusPtrsVirt[nexusIndex] = (Nexus *) -1;
        adapter->nexusPtrsPhys[nexusIndex] = (Nexus *) -1;

        if ( scriptPhase == A_kphase_ABORT_CURRENT )
        {
            abortCurrentSRB = NULL;
        }

        Sym8xxCompleteSRB( srb );

        scriptRestartAddr = (UInt32) &chipRamAddrPhys[Ent_select_phase];
    }

    /*
     * Phase Mis-match
     *
     * If we are in MsgOut phase then calculate how much of the message we sent. For
     * now, however, we dont handle the target rejecting messages, so the request is aborted.
     *
     * If we are in DataIn/DataOut phase. We update the SRB/Nexus with our current data 
     * pointers.
     */
    else if ( sistReg & MA )
    {
        if ( scriptPhase == A_kphase_MSG_OUT )
        {
            srb->srbMsgResid = Sym8xxCheckFifo( srb, &fifoCnt );
            nexus->msg.ppData   = OSSwapHostToLittleInt32( OSSwapHostToLittleInt32(nexus->msg.ppData) 
                                                             + OSSwapHostToLittleInt32(nexus->msg.length) 
                                                                 - srb->srbMsgResid );
            nexus->msg.length   = OSSwapHostToLittleInt32( srb->srbMsgResid );

            Sym8xxAbortCurrent( srb );
        }
        else if ( (scriptPhase == A_kphase_DATA_OUT) || (scriptPhase == A_kphase_DATA_IN) )
        {
            Sym8xxAdjustDataPtrs( srb, nexus );
        }
        else
        {
            IOLog("SCSI(Symbios8xx): Unexpected phase mismatch - scriptPhase = %08x\n\r", (int)scriptPhase);
            Sym8xxAbortCurrent( srb );
        }

        Sym8xxClearFifo();
    }
    
    /*
     * Selection Timeout.
     *
     * Clean-up the current request.
     */
    else if ( sistReg & STO )
    {
        srb->srbAdapterStatus = kSCSIAdapterStatusSelectionTimeout;

        adapter->nexusPtrsVirt[nexusIndex] = (Nexus *) -1;
        adapter->nexusPtrsPhys[nexusIndex] = (Nexus *) -1;
        SCRIPT_VAR(R_ld_IOdone_mailbox)    = 0;

        Sym8xxCompleteSRB( srb );

        scriptRestartAddr = (UInt32) &chipRamAddrPhys[Ent_select_phase];
    }
        
    /*
     * Handle script initiated interrupts
     */
    else if ( dstatReg & SIR )
    {
        dspsReg = Sym8xxReadRegs( chipBaseAddr, DSPS, DSPS_SIZE );

//        printf( "SCSI(Symbios8xx): DSPS = %08x\n\r", dspsReg  );

        switch ( dspsReg )
        {
            /* 
             * Non-zero SCSI status
             *
             * Send request sense CDB or complete request depending on SCSI status value
             */
            case A_status_error:
                Sym8xxProcessIODone();
                break;

            /*
             * Received SDTR/WDTR message from target.
             *
             * Prepare reply message if we requested negotiation. Otherwise reject
             * target initiated negotiation.
             */
	    case A_negotiateSDTR:
                Sym8xxNegotiateSDTR( srb, nexus );
                break;

	    case A_negotiateWDTR:
                Sym8xxNegotiateWDTR( srb, nexus );
                break;

            /*
             * Partial SG List completed.
             *
             * Refresh the list from the remaining addresses to be transfered and set the
             * script engine to branch into the list.
             */
            case A_sglist_complete:
                Sym8xxUpdateSGList( srb );
                scriptRestartAddr = (UInt32)&srb->srbPhys->nexus.sgListData[2];
                break;

            /*
             * Completed abort request
             *
             * Clean-up the aborted request.
             */
	    case A_abort_current:	
                adapter->nexusPtrsVirt[nexusIndex] = (Nexus *) -1;
                adapter->nexusPtrsPhys[nexusIndex] = (Nexus *) -1; 

                abortCurrentSRB = NULL;

                Sym8xxCompleteSRB( srb );

                scriptRestartAddr = (UInt32) &chipRamAddrPhys[Ent_select_phase];
                break;
    
            /*
             * Script detected protocol errors
             *
             * Abort the current request.
             */
            case A_unknown_phase:
                srb->srbAdapterStatus = kSCSIAdapterStatusProtocolError;
                Sym8xxAbortCurrent( srb );
                break;

            case A_unknown_msg_reject:
            case A_unexpected_msg:
            case A_unexpected_ext_msg:
                srb->srbAdapterStatus = kSCSIAdapterStatusMsgReject;
                Sym8xxAbortCurrent( srb );
                break;

            default:
                IOLog( "SCSI(Symbios8xx): Unknown Script Int = %08x\n\r", (int)dspsReg );
                Sym8xxAbortCurrent( srb );
        }
    }

    /*
     * Illegal script instruction.
     *
     * We're toast! Abort the current request and hope for the best!
     */
    else if ( dstatReg & IID )
    {
        dspReg  = Sym8xxReadRegs( chipBaseAddr, DSP, DSP_SIZE );

        IOLog("SCSI(Symbios8xx): Illegal script instruction - dsp = %08x srb=%08x\n\r", (int)dspReg, (int)srb );

        Sym8xxAbortCurrent( srb );
    }

    if ( scriptRestartAddr )
    {
        Sym8xxWriteRegs( chipBaseAddr, DSP, DSP_SIZE, scriptRestartAddr );
    }
}    


/*-----------------------------------------------------------------------------*
 * Current Data Pointer calculations
 * 
 * To do data transfers the driver generates a list of script instructions 
 * in system storage to deliver data to the requested physical addresses. The
 * script branches to the list when the target enters data transfer phase.
 *
 * When the target changes phase during a data transfer, data is left trapped
 * inside the various script engine registers. This routine determines how much
 * data was not actually transfered to/from the target and generates a new
 * S/G List entry for the partial transfer and a branch back into the original
 * S/G list. These script instructions are stored in two reserved slots at the
 * top of the original S/G List.
 *
 *-----------------------------------------------------------------------------*/
void Sym8xxSCSIController::Sym8xxAdjustDataPtrs( SRB *srb, Nexus *nexus )
{
    UInt32		i;
    UInt32		sgResid;
    UInt32		fifoCnt;
    UInt32		dspReg;
    UInt32		sgDone;
    UInt8		scntl2Reg;
    Nexus		*nexusPhys;

    /*
     * Determine SG element residual
     *
     * This routine returns how much of the current S/G List element the 
     * script was processing remains to be sent/received. All the information
     * required to do this is stored in the script engine's registers.
     */
    sgResid = Sym8xxCheckFifo( srb, &fifoCnt );

    /*
     * Determine which script instruction in our SGList we were executing when
     * the target changed phase.
     *
     * The script engine's dspReg tells us where the script thinks it was. Based
     * on the physical address of our current SRB/Nexus we can calculate
     * an index into our S/G List.  
     */
    dspReg  = Sym8xxReadRegs( chipBaseAddr, DSP, DSP_SIZE );

    i = ((dspReg - (UInt32)srb->srbPhys->nexus.sgListData) / sizeof(SGEntry)) - 1;
       
    if ( i > MAX_SGLIST_ENTRIES-1 )
    {
       IOLog("SCSI(Symbios8xx): Bad sgListIndex\n\r");
       Sym8xxAbortCurrent( srb );
       return;
    }

    /* 
     * Wide/odd-byte transfers.
     *     
     * When dealing with Wide data transfers, if a S/G List ends with an odd-transfer count, then a
     * valid received data byte is left in the script engine's SWIDE register. The least painful way
     * to recover this byte is to construct a small script thunk to transfer one additional byte. The
     * script will automatically draw this byte from the SWIDE register rather than the SCSI bus.
     * The script thunk then branches back to script's PhaseHandler entrypoint.
     * 
     */
    nexusPhys = &srb->srbPhys->nexus;

    scntl2Reg = Sym8xxReadRegs( chipBaseAddr, SCNTL2, SCNTL2_SIZE );
    if ( scntl2Reg & WSR )
    {
        adapter->xferSWideInst[0] = OSSwapHostToLittleInt32( srb->directionMask | 1 );
        adapter->xferSWideInst[1] = nexus->sgListData[i].physAddr;
        adapter->xferSWideInst[2] = OSSwapHostToLittleInt32( 0x80080000 );
        adapter->xferSWideInst[3] = OSSwapHostToLittleInt32( (UInt32)&chipRamAddrPhys[Ent_phase_handler] );

        scriptRestartAddr = (UInt32) adapterPhys->xferSWideInst;
        
        /*
         * Note: There is an assumption here that the sgResid count will be > 1. It appears 
         *       that the script engine does not generate a phase-mismatch interrupt until 
         *       we attempt to move > 1 byte from the SCSI bus and the only byte available is
         *       in SWIDE. 
         */        
        sgResid--;
    }

    /*
     * Calculate partial S/G List instruction and branch
     *
     * Fill in slots 0/1 of the SGList based on the SGList index (i) and SGList residual count
     * (sgResid) calculated above.
     *
     */
    sgDone  = (OSSwapHostToLittleInt32( nexus->sgListData[i].length ) & 0x00ffffff) - sgResid;

    nexus->sgListData[0].length   = OSSwapHostToLittleInt32( sgResid | srb->directionMask );
    nexus->sgListData[0].physAddr = OSSwapHostToLittleInt32( OSSwapHostToLittleInt32(nexus->sgListData[i].physAddr) + sgDone );
    /*
     * If a previously calculated SGList 0 entry was interrupted again, we dont need to calculate
     * a new branch address since the previous one is still valid.
     */
    if ( i != 0 )
    {
        nexus->sgListData[1].length   = OSSwapHostToLittleInt32( 0x80080000 );
        nexus->sgListData[1].physAddr = OSSwapHostToLittleInt32( (UInt32)&nexusPhys->sgListData[i+1] );
        nexus->sgNextIndex            = i + 1;
    }
    nexus->ppSGList = (SGEntry *)OSSwapHostToLittleInt32( (UInt32) &nexusPhys->sgListData[0] );
 
    /*
     * The script sets this Nexus variable to non-zero each time it calls the driver generated
     * S/G list. This allows the driver's completion routines to differentiate between a successful
     * transfer vs no data transfer at all.
     */
    nexus->dataXferCalled = 0;

    return;
}

/*-----------------------------------------------------------------------------*
 * Determine SG element residual
 *
 * This routine returns how much of the current S/G List element the 
 * script was processing remains to be sent/received. All the information
 * required to do this is stored in the script engine's registers.
 *
 *-----------------------------------------------------------------------------*/
UInt32 Sym8xxSCSIController::Sym8xxCheckFifo( SRB *srb, UInt32 *pfifoCnt )
{
    bool		fSCSISend;
    bool		fXferSync;
    UInt32		scriptPhase 	= 0;
    UInt32		dbcReg    	= 0;
    UInt32		dfifoReg  	= 0;
    UInt32		ctest5Reg 	= 0;
    UInt8		sstat0Reg 	= 0;
    UInt8		sstat1Reg 	= 0;
    UInt8		sstat2Reg 	= 0;
    UInt32		fifoCnt   	= 0;
    UInt32		sgResid	  	= 0;

    scriptPhase = OSSwapHostToLittleInt32( SCRIPT_VAR(R_ld_phase_flag) );

    fSCSISend =  (scriptPhase == A_kphase_DATA_OUT) || (scriptPhase == A_kphase_MSG_OUT);
 
    fXferSync =  ((scriptPhase == A_kphase_DATA_OUT) || (scriptPhase == A_kphase_DATA_IN)) 
                         && (srb->nexus.targetParms.sxferReg & 0x1F);  

    dbcReg = Sym8xxReadRegs( chipBaseAddr, DBC, DBC_SIZE ) & 0x00ffffff;

    if ( !(dstatReg & DFE) )
    {
        ctest5Reg = Sym8xxReadRegs( chipBaseAddr, CTEST5, CTEST5_SIZE );
        dfifoReg  = Sym8xxReadRegs( chipBaseAddr, DFIFO,  DFIFO_SIZE );

        if ( ctest5Reg & DFS )
        {
            fifoCnt = ((((ctest5Reg & 0x03) << 8) | dfifoReg) - dbcReg) & 0x3ff;
        }
        else
        {
            fifoCnt = (dfifoReg - dbcReg) & 0x7f;
        }
    }

    sstat0Reg = Sym8xxReadRegs( chipBaseAddr, SSTAT0, SSTAT0_SIZE );
    sstat2Reg = Sym8xxReadRegs( chipBaseAddr, SSTAT2, SSTAT2_SIZE );
 
    if ( fSCSISend )
    {    
        fifoCnt += (sstat0Reg & OLF )  ? 1 : 0;
        fifoCnt += (sstat2Reg & OLF1)  ? 1 : 0;

        if ( fXferSync )
        {
            fifoCnt += (sstat0Reg & ORF )  ? 1 : 0;
            fifoCnt += (sstat2Reg & ORF1)  ? 1 : 0;
        }
    }
    else
    {
        if ( fXferSync )
        {
            sstat1Reg = Sym8xxReadRegs( chipBaseAddr, SSTAT0, SSTAT0_SIZE );
            fifoCnt +=  (sstat1Reg >> 4) | (sstat2Reg & FF4);  
        }
        else
        {
            fifoCnt += (sstat0Reg & ILF )  ? 1 : 0;
            fifoCnt += (sstat2Reg & ILF1)  ? 1 : 0;
        }
    }   
    
    sgResid   = dbcReg + fifoCnt;
    *pfifoCnt = fifoCnt;

    return sgResid;
}

/*-----------------------------------------------------------------------------*
 * Calculate transfer counts.
 *
 * This routine updates srb->xferDone with the amount of data transferred
 * by the last S/G List executed.
 *
 *-----------------------------------------------------------------------------*/
void Sym8xxSCSIController::Sym8xxUpdateXferOffset( SRB *srb )
{
    UInt32		i;
    UInt32		xferOffset;

    /*
     * srb->xferOffset contains the client buffer offset INCLUDING the range
     * covered by the current SGList.
     */
    xferOffset = srb->xferOffset;

    /*
     * If script did not complete the current transfer list then we need to determine
     * how much of the list was completed.
     */
    if ( srb->nexus.dataXferCalled == 0 )
    {
        /* 
         * srb->xferOffsetPrev contains the client buffer offset EXCLUDING the
         * range covered by the current SGList.
         */
        xferOffset = srb->xferOffsetPrev;

        /*
         * Calculate bytes transferred for partially completed list.
         *
         * To calculate the amount of this list completed, we sum the residual amount
         * in SGList Slot 0 and the completed list elements 2 to sgNextIndex-1.
         */
        if ( srb->nexus.sgNextIndex != 0 )
        {
            xferOffset += OSSwapHostToLittleInt32( srb->nexus.sgListData[srb->nexus.sgNextIndex-1].length )
                             - OSSwapHostToLittleInt32( srb->nexus.sgListData[0].length );

            for ( i=2; i < srb->nexus.sgNextIndex-1; i++ )
            {
                xferOffset += OSSwapHostToLittleInt32( srb->nexus.sgListData[i].length ) & 0x00ffffff;
            }
        }
    }
    
    /*
     * The script leaves the result of any Ignore Wide Residual message received from the target
     * during the transfer.
     */
    xferOffset -= srb->nexus.wideResidCount;


#if 0
    {
        UInt32	resid = srb->xferOffset - xferOffset;
        if ( resid )
        {
            IOLog( "SCSI(Symbios8xx): Incomplete transfer - Req Count = %08x Act Count = %08x - srb = %08x\n\r", 
                    srb->xferCount, xferOffset, (UInt32)srb );
        }   
    }
#endif

    srb->xferDone = xferOffset;
}

/*-----------------------------------------------------------------------------*
 * No SRB/Nexus Processing.
 *
 * In some cases (mainly Aborts) not having a SRB/Nexus is normal. In other
 * cases it indicates a problem such a reconnection from a target that we
 * have no record of.
 *
 *-----------------------------------------------------------------------------*/
void Sym8xxSCSIController::Sym8xxProcessNoNexus()
{
    UInt32			dspsReg;
    UInt32			dspReg      = 0;
    UInt32			scriptPhase = (UInt32)-1 ;

    scriptRestartAddr = (UInt32) &chipRamAddrPhys[Ent_select_phase];

    dspsReg = Sym8xxReadRegs( chipBaseAddr, DSPS, DSPS_SIZE );

    scriptPhase = OSSwapHostToLittleInt32( SCRIPT_VAR(R_ld_phase_flag) );

    /* 
     * If we were trying to abort or disconnect a target and the bus
     * is now free we consider the abort to have completed.
     */
    if ( sistReg & UDC ) 
    {
        if ( (scriptPhase == A_kphase_ABORT_MAILBOX) && abortSRB )
        {
            Sym8xxCompleteSRB( abortSRB );
            SCRIPT_VAR(R_ld_AbortBdr_mailbox) = 0;
        }         
        else if ( scriptPhase == A_kphase_ABORT_CURRENT )
        {
            abortCurrentSRB = NULL;
        }
    }
    /*
     * If we were trying to connect to a target to send it an abort message, and
     * we timed out, we consider the abort as completed.
     *
     * Note: In this case the target may be hung, but at least its not on the bus.
     */
    else if ( sistReg & STO )
    {
        if ( (scriptPhase == A_kphase_ABORT_MAILBOX) && abortSRB )
        {
            Sym8xxCompleteSRB( abortSRB );
            SCRIPT_VAR(R_ld_AbortBdr_mailbox) = 0;
        }         
    }     
    
    /*
     * If the script died, without a vaild nexusIndex, we abort anything that is currently
     * connected and hope for the best!
     */
    else if ( dstatReg & IID )
    {
        dspReg  = Sym8xxReadRegs( chipBaseAddr, DSP, DSP_SIZE );
        IOLog("SCSI(Symbios8xx): Illegal script instruction - dsp = %08x srb=0\n\r", (int)dspReg );
        Sym8xxAbortCurrent( (SRB *)-1 );
    }

    /*
     * Script signaled conditions
     */
    else if ( dstatReg & SIR )
    {
        switch ( dspsReg )
        {
            case A_abort_current:
                abortCurrentSRB = NULL;
                break;
              
            case A_abort_mailbox:
                Sym8xxCompleteSRB( abortSRB );
                SCRIPT_VAR(R_ld_AbortBdr_mailbox) = 0;
                break;
           
            default:
               Sym8xxAbortCurrent( (SRB *)-1 );
        }
    }             
    else
    {
        Sym8xxAbortCurrent( (SRB *)-1 );
    }

    if ( scriptRestartAddr )
    {
        Sym8xxWriteRegs( chipBaseAddr, DSP, DSP_SIZE, scriptRestartAddr );
    }
}
 

/*-----------------------------------------------------------------------------*
 * Abort currently connected target.
 *
 *-----------------------------------------------------------------------------*/
void Sym8xxSCSIController::Sym8xxAbortCurrent( SRB *srb )
{
    if ( abortCurrentSRB )
    {
        if ( abortCurrentSRB != srb )
        {
            IOLog("SCSI(Symbios8xx): Multiple abort immediate SRBs - resetting\n\r");
            Sym8xxSCSIBusReset( (SRB *)0 );
        }
        return;
    }
   
    abortCurrentSRB        = srb;

    if ( srb != (SRB *)-1 )
    {
        if ( srb->srbAdapterStatus == kSCSIAdapterStatusSuccess )
        {
            srb->srbAdapterStatus = kSCSIAdapterStatusProtocolError;
        }
    }

    /*
     * Issue abort or abort tag depending on whether the is a tagged request
     */
    SCRIPT_VAR(R_ld_AbortCode) = OSSwapHostToLittleInt32( ((srb != (SRB *)-1) && (srb->nexus.tag >= MIN_SCSI_TAG)) ? 0x0d : 0x06 );
    scriptRestartAddr = (UInt32) &chipRamAddrPhys[Ent_issueAbort_BDR];

    Sym8xxClearFifo();
}

/*-----------------------------------------------------------------------------*
 * This routine clears the script engine's SCSI and DMA fifos.
 *
 *-----------------------------------------------------------------------------*/
void  Sym8xxSCSIController::Sym8xxClearFifo()
{
    UInt8		ctest3Reg;
    UInt8		stest2Reg;
    UInt8		stest3Reg;

    stest2Reg  = Sym8xxReadRegs( chipBaseAddr, STEST2, STEST2_SIZE );
    if ( stest2Reg & ROF )
    {
        Sym8xxWriteRegs( chipBaseAddr, STEST2, STEST2_SIZE, stest2Reg );
    }

    ctest3Reg = Sym8xxReadRegs( chipBaseAddr, CTEST3, CTEST3_SIZE );
    ctest3Reg |= CLF;
    Sym8xxWriteRegs( chipBaseAddr, CTEST3, CTEST3_SIZE, ctest3Reg );

    stest3Reg = Sym8xxReadRegs( chipBaseAddr, STEST3, STEST3_SIZE );
    stest3Reg |= CSF;
    Sym8xxWriteRegs( chipBaseAddr,STEST3, STEST3_SIZE, stest3Reg );

    do
    {
        ctest3Reg = Sym8xxReadRegs( chipBaseAddr, CTEST3, CTEST3_SIZE );
        stest2Reg = Sym8xxReadRegs( chipBaseAddr, STEST3, STEST3_SIZE );
        stest3Reg = Sym8xxReadRegs( chipBaseAddr, STEST3, STEST3_SIZE );
    } 
    while( (ctest3Reg & CLF) || (stest3Reg & CSF) || (stest2Reg & ROF) );            
}

/*-----------------------------------------------------------------------------*
 * This routine processes the target's response to our SDTR message.
 * 
 * We calculate the values for the script engine's timing registers
 * for synchronous registers, and update our tables indicating that
 * requested data transfer mode is in-effect.
 *
 *-----------------------------------------------------------------------------*/
void Sym8xxSCSIController::Sym8xxNegotiateSDTR( SRB *srb, Nexus *nexus )
{
    UInt32		x;
    UInt8		*pMsg;
    UInt32		syncPeriod;
    
    /*
     * If we were not negotiating, the send MsgReject to targets negotiation
     * attempt.
     */
    if ( !(srb->srbCDBFlags & kCDBFlagsNegotiateSDTR) )
    {
        Sym8xxSendMsgReject( srb );
        return;
    }

    /* 
     * Get pointer to negotiation message received from target.
     */
    pMsg = (UInt8 *) &SCRIPT_VAR(R_ld_message);

    /*
     * The target's SDTR response contains the (transfer period / 4).
     *
     * We set our sync clock divisor to 1, 2, or 4 giving us a clock rates
     * of:
     *     80Mhz (Period = 12.5ns), 
     *     40Mhz (Period = 25.0ns)
     *     20Mhz (Period = 50.0ns) 
     *
     * This is further divided by the value in the sxfer reg to give us the final sync clock rate.
     *
     * The requested sync period is scaled up by 1000 and the clock periods are scaled up by 10
     * giving a result scaled up by 100. This is rounded-up and converted to sxfer reg values.
     */
    if ( pMsg[4] == 0 )
    {
        nexus->targetParms.scntl3Reg &= 0x0f;
        nexus->targetParms.sxferReg   = 0x00;
    }
    else
    {    
        syncPeriod = (UInt32)pMsg[3] << 2;
        if ( syncPeriod < 100 )
        {
            nexus->targetParms.scntl3Reg |= SCNTL3_INIT_875_ULTRA;
            x = (syncPeriod * 1000) / 125;
        }
        else if ( syncPeriod < 200 )
        {
            nexus->targetParms.scntl3Reg  |= SCNTL3_INIT_875_FAST;
            x = (syncPeriod * 1000) / 250;
        }
        else 
        {
            nexus->targetParms.scntl3Reg  |= SCNTL3_INIT_875_SLOW;
            x = (syncPeriod * 1000) / 500;
        }
           
        if ( x % 100 ) x += 100;
    
        /*
         * sxferReg  Bits: 5-0 - Transfer offset
         *                 7-6 - Sync Clock Divisor (0 = sync clock / 4)
         */
        nexus->targetParms.sxferReg = ((x/100 - 4) << 5) | pMsg[4];

        transferPeriod = syncPeriod * 1000;
        transferOffset = pMsg[4];

        srb->negotiateSDTRComplete = true;
    }    

    /*
     * Update our per-target tables and set-up the hardware regs for this request.
     *
     * On reconnection attempts, the script will use our per-target tables to set-up
     * the scntl3 and sxfer registers in the script engine.
     */
    adapter->targetClocks[srb->target].sxferReg  = nexus->targetParms.sxferReg;
    adapter->targetClocks[srb->target].scntl3Reg = nexus->targetParms.scntl3Reg;

    Sym8xxWriteRegs( chipBaseAddr, SCNTL3, SCNTL3_SIZE, nexus->targetParms.scntl3Reg );
    Sym8xxWriteRegs( chipBaseAddr, SXFER,  SXFER_SIZE,  nexus->targetParms.sxferReg );

    scriptRestartAddr = (UInt32) &chipRamAddrPhys[Ent_clearACK];
}
   
/*-----------------------------------------------------------------------------*
 * This routine processes the target's response to our WDTR message.
 *
 * In addition, if there is a pending SDTR message, this routine sends it
 * to the target.
 *
 *-----------------------------------------------------------------------------*/
void Sym8xxSCSIController::Sym8xxNegotiateWDTR( SRB *srb, Nexus *nexus )
{
    UInt8		*pMsg;
    UInt32		msgBytesSent;
    UInt32           msgBytesLeft;

    /*
     * If we were not negotiating, the send MsgReject to targets negotiation
     * attempt.
     */
   if ( !(srb->srbCDBFlags & kCDBFlagsNegotiateWDTR) )
    {
        Sym8xxSendMsgReject( srb );
        return;
    }

    /* 
     * Set Wide (16-bit) vs Narrow (8-bit) data transfer mode based on target's response.
     */
    pMsg = (UInt8 *) &SCRIPT_VAR(R_ld_message);

    if ( pMsg[3] == 1 )
    {
        nexus->targetParms.scntl3Reg |= EWS;
        transferWidth = 2;
    }
    else
    {
        nexus->targetParms.scntl3Reg &= ~EWS;
        transferWidth = 1;
    }

    /*
     * Update our per-target tables and set-up the hardware regs for this request.
     *
     * On reconnection attempts, the script will use our per-target tables to set-up
     * the scntl3 and sxfer registers in the script engine.
     */

    adapter->targetClocks[srb->target].scntl3Reg = nexus->targetParms.scntl3Reg;
    Sym8xxWriteRegs( chipBaseAddr, SCNTL3, SCNTL3_SIZE, nexus->targetParms.scntl3Reg );

    srb->negotiateWDTRComplete = true; 

    /*
     * If there any pending messages left for the target, send them now, 
     */
    msgBytesSent = OSSwapHostToLittleInt32( nexus->msg.length );
    msgBytesLeft = srb->srbMsgLength - msgBytesSent;
    if ( msgBytesLeft )
    {
        nexus->msg.length = OSSwapHostToLittleInt32( msgBytesLeft );
        nexus->msg.ppData = OSSwapHostToLittleInt32( OSSwapHostToLittleInt32( nexus->msg.ppData ) + msgBytesSent );                
        scriptRestartAddr = (UInt32) &chipRamAddrPhys[Ent_issueMessageOut];
    }

    /*
     * Otherwise, tell the script we're done with MsgOut phase.
     */
    else
    {
        scriptRestartAddr = (UInt32) &chipRamAddrPhys[Ent_clearACK];
    }
}  

/*-----------------------------------------------------------------------------*
 * Reject message received from target.
 *
 *-----------------------------------------------------------------------------*/
void Sym8xxSCSIController::Sym8xxSendMsgReject( SRB *srb )
{
    srb->nexus.msg.ppData = OSSwapHostToLittleInt32((UInt32)&srb->srbPhys->nexus.msgData);
    srb->nexus.msg.length = OSSwapHostToLittleInt32(0x01);
    srb->nexus.msgData[0] = 0x07;

    scriptRestartAddr = (UInt32) &chipRamAddrPhys[Ent_issueMessageOut];
}
  

/*-----------------------------------------------------------------------------*
 * This routine initiates a SCSI Bus Reset.
 *
 * This may be an internally generated request as part of error recovery or
 * a client's bus reset request.
 *
 *-----------------------------------------------------------------------------*/
void Sym8xxSCSIController::Sym8xxSCSIBusReset( SRB *srb )
{
    if ( srb )
    {
        if ( resetSRB )
        {
            srb->srbReturnCode = kIOReturnBusy;
            Sym8xxCompleteSRB( srb );
            return;
        }    
        resetSRB = srb;
    }

    Sym8xxAbortScript();

    Sym8xxWriteRegs( chipBaseAddr, SCNTL1, SCNTL1_SIZE, SCNTL1_SCSI_RST );
    IODelay( 100 );
    Sym8xxWriteRegs( chipBaseAddr, SCNTL1, SCNTL1_SIZE, SCNTL1_INIT );
}
    
/*-----------------------------------------------------------------------------*
 * This routine handles a SCSI Bus Reset interrupt.
 *
 * The SCSI Bus reset may be generated by a target on the bus, internally from
 * the driver's error recovery or from a client request.
 *
 * Once the reset is detected we establish a settle period where new client requests
 * are blocked in the client thread. In addition we flush all currently executing
 * scsi requests back to the client.
 *
 *-----------------------------------------------------------------------------*/
void Sym8xxSCSIController::Sym8xxProcessSCSIBusReset()
{
    UInt32		i;

   Sym8xxClearFifo();

    /*
     * We clear the script's request mailboxes. Any work in the script mailboxes is
     * already in the NexusPtr tables so we have already have handled the SRB/Nexus
     * cleanup.
     */
    for ( i=0; i < MAX_SCHED_MAILBOXES; i++ )
    {
        adapter->schedMailBox[i] = 0;
    }

    SCRIPT_VAR(R_ld_AbortBdr_mailbox) = 0;
    SCRIPT_VAR(R_ld_IOdone_mailbox)   = 0;
    SCRIPT_VAR(R_ld_counter)          = 0;
    mailBoxIndex                      = 0;


    /*
     * Reset the data transfer mode/clocks in our per-target tables back to Async/Narrow 8-bit
     */
    for ( i=0; i < MAX_SCSI_TARGETS; i++ )
    {
        adapter->targetClocks[i].scntl3Reg = SCNTL3_INIT_875;
        adapter->targetClocks[i].sxferReg  = 0;
    }

    scriptRestartAddr = (UInt32) &chipRamAddrPhys[Ent_select_phase];
    Sym8xxWriteRegs( chipBaseAddr, DSP, DSP_SIZE, scriptRestartAddr );

    if ( resetSRB )
    {
        resetSRB->srbReturnCode = kIOReturnBusy;
        Sym8xxCompleteSRB( resetSRB );
        resetSRB = 0;
    }
    else if ( initialReset == true )
    {
        initialReset = false;
    }    
    else
    {
        resetOccurred();
    }
}

/*-----------------------------------------------------------------------------*
 * This routine sets the SIGP bit in the script engine's ISTAT
 * register. This signals the script to wake-up for a WAIT for
 * reselection instruction. The script will then check the mailboxes
 * for work to do.
 *
 *-----------------------------------------------------------------------------*/
void Sym8xxSCSIController::Sym8xxSignalScript( SRB *srb )
{
    Sym8xxWriteRegs( chipBaseAddr, ISTAT, ISTAT_SIZE, SIGP );
}

/*-----------------------------------------------------------------------------*
 * 
 *
 *
 *
 *
 *-----------------------------------------------------------------------------*/
void  Sym8xxSCSIController::Sym8xxCheckRequestSense( SRB *srb )
{
    IOSCSIParallelCommand	*scsiCommand;
    IOMemoryDescriptor          *reqSenseDesc;
    
    scsiCommand = srb->scsiCommand;
    
    scsiCommand->getPointers( &reqSenseDesc, 0, 0, true );
    
    if ( reqSenseDesc != 0 )
    {
        Sym8xxCancelMailBox( srb->target, srb->lun, true );
    }    
}

/*-----------------------------------------------------------------------------*
 * This routine does a mailbox abort.
 *
 * This type of abort is used for targets not currently connected to the SCSI Bus.
 *
 * The script will select the target and send a tag (if required) followed by the
 * appropriate abort message (abort/abort-tag)
 *
 *-----------------------------------------------------------------------------*/
void  Sym8xxSCSIController::Sym8xxAbortBdr( SRB *srb )
{
    IOAbortBdrMailBox 			abortMailBox;

    abortSRB        = srb;

    /*
     * Setup a script variable containing the abort information.
     */
    abortMailBox.identify  = srb->nexus.msgData[0];
    abortMailBox.tag       = srb->nexus.msgData[1]; 
    abortMailBox.message   = srb->nexus.msgData[2];
    abortMailBox.scsi_id   = srb->target;

    SCRIPT_VAR(R_ld_AbortBdr_mailbox) = *(UInt32 *) &abortMailBox;

    Sym8xxSignalScript( srb );
}

/*-----------------------------------------------------------------------------*
 *
 *
 *
 *
 *-----------------------------------------------------------------------------*/
bool Sym8xxSCSIController::Sym8xxCancelMailBox( Nexus *nexusCancel )
{
    Nexus		*nexusPhys;
    UInt32		i;

    nexusPhys = (Nexus *)OSSwapHostToLittleInt32( (UInt32)nexusCancel );
    for ( i=0; i < MAX_SCHED_MAILBOXES; i++ )
    {
        if ( nexusPhys == adapter->schedMailBox[i] )
        {
            adapter->schedMailBox[i] = (Nexus *)OSSwapHostToLittleInt32( kMailBoxCancel );
            return true;
        }
    }
    return false;
}


/*-----------------------------------------------------------------------------*
 *
 *
 *
 *
 *-----------------------------------------------------------------------------*/
void  Sym8xxSCSIController::Sym8xxCancelMailBox( UInt32 target, UInt32 lun, bool fReschedule )
{
    UInt32		tag;
    UInt32		tagPos;
    UInt32		tagShift;

    UInt32		i;

    SRB			*srb;
    Nexus		*nexus;
    Nexus		*nexusPhys;

    tagPos = offsetof(Nexus, tag) & 0x03;
    tagShift  = 24 - (tagPos << 3);

    for ( i=0; i < MAX_SCHED_MAILBOXES; i++ )
    {
        nexusPhys = (Nexus *)OSSwapHostToLittleInt32( (UInt32)adapter->schedMailBox[i] );
        if ( (nexusPhys != (Nexus *)kMailBoxEmpty) && (nexusPhys != (Nexus *)kMailBoxCancel) )
        {
            /* 
             * Read the 'tag' byte given Nexus physical address from the mailBox. 
             * Look-up the virtual address of the corresponding Nexus struct.
             */                
            tag     = ml_phys_read((UInt32)&nexusPhys->tag - tagPos);
            tag     = (tag >> tagShift) & 0xff;

            nexus = adapter->nexusPtrsVirt[tag];
            if ( nexus == (Nexus *)-1 )
            {
                continue;
            }

            /*
             * If the SCSI target of the mailbox entry matches the abort SRB target,
             * then we may have a winner.
             */
            srb = (SRB *)((UInt32)nexus - offsetof(SRB, nexus));

            if ( srb->target == target )
            {
                /*
                 * For a device reset, we cancel all requests for that target regardless of lun.
                 * For an abort all, we must match on both target and lun
                 */
                if ( (lun == (UInt32)-1) || (srb->lun == lun) )
                {
                    adapter->schedMailBox[i] = (Nexus *)OSSwapHostToLittleInt32( kMailBoxCancel );

                    if ( fReschedule == true )
                    {
                        rescheduleCommand( srb->scsiCommand );
                    }                           
                }
            }
        }
    }
}

/*-----------------------------------------------------------------------------*
 * This routine is used to shutdown the script engine in an orderly fashion.
 *
 * Normally the script engine automatically stops when an interrupt is generated. However,
 * in the case of timeouts we need to change the script engine's dsp reg (instruction pointer).
 * to issue an abort.
 *
 *-----------------------------------------------------------------------------*/
void Sym8xxSCSIController::Sym8xxAbortScript()
{
    mach_timespec_t		currentTime;
    mach_timespec_t		startTime;

    getWorkLoop()->disableAllInterrupts();
    
    /*
     * We set the ABRT bit in ISTAT and spin until the script engine acknowledges the
     * abort or we timeout.
     */
    Sym8xxWriteRegs( chipBaseAddr, ISTAT, ISTAT_SIZE, ABRT );
    
    IOGetTime( &startTime );

    do
    {
        IOGetTime( &currentTime );
        SUB_MACH_TIMESPEC( &currentTime, &startTime );

        istatReg = Sym8xxReadRegs( chipBaseAddr, ISTAT, ISTAT_SIZE );

        if ( istatReg & SIP )
        {
            Sym8xxReadRegs( chipBaseAddr, SIST, SIST_SIZE );
            continue;
        }
    
        if ( istatReg & DIP )
        {
            Sym8xxWriteRegs( chipBaseAddr, ISTAT, ISTAT_SIZE, 0x00 );
            Sym8xxReadRegs( chipBaseAddr, DSTAT, DSTAT_SIZE );
            break;
        }
    }
    while ( currentTime.tv_nsec < (kAbortScriptTimeoutMS * 1000 * 1000) );
    
    istatReg = SIGP;
    Sym8xxWriteRegs( chipBaseAddr, ISTAT, ISTAT_SIZE, istatReg );

    getWorkLoop()->enableAllInterrupts();

    if ( currentTime.tv_nsec >= (kAbortScriptTimeoutMS * 1000 * 1000) )
    {
        IOLog( "SCSI(Symbios8xx): Abort script failed - resetting bus\n\r" );
    }  

  }
    

