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
 *    IOATAStandardDriverDma.cpp
 *
 */
#include <IOKit/ata/IOATAStandardInterface.h>

/*----------------------------------- ATA DMA Protocol ------------------------------*/

/*
 *
 *
 */
void IOATAStandardDriver::doATAProtocolDma( IOATAStandardCommand *cmd )
{    
    ATATaskfile		taskfile;
    UInt32		regmask;
    UInt32		i;

    setCommandLimit( currentDevice, 1 );

    cmd->getTaskfile( &taskfile );

    regmask = taskfile.regmask;

    if ( regmask & ATARegtoMask(kATARegDriveHead) )
    {
        regmask &= ~ATARegtoMask(kATARegDriveHead);
        if ( selectDrive( taskfile.ataRegs[kATARegDriveHead] ) == false )
        {
            completeCmd( cmd, kATAReturnBusyError );
            return;
        }          
    }
    
    programDma( cmd );

    for ( i = 0; regmask; i++ )
    {
        if ( regmask & 1 )
        {
            writeATAReg( i, taskfile.ataRegs[i] );
        }
        regmask >>= 1;
    }

    startDma( cmd );
}

/*
 *
 * 
 */
void IOATAStandardDriver::processATADmaInt()
{    
    UInt32			status;
    UInt32			reqCount;
    ATAReturnCode		rc = kATAReturnSuccess;
    IOATAStandardCommand	*ataCmd;
    UInt32			xferCount;

    ataCmd = findCommandWithNexus( currentDevice, (UInt32) -1 );
    if ( ataCmd == 0 )
    {
        IOLog( "IOATAStandardDriver::processATADmaInt() - ATA Command not found\n\r" );
        return;
    }
   
    if ( waitForStatus( 0, kATAStatusBSY, kATABusyTimeoutmS ) == false )
    {
        stopDma( ataCmd, &xferCount );
        completeCmd( ataCmd, kATAReturnBusyError, xferCount );
        return;
    }

    status = readATAReg( kATARegStatus );
   
    ataCmd->getPointers( 0, &reqCount, 0 );    

    if ( stopDma( ataCmd, &xferCount ) != true )
    {
        rc = kATAReturnDMAError;
    }

    else if ( status & kATAStatusDRQ )
    {
        rc = kATAReturnDMAError;
    }

    else if ( status & kATAStatusERR )
    {
        rc = kATAReturnStatusError;
    }

    else if ( reqCount != xferCount )
    {
        rc = kATAReturnProtocolError;
    }

    completeCmd( ataCmd, rc, xferCount );
}
 
/*----------------------------------- ATA DMA Queued Protocol ------------------------------*/

/*
 *
 *
 */
void IOATAStandardDriver::doATAProtocolDmaQueued( IOATAStandardCommand *ataCmd )
{    
    ATATaskfile		taskfile;
    UInt32		regmask;
    UInt32		i;

    if ( dmaActive == true )
    {
        setCommandLimit( currentDevice, 0 );
        rescheduleCommand( ataCmd );
        return;
    }

    setCommandLimit( currentDevice, 31 );

    ataCmd->getTaskfile( &taskfile );

    regmask = taskfile.regmask;

    regmask &= ~(ATARegtoMask(kATARegDriveHead) | ATARegtoMask(kATARegCommand));

    if ( selectDrive( taskfile.ataRegs[kATARegDriveHead] ) == false )
    {
        completeCmd( ataCmd, kATAReturnBusyError );
        return;
    }          
    
    programDma( ataCmd );
    dmaActive = true;
    startDma( ataCmd );

    taskfile.ataRegs[kATARegSectorCount] = taskfile.tag << 3;

    for ( i = 0; regmask; i++ )
    {
        if ( regmask & 1 )
        {
            writeATAReg( i, taskfile.ataRegs[i] );
        }
        regmask >>= 1;
    }

    writeATAReg( kATARegCommand, taskfile.ataRegs[kATARegCommand] );

#if 1
    IODelay( 1 );
    waitForAltStatus( 0, kATAStatusBSY, kATABusyTimeoutmS );
#endif
}

/*
 *
 * 
 */
void IOATAStandardDriver::processATADmaQueuedInt()
{    
    UInt32			status;
    UInt32			intReason;
    UInt32			tag;
    UInt32			xferCount;
    IOATAStandardCommand	*ataCmd;
    ATAReturnCode		rc = kATAReturnSuccess;

    while ( 1 )
    {
        status = readATAReg( kATARegStatus );
        intReason = readATAReg( kATARegSectorCount );
        tag       = intReason / kATATagBit;

        ataCmd = findCommandWithNexus( currentDevice, tag );

        if ( (intReason & kATAPIIntReasonCD) && (intReason & kATAPIIntReasonIO) && (dmaActive == true) )
        {
            if ( ataCmd == 0 )
            {
                IOLog( "IOATAStandardDriver::processATADmaQueuedInt() - ATA Command not found\n\r" );
                return;
            }

            dmaActive = false;

            if ( stopDma( ataCmd, &xferCount ) != true )
            {
                rc = kATAReturnDMAError;
            }

            else if ( status & kATAStatusERR )
            {
                rc = kATAReturnStatusError;
            }

            completeCmd( ataCmd, rc, xferCount );
        }
            
        if ( (status & kATAStatusDRQ) != 0 )
        {  
            if ( ataCmd == 0 )
            {
                IOLog( "IOATAStandardDriver::processATADmaQueuedInt() - ATA Command not found\n\r" );
                return;
            }

            programDma( ataCmd );
            dmaActive = true;
            startDma( ataCmd );
            break;
        }
        
        if ( status & kATAStatusSERV )
        {
            resetDma();
            
            writeATAReg( kATARegCommand, kATACommandService );

            if ( waitForAltStatus( 0, kATAStatusBSY, 500 ) == false )
            {
                return;
            }                
            continue;
        }
        
        if ( dmaActive == false )
        {
            setCommandLimit( currentDevice, 31 );
        }
        break;
    }

} 

/*----------------------------------- ATAPI DMA Protocols ------------------------------*/

/*
 *
 *
 *
 */
void IOATAStandardDriver::doATAPIProtocolDma( IOATAStandardCommand *ataCmd )
{    
    ATATaskfile		taskfile;
    ATACDBInfo		atapiCmd;
    ATAReturnCode	rc;
    UInt32		regmask;
    UInt32		i;

    setCommandLimit( currentDevice, 1 );

    ataCmd->getTaskfile( &taskfile );
    ataCmd->getCDB( &atapiCmd );

    regmask = taskfile.regmask;

    if ( regmask & ATARegtoMask(kATARegDriveHead) )
    {
        regmask &= ~ATARegtoMask(kATARegDriveHead);
        if ( selectDrive( taskfile.ataRegs[kATARegDriveHead] ) == false )
        {
            completeCmd( ataCmd, kATAReturnBusyError);
            return;
        }          
    }

    // Wait for BSY = 0 and DRQ = 0 before issuing a packet command.

    waitForStatus( 0, kATAStatusBSY | kATAStatusDRQ, kATABusyTimeoutmS );

    for ( i = 0; regmask; i++ )
    {
        if ( regmask & 1 )
        {
            writeATAReg( i, taskfile.ataRegs[i] );
        }
        regmask >>= 1;
    }

    programDma( ataCmd );
    
    if ( ataCmd->getDevice(kIOATAStandardDevice)->getATAPIPktInt() == false )
    {         
        rc = sendATAPIPacket( ataCmd );

       if ( rc != kATAReturnSuccess )
        {
            completeCmd( ataCmd, rc );
            return;
        }

        startDma( ataCmd );
    }
}


/*
 *
 * 
 */
void IOATAStandardDriver::processATAPIDmaInt()
{
    IOATAStandardCommand	*ataCmd;
    ATAReturnCode		rc = kATAReturnProtocolError;    
    UInt32			status;
    UInt32			intReason;
    UInt32			xferCount;

    ataCmd = findCommandWithNexus( currentDevice, (UInt32) -1 );
    if ( ataCmd == 0 )
    {
        IOLog( "IOATAStandardDriver::processATAPIDmaInt() - ATA Command not found\n\r" );
        return;
    }
   
    if ( waitForStatus( 0, kATAStatusBSY, kATABusyTimeoutmS ) == false )
    {
        completeCmd( ataCmd, kATAReturnBusyError, 0 );
        return;
    }

    status    = readATAReg( kATARegATAPIStatus );
    intReason = readATAReg( kATARegATAPIIntReason );

    if ( (status & kATAPIStatusDRQ) && (intReason & kATAPIIntReasonCD) && !(intReason & kATAPIIntReasonIO) )
    {
        rc = sendATAPIPacket( ataCmd );
        if ( rc != kATAReturnSuccess )
        {
            completeCmd( ataCmd, rc );
        }

        else if ( startDma( ataCmd ) != true )
        {
            rc = kATAReturnDMAError;
            completeCmd( ataCmd, rc );    
        }
    }

    else if ( !(status & kATAPIStatusDRQ) && (intReason & kATAPIIntReasonCD) && (intReason & kATAPIIntReasonIO) )    
    {  
        if ( stopDma( ataCmd, &xferCount ) != true )
        {
            rc = kATAReturnDMAError;
            xferCount = 0;      
        }
        else
        {
            rc = (status & kATAPIStatusCHK) ? kATAReturnStatusError : kATAReturnSuccess; 
        }

        completeCmd( ataCmd, rc, xferCount ); 
    }
    else 
    {
        stopDma( ataCmd, &xferCount );
        completeCmd( ataCmd, rc, 0 );
    }
}

