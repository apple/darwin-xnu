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
 *    IOATAStandardDriverPio.cpp
 *
 */
#include <IOKit/ata/IOATAStandardInterface.h>

/*----------------------------------- ATA SetRegs Protocol ------------------------------*/

/*
 *
 *
 */
void IOATAStandardDriver::doProtocolSetRegs( IOATAStandardCommand *ataCmd )
{    
    ATATaskfile		taskfile;
    UInt32		regmask;
    UInt32		i;

    setCommandLimit( currentDevice, 1 );

    ataCmd->getTaskfile( &taskfile );

    regmask = taskfile.regmask;

    if ( regmask & ATARegtoMask(kATARegDriveHead) )
    {
        regmask &= ~ATARegtoMask(kATARegDriveHead);
        if ( selectDrive( taskfile.ataRegs[kATARegDriveHead] ) == false )
        {
            completeCmd( ataCmd, kATAReturnBusyError );
            return;
        }          
    }

    for ( i = 0; regmask; i++ )
    {
        if ( regmask & 1 )
        {
            writeATAReg( i, taskfile.ataRegs[i] );
        }
        regmask >>= 1;
    }

    IODelay( 100 );

    completeCmd( ataCmd, kATAReturnSuccess );
}

/*----------------------------------- ATA PIO Protocol ------------------------------*/

/*
 *
 *
 */
void IOATAStandardDriver::doATAProtocolPio( IOATAStandardCommand *ataCmd )
{    
    ATATaskfile		taskfile;
    ATAReturnCode	rc;
    UInt32		regmask;
    UInt32		i;

    setCommandLimit( currentDevice, 1 );

    ataCmd->getTaskfile( &taskfile );

    regmask = taskfile.regmask;

    if ( regmask & ATARegtoMask(kATARegDriveHead) )
    {
        regmask &= ~ATARegtoMask(kATARegDriveHead);
        if ( selectDrive( taskfile.ataRegs[kATARegDriveHead] ) == false )
        {
            completeCmd( ataCmd, kATAReturnBusyError );
            return;
        }          
    }

    xferCount = 0;
    ataCmd->getPointers( &xferDesc, &xferRemaining, &xferIsWrite );
        
    for ( i = 0; regmask; i++ )
    {
        if ( regmask & 1 )
        {
            writeATAReg( i, taskfile.ataRegs[i] );
        }
        regmask >>= 1;
    }

    if ( xferIsWrite )
    {     
        rc = waitForDRQ( kATADRQTimeoutmS );
        if ( rc != kATAReturnSuccess )
        {
            completeCmd( ataCmd, rc );
            return;
        }   
        interruptOccurred();
    }     
}


/*
 *
 * 
 */
void IOATAStandardDriver::processATAPioInt()
{
    IOATAStandardCommand	*ataCmd;    
    UInt16			tmpBuffer[256];
    UInt32			status;
    UInt32			i;
    ATAReturnCode		rc = kATAReturnSuccess;

    ataCmd = findCommandWithNexus( currentDevice, (UInt32) -1 );
    if ( ataCmd == 0 )
    {
        IOLog( "IOATAStandardDriver::processATAPioInt() - ATA Command not found\n\r" );
        return;
    }

    if ( waitForStatus( 0, kATAStatusBSY, kATABusyTimeoutmS ) == false )
    {
        completeCmd( ataCmd, kATAReturnBusyError, xferCount );
        return;
    }

    status = readATAReg( kATARegStatus );

    if ( (status & kATAStatusDRQ) && (xferRemaining != 0) )
    {
        if ( xferIsWrite == true )
        {
            xferDesc->readBytes( xferCount, tmpBuffer, 512 );

            for ( i=0; i < 256; i++ )
            {
                writeATAReg( kATARegData, tmpBuffer[i] );
            }
        }
        else
        {
            for ( i=0; i < 256; i++ )
            {
                tmpBuffer[i] = readATAReg( kATARegData );
            }
            xferDesc->writeBytes( xferCount, tmpBuffer, 512 );
        }

        xferCount     += 512;
        xferRemaining -= 512;
    }

    if ( status & kATAStatusERR )
    {
        completeCmd( ataCmd, kATAReturnStatusError, xferCount );
    }
    else if ( !xferRemaining )
    {
        completeCmd( ataCmd, rc, xferCount );
    }
} 
/*----------------------------------- ATA Reset Protocol ------------------------------*/

/*
 *
 *
 *
 */
void IOATAStandardDriver::doATAReset( IOATAStandardCommand *ataCmd )
{

    if ( resetCmd != 0 )
    {
        completeCmd( ataCmd, kATAReturnNoResource );
        return;
    }
    
    if ( resetPollEvent == 0 )
    {    
        resetPollEvent = IOTimerEventSource::timerEventSource( this, 
                              (IOTimerEventSource::Action) &IOATAStandardDriver::checkATAResetComplete);

        if ( (resetPollEvent == 0) || (getWorkLoop()->addEventSource( resetPollEvent ) != kIOReturnSuccess) )
        {
            completeCmd( ataCmd, kATAReturnNoResource );
            return;
        }
    }

    resetCmd = ataCmd;

    clock_interval_to_deadline( resetCmd->getTimeout(), 1000000, &resetTimeout );
             
    writeATAReg( kATARegDeviceControl, kATADevControlnIEN | kATADevControlSRST );
    IODelay( 25 );
    writeATAReg( kATARegDeviceControl, 0 );

    IOSleep(5);
    
    checkATAResetComplete();
                             
    return;
}

/*
 *
 *
 *
 */
void IOATAStandardDriver::checkATAResetComplete()
{
    UInt32			status;
    IOATAStandardCommand        *ataCmd;
    AbsoluteTime                currentTime;
    ATAReturnCode               rc = kATAReturnSuccess;

    do
    {
        status = readATAReg( kATARegStatus );
    
        if ( (status & kATAStatusBSY) == 0 )
        {
            break;
        }        
     
        clock_get_uptime( &currentTime );
        if ( CMP_ABSOLUTETIME( &currentTime, &resetTimeout ) > 0  )
        {
            rc = kATAReturnBusyError;
            break;           
        }
        
        resetPollEvent->setTimeoutMS(kATAResetPollIntervalmS);
        return;
              
    } while ( 0 );
 
    ataCmd   = resetCmd;
    resetCmd = 0;    

    if ( ataCmd->getCmdType() != kATACommandBusReset )
    {
        resetOccurred();
    }

    completeCmd( ataCmd, rc );
}        
    
    
/*----------------------------------- ATAPI PIO Protocols ------------------------------*/

/*
 *
 *
 *
 */
void IOATAStandardDriver::doATAPIProtocolPio( IOATAStandardCommand *ataCmd )
{    
    ATATaskfile		taskfile;
    ATACDBInfo		atapiCmd;
    ATAReturnCode	rc;
    UInt32		regmask;
    UInt32		i;

    setCommandLimit( currentDevice, 1 );

    xferCount  = 0;

    ataCmd->getTaskfile( &taskfile );
    ataCmd->getCDB( &atapiCmd );

    regmask = taskfile.regmask;

    if ( regmask & ATARegtoMask(kATARegDriveHead) )
    {
        regmask &= ~ATARegtoMask(kATARegDriveHead);
        if ( selectDrive( taskfile.ataRegs[kATARegDriveHead] ) == false )
        {
            completeCmd( ataCmd, kATAReturnBusyError );
            return;
        }          
    }

    for ( i = 0; regmask; i++ )
    {
        if ( regmask & 1 )
        {
            writeATAReg( i, taskfile.ataRegs[i] );
        }
        regmask >>= 1;
    }

    xferCount = 0;
    ataCmd->getPointers( &xferDesc, &xferRemaining, &xferIsWrite );

    if ( ataCmd->getDevice(kIOATAStandardDevice)->getATAPIPktInt() == false )
    {         
        rc = sendATAPIPacket( ataCmd );

       if ( rc != kATAReturnSuccess )
        {
            completeCmd( ataCmd, rc );
            return;
        }
    }
}

/*
 *
 * 
 */
void IOATAStandardDriver::processATAPIPioInt()
{
    IOATAStandardCommand	*ataCmd;
    ATAReturnCode		rc = kATAReturnProtocolError;    
    UInt32			status;
    UInt32			intReason;
    UInt32			n;

    ataCmd = findCommandWithNexus( currentDevice, (UInt32) -1 );
    if ( ataCmd == 0 )
    {
        IOLog( "IOATAStandardDriver::processATAPIPioInt() - ATA Command not found\n\r" );
        return;
    }

    if ( waitForStatus( 0, kATAStatusBSY, kATABusyTimeoutmS ) == false )
    {
        completeCmd( ataCmd, kATAReturnBusyError, xferCount );
        return;
    }

    status    = readATAReg( kATARegATAPIStatus );
    intReason = readATAReg( kATARegATAPIIntReason );

    if ( status & kATAPIStatusDRQ )
    {
        if ( intReason & kATAPIIntReasonCD ) 
        {
            if ( !(intReason & kATAPIIntReasonIO) )
            {
                rc = sendATAPIPacket( ataCmd );
             }
        }
        else
        {
            n  = readATAReg( kATARegATAPIByteCountLow ) | (readATAReg( kATARegATAPIByteCountHigh ) << 8);
            n = (n+1) & ~0x01;

            if ( !(intReason & kATAPIIntReasonIO) && (xferIsWrite == true) )
            {
                rc = writeATAPIDevice( n );
            }
            else if ( (intReason & kATAPIIntReasonIO) && (xferIsWrite == false) )
            {
                rc = readATAPIDevice( n );
            }
        } 
    }
    else if ( (intReason & kATAPIIntReasonCD) && (intReason & kATAPIIntReasonIO) )    
    {  
        rc = (status & kATAPIStatusCHK) ? kATAReturnStatusError : kATAReturnSuccess; 
        completeCmd( ataCmd, rc, xferCount ); 
    }
}

/*
 *
 *
 */
ATAReturnCode IOATAStandardDriver::sendATAPIPacket( IOATAStandardCommand *ataCmd )
{
    UInt32		i;
    ATACDBInfo		atapiCmd;
    UInt16		*pCDB;
    ATAReturnCode	rc;

    ataCmd->getCDB( &atapiCmd );

    rc = waitForDRQ( kATADRQTimeoutmS );
    if ( rc != kATAReturnSuccess ) return rc;

    pCDB = (UInt16 *)atapiCmd.cdb;
    for ( i=0; i < atapiCmd.cdbLength >> 1; i++ )
    {
        writeATAReg( kATARegData, *pCDB++ );
    }

    return rc;
}    


/*
 *
 *
 */
ATAReturnCode IOATAStandardDriver::readATAPIDevice( UInt32 n )
{
    UInt16      tmpBuffer[256];
    UInt32	i,j,k;

    while ( n )
    {
        j = (n < 512) ? n : 512;

        j >>= 1;
        for ( i=0; i < j; i++ )
        {
            tmpBuffer[i] = readATAReg( kATARegData );
        }
        j <<= 1;
        n  -= j;

        k = (j > xferRemaining ) ? xferRemaining : j;
      
        xferDesc->writeBytes( xferCount, tmpBuffer, k );
        
        xferCount     += k;
        xferRemaining -= k;
    }

    return kATAReturnSuccess;
}    

/*
 *
 *
 */
ATAReturnCode IOATAStandardDriver::writeATAPIDevice( UInt32 n )
{
    UInt16      tmpBuffer[256];
    UInt32	i,j,k;


    while ( n )
    {
        j = (n < 512) ? n : 512;

        k = (j > xferRemaining ) ? xferRemaining : j;

        xferDesc->readBytes( xferCount, tmpBuffer, k );

        j >>= 1;
        for ( i=0; i < j; i++ )
        {
            writeATAReg( kATARegData, tmpBuffer[i] );
        }            
        j <<= 1;
        n  -= j;

        xferCount     += k;
        xferRemaining -= k;
    }

    return kATAReturnSuccess;
}               


/*
 *
 *
 */
bool IOATAStandardDriver::selectDrive( UInt32 driveHeadReg )
{
    if ( waitForAltStatus( 0, kATAStatusBSY, kATABusyTimeoutmS ) == false )
    {
        return false;
    }
         
    writeATAReg( kATARegDriveHead, driveHeadReg );

    if ( waitForAltStatus( 0, kATAStatusBSY, kATABusyTimeoutmS ) == false )
    {
        return false;
    }

    return true;     
}
