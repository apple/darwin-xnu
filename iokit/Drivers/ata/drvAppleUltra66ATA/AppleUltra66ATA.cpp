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
 *    AppleUltra66ATA.cpp
 *
 */
#include "AppleUltra66ATA.h"

#undef super
#define super IOATAStandardDriver

extern pmap_t 	kernel_pmap;

OSDefineMetaClassAndStructors( AppleUltra66ATA, IOATAStandardDriver )

static inline int rnddiv( int x, int y )
{
    if ( x < 0 )
      return 0;
    else
      return ( (x / y) + (( x % y ) ? 1 : 0) );
}


/*
 *
 *
 */
bool AppleUltra66ATA::configure( IOService *forProvider, ATAControllerInfo *controllerInfo )
{
    provider = forProvider;

    if ( identifyController() == false )
    {
        return false;
    }

    ioMapATA = provider->mapDeviceMemoryWithIndex(0);
    if ( ioMapATA == NULL ) return false;
    ioBaseATA = (volatile UInt32 *)ioMapATA->getVirtualAddress();

    ioMapDMA = provider->mapDeviceMemoryWithIndex(1);
    if ( ioMapDMA == NULL ) return false;
    ioBaseDMA = (volatile IODBDMAChannelRegisters *)ioMapDMA->getVirtualAddress();

    dmaDescriptors = (IODBDMADescriptor *)kalloc(page_size);
    if ( dmaDescriptors == 0 )
    {
        return false;
    }
    
    dmaDescriptorsPhys = (UInt32) pmap_extract(kernel_pmap, (vm_offset_t) dmaDescriptors);

    if ( (UInt32)dmaDescriptors & (page_size - 1) )
    {
        IOLog("AppleUltra66ATA::%s() - DMA Descriptor memory not page aligned!!", __FUNCTION__);
        return false;
    }
  
    bzero( dmaDescriptors, page_size );

    numDescriptors = page_size/sizeof(IODBDMADescriptor);

    dmaMemoryCursor = IOBigMemoryCursor::withSpecification( 64*1024-2, 0xffffffff );
    if ( dmaMemoryCursor == NULL )
    {
        return false;
    } 

    bitBucketAddr = IOMalloc(32);
    if ( bitBucketAddr == 0 )
    {
        return false;
    }
    bitBucketAddrPhys = (UInt32) pmap_extract(kernel_pmap, (vm_offset_t) (((UInt32)bitBucketAddr + 0xf) & ~0x0f));

    interruptEventSource = IOInterruptEventSource::interruptEventSource( (OSObject *)             this,
                                                                         (IOInterruptEventAction) &AppleUltra66ATA::interruptOccurred,
									 (IOService *)            provider,
									 (int)                    0 );

    if ( interruptEventSource == NULL )
    {
        return false;
    }

    disableControllerInterrupts();

    getWorkLoop()->addEventSource( interruptEventSource ); 

    controllerInfo->maxDevicesSupported 	= 2;
    controllerInfo->devicePrivateDataSize	= 0;
    controllerInfo->commandPrivateDataSize	= 0;
    controllerInfo->disableCancelCommands	= false;

    return true;
}


/*
 *
 *
 */
bool AppleUltra66ATA::identifyController()
{
    OSData		*compatibleEntry, *modelEntry;

    do    
    {
        controllerType = kControllerTypeDBDMAVersion1;

        compatibleEntry  = OSDynamicCast( OSData, provider->getProperty( "compatible" ) );
        if ( compatibleEntry == 0 ) break;

        if ( compatibleEntry->isEqualTo( "keylargo-ata", sizeof("keylargo-ata")-1 ) == true ) 
        {
            controllerType = kControllerTypeDBDMAVersion2;

            modelEntry = OSDynamicCast( OSData, provider->getProperty("model") );  
            if ( modelEntry == 0 ) break;
      
            if ( modelEntry->isEqualTo( "ata-4", sizeof("ata-4")-1 ) == true ) 
            {
                controllerType = kControllerTypeUltra66DBDMA;
            }
        }    
    } while ( 0 );

    return true;
}    


/*
 *
 *
 */
bool AppleUltra66ATA::calculateTiming( UInt32 deviceNum, ATATiming *pTiming )
{
    bool		rc = false;

    switch ( controllerType )
    {
        case kControllerTypeDBDMAVersion1:
        case kControllerTypeDBDMAVersion2:
            switch ( pTiming->timingProtocol )
            {
                case kATATimingPIO:
                    rc = calculatePIOTiming( deviceNum, pTiming );
                    break;

                case kATATimingDMA:
                    rc = calculateDMATiming( deviceNum, pTiming );
                    break;
 
                default:
                    ;
            }
            break;

        case kControllerTypeUltra66DBDMA:
            switch ( pTiming->timingProtocol )
            {
                case kATATimingPIO:
                    rc = calculateUltra66PIOTiming( deviceNum, pTiming );
                    break;

                case kATATimingDMA:
                    rc = calculateUltra66DMATiming( deviceNum, pTiming );
                    break;
 
                case kATATimingUltraDMA66:
                    rc = calculateUltra66UDMATiming( deviceNum, pTiming );
                    break;

                default:
                    ;
            }
            break;

        default:
            ;
    }

    return rc;
}


/*
 *
 *
 */
bool AppleUltra66ATA::calculatePIOTiming( UInt32 unitNum, ATATiming *pTiming )
{
    int			accessTime;
    int			accessTicks;
    int         	recTime;
    int			recTicks;
    int        		cycleTime;

    /*
     * Calc PIO access time >= minDataAccess in SYSCLK increments
     */
    accessTicks = rnddiv(pTiming->minDataAccess, kATASysClkNS);
    /*
     * Hardware limits access times to >= 120 ns 
     */
    accessTicks -= kATAPioAccessBase;
    if (accessTicks < kATAPioAccessMin )
    {
        accessTicks = kATAPioAccessMin;
    }
    accessTime = (accessTicks + kATAPioAccessBase) * kATASysClkNS;

    /*
     * Calc recovery time in SYSCLK increments based on time remaining in cycle
     */
    recTime = pTiming->minDataCycle - accessTime;
    recTicks = rnddiv( recTime, kATASysClkNS );
    /*
     * Hardware limits recovery time to >= 150ns 
     */
    recTicks -= kATAPioRecoveryBase;
    if ( recTicks < kATAPioRecoveryMin )
    {
      recTicks = kATAPioRecoveryMin;
    }

    cycleTime = (recTicks + kATAPioRecoveryBase + accessTicks + kATAPioAccessBase) * kATASysClkNS;

    ideTimingWord[unitNum] &= ~0x7ff;
    ideTimingWord[unitNum] |= accessTicks | (recTicks << 5);

#if 0
    IOLog("AppleUltra66ATA::%s() Unit %1d PIO Requested Timings: Access: %3dns Cycle: %3dns \n\r", 
             __FUNCTION__, (int)unitNum, (int)pTiming->minDataAccess, (int)pTiming->minDataCycle);
    IOLog("AppleUltra66ATA::%s()        PIO Actual    Timings: Access: %3dns Cycle: %3dns\n\r",
             __FUNCTION__, accessTime, cycleTime );
#endif

    return true;
}


/*
 *
 *
 */
bool AppleUltra66ATA::calculateDMATiming( UInt32 unitNum, ATATiming *pTiming )
{
    int			accessTime;
    int			accessTicks;
    int         	recTime;
    int			recTicks;
    int        		cycleTime;
    int                 cycleTimeOrig;
    int         	halfTick = 0;

    /*
     * Calc DMA access time >= minDataAccess in SYSCLK increments
     */

    /*
     * OHare II erata - Cant handle write cycle times below 150ns
     */
    cycleTimeOrig = pTiming->minDataCycle;
#if 0
    if ( IsPowerStar() )
    {
        if ( cycleTimeOrig < 150 ) pTiming->minDataCycle = 150;
    }
#endif

    accessTicks = rnddiv(pTiming->minDataAccess, kATASysClkNS);

    accessTicks -= kATADmaAccessBase;
    if ( accessTicks < kATADmaAccessMin )
    {
        accessTicks = kATADmaAccessMin;
    }
    accessTime = (accessTicks + kATADmaAccessBase) * kATASysClkNS;

    /*
     * Calc recovery time in SYSCLK increments based on time remaining in cycle
     */
    recTime = pTiming->minDataCycle - accessTime;    
    recTicks = rnddiv( recTime, kATASysClkNS );

    recTicks -= kATADmaRecoveryBase;
    if ( recTicks < kATADmaRecoveryMin )
    {
        recTicks = kATADmaRecoveryMin;
    }
    cycleTime = (recTicks + kATADmaRecoveryBase + accessTicks + kATADmaAccessBase) * kATASysClkNS;
 
    /*
     * If our calculated access time is at least SYSCLK/2 > than what the disk requires, 
     * see if selecting the 1/2 Clock option will help. This adds SYSCLK/2 to 
     * the access time and subtracts SYSCLK/2 from the recovery time.
     * 
     * By setting the H-bit and subtracting one from the current access tick count,
     * we are reducing the current access time by SYSCLK/2 and the current recovery
     * time by SYSCLK/2. Now, check if the new cycle time still meets the disk's requirements.
     */  
    if ( controllerType == kControllerTypeDBDMAVersion1 )
    {
        if ( (accessTicks > kATADmaAccessMin) &&  ((UInt32)(accessTime - kATASysClkNS/2) >= pTiming->minDataAccess) )
        {
            if ( (UInt32)(cycleTime - kATASysClkNS) >= pTiming->minDataCycle )
            {
                halfTick    = 1;
                accessTicks--;
                accessTime -= kATASysClkNS/2;
                cycleTime  -= kATASysClkNS;
            }
        }
    }

    ideTimingWord[unitNum] &= ~0xffff800;
    ideTimingWord[unitNum] |= (accessTicks | (recTicks << 5) | (halfTick << 10)) << 11;

#if 0
    IOLog("AppleUltra66ATA::%s() Unit %1d DMA Requested Timings: Access: %3dns Cycle: %3dns \n\r",  
             __FUNCTION__, (int)unitNum, (int)pTiming->minDataAccess, (int)cycleTimeOrig);
    IOLog("AppleUltra66ATA::%s()        DMA Actual    Timings: Access: %3dns Cycle: %3dns\n\r",   
             __FUNCTION__, accessTime, cycleTime );
    IOLog("AppleUltra66ATA::%s() Ide DMA Timings = %08lx\n\r", __FUNCTION__, ideTimingWord[unitNum] );
#endif

    return true;
}


/*
 *
 *
 */
bool AppleUltra66ATA::calculateUltra66PIOTiming( UInt32 unitNum, ATATiming *pTiming )
{
    int			accessTime;
    int			accessTicks;
    int         	recTime;
    int			recTicks;
    int        		cycleTime;

    /*
     * Calc PIO access time >= pioAccessTime in SYSCLK increments
     */
    accessTicks = rnddiv(pTiming->minDataAccess * 1000, kATAUltra66ClockPS );
    accessTime = accessTicks * kATAUltra66ClockPS;

    /*
     * Calc recovery time in SYSCLK increments based on time remaining in cycle
     */
    recTime = pTiming->minDataCycle * 1000 - accessTime;
    recTicks = rnddiv( recTime, kATAUltra66ClockPS );

    cycleTime = (recTicks + accessTicks ) * kATAUltra66ClockPS;

    ideTimingWord[unitNum] &= ~0xe00003ff;
    ideTimingWord[unitNum] |= accessTicks | (recTicks << 5);

#if 0
    IOLog("AppleUltra66ATA::%s()  Unit %1d PIO Requested Timings: Access: %3dns Cycle: %3dns \n\r",  
             __FUNCTION__, (int)unitNum, (int)pTiming->minDataAccess, (int)pTiming->minDataCycle);
    IOLog("AppleUltra66ATA::%s()         PIO Actual    Timings: Access: %3dns Cycle: %3dns\n\r",   
             __FUNCTION__, accessTime / 1000, cycleTime / 1000 );
    IOLog("AppleUltra66ATA::%s()  Ide PIO Timings = %08lx\n\r", __FUNCTION__, ideTimingWord[unitNum] );
#endif

    return true;
}


/*
 *
 *
 */
bool AppleUltra66ATA::calculateUltra66DMATiming( UInt32 unitNum, ATATiming *pTiming )
{
    int			accessTime;
    int			accessTicks;
    int         	recTime;
    int			recTicks;
    int        		cycleTime;

    /*
     * Calc DMA access time >= dmaAccessTime in SYSCLK increments
     */
    accessTicks = rnddiv(pTiming->minDataAccess * 1000, kATAUltra66ClockPS);
    accessTime = accessTicks * kATAUltra66ClockPS;

    /*
     * Calc recovery time in SYSCLK increments based on time remaining in cycle
     */
    recTime = pTiming->minDataCycle * 1000 - accessTime;    
    recTicks = rnddiv( recTime, kATAUltra66ClockPS );

    cycleTime = (recTicks + accessTicks) * kATAUltra66ClockPS;

    ideTimingWord[unitNum] &= ~0x001ffc00;
    ideTimingWord[unitNum] |= (accessTicks | (recTicks << 5)) << 10;

#if 0
    IOLog("AppleUltra66ATA::%s()  Unit %1d DMA Requested Timings: Access: %3dns Cycle: %3dns \n\r",  
             __FUNCTION__, (int)unitNum, (int)pTiming->minDataAccess, (int)pTiming->minDataCycle);
    IOLog("AppleUltra66ATA::%s()         DMA Actual    Timings: Access: %3dns Cycle: %3dns\n\r",   
             __FUNCTION__, accessTime / 1000, cycleTime / 1000 );
    IOLog("AppleUltra66ATA::%s()  Ide DMA Timings = %08lx\n\r", __FUNCTION__, ideTimingWord[unitNum] );
#endif

    return true;
}


/*
 *
 *
 */
bool AppleUltra66ATA::calculateUltra66UDMATiming( UInt32 unitNum, ATATiming *pTiming )
{
    int			rdyToPauseTicks;
    int			rdyToPauseTime;
    int        		cycleTime;
    int        		cycleTicks;

    /*
     * Ready to Pause delay in PCI_66_CLOCK / 2 increments
     */
    rdyToPauseTicks = rnddiv(pTiming->minDataAccess * 1000, kATAUltra66ClockPS);
    rdyToPauseTime  = rdyToPauseTicks * kATAUltra66ClockPS;

    /*
     * Calculate cycle time in PCI_66_CLOCK / 2 increments
     */
    cycleTicks = rnddiv(pTiming->minDataCycle * 1000, kATAUltra66ClockPS);
    cycleTime  = cycleTicks * kATAUltra66ClockPS;

    ideTimingWord[unitNum] &= ~0x1ff00000;
    ideTimingWord[unitNum] |= ((rdyToPauseTicks << 5) | (cycleTicks << 1) | 1) << 20;

#if 0
    IOLog("AppleUltra66ATA::%s() Unit %1d UDMA66 Requested Timings: ReadyToPause: %3dns Cycle: %3dns \n\r",  
             __FUNCTION__, (int)unitNum, (int)pTiming->minDataAccess, (int)pTiming->minDataCycle);
    IOLog("AppleUltra66ATA::%s()        UDMA66 Actual    Timings: ReadyToPause: %3dns Cycle: %3dns\n\r",   
             __FUNCTION__, rdyToPauseTime / 1000, cycleTime / 1000 );
    IOLog("AppleUltra66ATA::%s() Ide DMA Timings = %08lx\n\r", __FUNCTION__, ideTimingWord[unitNum] );
#endif

    return true;
}


/*
 *
 *
 */
void AppleUltra66ATA::newDeviceSelected( IOATAStandardDevice *newDevice )
{    
    OSWriteSwapInt32( ioBaseATA, 0x200, ideTimingWord[newDevice->getUnit()] );
    eieio();
}


/*
 *
 *
 */
bool AppleUltra66ATA::selectTiming( UInt32 unitNum, ATATimingProtocol timingProtocol )
{
    if ( controllerType == kControllerTypeUltra66DBDMA )
    {
        switch ( timingProtocol )
        {
             case kATATimingUltraDMA66:
                 ideTimingWord[unitNum] |=  0x00100000;
                 break;
             case kATATimingDMA:   
                 ideTimingWord[unitNum] &= ~0x00100000;
                 break;
             default:
                  ;
        }        
    }
    return true;
}

/*
 *
 *
 */
bool AppleUltra66ATA::programDma( IOATAStandardCommand *cmd )
{
    IOMemoryDescriptor			*memoryDesc;
    IODBDMADescriptor			*dmaDesc;
    UInt32				dmaCmd;
    bool				isWrite;
    IOPhysicalSegment			physSeg;
    IOByteCount				offset;
    UInt32				i;

    IODBDMAReset( ioBaseDMA );

    cmd->getPointers( &memoryDesc, &dmaReqLength, &isWrite );

    if ( dmaReqLength == 0 )
    {
        return true;
    }

    offset = 0;

    dmaCmd  = (isWrite == true) ? kdbdmaOutputMore : kdbdmaInputMore;
    dmaDesc = dmaDescriptors;

   for ( i = 0; i < numDescriptors; i++, dmaDesc++ )
    {
        if ( dmaMemoryCursor->getPhysicalSegments( memoryDesc, offset, &physSeg, 1 ) != 1 )
        {
            break;
        }

        IOMakeDBDMADescriptor( dmaDesc,
                               dmaCmd,
			       kdbdmaKeyStream0,
			       kdbdmaIntNever,
			       kdbdmaBranchNever,
			       kdbdmaWaitNever,
                               physSeg.length,
                               physSeg.location );
	offset += physSeg.length;
    }

    if ( i == numDescriptors )
    {
        return false;
    }

    /*
     * Note: ATAPI always transfers even byte-counts. Send the extra byte to/from the bit-bucket
     *       if the requested transfer length is odd.
     */
    if ( dmaReqLength & 1 )
    {
        i++;
        IOMakeDBDMADescriptor( dmaDesc++,
	    		       dmaCmd,
	  		       kdbdmaKeyStream0,
			       kdbdmaIntNever,
			       kdbdmaBranchNever,
			       kdbdmaWaitNever,
			       1,
			       bitBucketAddrPhys );
    }


    if ( i == numDescriptors )
    {
        return false;
    }


    IOMakeDBDMADescriptor( dmaDesc,
                           kdbdmaStop,
                           kdbdmaKeyStream0,
			   kdbdmaIntNever,
			   kdbdmaBranchNever,
			   kdbdmaWaitNever,
                           0,
                           0 );

    IOSetDBDMACommandPtr( ioBaseDMA, dmaDescriptorsPhys );


    return true;
}                      

 
/*
 *
 *
 */
bool AppleUltra66ATA::startDma( IOATAStandardCommand * )
{
    if ( dmaReqLength != 0 )
    {
        IODBDMAContinue( ioBaseDMA );
    }
    return true;
}


/*
 *
 *
 */
bool AppleUltra66ATA::stopDma( IOATAStandardCommand *, UInt32 *transferCount )
{
    UInt32			i;
    UInt32 	       		ccResult;
    UInt32 		       	byteCount = 0;

    *transferCount = 0;

    if ( dmaReqLength == 0 )
    {
        return true;
    }

    IODBDMAStop( ioBaseDMA );

    for ( i=0; i < numDescriptors; i++ )
    {
        ccResult = IOGetCCResult( &dmaDescriptors[i] );
    
        if ( (ccResult & (kdbdmaStatusActive | kdbdmaStatusDead)) == 0 )
        {
            break;
        } 
        byteCount += (IOGetCCOperation( &dmaDescriptors[i] ) & kdbdmaReqCountMask) - (ccResult & kdbdmaResCountMask); 
    }

    *transferCount = byteCount;

    return true;
}

/*
 *
 *
 */
bool AppleUltra66ATA::resetDma()
{
    IODBDMAReset( ioBaseDMA );
    return true;
}

/*
 *
 *
 */
bool AppleUltra66ATA::checkDmaActive()
{
    return ((IOGetDBDMAChannelStatus( ioBaseDMA ) & kdbdmaActive) != 0);
}
 

/*
 *
 *
 */
void AppleUltra66ATA::disableControllerInterrupts()
{
    interruptEventSource->disable();
}

/*
 *
 *
 */
void AppleUltra66ATA::enableControllerInterrupts()
{
    interruptEventSource->enable();
}

/*
 *
 *
 */
void AppleUltra66ATA::free()
{
    if ( interruptEventSource != 0 )
    {
        interruptEventSource->disable();
        interruptEventSource->release();
    }
  
    if ( ioMapATA != 0 )
    {
        ioMapATA->release();
    }
 
    if ( ioMapDMA != 0 )
    {
        ioMapDMA->release();
    }

    if ( bitBucketAddr != 0 )
    {
        IOFree( bitBucketAddr, 32 );
    }

    if ( dmaDescriptors != 0 )
    {
        kfree( (vm_offset_t)dmaDescriptors, page_size );
    } 
}

/*
 *
 *
 */
void AppleUltra66ATA::writeATAReg( UInt32 regIndex, UInt32 regValue )
{
    regIndex += (regIndex >= kATARegDeviceControl ) ? (kATACS3RegBase - kATARegDeviceControl + 6) : 0;

    if ( regIndex )
    {
        *((volatile UInt8 *)ioBaseATA + (regIndex<<4)) = regValue;
    }
    else
    {
        *(volatile UInt16 *)ioBaseATA = regValue;
    }     
    eieio();
}

UInt32 AppleUltra66ATA::readATAReg( UInt32 regIndex )
{
    regIndex += (regIndex >= kATARegAltStatus ) ? (kATACS3RegBase - kATARegAltStatus + 6) : 0;

    if ( regIndex )
    { 
        return *((volatile UInt8 *)ioBaseATA + (regIndex<<4));
    }
    else
    {
        return *(volatile UInt16 *)ioBaseATA;
    }
}
