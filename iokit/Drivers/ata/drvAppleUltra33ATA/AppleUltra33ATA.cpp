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
 *    AppleUltra33ATA.cpp
 *
 */
#include "AppleUltra33ATA.h"

#include <IOKit/IODeviceTreeSupport.h>

#undef super
#define super IOATAStandardDriver

extern pmap_t 	kernel_pmap;

OSDefineMetaClassAndStructors( AppleUltra33ATA, IOATAStandardDriver )


static struct
{
    UInt32	minDataAccess;
    UInt32	minDataCycle;
} pioModes[] =
{
    { 165,    600 },	/* Mode 0 */
    { 125,    383 },	/*      1 */ 
    { 100,    240 },	/*      2 */
    {  80,    180 },	/*      3 */
    {  70,    120 }	/*      4 */
};


/*
 *
 *
 */
bool AppleUltra33ATA::configure( IOService *forProvider, ATAControllerInfo *controllerInfo )
{

    provider = (IOPCIDevice *)forProvider;

    busNum = 0;

    ioMapATA[0] = provider->mapDeviceMemoryWithRegister( 0x10 + busNum * 8 + 0 );
    if ( ioMapATA[0] == NULL ) return false;
    ioBaseATA[0] = (volatile UInt32 *)ioMapATA[0]->getVirtualAddress();

    ioMapATA[1] = provider->mapDeviceMemoryWithRegister( 0x10 + busNum * 8 + 4 );
    if ( ioMapATA[1] == NULL ) return false;
    ioBaseATA[1] = (volatile UInt32 *)ioMapATA[1]->getVirtualAddress();

    pciWriteLong( 0x04, 0x05 );

    dmaDescriptors = (Ultra646Descriptor *)kalloc(page_size);
    if ( dmaDescriptors == 0 )
    {
        return false;
    }
    
    dmaDescriptorsPhys = (UInt32) pmap_extract(kernel_pmap, (vm_offset_t) dmaDescriptors);

    if ( (UInt32)dmaDescriptors & (page_size - 1) )
    {
        IOLog("AppleUltra33ATA::%s() - DMA Descriptor memory not page aligned!!", __FUNCTION__);
        return false;
    }
  
    bzero( dmaDescriptors, page_size );

    numDescriptors = page_size/sizeof(Ultra646Descriptor);

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
                                                                         (IOInterruptEventAction) &AppleUltra33ATA::interruptOccurred,
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
bool AppleUltra33ATA::calculateTiming( UInt32 unit, ATATiming *pTiming )
{
    bool		rc = false;

    ideTimingRegs[unit].arttimReg  = 0x40;
    ideTimingRegs[unit].cmdtimReg  = 0xA9;

    switch ( pTiming->timingProtocol )
    {
        case kATATimingPIO:
            rc = calculatePIOTiming( unit, pTiming );
            break;

        case kATATimingDMA:
            rc = calculateDMATiming( unit, pTiming );
            break;
 
        case kATATimingUltraDMA33:
            rc = calculateUltraDMATiming( unit, pTiming );
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
bool AppleUltra33ATA::calculatePIOTiming( UInt32 unit, ATATiming *pTiming )
{
    UInt32		accessTime;
    UInt32		drwActClks, drwRecClks;
    UInt32		drwActTime, drwRecTime;
   
    accessTime = pioModes[pTiming->mode].minDataAccess;

    drwActClks    =  accessTime / IDE_SYSCLK_NS;
    drwActClks   += (accessTime % IDE_SYSCLK_NS) ? 1 : 0;
    drwActTime    = drwActClks * IDE_SYSCLK_NS;

    drwRecTime    = pioModes[pTiming->mode].minDataCycle - drwActTime;
    drwRecClks    = drwRecTime / IDE_SYSCLK_NS;
    drwRecClks   += (drwRecTime % IDE_SYSCLK_NS) ? 1 : 0;

    if ( drwRecClks >= 16 ) 
        drwRecClks = 1;
    else if ( drwRecClks <= 1 )
        drwRecClks = 16;

    ideTimingRegs[unit].drwtimRegPIO = ((drwActClks & 0x0f) << 4) | ((drwRecClks-1)  & 0x0f);
 
    return true;
}


/*
 *
 *
 */
bool  AppleUltra33ATA::calculateDMATiming( UInt32 unit, ATATiming *pTiming )
{   
    UInt32		accessTime;
    UInt32		drwActClks, drwRecClks;
    UInt32		drwActTime, drwRecTime;

    ideTimingRegs[unit].udidetcrReg = 0;      

    accessTime    = pTiming->minDataAccess;

    drwActClks    =  accessTime / IDE_SYSCLK_NS;
    drwActClks   += (accessTime % IDE_SYSCLK_NS) ? 1 : 0;
    drwActTime    = drwActClks * IDE_SYSCLK_NS;

    drwRecTime    = pTiming->minDataCycle - drwActTime;
    drwRecClks    = drwRecTime / IDE_SYSCLK_NS;
    drwRecClks   += (drwRecTime % IDE_SYSCLK_NS) ? 1 : 0;

    if ( drwRecClks >= 16 ) 
        drwRecClks = 1;
    else if ( drwRecClks <= 1 )
        drwRecClks = 16;

    ideTimingRegs[unit].drwtimRegDMA = ((drwActClks & 0x0f) << 4) | ((drwRecClks-1)  & 0x0f);    

    return true;    
}

/*
 *
 *
 */
bool  AppleUltra33ATA::calculateUltraDMATiming( UInt32 unit, ATATiming *pTiming )
{
    UInt32		cycleClks;
    UInt32		cycleTime;

    cycleTime = pTiming->minDataCycle;
        
    cycleClks  = cycleTime / IDE_SYSCLK_NS;
    cycleClks += (cycleTime % IDE_SYSCLK_NS) ? 1 : 0;

    ideTimingRegs[unit].udidetcrReg = (0x01 << unit) | ((cycleClks-1) << ((!unit) ? 4 : 6)) ;
   
    return true;  
}

/*
 *
 *
 */
void AppleUltra33ATA::newDeviceSelected( IOATADevice *newDevice )
{    
}


/*
 *
 *
 */
bool AppleUltra33ATA::selectTiming( UInt32 unit, ATATimingProtocol timingProtocol )
{
    Ultra646Regs	       	*cfgRegs;
    UInt32			cfgByte;

    cfgRegs = &ideTimingRegs[unit];

    if ( busNum == 0 )
    {
        pciWriteByte( kUltra646CMDTIM, cfgRegs->cmdtimReg );             

        if ( unit == 0 )
        { 
            pciWriteByte( kUltra646ARTTIM0, cfgRegs->arttimReg );

            if ( timingProtocol == kATATimingPIO )
            {
                cfgByte = pciReadByte( kUltra646CNTRL );
                cfgByte &= ~kUltra646CNTRL_Drive0ReadAhead;
                cfgByte |= cfgRegs->cntrlReg;
                pciWriteByte( kUltra646CNTRL, cfgByte );

                pciWriteByte( kUltra646DRWTIM0, cfgRegs->drwtimRegPIO );             
            }
            else if ( timingProtocol == kATATimingDMA )
            {
                pciWriteByte( kUltra646DRWTIM0, cfgRegs->drwtimRegDMA );             
            }
            else if ( timingProtocol == kATATimingUltraDMA33 )
            {
                cfgByte = pciReadByte( kUltra646UDIDETCR0 );
                cfgByte &= ~(kUltra646UDIDETCR0_Drive0UDMACycleTime | kUltra646UDIDETCR0_Drive0UDMAEnable);
                cfgByte |= cfgRegs->udidetcrReg;
                pciWriteByte( kUltra646UDIDETCR0, cfgByte );
            }
        }        
        else
        {
            pciWriteByte( kUltra646ARTTIM1, cfgRegs->arttimReg );

            if ( timingProtocol == kATATimingPIO )
            {
                cfgByte = pciReadByte( kUltra646CNTRL );
                cfgByte &= ~kUltra646CNTRL_Drive1ReadAhead;
                cfgByte |= cfgRegs->cntrlReg;
                pciWriteByte( kUltra646CNTRL, cfgByte );

                pciWriteByte( kUltra646DRWTIM1, cfgRegs->drwtimRegPIO );
            }
            else if ( timingProtocol == kATATimingDMA )
            {
                pciWriteByte( kUltra646DRWTIM1, cfgRegs->drwtimRegDMA );
            }
            else if ( timingProtocol == kATATimingUltraDMA33 )
            {
                cfgByte = pciReadByte( kUltra646UDIDETCR0 );
                cfgByte &= ~(kUltra646UDIDETCR0_Drive1UDMACycleTime | kUltra646UDIDETCR0_Drive1UDMAEnable);
                cfgByte |= cfgRegs->udidetcrReg;
                pciWriteByte(  kUltra646UDIDETCR0, cfgByte );
            }
       }
    }
    else
    {
        pciWriteByte( kUltra646CMDTIM, cfgRegs->cmdtimReg );

        if ( unit == 0 )
        {
            cfgByte = pciReadByte( kUltra646ARTTIM23 ); 
            cfgByte &= ~(kUltra646ARTTIM23_Drive2ReadAhead | kUltra646ARTTIM23_AddrSetup);
            cfgByte |= (cfgRegs->cntrlReg >> 4) | cfgRegs->arttimReg;
            pciWriteByte( kUltra646ARTTIM23, cfgByte );

            if ( timingProtocol == kATATimingPIO )
            {
                pciWriteByte( kUltra646DRWTIM2, cfgRegs->drwtimRegPIO );
            }
            else if ( timingProtocol == kATATimingDMA )
            {
                pciWriteByte( kUltra646DRWTIM1, cfgRegs->drwtimRegDMA );
            }
            else if ( timingProtocol == kATATimingUltraDMA33 )
            {
                cfgByte = pciReadByte( kUltra646UDIDETCR1 );    
                cfgByte &= ~(kUltra646UDIDETCR1_Drive2UDMACycleTime | kUltra646UDIDETCR1_Drive2UDMAEnable);
                cfgByte |= cfgRegs->udidetcrReg;
                pciWriteByte(  kUltra646UDIDETCR1, cfgByte );
            }
        }        
        else
        {
            cfgByte = pciReadByte( kUltra646ARTTIM23 );
            cfgByte &= ~(kUltra646ARTTIM23_Drive3ReadAhead | kUltra646ARTTIM23_AddrSetup);
            cfgByte |= (cfgRegs->cntrlReg >> 4) | cfgRegs->arttimReg;
            pciWriteByte( kUltra646ARTTIM23, cfgByte ); 

            if ( timingProtocol == kATATimingPIO )
            {
                pciWriteByte( kUltra646DRWTIM3, cfgRegs->drwtimRegPIO );
            }
            else if ( timingProtocol == kATATimingDMA )
            {
                pciWriteByte( kUltra646DRWTIM3, cfgRegs->drwtimRegDMA );
            }
            else if ( timingProtocol == kATATimingUltraDMA33 )
            {
                cfgByte = pciReadByte( kUltra646UDIDETCR1 );
                cfgByte &= ~(kUltra646UDIDETCR1_Drive3UDMACycleTime | kUltra646UDIDETCR1_Drive3UDMAEnable);
                cfgByte |= cfgRegs->udidetcrReg;
                pciWriteByte( kUltra646UDIDETCR1, cfgByte );
            }
        }
    }

    return true;
}


/*
 *
 *
 */
void AppleUltra33ATA::interruptOccurred()
{
    UInt32			intReg;
    UInt32			cfgReg;    

    intReg = (busNum == 0) ? kUltra646CFR : kUltra646ARTTIM23;
    cfgReg = pciReadByte( intReg );
    pciWriteByte( intReg, cfgReg );

    intReg = (busNum == 0) ? kUltra646BMIDESR0 : kUltra646BMIDESR1;
    cfgReg = pciReadByte( intReg );
    pciWriteByte( intReg, cfgReg );
    
    super::interruptOccurred();

    enableControllerInterrupts();
}

/*
 *
 *
 */
bool AppleUltra33ATA::programDma( IOATAStandardCommand *cmd )
{
    IOMemoryDescriptor			*memoryDesc;
    IOPhysicalSegment			physSeg;
    IOByteCount				offset;
    UInt32				i;
    UInt32				bytesLeft;
    UInt32				len;
    Ultra646Descriptor			*dmaDesc;
    UInt32                              startSeg, endSeg;

    cmd->getPointers( &memoryDesc, &dmaReqLength, &dmaIsWrite );

    if ( dmaReqLength == 0 )
    {
        return true;
    }

    offset = 0;

    dmaDesc = dmaDescriptors;

    bytesLeft = dmaReqLength;

    for (i = 0; i < numDescriptors-1; i++, dmaDesc++ )
    {
        if ( dmaMemoryCursor->getPhysicalSegments( memoryDesc, offset, &physSeg, 1 ) != 1 )
        {
            break;
        }
        
        startSeg = (physSeg.location & ~0xffff);
        endSeg   = (physSeg.location + physSeg.length - 1) & ~0xffff;

        OSWriteSwapInt32( &dmaDesc->start, 0, physSeg.location);

        if ( startSeg == endSeg )
        {
            OSWriteSwapInt32( &dmaDesc->length, 0, physSeg.length );
        }
        else
        {
            len = (-physSeg.location & 0xffff);
            OSWriteSwapInt32( &dmaDesc->length, 0, len );
            dmaDesc++;
            i++;
            OSWriteSwapInt32( &dmaDesc->start,  0, physSeg.location + len );
            OSWriteSwapInt32( &dmaDesc->length, 0, physSeg.length   - len ); 
        }

        bytesLeft -= physSeg.length;
        offset += physSeg.length;
    }

    if ( bytesLeft != 0 )
    {
        return false;
    }

    /*
     * Note: ATAPI always transfers even byte-counts. Send the extra byte to/from the bit-bucket
     *       if the requested transfer length is odd.
     */
    if ( dmaReqLength & 1 )
    {
        if ( i == numDescriptors ) return false;

        dmaDesc++;
        OSWriteSwapInt32( &dmaDesc->start,  0, bitBucketAddrPhys );
        OSWriteSwapInt32( &dmaDesc->length, 0, 1 );
    }


    dmaDesc--;
    dmaDesc->length |= 0x80;

    pciWriteLong( ((busNum == 0) ? kUltra646DTPR0 : kUltra646DTPR1), dmaDescriptorsPhys );

    return true;
}                      

/*
 *
 *
 */
bool AppleUltra33ATA::startDma( IOATAStandardCommand * )
{
    UInt32		  reg;
    UInt32                cfgReg;
    UInt32		  startMask;
    UInt32		  writeMask;

    if ( dmaReqLength != 0 )
    {
        reg       = (busNum == 0) ? kUltra646BMIDECR0 : kUltra646BMIDECR1;
        startMask = (busNum == 0) ? kUltra646BMIDECR0_StartDMAPRI : kUltra646BMIDECR1_StartDMASDY;
        writeMask = (busNum == 0) ? kUltra646BMIDECR0_PCIWritePRI : kUltra646BMIDECR1_PCIWriteSDY; 
        cfgReg = pciReadByte( reg );
        cfgReg &= ~writeMask;
        cfgReg |= startMask | ((dmaIsWrite == false) ? writeMask : 0);
        pciWriteByte( reg, cfgReg );
    }
    return true;
}

/*
 *
 *
 */
bool AppleUltra33ATA::stopDma( IOATAStandardCommand *, UInt32 *transferCount )
{
    UInt32			reg;
    UInt32                      cfgReg;
    UInt32			startMask;

    *transferCount = 0;

    if ( dmaReqLength == 0 )
    {
        return true;
    }

    reg       = (busNum == 0) ? kUltra646BMIDECR0 : kUltra646BMIDECR1;
    startMask = (busNum == 0) ? kUltra646BMIDECR0_StartDMAPRI : kUltra646BMIDECR1_StartDMASDY;
    cfgReg = pciReadByte( reg );
    cfgReg &= ~startMask;
    pciWriteByte( reg, cfgReg );

    *transferCount = dmaReqLength;

    return true;
}
 
/*
 *
 *
 */
bool AppleUltra33ATA::checkDmaActive()
{
    UInt32			reg;
    UInt32                      cfgReg;
    UInt32			activeMask;

    reg        = (busNum == 0) ? kUltra646BMIDESR0 : kUltra646BMIDESR1;
    activeMask = (busNum == 0) ? kUltra646BMIDESR0_DMAActivePRI : kUltra646BMIDESR1_DMAActiveSDY;

    cfgReg = pciReadByte( reg );
  
    return ((cfgReg & activeMask) != 0);
}

/*
 *
 *
 */
bool AppleUltra33ATA::resetDma()
{
    UInt32			reg;
    UInt32                      cfgReg;
    UInt32			startMask;

    reg       = (busNum == 0) ? kUltra646BMIDECR0 : kUltra646BMIDECR1;
    startMask = (busNum == 0) ? kUltra646BMIDECR0_StartDMAPRI : kUltra646BMIDECR1_StartDMASDY;

    cfgReg = pciReadByte( reg );
    cfgReg &= ~startMask;
    pciWriteByte( reg, cfgReg );

    return true;
}

/*
 *
 *
 */
void AppleUltra33ATA::disableControllerInterrupts()
{
    interruptEventSource->disable();
}

/*
 *
 *
 */
void AppleUltra33ATA::enableControllerInterrupts()
{
    interruptEventSource->enable();
}

/*
 *
 *
 */
void AppleUltra33ATA::free()
{
    UInt32		i;

    if ( interruptEventSource != 0 )
    {
        interruptEventSource->disable();
        interruptEventSource->release();
    }
  
    for (i = 0; i < 2; i++ )
    {
        if ( ioMapATA[i] != 0 ) ioMapATA[i]->release();
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
void AppleUltra33ATA::writeATAReg( UInt32 regIndex, UInt32 regValue )
{
    if ( regIndex == 0 )
    {
        *(volatile UInt16 *)ioBaseATA[0] = regValue;
    }
    else if ( regIndex < kATARegDeviceControl )
    {
        *((volatile UInt8 *)ioBaseATA[0] + regIndex) = regValue;
    }     
    else
    {
        *((volatile UInt8 *)ioBaseATA[1] + regIndex - kATARegDeviceControl + 2) = regValue;
    }
    eieio();
}

UInt32 AppleUltra33ATA::readATAReg( UInt32 regIndex )
{
    if ( regIndex == 0 )
    { 
        return *(volatile UInt16 *)ioBaseATA[0];
    }
    else if ( regIndex < kATARegDeviceControl )
    {
        return *((volatile UInt8 *)ioBaseATA[0] + regIndex);
    }

    return *((volatile UInt8 *)ioBaseATA[1] + regIndex - kATARegDeviceControl + 2);
}

/*
 *
 *
 */
UInt32 AppleUltra33ATA::pciReadByte( UInt32 reg )
{
    volatile union
    {
        unsigned long	word;
        unsigned char   byte[4];
    } data;

    data.word = provider->configRead32( reg );
    return data.byte[3 - (reg & 0x03)];
}

void AppleUltra33ATA::pciWriteByte( UInt32 reg, UInt32 value )
{
    volatile union
    {
        unsigned long	word;
        unsigned char   byte[4];
    } data;

    UInt32		regWord;
 
    regWord = reg & ~0x03;

    data.word = provider->configRead32( regWord );
    data.word = OSReadSwapInt32( &data.word, 0 );

    switch (regWord)
    {
        case kUltra646CFR:
            data.byte[kUltra646CFR & 0x03] &= ~kUltra646CFR_IDEIntPRI;
            break;
        case kUltra646DRWTIM0:
            data.byte[kUltra646ARTTIM23 & 0x03] &= ~kUltra646ARTTIM23_IDEIntSDY;
            break;
        case kUltra646BMIDECR0:
            data.byte[kUltra646MRDMODE & 0x03 ] &= ~(kUltra646MRDMODE_IDEIntPRI  | kUltra646MRDMODE_IDEIntSDY);
            data.byte[kUltra646BMIDESR0 & 0x03] &= ~(kUltra646BMIDESR0_DMAIntPRI | kUltra646BMIDESR0_DMAErrorPRI);
            break;
        case kUltra646BMIDECR1:
            data.byte[kUltra646BMIDESR1 & 0x03] &= ~(kUltra646BMIDESR1_DMAIntSDY | kUltra646BMIDESR1_DMAErrorSDY);
            break;
    }        
    data.byte[reg & 0x03] = value;

    data.word = OSReadSwapInt32(&data.word, 0); 

    provider->configWrite32( regWord, data.word );
}

UInt32 AppleUltra33ATA::pciReadLong( UInt32 reg )
{
    return provider->configRead32( reg );
}

void AppleUltra33ATA::pciWriteLong( UInt32 reg, UInt32 value )
{
    provider->configWrite32( reg, value );
}

/* These overrides take care of OpenFirmware referring to the controller
 * as a child of the PCI device, "ata-4" */

bool AppleUltra33ATA::attach( IOService * provider )
{
    if ( super::attach(provider) )
    {
        // assumes the first child determines the path OF uses to reference the controller
        pathProvider = OSDynamicCast(IOService, provider->getChildEntry(gIODTPlane));

        if ( pathProvider )
        {
            setLocation(pathProvider->getLocation(gIODTPlane), gIODTPlane);
            setName(pathProvider->getName(gIODTPlane), gIODTPlane);
            attachToParent(provider, gIODTPlane);
            pathProvider->retain();
            pathProvider->detachFromParent(provider, gIODTPlane);
        }

        return true;
    }

    return false;
}

void AppleUltra33ATA::detach( IOService * provider )
{
    if ( pathProvider )
    {
        detachFromParent(provider, gIODTPlane);
        pathProvider->attachToParent(provider, gIODTPlane);
        pathProvider->release();
    }

    super::detach(provider);
}
