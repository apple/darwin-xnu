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
 *    	AppleUltra33ATA.h
 *
 */

#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOMemoryCursor.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <libkern/OSByteOrder.h>

#include <IOKit/ata/IOATAStandardInterface.h>
#include "AppleUltra33ATARegs.h"

class AppleUltra33ATA : public IOATAStandardDriver
{
    OSDeclareDefaultStructors( AppleUltra33ATA )

public:
   virtual bool		attach( IOService * provider );
   virtual void		detach( IOService * provider );
   void				free();

protected:
    bool 			configure( IOService *provider, ATAControllerInfo *controllerDataSize );

    void 			interruptOccurred();

    void			enableControllerInterrupts();
    void			disableControllerInterrupts();

    bool 			calculateTiming( UInt32 deviceNum, ATATiming *timing );
    bool	 		selectTiming( UInt32 deviceNum, ATATimingProtocol timingProtocol );

    void			newDeviceSelected( IOATADevice *newDevice );

    void			writeATAReg( UInt32 regIndex, UInt32 regValue );
    UInt32			readATAReg(  UInt32 regIndex );

    bool			programDma( IOATAStandardCommand *cmd );
    bool			startDma( IOATAStandardCommand *cmd );
    bool			stopDma( IOATAStandardCommand *cmd, UInt32 *transferCount );
    bool			checkDmaActive();
    bool			resetDma();

private:
    bool 			calculatePIOTiming( UInt32 deviceNum, ATATiming *timing );
    bool 			calculateDMATiming( UInt32 deviceNum, ATATiming *timing );
    bool 			calculateUltraDMATiming( UInt32 deviceNum, ATATiming *timing );

    UInt32 			pciReadByte( UInt32 reg );
    void 			pciWriteByte( UInt32 reg, UInt32 value );
    UInt32 			pciReadLong( UInt32 reg );
    void 			pciWriteLong( UInt32 reg, UInt32 value );

private:
    IOPCIDevice				*provider;
    IOService				*pathProvider;

    UInt32				busNum;

    IOMemoryMap				*ioMapATA[2];
    volatile UInt32			*ioBaseATA[2];

    IOInterruptEventSource		*interruptEventSource;

    Ultra646Regs			ideTimingRegs[2];

    IOBigMemoryCursor			*dmaMemoryCursor;
    Ultra646Descriptor			*dmaDescriptors;
    UInt32				dmaDescriptorsPhys;
    UInt32				numDescriptors;

    void				*bitBucketAddr;
    UInt32				bitBucketAddrPhys;

    UInt32				dmaReqLength;
    bool				dmaIsWrite;
};

