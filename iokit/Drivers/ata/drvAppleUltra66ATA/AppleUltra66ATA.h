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
 *    	AppleUltra66ATA.h
 *
 */

#include <IOKit/IOMemoryCursor.h>
#include <IOKit/ppc/IODBDMA.h>

#include <IOKit/ata/IOATAStandardInterface.h>

class AppleUltra66ATA : public IOATAStandardDriver
{
    OSDeclareDefaultStructors( AppleUltra66ATA )

public:
   void				free();

protected:
    bool 			configure( IOService *provider, ATAControllerInfo *controllerDataSize );

    void			enableControllerInterrupts();
    void			disableControllerInterrupts();

    bool 			calculateTiming( UInt32 deviceNum, ATATiming *timing );
    bool	 		selectTiming( UInt32 deviceNum, ATATimingProtocol timingProtocol );

    void			newDeviceSelected( IOATAStandardDevice *newDevice );

    void			writeATAReg( UInt32 regIndex, UInt32 regValue );
    UInt32			readATAReg(  UInt32 regIndex );

    bool			programDma( IOATAStandardCommand *cmd );
    bool			startDma( IOATAStandardCommand *cmd );
    bool			stopDma( IOATAStandardCommand *cmd, UInt32 *transferCount );
    bool			resetDma();
    bool			checkDmaActive();

private:
    bool			identifyController();

    bool 			calculatePIOTiming( UInt32 deviceNum, ATATiming *timing );
    bool 			calculateDMATiming( UInt32 deviceNum, ATATiming *timing );

    bool 			calculateUltra66PIOTiming( UInt32 deviceNum, ATATiming *timing );
    bool 			calculateUltra66DMATiming( UInt32 deviceNum, ATATiming *timing );
    bool 			calculateUltra66UDMATiming( UInt32 deviceNum, ATATiming *timing );

private:
    IOService				*provider;

    IOMemoryMap				*ioMapATA;
    volatile UInt32			*ioBaseATA;

    IOMemoryMap				*ioMapDMA;
    volatile IODBDMAChannelRegisters	*ioBaseDMA;

    UInt32				controllerType;

    IOInterruptEventSource		*interruptEventSource;

    UInt32				ideTimingWord[2];

    IOBigMemoryCursor			*dmaMemoryCursor;
    IODBDMADescriptor			*dmaDescriptors;
    UInt32				dmaDescriptorsPhys;
    UInt32				numDescriptors;

    void				*bitBucketAddr;
    UInt32				bitBucketAddrPhys;

    UInt32				dmaReqLength;
};

/*
 *
 *
 */
#define kATACS3RegBase		(16)

enum	
{
    kATASysClkNS	 	= 30,
    kATAUltra66ClockPS		= (15 * 1000 / 2),		// PCI 66 period / 2 (pS)

    kATAPioAccessBase		= 0,
    kATAPioAccessMin 		= 4,
    kATAPioRecoveryBase 	= 4,
    kATAPioRecoveryMin		= 1,

    kATADmaAccessBase		= 0,
    kATADmaAccessMin  		= 1,
    kATADmaRecoveryBase		= 1,
    kATADmaRecoveryMin		= 1,
};

enum
{
    kControllerTypeDBDMAVersion1	= 1,
    kControllerTypeDBDMAVersion2 	= 2,
    kControllerTypeUltra66DBDMA		= 3,
};
