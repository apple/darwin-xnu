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

/* Sym8xxController.h created by russb2 on Sat 30-May-1998 */

#include <IOKit/IOMemoryCursor.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <libkern/OSByteOrder.h>

#include <IOKit/scsi/IOSCSIParallelInterface.h>

#include "Sym8xxRegs.h"
#include "Sym8xxInterface.h"
#include "Sym8xxSRB.h"

#include "Sym8xxScript.h"

#define offsetof(type, field) ((int)&((type *)0)->field)

class Sym8xxSCSIController : public IOSCSIParallelController 
{
    OSDeclareDefaultStructors( Sym8xxSCSIController )

private:

    AdapterInterface            *adapter;
    AdapterInterface		*adapterPhys;

    UInt32   			nexusArrayVirt[MAX_SCSI_TAG];
    
    IOBigMemoryCursor		*memoryCursor;

    IOPCIDevice			*provider;

    IOInterruptEventSource	*interruptEvent;

    IOMemoryMap			*ioMapRegs;
    IOMemoryMap			*ioMapRam;

    UInt8   			mailBoxIndex;

    UInt32   			initiatorID;

    UInt8   			istatReg;
    UInt8   			dstatReg;
    u_int16_t			sistReg;

    UInt32   			scriptRestartAddr;

    UInt32   			srbSeqNum;
    UInt32   			resetSeqNum;
    
    SRB				*resetSRB;
    SRB				*abortSRB;
    SRB				*abortCurrentSRB;
    bool                        abortReqPending;
    bool			initialReset;

    bool			negotiateWDTRComplete;
    bool			negotiateSDTRComplete;

    UInt32			transferPeriod;
    UInt32			transferOffset;
    UInt32			transferWidth;

    UInt32   			chipId;
    UInt32   			chipClockRate;

    volatile UInt8   		*chipBaseAddr;
    UInt8   			*chipBaseAddrPhys;
    
    volatile UInt8   		*chipRamAddr;
    UInt8   			*chipRamAddrPhys;

public:
    bool 	configure( IOService *forProvider, SCSIControllerInfo *controllerInfo );
    void        executeCommand( IOSCSIParallelCommand *scsiCommand );
    void        cancelCommand(  IOSCSIParallelCommand *scsiCommand );
    void        resetCommand(   IOSCSIParallelCommand *scsiCommand );

private:
    bool  	Sym8xxInit();
    bool  	Sym8xxInitPCI();
    bool  	Sym8xxInitVars();
    bool  	Sym8xxInitScript();
    void  	Sym8xxLoadScript( UInt32 *scriptPgm, UInt32 scriptWords );
    bool  	Sym8xxInitChip();

    void 	Sym8xxCalcMsgs( IOSCSIParallelCommand *scsiCommand );
    void        Sym8xxAbortCommand( IOSCSIParallelCommand *scsiCommand );

    bool 	Sym8xxUpdateSGList( SRB *srb );
    bool        Sym8xxUpdateSGListVirt( SRB *srb );
    bool 	Sym8xxUpdateSGListDesc( SRB *srb );

    void	Sym8xxStartSRB( SRB *srb );
    void 	Sym8xxSignalScript( SRB *srb );
    void 	interruptOccurred( IOInterruptEventSource *ies, int intCount );
    void 	Sym8xxProcessIODone();
    void        Sym8xxCompleteSRB( SRB *srb );
    void 	Sym8xxProcessInterrupt();
    void 	Sym8xxAdjustDataPtrs( SRB *srb, Nexus *nexus );
    UInt32    	Sym8xxCheckFifo( SRB *srb, UInt32    *pfifoCnt );
    void 	Sym8xxUpdateXferOffset( SRB *srb );
    void        Sym8xxProcessNoNexus();
    void 	Sym8xxAbortCurrent( SRB *srb );
    void 	Sym8xxClearFifo();
    void 	Sym8xxNegotiateSDTR( SRB *srb, Nexus *nexus );
    void 	Sym8xxNegotiateWDTR( SRB *srb, Nexus *nexus );
    void 	Sym8xxSendMsgReject( SRB *srb );
    void 	Sym8xxSCSIBusReset(SRB *srb );
    void 	Sym8xxProcessSCSIBusReset();
    void        Sym8xxCheckRequestSense( SRB *srb );
    void 	Sym8xxAbortBdr( SRB *srb );
    bool        Sym8xxCancelMailBox( Nexus *nexusCancel );
    void        Sym8xxCancelMailBox( UInt32 target, UInt32 lun, bool fReschedule );

    void 	Sym8xxAbortScript();

    UInt32    	Sym8xxReadRegs( volatile UInt8 *chipRegs, UInt32 regOffset, UInt32 regSize );
    void     	Sym8xxWriteRegs( volatile UInt8 *chipRegs, UInt32 regOffset, UInt32 regSize, UInt32 regValue );

};

