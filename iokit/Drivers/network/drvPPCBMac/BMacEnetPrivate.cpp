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
 * Copyright (c) 1998-1999 by Apple Computer, Inc., All rights reserved.
 *
 * Implementation for hardware dependent (relatively) code 
 * for the BMac Ethernet controller. 
 *
 * HISTORY
 *
 */

#include <IOKit/assert.h>
#include <IOKit/system.h>

#include "BMacEnetPrivate.h"
#include <IOKit/IOLib.h>

/*****************************************************************************
 *
 * Hacks.
 */

typedef	unsigned long long	ns_time_t;	/* nanoseconds! */

#define NSEC_PER_SEC 	1000000000

static void
_IOGetTimestamp(ns_time_t *nsp)
{
	mach_timespec_t		now;

	IOGetTime(&now);
	*nsp = ((ns_time_t)now.tv_sec * NSEC_PER_SEC) + now.tv_nsec;
}

/*
 * Find a physical address (if any) for the specified virtual address.
 *
 * Note: what about vm_offset_t kvtophys(vm_offset_t va) 
 */
static IOReturn _IOPhysicalFromVirtual(
	vm_address_t virtualAddress,
	unsigned *physicalAddress)
{
	*physicalAddress = pmap_extract(kernel_pmap, virtualAddress);
	if(*physicalAddress == 0) {
		return kIOReturnBadArgument;
	}
	else {
		return kIOReturnSuccess;
	}
}

/****************************************************************************/

 
extern kern_return_t		kmem_alloc_wired();

static IODBDMADescriptor	dbdmaCmd_Nop;
static IODBDMADescriptor   	dbdmaCmd_NopWInt;
static IODBDMADescriptor	dbdmaCmd_LoadInt;			
static IODBDMADescriptor	dbdmaCmd_LoadIntWInt;
static IODBDMADescriptor	dbdmaCmd_Stop;
static IODBDMADescriptor	dbdmaCmd_Branch;

static u_int8_t reverseBitOrder(u_int8_t data )
{
	u_int8_t	val = 0;
	int			i;

	for ( i=0; i < 8; i++ )
	{
		val <<= 1;
		if (data & 1) val |= 1;
		data >>= 1;
	}
	return( val );
}

/*
 * Function: IOMallocPage
 *
 * Purpose:
 *   Returns a pointer to a page-aligned memory block of size >= PAGE_SIZE
 *
 * Return:
 *   Actual pointer and size of block returned in actual_ptr and actual_size.
 *   Use these as arguments to kfree: kfree(*actual_ptr, *actual_size);
 */
static void *
IOMallocPage(int request_size, void ** actual_ptr, u_int * actual_size)
{
    void * mem_ptr;
    
	*actual_size = round_page(request_size) + PAGE_SIZE;
	mem_ptr = IOMalloc(*actual_size);
	if (mem_ptr == NULL)
		return NULL;
	*actual_ptr = mem_ptr;
	return ((void *)round_page(mem_ptr));
}

/*
 * Private functions
 */
bool BMacEnet::_allocateMemory()
{
    u_int32_t			i, n;
    unsigned char *		virtAddr;
    u_int32_t			physBase;
    u_int32_t	 		physAddr;
	u_int32_t			dbdmaSize;
 
    /* 
     * Calculate total space for DMA channel commands
     */
    dbdmaSize = round_page(
		RX_RING_LENGTH * sizeof(enet_dma_cmd_t) + 
		TX_RING_LENGTH * sizeof(enet_txdma_cmd_t) +
		2 * sizeof(IODBDMADescriptor) );

    /*
     * Allocate required memory
     */
	dmaMemory.size = dbdmaSize;
	dmaMemory.ptr = (void *)IOMallocPage(
                                dmaMemory.size,
                                &dmaMemory.ptrReal,
                                &dmaMemory.sizeReal
                                );

	dmaCommands = (unsigned char *) dmaMemory.ptr;
	if (dmaCommands == NULL) {
		IOLog( "Ethernet(BMac): Cant allocate channel DBDMA commands\n\r" );
		return false;
	}

    /*
     * If we needed more than one page, then make sure we received
	 * contiguous memory.
     */
    n = (dbdmaSize - PAGE_SIZE) / PAGE_SIZE;
    _IOPhysicalFromVirtual( (vm_address_t) dmaCommands, &physBase );

    virtAddr = (unsigned char *) dmaCommands;
    for( i=0; i < n; i++, virtAddr += PAGE_SIZE )
	{
		_IOPhysicalFromVirtual( (vm_address_t) virtAddr, &physAddr );
		if (physAddr != (physBase + i * PAGE_SIZE) )
		{
			IOLog( "Ethernet(BMac): Cannot allocate contiguous memory"
				" for DBDMA commands\n\r" );
			return false;
		}
	}           

    /* 
     * Setup the receive ring pointers
     */
    rxDMACommands = (enet_dma_cmd_t *)dmaCommands;
    rxMaxCommand  = RX_RING_LENGTH;

    /*
     * Setup the transmit ring pointers
     */
    txDMACommands = (enet_txdma_cmd_t *)(dmaCommands +
		RX_RING_LENGTH * sizeof(enet_dma_cmd_t) + sizeof(IODBDMADescriptor));
    txMaxCommand  = TX_RING_LENGTH;

    /*
     * Setup pre-initialized DBDMA commands 
     */
    IOMakeDBDMADescriptor( (&dbdmaCmd_Nop),
                            kdbdmaNop,
							kdbdmaKeyStream0,
							kdbdmaIntNever,
							kdbdmaBranchNever,
							kdbdmaWaitNever,
                            0,
                            0);

    IOMakeDBDMADescriptor( (&dbdmaCmd_NopWInt),
                            kdbdmaNop,
							kdbdmaKeyStream0,
							kdbdmaIntAlways,
							kdbdmaBranchNever,
							kdbdmaWaitNever,
                            0,
                            0);

	UInt32 ioBaseEnetPhys = maps[MEMORY_MAP_ENET_INDEX]->getPhysicalAddress();

    IOMakeDBDMADescriptor( (&dbdmaCmd_LoadInt),
                            kdbdmaLoadQuad,
                            kdbdmaKeySystem,
                            kdbdmaIntNever,
                            kdbdmaBranchNever,
                            kdbdmaWaitNever,
                            2,
                            ((int)ioBaseEnetPhys +  kSTAT)   );

    IOMakeDBDMADescriptor( (&dbdmaCmd_LoadIntWInt),
                            kdbdmaLoadQuad,
                            kdbdmaKeySystem,
                            kdbdmaIntAlways,
                            kdbdmaBranchNever,
                            kdbdmaWaitNever,
                            2,
                            ((int)ioBaseEnetPhys +  kSTAT)   );

    IOMakeDBDMADescriptor( (&dbdmaCmd_Stop),
                            kdbdmaStop,
							kdbdmaKeyStream0,
							kdbdmaIntNever,
							kdbdmaBranchNever,
							kdbdmaWaitNever,
                            0,
                            0);

    IOMakeDBDMADescriptor( (&dbdmaCmd_Branch),
                            kdbdmaNop,
							kdbdmaKeyStream0,
							kdbdmaIntNever,
							kdbdmaBranchAlways,
							kdbdmaWaitNever,
                            0,
                            0);

    return true;
}

/*-------------------------------------------------------------------------
 *
 * Setup the Transmit Ring
 * -----------------------
 * Each transmit ring entry consists of two words to transmit data from buffer
 * segments (possibly) spanning a page boundary. This is followed by two DMA 
 * commands which read transmit frame status and interrupt status from the Bmac 
 * chip. The last DMA command in each transmit ring entry generates a host 
 * interrupt. The last entry in the ring is followed by a DMA branch to the 
 * first entry.
 *-------------------------------------------------------------------------*/

bool BMacEnet::_initTxRing()
{
    bool		kr;
	u_int32_t	i;
	IODBDMADescriptor	dbdmaCmd, dbdmaCmdInt;

    /*
     * Clear mbufs from TX ring.
     */
    for ( i = 0; i < txMaxCommand; i++ )
    {
    	if ( txMbuf[i] )
        {
            freePacket( txMbuf[i] );
            txMbuf[i] = 0;
        }
    }

    /*
     * Clear the transmit DMA command memory
     */  
    bzero( (void *)txDMACommands, sizeof(enet_txdma_cmd_t) * txMaxCommand);
    txCommandHead = 0;
    txCommandTail = 0;

    /*
     * DMA Channel commands 2 are the same for all DBDMA entries on transmit.
     * Initialize them now.
     */
    
    dbdmaCmd     = ( chipId >= kCHIPID_PaddingtonXmitStreaming ) ? dbdmaCmd_Nop     : dbdmaCmd_LoadInt;
    dbdmaCmdInt  = ( chipId >= kCHIPID_PaddingtonXmitStreaming ) ? dbdmaCmd_NopWInt : dbdmaCmd_LoadIntWInt;

    for( i=0; i < txMaxCommand; i++ )
    {
      txDMACommands[i].desc_seg[2] = ( (i+1) % TX_PKTS_PER_INT ) ? dbdmaCmd : dbdmaCmdInt;
    }

    /* 
     * Put a DMA Branch command after the last entry in the transmit ring.
	 * Set the branch address to the physical address of the start of the 
	 * transmit ring.
     */
    txDMACommands[txMaxCommand].desc_seg[0] = dbdmaCmd_Branch; 

    kr = _IOPhysicalFromVirtual( (vm_address_t) txDMACommands,
		(u_int32_t *)&txDMACommandsPhys );
	if ( kr != kIOReturnSuccess )
	{
		IOLog( "Ethernet(BMac): Bad DBDMA command buf - %08x\n\r", 
			(u_int32_t)txDMACommands );
    }
	IOSetCCCmdDep( &txDMACommands[txMaxCommand].desc_seg[0],
		txDMACommandsPhys );
 
    /* 
     * Set the Transmit DMA Channel pointer to the first entry in the
	 * transmit ring.
     */
    IOSetDBDMACommandPtr( ioBaseEnetTxDMA, txDMACommandsPhys );

    return true;
}

/*-------------------------------------------------------------------------
 *
 * Setup the Receive ring
 * ----------------------
 * Each receive ring entry consists of two DMA commands to receive data
 * into a network buffer (possibly) spanning a page boundary. The second
 * DMA command in each entry generates a host interrupt.
 * The last entry in the ring is followed by a DMA branch to the first
 * entry. 
 *
 *-------------------------------------------------------------------------*/

bool BMacEnet::_initRxRing()
{
    u_int32_t 		i;
    bool			status;
    IOReturn    	kr;
    
    /*
     * Clear the receive DMA command memory
     */
    bzero((void *)rxDMACommands, sizeof(enet_dma_cmd_t) * rxMaxCommand);

    kr = _IOPhysicalFromVirtual( (vm_address_t) rxDMACommands,
		(u_int32_t *)&rxDMACommandsPhys );
    if ( kr != kIOReturnSuccess )
    {
		IOLog( "Ethernet(BMac): Bad DBDMA command buf - %08x\n\r",
			(u_int32_t)rxDMACommands );
		return false;
    }

    /*
     * Allocate a receive buffer for each entry in the Receive ring
     */
    for (i = 0; i < rxMaxCommand-1; i++) 
	{	
		if (rxMbuf[i] == NULL)	
		{		
			rxMbuf[i] = allocatePacket(NETWORK_BUFSIZE);
			if (!rxMbuf[i])
			{
				IOLog("Ethernet(BMac): allocatePacket failed\n");
				return false;
			}
		}

		/* 
		 * Set the DMA commands for the ring entry to transfer data to the 
		 * mbuf.
		 */
		status = _updateDescriptorFromMbuf(rxMbuf[i], &rxDMACommands[i], true);
		if (status == false)
		{    
			IOLog("Ethernet(BMac): cannot map mbuf to physical memory in"
				" _initRxRing\n\r");
			return false;
		}
	}

    /*
     * Set the receive queue head to point to the first entry in the ring.
	 * Set the receive queue tail to point to a DMA Stop command after the
	 * last ring entry
     */    
    rxCommandHead = 0;
    rxCommandTail = i;

    rxDMACommands[i].desc_seg[0] = dbdmaCmd_Stop; 
    rxDMACommands[i].desc_seg[1] = dbdmaCmd_Nop;

    /*
     * Setup a DMA branch command after the stop command
     */
    i++;
    rxDMACommands[i].desc_seg[0] = dbdmaCmd_Branch; 

    IOSetCCCmdDep( &rxDMACommands[i].desc_seg[0], rxDMACommandsPhys );

    /*
     * Set DMA command pointer to first receive entry
     */ 
    IOSetDBDMACommandPtr (ioBaseEnetRxDMA, rxDMACommandsPhys);

    return true;
}

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

void BMacEnet::_startChip()
{
    u_int16_t	oldConfig;

    IODBDMAContinue( ioBaseEnetRxDMA );
  
    // turn on rx plus any other bits already on (promiscuous possibly)
    oldConfig = ReadBigMacRegister(ioBaseEnet, kRXCFG);		
    WriteBigMacRegister(ioBaseEnet, kRXCFG, oldConfig | kRxMACEnable ); 
 
    oldConfig = ReadBigMacRegister(ioBaseEnet, kTXCFG);		
    WriteBigMacRegister(ioBaseEnet, kTXCFG, oldConfig | kTxMACEnable ); 
}

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

void BMacEnet::_resetChip()
{
    volatile u_int32_t	*heathrowFCR;
    u_int32_t			fcrValue;
	u_int16_t			*pPhyType;
	 
    IODBDMAReset( ioBaseEnetRxDMA );  
    IODBDMAReset( ioBaseEnetTxDMA );  

    IOSetDBDMAWaitSelect( ioBaseEnetTxDMA,
		IOSetDBDMAChannelControlBits( kdbdmaS5 ) );

    IOSetDBDMABranchSelect( ioBaseEnetRxDMA,
		IOSetDBDMAChannelControlBits( kdbdmaS6 ) );

    IOSetDBDMAInterruptSelect( ioBaseEnetRxDMA,
		IOSetDBDMAChannelControlBits( kdbdmaS6 ) );

    heathrowFCR = (u_int32_t *)((u_int8_t *)ioBaseHeathrow + kHeathrowFCR);

    fcrValue = *heathrowFCR;
    eieio();

    fcrValue = OSReadSwapInt32( &fcrValue, 0 );

    /*
     * Enable the ethernet transceiver/clocks
     */
    fcrValue |= kEnetEnabledBits;
    fcrValue &= ~kResetEnetCell;
						
    *heathrowFCR = OSReadSwapInt32( &fcrValue, 0 );
    eieio();
    IOSleep( 100 );

    /*
     * Determine if PHY chip is configured. Reset and enable it (if present).
     */
    if ( phyId == 0xff )
    {
        phyMIIDelay = 20;
        if ( miiFindPHY(&phyId) == true )
        {
			miiResetPHY(phyId);

            pPhyType = (u_int16_t *)&phyType;
            miiReadWord(pPhyType,   MII_ID0, phyId);
			miiReadWord(pPhyType+1, MII_ID1, phyId);

            if ( (phyType & MII_ST10040_MASK) == MII_ST10040_ID )
            {
                phyMIIDelay = MII_ST10040_DELAY;
            }
            else if ( (phyType & MII_DP83843_MASK) == MII_DP83843_ID )
            {
                phyMIIDelay = MII_DP83843_DELAY;
            }

            kprintf("Ethernet(BMac): PHY id = %d\n", phyId);
        }
    }

    /*
     * Reset the reset the ethernet cell
     */
    fcrValue |= kResetEnetCell;
    *heathrowFCR = OSReadSwapInt32( &fcrValue, 0 );
    eieio();
    IOSleep( 10 );

    fcrValue &= ~kResetEnetCell;
    *heathrowFCR = OSReadSwapInt32( &fcrValue, 0 );
    eieio();
    IOSleep( 10 );

	chipId = ReadBigMacRegister(ioBaseEnet, kCHIPID) & 0xFF;
}

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

bool BMacEnet::_initChip()
{
    volatile u_int16_t		regValue;
    ns_time_t   		timeStamp;	   
    u_int16_t			*pWord16;

    WriteBigMacRegister(ioBaseEnet, kTXRST, kTxResetBit);

    do	
    {
		// wait for reset to clear..acknowledge
		regValue = ReadBigMacRegister(ioBaseEnet, kTXRST);		
    } 
    while( regValue & kTxResetBit );

    WriteBigMacRegister(ioBaseEnet, kRXRST, kRxResetValue);

    if ( phyId == 0xff )
    {
		WriteBigMacRegister(ioBaseEnet, kXCVRIF,
			kClkBit | kSerialMode | kCOLActiveLow);
    }	

    _IOGetTimestamp(&timeStamp);	
    WriteBigMacRegister(ioBaseEnet, kRSEED, (u_int16_t) timeStamp );		

    regValue = ReadBigMacRegister(ioBaseEnet, kXIFC);
    regValue |= kTxOutputEnable;
    WriteBigMacRegister(ioBaseEnet, kXIFC, regValue);

    ReadBigMacRegister(ioBaseEnet, kPAREG);

    // set collision counters to 0
    WriteBigMacRegister(ioBaseEnet, kNCCNT, 0);
    WriteBigMacRegister(ioBaseEnet, kNTCNT, 0);
    WriteBigMacRegister(ioBaseEnet, kEXCNT, 0);
    WriteBigMacRegister(ioBaseEnet, kLTCNT, 0);

    // set rx counters to 0
    WriteBigMacRegister(ioBaseEnet, kFRCNT, 0);
    WriteBigMacRegister(ioBaseEnet, kLECNT, 0);
    WriteBigMacRegister(ioBaseEnet, kAECNT, 0);
    WriteBigMacRegister(ioBaseEnet, kFECNT, 0);
    WriteBigMacRegister(ioBaseEnet, kRXCV, 0);

    // set tx fifo information
	// 255 octets before tx starts
    WriteBigMacRegister(ioBaseEnet, kTXTH, 0xff);

	// first disable txFIFO
    WriteBigMacRegister(ioBaseEnet, kTXFIFOCSR, 0);
    WriteBigMacRegister(ioBaseEnet, kTXFIFOCSR, kTxFIFOEnable );

    // set rx fifo information
	// first disable rxFIFO
    WriteBigMacRegister(ioBaseEnet, kRXFIFOCSR, 0);				
    WriteBigMacRegister(ioBaseEnet, kRXFIFOCSR, kRxFIFOEnable ); 

	// kTxNeverGiveUp maybe later
    //WriteBigMacRegister(ioBaseEnet, kTXCFG, kTxMACEnable);
    ReadBigMacRegister(ioBaseEnet, kSTAT);		// read it just to clear it

    // zero out the chip Hash Filter registers
    WriteBigMacRegister(ioBaseEnet, kHASH3, hashTableMask[0]); 	// bits 15 - 0
    WriteBigMacRegister(ioBaseEnet, kHASH2, hashTableMask[1]); 	// bits 31 - 16
    WriteBigMacRegister(ioBaseEnet, kHASH1, hashTableMask[2]); 	// bits 47 - 32
    WriteBigMacRegister(ioBaseEnet, kHASH0, hashTableMask[3]); 	// bits 63 - 48
	
    pWord16 = (u_int16_t *)&myAddress.bytes[0];
    WriteBigMacRegister(ioBaseEnet, kMADD0, *pWord16++);
    WriteBigMacRegister(ioBaseEnet, kMADD1, *pWord16++);
    WriteBigMacRegister(ioBaseEnet, kMADD2, *pWord16);
    
    WriteBigMacRegister(ioBaseEnet, kRXCFG,
		kRxCRCEnable | kRxHashFilterEnable | kRxRejectOwnPackets);
    
    return true;
}

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

void BMacEnet::_disableAdapterInterrupts()
{
	WriteBigMacRegister( ioBaseEnet, kINTDISABLE, kNoEventsMask );
}

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

void BMacEnet::_enableAdapterInterrupts()
{
    WriteBigMacRegister( ioBaseEnet, 
                         kINTDISABLE, 
                         ( chipId >= kCHIPID_PaddingtonXmitStreaming ) ?
						 	kNoEventsMask: kNormalIntEvents );
}

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

void BMacEnet::_setDuplexMode(bool duplexMode)
{
    u_int16_t		txCFGVal;

    isFullDuplex = duplexMode;

    txCFGVal = ReadBigMacRegister( ioBaseEnet, kTXCFG);

    WriteBigMacRegister( ioBaseEnet, kTXCFG, txCFGVal & ~kTxMACEnable );
    while( ReadBigMacRegister(ioBaseEnet, kTXCFG) & kTxMACEnable )
      ;
 
    if ( isFullDuplex )
    {
        txCFGVal |= (kTxIgnoreCollision | kTxFullDuplex);
    }
    else
    {
        txCFGVal &= ~(kTxIgnoreCollision | kTxFullDuplex);
    }
    
    WriteBigMacRegister( ioBaseEnet, kTXCFG, txCFGVal );
}    

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

void BMacEnet::_restartTransmitter()
{
    u_int16_t	regValue;

    /*
     * Shutdown DMA channel
     */
	_stopTransmitDMA();

    /*
     * Get the silicon's attention
     */
    WriteBigMacRegister( ioBaseEnet, kTXFIFOCSR, 0 );
    WriteBigMacRegister( ioBaseEnet, kTXFIFOCSR, kTxFIFOEnable);

	ReadBigMacRegister( ioBaseEnet, kSTAT );

    regValue = ReadBigMacRegister(ioBaseEnet, kTXCFG);		
    WriteBigMacRegister(ioBaseEnet, kTXCFG, regValue | kTxMACEnable );  

    /*
     * Restart transmit DMA
     */
    IODBDMAContinue( ioBaseEnetTxDMA );  
}

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

void BMacEnet::_restartReceiver()
{
    u_int16_t	oldConfig;

    /*
     * Shutdown DMA channel
     */
	_stopReceiveDMA();

    /*
     * Get the silicon's attention
     */
    WriteBigMacRegister( ioBaseEnet, kRXFIFOCSR, 0 );
    WriteBigMacRegister( ioBaseEnet, kRXFIFOCSR, kRxFIFOEnable);

    oldConfig = ReadBigMacRegister(ioBaseEnet, kRXCFG);		
    WriteBigMacRegister(ioBaseEnet, kRXCFG, oldConfig | kRxMACEnable ); 
 
    /*
     * Restart receive DMA
     */
    IODBDMAContinue( ioBaseEnetRxDMA );  
}

/*-------------------------------------------------------------------------
 *
 * Orderly stop of receive DMA.
 *
 *
 *-------------------------------------------------------------------------*/

void BMacEnet::_stopReceiveDMA()
{
    u_int32_t		dmaCmdPtr;
    u_int8_t		rxCFGVal;

    /* 
     * Stop the receiver and allow any frame receive in progress to complete.
     */
    rxCFGVal = ReadBigMacRegister(ioBaseEnet, kRXCFG);
    WriteBigMacRegister(ioBaseEnet, kRXCFG, rxCFGVal & ~kRxMACEnable );
    IODelay( RECEIVE_QUIESCE_uS );

    IODBDMAReset( ioBaseEnetRxDMA );

    dmaCmdPtr = rxDMACommandsPhys + rxCommandHead * sizeof(enet_dma_cmd_t);
    IOSetDBDMACommandPtr( ioBaseEnetRxDMA, dmaCmdPtr );
}    

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

void BMacEnet::_stopTransmitDMA()
{
    u_int32_t		dmaCmdPtr;
    u_int8_t		txCFGVal;

    /* 
     * Stop the transmitter and allow any frame transmit in progress to abort
     */
    txCFGVal = ReadBigMacRegister(ioBaseEnet, kTXCFG);
    WriteBigMacRegister(ioBaseEnet, kTXCFG, txCFGVal & ~kTxMACEnable );

    IODelay( TRANSMIT_QUIESCE_uS );

    IODBDMAReset( ioBaseEnetTxDMA );
    
    dmaCmdPtr = txDMACommandsPhys + txCommandHead * sizeof(enet_txdma_cmd_t); 
    IOSetDBDMACommandPtr( ioBaseEnetTxDMA, dmaCmdPtr );
}

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

bool BMacEnet::_transmitPacket(struct mbuf *packet)
{
    enet_dma_cmd_t	tmpCommand;
    u_int32_t		i;
	
    /*
     * Check for room on the transmit ring. There should always be space 
	 * since it is the responsibility of the caller to verify this before 
	 * calling _transmitPacket.
     *
     * Get a copy of the DMA transfer commands in a temporary buffer. 
     * The new DMA command is written into the channel program so that the 
	 * command word for the old Stop command is overwritten last. This prevents 
	 * the DMA engine from executing a partially written channel command.
     */
    i = txCommandTail + 1;
    if ( i >= txMaxCommand ) i = 0;
    
	if ( (i == txCommandHead) ||
		!_updateDescriptorFromMbuf(packet, &tmpCommand, false) )
    {
		IOLog("Ethernet(BMac): Freeing transmit packet eh?\n\r");
		if (packet != txDebuggerPkt)
			freePacket(packet);
		return false;
    }

    /*
     * txCommandTail points to the current DMA Stop command for the channel.
	 * We are now creating a new DMA Stop command in the next slot in the 
	 * transmit ring. The previous DMA Stop command will be overwritten with 
	 * the DMA commands to transfer the new mbuf.
     */
    txDMACommands[i].desc_seg[0] = dbdmaCmd_Stop;
    txDMACommands[i].desc_seg[1] = dbdmaCmd_Nop;

    bcopy( ((u_int32_t *)&tmpCommand)+1,
           ((u_int32_t *)&txDMACommands[txCommandTail])+1,
           sizeof(enet_dma_cmd_t)-sizeof(u_int32_t) );

	txMbuf[txCommandTail] = packet;
    txDMACommands[txCommandTail].desc_seg[0].operation = 
		tmpCommand.desc_seg[0].operation;

    /*
     * Set the transmit tail to the new stop command.
     */
	txCommandTail = i;

    /*
     * Tap the DMA channel to wake it up
     */
    IODBDMAContinue( ioBaseEnetTxDMA );

    return true;
}	

/*-------------------------------------------------------------------------
 * _receivePacket
 * --------------
 * This routine runs the receiver in polled-mode (yuk!) for the kernel debugger.
 *
 * The _receivePackets allocate NetBufs and pass them up the stack. The kernel
 * debugger interface passes a buffer into us. To reconsile the two interfaces,
 * we allow the receive routine to continue to allocate its own buffers and
 * transfer any received data to the passed-in buffer. This is handled by 
 * _receivePacket calling _packetToDebugger.
 *-------------------------------------------------------------------------*/

void BMacEnet::_receivePacket(void *pkt, unsigned int *pkt_len,
		unsigned int timeout)
{
    ns_time_t		startTime;
    ns_time_t		currentTime;
    u_int32_t		elapsedTimeMS;

    if (!ready || !pkt || !pkt_len)
      return;

    *pkt_len = 0;

    debuggerPkt     = pkt;
    debuggerPktSize = 0;

    _IOGetTimestamp(&startTime);
    do
    {
		_receivePackets(true);
		_IOGetTimestamp(&currentTime);
		elapsedTimeMS = (currentTime - startTime) / (1000*1000);
    } 
    while ( (debuggerPktSize == 0) && (elapsedTimeMS < timeout) );

    *pkt_len = debuggerPktSize;
}

/*-------------------------------------------------------------------------
 * _packetToDebugger
 * -----------------
 * This is called by _receivePackets when we are polling for kernel debugger
 * packets. It copies the NetBuf contents to the buffer passed by the debugger.
 * It also sets the var debuggerPktSize which will break the polling loop.
 *-------------------------------------------------------------------------*/

void BMacEnet::_packetToDebugger(struct mbuf * packet, u_int size)
{
    debuggerPktSize = size;
    bcopy( mtod(packet, char *), debuggerPkt, size );
}

/*-------------------------------------------------------------------------
 * _sendPacket
 * -----------
 *
 * This routine runs the transmitter in polled-mode (yuk!) for the kernel debugger.
 *
 *-------------------------------------------------------------------------*/

void BMacEnet::_sendPacket(void *pkt, unsigned int pkt_len)
{
    ns_time_t	startTime;
    ns_time_t	currentTime;
    u_int32_t	elapsedTimeMS;

    if (!ready || !pkt || (pkt_len > ETHERMAXPACKET))
      return;

    /*
     * Wait for the transmit ring to empty
     */
    _IOGetTimestamp(&startTime); 
	do
    {	
		_debugTransmitInterruptOccurred();
		_IOGetTimestamp(&currentTime);
		elapsedTimeMS = (currentTime - startTime) / (1000*1000);
    }
    while ( (txCommandHead != txCommandTail) &&
			(elapsedTimeMS < TX_KDB_TIMEOUT) ); 
	
	if ( txCommandHead != txCommandTail )
	{
		IOLog( "Ethernet(BMac): Polled tranmit timeout - 1\n\r");
		return;
    }

    /*
     * Allocate a NetBuf and copy the debugger transmit data into it.
	 *
	 * jliu - no allocation, just recycle the same buffer dedicated to
	 * KDB transmit.
     */
	txDebuggerPkt->m_next = 0;
	txDebuggerPkt->m_data = (caddr_t) pkt;
	txDebuggerPkt->m_pkthdr.len = txDebuggerPkt->m_len = pkt_len;

    /*
     * Send the debugger packet. txDebuggerPkt must not be freed by
	 * the transmit routine.
     */
	_transmitPacket(txDebuggerPkt);

    /*
     * Poll waiting for the transmit ring to empty again
     */
    do 
    {
		_debugTransmitInterruptOccurred();
		_IOGetTimestamp(&currentTime);
		elapsedTimeMS = (currentTime - startTime) / (1000*1000);
    }
    while ( (txCommandHead != txCommandTail) &&
			(elapsedTimeMS < TX_KDB_TIMEOUT) ); 

    if ( txCommandHead != txCommandTail )
    {
		IOLog( "Ethernet(BMac): Polled tranmit timeout - 2\n\r");
    }

    return;
}

/*-------------------------------------------------------------------------
 * _sendDummyPacket
 * ----------------
 * The BMac receiver seems to be locked until we send our first packet.
 *
 *-------------------------------------------------------------------------*/
void BMacEnet::_sendDummyPacket()
{
    union
    {
		u_int8_t		    bytes[64];
		IOEthernetAddress	enet_addr[2];
    } dummyPacket;
	
	bzero( &dummyPacket, sizeof(dummyPacket) );
    dummyPacket.enet_addr[0] = myAddress;   
    dummyPacket.enet_addr[1] = myAddress;
	_sendPacket((void *)dummyPacket.bytes, sizeof(dummyPacket));
	IOSleep(50);
}

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

bool BMacEnet::_receiveInterruptOccurred()
{
	return _receivePackets(false);
}

/*-------------------------------------------------------------------------
 * Work around a hardware bug where the controller will receive
 * unicast packets not directed to the station. The hardware is
 * erroneously using the hash table to qualify the unicast address.
 * This routine will check that the packet is unicast, and if so,
 * makes sure that the unicast address matches the station's address.
 * Thus function returns true if the packet should be rejected.
 *-------------------------------------------------------------------------*/

bool BMacEnet::_rejectBadUnicastPacket(ether_header_t * etherHeader)
{
	bool rejectPacket = false;

	if ( useUnicastFilter && (isPromiscuous == false) &&
		(etherHeader->ether_dhost[EA_GROUP_BYTE] & EA_GROUP_BIT) == 0) {
		//
		// Destination Ethernet address is not multicast nor broadcast.
		// Then it must be addresses to the station MAC address,
		// otherwise reject the packet.
		//
		if (bcmp(etherHeader->ether_dhost, &myAddress, NUM_EN_ADDR_BYTES) != 0)
			rejectPacket = true;
	}

	return rejectPacket;
}

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

bool BMacEnet::_receivePackets(bool fDebugger)
{
    enet_dma_cmd_t      tmpCommand;
    struct mbuf *		packet;
    u_int32_t           i, j, last;
    int					receivedFrameSize = 0;
    u_int32_t           dmaCount[2], dmaResid[2], dmaStatus[2];
    u_int32_t			dmaChnlStatus;
    u_int16_t           rxPktStatus = 0;
    u_int32_t           badFrameCount;
    bool				reusePkt;
    bool				status;
	bool				useNetif = !fDebugger && netifEnabled;
	bool                doFlushQueue = false;
    u_int32_t			nextDesc;
	static const u_int32_t		lastResetValue = (u_int32_t)(-1);
       
    last         = lastResetValue;
    i            = rxCommandHead;

	while ( 1 )
	{
		reusePkt     = false;

		/*
		 * Collect the DMA residual counts/status for the two
		 * buffer segments.
		 */ 
		for ( j = 0; j < 2; j++ )
		{
			dmaResid[j]  = IOGetCCResult( &rxDMACommands[i].desc_seg[j] );
			dmaStatus[j] = dmaResid[j] >> 16;
			dmaResid[j] &= 0x0000ffff;
			dmaCount[j]  = IOGetCCOperation( &rxDMACommands[i].desc_seg[j] ) 
				& kdbdmaReqCountMask;
		}

#if 0
      IOLog("Ethernet(BMac): Rx NetBuf[%2d] = %08x Resid[0] = %04x Status[0] = %04x Resid[1] = %04x Status[1] = %04x\n\r",
                i, (int)nb_map(rxNetbuf[i]), dmaResid[0], dmaStatus[0], dmaResid[1], dmaStatus[1] );      
#endif 

		/* 
		 * If the current entry has not been written, then stop at this entry
		 */
		if (  !((dmaStatus[0] & kdbdmaBt) || (dmaStatus[1] & kdbdmaActive)) )
		{
			break;
		}

		/*
		 * The BMac Ethernet controller appends two bytes to each receive
		 * buffer containing the buffer 
		 * size and receive frame status.
		 * We locate these bytes by using the DMA residual counts.
		 */ 
		receivedFrameSize = dmaCount[0] - dmaResid[0] + dmaCount[1] - 
			((dmaStatus[0] & kdbdmaBt) ? dmaCount[1] : dmaResid[1]);

		if ( ( receivedFrameSize >= 2 ) &&
			 ( receivedFrameSize <= NETWORK_BUFSIZE ) )
		{
			/*
			 * Get the receive frame size as reported by the BMac controller
			 */
			rxPktStatus =  *(u_int16_t *)(mtod(rxMbuf[i], u_int32_t) +
				receivedFrameSize - 2);
			receivedFrameSize = rxPktStatus & kRxLengthMask;
		}

		/*
		 * Reject packets that are runts or that have other mutations.
		 */
		if ( receivedFrameSize < (ETHERMINPACKET - ETHERCRC) || 
			 receivedFrameSize > (ETHERMAXPACKET + ETHERCRC) ||
			 rxPktStatus & kRxAbortBit ||
			 _rejectBadUnicastPacket(mtod(rxMbuf[i], ether_header_t *))
			 )
		{
			if (useNetif) netStats->inputErrors++;
			reusePkt = true;
		}
		else if ( useNetif == false )
		{
			/*
			 * Always reuse packets in debugger mode. We also refuse to
			 * pass anything up the stack unless the driver is open. The
			 * hardware is enabled before the stack has opened us, to
			 * allow earlier debug interface registration. But we must
			 * not pass any packets up.
			 */
			reusePkt = true;
			if (fDebugger)
				_packetToDebugger(rxMbuf[i], receivedFrameSize);
		}

		/*
		 * Before we pass this packet up the networking stack. Make sure we
		 * can get a replacement. Otherwise, hold on to the current packet and
		 * increment the input error count.
		 * Thanks Justin!
		 */

		packet = 0;

		if ( reusePkt == false )
		{
			bool replaced;
		
			packet = replaceOrCopyPacket(&rxMbuf[i], receivedFrameSize, 
				&replaced);

			reusePkt = true;

			if (packet && replaced)
			{
				status = _updateDescriptorFromMbuf(rxMbuf[i], 
					&rxDMACommands[i], true);

				if (status)
				{
					reusePkt = false;
				}
				else
				{
					// Assume descriptor has not been corrupted.
					freePacket(rxMbuf[i]);	// release new packet.
					rxMbuf[i] = packet;		// get the old packet back.
					packet = 0;				// pass up nothing.
					IOLog("Ethernet(BMac): _updateDescriptorFromMbuf error\n");
				}
			}
			
			if (packet == 0)
				netStats->inputErrors++;
		}

		/*
		 * If we are reusing the existing mbuf, then refurbish the existing 
		 * DMA command \ descriptors by clearing the status/residual count 
		 * fields.
		 */
		if ( reusePkt )
		{
			for ( j=0; j < sizeof(enet_dma_cmd_t)/sizeof(IODBDMADescriptor); 
				j++ )
			{
				IOSetCCResult( &rxDMACommands[i].desc_seg[j], 0 );
			}
		}

		/*
		 * Keep track of the last receive descriptor processed
		 */            
		last = i;

		/*
		 * Implement ring wrap-around
		 */
		if (++i >= rxMaxCommand) i = 0;

		if (fDebugger)
		{
			break;
		}

		/*
		 * Transfer received packet to network
		 */
		if (packet)
		{
			KERNEL_DEBUG(DBG_BMAC_RXCOMPLETE | DBG_FUNC_NONE, (int) packet, 
				(int)receivedFrameSize, 0, 0, 0 );

			networkInterface->inputPacket(packet, receivedFrameSize, true);
			doFlushQueue = true;
			netStats->inputPackets++;
		}
	}

    /*
     * OK...this is a little messy
     *
     * We just processed a bunch of DMA receive descriptors. We are going to 
	 * exchange the current DMA stop command (rxCommandTail) with the last 
	 * receive descriptor we processed (last). This will make these list of 
	 * descriptors we just processed available. If we processed no receive 
	 * descriptors on this call then skip this exchange.
     */

#if 0
	IOLog( "Ethernet(BMac): Prev - Rx Head = %2d Rx Tail = %2d Rx Last = %2d\n\r", rxCommandHead, rxCommandTail, last );
#endif

	if ( last != lastResetValue )
	{
		/*
		 * Save the contents of the last receive descriptor processed.
		 */
		packet   	= rxMbuf[last];
		tmpCommand	= rxDMACommands[last];

		/*
		 * Write a DMA stop command into this descriptor slot
		 */
		rxDMACommands[last].desc_seg[0] = dbdmaCmd_Stop;
		rxDMACommands[last].desc_seg[1] = dbdmaCmd_Nop;  
		rxMbuf[last] = 0;

		/*
		 * Replace the previous DMA stop command with the last receive 
		 * descriptor processed.
		 * 
		 * The new DMA command is written into the channel program so that the
		 * command word for the old Stop command is overwritten last. This 
		 * prevents the DMA engine from executing a partially written channel 
		 * command.
		 * 
		 * Note: When relocating the descriptor, we must update its branch 
		 * field to reflect its new location.
		 */
		nextDesc = rxDMACommandsPhys + 
			(int) &rxDMACommands[rxCommandTail + 1] - (int)rxDMACommands;
		IOSetCCCmdDep( &tmpCommand.desc_seg[0], nextDesc );

		bcopy( (u_int32_t *) &tmpCommand + 1,
               (u_int32_t *) &rxDMACommands[rxCommandTail] + 1,
               sizeof(enet_dma_cmd_t) - sizeof(u_int32_t) );

		rxMbuf[rxCommandTail] = packet;

		rxDMACommands[rxCommandTail].desc_seg[0].operation = 
			tmpCommand.desc_seg[0].operation;

		/*
		 * Update rxCommmandTail to point to the new Stop command. Update 
		 * rxCommandHead to point to the next slot in the ring past the Stop 
		 * command 
		 */
		rxCommandTail = last;
		rxCommandHead = i;
    }

    /*
     * Update receive error statistics
     */
    badFrameCount =  ReadBigMacRegister(ioBaseEnet, kFECNT) 
                       + ReadBigMacRegister(ioBaseEnet, kAECNT)
                           + ReadBigMacRegister(ioBaseEnet, kLECNT);

    /*
     * Clear Hardware counters
     */
    WriteBigMacRegister(ioBaseEnet, kFECNT, 0);
    WriteBigMacRegister(ioBaseEnet, kAECNT, 0);
    WriteBigMacRegister(ioBaseEnet, kLECNT, 0);

	if (badFrameCount && useNetif)
		netStats->inputErrors += badFrameCount;

    /*
     * Check for error conditions that may cause the receiver to stall
     */
    dmaChnlStatus = IOGetDBDMAChannelStatus( ioBaseEnetRxDMA );
 
    if ( dmaChnlStatus & kdbdmaDead )
	{
		if (useNetif) netStats->inputErrors++;
		IOLog( "Ethernet(BMac): Rx DMA Error - Status = %04x\n\r", 
			dmaChnlStatus );
		_restartReceiver();
	}
	else
	{
		/*
		 * Tap the DMA to wake it up
		 */
		IODBDMAContinue( ioBaseEnetRxDMA );
    }

#if 0
    IOLog( "Ethernet(BMac): New  - Rx Head = %2d Rx Tail = %2d\n\r", rxCommandHead, rxCommandTail );
#endif

    return doFlushQueue;
}
 
/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

bool BMacEnet::_transmitInterruptOccurred()
{
    u_int32_t	dmaStatus;
    u_int32_t	collisionCount;
	u_int32_t	badFrameCount;
	bool		fServiced = false;

    while ( 1 )
    {
		/*
		 * Check the status of the last descriptor in this entry to see if
		 * the DMA engine completed this entry.
		 */
		dmaStatus = IOGetCCResult(
			&(txDMACommands[txCommandHead].desc_seg[1])) >> 16;

		if ( !(dmaStatus & kdbdmaActive) )
		{
			break;
		}

		if (netifEnabled) netStats->outputPackets++;

		fServiced = true;

      	KERNEL_DEBUG(DBG_BMAC_TXCOMPLETE | DBG_FUNC_NONE,
			(int)txMbuf[txCommandHead],
			(int)txMbuf[txCommandHead]->m_pkthdr.len, 0, 0, 0 );

		/*
		 * Free the mbuf we just transmitted.
		 *
		 * If it is the debugger packet, just remove it from the ring.
		 * and reuse the same packet for the next sendPacket() request.
		 */
		if (txMbuf[txCommandHead] != txDebuggerPkt)
		{
			freePacket( txMbuf[txCommandHead] );
		}
		txMbuf[txCommandHead] = NULL;

		if ( ++(txCommandHead) >= txMaxCommand )
			txCommandHead = 0;
    }

    /* 
     * Increment transmit error statistics
     */
    collisionCount = ReadBigMacRegister(ioBaseEnet, kNCCNT ); 

    WriteBigMacRegister( ioBaseEnet, kNCCNT, 0 );

    badFrameCount = ReadBigMacRegister(ioBaseEnet, kEXCNT )
                      + ReadBigMacRegister(ioBaseEnet, kLTCNT );

    WriteBigMacRegister( ioBaseEnet, kEXCNT, 0 );
    WriteBigMacRegister( ioBaseEnet, kLTCNT, 0 );

	if (netifEnabled) {
		netStats->collisions += collisionCount;
		netStats->outputErrors += badFrameCount;
	}

    /*
     * Check for error conditions that may cause the transmitter to stall
     */
    dmaStatus = IOGetDBDMAChannelStatus( ioBaseEnetTxDMA );
 
    if ( dmaStatus & kdbdmaDead )
    {
		if (netifEnabled) netStats->outputErrors++;
		IOLog( "Ethernet(BMac): Tx DMA Error - Status = %04x\n\r", dmaStatus );
		_restartTransmitter();
		fServiced = true;
    }

    return fServiced;
}

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

bool BMacEnet::_debugTransmitInterruptOccurred()
{
    u_int32_t	dmaStatus;
    u_int32_t	badFrameCount;
	bool        fServiced = false;

	// Set the debugTxPoll flag to indicate the debugger was active
	// and some cleanup may be needed when the driver returns to
	// normal operation.
	//
	debugTxPoll = true;

    while ( 1 )
    {
		/*
		 * Check the status of the last descriptor in this entry to see if
		 * the DMA engine completed this entry.
		 */
		dmaStatus = IOGetCCResult(
			&(txDMACommands[txCommandHead].desc_seg[1])) >> 16;

		if ( !(dmaStatus & kdbdmaActive) )
		{
			break;
		}

		fServiced = true;

      	KERNEL_DEBUG(DBG_BMAC_TXCOMPLETE | DBG_FUNC_NONE,
			(int)txMbuf[txCommandHead],
			(int)txMbuf[txCommandHead]->m_pkthdr.len, 0, 0, 0 );

		/*
		 * Free the mbuf we just transmitted.
		 *
		 * If it is the debugger packet, just remove it from the ring.
		 * and reuse the same packet for the next sendPacket() request.
		 */
		if (txMbuf[txCommandHead] != txDebuggerPkt) {
			//
			// While in debugger mode, do not touch the mbuf pool.
			// Queue any used mbufs to a local queue. This queue
			// will get flushed after we exit from debugger mode.
			//
			// During continuous debugger transmission and
			// interrupt polling, we expect only the txDebuggerPkt
			// to show up on the transmit mbuf ring.
			//
			debugQueue->enqueue( txMbuf[txCommandHead] );
		}
		txMbuf[txCommandHead] = NULL;

		if ( ++(txCommandHead) >= txMaxCommand )
			txCommandHead = 0;
    }

    /* 
     * Clear transmit error statistics
     */
    badFrameCount = ReadBigMacRegister(ioBaseEnet, kNCCNT ); 
    WriteBigMacRegister( ioBaseEnet, kNCCNT, 0 );
    
    badFrameCount = ReadBigMacRegister(ioBaseEnet, kEXCNT )
                      + ReadBigMacRegister(ioBaseEnet, kLTCNT );
    WriteBigMacRegister( ioBaseEnet, kEXCNT, 0 );
    WriteBigMacRegister( ioBaseEnet, kLTCNT, 0 );

    /*
     * Check for error conditions that may cause the transmitter to stall
     */
    dmaStatus = IOGetDBDMAChannelStatus( ioBaseEnetTxDMA );
 
    if ( dmaStatus & kdbdmaDead )
    {
		IOLog( "Ethernet(BMac): Tx DMA Error - Status = %04x\n\r", dmaStatus );
		_restartTransmitter();
		fServiced = true;
    }

    return fServiced;
}
	
/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

bool
BMacEnet::_updateDescriptorFromMbuf(struct mbuf * m,  enet_dma_cmd_t *desc,
		bool isReceive)
{
    u_int32_t		nextDesc = 0;
	u_int32_t		waitMask = 0;   
	int 			segments;
	struct IOPhysicalSegment segVector[2];

	segments = mbufCursor->getPhysicalSegmentsWithCoalesce(m, segVector);
	
	if ((!segments) || (segments > 2)) {
		IOLog("BMac: _updateDescriptorFromMbuf error, %d segments\n", 
			segments);
		return false;
	}

	// IOLog("segments: %d\n", segments);

    if ( isReceive || chipId >= kCHIPID_PaddingtonXmitStreaming )
    {
        waitMask = kdbdmaWaitNever;
    }
    else
    {
        waitMask = kdbdmaWaitIfFalse;
    }
   
    if ( segments == 1 )
    {
		IOMakeDBDMADescriptor( (&desc->desc_seg[0]),
							((isReceive) ? kdbdmaInputLast : kdbdmaOutputLast), 
							(kdbdmaKeyStream0),
							(kdbdmaIntNever),
							(kdbdmaBranchNever),
							(waitMask),
							(segVector[0].length),
							(segVector[0].location)  );
  
		desc->desc_seg[1] = (isReceive) ? dbdmaCmd_NopWInt : dbdmaCmd_Nop;
    }
    else
	{
		if ( isReceive ) 
		{
			nextDesc = rxDMACommandsPhys + (int)desc - (int)rxDMACommands + 
				sizeof(enet_dma_cmd_t);
		}

		IOMakeDBDMADescriptorDep( (&desc->desc_seg[0]),
							((isReceive) ? kdbdmaInputMore : kdbdmaOutputMore), 
							(kdbdmaKeyStream0),
							((isReceive) ? kdbdmaIntIfTrue : kdbdmaIntNever),
							((isReceive) ? kdbdmaBranchIfTrue : 
								kdbdmaBranchNever),
							(kdbdmaWaitNever),
							(segVector[0].length),
							(segVector[0].location),  
							nextDesc   ); 

		IOMakeDBDMADescriptor( (&desc->desc_seg[1]),
							((isReceive) ? kdbdmaInputLast : kdbdmaOutputLast), 
							(kdbdmaKeyStream0),
							((isReceive) ? kdbdmaIntAlways : kdbdmaIntNever),
							(kdbdmaBranchNever),
							(waitMask),
							(segVector[1].length),
							(segVector[1].location)  );
    }

    return true;
}

#ifdef DEBUG
/*
 * Useful for testing. 
 */
void BMacEnet::_dump_srom()
{
    unsigned short data;
    int i;
	
    for (i = 0; i < 128; i++)	
    {
		reset_and_select_srom(ioBaseEnet);
		data = read_srom(ioBaseEnet, i, sromAddressBits);
		IOLog("Ethernet(BMac): %x = %x ", i, data);
		if (i % 10 == 0) IOLog("\n");
    }
}

void BMacEnet::_dumpDesc(void * addr, u_int32_t size)
{
    u_int32_t		i;
    unsigned long	*p;
    vm_offset_t		paddr;

    _IOPhysicalFromVirtual( (vm_offset_t) addr, (vm_offset_t *)&paddr );

    p = (unsigned long *)addr;

    for ( i=0; i < size/sizeof(IODBDMADescriptor); i++, p+=4, 
		paddr+=sizeof(IODBDMADescriptor) )
    {
        IOLog("Ethernet(BMac): %08x(v) %08x(p):  %08x %08x %08x %08x\n\r",
              (int)p,
              (int)paddr,
              (int)OSReadSwapInt32(p, 0),   (int)OSReadSwapInt32(p, 4),
              (int)OSReadSwapInt32(p, 8),   (int)OSReadSwapInt32(p, 12) );
    }
}

void BMacEnet::_dumpRegisters()
{
    u_int16_t	dataValue;

    IOLog("\nEthernet(BMac): IO Address = %08x", (int)ioBaseEnet );

    dataValue = ReadBigMacRegister(ioBaseEnet, kXIFC);
    IOLog("\nEthernet(BMac): Read Register %04x Transceiver I/F = %04x", kXIFC, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kSTAT);
    IOLog("\nEthernet(BMac): Read Register %04x Int Events      = %04x", kSTAT, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kINTDISABLE);
    IOLog("\nEthernet(BMac): Read Register %04x Int Disable     = %04x", kINTDISABLE, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kTXRST);
    IOLog("\nEthernet(BMac): Read Register %04x Tx Reset        = %04x", kTXRST, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kTXCFG);
    IOLog("\nEthernet(BMac): Read Register %04x Tx Config       = %04x", kTXCFG, dataValue );
    IOLog("\nEthernet(BMac): -------------------------------------------------------" );

    dataValue = ReadBigMacRegister(ioBaseEnet, kIPG1);
    IOLog("\nEthernet(BMac): Read Register %04x IPG1            = %04x", kIPG1, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kIPG2);
    IOLog("\nEthernet(BMac): Read Register %04x IPG2            = %04x", kIPG2, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kALIMIT);
    IOLog("\nEthernet(BMac): Read Register %04x Attempt Limit   = %04x", kALIMIT, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kSLOT);
    IOLog("\nEthernet(BMac): Read Register %04x Slot Time       = %04x", kSLOT, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kPALEN);
    IOLog("\nEthernet(BMac): Read Register %04x Preamble Length = %04x", kPALEN, dataValue );

    IOLog("\nEthernet(BMac): -------------------------------------------------------" );
    dataValue = ReadBigMacRegister(ioBaseEnet, kPAPAT);
    IOLog("\nEthernet(BMac): Read Register %04x Preamble Pattern         = %04x", kPAPAT, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kTXSFD);
    IOLog("\nEthernet(BMac): Read Register %04x Tx Start Frame Delimeter = %04x", kTXSFD, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kJAM);
    IOLog("\nEthernet(BMac): Read Register %04x Jam Size                 = %04x", kJAM, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kTXMAX);
    IOLog("\nEthernet(BMac): Read Register %04x Tx Max Size              = %04x", kTXMAX, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kTXMIN);
    IOLog("\nEthernet(BMac): Read Register %04x Tx Min Size              = %04x", kTXMIN, dataValue );
    IOLog("\nEthernet(BMac): -------------------------------------------------------" );

    dataValue = ReadBigMacRegister(ioBaseEnet, kPAREG);
    IOLog("\nEthernet(BMac): Read Register %04x Peak Attempts           = %04x", kPAREG, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kDCNT);
    IOLog("\nEthernet(BMac): Read Register %04x Defer Timer             = %04x", kDCNT, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kNCCNT);
    IOLog("\nEthernet(BMac): Read Register %04x Normal Collision Count  = %04x", kNCCNT, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kNTCNT);
    IOLog("\nEthernet(BMac): Read Register %04x Network Collision Count = %04x", kNTCNT, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kEXCNT);
    IOLog("\nEthernet(BMac): Read Register %04x Excessive Coll Count    = %04x", kEXCNT, dataValue );
    IOLog("\nEthernet(BMac): -------------------------------------------------------" );

    dataValue = ReadBigMacRegister(ioBaseEnet, kLTCNT);
    IOLog("\nEthernet(BMac): Read Register %04x Late Collision Count = %04x", kLTCNT, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kRSEED);
    IOLog("\nEthernet(BMac): Read Register %04x Random Seed          = %04x", kRSEED, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kTXSM);
    IOLog("\nEthernet(BMac): Read Register %04x Tx State Machine     = %04x", kTXSM, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kRXRST);
    IOLog("\nEthernet(BMac): Read Register %04x Rx Reset             = %04x", kRXRST, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kRXCFG);
    IOLog("\nEthernet(BMac): Read Register %04x Rx Config            = %04x", kRXCFG, dataValue );
    IOLog("\nEthernet(BMac): -------------------------------------------------------" );

    dataValue = ReadBigMacRegister(ioBaseEnet, kRXMAX);
    IOLog("\nEthernet(BMac): Read Register %04x Rx Max Size         = %04x", kRXMAX, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kRXMIN);
    IOLog("\nEthernet(BMac): Read Register %04x Rx Min Size         = %04x", kRXMIN, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kMADD2);
    IOLog("\nEthernet(BMac): Read Register %04x Mac Address 2       = %04x", kMADD2, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kMADD1);
    IOLog("\nEthernet(BMac): Read Register %04x Mac Address 1       = %04x", kMADD1, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kMADD0);
    IOLog("\nEthernet(BMac): Read Register %04x Mac Address 0       = %04x", kMADD0, dataValue );
    IOLog("\nEthernet(BMac): -------------------------------------------------------" );

    dataValue = ReadBigMacRegister(ioBaseEnet, kFRCNT);
    IOLog("\nEthernet(BMac): Read Register %04x Rx Frame Counter    = %04x", kFRCNT, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kLECNT);
    IOLog("\nEthernet(BMac): Read Register %04x Rx Length Error Cnt = %04x", kLECNT, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kAECNT);
    IOLog("\nEthernet(BMac): Read Register %04x Alignment Error Cnt = %04x", kAECNT, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kFECNT);
    IOLog("\nEthernet(BMac): Read Register %04x FCS Error Cnt       = %04x", kFECNT, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kRXSM);
    IOLog("\nEthernet(BMac): Read Register %04x Rx State Machine    = %04x", kRXSM, dataValue );
    IOLog("\nEthernet(BMac): -------------------------------------------------------" );

    dataValue = ReadBigMacRegister(ioBaseEnet, kRXCV);
    IOLog("\nEthernet(BMac): Read Register %04x Rx Code Violation = %04x", kRXCV, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kHASH3);
    IOLog("\nEthernet(BMac): Read Register %04x Hash 3            = %04x", kHASH3, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kHASH2);
    IOLog("\nEthernet(BMac): Read Register %04x Hash 2            = %04x", kHASH2, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kHASH1);
    IOLog("\nEthernet(BMac): Read Register %04x Hash 1            = %04x", kHASH1, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kHASH0);
    IOLog("\nEthernet(BMac): Read Register %04x Hash 0            = %04x", kHASH0, dataValue );
    IOLog("\n-------------------------------------------------------" );

    dataValue = ReadBigMacRegister(ioBaseEnet, kAFR2);
    IOLog("\nEthernet(BMac): Read Register %04x Address Filter 2   = %04x", kAFR2, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kAFR1);
    IOLog("\nEthernet(BMac): Read Register %04x Address Filter 1   = %04x", kAFR1, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kAFR0);
    IOLog("\nEthernet(BMac): Read Register %04x Address Filter 0   = %04x", kAFR0, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kAFCR);
    IOLog("\nEthernet(BMac): Read Register %04x Adress Filter Mask = %04x", kAFCR, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kTXFIFOCSR);
    IOLog("\nEthernet(BMac): Read Register %04x Tx FIFO CSR        = %04x", kTXFIFOCSR, dataValue );
    IOLog("\n-------------------------------------------------------" );

    dataValue = ReadBigMacRegister(ioBaseEnet, kTXTH);
    IOLog("\nEthernet(BMac): Read Register %04x Tx Threshold  = %04x", kTXTH, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kRXFIFOCSR);
    IOLog("\nEthernet(BMac): Read Register %04x Rx FIFO CSR   = %04x", kRXFIFOCSR, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kMEMADD);
    IOLog("\nEthernet(BMac): Read Register %04x Mem Addr      = %04x", kMEMADD, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kMEMDATAHI);
    IOLog("\nEthernet(BMac): Read Register %04x Mem Data High = %04x", kMEMDATAHI, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kMEMDATALO);
    IOLog("\nEthernet(BMac): Read Register %04x Mem Data Low  = %04x", kMEMDATALO, dataValue );
    IOLog("\n-------------------------------------------------------" );

    dataValue = ReadBigMacRegister(ioBaseEnet, kXCVRIF);
    IOLog("\nEthernet(BMac): Read Register %04x Transceiver IF Control = %04x", kXCVRIF, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kCHIPID);
    IOLog("\nEthernet(BMac): Read Register %04x Chip ID                = %04x", kCHIPID, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kMIFCSR);
    IOLog("\nEthernet(BMac): Read Register %04x MII CSR                = %04x", kMIFCSR, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kSROMCSR);
    IOLog("\nEthernet(BMac): Read Register %04x SROM CSR               = %04x", kSROMCSR, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kTXPNTR);
    IOLog("\nEthernet(BMac): Read Register %04x Tx Pointer             = %04x", kTXPNTR, dataValue );

    dataValue = ReadBigMacRegister(ioBaseEnet, kRXPNTR);
    IOLog("\nEthernet(BMac): Read Register %04x Rx Pointer             = %04x", kRXPNTR, dataValue );
    IOLog("\nEthernet(BMac): -------------------------------------------------------\n" );
}
#endif DEBUG


/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

IOReturn BMacEnet::getHardwareAddress(IOEthernetAddress *ea)
{
    int i;
    unsigned short data;

    for (i = 0; i < (unsigned short)sizeof(*ea)/2; i++)	
    {
		reset_and_select_srom(ioBaseEnet);
		data = read_srom(ioBaseEnet, i + enetAddressOffset/2, sromAddressBits);
		ea->bytes[2*i]   = reverseBitOrder(data & 0x0ff);
		ea->bytes[2*i+1] = reverseBitOrder((data >> 8) & 0x0ff);
    }
	
	return kIOReturnSuccess;
}

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

#define ENET_CRCPOLY 0x04c11db7

/* Real fast bit-reversal algorithm, 6-bit values */
static int reverse6[] = 
{	0x0,0x20,0x10,0x30,0x8,0x28,0x18,0x38,
	0x4,0x24,0x14,0x34,0xc,0x2c,0x1c,0x3c,
	0x2,0x22,0x12,0x32,0xa,0x2a,0x1a,0x3a,
	0x6,0x26,0x16,0x36,0xe,0x2e,0x1e,0x3e,
	0x1,0x21,0x11,0x31,0x9,0x29,0x19,0x39,
	0x5,0x25,0x15,0x35,0xd,0x2d,0x1d,0x3d,
	0x3,0x23,0x13,0x33,0xb,0x2b,0x1b,0x3b,
	0x7,0x27,0x17,0x37,0xf,0x2f,0x1f,0x3f
};

static u_int32_t crc416(unsigned int current, unsigned short nxtval )
{
    register unsigned int counter;
    register int highCRCBitSet, lowDataBitSet;

    /* Swap bytes */
    nxtval = ((nxtval & 0x00FF) << 8) | (nxtval >> 8);

	/* Compute bit-by-bit */
	for (counter = 0; counter != 16; ++counter)
		{	/* is high CRC bit set? */
		if ((current & 0x80000000) == 0)	
			highCRCBitSet = 0;
		else
			highCRCBitSet = 1;
		
		current = current << 1;
	
		if ((nxtval & 0x0001) == 0)
			lowDataBitSet = 0;
		else
			lowDataBitSet = 1;

		nxtval = nxtval >> 1;
	
		/* do the XOR */
		if (highCRCBitSet ^ lowDataBitSet)
			current = current ^ ENET_CRCPOLY;
    }

    return current;
}

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

static u_int32_t mace_crc(unsigned short *address)
{	
    register u_int32_t newcrc;

    newcrc = crc416(0xffffffff, *address);	/* address bits 47 - 32 */
    newcrc = crc416(newcrc, address[1]);	/* address bits 31 - 16 */
    newcrc = crc416(newcrc, address[2]);	/* address bits 15 - 0  */

    return(newcrc);
}

/*
 * Clear the hash table filter.  
 *  
 */
void BMacEnet::_resetHashTableMask()
{
	bzero(hashTableUseCount, sizeof(hashTableUseCount));
	bzero(hashTableMask, sizeof(hashTableMask));
}

/*
 * Add requested mcast addr to BMac's hash table filter.  
 *  
 */
void BMacEnet::_addToHashTableMask(u_int8_t *addr)
{	
    u_int32_t	 crc;
    u_int16_t	 mask;

    crc = mace_crc((unsigned short *)addr)&0x3f; /* Big-endian alert! */
    crc = reverse6[crc];	/* Hyperfast bit-reversing algorithm */
    if (hashTableUseCount[crc]++)	
		return;				/* This bit is already set */
    mask = crc % 16;
    mask = (unsigned short)1 << mask;
    hashTableMask[crc/16] |= mask;
}

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

void BMacEnet::_removeFromHashTableMask(u_int8_t *addr)
{
    unsigned int 	crc;
    u_int16_t 	mask;

    /* Now, delete the address from the filter copy, as indicated */
    crc = mace_crc((unsigned short *)addr)&0x3f; /* Big-endian alert! */
    crc = reverse6[crc];	/* Hyperfast bit-reversing algorithm */
	if (hashTableUseCount[crc] == 0)
		return;			/* That bit wasn't in use! */

	if (--hashTableUseCount[crc])
		return;			/* That bit is still in use */

	mask = crc % 16;
    mask = (u_int16_t)1 << mask; /* To turn off bit */
    hashTableMask[crc/16] &= ~mask;
}

/*
 * Sync the adapter with the software copy of the multicast mask
 *  (logical address filter).
 */
void BMacEnet::_updateBMacHashTableMask()
{
    u_int16_t 		rxCFGReg;

    rxCFGReg = ReadBigMacRegister(ioBaseEnet, kRXCFG);
    WriteBigMacRegister(ioBaseEnet, kRXCFG,
		rxCFGReg & ~(kRxMACEnable | kRxHashFilterEnable) );

    while ( ReadBigMacRegister(ioBaseEnet, kRXCFG) &
		(kRxMACEnable | kRxHashFilterEnable) )
		;

    WriteBigMacRegister(ioBaseEnet, kHASH0, hashTableMask[0]); 	// bits 15 - 0
    WriteBigMacRegister(ioBaseEnet, kHASH1, hashTableMask[1]); 	// bits 31 - 16
    WriteBigMacRegister(ioBaseEnet, kHASH2, hashTableMask[2]); 	// bits 47 - 32
    WriteBigMacRegister(ioBaseEnet, kHASH3, hashTableMask[3]); 	// bits 63 - 48

    rxCFGReg |= kRxHashFilterEnable;
    WriteBigMacRegister(ioBaseEnet, kRXCFG, rxCFGReg );
}
