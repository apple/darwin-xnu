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
 * Copyright (c) 1998-1999 Apple Computer
 *
 * Hardware independent (relatively) code for the Sun GEM Ethernet Controller 
 *
 * HISTORY
 *
 * dd-mmm-yy     
 *  Created.
 *
 */

//void call_kdp(void);

#include "UniNEnetPrivate.h"

#define super IOEthernetController

OSDefineMetaClassAndStructors( UniNEnet, IOEthernetController )

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

bool UniNEnet::init(OSDictionary * properties)
{
    if ( super::init(properties) == false )
        return false;

    /*
     * Initialize my ivars.
     */
    phyId          = 0xff;
    linkStatusPrev = kLinkStatusUnknown;

    return true;
}

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

bool UniNEnet::start(IOService * provider)
{    
    OSString		*matchEntry;
    
    keyLargo_resetUniNEthernetPhy = OSSymbol::withCString("keyLargo_resetUniNEthernetPhy");

    // Wait for KeyLargo to show up.
    keyLargo = waitForService(serviceMatching("KeyLargo"));
    if (keyLargo == 0) return false;

    nub = OSDynamicCast(IOPCIDevice, provider);

    if (!nub || !super::start(provider))
    {
        return false;
    }

    // Create spinlock to protect TxElementQueue.

	txQueueLock = IOSimpleLockAlloc();
	if ( txQueueLock == 0 ) return false;
	IOSimpleLockInit(txQueueLock);

    transmitQueue = (IOGatedOutputQueue *) getOutputQueue();
    if (!transmitQueue) 
    {
        IOLog("Ethernet(UniN): Output queue initialization failed\n");
        return false;
    }
    transmitQueue->retain();

    /*
     * Allocate debug queue. This stores packets retired from the TX ring
     * by the polling routine. We cannot call freePacket() or m_free() within
     * the debugger context.
     *
     * The capacity of the queue is set at maximum to prevent the queue from
     * calling m_free() due to over-capacity. But we don't expect the size
     * of the queue to grow too large.
     */
    debugQueue = IOPacketQueue::withCapacity((UInt) -1);
    if (!debugQueue)
    {
        return false;
    }
    
    /*
     * Allocate a IOMbufBigMemoryCursor instance. Currently, the maximum
     * number of segments is set to 1. The maximum length for each segment
     * is set to the maximum ethernet frame size (plus padding).
     */    
    mbufCursor = IOMbufBigMemoryCursor::withSpecification(NETWORK_BUFSIZE, 1);
    if (!mbufCursor) 
    {
        IOLog("Ethernet(UniN): IOMbufBigMemoryCursor allocation failure\n");
        return false;
    }

    matchEntry = OSDynamicCast( OSString, getProperty( gIONameMatchedKey ) );
    if ( matchEntry == 0 )
    {
        IOLog("Ethernet(UniN): Cannot obtain matching property.\n");
        return false;
    }

    if ( matchEntry->isEqualTo( "gmac" ) == true )
    {
	callPlatformFunction("EnableUniNEthernetClock", true,
			     (void *)true, 0, 0, 0);
    }

    /*
     * BUS MASTER, MEM I/O Space, MEM WR & INV
     */
    nub->configWrite32( 0x04, 0x16 );

    /*
     *  set Latency to Max , cache 32
     */
    nub->configWrite32( 0x0C, ((2 + (kGEMBurstSize * (0+1)))<< 8) | (CACHE_LINE_SIZE >> 2) );

    ioMapEnet = nub->mapDeviceMemoryWithRegister( 0x10 );
    if ( ioMapEnet == NULL )
    {
        return false;
    }
    ioBaseEnet = (volatile IOPPCAddress)ioMapEnet->getVirtualAddress();
	fpRegs = (GMAC_Registers*) ioBaseEnet;
    phyId             = (UInt8) -1;
    
    /*
     * Get a reference to the IOWorkLoop in our superclass.
     */
    IOWorkLoop * myWorkLoop = getWorkLoop();

    /*
     * Allocate three IOInterruptEventSources.
     */
    interruptSource = IOInterruptEventSource::interruptEventSource(
                        (OSObject *) this,
                        (IOInterruptEventAction) &UniNEnet::interruptOccurred,
                        (IOService *)            provider,
                        (int)                    0 );

    if ( interruptSource == NULL )
    {
        IOLog("Ethernet(UniN): Couldn't allocate Interrupt event source\n");    
        return false;
    }

    if ( myWorkLoop->addEventSource( interruptSource ) != kIOReturnSuccess )
    {
        IOLog("Ethernet(UniN): Couldn't add Interrupt event source\n");    
        return false;
    }     

        
    timerSource = IOTimerEventSource::timerEventSource
        (this, (IOTimerEventSource::Action) &UniNEnet::timeoutOccurred);
    if ( timerSource == NULL )
    {
        IOLog("Ethernet(UniN): Couldn't allocate timer event source\n");
        return false;
    }

    if ( myWorkLoop->addEventSource( timerSource ) != kIOReturnSuccess )
    {
        IOLog("Ethernet(UniN): Couldn't add timer event source\n");        
        return false;
    }     

    MGETHDR(txDebuggerPkt, M_DONTWAIT, MT_DATA);
    
    if (!txDebuggerPkt) 
    {
        IOLog("Ethernet(UniN): Couldn't allocate KDB buffer\n");
        return false;
    }

    /*
     * Perform a hardware reset.
     */
    if ( resetAndEnable(false) == false ) 
    {
        IOLog("Ethernet(UniN): resetAndEnable() failed\n");
        return false;
    }

    /*
     * Cache my MAC address.
     */
    if ( getHardwareAddress(&myAddress) != kIOReturnSuccess )
    {
        IOLog("Ethernet(UniN): getHardwareAddress() failed\n");
        return false;
    }

    /*
     * Allocate memory for ring buffers.
     */
    if ( allocateMemory() == false) 
    {
        IOLog("Ethernet(UniN): allocateMemory() failed\n");    
        return false;
    }

    if ( createMediumTables() == false )
    {
        IOLog("Ethernet(UniN): createMediumTables() failed\n");    
        return false;
    }

    /*
     * Attach an IOEthernetInterface client. But don't registers it just yet.
     */
    if ( !attachInterface((IONetworkInterface **) &networkInterface, false) )
    {
        IOLog("Ethernet(UniN): attachInterface() failed\n");      
        return false;
    }

    /*
     * Attach a kernel debugger client.
     */
	attachDebuggerClient(&debugger);

    /*
     * Ready to service interface requests.
     */
    networkInterface->registerService();

    return true;
}

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

bool UniNEnet::configureInterface(IONetworkInterface * netif)
{
    IONetworkData * nd;

    if ( super::configureInterface( netif ) == false )
        return false;

    /*
     * Grab a pointer to the statistics structure in the interface.
     */
    nd = netif->getNetworkData( kIONetworkStatsKey );
    if (!nd || !(fpNetStats = (IONetworkStats *) nd->getBuffer()))
    {
        IOLog("EtherNet(UniN): invalid network statistics\n");
        return false;
    }

		// Get the Ethernet statistics structure:
	nd = netif->getParameter( kIOEthernetStatsKey );
	if ( !nd || !(fpEtherStats = (IOEthernetStats*)nd->getBuffer()) )
	{
        IOLog("EtherNet(UniN): invalid ethernet statistics\n");
        return false;
	}

    /*
     * Set the driver/stack reentrancy flag. This is meant to reduce
     * context switches. May become irrelevant in the future.
     */
    return true;
}/* end configureInterface */


/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

void UniNEnet::free()
{
    TxQueueElement * txElement;
    
    resetAndEnable(false);

	if (debugger)
		debugger->release();

    if (getWorkLoop())
    {
        getWorkLoop()->disableAllEventSources();
    }
    
    if (timerSource)
    {
        timerSource->release();
        timerSource = 0;
    }
    
    if (interruptSource)
    {
        interruptSource->release();
    }
    
    if (txDebuggerPkt)
    {
        freePacket(txDebuggerPkt);
    }
    
    if (transmitQueue)
    {
        transmitQueue->release();
    }
    
    if (debugQueue)
    {
        debugQueue->release();
    }
    
    if (networkInterface)
    {
        networkInterface->release();
    }
    
    if (mbufCursor)
    {
        mbufCursor->release();
    }
    
    if ( mediumDict )
    {
        mediumDict->release();
    }

    while ( ( txElement = getTxElement() ) )
    {
        IOFree( txElement, sizeof(TxQueueElement) );
    }
    
    if ( ioMapEnet )
    {
        ioMapEnet->release();
    }     

    if ( dmaCommands != 0 )
    {
        IOFreeContiguous( (void *)dmaCommands, dmaCommandsSize );
    }

    if ( workLoop )
    {
        workLoop->release();
        workLoop = 0;
    }

    if ( txQueueLock )
    {
        IOSimpleLockFree( txQueueLock );
        txQueueLock = 0;
    }

    super::free();
}

/*-------------------------------------------------------------------------
 * Override IONetworkController::createWorkLoop() method and create
 * a workloop.
 *
 *-------------------------------------------------------------------------*/

bool UniNEnet::createWorkLoop()
{
    workLoop = IOWorkLoop::workLoop();

    return ( workLoop != 0 );
}

/*-------------------------------------------------------------------------
 * Override IOService::getWorkLoop() method to return our workloop.
 *
 *
 *-------------------------------------------------------------------------*/

IOWorkLoop * UniNEnet::getWorkLoop() const
{
    return workLoop;
}

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

void UniNEnet::interruptOccurred(IOInterruptEventSource * src, int /*count*/)
{
    IODebuggerLockState	lockState;
	UInt32				interruptStatus;
	bool				doFlushQueue;
	bool				doService;


    if ( ready == false ) return;

    do 
    {
		lockState = IODebuggerLock( this );

        interruptStatus = READ_REGISTER( Status )
						& ( kStatus_TX_INT_ME | kStatus_RX_DONE );

        doService  = false;

        if ( interruptStatus & kStatus_TX_INT_ME )
        {
            txWDInterrupts++;
            KERNEL_DEBUG(DBG_GEM_TXIRQ | DBG_FUNC_START, 0, 0, 0, 0, 0 );
            doService = transmitInterruptOccurred();
            KERNEL_DEBUG(DBG_GEM_TXIRQ | DBG_FUNC_END,   0, 0, 0, 0, 0 );
			ETHERNET_STAT_ADD( dot3TxExtraEntry.interrupts );
        }

        doFlushQueue = false;

        if ( interruptStatus & kStatus_RX_DONE )
        {
            rxWDInterrupts++;
            KERNEL_DEBUG(DBG_GEM_RXIRQ | DBG_FUNC_START, 0, 0, 0, 0, 0 );
            doFlushQueue = receiveInterruptOccurred();
            KERNEL_DEBUG(DBG_GEM_RXIRQ | DBG_FUNC_END,   0, 0, 0, 0, 0 );
			ETHERNET_STAT_ADD( dot3RxExtraEntry.interrupts );
        }

		IODebuggerUnlock( lockState );

	/*
	 * Submit all received packets queued up by _receiveInterruptOccurred()
	 * to the network stack. The up call is performed without holding the
	 * debugger lock.
	 */
	if (doFlushQueue)
	{
	    networkInterface->flushInputQueue();
	}

	/*
	 * Make sure the output queue is not stalled.
	 */
	if (doService && netifEnabled)
	{
	    transmitQueue->service();
	}
    }
    while ( interruptStatus );

//  interruptSource->enable();
	return;
}/* end interruptOccurred */


/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

UInt32 UniNEnet::outputPacket(struct mbuf * pkt, void * param)
{
    UInt32 ret = kIOReturnOutputSuccess;

    KERNEL_DEBUG( DBG_GEM_TXQUEUE | DBG_FUNC_NONE,
                  (int) pkt, (int) pkt->m_pkthdr.len, 0, 0, 0 );

    /*
     * Hold the debugger lock so the debugger can't interrupt us
     */
    reserveDebuggerLock();
 
    if ( linkStatusPrev != kLinkStatusUp )
    {
        freePacket( pkt );
    }
    else if ( transmitPacket(pkt) == false )
    {
        ret = kIOReturnOutputStall;
    }
      
    releaseDebuggerLock();

    return ret;
}

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

bool UniNEnet::resetAndEnable(bool enable)
{
    bool ret = true;

    reserveDebuggerLock();

    ready = false;

    if (timerSource) 
    {
        timerSource->cancelTimeout();
    }
    
    disableAdapterInterrupts();
    if (getWorkLoop())
    { 
        getWorkLoop()->disableAllInterrupts();
    }

    if (enable)
    {
        phyId = 0xff;
    }

    if ( resetChip() == false )
    {
        ret = false;
        goto resetAndEnable_exit;
    } 

    // Initialize the link status.

    setLinkStatus( 0, 0 );

    // Flush all mbufs from RX and TX rings.

    flushRings();

    while (enable)
    {
        if (!initRxRing() || !initTxRing()) 
        {
            ret = false;
            break;
        }

        if ( phyId != 0xff )
        {
            miiInitializePHY(phyId);
        }

        if (initChip() == false)
        {
            ret = false;
            break;
        }

//      startChip();

        timerSource->setTimeoutMS(WATCHDOG_TIMER_MS);

        if (getWorkLoop())
        { 
            getWorkLoop()->enableAllInterrupts();
        }    
        enableAdapterInterrupts();

        ready = true;

        monitorLinkStatus( true );

        break;
    }

resetAndEnable_exit: ;
    
    releaseDebuggerLock();

    return ret;
}

/*-------------------------------------------------------------------------
 * Called by IOEthernetInterface client to enable the controller.
 * This method is always called while running on the default workloop
 * thread.
 *-------------------------------------------------------------------------*/

IOReturn UniNEnet::enable(IONetworkInterface * netif)
{
    /*
     * If an interface client has previously enabled us,
     * and we know there can only be one interface client
     * for this driver, then simply return true.
     */
    if ( netifEnabled )
    {
        IOLog("EtherNet(UniN): already enabled\n");
        return kIOReturnSuccess;
    }

    if ( (ready == false) && !resetAndEnable(true) )
        return kIOReturnIOError;

    /*
     * Mark the controller as enabled by the interface.
     */
    netifEnabled = true;

    /*
     * Start our IOOutputQueue object.
     */
    transmitQueue->setCapacity( TRANSMIT_QUEUE_SIZE );
    transmitQueue->start();

    return kIOReturnSuccess;
}

/*-------------------------------------------------------------------------
 * Called by IOEthernetInterface client to disable the controller.
 * This method is always called while running on the default workloop
 * thread.
 *-------------------------------------------------------------------------*/
 
IOReturn UniNEnet::disable(IONetworkInterface * /*netif*/)
{
    /*
     * Disable our IOOutputQueue object. This will prevent the
     * outputPacket() method from being called.
     */
    transmitQueue->stop();

    /*
     * Flush all packets currently in the output queue.
     */
    transmitQueue->setCapacity(0);
    transmitQueue->flush();

    /*
     * If we have no active clients, then disable the controller.
     */
    if ( debugEnabled == false )
    {
        resetAndEnable(false);
    }

    netifEnabled = false;

    return kIOReturnSuccess;
}

/*-------------------------------------------------------------------------
 * This method is called by our debugger client to bring up the controller
 * just before the controller is registered as the debugger device. The
 * debugger client is attached in response to the attachDebuggerClient()
 * call.
 *
 * This method is always called while running on the default workloop
 * thread.
 *-------------------------------------------------------------------------*/

IOReturn UniNEnet::enable(IOKernelDebugger * /*debugger*/)
{
    /*
     * Enable hardware and make it ready to support the debugger client.
     */
    if ( (ready == false) && !resetAndEnable(true) )
    {
        return kIOReturnIOError;
    }

    /*
     * Mark the controller as enabled by the debugger.
     */
    debugEnabled = true;

    /*
     * Returning true will allow the kdp registration to continue.
     * If we return false, then we will not be registered as the
     * debugger device, and the attachDebuggerClient() call will
     * return NULL.
     */
    return kIOReturnSuccess;
}

/*-------------------------------------------------------------------------
 * This method is called by our debugger client to stop the controller.
 * The debugger will call this method when we issue a detachDebuggerClient().
 *
 * This method is always called while running on the default workloop
 * thread.
 *-------------------------------------------------------------------------*/

IOReturn UniNEnet::disable(IOKernelDebugger * /*debugger*/)
{
    debugEnabled = false;

    /*
     * If we have no active clients, then disable the controller.
     */
    if ( netifEnabled == false )
    {
        resetAndEnable(false);
    }

    return kIOReturnSuccess;
}

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

void UniNEnet::timeoutOccurred(IOTimerEventSource * /*timer*/)
{
    IODebuggerLockState	lockState;
	bool  				doService = false;
	UInt32				txRingIndex;
	UInt32				x;


    if ( ready == false )
    {
        // IOLog("EtherNet(UniN): Spurious timeout event!!\n");
        return;
    }


		/* Update statistics from the GMAC statistics registers:	*/

	x = READ_REGISTER( LengthErrorCounter );
	writeRegister( &fpRegs->LengthErrorCounter, 0 );
	fpEtherStats->dot3StatsEntry.frameTooLongs += x;

	x = READ_REGISTER( AlignmentErrorCounter );
	writeRegister( &fpRegs->AlignmentErrorCounter, 0 );
	fpEtherStats->dot3StatsEntry.alignmentErrors += x;

	x = READ_REGISTER( FCSErrorCounter );
	writeRegister( &fpRegs->FCSErrorCounter, 0 );
	fpEtherStats->dot3StatsEntry.fcsErrors += x;

	x = READ_REGISTER( RxCodeViolationErrorCounter );
	writeRegister( &fpRegs->RxCodeViolationErrorCounter, 0 );
	fpEtherStats->dot3StatsEntry.internalMacTransmitErrors += x;

	x = READ_REGISTER( FirstAttemptSuccessfulCollisionCounter );
	writeRegister( &fpRegs->FirstAttemptSuccessfulCollisionCounter, 0 );
	fpEtherStats->dot3StatsEntry.singleCollisionFrames += x;

	x = READ_REGISTER( ExcessiveCollisionCounter );
	writeRegister( &fpRegs->ExcessiveCollisionCounter, 0 );
	fpEtherStats->dot3StatsEntry.excessiveCollisions += x;

	x = READ_REGISTER( LateCollisionCounter );
	writeRegister( &fpRegs->LateCollisionCounter, 0 );
	fpEtherStats->dot3StatsEntry.lateCollisions += x;

	lockState = IODebuggerLock( this );

    monitorLinkStatus();

    /*
     * If there are pending entries on the Tx ring
     */
    if ( txCommandHead != txCommandTail )
    {
        /* 
         * If the hardware tx pointer did not move since the last
         * check, increment the txWDCount.
         */
		txRingIndex = READ_REGISTER( TxCompletion );
        if ( txRingIndex == txRingIndexLast )
        {
            txWDCount++;         
        }
        else
        {
            txWDCount = 0;
            txRingIndexLast = txRingIndex;
        }
   
        if ( txWDCount > 2 )
        {
            /* 
             * We only take interrupts every 64 tx completions, so we may be here just
             * to do normal clean-up of tx packets. We check if the hardware tx pointer
             * points to the next available tx slot. This indicates that we transmitted all
             * packets that were scheduled vs rather than the hardware tx being stalled.
             */
            if ( txRingIndex != txCommandTail )
            {
                UInt32        interruptStatus, compReg, kickReg;
 
				interruptStatus = READ_REGISTER( Status );
				compReg			= READ_REGISTER( TxCompletion );
				kickReg			= READ_REGISTER( TxKick );

                IOLog( "Tx Int Timeout - Comp = %04x Kick = %04x Int = %08x\n\r", (int)compReg, (int)kickReg, (int)interruptStatus ); 
            }

//          dumpRegisters();

            transmitInterruptOccurred();

            doService = true;

            txRingIndexLast = txRingIndex;
            txWDCount = 0;
        }
    }
    else
    {
        txWDCount        = 0;
    }
    
    // Monitor receiver's health.
    
    if ( rxWDInterrupts == 0 )
    {
        UInt32 rxMACStatus;

        switch ( rxWDCount )
        {
            case 0:
            case 1:
                rxWDCount++;	// Extend timeout
                break;

            default:
                // We could be less conservative here and restart the
                // receiver unconditionally.

                rxMACStatus = READ_REGISTER( RxMACStatus );

                if ( rxMACStatus & kRX_MAC_Status_Rx_Overflow )
                {
                    // Bad news, the receiver may be deaf as a result of this
                    // condition, and if so, a RX MAC reset is needed. Note
                    // that reading this register will clear all bits.

                    restartReceiver();

					NETWORK_STAT_ADD( inputErrors );
					ETHERNET_STAT_ADD( dot3RxExtraEntry.watchdogTimeouts );
                }
                rxWDCount = 0;
                break;
        }
    }
    else
    {
        // Reset watchdog

        rxWDCount      = 0;
        rxWDInterrupts = 0;
    }

		/* Clean-up after the debugger if the debugger was active:	*/

	if ( debugTxPoll )
	{
		debugQueue->flush();
		debugTxPoll	= false;
		doService	= true;
	}
	IODebuggerUnlock( lockState );

	/*
	 * Make sure the queue is not stalled.
	 */
	if (doService && netifEnabled)
	{
		transmitQueue->service();
	}

    /*
     * Restart the watchdog timer
     */
    timerSource->setTimeoutMS(WATCHDOG_TIMER_MS);
	return;
}/* end timeoutOccurred */


/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

const OSString * UniNEnet::newVendorString() const
{
    return OSString::withCString("Apple");
}

const OSString * UniNEnet::newModelString() const
{
    return OSString::withCString("gmac+");
}

const OSString * UniNEnet::newRevisionString() const
{
    return OSString::withCString("");
}


/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

IOReturn UniNEnet::setPromiscuousMode(IOEnetPromiscuousMode mode)
{
    reserveDebuggerLock();

	rxMacConfigReg = READ_REGISTER( RxMACConfiguration );
    if (mode == kIOEnetPromiscuousModeOff) 
    {
        rxMacConfigReg &= ~(kRxMACConfiguration_Promiscuous);
        isPromiscuous   = false;

    }
    else
    {
        rxMacConfigReg |= kRxMACConfiguration_Promiscuous;
        isPromiscuous   = true;

    }    
	WRITE_REGISTER( RxMACConfiguration, rxMacConfigReg );

    releaseDebuggerLock();
    
    return kIOReturnSuccess;
}

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

IOReturn UniNEnet::setMulticastMode(IOEnetMulticastMode mode)
{
	multicastEnabled = (mode == kIOEnetMulticastModeOff) ? false : true;

	return kIOReturnSuccess;
}

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

IOReturn UniNEnet::setMulticastList(IOEthernetAddress *addrs, UInt32 count)
{
    reserveDebuggerLock();
    
    resetHashTableMask();
    for (UInt32 i = 0; i < count; i++) 
    {
        addToHashTableMask(addrs->bytes);
        addrs++;
    }
    updateHashTableMask();
    
    releaseDebuggerLock();
    return kIOReturnSuccess;
}

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

IOOutputQueue* UniNEnet::createOutputQueue()
{
	return IOBasicOutputQueue::withTarget( this, TRANSMIT_QUEUE_SIZE );
}/* end createOutputQueue */


/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

static struct MediumTable
{
    UInt32	type;
    UInt32	speed;
} 
mediumTable[] =
{
    { kIOMediumEthernetNone                                  ,   0   },
    { kIOMediumEthernetAuto                                  ,   0   },
    { kIOMediumEthernet10BaseT    | kIOMediumOptionHalfDuplex,	10   },
    { kIOMediumEthernet10BaseT    | kIOMediumOptionFullDuplex,	10   },
    { kIOMediumEthernet100BaseTX  | kIOMediumOptionHalfDuplex,	100  },
    { kIOMediumEthernet100BaseTX  | kIOMediumOptionFullDuplex,	100  },
    { kIOMediumEthernet1000BaseSX | kIOMediumOptionFullDuplex,	1000 },
    { kIOMediumEthernet1000BaseTX | kIOMediumOptionFullDuplex,	1000 }
};


bool UniNEnet::createMediumTables()
{
    IONetworkMedium		*medium;
    UInt32			i;

    mediumDict = OSDictionary::withCapacity( sizeof(mediumTable)/sizeof(mediumTable[0]) );
    if ( mediumDict == 0 ) return false;

    for ( i=0; i < sizeof(mediumTable)/sizeof(mediumTable[0]); i++ )
    {
        medium = IONetworkMedium::medium( mediumTable[i].type, mediumTable[i].speed );
        if ( medium != 0 ) 
        {  
            IONetworkMedium::addMedium( mediumDict, medium );
            medium->release();
        }
    }

    if ( publishMediumDictionary( mediumDict ) != true ) 
    {
        return false;
    }

    medium = IONetworkMedium::getMediumWithType( mediumDict,
                                                 kIOMediumEthernetAuto );

    setCurrentMedium( medium );

    return true;    
}


void UniNEnet::writeRegister( UInt32 *pReg, UInt32 data )
{
///	ELG( data, (UInt32)pReg - (UInt32)fpRegs, 'wReg', "writeRegister" );

	OSWriteLittleInt32( pReg, 0, data );
	return;
}/* end writeRegister */
