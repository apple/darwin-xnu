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
 * Copyright (c) 1995-1996 NeXT Software, Inc.
 *
 * Hardware independent (relatively) code for the Mace Ethernet Controller 
 *
 * HISTORY
 *
 * dd-mmm-yy	 
 *	Created.
 *
 */

#include <IOKit/assert.h>
#include <IOKit/platform/AppleMacIODevice.h>
#include "MaceEnetPrivate.h"

//------------------------------------------------------------------------

#define super IOEthernetController

OSDefineMetaClassAndStructors( MaceEnet, IOEthernetController )

//------------------------------------------------------------------------

#define	PROVIDER_DEV	0
#define	PROVIDER_DMA_TX	1
#define	PROVIDER_DMA_RX	2

/*
 * Public Instance Methods
 */

bool MaceEnet::init(OSDictionary * properties)
{
	if (!super::init(properties))
		return false;

    isPromiscuous     = false;
    multicastEnabled  = false;
	ready             = false;
	debugClient       = false;
	debugTxPoll       = false;
	netifClient       = false;

	return true;
}

MaceEnet * MaceEnet::probe(IOService *    /*provider*/,
                           unsigned int * /*score*/,
                           unsigned int * /*specificity*/)
{
#ifdef OLD_CODE
    extern int		kdp_flag;

    /*
     * If bootargs: kdp bit 0 using in-kernel mace driver for early debugging,
     *              Don't probe this driver.
     */
    if( kdp_flag & 1)
	{
		return 0;
	}
#endif

	return this;
}

bool MaceEnet::start(IOService * provider)
{
	AppleMacIODevice *nub = OSDynamicCast(AppleMacIODevice, provider);

	if (!nub || !super::start(provider))
		return false;

	transmitQueue = OSDynamicCast(IOGatedOutputQueue, getOutputQueue());
	if (!transmitQueue)
	{
		IOLog("Mace: output queue initialization failed\n");
		return false;
	}
	transmitQueue->retain();

	// Allocate debug queue. This stores packets retired from the TX ring
	// by the polling routine. We cannot call freePacket() or m_free() within
	// the debugger context.
	//
	// The capacity of the queue is set at maximum to prevent the queue from
	// calling m_free() due to over-capacity. But we don't expect the size
	// of the queue to grow too large.
	//
	debugQueue = IOPacketQueue::withCapacity((UInt) -1);
	if (!debugQueue)
		return false;

	// Allocate a IOMbufBigMemoryCursor instance. Currently, the maximum
	// number of segments is set to 2. The maximum length for each segment
	// is set to the maximum ethernet frame size (plus padding).

	mbufCursor = IOMbufBigMemoryCursor::withSpecification(NETWORK_BUFSIZE, 2);
	if (!mbufCursor)
	{
		IOLog("Mace: IOMbufMemoryCursor allocation failed\n");
		return false;
	}

	//
	// Our provider is the nub representing the MaceEnet hardware
	// controller. We will query it for our resource information.
	//

	for (int i = 0; i < MEMORY_MAP_COUNT; i++) {
		IOMemoryMap * map;
		
		map = provider->mapDeviceMemoryWithIndex(i);
		if (!map)
			return false;

#ifdef DEBUG_XXX
		IOLog("map %d: Phys:%08x Virt:%08x len:%d\n",
			i,
			(UInt) map->getPhysicalAddress(),
			(UInt) map->getVirtualAddress(),
			(UInt) map->getLength());
#endif

		switch (i) {
			case MEMORY_MAP_ENET_INDEX:
				ioBaseEnet    = (IOPPCAddress) map->getVirtualAddress();
    			ioBaseEnetROM = (IOPPCAddress) ((map->getPhysicalAddress() &
					~0xffff) | kControllerROMOffset);
				break;
			
			case MEMORY_MAP_TXDMA_INDEX:
				ioBaseEnetTxDMA = (IODBDMAChannelRegisters *)
					map->getVirtualAddress();
				break;
			
			case MEMORY_MAP_RXDMA_INDEX:
				ioBaseEnetRxDMA = (IODBDMAChannelRegisters *)
					map->getVirtualAddress();
				break;
		}
		
		maps[i] = map;
	}

	// Manually create an IODeviceMemory for the ROM memory
	// range.
	//
	IODeviceMemory * romMemory = IODeviceMemory::withRange(
					(UInt) ioBaseEnetROM, 0x1000);
	if (!romMemory) {
		IOLog("Mace: can't create ROM memory object\n");
		return false;
	}
	
	romMap = romMemory->map();	
	romMemory->release();

	if (!romMap)
		return false;

	ioBaseEnetROM = (IOPPCAddress) romMap->getVirtualAddress();

#ifdef DEBUG_XXX
	IOLog("Mace: ioBaseEnet       : %08x\n", (UInt) ioBaseEnet);
	IOLog("Mace: ioBaseEnetTxDMA  : %08x\n", (UInt) ioBaseEnetTxDMA);
	IOLog("Mace: ioBaseEnetRxDMA  : %08x\n", (UInt) ioBaseEnetRxDMA);
	IOLog("Mace: ioBaseEnetROM    : %08x\n", (UInt) ioBaseEnetROM);
#endif

	//
	// Get a reference to the IOWorkLoop in our superclass.
	//
	IOWorkLoop * myWorkLoop = (IOWorkLoop *) getWorkLoop();
	assert(myWorkLoop);

	//
	// Allocate two IOInterruptEventSources.
	//
	txIntSrc = IOInterruptEventSource::interruptEventSource
            (this,
             (IOInterruptEventAction) &MaceEnet::interruptOccurredForSource,
             provider, PROVIDER_DMA_TX);
        if (!txIntSrc
        || (myWorkLoop->addEventSource(txIntSrc) != kIOReturnSuccess)) {
		IOLog("Mace: txIntSrc init failure\n");
		return false;
	}
	
	rxIntSrc = IOInterruptEventSource::interruptEventSource
            (this,
             (IOInterruptEventAction) &MaceEnet::interruptOccurredForSource,
             provider, PROVIDER_DMA_RX);
        if (!rxIntSrc
        || (myWorkLoop->addEventSource(rxIntSrc) != kIOReturnSuccess)) {
		IOLog("Mace: rxIntSrc init failure\n");
		return false;
	}

	timerSrc = IOTimerEventSource::timerEventSource
            (this, (IOTimerEventSource::Action) &MaceEnet::timeoutOccurred);
	if (!timerSrc
	|| (myWorkLoop->addEventSource(timerSrc) != kIOReturnSuccess)) {
		IOLog("Mace: timerSrc init failure\n");
		return false;
	}

	MGETHDR(txDebuggerPkt, M_DONTWAIT, MT_DATA);
	if (!txDebuggerPkt)
	{
		IOLog("Mace: Can't allocate KDB buffer\n");
		return false;
	}

#if 0
	// Do not enable interrupt sources until the hardware
	// is enabled.

	// Enable the interrupt event sources.
	myWorkLoop->enableAllInterrupts();
#endif

#if 0
	// Do not reset the hardware until we are ready to use it.
	// Otherwise, we would have messed up kdp_mace driver's
	// state. And we won't be able to break into the debugger
	// until we attach our debugger client.

	//
	// Perform a hardware reset.
	//
    if ( !resetAndEnable(false) ) 
    {
		return false;
    }
#endif

	// Cache my MAC address.
	//
	getHardwareAddress(&myAddress);

	//
	// Allocate memory for ring buffers.
	//
    if (_allocateMemory() == false) 
    {
		return false;
    }

	//
	// Attach a kernel debugger client.
	//
	attachDebuggerClient(&debugger);

	//
	// Allocate and initialize an IONetworkInterface object.
	//
	if (!attachInterface((IONetworkInterface **) &networkInterface))
		return false;

    return true;
}

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

void MaceEnet::free()
{
    UInt		i;
    
    timerSrc->cancelTimeout();
    
    _resetChip();

	if (debugger)
		debugger->release();

	if (timerSrc)
		timerSrc->release();

	if (rxIntSrc)
		rxIntSrc->release();

	if (txIntSrc)
		txIntSrc->release();

	if (transmitQueue)
		transmitQueue->release();

	if (debugQueue)
		debugQueue->release();

    if (networkInterface)
		networkInterface->release();

	if (mbufCursor)
		mbufCursor->release();

	if (txDebuggerPkt)
		freePacket(txDebuggerPkt);

    for (i = 0; i < rxMaxCommand; i++)
    	if (rxMbuf[i])  freePacket(rxMbuf[i]);

    for (i = 0; i < txMaxCommand; i++)
    	if (txMbuf[i]) freePacket(txMbuf[i]);

	if (romMap) romMap->release();

	for (i = 0; i < MEMORY_MAP_COUNT; i++)
		if (maps[i]) maps[i]->release();

	if (dmaMemory.ptr)
	{
		IOFree(dmaMemory.ptrReal, dmaMemory.sizeReal);
		dmaMemory.ptr = 0;
	}

    if ( workLoop )
    {
        workLoop->release();
        workLoop = 0;
    }

	super::free();
}

/*-------------------------------------------------------------------------
 * Override IONetworkController::createWorkLoop() method and create
 * a workloop.
 *
 *-------------------------------------------------------------------------*/

bool MaceEnet::createWorkLoop()
{
    workLoop = IOWorkLoop::workLoop();

    return ( workLoop != 0 );
}

/*-------------------------------------------------------------------------
 * Override IOService::getWorkLoop() method to return our workloop.
 *
 *
 *-------------------------------------------------------------------------*/

IOWorkLoop * MaceEnet::getWorkLoop() const
{
    return workLoop;
}

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

void MaceEnet::interruptOccurredForSource(IOInterruptEventSource *src,
		 int /*count*/)
{
	bool doFlushQueue = false;
	bool doService    = false;

	// IOLog("Mace: interrupt %08x %d\n", (UInt) src, count);
	
	if (!ready) {
		// IOLog("Mace: unexpected interrupt\n");
		return;
	}

	reserveDebuggerLock();

	if (src == txIntSrc) {
        txWDInterrupts++;
        KERNEL_DEBUG(DBG_MACE_TXIRQ | DBG_FUNC_START, 0, 0, 0, 0, 0 );
		doService = _transmitInterruptOccurred();
        KERNEL_DEBUG(DBG_MACE_TXIRQ | DBG_FUNC_END,   0, 0, 0, 0, 0 );
	}
	else {
        KERNEL_DEBUG(DBG_MACE_RXIRQ | DBG_FUNC_START, 0, 0, 0, 0, 0 );		
		doFlushQueue = _receiveInterruptOccurred();
        KERNEL_DEBUG(DBG_MACE_RXIRQ | DBG_FUNC_END,   0, 0, 0, 0, 0 );	
	}

	releaseDebuggerLock();

	/*
	 * Submit all received packets queued up by _receiveInterruptOccurred()
	 * to the network stack. The up call is performed without holding the
	 * debugger lock.
	 */
	if (doFlushQueue)
		networkInterface->flushInputQueue();

	/*
	 * Make sure the output queue is not stalled.
	 */
	if (doService && netifClient)
		transmitQueue->service();
}

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

UInt32 MaceEnet::outputPacket(struct mbuf *pkt, void *param)
{
    u_int32_t    i;
    u_int8_t     regValue;
    UInt32       ret = kIOReturnOutputSuccess;

	// IOLog("Mace: outputPacket %d\n", pkt->m_pkthdr.len);

    KERNEL_DEBUG(DBG_MACE_TXQUEUE | DBG_FUNC_NONE, (int) pkt,
		(int) pkt->m_pkthdr.len, 0, 0, 0 );
	
    /*
     * Hold the debugger lock so the debugger can't interrupt us
     */
	reserveDebuggerLock();
	
    do
    {
		/*
		 * Someone is turning off the receiver before the first transmit.
		 * Dont know who yet!
		 */
		regValue = ReadMaceRegister( ioBaseEnet, kMacCC );
		regValue |= kMacCCEnRcv;
		WriteMaceRegister( ioBaseEnet, kMacCC, regValue );
		
		/* 
		 * Preliminary sanity checks
		 */
		assert(pkt && netifClient);

		/*
		 * Remove any completed packets from the Tx ring 
		 */
		_transmitInterruptOccurred();
		
		i = txCommandTail + 1;
		if ( i >= txMaxCommand ) i = 0;
		if ( i == txCommandHead )
		{
			ret = kIOReturnOutputStall;
			continue;
		}

		/*
		 * If there is space on the Tx ring, add the packet directly to the
		 * ring
		 */
		_transmitPacket(pkt);
    }
    while ( 0 );

	releaseDebuggerLock();
	
	return ret;
}

/*-------------------------------------------------------------------------
 * Called by IOEthernetInterface client to enable the controller.
 * This method is always called while running on the default workloop
 * thread.
 *-------------------------------------------------------------------------*/

IOReturn MaceEnet::enable(IONetworkInterface * netif)
{
	IONetworkParameter * param;
	
	// If an interface client has previously enabled us,
	// and we know there can only be one interface client
	// for this driver, then simply return true.
	//
	if (netifClient) {
		IOLog("Mace: already enabled\n");
		return kIOReturnSuccess;
	}

	param = netif->getParameter(kIONetworkStatsKey);
	if (!param || !(netStats = (IONetworkStats *) param->getBuffer()))
	{
		IOLog("Mace: invalid network statistics\n");
		return kIOReturnError;
	}

	if ((ready == false) && !resetAndEnable(true))
		return kIOReturnIOError;

	// Record the interface as an active client.
	//
	netifClient = true;

	// Start our IOOutputQueue object.
	//
	transmitQueue->setCapacity(TRANSMIT_QUEUE_SIZE);
	transmitQueue->start();

	return kIOReturnSuccess;
}

/*-------------------------------------------------------------------------
 * Called by IOEthernetInterface client to disable the controller.
 * This method is always called while running on the default workloop
 * thread.
 *-------------------------------------------------------------------------*/

IOReturn MaceEnet::disable(IONetworkInterface * /*netif*/)
{
	// If we have no active clients, then disable the controller.
	//
	if (debugClient == false)
		resetAndEnable(false);
	
	// Disable our IOOutputQueue object.
	//
	transmitQueue->stop();

	// Flush all packets currently in the output queue.
	//
	transmitQueue->setCapacity(0);
	transmitQueue->flush();

	netifClient = false;

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

IOReturn MaceEnet::enable(IOKernelDebugger * /*debugger*/)
{
	// Enable hardware and make it ready to support the debugger client.
	//
	if ((ready == false) && !resetAndEnable(true))
		return kIOReturnIOError;

	// Record the debugger as an active client of ours.
	//
	debugClient = true;

	// Returning true will allow the kdp registration to continue.
	// If we return false, then we will not be registered as the
	// debugger device, and the attachDebuggerClient() call will
	// return NULL.
	//
	return kIOReturnSuccess;
}

/*-------------------------------------------------------------------------
 * This method is called by our debugger client to stop the controller.
 * The debugger will call this method when we issue a detachDebuggerClient().
 *
 * This method is always called while running on the default workloop
 * thread.
 *-------------------------------------------------------------------------*/

IOReturn MaceEnet::disable(IOKernelDebugger * /*debugger*/)
{
	debugClient = false;

	// If we have no active clients, then disable the controller.
	//
	if (netifClient == false)
		resetAndEnable(false);

	return kIOReturnSuccess;
}

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

bool MaceEnet::resetAndEnable(bool enable)
{
	bool ret = true;

	if (timerSrc)
		timerSrc->cancelTimeout();

	_disableAdapterInterrupts();
	if (getWorkLoop()) getWorkLoop()->disableAllInterrupts();

	reserveDebuggerLock();

	ready = false;

	_resetChip();

    do {
		if (!enable) break;

		if ( !_initRxRing() || !_initTxRing() || !_initChip() ) 
		{
			ret = false;
			break;
		}

		_startChip();

		ready = true;

		releaseDebuggerLock();

		timerSrc->setTimeoutMS(WATCHDOG_TIMER_MS);
		
		if (getWorkLoop()) getWorkLoop()->enableAllInterrupts();
		_enableAdapterInterrupts();

		return true;
    }
	while (0);

	releaseDebuggerLock();

    return ret;
}

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

void MaceEnet::_sendTestPacket()
{
//	IOOutputPacketStatus ret;
    unsigned char * buf;
	const unsigned int size = 64;
	
	struct mbuf * m = allocatePacket(size);
	if (!m) {
		IOLog("Mace: _sendTestpacket:  allocatePacket() failed\n");
		return;
	}

	buf = mtod(m, unsigned char *);

	bcopy(&myAddress, buf, NUM_EN_ADDR_BYTES);
	buf += NUM_EN_ADDR_BYTES;
    bcopy(&myAddress, buf, NUM_EN_ADDR_BYTES);
	buf += NUM_EN_ADDR_BYTES;
	*buf++ = 0;
	*buf++ = 0;

	outputPacket(m, 0);
}

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

void MaceEnet::timeoutOccurred(IOTimerEventSource * /*timer*/)
{
    u_int32_t   dmaStatus;
	bool        doFlushQueue = false;
	bool        doService    = false;

	reserveDebuggerLock();

    /*
     * Check for DMA shutdown on receive channel
     */
    dmaStatus = IOGetDBDMAChannelStatus( ioBaseEnetRxDMA );
    if ( !(dmaStatus & kdbdmaActive) )
    {
#if 0
		IOLog("Mace: Timeout check - RxHead = %d RxTail = %d\n", 
			rxCommandHead, rxCommandTail);
#endif

#if 0
      IOLog( "Mace: Rx Commands = %08x(p) Rx DMA Ptr = %08x(p)\n\r", rxDMACommandsPhys, IOGetDBDMACommandPtr(ioBaseEnetRxDMA) ); 
      [self _dumpDesc:(void *)rxDMACommands Size:rxMaxCommand * sizeof(enet_dma_cmd_t)];
#endif 

		doFlushQueue = _receiveInterruptOccurred();
    } 

    /*
     * If there are pending entries on the Tx ring
     */
    if ( txCommandHead != txCommandTail )
    {
		/* 
		 * If we did not service the Tx ring during the last timeout interval,
		 * then force servicing of the Tx ring.
		 * If we have more than one timeout interval without any transmit 
		 * interrupts, then force the transmitter to reset.
		 */
		if ( txWDInterrupts == 0 )
		{ 
			if ( ++txWDTimeouts > 1 ) txWDForceReset = true;

#if 0
			IOLog( "Mace: Checking for timeout - TxHead = %d TxTail = %d\n", 
				txCommandHead, txCommandTail);
#endif
			doService = _transmitInterruptOccurred();
		}
		else
		{
			txWDTimeouts     = 0;
			txWDInterrupts   = 0;
		}
    }
    else
    {
		txWDTimeouts     = 0;
		txWDInterrupts   = 0;
    }

	// Clean-up after the debugger if the debugger was active.
	//
	if (debugTxPoll)
	{
		debugQueue->flush();
		debugTxPoll = false;
		releaseDebuggerLock();
		doService = true;
	}
	else
	{
		releaseDebuggerLock();
	}

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
	if (doService && netifClient)
	{
		transmitQueue->service();
	}

    /*
     * Restart the watchdog timer
     */
	timerSrc->setTimeoutMS(WATCHDOG_TIMER_MS);
}

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

const OSString * MaceEnet::newVendorString() const
{
	return OSString::withCString("Apple");
}

const OSString * MaceEnet::newModelString() const
{
	return OSString::withCString("Mace");
}

const OSString * MaceEnet::newRevisionString() const
{
	return OSString::withCString("");
}

/*-------------------------------------------------------------------------
 *
 *
 *
 *-------------------------------------------------------------------------*/

IOReturn MaceEnet::_setPromiscuousMode(IOEnetPromiscuousMode mode)
{
    u_int8_t		regVal;
	
    regVal = ReadMaceRegister( ioBaseEnet, kMacCC );
    WriteMaceRegister( ioBaseEnet, kMacCC, regVal & ~kMacCCEnRcv );
	if (mode == kIOEnetPromiscuousModeOff) {
		regVal &= ~kMacCCProm;
		isPromiscuous = false;
	}
	else {
		regVal |= kMacCCProm;
		isPromiscuous = true;
	}
	WriteMaceRegister( ioBaseEnet, kMacCC, regVal );
    
    return kIOReturnSuccess;

}

IOReturn MaceEnet::setPromiscuousMode(IOEnetPromiscuousMode mode)
{
	IOReturn ret;

	reserveDebuggerLock();
	ret = _setPromiscuousMode(mode);
	releaseDebuggerLock();

    return ret;
}

IOReturn MaceEnet::setMulticastMode(IOEnetMulticastMode mode)
{
	multicastEnabled = (mode == kIOEnetMulticastModeOff) ? false : true;
	return kIOReturnSuccess;
}

IOReturn MaceEnet::setMulticastList(IOEthernetAddress *addrs, UInt32 count)
{
	reserveDebuggerLock();
	_resetHashTableMask();
	for (UInt32 i = 0; i < count; i++) {
		_addToHashTableMask(addrs->bytes);
		addrs++;
	}
	_updateHashTableMask();
	releaseDebuggerLock();
	return kIOReturnSuccess;
}

/*
 * Allocate an IOOutputQueue object.
 */
IOOutputQueue * MaceEnet::createOutputQueue()
{	
	return IOGatedOutputQueue::withTarget( this, getWorkLoop() );
}

/*
 * Kernel Debugger Support 
 */
void MaceEnet::sendPacket(void *pkt, UInt32 pkt_len)
{
	_sendPacket(pkt, pkt_len);
}

void MaceEnet::receivePacket(void *pkt, UInt32 *pkt_len, UInt32 timeout)
{
    _receivePacket(pkt, (UInt *) pkt_len, timeout);
}

#if 0	// no power management stuff in IOKit yet.
/*
 * Power management methods. 
 */
- (IOReturn)getPowerState:(PMPowerState *)state_p
{
    return kIOReturnUnsupported;
}

- (IOReturn)setPowerState:(PMPowerState)state
{
    if (state == PM_OFF) {
	resetAndEnabled = NO;
        [self _resetChip];
	return kIOReturnSuccess;
    }
    return kIOReturnUnsupported;
}

- (IOReturn)getPowerManagement:(PMPowerManagementState *)state_p
{
    return kIOReturnUnsupported;
}

- (IOReturn)setPowerManagement:(PMPowerManagementState)state
{
    return kIOReturnUnsupported;
}
#endif /* 0 */
