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
 * Copyright (c) 1996 NeXT Software, Inc.  All rights reserved. 
 *
 * i82557.cpp
 *
 * HISTORY
 *
 * 22-Jan-96	Dieter Siegmund (dieter) at NeXT
 *	Created.
 *
 * 03-May-96	Dieter Siegmund (dieter) at NeXT
 *	Added a real ISR to improve performance.
 *
 * 10-June-96	Dieter Siegmund (dieter) at NeXT
 *	Added support for Splash 3 (10 Base-T only card).
 *
 * 18-June-96	Dieter Siegmund (dieter) at NeXT
 *	Keep the transmit queue draining by interrupting every
 *	N / 2 transmits (where N is the size of the hardware queue).
 *
 * 15-Dec-97	Joe Liu (jliu) at Apple
 *	Updated PHY programming to be 82558 aware.
 *	Misc changes to conform to new 82558 register flags.
 *	Changed RNR interrupt handler to restart RU instead of a reset.
 *	Interrupt handler now does a thread_call_func() to do most of its work.
 *	Interrupts are disabled until the thread callout finishes its work.
 *	Increased the size of TX/RX rings.
 *	buffer object removed, we use cluster mbufs to back up the receive ring.
 *
 * 29-May-98	Joe Liu (jliu) at Apple
 *	Updated _setupPhy method to take advantage of parallel detection whenever
 *	possible in order to detect the proper link speed.
 *
 * 17-Aug-98	Joe Liu (jliu) at Apple
 *	Re-enabled the setting of txready_sel PHY (PCS) bit for DP83840.
 *	Simplified interrupt handling, resulting in RCV performance improvements.
 *	Receive packets are sent upstream via a cached function pointer.
 */

#include "i82557.h"

#define ONE_SECOND_TICKS			1000
#define LOAD_STATISTICS_INTERVAL	(4 * ONE_SECOND_TICKS)

#define super IOEthernetController
OSDefineMetaClassAndStructors( Intel82557, IOEthernetController )

//---------------------------------------------------------------------------
// Function: pciConfigInit
//
// Update PCI command register to enable the memory-mapped range,
// and bus-master interface.

bool Intel82557::pciConfigInit(IOPCIDevice * provider)
{
	UInt32	reg;
	
	reg = provider->configRead32( kIOPCIConfigCommand );

    reg |= ( kIOPCICommandBusMaster       |
             kIOPCICommandMemorySpace     |
             kIOPCICommandMemWrInvalidate );

    reg &= ~kIOPCICommandIOSpace;  // disable I/O space

	provider->configWrite32( kIOPCIConfigCommand, reg );

	return true;
}

//---------------------------------------------------------------------------
// Function: initDriver
//
// Create and initialize driver objects before the hardware is 
// enabled.
//
// Returns true on sucess, and false if initialization failed.

bool Intel82557::initDriver(IOService * provider)
{
	currentMediumType = MEDIUM_TYPE_INVALID;

	// This driver will allocate and use an IOGatedOutputQueue.
	//
	transmitQueue = getOutputQueue();
	if ( transmitQueue == 0 ) return false;

	// Allocate two IOMbufLittleMemoryCursor instances. One for transmit and
	// the other for receive.
	//
	rxMbufCursor = IOMbufLittleMemoryCursor::withSpecification(MAX_BUF_SIZE,1);
	txMbufCursor = IOMbufLittleMemoryCursor::withSpecification(MAX_BUF_SIZE, 
	                                                           TBDS_PER_TCB);
	if (!rxMbufCursor || !txMbufCursor)
		return false;

	// Get a handle to our superclass' workloop.
	//
	IOWorkLoop * myWorkLoop = (IOWorkLoop *) getWorkLoop();
	if (!myWorkLoop)
		return false;

	// Create and register an interrupt event source. The provider will
	// take care of the low-level interrupt registration stuff.
	//
	interruptSrc = 
		IOInterruptEventSource::interruptEventSource(this,
                    (IOInterruptEventAction) &Intel82557::interruptOccurred,
                    provider);

	if (!interruptSrc ||
		(myWorkLoop->addEventSource(interruptSrc) != kIOReturnSuccess))
		return false;

	// Register a timer event source. This is used as a watchdog timer.
	//
	timerSrc = IOTimerEventSource::timerEventSource( this,
               (IOTimerEventSource::Action) &Intel82557::timeoutOccurred );
	if (!timerSrc ||
		(myWorkLoop->addEventSource(timerSrc) != kIOReturnSuccess))
		return false;

	// Create a dictionary to hold IONetworkMedium objects.
	//
	mediumDict = OSDictionary::withCapacity(5);
	if (!mediumDict)
		return false;

	return true;
}

//---------------------------------------------------------------------------
// Function: getDefaultSettings
//
// Get the default driver settings chosen by the user. The properties
// are all stored in our property table (an OSDictionary).

bool Intel82557::getDefaultSettings()
{
	OSNumber *  numObj;
    OSBoolean * boolObj;

    // Check for PHY address override.
	//
    phyAddr = PHY_ADDRESS_DEFAULT;
	numObj  = OSDynamicCast( OSNumber, getProperty("PHY Address") );
	if ( numObj )
    {
		phyAddr = numObj->unsigned32BitValue();
    }

    // Check for Verbose flag.
	//
    verbose = false;
	boolObj = OSDynamicCast( OSBoolean, getProperty("Verbose") );
	if ( boolObj && boolObj->isTrue() )
    {
		IOLog("%s: verbose mode enabled\n", getName());
		verbose = true;
	}

    // Check for Flow-Control enable flag.
	//
    flowControl = false;
    boolObj = OSDynamicCast( OSBoolean, getProperty("Flow Control") );
	if ( boolObj && boolObj->isTrue() )
    {
		IOLog("%s: 802.3x flow control enabled\n", getName());
		flowControl = true;
	}

	return true;
}

//---------------------------------------------------------------------------
// Function: start <IOService>
//
// Hardware was detected and initialized, start the driver.

bool Intel82557::start( IOService * provider )
{
    bool ret = false;

    do {
        // Start our superclass first.

        if ( super::start(provider) == false )
            break;

        // Cache our provider to an instance variable.

        pciNub = OSDynamicCast(IOPCIDevice, provider);
        if ( pciNub == 0 ) break;

        // Retain provider, released in free().

        pciNub->retain();

        // Open our provider.

        if ( pciNub->open(this) == false ) break;

        // Initialize the driver's event sources and other support objects.

        if ( initDriver(provider) == false ) break;

        // Get the virtual address mapping of CSR registers located at
        // Base Address Range 0 (0x10). The size of this range is 4K.

        csrMap = pciNub->mapDeviceMemoryWithRegister( kIOPCIConfigBaseAddress0 );
        if ( csrMap == 0 ) break;
        
        CSR_p  = (CSR_t *) csrMap->getVirtualAddress();

        // Setup our PCI config space.

        if ( pciConfigInit(pciNub) == false ) break;

        // Create the EEPROM object.

        eeprom = i82557eeprom::withAddress(&CSR_p->eepromControl);
        if ( eeprom == 0 )
        {
            IOLog("%s: couldn't allocate eeprom object", getName());
			break;
        }

        // Get default driver settings (stored in property table).

        if ( getDefaultSettings() == false ) break;

        if ( verbose ) eeprom->dumpContents();

        // Execute one-time initialization code.

        if ( coldInit() == false )
        {
            IOLog("%s: coldInit failed\n", getName());
            break;
        }

        if ( hwInit() == false )
        {
            IOLog("%s: hwInit failed\n", getName());
            break;
        }

        // Publish our media capabilities.

        _phyPublishMedia();
        if ( publishMediumDictionary(mediumDict) == false )
        {
            IOLog("%s: publishMediumDictionary failed\n", getName());
			break;
        }

#if 0
        // Announce the basic hardware configuration info.
        IOLog("%s: Memory 0x%lx irq %d\n", getName(),
              csrMap->getPhysicalAddress(), 0);
#endif

        ret = true;
    }
    while ( false );

    // Close our provider, it will be re-opened on demand when
    // our enable() is called.

    if ( pciNub ) pciNub->close(this);

    do {
        if ( ret == false ) break;

        ret = false;

        // Allocate and attach an IOEthernetInterface instance to this driver
        // object.

        if ( attachInterface((IONetworkInterface **) &netif, false) == false )
            break;
        
        // Attach a kernel debugger client. This is not an essential service,
        // and the return is not checked.

        attachDebuggerClient(&debugger);

        // Start matching for clients of IONetworkInterface.

        netif->registerService();
        
        ret = true;
    }
    while ( false );
    
    return ret;
}

//---------------------------------------------------------------------------
// Function: stop <IOService>
//
// Stop all activities and prepare for termination.

void Intel82557::stop(IOService * provider)
{
    super::stop(provider);
}

//---------------------------------------------------------------------------
// Function: createWorkLoop <IONetworkController>
//
// Override IONetworkController::createWorkLoop() method to create a workloop.

bool Intel82557::createWorkLoop()
{
    workLoop = IOWorkLoop::workLoop();

    return ( workLoop != 0 );
}

//---------------------------------------------------------------------------
// Function: getWorkLoop <IOService>
//
// Override IOService::getWorkLoop() method to return our workloop.

IOWorkLoop * Intel82557::getWorkLoop() const
{
    return workLoop;
}

//---------------------------------------------------------------------------
// Function: configureInterface <IONetworkController>
//
// Configure a newly instantiated IONetworkInterface object.

bool Intel82557::configureInterface(IONetworkInterface * netif)
{
	IONetworkData * data;
	
	if ( super::configureInterface(netif) == false )
		return false;
	
	// Get the generic network statistics structure.

	data = netif->getParameter(kIONetworkStatsKey);
	if (!data || !(netStats = (IONetworkStats *) data->getBuffer())) {
		return false;
	}

	// Get the Ethernet statistics structure.

	data = netif->getParameter(kIOEthernetStatsKey);
	if (!data || !(etherStats = (IOEthernetStats *) data->getBuffer())) {
		return false;
	}
	
	return true;
}

//---------------------------------------------------------------------------
// Function: free <IOService>
//
// Deallocate all resources and destroy the instance.

void Intel82557::free()
{
	if (debugger)      { debugger->release();     debugger = 0;     }
    if (netif)         { netif->release();        netif = 0;        }
	if (interruptSrc)  { interruptSrc->release(); interruptSrc = 0; }
	if (timerSrc)      { timerSrc->release();     timerSrc = 0;     }
	if (rxMbufCursor)  { rxMbufCursor->release(); rxMbufCursor = 0; }
	if (txMbufCursor)  { txMbufCursor->release(); txMbufCursor = 0; }
	if (csrMap)        { csrMap->release();       csrMap = 0;       }
	if (eeprom)        { eeprom->release();       eeprom = 0;       }
	if (mediumDict)    { mediumDict->release();   mediumDict = 0;   }
    if ( pciNub )      { pciNub->release();       pciNub = 0;       }
    if ( workLoop )    { workLoop->release();     workLoop = 0;     }

	_freeMemPage( &shared );
	_freeMemPage( &txRing );
	_freeMemPage( &rxRing );

	super::free();	// pass it to our superclass
}

//---------------------------------------------------------------------------
// Function: enableAdapter
//
// Enables the adapter & driver to the given level of support.

bool Intel82557::enableAdapter(UInt32 level)
{
	bool ret = false;

//	IOLog("%s::%s enabling level %ld\n", getName(), __FUNCTION__, level);

	switch (level) {
		case kActivationLevel1:

            // Open provider.
            //
            if ( ( pciNub == 0 ) || ( pciNub->open(this) == false ) )
            {
                break;
            }

			if (!_initRingBuffers())
				break;
		
			if (!_startReceive()) {
				_clearRingBuffers();
				break;
			}
		
			// Set current medium.
			//
			if (setMedium(getCurrentMedium()) != kIOReturnSuccess)
				IOLog("%s: setMedium error\n", getName());

			// Start the watchdog timer.
			//
			timerSrc->setTimeoutMS(LOAD_STATISTICS_INTERVAL);

			// Enable interrupt event sources and hardware interrupts.
			//
			if (getWorkLoop())
				getWorkLoop()->enableAllInterrupts();
			enableAdapterInterrupts();

            // Force PHY to report link status.
            //
            _phyReportLinkStatus(true);

			ret = true;
			break;
		
		case kActivationLevel2:
			// Issue a dump statistics command.
			//
			_dumpStatistics();
		
			// Start our IOOutputQueue object.
			//
			transmitQueue->setCapacity(TRANSMIT_QUEUE_SIZE);
			transmitQueue->start();

			ret = true;
			break;
	}

	if (!ret)
		IOLog("%s::%s error in level %ld\n", getName(), __FUNCTION__, level);

	return ret;
}

//---------------------------------------------------------------------------
// Function: disableAdapter
//
// Disables the adapter & driver to the given level of support.

bool Intel82557::disableAdapter(UInt32 level)
{
	bool ret = false;

//	IOLog("%s::%s disabling level %ld\n", getName(), __FUNCTION__, level);
		
	switch (level) {
		case kActivationLevel1:
			// Disable interrupt handling and hardware interrupt sources.
			//
			disableAdapterInterrupts();
			if (getWorkLoop())
				getWorkLoop()->disableAllInterrupts();

			// Stop the timer event source, and initialize the watchdog state.
			//
			timerSrc->cancelTimeout();
			packetsReceived    = true;	// assume we're getting packets
			packetsTransmitted = false;
			txCount = 0;
		
			// Reset the hardware engine.
			//
			ret = hwInit();
		
			// Clear the descriptor rings after the hardware is idle.
			//
			_clearRingBuffers();
		
			// Report link status: unknown.
			//
			setLinkStatus(0, 0);
		
			// Flush all packets held in the queue and prevent it
			// from accumulating any additional packets.
			//
			transmitQueue->setCapacity(0);
			transmitQueue->flush();

            // Close provider.
            //
            if ( pciNub )
            {
                pciNub->close(this);
            }

			break;
		
		case kActivationLevel2:
			// Stop the transmit queue. outputPacket() will not get called
			// after this.
			//
			transmitQueue->stop();

			ret = true;
			break;
	}

	if (!ret)
		IOLog("%s::%s error in level %ld\n", getName(), __FUNCTION__, level);

	return ret;
}

//---------------------------------------------------------------------------
// Function: setActivationLevel
//
// Sets the adapter's activation level.
//
// kActivationLevel0 - Adapter is disabled.
// kActivationLevel1 - Adapter is brought up just enough to support debugging.
// kActivationLevel2 - Adapter is completely up.

bool Intel82557::setActivationLevel(UInt32 level)
{
	bool    ret = false;
	UInt32  nextLevel;

    // IOLog("---> DESIRED LEVEL : %d\n", level);

	if (currentLevel == level) return true;

	for ( ; currentLevel > level; currentLevel--) 
	{
		if ( (ret = disableAdapter(currentLevel)) == false )
			break;
	}

	for ( nextLevel = currentLevel + 1;
          currentLevel < level; 
	      currentLevel++, nextLevel++ ) 
	{
		if ( (ret = enableAdapter(nextLevel)) == false )
			break;
	}

    // IOLog("---> PRESENT LEVEL : %d\n\n", currentLevel);

	return ret;
}

//---------------------------------------------------------------------------
// Function: enable <IONetworkController>
//
// A request from our interface client to enable the adapter.

IOReturn Intel82557::enable(IONetworkInterface * /*netif*/)
{
	if ( enabledForNetif ) return kIOReturnSuccess;

	enabledForNetif = setActivationLevel( kActivationLevel2 );

	return ( enabledForNetif ? kIOReturnSuccess : kIOReturnIOError );
}

//---------------------------------------------------------------------------
// Function: disable <IONetworkController>
//
// A request from our interface client to disable the adapter.

IOReturn Intel82557::disable(IONetworkInterface * /*netif*/)
{
	enabledForNetif = false;

    setActivationLevel( enabledForDebugger ?
                        kActivationLevel1 : kActivationLevel0 );

	return kIOReturnSuccess;
}

//---------------------------------------------------------------------------
// Function: enable <IONetworkController>
//
// A request from our debugger client to enable the adapter.

IOReturn Intel82557::enable(IOKernelDebugger * /*debugger*/)
{
	if ( enabledForDebugger || enabledForNetif )
    {
		enabledForDebugger = true;
		return kIOReturnSuccess;
	}

	enabledForDebugger = setActivationLevel( kActivationLevel1 );

	return ( enabledForDebugger ? kIOReturnSuccess : kIOReturnIOError );
}

//---------------------------------------------------------------------------
// Function: disable <IONetworkController>
//
// A request from our debugger client to disable the adapter.

IOReturn Intel82557::disable(IOKernelDebugger * /*debugger*/)
{
	enabledForDebugger = false;

	if ( enabledForNetif == false )
		setActivationLevel( kActivationLevel0 );

	return kIOReturnSuccess;
}

//---------------------------------------------------------------------------
// Function: timeoutOccurred
//
// Periodic timer that monitors the receiver status, updates error
// and collision statistics, and update the current link status.

void Intel82557::timeoutOccurred(IOTimerEventSource * /*timer*/)
{
	if ( (packetsReceived == false) && (packetsTransmitted == true) )
    {
		/*
		 * The B-step of the i82557 requires that an mcsetup command be
		 * issued if the receiver stops receiving.  This is a documented
		 * errata.
		 */
		mcSetup(0, 0, true);
	}
	packetsReceived = packetsTransmitted = false;

	_updateStatistics();

    _phyReportLinkStatus();

	timerSrc->setTimeoutMS(LOAD_STATISTICS_INTERVAL);
}

//---------------------------------------------------------------------------
// Function: setPromiscuousMode <IOEthernetController>

IOReturn Intel82557::setPromiscuousMode(IOEnetPromiscuousMode mode)
{
    bool rv;
	promiscuousEnabled = (mode == kIOEnetPromiscuousModeOff) ? false : true;
	reserveDebuggerLock();
	rv = config();
	releaseDebuggerLock();
    return (rv ? kIOReturnSuccess : kIOReturnIOError);
}

//---------------------------------------------------------------------------
// Function: setMulticastMode <IOEthernetController>

IOReturn Intel82557::setMulticastMode(IOEnetMulticastMode mode)
{
	multicastEnabled = (mode == kIOEnetMulticastModeOff) ? false : true;
	return kIOReturnSuccess;
}

//---------------------------------------------------------------------------
// Function: setMulticastList <IOEthernetController>

IOReturn Intel82557::setMulticastList(IOEthernetAddress * addrs, UInt32 count)
{
	IOReturn ret = kIOReturnSuccess;

    if ( mcSetup(addrs, count) == false )
    {
    	IOLog("%s: set multicast list failed\n", getName());
		ret = kIOReturnIOError;
	}
	return ret;
}

//---------------------------------------------------------------------------
// Function: getPacketBufferConstraints <IONetworkController>
//
// Return our driver's packet alignment requirements.

void
Intel82557::getPacketBufferConstraints(IOPacketBufferConstraints * constraints) const
{
	constraints->alignStart  = kIOPacketBufferAlign2;	// even word aligned.
	constraints->alignLength = kIOPacketBufferAlign1;	// no restriction.
}

//---------------------------------------------------------------------------
// Function: getHardwareAddress <IOEthernetController>
//
// Return the adapter's hardware/Ethernet address.

IOReturn Intel82557::getHardwareAddress(IOEthernetAddress * addrs)
{
	bcopy(&myAddress, addrs, sizeof(*addrs));
	return kIOReturnSuccess;
}

//---------------------------------------------------------------------------
// Function: createOutputQueue <IONetworkController>
//
// Allocate an IOGatedOutputQueue instance.

IOOutputQueue * Intel82557::createOutputQueue()
{	
	return IOGatedOutputQueue::withTarget(this, getWorkLoop());
}

//---------------------------------------------------------------------------
// Function: setMedium <IONetworkController>
//
// Transition the controller/PHY to use a new medium. Note that
// this function can be called my the driver, or by our client.

IOReturn Intel82557::setMedium(const IONetworkMedium * medium)
{
	bool  r;

	if ( OSDynamicCast(IONetworkMedium, medium) == 0 )
    {
        // Defaults to Auto.
        medium = _phyGetMediumWithType( MEDIUM_TYPE_AUTO );
        if ( medium == 0 ) return kIOReturnError;
    }

#if 0
	IOLog("%s: setMedium -> %s\n", getName(),
          medium->getName()->getCStringNoCopy());
#endif

	// Program PHY to select the desired medium.
	//
	r = _phySetMedium( (mediumType_t) medium->getIndex() );

	// Update the current medium property.
	//
	if ( r && !setCurrentMedium(medium) )
		IOLog("%s: setCurrentMedium error\n", getName());

	return ( r ? kIOReturnSuccess : kIOReturnIOError );
}

//---------------------------------------------------------------------------
// Function: newVendorString(), newModelString()
//           <IONetworkController>
//
// Report human readable hardware information strings.

const OSString * Intel82557::newVendorString() const
{
	return OSString::withCString("Intel");
}

const OSString * Intel82557::newModelString() const
{
	const char * model = 0;

	assert( eeprom && eeprom->getContents() );

	switch ( eeprom->getContents()->controllerType )
    {
		case I82558_CONTROLLER_TYPE:
			model = "82558";
			break;
		case I82557_CONTROLLER_TYPE:
		default:
			model = "82557";
			break;
	}
	return OSString::withCString(model);
}

//---------------------------------------------------------------------------
// Kernel debugger entry points.
//
// KDP driven polling routines to send and transmit a frame.
// Remember, no memory allocation! Not even mbufs are safe.

void Intel82557::sendPacket(void * pkt, UInt32 pkt_len)
{
	_sendPacket(pkt, pkt_len);
}

void Intel82557::receivePacket(void * pkt, UInt32 * pkt_len, UInt32 timeout)
{
	_receivePacket(pkt, (UInt *) pkt_len, timeout);
}
