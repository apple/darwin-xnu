/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 2000 Apple Computer, Inc.  All rights reserved. 
 *
 * AppleATAPIIX.cpp - ATA controller driver for Intel PIIX/PIIX3/PIIX4.
 *
 * HISTORY
 *
 */

#include <architecture/i386/pio.h>
#include <IOKit/IOService.h>
#include <IOKit/assert.h>
#include "AppleATAPIIX.h"
#include "AppleATAPIIXTiming.h"

extern pmap_t 			    kernel_pmap;	// for pmap_extract()

// Resources shared between the two IDE channels are protected
// by this mutex.
//
static IOLock *      	    gPIIXLock = 0;
#define PIIX_LOCK	 	    IOLockLock(gPIIXLock)
#define PIIX_UNLOCK	 	    IOLockUnlock(gPIIXLock)

#define IOREG(x)		    (ioBMRange + PIIX_IO_ ## x)

#define CHECK_UNIT(drv)	    assert(drv < 2)

#ifdef  DEBUG_XXX
#define DLOG(fmt, args...)	IOLog(fmt, ## args)
#else
#define DLOG(fmt, args...)
#endif

//--------------------------------------------------------------------------
// Metaclass macro.
//
#undef  super
#define super IOATAStandardDriver

OSDefineMetaClassAndStructorsWithInit( AppleATAPIIX, IOATAStandardDriver,
                                       AppleATAPIIX::initialize() )

//--------------------------------------------------------------------------
// PIIX class initializer.
//
void AppleATAPIIX::initialize()
{
	gPIIXLock = IOLockAlloc();
	assert(gPIIXLock);
}

//--------------------------------------------------------------------------
// Defines a table of supported PIIX device types, listing their
// PCI ID, and a name string. Also supply some utility functions
// to locate a table entry based on an arbitrary PCI ID.
//
static struct {
	UInt32        CFID;
	const char *  name;
} piixDeviceTable[] = {{ PCI_ID_PIIX,   "PIIX"   },
                       { PCI_ID_PIIX3,  "PIIX3"  },
                       { PCI_ID_PIIX4,  "PIIX4"  },
                       { PCI_ID_ICH,    "ICH"    },
                       { PCI_ID_ICH0,   "ICH0"   },
                       { PCI_ID_ICH2_M, "ICH2-M" },
                       { PCI_ID_ICH2,   "ICH2"   },
                       { PCI_ID_NONE,    NULL    }};

static const char *
PIIXGetName(UInt32 pciID)
{
	for (int i = 0; piixDeviceTable[i].name; i++) {
		if (piixDeviceTable[i].CFID == pciID)
			return piixDeviceTable[i].name;
	}
	return 0;
}

static bool
PIIXVerifyID(UInt32 pciID)
{
	return (PIIXGetName(pciID) == 0) ? false : true;
}

//--------------------------------------------------------------------------
// A hack to modify our PCI nub to have two interrupts.
// This code was borrowed from the setupIntelPIC() function
// in iokit/Families/IOPCIBus/IOPCIBridge.cpp.
//
static void setupProviderInterrupts(IOPCIDevice * nub, long irq_p, long irq_s)
{
	OSArray *         controller;
	OSArray *         specifier;
	OSData *          tmpData;
	extern OSSymbol * gIntelPICName;

	do {
		// Create the interrupt specifer array.
		specifier = OSArray::withCapacity(2);
		if (!specifier)
			break;

        tmpData = OSData::withBytes(&irq_p, sizeof(irq_p));
        if (tmpData) {
            specifier->setObject(tmpData);
            tmpData->release();
        }
        tmpData = OSData::withBytes(&irq_s, sizeof(irq_s));
        if (tmpData) {
            specifier->setObject(tmpData);
            tmpData->release();
        }

        controller = OSArray::withCapacity(2);
        if (controller) {
			controller->setObject(gIntelPICName);
			controller->setObject(gIntelPICName);

            // Put the two arrays into the property table.
			nub->setProperty(gIOInterruptControllersKey, controller);
            controller->release();
        }
        nub->setProperty(gIOInterruptSpecifiersKey, specifier);
        specifier->release();

    } while( false );
}

//--------------------------------------------------------------------------
// A static member function that returns the IDE channel for the
// current driver instance, and also registers the interrupts in
// the IOPCIDevice nub.
//
int AppleATAPIIX::PIIXGetChannel(IOPCIDevice * provider)
{
	static bool       primaryRegistered = false;
	int               rc;
	extern OSSymbol * gIntelPICName;

	PIIX_LOCK;
	
	if (primaryRegistered == false) {
		rc = PIIX_CHANNEL_PRIMARY;
		primaryRegistered = true;

		// Is this necessary?
		waitForService(resourceMatching(gIntelPICName));

		setupProviderInterrupts(provider, PIIX_P_IRQ, PIIX_S_IRQ);
	}
	else {
		rc = PIIX_CHANNEL_SECONDARY;
	}

	PIIX_UNLOCK;

	if (rc == PIIX_CHANNEL_SECONDARY) IOSleep(20);

	return rc;
}

//--------------------------------------------------------------------------
// Private function: _getIDERanges
//
// Setup the variables that stores the start of the Command and Control
// block in I/O space. The variable 'channel' must have been previously
// set. These ISA I/O ranges are implicit and does not show up in PCI
// config space.
//
bool AppleATAPIIX::_getIDERanges(IOPCIDevice * provider)
{
	ioCmdRange = (channel == PIIX_CHANNEL_PRIMARY) ?
                 PIIX_P_CMD_ADDR : PIIX_S_CMD_ADDR;
	
	ioCtlRange = (channel == PIIX_CHANNEL_PRIMARY) ?
                 PIIX_P_CTL_ADDR : PIIX_S_CTL_ADDR;

	DLOG("%s: ioCmdRange - %04x\n", getName(), ioCmdRange);
	DLOG("%s: ioCtlRange - %04x\n", getName(), ioCtlRange);

	return true;
}

//--------------------------------------------------------------------------
// Private function: _getBMRange
//
// Determine the start of the I/O mapped Bus-Master registers.
// This range is defined by PCI config space register PIIX_PCI_BMIBA.
//
bool AppleATAPIIX::_getBMRange(IOPCIDevice * provider)
{
	UInt32 bmiba;

	bmiba = provider->configRead32(PIIX_PCI_BMIBA);
	if ((bmiba & PIIX_PCI_BMIBA_RTE) == 0) {
		IOLog("%s: PCI memory range 0x%02x (0x%08lx) is not an I/O range\n",
			getName(), PIIX_PCI_BMIBA, bmiba);
		return false;
	}
	
	bmiba &= PIIX_PCI_BMIBA_MASK;	// get the address portion

	// If bmiba is zero, it is likely that the user has elected to
	// turn off PCI IDE support in the BIOS.
	//
	if (bmiba == 0)
		return false;

	if (channel == PIIX_CHANNEL_SECONDARY)
		bmiba += PIIX_IO_BM_OFFSET;

	ioBMRange = (UInt16) bmiba;
	
	DLOG("%s: ioBMRange - %04x\n", getName(), ioBMRange);

	return true;
}

//--------------------------------------------------------------------------
// Private function: _resetTimings()
//
// Reset all timing registers to the slowest (most compatible) timing.
// UDMA modes are disabled. We take a lock to prevent the other IDE
// channel from modifying the shared PCI config space.
//
bool AppleATAPIIX::_resetTimings()
{
	union {
		UInt32 b32;
		struct {
			UInt16 pri;
			UInt16 sec;
		} b16;
	} timing;

	UInt32  udmaControl;

	PIIX_LOCK;

	timing.b32 = provider->configRead32(PIIX_PCI_IDETIM);
	udmaControl = provider->configRead32(PIIX_PCI_UDMACTL);

	// Set slowest timing, and disable UDMA. Only modify the flags
	// associated with the local channel.
	//
	switch (channel) {
		case PIIX_CHANNEL_PRIMARY:
			timing.b16.pri &= PIIX_PCI_IDETIM_IDE;			
			udmaControl &= ~(PIIX_PCI_UDMACTL_PSDE0 | PIIX_PCI_UDMACTL_PSDE1);
			break;
		
		case PIIX_CHANNEL_SECONDARY:
			timing.b16.sec &= PIIX_PCI_IDETIM_IDE;
			udmaControl &= ~(PIIX_PCI_UDMACTL_SSDE0 | PIIX_PCI_UDMACTL_SSDE1);
			break;
	}

	provider->configWrite32(PIIX_PCI_UDMACTL, udmaControl);
	provider->configWrite32(PIIX_PCI_IDETIM,  timing.b32);

    // FIXME
    // No support for ATA/66 or ATA/100 modes. Set this register
    // to 0 (new in ICH2) to disable those faster timings.
    //
	provider->configWrite32(PIIX_PCI_IDECONFIG,  0);

	PIIX_UNLOCK;

	return true;
}

//--------------------------------------------------------------------------
// Private function: _allocatePRDTable()
//
// Allocate the physical region descriptor (PRD) table. The physical
// address of this table is stored in 'prdTablePhys'. Look at Intel
// documentation for the alignment requirements.
//
bool AppleATAPIIX::_allocatePRDTable()
{
	prdTable = (prdEntry_t *) IOMallocAligned(PRD_TABLE_SIZE, PAGE_SIZE);
	if (!prdTable)
		return false;

	prdTablePhys = (UInt32) pmap_extract(kernel_pmap, (vm_offset_t) prdTable);

	bzero(prdTable, PRD_TABLE_SIZE);

	return true;
}

//--------------------------------------------------------------------------
// Private function: _deallocatePRDTable()
//
void AppleATAPIIX::_deallocatePRDTable()
{
	IOFreeAligned(prdTable, PRD_TABLE_SIZE);
	prdTable = NULL;
	prdTablePhys = 0;
}

//--------------------------------------------------------------------------
// Function inherited from IOATAController.
//
// Configure the driver/controller. This is the first function called by
// our superclass, in its start() function, to initialize the controller
// hardware.
//
bool
AppleATAPIIX::configure(IOService * forProvider,
                        ATAControllerInfo * controllerInfo)
{
	UInt32  reg;

//	IOSleep(1000);

    provider = OSDynamicCast(IOPCIDevice, forProvider);
	if (!provider)
		return false;
	
	// Superclass performs an exclusive open on the provider, we close
	// it to allow more than one instance of this driver to attach to
	// the same PCI nub. We should maintain an non-exclusive open on
	// the provider.
	//
	provider->close(this);

	// Determine the type of PIIX controller. Save the controller's
	// PCI ID in pciCFID.
	//
	pciCFID = provider->configRead32(PIIX_PCI_CFID);
	if (PIIXVerifyID(pciCFID) == false) {
		IOLog("%s: Unknown PCI IDE controller (0x%08lx)\n",
              getName(),
              pciCFID);
		return false;
	}

	// Determine our IDE channel, primary or secondary.
	//
	channel = PIIXGetChannel(provider);

	_getIDERanges(provider);

	IOLog("%s: %s %s IDE controller, 0x%x, irq %d\n",
		getName(),
		(channel == PIIX_CHANNEL_PRIMARY) ? "Primary" : "Secondary",
		PIIXGetName(pciCFID),
		ioCmdRange,
		(channel == PIIX_CHANNEL_PRIMARY) ? PIIX_P_IRQ : PIIX_S_IRQ);

	// Check the I/O Space Enable bit in the PCI command register.
	// This is the master enable bit for the PIIX controller.
	// Each IDE channel also has its own enable bit, which is
	// checked later.
	//
	reg = provider->configRead32(PIIX_PCI_PCICMD);
	if ((reg & PIIX_PCI_PCICMD_IOSE) == 0) {
		IOLog("%s: PCI IDE controller is not enabled\n", getName());
		return false;
	}

	// Set BME bit to enable bus-master.
	//
	if ((reg & PIIX_PCI_PCICMD_BME) == 0) {
		reg |= PIIX_PCI_PCICMD_BME;
		PIIX_LOCK;
		provider->configWrite32(PIIX_PCI_PCICMD, reg);
		PIIX_UNLOCK;
	}

	// Fetch the corresponding primary/secondary IDETIM register and
	// check the individual channel enable bit.
	//
	reg = provider->configRead32(PIIX_PCI_IDETIM);
	if (channel == PIIX_CHANNEL_SECONDARY)
		reg >>= 16;		// PIIX_PCI_IDETIM + 2 for secondary channel

	if ((reg & PIIX_PCI_IDETIM_IDE) == 0) {
		IOLog("%s: %s PCI IDE channel is not enabled\n",
			getName(),
			(channel == PIIX_CHANNEL_PRIMARY) ? "Primary" : "Secondary");
		return false;
	}

	// Locate and add the I/O mapped bus-master registers to
	// ioRange[] array.
	//
	if (_getBMRange(provider) == false) {
		IOLog("%s: Bus master I/O range is invalid\n", getName());
		return false;
	}

	// Allocate page-aligned memory for the PRD table.
	//
	if (_allocatePRDTable() == false) {
		IOLog("%s: unable to allocate descriptor table\n", getName());
		return false;
	}

	// Allocate a cursor object to generate the scatter-gather list
	// for each transfer request. Maximum segment size is set to 64K.
	// However, there is no way to indicate our requirement that each
	// memory segment cannot cross a 64K boundary. We have to do this
	// manually.
	//
    prdCursor = IOLittleMemoryCursor::withSpecification(64 * 1024, 0xffffffff);
    if (prdCursor == 0)
        return false;

    // Attach an interruptEventSource to handle HW interrupts.
    // Must do this after PIIXGetChannel(), since thats where the
    // provider's interrupt property is set by setupProviderInterrupts().

    interruptEventSource = IOInterruptEventSource::interruptEventSource(
                     (OSObject *)             this,
                     (IOInterruptEventAction) &AppleATAPIIX::interruptOccurred,
                     (IOService *)            provider,
                     (channel == PIIX_CHANNEL_PRIMARY) ? 0 : 1);
    if (interruptEventSource == 0) {
		IOLog("%s: unable to create an IOInterruptEventSource object\n",
			  getName());
        return false;
	}

	disableControllerInterrupts();

    getWorkLoop()->addEventSource(interruptEventSource);

	// Revert to default (compatible) timing.
	//
	_resetTimings();

    controllerInfo->maxDevicesSupported 	= 2;
    controllerInfo->devicePrivateDataSize	= 0;
    controllerInfo->commandPrivateDataSize	= 0;
    controllerInfo->disableCancelCommands	= false;


	DLOG("AppleATAPIIX::%s() completed successfully\n", __FUNCTION__);

    return true;
}

//--------------------------------------------------------------------------
//
//
bool AppleATAPIIX::provideProtocols(enum ATAProtocol * protocolsSupported)
{
    return false;
}

//--------------------------------------------------------------------------
//
//
bool AppleATAPIIX::provideTimings(UInt32 *    numTimings,
                                  ATATiming * timingsSupported)
{
    return false;
}

//--------------------------------------------------------------------------
// Determine the timing selection based on the ATATiming structure given.
//
bool AppleATAPIIX::calculateTiming(UInt32 unit, ATATiming * pTiming)
{
	int           i;
	PIIXProtocol  protocol = ataToPIIXProtocol(pTiming->timingProtocol);

	DLOG("AppleATAPIIX::%s() - unit:%ld protocol:%d minCycles:%ld\n",
		 __FUNCTION__, unit, protocol, pTiming->minDataCycle);

	CHECK_UNIT(unit);

	timings[unit].validTimings[protocol] = 0;

	switch (protocol) {

		case kPIIXProtocolPIO:

			for (i = 0; i < PIIXPIOTimingTableSize; i++)
			{
				if (PIIXPIOTimingTable[i].pioMode == _NVM_)
					continue;

				if (PIIXPIOTimingTable[i].cycle < pTiming->minDataCycle)
					break;

				timings[unit].validTimings[protocol] = i;
			}
			break;

		case kPIIXProtocolDMA:

			for (i = 0; i < PIIXPIOTimingTableSize; i++)
			{
				if (PIIXPIOTimingTable[i].mwDMAMode == _NVM_)
					continue;

				if (PIIXPIOTimingTable[i].cycle < pTiming->minDataCycle)
					break;

				timings[unit].validTimings[protocol] = i;
			}
			break;
		
		case kPIIXProtocolUDMA33:
			
			for (i = 0; i < PIIXUDMATimingTableSize; i++)
			{
				if (PIIXUDMATimingTable[i].strobe < pTiming->minDataCycle)
					break;
			
				timings[unit].validTimings[protocol] = i;
			}
			break;
		
		default:
			return false;
	}

	timings[unit].validFlag |= (1 << protocol);

	return true;
}

//--------------------------------------------------------------------------
// Setup the timing register for the given timing protocol.
//
bool AppleATAPIIX::selectTiming(UInt32            unit,
                                ATATimingProtocol timingProtocol)
{
	bool          ret = false;
	UInt8         pciConfig[256];
	PIIXProtocol  protocol = ataToPIIXProtocol(timingProtocol);

	DLOG("AppleATAPIIX::%s() - unit:%ld protocol:%d\n",
		 __FUNCTION__, unit, protocol);

	CHECK_UNIT(unit);

	PIIX_LOCK;

	do {
		if (protocol >= kPIIXProtocolLast)
			break;
		
		if (PIIX_PROTOCOL_IS_VALID(protocol) == 0) {
			
			// superclass error, calculateTiming() was not called
			// before calling selectTiming().
			
			IOLog("%s: timing protocol selected is invalid\n", getName());
			break;
		}

		if (!_readPCIConfigSpace(pciConfig) ||
			!_selectTiming(unit, protocol, pciConfig) ||
			!_writePCIConfigSpace(pciConfig))
			break;

		ret = true;
	}
	while (0);

	PIIX_UNLOCK;

	return ret;
}

//--------------------------------------------------------------------------
// Setup the timing registers.
//
bool AppleATAPIIX::_selectTiming(UInt32         unit,
                                 PIIXProtocol   protocol,
								 UInt8 *        pciConfig)
{
	UInt8     isp, rtc;
	UInt8     index, dma, pio;
	bool      dmaActive;
	bool      pioActive;
	bool      useCompatiblePIOTiming = false;
	bool      ret = true;
	UInt16 *  idetim;
	UInt8 *   sidetim = (UInt8 *)  &pciConfig[PIIX_PCI_SIDETIM];
	UInt8 *   udmactl = (UInt8 *)  &pciConfig[PIIX_PCI_UDMACTL];
	UInt16 *  udmatim = (UInt16 *) &pciConfig[PIIX_PCI_UDMATIM];

	idetim = (channel == PIIX_CHANNEL_PRIMARY) ? 
             (UInt16 *) &pciConfig[PIIX_PCI_IDETIM] :
			 (UInt16 *) &pciConfig[PIIX_PCI_IDETIM_S];

	switch (protocol) {
		case kPIIXProtocolUDMA66:
			// Not yet!
			return false;

		case kPIIXProtocolUDMA33:
			if ((pciCFID == PCI_ID_PIIX) || (pciCFID == PCI_ID_PIIX3)) {
				// Only PIIX4 (and newer devices) supports UDMA.
				return false;
			}
			PIIX_DEACTIVATE_PROTOCOL(kPIIXProtocolDMA);
			break;

		case kPIIXProtocolDMA:
			PIIX_DEACTIVATE_PROTOCOL(kPIIXProtocolUDMA33);
			break;

		case kPIIXProtocolPIO:
			break;

		default:
			IOLog("%s: PIIX protocol not handled (%d)\n", getName(),
				  protocol);
			return false;
	}
	PIIX_ACTIVATE_PROTOCOL(protocol);


	if (PIIX_PROTOCOL_IS_ACTIVE(kPIIXProtocolUDMA33)) {

		index = PIIX_GET_ACTIVE_TIMING(kPIIXProtocolUDMA33);

		if (unit == 0) {
			if (channel == PIIX_CHANNEL_PRIMARY) {
				*udmactl |= PIIX_PCI_UDMACTL_PSDE0;
				SET_REG_FIELD(*udmatim, PIIX_PCI_UDMATIM_PCT0,
								PIIXUDMATimingTable[index].bits);
			}
			else {
				*udmactl |= PIIX_PCI_UDMACTL_SSDE0;
				SET_REG_FIELD(*udmatim, PIIX_PCI_UDMATIM_SCT0,
								PIIXUDMATimingTable[index].bits);
			}
		}
		else {
			if (channel == PIIX_CHANNEL_PRIMARY) {
				*udmactl |= PIIX_PCI_UDMACTL_PSDE1;
				SET_REG_FIELD(*udmatim, PIIX_PCI_UDMATIM_PCT1,
								PIIXUDMATimingTable[index].bits);
			}
			else {
				*udmactl |= PIIX_PCI_UDMACTL_SSDE1;
				SET_REG_FIELD(*udmatim, PIIX_PCI_UDMATIM_SCT1,
								PIIXUDMATimingTable[index].bits);
			}
		}
	}
	else {
		if (unit == 0) {
			if (channel == PIIX_CHANNEL_PRIMARY) {
				*udmactl &= ~PIIX_PCI_UDMACTL_PSDE0;
			}
			else {
				*udmactl &= ~PIIX_PCI_UDMACTL_SSDE0;
			}
		}
		else {
			if (channel == PIIX_CHANNEL_PRIMARY) {
				*udmactl &= ~PIIX_PCI_UDMACTL_PSDE1;
			}
			else {
				*udmactl &= ~PIIX_PCI_UDMACTL_SSDE1;
			}
		}
	}

	dmaActive = PIIX_PROTOCOL_IS_ACTIVE(kPIIXProtocolDMA);
	pioActive = PIIX_PROTOCOL_IS_ACTIVE(kPIIXProtocolPIO);
		
	if (dmaActive || pioActive) {

		dma = PIIX_GET_ACTIVE_TIMING(kPIIXProtocolDMA);
		pio = PIIX_GET_ACTIVE_TIMING(kPIIXProtocolPIO);

		// Early PIIX devices does not have a slave timing register.
		// Rather than switching timing registers whenever a new
		// drive was selected, We program in a (slower) timing that
		// is acceptable for both drive0 and drive1.

		if (pciCFID == PCI_ID_PIIX) {

			unit = (unit ^ 1) & 1;		// unit <- other drive unit

			if (PIIX_PROTOCOL_IS_ACTIVE(kPIIXProtocolPIO)) {
				if (!pioActive || 
					(PIIX_GET_ACTIVE_TIMING(kPIIXProtocolPIO) < pio)) {
					pio = PIIX_GET_ACTIVE_TIMING(kPIIXProtocolPIO);
				}
				pioActive = true;
			}

			if (PIIX_PROTOCOL_IS_ACTIVE(kPIIXProtocolDMA)) {
				if (!dmaActive ||
					(PIIX_GET_ACTIVE_TIMING(kPIIXProtocolDMA) < dma)) {
					dma = PIIX_GET_ACTIVE_TIMING(kPIIXProtocolDMA);
				}
				dmaActive = true;
			}

			*idetim &= ~PIIX_PCI_IDETIM_SITRE;	// disable slave timing
			unit = 0;
		}
		else {
			*idetim |= PIIX_PCI_IDETIM_SITRE;	// enable slave timing
		}

		// Pick an index to the PIIXPIOTimingTable[] for the new
		// timing selection.
		//
		if (dmaActive && pioActive) {

			// Both PIO and DMA are active, select DMA timing to
			// optimize DMA transfer.

			index = dma;		// pick DMA timing

			if (pio < dma)
				useCompatiblePIOTiming = true;
		}
		else if (dmaActive) {
			index = dma;
		}
		else {
			index = pio;
		}

		isp = PIIX_CLK_TO_ISP(PIIXPIOTimingTable[index].isp);
		rtc = PIIX_CLK_TO_RTC(PIIXPIOTimingTable[index].rtc);

		if (unit == 0) {
			SET_REG_FIELD(*idetim, PIIX_PCI_IDETIM_ISP, isp);
			SET_REG_FIELD(*idetim, PIIX_PCI_IDETIM_RTC, rtc);
			if (useCompatiblePIOTiming)
				*idetim |= PIIX_PCI_IDETIM_DTE0;
			else
				*idetim &= ~PIIX_PCI_IDETIM_DTE0;
			
			if (pciCFID == PCI_ID_PIIX) {
				if (useCompatiblePIOTiming)
					*idetim |= PIIX_PCI_IDETIM_DTE1;
				else
					*idetim &= ~PIIX_PCI_IDETIM_DTE1;
			}
		}
		else {
			if (channel == PIIX_CHANNEL_PRIMARY) {
				SET_REG_FIELD(*sidetim, PIIX_PCI_SIDETIM_PISP1, isp);
				SET_REG_FIELD(*sidetim, PIIX_PCI_SIDETIM_PRTC1, rtc);
			}
			else {
				SET_REG_FIELD(*sidetim, PIIX_PCI_SIDETIM_SISP1, isp);
				SET_REG_FIELD(*sidetim, PIIX_PCI_SIDETIM_SRTC1, rtc);
			}
			if (useCompatiblePIOTiming)
				*idetim |= PIIX_PCI_IDETIM_DTE1;
			else
				*idetim &= ~PIIX_PCI_IDETIM_DTE1;
		}

		*idetim |= (PIIX_PCI_IDETIM_TIME0 |
					PIIX_PCI_IDETIM_PPE0  | 
					PIIX_PCI_IDETIM_IE0   |
					PIIX_PCI_IDETIM_TIME1 |
					PIIX_PCI_IDETIM_PPE1  | 
					PIIX_PCI_IDETIM_IE1);
	}

#ifdef DEBUG_XXX
	IOLog("\n%s: %s channel\n", getName(), 
		  (channel == PIIX_CHANNEL_PRIMARY) ? "Primary" : "Secondary");
	IOLog("%s: IDETIM : %04x\n", getName(), *idetim);
	IOLog("%s: SIDETIM: %02x\n", getName(), *sidetim);
	IOLog("%s: UDMACTL: %02x\n", getName(), *udmactl);
	IOLog("%s: UDMATIM: %04x\n", getName(), *udmatim);
	IOLog("%s: Active : %04lx\n", getName(), timings[unit].activeFlag);
	IOLog("%s: Valid  : %04lx\n", getName(), timings[unit].validFlag);
	IOLog("%s: PIO:%d DMA:%d UDMA:%d\n\n", getName(),
		timings[unit].activeTimings[kPIIXProtocolPIO],
		timings[unit].activeTimings[kPIIXProtocolDMA],
		timings[unit].activeTimings[kPIIXProtocolUDMA33]);
#endif /* DEBUG */

	return ret;
}

//--------------------------------------------------------------------------
// Setup the descriptor table to perform the transfer indicated by the
// IOMemoryDescriptor in the IOATACommand object provided.
//
bool AppleATAPIIX::programDma(IOATAStandardCommand * cmd)
{
    IOPhysicalSegment       physSeg;
    IOByteCount				offset = 0;
    IOMemoryDescriptor *	memDesc;
	prdEntry_t *            prd = prdTable;
    UInt32					startSeg;
	UInt32                  endSeg;
	UInt32                  partialCount;
    UInt32					bytesLeft;

    cmd->getPointers(&memDesc, &dmaReqLength, &dmaIsWrite);

    if (dmaReqLength == 0)
        return true;

	bytesLeft = dmaReqLength;

	// Setup the PRD entries in the descriptor table in memory.
	//
    for (UInt32 i = 0; i < (PRD_ENTRIES - 1); i++, prd++)
	{
		if (prdCursor->getPhysicalSegments(memDesc, offset, &physSeg, 1) != 1)
			break;
		
		startSeg = (physSeg.location & ~0xffff);
		endSeg   = (physSeg.location + physSeg.length - 1) & ~0xffff;
		
		prd->base  = physSeg.location;
		prd->flags = 0;
		
		if (startSeg == endSeg) {			
			prd->count = PRD_COUNT(physSeg.length);
		}
		else {
			partialCount = (-physSeg.location & 0xffff);
			prd->count = PRD_COUNT(partialCount);
			prd++;
			i++;
			prd->base  = physSeg.location + partialCount;
			prd->count = physSeg.length - partialCount;
			prd->flags = 0;
		}
		
		bytesLeft -= physSeg.length;
		offset += physSeg.length;
	}
	if (bytesLeft != 0)
		return false;
	
	// Set the 'end-of-table' bit on the last PRD entry.
	//
	prd--;
	prd->flags = PRD_FLAG_EOT;

	/*
	 * Provide the starting address of the PRD table by loading the
	 * PRD Table Pointer Register.
	 */
	outl(IOREG(BMIDTPX), prdTablePhys);

	return true;
}

//--------------------------------------------------------------------------
// Start the DMA engine.
//
bool AppleATAPIIX::startDma(IOATAStandardCommand * cmd)
{
	/*
	 * Clear interrupt and error bits in the Status Register.
	 */
	outb(IOREG(BMISX), PIIX_IO_BMISX_ERROR   |
                       PIIX_IO_BMISX_IDEINTS |
					   PIIX_IO_BMISX_DMA0CAP |
					   PIIX_IO_BMISX_DMA1CAP);

	/*
	 * Engage the bus master by writing 1 to the start bit in the
	 * Command Register. Also set the RWCON bit for the direction
	 * of the data transfer.
	 */
	outb(IOREG(BMICX), (dmaIsWrite ? 0 : PIIX_IO_BMICX_RWCON) | 
	                   PIIX_IO_BMICX_SSBM);

	return true;
}

//--------------------------------------------------------------------------
// Stop the DMA engine.
//
bool AppleATAPIIX::stopDma(IOATAStandardCommand * cmd, UInt32 * transferCount)
{
	UInt8  bmisx;

	*transferCount = 0;
	
    if (dmaReqLength == 0)
        return true;

	outb(IOREG(BMICX), 0);	// stop the bus-master

	bmisx = inb(IOREG(BMISX));

	if ((bmisx & PIIX_IO_BMISX_STATUS) != PIIX_IO_BMISX_IDEINTS) {
		IOLog("AppleATAPIIX::%s() DMA error (0x%02x)\n", __FUNCTION__, bmisx);
		return false;
	}

	*transferCount = dmaReqLength;

	return true;
}

//--------------------------------------------------------------------------
// Perform a write to the ATA block registers.
//
void AppleATAPIIX::writeATAReg(UInt32 regIndex, UInt32 regValue)
{
    if (regIndex == 0) {
		outw(ioCmdRange, (UInt16) regValue);
    }
    else if (regIndex < kATARegDeviceControl) {
		outb(ioCmdRange + regIndex, (UInt8) regValue);
    }     
    else {
		outb(ioCtlRange + regIndex - kATARegDeviceControl + 2, 
		     (UInt8) regValue);
    }
}

//--------------------------------------------------------------------------
// Perform a read from the ATA block registers.
//
UInt32 AppleATAPIIX::readATAReg( UInt32 regIndex )
{
    if (regIndex == 0) {
		return inw(ioCmdRange);
    }
    else if (regIndex < kATARegDeviceControl) {
		return inb(ioCmdRange + regIndex);
    }
	return inb(ioCtlRange + regIndex - kATARegDeviceControl + 2);
}

//--------------------------------------------------------------------------
// Frees the drivers instance. Make sure all objects allocated during
// our initialization are freed.
//
void AppleATAPIIX::free()
{
    if (interruptEventSource) {
        interruptEventSource->disable();
        interruptEventSource->release();
    }
  
	if (prdCursor)
		prdCursor->release();
 
    if (prdTable != 0)
		_deallocatePRDTable();
	
	return super::free();
}

//--------------------------------------------------------------------------
// This function is called when our interruptEventSource receives an
// interrupt. Simply pass the action to our superclass to advance its
// state machine.
//
void AppleATAPIIX::interruptOccurred()
{
    super::interruptOccurred();
}

//--------------------------------------------------------------------------
// This function is called by our superclass to disable controller
// interrupts.
//
void AppleATAPIIX::disableControllerInterrupts()
{
    interruptEventSource->disable();
}

//--------------------------------------------------------------------------
// This function is called by our superclass to enable controller
// interrupts.
//
void AppleATAPIIX::enableControllerInterrupts()
{
    interruptEventSource->enable();
}

//--------------------------------------------------------------------------
// Private function: _readPCIConfigSpace
//
// Read the entire PCI config space and stores it to the buffer
// pointed by 'configSpace'.
//
bool AppleATAPIIX::_readPCIConfigSpace(UInt8 * configSpace)
{
	UInt32 * dwordPtr = (UInt32 *) configSpace;

	for (int i = 0; i < 64; i++, dwordPtr++)
		*dwordPtr = provider->configRead32(i * 4);

	return true;
}

//--------------------------------------------------------------------------
// Private function: _writePCIConfigSpace
//
// Write the entire PCI config space from the buffer pointed
// by 'configSpace'.
//
bool AppleATAPIIX::_writePCIConfigSpace(UInt8 * configSpace)
{
	UInt32 * dwordPtr = (UInt32 *) configSpace;

	for (int i = 0; i < 64; i++, dwordPtr++)
		provider->configWrite32(i * 4, *dwordPtr);

	return true;
}
