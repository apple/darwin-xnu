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
 * Copyright (c) 1999-2000 Apple Computer, Inc.  All rights reserved.
 *
 */

extern "C" {
#include <ppc/proc_reg.h>
}

#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOPlatformExpert.h>

#include "GossamerCPU.h"
#include "Gossamer.h"

extern "C" {
unsigned int ml_throttle(unsigned int step);
int kdp_getc(void);
void machine_idle(void);
}

// Uncomment the following define to get verbose logs on the sleep/wake cycles
//#define VERBOSE_LOGS_ON


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define super IOCPU

OSDefineMetaClassAndStructors(GossamerCPU, IOCPU);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

UInt32 GossamerCPU::restartAddress = 0x100;

IOService *GossamerCPU::findIOInterface(char *name)
{
    OSDictionary         *dict;
    IOService            *service;

    heathrow = NULL;

    // find the dictionary of the Heathrow matches.
    dict = serviceMatching(name);
    if (dict == NULL) {
#ifdef VERBOSE_LOGS_ON
        kprintf("GossamerCPU::findIOInterface faild to get a matching dictionary for %s\n", name);
#endif // VERBOSE_LOGS_ON
        return NULL;
    }

    service = waitForService(dict, NULL);
    if (service == NULL) {
#ifdef VERBOSE_LOGS_ON
        kprintf("GossamerCPU::findIOInterface failed to get a matching service for %s\n", name);
#endif// VERBOSE_LOGS_ON
        return NULL;
    }

    return (service);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool GossamerCPU::start(IOService *provider)
{
    kern_return_t       result;
    ml_processor_info_t processor_info;
    bool                 success = super::start(provider);
    GossamerPE		 *gossamerBoard;

    if (!success)
        return false;

    // callPlatformFunction symbols
    heathrow_sleepState = OSSymbol::withCString("heathrow_sleepState");
    heathrow_set_light = OSSymbol::withCString("heathrow_set_light");
    cuda_check_any_interrupt = OSSymbol::withCString("cuda_check_any_interrupt");
    usb_remote_wakeup = OSSymbol::withCString("usb_remote_wakeup");

#ifdef VERBOSE_LOGS_ON
   kprintf("GossamerCPU::start start\n");
#endif // VERBOSE_LOGS_ON

    // Checks the board:
    gossamerBoard = OSDynamicCast(GossamerPE, getPlatform());
    if (gossamerBoard == 0) {
#ifdef VERBOSE_LOGS_ON
        kprintf("GossamerCPU::start this is not a GossamerPE\n");
#endif // VERBOSE_LOGS_ON
        return false;
    }

    cpuIC = new IOCPUInterruptController;
    if (cpuIC == 0)
        return false;

    if (cpuIC->initCPUInterruptController(1) != kIOReturnSuccess) return false;
    cpuIC->attach(this);

    cpuIC->registerCPUInterruptController();

    processor_info.cpu_id           = (cpu_id_t)this;
    processor_info.boot_cpu         = true;
    processor_info.start_paddr      = restartAddress;
    processor_info.l2cr_value       = mfl2cr() & 0x7FFFFFFF;  // cache-disabled value
    processor_info.supports_nap     = false;                  // doze, do not nap
    processor_info.time_base_enable = 0;

    // Register this CPU with mach.
    result = ml_processor_register(&processor_info, &machProcessor,
                                   &ipi_handler);
    if (result == KERN_FAILURE)
        return false;

    setCPUState(kIOCPUStateUninitalized);

    processor_start(machProcessor);

#ifdef VERBOSE_LOGS_ON
    kprintf("GossamerCPU::start end %d \n", success);
#endif // VERBOSE_LOGS_ON

    registerService();

    return success;
}

void GossamerCPU::ipiHandler(void *refCon, void *nub, int source)
{
    // Call mach IPI handler for this CPU.
    if (ipi_handler)
        ipi_handler();
}

void GossamerCPU::initCPU(bool boot)
{
#ifdef VERBOSE_LOGS_ON
    kprintf("GossamerCPU::initCPU start\n");
#endif // VERBOSE_LOGS_ON

    if (grackle != NULL) {
        IOPCIAddressSpace grackleSpace;
        UInt32 grackleMemConfiguration;

#ifdef VERBOSE_LOGS_ON
        kprintf("GossamerCPU::initCPU AppleGracklePCI sets the ram in autorefresh off\n");
#endif // VERBOSE_LOGS_ON

        grackleSpace.bits = 0x80000000;
        grackleMemConfiguration = grackle->configRead32(grackleSpace, 0x70);
        
#ifdef VERBOSE_LOGS_ON
        kprintf("GossamerCPU::initCPU AppleGracklePCI current power managment mode :0x%08lx\n", grackleMemConfiguration);
#endif // VERBOSE_LOGS_ON

        // Disables NAP and PM
        grackleMemConfiguration &= ~(0x90);
#ifdef VERBOSE_LOGS_ON
        kprintf("GossamerCPU::initCPU AppleGracklePCI new power managment mode :0x%08lx\n", grackleMemConfiguration);
#endif // VERBOSE_LOGS_ON

        grackle->configWrite32(grackleSpace, 0x70, grackleMemConfiguration);

        grackle = NULL;
    }
    else
        kprintf("GossamerCPU::initCPU not found AppleGracklePCI\n");

    if (heathrow != NULL) {
        // we are waking up from sleep so:
        heathrow->callPlatformFunction(heathrow_sleepState, false, (void *)false, 0, 0, 0);
        heathrow = NULL;
    }
    else
        kprintf("GossamerCPU::initCPU not found Heathrow\n");

    /*
     The following code is commented because the only Gossamer machine with a pci 2 pci Bridge
     is the BWG3 and in that machine we do not remove power from the bridge. I am however leaving
     this code here as reference (and to make clear that it is not running for a reason)
    // Restore the PCI-PCI Bridge.
    if (pci2pciBridge != NULL)
        pci2pciBridge->restoreBridgeState(); */

    // Restore time base after wake (since CPU's TBR was set to zero during sleep)
    if(!boot)
        saveTimeBase(false);

    // Init the interrupts.
    if (boot)
        cpuIC->enableCPUInterrupt(this);

    setCPUState(kIOCPUStateRunning);

    gossamerPE = OSDynamicCast(GossamerPE, getPlatform());
    if (gossamerPE ) {
	//Initially Gossamers with Cuda are not in sleep mode
	gossamerPE->setProperty("GossamerCudaSleeping", false);
    }

#ifdef VERBOSE_LOGS_ON
    kprintf("GossamerCPU::initCPU end\n");
#endif VERBOSE_LOGS_ON
}

//extern "C" void _gossamer_cpu_wake(void);
extern UInt32 ResetHandler;

#ifdef VERBOSE_LOGS_ON
// The following function exist only to check that the wake vector is placed correctly.
static void
cpu_foo_wake()
{
    __asm__ volatile("_gossamer_cpu_wake:");
    //kprintf("_gossamer_cpu_wake going to 0x100\n");
    __asm__ volatile("            ba      0x100");
}
#endif // VERBOSE_LOGS_ON

// flushes the cash for a word at the given address.
#define cFlush(addr) __asm__ volatile("dcbf	0, %0" : : "r" (addr))

extern "C" {
    void gossamer_cpu_wake(void);
    extern void cacheInit(void);
    extern void cacheDisable(void);
}

void GossamerCPU::quiesceCPU(void)
{
    UInt32 larsCode = (((UInt32)'L') << 24) | (((UInt32)'a') << 16) | (((UInt32)'r') << 8) | (((UInt32)'s') << 0);
    UInt32 restartReferencePhi = pmap_extract(kernel_pmap,(vm_address_t)&restartAddress);

    // disables the interrupts (they should be already disabled, but one more tiem won't hurt):
    ml_set_interrupts_enabled(FALSE);
    
#ifdef VERBOSE_LOGS_ON
    kprintf("GossamerCPU::quiesceCPU BEFORE 0x%08lx 0x%08lx start\n", 0x00000000, ml_phys_read(0x00000000));
    kprintf("GossamerCPU::quiesceCPU BEFORE 0x%08lx 0x%08lx start\n", 0x00000004, ml_phys_read(0x00000004));

    // Set the wake vector to point to the my checkpoint vector
    ml_phys_write(restartReferencePhi, gossamer_cpu_wake); //restartAddress = gossamer_cpu_wake;   
    eieio();
#else
     // Set the wake vector to point to the reset vector
    ml_phys_write(restartReferencePhi, 0x100); //restartAddress = 0x100;   
    eieio();
#endif // VERBOSE_LOGS_ON

    ml_phys_write(0x00000000, restartReferencePhi);
    eieio();

    // Set the wake vector to point to the reset vector
    ml_phys_write(0x00000004, larsCode);
    eieio();

    // and flushes the data cache:
    flush_dcache(restartReferencePhi, 4, true);
    flush_dcache(0x00000000, 8, true);

    // Also makes sure that the reset hander is correctly flushed:
    flush_dcache(&ResetHandler, 12, true);

    __asm__ volatile("sync");
    __asm__ volatile("isync");

#ifdef VERBOSE_LOGS_ON
    kprintf("GossamerCPU::quiesceCPU AFTER 0x%08lx 0x%08lx start\n", 0x00000000, ml_phys_read(0x00000000));
    kprintf("GossamerCPU::quiesceCPU AFTER 0x%08lx 0x%08lx start\n", ml_phys_read(0x00000000), ml_phys_read(ml_phys_read(0x00000000)));
    kprintf("GossamerCPU::quiesceCPU AFTER 0x%08lx 0x%08lx start\n", 0x00000004, ml_phys_read(0x00000004));
#endif

    // Send PMU command to shutdown system before io is turned off
    if (pmu != 0)
        pmu->callPlatformFunction("sleepNow", false, 0, 0, 0, 0);
    else
        kprintf("GossamerCPU::quiesceCPU can't find ApplePMU\n");

    if (heathrow != NULL) {
        heathrow->callPlatformFunction(heathrow_sleepState, false, (void *)true, 0, 0, 0);
    }
    else
        kprintf("GossamerCPU::quiesceCPU not found Heathrow\n");

    if (grackle != NULL) {
        IOPCIAddressSpace grackleSpace;
        UInt32 grackleProcConfiguration, grackleMemConfiguration;

#ifdef VERBOSE_LOGS_ON
        kprintf("GossamerCPU::quiesceCPU AppleGracklePCI sets the ram in autorefresh\n");

        grackleSpace.bits = 0x80000000;
        grackleProcConfiguration = grackle->configRead32(grackleSpace, 0xA8);
        kprintf("GossamerCPU::quiesceCPU AppleGracklePCI current processorinterface conf :0x%08lx\n", grackleProcConfiguration);
#endif // VERBOSE_LOGS_ON
   
        grackleSpace.bits = 0x80000000;
        grackleMemConfiguration = grackle->configRead32(grackleSpace, 0x70);
#ifdef VERBOSE_LOGS_ON
        kprintf("GossamerCPU::quiesceCPU AppleGracklePCI current power managment mode :0x%08lx\n", grackleMemConfiguration);
#endif // VERBOSE_LOGS_ON

        // Enables NAP and PM
        grackleMemConfiguration |= 0x90;
#ifdef VERBOSE_LOGS_ON
        kprintf("GossamerCPU::quiesceCPU AppleGracklePCI new power managment mode :0x%08lx\n", grackleMemConfiguration);
#endif // VERBOSE_LOGS_ON

        grackle->configWrite32(grackleSpace, 0x70, grackleMemConfiguration);
    }
    else
        kprintf("GossamerCPU::quiesceCPU not found AppleGracklePCI\n");

    // Save time base before sleep since CPU's TBR will be set to zero at wake.
    saveTimeBase(true);

    // These make all the difference between a succesful wake and a crash,
    // however it is still unclear why this happens. I'll leave to B.A. to
    // figure it out.
    cacheInit();
    cacheDisable();

#ifdef VERBOSE_LOGS_ON
    kprintf("GossamerCPU::quiesceCPU calling ml_ppc_sleep\n");
#endif // VERBOSE_LOGS_ON

    // Now we loop here waiting for the PMU to kick in and sleep the machine.
    // We do NOT call ml_ppc_sleep because while ml_ppc_sleep works greate for Core99
    // it has some problems with Gossamer CPUS. Also the code in ml_ppc_sleep to
    // clear the interrupts (and so keep the processor in its sleep state) is needed
    // by the Core99 platform (otherwise the machine does not sleep), but it is totally
    // useless for Gossamer CPUs since whatever is the state of the CPU the pmu
    // will put the whole system to sleep.

    while(true) {
    }

    //ml_ppc_sleep();
}

const OSSymbol *GossamerCPU::getCPUName(void)
{
    return OSSymbol::withCStringNoCopy("Primary0");
}

kern_return_t GossamerCPU::startCPU(vm_offset_t /*start_paddr*/,
					    vm_offset_t /*arg_paddr*/)
{
  return KERN_FAILURE;
}

void GossamerCPU::haltCPU(void)
{
    long	machine_type;
    grackle = NULL;

    grackle = (IOPCIBridge *)findIOInterface("AppleGracklePCI")->metaCast("IOPCIBridge");
    if (grackle == NULL)
        kprintf("GossamerCPU::haltCPU missing grackle\n");

    pci2pciBridge = NULL;

    // Finds heathrow and pmu because we need them in quienceCPU. We can
    // not put the "findIOInterface" code there because it may block and
    // quienceCPU runs in interrupt context.
    heathrow = OSDynamicCast(IOService, findIOInterface("Heathrow"));
    //Actually, pmu find is moved below because it hangs when beige G3 go to sleep

    /*
     The following code is commented because the only Gossamer machine with a pci 2 pci Bridge
     is the BWG3 and in that machine we do not remove power from the bridge. I am however leaving
     this code here as reference (and to make clear that it is not running for a reason)
     IORegistryEntry *pci2pciBridgeEntry = fromPath("/pci@80000000/@d", gIODTPlane);
     IOService *pci2pciBridgeNub = OSDynamicCast(IOService, pci2pciBridgeEntry);
     if (pci2pciBridgeNub != NULL) {
         pci2pciBridge = OSDynamicCast(IOPCI2PCIBridge, pci2pciBridgeNub->getClient());
     }

     if (pci2pciBridge != NULL)
     pci2pciBridge->saveBridgeState();
     */
#ifdef VERBOSE_LOGS_ON
    kprintf("GossamerCPU::haltCPU Here!\n");
#endif // VERBOSE_LOGS_ON

    gossamerPE = OSDynamicCast(GossamerPE, getPlatform());
    if (gossamerPE == 0 )  
    {
	processor_exit(machProcessor); 
	return;
    }
    machine_type = gossamerPE->getMachineType();

    //Isolate only those Gossamers that have a Cuda, not PG&E
    if ((machine_type != kGossamerType101) && (machine_type != kGossamerTypeWallstreet))
    {
	mach_timespec_t     t;
	IOService  *cudaDriver;
	IOService  *usbOHCIDriver;
	bool	anyint = false;

	t.tv_sec = 1;
	t.tv_nsec = 0;
	cudaDriver = waitForService(serviceMatching("AppleCuda"), &t);
	usbOHCIDriver = waitForService(serviceMatching("AppleUSBOHCI"), &t);
	
	if ((heathrow != NULL) && (machine_type == kGossamerTypeYosemite))
	{
	    heathrow->callPlatformFunction(heathrow_set_light, false, (void *)false, 0, 0, 0);	    
	}

	gossamerPE->setProperty("GossamerCudaSleeping", true);
	ml_throttle(254);  	//throttle cpu speed as much as possible

	while (true) //sit here in a loop, pretending to be asleep
	{
	    machine_idle();	//Max power savings for G3 CPU, needs interrupts enabled.
				//   It will return when any interrupt occurs
	    if (cudaDriver != NULL)
	    {
		anyint = false;
		cudaDriver->callPlatformFunction(cuda_check_any_interrupt, false, (void *)&anyint, 0, 0, 0);
		if (anyint)
		{
		    break;
		}		
	    }

	    if (usbOHCIDriver != NULL)
	    {
		anyint = false;
		usbOHCIDriver->callPlatformFunction(usb_remote_wakeup, false, (void *)&anyint, 0, 0, 0);
		if (anyint)
		{
		    break;
		}		
	    }
	    IOSleep(7);	//allows USB thread to run since no more thread scheduling.  1 ms
			// is enough for slow Yosemite, 7 is needed for iMacs.
	}

	ml_throttle(0);		//remove throttle from CPU speed

	gossamerPE->setProperty("GossamerCudaSleeping", false);
	
	if ((heathrow != NULL) && (machine_type == kGossamerTypeYosemite))
	{
	    heathrow->callPlatformFunction(heathrow_set_light, false, (void *)true, 0, 0, 0);	    
	}
    
    }
    else
    {
	pmu = OSDynamicCast(IOService, findIOInterface("ApplePMU"));
processor_exit(machProcessor); 
    }
}

void GossamerCPU::saveTimeBase(bool save)
{
    if(save) {        	// Save time base.
        do {
          tbHigh  = mftbu();
          tbLow   = mftb();
          tbHigh2 = mftbu();
        } while (tbHigh != tbHigh2);
    } else {		// Restore time base
        mttb(0);
        mttbu(tbHigh);
        mttb(tbLow);
    }
}

