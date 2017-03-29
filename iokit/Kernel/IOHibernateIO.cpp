/*
 * Copyright (c) 2004-2016 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

/*

Sleep:

- PMRootDomain calls IOHibernateSystemSleep() before system sleep
(devices awake, normal execution context)
- IOHibernateSystemSleep opens the hibernation file (or partition) at the bsd level, 
  grabs its extents and searches for a polling driver willing to work with that IOMedia.
  The BSD code makes an ioctl to the storage driver to get the partition base offset to
  the disk, and other ioctls to get the transfer constraints 
  If successful, the file is written to make sure its initially not bootable (in case of
  later failure) and nvram set to point to the first block of the file. (Has to be done
  here so blocking is possible in nvram support).
  hibernate_setup() in osfmk is called to allocate page bitmaps for all dram, and
  page out any pages it wants to (currently zero, but probably some percentage of memory).
  Its assumed just allocating pages will cause the VM system to naturally select the best
  pages for eviction. It also copies processor flags needed for the restore path and sets
  a flag in the boot processor proc info.
  gIOHibernateState = kIOHibernateStateHibernating.
- Regular sleep progresses - some drivers may inspect the root domain property 
  kIOHibernateStateKey to modify behavior. The platform driver saves state to memory
  as usual but leaves motherboard I/O on.
- Eventually the platform calls ml_ppc_sleep() in the shutdown context on the last cpu,
  at which point memory is ready to be saved. mapping_hibernate_flush() is called to get
  all ppc RC bits out of the hash table and caches into the mapping structures.
- hibernate_write_image() is called (still in shutdown context, no blocking or preemption).
  hibernate_page_list_setall() is called to get a bitmap of dram pages that need to be saved.
  All pages are assumed to be saved (as part of the wired image) unless explicitly subtracted
  by hibernate_page_list_setall(), avoiding having to find arch dependent low level bits.
  The image header and block list are written. The header includes the second file extent so
  only the header block is needed to read the file, regardless of filesystem.
  The kernel segment "__HIB" is written uncompressed to the image. This segment of code and data 
  (only) is used to decompress the image during wake/boot.
  Some additional pages are removed from the bitmaps - the buffers used for hibernation.
  The bitmaps are written to the image.
  More areas are removed from the bitmaps (after they have been written to the image) - the 
  segment "__HIB" pages and interrupt stack.
  Each wired page is compressed and written and then each non-wired page. Compression and 
  disk writes are in parallel.
  The image header is written to the start of the file and the polling driver closed.
  The machine powers down (or sleeps).
  
Boot/Wake:

- BootX sees the boot-image nvram variable containing the device and block number of the image,
  reads the header and if the signature is correct proceeds. The boot-image variable is cleared.
- BootX reads the portion of the image used for wired pages, to memory. Its assumed this will fit
  in the OF memory environment, and the image is decrypted. There is no decompression in BootX,
  that is in the kernel's __HIB section.
- BootX copies the "__HIB" section to its correct position in memory, quiesces and calls its entry
  hibernate_kernel_entrypoint(), passing the location of the image in memory. Translation is off, 
  only code & data in that section is safe to call since all the other wired pages are still 
  compressed in the image.
- hibernate_kernel_entrypoint() removes pages occupied by the raw image from the page bitmaps.
  It uses the bitmaps to work out which pages can be uncompressed from the image to their final
  location directly, and copies those that can't to interim free pages. When the image has been
  completed, the copies are uncompressed, overwriting the wired image pages.
  hibernate_restore_phys_page() (in osfmk since its arch dependent, but part of the "__HIB" section)
  is used to get pages into place for 64bit.
- the reset vector is called (at least on ppc), the kernel proceeds on a normal wake, with some
  changes conditional on the per proc flag - before VM is turned on the boot cpu, all mappings
  are removed from the software strutures, and the hash table is reinitialized. 
- After the platform CPU init code is called, hibernate_machine_init() is called to restore the rest
  of memory, using the polled mode driver, before other threads can run or any devices are turned on.
  This reduces the memory usage for BootX and allows decompression in parallel with disk reads,
  for the remaining non wired pages. 
- The polling driver is closed down and regular wake proceeds. When the kernel calls iokit to wake
  (normal execution context) hibernate_teardown() in osmfk is called to release any memory, the file
  is closed via bsd.

Polled Mode I/O:

IOHibernateSystemSleep() finds a polled mode interface to the ATA controller via a property in the
registry, specifying an object of calls IOPolledInterface.

Before the system goes to sleep it searches from the IOMedia object (could be a filesystem or
partition) that the image is going to live, looking for polled interface properties. If it finds
one the IOMedia object is passed to a "probe" call for the interface to accept or reject. All the
interfaces found are kept in an ordered list.

There is an Open/Close pair of calls made to each of the interfaces at various stages since there are 
few different contexts things happen in:

- there is an Open/Close (Preflight) made before any part of the system has slept (I/O is all
up and running) and after wake - this is safe to allocate memory and do anything. The device
ignores sleep requests from that point since its a waste of time if it goes to sleep and
immediately wakes back up for the image write.

- there is an Open/Close (BeforeSleep) pair made around the image write operations that happen
immediately before sleep. These can't block or allocate memory - the I/O system is asleep apart
from the low level bits (motherboard I/O etc). There is only one thread running. The close can be 
used to flush and set the disk to sleep.

- there is an Open/Close (AfterSleep) pair made around the image read operations that happen
immediately after sleep. These can't block or allocate memory. This is happening after the platform
expert has woken the low level bits of the system, but most of the I/O system has not. There is only
one thread running.

For the actual I/O, all the ops are with respect to a single IOMemoryDescriptor that was passed
(prepared) to the Preflight Open() call. There is a read/write op, buffer offset to the IOMD for
the data, an offset to the disk and length (block aligned 64 bit numbers), and completion callback.
Each I/O is async but only one is ever outstanding. The polled interface has a checkForWork call
that is called for the hardware to check for events, and complete the I/O via the callback.
The hibernate path uses the same transfer constraints the regular cluster I/O path in BSD uses
to restrict I/O ops.
*/

#include <sys/systm.h>

#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOKitDebug.h>
#include <IOKit/IOTimeStamp.h>
#include <IOKit/pwr_mgt/RootDomain.h>
#include <IOKit/pwr_mgt/IOPMPrivate.h>
#include <IOKit/IOMessage.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOBSD.h>
#include "RootDomainUserClient.h"
#include <IOKit/pwr_mgt/IOPowerConnection.h>
#include "IOPMPowerStateQueue.h"
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/AppleKeyStoreInterface.h>
#include <libkern/crypto/aes.h>

#include <sys/uio.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/fcntl.h>                       // (FWRITE, ...)
#include <sys/sysctl.h>
#include <sys/kdebug.h>
#include <stdint.h>

#include <IOKit/IOHibernatePrivate.h>
#include <IOKit/IOPolledInterface.h>
#include <IOKit/IONVRAM.h>
#include "IOHibernateInternal.h"
#include <vm/WKdm_new.h>
#include <vm/vm_protos.h>
#include "IOKitKernelInternal.h"
#include <pexpert/device_tree.h>

#include <machine/pal_routines.h>
#include <machine/pal_hibernate.h>
#include <i386/tsc.h>
#include <i386/cpuid.h>

extern "C" addr64_t		kvtophys(vm_offset_t va);
extern "C" ppnum_t		pmap_find_phys(pmap_t pmap, addr64_t va);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define	DISABLE_TRIM		0
#define TRIM_DELAY		25000

extern unsigned int		save_kdebug_enable;
extern uint32_t 		gIOHibernateState;
uint32_t			gIOHibernateMode;
static char			gIOHibernateBootSignature[256+1];
static char			gIOHibernateFilename[MAXPATHLEN+1];
static uint32_t			gIOHibernateFreeRatio = 0;	 // free page target (percent)
uint32_t			gIOHibernateFreeTime  = 0*1000;  // max time to spend freeing pages (ms)
static uint64_t			gIOHibernateCompression = 0x80;  // default compression 50%
boolean_t                       gIOHibernateStandbyDisabled;

static IODTNVRAM *		gIOOptionsEntry;
static IORegistryEntry *	gIOChosenEntry;

static const OSSymbol * 	gIOHibernateBootImageKey;

#if defined(__i386__) || defined(__x86_64__)

static const OSSymbol * 	gIOHibernateRTCVariablesKey;
static const OSSymbol *         gIOHibernateBoot0082Key;
static const OSSymbol *         gIOHibernateBootNextKey;
static OSData *	                gIOHibernateBoot0082Data;
static OSData *	                gIOHibernateBootNextData;
static OSObject *		gIOHibernateBootNextSave;

static IOPolledFileIOVars *     gDebugImageFileVars;
static IOLock             *     gDebugImageLock;

#endif /* defined(__i386__) || defined(__x86_64__) */

static IOLock *                           gFSLock;
static uint32_t                           gFSState;
static thread_call_t                      gIOHibernateTrimCalloutEntry;
static IOPolledFileIOVars	          gFileVars;
static IOHibernateVars			  gIOHibernateVars;
static IOPolledFileCryptVars 		  gIOHibernateCryptWakeContext;
static hibernate_graphics_t  		  _hibernateGraphics;
static hibernate_graphics_t * 		  gIOHibernateGraphicsInfo = &_hibernateGraphics;
static hibernate_statistics_t		  _hibernateStats;
static hibernate_statistics_t *		  gIOHibernateStats = &_hibernateStats;

enum 
{
    kFSIdle      = 0,
    kFSOpening   = 2,
    kFSOpened    = 3,
    kFSTimedOut  = 4,
    kFSTrimDelay = 5
};

static IOReturn IOHibernateDone(IOHibernateVars * vars);
static IOReturn IOWriteExtentsToFile(IOPolledFileIOVars * vars, uint32_t signature);
static void     IOSetBootImageNVRAM(OSData * data);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

enum { kDefaultIOSize = 128 * 1024 };
enum { kVideoMapSize  = 80 * 1024 * 1024 };

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// copy from phys addr to MD

static IOReturn
IOMemoryDescriptorWriteFromPhysical(IOMemoryDescriptor * md,
				    IOByteCount offset, addr64_t bytes, IOByteCount length)
{
    addr64_t srcAddr = bytes;
    IOByteCount remaining;

    remaining = length = min(length, md->getLength() - offset);
    while (remaining) {	// (process another target segment?)
        addr64_t    dstAddr64;
        IOByteCount dstLen;

        dstAddr64 = md->getPhysicalSegment(offset, &dstLen, kIOMemoryMapperNone);
        if (!dstAddr64)
            break;

        // Clip segment length to remaining
        if (dstLen > remaining)
            dstLen = remaining;

#if 1
	bcopy_phys(srcAddr, dstAddr64, dstLen);
#else
        copypv(srcAddr, dstAddr64, dstLen,
                            cppvPsnk | cppvFsnk | cppvNoRefSrc | cppvNoModSnk | cppvKmap);
#endif
        srcAddr   += dstLen;
        offset    += dstLen;
        remaining -= dstLen;
    }

    assert(!remaining);

    return remaining ? kIOReturnUnderrun : kIOReturnSuccess;
}

// copy from MD to phys addr

static IOReturn
IOMemoryDescriptorReadToPhysical(IOMemoryDescriptor * md,
				 IOByteCount offset, addr64_t bytes, IOByteCount length)
{
    addr64_t dstAddr = bytes;
    IOByteCount remaining;

    remaining = length = min(length, md->getLength() - offset);
    while (remaining) {	// (process another target segment?)
        addr64_t    srcAddr64;
        IOByteCount dstLen;

        srcAddr64 = md->getPhysicalSegment(offset, &dstLen, kIOMemoryMapperNone);
        if (!srcAddr64)
            break;

        // Clip segment length to remaining
        if (dstLen > remaining)
            dstLen = remaining;

#if 1
	bcopy_phys(srcAddr64, dstAddr, dstLen);
#else
        copypv(srcAddr, dstAddr64, dstLen,
                            cppvPsnk | cppvFsnk | cppvNoRefSrc | cppvNoModSnk | cppvKmap);
#endif
        dstAddr    += dstLen;
        offset     += dstLen;
        remaining  -= dstLen;
    }

    assert(!remaining);

    return remaining ? kIOReturnUnderrun : kIOReturnSuccess;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void
hibernate_set_page_state(hibernate_page_list_t * page_list, hibernate_page_list_t * page_list_wired,
				vm_offset_t ppnum, vm_offset_t count, uint32_t kind)
{
    count += ppnum;
    switch (kind)
    {
      case kIOHibernatePageStateUnwiredSave:
	// unwired save
	for (; ppnum < count; ppnum++)
	{
	    hibernate_page_bitset(page_list,       FALSE, ppnum);
	    hibernate_page_bitset(page_list_wired, TRUE,  ppnum);
	}
	break;
      case kIOHibernatePageStateWiredSave:
	// wired save
	for (; ppnum < count; ppnum++)
	{
	    hibernate_page_bitset(page_list,       FALSE, ppnum);
	    hibernate_page_bitset(page_list_wired, FALSE, ppnum);
	}
	break;
      case kIOHibernatePageStateFree:
	// free page
	for (; ppnum < count; ppnum++)
	{
	    hibernate_page_bitset(page_list,       TRUE, ppnum);
	    hibernate_page_bitset(page_list_wired, TRUE, ppnum);
	}
	break;
      default:
	panic("hibernate_set_page_state");
    }
}

static vm_offset_t
hibernate_page_list_iterate(hibernate_page_list_t * list, vm_offset_t * pPage)
{
    uint32_t		 page = *pPage;
    uint32_t		 count;
    hibernate_bitmap_t * bitmap;

    while ((bitmap = hibernate_page_bitmap_pin(list, &page)))
    {
	count = hibernate_page_bitmap_count(bitmap, TRUE, page);
	if (!count)
	    break;
	page += count;
	if (page <= bitmap->last_page)
	    break;
    }

    *pPage = page;
    if (bitmap)
	count = hibernate_page_bitmap_count(bitmap, FALSE, page);
    else
	count = 0;

    return (count);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn
IOHibernateSystemSleep(void)
{
    IOReturn   err;
    OSData *   nvramData;
    OSObject * obj;
    OSString * str;
    OSNumber * num;
    bool       dsSSD, vmflush, swapPinned;
    IOHibernateVars * vars;
    uint64_t   setFileSize = 0;

    gIOHibernateState = kIOHibernateStateInactive;

    gIOHibernateDebugFlags = 0;
    if (kIOLogHibernate & gIOKitDebug)
	gIOHibernateDebugFlags |= kIOHibernateDebugRestoreLogs;

    if (IOService::getPMRootDomain()->getHibernateSettings(
        &gIOHibernateMode, &gIOHibernateFreeRatio, &gIOHibernateFreeTime))
    {
        if (kIOHibernateModeSleep & gIOHibernateMode)
            // default to discard clean for safe sleep
            gIOHibernateMode ^= (kIOHibernateModeDiscardCleanInactive 
                                | kIOHibernateModeDiscardCleanActive);
    }

    if ((obj = IOService::getPMRootDomain()->copyProperty(kIOHibernateFileKey)))
    {
	if ((str = OSDynamicCast(OSString, obj)))
	    strlcpy(gIOHibernateFilename, str->getCStringNoCopy(),
			    sizeof(gIOHibernateFilename));
	obj->release();
    }

    if (!gIOHibernateMode || !gIOHibernateFilename[0])
	return (kIOReturnUnsupported);

    HIBLOG("hibernate image path: %s\n", gIOHibernateFilename);

    vars = IONew(IOHibernateVars, 1);
    if (!vars) return (kIOReturnNoMemory);
    bzero(vars, sizeof(*vars));

    IOLockLock(gFSLock);
    if (!gIOHibernateTrimCalloutEntry)
    {
        gIOHibernateTrimCalloutEntry = thread_call_allocate(&IOHibernateSystemPostWakeTrim, &gFSLock);
    }
    IOHibernateSystemPostWakeTrim(NULL, NULL);
    if (kFSIdle != gFSState)
    {
	HIBLOG("hibernate file busy\n");
	IOLockUnlock(gFSLock);
	IODelete(vars, IOHibernateVars, 1);
        return (kIOReturnBusy);
    }
    gFSState = kFSOpening;
    IOLockUnlock(gFSLock);

    swapPinned = false;
    do
    {
        vars->srcBuffer = IOBufferMemoryDescriptor::withOptions(kIODirectionOutIn,
				    2 * page_size + WKdm_SCRATCH_BUF_SIZE_INTERNAL, page_size);

	vars->handoffBuffer = IOBufferMemoryDescriptor::withOptions(kIODirectionOutIn, 
				    ptoa_64(gIOHibernateHandoffPageCount), page_size);

        if (!vars->srcBuffer || !vars->handoffBuffer)
        {
            err = kIOReturnNoMemory;
            break;
        }

	if ((obj = IOService::getPMRootDomain()->copyProperty(kIOHibernateFileMinSizeKey)))
	{
	    if ((num = OSDynamicCast(OSNumber, obj))) vars->fileMinSize = num->unsigned64BitValue();
	    obj->release();
	}
	if ((obj = IOService::getPMRootDomain()->copyProperty(kIOHibernateFileMaxSizeKey)))
	{
	    if ((num = OSDynamicCast(OSNumber, obj))) vars->fileMaxSize = num->unsigned64BitValue();
	    obj->release();
	}

        boolean_t encryptedswap = true;
        uint32_t pageCount;
        AbsoluteTime startTime, endTime;
        uint64_t nsec;

	bzero(gIOHibernateCurrentHeader, sizeof(IOHibernateImageHeader));
	gIOHibernateCurrentHeader->debugFlags = gIOHibernateDebugFlags;
	gIOHibernateCurrentHeader->signature = kIOHibernateHeaderInvalidSignature;

	vmflush = ((kOSBooleanTrue == IOService::getPMRootDomain()->getProperty(kIOPMDeepSleepEnabledKey)));
        err = hibernate_alloc_page_lists(&vars->page_list, 
        				 &vars->page_list_wired,
        				 &vars->page_list_pal);
        if (KERN_SUCCESS != err) break;

	err = hibernate_pin_swap(TRUE);
	if (KERN_SUCCESS != err) break;
	swapPinned = true;

	if (vars->fileMinSize || (kIOHibernateModeFileResize & gIOHibernateMode))
	{
	    hibernate_page_list_setall(vars->page_list,
				       vars->page_list_wired,
				       vars->page_list_pal,
				       true /* preflight */,
				       vmflush /* discard */,
				       &pageCount);
	    PE_Video consoleInfo;
	    bzero(&consoleInfo, sizeof(consoleInfo));
	    IOService::getPlatform()->getConsoleInfo(&consoleInfo);

	    // estimate: 6% increase in pages compressed
	    // screen preview 2 images compressed 0%
	    setFileSize = ((ptoa_64((106 * pageCount) / 100) * gIOHibernateCompression) >> 8)
				+ vars->page_list->list_size
	 			+ (consoleInfo.v_width * consoleInfo.v_height * 8);
	    enum { setFileRound = 1024*1024ULL };
	    setFileSize = ((setFileSize + setFileRound) & ~(setFileRound - 1));
	
	    HIBLOG("hibernate_page_list_setall preflight pageCount %d est comp %qd setfile %qd min %qd\n", 
		    pageCount, (100ULL * gIOHibernateCompression) >> 8,
		    setFileSize, vars->fileMinSize);

	    if (!(kIOHibernateModeFileResize & gIOHibernateMode)
	     && (setFileSize < vars->fileMinSize))
	    { 
		setFileSize = vars->fileMinSize;
	    }
	}
    
	// Invalidate the image file
    if (gDebugImageLock) {
        IOLockLock(gDebugImageLock);
        if (gDebugImageFileVars != 0) {
            IOSetBootImageNVRAM(0);
            IOPolledFileClose(&gDebugImageFileVars, 0, 0, 0, 0, 0);
        }
        IOLockUnlock(gDebugImageLock);
    }

        err = IOPolledFileOpen(gIOHibernateFilename, setFileSize, 0,
        			gIOHibernateCurrentHeader, sizeof(gIOHibernateCurrentHeader),
                                &vars->fileVars, &nvramData, 
                                &vars->volumeCryptKey[0], sizeof(vars->volumeCryptKey));

        if (KERN_SUCCESS != err)
        {
	    IOLockLock(gFSLock);
	    if (kFSOpening != gFSState) err = kIOReturnTimeout;
	    IOLockUnlock(gFSLock);
	}

        if (KERN_SUCCESS != err)
        {
	    HIBLOG("IOPolledFileOpen(%x)\n", err);
            break;
        }

	// write extents for debug data usage in EFI
        IOWriteExtentsToFile(vars->fileVars, kIOHibernateHeaderOpenSignature);

        err = IOPolledFilePollersSetup(vars->fileVars, kIOPolledPreflightState);
        if (KERN_SUCCESS != err) break;

        clock_get_uptime(&startTime);
        err = hibernate_setup(gIOHibernateCurrentHeader, 
                                vmflush,
                                vars->page_list, vars->page_list_wired, vars->page_list_pal);
        clock_get_uptime(&endTime);
        SUB_ABSOLUTETIME(&endTime, &startTime);
        absolutetime_to_nanoseconds(endTime, &nsec);

        boolean_t haveSwapPin, hibFileSSD;
        haveSwapPin = vm_swap_files_pinned();

        hibFileSSD = (kIOPolledFileSSD & vars->fileVars->flags);

        HIBLOG("hibernate_setup(%d) took %qd ms, swapPin(%d) ssd(%d)\n",
                err, nsec / 1000000ULL,
                haveSwapPin, hibFileSSD);
        if (KERN_SUCCESS != err) break;

        gIOHibernateStandbyDisabled = ((!haveSwapPin || !hibFileSSD));

        dsSSD = ((0 != (kIOPolledFileSSD & vars->fileVars->flags))
                && (kOSBooleanTrue == IOService::getPMRootDomain()->getProperty(kIOPMDeepSleepEnabledKey)));

        if (dsSSD) gIOHibernateCurrentHeader->options |= kIOHibernateOptionSSD | kIOHibernateOptionColor;
        else       gIOHibernateCurrentHeader->options |= kIOHibernateOptionProgress;


#if defined(__i386__) || defined(__x86_64__)
	if (!uuid_is_null(vars->volumeCryptKey) &&
	      (kOSBooleanTrue != IOService::getPMRootDomain()->getProperty(kIOPMDestroyFVKeyOnStandbyKey)))
	{
	    uintptr_t smcVars[2];
	    smcVars[0] = sizeof(vars->volumeCryptKey);
	    smcVars[1] = (uintptr_t)(void *) &gIOHibernateVars.volumeCryptKey[0];

	    IOService::getPMRootDomain()->setProperty(kIOHibernateSMCVariablesKey, smcVars, sizeof(smcVars));
	    bzero(smcVars, sizeof(smcVars));
	}
#endif


        if (encryptedswap || !uuid_is_null(vars->volumeCryptKey))
            gIOHibernateMode ^= kIOHibernateModeEncrypt; 

        if (kIOHibernateOptionProgress & gIOHibernateCurrentHeader->options)
        {
            vars->videoAllocSize = kVideoMapSize;
            if (KERN_SUCCESS != kmem_alloc_pageable(kernel_map, &vars->videoMapping, vars->videoAllocSize, VM_KERN_MEMORY_IOKIT))
                vars->videoMapping = 0;
        }

	// generate crypt keys
        for (uint32_t i = 0; i < sizeof(vars->wiredCryptKey); i++)
            vars->wiredCryptKey[i] = random();
        for (uint32_t i = 0; i < sizeof(vars->cryptKey); i++)
            vars->cryptKey[i] = random();

	// set nvram

	IOSetBootImageNVRAM(nvramData);
        nvramData->release();

#if defined(__i386__) || defined(__x86_64__)
	{
	    struct AppleRTCHibernateVars
	    {
		uint8_t     signature[4];
		uint32_t    revision;
		uint8_t	    booterSignature[20];
		uint8_t	    wiredCryptKey[16];
	    };
	    AppleRTCHibernateVars rtcVars;
	    OSData * data;

	    rtcVars.signature[0] = 'A';
	    rtcVars.signature[1] = 'A';
	    rtcVars.signature[2] = 'P';
	    rtcVars.signature[3] = 'L';
	    rtcVars.revision     = 1;
	    bcopy(&vars->wiredCryptKey[0], &rtcVars.wiredCryptKey[0], sizeof(rtcVars.wiredCryptKey));
	    if (gIOHibernateBootSignature[0])
	    {
		char c;
		uint8_t value = 0;
		for (uint32_t i = 0;
		    (c = gIOHibernateBootSignature[i]) && (i < (sizeof(rtcVars.booterSignature) << 1));
		    i++)
		{
		    if (c >= 'a')      c -= 'a' - 10;
		    else if (c >= 'A') c -= 'A' - 10;
		    else if (c >= '0') c -= '0';
		    else               continue;
		    value = (value << 4) | c;
		    if (i & 1) rtcVars.booterSignature[i >> 1] = value;
		}
	    }
	    data = OSData::withBytes(&rtcVars, sizeof(rtcVars));
	    if (data)
	    { 
		if (gIOHibernateRTCVariablesKey)
		    IOService::getPMRootDomain()->setProperty(gIOHibernateRTCVariablesKey, data);
		data->release();
	    }
            if (gIOChosenEntry)
            {
                data = OSDynamicCast(OSData, gIOChosenEntry->getProperty(kIOHibernateMachineSignatureKey));
                if (data) gIOHibernateCurrentHeader->machineSignature = *((UInt32 *)data->getBytesNoCopy());
		// set BootNext
		if (!gIOHibernateBoot0082Data)
		{
		    data = OSDynamicCast(OSData, gIOChosenEntry->getProperty("boot-device-path"));
		    if (data)
		    {
			// AppleNVRAM_EFI_LOAD_OPTION
			struct {
			    uint32_t Attributes;
			    uint16_t FilePathLength;
			    uint16_t Desc;
			} loadOptionHeader;
			loadOptionHeader.Attributes     = 1;
			loadOptionHeader.FilePathLength = data->getLength();
			loadOptionHeader.Desc           = 0;
			gIOHibernateBoot0082Data = OSData::withCapacity(sizeof(loadOptionHeader) + loadOptionHeader.FilePathLength);
			if (gIOHibernateBoot0082Data)
			{
			    gIOHibernateBoot0082Data->appendBytes(&loadOptionHeader, sizeof(loadOptionHeader));
			    gIOHibernateBoot0082Data->appendBytes(data);
			}
		    }
		}
		if (!gIOHibernateBootNextData)
		{
		    uint16_t bits = 0x0082;
		    gIOHibernateBootNextData = OSData::withBytes(&bits, sizeof(bits));
		}
		if (gIOHibernateBoot0082Key && gIOHibernateBoot0082Data && gIOHibernateBootNextKey && gIOHibernateBootNextData)
		{
		    gIOHibernateBootNextSave = gIOOptionsEntry->copyProperty(gIOHibernateBootNextKey);
		    gIOOptionsEntry->setProperty(gIOHibernateBoot0082Key, gIOHibernateBoot0082Data);
		    gIOOptionsEntry->setProperty(gIOHibernateBootNextKey, gIOHibernateBootNextData);
		}
		// BootNext
            }
	}
#endif /* !i386 && !x86_64 */
    }
    while (false);

    if (swapPinned) hibernate_pin_swap(FALSE);

    IOLockLock(gFSLock);
    if ((kIOReturnSuccess == err) && (kFSOpening != gFSState))
    {
	HIBLOG("hibernate file close due timeout\n");
	err = kIOReturnTimeout;
    }
    if (kIOReturnSuccess == err)
    {
	gFSState = kFSOpened;
	gIOHibernateVars = *vars;
	gFileVars = *vars->fileVars;
	gFileVars.allocated = false;
	gIOHibernateVars.fileVars = &gFileVars;
	gIOHibernateCurrentHeader->signature = kIOHibernateHeaderSignature;
	gIOHibernateState = kIOHibernateStateHibernating;
    }
    else
    {
	IOPolledFileIOVars * fileVars = vars->fileVars;
	IOHibernateDone(vars);
    IOPolledFileClose(&fileVars,
#if DISABLE_TRIM
                      0, NULL, 0, 0, 0);
#else
                      0, NULL, 0, sizeof(IOHibernateImageHeader), setFileSize);
#endif
	gFSState = kFSIdle;
    }
    IOLockUnlock(gFSLock);

    if (vars->fileVars) IODelete(vars->fileVars, IOPolledFileIOVars, 1);
    IODelete(vars, IOHibernateVars, 1);

    return (err);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static void
IOSetBootImageNVRAM(OSData * data)
{
    IORegistryEntry * regEntry;

    if (!gIOOptionsEntry)
    {
        regEntry = IORegistryEntry::fromPath("/options", gIODTPlane);
        gIOOptionsEntry = OSDynamicCast(IODTNVRAM, regEntry);
        if (regEntry && !gIOOptionsEntry)
            regEntry->release();
    }
    if (gIOOptionsEntry && gIOHibernateBootImageKey)
    {
    	if (data) gIOOptionsEntry->setProperty(gIOHibernateBootImageKey, data);
    	else
    	{
	    gIOOptionsEntry->removeProperty(gIOHibernateBootImageKey);
	    gIOOptionsEntry->sync();
	}
    }
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* 
 * Writes header to disk with signature, block size and file extents data.
 * If there are more than 2 extents, then they are written on second block.
 */
static IOReturn
IOWriteExtentsToFile(IOPolledFileIOVars * vars, uint32_t signature)
{
    IOHibernateImageHeader hdr;
    IOItemCount            count;
    IOReturn               err = kIOReturnSuccess;
    int                    rc;
    IOPolledFileExtent *   fileExtents;

    fileExtents = (typeof(fileExtents)) vars->fileExtents->getBytesNoCopy();

    memset(&hdr, 0, sizeof(IOHibernateImageHeader));
    count = vars->fileExtents->getLength();
    if (count > sizeof(hdr.fileExtentMap))
    {
        hdr.fileExtentMapSize = count;
        count = sizeof(hdr.fileExtentMap);
    }
    else
        hdr.fileExtentMapSize = sizeof(hdr.fileExtentMap);

    bcopy(fileExtents, &hdr.fileExtentMap[0], count);

    // copy file block extent list if larger than header
    if (hdr.fileExtentMapSize > sizeof(hdr.fileExtentMap))
    {
            count = hdr.fileExtentMapSize - sizeof(hdr.fileExtentMap);
            rc = kern_write_file(vars->fileRef, vars->blockSize, 
                                 (caddr_t)(((uint8_t *)fileExtents) + sizeof(hdr.fileExtentMap)), 
                                 count, IO_SKIP_ENCRYPTION);
            if (rc != 0) {
                HIBLOG("kern_write_file returned %d\n", rc);
                err = kIOReturnIOError;
                goto exit;
            }    
    }
    hdr.signature = signature;
    hdr.deviceBlockSize = vars->blockSize;

    rc = kern_write_file(vars->fileRef, 0, (char *)&hdr, sizeof(hdr), IO_SKIP_ENCRYPTION);
    if (rc != 0) {
        HIBLOG("kern_write_file returned %d\n", rc);
        err = kIOReturnIOError;
        goto exit;
    }

exit:
    return err;
}

extern "C" boolean_t root_is_CF_drive;

void
IOOpenDebugDataFile(const char *fname, uint64_t size)
{
    IOReturn   err;
    OSData *   imagePath = NULL;
    uint64_t   padding;

    if (!gDebugImageLock) {
        gDebugImageLock = IOLockAlloc();
    }

    if (root_is_CF_drive) return;

    // Try to get a lock, but don't block for getting lock
    if (!IOLockTryLock(gDebugImageLock)) {
        HIBLOG("IOOpenDebugDataFile: Failed to get lock\n");
        return;
    }

    if (gDebugImageFileVars ||  !fname || !size) {
        HIBLOG("IOOpenDebugDataFile: conditions failed\n");
        goto exit;
    }

    padding = (PAGE_SIZE*2);  // allocate couple more pages for header and fileextents
    err = IOPolledFileOpen(fname, size+padding, 32ULL*1024*1024*1024,
                           NULL, 0,
                           &gDebugImageFileVars, &imagePath, NULL, 0);

    if ((kIOReturnSuccess == err) && imagePath)
    {
        if ((gDebugImageFileVars->fileSize < (size+padding)) ||
            (gDebugImageFileVars->fileExtents->getLength() > PAGE_SIZE)) {
            // Can't use the file
            IOPolledFileClose(&gDebugImageFileVars, 0, 0, 0, 0, 0);
            HIBLOG("IOOpenDebugDataFile: too many file extents\n");
            goto exit;
        }

        // write extents for debug data usage in EFI
        IOWriteExtentsToFile(gDebugImageFileVars, kIOHibernateHeaderOpenSignature);
        IOSetBootImageNVRAM(imagePath);
    }

exit:
    IOLockUnlock(gDebugImageLock);

    if (imagePath) imagePath->release();
    return;
}

void
IOCloseDebugDataFile()
{
    IOSetBootImageNVRAM(0);

    if (gDebugImageLock) {
        IOLockLock(gDebugImageLock);
        if (gDebugImageFileVars != 0) {
            IOPolledFileClose(&gDebugImageFileVars, 0, 0, 0, 0, 0);
        }
        IOLockUnlock(gDebugImageLock);
    }


}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

DECLARE_IOHIBERNATEPROGRESSALPHA

static void
ProgressInit(hibernate_graphics_t * display, uint8_t * screen, uint8_t * saveunder, uint32_t savelen)
{
    uint32_t	rowBytes, pixelShift;
    uint32_t	x, y;
    int32_t	blob;
    uint32_t	alpha, in, color, result;
    uint8_t *	out;
    uint32_t	saveindex[kIOHibernateProgressCount] = { 0 };

    rowBytes = display->rowBytes;
    pixelShift = display->depth >> 4;
    if (pixelShift < 1) return;
    
    screen += ((display->width
                - kIOHibernateProgressCount * (kIOHibernateProgressWidth + kIOHibernateProgressSpacing)) << (pixelShift - 1))
        + (display->height - kIOHibernateProgressOriginY - kIOHibernateProgressHeight) * rowBytes;
    
    for (y = 0; y < kIOHibernateProgressHeight; y++)
    {
        out = screen + y * rowBytes;
        for (blob = 0; blob < kIOHibernateProgressCount; blob++)
        {
            color = blob ? kIOHibernateProgressDarkGray : kIOHibernateProgressMidGray;
            for (x = 0; x < kIOHibernateProgressWidth; x++)
            {
                alpha  = gIOHibernateProgressAlpha[y][x];
                result = color;
                if (alpha)
                {
                    if (0xff != alpha)
                    {
                        if (1 == pixelShift)
                        {
                            in = *((uint16_t *)out) & 0x1f;	// 16
                            in = (in << 3) | (in >> 2);
                        }
                        else
                            in = *((uint32_t *)out) & 0xff;	// 32
                        saveunder[blob * kIOHibernateProgressSaveUnderSize + saveindex[blob]++] = in;
                        result = ((255 - alpha) * in + alpha * result + 0xff) >> 8;
                    }
                    if (1 == pixelShift)
                    {
                        result >>= 3;
                        *((uint16_t *)out) = (result << 10) | (result << 5) | result;	// 16
                    }
                    else
                        *((uint32_t *)out) = (result << 16) | (result << 8) | result;	// 32
                }
                out += (1 << pixelShift);
            }
            out += (kIOHibernateProgressSpacing << pixelShift);
        }
    }
}


static void
ProgressUpdate(hibernate_graphics_t * display, uint8_t * screen, int32_t firstBlob, int32_t select)
{
    uint32_t  rowBytes, pixelShift;
    uint32_t  x, y;
    int32_t   blob, lastBlob;
    uint32_t  alpha, in, color, result;
    uint8_t * out;
    uint32_t  saveindex[kIOHibernateProgressCount] = { 0 };

    pixelShift = display->depth >> 4;
    if (pixelShift < 1)
        return;

    rowBytes = display->rowBytes;

    screen += ((display->width 
            - kIOHibernateProgressCount * (kIOHibernateProgressWidth + kIOHibernateProgressSpacing)) << (pixelShift - 1))
                + (display->height - kIOHibernateProgressOriginY - kIOHibernateProgressHeight) * rowBytes;

    lastBlob  = (select < kIOHibernateProgressCount) ? select : (kIOHibernateProgressCount - 1);

    screen += (firstBlob * (kIOHibernateProgressWidth + kIOHibernateProgressSpacing)) << pixelShift;

    for (y = 0; y < kIOHibernateProgressHeight; y++)
    {
        out = screen + y * rowBytes;
        for (blob = firstBlob; blob <= lastBlob; blob++)
        {
            color = (blob < select) ? kIOHibernateProgressLightGray : kIOHibernateProgressMidGray;
            for (x = 0; x < kIOHibernateProgressWidth; x++)
            {
                alpha  = gIOHibernateProgressAlpha[y][x];
                result = color;
                if (alpha)
                {
                    if (0xff != alpha)
                    {
                        in = display->progressSaveUnder[blob][saveindex[blob]++];
                        result = ((255 - alpha) * in + alpha * result + 0xff) / 255;
                    }
                    if (1 == pixelShift)
                    {
                        result >>= 3;
                        *((uint16_t *)out) = (result << 10) | (result << 5) | result;	// 16
                    }
                    else
                        *((uint32_t *)out) = (result << 16) | (result << 8) | result;	// 32
                }
                out += (1 << pixelShift);
            }
            out += (kIOHibernateProgressSpacing << pixelShift);
        }
    }
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn
IOHibernateIOKitSleep(void)
{
    IOReturn ret = kIOReturnSuccess;
    IOLockLock(gFSLock);
    if (kFSOpening == gFSState)
    {
	gFSState = kFSTimedOut;
	HIBLOG("hibernate file open timed out\n");
	ret = kIOReturnTimeout;
    }
    IOLockUnlock(gFSLock);
    return (ret);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn
IOHibernateSystemHasSlept(void)
{
    IOReturn          ret = kIOReturnSuccess;
    IOHibernateVars * vars  = &gIOHibernateVars;
    OSObject        * obj = 0;
    OSData          * data;

    IOLockLock(gFSLock);
    if ((kFSOpened != gFSState) && gIOHibernateMode)
    {
	ret = kIOReturnTimeout;
    }
    IOLockUnlock(gFSLock);
    if (kIOReturnSuccess != ret) return (ret);

    if (gIOHibernateMode) obj = IOService::getPMRootDomain()->copyProperty(kIOHibernatePreviewBufferKey);
    vars->previewBuffer = OSDynamicCast(IOMemoryDescriptor, obj);
    if (obj && !vars->previewBuffer)
	obj->release();

    vars->consoleMapping = NULL;
    if (vars->previewBuffer && (kIOReturnSuccess != vars->previewBuffer->prepare()))
    {
	vars->previewBuffer->release();
	vars->previewBuffer = 0;
    }

    if ((kIOHibernateOptionProgress & gIOHibernateCurrentHeader->options)
        && vars->previewBuffer 
        && (data = OSDynamicCast(OSData, 
	IOService::getPMRootDomain()->getProperty(kIOHibernatePreviewActiveKey))))
    {
	UInt32 flags = *((UInt32 *)data->getBytesNoCopy());
	HIBPRINT("kIOHibernatePreviewActiveKey %08lx\n", (long)flags);

	IOService::getPMRootDomain()->removeProperty(kIOHibernatePreviewActiveKey);

	if (kIOHibernatePreviewUpdates & flags)
	{
	    PE_Video	       consoleInfo;
	    hibernate_graphics_t * graphicsInfo = gIOHibernateGraphicsInfo;

	    IOService::getPlatform()->getConsoleInfo(&consoleInfo);

	    graphicsInfo->width    = consoleInfo.v_width;
	    graphicsInfo->height   = consoleInfo.v_height;
	    graphicsInfo->rowBytes = consoleInfo.v_rowBytes;
	    graphicsInfo->depth    = consoleInfo.v_depth;
	    vars->consoleMapping   = (uint8_t *) consoleInfo.v_baseAddr;

	    HIBPRINT("video %p %d %d %d\n",
			vars->consoleMapping, graphicsInfo->depth, 
			graphicsInfo->width, graphicsInfo->height);
	    if (vars->consoleMapping)
			ProgressInit(graphicsInfo, vars->consoleMapping,
					&graphicsInfo->progressSaveUnder[0][0], sizeof(graphicsInfo->progressSaveUnder));
	}
    }

    if (gIOOptionsEntry)
        gIOOptionsEntry->sync();

    return (ret);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static DeviceTreeNode *
MergeDeviceTree(DeviceTreeNode * entry, IORegistryEntry * regEntry)
{
    DeviceTreeNodeProperty * prop;
    DeviceTreeNode *         child;
    IORegistryEntry *        childRegEntry;
    const char *             nameProp;
    unsigned int             propLen, idx;

    prop = (DeviceTreeNodeProperty *) (entry + 1);
    for (idx = 0; idx < entry->nProperties; idx++)
    {
	if (regEntry && (0 != strcmp("name", prop->name)))
	{
	    regEntry->setProperty((const char *) prop->name, (void *) (prop + 1), prop->length);
//	    HIBPRINT("%s: %s, %d\n", regEntry->getName(), prop->name, prop->length);
	}
	prop = (DeviceTreeNodeProperty *) (((uintptr_t)(prop + 1)) + ((prop->length + 3) & ~3));
    }

    child = (DeviceTreeNode *) prop;
    for (idx = 0; idx < entry->nChildren; idx++)
    {
	if (kSuccess != DTGetProperty(child, "name", (void **) &nameProp, &propLen))
	    panic("no name");
	childRegEntry = regEntry ? regEntry->childFromPath(nameProp, gIODTPlane) : NULL;
//	HIBPRINT("%s == %p\n", nameProp, childRegEntry);
	child = MergeDeviceTree(child, childRegEntry);
    }
    return (child);
}

IOReturn
IOHibernateSystemWake(void)
{
    if (kFSOpened == gFSState)
    {
	IOPolledFilePollersClose(gIOHibernateVars.fileVars, kIOPolledPostflightState);
    	IOHibernateDone(&gIOHibernateVars);
    }
    else
    {
        IOService::getPMRootDomain()->removeProperty(kIOHibernateOptionsKey);
        IOService::getPMRootDomain()->removeProperty(kIOHibernateGfxStatusKey);
    }
    return (kIOReturnSuccess);
}

static IOReturn
IOHibernateDone(IOHibernateVars * vars)
{
    hibernate_teardown(vars->page_list, vars->page_list_wired, vars->page_list_pal);

    if (vars->videoMapping)
    {
        if (vars->videoMapSize)
            // remove mappings
            IOUnmapPages(kernel_map, vars->videoMapping, vars->videoMapSize);
        if (vars->videoAllocSize)
            // dealloc range
            kmem_free(kernel_map, trunc_page(vars->videoMapping), vars->videoAllocSize);
    }

    if (vars->previewBuffer)
    {
        vars->previewBuffer->release();
        vars->previewBuffer = 0;
    }

    if (kIOHibernateStateWakingFromHibernate == gIOHibernateState)
    {
        IOService::getPMRootDomain()->setProperty(kIOHibernateOptionsKey, 
                                            gIOHibernateCurrentHeader->options, 32);
    }
    else
    {
        IOService::getPMRootDomain()->removeProperty(kIOHibernateOptionsKey);
    }

    if ((kIOHibernateStateWakingFromHibernate == gIOHibernateState)
      && (kIOHibernateGfxStatusUnknown != gIOHibernateGraphicsInfo->gfxStatus))
    {
        IOService::getPMRootDomain()->setProperty(kIOHibernateGfxStatusKey, 
                                        &gIOHibernateGraphicsInfo->gfxStatus,
                                        sizeof(gIOHibernateGraphicsInfo->gfxStatus));
    }
    else
    {
        IOService::getPMRootDomain()->removeProperty(kIOHibernateGfxStatusKey);
    }

    // invalidate nvram properties - (gIOOptionsEntry != 0) => nvram was touched

#if defined(__i386__) || defined(__x86_64__)
	IOService::getPMRootDomain()->removeProperty(gIOHibernateRTCVariablesKey);
	IOService::getPMRootDomain()->removeProperty(kIOHibernateSMCVariablesKey);

	/*
	 * Hibernate variable is written to NVRAM on platforms in which RtcRam
	 * is not backed by coin cell.  Remove Hibernate data from NVRAM.
	 */
	if (gIOOptionsEntry) {

	    if (gIOHibernateRTCVariablesKey) {
		if (gIOOptionsEntry->getProperty(gIOHibernateRTCVariablesKey)) {
		    gIOOptionsEntry->removeProperty(gIOHibernateRTCVariablesKey);
		}
	    }

	    if (gIOHibernateBootNextKey)
	    {
		if (gIOHibernateBootNextSave)
		{
		    gIOOptionsEntry->setProperty(gIOHibernateBootNextKey, gIOHibernateBootNextSave);
		    gIOHibernateBootNextSave->release();
		    gIOHibernateBootNextSave = NULL;
		}
		else
		    gIOOptionsEntry->removeProperty(gIOHibernateBootNextKey);
	    }
	    if (kIOHibernateStateWakingFromHibernate != gIOHibernateState) gIOOptionsEntry->sync();
	}
#endif

    if (vars->srcBuffer) vars->srcBuffer->release();
    bzero(&gIOHibernateHandoffPages[0], gIOHibernateHandoffPageCount * sizeof(gIOHibernateHandoffPages[0]));
    if (vars->handoffBuffer)
    {
	if (kIOHibernateStateWakingFromHibernate == gIOHibernateState)
	{
	    IOHibernateHandoff * handoff;
	    bool done = false;
	    for (handoff = (IOHibernateHandoff *) vars->handoffBuffer->getBytesNoCopy();
		 !done;
		 handoff = (IOHibernateHandoff *) &handoff->data[handoff->bytecount])
	    {
		HIBPRINT("handoff %p, %x, %x\n", handoff, handoff->type, handoff->bytecount);
		uint8_t * data = &handoff->data[0];
		switch (handoff->type)
		{
		    case kIOHibernateHandoffTypeEnd:
			done = true;
			break;

		    case kIOHibernateHandoffTypeDeviceTree:
			MergeDeviceTree((DeviceTreeNode *) data, IOService::getServiceRoot());
			break;
	
		    case kIOHibernateHandoffTypeKeyStore:
#if defined(__i386__) || defined(__x86_64__)
			{
			    IOBufferMemoryDescriptor *
			    md = IOBufferMemoryDescriptor::withBytes(data, handoff->bytecount, kIODirectionOutIn);
			    if (md)
			    {
				IOSetKeyStoreData(md);
			    }
			}
#endif
			break;
	
		    default:
			done = (kIOHibernateHandoffType != (handoff->type & 0xFFFF0000));
			break;
		}    
	    }
	}
	vars->handoffBuffer->release();
    }

    bzero(vars, sizeof(*vars));

//    gIOHibernateState = kIOHibernateStateInactive;       // leave it for post wake code to see

    return (kIOReturnSuccess);
}

void
IOHibernateSystemPostWakeTrim(void * p1, void * p2)
{
    // invalidate & close the image file
    if (p1) IOLockLock(gFSLock);
    if (kFSTrimDelay == gFSState)
    {
	IOPolledFileIOVars * vars = &gFileVars;
	IOPolledFileClose(&vars,
#if DISABLE_TRIM
			  0, NULL, 0, 0, 0);
#else
			  0, (caddr_t)gIOHibernateCurrentHeader, sizeof(IOHibernateImageHeader),
			  sizeof(IOHibernateImageHeader), gIOHibernateCurrentHeader->imageSize);
#endif
        gFSState = kFSIdle;
    }
    if (p1) IOLockUnlock(gFSLock);
}

IOReturn
IOHibernateSystemPostWake(void)
{
    gIOHibernateCurrentHeader->signature = kIOHibernateHeaderInvalidSignature;
    IOLockLock(gFSLock);
    if (kFSTrimDelay == gFSState) IOHibernateSystemPostWakeTrim(NULL, NULL);
    else if (kFSOpened != gFSState) gFSState = kFSIdle;
    else
    {
	AbsoluteTime deadline;

        gFSState = kFSTrimDelay;
	clock_interval_to_deadline(TRIM_DELAY, kMillisecondScale, &deadline );
	thread_call_enter1_delayed(gIOHibernateTrimCalloutEntry, NULL, deadline);
    }
    IOLockUnlock(gFSLock);

    // IOCloseDebugDataFile() calls IOSetBootImageNVRAM() unconditionally
    IOCloseDebugDataFile( );
    return (kIOReturnSuccess);
}

uint32_t IOHibernateWasScreenLocked(void)
{
    uint32_t ret = 0;
    if ((kIOHibernateStateWakingFromHibernate == gIOHibernateState) && gIOChosenEntry)
    {
	OSData *
	data = OSDynamicCast(OSData, gIOChosenEntry->getProperty(kIOScreenLockStateKey));
	if (data)
	{
	    ret = ((uint32_t *)data->getBytesNoCopy())[0];
	    gIOChosenEntry->setProperty(kIOBooterScreenLockStateKey, data);
        }
    }
    else gIOChosenEntry->removeProperty(kIOBooterScreenLockStateKey);

    return (ret);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

SYSCTL_STRING(_kern, OID_AUTO, hibernatefile, 
		CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
		gIOHibernateFilename, sizeof(gIOHibernateFilename), "");
SYSCTL_STRING(_kern, OID_AUTO, bootsignature, 
		CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
		gIOHibernateBootSignature, sizeof(gIOHibernateBootSignature), "");
SYSCTL_UINT(_kern, OID_AUTO, hibernatemode, 
		CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
		&gIOHibernateMode, 0, "");
SYSCTL_STRUCT(_kern, OID_AUTO, hibernatestatistics,
		CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
		&_hibernateStats, hibernate_statistics_t, "");

SYSCTL_UINT(_kern, OID_AUTO, hibernategraphicsready,
		CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_ANYBODY,
		&_hibernateStats.graphicsReadyTime, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, hibernatewakenotification,
		CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_ANYBODY,
		&_hibernateStats.wakeNotificationTime, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, hibernatelockscreenready,
		CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_ANYBODY,
		&_hibernateStats.lockScreenReadyTime, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, hibernatehidready,
		CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_ANYBODY,
		&_hibernateStats.hidReadyTime, 0, "");


void
IOHibernateSystemInit(IOPMrootDomain * rootDomain)
{
    gIOHibernateBootImageKey = OSSymbol::withCStringNoCopy(kIOHibernateBootImageKey);

#if defined(__i386__) || defined(__x86_64__)
    gIOHibernateRTCVariablesKey = OSSymbol::withCStringNoCopy(kIOHibernateRTCVariablesKey);
    gIOHibernateBoot0082Key     = OSSymbol::withCString("8BE4DF61-93CA-11D2-AA0D-00E098032B8C:Boot0082");
    gIOHibernateBootNextKey     = OSSymbol::withCString("8BE4DF61-93CA-11D2-AA0D-00E098032B8C:BootNext");
    gIOHibernateRTCVariablesKey = OSSymbol::withCStringNoCopy(kIOHibernateRTCVariablesKey);
#endif /* defined(__i386__) || defined(__x86_64__) */

    OSData * data = OSData::withBytesNoCopy(&gIOHibernateState, sizeof(gIOHibernateState));
    if (data)
    {
	rootDomain->setProperty(kIOHibernateStateKey, data);
	data->release();
    }

    if (PE_parse_boot_argn("hfile", gIOHibernateFilename, sizeof(gIOHibernateFilename)))
	gIOHibernateMode = kIOHibernateModeOn;
    else
	gIOHibernateFilename[0] = 0;

    sysctl_register_oid(&sysctl__kern_hibernatefile);
    sysctl_register_oid(&sysctl__kern_bootsignature);
    sysctl_register_oid(&sysctl__kern_hibernatemode);
    sysctl_register_oid(&sysctl__kern_hibernatestatistics);
    sysctl_register_oid(&sysctl__kern_hibernategraphicsready);
    sysctl_register_oid(&sysctl__kern_hibernatewakenotification);
    sysctl_register_oid(&sysctl__kern_hibernatelockscreenready);
    sysctl_register_oid(&sysctl__kern_hibernatehidready);

    gIOChosenEntry = IORegistryEntry::fromPath("/chosen", gIODTPlane);

    gFSLock = IOLockAlloc();
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static IOReturn 
IOHibernatePolledFileWrite(IOPolledFileIOVars * vars,
			   const uint8_t * bytes, IOByteCount size,
			   IOPolledFileCryptVars * cryptvars)
{
    IOReturn err;

    err = IOPolledFileWrite(vars, bytes, size, cryptvars);
    if ((kIOReturnSuccess == err) && hibernate_should_abort()) err = kIOReturnAborted;

    return (err);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

extern "C" uint32_t
hibernate_write_image(void)
{
    IOHibernateImageHeader * header = gIOHibernateCurrentHeader;
    IOHibernateVars *        vars  = &gIOHibernateVars;
    IOPolledFileExtent *     fileExtents;

    _static_assert_1_arg(sizeof(IOHibernateImageHeader) == 512);

    uint32_t	 pageCount, pagesDone;
    IOReturn     err;
    vm_offset_t  ppnum, page;
    IOItemCount  count;
    uint8_t *	 src;
    uint8_t *	 data;
    uint8_t *	 compressed;
    uint8_t *	 scratch;
    IOByteCount  pageCompressedSize;
    uint64_t	 compressedSize, uncompressedSize;
    uint64_t	 image1Size = 0;
    uint32_t	 bitmap_size;
    bool	 iterDone, pollerOpen, needEncrypt;
    uint32_t	 restore1Sum, sum, sum1, sum2;
    int          wkresult;
    uint32_t	 tag;
    uint32_t	 pageType;
    uint32_t	 pageAndCount[2];
    addr64_t     phys64;
    IOByteCount  segLen;
    uintptr_t    hibernateBase;
    uintptr_t    hibernateEnd;

    AbsoluteTime startTime, endTime;
    AbsoluteTime allTime, compTime;
    uint64_t     compBytes;
    uint64_t     nsec;
    uint32_t     lastProgressStamp = 0;
    uint32_t     progressStamp;
    uint32_t	 blob, lastBlob = (uint32_t) -1L;

    uint32_t	 wiredPagesEncrypted;
    uint32_t	 dirtyPagesEncrypted;
    uint32_t	 wiredPagesClear;
    uint32_t	 svPageCount;
    uint32_t	 zvPageCount;

    IOPolledFileCryptVars _cryptvars;
    IOPolledFileCryptVars * cryptvars = 0;

    wiredPagesEncrypted = 0;
    dirtyPagesEncrypted = 0;
    wiredPagesClear     = 0;
    svPageCount         = 0;
    zvPageCount         = 0;

    if (!vars->fileVars
    || !vars->fileVars->pollers
    || !(kIOHibernateModeOn & gIOHibernateMode))      return (kIOHibernatePostWriteSleep);

    if (kIOHibernateModeSleep & gIOHibernateMode)
	kdebug_enable = save_kdebug_enable;

    KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 1) | DBG_FUNC_START, 0, 0, 0, 0, 0);
    IOService::getPMRootDomain()->tracePoint(kIOPMTracePointHibernate);

    restore1Sum = sum1 = sum2 = 0;

#if CRYPTO
    // encryption data. "iv" is the "initial vector".
    if (kIOHibernateModeEncrypt & gIOHibernateMode)
    {
        static const unsigned char first_iv[AES_BLOCK_SIZE]
        = {  0xa3, 0x63, 0x65, 0xa9, 0x0b, 0x71, 0x7b, 0x1c,
             0xdf, 0x9e, 0x5f, 0x32, 0xd7, 0x61, 0x63, 0xda };
    
        cryptvars = &gIOHibernateCryptWakeContext;
        bzero(cryptvars, sizeof(IOPolledFileCryptVars));
        aes_encrypt_key(vars->cryptKey,
                        kIOHibernateAESKeySize,
                        &cryptvars->ctx.encrypt);
        aes_decrypt_key(vars->cryptKey,
                        kIOHibernateAESKeySize,
                        &cryptvars->ctx.decrypt);

        cryptvars = &_cryptvars;
        bzero(cryptvars, sizeof(IOPolledFileCryptVars));
        for (pageCount = 0; pageCount < sizeof(vars->wiredCryptKey); pageCount++)
            vars->wiredCryptKey[pageCount] ^= vars->volumeCryptKey[pageCount];
        bzero(&vars->volumeCryptKey[0], sizeof(vars->volumeCryptKey));
        aes_encrypt_key(vars->wiredCryptKey,
                        kIOHibernateAESKeySize,
                        &cryptvars->ctx.encrypt);

        bcopy(&first_iv[0], &cryptvars->aes_iv[0], AES_BLOCK_SIZE);
        bzero(&vars->wiredCryptKey[0], sizeof(vars->wiredCryptKey));
        bzero(&vars->cryptKey[0], sizeof(vars->cryptKey));
    }
#endif /* CRYPTO */

    hibernate_page_list_setall(vars->page_list,
                               vars->page_list_wired,
                               vars->page_list_pal,
			       false /* !preflight */,
			       /* discard_all */
			       ((0 == (kIOHibernateModeSleep & gIOHibernateMode)) 
			       && (0 != ((kIOHibernateModeDiscardCleanActive | kIOHibernateModeDiscardCleanInactive) & gIOHibernateMode))),
                               &pageCount);

    HIBLOG("hibernate_page_list_setall found pageCount %d\n", pageCount);

    fileExtents = (IOPolledFileExtent *) vars->fileVars->fileExtents->getBytesNoCopy();

#if 0
    count = vars->fileExtents->getLength() / sizeof(IOPolledFileExtent);
    for (page = 0; page < count; page++)
    {
	HIBLOG("fileExtents[%d] %qx, %qx (%qx)\n", page, 
		fileExtents[page].start, fileExtents[page].length,
		fileExtents[page].start + fileExtents[page].length);
    }
#endif

    needEncrypt = (0 != (kIOHibernateModeEncrypt & gIOHibernateMode));
    AbsoluteTime_to_scalar(&compTime) = 0;
    compBytes = 0;

    clock_get_uptime(&allTime);
    IOService::getPMRootDomain()->pmStatsRecordEvent( 
                        kIOPMStatsHibernateImageWrite | kIOPMStatsEventStartFlag, allTime);
    do 
    {
        compressedSize   = 0;
        uncompressedSize = 0;
        svPageCount      = 0;
        zvPageCount      = 0;

        IOPolledFileSeek(vars->fileVars, vars->fileVars->blockSize);
    
        HIBLOG("IOHibernatePollerOpen, ml_get_interrupts_enabled %d\n", 
                ml_get_interrupts_enabled());
        err = IOPolledFilePollersOpen(vars->fileVars, kIOPolledBeforeSleepState, true);
        HIBLOG("IOHibernatePollerOpen(%x)\n", err);
        pollerOpen = (kIOReturnSuccess == err);
        if (!pollerOpen)
            break;
    
        // copy file block extent list if larger than header
    
        count = vars->fileVars->fileExtents->getLength();
        if (count > sizeof(header->fileExtentMap))
        {
            count -= sizeof(header->fileExtentMap);
            err = IOHibernatePolledFileWrite(vars->fileVars,
                                    ((uint8_t *) &fileExtents[0]) + sizeof(header->fileExtentMap), count, cryptvars);
            if (kIOReturnSuccess != err)
                break;
        }

        hibernateBase = HIB_BASE; /* Defined in PAL headers */
        hibernateEnd = (segHIBB + segSizeHIB);

        // copy out restore1 code

        for (count = 0;
            (phys64 = vars->handoffBuffer->getPhysicalSegment(count, &segLen, kIOMemoryMapperNone));
            count += segLen)
        {
	    for (pagesDone = 0; pagesDone < atop_32(segLen); pagesDone++)
	    {
	    	gIOHibernateHandoffPages[atop_32(count) + pagesDone] = atop_64(phys64) + pagesDone;
	    }
        }

        page = atop_32(kvtophys(hibernateBase));
        count = atop_32(round_page(hibernateEnd) - hibernateBase);
        header->restore1CodePhysPage = page;
        header->restore1CodeVirt = hibernateBase;
        header->restore1PageCount = count;
        header->restore1CodeOffset = ((uintptr_t) &hibernate_machine_entrypoint)      - hibernateBase;
        header->restore1StackOffset = ((uintptr_t) &gIOHibernateRestoreStackEnd[0]) - 64 - hibernateBase;

        // sum __HIB seg, with zeros for the stack
        src = (uint8_t *) trunc_page(hibernateBase);
        for (page = 0; page < count; page++)
        {
            if ((src < &gIOHibernateRestoreStack[0]) || (src >= &gIOHibernateRestoreStackEnd[0]))
                restore1Sum += hibernate_sum_page(src, header->restore1CodeVirt + page);
            else
                restore1Sum += 0x00000000;
            src += page_size;
        }
        sum1 = restore1Sum;
    
        // write the __HIB seg, with zeros for the stack

        src = (uint8_t *) trunc_page(hibernateBase);
        count = ((uintptr_t) &gIOHibernateRestoreStack[0]) - trunc_page(hibernateBase);
        if (count)
        {
            err = IOHibernatePolledFileWrite(vars->fileVars, src, count, cryptvars);
            if (kIOReturnSuccess != err)
                break;
        }
        err = IOHibernatePolledFileWrite(vars->fileVars, 
                                        (uint8_t *) 0,
                                        &gIOHibernateRestoreStackEnd[0] - &gIOHibernateRestoreStack[0],
                                        cryptvars);
        if (kIOReturnSuccess != err)
            break;
        src = &gIOHibernateRestoreStackEnd[0];
        count = round_page(hibernateEnd) - ((uintptr_t) src);
        if (count)
        {
            err = IOHibernatePolledFileWrite(vars->fileVars, src, count, cryptvars);
            if (kIOReturnSuccess != err)
                break;
        }

	if (kIOHibernateModeEncrypt & gIOHibernateMode)
	{
	    vars->fileVars->encryptStart = (vars->fileVars->position & ~(AES_BLOCK_SIZE - 1));
	    vars->fileVars->encryptEnd   = UINT64_MAX;
	    HIBLOG("encryptStart %qx\n", vars->fileVars->encryptStart);
	}

        // write the preview buffer

        if (vars->previewBuffer)
        {
            ppnum = 0;
            count = 0;
            do
            {
                phys64 = vars->previewBuffer->getPhysicalSegment(count, &segLen, kIOMemoryMapperNone);
                pageAndCount[0] = atop_64(phys64);
                pageAndCount[1] = atop_32(segLen);
                err = IOHibernatePolledFileWrite(vars->fileVars, 
                                        (const uint8_t *) &pageAndCount, sizeof(pageAndCount), 
                                        cryptvars);
                if (kIOReturnSuccess != err)
                    break;
                count += segLen;
                ppnum += sizeof(pageAndCount);
            }
            while (phys64);
            if (kIOReturnSuccess != err)
                break;

            src = (uint8_t *) vars->previewBuffer->getPhysicalSegment(0, NULL, _kIOMemorySourceSegment);

			((hibernate_preview_t *)src)->lockTime = gIOConsoleLockTime;

            count = vars->previewBuffer->getLength();

            header->previewPageListSize = ppnum;
            header->previewSize = count + ppnum;

            for (page = 0; page < count; page += page_size)
            {
                phys64 = vars->previewBuffer->getPhysicalSegment(page, NULL, kIOMemoryMapperNone);
                sum1 += hibernate_sum_page(src + page, atop_64(phys64));
            }
            err = IOHibernatePolledFileWrite(vars->fileVars, src, count, cryptvars);
            if (kIOReturnSuccess != err)
                break;
        }

        // mark areas for no save
        IOMemoryDescriptor * ioBuffer;
        ioBuffer = IOPolledFileGetIOBuffer(vars->fileVars);
        for (count = 0;
            (phys64 = ioBuffer->getPhysicalSegment(count, &segLen, kIOMemoryMapperNone));
            count += segLen)
        {
            hibernate_set_page_state(vars->page_list, vars->page_list_wired, 
                                        atop_64(phys64), atop_32(segLen),
                                        kIOHibernatePageStateFree);
            pageCount -= atop_32(segLen);
        }
    
        for (count = 0;
            (phys64 = vars->srcBuffer->getPhysicalSegment(count, &segLen, kIOMemoryMapperNone));
            count += segLen)
        {
            hibernate_set_page_state(vars->page_list, vars->page_list_wired, 
                                        atop_64(phys64), atop_32(segLen),
                                        kIOHibernatePageStateFree);
            pageCount -= atop_32(segLen);
        }

        // copy out bitmap of pages available for trashing during restore
    
        bitmap_size = vars->page_list_wired->list_size;
        src = (uint8_t *) vars->page_list_wired;
        err = IOHibernatePolledFileWrite(vars->fileVars, src, bitmap_size, cryptvars);
        if (kIOReturnSuccess != err)
            break;

        // mark more areas for no save, but these are not available 
        // for trashing during restore

	hibernate_page_list_set_volatile(vars->page_list, vars->page_list_wired, &pageCount);
    

        page = atop_32(KERNEL_IMAGE_TO_PHYS(hibernateBase));
        count = atop_32(round_page(KERNEL_IMAGE_TO_PHYS(hibernateEnd))) - page;
        hibernate_set_page_state(vars->page_list, vars->page_list_wired,
                                        page, count,
                                        kIOHibernatePageStateFree);
        pageCount -= count;

        if (vars->previewBuffer) for (count = 0;
                                        (phys64 = vars->previewBuffer->getPhysicalSegment(count, &segLen, kIOMemoryMapperNone));
                                        count += segLen)
        {
            hibernate_set_page_state(vars->page_list, vars->page_list_wired, 
                                        atop_64(phys64), atop_32(segLen),
                                        kIOHibernatePageStateFree);
            pageCount -= atop_32(segLen);
        }

        for (count = 0;
            (phys64 = vars->handoffBuffer->getPhysicalSegment(count, &segLen, kIOMemoryMapperNone));
            count += segLen)
        {
            hibernate_set_page_state(vars->page_list, vars->page_list_wired, 
                                        atop_64(phys64), atop_32(segLen),
                                        kIOHibernatePageStateFree);
            pageCount -= atop_32(segLen);
        }

        src = (uint8_t *) vars->srcBuffer->getBytesNoCopy();
	compressed = src + page_size;
        scratch    = compressed + page_size;

        pagesDone  = 0;
        lastBlob   = 0;
    
        HIBLOG("bitmap_size 0x%x, previewSize 0x%x, writing %d pages @ 0x%llx\n", 
        	bitmap_size, header->previewSize,
        	pageCount, vars->fileVars->position);

        enum
        // pageType
        { 
            kWired          = 0x02,
            kEncrypt        = 0x01,
            kWiredEncrypt   = kWired | kEncrypt,
            kWiredClear     = kWired,
            kUnwiredEncrypt = kEncrypt
        };

        bool cpuAES = (0 != (CPUID_FEATURE_AES & cpuid_features()));
#define _pmap_is_noencrypt(x) (cpuAES ? false : pmap_is_noencrypt((x)))

        for (pageType = kWiredEncrypt; pageType >= kUnwiredEncrypt; pageType--)
        {
	    if (kUnwiredEncrypt == pageType)
	   {
		// start unwired image
		if (kIOHibernateModeEncrypt & gIOHibernateMode)
		{
		    vars->fileVars->encryptStart = (vars->fileVars->position & ~(((uint64_t)AES_BLOCK_SIZE) - 1));
		    vars->fileVars->encryptEnd   = UINT64_MAX;
		    HIBLOG("encryptStart %qx\n", vars->fileVars->encryptStart);
		}
		bcopy(&cryptvars->aes_iv[0], 
			&gIOHibernateCryptWakeContext.aes_iv[0], 
			sizeof(cryptvars->aes_iv));
		cryptvars = &gIOHibernateCryptWakeContext;
            }
            for (iterDone = false, ppnum = 0; !iterDone; )
            {
                count = hibernate_page_list_iterate((kWired & pageType) 
                                                            ? vars->page_list_wired : vars->page_list,
                                                        &ppnum);
//              kprintf("[%d](%x : %x)\n", pageType, ppnum, count);
                iterDone = !count;

                if (count && (kWired & pageType) && needEncrypt)
                {
                    uint32_t checkIndex;
                    for (checkIndex = 0;
                            (checkIndex < count) 
                                && (((kEncrypt & pageType) == 0) == _pmap_is_noencrypt(ppnum + checkIndex));
                            checkIndex++)
                    {}
                    if (!checkIndex)
                    {
                        ppnum++;
                        continue;
                    }
                    count = checkIndex;
                }

                switch (pageType)
                {
                    case kWiredEncrypt:   wiredPagesEncrypted += count; break;
                    case kWiredClear:     wiredPagesClear     += count; break;
                    case kUnwiredEncrypt: dirtyPagesEncrypted += count; break;
                }
    
                if (iterDone && (kWiredEncrypt == pageType))   {/* not yet end of wired list */}
                else
                {
                    pageAndCount[0] = ppnum;
                    pageAndCount[1] = count;
                    err = IOHibernatePolledFileWrite(vars->fileVars, 
                                            (const uint8_t *) &pageAndCount, sizeof(pageAndCount), 
                                            cryptvars);
                    if (kIOReturnSuccess != err)
                        break;
                }
    
                for (page = ppnum; page < (ppnum + count); page++)
                {
                    err = IOMemoryDescriptorWriteFromPhysical(vars->srcBuffer, 0, ptoa_64(page), page_size);
                    if (err)
                    {
                        HIBLOG("IOMemoryDescriptorWriteFromPhysical %d [%ld] %x\n", __LINE__, (long)page, err);
                        break;
                    }
        
                    sum = hibernate_sum_page(src, page);
                    if (kWired & pageType)
                        sum1 += sum;
                    else
                        sum2 += sum;
       
                    clock_get_uptime(&startTime);
                    wkresult = WKdm_compress_new((const WK_word*) src,
						 (WK_word*) compressed, 
						 (WK_word*) scratch,
						 page_size - 4);

                    clock_get_uptime(&endTime);
                    ADD_ABSOLUTETIME(&compTime, &endTime);
                    SUB_ABSOLUTETIME(&compTime, &startTime);

                    compBytes += page_size;
                    pageCompressedSize = (-1 == wkresult) ? page_size : wkresult;

		    if (pageCompressedSize == 0) 
		    {
			pageCompressedSize = 4;
                        data = src;

			if (*(uint32_t *)src)
				svPageCount++;
			else
				zvPageCount++;
		    }
		    else 
		    {
			if (pageCompressedSize != page_size)
			    data = compressed;
			else
			    data = src;
		    }
    
                    tag = pageCompressedSize | kIOHibernateTagSignature;
                    err = IOHibernatePolledFileWrite(vars->fileVars, (const uint8_t *) &tag, sizeof(tag), cryptvars);
                    if (kIOReturnSuccess != err)
                        break;
    
                    err = IOHibernatePolledFileWrite(vars->fileVars, data, (pageCompressedSize + 3) & ~3, cryptvars);
                    if (kIOReturnSuccess != err)
                        break;
    
                    compressedSize += pageCompressedSize;
                    uncompressedSize += page_size;
                    pagesDone++;
    
                    if (vars->consoleMapping && (0 == (1023 & pagesDone)))
                    {
                        blob = ((pagesDone * kIOHibernateProgressCount) / pageCount);
                        if (blob != lastBlob)
                        {
                            ProgressUpdate(gIOHibernateGraphicsInfo, vars->consoleMapping, lastBlob, blob);
                            lastBlob = blob;
                        }
                    }
                    if (0 == (8191 & pagesDone))
                    {
                        clock_get_uptime(&endTime);
                        SUB_ABSOLUTETIME(&endTime, &allTime);
                        absolutetime_to_nanoseconds(endTime, &nsec);
                        progressStamp = nsec / 750000000ULL;
                        if (progressStamp != lastProgressStamp)
                        {
                            lastProgressStamp = progressStamp;
                            HIBPRINT("pages %d (%d%%)\n", pagesDone, (100 * pagesDone) / pageCount);
                        }
                    }
                }
                if (kIOReturnSuccess != err)
                    break;
                ppnum = page;
            }

            if (kIOReturnSuccess != err)
                break;

            if ((kEncrypt & pageType) && vars->fileVars->encryptStart)
            {
                vars->fileVars->encryptEnd = ((vars->fileVars->position + 511) & ~511ULL);
                HIBLOG("encryptEnd %qx\n", vars->fileVars->encryptEnd);
            }

            if (kWiredEncrypt != pageType)
            {
                // end of image1/2 - fill to next block
                err = IOHibernatePolledFileWrite(vars->fileVars, 0, 0, cryptvars);
                if (kIOReturnSuccess != err)
                    break;
            }
            if (kWiredClear == pageType)
            {
		// enlarge wired image for test
//              err = IOHibernatePolledFileWrite(vars->fileVars, 0, 0x60000000, cryptvars);

                // end wired image
                header->encryptStart = vars->fileVars->encryptStart;
                header->encryptEnd   = vars->fileVars->encryptEnd;
                image1Size = vars->fileVars->position;
                HIBLOG("image1Size 0x%qx, encryptStart1 0x%qx, End1 0x%qx\n",
                        image1Size, header->encryptStart, header->encryptEnd);
            }
        }
        if (kIOReturnSuccess != err)
        {
            if (kIOReturnOverrun == err)
            {
                // update actual compression ratio on not enough space (for retry)
                gIOHibernateCompression = (compressedSize << 8) / uncompressedSize;
            }

            // update partial amount written (for IOPolledFileClose cleanup/unmap)
            header->imageSize = vars->fileVars->position;
            break;
        }

        // Header:
    
        header->imageSize    = vars->fileVars->position;
        header->image1Size   = image1Size;
        header->bitmapSize   = bitmap_size;
        header->pageCount    = pageCount;
    
        header->restore1Sum  = restore1Sum;
        header->image1Sum    = sum1;
        header->image2Sum    = sum2;
        header->sleepTime    = gIOLastSleepTime.tv_sec;

	header->compression     = (compressedSize << 8) / uncompressedSize;
	gIOHibernateCompression = header->compression;
    
        count = vars->fileVars->fileExtents->getLength();
        if (count > sizeof(header->fileExtentMap))
        {
            header->fileExtentMapSize = count;
            count = sizeof(header->fileExtentMap);
        }
        else
            header->fileExtentMapSize = sizeof(header->fileExtentMap);
        bcopy(&fileExtents[0], &header->fileExtentMap[0], count);

        header->deviceBase      = vars->fileVars->block0;
        header->deviceBlockSize = vars->fileVars->blockSize;
    
        IOPolledFileSeek(vars->fileVars, 0);
        err = IOHibernatePolledFileWrite(vars->fileVars,
                                    (uint8_t *) header, sizeof(IOHibernateImageHeader), 
                                    cryptvars);
        if (kIOReturnSuccess != err)
            break;
        err = IOHibernatePolledFileWrite(vars->fileVars, 0, 0, cryptvars);
    }
    while (false);
    
    clock_get_uptime(&endTime);

    IOService::getPMRootDomain()->pmStatsRecordEvent( 
                        kIOPMStatsHibernateImageWrite | kIOPMStatsEventStopFlag, endTime);

    SUB_ABSOLUTETIME(&endTime, &allTime);
    absolutetime_to_nanoseconds(endTime, &nsec);
    HIBLOG("all time: %qd ms, ", nsec / 1000000ULL);

    absolutetime_to_nanoseconds(compTime, &nsec);
    HIBLOG("comp bytes: %qd time: %qd ms %qd Mb/s, ", 
		compBytes, 
		nsec / 1000000ULL,
		nsec ? (((compBytes * 1000000000ULL) / 1024 / 1024) / nsec) : 0);

    absolutetime_to_nanoseconds(vars->fileVars->cryptTime, &nsec);
    HIBLOG("crypt bytes: %qd time: %qd ms %qd Mb/s, ", 
		vars->fileVars->cryptBytes, 
		nsec / 1000000ULL, 
		nsec ? (((vars->fileVars->cryptBytes * 1000000000ULL) / 1024 / 1024) / nsec) : 0);

    HIBLOG("\nimage %qd (%lld%%), uncompressed %qd (%d), compressed %qd (%d%%), sum1 %x, sum2 %x\n", 
               header->imageSize, (header->imageSize * 100) / vars->fileVars->fileSize,
               uncompressedSize, atop_32(uncompressedSize), compressedSize,
               uncompressedSize ? ((int) ((compressedSize * 100ULL) / uncompressedSize)) : 0,
               sum1, sum2);

    HIBLOG("svPageCount %d, zvPageCount %d, wiredPagesEncrypted %d, wiredPagesClear %d, dirtyPagesEncrypted %d\n", 
	   svPageCount, zvPageCount, wiredPagesEncrypted, wiredPagesClear, dirtyPagesEncrypted);

    if (pollerOpen)
        IOPolledFilePollersClose(vars->fileVars, (kIOReturnSuccess == err) ? kIOPolledBeforeSleepState : kIOPolledBeforeSleepStateAborted );

    if (vars->consoleMapping)
        ProgressUpdate(gIOHibernateGraphicsInfo, 
                        vars->consoleMapping, 0, kIOHibernateProgressCount);

    HIBLOG("hibernate_write_image done(%x)\n", err);

    // should we come back via regular wake, set the state in memory.
    gIOHibernateState = kIOHibernateStateInactive;

    KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 1) | DBG_FUNC_END,
			  wiredPagesEncrypted, wiredPagesClear, dirtyPagesEncrypted, 0, 0);

    if (kIOReturnSuccess == err)
    {
	if (kIOHibernateModeSleep & gIOHibernateMode)
	{
	    return (kIOHibernatePostWriteSleep);
	}
	else if(kIOHibernateModeRestart & gIOHibernateMode)
	{
	    return (kIOHibernatePostWriteRestart);
	}
	else
	{
	    /* by default, power down */
	    return (kIOHibernatePostWriteHalt);
	}
    }
    else if (kIOReturnAborted == err)
    {
	return (kIOHibernatePostWriteWake);
    }
    else
    {
	/* on error, sleep */
	return (kIOHibernatePostWriteSleep);
    }
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

extern "C" void 
hibernate_machine_init(void)
{
    IOReturn     err;
    uint32_t     sum;
    uint32_t     pagesDone;
    uint32_t     pagesRead = 0;
    AbsoluteTime startTime, compTime;
    AbsoluteTime allTime, endTime;
    AbsoluteTime startIOTime, endIOTime;
    uint64_t     nsec, nsecIO;
    uint64_t     compBytes;
    uint32_t     lastProgressStamp = 0;
    uint32_t     progressStamp;
    IOPolledFileCryptVars * cryptvars = 0;

    IOHibernateVars * vars  = &gIOHibernateVars;
    bzero(gIOHibernateStats, sizeof(hibernate_statistics_t));

    if (!vars->fileVars || !vars->fileVars->pollers)
	return;

    sum = gIOHibernateCurrentHeader->actualImage1Sum;
    pagesDone = gIOHibernateCurrentHeader->actualUncompressedPages;

    if (kIOHibernateStateWakingFromHibernate != gIOHibernateState)
    {
	HIBLOG("regular wake\n");
	return;
    }

    HIBPRINT("diag %x %x %x %x\n",
	    gIOHibernateCurrentHeader->diag[0], gIOHibernateCurrentHeader->diag[1], 
	    gIOHibernateCurrentHeader->diag[2], gIOHibernateCurrentHeader->diag[3]);

#define t40ms(x)	(tmrCvt((((uint64_t)(x)) << 8), tscFCvtt2n) / 1000000)
#define tStat(x, y)	gIOHibernateStats->x = t40ms(gIOHibernateCurrentHeader->y);
    tStat(booterStart, booterStart);
    gIOHibernateStats->smcStart = gIOHibernateCurrentHeader->smcStart;
    tStat(booterDuration0, booterTime0);
    tStat(booterDuration1, booterTime1);
    tStat(booterDuration2, booterTime2);
    tStat(booterDuration, booterTime);
    tStat(booterConnectDisplayDuration, connectDisplayTime);
    tStat(booterSplashDuration, splashTime);
    tStat(trampolineDuration, trampolineTime);

    gIOHibernateStats->image1Size  = gIOHibernateCurrentHeader->image1Size;
    gIOHibernateStats->imageSize   = gIOHibernateCurrentHeader->imageSize;
    gIOHibernateStats->image1Pages = pagesDone;

    HIBLOG("booter start at %d ms smc %d ms, [%d, %d, %d] total %d ms, dsply %d, %d ms, tramp %d ms\n", 
	   gIOHibernateStats->booterStart,
	   gIOHibernateStats->smcStart,
	   gIOHibernateStats->booterDuration0,
	   gIOHibernateStats->booterDuration1,
	   gIOHibernateStats->booterDuration2,
	   gIOHibernateStats->booterDuration,
	   gIOHibernateStats->booterConnectDisplayDuration,
	   gIOHibernateStats->booterSplashDuration,
	   gIOHibernateStats->trampolineDuration);

    HIBLOG("hibernate_machine_init: state %d, image pages %d, sum was %x, imageSize 0x%qx, image1Size 0x%qx, conflictCount %d, nextFree %x\n",
	    gIOHibernateState, pagesDone, sum, gIOHibernateStats->imageSize, gIOHibernateStats->image1Size,
	    gIOHibernateCurrentHeader->conflictCount, gIOHibernateCurrentHeader->nextFree);

    if ((0 != (kIOHibernateModeSleep & gIOHibernateMode)) 
     && (0 != ((kIOHibernateModeDiscardCleanActive | kIOHibernateModeDiscardCleanInactive) & gIOHibernateMode)))
    {
        hibernate_page_list_discard(vars->page_list);
    }

    cryptvars = (kIOHibernateModeEncrypt & gIOHibernateMode) ? &gIOHibernateCryptWakeContext : 0;

    if (gIOHibernateCurrentHeader->handoffPageCount > gIOHibernateHandoffPageCount)
    	panic("handoff overflow");

    IOHibernateHandoff * handoff;
    bool                 done           = false;
    bool                 foundCryptData = false;

    for (handoff = (IOHibernateHandoff *) vars->handoffBuffer->getBytesNoCopy();
    	 !done;
    	 handoff = (IOHibernateHandoff *) &handoff->data[handoff->bytecount])
    {
//	HIBPRINT("handoff %p, %x, %x\n", handoff, handoff->type, handoff->bytecount);
	uint8_t * data = &handoff->data[0];
    	switch (handoff->type)
    	{
	    case kIOHibernateHandoffTypeEnd:
	    	done = true;
		break;

	    case kIOHibernateHandoffTypeGraphicsInfo:
		if (handoff->bytecount == sizeof(*gIOHibernateGraphicsInfo))
		{
		    bcopy(data, gIOHibernateGraphicsInfo, sizeof(*gIOHibernateGraphicsInfo));
		}
		break;

	    case kIOHibernateHandoffTypeCryptVars:
		if (cryptvars)
		{
		    hibernate_cryptwakevars_t *
		    wakevars = (hibernate_cryptwakevars_t *) &handoff->data[0];
		    bcopy(&wakevars->aes_iv[0], &cryptvars->aes_iv[0], sizeof(cryptvars->aes_iv));
		}
		foundCryptData = true;
		bzero(data, handoff->bytecount);
		break;

	    case kIOHibernateHandoffTypeMemoryMap:

		clock_get_uptime(&allTime);

		hibernate_newruntime_map(data, handoff->bytecount, 
					 gIOHibernateCurrentHeader->systemTableOffset);

		clock_get_uptime(&endTime);
	    
		SUB_ABSOLUTETIME(&endTime, &allTime);
		absolutetime_to_nanoseconds(endTime, &nsec);
	    
		HIBLOG("hibernate_newruntime_map time: %qd ms, ", nsec / 1000000ULL);

	    	break;

	    case kIOHibernateHandoffTypeDeviceTree:
		{
//		    DTEntry chosen = NULL;
//		    HIBPRINT("DTLookupEntry %d\n", DTLookupEntry((const DTEntry) data, "/chosen", &chosen));
		}
	    	break;

	    default:
	    	done = (kIOHibernateHandoffType != (handoff->type & 0xFFFF0000));
	    	break;
	}    
    }
    if (cryptvars && !foundCryptData)
    	panic("hibernate handoff");

    HIBPRINT("video 0x%llx %d %d %d status %x\n",
	    gIOHibernateGraphicsInfo->physicalAddress, gIOHibernateGraphicsInfo->depth, 
	    gIOHibernateGraphicsInfo->width, gIOHibernateGraphicsInfo->height, gIOHibernateGraphicsInfo->gfxStatus); 

    if (vars->videoMapping && gIOHibernateGraphicsInfo->physicalAddress)
    {
        vars->videoMapSize = round_page(gIOHibernateGraphicsInfo->height 
                                        * gIOHibernateGraphicsInfo->rowBytes);
	if (vars->videoMapSize > vars->videoAllocSize) vars->videoMapSize = 0;
	else
	{
	    IOMapPages(kernel_map, 
			vars->videoMapping, gIOHibernateGraphicsInfo->physicalAddress,
			vars->videoMapSize, kIOMapInhibitCache );
	}
    }

    if (vars->videoMapSize)
        ProgressUpdate(gIOHibernateGraphicsInfo, 
                        (uint8_t *) vars->videoMapping, 0, kIOHibernateProgressCount);

    uint8_t * src = (uint8_t *) vars->srcBuffer->getBytesNoCopy();
    uint8_t * compressed = src + page_size;
    uint8_t * scratch    = compressed + page_size;
    uint32_t  decoOffset;

    clock_get_uptime(&allTime);
    AbsoluteTime_to_scalar(&compTime) = 0;
    compBytes = 0;

    HIBLOG("IOPolledFilePollersOpen(), ml_get_interrupts_enabled %d\n", ml_get_interrupts_enabled());
    err = IOPolledFilePollersOpen(vars->fileVars, kIOPolledAfterSleepState, false);
    clock_get_uptime(&startIOTime);
    endTime = startIOTime;
    SUB_ABSOLUTETIME(&endTime, &allTime);
    absolutetime_to_nanoseconds(endTime, &nsec);
    HIBLOG("IOPolledFilePollersOpen(%x) %qd ms\n", err, nsec / 1000000ULL);

    IOPolledFileSeek(vars->fileVars, gIOHibernateCurrentHeader->image1Size);

    // kick off the read ahead
    vars->fileVars->bufferHalf   = 0;
    vars->fileVars->bufferLimit  = 0;
    vars->fileVars->lastRead     = 0;
    vars->fileVars->readEnd      = gIOHibernateCurrentHeader->imageSize;
    vars->fileVars->bufferOffset = vars->fileVars->bufferLimit;
    vars->fileVars->cryptBytes   = 0;
    AbsoluteTime_to_scalar(&vars->fileVars->cryptTime) = 0;

    err = IOPolledFileRead(vars->fileVars, 0, 0, cryptvars);
    vars->fileVars->bufferOffset = vars->fileVars->bufferLimit;
    // --

    HIBLOG("hibernate_machine_init reading\n");

    uint32_t * header = (uint32_t *) src;
    sum = 0;

    while (kIOReturnSuccess == err)
    {
	unsigned int count;
	unsigned int page;
        uint32_t     tag;
	vm_offset_t  ppnum, compressedSize;

	err = IOPolledFileRead(vars->fileVars, src, 8, cryptvars);
	if (kIOReturnSuccess != err)
	    break;

	ppnum = header[0];
	count = header[1];

//	HIBPRINT("(%x, %x)\n", ppnum, count);

	if (!count)
	    break;

	for (page = 0; page < count; page++)
	{
	    err = IOPolledFileRead(vars->fileVars, (uint8_t *) &tag, 4, cryptvars);
	    if (kIOReturnSuccess != err)
		break;

	    compressedSize = kIOHibernateTagLength & tag;
	    if (kIOHibernateTagSignature != (tag & ~kIOHibernateTagLength))
	    {
		err = kIOReturnIPCError;
		break;
	    }

	    err = IOPolledFileRead(vars->fileVars, src, (compressedSize + 3) & ~3, cryptvars);
	    if (kIOReturnSuccess != err) break;

	    if (compressedSize < page_size)
	    {
		decoOffset = page_size;
		clock_get_uptime(&startTime);

		if (compressedSize == 4) {
		    int i;
		    uint32_t *s, *d;
			
		    s = (uint32_t *)src;
		    d = (uint32_t *)(uintptr_t)compressed;

		    for (i = 0; i < (int)(PAGE_SIZE / sizeof(int32_t)); i++)
			*d++ = *s;
		}
		else 
		    WKdm_decompress_new((WK_word*) src, (WK_word*) compressed, (WK_word*) scratch, compressedSize);
		clock_get_uptime(&endTime);
		ADD_ABSOLUTETIME(&compTime, &endTime);
		SUB_ABSOLUTETIME(&compTime, &startTime);
		compBytes += page_size;
	    }
	    else decoOffset = 0;

	    sum += hibernate_sum_page((src + decoOffset), ppnum);
	    err = IOMemoryDescriptorReadToPhysical(vars->srcBuffer, decoOffset, ptoa_64(ppnum), page_size);
	    if (err)
	    {
		    HIBLOG("IOMemoryDescriptorReadToPhysical [%ld] %x\n", (long)ppnum, err);
		    break;
	    }

	    ppnum++;
	    pagesDone++;
	    pagesRead++;

	    if (0 == (8191 & pagesDone))
	    {
		clock_get_uptime(&endTime);
		SUB_ABSOLUTETIME(&endTime, &allTime);
		absolutetime_to_nanoseconds(endTime, &nsec);
		progressStamp = nsec / 750000000ULL;
		if (progressStamp != lastProgressStamp)
		{
		    lastProgressStamp = progressStamp;
		    HIBPRINT("pages %d (%d%%)\n", pagesDone, 
			    (100 * pagesDone) / gIOHibernateCurrentHeader->pageCount);
		}
	    }
	}
    }
    if ((kIOReturnSuccess == err) && (pagesDone == gIOHibernateCurrentHeader->actualUncompressedPages))
    	err = kIOReturnLockedRead;

    if (kIOReturnSuccess != err)
	panic("Hibernate restore error %x", err);

    gIOHibernateCurrentHeader->actualImage2Sum = sum;
    gIOHibernateCompression = gIOHibernateCurrentHeader->compression;

    clock_get_uptime(&endIOTime);

    err = IOPolledFilePollersClose(vars->fileVars, kIOPolledAfterSleepState);

    clock_get_uptime(&endTime);

    IOService::getPMRootDomain()->pmStatsRecordEvent( 
                        kIOPMStatsHibernateImageRead | kIOPMStatsEventStartFlag, allTime);
    IOService::getPMRootDomain()->pmStatsRecordEvent( 
                        kIOPMStatsHibernateImageRead | kIOPMStatsEventStopFlag, endTime);

    SUB_ABSOLUTETIME(&endTime, &allTime);
    absolutetime_to_nanoseconds(endTime, &nsec);

    SUB_ABSOLUTETIME(&endIOTime, &startIOTime);
    absolutetime_to_nanoseconds(endIOTime, &nsecIO);

    gIOHibernateStats->kernelImageReadDuration = nsec / 1000000ULL;
    gIOHibernateStats->imagePages              = pagesDone;

    HIBLOG("hibernate_machine_init pagesDone %d sum2 %x, time: %d ms, disk(0x%x) %qd Mb/s, ", 
		pagesDone, sum, gIOHibernateStats->kernelImageReadDuration, kDefaultIOSize,
		nsecIO ? ((((gIOHibernateCurrentHeader->imageSize - gIOHibernateCurrentHeader->image1Size) * 1000000000ULL) / 1024 / 1024) / nsecIO) : 0);

    absolutetime_to_nanoseconds(compTime, &nsec);
    HIBLOG("comp bytes: %qd time: %qd ms %qd Mb/s, ", 
		compBytes, 
		nsec / 1000000ULL,
		nsec ? (((compBytes * 1000000000ULL) / 1024 / 1024) / nsec) : 0);

    absolutetime_to_nanoseconds(vars->fileVars->cryptTime, &nsec);
    HIBLOG("crypt bytes: %qd time: %qd ms %qd Mb/s\n", 
		vars->fileVars->cryptBytes, 
		nsec / 1000000ULL, 
		nsec ? (((vars->fileVars->cryptBytes * 1000000000ULL) / 1024 / 1024) / nsec) : 0);

    KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 2) | DBG_FUNC_NONE, pagesRead, pagesDone, 0, 0, 0);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void IOHibernateSetWakeCapabilities(uint32_t capability)
{
    if (kIOHibernateStateWakingFromHibernate == gIOHibernateState)
    {
	gIOHibernateStats->wakeCapability = capability;

	if (kIOPMSystemCapabilityGraphics & capability)
	{
		vm_compressor_do_warmup();
	}
    }
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void IOHibernateSystemRestart(void)
{
    static uint8_t    noteStore[32] __attribute__((aligned(32)));
    IORegistryEntry * regEntry;
    const OSSymbol *  sym;
    OSData *          noteProp;
    OSData *          data;
    uintptr_t *       smcVars;
    uint8_t *         smcBytes;
    size_t            len;
    addr64_t          element;

    data = OSDynamicCast(OSData, IOService::getPMRootDomain()->getProperty(kIOHibernateSMCVariablesKey));
    if (!data) return;

    smcVars = (typeof(smcVars)) data->getBytesNoCopy();
    smcBytes = (typeof(smcBytes)) smcVars[1];
    len = smcVars[0];
    if (len > sizeof(noteStore)) len = sizeof(noteStore);
    noteProp = OSData::withCapacity(3 * sizeof(element));
    if (!noteProp) return;
    element = len;
    noteProp->appendBytes(&element, sizeof(element));
    element = crc32(0, smcBytes, len);
    noteProp->appendBytes(&element, sizeof(element));

    bcopy(smcBytes, noteStore, len);
    element = (addr64_t) &noteStore[0];
    element = (element & page_mask) | ptoa_64(pmap_find_phys(kernel_pmap, element));
    noteProp->appendBytes(&element, sizeof(element));

    if (!gIOOptionsEntry)
    {
	regEntry = IORegistryEntry::fromPath("/options", gIODTPlane);
	gIOOptionsEntry = OSDynamicCast(IODTNVRAM, regEntry);
	if (regEntry && !gIOOptionsEntry)
	    regEntry->release();
    }

    sym = OSSymbol::withCStringNoCopy(kIOHibernateBootNoteKey);
    if (gIOOptionsEntry && sym) gIOOptionsEntry->setProperty(sym, noteProp);
    if (noteProp)               noteProp->release();
    if (sym)                    sym->release();
}



