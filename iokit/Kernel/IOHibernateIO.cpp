/*
 * Copyright (c) 2004-2008 Apple Computer, Inc. All rights reserved.
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
  The kernel section "__HIB" is written uncompressed to the image. This section of code and data 
  (only) is used to decompress the image during wake/boot.
  Some additional pages are removed from the bitmaps - the buffers used for hibernation.
  The bitmaps are written to the image.
  More areas are removed from the bitmaps (after they have been written to the image) - the 
  section "__HIB" pages and interrupt stack.
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
#include <crypto/aes.h>

#include <sys/uio.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/fcntl.h>                       // (FWRITE, ...)
#include <sys/sysctl.h>
#include <sys/kdebug.h>

#include <IOKit/IOHibernatePrivate.h>
#include <IOKit/IOPolledInterface.h>
#include <IOKit/IONVRAM.h>
#include "IOHibernateInternal.h"
#include <libkern/WKdm.h>
#include "IOKitKernelInternal.h"
#include <pexpert/device_tree.h>

#include <machine/pal_routines.h>
#include <machine/pal_hibernate.h>

extern "C" addr64_t		kvtophys(vm_offset_t va);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

extern unsigned int		save_kdebug_enable;
extern uint32_t 		gIOHibernateState;
uint32_t			gIOHibernateMode;
static char			gIOHibernateBootSignature[256+1];
static char			gIOHibernateFilename[MAXPATHLEN+1];
static uint32_t			gIOHibernateFreeRatio = 0;		// free page target (percent)
uint32_t			gIOHibernateFreeTime  = 0*1000;	// max time to spend freeing pages (ms)

static IODTNVRAM *		gIOOptionsEntry;
static IORegistryEntry *	gIOChosenEntry;
#if defined(__i386__) || defined(__x86_64__)
static const OSSymbol *         gIOCreateEFIDevicePathSymbol;
static const OSSymbol * 	gIOHibernateRTCVariablesKey;
static const OSSymbol *         gIOHibernateBoot0082Key;
static const OSSymbol *         gIOHibernateBootNextKey;
static OSData *	                gIOHibernateBoot0082Data;
static OSData *	                gIOHibernateBootNextData;
static OSObject *		gIOHibernateBootNextSave;
#endif

static IOPolledFileIOVars	          gFileVars;
static IOHibernateVars			  gIOHibernateVars;
static struct kern_direct_file_io_ref_t * gIOHibernateFileRef;
static hibernate_cryptvars_t 		  gIOHibernateCryptWakeContext;
static hibernate_graphics_t  		  _hibernateGraphics;
static hibernate_graphics_t * 		  gIOHibernateGraphicsInfo = &_hibernateGraphics;

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

enum { kXPRamAudioVolume = 8 };
enum { kDefaultIOSize = 128 * 1024 };
enum { kVideoMapSize  = 32 * 1024 * 1024 };

#ifndef kIOMediaPreferredBlockSizeKey
#define kIOMediaPreferredBlockSizeKey	"Preferred Block Size"
#endif

#ifndef kIOBootPathKey	
#define kIOBootPathKey			"bootpath"
#endif
#ifndef kIOSelectedBootDeviceKey	
#define kIOSelectedBootDeviceKey	"boot-device"
#endif


enum { kIOHibernateMinPollersNeeded = 2 };

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

static IOReturn
IOHibernatePollerProbe(IOPolledFileIOVars * vars, IOService * target)
{
    IOReturn            err = kIOReturnError;
    int32_t		idx;
    IOPolledInterface * poller;

    for (idx = vars->pollers->getCount() - 1; idx >= 0; idx--)
    {
        poller = (IOPolledInterface *) vars->pollers->getObject(idx);
        err = poller->probe(target);
        if (err)
        {
            HIBLOG("IOPolledInterface::probe[%d] 0x%x\n", idx, err);
            break;
        }
    }

    return (err);
}

static IOReturn
IOHibernatePollerOpen(IOPolledFileIOVars * vars, uint32_t state, IOMemoryDescriptor * md)
{
    IOReturn            err = kIOReturnError;
    int32_t		idx;
    IOPolledInterface * poller;

    for (idx = vars->pollers->getCount() - 1; idx >= 0; idx--)
    {
        poller = (IOPolledInterface *) vars->pollers->getObject(idx);
        err = poller->open(state, md);
        if (err)
        {
            HIBLOG("IOPolledInterface::open[%d] 0x%x\n", idx, err);
            break;
        }
    }

    return (err);
}

static IOReturn
IOHibernatePollerClose(IOPolledFileIOVars * vars, uint32_t state)
{
    IOReturn            err = kIOReturnError;
    int32_t		idx;
    IOPolledInterface * poller;

    for (idx = 0;
         (poller = (IOPolledInterface *) vars->pollers->getObject(idx));
         idx++)
    {
        err = poller->close(state);
        if (err)
            HIBLOG("IOPolledInterface::close[%d] 0x%x\n", idx, err);
    }

    return (err);
}

static void
IOHibernatePollerIOComplete(void *   target,
                            void *   parameter,
                            IOReturn status,
                            UInt64   actualByteCount)
{
    IOPolledFileIOVars * vars = (IOPolledFileIOVars *) parameter;

    vars->ioStatus = status;
}

static IOReturn
IOHibernatePollerIO(IOPolledFileIOVars * vars, 
                    uint32_t operation, uint32_t bufferOffset, 
		    uint64_t deviceOffset, uint64_t length)
{

    IOReturn            err = kIOReturnError;
    IOPolledInterface * poller;
    IOPolledCompletion  completion;

    completion.target    = 0;
    completion.action    = &IOHibernatePollerIOComplete;
    completion.parameter = vars;

    vars->ioStatus = -1;

    poller = (IOPolledInterface *) vars->pollers->getObject(0);
    err = poller->startIO(operation, bufferOffset, deviceOffset + vars->block0, length, completion);
    if (err)
        HIBLOG("IOPolledInterface::startIO[%d] 0x%x\n", 0, err);

    return (err);
}

static IOReturn
IOHibernatePollerIODone(IOPolledFileIOVars * vars, bool abortable)
{
    IOReturn            err = kIOReturnSuccess;
    int32_t		idx = 0;
    IOPolledInterface * poller;

    while (-1 == vars->ioStatus)
    {
        for (idx = 0; 
	    (poller = (IOPolledInterface *) vars->pollers->getObject(idx));
             idx++)
        {
	    IOReturn newErr;
            newErr = poller->checkForWork();
	    if ((newErr == kIOReturnAborted) && !abortable)
		newErr = kIOReturnSuccess;
	    if (kIOReturnSuccess == err)
		err = newErr;
        }
    }

    if ((kIOReturnSuccess == err) && abortable && hibernate_should_abort())
    {
        err = kIOReturnAborted;
	HIBLOG("IOPolledInterface::checkForWork sw abort\n");
    }

    if (err)
    {
	HIBLOG("IOPolledInterface::checkForWork[%d] 0x%x\n", idx, err);
    }
    else 
    {
	err = vars->ioStatus;
	if (kIOReturnSuccess != err)
	    HIBLOG("IOPolledInterface::ioStatus 0x%x\n", err);
    }

    return (err);
}

IOReturn
IOPolledInterface::checkAllForWork(void)
{
    IOReturn            err = kIOReturnNotReady;
    int32_t		idx;
    IOPolledInterface * poller;

    IOHibernateVars * vars  = &gIOHibernateVars;

    if (!vars->fileVars || !vars->fileVars->pollers)
	return (err);

    for (idx = 0;
            (poller = (IOPolledInterface *) vars->fileVars->pollers->getObject(idx));
            idx++)
    {
        err = poller->checkForWork();
        if (err)
            HIBLOG("IOPolledInterface::checkAllForWork[%d] 0x%x\n", idx, err);
    }

    return (err);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct _OpenFileContext
{
    OSData * extents;
    uint64_t size;
};

static void
file_extent_callback(void * ref, uint64_t start, uint64_t length)
{
    _OpenFileContext * ctx = (_OpenFileContext *) ref;
    IOPolledFileExtent extent;

    extent.start  = start;
    extent.length = length;

    ctx->extents->appendBytes(&extent, sizeof(extent));
    ctx->size += length;
}

static IOService * 
IOCopyMediaForDev(dev_t device)
{
    OSDictionary * matching;
    OSNumber *     num;
    OSIterator *   iter;
    IOService *    result = 0;

    matching = IOService::serviceMatching("IOMedia");
    if (!matching)
        return (0);
    do
    {
        num = OSNumber::withNumber(major(device), 32);
        if (!num)
            break;
        matching->setObject(kIOBSDMajorKey, num);
        num->release();
        num = OSNumber::withNumber(minor(device), 32);
        if (!num)
            break;
        matching->setObject(kIOBSDMinorKey, num);
        num->release();
        if (!num)
            break;
        iter = IOService::getMatchingServices(matching);
        if (iter)
        {
            result = (IOService *) iter->getNextObject();
            result->retain();
            iter->release();
        }
    }
    while (false);
    matching->release();

    return (result);
}

IOReturn
IOPolledFileOpen( const char * filename, IOBufferMemoryDescriptor * ioBuffer,
			    IOPolledFileIOVars ** fileVars, OSData ** fileExtents,
			    OSData ** imagePath, uint8_t * volumeCryptKey)
{
    IOReturn			err = kIOReturnError;
    IOPolledFileIOVars *	vars;
    _OpenFileContext		ctx;
    OSData *			extentsData;
    OSNumber *			num;
    IOService *                 part = 0;
    OSString *                  keyUUID = 0;
    OSString *                  keyStoreUUID = 0;
    dev_t 			block_dev;
    dev_t 			hibernate_image_dev;
    uint64_t			maxiobytes;

    vars = &gFileVars;
    do
    {
	HIBLOG("sizeof(IOHibernateImageHeader) == %ld\n", sizeof(IOHibernateImageHeader));
	if (sizeof(IOHibernateImageHeader) != 512)
	    continue;
    
	vars->io           = false;
	vars->buffer       = (uint8_t *) ioBuffer->getBytesNoCopy();
	vars->bufferHalf   = 0;
	vars->bufferOffset = 0;
	vars->bufferSize   = ioBuffer->getLength() >> 1;
    
	extentsData = OSData::withCapacity(32);
    
	ctx.extents = extentsData;
	ctx.size    = 0;
	vars->fileRef = kern_open_file_for_direct_io(filename, 
						    &file_extent_callback, &ctx, 
						    &block_dev,
						    &hibernate_image_dev,
                                                    &vars->block0,
                                                    &maxiobytes,
                                                    &vars->flags, 
                                                    0, (caddr_t) gIOHibernateCurrentHeader, 
                                                    sizeof(IOHibernateImageHeader));
	if (!vars->fileRef)
	{
	    err = kIOReturnNoSpace;
	    break;
	}
	gIOHibernateFileRef = vars->fileRef;

        if (kIOHibernateModeSSDInvert & gIOHibernateMode)
            vars->flags ^= kIOHibernateOptionSSD;

	HIBLOG("Opened file %s, size %qd, partition base 0x%qx, maxio %qx ssd %d\n", filename, ctx.size, 
                    vars->block0, maxiobytes, kIOHibernateOptionSSD & vars->flags);
	if (ctx.size < 1*1024*1024)		// check against image size estimate!
	{
	    err = kIOReturnNoSpace;
	    break;
	}

        if (maxiobytes < vars->bufferSize)
            vars->bufferSize = maxiobytes;
    
	vars->extentMap = (IOPolledFileExtent *) extentsData->getBytesNoCopy();

        part = IOCopyMediaForDev(block_dev);
        if (!part)
            break;

        err = part->callPlatformFunction(PLATFORM_FUNCTION_GET_MEDIA_ENCRYPTION_KEY_UUID, false, 
        				  (void *) &keyUUID, (void *) &keyStoreUUID, NULL, NULL);
        if ((kIOReturnSuccess == err) && keyUUID && keyStoreUUID)
        {
//            IOLog("got volume key %s\n", keyStoreUUID->getCStringNoCopy());
            uuid_t                  volumeKeyUUID;
            aks_volume_key_t        vek;
            static IOService *      sKeyStore;
            static const OSSymbol * sAKSGetKey;

            if (!sAKSGetKey)
                sAKSGetKey = OSSymbol::withCStringNoCopy(AKS_PLATFORM_FUNCTION_GETKEY);
            if (!sKeyStore)
                sKeyStore = (IOService *) IORegistryEntry::fromPath(AKS_SERVICE_PATH, gIOServicePlane);
            if (sKeyStore)
                err = uuid_parse(keyStoreUUID->getCStringNoCopy(), volumeKeyUUID);
            else
                err = kIOReturnNoResources;
            if (kIOReturnSuccess == err)    
                err = sKeyStore->callPlatformFunction(sAKSGetKey, true, volumeKeyUUID, &vek, NULL, NULL);
            if (kIOReturnSuccess != err)    
                IOLog("volume key err 0x%x\n", err);
            else
            {
                size_t bytes = (kIOHibernateAESKeySize / 8);
                if (vek.key.keybytecount < bytes)
                     bytes = vek.key.keybytecount;
                bcopy(&vek.key.keybytes[0], volumeCryptKey, bytes);
            }
            bzero(&vek, sizeof(vek));
        }
        part->release();

        part = IOCopyMediaForDev(hibernate_image_dev);
        if (!part)
            break;

	IORegistryEntry * next;
	IORegistryEntry * child;
	OSData * data;

        vars->pollers = OSArray::withCapacity(4);
	if (!vars->pollers)
	    break;

	vars->blockSize = 512;
	next = part;
	do
	{
            IOPolledInterface * poller;
	    OSObject *          obj;

	    obj = next->getProperty(kIOPolledInterfaceSupportKey);
	    if (kOSBooleanFalse == obj)
	    {
		vars->pollers->flushCollection();
		break;
	    }
            else if ((poller = OSDynamicCast(IOPolledInterface, obj)))
                vars->pollers->setObject(poller);
	    if ((num = OSDynamicCast(OSNumber, next->getProperty(kIOMediaPreferredBlockSizeKey))))
		vars->blockSize = num->unsigned32BitValue();
            child = next;
	}
	while ((next = child->getParentEntry(gIOServicePlane)) 
                && child->isParent(next, gIOServicePlane, true));

	HIBLOG("hibernate image major %d, minor %d, blocksize %ld, pollers %d\n",
		    major(hibernate_image_dev), minor(hibernate_image_dev), (long)vars->blockSize, vars->pollers->getCount());
	if (vars->pollers->getCount() < kIOHibernateMinPollersNeeded)
	    continue;

	err = IOHibernatePollerProbe(vars, (IOService *) part);
	if (kIOReturnSuccess != err)
	    break;

	err = IOHibernatePollerOpen(vars, kIOPolledPreflightState, ioBuffer);
	if (kIOReturnSuccess != err)
	    break;

	*fileVars    = vars;
	*fileExtents = extentsData;
    
	// make imagePath

	if ((extentsData->getLength() >= sizeof(IOPolledFileExtent)))
	{
	    char str2[24 + sizeof(uuid_string_t) + 2];

#if defined(__i386__) || defined(__x86_64__)
	    if (!gIOCreateEFIDevicePathSymbol)
		gIOCreateEFIDevicePathSymbol = OSSymbol::withCString("CreateEFIDevicePath");

            if (keyUUID)
                snprintf(str2, sizeof(str2), "%qx:%s", 
                                vars->extentMap[0].start, keyUUID->getCStringNoCopy());
            else
                snprintf(str2, sizeof(str2), "%qx", vars->extentMap[0].start);

	    err = IOService::getPlatform()->callPlatformFunction(
						gIOCreateEFIDevicePathSymbol, false,
						(void *) part, (void *) str2,
						(void *) (uintptr_t) true, (void *) &data);
#else
	    char str1[256];
	    int len = sizeof(str1);

	    if (!part->getPath(str1, &len, gIODTPlane))
		err = kIOReturnNotFound;
	    else
	    {
		snprintf(str2, sizeof(str2), ",%qx", vars->extentMap[0].start);
		// (strip the plane name)
		char * tail = strchr(str1, ':');
		if (!tail)
		    tail = str1 - 1;
		data = OSData::withBytes(tail + 1, strlen(tail + 1));
		data->appendBytes(str2, strlen(str2));
	    }
#endif
	if (kIOReturnSuccess == err)
	    *imagePath = data;
	else
	    HIBLOG("error 0x%x getting path\n", err);
	}
    }
    while (false);

    if (kIOReturnSuccess != err)
    {
        HIBLOG("error 0x%x opening hibernation file\n", err);
	if (vars->fileRef)
	{
	    kern_close_file_for_direct_io(vars->fileRef, 0, 0, 0, 0, 0);
	    gIOHibernateFileRef = vars->fileRef = NULL;
	}
    }

    if (part)
	part->release();

    return (err);
}

IOReturn
IOPolledFileClose( IOPolledFileIOVars * vars )
{
    if (vars->pollers)
    {
	IOHibernatePollerClose(vars, kIOPolledPostflightState);
        vars->pollers->release();
    }

    bzero(vars, sizeof(IOPolledFileIOVars));

    return (kIOReturnSuccess);
}

static IOReturn
IOPolledFileSeek(IOPolledFileIOVars * vars, uint64_t position)
{
    IOPolledFileExtent * extentMap;

    extentMap = vars->extentMap;

    vars->position = position;

    while (position >= extentMap->length)
    {
	position -= extentMap->length;
	extentMap++;
    }

    vars->currentExtent   = extentMap;
    vars->extentRemaining = extentMap->length - position;
    vars->extentPosition  = vars->position - position;

    if (vars->bufferSize <= vars->extentRemaining)
	vars->bufferLimit = vars->bufferSize;
    else
	vars->bufferLimit = vars->extentRemaining;

    return (kIOReturnSuccess);
}

static IOReturn
IOPolledFileWrite(IOPolledFileIOVars * vars,
                    const uint8_t * bytes, IOByteCount size,
                    hibernate_cryptvars_t * cryptvars)
{
    IOReturn    err = kIOReturnSuccess;
    IOByteCount copy;
    bool	flush = false;

    do
    {
	if (!bytes && !size)
	{
	    // seek to end of block & flush
	    size = vars->position & (vars->blockSize - 1);
	    if (size)
		size = vars->blockSize - size;
	    flush = true;
            // use some garbage for the fill
            bytes = vars->buffer + vars->bufferOffset;
	}

	copy = vars->bufferLimit - vars->bufferOffset;
	if (copy > size)
	    copy = size;
	else
	    flush = true;

	if (bytes)
	{
	    bcopy(bytes, vars->buffer + vars->bufferHalf + vars->bufferOffset, copy);
	    bytes += copy;
	}
        else
	    bzero(vars->buffer + vars->bufferHalf + vars->bufferOffset, copy);
        
	size -= copy;
	vars->bufferOffset += copy;
	vars->position += copy;

	if (flush && vars->bufferOffset)
	{
	    uint64_t offset = (vars->position - vars->bufferOffset 
				- vars->extentPosition + vars->currentExtent->start);
	    uint32_t length = (vars->bufferOffset);

#if CRYPTO
            if (cryptvars && vars->encryptStart
                && (vars->position > vars->encryptStart)
                && ((vars->position - length) < vars->encryptEnd))
            {
                AbsoluteTime startTime, endTime;

                uint64_t encryptLen, encryptStart;
                encryptLen = vars->position - vars->encryptStart;
                if (encryptLen > length)
                    encryptLen = length;
                encryptStart = length - encryptLen;
                if (vars->position > vars->encryptEnd)
                    encryptLen -= (vars->position - vars->encryptEnd);

                clock_get_uptime(&startTime);

                // encrypt the buffer
                aes_encrypt_cbc(vars->buffer + vars->bufferHalf + encryptStart,
                                &cryptvars->aes_iv[0],
                                encryptLen / AES_BLOCK_SIZE,
                                vars->buffer + vars->bufferHalf + encryptStart,
                                &cryptvars->ctx.encrypt);
    
                clock_get_uptime(&endTime);
                ADD_ABSOLUTETIME(&vars->cryptTime, &endTime);
                SUB_ABSOLUTETIME(&vars->cryptTime, &startTime);
                vars->cryptBytes += encryptLen;

                // save initial vector for following encrypts
                bcopy(vars->buffer + vars->bufferHalf + encryptStart + encryptLen - AES_BLOCK_SIZE,
                        &cryptvars->aes_iv[0],
                        AES_BLOCK_SIZE);
            }
#endif /* CRYPTO */

	    if (vars->io)
            {
		err = IOHibernatePollerIODone(vars, true);
                if (kIOReturnSuccess != err)
                    break;
            }

if (vars->position & (vars->blockSize - 1)) HIBLOG("misaligned file pos %qx\n", vars->position);
//if (length != vars->bufferSize) HIBLOG("short write of %qx ends@ %qx\n", length, offset + length);

	    err = IOHibernatePollerIO(vars, kIOPolledWrite, vars->bufferHalf, offset, length);
            if (kIOReturnSuccess != err)
                break;
	    vars->io = true;

	    vars->extentRemaining -= vars->bufferOffset;
	    if (!vars->extentRemaining)
	    {
		vars->currentExtent++;
		vars->extentRemaining = vars->currentExtent->length;
		vars->extentPosition  = vars->position;
                if (!vars->extentRemaining)
                {
                    err = kIOReturnOverrun;
                    break;
                }
	    }

	    vars->bufferHalf = vars->bufferHalf ? 0 : vars->bufferSize;
	    vars->bufferOffset = 0;
	    if (vars->bufferSize <= vars->extentRemaining)
		vars->bufferLimit = vars->bufferSize;
	    else
		vars->bufferLimit = vars->extentRemaining;

	    flush = false;
	}
    }
    while (size);

    return (err);
}

static IOReturn
IOPolledFileRead(IOPolledFileIOVars * vars,
                    uint8_t * bytes, IOByteCount size,
                    hibernate_cryptvars_t * cryptvars)
{
    IOReturn    err = kIOReturnSuccess;
    IOByteCount copy;

//    bytesWritten += size;

    do
    {
	copy = vars->bufferLimit - vars->bufferOffset;
	if (copy > size)
	    copy = size;

	if (bytes)
	{
	    bcopy(vars->buffer + vars->bufferHalf + vars->bufferOffset, bytes, copy);
	    bytes += copy;
	}
	size -= copy;
	vars->bufferOffset += copy;
//	vars->position += copy;

	if ((vars->bufferOffset == vars->bufferLimit) && (vars->position < vars->readEnd))
	{
	    if (vars->io)
            {
		err = IOHibernatePollerIODone(vars, false);
                if (kIOReturnSuccess != err)
                    break;
            }
            else
                cryptvars = 0;

if (vars->position & (vars->blockSize - 1)) HIBLOG("misaligned file pos %qx\n", vars->position);

	    vars->position        += vars->lastRead;
	    vars->extentRemaining -= vars->lastRead;
	    vars->bufferLimit      = vars->lastRead;

	    if (!vars->extentRemaining)
	    {
		vars->currentExtent++;
		vars->extentRemaining = vars->currentExtent->length;
		vars->extentPosition  = vars->position;
                if (!vars->extentRemaining)
                {
                    err = kIOReturnOverrun;
                    break;
                }
	    }

	    uint64_t length;
	    uint64_t lastReadLength = vars->lastRead;
	    uint64_t offset = (vars->position 
				- vars->extentPosition + vars->currentExtent->start);
	    if (vars->extentRemaining <= vars->bufferSize)
		length = vars->extentRemaining;
	    else
		length = vars->bufferSize;
	    if ((length + vars->position) > vars->readEnd)
	    	length = vars->readEnd - vars->position;

	    vars->lastRead = length;
	    if (length)
	    {
//if (length != vars->bufferSize) HIBLOG("short read of %qx ends@ %qx\n", length, offset + length);
		err = IOHibernatePollerIO(vars, kIOPolledRead, vars->bufferHalf, offset, length);
		if (kIOReturnSuccess != err)
		    break;
		vars->io = true;
	    }

	    vars->bufferHalf = vars->bufferHalf ? 0 : vars->bufferSize;
	    vars->bufferOffset = 0;

#if CRYPTO
            if (cryptvars)
            {
                uint8_t thisVector[AES_BLOCK_SIZE];
                AbsoluteTime startTime, endTime;

                // save initial vector for following decrypts
                bcopy(&cryptvars->aes_iv[0], &thisVector[0], AES_BLOCK_SIZE);
                bcopy(vars->buffer + vars->bufferHalf + lastReadLength - AES_BLOCK_SIZE, 
                        &cryptvars->aes_iv[0], AES_BLOCK_SIZE);

                // decrypt the buffer
                clock_get_uptime(&startTime);

                aes_decrypt_cbc(vars->buffer + vars->bufferHalf,
                                &thisVector[0],
                                lastReadLength / AES_BLOCK_SIZE,
                                vars->buffer + vars->bufferHalf,
                                &cryptvars->ctx.decrypt);

                clock_get_uptime(&endTime);
                ADD_ABSOLUTETIME(&vars->cryptTime, &endTime);
                SUB_ABSOLUTETIME(&vars->cryptTime, &startTime);
                vars->cryptBytes += lastReadLength;
            }
#endif /* CRYPTO */
	}
    }
    while (size);

    return (err);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
		
IOReturn
IOHibernateSystemSleep(void)
{
    IOReturn   err;
    OSData *   data;
    OSObject * obj;
    OSString * str;
    bool       dsSSD;

    IOHibernateVars * vars  = &gIOHibernateVars;

    if (vars->fileVars && vars->fileVars->fileRef)
	// already on the way down
	return (kIOReturnSuccess);

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


    do
    {
        vars->srcBuffer = IOBufferMemoryDescriptor::withOptions(kIODirectionOutIn,
				    4 * page_size, page_size);
        vars->ioBuffer  = IOBufferMemoryDescriptor::withOptions(kIODirectionOutIn, 
				    2 * kDefaultIOSize, page_size);

	vars->handoffBuffer = IOBufferMemoryDescriptor::withOptions(kIODirectionOutIn, 
				    ptoa_64(gIOHibernateHandoffPageCount), page_size);

        if (!vars->srcBuffer || !vars->ioBuffer || !vars->handoffBuffer)
        {
            err = kIOReturnNoMemory;
            break;
        }

	// open & invalidate the image file
	gIOHibernateCurrentHeader->signature = kIOHibernateHeaderInvalidSignature;
        err = IOPolledFileOpen(gIOHibernateFilename, vars->ioBuffer,
                                &vars->fileVars, &vars->fileExtents, &data, 
                                &vars->volumeCryptKey[0]);
        if (KERN_SUCCESS != err)
        {
	    HIBLOG("IOPolledFileOpen(%x)\n", err);
            break;
        }

	bzero(gIOHibernateCurrentHeader, sizeof(IOHibernateImageHeader));
	gIOHibernateCurrentHeader->debugFlags = gIOHibernateDebugFlags;
        dsSSD = ((0 != (kIOHibernateOptionSSD & vars->fileVars->flags))
                && (kOSBooleanTrue == IOService::getPMRootDomain()->getProperty(kIOPMDeepSleepEnabledKey)));
        if (dsSSD)
        {
            gIOHibernateCurrentHeader->options |= 
                                                kIOHibernateOptionSSD
                                              | kIOHibernateOptionColor;

#if defined(__i386__) || defined(__x86_64__)
            if (!uuid_is_null(vars->volumeCryptKey) &&
                  (kOSBooleanTrue != IOService::getPMRootDomain()->getProperty(kIOPMDestroyFVKeyOnStandbyKey)))
            {
                uintptr_t smcVars[2];
                smcVars[0] = sizeof(vars->volumeCryptKey);
                smcVars[1] = (uintptr_t)(void *) &vars->volumeCryptKey[0];

                IOService::getPMRootDomain()->setProperty(kIOHibernateSMCVariablesKey, smcVars, sizeof(smcVars));
                bzero(smcVars, sizeof(smcVars));
            }
#endif
        }
        else
        {
            gIOHibernateCurrentHeader->options |= kIOHibernateOptionProgress;
        }

        boolean_t encryptedswap;
        AbsoluteTime startTime, endTime;
        uint64_t nsec;

        clock_get_uptime(&startTime);
        err = hibernate_setup(gIOHibernateCurrentHeader, 
                                gIOHibernateFreeRatio, gIOHibernateFreeTime,
                                dsSSD,
                                &vars->page_list, &vars->page_list_wired, &vars->page_list_pal, &encryptedswap);
        clock_get_uptime(&endTime);
        SUB_ABSOLUTETIME(&endTime, &startTime);
        absolutetime_to_nanoseconds(endTime, &nsec);
        HIBLOG("hibernate_setup(%d) took %qd ms\n", err, nsec / 1000000ULL);

        if (KERN_SUCCESS != err)
            break;

        if (encryptedswap || !uuid_is_null(vars->volumeCryptKey))
            gIOHibernateMode ^= kIOHibernateModeEncrypt; 

        if (kIOHibernateOptionProgress & gIOHibernateCurrentHeader->options)
        {
            vars->videoAllocSize = kVideoMapSize;
            if (KERN_SUCCESS != kmem_alloc_pageable(kernel_map, &vars->videoMapping, vars->videoAllocSize))
                vars->videoMapping = 0;
        }

	// generate crypt keys
        for (uint32_t i = 0; i < sizeof(vars->wiredCryptKey); i++)
            vars->wiredCryptKey[i] = random();
        for (uint32_t i = 0; i < sizeof(vars->cryptKey); i++)
            vars->cryptKey[i] = random();

	// set nvram

        IORegistryEntry * regEntry;
        if (!gIOOptionsEntry)
        {
            regEntry = IORegistryEntry::fromPath("/options", gIODTPlane);
            gIOOptionsEntry = OSDynamicCast(IODTNVRAM, regEntry);
            if (regEntry && !gIOOptionsEntry)
                regEntry->release();
        }
        if (!gIOChosenEntry)
            gIOChosenEntry = IORegistryEntry::fromPath("/chosen", gIODTPlane);

	if (gIOOptionsEntry)
	{
            const OSSymbol *  sym;

            sym = OSSymbol::withCStringNoCopy(kIOHibernateBootImageKey);
            if (sym)
            {
                gIOOptionsEntry->setProperty(sym, data);
                sym->release();
            }
            data->release();

#if defined(__i386__) || defined(__x86_64__)
	    struct AppleRTCHibernateVars
	    {
		uint8_t     signature[4];
		uint32_t    revision;
		uint8_t	    booterSignature[20];
		uint8_t	    wiredCryptKey[16];
	    };
	    AppleRTCHibernateVars rtcVars;

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
		    if (c >= 'a')
			c -= 'a' - 10;
		    else if (c >= 'A')
			c -= 'A' - 10;
		    else if (c >= '0')
			c -= '0';
		    else
			continue;
		    value = (value << 4) | c;
		    if (i & 1)
			rtcVars.booterSignature[i >> 1] = value;
		}
	    }
	    data = OSData::withBytes(&rtcVars, sizeof(rtcVars));
	    if (data)
	    { 
		if (!gIOHibernateRTCVariablesKey)
		    gIOHibernateRTCVariablesKey = OSSymbol::withCStringNoCopy(kIOHibernateRTCVariablesKey);
		if (gIOHibernateRTCVariablesKey)
		    IOService::getPMRootDomain()->setProperty(gIOHibernateRTCVariablesKey, data);
	
		if( gIOOptionsEntry )
		{
		    if( gIOHibernateMode & kIOHibernateModeSwitch )
		    {
			const OSSymbol *sym;
			sym = OSSymbol::withCStringNoCopy(kIOHibernateBootSwitchVarsKey);
			if( sym )
			{
			    gIOOptionsEntry->setProperty(sym, data); /* intentional insecure backup of rtc boot vars */
			    sym->release();
			}
		    }	
		}

		data->release();
	    }
            if (gIOChosenEntry)
            {
                data = OSDynamicCast(OSData, gIOChosenEntry->getProperty(kIOHibernateMachineSignatureKey));
                if (data)
                    gIOHibernateCurrentHeader->machineSignature = *((UInt32 *)data->getBytesNoCopy());
		{
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
		    if (!gIOHibernateBoot0082Key)
			gIOHibernateBoot0082Key = OSSymbol::withCString("8BE4DF61-93CA-11D2-AA0D-00E098032B8C:Boot0082");
		    if (!gIOHibernateBootNextKey)
			gIOHibernateBootNextKey = OSSymbol::withCString("8BE4DF61-93CA-11D2-AA0D-00E098032B8C:BootNext");
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
	   	}
            }
#else /* !i386 && !x86_64 */
            if (kIOHibernateModeEncrypt & gIOHibernateMode)
            {
                data = OSData::withBytes(&vars->wiredCryptKey[0], sizeof(vars->wiredCryptKey));
                sym = OSSymbol::withCStringNoCopy(kIOHibernateBootImageKeyKey);
                if (sym && data)
                    gIOOptionsEntry->setProperty(sym, data);
                if (sym)
                    sym->release();
                if (data)
                    data->release();
                if (false && gIOHibernateBootSignature[0])
                {
                    data = OSData::withCapacity(16);
                    sym = OSSymbol::withCStringNoCopy(kIOHibernateBootSignatureKey);
                    if (sym && data)
                    {
                        char c;
                        uint8_t value = 0;
                        for (uint32_t i = 0; (c = gIOHibernateBootSignature[i]); i++)
                        {
                            if (c >= 'a')
                                c -= 'a' - 10;
                            else if (c >= 'A')
                                c -= 'A' - 10;
                            else if (c >= '0')
                                c -= '0';
                            else
                                continue;
                            value = (value << 4) | c;
                            if (i & 1)
                                data->appendBytes(&value, sizeof(value));
                        }
                        gIOOptionsEntry->setProperty(sym, data);
                    }
                    if (sym)
                        sym->release();
                    if (data)
                        data->release();
                }
            }
            if (!vars->haveFastBoot)
            {
                // set boot volume to zero
                IODTPlatformExpert * platform = OSDynamicCast(IODTPlatformExpert, IOService::getPlatform());
                if (platform && (kIOReturnSuccess == platform->readXPRAM(kXPRamAudioVolume, 
                                            &vars->saveBootAudioVolume, sizeof(vars->saveBootAudioVolume))))
                {
                    uint8_t newVolume;
                    newVolume = vars->saveBootAudioVolume & 0xf8;
                    platform->writeXPRAM(kXPRamAudioVolume, 
                                            &newVolume, sizeof(newVolume));
                }
            }
#endif /* !i386 && !x86_64 */
	}
	// --

	gIOHibernateCurrentHeader->signature = kIOHibernateHeaderSignature;
	gIOHibernateState = kIOHibernateStateHibernating;
    }
    while (false);

    return (err);
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
IOHibernateSystemHasSlept(void)
{
    IOHibernateVars * vars  = &gIOHibernateVars;
    OSObject        * obj;
    OSData          * data;

    obj = IOService::getPMRootDomain()->copyProperty(kIOHibernatePreviewBufferKey);
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

    return (kIOReturnSuccess);
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
    IOHibernateVars * vars  = &gIOHibernateVars;

    hibernate_teardown(vars->page_list, vars->page_list_wired);

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


    if (vars->fileVars)
    {
	IOPolledFileClose(vars->fileVars);
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
	    gIOOptionsEntry->sync();
	}
#endif

    if (vars->srcBuffer)
	vars->srcBuffer->release();
    if (vars->ioBuffer)
	vars->ioBuffer->release();
    bzero(&gIOHibernateHandoffPages[0], gIOHibernateHandoffPageCount * sizeof(gIOHibernateHandoffPages[0]));
    if (vars->handoffBuffer && (kIOHibernateStateWakingFromHibernate == gIOHibernateState))
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
	vars->handoffBuffer->release();
    }
    if (vars->fileExtents)
	vars->fileExtents->release();

    bzero(vars, sizeof(*vars));

//    gIOHibernateState = kIOHibernateStateInactive;       // leave it for post wake code to see

    return (kIOReturnSuccess);
}

IOReturn
IOHibernateSystemPostWake(void)
{
    if (gIOHibernateFileRef)
    {
	// invalidate & close the image file
	gIOHibernateCurrentHeader->signature = kIOHibernateHeaderInvalidSignature;
	kern_close_file_for_direct_io(gIOHibernateFileRef,
				       0, (caddr_t) gIOHibernateCurrentHeader, 
				       sizeof(IOHibernateImageHeader),
				       sizeof(IOHibernateImageHeader),
				       gIOHibernateCurrentHeader->imageSize);
        gIOHibernateFileRef = 0;
    }
    return (kIOReturnSuccess);
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

void
IOHibernateSystemInit(IOPMrootDomain * rootDomain)
{
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
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static void
hibernate_setup_for_wake(void)
{
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define C_ASSERT(e) typedef char    __C_ASSERT__[(e) ? 1 : -1]

static bool
no_encrypt_page(vm_offset_t ppnum)
{
    if (pmap_is_noencrypt((ppnum_t)ppnum) == TRUE)
    {
        return true;
    }
    return false;
}

uint32_t	wired_pages_encrypted = 0;
uint32_t	dirty_pages_encrypted = 0;
uint32_t	wired_pages_clear = 0;

static void
hibernate_pal_callback(void *vars_arg, vm_offset_t addr)
{
	IOHibernateVars *vars = (IOHibernateVars *)vars_arg;
	/* Make sure it's not in either of the save lists */
	hibernate_set_page_state(vars->page_list, vars->page_list_wired, atop_64(addr), 1, kIOHibernatePageStateFree);

	/* Set it in the bitmap of pages owned by the PAL */
	hibernate_page_bitset(vars->page_list_pal, TRUE, atop_64(addr));
}

static struct hibernate_cryptvars_t *local_cryptvars;

extern "C" int
hibernate_pal_write(void *buffer, size_t size)
{
    IOHibernateVars * vars  = &gIOHibernateVars;

	IOReturn err = IOPolledFileWrite(vars->fileVars, (const uint8_t *)buffer, size, local_cryptvars);
	if (kIOReturnSuccess != err) {
		kprintf("epic hibernate fail! %d\n", err);
		return err;
	}

	return 0;
}


extern "C" uint32_t
hibernate_write_image(void)
{
    IOHibernateImageHeader * header = gIOHibernateCurrentHeader;
    IOHibernateVars *        vars  = &gIOHibernateVars;
    IOPolledFileExtent *     fileExtents;

    C_ASSERT(sizeof(IOHibernateImageHeader) == 512);

    uint32_t	 pageCount, pagesDone;
    IOReturn     err;
    vm_offset_t  ppnum, page;
    IOItemCount  count;
    uint8_t *	 src;
    uint8_t *	 data;
    IOByteCount  pageCompressedSize;
    uint64_t	 compressedSize, uncompressedSize;
    uint64_t	 image1Size = 0;
    uint32_t	 bitmap_size;
    bool	 iterDone, pollerOpen, needEncrypt;
    uint32_t	 restore1Sum, sum, sum1, sum2;
    uint32_t	 tag;
    uint32_t	 pageType;
    uint32_t	 pageAndCount[2];
    addr64_t     phys64;
    IOByteCount  segLen;

    AbsoluteTime startTime, endTime;
    AbsoluteTime allTime, compTime;
    uint64_t     compBytes;
    uint64_t     nsec;
    uint32_t     lastProgressStamp = 0;
    uint32_t     progressStamp;
    uint32_t	 blob, lastBlob = (uint32_t) -1L;

    hibernate_cryptvars_t _cryptvars;
    hibernate_cryptvars_t * cryptvars = 0;

    wired_pages_encrypted = 0;
    dirty_pages_encrypted = 0;
    wired_pages_clear = 0;

    if (!vars->fileVars || !vars->fileVars->pollers || !vars->fileExtents)
        return (false /* sleep */ );

    if (kIOHibernateModeSleep & gIOHibernateMode)
	kdebug_enable = save_kdebug_enable;

    KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 1) | DBG_FUNC_START, 0, 0, 0, 0, 0);
    IOService::getPMRootDomain()->tracePoint(kIOPMTracePointHibernate);

    restore1Sum = sum1 = sum2 = 0;

    hibernate_pal_prepare();

#if CRYPTO
    // encryption data. "iv" is the "initial vector".
    if (kIOHibernateModeEncrypt & gIOHibernateMode)
    {
        static const unsigned char first_iv[AES_BLOCK_SIZE]
        = {  0xa3, 0x63, 0x65, 0xa9, 0x0b, 0x71, 0x7b, 0x1c,
             0xdf, 0x9e, 0x5f, 0x32, 0xd7, 0x61, 0x63, 0xda };
    
        cryptvars = &gIOHibernateCryptWakeContext;
        bzero(cryptvars, sizeof(hibernate_cryptvars_t));
        aes_encrypt_key(vars->cryptKey,
                        kIOHibernateAESKeySize,
                        &cryptvars->ctx.encrypt);
        aes_decrypt_key(vars->cryptKey,
                        kIOHibernateAESKeySize,
                        &cryptvars->ctx.decrypt);

        cryptvars = &_cryptvars;
        bzero(cryptvars, sizeof(hibernate_cryptvars_t));
        for (pageCount = 0; pageCount < sizeof(vars->wiredCryptKey); pageCount++)
            vars->wiredCryptKey[pageCount] ^= vars->volumeCryptKey[pageCount];
        bzero(&vars->volumeCryptKey[0], sizeof(vars->volumeCryptKey));
        aes_encrypt_key(vars->wiredCryptKey,
                        kIOHibernateAESKeySize,
                        &cryptvars->ctx.encrypt);

        bcopy(&first_iv[0], &cryptvars->aes_iv[0], AES_BLOCK_SIZE);
        bzero(&vars->wiredCryptKey[0], sizeof(vars->wiredCryptKey));
        bzero(&vars->cryptKey[0], sizeof(vars->cryptKey));

        local_cryptvars = cryptvars;
    }
#endif /* CRYPTO */

    hibernate_setup_for_wake();

    hibernate_page_list_setall(vars->page_list,
                               vars->page_list_wired,
							   vars->page_list_pal,
                               &pageCount);

    HIBLOG("hibernate_page_list_setall found pageCount %d\n", pageCount);

    fileExtents = (IOPolledFileExtent *) vars->fileExtents->getBytesNoCopy();

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

        IOPolledFileSeek(vars->fileVars, sizeof(IOHibernateImageHeader));
    
        HIBLOG("IOHibernatePollerOpen, ml_get_interrupts_enabled %d\n", 
                ml_get_interrupts_enabled());
        err = IOHibernatePollerOpen(vars->fileVars, kIOPolledBeforeSleepState, vars->ioBuffer);
        HIBLOG("IOHibernatePollerOpen(%x)\n", err);
        pollerOpen = (kIOReturnSuccess == err);
        if (!pollerOpen)
            break;
    
        // copy file block extent list if larger than header
    
        count = vars->fileExtents->getLength();
        if (count > sizeof(header->fileExtentMap))
        {
            count -= sizeof(header->fileExtentMap);
            err = IOPolledFileWrite(vars->fileVars,
                                    ((uint8_t *) &fileExtents[0]) + sizeof(header->fileExtentMap), count, cryptvars);
            if (kIOReturnSuccess != err)
                break;
        }

        uintptr_t hibernateBase;
        uintptr_t hibernateEnd;

        hibernateBase = HIB_BASE; /* Defined in PAL headers */

        hibernateEnd = (sectHIBB + sectSizeHIB);

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

        // sum __HIB sect, with zeros for the stack
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
    
        // write the __HIB sect, with zeros for the stack

        src = (uint8_t *) trunc_page(hibernateBase);
        count = ((uintptr_t) &gIOHibernateRestoreStack[0]) - trunc_page(hibernateBase);
        if (count)
        {
            err = IOPolledFileWrite(vars->fileVars, src, count, cryptvars);
            if (kIOReturnSuccess != err)
                break;
        }
        err = IOPolledFileWrite(vars->fileVars, 
                                        (uint8_t *) 0,
                                        &gIOHibernateRestoreStackEnd[0] - &gIOHibernateRestoreStack[0],
                                        cryptvars);
        if (kIOReturnSuccess != err)
            break;
        src = &gIOHibernateRestoreStackEnd[0];
        count = round_page(hibernateEnd) - ((uintptr_t) src);
        if (count)
        {
            err = IOPolledFileWrite(vars->fileVars, src, count, cryptvars);
            if (kIOReturnSuccess != err)
                break;
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
                err = IOPolledFileWrite(vars->fileVars, 
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
            count = vars->previewBuffer->getLength();

            header->previewPageListSize = ppnum;
            header->previewSize = count + ppnum;

            for (page = 0; page < count; page += page_size)
            {
                phys64 = vars->previewBuffer->getPhysicalSegment(page, NULL, kIOMemoryMapperNone);
                sum1 += hibernate_sum_page(src + page, atop_64(phys64));
            }
            err = IOPolledFileWrite(vars->fileVars, src, count, cryptvars);
            if (kIOReturnSuccess != err)
                break;
        }

        // mark areas for no save
    
        for (count = 0;
            (phys64 = vars->ioBuffer->getPhysicalSegment(count, &segLen, kIOMemoryMapperNone));
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
        err = IOPolledFileWrite(vars->fileVars, src, bitmap_size, cryptvars);
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

		(void)hibernate_pal_callback;

        src = (uint8_t *) vars->srcBuffer->getBytesNoCopy();
    
        pagesDone  = 0;
        lastBlob   = 0;
    
        HIBLOG("writing %d pages\n", pageCount);

        enum
        // pageType
        { 
            kWired          = 0x02,
            kEncrypt        = 0x01,
            kWiredEncrypt   = kWired | kEncrypt,
            kWiredClear     = kWired,
            kUnwiredEncrypt = kEncrypt
        };

        for (pageType = kWiredEncrypt; pageType >= kUnwiredEncrypt; pageType--)
        {
            if (needEncrypt && (kEncrypt & pageType))
            {
                vars->fileVars->encryptStart = (vars->fileVars->position & ~(((uint64_t)AES_BLOCK_SIZE) - 1));
                vars->fileVars->encryptEnd   = UINT64_MAX;
                HIBLOG("encryptStart %qx\n", vars->fileVars->encryptStart);

                if (kUnwiredEncrypt == pageType)
                {
                    // start unwired image
                    bcopy(&cryptvars->aes_iv[0], 
                            &gIOHibernateCryptWakeContext.aes_iv[0], 
                            sizeof(cryptvars->aes_iv));
                    cryptvars = &gIOHibernateCryptWakeContext;
                }
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
                                && (((kEncrypt & pageType) == 0) == no_encrypt_page(ppnum + checkIndex)); 
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
                    case kWiredEncrypt:   wired_pages_encrypted += count; break;
                    case kWiredClear:     wired_pages_clear     += count; break;
                    case kUnwiredEncrypt: dirty_pages_encrypted += count; break;
                }
    
                if (iterDone && (kWiredEncrypt == pageType))   {/* not yet end of wired list */}
                else
                {
                    pageAndCount[0] = ppnum;
                    pageAndCount[1] = count;
                    err = IOPolledFileWrite(vars->fileVars, 
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

                    pageCompressedSize = WKdm_compress ((WK_word*) src, (WK_word*) (src + page_size), PAGE_SIZE_IN_WORDS);
        
                    clock_get_uptime(&endTime);
                    ADD_ABSOLUTETIME(&compTime, &endTime);
                    SUB_ABSOLUTETIME(&compTime, &startTime);
                    compBytes += page_size;
        
                    if (kIOHibernateModeEncrypt & gIOHibernateMode)
                        pageCompressedSize = (pageCompressedSize + AES_BLOCK_SIZE - 1) & ~(AES_BLOCK_SIZE - 1);
    
                    if (pageCompressedSize > page_size)
                    {
//                      HIBLOG("------------lose: %d\n", pageCompressedSize);
                        pageCompressedSize = page_size;
                    }
    
                    if (pageCompressedSize != page_size)
                        data = (src + page_size);
                    else
                        data = src;
    
                    tag = pageCompressedSize | kIOHibernateTagSignature;
                    err = IOPolledFileWrite(vars->fileVars, (const uint8_t *) &tag, sizeof(tag), cryptvars);
                    if (kIOReturnSuccess != err)
                        break;
    
                    err = IOPolledFileWrite(vars->fileVars, data, (pageCompressedSize + 3) & ~3, cryptvars);
                    if (kIOReturnSuccess != err)
                        break;
    
                    compressedSize += pageCompressedSize;
                    if (pageCompressedSize)
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

            if ((kEncrypt & pageType))
            {
                vars->fileVars->encryptEnd = ((vars->fileVars->position + 511) & ~511ULL);
                HIBLOG("encryptEnd %qx\n", vars->fileVars->encryptEnd);
            }

            if (kWiredEncrypt != pageType)
            {
                // end of image1/2 - fill to next block
                err = IOPolledFileWrite(vars->fileVars, 0, 0, cryptvars);
                if (kIOReturnSuccess != err)
                    break;
            }
            if (kWiredClear == pageType)
            {
		// enlarge wired image for test
//              err = IOPolledFileWrite(vars->fileVars, 0, 0x60000000, cryptvars);

                // end wired image
                header->encryptStart = vars->fileVars->encryptStart;
                header->encryptEnd   = vars->fileVars->encryptEnd;
                image1Size = vars->fileVars->position;
                HIBLOG("image1Size 0x%qx, encryptStart1 0x%qx, End1 0x%qx\n",
                        image1Size, header->encryptStart, header->encryptEnd);
            }
        }
        if (kIOReturnSuccess != err)
            break;

        // Header:
    
        header->imageSize    = vars->fileVars->position;
        header->image1Size   = image1Size;
        header->bitmapSize   = bitmap_size;
        header->pageCount    = pageCount;
    
        header->restore1Sum  = restore1Sum;
        header->image1Sum    = sum1;
        header->image2Sum    = sum2;
    
        count = vars->fileExtents->getLength();
        if (count > sizeof(header->fileExtentMap))
        {
            header->fileExtentMapSize = count;
            count = sizeof(header->fileExtentMap);
        }
        else
            header->fileExtentMapSize = sizeof(header->fileExtentMap);
        bcopy(&fileExtents[0], &header->fileExtentMap[0], count);

        header->deviceBase = vars->fileVars->block0;
    
        IOPolledFileSeek(vars->fileVars, 0);
        err = IOPolledFileWrite(vars->fileVars,
                                    (uint8_t *) header, sizeof(IOHibernateImageHeader), 
                                    cryptvars);
        if (kIOReturnSuccess != err)
            break;
        err = IOPolledFileWrite(vars->fileVars, 0, 0, cryptvars);
        if (kIOReturnSuccess != err)
            break;
        err = IOHibernatePollerIODone(vars->fileVars, true);
        if (kIOReturnSuccess != err)
            break;
    }
    while (false);
    
    clock_get_uptime(&endTime);

    IOService::getPMRootDomain()->pmStatsRecordEvent( 
                        kIOPMStatsHibernateImageWrite | kIOPMStatsEventStopFlag, endTime);

    SUB_ABSOLUTETIME(&endTime, &allTime);
    absolutetime_to_nanoseconds(endTime, &nsec);
    HIBLOG("all time: %qd ms, ", 
		nsec / 1000000ULL);

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

    HIBLOG("\nimage %qd, uncompressed %qd (%d), compressed %qd (%d%%), sum1 %x, sum2 %x\n", 
               header->imageSize,
               uncompressedSize, atop_32(uncompressedSize), compressedSize,
               uncompressedSize ? ((int) ((compressedSize * 100ULL) / uncompressedSize)) : 0,
               sum1, sum2);

    HIBLOG("wired_pages_encrypted %d, wired_pages_clear %d, dirty_pages_encrypted %d\n", 
             wired_pages_encrypted, wired_pages_clear, dirty_pages_encrypted);

    if (vars->fileVars->io)
        (void) IOHibernatePollerIODone(vars->fileVars, false);

    if (pollerOpen)
        IOHibernatePollerClose(vars->fileVars, kIOPolledBeforeSleepState);

    if (vars->consoleMapping)
        ProgressUpdate(gIOHibernateGraphicsInfo, 
                        vars->consoleMapping, 0, kIOHibernateProgressCount);

    HIBLOG("hibernate_write_image done(%x)\n", err);

    // should we come back via regular wake, set the state in memory.
    gIOHibernateState = kIOHibernateStateInactive;

    KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 1) | DBG_FUNC_END,
			  wired_pages_encrypted, wired_pages_clear, dirty_pages_encrypted, 0, 0);

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
    uint64_t     compBytes;
    uint64_t     nsec;
    uint32_t     lastProgressStamp = 0;
    uint32_t     progressStamp;
    uint64_t	 progressZeroPosition = 0;
    uint32_t	 blob, lastBlob = (uint32_t) -1L;
    hibernate_cryptvars_t * cryptvars = 0;

    IOHibernateVars * vars  = &gIOHibernateVars;

    if (!vars->fileVars || !vars->fileVars->pollers || !vars->fileExtents)
	return;

    sum = gIOHibernateCurrentHeader->actualImage1Sum;
    pagesDone = gIOHibernateCurrentHeader->actualUncompressedPages;

    HIBLOG("hibernate_machine_init: state %d, image pages %d, sum was %x, image1Size %qx, conflictCount %d, nextFree %x\n",
	    gIOHibernateState, pagesDone, sum, gIOHibernateCurrentHeader->image1Size,
	    gIOHibernateCurrentHeader->conflictCount, gIOHibernateCurrentHeader->nextFree);

    if (kIOHibernateStateWakingFromHibernate != gIOHibernateState)
    {
	HIBLOG("regular wake\n");
	return;
    }

    HIBPRINT("diag %x %x %x %x\n",
	    gIOHibernateCurrentHeader->diag[0], gIOHibernateCurrentHeader->diag[1], 
	    gIOHibernateCurrentHeader->diag[2], gIOHibernateCurrentHeader->diag[3]);

    HIBPRINT("video %x %d %d %d status %x\n",
	    gIOHibernateGraphicsInfo->physicalAddress, gIOHibernateGraphicsInfo->depth, 
	    gIOHibernateGraphicsInfo->width, gIOHibernateGraphicsInfo->height, gIOHibernateGraphicsInfo->gfxStatus); 

    if ((kIOHibernateModeDiscardCleanActive | kIOHibernateModeDiscardCleanInactive) & gIOHibernateMode)
        hibernate_page_list_discard(vars->page_list);

    boot_args *args = (boot_args *) PE_state.bootArgs;

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
		bcopy(data, gIOHibernateGraphicsInfo, sizeof(*gIOHibernateGraphicsInfo));
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
		hibernate_newruntime_map(data, handoff->bytecount, 
					 gIOHibernateCurrentHeader->systemTableOffset);
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

    if (vars->videoMapping 
	&& gIOHibernateGraphicsInfo->physicalAddress
	&& (args->Video.v_baseAddr == gIOHibernateGraphicsInfo->physicalAddress))
    {
        vars->videoMapSize = round_page(gIOHibernateGraphicsInfo->height 
                                        * gIOHibernateGraphicsInfo->rowBytes);
        IOMapPages(kernel_map, 
                    vars->videoMapping, gIOHibernateGraphicsInfo->physicalAddress,
                    vars->videoMapSize, kIOMapInhibitCache );
    }

    uint8_t * src = (uint8_t *) vars->srcBuffer->getBytesNoCopy();
    uint32_t decoOffset;

    clock_get_uptime(&allTime);
    AbsoluteTime_to_scalar(&compTime) = 0;
    compBytes = 0;

    HIBLOG("IOHibernatePollerOpen(), ml_get_interrupts_enabled %d\n", ml_get_interrupts_enabled());
    err = IOHibernatePollerOpen(vars->fileVars, kIOPolledAfterSleepState, 0);
    HIBLOG("IOHibernatePollerOpen(%x)\n", err);

    if (gIOHibernateCurrentHeader->previewSize)
        progressZeroPosition = gIOHibernateCurrentHeader->previewSize 
                             + gIOHibernateCurrentHeader->fileExtentMapSize 
                             - sizeof(gIOHibernateCurrentHeader->fileExtentMap) 
                             + ptoa_64(gIOHibernateCurrentHeader->restore1PageCount);

    IOPolledFileSeek(vars->fileVars, gIOHibernateCurrentHeader->image1Size);

    if (vars->videoMapSize)
    {
        lastBlob = ((vars->fileVars->position - progressZeroPosition) * kIOHibernateProgressCount)
                        / (gIOHibernateCurrentHeader->imageSize - progressZeroPosition);
        ProgressUpdate(gIOHibernateGraphicsInfo, (uint8_t *) vars->videoMapping, 0, lastBlob);
    }

    // kick off the read ahead
    vars->fileVars->io	         = false;
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

	    if (!compressedSize)
	    {
		ppnum++;
		pagesDone++;
		continue;
	    }

	    err = IOPolledFileRead(vars->fileVars, src, (compressedSize + 3) & ~3, cryptvars);
   	    if (kIOReturnSuccess != err)
		break;

	    if (compressedSize < page_size)
	    {
		decoOffset = page_size;

                clock_get_uptime(&startTime);
		WKdm_decompress((WK_word*) src, (WK_word*) (src + decoOffset), PAGE_SIZE_IN_WORDS);
                clock_get_uptime(&endTime);
                ADD_ABSOLUTETIME(&compTime, &endTime);
                SUB_ABSOLUTETIME(&compTime, &startTime);

                compBytes += page_size;
	    }
	    else
		decoOffset = 0;

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

            if (vars->videoMapSize && (0 == (1023 & pagesDone)))
            {
                blob = ((vars->fileVars->position - progressZeroPosition) * kIOHibernateProgressCount)
                        / (gIOHibernateCurrentHeader->imageSize - progressZeroPosition);
                if (blob != lastBlob)
                {
                    ProgressUpdate(gIOHibernateGraphicsInfo, (uint8_t *) vars->videoMapping, lastBlob, blob);
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

    if (vars->fileVars->io)
        (void) IOHibernatePollerIODone(vars->fileVars, false);

    err = IOHibernatePollerClose(vars->fileVars, kIOPolledAfterSleepState);

    if (vars->videoMapSize)
        ProgressUpdate(gIOHibernateGraphicsInfo, 
                        (uint8_t *) vars->videoMapping, 0, kIOHibernateProgressCount);

    clock_get_uptime(&endTime);

    IOService::getPMRootDomain()->pmStatsRecordEvent( 
                        kIOPMStatsHibernateImageRead | kIOPMStatsEventStartFlag, allTime);
    IOService::getPMRootDomain()->pmStatsRecordEvent( 
                        kIOPMStatsHibernateImageRead | kIOPMStatsEventStopFlag, endTime);

    SUB_ABSOLUTETIME(&endTime, &allTime);
    absolutetime_to_nanoseconds(endTime, &nsec);

    HIBLOG("hibernate_machine_init pagesDone %d sum2 %x, time: %qd ms, ", 
		pagesDone, sum, nsec / 1000000ULL);

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
