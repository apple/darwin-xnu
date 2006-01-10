/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
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
#include <crypto/aes.h>

#include <sys/uio.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/fcntl.h>                       // (FWRITE, ...)
extern "C" {
#include <sys/sysctl.h>
}

#include <IOKit/IOHibernatePrivate.h>
#include <IOKit/IOPolledInterface.h>
#include <IOKit/IONVRAM.h>
#include "IOHibernateInternal.h"
#include "WKdm.h"
#include "IOKitKernelInternal.h"

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSDefineMetaClassAndAbstractStructors(IOPolledInterface, OSObject);

OSMetaClassDefineReservedUnused(IOPolledInterface, 0);
OSMetaClassDefineReservedUnused(IOPolledInterface, 1);
OSMetaClassDefineReservedUnused(IOPolledInterface, 2);
OSMetaClassDefineReservedUnused(IOPolledInterface, 3);
OSMetaClassDefineReservedUnused(IOPolledInterface, 4);
OSMetaClassDefineReservedUnused(IOPolledInterface, 5);
OSMetaClassDefineReservedUnused(IOPolledInterface, 6);
OSMetaClassDefineReservedUnused(IOPolledInterface, 7);
OSMetaClassDefineReservedUnused(IOPolledInterface, 8);
OSMetaClassDefineReservedUnused(IOPolledInterface, 9);
OSMetaClassDefineReservedUnused(IOPolledInterface, 10);
OSMetaClassDefineReservedUnused(IOPolledInterface, 11);
OSMetaClassDefineReservedUnused(IOPolledInterface, 12);
OSMetaClassDefineReservedUnused(IOPolledInterface, 13);
OSMetaClassDefineReservedUnused(IOPolledInterface, 14);
OSMetaClassDefineReservedUnused(IOPolledInterface, 15);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

extern uint32_t 		gIOHibernateState;
uint32_t			gIOHibernateMode;
static char			gIOHibernateBootSignature[256+1];
static char			gIOHibernateFilename[MAXPATHLEN+1];
static uint32_t			gIOHibernateFreeRatio = 0;		// free page target (percent)
uint32_t			gIOHibernateFreeTime  = 0*1000;	// max time to spend freeing pages (ms)

static IODTNVRAM *		gIOOptionsEntry;
static IORegistryEntry *	gIOChosenEntry;

static IOPolledFileIOVars	          gFileVars;
static IOHibernateVars			  gIOHibernateVars;
static struct kern_direct_file_io_ref_t * gIOHibernateFileRef;
static hibernate_cryptvars_t 		  gIOHibernateCryptWakeContext;

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

        dstAddr64 = md->getPhysicalSegment64(offset, &dstLen);
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

        srcAddr64 = md->getPhysicalSegment64(offset, &dstLen);
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
hibernate_page_list_iterate(hibernate_page_list_t * list, 
				void ** iterator, vm_offset_t * ppnum)
{
    uint32_t count, idx;

    idx = (uint32_t) *iterator;

    if (!idx)
	idx = hibernate_page_list_count(list, TRUE, idx);

    *ppnum = idx;
    count  = hibernate_page_list_count(list, FALSE, idx);
    idx   += count;
    idx   += hibernate_page_list_count(list, TRUE, idx);
    *iterator  = (void *) idx;

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
IOHibernatePollerIODone(IOPolledFileIOVars * vars)
{
    IOReturn            err = kIOReturnError;
    int32_t		idx;
    IOPolledInterface * poller;

    while (-1 == vars->ioStatus)
    {
        for (idx = 0;
             (poller = (IOPolledInterface *) vars->pollers->getObject(idx));
             idx++)
        {
            err = poller->checkForWork();
            if (err)
                HIBLOG("IOPolledInterface::checkForWork[%d] 0x%x\n", idx, err);
        }
    }

    if (kIOReturnSuccess != vars->ioStatus)
        HIBLOG("IOPolledInterface::ioStatus 0x%x\n", vars->ioStatus);

    return (vars->ioStatus);
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

IOReturn
IOPolledFileOpen( const char * filename, IOBufferMemoryDescriptor * ioBuffer,
			    IOPolledFileIOVars ** fileVars, OSData ** fileExtents,
			    OSData ** imagePath)
{
    IOReturn			err = kIOReturnError;
    IOPolledFileIOVars *	vars;
    _OpenFileContext		ctx;
    OSData *			extentsData;
    OSNumber *			num;
    IORegistryEntry *		part = 0;
    OSDictionary *		matching;
    OSIterator *		iter;
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
						    &hibernate_image_dev,
                                                    &vars->block0,
                                                    &maxiobytes);
	if (!vars->fileRef)
	{
	    err = kIOReturnNoSpace;
	    break;
	}
	HIBLOG("Opened file %s, size %qd, partition base 0x%qx, maxio %qx\n", filename, ctx.size, 
                    vars->block0, maxiobytes);
	if (ctx.size < 1*1024*1024)		// check against image size estimate!
	{
	    err = kIOReturnNoSpace;
	    break;
	}

        if (maxiobytes < vars->bufferSize)
            vars->bufferSize = maxiobytes;
    
	vars->extentMap = (IOPolledFileExtent *) extentsData->getBytesNoCopy();
    
	matching = IOService::serviceMatching("IOMedia");
	num = OSNumber::withNumber(major(hibernate_image_dev), 32);
	matching->setObject(kIOBSDMajorKey, num);
	num->release();
	num = OSNumber::withNumber(minor(hibernate_image_dev), 32);
	matching->setObject(kIOBSDMinorKey, num);
	num->release();
	iter = IOService::getMatchingServices(matching);
	matching->release();
	if (iter)
	{
	    part = (IORegistryEntry *) iter->getNextObject();
	    part->retain();
	    iter->release();
	}
    
	int minor, major;
	IORegistryEntry * next;
	IORegistryEntry * child;
	OSData * data;

	num = (OSNumber *) part->getProperty(kIOBSDMajorKey);
	if (!num)
	    break;
	major = num->unsigned32BitValue();
	num = (OSNumber *) part->getProperty(kIOBSDMinorKey);
	if (!num)
	    break;
	minor = num->unsigned32BitValue();

	hibernate_image_dev = makedev(major, minor);

        vars->pollers = OSArray::withCapacity(4);
	if (!vars->pollers)
	    break;

	vars->blockSize = 512;
	next = part;
	do
	{
            IOPolledInterface * poller;
            if ((poller = OSDynamicCast(IOPolledInterface, next->getProperty(kIOPolledInterfaceSupportKey))))
                vars->pollers->setObject(poller);
	    if ((num = OSDynamicCast(OSNumber, next->getProperty(kIOMediaPreferredBlockSizeKey))))
		vars->blockSize = num->unsigned32BitValue();
            child = next;
	}
	while ((next = child->getParentEntry(gIOServicePlane)) 
                && child->isParent(next, gIOServicePlane, true));

	HIBLOG("hibernate image major %d, minor %d, blocksize %ld, pollers %d\n",
		    major, minor, vars->blockSize, vars->pollers->getCount());
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
	char str1[256];
	char str2[24];
	int len = sizeof(str1);

	if ((extentsData->getLength() >= sizeof(IOPolledFileExtent))
	    && part->getPath(str1, &len, gIODTPlane))
	{
	    // (strip the plane name)
	    char * tail = strchr(str1, ':');
	    if (!tail)
		tail = str1 - 1;
	    data = OSData::withBytes(tail + 1, strlen(tail + 1));
	    sprintf(str2, ",%qx", vars->extentMap[0]);
	    data->appendBytes(str2, strlen(str2));
	    *imagePath = data;
	}
    }
    while (false);

    if (kIOReturnSuccess != err)
    {
        HIBLOG("error 0x%x opening hibernation file\n", err);
	if (vars->fileRef)
	    kern_close_file_for_direct_io(vars->fileRef);
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

    gIOHibernateFileRef = vars->fileRef;

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

            if (cryptvars && vars->encryptStart && (vars->position > vars->encryptStart))
            {
                uint32_t encryptLen, encryptStart;
                encryptLen = vars->position - vars->encryptStart;
                if (encryptLen > length)
                    encryptLen = length;
                encryptStart = length - encryptLen;
                
                // encrypt the buffer
                aes_encrypt_cbc(vars->buffer + vars->bufferHalf + encryptStart,
                                &cryptvars->aes_iv[0],
                                encryptLen / AES_BLOCK_SIZE,
                                vars->buffer + vars->bufferHalf + encryptStart,
                                &cryptvars->ctx.encrypt);
                // save initial vector for following encrypts
                bcopy(vars->buffer + vars->bufferHalf + encryptStart + encryptLen - AES_BLOCK_SIZE,
                        &cryptvars->aes_iv[0],
                        AES_BLOCK_SIZE);
            }

	    if (vars->io)
            {
		err = IOHibernatePollerIODone(vars);
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

	if (vars->bufferOffset == vars->bufferLimit)
	{
	    if (vars->io)
            {
		err = IOHibernatePollerIODone(vars);
                if (kIOReturnSuccess != err)
                    break;
            }
            else
                cryptvars = 0;

if (vars->position & (vars->blockSize - 1)) HIBLOG("misaligned file pos %qx\n", vars->position);

	    vars->position += vars->lastRead;
	    vars->extentRemaining -= vars->lastRead;
	    vars->bufferLimit = vars->lastRead;

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

	    if (vars->extentRemaining <= vars->bufferSize)
		vars->lastRead = vars->extentRemaining;
	    else
		vars->lastRead = vars->bufferSize;

	    uint64_t offset = (vars->position 
				- vars->extentPosition + vars->currentExtent->start);
	    uint64_t length = (vars->lastRead);

//if (length != vars->bufferSize) HIBLOG("short read of %qx ends@ %qx\n", length, offset + length);

	    err = IOHibernatePollerIO(vars, kIOPolledRead, vars->bufferHalf, offset, length);
            if (kIOReturnSuccess != err)
                break;
	    vars->io = true;

	    vars->bufferHalf = vars->bufferHalf ? 0 : vars->bufferSize;
	    vars->bufferOffset = 0;

            if (cryptvars)
            {
                uint8_t thisVector[AES_BLOCK_SIZE];
                // save initial vector for following decrypts
                bcopy(&cryptvars->aes_iv[0], &thisVector[0], AES_BLOCK_SIZE);
                bcopy(vars->buffer + vars->bufferHalf + vars->lastRead - AES_BLOCK_SIZE, 
                        &cryptvars->aes_iv[0], AES_BLOCK_SIZE);
                // decrypt the buffer
                aes_decrypt_cbc(vars->buffer + vars->bufferHalf,
                                &thisVector[0],
                                vars->lastRead / AES_BLOCK_SIZE,
                                vars->buffer + vars->bufferHalf,
                                &cryptvars->ctx.decrypt);
            }
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
    OSNumber * num;

    IOHibernateVars * vars  = &gIOHibernateVars;

    if (vars->fileVars && vars->fileVars->fileRef)
	// already on the way down
	return (kIOReturnSuccess);

    gIOHibernateState = kIOHibernateStateInactive;

    if ((obj = IOService::getPMRootDomain()->copyProperty(kIOHibernateModeKey)))
    {
	if ((num = OSDynamicCast(OSNumber, obj)))
	    gIOHibernateMode = num->unsigned32BitValue();
        if (kIOHibernateModeSleep & gIOHibernateMode)
            // default to discard clean for safe sleep
            gIOHibernateMode ^= (kIOHibernateModeDiscardCleanInactive 
                                | kIOHibernateModeDiscardCleanActive);

	obj->release();
    }
    if ((obj = IOService::getPMRootDomain()->copyProperty(kIOHibernateFreeRatioKey)))
    {
	if ((num = OSDynamicCast(OSNumber, obj)))
	    gIOHibernateFreeRatio = num->unsigned32BitValue();
	obj->release();
    }
    if ((obj = IOService::getPMRootDomain()->copyProperty(kIOHibernateFreeTimeKey)))
    {
	if ((num = OSDynamicCast(OSNumber, obj)))
	    gIOHibernateFreeTime = num->unsigned32BitValue();
	obj->release();
    }
    if ((obj = IOService::getPMRootDomain()->copyProperty(kIOHibernateFileKey)))
    {
	if ((str = OSDynamicCast(OSString, obj)))
	    strcpy(gIOHibernateFilename, str->getCStringNoCopy());
	obj->release();
    }

    if (!gIOHibernateMode || !gIOHibernateFilename[0])
	return (kIOReturnUnsupported);

    HIBLOG("hibernate image path: %s\n", gIOHibernateFilename);

    do
    {
        vars->srcBuffer = IOBufferMemoryDescriptor::withOptions(0, 4 * page_size, page_size);
        vars->ioBuffer  = IOBufferMemoryDescriptor::withOptions(0, 2 * kDefaultIOSize, page_size);

        if (!vars->srcBuffer || !vars->ioBuffer)
        {
            err = kIOReturnNoMemory;
            break;
        }

        err = IOPolledFileOpen(gIOHibernateFilename, vars->ioBuffer,
                                &vars->fileVars, &vars->fileExtents, &data);
        if (KERN_SUCCESS != err)
        {
	    HIBLOG("IOPolledFileOpen(%x)\n", err);
            break;
        }
	if (vars->fileVars->fileRef)
	{
	    // invalidate the image file
	    gIOHibernateCurrentHeader->signature = kIOHibernateHeaderInvalidSignature;
	    int err = kern_write_file(vars->fileVars->fileRef, 0,
					(caddr_t) gIOHibernateCurrentHeader, sizeof(IOHibernateImageHeader));
            if (KERN_SUCCESS != err)
                HIBLOG("kern_write_file(%d)\n", err);
	}

	bzero(gIOHibernateCurrentHeader, sizeof(IOHibernateImageHeader));

        boolean_t encryptedswap;
        err = hibernate_setup(gIOHibernateCurrentHeader, 
                                gIOHibernateFreeRatio, gIOHibernateFreeTime,
                                &vars->page_list, &vars->page_list_wired, &encryptedswap);
        if (KERN_SUCCESS != err)
        {
	    HIBLOG("hibernate_setup(%d)\n", err);
            break;
        }

        if (encryptedswap)
            gIOHibernateMode ^= kIOHibernateModeEncrypt; 

        vars->videoAllocSize = kVideoMapSize;
        if (KERN_SUCCESS != kmem_alloc_pageable(kernel_map, &vars->videoMapping, vars->videoAllocSize))
            vars->videoMapping = 0;

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
            size_t	      len;
            char              valueString[16];

            sym = OSSymbol::withCStringNoCopy(kIOHibernateBootImageKey);
            if (sym)
            {
                gIOOptionsEntry->setProperty(sym, data);
                sym->release();
            }
            data->release();

	    vars->saveBootDevice = gIOOptionsEntry->copyProperty(kIOSelectedBootDeviceKey);
            if (gIOChosenEntry)
            {
		OSData * bootDevice = OSDynamicCast(OSData, gIOChosenEntry->getProperty(kIOBootPathKey));
		if (bootDevice)
		{
		    sym = OSSymbol::withCStringNoCopy(kIOSelectedBootDeviceKey);
		    OSString * str2 = OSString::withCStringNoCopy((const char *) bootDevice->getBytesNoCopy());
		    if (sym && str2)
			gIOOptionsEntry->setProperty(sym, str2);
		    if (sym)
			sym->release();
		    if (str2)
			str2->release();
		}

                data = OSDynamicCast(OSData, gIOChosenEntry->getProperty(kIOHibernateMemorySignatureKey));
                if (data)
                {
                    vars->haveFastBoot = true;

                    len = sprintf(valueString, "0x%lx", *((UInt32 *)data->getBytesNoCopy()));
                    data = OSData::withBytes(valueString, len + 1);
                    sym = OSSymbol::withCStringNoCopy(kIOHibernateMemorySignatureEnvKey);
                    if (sym && data)
                        gIOOptionsEntry->setProperty(sym, data);
                    if (sym)
                        sym->release();
                    if (data)
                        data->release();
                }
                data = OSDynamicCast(OSData, gIOChosenEntry->getProperty(kIOHibernateMachineSignatureKey));
                if (data)
                    gIOHibernateCurrentHeader->machineSignature = *((UInt32 *)data->getBytesNoCopy());
            }

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
                if (gIOHibernateBootSignature[0])
                {
                    data = OSData::withCapacity(16);
                    sym = OSSymbol::withCStringNoCopy(kIOHibernateBootSignatureKey);
                    if (sym && data)
                    {
                        char c;
                        uint8_t value;
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
	}
	// --

	gIOHibernateCurrentHeader->signature = kIOHibernateHeaderSignature;
	gIOHibernateState = kIOHibernateStateHibernating;
    }
    while (false);

    return (err);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn
IOHibernateSystemHasSlept(void)
{
    IOHibernateVars * vars  = &gIOHibernateVars;

    if ((vars->previewData = OSDynamicCast(OSData, 
            IOService::getPMRootDomain()->getProperty(kIOHibernatePreviewBufferKey))))
    {
        vars->previewBuffer = IOMemoryDescriptor::withAddress(
                                    (void *) vars->previewData->getBytesNoCopy(), 
                                    vars->previewData->getLength(), 
                                    kIODirectionInOut);

        if (vars->previewBuffer && (kIOReturnSuccess != vars->previewBuffer->prepare()))
        {
            vars->previewBuffer->release();
            vars->previewBuffer = 0;
        }
        if (!vars->previewBuffer)
            vars->previewData = 0;
    }
    if (gIOOptionsEntry)
        gIOOptionsEntry->sync();

    return (kIOReturnSuccess);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

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
            kmem_free(kernel_map, trunc_page_32(vars->videoMapping), vars->videoAllocSize);
    }

    if (vars->previewBuffer)
    {
        vars->previewBuffer->release();
        vars->previewBuffer = 0;
    }

    if (vars->fileVars)
    {
	IOPolledFileClose(vars->fileVars);
    }

    // invalidate nvram properties - (gIOOptionsEntry != 0) => nvram was touched

    OSData * data = OSData::withCapacity(4);
    if (gIOOptionsEntry && data)
    {
        const OSSymbol * sym = OSSymbol::withCStringNoCopy(kIOHibernateBootImageKey);
        if (sym)
        {
            gIOOptionsEntry->setProperty(sym, data);
            sym->release();
        }
        sym = OSSymbol::withCStringNoCopy(kIOSelectedBootDeviceKey);
        if (sym)
        {
	    if (vars->saveBootDevice)
	    {
		gIOOptionsEntry->setProperty(sym, vars->saveBootDevice);
		vars->saveBootDevice->release();
	    }
            sym->release();
        }
        sym = OSSymbol::withCStringNoCopy(kIOHibernateBootImageKeyKey);
        if (sym)
        {
            gIOOptionsEntry->setProperty(sym, data);
            sym->release();
        }
        sym = OSSymbol::withCStringNoCopy(kIOHibernateMemorySignatureEnvKey);
        if (sym)
        {
            gIOOptionsEntry->removeProperty(sym);
            sym->release();
        }
    }
    if (data)
        data->release();

    if (gIOOptionsEntry)
    {
	if (!vars->haveFastBoot)
	{
	    // reset boot audio volume
	    IODTPlatformExpert * platform = OSDynamicCast(IODTPlatformExpert, IOService::getPlatform());
	    if (platform)
		platform->writeXPRAM(kXPRamAudioVolume, 
					&vars->saveBootAudioVolume, sizeof(vars->saveBootAudioVolume));
	}

	// sync now to hardware if the booter has not
	if (kIOHibernateStateInactive == gIOHibernateState)
	    gIOOptionsEntry->sync();
	else
	    // just sync the variables in case a later panic syncs nvram (it won't sync variables)
	    gIOOptionsEntry->syncOFVariables();
    }

    if (vars->srcBuffer)
	vars->srcBuffer->release();
    if (vars->ioBuffer)
	vars->ioBuffer->release();
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
	kern_close_file_for_direct_io(gIOHibernateFileRef);
        gIOHibernateFileRef = 0;
    }
    return (kIOReturnSuccess);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void
IOHibernateSystemInit(IOPMrootDomain * rootDomain)
{
    OSData * data = OSData::withBytesNoCopy(&gIOHibernateState, sizeof(gIOHibernateState));
    if (data)
    {
	rootDomain->setProperty(kIOHibernateStateKey, data);
	data->release();
    }

    if (PE_parse_boot_arg("hfile", gIOHibernateFilename))
	gIOHibernateMode = kIOHibernateModeOn;
    else
	gIOHibernateFilename[0] = 0;

    static SYSCTL_STRING(_kern, OID_AUTO, hibernatefile, 
				CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN, 
				gIOHibernateFilename, sizeof(gIOHibernateFilename), "");
    sysctl_register_oid(&sysctl__kern_hibernatefile);

    static SYSCTL_STRING(_kern, OID_AUTO, bootsignature, 
				CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN, 
				gIOHibernateBootSignature, sizeof(gIOHibernateBootSignature), "");
    sysctl_register_oid(&sysctl__kern_bootsignature);

    static SYSCTL_UINT(_kern, OID_AUTO, hibernatemode, 
				CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN, 
				&gIOHibernateMode, 0, "");
    sysctl_register_oid(&sysctl__kern_hibernatemode);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static void
hibernate_setup_for_wake(void)
{
#if __ppc__
    // go slow (state needed for wake)
    ml_set_processor_speed(1);
#endif
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

extern "C" boolean_t
hibernate_write_image(void)
{
    IOHibernateImageHeader * header = gIOHibernateCurrentHeader;
    IOHibernateVars *        vars  = &gIOHibernateVars;
    IOPolledFileExtent *     fileExtents;

    uint32_t	 pageCount, pagesDone;
    IOReturn     err;
    vm_offset_t  ppnum;
    IOItemCount  page, count;
    uint8_t *	 src;
    uint8_t *	 data;
    IOByteCount  pageCompressedSize;
    uint64_t	 compressedSize, uncompressedSize;
    uint64_t	 image1Size = 0;
    uint32_t	 bitmap_size;
    bool	 iterDone, pollerOpen, needEncryptStart;
    uint32_t	 restore1Sum, sum, sum1, sum2;
    uint32_t	 tag;
    uint32_t	 pageType;
    uint32_t	 pageAndCount[2];

    AbsoluteTime startTime, endTime;
    AbsoluteTime allTime, compTime, decoTime;
    uint64_t     nsec;
    uint32_t     lastProgressStamp = 0;
    uint32_t     progressStamp;

    hibernate_cryptvars_t _cryptvars;
    hibernate_cryptvars_t * cryptvars = 0;

    if (!vars->fileVars || !vars->fileVars->pollers || !vars->fileExtents)
        return (false /* sleep */ );

    restore1Sum = sum1 = sum2 = 0;

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
        aes_encrypt_key(vars->wiredCryptKey,
                        kIOHibernateAESKeySize,
                        &cryptvars->ctx.encrypt);

        bcopy(&first_iv[0], &cryptvars->aes_iv[0], AES_BLOCK_SIZE);
        bzero(&vars->wiredCryptKey[0], sizeof(vars->wiredCryptKey));
        bzero(&vars->cryptKey[0], sizeof(vars->cryptKey));
        bzero(gIOHibernateCryptWakeVars, sizeof(hibernate_cryptwakevars_t));
    }

    hibernate_setup_for_wake();

    hibernate_page_list_setall(vars->page_list,
                               vars->page_list_wired,
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

    needEncryptStart = (0 != (kIOHibernateModeEncrypt & gIOHibernateMode));

    AbsoluteTime_to_scalar(&compTime) = 0;
    AbsoluteTime_to_scalar(&decoTime) = 0;

    clock_get_uptime(&allTime);

    do 
    {
        compressedSize   = 0;
        uncompressedSize = 0;
        iterDone         = false;
        pageType         = 0;		// wired pages first

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

        // copy out restore1 code
    
        page = atop_32(sectHIBB);
        count = atop_32(round_page(sectHIBB + sectSizeHIB)) - page;
        header->restore1CodePage = page;
        header->restore1PageCount = count;
        header->restore1CodeOffset = ((uint32_t) &hibernate_machine_entrypoint)      - sectHIBB;
        header->restore1StackOffset = ((uint32_t) &gIOHibernateRestoreStackEnd[0]) - 64 - sectHIBB;

        // sum __HIB sect, with zeros for the stack
        src = (uint8_t *) trunc_page(sectHIBB);
        for (page = 0; page < count; page++)
        {
            if ((src < &gIOHibernateRestoreStack[0]) || (src >= &gIOHibernateRestoreStackEnd[0]))
                restore1Sum += hibernate_sum(src, page_size);
            else
                restore1Sum += 0x10000001;
            src += page_size;
        }
        sum1 = restore1Sum;
    
        // write the __HIB sect, with zeros for the stack

        src = (uint8_t *) trunc_page(sectHIBB);
        count = ((uint32_t) &gIOHibernateRestoreStack[0]) - trunc_page(sectHIBB);
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
        count = round_page(sectHIBB + sectSizeHIB) - ((uint32_t) src);
        if (count)
        {
            err = IOPolledFileWrite(vars->fileVars, src, count, cryptvars);
            if (kIOReturnSuccess != err)
                break;
        }

        // write the preview buffer

        addr64_t phys64;
        IOByteCount segLen;

        if (vars->previewData)
        {
            ppnum = 0;
            count = 0;
            do
            {
                phys64 = vars->previewBuffer->getPhysicalSegment64(count, &segLen);
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

            src = (uint8_t *) vars->previewData->getBytesNoCopy();
            count = vars->previewData->getLength();

            header->previewPageListSize = ppnum;
            header->previewSize = count + ppnum;

            for (page = 0; page < count; page += page_size)
                sum1 += hibernate_sum(src + page, page_size);

            err = IOPolledFileWrite(vars->fileVars, src, count, cryptvars);
            if (kIOReturnSuccess != err)
                break;
        }

        // mark areas for no save
    
        for (count = 0;
            (phys64 = vars->ioBuffer->getPhysicalSegment64(count, &segLen));
            count += segLen)
        {
            hibernate_set_page_state(vars->page_list, vars->page_list_wired, 
                                        atop_64(phys64), atop_32(segLen),
                                        kIOHibernatePageStateFree);
            pageCount -= atop_32(segLen);
        }
    
        for (count = 0;
            (phys64 = vars->srcBuffer->getPhysicalSegment64(count, &segLen));
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
    
#if !__i386__
        page = atop_32(sectHIBB);
        count = atop_32(round_page(sectHIBB + sectSizeHIB)) - page;
#else
        // XXX
        page = atop_32(sectHIBB & 0x3FFFFFFF);
        count = atop_32(round_page((sectHIBB + sectSizeHIB) & 0x3FFFFFFF)) - page;
#endif
        hibernate_set_page_state(vars->page_list, vars->page_list_wired,
                                        page, count,
                                        kIOHibernatePageStateFree);
        pageCount -= count;
    


        if (vars->previewBuffer) for (count = 0;
                                        (phys64 = vars->previewBuffer->getPhysicalSegment64(count, &segLen));
                                        count += segLen)
        {
            hibernate_set_page_state(vars->page_list, vars->page_list_wired, 
                                        atop_64(phys64), atop_32(segLen),
                                        kIOHibernatePageStateFree);
            pageCount -= atop_32(segLen);
        }

        src = (uint8_t *) vars->srcBuffer->getBytesNoCopy();
    
        void * iter = 0;
        pagesDone   = 0;
    
        HIBLOG("writing %d pages\n", pageCount);

        do
        {
            count = hibernate_page_list_iterate(pageType ? vars->page_list : vars->page_list_wired,
                                                    &iter, &ppnum);
//          kprintf("[%d](%x : %x)\n", pageType, ppnum, count);
    
            iterDone = !count;

            pageAndCount[0] = ppnum;
            pageAndCount[1] = count;
            err = IOPolledFileWrite(vars->fileVars, 
                                    (const uint8_t *) &pageAndCount, sizeof(pageAndCount), 
                                    cryptvars);
            if (kIOReturnSuccess != err)
                break;

            for (page = 0; page < count; page++)
            {
                err = IOMemoryDescriptorWriteFromPhysical(vars->srcBuffer, 0, ptoa_64(ppnum), page_size);
                if (err)
                {
                    HIBLOG("IOMemoryDescriptorWriteFromPhysical %d [%d] %x\n", __LINE__, ppnum, err);
                    break;
                }
    
                sum = hibernate_sum(src, page_size);
   
                clock_get_uptime(&startTime);

                pageCompressedSize = WKdm_compress ((WK_word*) src, (WK_word*) (src + page_size), PAGE_SIZE_IN_WORDS);
    
                clock_get_uptime(&endTime);
                ADD_ABSOLUTETIME(&compTime, &endTime);
                SUB_ABSOLUTETIME(&compTime, &startTime);
    
                if (kIOHibernateModeEncrypt & gIOHibernateMode)
                    pageCompressedSize = (pageCompressedSize + AES_BLOCK_SIZE - 1) & ~(AES_BLOCK_SIZE - 1);

                if (pageCompressedSize > page_size)
                {
//                  HIBLOG("------------lose: %d\n", pageCompressedSize);
                    pageCompressedSize = page_size;
                }

                if (pageCompressedSize != page_size)
                    data = (src + page_size);
                else
                    data = src;

                tag = pageCompressedSize | kIOHibernateTagSignature;

                if (pageType)
                    sum2 += sum;
                else
                    sum1 += sum;

                if (needEncryptStart && (ppnum >= atop_32(sectDATAB)))
                {
                    // start encrypting partway into the data about to be written
                    vars->fileVars->encryptStart = (vars->fileVars->position + AES_BLOCK_SIZE - 1) 
                                                    & ~(AES_BLOCK_SIZE - 1);
                    needEncryptStart = false;
                }

                err = IOPolledFileWrite(vars->fileVars, (const uint8_t *) &tag, sizeof(tag), cryptvars);
                if (kIOReturnSuccess != err)
                    break;

                err = IOPolledFileWrite(vars->fileVars, data, (pageCompressedSize + 3) & ~3, cryptvars);
                if (kIOReturnSuccess != err)
                    break;

                compressedSize += pageCompressedSize;
                if (pageCompressedSize)
                    uncompressedSize += page_size;
                ppnum++;
                pagesDone++;
    
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
            if (iterDone && !pageType)
            {
                err = IOPolledFileWrite(vars->fileVars, 0, 0, cryptvars);
                if (kIOReturnSuccess != err)
                    break;

                iterDone = false;
                pageType = 1;
                iter = 0;
                image1Size = vars->fileVars->position;
                if (cryptvars)
                {
                    bcopy(&cryptvars->aes_iv[0], 
                            &gIOHibernateCryptWakeContext.aes_iv[0], 
                            sizeof(cryptvars->aes_iv));
                    cryptvars = &gIOHibernateCryptWakeContext;
                }
                HIBLOG("image1Size %qd\n", image1Size);
            }
        }
        while (!iterDone);
        if (kIOReturnSuccess != err)
            break;
        err = IOPolledFileWrite(vars->fileVars, 0, 0, cryptvars);
        if (kIOReturnSuccess != err)
            break;

        // Header:
    
        header->imageSize    = vars->fileVars->position;
        header->image1Size   = image1Size;
        header->bitmapSize   = bitmap_size;
        header->pageCount    = pageCount;
        header->encryptStart = vars->fileVars->encryptStart;
    
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
    
        IOPolledFileSeek(vars->fileVars, 0);
        err = IOPolledFileWrite(vars->fileVars,
                                    (uint8_t *) header, sizeof(IOHibernateImageHeader), 
                                    cryptvars);
        if (kIOReturnSuccess != err)
            break;
        err = IOPolledFileWrite(vars->fileVars, 0, 0, cryptvars);
        if (kIOReturnSuccess != err)
            break;
        err = IOHibernatePollerIODone(vars->fileVars);
        if (kIOReturnSuccess != err)
            break;
    }
    while (false);
    
    clock_get_uptime(&endTime);
    SUB_ABSOLUTETIME(&endTime, &allTime);
    absolutetime_to_nanoseconds(endTime, &nsec);
    HIBLOG("all time: %qd ms, ", 
		nsec / 1000000ULL);

    absolutetime_to_nanoseconds(compTime, &nsec);
    HIBLOG("comp time: %qd ms, ", 
		nsec / 1000000ULL);

    absolutetime_to_nanoseconds(decoTime, &nsec);
    HIBLOG("deco time: %qd ms, ", 
		nsec / 1000000ULL);

    HIBLOG("\nimage %qd, uncompressed %qd (%d), compressed %qd (%d%%), sum1 %x, sum2 %x\n", 
               header->imageSize,
               uncompressedSize, atop_32(uncompressedSize), compressedSize,
               (int) ((compressedSize * 100ULL) / uncompressedSize),
               sum1, sum2);

    if (pollerOpen)
        IOHibernatePollerClose(vars->fileVars, kIOPolledBeforeSleepState);

    HIBLOG("hibernate_write_image done(%x)\n", err);

    // should we come back via regular wake, set the state in memory.
    gIOHibernateState = kIOHibernateStateInactive;

    if ((kIOReturnSuccess == err) && !(kIOHibernateModeSleep & gIOHibernateMode))
        return (true  /* power down */ );
    else
        return (false /* sleep */ );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

DECLARE_IOHIBERNATEPROGRESSALPHA

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

extern "C" void 
hibernate_machine_init(void)
{
    IOReturn     err;
    uint32_t     sum;
    uint32_t     pagesDone;
    AbsoluteTime allTime, endTime;
    uint64_t     nsec;
    uint32_t     lastProgressStamp = 0;
    uint32_t     progressStamp;
    uint64_t	 progressZeroPosition = 0;
    uint32_t	 blob, lastBlob = (uint32_t) -1L;
    hibernate_cryptvars_t * cryptvars = 0;

    IOHibernateVars * vars  = &gIOHibernateVars;

    if (!vars->fileVars || !vars->fileVars->pollers || !vars->fileExtents)
	return;

    if ((kIOHibernateModeDiscardCleanActive | kIOHibernateModeDiscardCleanInactive) & gIOHibernateMode)
        hibernate_page_list_discard(vars->page_list);


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

    HIBPRINT("video %x %d %d %d\n",
	    gIOHibernateGraphicsInfo->physicalAddress, gIOHibernateGraphicsInfo->depth, 
	    gIOHibernateGraphicsInfo->width, gIOHibernateGraphicsInfo->height); 

    if (vars->videoMapping && gIOHibernateGraphicsInfo->physicalAddress)
    {
        vars->videoMapSize = round_page(gIOHibernateGraphicsInfo->height 
                                        * gIOHibernateGraphicsInfo->rowBytes);
        IOMapPages(kernel_map, 
                    vars->videoMapping, gIOHibernateGraphicsInfo->physicalAddress,
                    vars->videoMapSize, kIOMapInhibitCache );
    }

    uint8_t * src = (uint8_t *) vars->srcBuffer->getBytesNoCopy();;
    uint32_t decoOffset;

    clock_get_uptime(&allTime);

    HIBLOG("IOHibernatePollerOpen(), ml_get_interrupts_enabled %d\n", ml_get_interrupts_enabled());
    err = IOHibernatePollerOpen(vars->fileVars, kIOPolledAfterSleepState, 0);
    HIBLOG("IOHibernatePollerOpen(%x)\n", err);

    if (gIOHibernateCurrentHeader->previewSize)
        progressZeroPosition = gIOHibernateCurrentHeader->previewSize 
                             + gIOHibernateCurrentHeader->fileExtentMapSize 
                             - sizeof(gIOHibernateCurrentHeader->fileExtentMap) 
                             + ptoa_64(gIOHibernateCurrentHeader->restore1PageCount);

    IOPolledFileSeek(vars->fileVars, gIOHibernateCurrentHeader->image1Size);

    if (vars->videoMapping)
    {
        lastBlob = ((vars->fileVars->position - progressZeroPosition) * kIOHibernateProgressCount)
                        / (gIOHibernateCurrentHeader->imageSize - progressZeroPosition);
        ProgressUpdate(gIOHibernateGraphicsInfo, (uint8_t *) vars->videoMapping, 0, lastBlob);
    }

    cryptvars = (kIOHibernateModeEncrypt & gIOHibernateMode) ? &gIOHibernateCryptWakeContext : 0;
    if (kIOHibernateModeEncrypt & gIOHibernateMode)
    {
        cryptvars = &gIOHibernateCryptWakeContext;
        bcopy(&gIOHibernateCryptWakeVars->aes_iv[0], 
                &cryptvars->aes_iv[0], 
                sizeof(cryptvars->aes_iv));
    }

    // kick off the read ahead
    vars->fileVars->io	         = false;
    vars->fileVars->bufferHalf   = 0;
    vars->fileVars->bufferLimit  = 0;
    vars->fileVars->lastRead     = 0;
    vars->fileVars->bufferOffset = vars->fileVars->bufferLimit;

    IOPolledFileRead(vars->fileVars, 0, 0, cryptvars);
    vars->fileVars->bufferOffset = vars->fileVars->bufferLimit;
    // --

    HIBLOG("hibernate_machine_init reading\n");

    uint32_t * header = (uint32_t *) src;
    sum = 0;

    do
    {
	unsigned int count;
	unsigned int page;
        uint32_t     tag;
	vm_offset_t  ppnum, compressedSize;

	IOPolledFileRead(vars->fileVars, src, 8, cryptvars);

	ppnum = header[0];
	count = header[1];

//	HIBPRINT("(%x, %x)\n", ppnum, count);

	if (!count)
	    break;

	for (page = 0; page < count; page++)
	{
	    IOPolledFileRead(vars->fileVars, (uint8_t *) &tag, 4, cryptvars);

	    compressedSize = kIOHibernateTagLength & tag;
	    if (!compressedSize)
	    {
		ppnum++;
		pagesDone++;
		continue;
	    }

	    IOPolledFileRead(vars->fileVars, src, (compressedSize + 3) & ~3, cryptvars);
   
	    if (compressedSize != page_size)
	    {
		decoOffset = page_size;
		WKdm_decompress((WK_word*) src, (WK_word*) (src + decoOffset), PAGE_SIZE_IN_WORDS);
	    }
	    else
		decoOffset = 0;

	    sum += hibernate_sum((src + decoOffset), page_size);

	    err = IOMemoryDescriptorReadToPhysical(vars->srcBuffer, decoOffset, ptoa_64(ppnum), page_size);
	    if (err)
		HIBLOG("IOMemoryDescriptorReadToPhysical [%d] %x\n", ppnum, err);

	    ppnum++;
	    pagesDone++;

            if (vars->videoMapping && (0 == (255 & pagesDone)))
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
    while (true);

    gIOHibernateCurrentHeader->actualImage2Sum = sum;

    if (vars->fileVars->io)
        (void) IOHibernatePollerIODone(vars->fileVars);

    err = IOHibernatePollerClose(vars->fileVars, kIOPolledAfterSleepState);

    if (vars->videoMapping)
        ProgressUpdate(gIOHibernateGraphicsInfo, 
                        (uint8_t *) vars->videoMapping, 0, kIOHibernateProgressCount);

    clock_get_uptime(&endTime);
    SUB_ABSOLUTETIME(&endTime, &allTime);
    absolutetime_to_nanoseconds(endTime, &nsec);

    HIBLOG("hibernate_machine_init pagesDone %d sum2 %x, time: %qd ms\n", 
		pagesDone, sum, nsec / 1000000ULL);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
