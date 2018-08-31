/*
 * Copyright (c) 2006-2009 Apple Inc. All rights reserved.
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

#include <sys/uio.h>
#include <sys/conf.h>

#include <IOKit/IOLib.h>
#include <IOKit/IOBSD.h>
#include <IOKit/IOService.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOPolledInterface.h>
#include <IOKit/IOHibernatePrivate.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/AppleKeyStoreInterface.h>
#include "IOKitKernelInternal.h"


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSDefineMetaClassAndAbstractStructors(IOPolledInterface, OSObject);

OSMetaClassDefineReservedUsed(IOPolledInterface, 0);
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

#ifndef kIOMediaPreferredBlockSizeKey
#define kIOMediaPreferredBlockSizeKey	"Preferred Block Size"
#endif

enum { kDefaultIOSize = 128*1024 };

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

class IOPolledFilePollers : public OSObject
{
    OSDeclareDefaultStructors(IOPolledFilePollers)

public:
    IOService                * media;
    OSArray                  * pollers;
    IOBufferMemoryDescriptor * ioBuffer;
    bool                 abortable;
    bool                 io;
    IOReturn		 ioStatus;
    uint32_t             openCount;

    static IOPolledFilePollers * copyPollers(IOService * media);
};

OSDefineMetaClassAndStructors(IOPolledFilePollers, OSObject)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOPolledFilePollers *
IOPolledFilePollers::copyPollers(IOService * media)
{
    IOPolledFilePollers * vars;
    IOReturn              err;
    IOService       * service;
    OSObject        * obj;
    IORegistryEntry * next;
    IORegistryEntry * child;

    if ((obj = media->copyProperty(kIOPolledInterfaceStackKey)))
    {
	return (OSDynamicCast(IOPolledFilePollers, obj));
    }

    do
    {
	vars = OSTypeAlloc(IOPolledFilePollers);
	vars->init();

	vars->pollers = OSArray::withCapacity(4);
	if (!vars->pollers)
	{
	    err = kIOReturnNoMemory;
	    break;
	}

	next = vars->media = media;
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

	    if ((service = OSDynamicCast(IOService, next)) 
		&& service->getDeviceMemory()
		&& !vars->pollers->getCount())	break;

	    child = next;
	}
	while ((next = child->getParentEntry(gIOServicePlane)) 
	       && child->isParent(next, gIOServicePlane, true));

	if (!vars->pollers->getCount())
	{
	    err = kIOReturnUnsupported;
	    break;
	}
    }
    while (false);

    media->setProperty(kIOPolledInterfaceStackKey, vars);

    return (vars);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static IOReturn 
IOPolledFilePollersIODone(IOPolledFilePollers * vars, bool abortable);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static IOReturn
IOPolledFilePollersProbe(IOPolledFilePollers * vars)
{
    IOReturn            err = kIOReturnError;
    int32_t		idx;
    IOPolledInterface * poller;

    for (idx = vars->pollers->getCount() - 1; idx >= 0; idx--)
    {
        poller = (IOPolledInterface *) vars->pollers->getObject(idx);
        err = poller->probe(vars->media);
        if (err)
        {
            HIBLOG("IOPolledInterface::probe[%d] 0x%x\n", idx, err);
            break;
        }
    }

    return (err);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn
IOPolledFilePollersOpen(IOPolledFileIOVars * filevars, uint32_t state, bool abortable)
{

    IOPolledFilePollers      * vars = filevars->pollers;
    IOBufferMemoryDescriptor * ioBuffer;
    IOPolledInterface        * poller;
    IOService                * next;
    IOReturn                   err = kIOReturnError;
    int32_t		       idx;

    vars->abortable = abortable;
    ioBuffer = 0;

    if (kIOPolledAfterSleepState == state)
    {
        vars->ioStatus = 0;
	vars->io = false;
    }
    (void) IOPolledFilePollersIODone(vars, false);

    if ((kIOPolledPreflightState == state) || (kIOPolledPreflightCoreDumpState == state))
    {
        ioBuffer = vars->ioBuffer;
        if (!ioBuffer)
        {
	    vars->ioBuffer = ioBuffer = IOBufferMemoryDescriptor::withOptions(kIODirectionInOut, 
							    2 * kDefaultIOSize, page_size);
	    if (!ioBuffer) return (kIOReturnNoMemory);
        }
    }

    for (idx = vars->pollers->getCount() - 1; idx >= 0; idx--)
    {
        poller = (IOPolledInterface *) vars->pollers->getObject(idx);
        err = poller->open(state, ioBuffer);
        if (kIOReturnSuccess != err)
        {
            HIBLOG("IOPolledInterface::open[%d] 0x%x\n", idx, err);
            break;
        }
    }
    if ((kIOReturnSuccess == err) && (kIOPolledPreflightState == state))
    {
        next = vars->media;
	while (next)
	{
	    next->setProperty(kIOPolledInterfaceActiveKey, kOSBooleanTrue);
	    next = next->getProvider();
	}
    }

    return (err);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn
IOPolledFilePollersClose(IOPolledFileIOVars * filevars, uint32_t state)
{
    IOPolledFilePollers * vars = filevars->pollers;
    IOPolledInterface * poller;
    IORegistryEntry *   next;
    IOReturn            err;
    int32_t		idx;

    (void) IOPolledFilePollersIODone(vars, false);

    if ((kIOPolledPostflightState == state) || (kIOPolledPostflightCoreDumpState == state))
    {
	vars->openCount--;
    }

    for (idx = 0, err = kIOReturnSuccess;
         (poller = (IOPolledInterface *) vars->pollers->getObject(idx));
         idx++)
    {
        err = poller->close(state);
        if ((kIOReturnSuccess != err) && (kIOPolledBeforeSleepStateAborted == state))
        {
            err = poller->close(kIOPolledBeforeSleepState);
        }
        if (err) HIBLOG("IOPolledInterface::close[%d] 0x%x\n", idx, err);
    }

    if (kIOPolledPostflightState == state)
    {
	next = vars->media;
	while (next)
	{
	    next->removeProperty(kIOPolledInterfaceActiveKey);
	    next = next->getParentEntry(gIOServicePlane);
	}
    }

    if ((kIOPolledPostflightState == state) || (kIOPolledPostflightCoreDumpState == state)) do
    {
	if (vars->openCount) break;
	if (vars->ioBuffer)
	{
	    vars->ioBuffer->release();
	    vars->ioBuffer = 0;
	}
    }
    while (false);

    return (err);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn IOPolledInterface::setEncryptionKey(const uint8_t * key, size_t keySize)
{
    return (kIOReturnUnsupported);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn
IOPolledFilePollersSetEncryptionKey(IOPolledFileIOVars * filevars,
				    const uint8_t * key, size_t keySize)
{
    IOReturn              ret = kIOReturnUnsupported;
    IOReturn              err;
    int32_t		  idx;
    IOPolledFilePollers * vars = filevars->pollers;
    IOPolledInterface   * poller;

    for (idx = 0;
         (poller = (IOPolledInterface *) vars->pollers->getObject(idx));
         idx++)
    {
        poller = (IOPolledInterface *) vars->pollers->getObject(idx);
        err = poller->setEncryptionKey(key, keySize);
	if (kIOReturnSuccess == err) ret = err;
    }

    return (ret);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOMemoryDescriptor *
IOPolledFileGetIOBuffer(IOPolledFileIOVars * vars)
{
    return (vars->pollers->ioBuffer);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static void
IOPolledIOComplete(void *   target,
		   void *   parameter,
		   IOReturn status,
		   UInt64   actualByteCount)
{
    IOPolledFilePollers * vars = (IOPolledFilePollers *) parameter;

    vars->ioStatus = status;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static IOReturn
IOStartPolledIO(IOPolledFilePollers * vars, 
                    uint32_t operation, uint32_t bufferOffset, 
		    uint64_t deviceOffset, uint64_t length)
{
    IOReturn            err;
    IOPolledInterface * poller;
    IOPolledCompletion  completion;

    err = vars->ioStatus;
    if (kIOReturnSuccess != err) return (err);

    completion.target    = 0;
    completion.action    = &IOPolledIOComplete;
    completion.parameter = vars;

    vars->ioStatus = -1;

    poller = (IOPolledInterface *) vars->pollers->getObject(0);
    err = poller->startIO(operation, bufferOffset, deviceOffset, length, completion);
    if (err) {
	if (kernel_debugger_entry_count) {
            HIBLOG("IOPolledInterface::startIO[%d] 0x%x\n", 0, err);
	} else {
            HIBLOGFROMPANIC("IOPolledInterface::IOStartPolledIO(0x%p, %d, 0x%x, 0x%llx, %llu) : poller->startIO(%d, 0x%x, 0x%llx, %llu, completion) returned 0x%x",
			vars, operation, bufferOffset, deviceOffset, length, operation, bufferOffset, deviceOffset, length, err);
	}
    }
    return (err);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static IOReturn
IOPolledFilePollersIODone(IOPolledFilePollers * vars, bool abortable)
{
    IOReturn            err = kIOReturnSuccess;
    int32_t		idx = 0;
    IOPolledInterface * poller;
    AbsoluteTime        deadline;

    if (!vars->io) return (kIOReturnSuccess);

    abortable &= vars->abortable;

    clock_interval_to_deadline(2000, kMillisecondScale, &deadline);

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
        if ((false) && (kIOReturnSuccess == err) && (mach_absolute_time() > AbsoluteTime_to_scalar(&deadline)))
    	{
	    HIBLOG("IOPolledInterface::forced timeout\n");
	    vars->ioStatus = kIOReturnTimeout;
    	}
    }
    vars->io = false;

#if HIBERNATION
    if ((kIOReturnSuccess == err) && abortable && hibernate_should_abort())
    {
        err = kIOReturnAborted;
	HIBLOG("IOPolledInterface::checkForWork sw abort\n");
    }
#endif

    if (err)
    {
	HIBLOG("IOPolledInterface::checkForWork[%d] 0x%x\n", idx, err);
    }
    else 
    {
	err = vars->ioStatus;
	if (kIOReturnSuccess != err) HIBLOG("IOPolledInterface::ioStatus 0x%x\n", err);
    }

    return (err);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
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

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

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

#define APFSMEDIA_GETHIBERKEY         "getHiberKey"

static IOReturn 
IOGetVolumeCryptKey(dev_t block_dev,  OSString ** pKeyUUID, 
		    uint8_t * volumeCryptKey, size_t * keySize)
{
    IOReturn         err;
    IOService *      part;
    OSString *       keyUUID = 0;
    OSString *       keyStoreUUID = 0;
    uuid_t           volumeKeyUUID;
    aks_volume_key_t vek;

    static IOService * sKeyStore;

    part = IOCopyMediaForDev(block_dev);
    if (!part) return (kIOReturnNotFound);

    // Try APFS first
    {
        uuid_t volUuid = {0};
        err = part->callPlatformFunction(APFSMEDIA_GETHIBERKEY, false, &volUuid, volumeCryptKey, keySize, keySize);
	if (kIOReturnBadArgument == err)
	{
	    // apfs fails on buffer size >32
	    *keySize = 32;
	    err = part->callPlatformFunction(APFSMEDIA_GETHIBERKEY, false, &volUuid, volumeCryptKey, keySize, keySize);
	}
        if (err != kIOReturnSuccess) *keySize = 0;
        else
        {
            // No need to create uuid string if it's not requested
            if (pKeyUUID)
            {
                uuid_string_t volUuidStr;
                uuid_unparse(volUuid, volUuidStr);
                *pKeyUUID = OSString::withCString(volUuidStr);
            }

            part->release();
            return kIOReturnSuccess;
        }
    }

    // Then old CS path
    err = part->callPlatformFunction(PLATFORM_FUNCTION_GET_MEDIA_ENCRYPTION_KEY_UUID, false,
                  (void *) &keyUUID, (void *) &keyStoreUUID, NULL, NULL);
    if ((kIOReturnSuccess == err) && keyUUID && keyStoreUUID)
    {
//        IOLog("got volume key %s\n", keyStoreUUID->getCStringNoCopy());

        if (!sKeyStore)
            sKeyStore = (IOService *) IORegistryEntry::fromPath(AKS_SERVICE_PATH, gIOServicePlane);
        if (sKeyStore)
            err = uuid_parse(keyStoreUUID->getCStringNoCopy(), volumeKeyUUID);
        else
            err = kIOReturnNoResources;
        if (kIOReturnSuccess == err)
            err = sKeyStore->callPlatformFunction(gAKSGetKey, true, volumeKeyUUID, &vek, NULL, NULL);
        if (kIOReturnSuccess != err)
            IOLog("volume key err 0x%x\n", err);
        else
        {
            if (vek.key.keybytecount < *keySize) *keySize = vek.key.keybytecount;
            bcopy(&vek.key.keybytes[0], volumeCryptKey, *keySize);
        }
        bzero(&vek, sizeof(vek));

        if (pKeyUUID)
        {
            // Create a copy because the caller would release it
            *pKeyUUID = OSString::withString(keyUUID);
        }
    }

    part->release();
    return (err);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn
IOPolledFileOpen(const char * filename,
                 uint64_t setFileSize, uint64_t fsFreeSize,
                 void * write_file_addr, size_t write_file_len,
                 IOPolledFileIOVars ** fileVars,
                 OSData ** imagePath,
                 uint8_t * volumeCryptKey, size_t * keySize)
{
    IOReturn             err = kIOReturnSuccess;
    IOPolledFileIOVars * vars;
    _OpenFileContext     ctx;
    OSData *             extentsData = NULL;
    OSNumber *           num;
    IOService *          part = 0;
    dev_t                block_dev;
    dev_t                image_dev;
    AbsoluteTime         startTime, endTime;
    uint64_t             nsec;

    vars = IONew(IOPolledFileIOVars, 1);
    if (!vars) return (kIOReturnNoMemory);
    bzero(vars, sizeof(*vars));
    vars->allocated = true;

    do
    {
        extentsData = OSData::withCapacity(32);
        ctx.extents = extentsData;
        ctx.size    = 0;
        clock_get_uptime(&startTime);

        vars->fileRef = kern_open_file_for_direct_io(filename,
                                                     (write_file_addr != NULL) || (0 != setFileSize),
                                                     &file_extent_callback, &ctx,
                                                     setFileSize,
                                                     fsFreeSize,
                                                     // write file:
                                                     0, write_file_addr, write_file_len,
                                                     // results
                                                     &block_dev,
                                                     &image_dev,
                                                     &vars->block0,
                                                     &vars->maxiobytes,
                                                     &vars->flags);
#if 0
        uint32_t msDelay = (131071 & random());
        HIBLOG("sleep %d\n", msDelay);
        IOSleep(msDelay);
#endif
        clock_get_uptime(&endTime);
        SUB_ABSOLUTETIME(&endTime, &startTime);
        absolutetime_to_nanoseconds(endTime, &nsec);

        if (!vars->fileRef) err = kIOReturnNoSpace;

        HIBLOG("kern_open_file_for_direct_io took %qd ms\n", nsec / 1000000ULL);
        if (kIOReturnSuccess != err) break;

        HIBLOG("Opened file %s, size %qd, extents %ld, maxio %qx ssd %d\n", filename, ctx.size,
               (extentsData->getLength() / sizeof(IOPolledFileExtent)) - 1,
               vars->maxiobytes, kIOPolledFileSSD & vars->flags);
        assert(!vars->block0);
        if (extentsData->getLength() < sizeof(IOPolledFileExtent))
        {
            err = kIOReturnNoSpace;
            break;
        }

        vars->fileSize = ctx.size;
        vars->extentMap = (IOPolledFileExtent *) extentsData->getBytesNoCopy();

        part = IOCopyMediaForDev(image_dev);
        if (!part)
        {
            err = kIOReturnNotFound;
            break;
        }

        if (!(vars->pollers = IOPolledFilePollers::copyPollers(part))) break;

        if ((num = OSDynamicCast(OSNumber, part->getProperty(kIOMediaPreferredBlockSizeKey))))
            vars->blockSize = num->unsigned32BitValue();
        if (vars->blockSize < 4096) vars->blockSize = 4096;

        HIBLOG("polled file major %d, minor %d, blocksize %ld, pollers %d\n",
               major(image_dev), minor(image_dev), (long)vars->blockSize,
               vars->pollers->pollers->getCount());

        OSString * keyUUID = NULL;
        if (volumeCryptKey)
        {
            err = IOGetVolumeCryptKey(block_dev, &keyUUID, volumeCryptKey, keySize);
        }

        *fileVars    = vars;
        vars->fileExtents = extentsData;

        // make imagePath
        OSData * data;
        if (imagePath)
        {
#if defined(__i386__) || defined(__x86_64__)
            char str2[24 + sizeof(uuid_string_t) + 2];

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
            data = 0;
            err = kIOReturnSuccess;
#endif
            if (kIOReturnSuccess != err)
            {
                HIBLOG("error 0x%x getting path\n", err);
                break;
            }
            *imagePath = data;
        }

        // Release key UUID if we have one
        if (keyUUID)
        {
            keyUUID->release();
            keyUUID = NULL; // Just in case
        }
    }
    while (false);

    if (kIOReturnSuccess != err)
    {
        HIBLOG("error 0x%x opening polled file\n", err);
        IOPolledFileClose(&vars, 0, 0, 0, 0, 0);
        if (extentsData) extentsData->release();
    }

    if (part) part->release();

    return (err);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn
IOPolledFileClose(IOPolledFileIOVars ** pVars,
		  off_t write_offset, void * addr, size_t write_length,
		  off_t discard_offset, off_t discard_end)
{
    IOPolledFileIOVars * vars;

    vars = *pVars;
    if (!vars) return(kIOReturnSuccess);

    if (vars->fileRef)
    {
	kern_close_file_for_direct_io(vars->fileRef, write_offset, addr, write_length, 
				      discard_offset, discard_end);
	vars->fileRef = NULL;
    }
    if (vars->fileExtents) 
    {
    	vars->fileExtents->release();
    	vars->fileExtents = 0;
    }
    if (vars->pollers) 
    {
    	vars->pollers->release();
    	vars->pollers = 0;
    }

    if (vars->allocated) IODelete(vars, IOPolledFileIOVars, 1);
    else                 bzero(vars, sizeof(IOPolledFileIOVars));
    *pVars = NULL;

    return (kIOReturnSuccess);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn
IOPolledFilePollersSetup(IOPolledFileIOVars * vars,
		         uint32_t openState)
{
    IOReturn err;

    err = kIOReturnSuccess;
    do
    {
        if (!vars->pollers->openCount)
        {
	    err = IOPolledFilePollersProbe(vars->pollers);
	    if (kIOReturnSuccess != err) break;
	}
	err = IOPolledFilePollersOpen(vars, openState, false);
	if (kIOReturnSuccess != err) break;
	if ((kIOPolledPreflightState == openState) || (kIOPolledPreflightCoreDumpState == openState))
	{
	    vars->pollers->openCount++;
	}
	vars->pollers->io  = false;
	vars->buffer       = (uint8_t *) vars->pollers->ioBuffer->getBytesNoCopy();
	vars->bufferHalf   = 0;
	vars->bufferOffset = 0;
	vars->bufferSize   = (vars->pollers->ioBuffer->getLength() >> 1);

        if (vars->maxiobytes < vars->bufferSize) vars->bufferSize = vars->maxiobytes;
    }
    while (false);

    if (kIOReturnSuccess != err) HIBLOG("IOPolledFilePollersSetup(%d) error 0x%x\n", openState, err);

    return (err);
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn
IOPolledFileSeek(IOPolledFileIOVars * vars, uint64_t position)
{
    IOPolledFileExtent * extentMap;

    extentMap = vars->extentMap;

    vars->position = position;

    if (position > vars->fileSize) {
	HIBLOG("IOPolledFileSeek: called to seek to 0x%llx greater than file size of 0x%llx\n", vars->position,  vars->fileSize);
	return kIOReturnNoSpace;
    }

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

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn
IOPolledFileWrite(IOPolledFileIOVars * vars,
                    const uint8_t * bytes, IOByteCount size,
                    IOPolledFileCryptVars * cryptvars)
{
    IOReturn    err = kIOReturnSuccess;
    IOByteCount copy, original_size = size;
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
#if KASAN
	  /* Since this may copy mach-o segments in bulk, use the nosan variants of bcopy to
	   * avoid triggering global redzone sanitizer violations when accessing
	   * interstices between 'C' structures
	   */
	    __nosan_bcopy(bytes, vars->buffer + vars->bufferHalf + vars->bufferOffset, copy);
#else
	    bcopy(bytes, vars->buffer + vars->bufferHalf + vars->bufferOffset, copy);
#endif
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

	    err = IOPolledFilePollersIODone(vars->pollers, true);
	    if (kIOReturnSuccess != err)
		break;

if (vars->position & (vars->blockSize - 1)) HIBLOG("misaligned file pos %qx\n", vars->position);
//if (length != vars->bufferSize) HIBLOG("short write of %qx ends@ %qx\n", length, offset + length);

	    err = IOStartPolledIO(vars->pollers, kIOPolledWrite, vars->bufferHalf, offset, length);
	    if (kIOReturnSuccess != err) {
                HIBLOGFROMPANIC("IOPolledFileWrite(0x%p, 0x%p, %llu, 0x%p) : IOStartPolledIO(0x%p, kIOPolledWrite, %llu, 0x%llx, %d) returned 0x%x\n",
                    vars, bytes, (uint64_t) original_size, cryptvars, vars->pollers, (uint64_t) vars->bufferHalf, offset, length, err);
                break;
	    }
	    vars->pollers->io = true;

	    vars->extentRemaining -= vars->bufferOffset;
	    if (!vars->extentRemaining)
	    {
		vars->currentExtent++;
		vars->extentRemaining = vars->currentExtent->length;
		vars->extentPosition  = vars->position;
	    }

	    vars->bufferHalf = vars->bufferHalf ? 0 : vars->bufferSize;
	    vars->bufferOffset = 0;
	    if (vars->bufferSize <= vars->extentRemaining)
		vars->bufferLimit = vars->bufferSize;
	    else
		vars->bufferLimit = vars->extentRemaining;

	    if (!vars->extentRemaining)
	    {
		err = kIOReturnOverrun;
		break;
	    }

	    flush = false;
	}
    }
    while (size);

    return (err);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn
IOPolledFileFlush(IOPolledFileIOVars * vars)
{
    // Only supported by the underlying polled mode driver on embedded currently (expect kIOReturnUnsupported on other platforms)
    IOReturn err = kIOReturnSuccess;

    err = IOPolledFilePollersIODone(vars->pollers, true);
    if (kIOReturnSuccess != err)
	    return err;

    err = IOStartPolledIO(vars->pollers, kIOPolledFlush, 0, 0, 0);
    if (kIOReturnSuccess != err) {
	    HIBLOGFROMPANIC("IOPolledFileFlush(0x%p) : IOStartPolledIO(0x%p, kIOPolledFlush, 0, 0, 0) returned 0x%x\n",
                    vars, vars->pollers, err);
	    return err;
    }
    vars->pollers->io = true;

    return err;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn
IOPolledFileRead(IOPolledFileIOVars * vars,
                    uint8_t * bytes, IOByteCount size,
                    IOPolledFileCryptVars * cryptvars)
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
#if KASAN
	  __nosan_bcopy(vars->buffer + vars->bufferHalf + vars->bufferOffset, bytes, copy);
#else
	  bcopy(vars->buffer + vars->bufferHalf + vars->bufferOffset, bytes, copy);
#endif
	    bytes += copy;
	}
	size -= copy;
	vars->bufferOffset += copy;
//	vars->position += copy;

	if ((vars->bufferOffset == vars->bufferLimit) && (vars->position < vars->readEnd))
	{
	    if (!vars->pollers->io) cryptvars = 0;
	    err = IOPolledFilePollersIODone(vars->pollers, true);
	    if (kIOReturnSuccess != err)
		break;

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
		err = IOStartPolledIO(vars->pollers, kIOPolledRead, vars->bufferHalf, offset, length);
		if (kIOReturnSuccess != err)
		    break;
		vars->pollers->io = true;
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

