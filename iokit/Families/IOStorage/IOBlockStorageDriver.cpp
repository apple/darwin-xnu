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

#include <IOKit/assert.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/storage/IOBlockStorageDevice.h>
#include <IOKit/storage/IOBlockStorageDriver.h>
#include <IOKit/storage/IOMedia.h>

#define super IOStorage
OSDefineMetaClassAndStructors(IOBlockStorageDriver, IOStorage)

// Hack for Cheetah to prevent sleep if there's disk activity.
static IOService * gIORootPowerDomain = NULL;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

const UInt32 kPollerInterval = 1000;                           // (ms, 1 second)

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOBlockStorageDevice * IOBlockStorageDriver::getProvider() const
{
    //
    // Obtain this object's provider.  We override the superclass's method to
    // return a more specific subclass of IOService -- IOBlockStorageDevice.  
    // This method serves simply as a convenience to subclass developers.
    //

    return (IOBlockStorageDevice *) IOService::getProvider();
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOBlockStorageDriver::init(OSDictionary * properties = 0)
{
    //
    // Initialize this object's minimal state.
    //

    if (super::init(properties) == false)  return false;

    initMediaState();
    
    _ejectable               = false;
    _lockable                = false;
    _pollIsExpensive         = false;
    _pollIsRequired          = false;
    _removable               = false;
    
    _mediaBlockSize          = 0;
    _maxBlockNumber          = 0;
    _maxReadByteTransfer     = 0;
    _maxWriteByteTransfer    = 0;

    _mediaStateLock          = IOLockAlloc();

    if (_mediaStateLock == 0)
        return false;

    _deblockRequestWriteLock = IOLockAlloc();
    _openClients             = OSSet::withCapacity(2);
    _pollerCall              = thread_call_allocate(poller, this);

    for (unsigned index = 0; index < kStatisticsCount; index++)
        _statistics[index] = OSNumber::withNumber(0ULL, 64);

    if (_deblockRequestWriteLock == 0 || _openClients == 0 || _pollerCall == 0)
        return false;

    for (unsigned index = 0; index < kStatisticsCount; index++)
        if (_statistics[index] == 0)  return false;

    //
    // Create the standard block storage driver registry properties.
    //

    OSDictionary * statistics = OSDictionary::withCapacity(kStatisticsCount);

    if (statistics == 0)  return false;

    statistics->setObject( kIOBlockStorageDriverStatisticsBytesReadKey,
                           _statistics[kStatisticsBytesRead] );
    statistics->setObject( kIOBlockStorageDriverStatisticsBytesWrittenKey,
                           _statistics[kStatisticsBytesWritten] );
    statistics->setObject( kIOBlockStorageDriverStatisticsReadErrorsKey,
                           _statistics[kStatisticsReadErrors] );
    statistics->setObject( kIOBlockStorageDriverStatisticsWriteErrorsKey,
                           _statistics[kStatisticsWriteErrors] );
    statistics->setObject( kIOBlockStorageDriverStatisticsLatentReadTimeKey,
                           _statistics[kStatisticsLatentReadTime] );
    statistics->setObject( kIOBlockStorageDriverStatisticsLatentWriteTimeKey,
                           _statistics[kStatisticsLatentWriteTime] );
    statistics->setObject( kIOBlockStorageDriverStatisticsReadsKey,
                           _statistics[kStatisticsReads] );
    statistics->setObject( kIOBlockStorageDriverStatisticsWritesKey,
                           _statistics[kStatisticsWrites] );
    statistics->setObject( kIOBlockStorageDriverStatisticsReadRetriesKey,
                           _statistics[kStatisticsReadRetries] );
    statistics->setObject( kIOBlockStorageDriverStatisticsWriteRetriesKey,
                           _statistics[kStatisticsWriteRetries] );
    statistics->setObject( kIOBlockStorageDriverStatisticsTotalReadTimeKey,
                           _statistics[kStatisticsTotalReadTime] );
    statistics->setObject( kIOBlockStorageDriverStatisticsTotalWriteTimeKey,
                           _statistics[kStatisticsTotalWriteTime] );
    
    setProperty(kIOBlockStorageDriverStatisticsKey, statistics);

    // Hack for Cheetah to prevent sleep if there's disk activity.
    if (!gIORootPowerDomain) {
        // No danger of race here as we're ultimately just setting
        // the gIORootPowerDomain variable.

        do {
            IOService * root = NULL;
            OSIterator * iterator = NULL;
            OSDictionary * pmDict = NULL;

            root = IOService::getServiceRoot();
            if (!root) break;

            pmDict = root->serviceMatching("IOPMrootDomain");
            if (!pmDict) break;

            iterator = root->getMatchingServices(pmDict);
            pmDict->release();
            if (!iterator) break;

            if (iterator) {
                gIORootPowerDomain = OSDynamicCast(IOService, iterator->getNextObject());
                iterator->release();
            }
        } while (false);
    }

    return true;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOBlockStorageDriver::start(IOService * provider)
{
    //
    // This method is called once we have been attached to the provider object.
    //

    // Open the block storage device.

    if (provider->open(this) == false)  return false;

    // Prepare the block storage driver for operation.

    if (handleStart(provider) == false)
    {
        provider->close(this);
        return false;
    }

    // Initiate the poller mechanism if it is required.

    if (isMediaEjectable() && isMediaPollRequired() && !isMediaPollExpensive())
    {
        lockForArbitration();        // (disable opens/closes; a recursive lock)

        if (!isOpen() && !isInactive())
            schedulePoller();        // (schedule the poller, increments retain)

        unlockForArbitration();       // (enable opens/closes; a recursive lock)
    }

    // Register this object so it can be found via notification requests. It is
    // not being registered to have I/O Kit attempt to have drivers match on it,
    // which is the reason most other services are registered -- that's not the
    // intention of this registerService call.

    registerService();

    return true;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOBlockStorageDriver::yield(IOService *  provider,
                                 IOOptionBits options,
                                 void *       argument)
{
    //
    // This method is called as a result of the kIOMessageServiceIsTerminated
    // or kIOMessageServiceIsRequestingClose provider messages.  The argument
    // is passed in as-is from the message.  The kIOServiceRequired option is
    // set for the kIOMessageServiceIsTerminated message to indicate that the
    // yield must succeed.
    //

    bool success = false;

    lockForArbitration();

    // Yield the block storage device.

    success = handleYield(provider, options, argument);

    if (success)
    {
        // Close the block storage device.

        provider->close(this);
    }

    unlockForArbitration();

    return success;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IOBlockStorageDriver::free()
{
    //
    // Free all of this object's outstanding resources.
    //

    if (_mediaStateLock)  IOLockFree(_mediaStateLock);

    if (_deblockRequestWriteLock)  IOLockFree(_deblockRequestWriteLock);
    if (_openClients)  _openClients->release();
    if (_pollerCall)  thread_call_free(_pollerCall);

    for (unsigned index = 0; index < kStatisticsCount; index++)
        if (_statistics[index])  _statistics[index]->release();

    super::free();
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOBlockStorageDriver::handleOpen(IOService *  client,
                                      IOOptionBits options,
                                      void *       argument)
{
    //
    // The handleOpen method grants or denies permission to access this object
    // to an interested client.  The argument is an IOStorageAccess value that
    // specifies the level of access desired -- reader or reader-writer.
    //
    // This method can be invoked to upgrade or downgrade the access level for
    // an existing client as well.  The previous access level will prevail for
    // upgrades that fail, of course.   A downgrade should never fail.  If the
    // new access level should be the same as the old for a given client, this
    // method will do nothing and return success.  In all cases, one, singular
    // close-per-client is expected for all opens-per-client received.
    //
    // This method assumes that the arbitration lock is held.
    //

    assert(client);

    // Ensure there is media in the block storage device.

    if (getMediaState() == kIOMediaStateOffline)  return false;

    // Handle the first open on removable media in a special case.

    if (isMediaEjectable() && _openClients->getCount() == 0)
    {
        // Halt the poller if it is active and this is the first open.

        if (isMediaPollRequired() && !isMediaPollExpensive())
            unschedulePoller();                       // (unschedule the poller)

        // Lock down the media while we have opens on this driver object.

        if (lockMedia(true) != kIOReturnSuccess)
            IOLog("%s: Unable to lock down removable media.\n", getName());
    }

    // Process the open.

    _openClients->setObject(client);            // (works for up/downgrade case)

    return true;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOBlockStorageDriver::handleIsOpen(const IOService * client) const
{
    //
    // The handleIsOpen method determines whether the specified client, or any
    // client if none is specificed, presently has an open on this object.
    //
    // This method assumes that the arbitration lock is held.
    //

    if (client)
        return _openClients->containsObject(client);
    else
        return (_openClients->getCount() != 0);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IOBlockStorageDriver::handleClose(IOService * client, IOOptionBits options)
{
    //
    // The handleClose method drops the incoming client's access to this object.
    //
    // This method assumes that the arbitration lock is held.
    //

    assert(client);

    // Process the close.

    _openClients->removeObject(client);

    // Handle the last close in a special case.

    if (!isInactive() && _openClients->getCount() == 0)
    {
        if (isMediaWritable())
        {
            if (getMediaState() == kIOMediaStateOnline)
            {
                // Synchronize the cache on writeable media.

                if (synchronizeCache(this) != kIOReturnSuccess)
                    IOLog("%s: Unable to flush cache on media.\n", getName());
            }
        }

        if (isMediaEjectable())
        {
            // Unlock the removable media.

            if (getMediaState() == kIOMediaStateOnline)
            {
                if (lockMedia(false) != kIOReturnSuccess)
                    IOLog("%s: Unable to unlock removable media.\n", getName());
            }

            // Reactivate the poller.

            if (isMediaPollRequired() && !isMediaPollExpensive())
                schedulePoller();    // (schedule the poller, increments retain)
          }
    }
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IOBlockStorageDriver::read(IOService *          /* client */,
                                UInt64               byteStart,
                                IOMemoryDescriptor * buffer,
                                IOStorageCompletion  completion)
{
    //
    // The read method is the receiving end for all read requests from the
    // storage framework, ie. via the media object created by this driver.
    //
    // This method kicks off a sequence of three methods for each read or write
    // request.  The first is prepareRequest, which allocates and prepares some
    // context for the transfer; the second is deblockRequest, which aligns the
    // transfer at the media block boundaries; and the third is executeRequest,
    // which implements the actual transfer from the block storage device.
    //

    // State our assumptions.

    assert(buffer->getDirection() == kIODirectionIn);

    // Prepare the transfer.

    prepareRequest(byteStart, buffer, completion);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IOBlockStorageDriver::write(IOService *          /* client */,
                                 UInt64               byteStart,
                                 IOMemoryDescriptor * buffer,
                                 IOStorageCompletion  completion)
{
    //
    // The write method is the receiving end for all write requests from the
    // storage framework, ie. via the media object created by this driver.
    //
    // This method kicks off a sequence of three methods for each read or write
    // request.  The first is prepareRequest, which allocates and prepares some
    // context for the transfer; the second is deblockRequest, which aligns the
    // transfer at the media block boundaries; and the third is executeRequest,
    // which implements the actual transfer from the block storage driver.
    //

    // State our assumptions.

    assert(buffer->getDirection() == kIODirectionOut);

    // Prepare the transfer.

    prepareRequest(byteStart, buffer, completion);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IOBlockStorageDriver::addToBytesTransferred(UInt64 bytesTransferred,
                                                 UInt64 totalTime,       // (ns)
                                                 UInt64 latentTime,      // (ns)
                                                 bool   isWrite)
{
    //
    // Update the total number of bytes transferred, the total transfer time,
    // and the total latency time -- used for statistics.
    //

    if (isWrite)
    {
        _statistics[kStatisticsWrites]->addValue(1);
        _statistics[kStatisticsBytesWritten]->addValue(bytesTransferred);
        _statistics[kStatisticsTotalWriteTime]->addValue(totalTime);
        _statistics[kStatisticsLatentWriteTime]->addValue(latentTime);
        if (bytesTransferred <= getMediaBlockSize())
            _statistics[kStatisticsSingleBlockWrites]->addValue(1);
    }
    else
    {
        _statistics[kStatisticsReads]->addValue(1);
        _statistics[kStatisticsBytesRead]->addValue(bytesTransferred);
        _statistics[kStatisticsTotalReadTime]->addValue(totalTime);
        _statistics[kStatisticsLatentReadTime]->addValue(latentTime);
    }
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IOBlockStorageDriver::incrementRetries(bool isWrite)
{
    //
    // Update the total retry count -- used for statistics.
    //

    if (isWrite)
        _statistics[kStatisticsWriteRetries]->addValue(1);
    else
        _statistics[kStatisticsReadRetries]->addValue(1);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IOBlockStorageDriver::incrementErrors(bool isWrite)
{
    //
    // Update the total error count -- used for statistics.
    //

    if (isWrite)
        _statistics[kStatisticsWriteErrors]->addValue(1);
    else
        _statistics[kStatisticsReadErrors]->addValue(1);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

UInt32 IOBlockStorageDriver::getStatistics(UInt64 * statistics,
                                           UInt32   statisticsMaxCount) const
{
    //
    // Ask the driver to report its operating statistics.
    //
    // The statistics are each indexed by IOBlockStorageDriver::Statistics
    // indices.  This routine fills the caller's buffer, up to the maximum
    // count specified if the real number of statistics would overflow the
    // buffer.  The return value indicates the actual number of statistics
    // copied to the buffer.
    //
    // If the statistics buffer is not supplied or if the maximum count is
    // zero, the routine returns the proposed count of statistics instead.
    //

    if (statistics == 0)
        return kStatisticsCount;

    UInt32 statisticsCount = min(kStatisticsCount, statisticsMaxCount);

    for (unsigned index = 0; index < statisticsCount; index++)
        statistics[index] = _statistics[index]->unsigned64BitValue();

    return statisticsCount;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

UInt64 IOBlockStorageDriver::getStatistic(Statistics statistic) const
{
    //
    // Ask the driver to report one of its operating statistics.
    //

    if ((UInt32) statistic >= kStatisticsCount)  return 0;

    return _statistics[statistic]->unsigned64BitValue();
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOBlockStorageDriver::Context * IOBlockStorageDriver::allocateContext()
{
    //
    // Allocate a context structure for a read/write operation.
    //

    Context * context = IONew(Context, 1);

    if (context)
    {
        bzero(context, sizeof(Context));
    }

    return context;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IOBlockStorageDriver::deleteContext(
                                        IOBlockStorageDriver::Context * context)
{
    //
    // Delete a context structure from a read/write operation.
    //

    IODelete(context, Context, 1);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IOBlockStorageDriver::prepareRequest(UInt64               byteStart,
                                          IOMemoryDescriptor * buffer,
                                          IOStorageCompletion  completion)
{
    //
    // The prepareRequest method allocates and prepares state for the transfer.
    //
    // This method is part of a sequence of methods invoked for each read/write
    // request.  The first is prepareRequest, which allocates and prepares some
    // context for the transfer; the second is deblockRequest, which aligns the
    // transfer at the media block boundaries; and the third is executeRequest,
    // which implements the actual transfer from the block storage device.
    //

    Context * context;
    IOReturn  status;

    // Allocate a context structure to hold some of our state.

    context = allocateContext();

    if (context == 0)
    {
        complete(completion, kIOReturnNoMemory);
        return;
    }
    
    // Prepare the transfer buffer.

    status = buffer->prepare();

    if (status != kIOReturnSuccess)
    {
        deleteContext(context);
        complete(completion, status);
        return;
    }

    // Fill in the context structure with some of our state.

    context->block.size = getMediaBlockSize();
    context->block.type = kBlockTypeStandard;

    context->original.byteStart  = byteStart;
    context->original.buffer     = buffer;
    context->original.buffer->retain();
    context->original.completion = completion;

    completion.target    = this;
    completion.action    = prepareRequestCompletion;
    completion.parameter = context;

    // Deblock the transfer.

    deblockRequest(byteStart, buffer, completion, context);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IOBlockStorageDriver::prepareRequestCompletion(void *   target,
                                                    void *   parameter,
                                                    IOReturn status,
                                                    UInt64   actualByteCount)
{
    //
    // This is the completion routine for the prepared request.  It updates
    // the driver's statistics, performs some clean up work, then calls the
    // original request's completion routine.
    //

    Context *              context = (Context              *) parameter;
    IOBlockStorageDriver * driver  = (IOBlockStorageDriver *) target;
    bool                   isWrite;
    
    isWrite = (context->original.buffer->getDirection() == kIODirectionOut);

    // State our assumptions.

    assert(status                                != kIOReturnSuccess ||
           context->original.buffer->getLength() == actualByteCount);

    // Update the total number of bytes transferred.

    driver->addToBytesTransferred(actualByteCount, 0, 0, isWrite);

    // Update the total error count.

    if (status != kIOReturnSuccess)
    {
        driver->incrementErrors(isWrite);
    }

    // Complete the transfer buffer.

    context->original.buffer->complete();

    // Complete the transfer request.

    IOStorage::complete(context->original.completion, status, actualByteCount);

    // Release our resources.

    context->original.buffer->release();

    driver->deleteContext(context);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IOBlockStorageDriver::schedulePoller()
{
    //
    // Schedule the poller mechanism.
    //
    // This method assumes that the arbitration lock is held.
    //

    AbsoluteTime deadline;

    retain();

    clock_interval_to_deadline(kPollerInterval, kMillisecondScale, &deadline);
    thread_call_enter_delayed(_pollerCall, deadline);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IOBlockStorageDriver::unschedulePoller()
{
    //
    // Unschedule the poller mechanism.
    //
    // This method assumes that the arbitration lock is held.
    //

    if (thread_call_cancel(_pollerCall))  release();
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IOBlockStorageDriver::poller(void * target, void *)
{
    //
    // This method is the timeout handler for the poller mechanism.  It polls
    // for media and reschedules another timeout if there are still no opens.
    //

    IOBlockStorageDriver * driver = (IOBlockStorageDriver *) target;

    driver->pollMedia();

    driver->lockForArbitration();    // (disable opens/closes; a recursive lock)

    if (!driver->isOpen() && !driver->isInactive())
        driver->schedulePoller();    // (schedule the poller, increments retain)

    driver->unlockForArbitration();   // (enable opens/closes; a recursive lock)

    driver->release();            // (drop the retain associated with this poll)
}


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOReturn IOBlockStorageDriver::message(UInt32      type,
                                       IOService * provider,
                                       void *      argument)
{
    //
    // Generic entry point for calls from the provider.  A return value of
    // kIOReturnSuccess indicates that the message was received, and where
    // applicable, that it was successful.
    //

    switch (type)
    {
        case kIOMessageMediaStateHasChanged:
        {
            IOReturn status;
            IOLockLock(_mediaStateLock);    
            status = mediaStateHasChanged((IOMediaState) argument);
            IOLockUnlock(_mediaStateLock);    
            return status;
        }
        case kIOMessageServiceIsRequestingClose:
        {
            bool success;
            success = yield(provider, 0, argument);
            return success ? kIOReturnSuccess : kIOReturnBusy;
        }
        case kIOMessageServiceIsTerminated:
        {
            bool success;
            success = yield(provider, kIOServiceRequired, argument);
            return success ? kIOReturnSuccess : kIOReturnError;
        }
        default:
        {
            return super::message(type, provider, argument);
        }
    }
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

/* Accept a new piece of media, doing whatever's necessary to make it
 * show up properly to the system. The arbitration lock is assumed to
 * be held during the call.
 */
IOReturn
IOBlockStorageDriver::acceptNewMedia(void)
{
    IOReturn result;
    bool ok;
    UInt64 nbytes;
    char name[128];
    bool nameSep;

    /* Since the kernel printf doesn't handle 64-bit integers, we
     * simply make an assumption that the block count and size
     * will be 32-bit values max.
     */

#ifdef moreDebug
    IOLog("%s[IOBlockStorageDriver]::%s media: %ld blocks, %ld bytes each, write-%s.\n",
            getName(),
            getDeviceTypeName(),
            (UInt32)_maxBlockNumber + 1,(UInt32)getMediaBlockSize(),
            (_writeProtected ? "protected" : "enabled"));
#endif

    if (_maxBlockNumber) {
        nbytes = _mediaBlockSize * (_maxBlockNumber + 1);  
    } else {
        nbytes = 0;
    }

    /* Instantiate a media object and attach it to ourselves. */

    name[0] = 0;
    nameSep = false;
    if (getProvider()->getVendorString()) {
        strcat(name, getProvider()->getVendorString());
        nameSep = true;
    }
    if (getProvider()->getProductString()) {
        if (nameSep == true)  strcat(name, " ");
        strcat(name, getProvider()->getProductString());
        nameSep = true;
    }
    if (nameSep == true)  strcat(name, " ");
    strcat(name, "Media");

    _mediaObject = instantiateMediaObject(0,nbytes,_mediaBlockSize,name);
    result = (_mediaObject) ? kIOReturnSuccess : kIOReturnBadArgument;
    
    if (result == kIOReturnSuccess) {
        ok = _mediaObject->attach(this);       		/* attach media object above us */
        if (ok) {
            _mediaPresent = true;
            _mediaObject->registerService();		/* enable matching */
        } else {
            _mediaObject->release();
            _mediaObject = 0;
            return(kIOReturnNoMemory);	/* give up now */
        }
    }
    
    return(result);
}

IOReturn
IOBlockStorageDriver::checkForMedia(void)
{
    IOReturn result;
    bool currentState;
    bool changed;
    
    IOLockLock(_mediaStateLock);    

    result = getProvider()->reportMediaState(&currentState,&changed);
    if (result != kIOReturnSuccess) {		/* the poll operation failed */
        IOLog("%s[IOBlockStorageDriver]::checkForMedia; err '%s' from reportMediaState\n",
              getName(),stringFromReturn(result));
    } else if (changed) {	/* the poll succeeded, media state has changed */
        result = mediaStateHasChanged(currentState ? kIOMediaStateOnline
                                                   : kIOMediaStateOffline);
    }

    IOLockUnlock(_mediaStateLock);
    return(result);
}

IOReturn
IOBlockStorageDriver::mediaStateHasChanged(IOMediaState state)
{
    IOReturn result;

    /* The media has changed state. See if it's just inserted or removed. */

    if (state == kIOMediaStateOnline) {		/* media is now present */

        /* Allow a subclass to decide whether we accept the media. Such a
         * decision might be based on things like password-protection, etc.
         */

        if (validateNewMedia() == false) {	/* we're told to reject it */
            rejectMedia();			/* so let subclass do whatever it wants */
            return(kIOReturnSuccess);		/* pretend nothing happened */
        }

        result = recordMediaParameters();	/* learn about media */
        if (result != kIOReturnSuccess) {	/* couldn't record params */
            initMediaState();		/* deny existence of new media */
	    IOLog("%s[IOBlockStorageDriver]::checkForMedia: err '%s' from recordMediaParameters\n",
			getName(),stringFromReturn(result));
            return(result);
        }

        /* Now we do what's necessary to make the new media
         * show up properly in the system.
         */

        lockForArbitration();    
        result = acceptNewMedia();

        if (result != kIOReturnSuccess) {
            initMediaState();		/* deny existence of new media */
	    IOLog("%s[IOBlockStorageDriver]::checkForMedia; err '%s' from acceptNewMedia\n",
            getName(),stringFromReturn(result));
        }

        unlockForArbitration();    
        return(result);		/* all done, new media is ready */

    } else {				/* media is now absent */

        lockForArbitration();
        result = decommissionMedia(true);	/* force a teardown */
        unlockForArbitration();

        if (result != kIOReturnSuccess && result != kIOReturnNoMedia) {
	    IOLog("%s[IOBlockStorageDriver]::checkForMedia; err '%s' from decommissionNewMedia\n",
			getName(),stringFromReturn(result));
            return(result);
        }

        return(kIOReturnSuccess);		/* all done; media is gone */
    }
}

UInt64
IOBlockStorageDriver::constrainByteCount(UInt64 /* requestedCount */ ,bool isWrite)
{
    if (isWrite) {
        return(_maxWriteByteTransfer);
    } else {
        return(_maxReadByteTransfer);
    }
}

/* Decommission a piece of media that has become unavailable either due to
 * ejection or some outside force (e.g. the Giant Hand of the User).
 * (I prefer the term "decommission" rather than "abandon." The former implies
 * a well-determined procedure, whereas the latter implies leaving the media
 * in an orphaned state.)
 */
/* Tear down the stack above the specified object. Usually these objects will
 * be of type IOMedia, but they could be any IOService. The arbitration lock is
 * assumed to be held during the call.
 */
IOReturn
IOBlockStorageDriver::decommissionMedia(bool forcible)
{
    IOReturn result;

    if (_mediaObject) {
        /* If this is a forcible decommission (i.e. media is gone), we don't
         * care whether the teardown worked; we forget about the media.
         */
        if (_mediaObject->terminate(forcible ? kIOServiceRequired : 0) || forcible) {
            _mediaObject->release();
            _mediaObject = 0;

            initMediaState();        /* clear all knowledge of the media */
            result = kIOReturnSuccess;

        } else {
            result = kIOReturnBusy;
        }
    } else {
        result = kIOReturnNoMedia;
    }

    return(result);
}

IOReturn
IOBlockStorageDriver::ejectMedia(void)
{
    IOReturn result;

    if (_removable) {
        
        IOLockLock(_mediaStateLock);

        lockForArbitration();
        result = decommissionMedia(false);	/* try to teardown */
        unlockForArbitration();

        if (result == kIOReturnSuccess) {	/* eject */
            if (lockMedia(false) != kIOReturnSuccess)
                IOLog("%s: Unable to unlock removable media.\n", getName());

            (void)getProvider()->doEjectMedia();	/* ignore any error */
        }

        IOLockUnlock(_mediaStateLock);

        return(result);
            
    } else {
        return(kIOReturnUnsupported);        
    }
}

void
IOBlockStorageDriver::executeRequest(UInt64                          byteStart,
                                     IOMemoryDescriptor *            buffer,
                                     IOStorageCompletion             completion,
                                     IOBlockStorageDriver::Context * context)
{
    UInt32 block;
    UInt32 nblks;
    IOReturn result;

    if (!_mediaPresent) {		/* no media? you lose */
        complete(completion, kIOReturnNoMedia,0);
        return;
    }

    /* We know that we are never called with a request too large,
     * nor one that is misaligned with a block.
     */
    assert((byteStart           % _mediaBlockSize) == 0);
    assert((buffer->getLength() % _mediaBlockSize) == 0);
    
    block = byteStart           / _mediaBlockSize;
    nblks = buffer->getLength() / _mediaBlockSize;

/* Now the protocol-specific provider implements the actual
     * start of the data transfer: */

    // Tickle the root power domain to reset the sleep countdown.
    if (gIORootPowerDomain) {
        gIORootPowerDomain->activityTickle(kIOPMSubclassPolicy);
    }

    result = getProvider()->doAsyncReadWrite(buffer,block,nblks,completion);
    
    if (result != kIOReturnSuccess) {		/* it failed to start */
        IOLog("%s[IOBlockStorageDriver]; executeRequest: request failed to start!\n",getName());
        complete(completion,result);
        return;
    }
}

IOReturn
IOBlockStorageDriver::formatMedia(UInt64 byteCapacity)
{
    if (!_mediaPresent) {
        return(kIOReturnNoMedia);
    }

    return(getProvider()->doFormatMedia(byteCapacity));
}

const char *
IOBlockStorageDriver::getDeviceTypeName(void)
{
    return(kIOBlockStorageDeviceTypeGeneric);
}

UInt32
IOBlockStorageDriver::getFormatCapacities(UInt64 * capacities,
                                            UInt32   capacitiesMaxCount) const
{
    return(getProvider()->doGetFormatCapacities(capacities,capacitiesMaxCount));
}

UInt64
IOBlockStorageDriver::getMediaBlockSize() const
{
    return(_mediaBlockSize);
}

IOMediaState
IOBlockStorageDriver::getMediaState() const
{
    if (_mediaPresent) {
        return(kIOMediaStateOnline);
    } else {
        return(kIOMediaStateOffline);
    }
}

bool
IOBlockStorageDriver::handleStart(IOService * provider)
{
    IOReturn result;

    /* Print device name/type information on the console: */
    
    /*The protocol-specific provider determines whether the media is removable. */

    result = getProvider()->reportRemovability(&_removable);
    if (result != kIOReturnSuccess) {
	IOLog("%s[IOBlockStorageDriver]::handleStart; err '%s' from reportRemovability\n",
			getName(),stringFromReturn(result));
        return(false);
    }

    if (_removable) {

        /* The protocol-specific provider determines whether we must poll to detect
         * media insertion. Nonremovable devices never need polling.
         */
        
        result = getProvider()->reportPollRequirements(&_pollIsRequired,&_pollIsExpensive);

            if (result != kIOReturnSuccess) {
	    IOLog("%s[IOBlockStorageDriver]::handleStart; err '%s' from reportPollRequirements\n",
			getName(),stringFromReturn(result));
            return(false);
        }
        
        /* The protocol-specific provider determines whether the media is ejectable
         * under software control.
         */
        result = getProvider()->reportEjectability(&_ejectable);
        if (result != kIOReturnSuccess) {
	    IOLog("%s[IOBlockStorageDriver]::handleStart; err '%s' from reportEjectability\n",
			getName(),stringFromReturn(result));
            return(false);
        }

        /* The protocol-specific provider determines whether the media is lockable
         * under software control.
         */
        result = getProvider()->reportLockability(&_lockable);
        if (result != kIOReturnSuccess) {
	    IOLog("%s[IOBlockStorageDriver]::handleStart; err '%s' from reportLockability\n",
			getName(),stringFromReturn(result));
            return(false);
        }

    } else {		/* fixed disk: not ejectable, not lockable */
        _ejectable	= false;
        _lockable	= false;
        _pollIsRequired	= true;		/* polling detects device disappearance */
    }
    
    /* Check for the device being ready with media inserted: */

    result = checkForMedia();

    /* The poll should never fail for nonremovable media: */
    
    if (result != kIOReturnSuccess && !_removable) {
	IOLog("%s[IOBlockStorageDriver]::handleStart: err '%s' from checkForMedia\n",
			getName(),stringFromReturn(result));
        return(false);
    }

    return(true);
}

/* The driver has been instructed to yield. The arbitration lock is assumed to
 * be held during the call.
 */
bool
IOBlockStorageDriver::handleYield(IOService *  provider,
                                  IOOptionBits options,
                                  void *       argument)
{
    // Determine whether we can yield (for non-required yield requests).

    if ( (options & kIOServiceRequired) == 0 && isOpen() != false )
    {
        return false;
    }

    // Halt the poller mechanism.

    if ( isMediaEjectable()     != false &&
         isMediaPollRequired()  != false &&
         isMediaPollExpensive() == false )
    {
        unschedulePoller();                           // (unschedule the poller)
    }

    // Force a teardown.

    decommissionMedia(true);

    return true;
}

void
IOBlockStorageDriver::initMediaState(void)
{
    _mediaPresent	= false;
    _writeProtected    	= false;
}

IOMedia *
IOBlockStorageDriver::instantiateDesiredMediaObject(void)
{
    return(new IOMedia);
}

IOMedia *
IOBlockStorageDriver::instantiateMediaObject(UInt64 base,UInt64 byteSize,
                                        UInt32 blockSize,char *mediaName)
{
    IOMedia *m;
    bool result;

    m = instantiateDesiredMediaObject();
    if (m == NULL) {
        return(NULL);
    }

    result = m->init(   base,			/* base byte offset */
                        byteSize,		/* byte size */
                        blockSize,		/* preferred block size */
        		_ejectable,		/* TRUE if ejectable */
                        true,			/* TRUE if whole physical media */
                        !_writeProtected,	/* TRUE if writable */
        		"");			/* content hint */

    if (result) {
        m->setName(mediaName);
        return(m);
        
    } else {					/* some init error */
        m->release();
        return(NULL);		/* beats me...call it this error */
    }
}

bool
IOBlockStorageDriver::isMediaEjectable(void) const
{
    return(_ejectable);
}

bool
IOBlockStorageDriver::isMediaPollExpensive(void) const
{
    return(_pollIsExpensive);
}

bool
IOBlockStorageDriver::isMediaPollRequired(void) const
{
    return(_pollIsRequired);
}

bool
IOBlockStorageDriver::isMediaWritable(void) const
{
    return(!_writeProtected);
}

IOReturn
IOBlockStorageDriver::lockMedia(bool locked)
{
    if (_lockable) {
        return(getProvider()->doLockUnlockMedia(locked));
    } else {
        return(kIOReturnUnsupported);        
    }
}

IOReturn
IOBlockStorageDriver::pollMedia(void)
{
    if (!_pollIsRequired) {			/* shouldn't poll; it's an error */
        
        return(kIOReturnUnsupported);
        
    } else {					/* poll is required...do it */

        return(checkForMedia());
        
    }
}

IOReturn
IOBlockStorageDriver::recordMediaParameters(void)
{
    IOReturn result;

    /* Determine the device's block size and max block number.
     * What should an unformatted device report? All zeroes, or an error?
     */

    result = getProvider()->reportBlockSize(&_mediaBlockSize);    
    if (result != kIOReturnSuccess) {
        goto err;
    }

    result = getProvider()->reportMaxValidBlock(&_maxBlockNumber);    
    if (result != kIOReturnSuccess) {
        goto err;
    }

    /* Calculate the maximum allowed byte transfers for reads and writes. */

    result = getProvider()->reportMaxReadTransfer(_mediaBlockSize,&_maxReadByteTransfer);
    if (result != kIOReturnSuccess) {
        goto err;
    }

    result = getProvider()->reportMaxWriteTransfer(_mediaBlockSize,&_maxWriteByteTransfer);
    if (result != kIOReturnSuccess) {
        goto err;
    }

    /* Is the media write-protected? */

    result = getProvider()->reportWriteProtection(&_writeProtected);
    if (result != kIOReturnSuccess) {
        goto err;
    }

    return(kIOReturnSuccess);		/* everything was successful */

    /* If we fall thru to here, we had some kind of error. Set everything to
     * a reasonable state since we haven't got any real information.
     */

err:
    _mediaPresent = false;
    _writeProtected = true;

    return(result);
}

void
IOBlockStorageDriver::rejectMedia(void)
{
    (void)getProvider()->doEjectMedia();	/* eject it, ignoring any error */
    initMediaState();			/* deny existence of new media */
}

IOReturn
IOBlockStorageDriver::synchronizeCache(IOService *client)
{
    return(getProvider()->doSynchronizeCache());
}

bool
IOBlockStorageDriver::validateNewMedia(void)
{
    return(true);
}

// -----------------------------------------------------------------------------
// Deblocker Implementation

#include <IOKit/IOBufferMemoryDescriptor.h>

class IODeblocker : public IOMemoryDescriptor
{
    OSDeclareDefaultStructors(IODeblocker);

protected:

    UInt64                     _blockSize;

    struct
    {
        IOMemoryDescriptor * buffer;
        UInt32               offset;
        UInt32               length;
    }                          _chunks[3];
    UInt32                     _chunksCount;

    IOBufferMemoryDescriptor * _excessBuffer;
    UInt64                     _excessCountFinal;
    UInt64                     _excessCountStart;

    IOMemoryDescriptor *       _requestBuffer;
    IOStorageCompletion        _requestCompletion;
    void *                     _requestContext;
    UInt64                     _requestCount;
    bool                       _requestIsOneBlock;
    UInt64                     _requestStart;

    enum
    {
        kStageInit,
        kStagePrepareExcessStart,
        kStagePrepareExcessFinal,
        kStageLast,
        kStageDone
    } _stage;

    virtual void free();

    virtual bool initWithAddress( void *      address,       /* not supported */
                                  IOByteCount withLength,
                                  IODirection withDirection );

    virtual bool initWithAddress( vm_address_t address,      /* not supported */
                                  IOByteCount  withLength,
                                  IODirection  withDirection,
                                  task_t       withTask );

    virtual bool initWithPhysicalAddress( 
                                  IOPhysicalAddress address, /* not supported */
                                  IOByteCount       withLength,
                                  IODirection       withDirection );

    virtual bool initWithPhysicalRanges( 
                                  IOPhysicalRange * ranges,  /* not supproted */
                                  UInt32            withCount,
                                  IODirection       withDirection,
                                  bool              asReference = false );

    virtual bool initWithRanges(  IOVirtualRange * ranges,   /* not supported */
                                  UInt32           withCount,
                                  IODirection      withDirection,
                                  task_t           withTask,
                                  bool             asReference = false );

    virtual void * getVirtualSegment( IOByteCount   offset,  /* not supported */
                                      IOByteCount * length );

    IOMemoryDescriptor::withAddress;                         /* not supported */
    IOMemoryDescriptor::withPhysicalAddress;                 /* not supported */
    IOMemoryDescriptor::withPhysicalRanges;                  /* not supported */
    IOMemoryDescriptor::withRanges;                          /* not supported */
    IOMemoryDescriptor::withSubRange;                        /* not supported */

public:

    static IODeblocker * withBlockSize(
                                  UInt64               blockSize,
                                  UInt64               withRequestStart,
                                  IOMemoryDescriptor * withRequestBuffer,
                                  IOStorageCompletion  withRequestCompletion,
                                  void *               withRequestContext );

    virtual bool initWithBlockSize(
                                  UInt64               blockSize,
                                  UInt64               withRequestStart,
                                  IOMemoryDescriptor * withRequestBuffer,
                                  IOStorageCompletion  withRequestCompletion,
                                  void *               withRequestContext );

    virtual IOPhysicalAddress getPhysicalSegment( IOByteCount   offset,
                                                  IOByteCount * length );

    virtual IOReturn prepare(IODirection forDirection = kIODirectionNone);

    virtual IOReturn complete(IODirection forDirection = kIODirectionNone);

    virtual IOByteCount readBytes( IOByteCount offset,
                                   void *      bytes,
                                   IOByteCount withLength );

    virtual IOByteCount writeBytes( IOByteCount  offset,
                                    const void * bytes,
                                    IOByteCount  withLength );

    virtual bool getNextStage(UInt64 * byteStart);

    virtual void getRequestCompletion( IOStorageCompletion * completion,
                                       IOReturn *            status,
                                       UInt64 *              actualByteCount );

    virtual IOMemoryDescriptor * getRequestBuffer();

    virtual void * getRequestContext();
};

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#undef  super
#define super IOMemoryDescriptor
OSDefineMetaClassAndStructors(IODeblocker, IOMemoryDescriptor)

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IODeblocker::initWithAddress( void *      /* address       */ ,
                                   IOByteCount /* withLength    */ ,
                                   IODirection /* withDirection */ )
{
    return false;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IODeblocker::initWithAddress( vm_address_t /* address       */ ,
                                   IOByteCount  /* withLength    */ ,
                                   IODirection  /* withDirection */ ,
                                   task_t       /* withTask      */ )
{
    return false;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IODeblocker::initWithPhysicalAddress(
                                   IOPhysicalAddress /* address       */ ,
                                   IOByteCount       /* withLength    */ ,
                                   IODirection       /* withDirection */ )
{
    return false;
}


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IODeblocker::initWithPhysicalRanges(
                                   IOPhysicalRange * /* ranges        */ ,
                                   UInt32            /* withCount     */ ,
                                   IODirection       /* withDirection */ ,
                                   bool              /* asReference   */ )
{
    return false;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IODeblocker::initWithRanges( IOVirtualRange * /* ranges        */ ,
                                  UInt32           /* withCount     */ ,
                                  IODirection      /* withDirection */ ,
                                  task_t           /* withTask      */ ,
                                  bool             /* asReference   */ )
{
    return false;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IODeblocker * IODeblocker::withBlockSize(
                                  UInt64               blockSize,
                                  UInt64               withRequestStart,
                                  IOMemoryDescriptor * withRequestBuffer,
                                  IOStorageCompletion  withRequestCompletion,
                                  void *               withRequestContext )
{
    //
    // Create a new IODeblocker.
    //

    IODeblocker * me = new IODeblocker;
    
    if ( me && me->initWithBlockSize(
                /* blockSize               */ blockSize,
                /* withRequestStart        */ withRequestStart,
                /* withRequestBuffer       */ withRequestBuffer,
                /* withRequestCompletion   */ withRequestCompletion,
                /* withRequestContext      */ withRequestContext ) == false )
    {
	    me->release();
	    me = 0;
    }

    return me;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IODeblocker::initWithBlockSize(
                                  UInt64               blockSize,
                                  UInt64               withRequestStart,
                                  IOMemoryDescriptor * withRequestBuffer,
                                  IOStorageCompletion  withRequestCompletion,
                                  void *               withRequestContext )
{
    //
    // Initialize an IODeblocker.
    //
    // _excessCountStart = byte count from media boundary to start of request
    // _excessCountFinal = byte count from end of request to a media boundary
    //

    UInt32 excessBufferSize = 0;

    // Ask our superclass' opinion.

    if ( super::init() == false )  return false;

    // Initialize our minimal state.

    _blockSize         = blockSize;
    _chunksCount       = 0;
    _direction         = kIODirectionNone;
    _length            = 0;

    _requestBuffer     = withRequestBuffer;
    _requestBuffer->retain();
    _requestCompletion = withRequestCompletion;
    _requestContext    = withRequestContext;
    _requestCount      = withRequestBuffer->getLength();
    _requestStart      = withRequestStart;

    _excessCountStart  = (withRequestStart                ) % blockSize;
    _excessCountFinal  = (withRequestStart + _requestCount) % blockSize;
    if ( _excessCountFinal )  _excessCountFinal = blockSize - _excessCountFinal;

    _requestIsOneBlock = (_excessCountStart + _requestCount <= blockSize);

    // Determine the necessary size for our scratch buffer.

    switch ( _requestBuffer->getDirection() )
    {
        case kIODirectionIn:                                           // (read)
        {
            excessBufferSize = max(_excessCountStart, _excessCountFinal);
        } break;

        case kIODirectionOut:                                         // (write)
        {
            if ( _excessCountStart )  excessBufferSize += blockSize;
            if ( _excessCountFinal )  excessBufferSize += blockSize;

            // If there is excess both ends of the original request, but both
            // ends reside within the same media block, then we could shorten
            // our buffer size to just one block.

            if ( _excessCountStart && _excessCountFinal && _requestIsOneBlock )
            {
                excessBufferSize -= blockSize;
            }
        } break;

        default:
        {
            assert(0);
        } break;
    }

    // Allocate our scratch buffer.

    if ( excessBufferSize )
    {
        _excessBuffer = IOBufferMemoryDescriptor::withCapacity(
                                         /* capacity      */ excessBufferSize,
                                         /* withDirection */ kIODirectionNone );
        if ( _excessBuffer == 0 )  return false;
    }

    return true;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IODeblocker::free()
{
    //
    // Free all of this object's outstanding resources.
    //

    if ( _requestBuffer )  _requestBuffer->release();
    if ( _excessBuffer )  _excessBuffer->release();

    super::free();
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOReturn IODeblocker::prepare(IODirection forDirection)
{
    //
    // Prepare the memory for an I/O transfer.
    //
    // This involves paging in the memory and wiring it down for the duration
    // of the transfer.  The complete() method finishes the processing of the
    // memory after the I/O transfer finishes.
    //

    unsigned index;
    IOReturn status = kIOReturnInternalError;
    IOReturn statusUndo;

    if ( forDirection == kIODirectionNone )
    {
        forDirection = _direction;
    }

    for ( index = 0; index < _chunksCount; index++ ) 
    {
        status = _chunks[index].buffer->prepare(forDirection);
        if ( status != kIOReturnSuccess )  break;
    }

    if ( status != kIOReturnSuccess )
    {
        for ( unsigned indexUndo = 0; indexUndo <= index; indexUndo++ )
        {
            statusUndo = _chunks[index].buffer->complete(forDirection);
            assert(statusUndo == kIOReturnSuccess);
        }
    }

    return status;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOReturn IODeblocker::complete(IODirection forDirection)
{
    //
    // Complete processing of the memory after an I/O transfer finishes.
    //
    // This method shouldn't be called unless a prepare() was previously issued;
    // the prepare() and complete() must occur in pairs, before and after an I/O
    // transfer.
    //

    IOReturn status;
    IOReturn statusFinal = kIOReturnSuccess;

    if ( forDirection == kIODirectionNone )
    {
        forDirection = _direction;
    }

    for ( unsigned index = 0; index < _chunksCount; index++ ) 
    {
        status = _chunks[index].buffer->complete(forDirection);
        if ( status != kIOReturnSuccess )  statusFinal = status;
        assert(status == kIOReturnSuccess);
    }

    return statusFinal;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOPhysicalAddress IODeblocker::getPhysicalSegment( IOByteCount   offset,
                                                   IOByteCount * length )
{
    //
    // This method returns the physical address of the byte at the given offset
    // into the memory,  and optionally the length of the physically contiguous
    // segment from that offset.
    //

    assert(offset <= _length);

    for ( unsigned index = 0; index < _chunksCount; index++ ) 
    {
        if ( offset < _chunks[index].length )
        {
            IOPhysicalAddress address;
            address = _chunks[index].buffer->getPhysicalSegment(
                                    /* offset */ offset + _chunks[index].offset,
                                    /* length */ length );
            if ( length )  *length = min(*length, _chunks[index].length);
            return address;
        }
        offset -= _chunks[index].length;
    }

    if ( length )  *length = 0;

    return 0;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void * IODeblocker::getVirtualSegment( IOByteCount   /* offset */ ,
                                       IOByteCount * /* length */ )
{
    return 0;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOByteCount IODeblocker::readBytes( IOByteCount offset,
                                    void *      bytes,
                                    IOByteCount withLength )
{
    //
    // Copies data from the memory descriptor's buffer at the given offset, to
    // the specified buffer.  Returns the number of bytes copied.
    //

    IOByteCount bytesCopied = 0;
    unsigned    index;

    for ( index = 0; index < _chunksCount; index++ ) 
    {
        if ( offset < _chunks[index].length )  break;
        offset -= _chunks[index].length;
    }

    for ( ; index < _chunksCount && withLength; index++)
    {
        IOByteCount copy   = min(_chunks[index].length, withLength);
        IOByteCount copied = _chunks[index].buffer->readBytes(
                                    /* offset */ offset + _chunks[index].offset,
                                    /* bytes  */ bytes,
                                    /* length */ copy );

        bytesCopied += copied;
        if ( copied != copy )  break;

        bytes = ((UInt8 *) bytes) + copied;
        withLength -= copied;
        offset = 0;
    }

    return bytesCopied;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOByteCount IODeblocker::writeBytes( IOByteCount  offset,
                                     const void * bytes,
                                     IOByteCount  withLength )
{
    //
    // Copies data to the memory descriptor's buffer at the given offset, from
    // the specified buffer.  Returns the number of bytes copied.
    //

    IOByteCount bytesCopied = 0;
    unsigned    index;

    for ( index = 0; index < _chunksCount; index++ ) 
    {
        if ( offset < _chunks[index].length )  break;
        offset -= _chunks[index].length;
    }

    for ( ; index < _chunksCount && withLength; index++)
    {
        IOByteCount copy   = min(_chunks[index].length, withLength);
        IOByteCount copied = _chunks[index].buffer->writeBytes(
                                    /* offset */ offset + _chunks[index].offset,
                                    /* bytes  */ bytes,
                                    /* length */ copy );

        bytesCopied += copied;
        if ( copied != copy )  break;

        bytes = ((UInt8 *) bytes) + copied;
        withLength -= copied;
        offset = 0;
    }

    return bytesCopied;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IODeblocker::getNextStage(UInt64 * byteStart)
{
    //
    // Obtain the next stage of the transfer.   The transfer buffer will be the
    // deblocker object itself and the byte start will be returned in byteStart.
    //
    // This method must not be called if the current stage failed with an error
    // or a short byte count, but instead getRequestCompletion() must be called
    // to adjust the status and actual byte count (with respect to the original
    // request) and return the original request's completion routine.  The same
    // call to getRequestCompletion() should also be done if the getNextStage()
    // method returns false.
    //

    _chunksCount = 0;
    _direction   = kIODirectionNone;
    _length      = 0;

    switch ( _requestBuffer->getDirection() )
    {
        case kIODirectionIn:                                           // (read)
        {
            switch ( _stage )
            {
                case kStageInit:
                {
                    _stage     = kStageLast;
                    _excessBuffer->setDirection(kIODirectionIn);
                    _direction = kIODirectionIn;
                    *byteStart = _requestStart - _excessCountStart;

                    if ( _excessCountStart )
                    {
                        _chunks[_chunksCount].buffer = _excessBuffer;
                        _chunks[_chunksCount].offset = 0;
                        _chunks[_chunksCount].length = _excessCountStart;
                        _chunksCount++;
                    }

                    _chunks[_chunksCount].buffer = _requestBuffer;
                    _chunks[_chunksCount].offset = 0;
                    _chunks[_chunksCount].length = _requestBuffer->getLength();
                    _chunksCount++;

                    if ( _excessCountFinal )
                    {
                        _chunks[_chunksCount].buffer = _excessBuffer;
                        _chunks[_chunksCount].offset = 0;
                        _chunks[_chunksCount].length = _excessCountFinal;
                        _chunksCount++;
                    }
                } break;

                case kStageLast:
                {
                    _stage = kStageDone;
                } break;

                default:
                {
                    assert(0);
                } break;
            } // (switch)
        } break;

        case kIODirectionOut:                                         // (write)
        {
            switch ( _stage )
            {
                case kStageInit:
                {
                    if ( _excessCountStart )
                    {
                        _stage = kStagePrepareExcessStart;
                        _excessBuffer->setDirection(kIODirectionIn);
                        _direction = kIODirectionIn;
                        *byteStart = _requestStart - _excessCountStart;

                        _chunks[_chunksCount].buffer = _excessBuffer;
                        _chunks[_chunksCount].offset = 0;
                        _chunks[_chunksCount].length = _blockSize;
                        _chunksCount++;
                        break;
                    } 
                } // (fall thru)

                case kStagePrepareExcessStart:
                {
                    if ( _excessCountFinal )
                    {
                        // We do not issue this stage if the original transfer
                        // resides within one media block, and we already read
                        // that block into our buffer in the previous stage.

                        if ( !_excessCountStart || !_requestIsOneBlock )
                        {
                            _stage = kStagePrepareExcessFinal;
                            _excessBuffer->setDirection(kIODirectionIn);
                            _direction = kIODirectionIn;
                            *byteStart = _requestStart + _requestCount +
                                         _excessCountFinal - _blockSize;

                            _chunks[_chunksCount].buffer = _excessBuffer;
                            _chunks[_chunksCount].offset = (_requestIsOneBlock)
                                                           ? 0
                                                           : (_excessCountStart)
                                                             ? _blockSize
                                                             : 0;
                            _chunks[_chunksCount].length = _blockSize;
                            _chunksCount++;
                            break;
                        }
                    }
                } // (fall thru)

                case kStagePrepareExcessFinal:
                {
                    _stage     = kStageLast;
                    _excessBuffer->setDirection(kIODirectionOut);
                    _direction = kIODirectionOut;
                    *byteStart = _requestStart - _excessCountStart;

                    if ( _excessCountStart )
                    {
                        _chunks[_chunksCount].buffer = _excessBuffer;
                        _chunks[_chunksCount].offset = 0;
                        _chunks[_chunksCount].length = _excessCountStart;
                        _chunksCount++;
                    }

                    _chunks[_chunksCount].buffer = _requestBuffer;
                    _chunks[_chunksCount].offset = 0;
                    _chunks[_chunksCount].length = _requestBuffer->getLength();
                    _chunksCount++;

                    if ( _excessCountFinal )
                    {
                        _chunks[_chunksCount].buffer = _excessBuffer;
                        _chunks[_chunksCount].offset = (_requestIsOneBlock)
                                                       ? 0
                                                       : (_excessCountStart)
                                                         ? _blockSize
                                                         : 0;
                        _chunks[_chunksCount].offset += ( _blockSize -
                                                          _excessCountFinal );
                        _chunks[_chunksCount].length = _excessCountFinal;
                        _chunksCount++;
                    }
                } break;

                case kStageLast:
                {
                    _stage = kStageDone;
                } break;

                default:
                {
                    assert(0);
                } break;
            } // (switch)
        } break;

        default:
        {
            assert(0);
        } break;
    } // (switch)

    // Determine whether we have an abort or completion condition.

    if ( _chunksCount == 0 )  return false;

    // Compute the total length of the descriptor over all chunks.

    for ( unsigned index = 0; index < _chunksCount; index++ )
    {
        _length += _chunks[index].length;
    }

    return true;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IODeblocker::getRequestCompletion( IOStorageCompletion * completion,
                                        IOReturn *            status,
                                        UInt64 *              actualByteCount )
{
    //
    // Obtain the completion information for the original request, taking
    // into account the status and actual byte count of the current stage. 
    //

    *completion = _requestCompletion;

    switch ( _stage )
    {
        case kStageInit:                                       // (inital stage)
        {
            *status = kIOReturnInternalError;
            *actualByteCount = 0;
        } break;

        case kStagePrepareExcessStart:              // (write preparation stage)
        case kStagePrepareExcessFinal:
        {
            *actualByteCount = 0;
        } break;

        case kStageLast:                                         // (last stage)
        case kStageDone:
        {
            if ( *actualByteCount > _excessCountStart )
                *actualByteCount -= _excessCountStart;
            else
                *actualByteCount = 0;

            if ( *actualByteCount > _requestBuffer->getLength() )
                *actualByteCount = _requestBuffer->getLength();
        } break;

        default:
        {
            assert(0);
        } break;
    }
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOMemoryDescriptor * IODeblocker::getRequestBuffer()
{
    //
    // Obtain the buffer for the original request. 
    //

    return _requestBuffer;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void * IODeblocker::getRequestContext()
{
    //
    // Obtain the context for the original request. 
    //

    return _requestContext;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IOBlockStorageDriver::deblockRequest(
                                     UInt64                          byteStart,
                                     IOMemoryDescriptor *            buffer,
                                     IOStorageCompletion             completion,
                                     IOBlockStorageDriver::Context * context )
{
    //
    // The deblockRequest method checks to see if the incoming request rests
    // on the media's block boundaries, and if not, deblocks it.  Deblocking
    // involves rounding out the request to the nearest block boundaries and
    // transferring the excess bytes into a scratch buffer.
    //
    // This method is part of a sequence of methods invoked for each read/write
    // request.  The first is prepareRequest, which allocates and prepares some
    // context for the transfer; the second is deblockRequest, which aligns the
    // transfer at the media block boundaries; and the third is executeRequest,
    // which implements the actual transfer from the block storage device.
    //
    // The current implementation of deblockRequest is asynchronous.
    //

    IODeblocker * deblocker;

    // If the request is aligned with the media's block boundaries, we
    // do short-circuit the deblocker and call executeRequest directly.

    if ( (byteStart           % context->block.size) == 0 &&
         (buffer->getLength() % context->block.size) == 0 )
    {
        executeRequest(byteStart, buffer, completion, context);
        return;
    }

    // Build a deblocker object.

    deblocker = IODeblocker::withBlockSize(
                                /* blockSize             */ context->block.size,
                                /* withRequestStart      */ byteStart,
                                /* withRequestBuffer     */ buffer,
                                /* withRequestCompletion */ completion,
                                /* withRequestContext    */ context );

    if ( deblocker == 0 )
    {
        complete(completion, kIOReturnNoMemory);
        return;
    }

    // This implementation of the deblocker permits only one read-modify-write
    // at any given time.  Note that other write requests can, and do, proceed
    // simultaneously so long as they do not require the deblocker -- refer to
    // the read() and the write() routines for the short-cut logic.
    //
    // Note that the original buffer during a read-modify-write operation must
    // be prepared on the client's thread, that is, right now, or else it will
    // happen on the controller's thread after the read stage(s) complete, and
    // this is bad (causes deadlock if that controller was the swap device).

    if ( buffer->getDirection() == kIODirectionOut )
    {
        if ( buffer->prepare() != kIOReturnSuccess )
        {
            deblocker->release();
            complete(completion, kIOReturnNoMemory);
            return;
        }

        IOLockLock(_deblockRequestWriteLock);
    }

    // Execute the transfer (for the next stage).

    deblockRequestCompletion(this, deblocker, kIOReturnSuccess, 0);

    return;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IOBlockStorageDriver::deblockRequestCompletion( void *   target,
                                                     void *   parameter,
                                                     IOReturn status,
                                                     UInt64   actualByteCount )
{
    //
    // This is the completion routine for the aligned deblocker subrequests.
    // It verifies the success of the just-completed stage,  transitions to
    // the next stage, then builds and issues a transfer for the next stage.
    //

    UInt64                 byteStart;
    IOStorageCompletion    completion;
    Context *              context;
    IODeblocker *          deblocker = (IODeblocker          *) parameter;
    IOBlockStorageDriver * driver    = (IOBlockStorageDriver *) target;

    // Determine whether an error occurred or whether there are no more stages.

    if ( actualByteCount                      < deblocker->getLength() ||
         status                              != kIOReturnSuccess       ||
         deblocker->getNextStage(&byteStart) == false                  )
    {
        // Unlock the write-lock in order to allow the next write to proceed.

        if ( deblocker->getRequestBuffer()->getDirection() == kIODirectionOut )
        {
            IOLockUnlock(driver->_deblockRequestWriteLock);

            deblocker->getRequestBuffer()->complete();
        }

        // Obtain the completion information for the original request, taking
        // into account the status and actual byte count of the current stage. 

        deblocker->getRequestCompletion(&completion, &status, &actualByteCount);

        // Complete the original request.

        IOStorage::complete(completion, status, actualByteCount);

        // Release our resources.

        deblocker->release();

        return;
    }

    // Execute the transfer (for the next stage).

    completion.target    = driver;
    completion.action    = deblockRequestCompletion;
    completion.parameter = deblocker;

    context = (Context *) deblocker->getRequestContext();

    driver->executeRequest(byteStart, deblocker, completion, context);

    return;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOBlockStorageDriver,  0);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOBlockStorageDriver,  1);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOBlockStorageDriver,  2);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOBlockStorageDriver,  3);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOBlockStorageDriver,  4);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOBlockStorageDriver,  5);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOBlockStorageDriver,  6);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOBlockStorageDriver,  7);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOBlockStorageDriver,  8);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOBlockStorageDriver,  9);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOBlockStorageDriver, 10);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOBlockStorageDriver, 11);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOBlockStorageDriver, 12);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOBlockStorageDriver, 13);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOBlockStorageDriver, 14);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOBlockStorageDriver, 15);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOBlockStorageDriver, 16);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOBlockStorageDriver, 17);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOBlockStorageDriver, 18);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOBlockStorageDriver, 19);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOBlockStorageDriver, 20);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOBlockStorageDriver, 21);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOBlockStorageDriver, 22);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOBlockStorageDriver, 23);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOBlockStorageDriver, 24);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOBlockStorageDriver, 25);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOBlockStorageDriver, 26);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOBlockStorageDriver, 27);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOBlockStorageDriver, 28);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOBlockStorageDriver, 29);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOBlockStorageDriver, 30);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOBlockStorageDriver, 31);
