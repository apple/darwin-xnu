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

/*!
 * @header IOBlockStorageDriver
 * @abstract
 * This header contains the IOBlockStorageDriver class definition.
 */

#ifndef _IOBLOCKSTORAGEDRIVER_H
#define _IOBLOCKSTORAGEDRIVER_H

/*!
 * @defined kIOBlockStorageDriverClass
 * @abstract
 * kIOBlockStorageDriverClass is the name of the IOBlockStorageDriver class.
 * @discussion
 * kIOBlockStorageDriverClass is the name of the IOBlockStorageDriver class.
 */

#define kIOBlockStorageDriverClass "IOBlockStorageDriver"

/*!
 * @defined kIOBlockStorageDriverStatisticsKey
 * @abstract
 * This property holds a table of numeric values describing the driver's
 * operating statistics.
 * @discussion
 * This property holds a table of numeric values describing the driver's
 * operating statistics.  The table is an OSDictionary, where each entry
 * describes one given statistic.
 */
 
#define kIOBlockStorageDriverStatisticsKey "Statistics"

/*!
 * @defined kIOBlockStorageDriverStatisticsBytesReadKey
 * @abstract
 * This property describes the number of bytes read since the block storage
 * driver was instantiated.  It is one of the statistic entries listed under
 * the top-level kIOBlockStorageDriverStatisticsKey property table.
 * @discussion
 * This property describes the number of bytes read since the block storage
 * driver was instantiated.  It is one of the statistic entries listed under
 * the top-level kIOBlockStorageDriverStatisticsKey property table.  It has
 * an OSNumber value.
 */

#define kIOBlockStorageDriverStatisticsBytesReadKey "Bytes (Read)"

/*!
 * @defined kIOBlockStorageDriverStatisticsBytesWrittenKey
 * @abstract
 * This property describes the number of bytes written since the block storage
 * driver was instantiated.  It is one of the statistic entries listed under the
 * top-level kIOBlockStorageDriverStatisticsKey property table.
 * @discussion
 * This property describes the number of bytes written since the block storage
 * driver was instantiated.  It is one of the statistic entries listed under the
 * top-level kIOBlockStorageDriverStatisticsKey property table.  It has an
 * OSNumber value.
 */

#define kIOBlockStorageDriverStatisticsBytesWrittenKey "Bytes (Write)"

/*!
 * @defined kIOBlockStorageDriverStatisticsReadErrorsKey
 * @abstract
 * This property describes the number of read errors encountered since the block
 * storage driver was instantiated.  It is one of the statistic entries listed
 * under the top-level kIOBlockStorageDriverStatisticsKey property table.
 * @discussion
 * This property describes the number of read errors encountered since the block
 * storage driver was instantiated.  It is one of the statistic entries listed
 * under the top-level kIOBlockStorageDriverStatisticsKey property table.  It
 * has an OSNumber value.
 */

#define kIOBlockStorageDriverStatisticsReadErrorsKey "Errors (Read)"

/*!
 * @defined kIOBlockStorageDriverStatisticsWriteErrorsKey
 * @abstract
 * This property describes the number of write errors encountered since the
 * block storage driver was instantiated.  It is one of the statistic entries
 * listed under the top-level kIOBlockStorageDriverStatisticsKey property table.
 * @discussion
 * This property describes the number of write errors encountered since the
 * block storage driver was instantiated.  It is one of the statistic entries
 * listed under the top-level kIOBlockStorageDriverStatisticsKey property table. 
 * It has an OSNumber value.
 */

#define kIOBlockStorageDriverStatisticsWriteErrorsKey "Errors (Write)"

/*!
 * @defined kIOBlockStorageDriverStatisticsLatentReadTimeKey
 * @abstract
 * This property describes the number of nanoseconds of latency during reads
 * since the block storage driver was instantiated.  It is one of the statistic
 * entries listed under the top-level kIOBlockStorageDriverStatisticsKey
 * property table. 
 * @discussion
 * This property describes the number of nanoseconds of latency during reads
 * since the block storage driver was instantiated.  It is one of the statistic
 * entries listed under the top-level kIOBlockStorageDriverStatisticsKey
 * property table.  It has an OSNumber value.
 */

#define kIOBlockStorageDriverStatisticsLatentReadTimeKey "Latency Time (Read)"

/*!
 * @defined kIOBlockStorageDriverStatisticsLatentWriteTimeKey
 * @abstract
 * This property describes the number of nanoseconds of latency during writes
 * since the block storage driver was instantiated.  It is one of the statistic
 * entries listed under the top-level kIOBlockStorageDriverStatisticsKey
 * property table. 
 * @discussion
 * This property describes the number of nanoseconds of latency during writes
 * since the block storage driver was instantiated.  It is one of the statistic
 * entries listed under the top-level kIOBlockStorageDriverStatisticsKey
 * property table.  It has an OSNumber value.
 */

#define kIOBlockStorageDriverStatisticsLatentWriteTimeKey "Latency Time (Write)"

/*!
 * @defined kIOBlockStorageDriverStatisticsReadsKey
 * @abstract
 * This property describes the number of read operations processed since the
 * block storage driver was instantiated.  It is one of the statistic entries
 * listed under the top-level kIOBlockStorageDriverStatisticsKey property table.
 * @discussion
 * This property describes the number of read operations processed since the
 * block storage driver was instantiated.  It is one of the statistic entries
 * listed under the top-level kIOBlockStorageDriverStatisticsKey property table.
 * It has an OSNumber value.
 */

#define kIOBlockStorageDriverStatisticsReadsKey "Operations (Read)"

/*!
 * @defined kIOBlockStorageDriverStatisticsWritesKey
 * @abstract
 * This property describes the number of write operations processed since the
 * block storage driver was instantiated.  It is one of the statistic entries
 * listed under the top-level kIOBlockStorageDriverStatisticsKey property table.
 * @discussion
 * This property describes the number of write operations processed since the
 * block storage driver was instantiated.  It is one of the statistic entries
 * listed under the top-level kIOBlockStorageDriverStatisticsKey property table.
 * It has an OSNumber value.
 */

#define kIOBlockStorageDriverStatisticsWritesKey "Operations (Write)"

/*!
 * @defined kIOBlockStorageDriverStatisticsReadRetriesKey
 * @abstract
 * This property describes the number of read retries required since the block
 * storage driver was instantiated.  It is one of the statistic entries listed
 * under the top-level kIOBlockStorageDriverStatisticsKey property table.
 * @discussion
 * This property describes the number of read retries required since the block
 * storage driver was instantiated.  It is one of the statistic entries listed
 * under the top-level kIOBlockStorageDriverStatisticsKey property table.  It
 * has an OSNumber value.
 */

#define kIOBlockStorageDriverStatisticsReadRetriesKey "Retries (Read)"

/*!
 * @defined kIOBlockStorageDriverStatisticsWriteRetriesKey
 * @abstract
 * This property describes the number of write retries required since the block
 * storage driver was instantiated.  It is one of the statistic entries listed
 * under the top-level kIOBlockStorageDriverStatisticsKey property table.  It
 * has an OSNumber value.
 * @discussion
 * This property describes the number of write retries required since the block
 * storage driver was instantiated.  It is one of the statistic entries listed
 * under the top-level kIOBlockStorageDriverStatisticsKey property table.  It
 * has an OSNumber value.
 */

#define kIOBlockStorageDriverStatisticsWriteRetriesKey "Retries (Write)"

/*!
 * @defined kIOBlockStorageDriverStatisticsTotalReadTimeKey
 * @abstract
 * This property describes the number of nanoseconds spent performing reads
 * since the block storage driver was instantiated.  It is one of the statistic
 * entries listed under the top-level kIOBlockStorageDriverStatisticsKey
 * property table.
 * @discussion
 * This property describes the number of nanoseconds spent performing reads
 * since the block storage driver was instantiated.  It is one of the statistic
 * entries listed under the top-level kIOBlockStorageDriverStatisticsKey
 * property table.  It has an OSNumber value.
 */

#define kIOBlockStorageDriverStatisticsTotalReadTimeKey "Total Time (Read)"

/*!
 * @defined kIOBlockStorageDriverStatisticsTotalWriteTimeKey
 * @abstract
 * This property describes the number of nanoseconds spent performing writes
 * since the block storage driver was instantiated.  It is one of the statistic
 * entries listed under the top-level kIOBlockStorageDriverStatisticsKey
 * property table.
 * @discussion
 * This property describes the number of nanoseconds spent performing writes
 * since the block storage driver was instantiated.  It is one of the statistic
 * entries listed under the top-level kIOBlockStorageDriverStatisticsKey
 * property table.  It has an OSNumber value.
 */

#define kIOBlockStorageDriverStatisticsTotalWriteTimeKey "Total Time (Write)"

/*!
 * @enum IOMediaState
 * @discussion
 * The different states that getMediaState() can report.
 * @constant kIOMediaStateOffline
 * Media is not available.
 * @constant kIOMediaStateOnline
 * Media is available and ready for operations.
 * @constant kIOMediaStateBusy
 * Media is available, but not ready for operations.
 */

typedef UInt32 IOMediaState;

#define kIOMediaStateOffline 0
#define kIOMediaStateOnline  1
#define kIOMediaStateBusy    2

/*
 * Kernel
 */

#if defined(KERNEL) && defined(__cplusplus)

#include <IOKit/storage/IOBlockStorageDevice.h>
#include <IOKit/storage/IOMedia.h>
#include <IOKit/storage/IOStorage.h>
#include <kern/thread_call.h>

/*!
 * @class IOBlockStorageDriver
 * @abstract
 * The IOBlockStorageDriver class is the common base class for generic block
 * storage drivers.  It matches and communicates via an IOBlockStorageDevice
 * interface, and connects to the remainder of the storage framework via the
 * IOStorage protocol.
 * @discussion
 * The IOBlockStorageDriver class is the common base class for generic block
 * storage drivers.  It matches and communicates via an IOBlockStorageDevice
 * interface, and connects to the remainder of the storage framework via the
 * IOStorage protocol. It extends the IOStorage protocol by implementing the
 * appropriate open and close semantics, deblocking for unaligned transfers,
 * polling for ejectable media, locking and ejection policies, media object
 * creation and teardown, and statistics gathering and reporting.
 *
 * Block storage drivers are split into two parts: the generic driver handles
 * all generic device issues, independent of the lower-level transport
 * mechanism (e.g. SCSI, ATA, USB, FireWire). All storage operations
 * at the generic driver level are translated into a series of generic
 * device operations. These operations are passed via the IOBlockStorageDevice
 * nub to a transport driver, which implements the appropriate
 * transport-dependent protocol to execute these operations.
 *
 * To determine the write-protect state of a device (or media), for
 * example, the generic driver would issue a call to the
 * Transport Driver's reportWriteProtection method. If this were a SCSI
 * device, its transport driver would issue a Mode Sense command to
 * extract the write-protection status bit. The transport driver then
 * reports true or false to the generic driver.
 * 
 * The generic driver therefore has no knowledge of, or involvement
 * with, the actual commands and mechanisms used to communicate with
 * the device. It is expected that the generic driver will rarely, if
 * ever, need to be subclassed to handle device idiosyncrasies; rather,
 * the transport driver should be changed via overrides.
 * 
 * A generic driver could be subclassed to create a different type of
 * generic device. The generic driver IOCDBlockStorageDriver class is
 * a subclass of IOBlockStorageDriver, adding CD functions.
 */

class IOBlockStorageDriver : public IOStorage
{
    OSDeclareDefaultStructors(IOBlockStorageDriver);

public:

    /*!
     * @enum Statistics
     * @discussion
     * Indices for the different statistics that getStatistics() can report.
     * @constant kStatisticsReads
     * Number of read operations thus far.
     * @constant kStatisticsBytesRead
     * Number of bytes read thus far.
     * @constant kStatisticsTotalReadTime
     * Nanoseconds spent performing reads thus far.
     * @constant kStatisticsLatentReadTime
     * Nanoseconds of latency during reads thus far.
     * @constant kStatisticsReadRetries
     * Number of read retries thus far.
     * @constant kStatisticsReadErrors
     * Number of read errors thus far.
     * @constant kStatisticsWrites
     * Number of write operations thus far.
     * @constant kStatisticsSingleBlockWrites
     * Number of write operations for a single block thus far.
     * @constant kStatisticsBytesWritten
     * Number of bytes written thus far.
     * @constant kStatisticsTotalWriteTime
     * Nanoseconds spent performing writes thus far.
     * @constant kStatisticsLatentWriteTime
     * Nanoseconds of latency during writes thus far.
     * @constant kStatisticsWriteRetries
     * Number of write retries thus far.
     * @constant kStatisticsWriteErrors
     * Number of write errors thus far.
     */

    enum Statistics
    {
        kStatisticsReads,
        kStatisticsBytesRead,
        kStatisticsTotalReadTime,
        kStatisticsLatentReadTime,
        kStatisticsReadRetries,
        kStatisticsReadErrors,

        kStatisticsWrites,
        kStatisticsSingleBlockWrites,
        kStatisticsBytesWritten,
        kStatisticsTotalWriteTime,
        kStatisticsLatentWriteTime,
        kStatisticsWriteRetries,
        kStatisticsWriteErrors
    };

    static const UInt32 kStatisticsCount = kStatisticsWriteErrors + 1;

protected:

    struct ExpansionData { /* */ };
    ExpansionData * _expansionData;

    OSSet *         _openClients;
    OSNumber *      _statistics[kStatisticsCount];

    /*
     * @struct Context
     * @discussion
     * Context structure for a read/write operation.  It describes the block size,
     * and where applicable, a block type and block sub-type, for a data transfer,
     * as well as the completion information for the original request.  Note that
     * the block type field is unused in the IOBlockStorageDriver class.
     * @field block.size
     * Block size for the operation.
     * @field block.type
     * Block type for the operation.  Unused in IOBlockStorageDriver.  The default
     * value for this field is IOBlockStorageDriver::kBlockTypeStandard.
     * @field block.typeSub
     * Block sub-type for the operation.  It's definition depends on block.type.
     * Unused in IOBlockStorageDriver.
     * @field original.byteStart
     * Starting byte offset for the data transfer.
     * @param original.buffer
     * Buffer for the data transfer.  The size of the buffer implies the size of
     * the data transfer.
     * @param original.completion
     * Completion routine to call once the data transfer is complete.
     */

    struct Context
    {
        struct
        {
            UInt32               size;
            UInt8                type;
            UInt8                typeSub[3];
        } block;
    
        struct
        {
            UInt64               byteStart;
            IOMemoryDescriptor * buffer;
            IOStorageCompletion  completion;
        } original;
        
        UInt32 reserved[8];
    };

    static const UInt8 kBlockTypeStandard = 0x00;

    /*
     * Free all of this object's outstanding resources.
     *
     * This method's implementation is not typically overidden.
     */

    void free();

    /*!
     * @function handleOpen
     * @discussion
     * The handleOpen method grants or denies permission to access this object
     * to an interested client.  The argument is an IOStorageAccess value that
     * specifies the level of access desired -- reader or reader-writer.
     *
     * This method can be invoked to upgrade or downgrade the access level for
     * an existing client as well.  The previous access level will prevail for
     * upgrades that fail, of course.   A downgrade should never fail.  If the
     * new access level should be the same as the old for a given client, this
     * method will do nothing and return success.  In all cases, one, singular
     * close-per-client is expected for all opens-per-client received.
     *
     * This implementation replaces the IOService definition of handleIsOpen().
     * @param client
     * Client requesting the open.
     * @param options
     * Options for the open.  Set to zero.
     * @param access
     * Access level for the open.  Set to kIOStorageAccessReader or
     * kIOStorageAccessReaderWriter.
     * @result
     * Returns true if the open was successful, false otherwise.
     */

    virtual bool handleOpen(IOService *  client,
                            IOOptionBits options,
                            void *       access);

    /*!
     * @function handleIsOpen
     * @discussion
     * The handleIsOpen method determines whether the specified client, or any
     * client if none is specificed, presently has an open on this object.
     *
     * This implementation replaces the IOService definition of handleIsOpen().
     * @param client
     * Client to check the open state of.  Set to zero to check the open state
     * of all clients.
     * @result
     * Returns true if the client was (or clients were) open, false otherwise.
     */

    virtual bool handleIsOpen(const IOService * client) const;

    /*!
     * @function handleClose
     * @discussion
     * The handleClose method closes the client's access to this object.
     *
     * This implementation replaces the IOService definition of handleIsOpen().
     * @param client
     * Client requesting the close.
     * @param options
     * Options for the close.  Set to zero.
     */

    virtual void handleClose(IOService * client, IOOptionBits options);

    /*!
     * @function addToBytesTransferred
     * @discussion
     * Update the total number of bytes transferred, the total transfer time,
     * and the total latency time -- used for statistics.
     *
     * This method's implementation is not typically overidden.
     * @param bytesTransferred
     * Number of bytes transferred in this operation.
     * @param totalTime
     * Nanoseconds spent performing this operation.
     * @param latentTime
     * Nanoseconds of latency during this operation.
     * @param isWrite
     * Indicates whether this operation was a write, otherwise is was a read.
     */

    virtual void addToBytesTransferred(UInt64 bytesTransferred,
                                       UInt64 totalTime,
                                       UInt64 latentTime,
                                       bool   isWrite);

    /*!
     * @function incrementErrors
     * @discussion
     * Update the total error count -- used for statistics.
     *
     * This method's implementation is not typically overidden.
     * @param isWrite
     * Indicates whether this operation was a write, otherwise is was a read.
     */

    virtual void incrementErrors(bool isWrite);

    /*!
     * @function incrementRetries
     * @discussion
     * Update the total retry count -- used for statistics.
     *
     * This method's implementation is not typically overidden.
     * @param isWrite
     * Indicates whether this operation was a write, otherwise is was a read.
     */

    virtual void incrementRetries(bool isWrite);

    /*!
     * @function allocateContext
     * @discussion
     * Allocate a context structure for a read/write operation.
     * @result
     * Context structure.
     */

    virtual Context * allocateContext();

    /*!
     * @function deleteContext
     * @discussion
     * Delete a context structure from a read/write operation.
     * @param context
     * Context structure to be deleted.
     */

    virtual void deleteContext(Context * context);

    /*!
     * @function prepareRequest
     * @discussion
     * The prepareRequest method allocates and prepares state for the transfer.
     *
     * This method is part of a sequence of methods invoked for each read/write
     * request.  The first is prepareRequest, which allocates and prepares some
     * context for the transfer; the second is deblockRequest, which aligns the
     * transfer at the media block boundaries; and the third is executeRequest,
     * which implements the actual transfer from the block storage device.
     *
     * This method's implementation is not typically overidden.
     * @param byteStart
     * Starting byte offset for the data transfer.
     * @param buffer
     * Buffer for the data transfer.  The size of the buffer implies the size of
     * the data transfer.
     * @param completion
     * Completion routine to call once the data transfer is complete.
     */

    virtual void prepareRequest(UInt64               byteStart,
                                IOMemoryDescriptor * buffer,
                                IOStorageCompletion  completion);

    /*!
     * @function deblockRequest
     * @discussion
     * The deblockRequest method checks to see if the incoming request rests
     * on the media's block boundaries, and if not, deblocks it.  Deblocking
     * involves rounding out the request to the nearest block boundaries and
     * transferring the excess bytes into a scratch buffer.
     *
     * This method is part of a sequence of methods invoked for each read/write
     * request.  The first is prepareRequest, which allocates and prepares some
     * context for the transfer; the second is deblockRequest, which aligns the
     * transfer at the media block boundaries; and the third is executeRequest,
     * which implements the actual transfer from the block storage device.
     *
     * This method's implementation is not typically overidden.
     * @param byteStart
     * Starting byte offset for the data transfer.
     * @param buffer
     * Buffer for the data transfer.  The size of the buffer implies the size of
     * the data transfer.
     * @param completion
     * Completion routine to call once the data transfer is complete.
     * @param context
     * Additional context information for the data transfer (eg. block size).
     */

    virtual void deblockRequest(UInt64               byteStart,
                                IOMemoryDescriptor * buffer,
                                IOStorageCompletion  completion,
                                Context *            context);

    /*!
     * @function executeRequest
     * @discussion
     * Execute an asynchrnous storage request.  The request is guaranteed to be
     * block-aligned.
     *
     * This method is part of a sequence of methods invoked for each read/write
     * request.  The first is prepareRequest, which allocates and prepares some
     * context for the transfer; the second is deblockRequest, which aligns the
     * transfer at the media block boundaries; and the third is executeRequest,
     * which implements the actual transfer from the block storage device.
     * @param byteStart
     * Starting byte offset for the data transfer.
     * @param buffer
     * Buffer for the data transfer.  The size of the buffer implies the size of
     * the data transfer.
     * @param completion
     * Completion routine to call once the data transfer is complete.
     * @param context
     * Additional context information for the data transfer (eg. block size).
     */

    virtual void executeRequest(UInt64               byteStart,
                                IOMemoryDescriptor * buffer,
                                IOStorageCompletion  completion,
                                Context *            context);

    /*!
     * @function handleStart
     * @discussion
     * Prepare the block storage driver for operation.
     *
     * This is where a media object needs to be created for fixed media, and
     * optionally for removable media.
     *
     * Note that this method is called from within the start() routine;
     * if this method returns successfully,  it should be prepared to accept
     * any of IOBlockStorageDriver's APIs.
     * @param provider
     * This object's provider.
     * @result
     * Returns true on success, false otherwise.
     */

    virtual bool handleStart(IOService * provider);

    /*!
     * @function handleYield
     * @discussion
     * Stop the block storage driver.
     *
     * This method is called as a result of the kIOMessageServiceIsTerminated
     * or kIOMessageServiceIsRequestingClose provider messages.  The argument
     * is passed in as-is from the message.  The kIOServiceRequired option is
     * set for the kIOMessageServiceIsTerminated message to indicate that the
     * yield must succeed.
     *
     * This is where the driver should clean up its state in preparation for
     * removal from the system.  This implementation issues a synchronize cache
     * operation, if the media is writable, and then ejects the media.
     *
     * Note that this method is called from within the yield() routine.
     *
     * This method is called with the arbitration lock held.
     * @param provider
     * This object's provider.
     */

    virtual bool handleYield(IOService *  provider,
                             IOOptionBits options  = 0,
                             void *       argument = 0);


    /*!
     * @function getMediaBlockSize
     * @discussion
     * Ask the driver about the media's natural block size.
     * @result
     * Natural block size, in bytes.
     */

    virtual UInt64 getMediaBlockSize() const;

public:

///m:2333367:workaround:commented:start
//  using read;
//  using write;
///m:2333367:workaround:commented:stop

    /*
     * Initialize this object's minimal state.
     *
     * This method's implementation is not typically overidden.
     */

    virtual bool init(OSDictionary * properties = 0);

    /*
     * This method is called once we have been attached to the provider object.
     *
     * This method's implementation is not typically overidden.
     */

    virtual bool start(IOService * provider);

    /*
     * This method is called as a result of the kIOMessageServiceIsTerminated
     * or kIOMessageServiceIsRequestingClose provider messages.  The argument
     * is passed in as-is from the message.  The kIOServiceRequired option is
     * set for the kIOMessageServiceIsTerminated message to indicate that the
     * yield must succeed.
     *
     * This method is called with the arbitration lock held.
     *
     * This method's implementation is not typically overidden.
     */

    virtual bool yield(IOService *  provider,
                       IOOptionBits options  = 0,
                       void *       argument = 0);

    /*!
     * @function read
     * @discussion
     * The read method is the receiving end for all read requests from the
     * storage framework (through the media object created by this driver).
     *
     * This method kicks off a sequence of three methods for each read or write
     * request.  The first is prepareRequest, which allocates and prepares some
     * context for the transfer; the second is deblockRequest, which aligns the
     * transfer at the media block boundaries; and the third is executeRequest,
     * which implements the actual transfer from the block storage device.
     *
     * This method's implementation is not typically overidden.
     * @param client
     * Client requesting the read.
     * @param byteStart
     * Starting byte offset for the data transfer.
     * @param buffer
     * Buffer for the data transfer.  The size of the buffer implies the size of
     * the data transfer.
     * @param completion
     * Completion routine to call once the data transfer is complete.
     */

    virtual void read(IOService *          client,
                      UInt64               byteStart,
                      IOMemoryDescriptor * buffer,
                      IOStorageCompletion  completion);

    /*!
     * @function write
     * @discussion
     * The write method is the receiving end for all write requests from the
     * storage framework (through the media object created by this driver).
     *
     * This method kicks off a sequence of three methods for each read or write
     * request.  The first is prepareRequest, which allocates and prepares some
     * context for the transfer; the second is deblockRequest, which aligns the
     * transfer at the media block boundaries; and the third is executeRequest,
     * which implements the actual transfer from the block storage device.
     *
     * This method's implementation is not typically overidden.
     * @param client
     * Client requesting the write.
     * @param byteStart
     * Starting byte offset for the data transfer.
     * @param buffer
     * Buffer for the data transfer.  The size of the buffer implies the size of
     * the data transfer.
     * @param completion
     * Completion routine to call once the data transfer is complete.
     */

    virtual void write(IOService *          client,
                       UInt64               byteStart,
                       IOMemoryDescriptor * buffer,
                       IOStorageCompletion  completion);

    virtual IOReturn synchronizeCache(IOService * client);

    /*!
     * @function ejectMedia
     * @discussion
     * Eject the media from the device.  The driver is responsible for tearing
     * down the media object it created before proceeding with the eject.   If
     * the teardown fails, an error should be returned.
     * @result
     * An IOReturn code.
     */

    virtual IOReturn ejectMedia();

    /*!
     * @function formatMedia
     * @discussion
     * Format the media with the specified byte capacity.  The driver is
     * responsible for tearing down the media object and recreating it.
     * @param byteCapacity
     * Number of bytes to format media to.
     * @result
     * An IOReturn code.
     */

    virtual IOReturn formatMedia(UInt64 byteCapacity);

    /*!
     * @function lockMedia
     * @discussion
     * Lock or unlock the ejectable media in the device, that is, prevent
     * it from manual ejection or allow its manual ejection.
     * @param lock
     * Pass true to lock the media, otherwise pass false to unlock the media.
     * @result
     * An IOReturn code.
     */

    virtual IOReturn lockMedia(bool lock);

    /*!
     * @function pollMedia
     * @discussion
     * Poll for the presence of media in the device.  The driver is responsible
     * for tearing down the media object it created should the media have been
     * removed since the last poll, and vice-versa, creating the media object
     * should new media have arrived since the last poll.
     * @result
     * An IOReturn code.
     */

    virtual IOReturn pollMedia();

    /*!
     * @function isMediaEjectable
     * @discussion
     * Ask the driver whether the media is ejectable.
     * @result
     * Returns true if the media is ejectable, false otherwise.
     */

    virtual bool isMediaEjectable() const;

    /*!
     * @function isMediaPollExpensive
     * @discussion
     * Ask the driver whether a pollMedia() would be an expensive operation,
     * that is, one that requires the device to spin up or delay for a while.
     * @result
     * Returns true if polling the media is expensive, false otherwise.
     */

    virtual bool isMediaPollExpensive() const;

    /*!
     * @function isMediaPollRequired
     * @discussion
     * Ask the driver whether the block storage device requires polling,  which is
     * typically required for devices without the ability to asynchronously detect
     * the arrival or departure of the media.
     * @result
     * Returns true if polling the media is required, false otherwise.
     */

    virtual bool isMediaPollRequired() const;

    virtual bool isMediaWritable() const;

    /*!
     * @function getMediaState
     * @discussion
     * Ask the driver about the media's current state.
     * @result
     * An IOMediaState value.
     */

    virtual IOMediaState getMediaState() const;

    /*!
     * @function getFormatCapacities
     * @discussion
     * Ask the driver to report the feasible formatting capacities for the
     * inserted media (in bytes).  This routine fills the caller's buffer,
     * up to the maximum count specified if the real number of capacities
     * would overflow the buffer.   The return value indicates the actual
     * number of capacities copied to the buffer.
     *
     * If the capacities buffer is not supplied or if the maximum count is
     * zero, the routine returns the proposed count of capacities instead.
     * @param capacities
     * Buffer that will receive the UInt64 capacity values.
     * @param capacitiesMaxCount
     * Maximum number of capacity values that can be held in the buffer.
     * @result
     * Actual number of capacity values copied to the buffer, or if no buffer
     * is given, the total number of capacity values available.
     */

    virtual UInt32 getFormatCapacities(UInt64 * capacities,
                                       UInt32   capacitiesMaxCount) const;

    /*!
     * @function getStatistics
     * @discussion
     * Ask the driver to report its operating statistics.
     *
     * The statistics are each indexed by IOBlockStorageDriver::Statistics
     * indices.  This routine fills the caller's buffer, up to the maximum
     * count specified if the real number of statistics would overflow the
     * buffer.  The return value indicates the actual number of statistics
     * copied to the buffer.
     *
     * If the statistics buffer is not supplied or if the maximum count is
     * zero, the routine returns the proposed count of statistics instead.
     * @param statistics
     * Buffer that will receive the UInt64 statistic values.
     * @param statisticsMaxCount
     * Maximum number of statistic values that can be held in the buffer.
     * @result
     * Actual number of statistic values copied to the buffer, or if no buffer
     * is given, the total number of statistic values available.
     */

    virtual UInt32 getStatistics(UInt64 * statistics,
                                 UInt32   statisticsMaxCount) const;

    /*!
     * @function getStatistic
     * @discussion
     * Ask the driver to report one of its operating statistics.
     * @param statistic
     * Statistic index (an IOBlockStorageDriver::Statistics index).
     * @result
     * Statistic value.
     */

    virtual UInt64 getStatistic(Statistics statistic) const;

    /*
     * Generic entry point for calls from the provider.  A return value of
     * kIOReturnSuccess indicates that the message was received, and where
     * applicable, that it was successful.
     */

    virtual IOReturn message(UInt32 type, IOService * provider, void * argument);

    /*
     * Obtain this object's provider.  We override the superclass's method to
     * return a more specific subclass of IOService -- IOBlockStorageDevice.  
     * This method serves simply as a convenience to subclass developers.
     */

    virtual IOBlockStorageDevice * getProvider() const;

protected:

    IOLock *      _deblockRequestWriteLock;
    thread_call_t _pollerCall;

    /*
     * This is the completion routine for the aligned deblocker subrequests.
     * It verifies the success of the just-completed stage,  transitions to
     * the next stage, then builds and issues a transfer for the next stage.
     */

    static void deblockRequestCompletion(void *   target,
                                         void *   parameter,
                                         IOReturn status,
                                         UInt64   actualByteCount);

    /*
     * This is the completion routine for the prepared request.  It updates
     * the driver's statistics, performs some clean up work, then calls the
     * original request's completion routine.
     */

    static void prepareRequestCompletion(void *   target,
                                         void *   parameter,
                                         IOReturn status,
                                         UInt64   actualByteCount);

    /*
     * Schedule the poller mechanism.
     */

    virtual void schedulePoller();

    /*
     * Unschedule the poller mechanism.
     */

    virtual void unschedulePoller();

    /*
     * This method is the timeout handler for the poller mechanism.  It polls
     * for media and reschedules another timeout if there are still no opens.
     */

    static void poller(void *, void *);

protected:

    /* Device info: */

    /*!
     * @var _removable
     * True if the media is removable; False if it is fixed (not removable).
     */
    bool		_removable;

    /*!
     * @var _ejectable
     * True if the media is ejectable under software control.
     */
    bool		_ejectable;		/* software-ejectable */

    /*!
     * @var _lockable
     * True if the media can be locked in the device under software control.
     */
    bool		_lockable;		/* software lockable in device */
    /*!
     * @var _pollIsRequired
     * True if we must poll to detect media insertion or removal.
     */
    bool		_pollIsRequired;
    /*!
     * @var _pollIsExpensive
     * True if polling is expensive; False if not.
     */
    bool		_pollIsExpensive;

    /* Media info and states: */

    /*!
     * @var _mediaObject
     * A pointer to the media object we have instantiated (if any).
     */
    IOMedia *		_mediaObject;
    /*!
     * @var _mediaType
     * Type of the media (can be used to differentiate between the
     * different types of CD media, DVD media, etc).
     */
    UInt32		_mediaType;
    /*!
     * @var _mediaPresent
     * True if media is present in the device; False if not.
     */
    bool		_mediaPresent;		/* media is present and ready */
    /*!
     * @var _writeProtected
     * True if the media is write-protected; False if not.
     */
    bool		_writeProtected;
    
private:

    /*!
     * @var _mediaStateLock
     * A lock used to protect during media checks.
     */
    IOLock *		_mediaStateLock;

protected:

    /*!
     * @var _mediaBlockSize
     * The block size of the media, in bytes.
     */
    UInt64		_mediaBlockSize;
    /*!
     * @var _maxBlockNumber
     * The maximum allowable block number for the media, zero-based.
     */
    UInt64		_maxBlockNumber;

    /*!
     * @var _maxReadByteTransfer
     * The maximum byte transfer allowed for read operations.
     */
    UInt64		_maxReadByteTransfer;

    /*!
     * @var _maxWriteByteTransfer
     * The maximum byte transfer allowed for write operations.
     */
    UInt64		_maxWriteByteTransfer;

    /*!
     * @function acceptNewMedia
     * @abstract
     * React to new media insertion.
     * @discussion
     * This method logs the media block size and block count, then calls
     * instantiateMediaObject to get a media object instantiated. The
     * media object is then attached above us and registered.
     * 
     * This method can be overridden to control what happens when new media
     * is inserted. The default implementation deals with one IOMedia object.
     */
    virtual IOReturn	acceptNewMedia(void);
    
    /*!
     * @function constrainByteCount
     * @abstract
     * Constrain the byte count for this IO to device limits.
     * @discussion
     * This function should be called prior to each read or write operation, so that
     * the driver can constrain the requested byte count, as necessary, to meet
     * current device limits. Such limits could be imposed by the device depending
     * on operating modes, media types, or transport prototol (e.g. ATA, SCSI).
     * 
     * At present, this method is not used.
     * @param requestedCount
     * The requested byte count for the next read or write operation.
     * @param isWrite
     * True if the operation will be a write; False if the operation will be a read.
     */
    virtual UInt64	constrainByteCount(UInt64 requestedCount,bool isWrite);

    /*!
     * @function decommissionMedia
     * @abstract
     * Decommission an existing piece of media that has gone away.
     * @discussion
     * This method wraps a call to terminate, to tear down the stack and
     * the IOMedia object for the media. If "forcible" is true, the media
     * object will be forgotten, and initMediaState will be called. A
     * forcible decommission would occur when an unrecoverable error
     * happens during teardown (e.g. perhaps a client is still open), but
     * we must still forget about the media.
     * @param forcible
     * True to force forgetting of the media object even if terminate reports
     * that there was an active client.
     */
    virtual IOReturn	decommissionMedia(bool forcible);

    /*!
     * @function instantiateDesiredMediaObject
     * @abstract
     * Create an IOMedia object for media.
     * @discussion
     * This method creates the exact type of IOMedia object desired. It is called by
     * instantiateMediaObject. A subclass may override this one-line method to change
     * the type of media object actually instantiated.
     */
    virtual IOMedia *	instantiateDesiredMediaObject(void);

    /*!
     * @function instantiateMediaObject
     * @abstract
     * Create an IOMedia object for media.
     * @discussion
     * This method creates an IOMedia object from the supplied parameters. It is a
     * convenience method to wrap the handful of steps to do the job.
     * @param base
     * Byte number of beginning of active data area of the media. Usually zero.
     * @param byteSize
     * Size of the data area of the media, in bytes.
     * @param blockSize
     * Block size of the media, in bytes.
     * @param mediaName
     * Name of the IOMedia object.
     * @result
     * A pointer to the created IOMedia object, or a null on error.
     */
    virtual IOMedia *	instantiateMediaObject(UInt64 base,UInt64 byteSize,
                                            UInt32 blockSize,char *mediaName);

    /*!
     * @function recordMediaParameters
     * @abstract
     * Obtain media-related parameters on media insertion.
     * @discussion
     * This method obtains media-related parameters via calls to the
     * Transport Driver's reportBlockSize, reportMaxValidBlock,
     * reportMaxReadTransfer, reportMaxWriteTransfer, and reportWriteProtection
     * methods.
     */
    virtual IOReturn	recordMediaParameters(void);

    /*!
     * @function rejectMedia
     * @abstract
     * Reject new media.
     * @discussion
     * This method will be called if validateNewMedia returns False (thus rejecting
     * the new media. A vendor may choose to override this method to control behavior
     * when media is rejected.
     * 
     * The default implementation simply calls ejectMedia.
     */
    virtual void	rejectMedia(void);	/* default ejects */
    
    /*!
     * @function validateNewMedia
     * @abstract
     * Verify that new media is acceptable.
     * @discussion
     * This method will be called whenever new media is detected. Return true to accept
     * the media, or false to reject it (andcall rejectMedia). Vendors might override
     * this method to handle password-protection for new media.
     * 
     * The default implementation always returns True, indicating media is accepted.
     */
    virtual bool	validateNewMedia(void);

    /* --- Internally used methods. --- */

    /*
     * @group
     * Internally Used Methods
     * @discussion
     * These methods are used internally, and will not generally be modified.
     */
    
    /*!
     * @function checkForMedia
     * @abstract
     * Check if media has newly arrived or disappeared.
     * @discussion
     * This method does most of the work in polling for media, first
     * calling the block storage device's reportMediaState method. If
     * reportMediaState reports no change in the media state, kIOReturnSuccess
     * is returned. If the media state has indeed changed, a call is made to
     * mediaStateHasChanged to act on the event.
     */
    virtual IOReturn	checkForMedia(void);

    /*!
     * @function getDeviceTypeName
     * @abstract
     * Return the desired device name.
     * @discussion
     * This method returns a string, used to compare the 
     * kIOBlockStorageDeviceTypeKey of our provider. This method is called from
     * probe.
     *  
     * The default implementation of this method returns 
     * kIOBlockStorageDeviceTypeGeneric.
     */
    virtual const char * getDeviceTypeName(void);

    /*!
     * @function initMediaState
     * @abstract
     * Initialize media-related instance variables.
     * @discussion
     * Called when media is not present, this method marks the device state
     * as not having media present, not spun up, and write-enabled.
     */
    virtual void	initMediaState(void);
    
    /*!
     * @function mediaStateHasChanged
     * @abstract
     * React to a new media insertion or a media removal.
     * @discussion
     * This method is called on a media state change, that is, an arrival
     * or removal. If media has just become available, calls are made to
     * recordMediaParameters and acceptNewMedia. If media has just gone
     * away, a call is made to decommissionMedia, with the forcible
     * parameter set to true. The forcible teardown is needed to enforce
     * the disappearance of media, regardless of interested clients.
     */
    virtual IOReturn	mediaStateHasChanged(IOMediaState state);

    /*
     * @endgroup
     */

    OSMetaClassDeclareReservedUnused(IOBlockStorageDriver,  0);
    OSMetaClassDeclareReservedUnused(IOBlockStorageDriver,  1);
    OSMetaClassDeclareReservedUnused(IOBlockStorageDriver,  2);
    OSMetaClassDeclareReservedUnused(IOBlockStorageDriver,  3);
    OSMetaClassDeclareReservedUnused(IOBlockStorageDriver,  4);
    OSMetaClassDeclareReservedUnused(IOBlockStorageDriver,  5);
    OSMetaClassDeclareReservedUnused(IOBlockStorageDriver,  6);
    OSMetaClassDeclareReservedUnused(IOBlockStorageDriver,  7);
    OSMetaClassDeclareReservedUnused(IOBlockStorageDriver,  8);
    OSMetaClassDeclareReservedUnused(IOBlockStorageDriver,  9);
    OSMetaClassDeclareReservedUnused(IOBlockStorageDriver, 10);
    OSMetaClassDeclareReservedUnused(IOBlockStorageDriver, 11);
    OSMetaClassDeclareReservedUnused(IOBlockStorageDriver, 12);
    OSMetaClassDeclareReservedUnused(IOBlockStorageDriver, 13);
    OSMetaClassDeclareReservedUnused(IOBlockStorageDriver, 14);
    OSMetaClassDeclareReservedUnused(IOBlockStorageDriver, 15);
    OSMetaClassDeclareReservedUnused(IOBlockStorageDriver, 16);
    OSMetaClassDeclareReservedUnused(IOBlockStorageDriver, 17);
    OSMetaClassDeclareReservedUnused(IOBlockStorageDriver, 18);
    OSMetaClassDeclareReservedUnused(IOBlockStorageDriver, 19);
    OSMetaClassDeclareReservedUnused(IOBlockStorageDriver, 20);
    OSMetaClassDeclareReservedUnused(IOBlockStorageDriver, 21);
    OSMetaClassDeclareReservedUnused(IOBlockStorageDriver, 22);
    OSMetaClassDeclareReservedUnused(IOBlockStorageDriver, 23);
    OSMetaClassDeclareReservedUnused(IOBlockStorageDriver, 24);
    OSMetaClassDeclareReservedUnused(IOBlockStorageDriver, 25);
    OSMetaClassDeclareReservedUnused(IOBlockStorageDriver, 26);
    OSMetaClassDeclareReservedUnused(IOBlockStorageDriver, 27);
    OSMetaClassDeclareReservedUnused(IOBlockStorageDriver, 28);
    OSMetaClassDeclareReservedUnused(IOBlockStorageDriver, 29);
    OSMetaClassDeclareReservedUnused(IOBlockStorageDriver, 30);
    OSMetaClassDeclareReservedUnused(IOBlockStorageDriver, 31);
};

#endif /* defined(KERNEL) && defined(__cplusplus) */

#endif /* !_IOBLOCKSTORAGEDRIVER_H */
