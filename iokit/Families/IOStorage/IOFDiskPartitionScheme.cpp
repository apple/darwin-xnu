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
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOLib.h>
#include <IOKit/storage/IOFDiskPartitionScheme.h>
#include <libkern/OSByteOrder.h>

#define super IOPartitionScheme
OSDefineMetaClassAndStructors(IOFDiskPartitionScheme, IOPartitionScheme);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Notes
//
// o the on-disk structure's fields are: 16-bit packed, little-endian formatted
// o the relsect and numsect block values assume the drive's natural block size
// o the relsect block value is:
//   o for data partitions:
//     o relative to the FDisk map that defines the partition
//   o for extended partitions defined in the root-level FDisk map:
//     o relative to the FDisk map that defines the partition (start of disk)
//   o for extended partitions defined in a second-level or deeper FDisk map:
//     o relative to the second-level FDisk map, regardless of depth
// o the valid extended partition types are: 0x05, 0x0F, 0x85 
// o there should be no more than one extended partition defined per FDisk map
//

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#define kIOFDiskPartitionSchemeContentTable "Content Table"

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOFDiskPartitionScheme::init(OSDictionary * properties = 0)
{
    //
    // Initialize this object's minimal state.
    //

    // State our assumptions.

    assert(sizeof(fdisk_part) ==  16);              // (compiler/platform check)
    assert(sizeof(disk_blk0)  == 512);              // (compiler/platform check)

    // Ask our superclass' opinion.

    if ( super::init(properties) == false )  return false;

    // Initialize our state.

    _partitions = 0;

    return true;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IOFDiskPartitionScheme::free()
{
    //
    // Free all of this object's outstanding resources.
    //

    if ( _partitions )  _partitions->release();

    super::free();
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOService * IOFDiskPartitionScheme::probe(IOService * provider, SInt32 * score)
{
    //
    // Determine whether the provider media contains an FDisk partition map.
    //

    // State our assumptions.

    assert(OSDynamicCast(IOMedia, provider));

    // Ask our superclass' opinion.

    if ( super::probe(provider, score) == 0 )  return 0;

    // Scan the provider media for an FDisk partition map.

    _partitions = scan(score);

    // There might be an FDisk partition scheme on disk with boot code, but with
    // no partitions defined.  We don't consider this a match and return failure
    // from probe.

    if ( _partitions && _partitions->getCount() == 0 )
    {
        _partitions->release();
        _partitions = 0;        
    }

    return ( _partitions ) ? this : 0;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOFDiskPartitionScheme::start(IOService * provider)
{
    //
    // Publish the new media objects which represent our partitions.
    //

    IOMedia *    partition;
    OSIterator * partitionIterator;

    // State our assumptions.

    assert(_partitions);

    // Ask our superclass' opinion.

    if ( super::start(provider) == false )  return false;

    // Attach and register the new media objects representing our partitions.

    partitionIterator = OSCollectionIterator::withCollection(_partitions);
    if ( partitionIterator == 0 )  return false;

    while ( (partition = (IOMedia *) partitionIterator->getNextObject()) )
    {
        if ( partition->attach(this) )
        {
            partition->registerService();
        }
    }

    partitionIterator->release();

    return true;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSSet * IOFDiskPartitionScheme::scan(SInt32 * score)
{
    //
    // Scan the provider media for an FDisk partition map.  Returns the set
    // of media objects representing each of the partitions (the retain for
    // the set is passed to the caller), or null should no partition map be
    // found.  The default probe score can be adjusted up or down, based on
    // the confidence of the scan.
    //

    IOBufferMemoryDescriptor * buffer         = 0;
    UInt32                     bufferSize     = 0;
    UInt32                     fdiskBlock     = 0;
    UInt32                     fdiskBlockExtn = 0;
    UInt32                     fdiskBlockNext = 0;
    UInt32                     fdiskID        = 0;
    disk_blk0 *                fdiskMap       = 0;
    IOMedia *                  media          = getProvider();
    UInt64                     mediaBlockSize = media->getPreferredBlockSize();
    bool                       mediaIsOpen    = false;
    OSSet *                    partitions     = 0;
    IOReturn                   status         = kIOReturnError;

    // Determine whether this media is formatted.

    if ( media->isFormatted() == false )  goto scanErr;

    // Determine whether this media has an appropriate block size.

    if ( (mediaBlockSize % sizeof(disk_blk0)) )  goto scanErr;

    // Allocate a buffer large enough to hold one map, rounded to a media block.

    bufferSize = IORound(sizeof(disk_blk0), mediaBlockSize);
    buffer     = IOBufferMemoryDescriptor::withCapacity(
                                           /* capacity      */ bufferSize,
                                           /* withDirection */ kIODirectionIn );
    if ( buffer == 0 )  goto scanErr;

    // Allocate a set to hold the set of media objects representing partitions.

    partitions = OSSet::withCapacity(4);
    if ( partitions == 0 )  goto scanErr;

    // Open the media with read access.

    mediaIsOpen = media->open(this, 0, kIOStorageAccessReader);
    if ( mediaIsOpen == false )  goto scanErr;

    // Scan the media for FDisk partition map(s).

    do
    {
        // Read the next FDisk map into our buffer.

///m:2333367:workaround:commented:start
//      status = media->read(this, fdiskBlock * mediaBlockSize, buffer);
///m:2333367:workaround:commented:stop
///m:2333367:workaround:added:start
        status = media->IOStorage::read(this, fdiskBlock * mediaBlockSize, buffer);
///m:2333367:workaround:added:stop
        if ( status != kIOReturnSuccess )  goto scanErr;

        fdiskMap = (disk_blk0 *) buffer->getBytesNoCopy();

        // Determine whether the partition map signature is present.

        if ( OSSwapLittleToHostInt16(fdiskMap->signature) != DISK_SIGNATURE )
        {
            goto scanErr;
        }

        // Scan for valid partition entries in the partition map.

        fdiskBlockNext = 0;

        for ( unsigned index = 0; index < DISK_NPART; index++ )
        {
            // Determine whether this is an extended (vs. data) partition.

            if ( isPartitionExtended(fdiskMap->parts + index) )    // (extended)
            {
                // If peer extended partitions exist, we accept only the first.

                if ( fdiskBlockNext == 0 )      // (no peer extended partition)
                {
                    fdiskBlockNext = fdiskBlockExtn +
                                     OSSwapLittleToHostInt32(
                                    /* data */ fdiskMap->parts[index].relsect );

                    if ( fdiskBlockNext * mediaBlockSize >= media->getSize() )
                    {
                        fdiskBlockNext = 0;       // (exceeds confines of media)
                    }
                }
            }
            else if ( isPartitionUsed(fdiskMap->parts + index) )       // (data)
            {
                // Prepare this partition's ID.

                fdiskID = ( fdiskBlock == 0 ) ? (index + 1) : (fdiskID + 1);

                // Determine whether the partition is corrupt (fatal).

                if ( isPartitionCorrupt(
                                   /* partition   */ fdiskMap->parts + index,
                                   /* partitionID */ fdiskID,
                                   /* fdiskBlock  */ fdiskBlock ) )
                {
                    goto scanErr;
                }

                // Determine whether the partition is invalid (skipped).

                if ( isPartitionInvalid(
                                   /* partition   */ fdiskMap->parts + index,
                                   /* partitionID */ fdiskID,
                                   /* fdiskBlock  */ fdiskBlock ) )
                {
                    continue;
                }

                // Create a media object to represent this partition.

                IOMedia * newMedia = instantiateMediaObject(
                                   /* partition   */ fdiskMap->parts + index,
                                   /* partitionID */ fdiskID,
                                   /* fdiskBlock  */ fdiskBlock );

                if ( newMedia )
                {
                    partitions->setObject(newMedia);
                    newMedia->release();
                }
            }
        }

        // Prepare for first extended partition, if any.

        if ( fdiskBlock == 0 )
        {
            fdiskID        = DISK_NPART;
            fdiskBlockExtn = fdiskBlockNext;
        }

    } while ( (fdiskBlock = fdiskBlockNext) );

    // Release our resources.

    media->close(this);
    buffer->release();

    return partitions;

scanErr:

    // Release our resources.

    if ( mediaIsOpen )  media->close(this);
    if ( partitions )  partitions->release();
    if ( buffer )  buffer->release();

    return 0;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOFDiskPartitionScheme::isPartitionExtended(fdisk_part * partition)
{
    //
    // Ask whether the given partition is extended.
    //

    return ( partition->systid == 0x05 ||
             partition->systid == 0x0F ||
             partition->systid == 0x85 );
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOFDiskPartitionScheme::isPartitionUsed(fdisk_part * partition)
{
    //
    // Ask whether the given partition is used.
    //

    return ( partition->systid != 0 && partition->numsect != 0 );
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOFDiskPartitionScheme::isPartitionCorrupt( 
                                                fdisk_part * /* partition   */ ,
                                                UInt32       /* partitionID */ ,
                                                UInt32       /* fdiskBlock  */ )
{
    //
    // Ask whether the given partition appears to be corrupt.  A partition that
    // is corrupt will cause the failure of the FDisk partition map recognition
    // altogether.
    //

    return false;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOFDiskPartitionScheme::isPartitionInvalid( fdisk_part * partition,
                                                 UInt32       partitionID,
                                                 UInt32       fdiskBlock )
{
    //
    // Ask whether the given partition appears to be invalid.  A partition that
    // is invalid will cause it to be skipped in the scan, but will not cause a
    // failure of the FDisk partition map recognition.
    //

    IOMedia * media          = getProvider();
    UInt64    mediaBlockSize = media->getPreferredBlockSize();
    UInt64    partitionBase  = 0;
    UInt64    partitionSize  = 0;

    // Compute the relative byte position and size of the new partition.

    partitionBase  = OSSwapLittleToHostInt32(partition->relsect) + fdiskBlock;
    partitionSize  = OSSwapLittleToHostInt32(partition->numsect);
    partitionBase *= mediaBlockSize;
    partitionSize *= mediaBlockSize;

    // Determine whether the partition starts at (or past) the end-of-media.

    if ( partitionBase >= media->getSize() )  return true;

    return false;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOMedia * IOFDiskPartitionScheme::instantiateMediaObject(
                                                     fdisk_part * partition,
                                                     UInt32       partitionID,
                                                     UInt32       fdiskBlock )
{
    //
    // Instantiate a new media object to represent the given partition.
    //

    IOMedia * media          = getProvider();
    UInt64    mediaBlockSize = media->getPreferredBlockSize();
    UInt64    partitionBase  = 0;
    char *    partitionHint  = 0;
    UInt64    partitionSize  = 0;

    // Compute the relative byte position and size of the new partition.

    partitionBase  = OSSwapLittleToHostInt32(partition->relsect) + fdiskBlock;
    partitionSize  = OSSwapLittleToHostInt32(partition->numsect);
    partitionBase *= mediaBlockSize;
    partitionSize *= mediaBlockSize;

    // Clip the size of the new partition if it extends past the end-of-media.

    if ( partitionBase + partitionSize > media->getSize() )
    {
        partitionSize = media->getSize() - partitionBase;
    }

    // Look up a type for the new partition.

    OSDictionary * hintTable = OSDynamicCast( 
              /* type     */ OSDictionary,
              /* instance */ getProperty(kIOFDiskPartitionSchemeContentTable) );

    if ( hintTable )
    {
        char       hintIndex[5];
        OSString * hintValue;

        sprintf(hintIndex, "0x%02X", partition->systid & 0xFF);

        hintValue = OSDynamicCast(OSString, hintTable->getObject(hintIndex));

        if ( hintValue ) partitionHint = (char *) hintValue->getCStringNoCopy();
    }

    // Create the new media object.

    IOMedia * newMedia = instantiateDesiredMediaObject(
                                   /* partition   */ partition,
                                   /* partitionID */ partitionID,
                                   /* fdiskBlock  */ fdiskBlock );

    if ( newMedia )
    {
         if ( newMedia->init(
                /* base               */ partitionBase,
                /* size               */ partitionSize,
                /* preferredBlockSize */ mediaBlockSize,
                /* isEjectable        */ media->isEjectable(),
                /* isWhole            */ false,
                /* isWritable         */ media->isWritable(),
                /* contentHint        */ partitionHint ) )
        {
            // Set a name for this partition.

            char name[24];
            sprintf(name, "Untitled %ld", partitionID);
            newMedia->setName(name);

            // Set a location value (the partition number) for this partition.

            char location[12];
            sprintf(location, "%ld", partitionID);
            newMedia->setLocation(location);

            // Set the "Partition ID" key for this partition.

            newMedia->setProperty(kIOMediaPartitionIDKey, partitionID, 32);
        }
        else
        {
            newMedia->release();
            newMedia = 0;
        }
    }

    return newMedia;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOMedia * IOFDiskPartitionScheme::instantiateDesiredMediaObject(
                                                     fdisk_part * partition,
                                                     UInt32       partitionID,
                                                     UInt32       fdiskBlock )
{
    //
    // Allocate a new media object (called from instantiateMediaObject).
    //

    return new IOMedia;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOFDiskPartitionScheme, 0);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOFDiskPartitionScheme, 1);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOFDiskPartitionScheme, 2);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOFDiskPartitionScheme, 3);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOFDiskPartitionScheme, 4);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOFDiskPartitionScheme, 5);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOFDiskPartitionScheme, 6);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOFDiskPartitionScheme, 7);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOFDiskPartitionScheme, 8);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOFDiskPartitionScheme, 9);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOFDiskPartitionScheme, 10);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOFDiskPartitionScheme, 11);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOFDiskPartitionScheme, 12);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOFDiskPartitionScheme, 13);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOFDiskPartitionScheme, 14);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOFDiskPartitionScheme, 15);
