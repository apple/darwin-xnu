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
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOLib.h>
#include <IOKit/storage/IOApplePartitionScheme.h>
#include <libkern/OSByteOrder.h>

#define super IOPartitionScheme
OSDefineMetaClassAndStructors(IOApplePartitionScheme, IOPartitionScheme);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Notes
//
// o the on-disk structure's fields are: 16-bit packed, big-endian formatted
// o the dpme_pblock_start and dpme_pblocks block values are:
//   o for media without a driver map:
//     o natural block size based
//   o for media with a driver map:
//     o driver map block size based, unless the driver map block size is 2048
//       and a valid partition entry exists at a 512 byte offset into the disk,
//       in which case, assume a 512 byte block size, except for the partition
//       entries that lie on a 2048 byte multiple and are one of the following
//       types: Apple_Patches, Apple_Driver, Apple_Driver43, Apple_Driver43_CD,
//       Apple_Driver_ATA, Apple_Driver_ATAPI; in which case, we assume a 2048
//       byte block size (for the one partition)
// o the dpme_pblock_start block value is relative to the media container
//

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#define kIOApplePartitionSchemeContentTable "Content Table"

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOApplePartitionScheme::init(OSDictionary * properties = 0)
{
    //
    // Initialize this object's minimal state.
    //

    // State our assumptions.

    assert(sizeof(dpme)   == 512);                  // (compiler/platform check)
    assert(sizeof(DDMap)  ==   8);                  // (compiler/platform check)
    assert(sizeof(Block0) == 512);                  // (compiler/platform check)

    // Ask our superclass' opinion.

    if (super::init(properties) == false)  return false;

    // Initialize our state.

    _partitions = 0;

    return true;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IOApplePartitionScheme::free()
{
    //
    // Free all of this object's outstanding resources.
    //

    if ( _partitions )  _partitions->release();

    super::free();
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOService * IOApplePartitionScheme::probe(IOService * provider, SInt32 * score)
{
    //
    // Determine whether the provider media contains an Apple partition map.
    //

    // State our assumptions.

    assert(OSDynamicCast(IOMedia, provider));

    // Ask superclass' opinion.

    if (super::probe(provider, score) == 0)  return 0;

    // Scan the provider media for an Apple partition map.

    _partitions = scan(score);

    return ( _partitions ) ? this : 0;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOApplePartitionScheme::start(IOService * provider)
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
            attachMediaObjectToDeviceTree(partition);

            partition->registerService();
        }
    }

    partitionIterator->release();

    return true;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IOApplePartitionScheme::stop(IOService * provider)
{
    //
    // Clean up after the media objects we published before terminating.
    //

    IOMedia *    partition;
    OSIterator * partitionIterator;

    // State our assumptions.

    assert(_partitions);

    // Detach the media objects we previously attached to the device tree.

    partitionIterator = OSCollectionIterator::withCollection(_partitions);

    if ( partitionIterator )
    {
        while ( (partition = (IOMedia *) partitionIterator->getNextObject()) )
        {
            detachMediaObjectFromDeviceTree(partition);
        }

        partitionIterator->release();
    }

    super::stop(provider);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSSet * IOApplePartitionScheme::scan(SInt32 * score)
{
    //
    // Scan the provider media for an Apple partition map.  Returns the set
    // of media objects representing each of the partitions (the retain for
    // the set is passed to the caller), or null should no partition map be
    // found.  The default probe score can be adjusted up or down, based on
    // the confidence of the scan.
    //

    IOBufferMemoryDescriptor * buffer         = 0;
    UInt32                     bufferReadAt   = 0;
    UInt32                     bufferSize     = 0;
    UInt32                     dpmeBlockSize  = 0;
    UInt32                     dpmeCount      = 0;
    UInt32                     dpmeID         = 0;
    dpme *                     dpmeMap        = 0;
    UInt32                     dpmeMaxCount   = 0;
    bool                       dpmeOldSchool  = false;
    Block0 *                   driverMap      = 0;
    IOMedia *                  media          = getProvider();
    UInt64                     mediaBlockSize = media->getPreferredBlockSize();
    bool                       mediaIsOpen    = false;
    OSSet *                    partitions     = 0;
    IOReturn                   status         = kIOReturnError;

    // Determine whether this media is formatted.

    if ( media->isFormatted() == false )  goto scanErr;

    // Determine whether this media has an appropriate block size.

    if ( (mediaBlockSize % sizeof(dpme)) )  goto scanErr;

    // Allocate a buffer large enough to hold one map, rounded to a media block.

    bufferSize = IORound(max(sizeof(Block0), sizeof(dpme)), mediaBlockSize);
    buffer     = IOBufferMemoryDescriptor::withCapacity(
                                           /* capacity      */ bufferSize,
                                           /* withDirection */ kIODirectionIn );
    if ( buffer == 0 )  goto scanErr;

    // Allocate a set to hold the set of media objects representing partitions.

    partitions = OSSet::withCapacity(8);
    if ( partitions == 0 )  goto scanErr;

    // Open the media with read access.

    mediaIsOpen = media->open(this, 0, kIOStorageAccessReader);
    if ( mediaIsOpen == false )  goto scanErr;

    // Read the driver map into our buffer.

    bufferReadAt = 0;

///m:2333367:workaround:commented:start
//  status = media->read(this, bufferReadAt, buffer);
///m:2333367:workaround:commented:stop
///m:2333367:workaround:added:start
    status = media->IOStorage::read(this, bufferReadAt, buffer);
///m:2333367:workaround:added:stop
    if ( status != kIOReturnSuccess )  goto scanErr;

    driverMap = (Block0 *) buffer->getBytesNoCopy();

    // Determine the official block size to use to scan the partition entries.

    dpmeBlockSize = mediaBlockSize;                      // (natural block size)

    if ( driverMap->sbSig == BLOCK0_SIGNATURE )
    {
        dpmeBlockSize = driverMap->sbBlkSize;         // (driver map block size)

        // Determine whether we have an old school partition map, where there is
        // a partition entry at a 512 byte offset into the disk, even though the
        // driver map block size is 2048.

        if ( dpmeBlockSize == 2048 )
        {
            if ( bufferSize >= sizeof(Block0) + sizeof(dpme) )   // (in buffer?)
            {
                dpmeMap = (dpme *) (driverMap + 1);
            }
            else                                              // (not in buffer)
            {
                // Read the partition entry at byte offset 512 into our buffer.

                bufferReadAt = sizeof(dpme);

///m:2333367:workaround:commented:start
//              status = media->read(this, bufferReadAt, buffer);
///m:2333367:workaround:commented:stop
///m:2333367:workaround:added:start
                status = media->IOStorage::read(this, bufferReadAt, buffer);
///m:2333367:workaround:added:stop
                if ( status != kIOReturnSuccess )  goto scanErr;

                dpmeMap = (dpme *) buffer->getBytesNoCopy();
            }

            // Determine whether the partition entry signature is present.

            if (OSSwapBigToHostInt16(dpmeMap->dpme_signature) == DPME_SIGNATURE)
            {
                dpmeBlockSize = sizeof(dpme);         // (old school block size)
                dpmeOldSchool = true;
            }
        }

        // Increase the probe score when a driver map is detected, since we are
        // more confident in the match when it is present.  This will eliminate
        // conflicts with FDisk when it shares the same block as the driver map.

        *score += 2000;
    }

    // Scan the media for Apple partition entries.

    for ( dpmeID = 1, dpmeCount = 1; dpmeID <= dpmeCount; dpmeID++ ) 
    {
        UInt32 partitionBlockSize = dpmeBlockSize;

        // Determine whether we've exhausted the current buffer of entries.

        if ( dpmeID * dpmeBlockSize + sizeof(dpme) > bufferReadAt + bufferSize )
        {
            // Read the next partition entry into our buffer.

            bufferReadAt = dpmeID * dpmeBlockSize;

///m:2333367:workaround:commented:start
//          status = media->read(this, bufferReadAt, buffer);
///m:2333367:workaround:commented:stop
///m:2333367:workaround:added:start
            status = media->IOStorage::read(this, bufferReadAt, buffer);
///m:2333367:workaround:added:stop
            if ( status != kIOReturnSuccess )  goto scanErr;
        }

        dpmeMap = (dpme *) ( ((UInt8 *) buffer->getBytesNoCopy()) +
                             (dpmeID * dpmeBlockSize) - bufferReadAt );

        // Determine whether the partition entry signature is present.

        if ( OSSwapBigToHostInt16(dpmeMap->dpme_signature) != DPME_SIGNATURE )
        {
            goto scanErr;
        }

        // Obtain an accurate number of entries in the partition map.

        if ( !strcmp(dpmeMap->dpme_type, "Apple_partition_map") ||
             !strcmp(dpmeMap->dpme_type, "Apple_Partition_Map") ||
             !strcmp(dpmeMap->dpme_type, "Apple_patition_map" ) )
        {
            dpmeCount    = OSSwapBigToHostInt32(dpmeMap->dpme_map_entries);
            dpmeMaxCount = OSSwapBigToHostInt32(dpmeMap->dpme_pblocks);
        }
        else if ( dpmeCount == 1 )
        {
            dpmeCount = OSSwapBigToHostInt32(dpmeMap->dpme_map_entries);
        }

        // Obtain an accurate block size for an old school partition map.

        if ( dpmeOldSchool && (dpmeID % 4) == 0 )
        {
            if ( !strcmp(dpmeMap->dpme_type, "Apple_Driver"      ) ||
                 !strcmp(dpmeMap->dpme_type, "Apple_Driver43"    ) ||
                 !strcmp(dpmeMap->dpme_type, "Apple_Driver43_CD" ) ||
                 !strcmp(dpmeMap->dpme_type, "Apple_Driver_ATA"  ) ||
                 !strcmp(dpmeMap->dpme_type, "Apple_Driver_ATAPI") ||
                 !strcmp(dpmeMap->dpme_type, "Apple_Patches"     ) )
            {
                partitionBlockSize = 2048;
            }
        }

        // Determine whether the partition is corrupt (fatal).

        if ( isPartitionCorrupt(
                                 /* partition          */ dpmeMap,
                                 /* partitionID        */ dpmeID,
                                 /* partitionBlockSize */ partitionBlockSize ) )
        {
            goto scanErr;
        }

        // Determine whether the partition is invalid (skipped).

        if ( isPartitionInvalid(
                                 /* partition          */ dpmeMap,
                                 /* partitionID        */ dpmeID,
                                 /* partitionBlockSize */ partitionBlockSize ) )
        {
            continue;
        }

        // Create a media object to represent this partition.

        IOMedia * newMedia = instantiateMediaObject(
                                 /* partition          */ dpmeMap,
                                 /* partitionID        */ dpmeID,
                                 /* partitionBlockSize */ partitionBlockSize );

        if ( newMedia )
        {
            partitions->setObject(newMedia);
            newMedia->release();
        }
    }

    // Determine whether we ever came accross an Apple_partition_map partition.

    if ( dpmeMaxCount == 0 )  goto scanErr;

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

bool IOApplePartitionScheme::isPartitionCorrupt(
                                               dpme * /* partition          */ ,
                                               UInt32 /* partitionID        */ ,
                                               UInt32 /* partitionBlockSize */ )
{
    //
    // Ask whether the given partition appears to be corrupt.  A partition that
    // is corrupt will cause the failure of the Apple partition map recognition
    // altogether.
    //

    return false;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOApplePartitionScheme::isPartitionInvalid( dpme * partition,
                                                 UInt32 partitionID,
                                                 UInt32 partitionBlockSize )
{
    //
    // Ask whether the given partition appears to be invalid.  A partition that
    // is invalid will cause it to be skipped in the scan, but will not cause a
    // failure of the Apple partition map recognition.
    //

    IOMedia * media         = getProvider();
    UInt64    partitionBase = 0;
    UInt64    partitionSize = 0;

    // Compute the relative byte position and size of the new partition.

    partitionBase  = OSSwapBigToHostInt32(partition->dpme_pblock_start);
    partitionSize  = OSSwapBigToHostInt32(partition->dpme_pblocks);
    partitionBase *= partitionBlockSize;
    partitionSize *= partitionBlockSize;

    // Determine whether the partition is a placeholder.

    if ( partitionSize == 0 )  return true;

    // Determine whether the partition starts at (or past) the end-of-media.

    if ( partitionBase >= media->getSize() )  return true;

    return false;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOMedia * IOApplePartitionScheme::instantiateMediaObject(
                                                     dpme * partition,
                                                     UInt32 partitionID,
                                                     UInt32 partitionBlockSize )
{
    //
    // Instantiate a new media object to represent the given partition.
    //

    IOMedia * media               = getProvider();
    UInt64    mediaBlockSize      = media->getPreferredBlockSize();
    UInt64    partitionBase       = 0;
    char *    partitionHint       = partition->dpme_type;
    bool      partitionIsWritable = media->isWritable();
    char *    partitionName       = partition->dpme_name;
    UInt64    partitionSize       = 0;

    // Compute the relative byte position and size of the new partition.

    partitionBase  = OSSwapBigToHostInt32(partition->dpme_pblock_start);
    partitionSize  = OSSwapBigToHostInt32(partition->dpme_pblocks);
    partitionBase *= partitionBlockSize;
    partitionSize *= partitionBlockSize;

    // Clip the size of the new partition if it extends past the end-of-media.

    if ( partitionBase + partitionSize > media->getSize() )
    {
        partitionSize = media->getSize() - partitionBase;
    }

    // Look up a type for the new partition.

    OSDictionary * hintTable = OSDynamicCast( 
              /* type     */ OSDictionary,
              /* instance */ getProperty(kIOApplePartitionSchemeContentTable) );

    if ( hintTable )
    {
        OSString * hintValue = OSDynamicCast( 
                       /* type     */ OSString,
                       /* instance */ hintTable->getObject(partitionHint) );

        if ( hintValue ) partitionHint = (char *) hintValue->getCStringNoCopy();
    }

    // Look up a name for the new partition.

    while ( *partitionName == ' ' )  { partitionName++; }

    if ( *partitionName == 0 )  partitionName = 0;

    // Determine whether the new partition type is Apple_Free, which we choose
    // not to publish because it is an internal concept to the partition map.

    if ( !strcmp(partitionHint, "Apple_Free") )  return 0;

    // Determine whether the new partition is read-only.
    //
    // Note that we treat the misspelt Apple_patition_map entries as equivalent
    // to Apple_partition_map entries due to the messed up CDs noted in 2513960.

    if ( !strcmp(partition->dpme_type, "Apple_partition_map")      ||
         !strcmp(partition->dpme_type, "Apple_Partition_Map")      ||
         !strcmp(partition->dpme_type, "Apple_patition_map" )      ||
         ( ((partition->dpme_flags & DPME_FLAGS_WRITABLE) == 0) &&
           ((partition->dpme_flags & DPME_FLAGS_VALID   ) != 0) )  )
    {
        partitionIsWritable = false;
    }

    // Create the new media object.

    IOMedia * newMedia = instantiateDesiredMediaObject(
                                 /* partition          */ partition,
                                 /* partitionID        */ partitionID,
                                 /* partitionBlockSize */ partitionBlockSize );

    if ( newMedia )
    {
        if ( newMedia->init(
                /* base               */ partitionBase,
                /* size               */ partitionSize,
                /* preferredBlockSize */ mediaBlockSize,
                /* isEjectable        */ media->isEjectable(),
                /* isWhole            */ false,
                /* isWritable         */ partitionIsWritable,
                /* contentHint        */ partitionHint ) )
        {
            // Set a name for this partition.

            char name[24];
            sprintf(name, "Untitled %ld", partitionID);
            newMedia->setName(partitionName ? partitionName : name);

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

IOMedia * IOApplePartitionScheme::instantiateDesiredMediaObject(
                                                     dpme * partition,
                                                     UInt32 partitionID,
                                                     UInt32 partitionBlockSize )
{
    //
    // Allocate a new media object (called from instantiateMediaObject).
    //

    return new IOMedia;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOApplePartitionScheme::attachMediaObjectToDeviceTree( IOMedia * media )
{
    //
    // Attach the given media object to the device tree plane.
    //

    IOService * service;
    SInt32      unit = -1;

    for ( service = this; service; service = service->getProvider() )
    {
        OSNumber * number;

        if ( (number = OSDynamicCast(OSNumber, service->getProperty("IOUnit"))))
        {
            unit = number->unsigned32BitValue();
        }

        if ( service->inPlane(gIODTPlane) )
        {
            IORegistryEntry *    child;
            IORegistryIterator * children;

            if ( unit == -1 )  break;

            children = IORegistryIterator::iterateOver(service, gIODTPlane);

            if ( children == 0 )  break;

            while ( (child = children->getNextObject()) )
            {
                const char * location = child->getLocation(gIODTPlane);
                const char * name     = child->getName(gIODTPlane);

                if ( name     == 0 || strcmp(name,     "" ) != 0 ||
                     location == 0 || strchr(location, ':') == 0 )
                {
                    child->detachAll(gIODTPlane);
                }
            }

            children->release();

            if ( media->attachToParent(service, gIODTPlane) )
            {
                char location[ sizeof("hhhhhhhh:dddddddddd") ];

                sprintf(location, "%lx:", unit);
                strcat(location, media->getLocation());
                media->setLocation(location, gIODTPlane);
                media->setName("", gIODTPlane);

                return true;
            }

            break;
        }
    }

    return false;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IOApplePartitionScheme::detachMediaObjectFromDeviceTree( IOMedia * media )
{
    //
    // Detach the given media object from the device tree plane.
    //

    IORegistryEntry * parent;

    if ( (parent = media->getParentEntry(gIODTPlane)) )
    {
        media->detachFromParent(parent, gIODTPlane);
    }
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOApplePartitionScheme, 0);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOApplePartitionScheme, 1);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOApplePartitionScheme, 2);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOApplePartitionScheme, 3);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOApplePartitionScheme, 4);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOApplePartitionScheme, 5);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOApplePartitionScheme, 6);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOApplePartitionScheme, 7);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOApplePartitionScheme, 8);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOApplePartitionScheme, 9);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOApplePartitionScheme, 10);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOApplePartitionScheme, 11);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOApplePartitionScheme, 12);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOApplePartitionScheme, 13);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOApplePartitionScheme, 14);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOApplePartitionScheme, 15);
