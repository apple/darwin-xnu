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

#include <sys/param.h>
#include <IOKit/assert.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOLib.h>
#include <IOKit/storage/IONeXTPartitionScheme.h>
#include <libkern/OSByteOrder.h>

#define super IOPartitionScheme
OSDefineMetaClassAndStructors(IONeXTPartitionScheme, IOPartitionScheme);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Notes
//
// o the on-disk structure's fields are: 16-bit packed, big-endian formatted
// o the on-disk structure is stored four times in succession, each takes up
//   sizeof(disk_label_t) bytes rounded up to the drive's natural block size
// o the dl_label_blkno block value assumes the drive's natural block size
// o the dl_part[].p_base, dl_part[].p_size and dl_front block values assume
//   a dl_secsize byte block size
// o the dl_part[].p_base and dl_label_blkno block values are absolute, with
//   respect to the whole disk
// o the dl_part[].p_base block value doesn't take into account the dl_front
//   offset, which is required in order to compute the actual start position
//   of the partition on the disk
// o note that CDs often suffer from the mastering-with-a-different-natural-
//   block-size problem, but we can assume that the first map will always be
//   valid in those cases, and that we'll never need to compute the position
//   of the next map correctly
// o note that bootable i386 disks will never have a valid first map, due to
//   the boot code that lives in block zero, however the second map is valid
// o this implementation checks for the existence of the first map only;  it
//   does not bother with the last three maps, since backwards compatibility
//   with unreleased NeXT-style i386 disks is a non-goal, and for reasons of
//   minimizing access to the media during probe
//

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#define kIONeXTPartitionSchemeContentTable "Content Table"

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IONeXTPartitionScheme::init(OSDictionary * properties = 0)
{
    //
    // Initialize this object's minimal state.
    //

    // State our assumptions.

    assert(sizeof(disktab_t)    ==  514);           // (compiler/platform check)
    assert(sizeof(partition_t)  ==   46);           // (compiler/platform check)
    assert(sizeof(disk_label_t) == 7240);           // (compiler/platform check)

    // Ask our superclass' opinion.

    if ( super::init(properties) == false )  return false;

    // Initialize our state.

    _partitions = 0;

    return true;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IONeXTPartitionScheme::free()
{
    //
    // Free all of this object's outstanding resources.
    //

    if ( _partitions )  _partitions->release();

    super::free();
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOService * IONeXTPartitionScheme::probe(IOService * provider, SInt32 * score)
{
    //
    // Determine whether the provider media contains a NeXT partition map.  If
    // it does, we return "this" to indicate success, otherwise we return zero.
    //

    // State our assumptions.

    assert(OSDynamicCast(IOMedia, provider));

    // Ask our superclass' opinion.

    if ( super::probe(provider, score) == 0 )  return 0;

    // Scan the provider media for a NeXT partition map.

    _partitions = scan(score);

    return ( _partitions ) ? this : 0;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IONeXTPartitionScheme::start(IOService * provider)
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

OSSet * IONeXTPartitionScheme::scan(SInt32 * score)
{
    //
    // Scan the provider media for a NeXT partition map.    Returns the set
    // of media objects representing each of the partitions (the retain for
    // the set is passed to the caller), or null should no partition map be
    // found.  The default probe score can be adjusted up or down, based on
    // the confidence of the scan.
    //

    IOBufferMemoryDescriptor * buffer         = 0;
    UInt32                     bufferSize     = 0;
    UInt64                     labelBase      = 0;
    UInt32                     labelBlock     = 0;
    UInt16 *                   labelCheckPtr  = 0;
    UInt32                     labelCheckSize = 0;
    bool                       labelFound     = false;
    UInt32                     labelIndex     = 0;
    disk_label_t *             labelMap       = 0;
    IOMedia *                  media          = getProvider();
    UInt64                     mediaBlockSize = media->getPreferredBlockSize();
    bool                       mediaIsOpen    = false;
    OSSet *                    partitions     = 0;
    IOReturn                   status         = kIOReturnError;

    // Determine whether this media is formatted.

    if ( media->isFormatted() == false )  goto scanErr;

    // Determine whether this media has an appropriate block size.

    if ( (mediaBlockSize % DEV_BSIZE) )  goto scanErr;

    // Allocate a buffer large enough to hold one map, rounded to a media block.

    bufferSize = IORound(sizeof(disk_label_t), mediaBlockSize);
    buffer     = IOBufferMemoryDescriptor::withCapacity(
                                           /* capacity      */ bufferSize,
                                           /* withDirection */ kIODirectionIn );
    if ( buffer == 0 )  goto scanErr;

    // Allocate a set to hold the set of media objects representing partitions.

    partitions = OSSet::withCapacity(1);
    if ( partitions == 0 )  goto scanErr;

    // Open the media with read access.

    mediaIsOpen = media->open(this, 0, kIOStorageAccessReader);
    if ( mediaIsOpen == false )  goto scanErr;

    // Compute this partition's absolute offset with respect to the whole media,
    // since the disk_label structure requires this information; we go down the
    // service hierarchy summing bases until we reach the whole media object.

    for (IOService * service = media; service; service = service->getProvider())
    {
        if ( OSDynamicCast(IOMedia, service) )      // (is this a media object?)
        {
            labelBase += ((IOMedia *)service)->getBase();
            if ( ((IOMedia *)service)->isWhole() )  break;
        }
    }

    // Scan the media for a NeXT partition map.
    //
    // In the spirit of minimizing reads, we only check the first of the four
    // possible label positions.  Backwards compatibility with old NeXT-style
    // i386 disks, including redundancy for NeXT-style disks in general, is a
    // non-goal.

    for ( labelIndex = 0; labelIndex < 1; labelIndex++ )     // (first map only)
    {
        // Read the next NeXT map into our buffer.

///m:2333367:workaround:commented:start
//      status = media->read(this, labelIndex * bufferSize, buffer);
///m:2333367:workaround:commented:stop
///m:2333367:workaround:added:start
        status = media->IOStorage::read(this, labelIndex * bufferSize, buffer);
///m:2333367:workaround:added:stop
        if ( status != kIOReturnSuccess )  goto scanErr;

        labelBlock = ((labelIndex * bufferSize) + labelBase) / mediaBlockSize;
        labelMap   = (disk_label_t *) buffer->getBytesNoCopy();

        // Determine whether the partition map signature is present.

        if ( OSSwapBigToHostInt32(labelMap->dl_version) == DL_V3 )
        {
            labelCheckPtr = &(labelMap->dl_v3_checksum);
        }
        else if ( OSSwapBigToHostInt32(labelMap->dl_version) == DL_V2 ||
                  OSSwapBigToHostInt32(labelMap->dl_version) == DL_V1 )
        {
            labelCheckPtr = &(labelMap->dl_checksum);
        }
        else
        {
            continue;
        }

        labelCheckSize = (UInt8 *) labelCheckPtr - 
                         (UInt8 *) labelMap      - sizeof(UInt16);

        // Determine whether the partition map block position is correct.

        if ( OSSwapBigToHostInt32(labelMap->dl_label_blkno) != labelBlock )
        {
            continue;
        }

        // Determine whether the partition map checksum is correct.

        labelMap->dl_label_blkno = OSSwapHostToBigInt32(0);

        if ( checksum16(labelMap, labelCheckSize) != *labelCheckPtr )
        {
            continue;
        }

        labelMap->dl_label_blkno = labelBlock;

        labelFound = true;
        break;
    }

    if ( labelFound == false )
    {
        goto scanErr;
    }

    // Scan for valid partition entries in the partition map.

    for ( unsigned index = 0; index < NPART; index++ )
    {
        if ( isPartitionUsed(labelMap->dl_part + index) )
        {
            // Determine whether the partition is corrupt (fatal).

            if ( isPartitionCorrupt(
                                   /* partition   */ labelMap->dl_part + index,
                                   /* partitionID */ index + 1,
                                   /* labelBase   */ labelBase,
                                   /* labelMap    */ labelMap ) )
            {
                goto scanErr;
            }

            // Determine whether the partition is invalid (skipped).

            if ( isPartitionInvalid(
                                   /* partition   */ labelMap->dl_part + index,
                                   /* partitionID */ index + 1,
                                   /* labelBase   */ labelBase,
                                   /* labelMap    */ labelMap ) )
            {
                continue;
            }

            // Create a media object to represent this partition.

            IOMedia * newMedia = instantiateMediaObject(
                                   /* partition   */ labelMap->dl_part + index,
                                   /* partitionID */ index + 1,
                                   /* labelBase   */ labelBase,
                                   /* labelMap    */ labelMap );

            if ( newMedia )
            {
                partitions->setObject(newMedia);
                newMedia->release();
            }
        }
    }

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

bool IONeXTPartitionScheme::isPartitionUsed(partition_t * partition)
{
    //
    // Ask whether the given partition is used.
    //

    return ( (SInt32) OSSwapBigToHostInt32(partition->p_base) >= 0 &&
             (SInt32) OSSwapBigToHostInt32(partition->p_size) >  0 );
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IONeXTPartitionScheme::isPartitionCorrupt(
                                              partition_t *  /* partition   */ ,
                                              UInt32         /* partitionID */ ,
                                              UInt64         /* labelBase   */ ,
                                              disk_label_t * /* labelMap    */ )
{
    //
    // Ask whether the given partition appears to be corrupt. A partition that
    // is corrupt will cause the failure of the NeXT partition map recognition
    // altogether.
    //

    return false;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IONeXTPartitionScheme::isPartitionInvalid( partition_t *  partition,
                                                UInt32         partitionID,
                                                UInt64         labelBase,
                                                disk_label_t * labelMap )
{
    //
    // Ask whether the given partition appears to be invalid.  A partition that
    // is invalid will cause it to be skipped in the scan, but will not cause a
    // failure of the NeXT partition map recognition.
    //

    IOMedia * media         = getProvider();
    UInt64    partitionBase = 0;
    UInt64    partitionSize = 0;

    // Compute the absolute byte position and size of the new partition.

    partitionBase  = OSSwapBigToHostInt32(partition->p_base) +
                     OSSwapBigToHostInt16(labelMap->dl_front);
    partitionSize  = OSSwapBigToHostInt32(partition->p_size);
    partitionBase *= OSSwapBigToHostInt32(labelMap->dl_secsize);
    partitionSize *= OSSwapBigToHostInt32(labelMap->dl_secsize);

    // Determine whether the new partition leaves the confines of the container.

    if ( partitionBase < labelBase )  return true;   // (absolute partitionBase)

    // Compute the relative byte position of the new partition.

    partitionBase -= labelBase;                      // (relative partitionBase)

    // Determine whether the new partition leaves the confines of the container.

    if ( partitionBase + partitionSize > media->getSize() )  return true;

    return false;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOMedia * IONeXTPartitionScheme::instantiateMediaObject(
                                                partition_t *  partition,
                                                UInt32         partitionID,
                                                UInt64         labelBase,
                                                disk_label_t * labelMap )
{
    //
    // Instantiate a new media object to represent the given partition.
    //

    IOMedia * media              = getProvider();
    UInt64    partitionBase      = 0;
    UInt64    partitionBlockSize = OSSwapBigToHostInt32(labelMap->dl_secsize);
    char *    partitionHint      = 0;
    char *    partitionName      = 0;
    UInt64    partitionSize      = 0;

    // Compute the relative byte position and size of the new partition.

    partitionBase  = OSSwapBigToHostInt32(partition->p_base) +
                     OSSwapBigToHostInt16(labelMap->dl_front);
    partitionSize  = OSSwapBigToHostInt32(partition->p_size);
    partitionBase *= OSSwapBigToHostInt32(labelMap->dl_secsize);
    partitionSize *= OSSwapBigToHostInt32(labelMap->dl_secsize);
    partitionBase -= labelBase;

    // Look up a type for the new partition.

    OSDictionary * hintTable = OSDynamicCast( 
              /* type     */ OSDictionary,
              /* instance */ getProperty(kIONeXTPartitionSchemeContentTable) );

    if ( hintTable )
    {
        OSString * hintValue = OSDynamicCast( 
                       /* type     */ OSString,
                       /* instance */ hintTable->getObject(partition->p_type) );

        if ( hintValue ) partitionHint = (char *) hintValue->getCStringNoCopy();
    }

    // Look up a name for the new partition.

    if ( partition->p_mountpt[0] )
        partitionName = partition->p_mountpt;
    else if ( labelMap->dl_label[0] )
        partitionName = labelMap->dl_label;

    // Create the new media object.

    IOMedia * newMedia = instantiateDesiredMediaObject(
                                   /* partition   */ partition,
                                   /* partitionID */ partitionID,
                                   /* labelBase   */ labelBase,
                                   /* labelMap    */ labelMap );

    if ( newMedia )
    {
        if ( newMedia->init(
                /* base               */ partitionBase,
                /* size               */ partitionSize,
                /* preferredBlockSize */ partitionBlockSize,
                /* isEjectable        */ media->isEjectable(),
                /* isWhole            */ false,
                /* isWritable         */ media->isWritable(),
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

IOMedia * IONeXTPartitionScheme::instantiateDesiredMediaObject(
                                                partition_t *  partition,
                                                UInt32         partitionID,
                                                UInt64         labelBase,
                                                disk_label_t * labelMap )
{
    //
    // Allocate a new media object (called from instantiateMediaObject).
    //

    return new IOMedia;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

UInt16 IONeXTPartitionScheme::checksum16(void * data, UInt32 bytes) const
{
    //
    // Compute a big-endian, 16-bit checksum over the specified data range.
    //

    UInt32   sum1 = 0;
    UInt32   sum2;
    UInt16 * wp = (UInt16 *) data;

    while ( bytes >= 2 )
    {
        sum1  += OSSwapBigToHostInt16(*wp);
        bytes -= sizeof(UInt16);
        wp++;
    }

    sum2 = ((sum1 & 0xFFFF0000) >> 16) + (sum1 & 0xFFFF);

    if ( sum2 > 65535 )
        sum2 -= 65535;

    return sum2;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IONeXTPartitionScheme, 0);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IONeXTPartitionScheme, 1);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IONeXTPartitionScheme, 2);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IONeXTPartitionScheme, 3);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IONeXTPartitionScheme, 4);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IONeXTPartitionScheme, 5);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IONeXTPartitionScheme, 6);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IONeXTPartitionScheme, 7);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IONeXTPartitionScheme, 8);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IONeXTPartitionScheme, 9);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IONeXTPartitionScheme, 10);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IONeXTPartitionScheme, 11);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IONeXTPartitionScheme, 12);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IONeXTPartitionScheme, 13);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IONeXTPartitionScheme, 14);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IONeXTPartitionScheme, 15);
