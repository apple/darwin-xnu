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
 * @header IOCDMedia
 * @abstract
 * This header contains the IOCDMedia class definition.
 */

#ifndef _IOCDMEDIA_H
#define _IOCDMEDIA_H

/*!
 * @defined kIOCDMediaClass
 * @abstract
 * kIOCDMediaClass is the name of the IOCDMedia class.
 * @discussion
 * kIOCDMediaClass is the name of the IOCDMedia class.
 */

#define kIOCDMediaClass "IOCDMedia"

/*!
 * @defined kIOCDMediaTOCKey
 * @abstract
 * kIOCDMediaTOCKey is a property of IOCDMedia objects.  It has an OSData value
 * and a CDTOC structure.
 * @discussion
 * The kIOCDMediaTOCKey property contains the CD's full table of contents,
 * formatted as a CDTOC structure.  The CDTOC structure is same as what is
 * returned by a READ TOC command, format 0x02, but with BCD numbers converted
 * to binary-encoded numbers, and the multi-byte fields converted to
 * host-endianess.
 */

#define kIOCDMediaTOCKey "TOC"
#define kIOCDMediaTOC "TOC" ///d:deprecated

/*!
 * @defined kIOCDMediaTypeKey
 * @abstract
 * kIOCDMediaTypeKey is a property of IOCDMedia objects.  It has an OSString
 * value.
 * @discussion
 * The kIOCDMediaTypeKey property identifies the CD media type (CD-ROM, CD-R,
 * CD-RW, etc).  See the kIOCDMediaType contants for possible values.
 */

#define kIOCDMediaTypeKey "Type"

/*!
 * @defined kIOCDMediaTypeROM
 * The kIOCDMediaTypeKey constant for CD-ROM media (inclusive of the CD-I,
 * CD-ROM XA, and CD Audio standards, and mixed mode combinations thereof).
 */

#define kIOCDMediaTypeROM "CD-ROM"

/*!
 * @defined kIOCDMediaTypeR
 * The kIOCDMediaTypeKey constant for CD Recordable (CD-R) media.
 */

#define kIOCDMediaTypeR "CD-R"

/*!
 * @defined kIOCDMediaTypeRW
 * The kIOCDMediaTypeKey constant for CD ReWritable (CD-RW) media.
 */

#define kIOCDMediaTypeRW "CD-RW"

/*
 * Kernel
 */

#if defined(KERNEL) && defined(__cplusplus)

#include <IOKit/storage/IOCDBlockStorageDriver.h>
#include <IOKit/storage/IOMedia.h>

/*!
 * @class IOCDMedia
 * @abstract
 * The IOCDMedia class is a random-access disk device abstraction for CDs.
 * @discussion
 * The IOCDMedia class is a random-access disk device abstraction for CDs. It
 * extends the IOMedia class by implementing special CD APIs, such as readCD,
 * and publishing the TOC as a property of the IOCDMedia object.
 */

class IOCDMedia : public IOMedia
{
    OSDeclareDefaultStructors(IOCDMedia)

protected:

    struct ExpansionData { /* */ };
    ExpansionData * _expansionData;

public:

///m:2333367:workaround:commented:start
//  using read;
///m:2333367:workaround:commented:stop

    /*!
     * @function read
     * @discussion
     * Read data from the storage object at the specified byte offset into the
     * specified buffer, asynchronously.   When the read completes, the caller
     * will be notified via the specified completion action.
     *
     * The buffer will be retained for the duration of the read.
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
     * @function readCD
     * @discussion
     * Read data from the CD media object at the specified byte offset into the
     * specified buffer, asynchronously.  Special areas of the CD sector can be
     * read via this method, such as the header and subchannel data.   When the
     * read completes, the caller will be notified via the specified completion
     * action.
     *
     * The buffer will be retained for the duration of the read.
     * @param client
     * Client requesting the read.
     * @param byteStart
     * Starting byte offset for the data transfer (see withAreas parameter).
     * @param buffer
     * Buffer for the data transfer.  The size of the buffer implies the size of
     * the data transfer.
     * @param sectorArea
     * Sector area(s) to read.  The sum of each area's size defines the "natural
     * block size" of the media for the call, which should be taken into account
     * when computing the address of byteStart.  See IOCDTypes.h.
     * @param sectorType
     * Sector type that is expected.  The data transfer is terminated as soon as
     * data is encountered that does not match the expected type.
     * @param completion
     * Completion routine to call once the data transfer is complete.
     */

    virtual void readCD(IOService *          client,
                        UInt64               byteStart,
                        IOMemoryDescriptor * buffer,
                        CDSectorArea         sectorArea,
                        CDSectorType         sectorType,
                        IOStorageCompletion  completion);

    /*!
     * @function readCD
     * @discussion
     * Read data from the CD media object at the specified byte offset into the
     * specified buffer, synchronously.   Special areas of the CD sector can be
     * read via this method, such as the header and subchannel data.   When the
     * read completes, this method will return to the caller.   The actual byte
     * count field is optional.
     * @param client
     * Client requesting the read.
     * @param byteStart
     * Starting byte offset for the data transfer.
     * @param buffer
     * Buffer for the data transfer.  The size of the buffer implies the size of
     * the data transfer.
     * @param sectorArea
     * Sector area(s) to read.  The sum of each area's size defines the "natural
     * block size" of the media for the call, which should be taken into account
     * when computing the address of byteStart.  See IOCDTypes.h.
     * @param sectorType
     * Sector type that is expected.  The data transfer is terminated as soon as
     * data is encountered that does not match the expected type.
     * @param actualByteCount
     * Returns the actual number of bytes transferred in the data transfer.
     * @result
     * Returns the status of the data transfer.
     */

    virtual IOReturn readCD(IOService *          client,
                            UInt64               byteStart,
                            IOMemoryDescriptor * buffer,
                            CDSectorArea         sectorArea,
                            CDSectorType         sectorType,
                            UInt64 *             actualByteCount = 0);

    /*!
     * @function readISRC
     * @abstract
     * Read the International Standard Recording Code for the specified track.
     * @param track
     * The track number from which to read the ISRC.
     * @param isrc
     * The buffer for the ISRC data.  Buffer contents will be zero-terminated.
     */

    virtual IOReturn readISRC(UInt8 track, CDISRC isrc);
    
    /*!
     * @function readMCN
     * @abstract
     * Read the Media Catalog Number (also known as the Universal Product Code).
     * @param mcn
     * The buffer for the MCN data.  Buffer contents will be zero-terminated.
     */

    virtual IOReturn readMCN(CDMCN mcn);

    /*
     * @function getTOC
     * @discussion
     * Get the full Table Of Contents.
     *
     * All CDTOC fields passed across I/O Kit APIs are guaranteed to be
     * binary-encoded numbers (not BCD) and converted to host-endianess.
     * @result
     * Returns a pointer to the TOC buffer (do not deallocate).
     */
     
    virtual CDTOC * getTOC();

    /*
     * Obtain this object's provider.  We override the superclass's method to
     * return a more specific subclass of IOService -- IOCDBlockStorageDriver.  
     * This method serves simply as a convenience to subclass developers.
     */

    virtual IOCDBlockStorageDriver * getProvider() const;

    OSMetaClassDeclareReservedUnused(IOCDMedia,  0);
    OSMetaClassDeclareReservedUnused(IOCDMedia,  1);
    OSMetaClassDeclareReservedUnused(IOCDMedia,  2);
    OSMetaClassDeclareReservedUnused(IOCDMedia,  3);
    OSMetaClassDeclareReservedUnused(IOCDMedia,  4);
    OSMetaClassDeclareReservedUnused(IOCDMedia,  5);
    OSMetaClassDeclareReservedUnused(IOCDMedia,  6);
    OSMetaClassDeclareReservedUnused(IOCDMedia,  7);
    OSMetaClassDeclareReservedUnused(IOCDMedia,  8);
    OSMetaClassDeclareReservedUnused(IOCDMedia,  9);
    OSMetaClassDeclareReservedUnused(IOCDMedia, 10);
    OSMetaClassDeclareReservedUnused(IOCDMedia, 11);
    OSMetaClassDeclareReservedUnused(IOCDMedia, 12);
    OSMetaClassDeclareReservedUnused(IOCDMedia, 13);
    OSMetaClassDeclareReservedUnused(IOCDMedia, 14);
    OSMetaClassDeclareReservedUnused(IOCDMedia, 15);
};

#endif /* defined(KERNEL) && defined(__cplusplus) */

#endif /* !_IOCDMEDIA_H */
