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
 * @header IODVDMedia
 * @abstract
 * This header contains the IODVDMedia class definition.
 */

#ifndef _IODVDMEDIA_H
#define _IODVDMEDIA_H

/*!
 * @defined kIODVDMediaClass
 * @abstract
 * kIODVDMediaClass is the name of the IODVDMedia class.
 * @discussion
 * kIODVDMediaClass is the name of the IODVDMedia class.
 */

#define kIODVDMediaClass "IODVDMedia"

/*!
 * @defined kIODVDMediaTypeKey
 * @abstract
 * kIODVDMediaTypeKey is a property of IODVDMedia objects.  It has an OSString
 * value.
 * @discussion
 * The kIODVDMediaTypeKey property identifies the DVD media type (DVD-ROM,
 * DVD-R, DVD-RW, DVD+RW, DVD-RAM, etc).  See the kIODVDMediaType contants
 * for possible values.
 */

#define kIODVDMediaTypeKey "Type"

/*!
 * @defined kIODVDMediaTypeROM
 * The kIODVDMediaTypeKey constant for DVD-ROM media.
 */

#define kIODVDMediaTypeROM "DVD-ROM"

/*!
 * @defined kIODVDMediaTypeR
 * The kIODVDMediaTypeKey constant for DVD Recordable (DVD-R) media.
 */

#define kIODVDMediaTypeR "DVD-R"

/*!
 * @defined kIODVDMediaTypeRW
 * The kIODVDMediaTypeKey constant for DVD ReWritable (DVD-RW) media.
 */

#define kIODVDMediaTypeRW "DVD-RW"

/*!
 * @defined kIODVDMediaTypePlusRW
 * The kIODVDMediaTypeKey constant for DVD "Plus" ReWritable (DVD+RW) media.
 */

#define kIODVDMediaTypePlusRW "DVD+RW"

/*!
 * @defined kIODVDMediaTypeRAM
 * The kIODVDMediaTypeKey constant for DVD-RAM media.
 */

#define kIODVDMediaTypeRAM "DVD-RAM"

/*
 * Kernel
 */

#if defined(KERNEL) && defined(__cplusplus)

#include <IOKit/storage/IODVDBlockStorageDriver.h>
#include <IOKit/storage/IOMedia.h>

/*!
 * @class IODVDMedia
 * @abstract
 * The IODVDMedia class is a random-access disk device abstraction for DVDs.
 * @discussion
 * The IODVDMedia class is a random-access disk device abstraction for DVDs.
 */

class IODVDMedia : public IOMedia
{
    OSDeclareDefaultStructors(IODVDMedia)

protected:

    struct ExpansionData { /* */ };
    ExpansionData * _expansionData;

public:

    /*
     * Obtain this object's provider.   We override the superclass's method to
     * return a more specific subclass of IOService -- IODVDBlockStorageDriver.  
     * This method serves simply as a convenience to subclass developers.
     */

    virtual IODVDBlockStorageDriver * getProvider() const;

    OSMetaClassDeclareReservedUnused(IODVDMedia,  0);
    OSMetaClassDeclareReservedUnused(IODVDMedia,  1);
    OSMetaClassDeclareReservedUnused(IODVDMedia,  2);
    OSMetaClassDeclareReservedUnused(IODVDMedia,  3);
    OSMetaClassDeclareReservedUnused(IODVDMedia,  4);
    OSMetaClassDeclareReservedUnused(IODVDMedia,  5);
    OSMetaClassDeclareReservedUnused(IODVDMedia,  6);
    OSMetaClassDeclareReservedUnused(IODVDMedia,  7);
    OSMetaClassDeclareReservedUnused(IODVDMedia,  8);
    OSMetaClassDeclareReservedUnused(IODVDMedia,  9);
    OSMetaClassDeclareReservedUnused(IODVDMedia, 10);
    OSMetaClassDeclareReservedUnused(IODVDMedia, 11);
    OSMetaClassDeclareReservedUnused(IODVDMedia, 12);
    OSMetaClassDeclareReservedUnused(IODVDMedia, 13);
    OSMetaClassDeclareReservedUnused(IODVDMedia, 14);
    OSMetaClassDeclareReservedUnused(IODVDMedia, 15);
    OSMetaClassDeclareReservedUnused(IODVDMedia, 16);
    OSMetaClassDeclareReservedUnused(IODVDMedia, 17);
    OSMetaClassDeclareReservedUnused(IODVDMedia, 18);
    OSMetaClassDeclareReservedUnused(IODVDMedia, 19);
    OSMetaClassDeclareReservedUnused(IODVDMedia, 20);
    OSMetaClassDeclareReservedUnused(IODVDMedia, 21);
    OSMetaClassDeclareReservedUnused(IODVDMedia, 22);
    OSMetaClassDeclareReservedUnused(IODVDMedia, 23);
    OSMetaClassDeclareReservedUnused(IODVDMedia, 24);
    OSMetaClassDeclareReservedUnused(IODVDMedia, 25);
    OSMetaClassDeclareReservedUnused(IODVDMedia, 26);
    OSMetaClassDeclareReservedUnused(IODVDMedia, 27);
    OSMetaClassDeclareReservedUnused(IODVDMedia, 28);
    OSMetaClassDeclareReservedUnused(IODVDMedia, 29);
    OSMetaClassDeclareReservedUnused(IODVDMedia, 30);
    OSMetaClassDeclareReservedUnused(IODVDMedia, 31);
};

#endif /* defined(KERNEL) && defined(__cplusplus) */

#endif /* !_IODVDMEDIA_H */
