/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
#include <IOKit/IOLib.h>
#include <IOKit/storage/IODVDBlockStorageDevice.h>
#include <IOKit/storage/IODVDBlockStorageDriver.h>
#include <IOKit/storage/IODVDMedia.h>

#define	super	IOCDBlockStorageDriver
OSDefineMetaClassAndStructors(IODVDBlockStorageDriver,IOCDBlockStorageDriver)

IODVDBlockStorageDevice *
IODVDBlockStorageDriver::getProvider() const
{
    return (IODVDBlockStorageDevice *) IOService::getProvider();
}

/* Accept a new piece of media, doing whatever's necessary to make it
 * show up properly to the system.
 */
IOReturn
IODVDBlockStorageDriver::acceptNewMedia(void)
{
    UInt32 mediaType = getMediaType();

    if (mediaType >= kCDMediaTypeMin && mediaType <= kCDMediaTypeMax) {
        return IOCDBlockStorageDriver::acceptNewMedia();
    } else {
        return IOBlockStorageDriver::acceptNewMedia();
    }
}

const char *
IODVDBlockStorageDriver::getDeviceTypeName(void)
{
    return(kIOBlockStorageDeviceTypeDVD);
}

IOMedia *
IODVDBlockStorageDriver::instantiateDesiredMediaObject(void)
{
    UInt32 mediaType = getMediaType();

    if (mediaType >= kCDMediaTypeMin && mediaType <= kCDMediaTypeMax) {
        return IOCDBlockStorageDriver::instantiateDesiredMediaObject();
    } else {
        return(new IODVDMedia);
    }
}

IOMedia *
IODVDBlockStorageDriver::instantiateMediaObject(UInt64 base,UInt64 byteSize,
                                        UInt32 blockSize,char *mediaName)
{
    IOMedia *media = NULL;
    UInt32 mediaType = getMediaType();

    if (mediaType >= kCDMediaTypeMin && mediaType <= kCDMediaTypeMax) {
        return IOCDBlockStorageDriver::instantiateMediaObject(
                                             base,byteSize,blockSize,mediaName);
    } else {
        media = IOBlockStorageDriver::instantiateMediaObject(
                                             base,byteSize,blockSize,mediaName);
    }

    if (media) {
        char *description = NULL;

        switch (mediaType) {
            case kDVDMediaTypeROM:
                description = kIODVDMediaTypeROM;
                break;
            case kDVDMediaTypeRAM:
                description = kIODVDMediaTypeRAM;
                break;
            case kDVDMediaTypeR:
                description = kIODVDMediaTypeR;
                break;
            case kDVDMediaTypeRW:
                description = kIODVDMediaTypeRW;
                break;
            case kDVDMediaTypePlusRW:
                description = kIODVDMediaTypePlusRW;
                break;
        }

        if (description) {
            media->setProperty(kIODVDMediaTypeKey, description);
        }
    }

    return media;
}

IOReturn
IODVDBlockStorageDriver::reportKey(IOMemoryDescriptor *buffer,const DVDKeyClass keyClass,
                                        const UInt32 lba,const UInt8 agid,const DVDKeyFormat keyFormat)
{
    return(getProvider()->reportKey(buffer,keyClass,lba,agid,keyFormat));
}

IOReturn
IODVDBlockStorageDriver::sendKey(IOMemoryDescriptor *buffer,const DVDKeyClass keyClass,
                                        const UInt8 agid,const DVDKeyFormat keyFormat)
{
    return(getProvider()->sendKey(buffer,keyClass,agid,keyFormat));
}

OSMetaClassDefineReservedUnused(IODVDBlockStorageDriver,  0);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDriver,  1);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDriver,  2);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDriver,  3);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDriver,  4);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDriver,  5);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDriver,  6);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDriver,  7);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDriver,  8);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDriver,  9);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDriver, 10);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDriver, 11);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDriver, 12);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDriver, 13);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDriver, 14);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDriver, 15);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDriver, 16);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDriver, 17);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDriver, 18);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDriver, 19);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDriver, 20);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDriver, 21);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDriver, 22);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDriver, 23);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDriver, 24);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDriver, 25);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDriver, 26);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDriver, 27);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDriver, 28);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDriver, 29);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDriver, 30);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDriver, 31);
