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
/*
 * IODVDBlockStorageDriver.h
 *
 * This class implements DVD functionality, independent of
 * the physical connection protocol (e.g. SCSI, ATA, USB).
 *
 * A protocol-specific provider implements the functionality using an appropriate
 * protocol and commands.
 */

#ifndef	_IODVDBLOCKSTORAGEDRIVER_H
#define	_IODVDBLOCKSTORAGEDRIVER_H

#include <IOKit/IOTypes.h>
#include <IOKit/storage/IOCDBlockStorageDriver.h>
#include <IOKit/storage/IODVDBlockStorageDevice.h>
#include <IOKit/storage/IODVDTypes.h>

/*!
 * @defined kIODVDBlockStorageDriverClass
 * @abstract
 * kIODVDBlockStorageDriverClass is the name of the IODVDBlockStorageDriver class.
 * @discussion
 * kIODVDBlockStorageDriverClass is the name of the IODVDBlockStorageDriver class.
 */

#define kIODVDBlockStorageDriverClass "IODVDBlockStorageDriver"

class IODVDBlockStorageDevice;

/*!
 * @class
 * IODVDBlockStorageDriver : public IOCDBlockStorageDriver
 * @abstract
 * Generic DVD Driver.
 * @discussion
 * Storage drivers are split into two parts: the Generic Driver handles
 * all generic device issues, independent of the lower-level transport
 * mechanism (e.g. SCSI, ATA, USB, FireWire). All storage operations
 * at the Generic Driver level are translated into a series of generic
 * device operations. These operations are passed via the Device Nub
 * to a Transport Driver, which implements the appropriate
 * transport-dependent protocol to execute these operations.
 * 
 * To determine the write-protect state of a device (or media), for
 * example, the generic driver would issue a call to the
 * Transport Driver's reportWriteProtection method. If this were a SCSI
 * device, its Transport Driver would issue a Mode Sense command to
 * extract the write-protection status bit. The Transport Driver then
 * reports true or false to the generic driver.
 * 
 * The generic driver therefore has no knowledge of, or involvement
 * with, the actual commands and mechanisms used to communicate with
 * the device. It is expected that the generic driver will rarely, if
 * ever, need to be subclassed to handle device idiosyncrasies; rather,
 * the Transport Driver should be changed via overrides.
 * 
 * A generic driver could be subclassed to create a different type of
 * generic device. The generic driver IODVDBlockStorageDriver class is a subclass
 * of IOCDBlockStorageDriver, adding DVD functions. Similarly, the Transport Driver
 * IODVDBlockStorageDevice is a subclass of IOCDBlockStorageDevice, adding DVD 
 * functions.
*/

class IODVDBlockStorageDriver : public IOCDBlockStorageDriver {

    OSDeclareDefaultStructors(IODVDBlockStorageDriver)

protected:

    struct ExpansionData { /* */ };
    ExpansionData * _expansionData;

public:

    /* Overrides of IOCDBlockStorageDriver: */

    virtual const char * getDeviceTypeName(void);
    virtual IOMedia *	instantiateDesiredMediaObject(void);
    virtual IOMedia *	instantiateMediaObject(UInt64 base,UInt64 byteSize,
                                            UInt32 blockSize,char *mediaName);

    /* End of IOCDBlockStorageDriver overrides. */

    /*!
     * @function reportKey
     * @abstract
     * Get key info from the DVD drive.
     * @discussion
     * This function handles the getting of key- and encryption-related data for the drive.
     * @param buffer
     * A buffer containing information, as documented in the specification
     * "MtFuji Commands For Multimedia Devices."
     * @param keyClass
     * As documented by MtFuji. See DVDKeyClass.
     * @param agid
     * An AGID, as documented by MtFuji.
     * @param keyFormat
     * As documented by MtFuji. See DVDKeyFormat.
     */
    virtual IOReturn	reportKey(IOMemoryDescriptor *buffer,const DVDKeyClass keyClass,
                                        const UInt32 lba,const UInt8 agid,const DVDKeyFormat keyFormat);

    /*!
     * @function sendKey
     * @abstract
     * Send key info to the DVD drive.
     * @discussion
     * This function handles the setting of key- and encryption-related data for the drive.
     * @param buffer
     * A buffer containing information, as documented in the specification
     * "MtFuji Commands For Multimedia Devices."
     * @param keyClass
     * As documented by MtFuji. See DVDKeyClass.
     * @param agid
     * As documented by MtFuji.
     * @param keyFormat
     * As documented by MtFuji. See DVDKeyFormat.
     */
    virtual IOReturn	sendKey(IOMemoryDescriptor *buffer,const DVDKeyClass keyClass,
                                        const UInt8 agid,const DVDKeyFormat keyFormat);

    /*
     * Obtain this object's provider.  We override the superclass's method to
     * return a more specific subclass of IOService -- IODVDBlockStorageDevice.  
     * This method serves simply as a convenience to subclass developers.
     */

    virtual IODVDBlockStorageDevice * getProvider() const;

protected:

    /* Overrides of IOCDBlockStorageDriver behavior. */

    virtual IOReturn	acceptNewMedia(void);

    /* End of IOCDBlockStorageDriver overrides. */

    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDriver,  0);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDriver,  1);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDriver,  2);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDriver,  3);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDriver,  4);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDriver,  5);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDriver,  6);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDriver,  7);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDriver,  8);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDriver,  9);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDriver, 10);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDriver, 11);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDriver, 12);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDriver, 13);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDriver, 14);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDriver, 15);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDriver, 16);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDriver, 17);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDriver, 18);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDriver, 19);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDriver, 20);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDriver, 21);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDriver, 22);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDriver, 23);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDriver, 24);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDriver, 25);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDriver, 26);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDriver, 27);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDriver, 28);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDriver, 29);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDriver, 30);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDriver, 31);
};
#endif
