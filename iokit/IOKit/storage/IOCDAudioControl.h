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
 * @header IOCDAudioControl
 * @abstract
 * This header contains the IOCDAudioControl class definition.
 */

#ifndef	_IOCDAUDIOCONTROL_H
#define	_IOCDAUDIOCONTROL_H

/*!
 * @defined kIOCDAudioControlClass
 * @abstract
 * kIOCDAudioControlClass is the name of the IOCDAudioControl class.
 * @discussion
 * kIOCDAudioControlClass is the name of the IOCDAudioControl class.
 */

#define kIOCDAudioControlClass "IOCDAudioControl"

/*
 * Kernel
 */

#if defined(KERNEL) && defined(__cplusplus)

#include <IOKit/storage/IOCDBlockStorageDriver.h>

/*!
 * @class IOCDAudioControl
 * @discussion
 * This class is the protocol for CD audio control functionality, independent of
 * the physical connection protocol (eg. SCSI, ATA, USB).  Any methods that deal
 * with audio play and/or volume are here.
 */

class IOCDAudioControl : public IOService
{
    OSDeclareDefaultStructors(IOCDAudioControl)

protected:

    struct ExpansionData { /* */ };
    ExpansionData * _expansionData;

    /*
     * Create a new IOCDAudioControlUserClient.
     */

    virtual IOReturn newUserClient( task_t          task,
                                    void *          security,
                                    UInt32          type,
                                    IOUserClient ** object ); 

public:

    /*!
     * @function getStatus
     * @abstract
     * Get the current audio play status information.
     * @param status
     * The buffer for the returned information.
     */

    virtual IOReturn getStatus(CDAudioStatus * status);

    /*!
     * @function getTOC
     * @abstract
     * Get the full Table Of Contents.
     * @result
     * Returns a pointer to the TOC buffer (do not deallocate).
     */

    virtual CDTOC * getTOC(void);

    /*!
     * @function getVolume
     * @abstract
     * Get the current audio volume.
     * @param left
     * A pointer to the returned left-channel volume.
     * @param right
     * A pointer to the returned right-channel volume.
     */

    virtual IOReturn getVolume(UInt8 * left, UInt8 * right);

    /*!
     * @function setVolume
     * @abstract
     * Set the current audio volume.
     * @param left
     * The desired left-channel volume.
     * @param right
     * The desired right-channel volume.
     */

    virtual IOReturn setVolume(UInt8 left, UInt8 right);

    /*!
     * @function pause
     * @abstract
     * Pause or resume the audio playback.
     * @param pause
     * True to pause playback; False to resume.
     */

    virtual IOReturn pause(bool pause);

    /*!
     * @function play
     * @abstract
     * Play audio.
     * @param timeStart
     * The M:S:F address from which to begin.
     * @param timeStop
     * The M:S:F address at which to stop.
     */

    virtual IOReturn play(CDMSF timeStart, CDMSF timeStop);

    /*!
     * @function scan
     * @abstract
     * Perform a fast-forward or fast-backward operation.
     * @param timeStart
     * The M:S:F address from which to begin.
     * @param reverse
     * True to go backward; False to go forward.
     */

    virtual IOReturn scan(CDMSF timeStart, bool reverse);

    /*!
     * @function stop
     * @abstract
     * Stop the audio playback (or audio scan).
     */
    
    virtual IOReturn stop();

    /*
     * Obtain this object's provider.  We override the superclass's method to
     * return a more specific subclass of IOService -- IOCDBlockStorageDriver.  
     * This method serves simply as a convenience to subclass developers.
     */

    virtual IOCDBlockStorageDriver * getProvider() const;

    OSMetaClassDeclareReservedUnused(IOCDAudioControl,  0);
    OSMetaClassDeclareReservedUnused(IOCDAudioControl,  1);
    OSMetaClassDeclareReservedUnused(IOCDAudioControl,  2);
    OSMetaClassDeclareReservedUnused(IOCDAudioControl,  3);
    OSMetaClassDeclareReservedUnused(IOCDAudioControl,  4);
    OSMetaClassDeclareReservedUnused(IOCDAudioControl,  5);
    OSMetaClassDeclareReservedUnused(IOCDAudioControl,  6);
    OSMetaClassDeclareReservedUnused(IOCDAudioControl,  7);
};

#endif /* defined(KERNEL) && defined(__cplusplus) */

#endif /* !_IOCDAUDIOCONTROL_H */
