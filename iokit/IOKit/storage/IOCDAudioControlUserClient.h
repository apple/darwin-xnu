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

#ifndef _IOCDAUDIOCONTROLUSERCLIENT_H
#define _IOCDAUDIOCONTROLUSERCLIENT_H

#include <IOKit/storage/IOCDTypes.h>

/*
 * Audio Control User Client Methods
 */

enum
{
    kIOCDAudioControlMethodGetStatus, // IOCDAudioControlUserClient::getStatus()
    kIOCDAudioControlMethodGetTOC,    // IOCDAudioControlUserClient::getTOC()
    kIOCDAudioControlMethodGetVolume, // IOCDAudioControlUserClient::getVolume()
    kIOCDAudioControlMethodSetVolume, // IOCDAudioControlUserClient::setVolume()
    kIOCDAudioControlMethodPause,     // IOCDAudioControlUserClient::pause()
    kIOCDAudioControlMethodPlay,      // IOCDAudioControlUserClient::play()
    kIOCDAudioControlMethodScan,      // IOCDAudioControlUserClient::scan()
    kIOCDAudioControlMethodStop,      // IOCDAudioControlUserClient::stop()
    kIOCDAudioControlMethodCount      // (total number of methods supported)
};

/*
 * Kernel
 */

#if defined(KERNEL) && defined(__cplusplus)

#include <IOKit/IOUserClient.h>
#include <IOKit/storage/IOCDAudioControl.h>

class IOCDAudioControlUserClient : public IOUserClient
{
    OSDeclareDefaultStructors(IOCDAudioControlUserClient)

protected:

    struct ExpansionData { /* */ };
    ExpansionData * _expansionData;

    IOExternalMethod _methods[kIOCDAudioControlMethodCount];

    /*
     * Get the current audio play status information.
     */

    virtual IOReturn getStatus(CDAudioStatus * status, UInt32 * statusSize);

    /*
     * Get the full Table Of Contents.
     */

    virtual IOReturn getTOC(CDTOC * toc, UInt32 * tocMaxSize);

    /*
     * Get the current audio volume.
     */

    virtual IOReturn getVolume(UInt32 * left, UInt32 * right);

    /*
     * Set the current audio volume.
     */

    virtual IOReturn setVolume(UInt32 left, UInt32 right);

    /*
     * Pause or resume the audio playback.
     */

    virtual IOReturn pause(UInt32 pause);

    /*
     * Play audio.
     */

    virtual IOReturn play(UInt32 msfStart, UInt32 msfStop);

    /*
     * Perform a fast-forward or fast-backward operation.
     */

    virtual IOReturn scan(UInt32 msfStart, UInt32 reverse);

    /*
     * Stop the audio playback (or audio scan).
     */

    virtual IOReturn stop();

public:

    /*
     * Create a new IOCDAudioControlUserClient.
     */

    static  IOCDAudioControlUserClient * withTask(task_t task);

    /*
     * Prepare the user client for usage.
     */

    virtual bool start(IOService * provider);

    /*
     * Relinquish the user client.
     */

    virtual IOReturn clientClose();

    /*
     * Obtain the method definition given a method index.
     */

    virtual IOExternalMethod * getExternalMethodForIndex(UInt32 index);

    /*
     * Obtain this object's provider.  We override the superclass's method
     * to return a more specific subclass of IOService -- IOCDAudioControl.  
     * This method serves simply as a convenience to subclass developers.
     */

    virtual IOCDAudioControl * getProvider() const;

    OSMetaClassDeclareReservedUnused(IOCDAudioControlUserClient,  0);
    OSMetaClassDeclareReservedUnused(IOCDAudioControlUserClient,  1);
    OSMetaClassDeclareReservedUnused(IOCDAudioControlUserClient,  2);
    OSMetaClassDeclareReservedUnused(IOCDAudioControlUserClient,  3);
    OSMetaClassDeclareReservedUnused(IOCDAudioControlUserClient,  4);
    OSMetaClassDeclareReservedUnused(IOCDAudioControlUserClient,  5);
    OSMetaClassDeclareReservedUnused(IOCDAudioControlUserClient,  6);
    OSMetaClassDeclareReservedUnused(IOCDAudioControlUserClient,  7);
};

#endif /* defined(KERNEL) && defined(__cplusplus) */

#endif /* _IOCDAUDIOCONTROLUSERCLIENT_H */
