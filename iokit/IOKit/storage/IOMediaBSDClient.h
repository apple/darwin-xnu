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

#ifndef _IOMEDIABSDCLIENT_H
#define _IOMEDIABSDCLIENT_H

#include <IOKit/IOService.h>

/*
 * Definitions
 */

class  AnchorTable;
class  MinorTable;
struct MinorSlot;

/*
 * Class
 */

class IOMediaBSDClient : public IOService
{
    OSDeclareDefaultStructors(IOMediaBSDClient)

protected:

    struct ExpansionData { /* */ };
    ExpansionData * _expansionData;

    AnchorTable * _anchors;              /* (table of anchors)                */
    bool          _bdevswInstalled;      /* (are bdevsw functions installed?) */
    bool          _cdevswInstalled;      /* (are cdevsw functions installed?) */
    MinorTable *  _minors;               /* (table of minors)                 */
    IONotifier *  _notifier;             /* (media arrival notification)      */

    /*
     * Notification handler for media arrivals.
     */

    static bool mediaHasArrived(void *, void *, IOService * service);

    /*
     * Find the whole media that roots this media tree.
     */

    virtual IOMedia * getWholeMedia( IOMedia * media,
                                     UInt32 *  slicePathSize = 0,
                                     char *    slicePath     = 0 );

    /*
     * Create bdevsw and cdevsw nodes for the given media object.
     */

    virtual bool createNodes(IOMedia * media);

    /*
     * Free all of this object's outstanding resources.
     */

    virtual void free();

public:
    /*
     * Initialize this object's minimal state.
     */

    virtual bool init(OSDictionary * properties  = 0);

    /*
     * This method is called once we have been attached to the provider object.
     */

    virtual bool start(IOService * provider);

    /*
     * This method is called before we are detached from the provider object.
     */

    virtual void stop(IOService * provider);

    /*
     * Obtain the table of anchors.
     */

    virtual AnchorTable * getAnchors();

    /*
     * Obtain the table of minors.
     */

    virtual MinorTable * getMinors();

    /*
     * Obtain information for the specified minor ID.
     */

    virtual MinorSlot * getMinor(UInt32 minorID);

    OSMetaClassDeclareReservedUnused(IOMediaBSDClient,  0);
    OSMetaClassDeclareReservedUnused(IOMediaBSDClient,  1);
    OSMetaClassDeclareReservedUnused(IOMediaBSDClient,  2);
    OSMetaClassDeclareReservedUnused(IOMediaBSDClient,  3);
    OSMetaClassDeclareReservedUnused(IOMediaBSDClient,  4);
    OSMetaClassDeclareReservedUnused(IOMediaBSDClient,  5);
    OSMetaClassDeclareReservedUnused(IOMediaBSDClient,  6);
    OSMetaClassDeclareReservedUnused(IOMediaBSDClient,  7);
    OSMetaClassDeclareReservedUnused(IOMediaBSDClient,  8);
    OSMetaClassDeclareReservedUnused(IOMediaBSDClient,  9);
    OSMetaClassDeclareReservedUnused(IOMediaBSDClient, 10);
    OSMetaClassDeclareReservedUnused(IOMediaBSDClient, 11);
    OSMetaClassDeclareReservedUnused(IOMediaBSDClient, 12);
    OSMetaClassDeclareReservedUnused(IOMediaBSDClient, 13);
    OSMetaClassDeclareReservedUnused(IOMediaBSDClient, 14);
    OSMetaClassDeclareReservedUnused(IOMediaBSDClient, 15);
};

#endif /* !_IOMEDIABSDCLIENT_H */
