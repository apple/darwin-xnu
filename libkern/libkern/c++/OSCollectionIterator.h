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
/* IOCollectionIterator.h created by gvdl on Fri 1998-10-30 */

#ifndef _OS_OSCOLLECTIONITERATOR_H
#define _OS_OSCOLLECTIONITERATOR_H

#include <libkern/c++/OSIterator.h>

class OSCollection;

/*!
    @class OSCollectionIterator
    @discussion
    OSCollectionIterator objects provide a consistent mechanism to iterate through all OSCollection derived collections.
*/
class OSCollectionIterator : public OSIterator
{
    OSDeclareDefaultStructors(OSCollectionIterator)

protected:
    const OSCollection *collection;
    void *collIterator;
    unsigned int initialUpdateStamp;
    bool valid;

public:
    /*!
        @function withCollection
        @abstract A static constructor function which creates and initializes an instance of OSCollectionIterator for the provided collection object.
        @param inColl The OSCollection derived collection object to be iteratated.
        @result Returns a new instance of OSCollection or 0 on failure.
    */
    static OSCollectionIterator *withCollection(const OSCollection *inColl);

    /*!
        @function withCollection
        @abstract A member function to initialize the intance of OSCollectionIterator with the provided colleciton object.
        @param inColl The OSCollection derived collection object to be iteratated.
        @result Returns true if the initialization was successful or false on failure.
    */
    virtual bool initWithCollection(const OSCollection *inColl);
    /*!
        @function free
        @abstract A member function to release and deallocate all resources created or used by the OSCollectionIterator object.
        @discussion This function should not be called directly, use release() instead.
    */
    virtual void free();

    /*!
        @function reset
        @abstract A member function which resets the iterator to begin the next iteration from the beginning of the collection.
    */
    virtual void reset();

    /*!
        @function isValid
        @abstract A member function for determining if the collection was modified during iteration.
    */
    virtual bool isValid();

    /*!
        @function getNextObject
        @abstract A member function to get the next object in the collection being iterated.
        @result Returns the next object in the collection or 0 when the end has been reached.
    */
    virtual OSObject *getNextObject();
};

#endif /* !_OS_OSCOLLECTIONITERATOR_H */
