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
/* IOCollection.h created by gvdl on Thu 1998-10-22 */

#ifndef _OS_OSCOLLECTION_H
#define _OS_OSCOLLECTION_H

#include <libkern/c++/OSObject.h>

/*!
    @class OSCollection
    @abstract Abstract super class for all collections.
    @discussion
    OSCollection is the abstract super class for all OSObject derived collections and provides the necessary interfaces for managing storage space and iteration through a collection.
*/
class OSCollection : public OSObject
{
    friend class OSCollectionIterator;

    OSDeclareAbstractStructors(OSCollection)

protected:
    unsigned int updateStamp;

    struct ExpansionData { };
    
    /*! @var reserved
        Reserved for future use.  (Internal use only)  */
    ExpansionData *reserved;

    // Member functions used by the OSCollectionIterator class.
    /*
        @function iteratorSize
        @abstract A pure virtual member function to return the size of the iterator context.
        @result Returns an integer size for the storage space required to contain context necessary for iterating through a collection.
        @discussion
        This member function is called by an OSCollectionIterator object to allow it to allocate enough storage space for the iterator context.  This context contains the data necessary to iterate through the collection when getNextObjectForIterator() is called.
    */
    virtual unsigned int iteratorSize() const = 0;
    /*
        @function initIterator
        @abstract Pure virtual member function to allocate and initialize the iterator context data.
        @param iterator The iterator context.
        @result Returns true if initialization was successful, false otherwise.
    */
    virtual bool initIterator(void *iterator) const = 0;
    /*
        @function getNextObjectForIterator
        @abstract A pure virtual member function which returns the next member of a collection.
        @param iterator The iterator context.
        @param ret The object returned to the caller.
        @result Returns true if an object was found, false otherwise.
        @discussion
        This is the entry point used by an OSCollectionIterator object to advance to next object in the collection.  The iterator context is passed to the receiver to allow it to find the location of the current object and then advance the iterator context to the next object.
    */
    virtual bool getNextObjectForIterator(void *iterator, OSObject **ret) const = 0;

    /*
        @function init
        @abstract A member function to initialize the OSCollection object.
        @result Returns true if an object was initialized successfully, false otherwise.
        @discussion
        This function is used to initialize state within a newly created OSCollection object.
    */
    virtual bool init();

public:
    /*
        @function haveUpdated
        @abstract A member function to track of all updates to the collection.
    */
    void haveUpdated() { updateStamp++; };

    /*
        @function getCount
        @abstract A pure virtual member function which returns the number of objects in the collection subclass.
        @results Returns the number objects in a collection.
     */
    virtual unsigned int getCount() const = 0;
    /*
        @function getCapacity
        @abstract A pure virtual member function which returns the storage space in the collection subclass.
        @results Returns the number objects in a collection.
     */
    virtual unsigned int getCapacity() const = 0;
    /*
        @function getCapacityIncrement
        @abstract A pure virtual member function which returns the growth factor of the collection subclass.
        @results Returns the size by which the collection subclass should grow.
     */
    virtual unsigned int getCapacityIncrement() const = 0;
    /*
        @function setCapacityIncrement
        @abstract A pure virtual member function which sets the growth factor of the collection subclass.
        @param increment The new size by which the capacity of the collection should grow.
        @results Returns the new capacity increment.
     */
    virtual unsigned int setCapacityIncrement(unsigned increment) = 0;

    /*
        @function ensureCapacity
        @abstract A pure virtual member function which
        @param newCapacity
        @result
     */
    virtual unsigned int ensureCapacity(unsigned int newCapacity) = 0;

    /*
        @function flushCollection
        @abstract A pure virtual member function which
     */
    virtual void flushCollection() = 0;

    OSMetaClassDeclareReservedUnused(OSCollection, 0);
    OSMetaClassDeclareReservedUnused(OSCollection, 1);
    OSMetaClassDeclareReservedUnused(OSCollection, 2);
    OSMetaClassDeclareReservedUnused(OSCollection, 3);
    OSMetaClassDeclareReservedUnused(OSCollection, 4);
    OSMetaClassDeclareReservedUnused(OSCollection, 5);
    OSMetaClassDeclareReservedUnused(OSCollection, 6);
    OSMetaClassDeclareReservedUnused(OSCollection, 7);
};

#endif /* !_OS_OSCOLLECTION_H */
