/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

#ifndef _OS_OSORDEREDSET_H
#define _OS_OSORDEREDSET_H

#include <libkern/c++/OSCollection.h>
#include <libkern/OSTypes.h>

class OSOffset;

/*!
    @class OSOrderedSet
    @abstract A collection class for maintaining and sorting a set of OSMetaClassBase derived objects.
    @discussion
    An instance of OSOrderedSet maintains and sorts a collection of OSMetaClassBase derived objects.  The sorting algorithm is supplied to the instance via the OSOrderFunction.
*/
class OSOrderedSet : public OSCollection
{
    OSDeclareDefaultStructors(OSOrderedSet)

public:
    /*!
        @typedef OSOrderFunction
        @abstract The sorting function used by the collection to order objects.
        @param obj1 An object from the collection.
        @param obj2 An object to be compared to obj1.
        @param ref The ordering context used by the sorting function as a hint for sorting.
        @result Returns a comparison result of the object, a negative value if obj1 < obj2, 0 if obj1 == obj2, and a positive value if obj1 > obj2.
     */
    typedef SInt32 (*OSOrderFunction)(const OSMetaClassBase * obj1,
                                      const OSMetaClassBase * obj2,
                                      void * ref );

protected:
    struct _Element *   array;
    OSOrderFunction	ordering;
    void *		orderingRef;
    unsigned int 	count;
    unsigned int 	capacity;
    unsigned int 	capacityIncrement;

    struct ExpansionData { };
    
    /*! @var reserved
        Reserved for future use.  (Internal use only)  */
    ExpansionData *reserved;

protected:
    /*
     * OSCollectionIterator interfaces.
     */
    virtual unsigned int iteratorSize() const;
    virtual bool initIterator(void *iterator) const;
    virtual bool getNextObjectForIterator(void *iterator, OSObject **ret) const;

public:

    /*!
        @function withCapacity
        @abstract A static constructor function for creating and initializing an instance of OSOrderedSet.
        @param capacity The initial storage size in number of objects of the set.
        @param orderFunc A c-style function which implements the sorting algorithm for the set.
        @param orderingRef A ordering context used as a hint for ordering objects within the set.
        @result Returns an instance of OSSet, or 0 if a failure occurred.
    */
    static OSOrderedSet *withCapacity(unsigned int capacity,
                                      OSOrderFunction orderFunc = 0,
                                      void * orderingRef = 0);

    /*!
        @function initWithCapacity
        @abstract A member function for initializing an instance of OSOrderedSet.
        @param capacity The initial storage size in number of objects of the set.
        @param orderFunc A c-style function which implements the sorting algorithm for the set.
        @param orderingRef A ordering context used as a hint for ordering objects within the set.
        @result Returns true if initialization was successful, or false if a failure occurred.
    */
    virtual bool initWithCapacity(unsigned int capacity,
                                  OSOrderFunction orderFunc = 0,
                                  void * orderingRef = 0);
    /*!
        @function free
        @abstract A member function to release and deallocate any resources used by the instance of OSOrderedSet.
    */
    virtual void free();

    /*!
        @function getCount
        @abstract A member function to return the number of objects within the collection.
        @result Returns the number of items in the set.
    */
    virtual unsigned int getCount() const;
    /*!
        @function getCapacity
        @abstract A member function to return the storage capacity of the collection.
        @result Returns the total storage capacity of the set.
    */
    virtual unsigned int getCapacity() const;
    /*!
        @function getCapacityIncrement
        @abstract A member function to get the size by which the collection will grow.
        @result Returns the current growth size.
    */
    virtual unsigned int getCapacityIncrement() const;
    /*!
        @function setCapacityIncrement
        @abstract A member function to set the size by which the collection will grow.
        @param increment The new growth factor for the set.
        @result Returns new growth size.
    */
    virtual unsigned int setCapacityIncrement(unsigned increment);

    /*!
        @function ensureCapacity
        @abstract A member function to expand the size of the collection.
        @param newCapacity The new size capacity for the collection.
        @result Returns new capacity of the set when successful or the old capacity on failure.
    */
    virtual unsigned int ensureCapacity(unsigned int newCapacity);

    /*!
        @function flushCollection
        @abstract A member function to remove and release all items in the set.
    */
    virtual void flushCollection();

    /*!
        @function setObject
        @abstract A member function to place an OSMetaClassBase derived object into the set.  The object will be automatically sorted in the set.
        @param anObject The object to be placed into the collection.
        @result Returns true if object was successfully added to the collection, false otherwise.
    */
    virtual bool setObject(const OSMetaClassBase *anObject);
    /*!
        @function setFirstObject
        @abstract A member function to place an OSMetaClassBase derived object order it first in the set.
        @param anObject The object to be placed into the collection.
        @result Returns true if object was successfully added to the collection, false otherwise.
    */
    virtual bool setFirstObject(const OSMetaClassBase *anObject);
    /*!
        @function setLastObject
        @abstract A member function to place an OSMetaClassBase derived object order it last in the set.
        @param anObject The object to be placed into the collection.
        @result Returns true if object was successfully added to the collection, false otherwise.
    */
    virtual bool setLastObject(const OSMetaClassBase *anObject);

    /*!
        @function removeObject
        @abstract A member function to remove and release an object in the set.
        @param anObject The object to remove from the set.
    */
    virtual void removeObject(const OSMetaClassBase *anObject);

    /*!
        @function containsObject
        @abstract A member function to query the set for the presence of a particular object.
        @param anObject The object to be located.
        @result Returns true if the object is present in the set, false otherwise.
    */
    virtual bool containsObject(const OSMetaClassBase *anObject) const;
    /*!
        @function member
        @abstract A member function to query the set for the presence of a particular object.
        @param anObject The object to be located.
        @result Returns true if the object is present in the set, false otherwise.
    */
    virtual bool member(const OSMetaClassBase *anObject) const;

    /*!
        @function getFirstObject
        @abstract A member function to return the first object in the set.
        @result Returns the object ordered first in the set or 0 if none exist.
    */
    virtual OSObject *getFirstObject() const;
    /*!
        @function getLastObject
        @abstract A member function to return the last object in the set.
        @result Returns the object ordered last in the set or 0 if none exist.
    */
    virtual OSObject *getLastObject() const;

    /*!
        @function orderObject
        @abstract A member function to return the ordering value of an object.
        @param anObject The object to be queried.
        @result Returns the ordering value for an object.
    */
    virtual SInt32 orderObject( const OSMetaClassBase * anObject );

    /*!
        @function setObject
        @abstract A member function to place an object into the set at a particular index.
        @param index The index in the set to place the object.
        @param anObject The object to be placed into the set.
        @result Returns true if the object was successfully placed into the collection, false otherwise.
    */
    virtual bool setObject(unsigned int index, const OSMetaClassBase *anObject);
    /*!
        @function getObject
        @abstract A member function to return a reference to an object at a particular index.
        @param index The index into the set.
        @result Returns a reference to the object at the given index, 0 if none exist at that location.
    */
    virtual OSObject *getObject( unsigned int index) const;
    /*!
        @function getOrderingRef
        @abstract A member function to return a the ordering context.
        @result Returns the ordering context, or NULL if none exist.
    */
    virtual void *getOrderingRef();

    /*!
        @function isEqualTo
        @abstract A member function to test the equality between an OSOrderedSet object and the receiver.
        @param anOrderedSet The OSOrderedSet object to be compared against the receiver.
        @result Returns true if the two objects are equivalent, false otherwise.
    */
    virtual bool isEqualTo(const OSOrderedSet *anOrderedSet) const;
    /*!
        @function isEqualTo
        @abstract A member function to test the equality between an arbitrary OSMetaClassBase derived object and the receiver.
        @param anObject The OSMetaClassBase derived object to be compared against the receiver.
        @result Returns true if the two objects are equivalent, false otherwise.
    */
    virtual bool isEqualTo(const OSMetaClassBase *anObject) const;


    OSMetaClassDeclareReservedUnused(OSOrderedSet, 0);
    OSMetaClassDeclareReservedUnused(OSOrderedSet, 1);
    OSMetaClassDeclareReservedUnused(OSOrderedSet, 2);
    OSMetaClassDeclareReservedUnused(OSOrderedSet, 3);
    OSMetaClassDeclareReservedUnused(OSOrderedSet, 4);
    OSMetaClassDeclareReservedUnused(OSOrderedSet, 5);
    OSMetaClassDeclareReservedUnused(OSOrderedSet, 6);
    OSMetaClassDeclareReservedUnused(OSOrderedSet, 7);
};

#endif /* ! _OS_OSORDEREDSET_H */
