/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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
/* IOArray.h created by rsulack on Thu 11-Sep-1997 */
/* IOArray.h converted to C++ by gvdl on Fri 1998-10-30 */

#ifndef _OS_OSARRAY_H
#define _OS_OSARRAY_H

#include <libkern/c++/OSCollection.h>

class OSSerialize;

/*!
    @class OSArray
    @abstract A collection class whose instances maintain a list of object references.
    @discussion
    An instance of an OSArray is a mutable collection which maintains a list of references to OSMetaClassBase derived objects.  Objects are referenced by index, where the index is an integer with a value of 0 to N-1 where N is the number of objects contained within the array.
    
    Objects placed into an array are automatically retained and objects removed or replaced are automatically released. All objects are released when the array is freed.
*/

class OSArray : public OSCollection
{
    friend class OSSet;

    OSDeclareDefaultStructors(OSArray)

protected:
    const OSMetaClassBase **array;
    unsigned int count;
    unsigned int capacity;
    unsigned int capacityIncrement;

    struct ExpansionData { };
    
    /*! @var reserved
        Reserved for future use.  (Internal use only)  */
    ExpansionData *reserved;

    /*
     * OSCollectionIterator interfaces.
     */
    virtual unsigned int iteratorSize() const;
    virtual bool initIterator(void *iterator) const;
    virtual bool getNextObjectForIterator(void *iterator, OSObject **ret) const;

public:
    /*!
        @function withCapacity
        @abstract A static constructor function to create and initialize a new instance of OSArray with a given capacity.
        @param capacity The initial capacity (number of refernces) of the OSArray instance.
        @result Returns a reference to an instance of OSArray or 0 if an error occurred.
    */
    static OSArray *withCapacity(unsigned int capacity);
    /*!
        @function withObjects
        @abstract A static constructor function to create and initialize a new instance of OSArray and populates it with a list of objects provided.
        @param objects A static array of references to OSMetaClassBase derived objects.
        @param count The number of objects provided.
        @param capacity The initial storage size of the OSArray instance. If 0, the capacity will be set to the size of count, else the capacity must be greater than or equal to count.
        @result Returns a reference to a new instance of OSArray or 0 if an error occurred.
    */
    static OSArray *withObjects(const OSObject *objects[],
                                unsigned int count,
                                unsigned int capacity = 0);
    /*!
        @function withArray
        @abstract A static constructor function to create and initialize an instance of OSArray of a given capacity and populate it with the contents of the supplied OSArray object.
        @param array An instance of OSArray from which the new instance will aquire its contents.
        @param capacity The capacity of the new OSArray.  If 0, the capacity will be set to the number of elements in the array, else the capacity must be greater than or equal to the number of elements in the array.
        @result Returns a reference to an new instance of OSArray or 0 if an error occurred.
    */
    static OSArray *withArray(const OSArray *array,
                              unsigned int capacity = 0);

    /*!
        @function initWithCapacity
        @abstract A member function which initializes an instance of OSArray.
        @param capacity The initial capacity of the new instance of OSArray.
        @result Returns a true if initialization succeeded or false if not.
    */
    virtual bool initWithCapacity(unsigned int capacity);
    /*!
        @function initWithObjects
        @abstract A member function which initializes an instance of OSArray and populates it with the given list of objects.
        @param objects A static array containing references to OSMetaClassBase derived objects.
        @param count The number of objects to added to the array.
        @param capacity The initial capacity of the new instance of OSArray.  If 0, the capacity will be set to the same value as the 'count' parameter, else capacity must be greater than or equal to the value of 'count'.
        @result Returns a true if initialization succeeded or false if not.
    */
    virtual bool initWithObjects(const OSObject *objects[],
                                 unsigned int count,
                                 unsigned int capacity = 0);
    /*!
        @function initWithArray
        @abstract A member function which initializes an instance of OSArray and populates it with the contents of the supplied OSArray object.
        @param anArray An instance of OSArray containing the references to objects which will be copied to the new instances of OSArray.
        @param capacity The initial capacity of the new instance of OSArray.  If 0, the capacity will be set to the number of elements in the array, else the capacity must be greater than or equal to the number of elements in the array.
        @result Returns a true if initialization succeeded or false if not.
    */
    virtual bool initWithArray(const OSArray *anArray,
                               unsigned int theCapacity = 0);
    /*!
        @function free
        @abstract Deallocates and releases all resources used by the OSArray instance.  Normally, this is not called directly.
        @discussion This function should not be called directly, use release() instead.
    */
    virtual void free();

    /*!
        @function getCount
        @abstract A member function which returns the number of references contained within the OSArray object.
        @result Returns the number of items within the OSArray object.
    */
    virtual unsigned int getCount() const;
    /*!
        @function getCapacity
        @abstract A member function which returns the storage capacity of the OSArray object.
        @result Returns the storage capacity of the OSArray object.
    */
    virtual unsigned int getCapacity() const;
    /*!
        @function getCapacityIncrement
        @abstract A member function which returns the size by which the array will grow.
        @result Returns the size by which the array will grow.
    */
    virtual unsigned int getCapacityIncrement() const;
    /*!
        @function setCapacityIncrement
        @abstract A member function which sets the growth size of the array.
        @result Returns the new growth size.
    */
    virtual unsigned int setCapacityIncrement(unsigned increment);

    /*!
        @function ensureCapacity
        @abstract A member function which will expand the size of the collection to a given storage capacity.
        @param newCapacity The new capacity for the array.
        @result Returns the new capacity of the array or the previous capacity upon error.
    */
    virtual unsigned int ensureCapacity(unsigned int newCapacity);

    /*!
        @function flushCollection
        @abstract A member function which removes and releases all items within the array.
    */
    virtual void flushCollection();

    /*!
        @function setObject
        @abstract A member function which appends an object onto the end of the array.
        @param anObject The object to add to the OSArray instance.  The object will be retained automatically.
        @result Returns true if the addition of 'anObject' was successful, false if not; failure usually results from failing to allocate the necessary memory.
    */
    virtual bool setObject(const OSMetaClassBase *anObject);
    /*!
        @function setObject
        @abstract A member function which inserts an object into the array at a particular index.
        @param index The index into the array to insert the object.
        @param anObject The object to add to the OSArray instance.  The object will be retained automatically.
        @result Returns true if the addition of 'anObject' was successful, false if not.
    */
    virtual bool setObject(unsigned int index, const OSMetaClassBase *anObject);

    /*!
        @function merge
        @abstract A member function which appends the contents of an array onto the receiving array.
        @param otherArray The array whose contents will be appended to the reveiving array.
        @result Returns true when merging was successful, false otherwise.
    */
    virtual bool merge(const OSArray *otherArray);

    /*!
        @function replaceObject
        @abstract A member function which will replace an object in an array at a given index.  The original object will be released and the new object will be retained.
        @param index The index into the array at which the new object will be placed.
        @param anObject The object to be placed into the array.
    */
    virtual void replaceObject(unsigned int index, const OSMetaClassBase *anObject);
    /*!
        @function removeObject
        @abstract A member function which removes an object from the array.
        @param index The index of the object to be removed.
        @discussion This function removes an object from the array which is located at a given index.  Once removed the contents of the array will shift to fill in the vacated spot. The removed object is automatically released.
    */
    virtual void removeObject(unsigned int index);
    
    /*!
        @function isEqualTo
        @abstract A member function which tests the equality of the values of two OSArray objects.
        @param anArray The array object being compared against the receiver.
        @result Returns true if the two arrays are equivalent or false otherwise.
    */
    virtual bool isEqualTo(const OSArray *anArray) const;
    /*!
        @function isEqualTo
        @abstract A member function which compares the equality of the values of a receiving array to an arbitrary object.
        @param anObject The object to be compared against the receiver.
        @result Returns true if the two objects are equivalent, that is they are either the same object or they are both arrays containing the same or equivalent objects, or false otherwise.
    */
    virtual bool isEqualTo(const OSMetaClassBase *anObject) const;
    
    /*!
        @function getObject
        @abstract A member function which returns a reference to an object located within the array at a given index.  The caller should not release the returned object.  
        @param index The index into the array from which the reference to an object is taken.
        @result Returns a reference to an object or 0 if the index is beyond the bounds of the array.
    */
    virtual OSObject *getObject(unsigned int index) const;
    /*!
        @function getLastObject
        @abstract A member function which returns a reference to the last object in the array. The caller should not release the returned object.
        @result Returns a reference to the last object in the array or 0 if the array is empty.
    */
    virtual OSObject *getLastObject() const;

    /*!
        @function getNextIndexOfObject
        @abstract A member function which searches the array for the next instance of a specific object, at or beyond the supplied index.
        @result Returns the next index of the object in the array or (-1) if none is found.
    */
    virtual unsigned int getNextIndexOfObject(const OSMetaClassBase * anObject,
                                               unsigned int index) const;

    /*!
        @function serialize
        @abstract A member function which archives the receiver.
        @param s The OSSerialize object.
        @result Returns true if serialization was successful, false if not.
    */
    virtual bool serialize(OSSerialize *s) const;

    /*!
        @function setOptions
        @abstract This function is used to recursively set option bits in this array and all child collections.
	@param options Set the (options & mask) bits.
        @param mask The mask of bits which need to be set, 0 to get the current value.
        @result The options before the set operation, NB setOptions(?,0) returns the current value of this collection.
     */
    virtual unsigned setOptions(unsigned options, unsigned mask, void * = 0);

    /*!
        @function copyCollection
        @abstract Do a deep copy of this array and its collections.
	@discussion This function copies this array included collections recursively.  Objects that don't derive from OSContainter are NOT copied, that is objects like OSString and OSData.
	@param cycleDict Is a dictionary of all of the collections that have been, to start the copy at the top level just leave this field 0.
	@result The newly copied collecton or 0 if insufficient memory
    */
    OSCollection *copyCollection(OSDictionary *cycleDict = 0);

    OSMetaClassDeclareReservedUnused(OSArray, 0);
    OSMetaClassDeclareReservedUnused(OSArray, 1);
    OSMetaClassDeclareReservedUnused(OSArray, 2);
    OSMetaClassDeclareReservedUnused(OSArray, 3);
    OSMetaClassDeclareReservedUnused(OSArray, 4);
    OSMetaClassDeclareReservedUnused(OSArray, 5);
    OSMetaClassDeclareReservedUnused(OSArray, 6);
    OSMetaClassDeclareReservedUnused(OSArray, 7);
};

#endif /* !_OS_OSARRAY_H */
