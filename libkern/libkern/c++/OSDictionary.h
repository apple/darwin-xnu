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
 * Copyright (c) 1998-1999 Apple Computer, Inc.  All rights reserved.
 *
 * HISTORY
 *
 * OSDictionary.h created by rsulack on Wed 17-Sep-1997
 * OSDictionary.h converted to C++ by gvdl on Fri 1998-10-30
 */

#ifndef _IOKIT_IODICTIONARY_H
#define _IOKIT_IODICTIONARY_H

#include <libkern/c++/OSCollection.h>

class OSArray;
class OSSymbol;
class OSString;

/*!
    @class OSDictionary
    @abstract A collection class whose instances maintain a list of object references.  Objects in the collection are acquired with unique associative keys.
    @discussion
    An instance of OSDictionary is a mutable container which contains a list of OSMetaClassBase derived object references and these objects are identified and acquired by unique associative keys.  When an object is placed into a dictionary, a unique identifier or key must provided to identify the object within the collection. The key then must be provided to find the object within the collection.  If an object is not found within the collection, a 0 is returned.  Placing an object into a dictionary for a key, which already identifies an object within that dictionary, will replace the current object with the new object.
    
    Objects placed into a dictionary are automatically retained and objects removed or replaced are automatically released.  All objects are released when the collection is freed.
*/
class OSDictionary : public OSCollection
{
    OSDeclareDefaultStructors(OSDictionary)

protected:
    struct dictEntry {
        const OSSymbol *key;
        const OSMetaClassBase *value;
    };
    dictEntry *dictionary;
    unsigned int count;
    unsigned int capacity;
    unsigned int capacityIncrement;

    struct ExpansionData { };
    
    /*! @var reserved
        Reserved for future use.  (Internal use only)  */
    ExpansionData *reserved;

    // Member functions used by the OSCollectionIterator class.
    virtual unsigned int iteratorSize() const;
    virtual bool initIterator(void *iterator) const;
    virtual bool getNextObjectForIterator(void *iterator, OSObject **ret) const;

public:
    /*!
        @function withCapacity
        @abstract A static constructor function to create and initialize an instance of OSDictionary.
        @param capacity The initial storage capacity of the dictionary object.
        @result Returns an instance of OSDictionary or 0 on failure.
    */
    static OSDictionary *withCapacity(unsigned int capacity);
    /*!
        @function withObjects
        @abstract A static constructor function to create and initialize an instance of OSDictionary and populate it with objects provided.
        @param objects A static array of OSMetaClassBase derived objects.
        @param keys A static array of OSSymbol keys.
        @param count The number of items to be placed into the dictionary.
        @param capacity The initial storage capacity of the dictionary object.  If 0, the capacity will be set to the size of 'count', else this value must be greater or equal to 'count'.
        @result Returns an instance of OSDictionary or 0 on failure.
    */
    static OSDictionary *withObjects(const OSObject *objects[],
                                     const OSSymbol *keys[],
                                     unsigned int count,
                                     unsigned int capacity = 0);
    /*!
        @function withObjects
        @abstract A static constructor function to create and initialize an instance of OSDictionary and populate it with objects provided.
        @param objects A static array of OSMetaClassBase derived objects.
        @param keys A static array of OSString keys.
        @param count The number of items to be placed into the dictionary.
        @param capacity The initial storage capacity of the dictionary object.  If 0, the capacity will be set to the size of 'count', else this value must be greater or equal to 'count'.
        @result Returns an instance of OSDictionary or 0 on failure.
    */
    static OSDictionary *withObjects(const OSObject *objects[],
                                     const OSString *keys[],
                                     unsigned int count,
                                     unsigned int capacity = 0);
    /*!
        @function withDictionary
        @abstract A static constructor function to create and initialize an instance of OSDictionary and populate it with objects from another dictionary.
        @param dict A dictionary whose contents will be placed in the new instance.
        @param capacity The initial storage capacity of the dictionary object.  If 0, the capacity will be set to the number of elements in the dictionary object, else the capacity must be greater than or equal to the number of elements in the dictionary.
        @result Returns an instance of OSDictionary or 0 on failure.
    */
    static OSDictionary *withDictionary(const OSDictionary *dict,
                                        unsigned int capacity = 0);

    /*!
        @function initWithCapacity
        @abstract A member function to initialize an instance of OSDictionary.
        @param capacity The initial storage capacity of the dictionary object.
        @result Returns true if initialization succeeded or false on failure.
    */
    virtual bool initWithCapacity(unsigned int capacity);
    /*!
        @function initWithObjects
        @abstract A member function to initialize an instance of OSDictionary and populate it with the provided objects and keys.
        @param objects A static array of OSMetaClassBase derived objects to be placed into the dictionary.
        @param keys A static array of OSSymbol keys which identify the corresponding objects provided in the 'objects' parameter.
        @param count The number of objects provided to the dictionary.
        @param capacity The initial storage capacity of the dictionary object.  If 0, the capacity will be set to the size of 'count', else the capacity must be greater than or equal to the value of 'count'.
        @result Returns true if initialization succeeded or false on failure.
    */
    virtual bool initWithObjects(const OSObject *objects[],
                                 const OSSymbol *keys[],
                                 unsigned int count,
                                 unsigned int capacity = 0);
    /*!
        @function initWithObjects
        @abstract A member function to initialize an instance of OSDictionary and populate it with the provided objects and keys.
        @param objects A static array of OSMetaClassBase derived objects to be placed into the dictionary.
        @param keys A static array of OSString keys which identify the corresponding objects provided in the 'objects' parameter.
        @param count The number of objects provided to the dictionary.
        @param capacity The initial storage capacity of the dictionary object.  If 0, the capacity will be set to the size of 'count', else the capacity must be greater than or equal to the value of 'count'.
        @result Returns true if initialization succeeded or false on failure.
    */
    virtual bool initWithObjects(const OSObject *objects[],
                                 const OSString *keys[],
                                 unsigned int count,
                                 unsigned int capacity = 0);
    /*!
        @function initWithDictionary
        @abstract A member function to initialize an instance of OSDictionary and populate it with the contents of another dictionary.
        @param dict The dictionary containing the objects to be used to populate the receiving dictionary.
        @param capacity The initial storage capacity of the dictionary.  If 0, the value of capacity will be set to the number of elements in the dictionary object, else the value of capacity must be greater than or equal to the number of elements in the dictionary object.
        @result Returns true if initialization succeeded or false on failure.
    */
    virtual bool initWithDictionary(const OSDictionary *dict,
                                    unsigned int capacity = 0);
    /*!
        @function free
        @abstract A member functions to deallocate and release all resources used by the OSDictionary instance.
        @discussion This function should not be called directly, use release() instead.
    */
    virtual void free();

    /*!
        @function getCount
        @abstract A member function which returns the current number of objects within the collection.
        @result Returns the number of objects contained within the dictionary.
    */
    virtual unsigned int getCount() const;
    /*!
        @function getCapacity
        @abstract A member function which returns the storage capacity of the collection.
        @result Returns the storage capacity of the dictionary.
    */
    virtual unsigned int getCapacity() const;
    /*!
        @function getCapacityIncrement
        @abstract A member function which returns the growth size for the collection.
    */
    virtual unsigned int getCapacityIncrement() const;
    /*!
        @function setCapacityIncrement
        @abstract A member function to set the growth size of the collection.
        @param increment The new growth size.
        @result Returns the new capacity increment.
    */
    virtual unsigned int setCapacityIncrement(unsigned increment);

    /*!
        @function ensureCapacity
        @abstract Member function to grow the size of the collection.
        @param newCapacity The new capacity for the dictionary to expand to.
        @result Returns the new capacity of the dictionary or the previous capacity upon error.
    */
    virtual unsigned int ensureCapacity(unsigned int newCapacity);

    /*!
        @function flushCollection
        @abstract A member function which removes and releases all objects within the collection.
    */
    virtual void flushCollection();

    /*!
        @function setObject
        @abstract A member function which places an object into the dictionary and identified by a unique key.
        @param aKey A unique OSSymbol identifying the object placed within the collection.
        @param anObject The object to be stored in the dictionary.  It is automatically retained.
        @result Returns true if the addition of an object was successful, false otherwise.
    */
    virtual bool setObject(const OSSymbol *aKey, const OSMetaClassBase *anObject);
    /*!
        @function setObject
        @abstract A member function which places an object into the dictionary and identified by a unique key.
        @param aKey A unique OSString identifying the object placed within the collection.
        @param anObject The object to be stored in the dictionary.  It is automatically retained.
        @result Returns true if the addition of an object was successful, false otherwise.
    */
    virtual bool setObject(const OSString *aKey, const OSMetaClassBase *anObject);
    /*!
        @function setObject
        @abstract A member function which places an object into the dictionary and identified by a unique key.
        @param aKey A unique string identifying the object placed within the collection.
        @param anObject The object to be stored in the dictionary.  It is automatically retained.
        @result Returns true if the addition of an object was successful, false otherwise.
    */
    virtual bool setObject(const char *aKey, const OSMetaClassBase *anObject);
    
    /*!
        @function removeObject
        @abstract A member function which removes an object from the dictionary.  The removed object is automatically released.
        @param aKey A unique OSSymbol identifying the object to be removed from the dictionary.
    */
    virtual void removeObject(const OSSymbol *aKey);
    /*!
        @function removeObject
        @abstract A member function which removes an object from the dictionary.  The removed object is automatically released.
        @param aKey A unique OSString identifying the object to be removed from the dictionary.
    */
    virtual void removeObject(const OSString *aKey);
    /*!
        @function removeObject
        @abstract A member function which removes an object from the dictionary.  The removed object is automatically released.
        @param aKey A unique string identifying the object to be removed from the dictionary.
    */
    virtual void removeObject(const char *aKey);

    /*!
        @function merge
        @abstract A member function which merges the contents of a dictionary into the receiver.
        @param aDictionary The dictionary whose contents are to be merged with the receiver.
        @result Returns true if the merger is successful, false otherwise.
        @discussion If there are keys in 'aDictionary' which match keys in the receiving dictionary, then the objects in the receiver are replaced by those from 'aDictionary', the replaced objects are released.  
    */
    virtual bool merge(const OSDictionary *aDictionary);
    
    /*!
        @function getObject
        @abstract A member function to find an object in the dictionary associated by a given key.
        @param aKey The unique OSSymbol key identifying the object to be returned to caller.
        @result Returns a reference to the object corresponding to the given key, or 0 if the key does not exist in the dictionary.
    */
    virtual OSObject *getObject(const OSSymbol *aKey) const;
    /*!
        @function getObject
        @abstract A member function to find an object in the dictionary associated by a given key.
        @param aKey The unique OSString key identifying the object to be returned to caller.
        @result Returns a reference to the object corresponding to the given key, or 0 if the key does not exist in the dictionary.
    */
    virtual OSObject *getObject(const OSString *aKey) const;
    /*!
        @function getObject
        @abstract A member function to find an object in the dictionary associated by a given key.
        @param aKey The unique string identifying the object to be returned to caller.
        @result Returns a reference to the object corresponding to the given key, or 0 if the key does not exist in the dictionary.
    */
    virtual OSObject *getObject(const char *aKey) const;

    /*!
        @function isEqualTo
        @abstract A member function to test the equality of the intersections of two dictionaries.
        @param aDictionary The dictionary to be compared against the receiver.
        @param keys An OSArray or OSDictionary containing the keys describing the intersection for the comparison.
        @result Returns true if the intersections of the two dictionaries are equal.
    */
    virtual bool isEqualTo(const OSDictionary *aDictionary, const OSCollection *keys) const;
    /*!
        @function isEqualTo
        @abstract A member function to test the equality of two dictionaries.
        @param aDictionary The dictionary to be compared against the receiver.
        @result Returns true if the dictionaries are equal.
    */
    virtual bool isEqualTo(const OSDictionary *aDictionary) const;
    /*!
        @function isEqualTo
        @abstract A member function to test the equality between the receiver and an unknown object.
        @param anObject An object to be compared against the receiver.
        @result Returns true if the objects are equal.
    */
    virtual bool isEqualTo(const OSMetaClassBase *anObject) const;
    
    /*!
        @function serialize
        @abstract A member function which archives the receiver.
        @param s The OSSerialize object.
        @result Returns true if serialization was successful, false if not.
    */
    virtual bool serialize(OSSerialize *s) const;


    OSMetaClassDeclareReservedUnused(OSDictionary, 0);
    OSMetaClassDeclareReservedUnused(OSDictionary, 1);
    OSMetaClassDeclareReservedUnused(OSDictionary, 2);
    OSMetaClassDeclareReservedUnused(OSDictionary, 3);
    OSMetaClassDeclareReservedUnused(OSDictionary, 4);
    OSMetaClassDeclareReservedUnused(OSDictionary, 5);
    OSMetaClassDeclareReservedUnused(OSDictionary, 6);
    OSMetaClassDeclareReservedUnused(OSDictionary, 7);
};

#endif /* !_IOKIT_IODICTIONARY_H */
