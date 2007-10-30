/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/* IOCollection.h created by gvdl on Thu 1998-10-22 */

#ifndef _OS_OSCOLLECTION_H
#define _OS_OSCOLLECTION_H

#include <libkern/c++/OSObject.h>

class OSDictionary;

/*!
    @class OSCollection
    @abstract Abstract super class for all collections.
    @discussion
    OSCollection is the abstract super class for all OSObject derived collections and provides the necessary interfaces for managing storage space and iteration through a collection.
*/
class OSCollection : public OSObject
{
    friend class OSCollectionIterator;

    OSDeclareAbstractStructors(OSCollection);

    struct ExpansionData { };
    
protected:
    unsigned int updateStamp;

private:
    /* Reserved for future use.  (Internal use only)  */
    // ExpansionData *reserved;
    unsigned int fOptions;

protected:
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
    enum {
	kImmutable = 0x00000001,
	kMASK	   = (unsigned) -1
    };

    /*
        @function haveUpdated
        @abstract A member function to track of all updates to the collection.
    */
    void haveUpdated();

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

    /*!
        @function setOptions
        @abstract This function is used to recursively set option bits in this collection and all child collections.
	@discussion setOptions is a recursive function but the OSCollection class itself does not know the structure of the particular collection.  This means that all derived classes are expected to override this method and recurse if the old value of the option was NOT set, which is why the old value is returned.  As this function is a reserved function override it is very multi purpose.  It can be used to get & set the options,
        @param options Set the (options & mask) bits.
        @param mask The mask of bits which need to be set, 0 to get the current value.
        @result The options before the set operation, NB setOptions(?,0) returns the current value of this collection.
     */
    OSMetaClassDeclareReservedUsed(OSCollection, 0);
    virtual unsigned setOptions(unsigned options, unsigned mask, void * = 0);

    /*!
        @function copyCollection
        @abstract Do a deep copy of a collection tree.
	@discussion This function copies this collection and all of the contained collections recursively.  Objects that don't derive from OSContainter are NOT copied, that is objects like OSString and OSData.  To a derive from OSConnection::copyCollection some code is required to be implemented in the derived class, below is the skeleton pseudo code to copy a collection.

OSCollection * <MyCollection>::copyCollection(OSDictionary *inCycleDict)
{
    bool allocDict = !cycleDict;
    OSCollection *ret = 0;
    <MyCollection> *newMyColl = 0;

    if (allocDict)
	cycleDict = OSDictionary::withCapacity(16);
    if (!cycleDict)
	return 0;

    do {
	// Check to see if we already have a copy of the new dictionary
	ret = super::copyCollection(cycleDict);
	if (ret)
	    continue;
	
	// Your code goes here to copy your collection,
	// see OSArray & OSDictionary for examples.
	newMyColl = <MyCollection>::with<MyCollection>(this);
	if (!newMyColl)
	    continue;

	// Insert object into cycle Dictionary
	cycleDict->setObject((const OSSymbol *) this, newMyColl);

	// Duplicate any collections in us
	for (unsigned int i = 0; i < count; i++) {
	    OSObject *obj = getObject(i);
	    OSCollection *coll = OSDynamicCast(OSCollection, obj);

	    if (coll) {
		OSCollection *newColl = coll->copyCollection(cycleDict);
		if (!newColl)
		    goto abortCopy;

		newMyColl->replaceObject(i, newColl);
		newColl->release();
	    };
	};

	ret = newMyColl;
	newMyColl = 0;

    } while (false);

abortCopy:
    if (newMyColl)
	newMyColl->release();

    if (allocDict)
	cycleDict->release();

    return ret;
}

	@param cycleDict Is a dictionary of all of the collections that have been, to start the copy at the top level just leave this field 0.
	@result The newly copied collecton or 0 if insufficient memory
    */
    virtual OSCollection *copyCollection(OSDictionary *cycleDict = 0);
    OSMetaClassDeclareReservedUsed(OSCollection, 1);

    OSMetaClassDeclareReservedUnused(OSCollection, 2);
    OSMetaClassDeclareReservedUnused(OSCollection, 3);
    OSMetaClassDeclareReservedUnused(OSCollection, 4);
    OSMetaClassDeclareReservedUnused(OSCollection, 5);
    OSMetaClassDeclareReservedUnused(OSCollection, 6);
    OSMetaClassDeclareReservedUnused(OSCollection, 7);
};

#endif /* !_OS_OSCOLLECTION_H */
