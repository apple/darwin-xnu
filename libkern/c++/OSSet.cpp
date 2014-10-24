/*
 * Copyright (c) 2000, 2014 Apple Computer, Inc. All rights reserved.
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
/* IOSet.m created by rsulack on Thu 11-Jun-1998 */

#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSSerialize.h>
#include <libkern/c++/OSSet.h>

#define super OSCollection

OSDefineMetaClassAndStructors(OSSet, OSCollection)
OSMetaClassDefineReservedUnused(OSSet, 0);
OSMetaClassDefineReservedUnused(OSSet, 1);
OSMetaClassDefineReservedUnused(OSSet, 2);
OSMetaClassDefineReservedUnused(OSSet, 3);
OSMetaClassDefineReservedUnused(OSSet, 4);
OSMetaClassDefineReservedUnused(OSSet, 5);
OSMetaClassDefineReservedUnused(OSSet, 6);
OSMetaClassDefineReservedUnused(OSSet, 7);

#define EXT_CAST(obj) \
    reinterpret_cast<OSObject *>(const_cast<OSMetaClassBase *>(obj))

bool OSSet::initWithCapacity(unsigned int inCapacity)
{
    if ( !super::init() )
        return false;

    members = OSArray::withCapacity(inCapacity);
    if (!members)
        return false;

    return true;
}

bool OSSet::initWithObjects(const OSObject *inObjects[],
                              unsigned int inCount,
                              unsigned int inCapacity)
{
    unsigned int capacity = inCount;

    if ( inCapacity ) {
        if ( inCount > inCapacity )
            return false;

        capacity = inCapacity;
    }

    if (!inObjects || !initWithCapacity(capacity))
        return false;

    for ( unsigned int i = 0; i < inCount; i++ ) {
// xx-review: no test here for failure of setObject()
        if (members->getCount() < capacity)
            setObject(inObjects[i]);
        else
            return false;
    }

    return true;	
}

bool OSSet::initWithArray(const OSArray *inArray,
                          unsigned int inCapacity)
{
    if ( !inArray )
        return false;
    
    return initWithObjects((const OSObject **) inArray->array,
                           inArray->count, inCapacity);
}

bool OSSet::initWithSet(const OSSet *inSet,
                        unsigned int inCapacity)
{
    return initWithArray(inSet->members, inCapacity);
}

OSSet *OSSet::withCapacity(unsigned int capacity)
{
    OSSet *me = new OSSet;

    if (me && !me->initWithCapacity(capacity)) {
        me->release();
        return 0;
    }

    return me;
}

OSSet *OSSet::withObjects(const OSObject *objects[],
                          unsigned int count,
                          unsigned int capacity)
{
    OSSet *me = new OSSet;

    if (me && !me->initWithObjects(objects, count, capacity)) {
        me->release();
        return 0;
    }

    return me;
}

OSSet *OSSet::withArray(const OSArray *array,
                        unsigned int capacity)
{
    OSSet *me = new OSSet;

    if (me && !me->initWithArray(array, capacity)) {
        me->release();
        return 0;
    }

    return me;
}

OSSet *OSSet::withSet(const OSSet *set,
                      unsigned int capacity)
{
    OSSet *me = new OSSet;

    if (me && !me->initWithSet(set, capacity)) {
        me->release();
        return 0;
    }

    return me;
}

void OSSet::free()
{
    (void) members->super::setOptions(0, kImmutable);
    if (members)
        members->release();

    super::free();
}

unsigned int OSSet::getCount() const
{
    return members->count;
}

unsigned int OSSet::getCapacity() const
{
    return members->capacity;
}

unsigned int OSSet::getCapacityIncrement() const
{
    return members->capacityIncrement;
}

unsigned int OSSet::setCapacityIncrement(unsigned int increment)
{
    return members->setCapacityIncrement(increment);
}

unsigned int OSSet::ensureCapacity(unsigned int newCapacity)
{
    return members->ensureCapacity(newCapacity);
}

void OSSet::flushCollection()
{
    haveUpdated();
    members->flushCollection();
}

bool OSSet::setObject(const OSMetaClassBase *anObject)
{
    if (containsObject(anObject)) {
        return false;
    } else {
        haveUpdated();
        return members->setObject(anObject);
    }
}

bool OSSet::merge(const OSArray * array)
{
    const OSMetaClassBase * anObject = 0;
    bool                    result   = true;

    for (int i = 0; (anObject = array->getObject(i)); i++) {

       /* setObject() returns false if the object is already in the set,
        * so we have to check beforehand here with containsObject().
        */
        if (containsObject(anObject)) {
            continue;
        }
        if (!setObject(anObject)) {
            result = false;
        }
    }

    return result;
}

bool OSSet::merge(const OSSet * set)
{
    return merge(set->members);
}

void OSSet::removeObject(const OSMetaClassBase *anObject)
{
    const OSMetaClassBase *probeObject;

    for (int i = 0; (probeObject = members->getObject(i)); i++)
        if (probeObject == anObject) {
            haveUpdated();
            members->removeObject(i);
            return;
        }
}


bool OSSet::containsObject(const OSMetaClassBase *anObject) const
{
    return anObject && member(anObject);
}

bool OSSet::member(const OSMetaClassBase *anObject) const
{
    OSMetaClassBase *probeObject;

    for (int i = 0; (probeObject = members->getObject(i)); i++)
        if (probeObject == anObject)
            return true;

    return false;
}

OSObject *OSSet::getAnyObject() const
{
    return members->getObject(0);
}

bool OSSet::isEqualTo(const OSSet *aSet) const
{
    unsigned int count;
    unsigned int i;
    const OSMetaClassBase *obj1;
    const OSMetaClassBase *obj2;

    if ( this == aSet )
        return true;

    count = members->count;
    if ( count != aSet->getCount() )
        return false;

    for ( i = 0; i < count; i++ ) {
        obj1 = aSet->members->getObject(i);
	if (containsObject(obj1))
		continue;
        obj2 = members->getObject(i);
        if ( !obj1 || !obj2 )
                return false;

        if ( !obj1->isEqualTo(obj2) )
            return false;
    }

    return true;
}

bool OSSet::isEqualTo(const OSMetaClassBase *anObject) const
{
    OSSet *otherSet;

    otherSet = OSDynamicCast(OSSet, anObject);
    if ( otherSet )
        return isEqualTo(otherSet);
    else
        return false;
}

unsigned int OSSet::iteratorSize() const
{
    return sizeof(unsigned int);
}

bool OSSet::initIterator(void *inIterator) const
{
    unsigned int *iteratorP = (unsigned int *) inIterator;

    *iteratorP = 0;
    return true;
}

bool OSSet::getNextObjectForIterator(void *inIterator, OSObject **ret) const
{
    unsigned int *iteratorP = (unsigned int *) inIterator;
    unsigned int index = (*iteratorP)++;

    if (index < members->count)
        *ret = members->getObject(index);
    else
        *ret = 0;

    return (*ret != 0);
}

bool OSSet::serialize(OSSerialize *s) const
{
    const OSMetaClassBase *o;

    if (s->previouslySerialized(this)) return true;   
 
    if (!s->addXMLStartTag(this, "set")) return false;

    for (int i = 0; (o = members->getObject(i)); i++) {
        if (!o->serialize(s)) return false;
    }   

    return s->addXMLEndTag("set");
}

unsigned OSSet::setOptions(unsigned options, unsigned mask, void *)
{
    unsigned old = super::setOptions(options, mask);
    if ((old ^ options) & mask)
	members->setOptions(options, mask);

    return old;
}

OSCollection * OSSet::copyCollection(OSDictionary *cycleDict)
{
    bool allocDict = !cycleDict;
    OSCollection *ret = 0;
    OSSet *newSet = 0;

    if (allocDict) {
	cycleDict = OSDictionary::withCapacity(16);
	if (!cycleDict)
	    return 0;
    }

    do {
	// Check for a cycle
	ret = super::copyCollection(cycleDict);
	if (ret)
	    continue;	// Found it

	newSet = OSSet::withCapacity(members->capacity);
	if (!newSet)
	    continue;	// Couldn't create new set abort

	// Insert object into cycle Dictionary
	cycleDict->setObject((const OSSymbol *) this, newSet);

	OSArray *newMembers = newSet->members;
	newMembers->capacityIncrement = members->capacityIncrement;

	// Now copy over the contents into the new duplicate
	for (unsigned int i = 0; i < members->count; i++) {
	    OSObject *obj = EXT_CAST(members->array[i]);
	    OSCollection *coll = OSDynamicCast(OSCollection, obj);
	    if (coll) {
		OSCollection *newColl = coll->copyCollection(cycleDict);
		if (newColl) {
		    obj = newColl;	// Rely on cycleDict ref for a bit
		    newColl->release();
		}
		else
		    goto abortCopy;
	    };
	    newMembers->setObject(obj);
	};

	ret = newSet;
	newSet = 0;

    } while(false);

abortCopy:
    if (newSet)
	newSet->release();

    if (allocDict)
	cycleDict->release();

    return ret;
}
