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
/* IOSet.m created by rsulack on Thu 11-Jun-1998 */

#include <libkern/c++/OSSet.h>
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSSerialize.h>

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
                              unsigned int inCapacity = 0)
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
        if (members->getCount() < inCapacity)
            setObject(inObjects[i]);
        else
            return false;
    }

    return true;	
}

bool OSSet::initWithArray(const OSArray *inArray,
                          unsigned int inCapacity = 0)
{
    if ( !inArray )
        return false;
    
    return initWithObjects((const OSObject **) inArray->array,
                           inArray->count, inCapacity);
}

bool OSSet::initWithSet(const OSSet *inSet,
                        unsigned int inCapacity = 0)
{
    return initWithArray(inSet->members, inCapacity);
}

OSSet *OSSet::withCapacity(unsigned int capacity)
{
    OSSet *me = new OSSet;

    if (me && !me->initWithCapacity(capacity)) {
        me->free();
        return 0;
    }

    return me;
}

OSSet *OSSet::withObjects(const OSObject *objects[],
                          unsigned int count,
                          unsigned int capacity = 0)
{
    OSSet *me = new OSSet;

    if (me && !me->initWithObjects(objects, count, capacity)) {
        me->free();
        return 0;
    }

    return me;
}

OSSet *OSSet::withArray(const OSArray *array,
                        unsigned int capacity = 0)
{
    OSSet *me = new OSSet;

    if (me && !me->initWithArray(array, capacity)) {
        me->free();
        return 0;
    }

    return me;
}

OSSet *OSSet::withSet(const OSSet *set,
                      unsigned int capacity = 0)
{
    OSSet *me = new OSSet;

    if (me && !me->initWithSet(set, capacity)) {
        me->free();
        return 0;
    }

    return me;
}

void OSSet::free()
{
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
    if (containsObject(anObject))
        return false;
    else {
        haveUpdated();
        return members->setObject(anObject);
    }
}

bool OSSet::merge(const OSArray *array)
{
    const OSMetaClassBase *anObject;
    bool retVal = false;

    for (int i = 0; (anObject = array->getObject(i)); i++)
        if (setObject(anObject))
            retVal = true;

    return retVal;
}

bool OSSet::merge(const OSSet *set)
{
    return setObject(set->members);
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
