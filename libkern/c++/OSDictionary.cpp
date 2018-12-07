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
/* OSDictionary.m created by rsulack on Fri 12-Sep-1997 */
/* OSDictionary.cpp converted to C++ by gvdl on Fri 1998-10-30 */
/* OSDictionary.cpp rewritten by gvdl on Fri 1998-10-30 */


#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSSymbol.h>
#include <libkern/c++/OSSerialize.h>
#include <libkern/c++/OSLib.h>
#include <libkern/c++/OSCollectionIterator.h>

#define super OSCollection

OSDefineMetaClassAndStructors(OSDictionary, OSCollection)
OSMetaClassDefineReservedUnused(OSDictionary, 0);
OSMetaClassDefineReservedUnused(OSDictionary, 1);
OSMetaClassDefineReservedUnused(OSDictionary, 2);
OSMetaClassDefineReservedUnused(OSDictionary, 3);
OSMetaClassDefineReservedUnused(OSDictionary, 4);
OSMetaClassDefineReservedUnused(OSDictionary, 5);
OSMetaClassDefineReservedUnused(OSDictionary, 6);
OSMetaClassDefineReservedUnused(OSDictionary, 7);

#define EXT_CAST(obj) \
    reinterpret_cast<OSObject *>(const_cast<OSMetaClassBase *>(obj))

bool OSDictionary::initWithCapacity(unsigned int inCapacity)
{
    if (!super::init())
        return false;

    if (inCapacity > (UINT_MAX / sizeof(dictEntry)))
        return false;

    unsigned int size = inCapacity * sizeof(dictEntry);
//fOptions |= kSort;

    dictionary = (dictEntry *) kalloc_container(size);
    if (!dictionary)
        return false;

    bzero(dictionary, size);
    OSCONTAINER_ACCUMSIZE(size);

    count = 0;
    capacity = inCapacity;
    capacityIncrement = (inCapacity)? inCapacity : 16;

    return true;	
}

bool OSDictionary::initWithObjects(const OSObject *objects[],
                                   const OSSymbol *keys[],
                                   unsigned int theCount,
                                   unsigned int theCapacity)
{
    unsigned int newCapacity = theCount;

    if (!objects || !keys)
        return false;

    if ( theCapacity ) {
        if (theCount > theCapacity)
            return false;
        
        newCapacity = theCapacity;
    }

    if (!initWithCapacity(newCapacity))
        return false;

    for (unsigned int i = 0; i < theCount; i++) {
        const OSMetaClassBase *newObject = *objects++;

        if (!newObject || !keys[i] || !setObject(keys[i], newObject))
            return false;
    }

    return true;	
}

bool OSDictionary::initWithObjects(const OSObject *objects[],
                                   const OSString *keys[],
                                   unsigned int theCount,
                                   unsigned int theCapacity)
{
    unsigned int newCapacity = theCount;

    if (!objects || !keys)
        return false;

    if ( theCapacity ) {
        if (theCount > theCapacity)
            return false;

        newCapacity = theCapacity;
    }

    if (!initWithCapacity(newCapacity))
        return false;

    for (unsigned int i = 0; i < theCount; i++) {
        const OSSymbol *key = OSSymbol::withString(*keys++);
        const OSMetaClassBase *newObject = *objects++;

        if (!key)
            return false;

        if (!newObject || !setObject(key, newObject)) {
            key->release();
            return false;
        }

        key->release();
    }

    return true;
}

bool OSDictionary::initWithDictionary(const OSDictionary *dict,
                                      unsigned int theCapacity)
{
    unsigned int newCapacity;

    if ( !dict )
        return false;

    newCapacity = dict->count;

    if ( theCapacity ) {
        if ( dict->count > theCapacity )
            return false;
        
        newCapacity = theCapacity;
    }

    if (!initWithCapacity(newCapacity))
        return false;

    if ((kSort & fOptions) && !(kSort & dict->fOptions)) {
	for (unsigned int i = 0; i < dict->count; i++) {
	    if (!setObject(dict->dictionary[i].key, dict->dictionary[i].value)) {
		return false;
	    }
	}
	return true;
    }

    count = dict->count;
    bcopy(dict->dictionary, dictionary, count * sizeof(dictEntry));
    for (unsigned int i = 0; i < count; i++) {
        dictionary[i].key->taggedRetain(OSTypeID(OSCollection));
        dictionary[i].value->taggedRetain(OSTypeID(OSCollection));
    }

    return true;
}

OSDictionary *OSDictionary::withCapacity(unsigned int capacity)
{
    OSDictionary *me = new OSDictionary;

    if (me && !me->initWithCapacity(capacity)) {
        me->release();
        return 0;
    }

    return me;
}

OSDictionary *OSDictionary::withObjects(const OSObject *objects[],
                                        const OSSymbol *keys[],
                                        unsigned int count,
                                        unsigned int capacity)
{
    OSDictionary *me = new OSDictionary;

    if (me && !me->initWithObjects(objects, keys, count, capacity)) {
        me->release();
        return 0;
    }

    return me;
}

OSDictionary *OSDictionary::withObjects(const OSObject *objects[],
                                        const OSString *keys[],
                                        unsigned int count,
                                        unsigned int capacity)
{
    OSDictionary *me = new OSDictionary;

    if (me && !me->initWithObjects(objects, keys, count, capacity)) {
        me->release();
        return 0;
    }

    return me;
}

OSDictionary *OSDictionary::withDictionary(const OSDictionary *dict,
                                           unsigned int capacity)
{
    OSDictionary *me = new OSDictionary;

    if (me && !me->initWithDictionary(dict, capacity)) {
        me->release();
        return 0;
    }

    return me;
}

void OSDictionary::free()
{
    (void) super::setOptions(0, kImmutable);
    flushCollection();
    if (dictionary) {
        kfree(dictionary, capacity * sizeof(dictEntry));
        OSCONTAINER_ACCUMSIZE( -(capacity * sizeof(dictEntry)) );
    }

    super::free();
}

unsigned int OSDictionary::getCount() const { return count; }
unsigned int OSDictionary::getCapacity() const { return capacity; }

unsigned int OSDictionary::getCapacityIncrement() const
{
    return capacityIncrement;
}

unsigned int OSDictionary::setCapacityIncrement(unsigned int increment)
{
    capacityIncrement = (increment)? increment : 16;

    return capacityIncrement;
}

unsigned int OSDictionary::ensureCapacity(unsigned int newCapacity)
{
    dictEntry *newDict;
    unsigned int finalCapacity;
    vm_size_t oldSize, newSize;

    if (newCapacity <= capacity)
        return capacity;

    // round up
    finalCapacity = (((newCapacity - 1) / capacityIncrement) + 1)
                * capacityIncrement;

    // integer overflow check
    if (finalCapacity < newCapacity || (finalCapacity > (UINT_MAX / sizeof(dictEntry))))
        return capacity;
    
    newSize = sizeof(dictEntry) * finalCapacity;

    newDict = (dictEntry *) kallocp_container(&newSize);
    if (newDict) {
        // use all of the actual allocation size
        finalCapacity = newSize / sizeof(dictEntry);

        oldSize = sizeof(dictEntry) * capacity;

        bcopy(dictionary, newDict, oldSize);
        bzero(&newDict[capacity], newSize - oldSize);

        OSCONTAINER_ACCUMSIZE(((size_t)newSize) - ((size_t)oldSize));
        kfree(dictionary, oldSize);

        dictionary = newDict;
        capacity = finalCapacity;
    }

    return capacity;
}

void OSDictionary::flushCollection()
{
    haveUpdated();

    for (unsigned int i = 0; i < count; i++) {
        dictionary[i].key->taggedRelease(OSTypeID(OSCollection));
        dictionary[i].value->taggedRelease(OSTypeID(OSCollection));
    }
    count = 0;
}

bool OSDictionary::
setObject(const OSSymbol *aKey, const OSMetaClassBase *anObject, bool onlyAdd)
{
    unsigned int i;
    bool exists;

    if (!anObject || !aKey)
        return false;

    // if the key exists, replace the object

    if (fOptions & kSort) {
    	i = OSSymbol::bsearch(aKey, &dictionary[0], count, sizeof(dictionary[0]));
	exists = (i < count) && (aKey == dictionary[i].key);
    } else for (exists = false, i = 0; i < count; i++) {
        if ((exists = (aKey == dictionary[i].key))) break;
    }

    if (exists) {

	if (onlyAdd) return false;

	const OSMetaClassBase *oldObject = dictionary[i].value;
    
	haveUpdated();
    
	anObject->taggedRetain(OSTypeID(OSCollection));
	dictionary[i].value = anObject;
    
	oldObject->taggedRelease(OSTypeID(OSCollection));
	return true;
    }

    // add new key, possibly extending our capacity
    if (count >= capacity && count >= ensureCapacity(count+1))
        return false;

    haveUpdated();

    bcopy(&dictionary[i], &dictionary[i+1], (count - i) * sizeof(dictionary[0]));

    aKey->taggedRetain(OSTypeID(OSCollection));
    anObject->taggedRetain(OSTypeID(OSCollection));
    dictionary[i].key = aKey;
    dictionary[i].value = anObject;
    count++;

    return true;
}

bool OSDictionary::
setObject(const OSSymbol *aKey, const OSMetaClassBase *anObject)
{
    return (setObject(aKey, anObject, false));
}

void OSDictionary::removeObject(const OSSymbol *aKey)
{
    unsigned int i;
    bool exists;

    if (!aKey)
        return;

    // if the key exists, remove the object

    if (fOptions & kSort) {
    	i = OSSymbol::bsearch(aKey, &dictionary[0], count, sizeof(dictionary[0]));
	exists = (i < count) && (aKey == dictionary[i].key);
    } else for (exists = false, i = 0; i < count; i++) {
        if ((exists = (aKey == dictionary[i].key))) break;
    }

    if (exists) {
	dictEntry oldEntry = dictionary[i];

	haveUpdated();

	count--;
	bcopy(&dictionary[i+1], &dictionary[i], (count - i) * sizeof(dictionary[0]));

	oldEntry.key->taggedRelease(OSTypeID(OSCollection));
	oldEntry.value->taggedRelease(OSTypeID(OSCollection));
	return;
    }
}


// Returns true on success, false on an error condition.
bool OSDictionary::merge(const OSDictionary *srcDict)
{
    const OSSymbol * sym;
    OSCollectionIterator * iter;

    if ( !OSDynamicCast(OSDictionary, srcDict) )
        return false;

    iter = OSCollectionIterator::withCollection(const_cast<OSDictionary *>(srcDict));
    if ( !iter )
        return false;

    while ( (sym = (const OSSymbol *)iter->getNextObject()) ) {
        const OSMetaClassBase * obj;

        obj = srcDict->getObject(sym);
        if ( !setObject(sym, obj) ) {
            iter->release();
            return false;
        }
    }
    iter->release();

    return true;
}

OSObject *OSDictionary::getObject(const OSSymbol *aKey) const
{
    unsigned int i;
    bool exists;

    if (!aKey)
        return 0;

    // if the key exists, return the object

    if (fOptions & kSort) {
    	i = OSSymbol::bsearch(aKey, &dictionary[0], count, sizeof(dictionary[0]));
	exists = (i < count) && (aKey == dictionary[i].key);
    } else for (exists = false, i = 0; i < count; i++) {
        if ((exists = (aKey == dictionary[i].key))) break;
    }

    if (exists) {
	return (const_cast<OSObject *> ((const OSObject *)dictionary[i].value));
    }

    return 0;
}

// Wrapper macros
#define OBJECT_WRAP_1(cmd, k)						\
{									\
    const OSSymbol *tmpKey = k;						\
    OSObject *retObj = cmd(tmpKey);					\
									\
    tmpKey->release();							\
    return retObj;							\
}

#define OBJECT_WRAP_2(cmd, k, o)					\
{									\
    const OSSymbol *tmpKey = k;						\
    bool ret = cmd(tmpKey, o);						\
									\
    tmpKey->release();							\
    return ret;								\
}

#define OBJECT_WRAP_3(cmd, k)						\
{									\
    const OSSymbol *tmpKey = k;						\
    cmd(tmpKey);							\
    tmpKey->release();							\
}


bool OSDictionary::setObject(const OSString *aKey, const OSMetaClassBase *anObject)
    OBJECT_WRAP_2(setObject, OSSymbol::withString(aKey), anObject)
bool OSDictionary::setObject(const char *aKey, const OSMetaClassBase *anObject)
    OBJECT_WRAP_2(setObject, OSSymbol::withCString(aKey), anObject)

OSObject *OSDictionary::getObject(const OSString *aKey) const
    OBJECT_WRAP_1(getObject, OSSymbol::withString(aKey))
OSObject *OSDictionary::getObject(const char *aKey) const
    OBJECT_WRAP_1(getObject, OSSymbol::withCString(aKey))

void OSDictionary::removeObject(const OSString *aKey)
    OBJECT_WRAP_3(removeObject, OSSymbol::withString(aKey))
void OSDictionary::removeObject(const char *aKey)
    OBJECT_WRAP_3(removeObject, OSSymbol::withCString(aKey))

bool
OSDictionary::isEqualTo(const OSDictionary *srcDict, const OSCollection *keys) const
{
    OSCollectionIterator * iter;
    unsigned int keysCount;
    const OSMetaClassBase * obj1;
    const OSMetaClassBase * obj2;
    OSString * aKey;
    bool ret;

    if ( this == srcDict )
        return true;

    keysCount = keys->getCount();
    if ( (count < keysCount) || (srcDict->getCount() < keysCount) )
        return false;

    iter = OSCollectionIterator::withCollection(keys);
    if ( !iter )
        return false;

    ret = true;
    while ( (aKey = OSDynamicCast(OSString, iter->getNextObject())) ) {
        obj1 = getObject(aKey);
        obj2 = srcDict->getObject(aKey);
        if ( !obj1 || !obj2 ) {
            ret = false;
            break;
        }

        if ( !obj1->isEqualTo(obj2) ) {
            ret = false;
            break;
        }
    }
    iter->release();

    return ret;
}

bool OSDictionary::isEqualTo(const OSDictionary *srcDict) const
{
    unsigned int i;
    const OSMetaClassBase * obj;
    
    if ( this == srcDict )
        return true;

    if ( count != srcDict->getCount() )
        return false;

    for ( i = 0; i < count; i++ ) {
        obj = srcDict->getObject(dictionary[i].key);
        if ( !obj )
            return false;

        if ( !dictionary[i].value->isEqualTo(obj) )
            return false;
    }
    
    return true;
}

bool OSDictionary::isEqualTo(const OSMetaClassBase *anObject) const
{
    OSDictionary *dict;

    dict = OSDynamicCast(OSDictionary, anObject);
    if ( dict )
        return isEqualTo(dict);
    else
        return false;
}

unsigned int OSDictionary::iteratorSize() const
{
    return sizeof(unsigned int);
}

bool OSDictionary::initIterator(void *inIterator) const
{
    unsigned int *iteratorP = (unsigned int *) inIterator;

    *iteratorP = 0;
    return true;
}

bool OSDictionary::getNextObjectForIterator(void *inIterator, OSObject **ret) const
{
    unsigned int *iteratorP = (unsigned int *) inIterator;
    unsigned int index = (*iteratorP)++;

    if (index < count)
        *ret = (OSObject *) dictionary[index].key;
    else
        *ret = 0;

    return (*ret != 0);
}

bool OSDictionary::serialize(OSSerialize *s) const
{
    if (s->previouslySerialized(this)) return true;

    if (!s->addXMLStartTag(this, "dict")) return false;

    for (unsigned i = 0; i < count; i++) {
        const OSSymbol *key = dictionary[i].key;

        // due the nature of the XML syntax, this must be a symbol
        if (!key->metaCast("OSSymbol")) {
            return false;
        }
        if (!s->addString("<key>")) return false;
        const char *c = key->getCStringNoCopy();
	while (*c) {
	    if (*c == '<') {
		if (!s->addString("&lt;")) return false;
	    } else if (*c == '>') {
		if (!s->addString("&gt;")) return false;
	    } else if (*c == '&') {
		if (!s->addString("&amp;")) return false;
	    } else {
		if (!s->addChar(*c)) return false;
	    }
	    c++;
	}   
        if (!s->addXMLEndTag("key")) return false;

        if (!dictionary[i].value->serialize(s)) return false;
    }

    return s->addXMLEndTag("dict");
}

unsigned OSDictionary::setOptions(unsigned options, unsigned mask, void *)
{
    unsigned old = super::setOptions(options, mask);
    if ((old ^ options) & mask) {

	// Value changed need to recurse over all of the child collections
	for ( unsigned i = 0; i < count; i++ ) {
	    OSCollection *v = OSDynamicCast(OSCollection, dictionary[i].value);
	    if (v)
		v->setOptions(options, mask);
	}
    }

    return old;
}

OSCollection * OSDictionary::copyCollection(OSDictionary *cycleDict)
{
    bool allocDict = !cycleDict;
    OSCollection *ret = 0;
    OSDictionary *newDict = 0;

    if (allocDict) {
	cycleDict = OSDictionary::withCapacity(16);
	if (!cycleDict)
	    return 0;
    }

    do {
	// Check for a cycle
	ret = super::copyCollection(cycleDict);
	if (ret)
	    continue;
	
	newDict = OSDictionary::withDictionary(this);
	if (!newDict)
	    continue;

	// Insert object into cycle Dictionary
	cycleDict->setObject((const OSSymbol *) this, newDict);

	for (unsigned int i = 0; i < count; i++) {
	    const OSMetaClassBase *obj = dictionary[i].value;
	    OSCollection *coll = OSDynamicCast(OSCollection, EXT_CAST(obj));

	    if (coll) {
		OSCollection *newColl = coll->copyCollection(cycleDict);
		if (!newColl)
		    goto abortCopy;

		newDict->dictionary[i].value = newColl;

		coll->taggedRelease(OSTypeID(OSCollection));
		newColl->taggedRetain(OSTypeID(OSCollection));
		newColl->release();
	    };
	}

	ret = newDict;
	newDict = 0;

    } while (false);

abortCopy:
    if (newDict)
	newDict->release();

    if (allocDict)
	cycleDict->release();

    return ret;
}

OSArray * OSDictionary::copyKeys(void)
{
    OSArray * array;

	array = OSArray::withCapacity(count);
	if (!array) return (0);

	for (unsigned int i = 0; i < count; i++)
	{
	    if (!array->setObject(i, dictionary[i].key))
	    {
            array->release();
            array = 0;
            break;
        }
	}
    return (array);
}

bool OSDictionary::iterateObjects(void * refcon, bool (*callback)(void * refcon, const OSSymbol * key, OSObject * object))
{
    unsigned int initialUpdateStamp;
    bool         done;

    initialUpdateStamp = updateStamp;
    done = false;
	for (unsigned int i = 0; i < count; i++)
    {
        done = callback(refcon, dictionary[i].key, EXT_CAST(dictionary[i].value));
        if (done)                              break;
        if (initialUpdateStamp != updateStamp) break;
    }

    return initialUpdateStamp == updateStamp;
}

static bool OSDictionaryIterateObjectsBlock(void * refcon, const OSSymbol * key, OSObject * object)
{
    bool (^block)(const OSSymbol * key, OSObject * object) = (typeof(block)) refcon;
    return (block(key, object));
}

bool OSDictionary::iterateObjects(bool (^block)(const OSSymbol * key, OSObject * object))
{
	return (iterateObjects((void *)block, &OSDictionaryIterateObjectsBlock));
}
