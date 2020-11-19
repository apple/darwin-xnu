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

#define IOKIT_ENABLE_SHARED_PTR

#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSCollectionIterator.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSLib.h>
#include <libkern/c++/OSSerialize.h>
#include <libkern/c++/OSSharedPtr.h>
#include <libkern/c++/OSSymbol.h>
#include <os/cpp_util.h>

#define super OSCollection

OSDefineMetaClassAndStructorsWithZone(OSDictionary, OSCollection,
    (zone_create_flags_t) (ZC_CACHING | ZC_ZFREE_CLEARMEM))
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

extern "C" {
void qsort(void *, size_t, size_t, int (*)(const void *, const void *));
}

int
OSDictionary::dictEntry::compare(const void *_e1, const void *_e2)
{
	const OSDictionary::dictEntry *e1 = (const OSDictionary::dictEntry *)_e1;
	const OSDictionary::dictEntry *e2 = (const OSDictionary::dictEntry *)_e2;

	if ((uintptr_t)e1->key.get() == (uintptr_t)e2->key.get()) {
		return 0;
	}

	return (uintptr_t)e1->key.get() > (uintptr_t)e2->key.get() ? 1 : -1;
}

void
OSDictionary::sortBySymbol(void)
{
	qsort(dictionary, count, sizeof(OSDictionary::dictEntry),
	    &OSDictionary::dictEntry::compare);
}

bool
OSDictionary::initWithCapacity(unsigned int inCapacity)
{
	if (!super::init()) {
		return false;
	}

	if (inCapacity > (UINT_MAX / sizeof(dictEntry))) {
		return false;
	}

	unsigned int size = inCapacity * sizeof(dictEntry);
//fOptions |= kSort;

	dictionary = (dictEntry *) kalloc_container(size);
	if (!dictionary) {
		return false;
	}

	os::uninitialized_value_construct(dictionary, dictionary + inCapacity);
	OSCONTAINER_ACCUMSIZE(size);

	count = 0;
	capacity = inCapacity;
	capacityIncrement = (inCapacity)? inCapacity : 16;

	return true;
}

bool
OSDictionary::initWithObjects(const OSObject *objects[],
    const OSSymbol *keys[],
    unsigned int theCount,
    unsigned int theCapacity)
{
	unsigned int newCapacity = theCount;

	if (!objects || !keys) {
		return false;
	}

	if (theCapacity) {
		if (theCount > theCapacity) {
			return false;
		}

		newCapacity = theCapacity;
	}

	if (!initWithCapacity(newCapacity)) {
		return false;
	}

	for (unsigned int i = 0; i < theCount; i++) {
		const OSMetaClassBase *newObject = *objects++;

		if (!newObject || !keys[i] || !setObject(keys[i], newObject)) {
			return false;
		}
	}

	return true;
}

bool
OSDictionary::initWithObjects(const OSObject *objects[],
    const OSString *keys[],
    unsigned int theCount,
    unsigned int theCapacity)
{
	unsigned int newCapacity = theCount;

	if (!objects || !keys) {
		return false;
	}

	if (theCapacity) {
		if (theCount > theCapacity) {
			return false;
		}

		newCapacity = theCapacity;
	}

	if (!initWithCapacity(newCapacity)) {
		return false;
	}

	for (unsigned int i = 0; i < theCount; i++) {
		OSSharedPtr<const OSSymbol> key = OSSymbol::withString(*keys++);
		const OSMetaClassBase *newObject = *objects++;

		if (!key) {
			return false;
		}

		if (!newObject || !setObject(key.get(), newObject)) {
			return false;
		}
	}

	return true;
}

bool
OSDictionary::initWithDictionary(const OSDictionary *dict,
    unsigned int theCapacity)
{
	unsigned int newCapacity;

	if (!dict) {
		return false;
	}

	newCapacity = dict->count;

	if (theCapacity) {
		if (dict->count > theCapacity) {
			return false;
		}

		newCapacity = theCapacity;
	}

	if (!initWithCapacity(newCapacity)) {
		return false;
	}

	count = dict->count;
	for (unsigned int i = 0; i < count; i++) {
		dictionary[i].key = dict->dictionary[i].key;
		dictionary[i].value = dict->dictionary[i].value;
	}

	if ((kSort & fOptions) && !(kSort & dict->fOptions)) {
		sortBySymbol();
	}

	return true;
}

OSSharedPtr<OSDictionary>
OSDictionary::withCapacity(unsigned int capacity)
{
	OSSharedPtr<OSDictionary> me = OSMakeShared<OSDictionary>();

	if (me && !me->initWithCapacity(capacity)) {
		return nullptr;
	}

	return me;
}

OSSharedPtr<OSDictionary>
OSDictionary::withObjects(const OSObject *objects[],
    const OSSymbol *keys[],
    unsigned int count,
    unsigned int capacity)
{
	OSSharedPtr<OSDictionary> me = OSMakeShared<OSDictionary>();

	if (me && !me->initWithObjects(objects, keys, count, capacity)) {
		return nullptr;
	}

	return me;
}

OSSharedPtr<OSDictionary>
OSDictionary::withObjects(const OSObject *objects[],
    const OSString *keys[],
    unsigned int count,
    unsigned int capacity)
{
	OSSharedPtr<OSDictionary> me = OSMakeShared<OSDictionary>();

	if (me && !me->initWithObjects(objects, keys, count, capacity)) {
		return nullptr;
	}

	return me;
}

OSSharedPtr<OSDictionary>
OSDictionary::withDictionary(const OSDictionary *dict,
    unsigned int capacity)
{
	OSSharedPtr<OSDictionary> me = OSMakeShared<OSDictionary>();

	if (me && !me->initWithDictionary(dict, capacity)) {
		return nullptr;
	}

	return me;
}

void
OSDictionary::free()
{
	(void) super::setOptions(0, kImmutable);
	flushCollection();
	if (dictionary) {
		kfree(dictionary, capacity * sizeof(dictEntry));
		OSCONTAINER_ACCUMSIZE( -(capacity * sizeof(dictEntry)));
	}

	super::free();
}

unsigned int
OSDictionary::getCount() const
{
	return count;
}
unsigned int
OSDictionary::getCapacity() const
{
	return capacity;
}

unsigned int
OSDictionary::getCapacityIncrement() const
{
	return capacityIncrement;
}

unsigned int
OSDictionary::setCapacityIncrement(unsigned int increment)
{
	capacityIncrement = (increment)? increment : 16;

	return capacityIncrement;
}

unsigned int
OSDictionary::ensureCapacity(unsigned int newCapacity)
{
	dictEntry *newDict;
	vm_size_t finalCapacity;
	vm_size_t oldSize, newSize;

	if (newCapacity <= capacity) {
		return capacity;
	}

	// round up
	finalCapacity = (((newCapacity - 1) / capacityIncrement) + 1)
	    * capacityIncrement;

	// integer overflow check
	if (finalCapacity < newCapacity) {
		return capacity;
	}

	newSize = sizeof(dictEntry) * finalCapacity;

	newDict = (dictEntry *) kallocp_container(&newSize);
	if (newDict) {
		// use all of the actual allocation size
		finalCapacity = (newSize / sizeof(dictEntry));
		if (finalCapacity > UINT_MAX) {
			// failure, too large
			kfree(newDict, newSize);
			return capacity;
		}

		oldSize = sizeof(dictEntry) * capacity;

		os::uninitialized_move(dictionary, dictionary + capacity, newDict);
		os::uninitialized_value_construct(newDict + capacity, newDict + finalCapacity);
		os::destroy(dictionary, dictionary + capacity);

		OSCONTAINER_ACCUMSIZE(((size_t)newSize) - ((size_t)oldSize));
		kfree(dictionary, oldSize);

		dictionary = newDict;
		capacity = (unsigned int) finalCapacity;
	}

	return capacity;
}

void
OSDictionary::flushCollection()
{
	haveUpdated();

	for (unsigned int i = 0; i < count; i++) {
		dictionary[i].key->taggedRelease(OSTypeID(OSCollection));
		dictionary[i].value->taggedRelease(OSTypeID(OSCollection));
	}
	count = 0;
}

bool
OSDictionary::
setObject(const OSSymbol *aKey, const OSMetaClassBase *anObject, bool onlyAdd)
{
	unsigned int i;
	bool exists;

	if (!anObject || !aKey) {
		return false;
	}

	// if the key exists, replace the object

	if (fOptions & kSort) {
		i = OSSymbol::bsearch(aKey, &dictionary[0], count, sizeof(dictionary[0]));
		exists = (i < count) && (aKey == dictionary[i].key);
	} else {
		for (exists = false, i = 0; i < count; i++) {
			if ((exists = (aKey == dictionary[i].key))) {
				break;
			}
		}
	}

	if (exists) {
		if (onlyAdd) {
			return false;
		}

		OSTaggedSharedPtr<const OSMetaClassBase, OSCollection> oldObject;

		haveUpdated();

		dictionary[i].value.reset(anObject, OSRetain);
		return true;
	}

	// add new key, possibly extending our capacity
	if (count >= capacity && count >= ensureCapacity(count + 1)) {
		return false;
	}

	haveUpdated();

	new (&dictionary[count]) dictEntry();
	os::move_backward(&dictionary[i], &dictionary[count], &dictionary[count + 1]);

	dictionary[i].key.reset(aKey, OSRetain);
	dictionary[i].value.reset(anObject, OSRetain);
	count++;

	return true;
}

bool
OSDictionary::
setObject(const OSSymbol *aKey, const OSMetaClassBase *anObject)
{
	return setObject(aKey, anObject, false);
}

bool
OSDictionary::setObject(OSSharedPtr<const OSSymbol> const& aKey, OSSharedPtr<const OSMetaClassBase> const& anObject)
{
	return setObject(aKey.get(), anObject.get());
}

bool
OSDictionary::setObject(const OSString* aKey, OSSharedPtr<const OSMetaClassBase> const& anObject)
{
	return setObject(aKey, anObject.get());
}

bool
OSDictionary::setObject(const char* aKey, OSSharedPtr<const OSMetaClassBase> const& anObject)
{
	return setObject(aKey, anObject.get());
}

void
OSDictionary::removeObject(const OSSymbol *aKey)
{
	unsigned int i;
	bool exists;

	if (!aKey) {
		return;
	}

	// if the key exists, remove the object

	if (fOptions & kSort) {
		i = OSSymbol::bsearch(aKey, &dictionary[0], count, sizeof(dictionary[0]));
		exists = (i < count) && (aKey == dictionary[i].key);
	} else {
		for (exists = false, i = 0; i < count; i++) {
			if ((exists = (aKey == dictionary[i].key))) {
				break;
			}
		}
	}

	if (exists) {
		dictEntry oldEntry = dictionary[i];

		haveUpdated();

		count--;
		bcopy(&dictionary[i + 1], &dictionary[i], (count - i) * sizeof(dictionary[0]));

		oldEntry.key->taggedRelease(OSTypeID(OSCollection));
		oldEntry.value->taggedRelease(OSTypeID(OSCollection));
		return;
	}
}


// Returns true on success, false on an error condition.
bool
OSDictionary::merge(const OSDictionary *srcDict)
{
	const OSSymbol * sym;
	OSSharedPtr<OSCollectionIterator> iter;

	if (!OSDynamicCast(OSDictionary, srcDict)) {
		return false;
	}

	iter = OSCollectionIterator::withCollection(const_cast<OSDictionary *>(srcDict));
	if (!iter) {
		return false;
	}

	while ((sym = (const OSSymbol *)iter->getNextObject())) {
		const OSMetaClassBase * obj;

		obj = srcDict->getObject(sym);
		if (!setObject(sym, obj)) {
			return false;
		}
	}

	return true;
}

OSObject *
OSDictionary::getObject(const OSSymbol *aKey) const
{
	unsigned int i, l = 0, r = count;

	if (!aKey) {
		return NULL;
	}

	// if the key exists, return the object
	//
	// inline OSSymbol::bsearch in this performance critical codepath
	// for performance, the compiler can't do that due to the genericity
	// of OSSymbol::bsearch
	//
	// If we have less than 4 objects, scanning is faster.
	if (count > 4 && (fOptions & kSort)) {
		while (l < r) {
			i = (l + r) / 2;
			if (aKey == dictionary[i].key) {
				return const_cast<OSObject *> ((const OSObject *)dictionary[i].value.get());
			}

			if ((uintptr_t)aKey < (uintptr_t)dictionary[i].key.get()) {
				r = i;
			} else {
				l = i + 1;
			}
		}
	} else {
		for (i = l; i < r; i++) {
			if (aKey == dictionary[i].key) {
				return const_cast<OSObject *> ((const OSObject *)dictionary[i].value.get());
			}
		}
	}

	return NULL;
}

// Wrapper macros
#define OBJECT_WRAP_1(cmd, k)                                           \
{                                                                       \
    OSSharedPtr<const OSSymbol> tmpKey = k;                                         \
    OSObject *retObj = NULL;                                            \
    if (tmpKey) {                                                       \
	retObj = cmd(tmpKey.get());                                           \
    }                                                                   \
    return retObj;                                                      \
}

#define OBJECT_WRAP_2(cmd, k, o)                                        \
{                                                                       \
    OSSharedPtr<const OSSymbol> tmpKey = k;                                         \
    bool ret = cmd(tmpKey.get(), o);                                          \
                                                                        \
    return ret;                                                         \
}

#define OBJECT_WRAP_3(cmd, k)                                           \
{                                                                       \
    OSSharedPtr<const OSSymbol> tmpKey = k;                                         \
    if (tmpKey) {                                                       \
	cmd(tmpKey.get());                                                    \
    }                                                                   \
}


bool
OSDictionary::setObject(const OSString *aKey, const OSMetaClassBase *anObject)
OBJECT_WRAP_2(setObject, OSSymbol::withString(aKey), anObject)
bool
OSDictionary::setObject(const char *aKey, const OSMetaClassBase *anObject)
OBJECT_WRAP_2(setObject, OSSymbol::withCString(aKey), anObject)

OSObject *OSDictionary::getObject(const OSString * aKey) const
OBJECT_WRAP_1(getObject, OSSymbol::existingSymbolForString(aKey))
OSObject *OSDictionary::getObject(const char *aKey) const
OBJECT_WRAP_1(getObject, OSSymbol::existingSymbolForCString(aKey))

void
OSDictionary::removeObject(const OSString *aKey)
OBJECT_WRAP_3(removeObject, OSSymbol::existingSymbolForString(aKey))
void
OSDictionary::removeObject(const char *aKey)
OBJECT_WRAP_3(removeObject, OSSymbol::existingSymbolForCString(aKey))

bool
OSDictionary::isEqualTo(const OSDictionary *srcDict, const OSCollection *keys) const
{
	OSSharedPtr<OSCollectionIterator> iter;
	unsigned int keysCount;
	const OSMetaClassBase * obj1;
	const OSMetaClassBase * obj2;
	OSString * aKey;
	bool ret;

	if (this == srcDict) {
		return true;
	}

	keysCount = keys->getCount();
	if ((count < keysCount) || (srcDict->getCount() < keysCount)) {
		return false;
	}

	iter = OSCollectionIterator::withCollection(keys);
	if (!iter) {
		return false;
	}

	ret = true;
	while ((aKey = OSDynamicCast(OSString, iter->getNextObject()))) {
		obj1 = getObject(aKey);
		obj2 = srcDict->getObject(aKey);
		if (!obj1 || !obj2) {
			ret = false;
			break;
		}

		if (!obj1->isEqualTo(obj2)) {
			ret = false;
			break;
		}
	}

	return ret;
}

bool
OSDictionary::isEqualTo(const OSDictionary *srcDict) const
{
	unsigned int i;
	const OSMetaClassBase * obj;

	if (this == srcDict) {
		return true;
	}

	if (count != srcDict->getCount()) {
		return false;
	}

	for (i = 0; i < count; i++) {
		obj = srcDict->getObject(dictionary[i].key.get());
		if (!obj) {
			return false;
		}

		if (!dictionary[i].value->isEqualTo(obj)) {
			return false;
		}
	}

	return true;
}

bool
OSDictionary::isEqualTo(const OSMetaClassBase *anObject) const
{
	OSDictionary *dict;

	dict = OSDynamicCast(OSDictionary, anObject);
	if (dict) {
		return isEqualTo(dict);
	} else {
		return false;
	}
}

unsigned int
OSDictionary::iteratorSize() const
{
	return sizeof(unsigned int);
}

bool
OSDictionary::initIterator(void *inIterator) const
{
	unsigned int *iteratorP = (unsigned int *) inIterator;

	*iteratorP = 0;
	return true;
}

bool
OSDictionary::getNextObjectForIterator(void *inIterator, OSObject **ret) const
{
	unsigned int *iteratorP = (unsigned int *) inIterator;
	unsigned int index = (*iteratorP)++;

	if (index < count) {
		*ret = const_cast<OSSymbol*>(dictionary[index].key.get());
	} else {
		*ret = NULL;
	}

	return *ret != NULL;
}

bool
OSDictionary::serialize(OSSerialize *s) const
{
	if (s->previouslySerialized(this)) {
		return true;
	}

	if (!s->addXMLStartTag(this, "dict")) {
		return false;
	}

	for (unsigned i = 0; i < count; i++) {
		const OSSymbol *key = dictionary[i].key.get();

		// due the nature of the XML syntax, this must be a symbol
		if (!key->metaCast("OSSymbol")) {
			return false;
		}
		if (!s->addString("<key>")) {
			return false;
		}
		const char *c = key->getCStringNoCopy();
		while (*c) {
			if (*c == '<') {
				if (!s->addString("&lt;")) {
					return false;
				}
			} else if (*c == '>') {
				if (!s->addString("&gt;")) {
					return false;
				}
			} else if (*c == '&') {
				if (!s->addString("&amp;")) {
					return false;
				}
			} else {
				if (!s->addChar(*c)) {
					return false;
				}
			}
			c++;
		}
		if (!s->addXMLEndTag("key")) {
			return false;
		}

		if (!dictionary[i].value->serialize(s)) {
			return false;
		}
	}

	return s->addXMLEndTag("dict");
}

unsigned
OSDictionary::setOptions(unsigned options, unsigned mask, void *)
{
	unsigned old = super::setOptions(options, mask);
	if ((old ^ options) & mask) {
		// Value changed need to recurse over all of the child collections
		for (unsigned i = 0; i < count; i++) {
			OSCollection *v = OSDynamicCast(OSCollection, dictionary[i].value.get());
			if (v) {
				v->setOptions(options, mask);
			}
		}
	}

	if (!(old & kSort) && (fOptions & kSort)) {
		sortBySymbol();
	}

	return old;
}

OSSharedPtr<OSCollection>
OSDictionary::copyCollection(OSDictionary *cycleDict)
{
	OSSharedPtr<OSDictionary> ourCycleDict;
	OSSharedPtr<OSCollection> ret;
	OSSharedPtr<OSDictionary> newDict;

	if (!cycleDict) {
		ourCycleDict = OSDictionary::withCapacity(16);
		if (!ourCycleDict) {
			return nullptr;
		}
		cycleDict = ourCycleDict.get();
	}

	do {
		// Check for a cycle
		ret = super::copyCollection(cycleDict);
		if (ret) {
			continue;
		}

		newDict = OSDictionary::withDictionary(this);
		if (!newDict) {
			continue;
		}

		// Insert object into cycle Dictionary
		cycleDict->setObject((const OSSymbol *) this, newDict.get());

		for (unsigned int i = 0; i < count; i++) {
			const OSMetaClassBase *obj = dictionary[i].value.get();
			OSTaggedSharedPtr<OSCollection, OSCollection> coll(OSDynamicCast(OSCollection, EXT_CAST(obj)), OSNoRetain);

			if (coll) {
				OSSharedPtr<OSCollection> newColl = coll->copyCollection(cycleDict);
				if (!newColl) {
					return ret;
				}
				newDict->dictionary[i].value.detach();
				newDict->dictionary[i].value.reset(newColl.get(), OSRetain);
			}
		}

		ret = os::move(newDict);
	} while (false);

	return ret;
}

OSSharedPtr<OSArray>
OSDictionary::copyKeys(void)
{
	OSSharedPtr<OSArray> array;

	array = OSArray::withCapacity(count);
	if (!array) {
		return nullptr;
	}

	for (unsigned int i = 0; i < count; i++) {
		if (!array->setObject(i, dictionary[i].key.get())) {
			return nullptr;
		}
	}
	return array;
}

bool
OSDictionary::iterateObjects(void * refcon, bool (*callback)(void * refcon, const OSSymbol * key, OSObject * object))
{
	unsigned int initialUpdateStamp;
	bool         done;

	initialUpdateStamp = updateStamp;
	done = false;
	for (unsigned int i = 0; i < count; i++) {
		done = callback(refcon, dictionary[i].key.get(), EXT_CAST(dictionary[i].value.get()));
		if (done) {
			break;
		}
		if (initialUpdateStamp != updateStamp) {
			break;
		}
	}

	return initialUpdateStamp == updateStamp;
}

static bool
OSDictionaryIterateObjectsBlock(void * refcon, const OSSymbol * key, OSObject * object)
{
	bool (^block)(const OSSymbol * key, OSObject * object) = (typeof(block))refcon;
	return block(key, object);
}

bool
OSDictionary::iterateObjects(bool (^block)(const OSSymbol * key, OSObject * object))
{
	return iterateObjects((void *)block, &OSDictionaryIterateObjectsBlock);
}
