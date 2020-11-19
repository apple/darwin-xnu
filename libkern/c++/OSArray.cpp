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
/* IOArray.m created by rsulack on Fri 12-Sep-1997 */
/* IOArray.cpp converted to C++ by gvdl on Fri 1998-10-30 */


#define IOKIT_ENABLE_SHARED_PTR

#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSLib.h>
#include <libkern/c++/OSSerialize.h>
#include <libkern/c++/OSSharedPtr.h>
#include <libkern/OSDebug.h>
#include <os/cpp_util.h>

#define super OSCollection

OSDefineMetaClassAndStructorsWithZone(OSArray, OSCollection,
    (zone_create_flags_t) (ZC_CACHING | ZC_ZFREE_CLEARMEM))
OSMetaClassDefineReservedUnused(OSArray, 0);
OSMetaClassDefineReservedUnused(OSArray, 1);
OSMetaClassDefineReservedUnused(OSArray, 2);
OSMetaClassDefineReservedUnused(OSArray, 3);
OSMetaClassDefineReservedUnused(OSArray, 4);
OSMetaClassDefineReservedUnused(OSArray, 5);
OSMetaClassDefineReservedUnused(OSArray, 6);
OSMetaClassDefineReservedUnused(OSArray, 7);

bool
OSArray::initWithCapacity(unsigned int inCapacity)
{
	unsigned int size;

	if (!super::init()) {
		return false;
	}

	// integer overflow check
	if (inCapacity > (UINT_MAX / sizeof(*array))) {
		return false;
	}

	size = sizeof(*array) * inCapacity;
	array = (ArraySharedPtrType *)kalloc_container(size);
	if (!array) {
		return false;
	}

	count = 0;
	capacity = inCapacity;
	capacityIncrement = (inCapacity)? inCapacity : 16;

	os::uninitialized_value_construct(array, array + capacity);
	OSCONTAINER_ACCUMSIZE(size);

	return true;
}

bool
OSArray::initWithObjects(const OSObject *objects[],
    unsigned int theCount,
    unsigned int theCapacity)
{
	unsigned int initCapacity;

	if (!theCapacity) {
		initCapacity = theCount;
	} else if (theCount > theCapacity) {
		return false;
	} else {
		initCapacity = theCapacity;
	}

	if (!objects || !initWithCapacity(initCapacity)) {
		return false;
	}

	for (unsigned int i = 0; i < theCount; i++) {
		const OSMetaClassBase *newObject = *objects++;

		if (!newObject) {
			return false;
		}

		array[count++].reset(newObject, OSRetain);
	}

	return true;
}

bool
OSArray::initWithArray(const OSArray *anArray,
    unsigned int theCapacity)
{
	if (!anArray) {
		return false;
	}

	return initWithObjects((const OSObject **) anArray->array,
	           anArray->count, theCapacity);
}

OSSharedPtr<OSArray>
OSArray::withCapacity(unsigned int capacity)
{
	OSSharedPtr<OSArray> me = OSMakeShared<OSArray>();

	if (me && !me->initWithCapacity(capacity)) {
		return nullptr;
	}

	return me;
}

OSSharedPtr<OSArray>
OSArray::withObjects(const OSObject *objects[],
    unsigned int count,
    unsigned int capacity)
{
	OSSharedPtr<OSArray> me = OSMakeShared<OSArray>();

	if (me && !me->initWithObjects(objects, count, capacity)) {
		return nullptr;
	}

	return me;
}

OSSharedPtr<OSArray>
OSArray::withArray(const OSArray *array,
    unsigned int capacity)
{
	OSSharedPtr<OSArray> me = OSMakeShared<OSArray>();

	if (me && !me->initWithArray(array, capacity)) {
		return nullptr;
	}

	return me;
}

void
OSArray::free()
{
	// Clear immutability - assumes the container is doing the right thing
	(void) super::setOptions(0, kImmutable);

	flushCollection();

	if (array) {
		os::destroy(array, array + capacity);
		kfree(array, sizeof(*array) * capacity);
		OSCONTAINER_ACCUMSIZE( -(sizeof(*array) * capacity));
	}

	super::free();
}


unsigned int
OSArray::getCount() const
{
	return count;
}
unsigned int
OSArray::getCapacity() const
{
	return capacity;
}
unsigned int
OSArray::getCapacityIncrement() const
{
	return capacityIncrement;
}
unsigned int
OSArray::setCapacityIncrement(unsigned int increment)
{
	capacityIncrement = (increment)? increment : 16;

	return capacityIncrement;
}

unsigned int
OSArray::ensureCapacity(unsigned int newCapacity)
{
	ArraySharedPtrType *newArray;
	vm_size_t    finalCapacity;
	vm_size_t    oldSize, newSize;

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

	newSize = sizeof(*newArray) * finalCapacity;

	newArray = (decltype(newArray))kallocp_container(&newSize);
	if (newArray) {
		// use all of the actual allocation size
		finalCapacity = (newSize / sizeof(*newArray));
		if (finalCapacity > UINT_MAX) {
			// failure, too large
			kfree(newArray, newSize);
			return capacity;
		}

		oldSize = sizeof(*array) * capacity;

		OSCONTAINER_ACCUMSIZE(((size_t)newSize) - ((size_t)oldSize));

		os::uninitialized_move(array, array + capacity, newArray);
		os::uninitialized_value_construct(newArray + capacity, newArray + finalCapacity);
		os::destroy(array, array + capacity);
		kfree(array, oldSize);
		array = newArray;
		capacity = (unsigned int) finalCapacity;
	}

	return capacity;
}

void
OSArray::flushCollection()
{
	unsigned int i;

	haveUpdated();
	for (i = 0; i < count; i++) {
		array[i].reset();
	}
	count = 0;
}

bool
OSArray::setObject(const OSMetaClassBase *anObject)
{
	return setObject(count, anObject);
}

bool
OSArray::setObject(OSSharedPtr<const OSMetaClassBase> const& anObject)
{
	return setObject(count, anObject);
}

bool
OSArray::setObject(unsigned int index, const OSMetaClassBase *anObject)
{
	unsigned int i;
	unsigned int newCount = count + 1;

	if ((index > count) || !anObject) {
		return false;
	}

	// do we need more space?
	if (newCount > capacity && newCount > ensureCapacity(newCount)) {
		return false;
	}

	haveUpdated();
	if (index != count) {
		for (i = count; i > index; i--) {
			array[i] = os::move(array[i - 1]);
		}
	}
	array[index].reset(anObject, OSRetain);
	count++;

	return true;
}

bool
OSArray::setObject(unsigned int index, OSSharedPtr<const OSMetaClassBase> const& anObject)
{
	return setObject(index, anObject.get());
}

bool
OSArray::merge(const OSArray * otherArray)
{
	unsigned int otherCount = otherArray->getCount();
	unsigned int newCount = count + otherCount;

	if (!otherCount) {
		return true;
	}

	if (newCount < count) {
		return false;
	}

	// do we need more space?
	if (newCount > capacity && newCount > ensureCapacity(newCount)) {
		return false;
	}

	haveUpdated();
	for (unsigned int i = 0; i < otherCount; i++) {
		const OSMetaClassBase *newObject = otherArray->getObject(i);

		array[count++].reset(newObject, OSRetain);
	}

	return true;
}

void
OSArray::
replaceObject(unsigned int index, const OSMetaClassBase *anObject)
{
	if ((index >= count) || !anObject) {
		return;
	}

	haveUpdated();

	array[index].reset(anObject, OSRetain);
}

void
OSArray::replaceObject(unsigned int index, OSSharedPtr<const OSMetaClassBase> const& anObject)
{
	return replaceObject(index, anObject.get());
}

void
OSArray::removeObject(unsigned int index)
{
	unsigned int i;
	ArraySharedPtrType oldObject;

	if (index >= count) {
		return;
	}

	haveUpdated();
	oldObject = os::move(array[index]);

	count--;
	for (i = index; i < count; i++) {
		array[i] = os::move(array[i + 1]);
	}
}

bool
OSArray::isEqualTo(const OSArray *anArray) const
{
	unsigned int i;

	if (this == anArray) {
		return true;
	}

	if (count != anArray->getCount()) {
		return false;
	}

	for (i = 0; i < count; i++) {
		if (!array[i]->isEqualTo(anArray->getObject(i))) {
			return false;
		}
	}

	return true;
}

bool
OSArray::isEqualTo(const OSMetaClassBase *anObject) const
{
	OSArray *otherArray;

	otherArray = OSDynamicCast(OSArray, anObject);
	if (otherArray) {
		return isEqualTo(otherArray);
	} else {
		return false;
	}
}

OSObject *
OSArray::getObject(unsigned int index) const
{
	if (index >= count) {
		return NULL;
	} else {
		return static_cast<OSObject *>(const_cast<OSMetaClassBase *>(array[index].get()));
	}
}

OSObject *
OSArray::getLastObject() const
{
	if (count == 0) {
		return NULL;
	} else {
		return static_cast<OSObject *>(const_cast<OSMetaClassBase *>(array[count - 1].get()));
	}
}

unsigned int
OSArray::getNextIndexOfObject(const OSMetaClassBase * anObject,
    unsigned int index) const
{
	while ((index < count) && (array[index] != anObject)) {
		index++;
	}
	if (index >= count) {
		index = (unsigned int)-1;
	}
	return index;
}

unsigned int
OSArray::iteratorSize() const
{
	return sizeof(unsigned int);
}

bool
OSArray::initIterator(void *inIterator) const
{
	unsigned int *iteratorP = (unsigned int *) inIterator;

	*iteratorP = 0;
	return true;
}

bool
OSArray::getNextObjectForIterator(void *inIterator, OSObject **ret) const
{
	unsigned int *iteratorP = (unsigned int *) inIterator;
	unsigned int index = (*iteratorP)++;

	if (index < count) {
		*ret = static_cast<OSObject *>(const_cast<OSMetaClassBase *>(array[index].get()));
		return true;
	} else {
		*ret = NULL;
		return false;
	}
}

bool
OSArray::serialize(OSSerialize *s) const
{
	if (s->previouslySerialized(this)) {
		return true;
	}

	if (!s->addXMLStartTag(this, "array")) {
		return false;
	}

	for (unsigned i = 0; i < count; i++) {
		if (array[i] == NULL || !array[i]->serialize(s)) {
			return false;
		}
	}

	return s->addXMLEndTag("array");
}

unsigned
OSArray::setOptions(unsigned options, unsigned mask, void *)
{
	unsigned old = super::setOptions(options, mask);
	if ((old ^ options) & mask) {
		// Value changed need to recurse over all of the child collections
		for (unsigned i = 0; i < count; i++) {
			OSCollection *coll = OSDynamicCast(OSCollection, array[i].get());
			if (coll) {
				coll->setOptions(options, mask);
			}
		}
	}

	return old;
}

OSSharedPtr<OSCollection>
OSArray::copyCollection(OSDictionary *cycleDict)
{
	OSSharedPtr<OSDictionary> ourCycleDict;
	OSSharedPtr<OSCollection> ret;
	OSSharedPtr<OSArray> newArray;

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

		newArray = OSArray::withArray(this);
		if (!newArray) {
			continue;
		}

		// Insert object into cycle Dictionary
		cycleDict->setObject((const OSSymbol *) this, newArray.get());

		for (unsigned int i = 0; i < count; i++) {
			OSCollection *coll =
			    OSDynamicCast(OSCollection, static_cast<OSObject *>(
				    const_cast<OSMetaClassBase *>(
					    newArray->array[i].get())));

			if (coll) {
				OSSharedPtr<OSCollection> newColl = coll->copyCollection(cycleDict);
				if (!newColl) {
					return ret;
				}

				newArray->replaceObject(i, newColl.get());
			}
		}

		ret = os::move(newArray);
	} while (false);

	return ret;
}
