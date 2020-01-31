/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
/* OSSerialize.cpp created by rsulack on Wen 25-Nov-1998 */

#include <sys/cdefs.h>

__BEGIN_DECLS
#include <vm/vm_kern.h>
__END_DECLS

#include <libkern/c++/OSContainers.h>
#include <libkern/c++/OSLib.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/OSSerializeBinary.h>
#include <libkern/Block.h>
#include <IOKit/IOLib.h>

#define super OSObject

OSDefineMetaClassAndStructors(OSSerialize, OSObject)
OSMetaClassDefineReservedUnused(OSSerialize, 0);
OSMetaClassDefineReservedUnused(OSSerialize, 1);
OSMetaClassDefineReservedUnused(OSSerialize, 2);
OSMetaClassDefineReservedUnused(OSSerialize, 3);
OSMetaClassDefineReservedUnused(OSSerialize, 4);
OSMetaClassDefineReservedUnused(OSSerialize, 5);
OSMetaClassDefineReservedUnused(OSSerialize, 6);
OSMetaClassDefineReservedUnused(OSSerialize, 7);


char *
OSSerialize::text() const
{
	return data;
}

void
OSSerialize::clearText()
{
	if (binary) {
		length = sizeof(kOSSerializeBinarySignature);
		bzero(&data[length], capacity - length);
		endCollection = true;
	} else {
		bzero((void *)data, capacity);
		length = 1;
	}
	tags->flushCollection();
}

bool
OSSerialize::previouslySerialized(const OSMetaClassBase *o)
{
	char temp[16];
	unsigned int tagIdx;

	if (binary) {
		return binarySerialize(o);
	}

	// look it up
	tagIdx = tags->getNextIndexOfObject(o, 0);

// xx-review: no error checking here for addString calls!
	// does it exist?
	if (tagIdx != -1U) {
		addString("<reference IDREF=\"");
		snprintf(temp, sizeof(temp), "%u", tagIdx);
		addString(temp);
		addString("\"/>");
		return true;
	}

	// add to tag array
	tags->setObject(o);// XXX check return

	return false;
}

bool
OSSerialize::addXMLStartTag(const OSMetaClassBase *o, const char *tagString)
{
	char temp[16];
	unsigned int tagIdx;

	if (binary) {
		printf("class %s: xml serialize\n", o->getMetaClass()->getClassName());
		return false;
	}

	if (!addChar('<')) {
		return false;
	}
	if (!addString(tagString)) {
		return false;
	}
	if (!addString(" ID=\"")) {
		return false;
	}
	tagIdx = tags->getNextIndexOfObject(o, 0);
	assert(tagIdx != -1U);
	snprintf(temp, sizeof(temp), "%u", tagIdx);
	if (!addString(temp)) {
		return false;
	}
	if (!addChar('\"')) {
		return false;
	}
	if (!addChar('>')) {
		return false;
	}
	return true;
}

bool
OSSerialize::addXMLEndTag(const char *tagString)
{
	if (!addChar('<')) {
		return false;
	}
	if (!addChar('/')) {
		return false;
	}
	if (!addString(tagString)) {
		return false;
	}
	if (!addChar('>')) {
		return false;
	}
	return true;
}

bool
OSSerialize::addChar(const char c)
{
	if (binary) {
		printf("xml serialize\n");
		return false;
	}

	// add char, possibly extending our capacity
	if (length >= capacity && length >= ensureCapacity(capacity + capacityIncrement)) {
		return false;
	}

	data[length - 1] = c;
	length++;

	return true;
}

bool
OSSerialize::addString(const char *s)
{
	bool rc = false;

	while (*s && (rc = addChar(*s++))) {
		;
	}

	return rc;
}

bool
OSSerialize::initWithCapacity(unsigned int inCapacity)
{
	if (!super::init()) {
		return false;
	}

	tags = OSArray::withCapacity(256);
	if (!tags) {
		return false;
	}

	length = 1;

	if (!inCapacity) {
		inCapacity = 1;
	}
	if (round_page_overflow(inCapacity, &capacity)) {
		tags->release();
		tags = 0;
		return false;
	}

	capacityIncrement = capacity;

	// allocate from the kernel map so that we can safely map this data
	// into user space (the primary use of the OSSerialize object)

	kern_return_t rc = kmem_alloc(kernel_map, (vm_offset_t *)&data, capacity, IOMemoryTag(kernel_map));
	if (rc) {
		tags->release();
		tags = 0;
		return false;
	}
	bzero((void *)data, capacity);


	OSCONTAINER_ACCUMSIZE(capacity);

	return true;
}

OSSerialize *
OSSerialize::withCapacity(unsigned int inCapacity)
{
	OSSerialize *me = new OSSerialize;

	if (me && !me->initWithCapacity(inCapacity)) {
		me->release();
		return 0;
	}

	return me;
}

unsigned int
OSSerialize::getLength() const
{
	return length;
}
unsigned int
OSSerialize::getCapacity() const
{
	return capacity;
}
unsigned int
OSSerialize::getCapacityIncrement() const
{
	return capacityIncrement;
}
unsigned int
OSSerialize::setCapacityIncrement(unsigned int increment)
{
	capacityIncrement = (increment)? increment : 256;
	return capacityIncrement;
}

unsigned int
OSSerialize::ensureCapacity(unsigned int newCapacity)
{
	char *newData;

	if (newCapacity <= capacity) {
		return capacity;
	}

	if (round_page_overflow(newCapacity, &newCapacity)) {
		return capacity;
	}

	kern_return_t rc = kmem_realloc(kernel_map,
	    (vm_offset_t)data,
	    capacity,
	    (vm_offset_t *)&newData,
	    newCapacity,
	    VM_KERN_MEMORY_IOKIT);
	if (!rc) {
		OSCONTAINER_ACCUMSIZE(newCapacity);

		// kmem realloc does not free the old address range
		kmem_free(kernel_map, (vm_offset_t)data, capacity);
		OSCONTAINER_ACCUMSIZE(-((size_t)capacity));

		// kmem realloc does not zero out the new memory
		// and this could end up going to user land
		bzero(&newData[capacity], newCapacity - capacity);

		data = newData;
		capacity = newCapacity;
	}

	return capacity;
}

void
OSSerialize::free()
{
	if (tags) {
		tags->release();
	}

	if (data) {
		kmem_free(kernel_map, (vm_offset_t)data, capacity);
		OSCONTAINER_ACCUMSIZE( -((size_t)capacity));
	}
	super::free();
}


OSDefineMetaClassAndStructors(OSSerializer, OSObject)

OSSerializer * OSSerializer::forTarget( void * target,
    OSSerializerCallback callback, void * ref )
{
	OSSerializer * thing;

	thing = new OSSerializer;
	if (thing && !thing->init()) {
		thing->release();
		thing = 0;
	}

	if (thing) {
		thing->target   = target;
		thing->ref      = ref;
		thing->callback = callback;
	}
	return thing;
}

bool
OSSerializer::callbackToBlock(void * target __unused, void * ref,
    OSSerialize * serializer)
{
	return ((OSSerializerBlock)ref)(serializer);
}

OSSerializer *
OSSerializer::withBlock(
	OSSerializerBlock callback)
{
	OSSerializer * serializer;
	OSSerializerBlock block;

	block = Block_copy(callback);
	if (!block) {
		return 0;
	}

	serializer = (OSSerializer::forTarget(NULL, &OSSerializer::callbackToBlock, block));

	if (!serializer) {
		Block_release(block);
	}

	return serializer;
}

void
OSSerializer::free(void)
{
	if (callback == &callbackToBlock) {
		Block_release(ref);
	}

	super::free();
}

bool
OSSerializer::serialize( OSSerialize * s ) const
{
	return (*callback)(target, ref, s);
}
