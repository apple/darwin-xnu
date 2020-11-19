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
/* IOData.m created by rsulack on Thu 25-Sep-1997 */

#include <string.h>

__BEGIN_DECLS
#include <vm/vm_kern.h>
__END_DECLS

#define IOKIT_ENABLE_SHARED_PTR

#include <libkern/c++/OSData.h>
#include <libkern/c++/OSSerialize.h>
#include <libkern/c++/OSLib.h>
#include <libkern/c++/OSString.h>
#include <IOKit/IOLib.h>

#define super OSObject

OSDefineMetaClassAndStructorsWithZone(OSData, OSObject, ZC_ZFREE_CLEARMEM)
OSMetaClassDefineReservedUsedX86(OSData, 0);    // setDeallocFunction
OSMetaClassDefineReservedUnused(OSData, 1);
OSMetaClassDefineReservedUnused(OSData, 2);
OSMetaClassDefineReservedUnused(OSData, 3);
OSMetaClassDefineReservedUnused(OSData, 4);
OSMetaClassDefineReservedUnused(OSData, 5);
OSMetaClassDefineReservedUnused(OSData, 6);
OSMetaClassDefineReservedUnused(OSData, 7);

#define EXTERNAL ((unsigned int) -1)

bool
OSData::initWithCapacity(unsigned int inCapacity)
{
	void *_data = NULL;

	if (data) {
		OSCONTAINER_ACCUMSIZE(-((size_t)capacity));
		if (!inCapacity || (capacity < inCapacity)) {
			// clean out old data's storage if it isn't big enough
			if (capacity < page_size) {
				kfree_data_container(data, capacity);
			} else {
				kmem_free(kernel_map, (vm_offset_t)data, capacity);
			}
			data = NULL;
			capacity = 0;
		}
	}

	if (!super::init()) {
		return false;
	}

	if (inCapacity && !data) {
		if (inCapacity < page_size) {
			data = (void *)kalloc_data_container(inCapacity, Z_WAITOK);
		} else {
			kern_return_t kr;
			if (round_page_overflow(inCapacity, &inCapacity)) {
				kr = KERN_RESOURCE_SHORTAGE;
			} else {
				kr = kmem_alloc(kernel_map, (vm_offset_t *)&_data, inCapacity, IOMemoryTag(kernel_map));
				data = _data;
			}
			if (KERN_SUCCESS != kr) {
				data = NULL;
			}
		}
		if (!data) {
			return false;
		}
		capacity = inCapacity;
	}
	OSCONTAINER_ACCUMSIZE(capacity);

	length = 0;
	if (inCapacity < 16) {
		capacityIncrement = 16;
	} else {
		capacityIncrement = inCapacity;
	}

	return true;
}

bool
OSData::initWithBytes(const void *bytes, unsigned int inLength)
{
	if ((inLength && !bytes) || !initWithCapacity(inLength)) {
		return false;
	}

	if (bytes != data) {
		bcopy(bytes, data, inLength);
	}
	length = inLength;

	return true;
}

bool
OSData::initWithBytesNoCopy(void *bytes, unsigned int inLength)
{
	if (!super::init()) {
		return false;
	}

	length = inLength;
	capacity = EXTERNAL;
	data = bytes;

	return true;
}

bool
OSData::initWithData(const OSData *inData)
{
	return initWithBytes(inData->data, inData->length);
}

bool
OSData::initWithData(const OSData *inData,
    unsigned int start, unsigned int inLength)
{
	const void *localData = inData->getBytesNoCopy(start, inLength);

	if (localData) {
		return initWithBytes(localData, inLength);
	} else {
		return false;
	}
}

OSSharedPtr<OSData>
OSData::withCapacity(unsigned int inCapacity)
{
	OSSharedPtr<OSData> me = OSMakeShared<OSData>();

	if (me && !me->initWithCapacity(inCapacity)) {
		return nullptr;
	}

	return me;
}

OSSharedPtr<OSData>
OSData::withBytes(const void *bytes, unsigned int inLength)
{
	OSSharedPtr<OSData> me = OSMakeShared<OSData>();

	if (me && !me->initWithBytes(bytes, inLength)) {
		return nullptr;
	}
	return me;
}

OSSharedPtr<OSData>
OSData::withBytesNoCopy(void *bytes, unsigned int inLength)
{
	OSSharedPtr<OSData> me = OSMakeShared<OSData>();

	if (me && !me->initWithBytesNoCopy(bytes, inLength)) {
		return nullptr;
	}

	return me;
}

OSSharedPtr<OSData>
OSData::withData(const OSData *inData)
{
	OSSharedPtr<OSData> me = OSMakeShared<OSData>();

	if (me && !me->initWithData(inData)) {
		return nullptr;
	}

	return me;
}

OSSharedPtr<OSData>
OSData::withData(const OSData *inData,
    unsigned int start, unsigned int inLength)
{
	OSSharedPtr<OSData> me = OSMakeShared<OSData>();

	if (me && !me->initWithData(inData, start, inLength)) {
		return nullptr;
	}

	return me;
}

void
OSData::free()
{
	if ((capacity != EXTERNAL) && data && capacity) {
		if (capacity < page_size) {
			kfree_data_container(data, capacity);
		} else {
			kmem_free(kernel_map, (vm_offset_t)data, capacity);
		}
		OSCONTAINER_ACCUMSIZE( -((size_t)capacity));
	} else if (capacity == EXTERNAL) {
		DeallocFunction freemem = reserved ? reserved->deallocFunction : NULL;
		if (freemem && data && length) {
			freemem(data, length);
		}
	}
	if (reserved) {
		kfree(reserved, sizeof(ExpansionData));
	}
	super::free();
}

unsigned int
OSData::getLength() const
{
	return length;
}
unsigned int
OSData::getCapacity() const
{
	return capacity;
}

unsigned int
OSData::getCapacityIncrement() const
{
	return capacityIncrement;
}

unsigned int
OSData::setCapacityIncrement(unsigned increment)
{
	return capacityIncrement = increment;
}

// xx-review: does not check for capacity == EXTERNAL

unsigned int
OSData::ensureCapacity(unsigned int newCapacity)
{
	unsigned char * newData;
	unsigned int finalCapacity;
	void * copydata;
	kern_return_t kr;

	if (newCapacity <= capacity) {
		return capacity;
	}

	finalCapacity = (((newCapacity - 1) / capacityIncrement) + 1)
	    * capacityIncrement;

	// integer overflow check
	if (finalCapacity < newCapacity) {
		return capacity;
	}

	copydata = data;

	if (finalCapacity >= page_size) {
		// round up
		finalCapacity = round_page_32(finalCapacity);
		// integer overflow check
		if (finalCapacity < newCapacity) {
			return capacity;
		}
		if (capacity >= page_size) {
			copydata = NULL;
			kr = kmem_realloc(kernel_map,
			    (vm_offset_t)data,
			    capacity,
			    (vm_offset_t *)&newData,
			    finalCapacity,
			    IOMemoryTag(kernel_map));
		} else {
			kr = kmem_alloc(kernel_map, (vm_offset_t *)&newData, finalCapacity, IOMemoryTag(kernel_map));
		}
		if (KERN_SUCCESS != kr) {
			newData = NULL;
		}
	} else {
		newData = (unsigned char *)kalloc_data_container(finalCapacity, Z_WAITOK);
	}

	if (newData) {
		bzero(newData + capacity, finalCapacity - capacity);
		if (copydata) {
			bcopy(copydata, newData, capacity);
		}
		if (data) {
			if (capacity < page_size) {
				kfree_data_container(data, capacity);
			} else {
				kmem_free(kernel_map, (vm_offset_t)data, capacity);
			}
		}
		OSCONTAINER_ACCUMSIZE(((size_t)finalCapacity) - ((size_t)capacity));
		data = (void *) newData;
		capacity = finalCapacity;
	}

	return capacity;
}

bool
OSData::appendBytes(const void *bytes, unsigned int inLength)
{
	unsigned int newSize;

	if (!inLength) {
		return true;
	}

	if (capacity == EXTERNAL) {
		return false;
	}

	if (os_add_overflow(length, inLength, &newSize)) {
		return false;
	}

	if ((newSize > capacity) && newSize > ensureCapacity(newSize)) {
		return false;
	}

	if (bytes) {
		bcopy(bytes, &((unsigned char *)data)[length], inLength);
	} else {
		bzero(&((unsigned char *)data)[length], inLength);
	}

	length = newSize;

	return true;
}

bool
OSData::appendByte(unsigned char byte, unsigned int inLength)
{
	unsigned int newSize;

	if (!inLength) {
		return true;
	}

	if (capacity == EXTERNAL) {
		return false;
	}

	if (os_add_overflow(length, inLength, &newSize)) {
		return false;
	}

	if ((newSize > capacity) && newSize > ensureCapacity(newSize)) {
		return false;
	}

	memset(&((unsigned char *)data)[length], byte, inLength);
	length = newSize;

	return true;
}

bool
OSData::appendBytes(const OSData *other)
{
	return appendBytes(other->data, other->length);
}

const void *
OSData::getBytesNoCopy() const
{
	if (!length) {
		return NULL;
	} else {
		return data;
	}
}

const void *
OSData::getBytesNoCopy(unsigned int start,
    unsigned int inLength) const
{
	const void *outData = NULL;

	if (length
	    && start < length
	    && (start + inLength) >= inLength // overflow check
	    && (start + inLength) <= length) {
		outData = (const void *) ((char *) data + start);
	}

	return outData;
}

bool
OSData::isEqualTo(const OSData *aData) const
{
	unsigned int len;

	len = aData->length;
	if (length != len) {
		return false;
	}

	return isEqualTo(aData->data, len);
}

bool
OSData::isEqualTo(const void *someData, unsigned int inLength) const
{
	return (length >= inLength) && (bcmp(data, someData, inLength) == 0);
}

bool
OSData::isEqualTo(const OSMetaClassBase *obj) const
{
	OSData *    otherData;
	OSString *  str;

	if ((otherData = OSDynamicCast(OSData, obj))) {
		return isEqualTo(otherData);
	} else if ((str = OSDynamicCast(OSString, obj))) {
		return isEqualTo(str);
	} else {
		return false;
	}
}

bool
OSData::isEqualTo(const OSString *obj) const
{
	const char * aCString;
	char * dataPtr;
	unsigned int checkLen = length;
	unsigned int stringLen;

	if (!obj) {
		return false;
	}

	stringLen = obj->getLength();

	dataPtr = (char *)data;

	if (stringLen != checkLen) {
		// check for the fact that OSData may be a buffer that
		// that includes a termination byte and will thus have
		// a length of the actual string length PLUS 1. In this
		// case we verify that the additional byte is a terminator
		// and if so count the two lengths as being the same.

		if ((checkLen - stringLen) == 1) {
			if (dataPtr[checkLen - 1] != 0) { // non-zero means not a terminator and thus not likely the same
				return false;
			}
			checkLen--;
		} else {
			return false;
		}
	}

	aCString = obj->getCStringNoCopy();

	for (unsigned int i = 0; i < checkLen; i++) {
		if (*dataPtr++ != aCString[i]) {
			return false;
		}
	}

	return true;
}

//this was taken from CFPropertyList.c
static const char __CFPLDataEncodeTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

bool
OSData::serialize(OSSerialize *s) const
{
	unsigned int i;
	const unsigned char *p;
	unsigned char c;
	unsigned int serializeLength;

	if (s->previouslySerialized(this)) {
		return true;
	}

	if (!s->addXMLStartTag(this, "data")) {
		return false;
	}

	serializeLength = length;
	if (reserved && reserved->disableSerialization) {
		serializeLength = 0;
	}

	for (i = 0, p = (unsigned char *)data; i < serializeLength; i++, p++) {
		/* 3 bytes are encoded as 4 */
		switch (i % 3) {
		case 0:
			c = __CFPLDataEncodeTable[((p[0] >> 2) & 0x3f)];
			if (!s->addChar(c)) {
				return false;
			}
			break;
		case 1:
			c = __CFPLDataEncodeTable[((((p[-1] << 8) | p[0]) >> 4) & 0x3f)];
			if (!s->addChar(c)) {
				return false;
			}
			break;
		case 2:
			c = __CFPLDataEncodeTable[((((p[-1] << 8) | p[0]) >> 6) & 0x3f)];
			if (!s->addChar(c)) {
				return false;
			}
			c = __CFPLDataEncodeTable[(p[0] & 0x3f)];
			if (!s->addChar(c)) {
				return false;
			}
			break;
		}
	}
	switch (i % 3) {
	case 0:
		break;
	case 1:
		c = __CFPLDataEncodeTable[((p[-1] << 4) & 0x30)];
		if (!s->addChar(c)) {
			return false;
		}
		if (!s->addChar('=')) {
			return false;
		}
		if (!s->addChar('=')) {
			return false;
		}
		break;
	case 2:
		c = __CFPLDataEncodeTable[((p[-1] << 2) & 0x3c)];
		if (!s->addChar(c)) {
			return false;
		}
		if (!s->addChar('=')) {
			return false;
		}
		break;
	}

	return s->addXMLEndTag("data");
}

void
OSData::setDeallocFunction(DeallocFunction func)
{
	if (!reserved) {
		reserved = (typeof(reserved))kalloc_container(sizeof(ExpansionData));
		if (!reserved) {
			return;
		}
		bzero(reserved, sizeof(ExpansionData));
	}
	reserved->deallocFunction = func;
}

void
OSData::setSerializable(bool serializable)
{
	if (!reserved) {
		reserved = (typeof(reserved))kalloc_container(sizeof(ExpansionData));
		if (!reserved) {
			return;
		}
		bzero(reserved, sizeof(ExpansionData));
	}
	reserved->disableSerialization = (!serializable);
}

bool
OSData::isSerializable(void)
{
	return !reserved || !reserved->disableSerialization;
}
