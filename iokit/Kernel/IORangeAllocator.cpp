/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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
/*
 * Copyright (c) 1999 Apple Computer, Inc.
 *
 *
 * HISTORY
 *
 * sdouglas 05 Nov 99 - created.
 */

#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSNumber.h>
#include <IOKit/IORangeAllocator.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOLocks.h>
#include <IOKit/assert.h>

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super OSObject

OSDefineMetaClassAndStructors( IORangeAllocator, OSObject )

struct IORangeAllocatorElement {
	// closed range
	IORangeScalar       start;
	IORangeScalar       end;
};

IOLock *        gIORangeAllocatorLock;

#define LOCK()          \
	if( options & kLocking)	IOTakeLock( gIORangeAllocatorLock )
#define UNLOCK()        \
	if( options & kLocking)	IOUnlock( gIORangeAllocatorLock )

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool
IORangeAllocator::init( IORangeScalar endOfRange,
    IORangeScalar _defaultAlignment,
    UInt32 _capacity,
    IOOptionBits _options )
{
	if (!super::init()) {
		return false;
	}

	if (!_capacity) {
		_capacity = 1;
	}
	if (!_defaultAlignment) {
		_defaultAlignment = 1;
	}
	capacity            = 0;
	capacityIncrement   = _capacity;
	numElements         = 0;
	elements            = 0;
	defaultAlignmentMask = _defaultAlignment - 1;
	options             = _options;

	if ((!gIORangeAllocatorLock) && (options & kLocking)) {
		gIORangeAllocatorLock = IOLockAlloc();
	}

	if (endOfRange) {
		deallocate( 0, endOfRange + 1 );
	}

	return true;
}

IORangeAllocator *
IORangeAllocator::withRange(
	IORangeScalar endOfRange,
	IORangeScalar defaultAlignment,
	UInt32 capacity,
	IOOptionBits options )
{
	IORangeAllocator * thingy;

	thingy = new IORangeAllocator;
	if (thingy && !thingy->init( endOfRange, defaultAlignment,
	    capacity, options )) {
		thingy->release();
		thingy = 0;
	}

	return thingy;
}

void
IORangeAllocator::free()
{
	if (elements) {
		IODelete( elements, IORangeAllocatorElement, capacity );
	}

	super::free();
}

UInt32
IORangeAllocator::getFragmentCount( void )
{
	return numElements;
}

UInt32
IORangeAllocator::getFragmentCapacity( void )
{
	return capacity;
}

void
IORangeAllocator::setFragmentCapacityIncrement( UInt32 count )
{
	capacityIncrement = count;
}


// allocate element at index
bool
IORangeAllocator::allocElement( UInt32 index )
{
	UInt32                      newCapacity;
	IORangeAllocatorElement *   newElements;

	if (((numElements == capacity) && capacityIncrement)
	    || (!elements)) {
		if (os_add_overflow(capacity, capacityIncrement, &newCapacity)) {
			return false;
		}
		newElements = IONew( IORangeAllocatorElement, newCapacity );
		if (!newElements) {
			return false;
		}

		if (elements) {
			bcopy( elements,
			    newElements,
			    index * sizeof(IORangeAllocatorElement));
			bcopy( elements + index,
			    newElements + index + 1,
			    (numElements - index) * sizeof(IORangeAllocatorElement));

			IODelete( elements, IORangeAllocatorElement, capacity );
		}

		elements = newElements;
		capacity = newCapacity;
	} else {
		bcopy( elements + index,
		    elements + index + 1,
		    (numElements - index) * sizeof(IORangeAllocatorElement));
	}
	numElements++;

	return true;
}

// destroy element at index
void
IORangeAllocator::deallocElement( UInt32 index )
{
	numElements--;
	bcopy( elements + index + 1,
	    elements + index,
	    (numElements - index) * sizeof(IORangeAllocatorElement));
}

bool
IORangeAllocator::allocate( IORangeScalar size,
    IORangeScalar * result,
    IORangeScalar alignment )
{
	IORangeScalar       data, dataEnd;
	IORangeScalar       thisStart, thisEnd;
	UInt32              index;
	bool                ok = false;

	if (!size || !result) {
		return false;
	}

	if (0 == alignment) {
		alignment = defaultAlignmentMask;
	} else {
		alignment--;
	}

	size = (size + defaultAlignmentMask) & ~defaultAlignmentMask;

	LOCK();

	for (index = 0; index < numElements; index++) {
		thisStart = elements[index].start;
		thisEnd = elements[index].end;
		data = (thisStart + alignment) & ~alignment;
		dataEnd = (data + size - 1);

		ok = (dataEnd <= thisEnd);
		if (ok) {
			if (data != thisStart) {
				if (dataEnd != thisEnd) {
					if (allocElement( index + 1 )) {
						elements[index++].end = data - 1;
						elements[index].start = dataEnd + 1;
						elements[index].end = thisEnd;
					} else {
						ok = false;
					}
				} else {
					elements[index].end = data - 1;
				}
			} else {
				if (dataEnd != thisEnd) {
					elements[index].start = dataEnd + 1;
				} else {
					deallocElement( index );
				}
			}
			if (ok) {
				*result = data;
			}
			break;
		}
	}

	UNLOCK();

	return ok;
}

bool
IORangeAllocator::allocateRange( IORangeScalar data,
    IORangeScalar size )
{
	IORangeScalar       thisStart, thisEnd;
	IORangeScalar       dataEnd;
	UInt32              index;
	bool                found = false;

	if (!size) {
		return 0;
	}

	size = (size + defaultAlignmentMask) & ~defaultAlignmentMask;
	dataEnd = data + size - 1;

	LOCK();

	for (index = 0;
	    (!found) && (index < numElements);
	    index++) {
		thisStart = elements[index].start;
		thisEnd = elements[index].end;

		if (thisStart > data) {
			break;
		}
		found = (dataEnd <= thisEnd);

		if (found) {
			if (data != thisStart) {
				if (dataEnd != thisEnd) {
					found = allocElement( index + 1 );
					if (found) {
						elements[index++].end = data - 1;
						elements[index].start = dataEnd + 1;
						elements[index].end = thisEnd;
					}
				} else {
					elements[index].end = data - 1;
				}
			} else if (dataEnd != thisEnd) {
				elements[index].start = dataEnd + 1;
			} else {
				deallocElement( index );
			}
		}
	}

	UNLOCK();

	return found;
}

void
IORangeAllocator::deallocate( IORangeScalar data,
    IORangeScalar size )
{
	IORangeScalar       dataEnd;
	UInt32              index;
	bool                headContig = false;
	bool                tailContig = false;

	size = (size + defaultAlignmentMask) & ~defaultAlignmentMask;
	dataEnd = data + size - 1;

	LOCK();

	for (index = 0; index < numElements; index++) {
		if (elements[index].start < data) {
			headContig = (data <= (elements[index].end + 1));
			continue;
		}
		tailContig = ((data + size) >= elements[index].start);
		break;
	}

	if (headContig) {
		if (tailContig) {
			elements[index - 1].end = elements[index].end;
			deallocElement( index );
		} else /*safe*/ if (dataEnd > elements[index - 1].end) {
			elements[index - 1].end = dataEnd;
		}
	} else if (tailContig) {
		if (data < elements[index].start) { /*safe*/
			elements[index].start = data;
		}
	} else if (allocElement( index)) {
		elements[index].start = data;
		elements[index].end = dataEnd;
	}

	UNLOCK();
}

bool
IORangeAllocator::serialize(OSSerialize *s) const
{
	OSArray *   array = OSArray::withCapacity( numElements * 2 );
	OSNumber *  num;
	UInt32      index;
	bool        ret;

	if (!array) {
		return false;
	}

	LOCK();

	for (index = 0; index < numElements; index++) {
		if ((num = OSNumber::withNumber( elements[index].start,
		    8 * sizeof(IORangeScalar)))) {
			array->setObject(num);
			num->release();
		}
		if ((num = OSNumber::withNumber( elements[index].end,
		    8 * sizeof(IORangeScalar)))) {
			array->setObject(num);
			num->release();
		}
	}

	UNLOCK();

	ret = array->serialize(s);
	array->release();

	return ret;
}

IORangeScalar
IORangeAllocator::getFreeCount( void )
{
	UInt32              index;
	IORangeScalar       sum = 0;

	for (index = 0; index < numElements; index++) {
		sum += elements[index].end - elements[index].start + 1;
	}

	return sum;
}
