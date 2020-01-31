/*
 * Copyright (c) 2000 Apple Inc. All rights reserved.
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
/* OSObject.cpp created by gvdl on Fri 1998-11-17 */

#include <libkern/c++/OSObject.h>
#include <libkern/c++/OSString.h>
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSSerialize.h>
#include <libkern/c++/OSLib.h>
#include <libkern/OSDebug.h>
#include <libkern/c++/OSCPPDebug.h>
#include <IOKit/IOKitDebug.h>
#include <libkern/OSAtomic.h>

#include <libkern/c++/OSCollection.h>

#include <kern/queue.h>

__BEGIN_DECLS
int debug_ivars_size;
__END_DECLS


// OSDefineMetaClassAndAbstractStructors(OSObject, 0);
/* Class global data */
OSObject::MetaClass OSObject::gMetaClass;
const OSMetaClass * const OSObject::metaClass = &OSObject::gMetaClass;
const OSMetaClass * const OSObject::superClass = 0;

/* Class member functions - Can't use defaults */
OSObject::~OSObject()
{
}
const OSMetaClass *
OSObject::getMetaClass() const
{
	return &gMetaClass;
}
OSObject *
OSObject::MetaClass::alloc() const
{
	return 0;
}

/* The OSObject::MetaClass constructor */
OSObject::MetaClass::MetaClass()
	: OSMetaClass("OSObject", OSObject::superClass, sizeof(OSObject))
{
}

// Virtual Padding
OSMetaClassDefineReservedUnused(OSObject, 0);
OSMetaClassDefineReservedUnused(OSObject, 1);
OSMetaClassDefineReservedUnused(OSObject, 2);
OSMetaClassDefineReservedUnused(OSObject, 3);
OSMetaClassDefineReservedUnused(OSObject, 4);
OSMetaClassDefineReservedUnused(OSObject, 5);
OSMetaClassDefineReservedUnused(OSObject, 6);
OSMetaClassDefineReservedUnused(OSObject, 7);
OSMetaClassDefineReservedUnused(OSObject, 8);
OSMetaClassDefineReservedUnused(OSObject, 9);
OSMetaClassDefineReservedUnused(OSObject, 10);
OSMetaClassDefineReservedUnused(OSObject, 11);
OSMetaClassDefineReservedUnused(OSObject, 12);
OSMetaClassDefineReservedUnused(OSObject, 13);
OSMetaClassDefineReservedUnused(OSObject, 14);
OSMetaClassDefineReservedUnused(OSObject, 15);

static const char *
getClassName(const OSObject *obj)
{
	const OSMetaClass *meta = obj->getMetaClass();
	return (meta) ? meta->getClassName() : "unknown class?";
}

int
OSObject::getRetainCount() const
{
	return (int) ((UInt16) retainCount);
}

bool
OSObject::taggedTryRetain(const void *tag) const
{
	volatile UInt32 *countP = (volatile UInt32 *) &retainCount;
	UInt32 inc = 1;
	UInt32 origCount;
	UInt32 newCount;

	// Increment the collection bucket.
	if ((const void *) OSTypeID(OSCollection) == tag) {
		inc |= (1UL << 16);
	}

	do {
		origCount = *countP;
		if (((UInt16) origCount | 0x1) == 0xffff) {
			if (origCount & 0x1) {
				// If count == 0xffff that means we are freeing now so we can
				// just return obviously somebody is cleaning up dangling
				// references.
				return false;
			} else {
				// If count == 0xfffe then we have wrapped our reference count.
				// We should stop counting now as this reference must be
				// leaked rather than accidently wrapping around the clock and
				// freeing a very active object later.

#if !DEBUG
				break; // Break out of update loop which pegs the reference
#else /* DEBUG */
				// @@@ gvdl: eventually need to make this panic optional
				// based on a boot argument i.e. debug= boot flag
				panic("OSObject::refcount: "
				    "About to wrap the reference count, reference leak?");
#endif /* !DEBUG */
			}
		}

		newCount = origCount + inc;
	} while (!OSCompareAndSwap(origCount, newCount, const_cast<UInt32 *>(countP)));

	return true;
}

void
OSObject::taggedRetain(const void *tag) const
{
	if (!taggedTryRetain(tag)) {
		panic("OSObject::refcount: Attempting to retain a freed object");
	}
}

void
OSObject::taggedRelease(const void *tag) const
{
	taggedRelease(tag, 1);
}

void
OSObject::taggedRelease(const void *tag, const int when) const
{
	volatile UInt32 *countP = (volatile UInt32 *) &retainCount;
	UInt32 dec = 1;
	UInt32 origCount;
	UInt32 newCount;
	UInt32 actualCount;

	// Increment the collection bucket.
	if ((const void *) OSTypeID(OSCollection) == tag) {
		dec |= (1UL << 16);
	}

	do {
		origCount = *countP;

		if (((UInt16) origCount | 0x1) == 0xffff) {
			if (origCount & 0x1) {
				// If count == 0xffff that means we are freeing now so we can
				// just return obviously somebody is cleaning up some dangling
				// references.  So we blow out immediately.
				return;
			} else {
				// If count == 0xfffe then we have wrapped our reference
				// count.  We should stop counting now as this reference must be
				// leaked rather than accidently freeing an active object later.

#if !DEBUG
				return; // return out of function which pegs the reference
#else /* DEBUG */
				// @@@ gvdl: eventually need to make this panic optional
				// based on a boot argument i.e. debug= boot flag
				panic("OSObject::refcount: %s",
				    "About to unreference a pegged object, reference leak?");
#endif /* !DEBUG */
			}
		}
		actualCount = origCount - dec;
		if ((UInt16) actualCount < when) {
			newCount = 0xffff;
		} else {
			newCount = actualCount;
		}
	} while (!OSCompareAndSwap(origCount, newCount, const_cast<UInt32 *>(countP)));

	//
	// This panic means that we have just attempted to release an object
	// whose retain count has gone to less than the number of collections
	// it is a member off.  Take a panic immediately.
	// In fact the panic MAY not be a registry corruption but it is
	// ALWAYS the wrong thing to do.  I call it a registry corruption 'cause
	// the registry is the biggest single use of a network of collections.
	//
// xxx - this error message is overly-specific;
// xxx - any code in the kernel could trip this,
// xxx - and it applies as noted to all collections, not just the registry
	if ((UInt16) actualCount < (actualCount >> 16)) {
		panic("A kext releasing a(n) %s has corrupted the registry.",
		    getClassName(this));
	}

	// Check for a 'free' condition and that if we are first through
	if (newCount == 0xffff) {
		(const_cast<OSObject *>(this))->free();
	}
}

void
OSObject::release() const
{
	taggedRelease(0);
}

void
OSObject::retain() const
{
	taggedRetain(0);
}

extern "C" void
osobject_retain(void * object)
{
	((OSObject *)object)->retain();
}

extern "C" void
osobject_release(void * object)
{
	((OSObject *)object)->release();
}

void
OSObject::release(int when) const
{
	taggedRelease(0, when);
}

bool
OSObject::serialize(OSSerialize *s) const
{
	char cstr[128];
	bool ok;

	snprintf(cstr, sizeof(cstr), "%s is not serializable", getClassName(this));

	OSString * str;
	str = OSString::withCStringNoCopy(cstr);
	if (!str) {
		return false;
	}

	ok = str->serialize(s);
	str->release();

	return ok;
}

void *
OSObject::operator new(size_t size)
{
#if IOTRACKING
	if (kIOTracking & gIOKitDebug) {
		return OSMetaClass::trackedNew(size);
	}
#endif

	void * mem = kalloc_tag_bt(size, VM_KERN_MEMORY_LIBKERN);
	assert(mem);
	bzero(mem, size);
	OSIVAR_ACCUMSIZE(size);

	return (void *) mem;
}

void
OSObject::operator delete(void * mem, size_t size)
{
	if (!mem) {
		return;
	}

#if IOTRACKING
	if (kIOTracking & gIOKitDebug) {
		return OSMetaClass::trackedDelete(mem, size);
	}
#endif

	kfree(mem, size);
	OSIVAR_ACCUMSIZE(-size);
}

bool
OSObject::init()
{
#if IOTRACKING
	if (kIOTracking & gIOKitDebug) {
		getMetaClass()->trackedInstance(this);
	}
#endif
	return true;
}

void
OSObject::free()
{
	const OSMetaClass *meta = getMetaClass();

	if (meta) {
		meta->instanceDestructed();
#if IOTRACKING
		if (kIOTracking & gIOKitDebug) {
			getMetaClass()->trackedFree(this);
		}
#endif
	}
	delete this;
}

#if IOTRACKING
void
OSObject::trackingAccumSize(size_t size)
{
	if (kIOTracking & gIOKitDebug) {
		getMetaClass()->trackedAccumSize(this, size);
	}
}
#endif

/* Class member functions - Can't use defaults */
/* During constructor vtable is always OSObject's - can't call any subclass */

OSObject::OSObject()
{
	retainCount = 1;
//    if (kIOTracking & gIOKitDebug) getMetaClass()->trackedInstance(this);
}

OSObject::OSObject(const OSMetaClass *)
{
	retainCount = 1;
//    if (kIOTracking & gIOKitDebug) getMetaClass()->trackedInstance(this);
}
