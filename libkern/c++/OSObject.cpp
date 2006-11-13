/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/* OSObject.cpp created by gvdl on Fri 1998-11-17 */

#include <libkern/c++/OSObject.h>
#include <libkern/c++/OSSerialize.h>
#include <libkern/c++/OSLib.h>
#include <libkern/c++/OSCPPDebug.h>
#include <libkern/OSAtomic.h>

#include <libkern/c++/OSCollection.h>

__BEGIN_DECLS
int debug_ivars_size;
__END_DECLS

#if OSALLOCDEBUG
#define ACCUMSIZE(s) do { debug_ivars_size += (s); } while(0)
#else
#define ACCUMSIZE(s)
#endif

// OSDefineMetaClassAndAbstractStructors(OSObject, 0);
/* Class global data */
OSObject::MetaClass OSObject::gMetaClass;
const OSMetaClass * const OSObject::metaClass = &OSObject::gMetaClass;
const OSMetaClass * const OSObject::superClass = 0;

/* Class member functions - Can't use defaults */
OSObject::OSObject()			{ retainCount = 1; }
OSObject::OSObject(const OSMetaClass *)	{ retainCount = 1; }
OSObject::~OSObject()			{ }
const OSMetaClass * OSObject::getMetaClass() const
    { return &gMetaClass; }
OSObject *OSObject::MetaClass::alloc() const { return 0; }

/* The OSObject::MetaClass constructor */
OSObject::MetaClass::MetaClass()
    : OSMetaClass("OSObject", OSObject::superClass, sizeof(OSObject))
    { }

// Virtual Padding
OSMetaClassDefineReservedUnused(OSObject,  0);
OSMetaClassDefineReservedUnused(OSObject,  1);
OSMetaClassDefineReservedUnused(OSObject,  2);
OSMetaClassDefineReservedUnused(OSObject,  3);
OSMetaClassDefineReservedUnused(OSObject,  4);
OSMetaClassDefineReservedUnused(OSObject,  5);
OSMetaClassDefineReservedUnused(OSObject,  6);
OSMetaClassDefineReservedUnused(OSObject,  7);
OSMetaClassDefineReservedUnused(OSObject,  8);
OSMetaClassDefineReservedUnused(OSObject,  9);
OSMetaClassDefineReservedUnused(OSObject, 10);
OSMetaClassDefineReservedUnused(OSObject, 11);
OSMetaClassDefineReservedUnused(OSObject, 12);
OSMetaClassDefineReservedUnused(OSObject, 13);
OSMetaClassDefineReservedUnused(OSObject, 14);
OSMetaClassDefineReservedUnused(OSObject, 15);
OSMetaClassDefineReservedUnused(OSObject, 16);
OSMetaClassDefineReservedUnused(OSObject, 17);
OSMetaClassDefineReservedUnused(OSObject, 18);
OSMetaClassDefineReservedUnused(OSObject, 19);
OSMetaClassDefineReservedUnused(OSObject, 20);
OSMetaClassDefineReservedUnused(OSObject, 21);
OSMetaClassDefineReservedUnused(OSObject, 22);
OSMetaClassDefineReservedUnused(OSObject, 23);
OSMetaClassDefineReservedUnused(OSObject, 24);
OSMetaClassDefineReservedUnused(OSObject, 25);
OSMetaClassDefineReservedUnused(OSObject, 26);
OSMetaClassDefineReservedUnused(OSObject, 27);
OSMetaClassDefineReservedUnused(OSObject, 28);
OSMetaClassDefineReservedUnused(OSObject, 29);
OSMetaClassDefineReservedUnused(OSObject, 30);
OSMetaClassDefineReservedUnused(OSObject, 31);

static const char *getClassName(const OSObject *obj)
{
    const OSMetaClass *meta = obj->getMetaClass();
    return (meta) ? meta->getClassName() : "unknown class?";
}

bool OSObject::init()
    { return true; }

#if (!__ppc__) || (__GNUC__ < 3)

// Implemented in assembler in post gcc 3.x systems as we have a problem
// where the destructor in gcc2.95 gets 2 arguments.  The second argument
// appears to be a flag argument.  I have copied the assembler from Puma xnu
// to OSRuntimeSupport.c  So for 2.95 builds use the C 
void OSObject::free()
{
    const OSMetaClass *meta = getMetaClass();

    if (meta)
	meta->instanceDestructed();
    delete this;
}
#endif /* (!__ppc__) || (__GNUC__ < 3) */

int OSObject::getRetainCount() const
{
    return (int) ((UInt16) retainCount);
}

void OSObject::taggedRetain(const void *tag) const
{
    volatile UInt32 *countP = (volatile UInt32 *) &retainCount;
    UInt32 inc = 1;
    UInt32 origCount;
    UInt32 newCount;

    // Increment the collection bucket.
    if ((const void *) OSTypeID(OSCollection) == tag)
	inc |= (1UL<<16);

    do {
	origCount = *countP;
        if ( ((UInt16) origCount | 0x1) == 0xffff ) {
            const char *msg;
            if (origCount & 0x1) {
                // If count == 0xffff that means we are freeing now so we can
                // just return obviously somebody is cleaning up dangling
                // references.
                msg = "Attempting to retain a freed object";
            }
            else {
                // If count == 0xfffe then we have wrapped our reference count.
                // We should stop counting now as this reference must be
                // leaked rather than accidently wrapping around the clock and
                // freeing a very active object later.

#if !DEBUG
		break;	// Break out of update loop which pegs the reference
#else DEBUG
                // @@@ gvdl: eventually need to make this panic optional
                // based on a boot argument i.e. debug= boot flag
                msg = "About to wrap the reference count, reference leak?";
#endif /* !DEBUG */
            }
            panic("OSObject::refcount: %s", msg);
        }

	newCount = origCount + inc;
    } while (!OSCompareAndSwap(origCount, newCount, (UInt32 *) countP));
}

void OSObject::taggedRelease(const void *tag) const
{
    taggedRelease(tag, 1);
}

void OSObject::taggedRelease(const void *tag, const int when) const
{
    volatile UInt32 *countP = (volatile UInt32 *) &retainCount;
    UInt32 dec = 1;
    UInt32 origCount;
    UInt32 newCount;
    UInt32 actualCount;

    // Increment the collection bucket.
    if ((const void *) OSTypeID(OSCollection) == tag)
	dec |= (1UL<<16);

    do {
	origCount = *countP;
        
        if ( ((UInt16) origCount | 0x1) == 0xffff ) {
            if (origCount & 0x1) {
                // If count == 0xffff that means we are freeing now so we can
                // just return obviously somebody is cleaning up some dangling
                // references.  So we blow out immediately.
                return;
            }
            else {
                // If count == 0xfffe then we have wrapped our reference
                // count.  We should stop counting now as this reference must be
                // leaked rather than accidently freeing an active object later.

#if !DEBUG
		return;	// return out of function which pegs the reference
#else DEBUG
                // @@@ gvdl: eventually need to make this panic optional
                // based on a boot argument i.e. debug= boot flag
                panic("OSObject::refcount: %s",
                      "About to unreference a pegged object, reference leak?");
#endif /* !DEBUG */
            }
        }
	actualCount = origCount - dec;
        if ((UInt16) actualCount < when)
            newCount = 0xffff;
        else
            newCount = actualCount;

    } while (!OSCompareAndSwap(origCount, newCount, (UInt32 *) countP));

    //
    // This panic means that we have just attempted to release an object
    // who's retain count has gone to less than the number of collections
    // it is a member off.  Take a panic immediately.
    // In Fact the panic MAY not be a registry corruption but it is 
    // ALWAYS the wrong thing to do.  I call it a registry corruption 'cause
    // the registry is the biggest single use of a network of collections.
    //
    if ((UInt16) actualCount < (actualCount >> 16))
	panic("A driver releasing a(n) %s has corrupted the registry\n",
	    getClassName(this));

    // Check for a 'free' condition and that if we are first through
    if (newCount == 0xffff)
	((OSObject *) this)->free();
}

void OSObject::release() const
{
    taggedRelease(0);
}

void OSObject::retain() const
{
    taggedRetain(0);
}

void OSObject::release(int when) const
{
    taggedRelease(0, when);
}

bool OSObject::serialize(OSSerialize *s) const
{
    if (s->previouslySerialized(this)) return true;

    if (!s->addXMLStartTag(this, "string")) return false;

    if (!s->addString(getClassName(this))) return false;
    if (!s->addString(" is not serializable")) return false;
    
    return s->addXMLEndTag("string");
}

void *OSObject::operator new(size_t size)
{
    void *mem = (void *) kalloc(size);
    assert(mem);
    bzero(mem, size);

    ACCUMSIZE(size);

    return mem;
}

void OSObject::operator delete(void *mem, size_t size)
{
    kfree((vm_offset_t) mem, size);

    ACCUMSIZE(-size);
}
