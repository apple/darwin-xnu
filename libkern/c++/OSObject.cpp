/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/* OSObject.cpp created by gvdl on Fri 1998-11-17 */

#include <libkern/c++/OSObject.h>
#include <libkern/c++/OSSerialize.h>
#include <libkern/c++/OSSymbol.h>
#include <libkern/c++/OSLib.h>
#include <libkern/c++/OSCPPDebug.h>
#include <libkern/OSAtomic.h>

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


bool OSObject::init()			{ return true; }
void OSObject::free()
{
    const OSMetaClass *meta = getMetaClass();

    if (meta)
	meta->instanceDestructed();
    delete this;
}

int OSObject::getRetainCount() const
{
    return retainCount;
}

void OSObject::retain() const
{
    OSIncrementAtomic((SInt32 *) &retainCount);
}

void OSObject::release(int when) const
{
    if (OSDecrementAtomic((SInt32 *) &retainCount) <= when)
	((OSObject *) this)->free();
}

void OSObject::release() const
{
    release(1);
}

bool OSObject::serialize(OSSerialize *s) const
{
    if (s->previouslySerialized(this)) return true;

    if (!s->addXMLStartTag(this, "string")) return false;

    const OSMetaClass *meta = getMetaClass();
    const char *className = (meta)? meta->getClassName() : "unknown class?";

    if (!s->addString(className)) return false;
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
