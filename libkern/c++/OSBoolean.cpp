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
/* OSBoolean.cpp created by rsulack on Tue Oct 12 1999 */

#include <libkern/c++/OSBoolean.h>
#include <libkern/c++/OSString.h>
#include <libkern/c++/OSSerialize.h>
#include <libkern/c++/OSLib.h>

#define super OSObject

OSDefineMetaClassAndStructorsWithInit(OSBoolean, OSObject, OSBoolean::initialize())
OSMetaClassDefineReservedUnused(OSBoolean, 0);
OSMetaClassDefineReservedUnused(OSBoolean, 1);
OSMetaClassDefineReservedUnused(OSBoolean, 2);
OSMetaClassDefineReservedUnused(OSBoolean, 3);
OSMetaClassDefineReservedUnused(OSBoolean, 4);
OSMetaClassDefineReservedUnused(OSBoolean, 5);
OSMetaClassDefineReservedUnused(OSBoolean, 6);
OSMetaClassDefineReservedUnused(OSBoolean, 7);

static OSBoolean * gOSBooleanTrue  = 0;
static OSBoolean * gOSBooleanFalse = 0;

OSBoolean * const & kOSBooleanTrue  = gOSBooleanTrue;
OSBoolean * const & kOSBooleanFalse = gOSBooleanFalse;

void OSBoolean::initialize()
{
    gOSBooleanTrue = new OSBoolean;
    assert(gOSBooleanTrue);

    if (!gOSBooleanTrue->init()) {
        gOSBooleanTrue->OSObject::free();
        assert(false);
    };
    gOSBooleanTrue->value = true;

    gOSBooleanFalse = new OSBoolean;
    assert(gOSBooleanFalse);

    if (!gOSBooleanFalse->init()) {
        gOSBooleanFalse->OSObject::free();
        assert(false);
    };
    gOSBooleanFalse->value = false;
}

void OSBoolean::free()
{
    /*
     * An OSBoolean should never have free() called on it, since it is a shared
     * object, with two non-mutable instances: kOSBooleanTrue, kOSBooleanFalse.
     * There will be cases where an incorrect number of releases will cause the
     * free() method to be called, however, which we must catch and ignore here.
     */
    assert(false);
}

void OSBoolean::taggedRetain(__unused const void *tag) const { }
void OSBoolean::taggedRelease(__unused const void *tag, __unused const int when) const { }

OSBoolean *OSBoolean::withBoolean(bool inValue)
{
    return (inValue) ? kOSBooleanTrue : kOSBooleanFalse;
}

bool OSBoolean::isTrue() const { return value; }
bool OSBoolean::isFalse() const { return !value; }
bool OSBoolean::getValue() const { return value; }

bool OSBoolean::isEqualTo(const OSBoolean *boolean) const
{
    return (boolean == this);
}

bool OSBoolean::isEqualTo(const OSMetaClassBase *obj) const
{
    OSBoolean *	boolean;
    if ((boolean = OSDynamicCast(OSBoolean, obj)))
	return isEqualTo(boolean);
    else
	return false;
}

bool OSBoolean::serialize(OSSerialize *s) const
{
    if (s->binary) return s->binarySerialize(this);

    return s->addString(value ? "<true/>" : "<false/>");
}
