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
/* OSBoolean.cpp created by rsulack on Tue Oct 12 1999 */

#include <libkern/c++/OSBoolean.h>
#include <libkern/c++/OSString.h>
#include <libkern/c++/OSSerialize.h>
#include <libkern/c++/OSLib.h>

#define super OSObject

OSDefineMetaClassAndStructors(OSBoolean, OSObject)
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

void OSBoolean::taggedRetain(const void *tag) const { }
void OSBoolean::taggedRelease(const void *tag, const int when) const { }

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
    return s->addString(value ? "<true/>" : "<false/>");
}
