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
/* IOOffset.m created by rsulack on Wed 17-Sep-1997 */

#include <sys/cdefs.h>

__BEGIN_DECLS
extern unsigned long strtoul(const char *, char **, int);
__END_DECLS

#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSString.h>
#include <libkern/c++/OSSerialize.h>
#include <libkern/c++/OSLib.h>

#define sizeMask (~0ULL >> (64 - size))

#define super OSObject

OSDefineMetaClassAndStructors(OSNumber, OSObject)

OSMetaClassDefineReservedUnused(OSNumber, 0);
OSMetaClassDefineReservedUnused(OSNumber, 1);
OSMetaClassDefineReservedUnused(OSNumber, 2);
OSMetaClassDefineReservedUnused(OSNumber, 3);
OSMetaClassDefineReservedUnused(OSNumber, 4);
OSMetaClassDefineReservedUnused(OSNumber, 5);
OSMetaClassDefineReservedUnused(OSNumber, 6);
OSMetaClassDefineReservedUnused(OSNumber, 7);

bool OSNumber::init(unsigned long long inValue, unsigned int numberOfBits)
{
    if (!super::init())
        return false;

    size = numberOfBits;
    value = (inValue & sizeMask);

    return true;
}

bool OSNumber::init(const char *value, unsigned int numberOfBits)
{
    return init((unsigned long long)strtoul(value, NULL, 0), numberOfBits);
}

void OSNumber::free() { super::free(); }

OSNumber *OSNumber::withNumber(unsigned long long value,
                           unsigned int numberOfBits)
{
    OSNumber *me = new OSNumber;

    if (me && !me->init(value, numberOfBits)) {
        me->release();
        return 0;
    }

    return me;
}

OSNumber *OSNumber::withNumber(const char *value, unsigned int numberOfBits)
{
    OSNumber *me = new OSNumber;

    if (me && !me->init(value, numberOfBits)) {
        me->release();
        return 0;
    }

    return me;
}

unsigned int OSNumber::numberOfBits() const { return size; }

unsigned int OSNumber::numberOfBytes() const { return (size + 7) / 8; }


unsigned char OSNumber::unsigned8BitValue() const
{
    return (unsigned char) value;
}

unsigned short OSNumber::unsigned16BitValue() const
{
    return (unsigned short) value;
}

unsigned int OSNumber::unsigned32BitValue() const
{
    return (unsigned int) value;
}

unsigned long long OSNumber::unsigned64BitValue() const
{
    return value;
}

void OSNumber::addValue(signed long long inValue)
{
    value = ((value + inValue) & sizeMask);
}

void OSNumber::setValue(unsigned long long inValue)
{
    value = (inValue & sizeMask);
}

bool OSNumber::isEqualTo(const OSNumber *integer) const
{
    return((value == integer->value));
}

bool OSNumber::isEqualTo(const OSMetaClassBase *obj) const
{
    OSNumber *	offset;
    if ((offset = OSDynamicCast(OSNumber, obj)))
	return isEqualTo(offset);
    else
	return false;
}

bool OSNumber::serialize(OSSerialize *s) const
{
    char temp[32];
    
    if (s->previouslySerialized(this)) return true;

    snprintf(temp, sizeof(temp), "integer size=\"%d\"", size); 
    if (!s->addXMLStartTag(this, temp)) return false;
    
    //XXX    sprintf(temp, "0x%qx", value);
    if ((value >> 32)) {
        snprintf(temp, sizeof(temp), "0x%lx%08lx", (unsigned long)(value >> 32),
                    (unsigned long)(value & 0xFFFFFFFF));
    } else { 
        snprintf(temp, sizeof(temp), "0x%lx", (unsigned long)value);
    }
    if (!s->addString(temp)) return false;

    return s->addXMLEndTag("integer");
}
