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
/* OSSerialize.cpp created by rsulack on Wen 25-Nov-1998 */

#include <libkern/c++/OSContainers.h>
#include <libkern/c++/OSLib.h>
#include <libkern/c++/OSDictionary.h>

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

#if OSALLOCDEBUG
extern "C" {
    extern int debug_container_malloc_size;
};
#define ACCUMSIZE(s) do { debug_container_malloc_size += (s); } while(0)
#else
#define ACCUMSIZE(s)
#endif

char * OSSerialize::text() const
{
	return data;
}

void OSSerialize::clearText()
{
	bzero((void *)data, capacity);
	length = 1;
	tag = 0;
	tags->flushCollection();
}

bool OSSerialize::previouslySerialized(const OSMetaClassBase *o)
{
	char temp[16];
	OSString *tagString;

	// look it up
	tagString = (OSString *)tags->getObject((const OSSymbol *) o);

	// does it exist?
	if (tagString) {
		addString("<reference IDREF=\"");
		addString(tagString->getCStringNoCopy());
		addString("\"/>");
		return true;
	}

	// build a tag
	sprintf(temp, "%u", tag++);
	tagString = OSString::withCString(temp);

	// add to tag dictionary
        tags->setObject((const OSSymbol *) o, tagString);// XXX check return
	tagString->release();

	return false;
}

bool OSSerialize::addXMLStartTag(const OSMetaClassBase *o, const char *tagString)
{

	if (!addChar('<')) return false;
	if (!addString(tagString)) return false;
	if (!addString(" ID=\"")) return false;
	if (!addString(((OSString *)tags->getObject((const OSSymbol *)o))->getCStringNoCopy())) 
		return false;
	if (!addChar('\"')) return false;
	if (!addChar('>')) return false;
	return true;
}

bool OSSerialize::addXMLEndTag(const char *tagString)
{

	if (!addChar('<')) return false;
	if (!addChar('/')) return false;
	if (!addString(tagString)) return false;
	if (!addChar('>')) return false;
	return true;
}

bool OSSerialize::addChar(const char c)
{
	// add char, possibly extending our capacity
	if (length >= capacity && length >=ensureCapacity(capacity+capacityIncrement))
		return false;

	data[length - 1] = c;
	length++;
 
	return true;
}

bool OSSerialize::addString(const char *s)
{
	bool rc = false;

	while (*s && (rc = addChar(*s++))) ;

	return rc;
}

bool OSSerialize::initWithCapacity(unsigned int inCapacity)
{
    if (!super::init())
            return false;

    tags = OSDictionary::withCapacity(32);
    if (!tags) {
        return false;
    }

    tag = 0;
    length = 1;
    capacity = inCapacity;
    capacityIncrement = (capacity)? capacity : 256;

    capacity = (((capacity - 1) / capacityIncrement) + 1)
             * capacityIncrement;
    data = (char *) kalloc(capacity);
    if (!data) {
        tags->release();
        tags = 0;
        return false;
    }
    bzero((void *)data, capacity);


    ACCUMSIZE(capacity);

    return true;
}

OSSerialize *OSSerialize::withCapacity(unsigned int inCapacity)
{
	OSSerialize *me = new OSSerialize;

	if (me && !me->initWithCapacity(inCapacity)) {
		me->free();
		return 0;
	}

	return me;
}

unsigned int OSSerialize::getLength() const { return length; }
unsigned int OSSerialize::getCapacity() const { return capacity; }
unsigned int OSSerialize::getCapacityIncrement() const { return capacityIncrement; }
unsigned int OSSerialize::setCapacityIncrement(unsigned int increment)
{
    capacityIncrement = (increment)? increment : 256;
    return capacityIncrement;
}

unsigned int OSSerialize::ensureCapacity(unsigned int newCapacity)
{
	char *newData;
	unsigned int oldCapacity;

	if (newCapacity <= capacity)
		return capacity;

	// round up
	newCapacity = (((newCapacity - 1) / capacityIncrement) + 1)
                * capacityIncrement;
	newData = (char *) kalloc(newCapacity);
	if (newData) {
		oldCapacity = capacity;

		ACCUMSIZE(newCapacity - oldCapacity);

		bcopy(data, newData, oldCapacity);
		bzero(&newData[capacity], newCapacity - oldCapacity);
		kfree((vm_offset_t)data, oldCapacity);
		data = newData;
		capacity = newCapacity;
	}

	return capacity;
}

void OSSerialize::free()
{
    if (tags)
        tags->release();

    if (data) {
        kfree((vm_offset_t)data, capacity);
        ACCUMSIZE( -capacity );
    }
    super::free();
}


OSDefineMetaClassAndStructors(OSSerializer, OSObject)

OSSerializer * OSSerializer::forTarget( void * target,
                               OSSerializerCallback callback, void * ref = 0 )
{
    OSSerializer * thing;

    thing = new OSSerializer;
    if( thing && !thing->init()) {
	thing->release();
	thing = 0;
    }

    if( thing) {
	thing->target	= target;
        thing->ref	= ref;
        thing->callback = callback;
    }
    return( thing );
}

bool OSSerializer::serialize( OSSerialize * s ) const
{
    return( (*callback)(target, ref, s) );
}
