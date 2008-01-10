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
/* IOData.m created by rsulack on Thu 25-Sep-1997 */

#include <string.h>

#include <libkern/c++/OSData.h>
#include <libkern/c++/OSSerialize.h>
#include <libkern/c++/OSLib.h>
#include <libkern/c++/OSString.h>
#include <string.h>

#define super OSObject

OSDefineMetaClassAndStructors(OSData, OSObject)
OSMetaClassDefineReservedUnused(OSData, 0);
OSMetaClassDefineReservedUnused(OSData, 1);
OSMetaClassDefineReservedUnused(OSData, 2);
OSMetaClassDefineReservedUnused(OSData, 3);
OSMetaClassDefineReservedUnused(OSData, 4);
OSMetaClassDefineReservedUnused(OSData, 5);
OSMetaClassDefineReservedUnused(OSData, 6);
OSMetaClassDefineReservedUnused(OSData, 7);

#define EXTERNAL ((unsigned int) -1)

#if OSALLOCDEBUG
extern int debug_container_malloc_size;
#define ACCUMSIZE(s) do { debug_container_malloc_size += (s); } while(0)
#else
#define ACCUMSIZE(s)
#endif

bool OSData::initWithCapacity(unsigned int inCapacity)
{
    if (!super::init())
        return false;

    if (data && (!inCapacity || capacity < inCapacity) ) {
        // clean out old data's storage if it isn't big enough
        kfree(data, capacity);
        data = 0;
        ACCUMSIZE(-capacity);
    }

    if (inCapacity && !data) {
        data = (void *) kalloc(inCapacity);
        if (!data)
            return false;
        capacity = inCapacity;
        ACCUMSIZE(inCapacity);
    }

    length = 0;
    if (inCapacity < 16)
        capacityIncrement = 16;
    else
        capacityIncrement = inCapacity;

    return true;
}

bool OSData::initWithBytes(const void *bytes, unsigned int inLength)
{
    if ((inLength && !bytes) || !initWithCapacity(inLength))
        return false;

    if (bytes != data)
	bcopy(bytes, data, inLength);
    length = inLength;

    return true;
}

bool OSData::initWithBytesNoCopy(void *bytes, unsigned int inLength)
{
    if (!super::init())
        return false;

    length = inLength;
    capacity = EXTERNAL;
    data = bytes;

    return true;
}

bool OSData::initWithData(const OSData *inData)
{
    return initWithBytes(inData->data, inData->length);
}

bool OSData::initWithData(const OSData *inData,
                          unsigned int start, unsigned int inLength)
{
    const void *localData = inData->getBytesNoCopy(start, inLength);

    if (localData)
        return initWithBytes(localData, inLength);
    else
        return false;
}

OSData *OSData::withCapacity(unsigned int inCapacity)
{
    OSData *me = new OSData;

    if (me && !me->initWithCapacity(inCapacity)) {
        me->release();
        return 0;
    }

    return me;
}

OSData *OSData::withBytes(const void *bytes, unsigned int inLength)
{
    OSData *me = new OSData;

    if (me && !me->initWithBytes(bytes, inLength)) {
        me->release();
        return 0;
    }
    return me;
}

OSData *OSData::withBytesNoCopy(void *bytes, unsigned int inLength)
{
    OSData *me = new OSData;

    if (me && !me->initWithBytesNoCopy(bytes, inLength)) {
        me->release();
        return 0;
    }

    return me;
}

OSData *OSData::withData(const OSData *inData)
{
    OSData *me = new OSData;

    if (me && !me->initWithData(inData)) {
        me->release();
        return 0;
    }

    return me;
}

OSData *OSData::withData(const OSData *inData,
                         unsigned int start, unsigned int inLength)
{
    OSData *me = new OSData;

    if (me && !me->initWithData(inData, start, inLength)) {
        me->release();
        return 0;
    }

    return me;
}

void OSData::free()
{
    if (capacity != EXTERNAL && data && capacity) {
        kfree(data, capacity);
        ACCUMSIZE( -capacity );
    }
    super::free();
}

unsigned int OSData::getLength() const { return length; }
unsigned int OSData::getCapacity() const { return capacity; }

unsigned int OSData::getCapacityIncrement() const 
{ 
    return capacityIncrement; 
}

unsigned int OSData::setCapacityIncrement(unsigned increment) 
{
    return capacityIncrement = increment; 
}

unsigned int OSData::ensureCapacity(unsigned int newCapacity)
{
    unsigned char * newData;

    if (newCapacity <= capacity)
        return capacity;

    newCapacity = (((newCapacity - 1) / capacityIncrement) + 1)
                * capacityIncrement;

    newData = (unsigned char *) kalloc(newCapacity);
    
    if ( newData ) {
        bzero(newData + capacity, newCapacity - capacity);
        if (data) {
            bcopy(data, newData, capacity);
            kfree(data, capacity);
        }
        ACCUMSIZE( newCapacity - capacity );
        data = (void *) newData;
        capacity = newCapacity;
    }

    return capacity;
}

bool OSData::appendBytes(const void *bytes, unsigned int inLength)
{
    unsigned int newSize;

    if (!inLength)
        return true;

    if (capacity == EXTERNAL)
        return false;
    
    newSize = length + inLength;
    if ( (newSize > capacity) && newSize > ensureCapacity(newSize) )
        return false;

    if (bytes)
        bcopy(bytes, &((unsigned char *)data)[length], inLength);
    else
        bzero(&((unsigned char *)data)[length], inLength);

    length = newSize;

    return true;
}

bool OSData::appendByte(unsigned char byte, unsigned int inLength)
{
    unsigned int newSize;

    if (!inLength)
        return true;

    if (capacity == EXTERNAL)
        return false;
    
    newSize = length + inLength;
    if ( (newSize > capacity) && newSize > ensureCapacity(newSize) )
        return false;

    memset(&((unsigned char *)data)[length], byte, inLength);
    length = newSize;

    return true;
}

bool OSData::appendBytes(const OSData *other)
{
    return appendBytes(other->data, other->length);
}

const void *OSData::getBytesNoCopy() const
{
    if (!length)
        return 0;
    else
        return data;
}

const void *OSData::getBytesNoCopy(unsigned int start,
                                   unsigned int inLength) const
{
    const void *outData = 0;

    if (length
    &&  start < length
    && (start + inLength) <= length)
        outData = (const void *) ((char *) data + start);

    return outData;
}

bool OSData::isEqualTo(const OSData *aData) const
{
    unsigned int len;

    len = aData->length;
    if ( length != len )
        return false;

    return isEqualTo(aData->data, len);
}

bool OSData::isEqualTo(const void *someData, unsigned int inLength) const
{
    return (length >= inLength) && (bcmp(data, someData, inLength) == 0);
}

bool OSData::isEqualTo(const OSMetaClassBase *obj) const
{
    OSData *	data;
    OSString *  str;

    if ((data = OSDynamicCast(OSData, obj)))
        return isEqualTo(data);
    else if ((str = OSDynamicCast (OSString, obj)))
        return isEqualTo(str);
    else
        return false;
}

bool OSData::isEqualTo(const OSString *obj) const
{
    const char * aCString;
    char * dataPtr;
    unsigned int checkLen = length;
    unsigned int stringLen;

    if (!obj)
      return false;

    stringLen = obj->getLength ();

    dataPtr = (char *)data;

    if (stringLen != checkLen) {

      // check for the fact that OSData may be a buffer that
      // that includes a termination byte and will thus have
      // a length of the actual string length PLUS 1. In this
      // case we verify that the additional byte is a terminator
      // and if so count the two lengths as being the same.

      if ( (checkLen - stringLen) == 1) {
	if (dataPtr[checkLen-1] != 0) // non-zero means not a terminator and thus not likely the same
	  return false;
        checkLen--;
      }
      else
	return false;
    }

    aCString = obj->getCStringNoCopy ();

    for ( unsigned int i=0; i < checkLen; i++ ) {
      if ( *dataPtr++ != aCString[i] ) 
        return false;
    }

   return true;
}

//this was taken from CFPropertyList.c 
static const char __CFPLDataEncodeTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

bool OSData::serialize(OSSerialize *s) const
{
    unsigned int i;
    const unsigned char *p;
    unsigned char c;

    if (s->previouslySerialized(this)) return true;

    if (!s->addXMLStartTag(this, "data")) return false;

    for (i = 0, p = (unsigned char *)data; i < length; i++, p++) {
        /* 3 bytes are encoded as 4 */
        switch (i % 3) {
	case 0:
		c = __CFPLDataEncodeTable [ ((p[0] >> 2) & 0x3f)];
		if (!s->addChar(c)) return false;
		break;
	case 1:
		c = __CFPLDataEncodeTable [ ((((p[-1] << 8) | p[0]) >> 4) & 0x3f)];
		if (!s->addChar(c)) return false;
		break;
	case 2:
		c = __CFPLDataEncodeTable [ ((((p[-1] << 8) | p[0]) >> 6) & 0x3f)];
		if (!s->addChar(c)) return false;
		c = __CFPLDataEncodeTable [ (p[0] & 0x3f)];
		if (!s->addChar(c)) return false;
		break;
	}
    }
    switch (i % 3) {
    case 0:
	    break;
    case 1:
	    c = __CFPLDataEncodeTable [ ((p[-1] << 4) & 0x30)];
	    if (!s->addChar(c)) return false;
	    if (!s->addChar('=')) return false;
	    if (!s->addChar('=')) return false;
	    break;
    case 2:
	    c = __CFPLDataEncodeTable [ ((p[-1] << 2) & 0x3c)];
	    if (!s->addChar(c)) return false;
	    if (!s->addChar('=')) return false;
	    break;
    }

    return s->addXMLEndTag("data");
}
