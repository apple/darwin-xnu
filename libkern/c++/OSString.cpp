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
/* IOString.m created by rsulack on Wed 17-Sep-1997 */
/* IOString.cpp converted to C++ on Tue 1998-9-22 */


#include <libkern/c++/OSString.h>
#include <libkern/c++/OSSerialize.h>
#include <libkern/c++/OSLib.h>
#include <libkern/c++/OSData.h>

#define super OSObject

OSDefineMetaClassAndStructors(OSString, OSObject)
OSMetaClassDefineReservedUnused(OSString,  0);
OSMetaClassDefineReservedUnused(OSString,  1);
OSMetaClassDefineReservedUnused(OSString,  2);
OSMetaClassDefineReservedUnused(OSString,  3);
OSMetaClassDefineReservedUnused(OSString,  4);
OSMetaClassDefineReservedUnused(OSString,  5);
OSMetaClassDefineReservedUnused(OSString,  6);
OSMetaClassDefineReservedUnused(OSString,  7);
OSMetaClassDefineReservedUnused(OSString,  8);
OSMetaClassDefineReservedUnused(OSString,  9);
OSMetaClassDefineReservedUnused(OSString, 10);
OSMetaClassDefineReservedUnused(OSString, 11);
OSMetaClassDefineReservedUnused(OSString, 12);
OSMetaClassDefineReservedUnused(OSString, 13);
OSMetaClassDefineReservedUnused(OSString, 14);
OSMetaClassDefineReservedUnused(OSString, 15);

#if OSALLOCDEBUG
extern "C" {
    extern int debug_container_malloc_size;
};
#define ACCUMSIZE(s) do { debug_container_malloc_size += (s); } while(0)
#else
#define ACCUMSIZE(s)
#endif

bool OSString::initWithString(const OSString *aString)
{
    return initWithCString(aString->string);
}

bool OSString::initWithCString(const char *cString)
{
    if (!cString || !super::init())
        return false;

    length = strlen(cString) + 1;
    string = (char *) kalloc(length);
    if (!string)
        return false;

    bcopy(cString, string, length);

    ACCUMSIZE(length);

    return true;
}

bool OSString::initWithCStringNoCopy(const char *cString)
{
    if (!cString || !super::init())
        return false;

    length = strlen(cString) + 1;
    flags |= kOSStringNoCopy;
    string = (char *) cString;

    return true;
}

OSString *OSString::withString(const OSString *aString)
{
    OSString *me = new OSString;

    if (me && !me->initWithString(aString)) {
        me->free();
        return 0;
    }

    return me;
}

OSString *OSString::withCString(const char *cString)
{
    OSString *me = new OSString;

    if (me && !me->initWithCString(cString)) {
        me->free();
        return 0;
    }

    return me;
}

OSString *OSString::withCStringNoCopy(const char *cString)
{
    OSString *me = new OSString;

    if (me && !me->initWithCStringNoCopy(cString)) {
        me->free();
        return 0;
    }

    return me;
}

/* @@@ gvdl */
#if 0
OSString *OSString::stringWithFormat(const char *format, ...)
{
#ifndef KERNEL			// mach3xxx
    OSString *me;
    va_list argList;

    if (!format)
        return 0;

    va_start(argList, format);
    me = stringWithCapacity(256);
    me->length = vsnprintf(me->string, 256, format, argList);
    me->length++;	// we include the null in the length
    if (me->Length > 256)
        me->Length = 256;
    va_end (argList);

    return me;
#else
    return 0;
#endif
}
#endif /* 0 */

void OSString::free()
{
    if ( !(flags & kOSStringNoCopy) && string) {
        kfree((vm_offset_t)string, (vm_size_t)length);
        ACCUMSIZE(-length);
    }

    super::free();
}

unsigned int OSString::getLength()  const { return length - 1; }

const char *OSString::getCStringNoCopy() const
{
    return string;
}

bool OSString::setChar(char aChar, unsigned int index)
{
    if ( !(flags & kOSStringNoCopy) && index < length - 1) {
        string[index] = aChar;

        return true;
    }
    else
        return false;
}

char OSString::getChar(unsigned int index) const
{
    if (index < length)
        return string[index];
    else
        return '\0';
}


bool OSString::isEqualTo(const OSString *aString) const
{
    if (length != aString->length)
        return false;
    else
        return isEqualTo((const char *) aString->string);
}

bool OSString::isEqualTo(const char *aCString) const
{
    return strcmp(string, aCString) == 0;
}

bool OSString::isEqualTo(const OSMetaClassBase *obj) const
{
    OSString *	str;
    OSData *    data;

    if ((str = OSDynamicCast(OSString, obj)))
        return isEqualTo(str);
    else if ((data = OSDynamicCast (OSData, obj)))
        return isEqualTo(data);
    else
        return false;
}

bool OSString::isEqualTo(const OSData *obj) const
{
    if (NULL == obj)
      return false;

    unsigned int dataLen = obj->getLength ();;
    char * dataPtr = (char *) obj->getBytesNoCopy ();

    if (dataLen != length) {

      // check for the fact that OSData may be a buffer that
      // that includes a termination byte and will thus have
      // a length of the actual string length PLUS 1. In this
      // case we verify that the additional byte is a terminator
      // and if so count the two lengths as being the same.

      if ( (dataLen - length) == 1 ) {
	if (dataPtr[dataLen-1] != 0)
	  return false;
	dataLen--;
      }
      else
	return false;
    }

    for ( unsigned int i=0; i < dataLen; i++ ) {
      if ( *dataPtr++ != string[i] )
        return false;
    }

    return true;
}

bool OSString::serialize(OSSerialize *s) const
{
    char *c = string;

    if (s->previouslySerialized(this)) return true;

    if (!s->addXMLStartTag(this, "string")) return false;
    while (*c) {
        if (*c == '<') {
            if (!s->addString("&lt;")) return false;
        } else if (*c == '>') {
            if (!s->addString("&gt;")) return false;
        } else if (*c == '&') {
            if (!s->addString("&amp;")) return false;
        } else {
            if (!s->addChar(*c)) return false;
        }
        c++;
    }   

    return s->addXMLEndTag("string");
}
