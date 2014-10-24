/*
 * Copyright (c) 2014 Apple Computer, Inc. All rights reserved.
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


#include <libkern/c++/OSContainers.h>
#include <libkern/c++/OSLib.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/OSSerializeBinary.h>

#include <IOKit/IOLib.h>

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if 0
#define DEBG(fmt, args...)  { kprintf(fmt, args); }
#else
#define DEBG(fmt, args...)	{}
#endif

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSSerialize *OSSerialize::binaryWithCapacity(unsigned int inCapacity, 
											 Editor editor, void * reference)
{
	OSSerialize *me;

    if (inCapacity < sizeof(uint32_t)) return (0);
	me = OSSerialize::withCapacity(inCapacity);
    if (!me) return (0);

    me->binary        = true;
    me->endCollection = true;
    me->editor        = editor;
    me->editRef       = reference;

	bcopy(kOSSerializeBinarySignature, &me->data[0], sizeof(kOSSerializeBinarySignature));
	me->length = sizeof(kOSSerializeBinarySignature);

    return (me);
}

bool OSSerialize::addBinary(const void * bits, size_t size)
{
    unsigned int newCapacity;
    size_t       alignSize;

	alignSize = ((size + 3) & ~3L);
	newCapacity = length + alignSize;
	if (newCapacity >= capacity) 
	{
	   newCapacity = (((newCapacity - 1) / capacityIncrement) + 1) * capacityIncrement;
	   if (newCapacity < ensureCapacity(newCapacity)) return (false);
    }

	bcopy(bits, &data[length], size);
	length += alignSize;
 
	return (true);
}

bool OSSerialize::addBinaryObject(const OSMetaClassBase * o, uint32_t key, 
								  const void * bits, size_t size)
{
    unsigned int newCapacity;
    size_t       alignSize;
	OSNumber   * tagNum;

	// build a tag
	tagNum = OSNumber::withNumber(tag, 32);
	tag++;
    // add to tag dictionary
	tags->setObject((const OSSymbol *) o, tagNum);
	tagNum->release();

	alignSize = ((size + sizeof(key) + 3) & ~3L);
	newCapacity = length + alignSize;
	if (newCapacity >= capacity) 
	{
	   newCapacity = (((newCapacity - 1) / capacityIncrement) + 1) * capacityIncrement;
	   if (newCapacity < ensureCapacity(newCapacity)) return (false);
    }

    if (endCollection)
    {
         endCollection = false;
         key |= kOSSerializeEndCollecton;
    }

	bcopy(&key, &data[length], sizeof(key));
	bcopy(bits, &data[length + sizeof(key)], size);
	length += alignSize;
 
	return (true);
}

bool OSSerialize::binarySerialize(const OSMetaClassBase *o)
{
    OSDictionary * dict;
    OSArray      * array;
    OSSet        * set;
    OSNumber     * num;
    OSSymbol     * sym;
    OSString     * str;
    OSData       * data;
    OSBoolean    * boo;

	OSNumber * tagNum;
    uint32_t   i, key;
    size_t     len;
    bool       ok;

	tagNum = (OSNumber *)tags->getObject((const OSSymbol *) o);
	// does it exist?
	if (tagNum)
	{
		key = (kOSSerializeObject | tagNum->unsigned32BitValue());
		if (endCollection)
		{
			 endCollection = false;
			 key |= kOSSerializeEndCollecton;
		}
		ok = addBinary(&key, sizeof(key));
		return (ok);
	}

	if ((dict = OSDynamicCast(OSDictionary, o)))
	{
		key = (kOSSerializeDictionary | dict->count);
		ok = addBinaryObject(o, key, NULL, 0);
		for (i = 0; ok && (i < dict->count);)
		{
			const OSSymbol        * dictKey;
			const OSMetaClassBase * dictValue;
			const OSMetaClassBase * nvalue = 0;

			i++;
			dictKey = dict->dictionary[i-1].key;
			dictValue = dict->dictionary[i-1].value;
			if (editor)
			{
				dictValue = nvalue = (*editor)(editRef, this, dict, dictKey, dictValue);
				if (!dictValue) dictValue = dict;
			}
			ok = binarySerialize(dictKey);
			if (!ok) break;
			endCollection = (i == dict->count);
			ok = binarySerialize(dictValue);
			if (!ok) ok = dictValue->serialize(this);
			if (nvalue) nvalue->release();
//			if (!ok) ok = binarySerialize(kOSBooleanFalse);
		}			
	}
	else if ((array = OSDynamicCast(OSArray, o)))
	{
		key = (kOSSerializeArray | array->count);
		ok = addBinaryObject(o, key, NULL, 0);
		for (i = 0; ok && (i < array->count);)
		{
			i++;
			endCollection = (i == array->count);
			ok = binarySerialize(array->array[i-1]);
			if (!ok) ok = array->array[i-1]->serialize(this);
//			if (!ok) ok = binarySerialize(kOSBooleanFalse);
		}			
	}
	else if ((set = OSDynamicCast(OSSet, o)))
	{
		key = (kOSSerializeSet | set->members->count);
		ok = addBinaryObject(o, key, NULL, 0);
		for (i = 0; ok && (i < set->members->count);)
		{
			i++;
			endCollection = (i == set->members->count);
			ok = binarySerialize(set->members->array[i-1]);
			if (!ok) ok = set->members->array[i-1]->serialize(this);
//			if (!ok) ok = binarySerialize(kOSBooleanFalse);
		}			
	}
	else if ((num = OSDynamicCast(OSNumber, o)))
	{
		key = (kOSSerializeNumber | num->size);
		ok = addBinaryObject(o, key, &num->value, sizeof(num->value));
	}
	else if ((boo = OSDynamicCast(OSBoolean, o)))
	{
		key = (kOSSerializeBoolean | (kOSBooleanTrue == boo));
		ok = addBinaryObject(o, key, NULL, 0);
	}
	else if ((sym = OSDynamicCast(OSSymbol, o)))
	{
		len = (sym->getLength() + 1);
		key = (kOSSerializeSymbol | len);
		ok = addBinaryObject(o, key, sym->getCStringNoCopy(), len);
	}
	else if ((str = OSDynamicCast(OSString, o)))
	{
		len = (str->getLength() + 0);
		key = (kOSSerializeString | len);
		ok = addBinaryObject(o, key, str->getCStringNoCopy(), len);
	}
	else if ((data = OSDynamicCast(OSData, o)))
	{
		len = data->getLength();
		if (data->reserved && data->reserved->disableSerialization) len = 0;
		key = (kOSSerializeData | len);
		ok = addBinaryObject(o, key, data->getBytesNoCopy(), len);
	}
	else return (false);

    return (ok);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define setAtIndex(v, idx, o)													\
	if (idx >= v##Capacity)														\
	{																			\
		uint32_t ncap = v##Capacity + 64;										\
		typeof(v##Array) nbuf = (typeof(v##Array)) kalloc(ncap * sizeof(o));	\
		if (!nbuf) ok = false;													\
		if (v##Array)															\
		{																		\
			bcopy(v##Array, nbuf, v##Capacity * sizeof(o));						\
			kfree(v##Array, v##Capacity * sizeof(o));							\
		}																		\
		v##Array    = nbuf;														\
		v##Capacity = ncap;														\
	}																			\
	if (ok) v##Array[idx] = o;

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSObject *
OSUnserializeBinary(const char *buffer, size_t bufferSize, OSString **errorString)
{
	OSObject ** objsArray;
	uint32_t    objsCapacity;
	uint32_t    objsIdx;

	OSObject ** stackArray;
	uint32_t    stackCapacity;
	uint32_t    stackIdx;

    OSObject     * result;
    OSObject     * parent;
    OSDictionary * dict;
    OSArray      * array;
    OSSet        * set;
    OSDictionary * newDict;
    OSArray      * newArray;
    OSSet        * newSet;
    OSObject     * o;
    OSSymbol     * sym;

    size_t           bufferPos;
    const uint32_t * next;
    uint32_t         key, len, wordLen;
    bool             end, newCollect, isRef;
    unsigned long long value;
    bool ok;

	if (errorString) *errorString = 0;
	if (0 != strcmp(kOSSerializeBinarySignature, buffer)) return (NULL);
	if (3 & ((uintptr_t) buffer)) return (NULL);
	if (bufferSize < sizeof(kOSSerializeBinarySignature)) return (NULL);
	bufferPos = sizeof(kOSSerializeBinarySignature);
	next = (typeof(next)) (((uintptr_t) buffer) + bufferPos);

	DEBG("---------OSUnserializeBinary(%p)\n", buffer);

	objsArray = stackArray    = NULL;
	objsIdx   = objsCapacity  = 0;
	stackIdx  = stackCapacity = 0;

    result   = 0;
    parent   = 0;
	dict     = 0;
	array    = 0;
	set      = 0;
	sym      = 0;

	ok = true;
	while (ok)
	{
		bufferPos += sizeof(*next);
		if (!(ok = (bufferPos <= bufferSize))) break;
		key = *next++;

        len = (key & kOSSerializeDataMask);
        wordLen = (len + 3) >> 2;
		end = (0 != (kOSSerializeEndCollecton & key));
        DEBG("key 0x%08x: 0x%04x, %d\n", key, len, end);

        newCollect = isRef = false;
		o = 0; newDict = 0; newArray = 0; newSet = 0;
		
		switch (kOSSerializeTypeMask & key)
		{
		    case kOSSerializeDictionary:
				o = newDict = OSDictionary::withCapacity(len);
				newCollect = (len != 0);
		        break;
		    case kOSSerializeArray:
				o = newArray = OSArray::withCapacity(len);
				newCollect = (len != 0);
		        break;
		    case kOSSerializeSet:
				o = newSet = OSSet::withCapacity(len);
				newCollect = (len != 0);
		        break;

		    case kOSSerializeObject:
				if (len >= objsIdx) break;
				o = objsArray[len];
				o->retain();
				isRef = true;
				break;

		    case kOSSerializeNumber:
				bufferPos += sizeof(long long);
				if (bufferPos > bufferSize) break;
		    	value = next[1];
		    	value <<= 32;
		    	value |= next[0];
		    	o = OSNumber::withNumber(value, len);
		    	next += 2;
		        break;

		    case kOSSerializeSymbol:
				bufferPos += (wordLen * sizeof(uint32_t));
				if (bufferPos > bufferSize)           break;
				if (0 != ((const char *)next)[len-1]) break;
		        o = (OSObject *) OSSymbol::withCString((const char *) next);
		        next += wordLen;
		        break;

		    case kOSSerializeString:
				bufferPos += (wordLen * sizeof(uint32_t));
				if (bufferPos > bufferSize) break;
		        o = OSString::withStringOfLength((const char *) next, len);
		        next += wordLen;
		        break;

    	    case kOSSerializeData:
				bufferPos += (wordLen * sizeof(uint32_t));
				if (bufferPos > bufferSize) break;
		        o = OSData::withBytes(next, len);
		        next += wordLen;
		        break;

    	    case kOSSerializeBoolean:
				o = (len ? kOSBooleanTrue : kOSBooleanFalse);
		        break;

		    default:
		        break;
		}

		if (!(ok = (o != 0))) break;

		if (!isRef)
		{
			setAtIndex(objs, objsIdx, o);
			if (!ok) break;
			objsIdx++;
		}

		if (dict)
		{
			if (sym)
			{
				DEBG("%s = %s\n", sym->getCStringNoCopy(), o->getMetaClass()->getClassName());
				if (o != dict) ok = dict->setObject(sym, o);
				o->release();
				sym->release();
				sym = 0;
			}
			else 
			{
				sym = OSDynamicCast(OSSymbol, o);
				ok = (sym != 0);
			}
		}
		else if (array) 
		{
			ok = array->setObject(o);
		    o->release();
		}
		else if (set)
		{
		   ok = set->setObject(o);
		   o->release();
		}
		else
		{
		    assert(!parent);
		    result = o;
		}

		if (!ok) break;

		if (newCollect)
		{
			if (!end)
			{
				stackIdx++;
				setAtIndex(stack, stackIdx, parent);
				if (!ok) break;
			}
			DEBG("++stack[%d] %p\n", stackIdx, parent);
			parent = o;
			dict   = newDict;
			array  = newArray;
			set    = newSet;
			end    = false;
		}

		if (end)
		{
			if (!stackIdx) break;
			parent = stackArray[stackIdx];
			DEBG("--stack[%d] %p\n", stackIdx, parent);
			stackIdx--;
			set   = 0; 
			dict  = 0; 
			array = 0;
			if (!(dict = OSDynamicCast(OSDictionary, parent)))
			{
				if (!(array = OSDynamicCast(OSArray, parent))) ok = (0 != (set = OSDynamicCast(OSSet, parent)));
			}
		}
	}
	DEBG("ret %p\n", result);

	if (objsCapacity)  kfree(objsArray,  objsCapacity  * sizeof(*objsArray));
	if (stackCapacity) kfree(stackArray, stackCapacity * sizeof(*stackArray));

	if (!ok && result)
	{
		result->release();
		result = 0;
	}
	return (result);
}