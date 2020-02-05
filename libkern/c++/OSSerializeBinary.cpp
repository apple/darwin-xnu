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
#define DEBG(fmt, args ...)  { kprintf(fmt, args); }
#else
#define DEBG(fmt, args ...)      {}
#endif

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSSerialize *
OSSerialize::binaryWithCapacity(unsigned int inCapacity,
    Editor editor, void * reference)
{
	OSSerialize *me;

	if (inCapacity < sizeof(uint32_t)) {
		return NULL;
	}
	me = OSSerialize::withCapacity(inCapacity);
	if (!me) {
		return NULL;
	}

	me->binary        = true;
	me->endCollection = true;
	me->editor        = editor;
	me->editRef       = reference;

	bcopy(kOSSerializeBinarySignature, &me->data[0], sizeof(kOSSerializeBinarySignature));
	me->length = sizeof(kOSSerializeBinarySignature);

	return me;
}

bool
OSSerialize::addBinary(const void * bits, size_t size)
{
	unsigned int newCapacity;
	size_t       alignSize;

	if (os_add_overflow(size, 3, &alignSize)) {
		return false;
	}
	alignSize &= ~3L;
	if (os_add_overflow(length, alignSize, &newCapacity)) {
		return false;
	}
	if (newCapacity >= capacity) {
		newCapacity = (((newCapacity - 1) / capacityIncrement) + 1) * capacityIncrement;
		if (newCapacity < capacity) {
			return false;
		}
		if (newCapacity > ensureCapacity(newCapacity)) {
			return false;
		}
	}

	bcopy(bits, &data[length], size);
	length += alignSize;

	return true;
}

void
OSSerialize::setIndexed(bool index __unused)
{
	assert(index && !indexData);
	indexData = OSData::withCapacity(256);
	assert(indexData);
}

bool
OSSerialize::addBinaryObject(const OSMetaClassBase * o, uint32_t key,
    const void * bits, size_t size,
    uint32_t * startCollection)
{
	unsigned int newCapacity;
	size_t       alignSize;
	size_t       headerSize;

	// add to tag array
	tags->setObject(o);

	headerSize = sizeof(key);
	if (indexData) {
		uint32_t offset = length;
		if (startCollection) {
			*startCollection = offset;
			headerSize += sizeof(uint32_t);
		}
		offset /= sizeof(uint32_t);
		indexData->appendBytes(&offset, sizeof(offset));
	}

	if (os_add3_overflow(size, headerSize, 3, &alignSize)) {
		return false;
	}
	alignSize &= ~3L;
	if (os_add_overflow(length, alignSize, &newCapacity)) {
		return false;
	}
	if (newCapacity >= capacity) {
		newCapacity = (((newCapacity - 1) / capacityIncrement) + 1) * capacityIncrement;
		if (newCapacity < capacity) {
			return false;
		}
		if (newCapacity > ensureCapacity(newCapacity)) {
			return false;
		}
	}

	if (endCollection) {
		endCollection = false;
		key |= kOSSerializeEndCollecton;
	}

	bcopy(&key, &data[length], sizeof(key));
	bcopy(bits, &data[length + headerSize], size);
	length += alignSize;

	return true;
}

void
OSSerialize::endBinaryCollection(uint32_t startCollection)
{
	uint32_t clength;

	if (!indexData) {
		return;
	}

	assert(length > startCollection);
	if (length <= startCollection) {
		return;
	}

	clength = length - startCollection;
	assert(!(clength & 3));
	clength /= sizeof(uint32_t);

	memcpy(&data[startCollection + sizeof(uint32_t)], &clength, sizeof(clength));
}

bool
OSSerialize::binarySerialize(const OSMetaClassBase *o)
{
	bool ok;
	uint32_t header;

	ok = binarySerializeInternal(o);
	if (!ok) {
		return ok;
	}

	if (indexData) {
		header = indexData->getLength() / sizeof(uint32_t);
		assert(header <= kOSSerializeDataMask);
		header <<= 8;
		header |= kOSSerializeIndexedBinarySignature;

		memcpy(&data[0], &header, sizeof(header));
	}

	return ok;
}

bool
OSSerialize::binarySerializeInternal(const OSMetaClassBase *o)
{
	OSDictionary * dict;
	OSArray      * array;
	OSSet        * set;
	OSNumber     * num;
	OSSymbol     * sym;
	OSString     * str;
	OSData       * ldata;
	OSBoolean    * boo;

	unsigned int  tagIdx;
	uint32_t   i, key, startCollection;
	size_t     len;
	bool       ok;

	tagIdx = tags->getNextIndexOfObject(o, 0);
	// does it exist?
	if (-1U != tagIdx) {
		if (indexData) {
			assert(indexData->getLength() > (tagIdx * sizeof(uint32_t)));
			tagIdx = ((const uint32_t *)indexData->getBytesNoCopy())[tagIdx];
			assert(tagIdx <= kOSSerializeDataMask);
		}
		key = (kOSSerializeObject | tagIdx);
		if (endCollection) {
			endCollection = false;
			key |= kOSSerializeEndCollecton;
		}
		ok = addBinary(&key, sizeof(key));
		return ok;
	}

	if ((dict = OSDynamicCast(OSDictionary, o))) {
		key = (kOSSerializeDictionary | dict->count);
		ok = addBinaryObject(o, key, NULL, 0, &startCollection);
		for (i = 0; ok && (i < dict->count);) {
			const OSSymbol        * dictKey;
			const OSMetaClassBase * dictValue;
			const OSMetaClassBase * nvalue = NULL;

			dictKey = dict->dictionary[i].key;
			dictValue = dict->dictionary[i].value;
			i++;
			if (editor) {
				dictValue = nvalue = (*editor)(editRef, this, dict, dictKey, dictValue);
				if (!dictValue) {
					dictValue = dict;
				}
			}
			ok = binarySerialize(dictKey);
			if (!ok) {
				break;
			}
			endCollection = (i == dict->count);
			ok = binarySerialize(dictValue);
			if (!ok) {
				ok = dictValue->serialize(this);
			}
			if (nvalue) {
				nvalue->release();
			}
//			if (!ok) ok = binarySerialize(kOSBooleanFalse);
		}
		endBinaryCollection(startCollection);
	} else if ((array = OSDynamicCast(OSArray, o))) {
		key = (kOSSerializeArray | array->count);
		ok = addBinaryObject(o, key, NULL, 0, &startCollection);
		for (i = 0; ok && (i < array->count);) {
			i++;
			endCollection = (i == array->count);
			ok = binarySerialize(array->array[i - 1]);
			if (!ok) {
				ok = array->array[i - 1]->serialize(this);
			}
//			if (!ok) ok = binarySerialize(kOSBooleanFalse);
		}
		endBinaryCollection(startCollection);
	} else if ((set = OSDynamicCast(OSSet, o))) {
		key = (kOSSerializeSet | set->members->count);
		ok = addBinaryObject(o, key, NULL, 0, &startCollection);
		for (i = 0; ok && (i < set->members->count);) {
			i++;
			endCollection = (i == set->members->count);
			ok = binarySerialize(set->members->array[i - 1]);
			if (!ok) {
				ok = set->members->array[i - 1]->serialize(this);
			}
//			if (!ok) ok = binarySerialize(kOSBooleanFalse);
		}
		endBinaryCollection(startCollection);
	} else if ((num = OSDynamicCast(OSNumber, o))) {
		key = (kOSSerializeNumber | num->size);
		ok = addBinaryObject(o, key, &num->value, sizeof(num->value), NULL);
	} else if ((boo = OSDynamicCast(OSBoolean, o))) {
		key = (kOSSerializeBoolean | (kOSBooleanTrue == boo));
		ok = addBinaryObject(o, key, NULL, 0, NULL);
	} else if ((sym = OSDynamicCast(OSSymbol, o))) {
		len = (sym->getLength() + 1);
		key = (kOSSerializeSymbol | len);
		ok = addBinaryObject(o, key, sym->getCStringNoCopy(), len, NULL);
	} else if ((str = OSDynamicCast(OSString, o))) {
		len = (str->getLength() + ((indexData != NULL) ? 1 : 0));
		key = (kOSSerializeString | len);
		ok = addBinaryObject(o, key, str->getCStringNoCopy(), len, NULL);
	} else if ((ldata = OSDynamicCast(OSData, o))) {
		len = ldata->getLength();
		if (ldata->reserved && ldata->reserved->disableSerialization) {
			len = 0;
		}
		key = (kOSSerializeData | len);
		ok = addBinaryObject(o, key, ldata->getBytesNoCopy(), len, NULL);
	} else {
		return false;
	}

	return ok;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define setAtIndex(v, idx, o)                                                                                                           \
	if (idx >= v##Capacity)                                                                                                                 \
	{                                                                                                                                                               \
	if (v##Capacity >= v##CapacityMax) ok = false;                                  \
	else                                                                                                                                                    \
	{                                                                                                                                                           \
	    uint32_t ncap = v##Capacity + 64;                                                                               \
	    typeof(v##Array) nbuf = (typeof(v##Array)) kalloc_container(ncap * sizeof(o)); \
	    if (!nbuf) ok = false;                                                                                                          \
	    else                                                                                                                                    \
	    {                                                                                                                                   \
	        if (v##Array)                                                                                                                   \
	        {                                                                                                                                               \
	            bcopy(v##Array, nbuf, v##Capacity * sizeof(o));                                             \
	            kfree(v##Array, v##Capacity * sizeof(o));                                                   \
	        }                                                                                                                                               \
	        v##Array    = nbuf;                                                                                                             \
	        v##Capacity = ncap;                                                                                                             \
	    }                                                                                                                                   \
	    }                                                                                                                                                       \
	}                                                                                                                                                               \
	if (ok) v##Array[idx] = o;

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSObject *
OSUnserializeBinary(const char *buffer, size_t bufferSize, OSString **errorString)
{
	OSObject ** objsArray;
	uint32_t    objsCapacity;
	enum      { objsCapacityMax = 16 * 1024 * 1024 };
	uint32_t    objsIdx;

	OSObject ** stackArray;
	uint32_t    stackCapacity;
	enum      { stackCapacityMax = 64 };
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
	OSString     * str;

	size_t           bufferPos;
	const uint32_t * next;
	uint32_t         key, len, wordLen, length;
	bool             end, newCollect, isRef;
	unsigned long long value;
	bool ok, indexed, hasLength;

	indexed = false;
	if (errorString) {
		*errorString = NULL;
	}

	if (bufferSize < sizeof(kOSSerializeBinarySignature)) {
		return NULL;
	}
	if (kOSSerializeIndexedBinarySignature == (((const uint8_t *) buffer)[0])) {
		indexed = true;
	} else if (0 != strcmp(kOSSerializeBinarySignature, buffer)) {
		return NULL;
	}
	if (3 & ((uintptr_t) buffer)) {
		return NULL;
	}

	bufferPos = sizeof(kOSSerializeBinarySignature);
	next = (typeof(next))(((uintptr_t) buffer) + bufferPos);

	DEBG("---------OSUnserializeBinary(%p)\n", buffer);

	objsArray = stackArray    = NULL;
	objsIdx   = objsCapacity  = 0;
	stackIdx  = stackCapacity = 0;

	result   = NULL;
	parent   = NULL;
	dict     = NULL;
	array    = NULL;
	set      = NULL;
	sym      = NULL;

	ok = true;
	while (ok) {
		bufferPos += sizeof(*next);
		if (!(ok = (bufferPos <= bufferSize))) {
			break;
		}
		key = *next++;
		length = 0;

		len = (key & kOSSerializeDataMask);
		wordLen = (len + 3) >> 2;
		end = (0 != (kOSSerializeEndCollecton & key));
		DEBG("key 0x%08x: 0x%04x, %d\n", key, len, end);

		newCollect = isRef = hasLength = false;
		o = NULL; newDict = NULL; newArray = NULL; newSet = NULL;

		switch (kOSSerializeTypeMask & key) {
		case kOSSerializeDictionary:
			o = newDict = OSDictionary::withCapacity(len);
			newCollect = (len != 0);
			hasLength  = indexed;
			break;
		case kOSSerializeArray:
			o = newArray = OSArray::withCapacity(len);
			newCollect = (len != 0);
			hasLength  = indexed;
			break;
		case kOSSerializeSet:
			o = newSet = OSSet::withCapacity(len);
			newCollect = (len != 0);
			hasLength  = indexed;
			break;

		case kOSSerializeObject:
			if (len >= objsIdx) {
				break;
			}
			o = objsArray[len];
			isRef = true;
			break;

		case kOSSerializeNumber:
			bufferPos += sizeof(long long);
			if (bufferPos > bufferSize) {
				break;
			}
			if ((len != 32) && (len != 64) && (len != 16) && (len != 8)) {
				break;
			}
			value = next[1];
			value <<= 32;
			value |= next[0];
			o = OSNumber::withNumber(value, len);
			next += 2;
			break;

		case kOSSerializeSymbol:
			bufferPos += (wordLen * sizeof(uint32_t));
			if (bufferPos > bufferSize) {
				break;
			}
			if (len < 2) {
				break;
			}
			if (0 != ((const char *)next)[len - 1]) {
				break;
			}
			o = (OSObject *) OSSymbol::withCString((const char *) next);
			next += wordLen;
			break;

		case kOSSerializeString:
			bufferPos += (wordLen * sizeof(uint32_t));
			if (bufferPos > bufferSize) {
				break;
			}
			o = OSString::withStringOfLength((const char *) next, len);
			next += wordLen;
			break;

		case kOSSerializeData:
			bufferPos += (wordLen * sizeof(uint32_t));
			if (bufferPos > bufferSize) {
				break;
			}
			o = OSData::withBytes(next, len);
			next += wordLen;
			break;

		case kOSSerializeBoolean:
			o = (len ? kOSBooleanTrue : kOSBooleanFalse);
			break;

		default:
			break;
		}

		if (!(ok = (o != NULL))) {
			break;
		}

		if (hasLength) {
			bufferPos += sizeof(*next);
			if (!(ok = (bufferPos <= bufferSize))) {
				break;
			}
			length = *next++;
		}

		if (!isRef) {
			setAtIndex(objs, objsIdx, o);
			if (!ok) {
				o->release();
				break;
			}
			objsIdx++;
		}

		if (dict) {
			if (!sym) {
				sym = (OSSymbol *) o;
			} else {
				str = sym;
				sym = OSDynamicCast(OSSymbol, sym);
				if (!sym && (str = OSDynamicCast(OSString, str))) {
					sym = const_cast<OSSymbol *>(OSSymbol::withString(str));
					ok = (sym != NULL);
					if (!ok) {
						break;
					}
				}
				DEBG("%s = %s\n", sym->getCStringNoCopy(), o->getMetaClass()->getClassName());
				if (o != dict) {
					ok = dict->setObject(sym, o);
				}
				if (sym && (sym != str)) {
					sym->release();
				}
				sym = NULL;
			}
		} else if (array) {
			ok = array->setObject(o);
		} else if (set) {
			ok = set->setObject(o);
		} else if (result) {
			ok = false;
		} else {
			assert(!parent);
			result = o;
		}

		if (!ok) {
			break;
		}

		if (end) {
			parent = NULL;
		}
		if (newCollect) {
			stackIdx++;
			setAtIndex(stack, stackIdx, parent);
			if (!ok) {
				break;
			}
			DEBG("++stack[%d] %p\n", stackIdx, parent);
			parent = o;
			dict   = newDict;
			array  = newArray;
			set    = newSet;
			end    = false;
		}

		if (end) {
			while (stackIdx) {
				parent = stackArray[stackIdx];
				DEBG("--stack[%d] %p\n", stackIdx, parent);
				stackIdx--;
				if (parent) {
					break;
				}
			}
			if (!parent) {
				break;
			}
			set   = NULL;
			dict  = NULL;
			array = NULL;
			if (!(dict = OSDynamicCast(OSDictionary, parent))) {
				if (!(array = OSDynamicCast(OSArray, parent))) {
					ok = (NULL != (set = OSDynamicCast(OSSet, parent)));
				}
			}
		}
	}
	DEBG("ret %p\n", result);

	if (!ok) {
		result = NULL;
	}

	if (objsCapacity) {
		for (len = (result != NULL); len < objsIdx; len++) {
			objsArray[len]->release();
		}
		kfree(objsArray, objsCapacity  * sizeof(*objsArray));
	}
	if (stackCapacity) {
		kfree(stackArray, stackCapacity * sizeof(*stackArray));
	}

	return result;
}
