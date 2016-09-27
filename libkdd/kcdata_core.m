/*
 * Copyright (c) 2015 Apple Inc. All rights reserved.
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

#include <kcdata.h>
#import <Foundation/Foundation.h>
#import "kdd.h"
#import "KCDBasicTypeDescription.h"
#import "KCDStructTypeDescription.h"
#import "KCDEmbeddedBufferDescription.h"

#define LIB_KCD_ERR_DOMAIN @"KCDataError"

#define GEN_ERROR(code, msg) gen_error(__LINE__, code, @msg)
#define GEN_ERRORF(code, msg, ...) gen_error(__LINE__, code, [NSString stringWithFormat:@msg, __VA_ARGS__])

#define MAX_KCDATATYPE_BUFFER_SIZE 2048
extern struct kcdata_type_definition * kcdata_get_typedescription(unsigned type_id, uint8_t * buffer, uint32_t buffer_size);

BOOL setKCDataTypeForID(uint32_t newTypeID, KCDataType *newTypeObj);

static NSError *
gen_error(int line, NSInteger code, NSString *message)
{
	return [NSError errorWithDomain:LIB_KCD_ERR_DOMAIN
							   code:code
						   userInfo:@{ @"line": @(line), @"message": message }];
}

static BOOL
mergedict(NSMutableDictionary * container, NSDictionary * object, NSError ** error)
{
	for (id key in object) {
		id existing = container[key];
		id new = object[key];
		if (existing) {
			if ([existing isKindOfClass:[NSMutableArray class]] && [new isKindOfClass:[ NSArray class ]]) {
				[existing addObjectsFromArray:new];
			} else {
				if (error) {
					*error = GEN_ERRORF(KERN_INVALID_OBJECT, "repeated key: %@", key);
				}
				return FALSE;
			}
		} else {
			[container setValue:new forKey:key];
		}
	}
	return TRUE;
}

/*!
 * @function getTypeFromTypeDef
 *
 * @abstract
 * Build a KCDataType from a type definition.
 *
 * @param typeDef
 * A pointer to kcdata_type_definition_t that specifies the type fields and has subtype definitions
 * in the memory immediately following the type_definition.
 *
 * @return KCDataType * type object which can be used to parse data into dictionaries.
 * This may return nil if it finds the data to be invalid.
 *
 * @discussion
 * This routine tries to decode the typeDef structure and create either a basic type (KCDBasicTypeDescription)
 * or a struct type.
 */
static KCDataType * getTypeFromTypeDef(struct kcdata_type_definition * typeDef);

static KCDataType *
getTypeFromTypeDef(struct kcdata_type_definition * typeDef)
{
	if (typeDef == NULL) {
		return nil;
	}
	NSString * kct_name = [NSString stringWithFormat:@"%s", typeDef->kct_name];
	if (typeDef->kct_num_elements == 1 && !(typeDef->kct_elements[0].kcs_flags & KCS_SUBTYPE_FLAGS_STRUCT)) {
		KCDBasicTypeDescription * retval = [[KCDBasicTypeDescription alloc] initWithKCTypeDesc:&typeDef->kct_elements[0]];
		return retval;
	} else {
		KCDStructTypeDescription * retval =
		    [[KCDStructTypeDescription alloc] initWithType:typeDef->kct_type_identifier withName:kct_name];
		/* need to do work here to get the array of elements setup here */
		KCDBasicTypeDescription * curField = nil;
		for (unsigned int i = 0; i < typeDef->kct_num_elements; i++) {
			curField = [[KCDBasicTypeDescription alloc] initWithKCTypeDesc:&typeDef->kct_elements[i]];
			[retval addFieldBasicType:curField];
			if (typeDef->kct_elements[i].kcs_flags & KCS_SUBTYPE_FLAGS_MERGE) {
				[retval setFlagsRequestedMerge];
			}
		}
		return retval;
	}
	return nil;
}

static dispatch_once_t onceToken;
static NSMutableDictionary * knownTypes = nil;

KCDataType *
getKCDataTypeForID(uint32_t typeID)
{
	dispatch_once(&onceToken, ^{
	  if (!knownTypes) {
		  knownTypes = [[NSMutableDictionary alloc] init];
	  }
	});

	NSNumber * type = [NSNumber numberWithUnsignedInt:typeID];
	if (!knownTypes[type]) {
		if (typeID == KCDATA_TYPE_NESTED_KCDATA) {
			knownTypes[type] = [[KCDEmbeddedBufferDescription alloc] init];
			return knownTypes[type];
		}
		/* code to query system for type information */
		uint8_t buffer[MAX_KCDATATYPE_BUFFER_SIZE];
		struct kcdata_type_definition * sys_def = kcdata_get_typedescription(typeID, buffer, MAX_KCDATATYPE_BUFFER_SIZE);
		if (sys_def == NULL) {
			knownTypes[type] = [[KCDBasicTypeDescription alloc] createDefaultForType:typeID];
		} else {
			knownTypes[type] = getTypeFromTypeDef(sys_def);
		}
	}
	assert(knownTypes[type] != nil);
	return knownTypes[type];
}

BOOL
setKCDataTypeForID(uint32_t newTypeID, KCDataType *newTypeObj) {
    if (newTypeObj == NULL || newTypeID == 0) {
        return FALSE;
    }
    
    dispatch_once(&onceToken, ^{
        if (!knownTypes) {
            knownTypes = [[NSMutableDictionary alloc] init];
        }
    });
    
    NSNumber * type = [NSNumber numberWithUnsignedInt:newTypeID];

    if (!knownTypes[type]) {
        knownTypes[type] = newTypeObj;
        return TRUE;
    }
    
    return FALSE;
}


NSString *
KCDataTypeNameForID(uint32_t typeID)
{
	NSString * retval = [NSString stringWithFormat:@"%u", typeID];
	KCDataType * t    = getKCDataTypeForID(typeID);

	if (![[t name] containsString:@"Type_"]) {
		retval = [t name];
	}
	return retval;
}

NSMutableDictionary *
parseKCDataArray(kcdata_iter_t iter, NSError **error)
{
	if (!kcdata_iter_array_valid(iter)) {
		if (error)
			*error = GEN_ERROR(KERN_INVALID_OBJECT, "invalid array");
		return NULL;
	}

	uint32_t typeID               = kcdata_iter_array_elem_type(iter);
	uint32_t count                = kcdata_iter_array_elem_count(iter);
	uint32_t size                 = kcdata_iter_array_elem_size(iter);
	uint8_t * buffer              = (uint8_t *)kcdata_iter_payload(iter);
	KCDataType * datatype         = getKCDataTypeForID(typeID);
	NSMutableDictionary * retval  = [[NSMutableDictionary alloc] initWithCapacity:1];
	NSMutableArray * arr          = [[NSMutableArray alloc] initWithCapacity:count];
	retval[[datatype name]]       = arr;
	NSDictionary * tmpdict = NULL;
	for (uint32_t i = 0; i < count; i++) {
		tmpdict = [datatype parseData:(void *)&buffer[i * size] ofLength:size];
		if (!tmpdict) {
			if (error)
				*error = GEN_ERRORF(KERN_INVALID_OBJECT, "failed to parse array element.  type=0x%x", (int)typeID);
			return NULL;
		}
		if ([datatype shouldMergeData]) {
			assert([tmpdict count] == 1);
			[arr addObject: [tmpdict allValues][0]];
		} else {
			[arr addObject:tmpdict];
		}
	}
	return retval;
}

NSMutableDictionary *
parseKCDataContainer(kcdata_iter_t *iter_p, NSError **error)
{
	kcdata_iter_t iter = *iter_p;

	if (!kcdata_iter_container_valid(iter)) {
		if (error)
			*error = GEN_ERROR(KERN_INVALID_OBJECT, "invalid container");
		return NULL;
	}
	uint64_t containerID = kcdata_iter_container_id(iter);

	/* setup collection object for sub containers */
	NSMutableDictionary * sub_containers = [[NSMutableDictionary alloc] init];
	NSMutableDictionary * retval         = [[NSMutableDictionary alloc] init];
	NSMutableDictionary * container      = [[NSMutableDictionary alloc] init];

	KCDataType * tmptype;
	uint32_t _t;
	void * _d;
	BOOL ok;
	NSDictionary * tmpdict;
	BOOL found_end = FALSE;
	retval[KCDataTypeNameForID(kcdata_iter_container_type(iter))] = container;

	iter = kcdata_iter_next(iter);

	KCDATA_ITER_FOREACH(iter)
	{
		_t = kcdata_iter_type(iter);
		_d = kcdata_iter_payload(iter);
		if (_t == KCDATA_TYPE_CONTAINER_END) {
			if (kcdata_iter_container_id(iter) != containerID) {
				if (error)
					*error = GEN_ERROR(KERN_INVALID_ARGUMENT, "container marker mismatch");
				return NULL;
			}
			found_end = TRUE;
			break;
		}

		if (_t == KCDATA_TYPE_ARRAY) {
			tmpdict = parseKCDataArray(iter, error);
			if (!tmpdict)
				return NULL;

			ok = mergedict(container, tmpdict, error);
			if (!ok)
				return NULL;

			continue;
		}

		if (_t == KCDATA_TYPE_CONTAINER_BEGIN) {
			NSString * subcontainerID = [NSString stringWithFormat:@"%llu", kcdata_iter_container_id(iter)];
			tmpdict                   = parseKCDataContainer(&iter, error);
			if (!tmpdict)
				return NULL;
			assert([tmpdict count] == 1);
			for (NSString * k in [tmpdict keyEnumerator]) {
				if (sub_containers[k] == nil) {
					sub_containers[k] = [[NSMutableDictionary alloc] init];
				}
				if (sub_containers[k][subcontainerID] != nil) {
					if (error)
						*error = GEN_ERRORF(KERN_INVALID_OBJECT, "repeated container id: %@", subcontainerID);
					return NULL;
				}
				sub_containers[k][subcontainerID] = tmpdict[k];
			}
			continue;
		}

		tmptype = getKCDataTypeForID(_t);
		tmpdict = [tmptype parseData:_d ofLength:kcdata_iter_size(iter)];
		if (!tmpdict) {
			if (error)
				*error = GEN_ERRORF(KERN_INVALID_OBJECT, "failed to parse. type=0x%x", (int)_t);
			return NULL;
		}
		if (![tmptype shouldMergeData]) {
			tmpdict = @{[tmptype name] : tmpdict};
		}
		ok = mergedict(container, tmpdict, error);
		if (!ok)
			return NULL;
	}

	if (!found_end) {
		if (error)
			*error = GEN_ERROR(KERN_INVALID_ARGUMENT, "missing container end");
		return NULL;
	}

	ok = mergedict(container, sub_containers, error);
	if (!ok)
		return NULL;

	*iter_p = iter;
	return retval;
}

NSDictionary *
parseKCDataBuffer(void * dataBuffer, uint32_t size, NSError ** error)
{
	if (dataBuffer == NULL) {
		if (error)
			*error = GEN_ERROR(KERN_INVALID_ARGUMENT, "buffer is null");
		return NULL;
	}

	uint32_t _type        = (size >= sizeof(uint32_t)) ? *(uint32_t*)dataBuffer : 0;
	uint32_t _size        = 0;
	uint64_t _flags       = 0;
	void * _datap         = NULL;
	KCDataType * kcd_type = NULL;
	NSString * rootKey    = NULL;
	uint32_t rootType     = _type;
	BOOL ok;

	/* validate begin tag and get root key */
	switch (_type) {
	case KCDATA_BUFFER_BEGIN_CRASHINFO:
		rootKey = @"kcdata_crashinfo";
		break;
	case KCDATA_BUFFER_BEGIN_STACKSHOT:
		rootKey = @"kcdata_stackshot";
		break;
	case KCDATA_BUFFER_BEGIN_DELTA_STACKSHOT:
		rootKey = @"kcdata_delta_stackshot";
		break;
	case KCDATA_BUFFER_BEGIN_OS_REASON:
		rootKey = @"kcdata_reason";
		break;
	case KCDATA_BUFFER_BEGIN_XNUPOST_CONFIG:
		rootKey = @"xnupost_testconfig";
		break;
	default: {
		if (error)
			*error = GEN_ERROR(KERN_INVALID_VALUE, "invalid magic number");
		return NULL;
		break;
	}
	}
	assert(rootKey != NULL);

	kcdata_iter_t iter = kcdata_iter(dataBuffer, size);

	if (!kcdata_iter_valid(iter)) {
		if (error) {
			*error = GEN_ERROR(KERN_INVALID_OBJECT, "initial item is invalid");
		}
		return NULL;
	}

	NSMutableDictionary * rootObject = [NSMutableDictionary dictionary];
	NSDictionary * retval            = [NSMutableDictionary dictionaryWithObject:rootObject forKey:rootKey];

	/* iterate over each kcdata item */
	KCDATA_ITER_FOREACH(iter)
	{
		_type  = kcdata_iter_type(iter);
		_size  = kcdata_iter_size(iter);
		_flags = kcdata_iter_flags(iter);
		_datap = kcdata_iter_payload(iter);

		if (_type == rootType)
			continue;

		if (_type == KCDATA_TYPE_ARRAY) {
			NSDictionary * dict = parseKCDataArray(iter, error);
			if (!dict)
				return nil;

			ok = mergedict(rootObject, dict, error);
			if (!ok)
				return NULL;

			continue;
		}

		if (_type == KCDATA_TYPE_CONTAINER_BEGIN) {
			NSString * containerID = [NSString stringWithFormat:@"%llu", kcdata_iter_container_id(iter)];
			NSMutableDictionary *container = parseKCDataContainer(&iter, error);
			if (!container)
				return nil;
			assert([container count] == 1);
			for (NSString * k in [container keyEnumerator]) {
				if (rootObject[k] == nil) {
					rootObject[k] = [[NSMutableDictionary alloc] init];
				}
				if (rootObject[k][containerID] != nil) {
					if (error)
						*error = GEN_ERRORF(KERN_INVALID_OBJECT, "repeated container id: %@", containerID);
					return NULL;
				}
				rootObject[k][containerID] = container[k];
			}
			continue;
		}
        
        if (_type == KCDATA_TYPE_TYPEDEFINTION) {
            KCDataType *new_type = getTypeFromTypeDef((struct kcdata_type_definition *)_datap);
            if (new_type != NULL) {
                setKCDataTypeForID([new_type typeID], new_type);
                kcd_type               = getKCDataTypeForID(_type);
                NSDictionary * tmpdict = [kcd_type parseData:_datap ofLength:_size];
                if (!tmpdict) {
                    if (error)
                        *error = GEN_ERRORF(KERN_INVALID_OBJECT, "failed to parse. type=0x%x", (int)_type);
                    return NULL;
                }
                NSString *k = [NSString stringWithFormat:@"typedef[%@]", [new_type name]];
                rootObject[k] = tmpdict;
            }else {
                if (error)
                    *error = GEN_ERRORF(KERN_INVALID_OBJECT, "Failed to parse type definition for type %u", _type);
                return NULL;
            }
            continue;
        }

		kcd_type               = getKCDataTypeForID(_type);
		NSDictionary * tmpdict = [kcd_type parseData:_datap ofLength:_size];
		if (!tmpdict) {
			if (error)
				*error = GEN_ERRORF(KERN_INVALID_OBJECT, "failed to parse. type=0x%x", (int)_type);
			return NULL;
		}
		if (![kcd_type shouldMergeData]) {
			tmpdict = @{[kcd_type name] : tmpdict};
		}
		ok = mergedict(rootObject, tmpdict, error);
		if (!ok)
			return NULL;
	}

	if (KCDATA_ITER_FOREACH_FAILED(iter)) {
		retval = nil;
		if (error) {
			*error = GEN_ERROR(KERN_INVALID_OBJECT, "invalid item or missing buffer end marker");
		}
	}

	return retval;
}
