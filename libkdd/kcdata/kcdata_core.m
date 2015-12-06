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

#include <kern/kern_cdata.h>
#import <Foundation/Foundation.h>
#import "kdd.h"
#import "KCDBasicTypeDescription.h"
#import "KCDStructTypeDescription.h"

#define MAX_KCDATATYPE_BUFFER_SIZE 2048
extern struct kcdata_type_definition *kcdata_get_typedescription(unsigned type_id, uint8_t *buffer, uint32_t buffer_size);


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
	if (typeDef->kct_num_elements == 1) {
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
		}
		return retval;
	}
	return nil;
}

KCDataType *
getKCDataTypeForID(uint32_t typeID)
{
	static dispatch_once_t onceToken;
	static NSMutableDictionary * knownTypes = nil;
	dispatch_once(&onceToken, ^{
		if (!knownTypes) {
			knownTypes = [[NSMutableDictionary alloc] init];
		}
	});
	NSNumber * type = [NSNumber numberWithUnsignedInt:typeID];
	if (!knownTypes[type]) {
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

NSString *
KCDataTypeNameForID(uint32_t typeID)
{
	NSString * retval = [NSString stringWithFormat:@"%u", typeID];
	KCDataType * t = getKCDataTypeForID(typeID);

	if (![[t name] containsString:@"Type_"]) {
		retval = [t name];
	}
	return retval;
}

NSMutableDictionary *
parseKCDataArray(void * dataBuffer)
{
	uint32_t typeID = KCDATA_ITEM_ARRAY_GET_EL_TYPE(dataBuffer);
	uint32_t count = KCDATA_ITEM_ARRAY_GET_EL_COUNT(dataBuffer);
	uint32_t size = KCDATA_ITEM_ARRAY_GET_EL_SIZE(dataBuffer);
	uint8_t * buffer = (uint8_t *)KCDATA_ITEM_DATA_PTR(dataBuffer);
	KCDataType * datatype = getKCDataTypeForID(typeID);
	NSMutableDictionary * retval = [[NSMutableDictionary alloc] initWithCapacity:1];
	NSMutableArray * arr = [[NSMutableArray alloc] initWithCapacity:count];
	retval[[datatype name]] = arr;
	NSMutableDictionary * tmpdict = NULL;
	for (uint32_t i = 0; i < count; i++) {
		tmpdict = [datatype parseData:(void *)&buffer[i * size] ofLength:size];
		[arr addObject:tmpdict];
	}
	return retval;
}

NSMutableDictionary *
parseKCDataContainer(void * dataBuffer, uint32_t * bytesParsed)
{
	if (bytesParsed == NULL)
		return nil;
	assert(KCDATA_ITEM_TYPE(dataBuffer) == KCDATA_TYPE_CONTAINER_BEGIN);
	uint64_t containerID = KCDATA_CONTAINER_ID(dataBuffer);

	/* setup collection object for sub containers */
	NSMutableDictionary * sub_containers = [[NSMutableDictionary alloc] init];
	NSMutableDictionary * retval = [[NSMutableDictionary alloc] init];
	NSMutableDictionary * container = [[NSMutableDictionary alloc] init];
	struct kcdata_item * buffer = (struct kcdata_item *)KCDATA_ITEM_NEXT_HEADER(dataBuffer);
	KCDataType * tmptype;
	uint32_t _t;
	void * _d;
	NSMutableDictionary * tmpdict;
	retval[KCDataTypeNameForID(kcdata_get_container_type(dataBuffer))] = container;

	KCDATA_ITEM_FOREACH(buffer)
	{
		_t = KCDATA_ITEM_TYPE(buffer);
		_d = KCDATA_ITEM_DATA_PTR(buffer);
		if (_t == KCDATA_TYPE_CONTAINER_END) {
			if (KCDATA_CONTAINER_ID(buffer) == containerID) {
				break;
			}
			continue;
		}

		if (_t == KCDATA_TYPE_ARRAY) {
			tmpdict = parseKCDataArray(buffer);
			[container addEntriesFromDictionary:tmpdict];
			continue;
		}

		if (_t == KCDATA_TYPE_CONTAINER_BEGIN) {
			uint32_t container_size = 0;
			tmpdict = parseKCDataContainer(buffer, &container_size);
			NSString * subcontainerID = [NSString stringWithFormat:@"%llu", KCDATA_CONTAINER_ID(buffer)];
			NSString * k_desc = nil;
			assert([tmpdict count] == 1);
			for (NSString * k in [tmpdict keyEnumerator]) {
				k_desc = k;
				if ([k intValue] != 0)
					k_desc = KCDataTypeNameForID([k intValue]);

				if ([sub_containers objectForKey:k_desc] == nil) {
					sub_containers[k_desc] = [[NSMutableDictionary alloc] init];
				}
				sub_containers[k_desc][subcontainerID] = tmpdict[k];
			}
			buffer = (struct kcdata_item *)((uintptr_t)buffer + container_size);
			if (KCDATA_ITEM_TYPE(buffer) == KCDATA_TYPE_BUFFER_END) {
				break;
			}
			continue;
		}

		tmptype = getKCDataTypeForID(_t);
		tmpdict = [tmptype parseData:_d ofLength:KCDATA_ITEM_SIZE(buffer)];
		if ([tmpdict count] == 1)
			[container addEntriesFromDictionary:tmpdict];
		else
			container[[tmptype name]] = tmpdict;
	}
	[container addEntriesFromDictionary:sub_containers];
	*bytesParsed = (uint32_t)((uintptr_t)buffer - (uintptr_t)dataBuffer);
	return retval;
}
