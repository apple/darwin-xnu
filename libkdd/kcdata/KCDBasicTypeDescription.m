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

#import "KCDBasicTypeDescription.h"

@interface
KCDBasicTypeDescription () {
	int _typeID;
	uint32_t _size;
	uint32_t _count;
	NSString * _name;
	struct kcdata_subtype_descriptor _subtype_desc;
}

@end

@implementation KCDBasicTypeDescription

- (id)initWithKCTypeDesc:(kcdata_subtype_descriptor_t)sub_type_desc
{
	_typeID = sub_type_desc->kcs_elem_type;
	_count = kcs_get_elem_count(sub_type_desc);
	_size = kcs_get_elem_size(sub_type_desc);

	memcpy(&_subtype_desc, sub_type_desc, sizeof(_subtype_desc));
	_name = [NSString stringWithFormat:@"%s", _subtype_desc.kcs_name];

	return self;
}

- (id)createDefaultForType:(uint32_t)typeID
{
	struct kcdata_subtype_descriptor subtype;
	subtype.kcs_flags = KCS_SUBTYPE_FLAGS_ARRAY;
	subtype.kcs_elem_type = KC_ST_UINT8;
	subtype.kcs_elem_offset = 0;
	subtype.kcs_elem_size = KCS_SUBTYPE_PACK_SIZE(UINT16_MAX, (uint16_t)sizeof(uint8_t));
	subtype.kcs_name[0] = '\0';
	(void)[self initWithKCTypeDesc:&subtype];
	_name = [NSString stringWithFormat:@"Type_0x%x", typeID];
	return self;
}

- (NSObject *)objectForType:(kctype_subtype_t)elem_type withData:(uint8_t *)data
{
	NSObject * obj;

	switch (elem_type) {
	case KC_ST_CHAR: obj = [NSString stringWithFormat:@"%c", *(char *)data]; break;
	case KC_ST_INT8: obj = [NSNumber numberWithInt:*(int8_t *)data]; break;
	case KC_ST_UINT8: obj = [NSNumber numberWithInt:*(uint8_t *)data]; break;
	case KC_ST_INT16: obj = [NSNumber numberWithShort:*(int16_t *)data]; break;
	case KC_ST_UINT16: obj = [NSNumber numberWithUnsignedShort:*(uint16_t *)data]; break;
	case KC_ST_INT32: obj = [NSNumber numberWithInt:*(int32_t *)data]; break;
	case KC_ST_UINT32: obj = [NSNumber numberWithUnsignedInt:*(uint32_t *)data]; break;
	case KC_ST_INT64: obj = [NSNumber numberWithLongLong:*(int64_t *)data]; break;
	case KC_ST_UINT64: obj = [NSNumber numberWithUnsignedLongLong:*(uint64_t *)data]; break;

	default: obj = @"<Unknown error occurred>"; break;
	}

	return obj;
}

- (NSMutableDictionary *)parseData:(void *)dataBuffer ofLength:(uint32_t)length
{
	NSMutableDictionary * retval = [[NSMutableDictionary alloc] init];
	uint8_t * data = (uint8_t *)dataBuffer;
	uint32_t elem_count = MIN(_count, length / (_size / _count));
	uint32_t elem_size = _size / _count;
	if (_count == 1) {
		retval[_name] = [self objectForType:_subtype_desc.kcs_elem_type withData:&data[_subtype_desc.kcs_elem_offset]];
	} else if (_subtype_desc.kcs_elem_type == KC_ST_CHAR) {
		retval[_name] = [NSString stringWithFormat:@"%s", (char *)&data[_subtype_desc.kcs_elem_offset]];
	} else {
		NSMutableArray * objArray = [NSMutableArray arrayWithCapacity:elem_count];
		for (unsigned int i = 0; i < elem_count; i++) {
			[objArray addObject:[self objectForType:_subtype_desc.kcs_elem_type
			                                  withData:&data[(_subtype_desc.kcs_elem_offset + (elem_size * i))]]];
		}
		retval[_name] = objArray;
	}
	return retval;
}

- (NSString *)description
{
	return [NSString stringWithFormat:@"type: %d => \"%@\" ", [self typeID], [self name]];
}

- (NSString *)name
{
	return _name;
}

- (uint32_t)count
{
	return _count;
}

- (int)typeID
{
	return _typeID;
}

@end
