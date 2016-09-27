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

#ifndef _KDD_H_
#define _KDD_H_

#include <kcdata.h>

#import <Foundation/Foundation.h>

/*!
 * @class KCDataType
 * A basic abstraction that allows for parsing data provided by kernel chunked
 * data library.
 *
 * @discussion
 * Each type object has a name and a method to parse and populate data in memory to
 * a dictionary. The dictionary will have keys as NSStrings and values could be NSObject
 *
 */
@interface KCDataType : NSObject
- (NSDictionary * _Nullable)parseData:(void * _Nonnull)dataBuffer ofLength:(uint32_t)length NS_RETURNS_RETAINED;
- (NSString * _Nonnull)name;
- (unsigned int)typeID;
- (BOOL) shouldMergeData;
@end

/*!
 * @function getKCDataTypeForID
 *
 * @abstract
 * Find a type description for give TypeID
 *
 * @param typeID
 * A unsinged int type specified by the KCDATA.
 *
 * @discussion
 * This routine queries the system for a give type. If a known type description is found it will be used to
 * initialize a KCDataType object. If no known type is found it assumes the data is uint8_t[].
 */
KCDataType * _Nullable getKCDataTypeForID(uint32_t typeID);

/*!
 * @function KCDataTypeNameForID
 *
 * @abstract
 * Get a name for the type.
 *
 * @param typeID
 * A unsinged int type specified by the KCDATA.
 *
 * @return NSString *
 * Returns name of the type. If a type is not found the return
 * value will be string object of the passed value.
 */
NSString * _Nonnull KCDataTypeNameForID(uint32_t typeID) NS_RETURNS_NOT_RETAINED;

/*!
 * @function parseKCDataArray
 *
 * @abstract
 * Parse the given KCDATA buffer as an Array of element. The buffer should begin with header
 * of type KCDATA_TYPE_ARRAY.
 *
 * @param iter
 * An iterator into the input buffer
 *
 * @param error
 * Error return.
 *
 * @return
 * A dictionary with  key specifying name of the type of each elements and value is an Array of data.
 *
 */

NSMutableDictionary * _Nullable parseKCDataArray(kcdata_iter_t iter, NSError * _Nullable * _Nullable error) NS_RETURNS_RETAINED;

/*!
 * @function parseKCDataContainer
 *
 * @abstract
 * Parse the given KCDATA buffer as a container and convert each sub structures as fields in a dictionary.
 *
 * @param iter
 * A pointer to an iterator into the input buffer.  The iterator will be updated
 * to point at the container end marker.
 *
 * @param error
 * Error return.
 *
 * @return NSDictionary *
 * containing each field and potentially sub containers within the provided container.
 *
 * @discussion
 * This function tries to parse one container. If it encounters sub containers
 * they will be parsed and collected within the same dictionary.
 * Other data type fields will also be parsed based on their type. 
 *
 */

NSMutableDictionary * _Nullable parseKCDataContainer(kcdata_iter_t * _Nonnull iter_p, NSError * _Nullable * _Nullable error) NS_RETURNS_RETAINED;

/*!
 * @function parseKCDataBuffer
 *
 * @abstract
 * Parse complete KCDATA buffer into NSMutableDictionary. Depending on the size of buffer and elements
 * this routine makes allocations for objects and strings.
 *
 * @param dataBuffer
 * A pointer in memory where KCDATA is allocated. The data should be of type
 * kcdata_item_t and have KCDATA_BUFFER_BEGIN_* tags (see kern_cdata.h)
 *
 * @param size
 * Size of the buffer as provided by kernel api.
 *
 * @return NSDictionary *
 * Dictionary with key:value pairs for each data item. KCDATA_TYPE_ARRAY and KCDATA_TYPE_CONTAINERS will
 * grouped and recursed as much possible. For unknown types NSData object is returned with "Type_0x123"
 * as keys.
 *
 * @discussion
 * This function tries to parse KCDATA buffer with known type description. If an error occurs,
 * NULL is returned, and error (if not NULL) will have the error string.
 *
 * Iff the buffer does begin with a known kcdata magic number, the error code
 * will be KERN_INVALID_VALUE.
 *
 */
NSDictionary * _Nullable parseKCDataBuffer(void * _Nonnull dataBuffer, uint32_t size, NSError * _Nullable * _Nullable error) NS_RETURNS_RETAINED;


#endif /* _KDD_H_ */
