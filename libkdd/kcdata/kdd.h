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
- (NSMutableDictionary *)parseData:(void *)dataBuffer ofLength:(uint32_t)length;
- (NSString *)name;
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
KCDataType * getKCDataTypeForID(uint32_t typeID);

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
NSString * KCDataTypeNameForID(uint32_t typeID);

/*!
 * @function parseKCDataArray
 *
 * @abstract
 * Parse the given KCDATA buffer as an Array of element. The buffer should begin with header
 * of type KCDATA_TYPE_ARRAY.
 *
 * @param dataBuffer
 * A pointer in memory where KCDATA is allocated.
 *
 * @return
 * A dictionary with  key specifying name of the type of each elements and value is an Array of data.
 *
 */

NSMutableDictionary * parseKCDataArray(void * dataBuffer);

/*!
 * @function parseKCDataContainer
 *
 * @abstract
 * Parse the given KCDATA buffer as a container and convert each sub structures as fields in a dictionary.
 *
 * @param dataBuffer
 * A pointer in memory where KCDATA is allocated. The data should be pointing to
 * kcdata_item_t of type KCDATA_TYPE_CONTAINER_BEGIN
 *
 * @param bytesParsed
 * A pointer to uint32_t field where the routine will save the number of bytes parsed for this container.
 *
 * @return NSDictionary *
 * containing each field and potentially sub containers within the provided container.
 *
 * @discussion
 * This function tries to parse one container. If it encounters sub containers
 * they will be parsed and collected within the same dictionary.
 * Other data type fields will also be parsed based on their type. The bytesParsed
 * param is populated with the number of bytes processed. With this return value the caller can
 * advance its buffer_read position as
 *   buffer = (kcdata_item_t)((uintptr_t)buffer + bytesParsed); //advance to next KCDATA_HEADER.
 * Note: Keep in mind that the next header may be KCDATA_TYPE_BUFFER_END.
 *
 * A sample usage call can be:
 * KCDATA_ITEM_FOREACH(buffer) {
 *     if(KCDATA_ITEM_TYPE(buffer) == KCDATA_TYPE_CONTAINER_BEGIN) {
 *         uint32_t container_size = 0;
 *         NSMutableDictionary *parsedContainer = parseKCDataContainer(buffer, &container_size);
 *         NSLog(@"Parsed container has : %@", parsedContainer);
 *         buffer = (kcdata_item_t) ((uintptr_t)buffer + container_size);
 *         if(KCDATA_ITEM_TYPE(buffer) == KCDATA_TYPE_BUFFER_END)
 *             break;
 *     }
 * }
 *
 */
NSMutableDictionary * parseKCDataContainer(void * dataBuffer, uint32_t * bytesParsed);

#endif /* _KDD_H_ */
