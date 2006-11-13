/*
 * Copyright (c) 2006 Apple Computer, Inc. All Rights Reserved.
 * 
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
 * http://www.opensource.apple.com/apsl/ and read it before using this 
 * file.
 *
 * The Original Code and all software distributed under the License are 
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, 
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. 
 * Please see the License for the specific language governing rights and 
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */

#ifndef __VN_SHADOW_H__
#define __VN_SHADOW_H__

#include <sys/appleapiopts.h>

#ifdef __APPLE_API_PRIVATE

typedef struct shadow_map shadow_map_t;

boolean_t
shadow_map_read(shadow_map_t * map, u_long block_offset, u_long block_count,
		u_long * incr_block_offset, u_long * incr_block_count);
boolean_t
shadow_map_write(shadow_map_t * map, u_long block_offset, u_long block_count,
		 u_long * incr_block_offset, u_long * incr_block_count);
boolean_t
shadow_map_is_written(shadow_map_t * map, u_long block_offset);

u_long
shadow_map_shadow_size(shadow_map_t * map);

shadow_map_t *
shadow_map_create(off_t file_size, off_t shadow_size, 
		  unsigned long band_size, unsigned long block_size);
void
shadow_map_free(shadow_map_t * map);

#endif /* __APPLE_API_PRIVATE */
#endif /* __VN_SHADOW_H__ */



