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

#ifndef _KERN_CDATA_H_
#define _KERN_CDATA_H_

#include <stdint.h>
#include <mach/mach_types.h>

#define KCDATA_DESC_MAXLEN          32      /* including NULL byte at end */

struct kcdata_item {
	uint32_t type;
	uint32_t size; /* len(data)  */
	uint64_t flags;
#ifndef KERNEL
	char data[];  /* must be at the end */
#endif
};

typedef struct kcdata_item * kcdata_item_t;

enum KCDATA_SUBTYPE_TYPES { KC_ST_CHAR = 1, KC_ST_INT8, KC_ST_UINT8, KC_ST_INT16, KC_ST_UINT16, KC_ST_INT32, KC_ST_UINT32, KC_ST_INT64, KC_ST_UINT64 };
typedef enum KCDATA_SUBTYPE_TYPES kctype_subtype_t;

/*
 * A subtype description structure that defines
 * how a compound data is laid out in memory. This
 * provides on the fly definition of types and consumption
 * by the parser.
 */
struct kcdata_subtype_descriptor {
	uint8_t              kcs_flags;
#define KCS_SUBTYPE_FLAGS_NONE    0x0
#define KCS_SUBTYPE_FLAGS_ARRAY   0x1
	uint8_t              kcs_elem_type;                 /* restricted to kctype_subtype_t */
	uint16_t             kcs_elem_offset;               /* offset in struct where data is found */
	uint32_t             kcs_elem_size;                 /* size of element (or) packed state for array type */
	char                 kcs_name[KCDATA_DESC_MAXLEN];  /* max 31 bytes for name of field */
};

typedef struct kcdata_subtype_descriptor * kcdata_subtype_descriptor_t;

/*
 * In case of array of basic c types in kctype_subtype_t,
 * size is packed in lower 16 bits and
 * count is packed in upper 16 bits of kcs_elem_size field.
 */
#define KCS_SUBTYPE_PACK_SIZE(e_count,e_size)      (((e_count) & 0xffff) << 16 | ((e_size) & 0xffff))

static inline uint32_t
kcs_get_elem_size(kcdata_subtype_descriptor_t d)
{
	if (d->kcs_flags & KCS_SUBTYPE_FLAGS_ARRAY) {
		/* size is composed as ((count &0xffff)<<16 | (elem_size & 0xffff)) */
		return (uint32_t)((d->kcs_elem_size & 0xffff) * ((d->kcs_elem_size & 0xffff0000)>>16));
	}
	return d->kcs_elem_size;
}

static inline uint32_t
kcs_get_elem_count(kcdata_subtype_descriptor_t d)
{
	if (d->kcs_flags & KCS_SUBTYPE_FLAGS_ARRAY)
		return (d->kcs_elem_size >> 16) & 0xffff;
	return 1;
}

static inline kern_return_t
kcs_set_elem_size(kcdata_subtype_descriptor_t d, uint32_t size, uint32_t count)
{
	if (count > 1) {
		/* means we are setting up an array */
		if (size > 0xffff || count > 0xffff)
			return KERN_INVALID_ARGUMENT;
		d->kcs_elem_size = ((count & 0xffff) << 16 | (size & 0xffff));
	}
	else
	{
		d->kcs_elem_size = size;
	}
	return KERN_SUCCESS;
}

struct kcdata_type_definition {
	uint32_t kct_type_identifier;
	uint32_t kct_num_elements;
	char kct_name[KCDATA_DESC_MAXLEN];
#ifndef KERNEL
	struct kcdata_subtype_descriptor kct_elements[];
#endif
};

/* chunk type definitions. 0 - 0x7ff are reserved  and defined here
 * NOTE: Please update libkdd/kcdata/kcdtypes.c if you make any changes
 * in STACKSHOT_KCTYPE_* types.
 */

/*
 * Types with description value.
 * these will have KCDATA_DESC_MAXLEN-1 length string description
 * and rest of KCDATA_ITEM_SIZE() - KCDATA_DESC_MAXLEN bytes as data
 */
#define KCDATA_TYPE_INVALID              0x0
#define KCDATA_TYPE_STRING_DESC          0x1
#define KCDATA_TYPE_UINT32_DESC          0x2
#define KCDATA_TYPE_UINT64_DESC          0x3
#define KCDATA_TYPE_INT32_DESC           0x4
#define KCDATA_TYPE_INT64_DESC           0x5
#define KCDATA_TYPE_BINDATA_DESC         0x6

/*
 * Compound type definitions
 */
#define KCDATA_TYPE_ARRAY                0x11       /* Array of data */
#define KCDATA_TYPE_TYPEDEFINTION        0x12       /* Meta type that describes a type on the fly. */
#define KCDATA_TYPE_CONTAINER_BEGIN      0x13       /* Container type which has corresponding CONTAINER_END header.
                                                     * KCDATA_TYPE_CONTAINER_BEGIN has type in the data segment.
                                                     * Both headers have (uint64_t) ID for matching up nested data.
                                                     */
#define KCDATA_TYPE_CONTAINER_END        0x14


/*
 * Generic data types that are most commonly used
 */
#define KCDATA_TYPE_LIBRARY_LOADINFO     0x30       /* struct dyld_uuid_info_32 */
#define KCDATA_TYPE_LIBRARY_LOADINFO64   0x31       /* struct dyld_uuid_info_64 */
#define KCDATA_TYPE_TIMEBASE             0x32       /* struct mach_timebase_info */
#define KCDATA_TYPE_MACH_ABSOLUTE_TIME   0x33       /* uint64_t */
#define KCDATA_TYPE_TIMEVAL              0x34       /* struct timeval64 */
#define KCDATA_TYPE_USECS_SINCE_EPOCH    0x35       /* time in usecs uint64_t */

#define KCDATA_TYPE_BUFFER_END      0xF19158ED

/* MAGIC numbers defined for each class of chunked data */
#define KCDATA_BUFFER_BEGIN_CRASHINFO  0xDEADF157   /* owner: corpses/task_corpse.h */
						    /* type-range: 0x800 - 0x8ff */
#define KCDATA_BUFFER_BEGIN_STACKSHOT  0x59a25807   /* owner: sys/stackshot.h */
						    /* type-range: 0x900 - 0x9ff */

/* next type range number available 0x1000 */

/* Common MACROS and library functions */
/* make header = sizeof(type, flags, size) */
#define KCDATA_ITEM_HEADER_SIZE         (sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint64_t))
#define KCDATA_ITEM_TYPE(item)          (((kcdata_item_t)(item))->type)
#define KCDATA_ITEM_SIZE(item)          (((kcdata_item_t)(item))->size)
#define KCDATA_ITEM_FLAGS(item)          (((kcdata_item_t)(item))->flags)

#define KCDATA_ITEM_ARRAY_GET_EL_TYPE(item)   ((KCDATA_ITEM_FLAGS(item) >> 32) & UINT32_MAX)
#define KCDATA_ITEM_ARRAY_GET_EL_COUNT(item)  (KCDATA_ITEM_FLAGS(item) & UINT32_MAX)
#define KCDATA_ITEM_ARRAY_GET_EL_SIZE(item)   (KCDATA_ITEM_SIZE(item) / KCDATA_ITEM_ARRAY_GET_EL_COUNT(item))

#define KCDATA_CONTAINER_ID(item)             ((uint64_t)KCDATA_ITEM_FLAGS(item))

#define KCDATA_ITEM_NEXT_HEADER(item)   ((kcdata_item_t)((uint64_t)((uintptr_t)(item)) + KCDATA_ITEM_HEADER_SIZE + KCDATA_ITEM_SIZE(item)))

#define KCDATA_ITEM_FOREACH(head) for (; KCDATA_ITEM_TYPE(head) != KCDATA_TYPE_BUFFER_END; (head) = KCDATA_ITEM_NEXT_HEADER(head))

static inline kcdata_item_t
KCDATA_ITEM_FIND_TYPE(kcdata_item_t head, uint32_t type)
{
	KCDATA_ITEM_FOREACH(head)
	{
		if (KCDATA_ITEM_TYPE(head) == type) {
			break;
		}
	}
	return (KCDATA_ITEM_TYPE(head) == type) ? (kcdata_item_t)head : 0;
}

#ifndef KERNEL
#define KCDATA_ITEM_DATA_PTR(item)      (&((kcdata_item_t)(item))->data)

static inline uint32_t kcdata_get_container_type(kcdata_item_t buffer) {
	if (KCDATA_ITEM_TYPE(buffer) == KCDATA_TYPE_CONTAINER_BEGIN)
		return *(uint32_t *)KCDATA_ITEM_DATA_PTR(buffer);
	return 0;
}

static inline void kcdata_get_data_with_desc(kcdata_item_t buffer, char **desc_ptr, void **data_ptr) {
	if (desc_ptr)
		*desc_ptr = (char *)KCDATA_ITEM_DATA_PTR(buffer);
	if (data_ptr)
		*data_ptr = (void *)((uintptr_t)KCDATA_ITEM_DATA_PTR(buffer) + KCDATA_DESC_MAXLEN);
}
#endif /* KERNEL */

#ifdef XNU_KERNEL_PRIVATE

/* Structure to save information about corpse data */
struct kcdata_descriptor {
	uint32_t            kcd_length;
	uint32_t            kcd_flags;
#define KCFLAG_USE_MEMCOPY  0x0
#define KCFLAG_USE_COPYOUT  0x1
	mach_vm_address_t   kcd_addr_begin;
	mach_vm_address_t   kcd_addr_end;
};

typedef struct kcdata_descriptor * kcdata_descriptor_t;

kcdata_descriptor_t kcdata_memory_alloc_init(mach_vm_address_t crash_data_p, unsigned data_type, unsigned size, unsigned flags);
kern_return_t kcdata_memory_static_init(kcdata_descriptor_t data, mach_vm_address_t buffer_addr_p, unsigned data_type, unsigned size, unsigned flags);
kern_return_t kcdata_memory_destroy(kcdata_descriptor_t data);
uint64_t kcdata_memory_get_used_bytes(kcdata_descriptor_t kcd);
kern_return_t kcdata_memcpy(kcdata_descriptor_t data, mach_vm_address_t dst_addr, void *src_addr, uint32_t size);

kern_return_t kcdata_get_memory_addr(kcdata_descriptor_t data, uint32_t type, uint32_t size, mach_vm_address_t *user_addr);
kern_return_t kcdata_get_memory_addr_for_array(kcdata_descriptor_t data, uint32_t type_of_element, uint32_t size_of_element, uint32_t count, mach_vm_address_t *user_addr);
kern_return_t kcdata_add_container_marker(kcdata_descriptor_t data, uint32_t header_type, uint32_t container_type, uint64_t identifier);
kern_return_t kcdata_add_type_definition(kcdata_descriptor_t data, uint32_t type_id, char *type_name, struct kcdata_subtype_descriptor *elements_array_addr, uint32_t elements_count);


kern_return_t kcdata_add_uint64_with_description(kcdata_descriptor_t crashinfo, uint64_t data, const char *description);
kern_return_t kcdata_add_uint32_with_description(kcdata_descriptor_t crashinfo, uint32_t data, const char *description);

#endif /* XNU_KERNEL_PRIVATE */

#endif /* _KERN_CDATA_H_ */
