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

#include <kern/assert.h>
#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/vm_param.h>
#include <kern/kern_types.h>
#include <kern/mach_param.h>
#include <kern/thread.h>
#include <kern/task.h>
#include <kern/kern_cdata.h>
#include <kern/kalloc.h>
#include <mach/mach_vm.h>

static kern_return_t kcdata_get_memory_addr_with_flavor(kcdata_descriptor_t data, uint32_t type, uint32_t size, uint64_t flags, mach_vm_address_t *user_addr);

/*
 * Estimates how large of a buffer that should be allocated for a buffer that will contain
 * num_items items of known types with overall length payload_size.
 *
 * NOTE: This function will not give an accurate estimate for buffers that will
 * 	 contain unknown types (those with string descriptions).
 */
uint32_t kcdata_estimate_required_buffer_size(uint32_t num_items, uint32_t payload_size)
{
	/*
	 * In the worst case each item will need (KCDATA_ALIGNMENT_SIZE - 1) padding
	 */
	uint32_t max_padding_bytes = num_items * (KCDATA_ALIGNMENT_SIZE - 1);
	uint32_t item_description_bytes = num_items * sizeof(struct kcdata_item);
	uint32_t begin_and_end_marker_bytes = 2 * sizeof(struct kcdata_item);

	return max_padding_bytes + item_description_bytes + begin_and_end_marker_bytes + payload_size;
}

kcdata_descriptor_t kcdata_memory_alloc_init(mach_vm_address_t buffer_addr_p, unsigned data_type, unsigned size, unsigned flags)
{
	kcdata_descriptor_t data = NULL;
	mach_vm_address_t user_addr = 0;

	data = kalloc(sizeof(struct kcdata_descriptor));
	if (data == NULL) {
		return NULL;
	}
	bzero(data, sizeof(struct kcdata_descriptor));
	data->kcd_addr_begin = buffer_addr_p;
	data->kcd_addr_end = buffer_addr_p;
	data->kcd_flags = (flags & KCFLAG_USE_COPYOUT)? KCFLAG_USE_COPYOUT : KCFLAG_USE_MEMCOPY;
	data->kcd_length = size;

	/* Initialize the BEGIN header */
	if (KERN_SUCCESS != kcdata_get_memory_addr(data, data_type, 0, &user_addr)){
		kcdata_memory_destroy(data);
		return NULL;
	}

	return data;
}

kern_return_t kcdata_memory_static_init(kcdata_descriptor_t data, mach_vm_address_t buffer_addr_p, unsigned data_type, unsigned size, unsigned flags)
{
	mach_vm_address_t user_addr = 0;

	if (data == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	bzero(data, sizeof(struct kcdata_descriptor));
	data->kcd_addr_begin = buffer_addr_p;
	data->kcd_addr_end = buffer_addr_p;
	data->kcd_flags = (flags & KCFLAG_USE_COPYOUT)? KCFLAG_USE_COPYOUT : KCFLAG_USE_MEMCOPY;
	data->kcd_length = size;

	/* Initialize the BEGIN header */
	return kcdata_get_memory_addr(data, data_type, 0, &user_addr);
}

void *kcdata_memory_get_begin_addr(kcdata_descriptor_t data)
{
	if (data == NULL) {
		return NULL;
	}

	return (void *)data->kcd_addr_begin;
}

uint64_t kcdata_memory_get_used_bytes(kcdata_descriptor_t kcd)
{
	assert(kcd != NULL);
	return ((uint64_t)kcd->kcd_addr_end - (uint64_t)kcd->kcd_addr_begin) + sizeof(struct kcdata_item);
}

/*
 * Free up the memory associated with kcdata
 */
kern_return_t kcdata_memory_destroy(kcdata_descriptor_t data)
{
	if (!data) {
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 * data->kcd_addr_begin points to memory in not tracked by
	 * kcdata lib. So not clearing that here.
	 */
	kfree(data, sizeof(struct kcdata_descriptor));
	return KERN_SUCCESS;
}



/*
 * Routine: kcdata_get_memory_addr
 * Desc: get memory address in the userspace memory for corpse info
 *       NOTE: The caller is responsible for zeroing the resulting memory or
 *             using other means to mark memory if it has failed populating the
 *             data in middle of operation.
 * params:  data - pointer describing the crash info allocation
 *	        type - type of data to be put. See corpse.h for defined types
 *          size - size requested. The header describes this size
 * returns: mach_vm_address_t address in user memory for copyout().
 */
kern_return_t
kcdata_get_memory_addr(kcdata_descriptor_t data, uint32_t type, uint32_t size, mach_vm_address_t * user_addr)
{
	/* record number of padding bytes as lower 4 bits of flags */
	uint64_t flags = (KCDATA_FLAGS_STRUCT_PADDING_MASK & kcdata_calc_padding(size)) | KCDATA_FLAGS_STRUCT_HAS_PADDING;
	return kcdata_get_memory_addr_with_flavor(data, type, size, flags, user_addr);
}

/*
 * Routine: kcdata_add_buffer_end
 *
 * Desc: Write buffer end marker.  This does not advance the end pointer in the
 * kcdata_descriptor_t, so it may be used conservatively before additional data
 * is added, as long as it is at least called after the last time data is added.
 *
 * params:  data - pointer describing the crash info allocation
 */

kern_return_t
kcdata_write_buffer_end(kcdata_descriptor_t data)
{
	struct kcdata_item info;
	bzero(&info, sizeof(info));
	info.type = KCDATA_TYPE_BUFFER_END;
	info.size = 0;
	return kcdata_memcpy(data, data->kcd_addr_end, &info, sizeof(info));
}

/*
 * Routine: kcdata_get_memory_addr_with_flavor
 * Desc: internal function with flags field. See documentation for kcdata_get_memory_addr for details
 */

static kern_return_t kcdata_get_memory_addr_with_flavor(
		kcdata_descriptor_t data,
		uint32_t type,
		uint32_t size,
		uint64_t flags,
		mach_vm_address_t *user_addr)
{
	kern_return_t kr;
	struct kcdata_item info;

	uint32_t orig_size = size;
	/* make sure 16 byte aligned */
	uint32_t padding = kcdata_calc_padding(size);
	size += padding;
	uint32_t total_size  = size + sizeof(info);

	if (user_addr == NULL || data == NULL || total_size + sizeof(info) < orig_size) {
		return KERN_INVALID_ARGUMENT;
	}

	bzero(&info, sizeof(info));
	info.type  = type;
	info.size = size;
	info.flags = flags;

	/* check available memory, including trailer size for KCDATA_TYPE_BUFFER_END */
	if (total_size + sizeof(info) > data->kcd_length ||
		data->kcd_length - (total_size + sizeof(info)) < data->kcd_addr_end - data->kcd_addr_begin) {
		return KERN_RESOURCE_SHORTAGE;
	}

	kr = kcdata_memcpy(data, data->kcd_addr_end, &info, sizeof(info));
	if (kr)
		return kr;

	data->kcd_addr_end += sizeof(info);

	if (padding) {
		kr = kcdata_bzero(data, data->kcd_addr_end + size - padding, padding);
		if (kr)
			return kr;
	}

	*user_addr = data->kcd_addr_end;
	data->kcd_addr_end += size;

	if (!(data->kcd_flags & KCFLAG_NO_AUTO_ENDBUFFER)) {
		/* setup the end header as well */
		return kcdata_write_buffer_end(data);
	} else {
		return KERN_SUCCESS;
	}
}

/*
 * Routine: kcdata_get_memory_addr_for_array
 * Desc: get memory address in the userspace memory for corpse info
 *       NOTE: The caller is responsible to zero the resulting memory or
 *             user other means to mark memory if it has failed populating the
 *             data in middle of operation.
 * params:  data - pointer describing the crash info allocation
 *          type_of_element - type of data to be put. See kern_cdata.h for defined types
 *          size_of_element - size of element. The header describes this size
 *          count - num of elements in array.
 * returns: mach_vm_address_t address in user memory for copyout().
 */

kern_return_t kcdata_get_memory_addr_for_array(
		kcdata_descriptor_t data,
		uint32_t type_of_element,
		uint32_t size_of_element,
		uint32_t count,
		mach_vm_address_t *user_addr)
{
	/* for arrays we record the number of padding bytes as the low-order 4 bits
	 * of the type field.  KCDATA_TYPE_ARRAY_PAD{x} means x bytes of pad. */
	uint64_t flags      = type_of_element;
	flags               = (flags << 32) | count;
	uint32_t total_size = count * size_of_element;
	uint32_t pad        = kcdata_calc_padding(total_size);

	return kcdata_get_memory_addr_with_flavor(data, KCDATA_TYPE_ARRAY_PAD0 | pad, total_size, flags, user_addr);
}

/*
 * Routine: kcdata_add_container_marker
 * Desc: Add a container marker in the buffer for type and identifier.
 * params:  data - pointer describing the crash info allocation
 *          header_type - one of (KCDATA_TYPE_CONTAINER_BEGIN ,KCDATA_TYPE_CONTAINER_END)
 *          container_type - type of data to be put. See kern_cdata.h for defined types
 *          identifier - unique identifier. This is required to match nested containers.
 * returns: return value of kcdata_get_memory_addr()
 */

kern_return_t kcdata_add_container_marker(
		kcdata_descriptor_t data,
		uint32_t header_type,
		uint32_t container_type,
		uint64_t identifier)
{
	mach_vm_address_t user_addr;
	kern_return_t kr;
	assert(header_type == KCDATA_TYPE_CONTAINER_END || header_type == KCDATA_TYPE_CONTAINER_BEGIN);
	uint32_t data_size = (header_type == KCDATA_TYPE_CONTAINER_BEGIN)? sizeof(uint32_t): 0;
	kr = kcdata_get_memory_addr_with_flavor(data, header_type, data_size, identifier, &user_addr);
	if (kr != KERN_SUCCESS)
		return kr;

	if (data_size)
		kr = kcdata_memcpy(data, user_addr, &container_type, data_size);
	return kr;
}

/*
 * Routine: kcdata_undo_addcontainer_begin
 * Desc: call this after adding a container begin but before adding anything else to revert.
 */
kern_return_t
kcdata_undo_add_container_begin(kcdata_descriptor_t data)
{
	/*
	 * the payload of a container begin is a single uint64_t.  It is padded out
	 * to 16 bytes.
	 */
	const mach_vm_address_t padded_payload_size = 16;
	data->kcd_addr_end -= sizeof(struct kcdata_item) + padded_payload_size;

	if (!(data->kcd_flags & KCFLAG_NO_AUTO_ENDBUFFER)) {
		/* setup the end header as well */
		return kcdata_write_buffer_end(data);
	} else {
		return KERN_SUCCESS;
	}
}

/*
 * Routine: kcdata_memcpy
 * Desc: a common function to copy data out based on either copyout or memcopy flags
 * params:  data - pointer describing the kcdata buffer
 *          dst_addr - destination address
 *          src_addr - source address
 *          size - size in bytes to copy.
 * returns: KERN_NO_ACCESS if copyout fails.
 */

kern_return_t kcdata_memcpy(kcdata_descriptor_t data, mach_vm_address_t dst_addr, const void *src_addr, uint32_t size)
{
	if (data->kcd_flags & KCFLAG_USE_COPYOUT) {
		if (copyout(src_addr, dst_addr, size))
			return KERN_NO_ACCESS;
	} else {
		memcpy((void *)dst_addr, src_addr, size);
	}
	return KERN_SUCCESS;
}

/*
 * Routine: kcdata_bzero
 * Desc: zero out a portion of a kcdata buffer.
 */
kern_return_t
kcdata_bzero(kcdata_descriptor_t data, mach_vm_address_t dst_addr, uint32_t size)
{
	kern_return_t kr = KERN_SUCCESS;
	if (data->kcd_flags & KCFLAG_USE_COPYOUT) {
		uint8_t zeros[16] = {};
		while (size) {
			uint32_t block_size = MIN(size, 16);
			kr = copyout(&zeros, dst_addr, block_size);
			if (kr)
				return KERN_NO_ACCESS;
			size -= block_size;
		}
		return KERN_SUCCESS;
	} else {
		bzero((void*)dst_addr, size);
		return KERN_SUCCESS;
	}
}

/*
 * Routine: kcdata_add_type_definition
 * Desc: add type definition to kcdata buffer.
 *       see feature description in documentation above.
 * params:  data - pointer describing the kcdata buffer
 *          type_id - unique type identifier for this data
 *          type_name - a string of max KCDATA_DESC_MAXLEN size for name of type
 *          elements_array - address to descriptors for each field in struct
 *          elements_count - count of how many fields are there in struct.
 * returns: return code from kcdata_get_memory_addr in case of failure.
 */

kern_return_t kcdata_add_type_definition(
		kcdata_descriptor_t data,
		uint32_t type_id,
		char *type_name,
		struct kcdata_subtype_descriptor *elements_array_addr,
		uint32_t elements_count)
{
	kern_return_t kr = KERN_SUCCESS;
	struct kcdata_type_definition kc_type_definition;
	mach_vm_address_t user_addr;
	uint32_t total_size = sizeof(struct kcdata_type_definition);
	bzero(&kc_type_definition, sizeof(kc_type_definition));

	if (strlen(type_name) >= KCDATA_DESC_MAXLEN)
		return KERN_INVALID_ARGUMENT;
	strlcpy(&kc_type_definition.kct_name[0], type_name, KCDATA_DESC_MAXLEN);
	kc_type_definition.kct_num_elements = elements_count;
	kc_type_definition.kct_type_identifier = type_id;

	total_size += elements_count * sizeof(struct kcdata_subtype_descriptor);
	/* record number of padding bytes as lower 4 bits of flags */
	if (KERN_SUCCESS != (kr = kcdata_get_memory_addr_with_flavor(data, KCDATA_TYPE_TYPEDEFINTION, total_size,
	                                                             kcdata_calc_padding(total_size), &user_addr)))
		return kr;
	if (KERN_SUCCESS != (kr = kcdata_memcpy(data, user_addr, (void *)&kc_type_definition, sizeof(struct kcdata_type_definition))))
		return kr;
	user_addr += sizeof(struct kcdata_type_definition);
	if (KERN_SUCCESS != (kr = kcdata_memcpy(data, user_addr, (void *)elements_array_addr, elements_count * sizeof(struct kcdata_subtype_descriptor))))
		return kr;
	return kr;
}

#pragma pack(4)

/* Internal structs for convenience */
struct _uint64_with_description_data {
	char desc[KCDATA_DESC_MAXLEN];
	uint64_t data;
};

struct _uint32_with_description_data {
	char     desc[KCDATA_DESC_MAXLEN];
	uint32_t data;
};

#pragma pack()

kern_return_t
kcdata_add_uint64_with_description(kcdata_descriptor_t data_desc, uint64_t data, const char * description)
{
	if (strlen(description) >= KCDATA_DESC_MAXLEN)
		return KERN_INVALID_ARGUMENT;

	kern_return_t kr = 0;
	mach_vm_address_t user_addr;
	struct _uint64_with_description_data save_data;
	const uint64_t size_req = sizeof(save_data);
	bzero(&save_data, size_req);

	strlcpy(&(save_data.desc[0]), description, sizeof(save_data.desc));
	save_data.data = data;

	kr = kcdata_get_memory_addr(data_desc, KCDATA_TYPE_UINT64_DESC, size_req, &user_addr);
	if (kr != KERN_SUCCESS)
		return kr;

	if (data_desc->kcd_flags & KCFLAG_USE_COPYOUT) {
		if (copyout(&save_data, user_addr, size_req))
			return KERN_NO_ACCESS;
	} else {
		memcpy((void *)user_addr, &save_data, size_req);
	}
	return KERN_SUCCESS;
}

kern_return_t kcdata_add_uint32_with_description(
				kcdata_descriptor_t data_desc,
				uint32_t data,
				const char *description)
{
	assert(strlen(description) < KCDATA_DESC_MAXLEN);
	if (strlen(description) >= KCDATA_DESC_MAXLEN)
		return KERN_INVALID_ARGUMENT;
	kern_return_t kr = 0;
	mach_vm_address_t user_addr;
	struct _uint32_with_description_data save_data;
	const uint64_t size_req = sizeof(save_data);

	bzero(&save_data, size_req);
	strlcpy(&(save_data.desc[0]), description, sizeof(save_data.desc));
	save_data.data = data;

	kr = kcdata_get_memory_addr(data_desc, KCDATA_TYPE_UINT32_DESC, size_req, &user_addr);
	if (kr != KERN_SUCCESS)
		return kr;
	if (data_desc->kcd_flags & KCFLAG_USE_COPYOUT) {
		if (copyout(&save_data, user_addr, size_req))
			return KERN_NO_ACCESS;
	} else {
		memcpy((void *)user_addr, &save_data, size_req);
	}
	return KERN_SUCCESS;
}


/* end buffer management api */
