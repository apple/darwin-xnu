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

/*
 *
 * The format for data is setup in a generic format as follows
 *
 * Layout of data structure:
 *
 *   |         8 - bytes         |
 *   |  type = MAGIC |  LENGTH   |
 *   |            0              |
 *   |      type     |  size     |
 *   |          flags            |
 *   |           data            |
 *   |___________data____________|
 *   |      type     |   size    |
 *   |          flags            |
 *   |___________data____________|
 *   |  type = END   |  size=0   |
 *   |            0              |
 *
 *
 * The type field describes what kind of data is passed. For example type = TASK_CRASHINFO_UUID means the following data is a uuid.
 * These types need to be defined in task_corpses.h for easy consumption by userspace inspection tools.
 *
 * Some range of types is reserved for special types like ints, longs etc. A cool new functionality made possible with this
 * extensible data format is that kernel can decide to put more information as required without requiring user space tools to
 * re-compile to be compatible. The case of rusage struct versions could be introduced without breaking existing tools.
 *
 * Feature description: Generic data with description
 * -------------------
 * Further more generic data with description is very much possible now. For example
 *
 *   - kcdata_add_uint64_with_description(cdatainfo, 0x700, "NUM MACH PORTS");
 *   - and more functions that allow adding description.
 * The userspace tools can then look at the description and print the data even if they are not compiled with knowledge of the field apriori.
 *
 *  Example data:
 * 0000  57 f1 ad de 00 00 00 00 00 00 00 00 00 00 00 00  W...............
 * 0010  01 00 00 00 00 00 00 00 30 00 00 00 00 00 00 00  ........0.......
 * 0020  50 49 44 00 00 00 00 00 00 00 00 00 00 00 00 00  PID.............
 * 0030  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
 * 0040  9c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
 * 0050  01 00 00 00 00 00 00 00 30 00 00 00 00 00 00 00  ........0.......
 * 0060  50 41 52 45 4e 54 20 50 49 44 00 00 00 00 00 00  PARENT PID......
 * 0070  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
 * 0080  01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
 * 0090  ed 58 91 f1
 *
 * Feature description: Container markers for compound data
 * ------------------
 * If a given kernel data type is complex and requires adding multiple optional fields inside a container
 * object for a consumer to understand arbitrary data, we package it using container markers.
 *
 * For example, the stackshot code gathers information and describes the state of a given task with respect
 * to many subsystems. It includes data such as io stats, vm counters, process names/flags and syscall counts.
 *
 * kcdata_add_container_marker(kcdata_p, KCDATA_TYPE_CONTAINER_BEGIN, STACKSHOT_KCCONTAINER_TASK, task_uniqueid);
 * // add multiple data, or add_<type>_with_description()s here
 *
 * kcdata_add_container_marker(kcdata_p, KCDATA_TYPE_CONTAINER_END, STACKSHOT_KCCONTAINER_TASK, task_uniqueid);
 *
 * Feature description: Custom Data formats on demand
 * --------------------
 * With the self describing nature of format, the kernel provider can describe a data type (uniquely identified by a number) and use
 * it in the buffer for sending data. The consumer can parse the type information and have knowledge of describing incoming data.
 * Following is an example of how we can describe a kernel specific struct sample_disk_io_stats in buffer.
 *
 * struct sample_disk_io_stats {
 *     uint64_t        disk_reads_count;
 *     uint64_t        disk_reads_size;
 *     uint64_t        io_priority_count[4];
 *     uint64_t        io_priority_size;
 * } __attribute__ ((packed));
 *
 *
 * struct kcdata_subtype_descriptor disk_io_stats_def[] = {
 *     {KCS_SUBTYPE_FLAGS_NONE, KC_ST_UINT64, 0 * sizeof(uint64_t), sizeof(uint64_t), "disk_reads_count"},
 *     {KCS_SUBTYPE_FLAGS_NONE, KC_ST_UINT64, 1 * sizeof(uint64_t), sizeof(uint64_t), "disk_reads_size"},
 *     {KCS_SUBTYPE_FLAGS_ARRAY, KC_ST_UINT64, 2 * sizeof(uint64_t), KCS_SUBTYPE_PACK_SIZE(4, sizeof(uint64_t)), "io_priority_count"},
 *     {KCS_SUBTYPE_FLAGS_ARRAY, KC_ST_UINT64, (2 + 4) * sizeof(uint64_t), sizeof(uint64_t), "io_priority_size"},
 * };
 *
 * Now you can add this custom type definition into the buffer as
 * kcdata_add_type_definition(kcdata_p, KCTYPE_SAMPLE_DISK_IO_STATS, "sample_disk_io_stats",
 *          &disk_io_stats_def[0], sizeof(disk_io_stats_def)/sizeof(struct kcdata_subtype_descriptor));
 *
 */

static kern_return_t kcdata_get_memory_addr_with_flavor(kcdata_descriptor_t data, uint32_t type, uint32_t size, uint64_t flags, mach_vm_address_t *user_addr);

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
 *       NOTE: The caller is responsible to zero the resulting memory or
 *             user other means to mark memory if it has failed populating the
 *             data in middle of operation.
 * params:  data - pointer describing the crash info allocation
 *	        type - type of data to be put. See corpse.h for defined types
 *          size - size requested. The header describes this size
 * returns: mach_vm_address_t address in user memory for copyout().
 */
kern_return_t kcdata_get_memory_addr(
		kcdata_descriptor_t data,
		uint32_t type,
		uint32_t size,
		mach_vm_address_t *user_addr)
{
	return kcdata_get_memory_addr_with_flavor(data, type, size, 0, user_addr);
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
	struct kcdata_item info;
	uint32_t total_size;

	if (user_addr == NULL || data == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	/* make sure 16 byte aligned */
	if (size & 0xf) {
		size += (0x10 - (size & 0xf));
	}

	bzero(&info, sizeof(info));
	KCDATA_ITEM_TYPE(&info) = type;
	KCDATA_ITEM_SIZE(&info) = size;
	KCDATA_ITEM_FLAGS(&info) = flags;
	total_size = size + sizeof(info);

	/* check available memory, including trailer size for KCDATA_TYPE_BUFFER_END */
	if (data->kcd_length < ((data->kcd_addr_end - data->kcd_addr_begin) + total_size + sizeof(info))) {
		return KERN_RESOURCE_SHORTAGE;
	}

	if (data->kcd_flags & KCFLAG_USE_COPYOUT) {
		if (copyout(&info, data->kcd_addr_end, sizeof(info)))
			return KERN_NO_ACCESS;
	} else {
		memcpy((void *)data->kcd_addr_end, &info, sizeof(info));
	}

	data->kcd_addr_end += sizeof(info);
	*user_addr = data->kcd_addr_end;
	data->kcd_addr_end += size;

	/* setup the end header as well */
	bzero(&info, sizeof(info));
	KCDATA_ITEM_TYPE(&info) = KCDATA_TYPE_BUFFER_END;
	KCDATA_ITEM_SIZE(&info) = 0;

	if (data->kcd_flags & KCFLAG_USE_COPYOUT) {
		if (copyout(&info, data->kcd_addr_end, sizeof(info)))
			return KERN_NO_ACCESS;
	} else {
		memcpy((void *)data->kcd_addr_end, &info, sizeof(info));
	}

	return KERN_SUCCESS;
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
	uint64_t flags = type_of_element;
	flags = (flags << 32) | count;
	uint32_t total_size = count * size_of_element;
	return kcdata_get_memory_addr_with_flavor(data, KCDATA_TYPE_ARRAY, total_size, flags, user_addr);
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
 * Routine: kcdata_memcpy
 * Desc: a common function to copy data out based on either copyout or memcopy flags
 * params:  data - pointer describing the kcdata buffer
 *          dst_addr - destination address
 *          src_addr - source address
 *          size - size in bytes to copy.
 * returns: KERN_NO_ACCESS if copyout fails.
 */

kern_return_t kcdata_memcpy(kcdata_descriptor_t data, mach_vm_address_t dst_addr, void *src_addr, uint32_t size)
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

	if (strnlen(type_name, KCDATA_DESC_MAXLEN + 1) >= KCDATA_DESC_MAXLEN)
		return KERN_INVALID_ARGUMENT;
	strlcpy(&kc_type_definition.kct_name[0], type_name, KCDATA_DESC_MAXLEN);
	kc_type_definition.kct_num_elements = elements_count;
	kc_type_definition.kct_type_identifier = type_id;

	total_size += elements_count * sizeof(struct kcdata_subtype_descriptor);
	if (KERN_SUCCESS != (kr = kcdata_get_memory_addr_with_flavor(data, KCDATA_TYPE_TYPEDEFINTION, total_size, 0, &user_addr)))
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

kern_return_t kcdata_add_uint64_with_description(
				kcdata_descriptor_t data_desc,
				uint64_t data,
				const char *description)
{
	if (strnlen(description, KCDATA_DESC_MAXLEN + 1) >= KCDATA_DESC_MAXLEN)
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
	if (strnlen(description, KCDATA_DESC_MAXLEN + 1) >= KCDATA_DESC_MAXLEN)
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
