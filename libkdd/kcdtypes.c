/*
 * Copyright (c) 2015 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
 */

#include <kcdata.h>
#include <sys/time.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <mach/mach_time.h>

/*!
 * @function kcdata_get_typedescription
 *
 * @abstract
 * Search the known type definitions for type with id type_id.
 *
 * @param type_id
 * A unsinged int type specified by the KCDATA.
 *
 * @param buffer
 * pointer to data area where type definition will be saved.
 *
 * @param buffer_size
 * size of the buffer provided.
 *
 * @return struct kcdata_type_definition *
 * pointer to a malloc'ed buffer holding the type definition and each subtype defintion for its fields.
 * It may return NULL if no type with id == type_id is found.
 * Note: The caller is responsible to free() the memory when its no longer used.
 *
 * @discussion
 * This function queries the known type definitions table. If found the defintion data is returned
 * else NULL is returned. It is advised to cache the return value from this function since the data
 * is always going to be the same for same type_id. The definition setup requires memory on heap.
 * The caller should make sure to free() the data once its done with using it.
 *
 */
struct kcdata_type_definition * kcdata_get_typedescription(unsigned type_id, uint8_t * buffer, uint32_t buffer_size);

/* forward declarations for helper routines */
static uint32_t get_kctype_subtype_size(kctype_subtype_t type);
static void setup_subtype_description(kcdata_subtype_descriptor_t desc, kctype_subtype_t type, uint32_t offset, char * name);
static void setup_subtype_array_description(
	kcdata_subtype_descriptor_t desc, kctype_subtype_t type, uint32_t offset, uint32_t count, char * name);
static void setup_type_definition(struct kcdata_type_definition * d, uint32_t type, uint32_t num_elems, char * name);

struct kcdata_type_definition *
kcdata_get_typedescription(unsigned type_id, uint8_t * buffer, uint32_t buffer_size)
{
	unsigned int i = 0;
#define _STR_VALUE(x) #x
#define _SUBTYPE(t, s, f) setup_subtype_description(&subtypes[i++], (t), offsetof(s, f), _STR_VALUE(f))
#define _SUBTYPE_ARRAY(t, s, f, c) setup_subtype_array_description(&subtypes[i++], (t), offsetof(s, f), (c), _STR_VALUE(f))
#define _STRINGTYPE(f) setup_subtype_array_description(&subtypes[i++], KC_ST_CHAR, 0, UINT16_MAX, f)

	if (buffer_size < sizeof(struct kcdata_type_definition) || buffer == NULL) {
		return NULL;
	}

	struct kcdata_type_definition * retval = (struct kcdata_type_definition *)&buffer[0];
	kcdata_subtype_descriptor_t subtypes = (kcdata_subtype_descriptor_t)&buffer[sizeof(struct kcdata_type_definition)];
	switch (type_id) {
	case KCDATA_TYPE_STRING_DESC: {
		i = 0;
		setup_subtype_array_description(&subtypes[i++], KC_ST_CHAR, 0, KCDATA_DESC_MAXLEN, "desc");
		setup_subtype_array_description(&subtypes[i++], KC_ST_CHAR, KCDATA_DESC_MAXLEN, UINT16_MAX, "data");
		setup_type_definition(retval, type_id, i, "string_desc");
		break;
	}

	case KCDATA_TYPE_UINT32_DESC: {
		i = 0;
		setup_subtype_array_description(&subtypes[i++], KC_ST_CHAR, 0, KCDATA_DESC_MAXLEN, "desc");
		setup_subtype_description(&subtypes[i++], KC_ST_UINT32, KCDATA_DESC_MAXLEN, "data");
		setup_type_definition(retval, type_id, i, "uint32_desc");
		break;
	}

	case KCDATA_TYPE_UINT64_DESC: {
		i = 0;
		setup_subtype_array_description(&subtypes[i++], KC_ST_CHAR, 0, KCDATA_DESC_MAXLEN, "desc");
		setup_subtype_description(&subtypes[i++], KC_ST_UINT64, KCDATA_DESC_MAXLEN, "data");
		setup_type_definition(retval, type_id, i, "uint64_desc");
		break;
	}

	case KCDATA_TYPE_INT32_DESC: {
		i = 0;
		setup_subtype_array_description(&subtypes[i++], KC_ST_CHAR, 0, KCDATA_DESC_MAXLEN, "desc");
		setup_subtype_description(&subtypes[i++], KC_ST_INT32, KCDATA_DESC_MAXLEN, "data");
		setup_type_definition(retval, type_id, i, "int32_desc");
		break;
	}

	case KCDATA_TYPE_INT64_DESC: {
		i = 0;
		setup_subtype_array_description(&subtypes[i++], KC_ST_CHAR, 0, KCDATA_DESC_MAXLEN, "desc");
		setup_subtype_description(&subtypes[i++], KC_ST_INT64, KCDATA_DESC_MAXLEN, "data");
		setup_type_definition(retval, type_id, i, "int64_desc");
		break;
	}

	case KCDATA_TYPE_TYPEDEFINTION: {
		i = 0;
		setup_subtype_description(&subtypes[i++], KC_ST_UINT32, offsetof(struct kcdata_type_definition, kct_type_identifier), "typeID");
		setup_subtype_description(&subtypes[i++], KC_ST_UINT32, offsetof(struct kcdata_type_definition, kct_num_elements), "numOfFields");
		setup_subtype_array_description(&subtypes[i++], KC_ST_CHAR, offsetof(struct kcdata_type_definition, kct_name), KCDATA_DESC_MAXLEN, "name");
		// Note "fields" is an array of run time defined length. So we populate fields at parsing time.
		setup_type_definition(retval, type_id, i, "typedef");
		break;
	}

	case KCDATA_TYPE_CONTAINER_BEGIN: {
		i = 0;
		setup_subtype_description(&subtypes[i++], KC_ST_UINT32, 0, "kcContainerType");
		setup_type_definition(retval, type_id, i, "container_begin");
		break;
	}

	case KCDATA_TYPE_LIBRARY_LOADINFO: {
		i = 0;
		_SUBTYPE(KC_ST_UINT32, struct user32_dyld_uuid_info, imageLoadAddress);
		_SUBTYPE_ARRAY(KC_ST_UINT8, struct user32_dyld_uuid_info, imageUUID, 16);
		setup_type_definition(retval, type_id, i, "dyld_load_info");
		break;
	}

	case KCDATA_TYPE_LIBRARY_LOADINFO64: {
		i = 0;
		_SUBTYPE(KC_ST_UINT64, struct user64_dyld_uuid_info, imageLoadAddress);
		_SUBTYPE_ARRAY(KC_ST_UINT8, struct user64_dyld_uuid_info, imageUUID, 16);
		setup_type_definition(retval, type_id, i, "dyld_load_info");
		break;
	}

	case STACKSHOT_KCTYPE_SHAREDCACHE_LOADINFO: {
		i = 0;
		_SUBTYPE(KC_ST_UINT64, struct dyld_uuid_info_64_v2, imageLoadAddress);
		_SUBTYPE_ARRAY(KC_ST_UINT8, struct dyld_uuid_info_64_v2, imageUUID, 16);
		_SUBTYPE(KC_ST_UINT64, struct dyld_uuid_info_64_v2, imageSlidBaseAddress);
		setup_type_definition(retval, type_id, i, "shared_cache_dyld_load_info");
		break;
	}

	case STACKSHOT_KCTYPE_KERNELCACHE_LOADINFO: {
		i = 0;
		_SUBTYPE(KC_ST_UINT64, struct dyld_uuid_info_64, imageLoadAddress);
		_SUBTYPE_ARRAY(KC_ST_UINT8, struct dyld_uuid_info_64, imageUUID, 16);
		setup_type_definition(retval, type_id, i, "kernelcache_load_info");
		break;
	}

	case KCDATA_TYPE_TIMEBASE: {
		i = 0;
		_SUBTYPE(KC_ST_UINT32, struct mach_timebase_info, numer);
		_SUBTYPE(KC_ST_UINT32, struct mach_timebase_info, denom);
		setup_type_definition(retval, type_id, i, "mach_timebase_info");
		break;
	}

	case KCDATA_TYPE_MACH_ABSOLUTE_TIME:
		setup_type_definition(retval, type_id, 1, "mach_absolute_time");
		setup_subtype_description(&subtypes[0], KC_ST_UINT64, 0, "mach_absolute_time");
		break;

	case KCDATA_TYPE_TIMEVAL: {
		i = 0;
		_SUBTYPE(KC_ST_INT64, struct timeval64, tv_sec);
		_SUBTYPE(KC_ST_INT64, struct timeval64, tv_usec);
		setup_type_definition(retval, type_id, i, "timeval");
		break;
	}

	case KCDATA_TYPE_USECS_SINCE_EPOCH:
		setup_type_definition(retval, type_id, 1, "usecs_since_epoch");
		setup_subtype_description(&subtypes[0], KC_ST_UINT64, 0, "usecs_since_epoch");
		break;

	case KCDATA_TYPE_PID:
		setup_subtype_description(&subtypes[0], KC_ST_INT32, 0, "pid");
		setup_type_definition(retval, type_id, 1, "pid");
		break;

	case KCDATA_TYPE_PROCNAME:
		i = 0;
		setup_subtype_array_description(&subtypes[i++], KC_ST_CHAR, 0, 64, "proc_name");
		setup_type_definition(retval, type_id, i, "proc_name");
		break;

	/* stackshot specific types */
	case STACKSHOT_KCTYPE_IOSTATS: {
		i = 0;
		_SUBTYPE(KC_ST_UINT64, struct io_stats_snapshot, ss_disk_reads_count);
		_SUBTYPE(KC_ST_UINT64, struct io_stats_snapshot, ss_disk_reads_size);
		_SUBTYPE(KC_ST_UINT64, struct io_stats_snapshot, ss_disk_writes_count);
		_SUBTYPE(KC_ST_UINT64, struct io_stats_snapshot, ss_disk_writes_size);
		_SUBTYPE_ARRAY(KC_ST_UINT64, struct io_stats_snapshot, ss_io_priority_count, STACKSHOT_IO_NUM_PRIORITIES);
		_SUBTYPE_ARRAY(KC_ST_UINT64, struct io_stats_snapshot, ss_io_priority_size, STACKSHOT_IO_NUM_PRIORITIES);
		_SUBTYPE(KC_ST_UINT64, struct io_stats_snapshot, ss_paging_count);
		_SUBTYPE(KC_ST_UINT64, struct io_stats_snapshot, ss_paging_size);
		_SUBTYPE(KC_ST_UINT64, struct io_stats_snapshot, ss_non_paging_count);
		_SUBTYPE(KC_ST_UINT64, struct io_stats_snapshot, ss_non_paging_size);
		_SUBTYPE(KC_ST_UINT64, struct io_stats_snapshot, ss_data_count);
		_SUBTYPE(KC_ST_UINT64, struct io_stats_snapshot, ss_data_size);
		_SUBTYPE(KC_ST_UINT64, struct io_stats_snapshot, ss_metadata_count);
		_SUBTYPE(KC_ST_UINT64, struct io_stats_snapshot, ss_metadata_size);

		setup_type_definition(retval, type_id, i, "io_statistics");
		break;
	}

	case STACKSHOT_KCTYPE_GLOBAL_MEM_STATS: {
		i = 0;
		_SUBTYPE(KC_ST_UINT32, struct mem_and_io_snapshot, snapshot_magic);
		_SUBTYPE(KC_ST_UINT32, struct mem_and_io_snapshot, free_pages);
		_SUBTYPE(KC_ST_UINT32, struct mem_and_io_snapshot, active_pages);
		_SUBTYPE(KC_ST_UINT32, struct mem_and_io_snapshot, inactive_pages);
		_SUBTYPE(KC_ST_UINT32, struct mem_and_io_snapshot, purgeable_pages);
		_SUBTYPE(KC_ST_UINT32, struct mem_and_io_snapshot, wired_pages);
		_SUBTYPE(KC_ST_UINT32, struct mem_and_io_snapshot, speculative_pages);
		_SUBTYPE(KC_ST_UINT32, struct mem_and_io_snapshot, throttled_pages);
		_SUBTYPE(KC_ST_UINT32, struct mem_and_io_snapshot, filebacked_pages);
		_SUBTYPE(KC_ST_UINT32, struct mem_and_io_snapshot, compressions);
		_SUBTYPE(KC_ST_UINT32, struct mem_and_io_snapshot, decompressions);
		_SUBTYPE(KC_ST_UINT32, struct mem_and_io_snapshot, compressor_size);
		_SUBTYPE(KC_ST_UINT32, struct mem_and_io_snapshot, busy_buffer_count);
		_SUBTYPE(KC_ST_UINT32, struct mem_and_io_snapshot, pages_wanted);
		_SUBTYPE(KC_ST_UINT32, struct mem_and_io_snapshot, pages_reclaimed);
		_SUBTYPE(KC_ST_UINT8, struct mem_and_io_snapshot, pages_wanted_reclaimed_valid);
		setup_type_definition(retval, type_id, i, "mem_and_io_snapshot");
		break;
	}

	case STACKSHOT_KCCONTAINER_TASK:
		setup_type_definition(retval, type_id, 0, "task_snapshots");
		break;

	case STACKSHOT_KCCONTAINER_THREAD:
		setup_type_definition(retval, type_id, 0, "thread_snapshots");
		break;

	case STACKSHOT_KCTYPE_TASK_SNAPSHOT: {
		i = 0;
		_SUBTYPE(KC_ST_UINT64, struct task_snapshot_v2, ts_unique_pid);
		_SUBTYPE(KC_ST_UINT64, struct task_snapshot_v2, ts_ss_flags);
		_SUBTYPE(KC_ST_UINT64, struct task_snapshot_v2, ts_user_time_in_terminated_threads);
		_SUBTYPE(KC_ST_UINT64, struct task_snapshot_v2, ts_system_time_in_terminated_threads);
		_SUBTYPE(KC_ST_UINT64, struct task_snapshot_v2, ts_p_start_sec);
		_SUBTYPE(KC_ST_UINT64, struct task_snapshot_v2, ts_task_size);
		_SUBTYPE(KC_ST_UINT64, struct task_snapshot_v2, ts_max_resident_size);
		_SUBTYPE(KC_ST_UINT32, struct task_snapshot_v2, ts_suspend_count);
		_SUBTYPE(KC_ST_UINT32, struct task_snapshot_v2, ts_faults);
		_SUBTYPE(KC_ST_UINT32, struct task_snapshot_v2, ts_pageins);
		_SUBTYPE(KC_ST_UINT32, struct task_snapshot_v2, ts_cow_faults);
		_SUBTYPE(KC_ST_UINT32, struct task_snapshot_v2, ts_was_throttled);
		_SUBTYPE(KC_ST_UINT32, struct task_snapshot_v2, ts_did_throttle);
		_SUBTYPE(KC_ST_UINT32, struct task_snapshot_v2, ts_latency_qos);
		_SUBTYPE(KC_ST_INT32, struct task_snapshot_v2, ts_pid);
		_SUBTYPE_ARRAY(KC_ST_CHAR, struct task_snapshot_v2, ts_p_comm, 32);
		setup_type_definition(retval, type_id, i, "task_snapshot");
		break;
	}

	case STACKSHOT_KCTYPE_TASK_DELTA_SNAPSHOT: {
		i = 0;
		_SUBTYPE(KC_ST_UINT64, struct task_delta_snapshot_v2, tds_unique_pid);
		_SUBTYPE(KC_ST_UINT64, struct task_delta_snapshot_v2, tds_ss_flags);
		_SUBTYPE(KC_ST_UINT64, struct task_delta_snapshot_v2, tds_user_time_in_terminated_threads);
		_SUBTYPE(KC_ST_UINT64, struct task_delta_snapshot_v2, tds_system_time_in_terminated_threads);
		_SUBTYPE(KC_ST_UINT64, struct task_delta_snapshot_v2, tds_task_size);
		_SUBTYPE(KC_ST_UINT64, struct task_delta_snapshot_v2, tds_max_resident_size);
		_SUBTYPE(KC_ST_UINT32, struct task_delta_snapshot_v2, tds_suspend_count);
		_SUBTYPE(KC_ST_UINT32, struct task_delta_snapshot_v2, tds_faults);
		_SUBTYPE(KC_ST_UINT32, struct task_delta_snapshot_v2, tds_pageins);
		_SUBTYPE(KC_ST_UINT32, struct task_delta_snapshot_v2, tds_cow_faults);
		_SUBTYPE(KC_ST_UINT32, struct task_delta_snapshot_v2, tds_was_throttled);
		_SUBTYPE(KC_ST_UINT32, struct task_delta_snapshot_v2, tds_did_throttle);
		_SUBTYPE(KC_ST_UINT32, struct task_delta_snapshot_v2, tds_latency_qos);
		setup_type_definition(retval, type_id, i, "task_delta_snapshot");
		break;
	}

	case STACKSHOT_KCTYPE_THREAD_SNAPSHOT: {
		i = 0;

		_SUBTYPE(KC_ST_UINT64, struct thread_snapshot_v3, ths_thread_id);
		_SUBTYPE(KC_ST_UINT64, struct thread_snapshot_v3, ths_wait_event);
		_SUBTYPE(KC_ST_UINT64, struct thread_snapshot_v3, ths_continuation);
		_SUBTYPE(KC_ST_UINT64, struct thread_snapshot_v3, ths_total_syscalls);
		_SUBTYPE(KC_ST_UINT64, struct thread_snapshot_v3, ths_voucher_identifier);
		_SUBTYPE(KC_ST_UINT64, struct thread_snapshot_v3, ths_dqserialnum);
		_SUBTYPE(KC_ST_UINT64, struct thread_snapshot_v3, ths_user_time);
		_SUBTYPE(KC_ST_UINT64, struct thread_snapshot_v3, ths_sys_time);
		_SUBTYPE(KC_ST_UINT64, struct thread_snapshot_v3, ths_ss_flags);
		_SUBTYPE(KC_ST_UINT64, struct thread_snapshot_v3, ths_last_run_time);
		_SUBTYPE(KC_ST_UINT64, struct thread_snapshot_v3, ths_last_made_runnable_time);
		_SUBTYPE(KC_ST_UINT32, struct thread_snapshot_v3, ths_state);
		_SUBTYPE(KC_ST_UINT32, struct thread_snapshot_v3, ths_sched_flags);
		_SUBTYPE(KC_ST_INT16, struct thread_snapshot_v3, ths_base_priority);
		_SUBTYPE(KC_ST_INT16, struct thread_snapshot_v3, ths_sched_priority);
		_SUBTYPE(KC_ST_UINT8, struct thread_snapshot_v3, ths_eqos);
		_SUBTYPE(KC_ST_UINT8, struct thread_snapshot_v3, ths_rqos);
		_SUBTYPE(KC_ST_UINT8, struct thread_snapshot_v3, ths_rqos_override);
		_SUBTYPE(KC_ST_UINT8, struct thread_snapshot_v3, ths_io_tier);
		_SUBTYPE(KC_ST_UINT64, struct thread_snapshot_v3, ths_thread_t);
		_SUBTYPE(KC_ST_UINT64, struct thread_snapshot_v4, ths_requested_policy);
		_SUBTYPE(KC_ST_UINT64, struct thread_snapshot_v4, ths_effective_policy);

		setup_type_definition(retval, type_id, i, "thread_snapshot");
		break;
	}

	case STACKSHOT_KCTYPE_THREAD_DELTA_SNAPSHOT: {
		i = 0;

		_SUBTYPE(KC_ST_UINT64, struct thread_delta_snapshot_v2, tds_thread_id);
		_SUBTYPE(KC_ST_UINT64, struct thread_delta_snapshot_v2, tds_voucher_identifier);
		_SUBTYPE(KC_ST_UINT64, struct thread_delta_snapshot_v2, tds_ss_flags);
		_SUBTYPE(KC_ST_UINT64, struct thread_delta_snapshot_v2, tds_last_made_runnable_time);
		_SUBTYPE(KC_ST_UINT32, struct thread_delta_snapshot_v2, tds_state);
		_SUBTYPE(KC_ST_UINT32, struct thread_delta_snapshot_v2, tds_sched_flags);
		_SUBTYPE(KC_ST_INT16, struct thread_delta_snapshot_v2, tds_base_priority);
		_SUBTYPE(KC_ST_INT16, struct thread_delta_snapshot_v2, tds_sched_priority);
		_SUBTYPE(KC_ST_UINT8, struct thread_delta_snapshot_v2, tds_eqos);
		_SUBTYPE(KC_ST_UINT8, struct thread_delta_snapshot_v2, tds_rqos);
		_SUBTYPE(KC_ST_UINT8, struct thread_delta_snapshot_v2, tds_rqos_override);
		_SUBTYPE(KC_ST_UINT8, struct thread_delta_snapshot_v2, tds_io_tier);
		_SUBTYPE(KC_ST_UINT64, struct thread_delta_snapshot_v3, tds_requested_policy);
		_SUBTYPE(KC_ST_UINT64, struct thread_delta_snapshot_v3, tds_effective_policy);

		setup_type_definition(retval, type_id, i, "thread_delta_snapshot");

		break;
	}

	case STACKSHOT_KCTYPE_DONATING_PIDS:
		setup_type_definition(retval, type_id, 1, "donating_pids");
		setup_subtype_description(&subtypes[0], KC_ST_INT32, 0, "donating_pids");
		break;

	case STACKSHOT_KCTYPE_THREAD_NAME: {
		i = 0;
		setup_subtype_array_description(&subtypes[i++], KC_ST_CHAR, 0, 64, "pth_name");
		setup_type_definition(retval, type_id, i, "pth_name");
		break;
	}

	case STACKSHOT_KCTYPE_KERN_STACKFRAME:
		setup_type_definition(retval, type_id, 2, "kernel_stack_frames");
		setup_subtype_description(&subtypes[0], KC_ST_UINT32, 0, "lr");
		setup_subtype_description(&subtypes[1], KC_ST_UINT32, sizeof(uint32_t), "sp");
		break;

	case STACKSHOT_KCTYPE_KERN_STACKFRAME64:
		setup_type_definition(retval, type_id, 2, "kernel_stack_frames");
		setup_subtype_description(&subtypes[0], KC_ST_UINT64, 0, "lr");
		setup_subtype_description(&subtypes[1], KC_ST_UINT64, sizeof(uint64_t), "sp");
		break;

	case STACKSHOT_KCTYPE_USER_STACKFRAME:
		setup_type_definition(retval, type_id, 2, "user_stack_frames");
		setup_subtype_description(&subtypes[0], KC_ST_UINT32, 0, "lr");
		setup_subtype_description(&subtypes[1], KC_ST_UINT32, sizeof(uint32_t), "sp");
		break;

	case STACKSHOT_KCTYPE_USER_STACKFRAME64:
		setup_type_definition(retval, type_id, 2, "user_stack_frames");
		setup_subtype_description(&subtypes[0], KC_ST_UINT64, 0, "lr");
		setup_subtype_description(&subtypes[1], KC_ST_UINT64, sizeof(uint64_t), "sp");
		break;

	case STACKSHOT_KCTYPE_KERN_STACKLR:
		setup_type_definition(retval, type_id, 1, "kernel_stack_frames");
		setup_subtype_description(&subtypes[0], KC_ST_UINT32, 0, "lr");
		subtypes[0].kcs_flags |= KCS_SUBTYPE_FLAGS_STRUCT;
		break;

	case STACKSHOT_KCTYPE_KERN_STACKLR64:
		setup_type_definition(retval, type_id, 1, "kernel_stack_frames");
		setup_subtype_description(&subtypes[0], KC_ST_UINT64, 0, "lr");
		subtypes[0].kcs_flags |= KCS_SUBTYPE_FLAGS_STRUCT;
		break;

	case STACKSHOT_KCTYPE_USER_STACKLR:
		setup_type_definition(retval, type_id, 1, "user_stack_frames");
		setup_subtype_description(&subtypes[0], KC_ST_UINT32, 0, "lr");
		subtypes[0].kcs_flags |= KCS_SUBTYPE_FLAGS_STRUCT;
		break;

	case STACKSHOT_KCTYPE_USER_STACKLR64:
		setup_type_definition(retval, type_id, 1, "user_stack_frames");
		setup_subtype_description(&subtypes[0], KC_ST_UINT64, 0, "lr");
		subtypes[0].kcs_flags |= KCS_SUBTYPE_FLAGS_STRUCT;
		break;

	case STACKSHOT_KCTYPE_NONRUNNABLE_TIDS:
		setup_type_definition(retval, type_id, 1, "nonrunnable_threads");
		setup_subtype_description(&subtypes[0], KC_ST_INT64, 0, "nonrunnable_threads");
		break;

	case STACKSHOT_KCTYPE_NONRUNNABLE_TASKS:
		setup_type_definition(retval, type_id, 1, "nonrunnable_tasks");
		setup_subtype_description(&subtypes[0], KC_ST_INT64, 0, "nonrunnable_tasks");
		break;

	case STACKSHOT_KCTYPE_BOOTARGS: {
		i = 0;
		_STRINGTYPE("boot_args");
		setup_type_definition(retval, type_id, i, "boot_args");
		break;
	}

	case STACKSHOT_KCTYPE_OSVERSION: {
		i = 0;
		_STRINGTYPE("osversion");
		setup_type_definition(retval, type_id, i, "osversion");
		break;
	}

	case STACKSHOT_KCTYPE_KERN_PAGE_SIZE: {
		i = 0;
		setup_subtype_description(&subtypes[i++], KC_ST_UINT32, 0, "kernel_page_size");
		setup_type_definition(retval, type_id, i, "kernel_page_size");
		break;
	}

	case STACKSHOT_KCTYPE_THREAD_POLICY_VERSION: {
		i = 0;
		setup_subtype_description(&subtypes[i++], KC_ST_UINT32, 0, "thread_policy_version");
		setup_type_definition(retval, type_id, i, "thread_policy_version");
		break;
	}

	case STACKSHOT_KCTYPE_JETSAM_LEVEL: {
		i = 0;
		setup_subtype_description(&subtypes[i++], KC_ST_UINT32, 0, "jetsam_level");
		setup_type_definition(retval, type_id, i, "jetsam_level");
		break;
	}

	case STACKSHOT_KCTYPE_DELTA_SINCE_TIMESTAMP: {
		i = 0;
		setup_subtype_description(&subtypes[i++], KC_ST_UINT64, 0, "stackshot_delta_since_timestamp");
		setup_type_definition(retval, type_id, i, "stackshot_delta_since_timestamp");
		break;
	}

	/* crashinfo types */
	case TASK_CRASHINFO_BSDINFOWITHUNIQID: {
		i = 0;
		_SUBTYPE_ARRAY(KC_ST_UINT8, struct crashinfo_proc_uniqidentifierinfo, p_uuid, 16);
		_SUBTYPE(KC_ST_UINT64, struct crashinfo_proc_uniqidentifierinfo, p_uniqueid);
		_SUBTYPE(KC_ST_UINT64, struct crashinfo_proc_uniqidentifierinfo, p_puniqueid);
		/* Ignore the p_reserve fields */
		setup_type_definition(retval, type_id, i, "proc_uniqidentifierinfo");
		break;
	}

	case TASK_CRASHINFO_PID: {
		setup_subtype_description(&subtypes[0], KC_ST_INT32, 0, "pid");
		setup_type_definition(retval, type_id, 1, "pid");
		break;
	}

	case TASK_CRASHINFO_PPID: {
		setup_subtype_description(&subtypes[0], KC_ST_INT32, 0, "ppid");
		setup_type_definition(retval, type_id, 1, "ppid");
		break;
	}

	/* case TASK_CRASHINFO_RUSAGE: { */
	/*      /\* */
	/*       * rusage is a complex structure and is only for legacy use for crashed processes rusage info. */
	/*       * So we just consider it as opaque data. */
	/*       *\/ */
	/*      i = 0; */
	/*      setup_subtype_array_description(&subtypes[i++], KC_ST_UINT8, 0, sizeof(struct rusage), "rusage"); */
	/*      setup_type_definition(retval, type_id, i, "rusage"); */
	/*      break; */
	/* } */

	case TASK_CRASHINFO_RUSAGE_INFO: {
		i = 0;
		_SUBTYPE_ARRAY(KC_ST_UINT8, struct rusage_info_v3, ri_uuid, 16);
		_SUBTYPE(KC_ST_UINT64, struct rusage_info_v3, ri_user_time);
		_SUBTYPE(KC_ST_UINT64, struct rusage_info_v3, ri_system_time);
		_SUBTYPE(KC_ST_UINT64, struct rusage_info_v3, ri_pkg_idle_wkups);
		_SUBTYPE(KC_ST_UINT64, struct rusage_info_v3, ri_interrupt_wkups);
		_SUBTYPE(KC_ST_UINT64, struct rusage_info_v3, ri_pageins);
		_SUBTYPE(KC_ST_UINT64, struct rusage_info_v3, ri_wired_size);
		_SUBTYPE(KC_ST_UINT64, struct rusage_info_v3, ri_resident_size);
		_SUBTYPE(KC_ST_UINT64, struct rusage_info_v3, ri_phys_footprint);
		_SUBTYPE(KC_ST_UINT64, struct rusage_info_v3, ri_proc_start_abstime);
		_SUBTYPE(KC_ST_UINT64, struct rusage_info_v3, ri_proc_exit_abstime);
		_SUBTYPE(KC_ST_UINT64, struct rusage_info_v3, ri_child_user_time);
		_SUBTYPE(KC_ST_UINT64, struct rusage_info_v3, ri_child_system_time);
		_SUBTYPE(KC_ST_UINT64, struct rusage_info_v3, ri_child_pkg_idle_wkups);
		_SUBTYPE(KC_ST_UINT64, struct rusage_info_v3, ri_child_interrupt_wkups);
		_SUBTYPE(KC_ST_UINT64, struct rusage_info_v3, ri_child_pageins);
		_SUBTYPE(KC_ST_UINT64, struct rusage_info_v3, ri_child_elapsed_abstime);
		_SUBTYPE(KC_ST_UINT64, struct rusage_info_v3, ri_diskio_bytesread);
		_SUBTYPE(KC_ST_UINT64, struct rusage_info_v3, ri_diskio_byteswritten);
		_SUBTYPE(KC_ST_UINT64, struct rusage_info_v3, ri_cpu_time_qos_default);
		_SUBTYPE(KC_ST_UINT64, struct rusage_info_v3, ri_cpu_time_qos_maintenance);
		_SUBTYPE(KC_ST_UINT64, struct rusage_info_v3, ri_cpu_time_qos_background);
		_SUBTYPE(KC_ST_UINT64, struct rusage_info_v3, ri_cpu_time_qos_utility);
		_SUBTYPE(KC_ST_UINT64, struct rusage_info_v3, ri_cpu_time_qos_legacy);
		_SUBTYPE(KC_ST_UINT64, struct rusage_info_v3, ri_cpu_time_qos_user_initiated);
		_SUBTYPE(KC_ST_UINT64, struct rusage_info_v3, ri_cpu_time_qos_user_interactive);
		_SUBTYPE(KC_ST_UINT64, struct rusage_info_v3, ri_billed_system_time);
		_SUBTYPE(KC_ST_UINT64, struct rusage_info_v3, ri_serviced_system_time);
		setup_type_definition(retval, type_id, i, "rusage_info");
		break;
	}

	case STACKSHOT_KCTYPE_CPU_TIMES: {
		i = 0;
		_SUBTYPE(KC_ST_UINT64, struct stackshot_cpu_times_v2, user_usec);
		_SUBTYPE(KC_ST_UINT64, struct stackshot_cpu_times_v2, system_usec);
		_SUBTYPE(KC_ST_UINT64, struct stackshot_cpu_times_v2, runnable_usec);
		setup_type_definition(retval, type_id, i, "cpu_times");
		break;
	}

	case STACKSHOT_KCTYPE_STACKSHOT_DURATION: {
		i = 0;
		_SUBTYPE(KC_ST_UINT64, struct stackshot_duration, stackshot_duration);
		_SUBTYPE(KC_ST_UINT64, struct stackshot_duration, stackshot_duration_outer);
		subtypes[0].kcs_flags |= KCS_SUBTYPE_FLAGS_MERGE;
		subtypes[1].kcs_flags |= KCS_SUBTYPE_FLAGS_MERGE;
		setup_type_definition(retval, type_id, i, "stackshot_duration");
		break;
	}

	case STACKSHOT_KCTYPE_STACKSHOT_FAULT_STATS: {
		i = 0;
		_SUBTYPE(KC_ST_UINT32, struct stackshot_fault_stats, sfs_pages_faulted_in);
		_SUBTYPE(KC_ST_UINT64, struct stackshot_fault_stats, sfs_time_spent_faulting);
		_SUBTYPE(KC_ST_UINT64, struct stackshot_fault_stats, sfs_system_max_fault_time);
		_SUBTYPE(KC_ST_UINT8, struct stackshot_fault_stats, sfs_stopped_faulting);

		setup_type_definition(retval, type_id, i, "stackshot_fault_stats");
		break;
	}

	case STACKSHOT_KCTYPE_THREAD_WAITINFO: {
		i = 0;
		_SUBTYPE(KC_ST_UINT64, struct stackshot_thread_waitinfo, owner);
		_SUBTYPE(KC_ST_UINT64, struct stackshot_thread_waitinfo, waiter);
		_SUBTYPE(KC_ST_UINT64, struct stackshot_thread_waitinfo, context);
		_SUBTYPE(KC_ST_UINT8, struct stackshot_thread_waitinfo, wait_type);
		setup_type_definition(retval, type_id, i, "thread_waitinfo");
		break;
	}

	case STACKSHOT_KCTYPE_THREAD_GROUP_SNAPSHOT: {
		i = 0;
		_SUBTYPE(KC_ST_UINT64, struct thread_group_snapshot_v2, tgs_id);
		_SUBTYPE_ARRAY(KC_ST_CHAR, struct thread_group_snapshot_v2, tgs_name, 16);
		_SUBTYPE(KC_ST_UINT64, struct thread_group_snapshot_v2, tgs_flags);
		setup_type_definition(retval, type_id, i, "thread_group_snapshot");
		break;
	}

	case STACKSHOT_KCTYPE_THREAD_GROUP: {
		i = 0;
		setup_subtype_description(&subtypes[i++], KC_ST_UINT64, 0, "thread_group");
		setup_type_definition(retval, type_id, i, "thread_group");
		break;
	};

	case STACKSHOT_KCTYPE_JETSAM_COALITION_SNAPSHOT: {
		i = 0;
		_SUBTYPE(KC_ST_UINT64, struct jetsam_coalition_snapshot, jcs_id);
		_SUBTYPE(KC_ST_UINT64, struct jetsam_coalition_snapshot, jcs_flags);
		_SUBTYPE(KC_ST_UINT64, struct jetsam_coalition_snapshot, jcs_thread_group);
		_SUBTYPE(KC_ST_UINT64, struct jetsam_coalition_snapshot, jcs_leader_task_uniqueid);
		setup_type_definition(retval, type_id, i, "jetsam_coalition_snapshot");
		break;
	}

	case STACKSHOT_KCTYPE_JETSAM_COALITION: {
		i = 0;
		setup_subtype_description(&subtypes[i++], KC_ST_UINT64, 0, "jetsam_coalition");
		setup_type_definition(retval, type_id, i, "jetsam_coalition");
		break;
	};

	case STACKSHOT_KCTYPE_INSTRS_CYCLES: {
		i = 0;
		_SUBTYPE(KC_ST_UINT64, struct instrs_cycles_snapshot, ics_instructions);
		_SUBTYPE(KC_ST_UINT64, struct instrs_cycles_snapshot, ics_cycles);
		setup_type_definition(retval, type_id, i, "instrs_cycles_snapshot");
		break;
	}

	case STACKSHOT_KCTYPE_USER_STACKTOP: {
		i = 0;
		_SUBTYPE(KC_ST_UINT64, struct stack_snapshot_stacktop, sp);
		_SUBTYPE_ARRAY(KC_ST_UINT8, struct stack_snapshot_stacktop, stack_contents, 8);
		setup_type_definition(retval, type_id, i, "user_stacktop");
		break;
	}

	case TASK_CRASHINFO_PROC_STARTTIME: {
		i = 0;
		_SUBTYPE(KC_ST_INT64, struct timeval64, tv_sec);
		_SUBTYPE(KC_ST_INT64, struct timeval64, tv_usec);
		setup_type_definition(retval, type_id, i, "proc_starttime");
		break;
	}

	case TASK_CRASHINFO_EXCEPTION_CODES: {
		i = 0;
		char codenum[100];
		for (i = 0; i < EXCEPTION_CODE_MAX; i++) {
			snprintf(codenum, sizeof(codenum), "code_%d", i);
			setup_subtype_description(&subtypes[i], KC_ST_UINT64, i * (sizeof(uint64_t)), codenum);
		}
		setup_type_definition(retval, type_id, i, "mach_exception_data_t");
		break;
	}

	case TASK_CRASHINFO_PROC_NAME: {
		i = 0;
		_STRINGTYPE("p_comm");
		setup_type_definition(retval, type_id, i, "p_comm");
		break;
	}

	case TASK_CRASHINFO_USERSTACK: {
		i = 0;
		setup_subtype_description(&subtypes[0], KC_ST_UINT64, 0, "userstack_ptr");
		setup_type_definition(retval, type_id, 1, "userstack_ptr");
		break;
	}

	case TASK_CRASHINFO_ARGSLEN: {
		i = 0;
		setup_subtype_description(&subtypes[0], KC_ST_INT32, 0, "p_argslen");
		setup_type_definition(retval, type_id, 1, "p_argslen");
		break;
	}

	case TASK_CRASHINFO_PROC_PATH: {
		i = 0;
		_STRINGTYPE("p_path");
		setup_type_definition(retval, type_id, i, "p_path");
		break;
	}

	case TASK_CRASHINFO_PROC_CSFLAGS: {
		setup_subtype_description(&subtypes[0], KC_ST_UINT32, 0, "p_csflags");
		setup_type_definition(retval, type_id, 1, "p_csflags");
		break;
	}

	case TASK_CRASHINFO_PROC_STATUS: {
		setup_subtype_description(&subtypes[0], KC_ST_UINT8, 0, "p_status");
		setup_type_definition(retval, type_id, 1, "p_status");
		break;
	}

	case TASK_CRASHINFO_UID: {
		setup_subtype_description(&subtypes[0], KC_ST_INT32, 0, "uid");
		setup_type_definition(retval, type_id, 1, "uid");
		break;
	}

	case TASK_CRASHINFO_GID: {
		setup_subtype_description(&subtypes[0], KC_ST_INT32, 0, "gid");
		setup_type_definition(retval, type_id, 1, "gid");
		break;
	}

	case TASK_CRASHINFO_PROC_ARGC: {
		setup_subtype_description(&subtypes[0], KC_ST_INT32, 0, "argc");
		setup_type_definition(retval, type_id, 1, "argc");
		break;
	}

	case TASK_CRASHINFO_PROC_FLAGS: {
		setup_subtype_description(&subtypes[0], KC_ST_UINT32, 0, "p_flags");
		setup_type_definition(retval, type_id, 1, "p_flags");
		break;
	}

	case TASK_CRASHINFO_CPUTYPE: {
		setup_subtype_description(&subtypes[0], KC_ST_INT32, 0, "cputype");
		setup_type_definition(retval, type_id, 1, "cputype");
		break;
	}

	case TASK_CRASHINFO_RESPONSIBLE_PID: {
		setup_subtype_description(&subtypes[0], KC_ST_INT32, 0, "responsible_pid");
		setup_type_definition(retval, type_id, 1, "responsible_pid");
		break;
	}

	case TASK_CRASHINFO_DIRTY_FLAGS: {
		setup_subtype_description(&subtypes[0], KC_ST_UINT32, 0, "dirty_flags");
		setup_type_definition(retval, type_id, 1, "dirty_flags");
		break;
	}

	case TASK_CRASHINFO_CRASHED_THREADID: {
		setup_subtype_description(&subtypes[0], KC_ST_UINT64, 0, "crashed_threadid");
		setup_type_definition(retval, type_id, 1, "crashed_threadid");
		break;
	}

	case TASK_CRASHINFO_COALITION_ID: {
		setup_subtype_description(&subtypes[0], KC_ST_UINT64, 0, "coalition_id");
		setup_type_definition(retval, type_id, 1, "coalition_id");
		break;
	}

	case TASK_CRASHINFO_UDATA_PTRS: {
		setup_subtype_description(&subtypes[0], KC_ST_UINT64, 0, "udata_ptrs");
		setup_type_definition(retval, type_id, 1, "udata_ptrs");
		break;
	}

	case TASK_CRASHINFO_MEMORY_LIMIT: {
		setup_subtype_description(&subtypes[0], KC_ST_UINT64, 0, "task_phys_mem_limit");
		setup_type_definition(retval, type_id, 1, "task_phys_mem_limit");
		break;
	}

	case EXIT_REASON_SNAPSHOT: {
		_SUBTYPE(KC_ST_UINT32, struct exit_reason_snapshot, ers_namespace);
		_SUBTYPE(KC_ST_UINT64, struct exit_reason_snapshot, ers_code);
		_SUBTYPE(KC_ST_UINT64, struct exit_reason_snapshot, ers_flags);
		setup_type_definition(retval, type_id, i, "exit_reason_basic_info");

		break;
	}

	case EXIT_REASON_USER_DESC: {
		i = 0;

		_STRINGTYPE("exit_reason_user_description");
		setup_type_definition(retval, type_id, i, "exit_reason_user_description");
		break;
	}

	case EXIT_REASON_USER_PAYLOAD: {
		i = 0;

		setup_subtype_array_description(&subtypes[i++], KC_ST_UINT8, 0, EXIT_REASON_PAYLOAD_MAX_LEN, "exit_reason_user_payload");
		setup_type_definition(retval, type_id, i, "exit_reason_user_payload");
		break;
	}

	case EXIT_REASON_CODESIGNING_INFO: {
		_SUBTYPE(KC_ST_UINT64, struct codesigning_exit_reason_info, ceri_virt_addr);
		_SUBTYPE(KC_ST_UINT64, struct codesigning_exit_reason_info, ceri_file_offset);
		_SUBTYPE_ARRAY(KC_ST_CHAR, struct codesigning_exit_reason_info, ceri_pathname, EXIT_REASON_CODESIG_PATH_MAX);
		_SUBTYPE_ARRAY(KC_ST_CHAR, struct codesigning_exit_reason_info, ceri_filename, EXIT_REASON_CODESIG_PATH_MAX);
		_SUBTYPE(KC_ST_UINT64, struct codesigning_exit_reason_info, ceri_codesig_modtime_secs);
		_SUBTYPE(KC_ST_UINT64, struct codesigning_exit_reason_info, ceri_codesig_modtime_nsecs);
		_SUBTYPE(KC_ST_UINT64, struct codesigning_exit_reason_info, ceri_page_modtime_secs);
		_SUBTYPE(KC_ST_UINT64, struct codesigning_exit_reason_info, ceri_page_modtime_nsecs);
		_SUBTYPE(KC_ST_UINT8, struct codesigning_exit_reason_info, ceri_path_truncated);
		_SUBTYPE(KC_ST_UINT8, struct codesigning_exit_reason_info, ceri_object_codesigned);
		_SUBTYPE(KC_ST_UINT8, struct codesigning_exit_reason_info, ceri_page_codesig_validated);
		_SUBTYPE(KC_ST_UINT8, struct codesigning_exit_reason_info, ceri_page_codesig_tainted);
		_SUBTYPE(KC_ST_UINT8, struct codesigning_exit_reason_info, ceri_page_codesig_nx);
		_SUBTYPE(KC_ST_UINT8, struct codesigning_exit_reason_info, ceri_page_wpmapped);
		_SUBTYPE(KC_ST_UINT8, struct codesigning_exit_reason_info, ceri_page_slid);
		_SUBTYPE(KC_ST_UINT8, struct codesigning_exit_reason_info, ceri_page_dirty);
		_SUBTYPE(KC_ST_UINT32, struct codesigning_exit_reason_info, ceri_page_shadow_depth);
		setup_type_definition(retval, type_id, i, "exit_reason_codesigning_info");
		break;
	}

	case EXIT_REASON_WORKLOOP_ID: {
		i = 0;
		setup_subtype_description(&subtypes[i++], KC_ST_UINT64, 0, "exit_reason_workloop_id");
		setup_type_definition(retval, type_id, i, "exit_reason_workloop_id");
		break;
	}

	case EXIT_REASON_DISPATCH_QUEUE_NO: {
		i = 0;
		setup_subtype_description(&subtypes[i++], KC_ST_UINT64, 0, "exit_reason_dispatch_queue_no");
		setup_type_definition(retval, type_id, i, "exit_reason_dispatch_queue_no");
		break;
	}

	case STACKSHOT_KCTYPE_ASID: {
		i = 0;
		setup_subtype_description(&subtypes[i++], KC_ST_UINT32, 0, "ts_asid");
		setup_type_definition(retval, type_id, i, "ts_asid");
		break;
	}

	case STACKSHOT_KCTYPE_PAGE_TABLES: {
		i = 0;
		setup_subtype_description(&subtypes[i++], KC_ST_UINT64, 0, "ts_pagetable");
		setup_type_definition(retval, type_id, i, "ts_pagetable");
		break;
	}

	case STACKSHOT_KCTYPE_SYS_SHAREDCACHE_LAYOUT: {
		i = 0;
		_SUBTYPE(KC_ST_UINT64, struct user64_dyld_uuid_info, imageLoadAddress);
		_SUBTYPE_ARRAY(KC_ST_UINT8, struct user64_dyld_uuid_info, imageUUID, 16);
		setup_type_definition(retval, type_id, i, "system_shared_cache_layout");
		break;
	}

	default:
		retval = NULL;
		break;
	}

	assert(retval == NULL || (buffer_size > sizeof(struct kcdata_type_definition) +
	    (retval->kct_num_elements * sizeof(struct kcdata_subtype_descriptor))));
	return retval;
}

static void
setup_type_definition(struct kcdata_type_definition * d, uint32_t type, uint32_t num_elems, char * name)
{
	d->kct_type_identifier = type;
	d->kct_num_elements = num_elems;
	memcpy(d->kct_name, name, sizeof(d->kct_name));
	d->kct_name[sizeof(d->kct_name) - 1] = '\0';
}

static uint32_t
get_kctype_subtype_size(kctype_subtype_t type)
{
	switch (type) {
	case KC_ST_CHAR:
	case KC_ST_INT8:
	case KC_ST_UINT8:
		return sizeof(uint8_t);
		break;
	case KC_ST_INT16:
	case KC_ST_UINT16:
		return sizeof(uint16_t);
		break;
	case KC_ST_INT32:
	case KC_ST_UINT32:
		return sizeof(uint32_t);
		break;
	case KC_ST_INT64:
	case KC_ST_UINT64:
		return sizeof(uint64_t);
		break;

	default:
		assert(0);
		break;
	}
	return 0;
}

static void
setup_subtype_array_description(
	kcdata_subtype_descriptor_t desc, kctype_subtype_t type, uint32_t offset, uint32_t count, char * name)
{
	desc->kcs_flags       = KCS_SUBTYPE_FLAGS_ARRAY;
	desc->kcs_elem_type   = type;
	desc->kcs_elem_offset = offset;
	desc->kcs_elem_size = KCS_SUBTYPE_PACK_SIZE(count, get_kctype_subtype_size(type));
	memcpy(desc->kcs_name, name, sizeof(desc->kcs_name));
	desc->kcs_name[sizeof(desc->kcs_name) - 1] = '\0';
}

static void
setup_subtype_description(kcdata_subtype_descriptor_t desc, kctype_subtype_t type, uint32_t offset, char * name)
{
	desc->kcs_flags       = KCS_SUBTYPE_FLAGS_NONE;
	desc->kcs_elem_type   = type;
	desc->kcs_elem_offset = offset;
	desc->kcs_elem_size = get_kctype_subtype_size(type);
	memcpy(desc->kcs_name, name, sizeof(desc->kcs_name));
	desc->kcs_name[sizeof(desc->kcs_name) - 1] = '\0';
}
