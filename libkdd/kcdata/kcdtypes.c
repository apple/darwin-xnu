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


#include <Kernel/kern/kern_cdata.h>
#include <Kernel/kern/debug.h>
#include <sys/time.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <mach/mach_time.h>
#include <sys/proc_info.h>
#include <corpses/task_corpse.h>

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
struct kcdata_type_definition *kcdata_get_typedescription(unsigned type_id, uint8_t *buffer, uint32_t buffer_size);



/* forward declarations for helper routines */
static uint32_t get_kctype_subtype_size(kctype_subtype_t type);
static void setup_subtype_description(kcdata_subtype_descriptor_t desc, kctype_subtype_t type, uint32_t offset, char *name);
static void setup_subtype_array_description(kcdata_subtype_descriptor_t desc, kctype_subtype_t type, uint32_t offset, uint32_t count, char *name);
static void setup_type_definition(struct kcdata_type_definition *d, uint32_t type, uint32_t num_elems, char *name);

struct kcdata_type_definition *kcdata_get_typedescription(unsigned type_id, uint8_t *buffer, uint32_t buffer_size)
{
	int i = 0;
#define _STR_VALUE(x)  #x
#define _SUBTYPE(t, s, f)     setup_subtype_description(&subtypes[i++], (t), offsetof(s,f), _STR_VALUE(f))
#define _SUBTYPE_ARRAY(t, s, f, c)   setup_subtype_array_description(&subtypes[i++], (t), offsetof(s,f), (c), _STR_VALUE(f))
#define _STRINGTYPE(f)        setup_subtype_array_description(&subtypes[i++], KC_ST_CHAR, 0, UINT16_MAX, f)


    
    if (buffer_size < sizeof(struct kcdata_type_definition) || buffer == NULL)
        return NULL;
    
	struct kcdata_type_definition *retval = (struct kcdata_type_definition *)&buffer[0];
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

		case KCDATA_TYPE_CONTAINER_BEGIN :{
			i = 0;
			setup_subtype_description(&subtypes[i++], KC_ST_UINT32, 0, "kcContainerType");
			setup_type_definition(retval, type_id, i, "container_begin");
			break;
		}
            
        case KCDATA_TYPE_LIBRARY_LOADINFO: {
            i = 0;
            _SUBTYPE(KC_ST_UINT32, struct dyld_uuid_info_32, imageLoadAddress);
            _SUBTYPE_ARRAY(KC_ST_UINT8, struct dyld_uuid_info_32, imageUUID, 16);
            setup_type_definition(retval, type_id, i, "dyld_load_info");
            break;
            
        }
        
        case KCDATA_TYPE_LIBRARY_LOADINFO64: /* fall through */
        case STACKSHOT_KCTYPE_SHAREDCACHE_LOADINFO: {
            i = 0;
            _SUBTYPE(KC_ST_UINT64, struct dyld_uuid_info_64, imageLoadAddress);
            _SUBTYPE_ARRAY(KC_ST_UINT8, struct dyld_uuid_info_64, imageUUID, 16);
            setup_type_definition(retval, type_id, i, "dyld_load_info");
            break;
        }
            
        case KCDATA_TYPE_TIMEBASE: {
            i = 0;
            _SUBTYPE(KC_ST_UINT32, struct mach_timebase_info, numer);
            _SUBTYPE(KC_ST_UINT32, struct mach_timebase_info, denom);
            setup_type_definition(retval, type_id, i, "mach_timebase_info");
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
        }

	case KCDATA_TYPE_USECS_SINCE_EPOCH:
            setup_type_definition(retval, type_id, 1, "usecs_since_epoch");
            setup_subtype_description(&subtypes[0], KC_ST_UINT64, 0, "usecs_since_epoch");
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
			
		case STACKSHOT_KCTYPE_GLOBAL_MEM_STATS       :
		{   i = 0;
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
            
		case STACKSHOT_KCTYPE_THREAD_SNAPSHOT: {
			i = 0;
			
			_SUBTYPE(KC_ST_UINT64, struct thread_snapshot_v2, ths_thread_id);
			_SUBTYPE(KC_ST_UINT64, struct thread_snapshot_v2, ths_wait_event);
			_SUBTYPE(KC_ST_UINT64, struct thread_snapshot_v2, ths_continuation);
			_SUBTYPE(KC_ST_UINT64, struct thread_snapshot_v2, ths_total_syscalls);
			_SUBTYPE(KC_ST_UINT64, struct thread_snapshot_v2, ths_voucher_identifier);
			_SUBTYPE(KC_ST_UINT64, struct thread_snapshot_v2, ths_dqserialnum);
			_SUBTYPE(KC_ST_UINT64, struct thread_snapshot_v2, ths_user_time);
			_SUBTYPE(KC_ST_UINT64, struct thread_snapshot_v2, ths_sys_time);
			_SUBTYPE(KC_ST_UINT64, struct thread_snapshot_v2, ths_ss_flags);
			_SUBTYPE(KC_ST_UINT64, struct thread_snapshot_v2, ths_last_run_time);
			_SUBTYPE(KC_ST_UINT32, struct thread_snapshot_v2, ths_state);
			_SUBTYPE(KC_ST_UINT32, struct thread_snapshot_v2, ths_sched_flags);
			_SUBTYPE(KC_ST_INT16, struct thread_snapshot_v2, ths_base_priority);
			_SUBTYPE(KC_ST_INT16, struct thread_snapshot_v2, ths_sched_priority);
			_SUBTYPE(KC_ST_UINT8, struct thread_snapshot_v2, ths_eqos);
			_SUBTYPE(KC_ST_UINT8, struct thread_snapshot_v2, ths_rqos);
			_SUBTYPE(KC_ST_UINT8, struct thread_snapshot_v2, ths_rqos_override);
			_SUBTYPE(KC_ST_UINT8, struct thread_snapshot_v2, ths_io_tier);
			
			setup_type_definition(retval, type_id, i, "thread_snapshot");
			break;
		}

			
		case STASKSHOT_KCTYPE_DONATING_PIDS:
			setup_type_definition(retval, type_id, 1, "donating_pids");
			setup_subtype_description(&subtypes[0], KC_ST_INT32, 0, "pid");
			break;
            
        case STACKSHOT_KCTYPE_THREAD_NAME:{
            i = 0;
            setup_subtype_array_description(&subtypes[i++], KC_ST_CHAR, 0, 64, "pth_name");
            setup_type_definition(retval, type_id, i, "pth_name");
            break;
        }
            
		case STACKSHOT_KCTYPE_KERN_STACKFRAME        :
			setup_type_definition(retval, type_id, 2, "kernel_stack_frames");
			setup_subtype_description(&subtypes[0], KC_ST_UINT32, 0, "lr");
			setup_subtype_description(&subtypes[1], KC_ST_UINT32, sizeof(uint32_t), "sp");
			break;
            
		case STACKSHOT_KCTYPE_KERN_STACKFRAME64      :
			setup_type_definition(retval, type_id, 2, "kernel_stack_frames");
			setup_subtype_description(&subtypes[0], KC_ST_UINT64, 0, "lr");
			setup_subtype_description(&subtypes[1], KC_ST_UINT64, sizeof(uint64_t), "sp");
			break;
			
		case STACKSHOT_KCTYPE_USER_STACKFRAME        :
			setup_type_definition(retval, type_id, 2, "user_stack_frames");
			setup_subtype_description(&subtypes[0], KC_ST_UINT32, 0, "lr");
			setup_subtype_description(&subtypes[1], KC_ST_UINT32, sizeof(uint32_t), "sp");
			break;
			
		case STACKSHOT_KCTYPE_USER_STACKFRAME64      :
			setup_type_definition(retval, type_id, 2, "user_stack_frames");
			setup_subtype_description(&subtypes[0], KC_ST_UINT64, 0, "lr");
			setup_subtype_description(&subtypes[1], KC_ST_UINT64, sizeof(uint64_t), "sp");
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

	case STACKSHOT_KCTYPE_JETSAM_LEVEL: {
		i = 0;
		setup_subtype_description(&subtypes[i++], KC_ST_UINT32, 0, "jetsam_level");
		setup_type_definition(retval, type_id, i, "jetsam_level");
		break;
	}

			/* crashinfo types */
        case TASK_CRASHINFO_BSDINFOWITHUNIQID:
        {   i = 0;
            _SUBTYPE_ARRAY(KC_ST_UINT8, struct proc_uniqidentifierinfo, p_uuid, 16);
            _SUBTYPE(KC_ST_UINT64, struct proc_uniqidentifierinfo, p_uniqueid);
            _SUBTYPE(KC_ST_UINT64, struct proc_uniqidentifierinfo, p_puniqueid);
            /* Ignore the p_reserve fields */
            setup_type_definition(retval, type_id, i, "proc_uniqidentifierinfo");
            break;
        }
            
        case TASK_CRASHINFO_PID:{
            setup_subtype_description(&subtypes[0], KC_ST_INT32, 0, "pid");
            setup_type_definition(retval, type_id, 1, "pid");
            break;
        }

        case TASK_CRASHINFO_PPID:{
            setup_subtype_description(&subtypes[0], KC_ST_INT32, 0, "ppid");
            setup_type_definition(retval, type_id, 1, "ppid");
            break;
        }
            
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
        }
            
        case TASK_CRASHINFO_PROC_NAME: {
            i = 0;
            _STRINGTYPE("p_comm");
            setup_type_definition(retval, type_id, i, "p_comm");
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
        }
            
        case TASK_CRASHINFO_PROC_CSFLAGS:{
            setup_subtype_description(&subtypes[0], KC_ST_UINT32, 0, "p_csflags");
            setup_type_definition(retval, type_id, 1, "p_csflags");
            break;
        }
            
        case TASK_CRASHINFO_PROC_STATUS: {
            setup_subtype_description(&subtypes[0], KC_ST_UINT8, 0, "p_status");
            setup_type_definition(retval, type_id, 1, "p_status");
            break;
        }
            
        case TASK_CRASHINFO_UID:{
            setup_subtype_description(&subtypes[0], KC_ST_INT32, 0, "uid");
            setup_type_definition(retval, type_id, 1, "uid");
            break;
        }
            
        case TASK_CRASHINFO_GID:{
            setup_subtype_description(&subtypes[0], KC_ST_INT32, 0, "gid");
            setup_type_definition(retval, type_id, 1, "gid");
            break;
        }
            
        case TASK_CRASHINFO_PROC_ARGC:{
            setup_subtype_description(&subtypes[0], KC_ST_INT32, 0, "argc");
            setup_type_definition(retval, type_id, 1, "argc");
            break;
        }
            
        case TASK_CRASHINFO_PROC_FLAGS:{
            setup_subtype_description(&subtypes[0], KC_ST_UINT32, 0, "p_flags");
            setup_type_definition(retval, type_id, 1, "p_flags");
            break;
        }
            
        case TASK_CRASHINFO_CPUTYPE:{
            setup_subtype_description(&subtypes[0], KC_ST_INT32, 0, "cputype");
            setup_type_definition(retval, type_id, 1, "cputype");
            break;
        }
            
        case TASK_CRASHINFO_RESPONSIBLE_PID:{
            setup_subtype_description(&subtypes[0], KC_ST_INT32, 0, "responsible_pid");
            setup_type_definition(retval, type_id, 1, "responsible_pid");
            break;
        }
            
        case TASK_CRASHINFO_DIRTY_FLAGS:{
            setup_subtype_description(&subtypes[0], KC_ST_UINT32, 0, "dirty_flags");
            setup_type_definition(retval, type_id, 1, "dirty_flags");
            break;
        }
            
        case TASK_CRASHINFO_CRASHED_THREADID: {
            setup_subtype_description(&subtypes[0], KC_ST_UINT64, 0, "crashed_threadid");
            setup_type_definition(retval, type_id, 1, "crashed_threadid");
            break;
        }

		default:
			retval = NULL;
			break;
	}
	
    assert(retval == NULL || (buffer_size > sizeof(struct kcdata_type_definition) + (retval->kct_num_elements * sizeof(struct kcdata_subtype_descriptor))));
	return retval;
}


static void setup_type_definition(struct kcdata_type_definition *d, uint32_t type, uint32_t num_elems, char *name)
{
    d->kct_type_identifier = type;
    d->kct_num_elements = num_elems;
    memcpy(d->kct_name, name, sizeof(d->kct_name));
    d->kct_name[sizeof(d->kct_name) - 1] = '\0';
}

static uint32_t get_kctype_subtype_size(kctype_subtype_t type){
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

static void setup_subtype_array_description(kcdata_subtype_descriptor_t desc, kctype_subtype_t type, uint32_t offset, uint32_t count, char *name)
{
    desc->kcs_flags = KCS_SUBTYPE_FLAGS_ARRAY;
    desc->kcs_elem_type = type;
    desc->kcs_elem_offset = offset;
    desc->kcs_elem_size = KCS_SUBTYPE_PACK_SIZE(count, get_kctype_subtype_size(type));
    memcpy(desc->kcs_name, name, sizeof(desc->kcs_name));
    desc->kcs_name[sizeof(desc->kcs_name) - 1] = '\0';
}

static void setup_subtype_description(kcdata_subtype_descriptor_t desc, kctype_subtype_t type, uint32_t offset, char *name)
{
    desc->kcs_flags = KCS_SUBTYPE_FLAGS_NONE;
    desc->kcs_elem_type = type;
    desc->kcs_elem_offset = offset;
    desc->kcs_elem_size = get_kctype_subtype_size(type);
    memcpy(desc->kcs_name, name, sizeof(desc->kcs_name));
    desc->kcs_name[sizeof(desc->kcs_name) - 1] = '\0';
}

