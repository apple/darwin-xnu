/*
 * Copyright (c) 2013 Apple Inc. All rights reserved.
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

#include <kern/energy_perf.h>
#include <sys/kdebug.h>
#include <stddef.h>
#include <machine/machine_routines.h>

void gpu_describe(__unused gpu_descriptor_t gdesc) {
	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_ENERGY_PERF, 1), gdesc->gpu_id, gdesc->gpu_max_domains, 0, 0, 0);
}

uint64_t gpu_accumulate_time(__unused uint32_t scope, __unused uint32_t gpu_id, __unused uint32_t gpu_domain, __unused uint64_t gpu_accumulated_ns, __unused uint64_t gpu_tstamp_ns) {
	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_ENERGY_PERF, 2), scope, gpu_id, gpu_domain, gpu_accumulated_ns, gpu_tstamp_ns);
	ml_gpu_stat_update(gpu_accumulated_ns);
	return 0;
}

static uint64_t io_rate_update_cb_default(__unused uint64_t io_rate_flags, __unused uint64_t read_ops_delta, __unused uint64_t write_ops_delta, __unused uint64_t read_bytes_delta, __unused uint64_t write_bytes_delta) {
	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_ENERGY_PERF, 3), io_rate_flags, read_ops_delta, write_ops_delta, read_bytes_delta, write_bytes_delta);
	return 0;
}

io_rate_update_callback_t io_rate_update_cb = io_rate_update_cb_default;

void io_rate_update_register(io_rate_update_callback_t io_rate_update_cb_new) {
	if (io_rate_update_cb_new != NULL) {
		io_rate_update_cb = io_rate_update_cb_new;
	} else {
		io_rate_update_cb = io_rate_update_cb_default;
	}
}

uint64_t io_rate_update(uint64_t io_rate_flags, uint64_t read_ops_delta, uint64_t write_ops_delta, uint64_t read_bytes_delta, uint64_t write_bytes_delta) {
	return io_rate_update_cb(io_rate_flags, read_ops_delta, write_ops_delta, read_bytes_delta, write_bytes_delta);
}
