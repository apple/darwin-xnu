/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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

#pragma once

#include <mach/port.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	kHV_ION_NONE             = (0u << 0),
	kHV_ION_ANY_VALUE        = (1u << 1),
	kHV_ION_ANY_SIZE         = (1u << 2),
	kHV_ION_EXIT_FULL        = (1u << 3),
};

#ifdef KERNEL_PRIVATE

typedef struct {
	mach_msg_header_t header;
	uint64_t addr;
	uint64_t size;
	uint64_t value;
} hv_ion_message_t;

typedef struct {
	uint64_t addr;
	uint64_t size;
	uint64_t value;
	uint32_t port_name;
	uint32_t flags;
} hv_ion_t;

typedef struct hv_ion_grp hv_ion_grp_t;

extern kern_return_t hv_io_notifier_grp_add(hv_ion_grp_t *grp, const hv_ion_t *);
extern kern_return_t hv_io_notifier_grp_remove(hv_ion_grp_t *, const hv_ion_t *);
extern kern_return_t hv_io_notifier_grp_fire(hv_ion_grp_t *, uint64_t, size_t, uint64_t);
extern kern_return_t hv_io_notifier_grp_alloc(hv_ion_grp_t **);
extern void hv_io_notifier_grp_free(hv_ion_grp_t **);

#endif /* KERNEL_PRIVATE */

#ifdef __cplusplus
}
#endif
