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

#ifndef _KERN_HVG_HYPERCALL_H_
#define _KERN_HVG_HYPERCALL_H_

#include <os/base.h>
#include <stdint.h>

/* Architecture-independent definitions (exported to userland) */

/*
 * Apple Hypercall arguments
 */
typedef struct hvg_hcall_args {
	uint64_t args[6];
} hvg_hcall_args_t;


/*
 * Apple Hypercall return output
 */
typedef struct hvg_hcall_output {
	uint64_t regs[7];
} hvg_hcall_output_t;


/*
 * Apple Hypercall return code
 */

OS_CLOSED_ENUM(hvg_hcall_return, uint32_t,
    HVG_HCALL_SUCCESS             = 0x0000,       /* The call succeeded */
    HVG_HCALL_ACCESS_DENIED       = 0x0001,       /* Invalid access right */
    HVG_HCALL_INVALID_CODE        = 0x0002,       /* Hypercall code not recognized */
    HVG_HCALL_INVALID_PARAMETER   = 0x0003,       /* Specified register value not valid */
    HVG_HCALL_IO_FAILED           = 0x0004,       /* Input/output error */
    HVG_HCALL_FEAT_DISABLED       = 0x0005,       /* Feature not available */
    HVG_HCALL_UNSUPPORTED         = 0x0006,       /* Hypercall not supported */
    );


/*
 * Apple Hypercall call code
 */

OS_CLOSED_ENUM(hvg_hcall_code, uint32_t,
    HVG_HCALL_TRIGGER_DUMP        = 0x0001,       /* Collect guest dump */
    );

/*
 * Options for collecting kernel vmcore
 */

OS_CLOSED_OPTIONS(hvg_hcall_dump_option, uint32_t,
    HVG_HCALL_DUMP_OPTION_REGULAR   =  0x0001     /* Regular dump-guest-memory */
    );

typedef struct hvg_hcall_vmcore_file {
	char tag[57];   /* 7 64-bit registers plus 1 byte for '\0' */
} hvg_hcall_vmcore_file_t;

extern hvg_hcall_return_t
hvg_hcall_trigger_dump(hvg_hcall_vmcore_file_t *vmcore,
    const hvg_hcall_dump_option_t dump_option);


#ifdef XNU_KERNEL_PRIVATE

/*
 * For XNU kernel use only (omitted from userland headers)
 */

#if defined (__x86_64__)
#include <i386/cpuid.h>
#include <i386/x86_hypercall.h>
#endif

#endif /* XNU_KERNEL_PRIVATE */

#endif /* _KERN_HV_HYPERCALL_H_ */
