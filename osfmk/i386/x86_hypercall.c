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

#include <kern/assert.h>
#include <kern/hvg_hypercall.h>
#include <i386/cpuid.h>
#include <os/log.h>


static bool
hvg_live_coredump_enabled(void)
{
	return cpuid_vmm_present() && (cpuid_vmm_get_applepv_features() & CPUID_LEAF_FEATURE_COREDUMP) != 0;
}

/*
 * This routine issues an Apple hypercall that notifies the hypervisor to
 * take a guest kernel coredump. If the vmcore argument is not NULL, the
 * name tag of the vmcore file is copied into the caller's vmcore tag array.
 * Otherwise the name tag is ignored.
 */

hvg_hcall_return_t
hvg_hcall_trigger_dump(hvg_hcall_vmcore_file_t *vmcore,
    const hvg_hcall_dump_option_t dump_option)
{
	hvg_hcall_return_t ret;
	hvg_hcall_output_regs_t output;
	const size_t reg_size = sizeof(output.rax);

	/* Does the hypervisor support feature: live kernel core dump? */
	if (!hvg_live_coredump_enabled()) {
		return HVG_HCALL_FEAT_DISABLED;
	}

	/* Make sure that we don't overflow vmcore tag array with hypercall output */
	if (vmcore && (reg_size != sizeof(uint64_t))) {
		os_log_error(OS_LOG_DEFAULT, "%s: invalid hcall register size, %zu bytes (expect %zu bytes)\n",
		    __func__, reg_size, sizeof(uint64_t));
		return HVG_HCALL_INVALID_PARAMETER;
	}

	switch (dump_option) {
	case HVG_HCALL_DUMP_OPTION_REGULAR:
		/* Only regular dump-guest-memory is supported for now */
		break;
	default:
		return HVG_HCALL_INVALID_PARAMETER;
	}

	/* Everything checks out, issue hypercall */
	memset(&output, 0, sizeof(hvg_hcall_output_regs_t));
	ret = hvg_hypercall1(HVG_HCALL_TRIGGER_DUMP,
	    dump_option,
	    &output);

	if (ret == HVG_HCALL_SUCCESS) {
		if (vmcore) {
			/* Caller requested vmcore tag to be returned */
			memcpy(&vmcore->tag[0], &output.rax, reg_size);
			memcpy(&vmcore->tag[reg_size], &output.rdi, reg_size);
			memcpy(&vmcore->tag[reg_size * 2], &output.rsi, reg_size);
			memcpy(&vmcore->tag[reg_size * 3], &output.rdx, reg_size);
			memcpy(&vmcore->tag[reg_size * 4], &output.rcx, reg_size);
			memcpy(&vmcore->tag[reg_size * 5], &output.r8, reg_size);
			memcpy(&vmcore->tag[reg_size * 6], &output.r9, reg_size);
			vmcore->tag[reg_size * 7] = '\0';
		}
	}
	return ret;
}
