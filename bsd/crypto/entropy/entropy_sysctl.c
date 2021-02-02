/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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

#include <sys/sysctl.h>
#include <kern/zalloc.h>
#include <kern/percpu.h>
#include <crypto/entropy/entropy_sysctl.h>
#include <prng/entropy.h>
#include <libkern/section_keywords.h>

SYSCTL_NODE(_kern, OID_AUTO, entropy, CTLFLAG_RD, 0, NULL);
SYSCTL_NODE(_kern_entropy, OID_AUTO, health, CTLFLAG_RD, 0, NULL);

SYSCTL_INT(_kern_entropy_health, OID_AUTO, startup_done, CTLFLAG_RD, &entropy_health_startup_done, 0, NULL);

SYSCTL_NODE(_kern_entropy_health, OID_AUTO, repetition_count_test, CTLFLAG_RD, 0, NULL);
SYSCTL_UINT(_kern_entropy_health_repetition_count_test, OID_AUTO, reset_count, CTLFLAG_RD, &entropy_health_rct_stats.reset_count, 0, NULL);
SYSCTL_UINT(_kern_entropy_health_repetition_count_test, OID_AUTO, failure_count, CTLFLAG_RD, &entropy_health_rct_stats.failure_count, 0, NULL);
SYSCTL_UINT(_kern_entropy_health_repetition_count_test, OID_AUTO, max_observation_count, CTLFLAG_RD, &entropy_health_rct_stats.max_observation_count, 0, NULL);

SYSCTL_NODE(_kern_entropy_health, OID_AUTO, adaptive_proportion_test, CTLFLAG_RD, 0, NULL);
SYSCTL_UINT(_kern_entropy_health_adaptive_proportion_test, OID_AUTO, reset_count, CTLFLAG_RD, &entropy_health_apt_stats.reset_count, 0, NULL);
SYSCTL_UINT(_kern_entropy_health_adaptive_proportion_test, OID_AUTO, failure_count, CTLFLAG_RD, &entropy_health_apt_stats.failure_count, 0, NULL);
SYSCTL_UINT(_kern_entropy_health_adaptive_proportion_test, OID_AUTO, max_observation_count, CTLFLAG_RD, &entropy_health_apt_stats.max_observation_count, 0, NULL);

static int
sysctl_entropy_collect(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	if (!req->oldptr || req->oldlen > entropy_analysis_buffer_size) {
		return EINVAL;
	}

	return SYSCTL_OUT(req, entropy_analysis_buffer, req->oldlen);
}

// Get current size of entropy buffer in bytes
SYSCTL_UINT(_kern_entropy, OID_AUTO, entropy_buffer_size, CTLFLAG_RD | CTLFLAG_MASKED | CTLFLAG_NOAUTO, &entropy_analysis_buffer_size, 0, NULL);
// Collect contents from entropy buffer
SYSCTL_PROC(_kern_entropy, OID_AUTO, entropy_collect, CTLTYPE_OPAQUE | CTLFLAG_RD | CTLFLAG_MASKED | CTLFLAG_NOAUTO, NULL, 0, sysctl_entropy_collect, "-", NULL);

void
entropy_analysis_register_sysctls(void)
{
	sysctl_register_oid(&sysctl__kern_entropy_entropy_buffer_size);
	sysctl_register_oid(&sysctl__kern_entropy_entropy_collect);
}
