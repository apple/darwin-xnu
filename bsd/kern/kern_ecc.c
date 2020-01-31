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
#include <kern/debug.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/priv.h>
#include <mach/machine.h>
#include <libkern/libkern.h>
#include <kern/assert.h>
#include <pexpert/pexpert.h>
#include <kern/ecc.h>

static int
get_ecc_data_handler(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2,
    struct sysctl_req *req)
{
	struct ecc_event ev;
	int changed, retval;

	if (priv_check_cred(kauth_cred_get(), PRIV_HW_DEBUG_DATA, 0) != 0) {
		return EPERM;
	}

	if (KERN_SUCCESS != ecc_log_get_next_event(&ev)) {
		/*
		 * EAGAIN would be better, but sysctl infrastructure
		 * interprets that */
		return EBUSY;
	}

	retval = sysctl_io_opaque(req, &ev, sizeof(ev), &changed);
	assert(!changed);

	return retval;
}

SYSCTL_PROC(_kern, OID_AUTO, next_ecc_event,
    CTLFLAG_RD | CTLFLAG_ANYBODY | CTLFLAG_MASKED | CTLTYPE_STRUCT,
    0, 0, get_ecc_data_handler,
    "-", "");
