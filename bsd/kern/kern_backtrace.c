/*
 * Copyright (c) 2016, 2019 Apple Computer, Inc. All rights reserved.
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

#include <kern/backtrace.h>
#include <kern/kalloc.h>
#include <sys/errno.h>
#include <sys/sysctl.h>
#include <sys/systm.h>

#if DEVELOPMENT || DEBUG

#define MAX_BACKTRACE  (128)

#define BACKTRACE_USER (0)

static int backtrace_sysctl SYSCTL_HANDLER_ARGS;

SYSCTL_NODE(_kern, OID_AUTO, backtrace, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "backtrace");

SYSCTL_PROC(_kern_backtrace, OID_AUTO, user,
    CTLFLAG_RW | CTLFLAG_LOCKED, (void *)BACKTRACE_USER,
    sizeof(uint64_t), backtrace_sysctl, "O",
    "take user backtrace of current thread");

static int
backtrace_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg2)
	uintptr_t type = (uintptr_t)arg1;
	uintptr_t *bt = NULL;
	uint32_t bt_len = 0, bt_filled = 0;
	size_t bt_size = 0;
	int error = 0;

	if (type != BACKTRACE_USER) {
		return EINVAL;
	}

	if (req->oldptr == USER_ADDR_NULL || req->oldlen == 0) {
		return EFAULT;
	}

	bt_len = req->oldlen > MAX_BACKTRACE ? MAX_BACKTRACE : req->oldlen;
	bt_size = sizeof(bt[0]) * bt_len;
	bt = kalloc(bt_size);
	if (!bt) {
		return ENOBUFS;
	}
	memset(bt, 0, bt_size);
	error = backtrace_user(bt, bt_len, &bt_filled, NULL, NULL);
	if (error) {
		goto out;
	}
	bt_filled = min(bt_filled, bt_len);

	error = copyout(bt, req->oldptr, sizeof(bt[0]) * bt_filled);
	if (error) {
		goto out;
	}
	req->oldidx = bt_filled;

out:
	kfree(bt, bt_size);
	return error;
}

#endif /* DEVELOPMENT || DEBUG */
