/*
 * Copyright (c) 2018 Apple Inc. All rights reserved.
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

#include <stdatomic.h>
#include <kern/kalloc.h>
#include <libkern/libkern.h>
#include <sys/sysctl.h>
#include "ubsan.h"

/*
 * To dump the violation log:
 *   $ sysctl kern.ubsan.log
 *
 * To reset:
 *   $ sysctl kern.ubsan.logentries=0
 */

static const size_t ubsan_log_size = 2048;
struct ubsan_violation ubsan_log[ubsan_log_size];

_Atomic size_t ubsan_log_head = 0; /* first valid entry */
_Atomic size_t ubsan_log_tail = 0; /* next free slot (reader) */
_Atomic size_t ubsan_log_next = 0; /* next free slot (writer) */

static const bool ubsan_logging = true;

static inline size_t
next_entry(size_t x)
{
	return (x + 1) % ubsan_log_size;
}

void
ubsan_log_append(struct ubsan_violation *e)
{
	if (!ubsan_logging) {
		return;
	}

	/* reserve a slot */
	size_t i = atomic_load(&ubsan_log_next);
	size_t n;
	do {
		n = next_entry(i);
		if (n == ubsan_log_tail) {
			return; /* full */
		}
	} while (!atomic_compare_exchange_weak(&ubsan_log_next, &i, n));

	ubsan_log[i] = *e;

	/* make the entry available */
	size_t prev;
	do {
		prev = i;
	} while (!atomic_compare_exchange_weak(&ubsan_log_head, &prev, n));
}

static int
sysctl_ubsan_log_dump SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	const size_t sz = ubsan_log_size * 256;
	size_t start = atomic_load(&ubsan_log_tail);
	size_t end = atomic_load(&ubsan_log_head);

	char *buf;
	size_t n = 0;
	int err;

	if (start == end) {
		return 0; /* log is empty */
	}

	buf = kalloc(sz);
	if (!buf) {
		return 0;
	}
	bzero(buf, sz);

	for (size_t i = start; i != end; i = next_entry(i)) {
		n += ubsan_format(&ubsan_log[i], buf + n, sz - n);
	}

	err = SYSCTL_OUT(req, buf, n);

	kfree(buf, sz);
	return err;
}

static int
sysctl_ubsan_log_entries SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int ch, err, val;

	int nentries;
	if (ubsan_log_head >= ubsan_log_tail) {
		nentries = ubsan_log_head - ubsan_log_tail;
	} else {
		nentries = ubsan_log_size - (ubsan_log_tail - ubsan_log_head + 1);
	}

	err = sysctl_io_number(req, nentries, sizeof(nentries), &val, &ch);
	if (err == 0 && ch) {
		if (val != 0) {
			err = EINVAL;
		} else {
			ubsan_log_tail = ubsan_log_head;
		}
	}

	return err;
}

SYSCTL_DECL(ubsan);
SYSCTL_NODE(_kern, OID_AUTO, ubsan, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "");

SYSCTL_COMPAT_UINT(_kern_ubsan, OID_AUTO, logsize, CTLFLAG_RD, NULL, (unsigned)ubsan_log_size, "");

SYSCTL_PROC(_kern_ubsan, OID_AUTO, logentries,
    CTLTYPE_INT | CTLFLAG_RW,
    0, 0, sysctl_ubsan_log_entries, "I", "");

SYSCTL_PROC(_kern_ubsan, OID_AUTO, log,
    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MASKED,
    0, 0, sysctl_ubsan_log_dump, "A", "");
