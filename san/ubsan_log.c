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

#include <os/atomic_private.h>
#include <kern/cpu_data.h>
#include <kern/kalloc.h>
#include <kern/simple_lock.h> // hw_wait_while_equals
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

/*
 * Implement a fixed-size buffer FIFO, similar to the Chase-Lev DeQueue.
 *
 * See https://fzn.fr/readings/ppopp13.pdf for explanations on barriers.
 */
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
ubsan_log_append(struct ubsan_violation *violation)
{
	if (!ubsan_logging) {
		return;
	}

	/* reserve a slot */
	size_t i, e, n;

	disable_preemption();

	os_atomic_rmw_loop(&ubsan_log_next, i, n, relaxed, {
		n = next_entry(i);
		if (n == os_atomic_load(&ubsan_log_tail, acquire)) {
		        enable_preemption();
		        return; /* full */
		}
	});

	ubsan_log[i] = *violation;
	os_atomic_thread_fence(release);

	/* make the entry available */
again:
	os_atomic_rmw_loop(&ubsan_log_head, e, n, relaxed, {
		if (e != i) {
		        // we need to wait for another enqueuer
		        os_atomic_rmw_loop_give_up({
				hw_wait_while_equals((void **)&ubsan_log_head, (void *)e);
				goto again;
			});
		}
	});

	enable_preemption();
}

static int
sysctl_ubsan_log_dump SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	const size_t sz = ubsan_log_size * 256;
	size_t head, tail;

	head = os_atomic_load(&ubsan_log_head, relaxed);
	os_atomic_thread_fence(seq_cst);
	tail = os_atomic_load(&ubsan_log_tail, relaxed);

	char *buf;
	size_t n = 0;
	int err;

	if (tail == head) {
		return 0; /* log is empty */
	}

	buf = kheap_alloc(KHEAP_TEMP, sz, Z_WAITOK | Z_ZERO);
	if (!buf) {
		return 0;
	}

	for (size_t i = tail; i != head; i = next_entry(i)) {
		n += ubsan_format(&ubsan_log[i], buf + n, sz - n);
	}

	err = SYSCTL_OUT(req, buf, n);

	kheap_free(KHEAP_TEMP, buf, sz);
	return err;
}

static int
sysctl_ubsan_log_entries SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int ch, err, val;
	size_t head, tail;

	size_t nentries;

	head = os_atomic_load(&ubsan_log_head, relaxed);
	os_atomic_thread_fence(seq_cst);
	tail = os_atomic_load(&ubsan_log_tail, relaxed);

	if (head >= tail) {
		nentries = head - tail;
	} else {
		nentries = ubsan_log_size - (tail - head + 1);
	}

	err = sysctl_io_number(req, nentries, sizeof(nentries), &val, &ch);
	if (err == 0 && ch) {
		if (val != 0) {
			err = EINVAL;
		} else {
			os_atomic_store(&ubsan_log_tail, head, relaxed);
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
