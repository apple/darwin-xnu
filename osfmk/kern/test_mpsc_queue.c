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

#include <machine/machine_cpu.h>
#include <kern/locks.h>
#include <kern/mpsc_queue.h>
#include <kern/thread.h>

#if !DEBUG && !DEVELOPMENT
#error "Test only file"
#endif

#include <sys/errno.h>

struct mpsc_test_pingpong_queue {
	struct mpsc_daemon_queue queue;
	struct mpsc_queue_chain link;
	struct mpsc_test_pingpong_queue *other;
	uint64_t *count, *end;
};

static void
mpsc_test_pingpong_invoke(mpsc_queue_chain_t elm, mpsc_daemon_queue_t dq)
{
	struct mpsc_test_pingpong_queue *q;
	q = mpsc_queue_element(elm, struct mpsc_test_pingpong_queue, link);
	assert(&q->queue == dq);

	if (*q->count % 10000 == 0) {
		printf("mpsc_test_pingpong: %lld asyncs left\n", *q->count);
	}
	if ((*q->count)-- > 0) {
		mpsc_daemon_enqueue(&q->other->queue, &q->other->link,
		    MPSC_QUEUE_DISABLE_PREEMPTION);
	} else {
		*q->end = mach_absolute_time();
		thread_wakeup(&mpsc_test_pingpong_invoke);
	}
}

/*
 * The point of this test is to exercise the enqueue/unlock-drain race
 * since the MPSC queue tries to mimize wakeups when it knows it's useless.
 *
 * It also ensures basic enqueue properties,
 * and will panic if anything goes wrong to help debugging state.
 *
 * Performance wise, we will always go through the wakeup codepath,
 * hence this is mostly a benchmark of
 * assert_wait()/clear_wait()/thread_block()/thread_wakeup()
 * rather than a benchmark of the MPSC queues.
 */
int
mpsc_test_pingpong(uint64_t count, uint64_t *out)
{
	struct mpsc_test_pingpong_queue ping, pong;
	kern_return_t kr;
	wait_result_t wr;

	if (count < 1000 || count > 1000 * 1000) {
		return EINVAL;
	}

	printf("mpsc_test_pingpong: START\n");

	kr = mpsc_daemon_queue_init_with_thread(&ping.queue,
	    mpsc_test_pingpong_invoke, MINPRI_KERNEL, "ping");
	if (kr != KERN_SUCCESS) {
		panic("mpsc_test_pingpong: unable to create pong: %x", kr);
	}

	kr = mpsc_daemon_queue_init_with_thread(&pong.queue,
	    mpsc_test_pingpong_invoke, MINPRI_KERNEL, "pong");
	if (kr != KERN_SUCCESS) {
		panic("mpsc_test_pingpong: unable to create ping: %x", kr);
	}

	uint64_t n = count, start, end;
	ping.count = pong.count = &n;
	ping.end   = pong.end   = &end;
	ping.other = &pong;
	pong.other = &ping;

	assert_wait_timeout(&mpsc_test_pingpong_invoke, THREAD_UNINT,
	    5000, 1000 * NSEC_PER_USEC);
	start = mach_absolute_time();
	mpsc_daemon_enqueue(&ping.queue, &ping.link, MPSC_QUEUE_DISABLE_PREEMPTION);

	wr = thread_block(THREAD_CONTINUE_NULL);
	if (wr == THREAD_TIMED_OUT) {
		panic("mpsc_test_pingpong: timed out: ping:%p pong:%p", &ping, &pong);
	}

	printf("mpsc_test_pingpong: CLEANUP\n");

	mpsc_daemon_queue_cancel_and_wait(&ping.queue);
	mpsc_daemon_queue_cancel_and_wait(&pong.queue);
	absolutetime_to_nanoseconds(end - start, out);

	printf("mpsc_test_pingpong: %lld ping-pongs in %lld ns (%lld.%03lld us/async)\n",
	    count, *out, (*out / count) / 1000, (*out / count) % 1000);
	return 0;
}
