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


#include <System/machine/cpu_capabilities.h>

#include <darwintest.h>

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <ptrauth.h>
#include <dispatch/dispatch.h>
#include <libkern/OSAtomic.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

#if TARGET_OS_OSX && defined(_COMM_PAGE_TEXT_ATOMIC_ENQUEUE)

/* Keys and discriminators */
#define COMMPAGE_PFZ_BASE_AUTH_KEY ptrauth_key_process_independent_code
#define COMMPAGE_PFZ_FN_AUTH_KEY ptrauth_key_function_pointer
#define COMMPAGE_PFZ_BASE_DISCRIMINATOR ptrauth_string_discriminator("pfz")

/* Auth and sign macros */
#define SIGN_COMMPAGE_PFZ_BASE_PTR(ptr) \
	ptrauth_sign_unauthenticated(ptr, COMMPAGE_PFZ_BASE_AUTH_KEY, COMMPAGE_PFZ_BASE_DISCRIMINATOR)
#define AUTH_COMMPAGE_PFZ_BASE_PTR(ptr) \
	        ptrauth_auth_data(ptr, COMMPAGE_PFZ_BASE_AUTH_KEY, COMMPAGE_PFZ_BASE_DISCRIMINATOR)
#define SIGN_COMMPAGE_PFZ_FUNCTION_PTR(ptr) \
	ptrauth_sign_unauthenticated(ptr, COMMPAGE_PFZ_FN_AUTH_KEY, 0)

static void *commpage_pfz_base = NULL;

static void *
get_pfz_base(void)
{
	void *pfz_base = NULL;
	size_t s = sizeof(void *);

	int ret = sysctlbyname("kern.pfz", &pfz_base, &s, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "sysctlbyname(kern.pfz)");

	commpage_pfz_base = SIGN_COMMPAGE_PFZ_BASE_PTR(pfz_base);
	T_LOG("pfz base = 0x%llx\n", commpage_pfz_base);
}

static void
undefined_function(void)
{
	// We can use the same commpage_pfz_base as parent since the PFZ is slide
	// once per boot and is same across all processes
	void (*undefined)(void);
	uintptr_t addr = (uintptr_t) (void *) AUTH_COMMPAGE_PFZ_BASE_PTR(commpage_pfz_base);
	addr += _COMM_PAGE_TEXT_ATOMIC_DEQUEUE;
	addr += 4; // Jump ahead
	undefined = SIGN_COMMPAGE_PFZ_FUNCTION_PTR((void *)addr);

	return undefined();
}

typedef struct {
	void *next;
	char *str;
} QueueNode;

T_DECL(test_arm_pfz, "Validate that ARM PFZ is mapped in",
    T_META_CHECK_LEAKS(false), T_META_IGNORECRASHES(".*undefined_function*"),
    T_META_ENABLED(false) /* rdar://62615792 */)
{
	static dispatch_once_t pred;
	dispatch_once(&pred, ^{
		commpage_pfz_base = get_pfz_base();
	});

	OSFifoQueueHead head = OS_ATOMIC_FIFO_QUEUE_INIT;
	char *str1 = "String 1", *str2 = "String 2";
	QueueNode node1 = { 0, str1 };
	QueueNode node2 = { 0, str2 };

	OSAtomicFifoEnqueue(&head, &node1, 0);
	OSAtomicFifoEnqueue(&head, &node2, 0);
	QueueNode *node_ptr = OSAtomicFifoDequeue(&head, 0);
	T_ASSERT_EQ(strcmp(node_ptr->str, str1), 0, "Dequeued first node correctly");

	node_ptr = OSAtomicFifoDequeue(&head, 0);
	T_ASSERT_EQ(strcmp(node_ptr->str, str2), 0, "Dequeued second node correctly");

	node_ptr = OSAtomicFifoDequeue(&head, 0);
	T_ASSERT_EQ(node_ptr, NULL, "Dequeuing from empty list correctly");

	int child_pid = 0;
	if ((child_pid = fork()) == 0) { // Child should call undefined function
		return undefined_function();
	} else {
		int status = 0;
		wait(&status);

		T_ASSERT_EQ(!WIFEXITED(status), true, "Did not exit cleanly");
		T_ASSERT_EQ(WIFSIGNALED(status), true, "Exited due to signal");
		T_LOG("Signal number = %d\n", WTERMSIG(status));
	}
}

T_DECL(test_rdar_65270017, "Testing for rdar 65270017",
    T_META_CHECK_LEAKS(false), T_META_ENABLED(false) /* rdar://65270017 */)
{
	static dispatch_once_t pred;
	dispatch_once(&pred, ^{
		commpage_pfz_base = get_pfz_base();
	});

	struct OSAtomicFifoHeadWrapper {
		// Embedded OSFifoQueueHead structure inside the structure
		void *first;
		void *last;
		int opaque;

		int data;
	} wrapped_head = {
		.first = NULL,
		.last = NULL,
		.opaque = 0,
		.data = 0xfeed
	};

	char *str1 = "String 1", *str2 = "String 2";
	QueueNode node1 = { 0, str1 };
	QueueNode node2 = { 0, str2 };

	OSAtomicFifoEnqueue(&wrapped_head, &node1, 0);
	T_ASSERT_EQ(wrapped_head.data, 0xfeed, "data is valid");

	OSAtomicFifoEnqueue(&wrapped_head, &node2, 0);
	T_ASSERT_EQ(wrapped_head.data, 0xfeed, "data is valid");

	QueueNode *node_ptr = OSAtomicFifoDequeue(&wrapped_head, 0);
	T_ASSERT_EQ(strcmp(node_ptr->str, str1), 0, "Dequeued first node correctly");
	T_ASSERT_EQ(wrapped_head.data, 0xfeed, "data is valid");

	node_ptr = OSAtomicFifoDequeue(&wrapped_head, 0);
	T_ASSERT_EQ(strcmp(node_ptr->str, str2), 0, "Dequeued second node correctly");
	T_ASSERT_EQ(wrapped_head.data, 0xfeed, "data is valid");

	node_ptr = OSAtomicFifoDequeue(&wrapped_head, 0);
	T_ASSERT_EQ(node_ptr, NULL, "Dequeuing from empty list correctly");
	T_ASSERT_EQ(wrapped_head.data, 0xfeed, "data is valid");
}

#define WIDE    50ll
#define SMALL   2000ll

void
preheat(dispatch_queue_t dq)
{
	dispatch_apply(WIDE, dq, ^(size_t i) {
		sleep(1);
	});
}

typedef struct elem {
	long    data1;
	struct elem *link;
	int     data2;
} elem_t;

static size_t offset = offsetof(elem_t, link);
static elem_t elements[WIDE][SMALL];

T_DECL(test_65270017_contended, "multithreaded testing for radar 65270017")
{
	dispatch_queue_t global_q = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0);
	dispatch_queue_t queue = dispatch_queue_create("com.apple.libctests.threaded", 0);
	uint64_t __block t = 0;

	struct OSAtomicFifoHeadWrapper {
		// Embedded OSFifoQueueHead structure inside the structure
		void *first;
		void *last;
		int opaque;

		int data;
	};

	struct OSAtomicFifoHeadWrapper wrapped_q_head1 = {
		.first = NULL,
		.last = NULL,
		.opaque = 0,
		.data = 0xfeed
	};
	OSFifoQueueHead *q1 = (OSFifoQueueHead *) &wrapped_q_head1;

	struct OSAtomicFifoHeadWrapper wrapped_q_head2 = {
		.first = NULL,
		.last = NULL,
		.opaque = 0,
		.data = 0xdead
	};
	OSFifoQueueHead *q2 = (OSFifoQueueHead *) &wrapped_q_head2;

	t = 0;
	T_LOG("Preheating thread pool");

	preheat(global_q);

	T_LOG("Starting contended pfz test");

	dispatch_apply(WIDE, global_q, ^(size_t i) {
		dispatch_apply(SMALL, global_q, ^(size_t idx) {
			OSAtomicFifoEnqueue(q1, &(elements[i][idx]), offset); // contended enqueue on q1
		});

		uint32_t count = 0;
		elem_t *p = NULL;
		do {
		        p = OSAtomicFifoDequeue(q1, offset);
		        T_QUIET; T_ASSERT_EQ(wrapped_q_head1.data, 0xfeed, "q1 data is valid");
		        if (p) {
		                OSAtomicFifoEnqueue(q2, p, offset);
		                T_QUIET; T_ASSERT_EQ(wrapped_q_head2.data, 0xdead, "q2 data is valid");
		                count++;
			}
		} while (p != NULL);

		dispatch_sync(queue, ^{
			t += count;
		});
	});
	T_ASSERT_EQ(t, ((uint64_t)WIDE * (uint64_t)SMALL), "OSAtomicFifoEnqueue");

	t = 0;
	dispatch_apply(WIDE, global_q, ^(size_t i) {
		uint32_t count = 0;
		elem_t *p = NULL;
		do {
		        p = OSAtomicFifoDequeue(q2, offset);
		        T_QUIET; T_ASSERT_EQ(wrapped_q_head2.data, 0xdead, "q2 data is valid");
		        if (p) {
		                count++;
			}
		} while (p != NULL);
		dispatch_sync(queue, ^{
			t += count;
		});
	});

	T_ASSERT_EQ(t, ((uint64_t)WIDE * (uint64_t)SMALL), "OSAtomicFifoDequeue");

	dispatch_release(queue);
}

#else

T_DECL(test_arm_pfz, "Validate that ARM PFZ is mapped in",
    T_META_CHECK_LEAKS(false))
{
	T_SKIP("No PFZ, _COMM_PAGE_TEXT_ATOMIC_ENQUEUE doesn't exist");
}

#endif
