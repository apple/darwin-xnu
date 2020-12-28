/*
 * Copyright (c) 2019 Apple Computer, Inc. All rights reserved.
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

#include <darwintest.h>
#include <darwintest_multiprocess.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <pthread.h>
#include <stdlib.h>
#include <signal.h>

static void
signal_handler(int sig, siginfo_t *sip __unused, void *ucontext __unused)
{
	if (sig == SIGPIPE) {
		T_FAIL("Received SIGPIPE");
	}

	exit(141);
}

static void *
thread_read(void *arg)
{
	int fd = (int) (uintptr_t)arg;
	char buf[10];

	read(fd, buf, 10);
	T_LOG("thread returned from read");
	return 0;
}

T_DECL(pipe_drain,
    "test a pipe with multiple read descriptor could close one descriptor and drain that descriptor")
{
	int pipe_fd[2];
	int dup_fd;
	int ret;
	char buf[10] = "Hello";
	pthread_t thread;

	/* Install the signal handler for SIGPIPE */

	struct sigaction sa = {
		.sa_sigaction = signal_handler,
		.sa_flags = SA_SIGINFO
	};
	sigfillset(&sa.sa_mask);

	T_QUIET; T_ASSERT_POSIX_ZERO(sigaction(SIGPIPE, &sa, NULL), NULL);

	ret = pipe(pipe_fd);
	T_EXPECT_EQ(ret, 0, NULL);

	dup_fd = dup(pipe_fd[0]);
	T_EXPECT_GE(dup_fd, 0, NULL);

	pthread_create(&thread, NULL, thread_read, (void *) (uintptr_t) pipe_fd[0]);

	sleep(5);

	close(pipe_fd[0]);
	ret = (int)write(pipe_fd[1], buf, strlen(buf) + 1);
	T_EXPECT_EQ(ret, (int)strlen(buf) + 1, NULL);
}
