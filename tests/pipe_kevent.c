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
#include <dispatch/dispatch.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

T_DECL(pipe_noblock_kevent,
    "Set a pipe and no block and setup EVFLT_WRITE kevent on it and make sure it does not fire when the pipe is full")
{
	int fd[2], write_fd;
	dispatch_queue_t dq1 = dispatch_queue_create("com.apple.test.pipe_noblock_kevent.queue", DISPATCH_QUEUE_SERIAL);

	pipe(fd);
	write_fd = fd[1];
	__block int iter = 1;

	/* Make sure the pipe is No block */
	fcntl(write_fd, F_SETFL, (O_NONBLOCK));

	dispatch_source_t write_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_WRITE, (uintptr_t)write_fd, 0, dq1);
	dispatch_source_set_event_handler(write_source, ^{
		unsigned long length = dispatch_source_get_data(write_source);

		T_LOG("Iteration: %d, Length available: %lu\n", iter++, length);

		char buf[512] = "deadbeef";
		ssize_t rv = write(write_fd, buf, 512);
		T_EXPECT_POSIX_SUCCESS(rv, "write success");
		if (rv < 0) {
		        T_FAIL("Write should have succeeded but failed with error %ld", rv);
		        T_END;
		}
	});

	dispatch_resume(write_source);

	T_LOG("Arming a timer for 15 seconds to exit, assuming kevent will block before that");
	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
		T_LOG("PASS: Kevent blocked as expected in the EVFLT_WRITE");
		T_END;
	});

	dispatch_main();
}
