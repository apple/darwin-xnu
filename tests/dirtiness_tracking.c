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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/kern_event.h>
#include <sys/sysctl.h>
#include "../bsd/sys/kern_memorystatus.h"

static int
read_event(int so)
{
	ssize_t    status;
	char    buf[256];
	struct    kern_event_msg    *ev_msg = (struct kern_event_msg *)&buf[0];

	status = recv(so, &buf, sizeof(buf), 0);
	if (status == -1) {
		T_LOG("recv() failed: %s", strerror(errno));
		return -1;
	}

	if (ev_msg->total_size > status) {
		T_LOG("missed SYSPROTO_EVENT event, buffer not big enough");
		return -1;
	}

	if (ev_msg->vendor_code == KEV_VENDOR_APPLE && ev_msg->kev_class == KEV_SYSTEM_CLASS && ev_msg->kev_subclass == KEV_DIRTYSTATUS_SUBCLASS) {
		if (ev_msg->event_code == kDirtyStatusChangeNote) {
			dirty_status_change_event_t *ev_data = (dirty_status_change_event_t *)&ev_msg->event_data;
			switch (ev_data->dsc_event_type) {
			case kDirtyStatusChangedClean:
			case kDirtyStatusChangedDirty:
				break;
			default:
				T_LOG("Unknown event type %d", ev_data->dsc_event_type);
				return -1;
			}
			T_LOG("Process: %s, status: %s, pages: %llu, timestamp: %llu, priority: %d",
			    ev_data->dsc_process_name, ev_data->dsc_event_type == kDirtyStatusChangedDirty ? "dirty" : "clean", ev_data->dsc_pages, ev_data->dsc_time, ev_data->dsc_priority);
			return 1;
		} else {
			T_LOG("Ignoring message with code: %d", ev_msg->event_code);
		}
	} else {
		T_LOG(("Unexpected event with vendor code: %d"), ev_msg->vendor_code);
		return -1;
	}
	return 0;
}


T_DECL(dirtiness_tracking,
    "Check if we are able to receive dirtiness-tracking events from the kernel")
{
	int                   so, status;
	struct kev_request    kev_req;
	int                   enable_sysctl = 1;

	// First try enabling the dirtystatus_tracking sysctl if available
	if (sysctlbyname("kern.dirtystatus_tracking_enabled", NULL, NULL, &enable_sysctl, sizeof(enable_sysctl)) != 0) {
		T_SKIP("The kern.dirtystatus_tracking_enabled sysctl is not available, skipping...");
	}
	/* Open an event socket */
	so = socket(PF_SYSTEM, SOCK_RAW, SYSPROTO_EVENT);
	if (so != -1) {
		/* establish filter to return all events */
		kev_req.vendor_code  = KEV_VENDOR_APPLE;
		kev_req.kev_class    = KEV_SYSTEM_CLASS;/* Not used if vendor_code is 0 */
		kev_req.kev_subclass = KEV_DIRTYSTATUS_SUBCLASS; /* Not used if either kev_class OR vendor_code are 0 */
		status = ioctl(so, SIOCSKEVFILT, &kev_req);
		if (status) {
			so = -1;
			T_FAIL("could not establish event filter, ioctl() failed: %s", strerror(errno));
			T_END;
		}
	} else {
		T_FAIL("could not open event socket, socket() failed: %s", strerror(errno));
		T_END;
	}

	if (so != -1) {
		int    yes = 1;

		status = ioctl(so, FIONBIO, &yes);
		if (status) {
			(void) close(so);
			so = -1;
			T_FAIL( "could not set non-blocking io, ioctl() failed: %s", strerror(errno));
			T_END;
		}
	}

	if (so == -1) {
		T_FAIL("memory monitor disabled");
		T_END;
	}


	dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);

	dispatch_source_t read_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,
	    (uintptr_t)so, 0, queue);

	dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);
	dispatch_source_set_timer(timer, dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC), 5 * NSEC_PER_SEC, 1 * NSEC_PER_SEC);

	dispatch_source_set_event_handler(read_source, ^{
		int rc = read_event(so);
		if (rc != 0) {
		        dispatch_source_cancel(read_source);
		        if (rc == 1) {
		                T_PASS("Dirtiness-tracking Kevent successfully received");
			} else {
		                T_FAIL("Could not read from the system socket, aborting data collection");
			}
		}
	});

	dispatch_source_set_cancel_handler(read_source, ^{
		close(so);
		dispatch_cancel(timer);
		T_END;
	});

	dispatch_activate(read_source);

	dispatch_source_set_event_handler(timer, ^{
		dispatch_cancel(read_source);
		T_FAIL("Timeout expired, no events received from the kernel");
		T_END;
	});
	dispatch_activate(timer);

	dispatch_main();
}
