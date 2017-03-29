/*
 * Copyright (c) 2016 Apple Inc. All rights reserved.
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

#include <CoreFoundation/CoreFoundation.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_time.h>

/* These externs can be removed once the prototypes make it to the SDK */
extern mach_port_name_t mk_timer_create(void);
extern kern_return_t mk_timer_arm(mach_port_name_t name, uint64_t expire_time);

#define MK_TIMER_CRITICAL (1)
extern kern_return_t    mk_timer_arm_leeway(mach_port_name_t  name,
    uint64_t          mk_timer_flags,
    uint64_t          mk_timer_expire_time,
    uint64_t          mk_timer_leeway);

struct mach_timebase_info tbinfo;
double conversion;

mach_port_t timerPort;

uint64_t interval_abs = 1000000000;

uint32_t use_leeway = 0;
uint32_t report = 1000;

uint64_t on, lastfire = 0, totaljitter = 0, max_jitter = 0, min_jitter = ~0ULL, jiterations = 0, leeway_ns = 0, leeway_abs = 0;
uint64_t deadline;

void cfmcb(CFMachPortRef port, void *msg, CFIndex size, void *msginfo) {
	uint64_t ctime = mach_absolute_time();
	uint64_t jitter = 0;

	if (deadline) {
		jitter = (ctime - deadline);
		if (jitter > max_jitter) {
			max_jitter = jitter;
		}

		if (jitter < min_jitter) {
			min_jitter = jitter;
		}

		totaljitter += jitter;
		if ((++jiterations % report) == 0) {
			printf("max_jitter: %g (ns), min_jitter: %g (ns), average_jitter: %g (ns)\n", max_jitter * conversion, min_jitter * conversion, ((double)totaljitter/(double)jiterations) * conversion);
			max_jitter = 0; min_jitter = ~0ULL; jiterations = 0; totaljitter = 0;
		}
	}

	deadline = mach_absolute_time() + interval_abs;

	if (use_leeway) {
		mk_timer_arm_leeway(timerPort, MK_TIMER_CRITICAL, deadline, leeway_abs);
	} else {
		mk_timer_arm(timerPort, deadline);
	}
}

int main(int argc, char **argv) {
	if (argc != 4) {
		printf("Usage: mktimer_test <interval_ns> <use leeway trap> <leeway_ns>\n");
		return 0;
	}

	on = strtoul(argv[1], NULL, 0);
	use_leeway = strtoul(argv[2], NULL, 0);

	mach_timebase_info(&tbinfo);
	conversion = ((double)tbinfo.numer / (double) tbinfo.denom);

	leeway_ns = strtoul(argv[3], NULL, 0);

	leeway_abs = leeway_ns / conversion;
	printf("Interval in ns: %llu, timebase conversion: %g, use leeway syscall: %d, leeway_ns: %llu\n", on, conversion, !!use_leeway, leeway_ns);

	interval_abs = on / conversion;

	uint64_t cID = 0;
	CFMachPortContext context = (CFMachPortContext){
		1,
		(void *)cID,
		NULL,
		NULL,
		NULL,
	};

	timerPort = mk_timer_create();
	CFMachPortRef port = CFMachPortCreateWithPort(NULL, timerPort, cfmcb, &context, NULL);
	CFRunLoopSourceRef eventSource = CFMachPortCreateRunLoopSource(NULL, port, -1);
	CFRunLoopAddSource(CFRunLoopGetCurrent(), eventSource, kCFRunLoopDefaultMode);
	CFRelease(eventSource);

	if (use_leeway) {
		mk_timer_arm_leeway(timerPort, MK_TIMER_CRITICAL, mach_absolute_time() + interval_abs, leeway_abs);
	} else  {
		mk_timer_arm(timerPort, mach_absolute_time() + interval_abs);
	}

	for (;;) {
		CFRunLoopRun();
	}
	return 0;
}
