/*
 * Copyright (c) 2015-2018 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

#include <darwintest.h>

#include <stdlib.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <sys/utsname.h>
#include <TargetConditionals.h>

#define WIRED_MEM_THRESHOLD_PERCENTAGE 30

T_DECL(wired_mem_bench,
    "report the amount of wired memory consumed by the booted OS; guard against egregious or unexpected regressions",
    T_META_CHECK_LEAKS(false),
    T_META_ASROOT(true),
    T_META_REQUIRES_REBOOT(true))     // Help reduce noise by asking for a clean boot
//	T_META_TAG_PERF)
{
	vm_statistics64_data_t  stat;
	uint64_t                memsize;
	vm_size_t               page_size = 0;
	unsigned int            count = HOST_VM_INFO64_COUNT;
	kern_return_t           ret;
	int                     wired_mem_pct;
	struct utsname          uname_vers;

	T_SETUPBEGIN;
	ret = uname(&uname_vers);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "uname()");

	if (strnstr(uname_vers.version, "KASAN", sizeof(uname_vers.version)) != NULL) {
		T_SKIP("wired memory metrics are not meaningful on KASAN kernels.");
	}

	ret = host_statistics64(mach_host_self(), HOST_VM_INFO64, (host_info64_t)&stat, &count);
	T_QUIET;
	T_ASSERT_MACH_SUCCESS(ret, "wired memory query via host_statistics64()");

	size_t s = sizeof(memsize);
	ret = sysctlbyname("hw.memsize", &memsize, &s, NULL, 0);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "sysctlbyname(\"hw.memsize\")");

	T_QUIET;
	T_EXPECT_NE(memsize, 0ULL, "hw.memsize sysctl failed to provide device DRAM size");

	ret = host_page_size(mach_host_self(), &page_size);
	T_QUIET;
	T_ASSERT_MACH_SUCCESS(ret, "page size query via host_page_size()");

	T_SETUPEND;

	T_PERF("wired_memory", (double)(stat.wire_count * (mach_vm_size_t)vm_kernel_page_size >> 10), "kB",
	    "Wired memory at boot");

	T_LOG("\nwired memory: %llu kB (%llu MB)\n", stat.wire_count * (mach_vm_size_t)vm_kernel_page_size >> 10,
	    stat.wire_count * (mach_vm_size_t)vm_kernel_page_size >> 20);

#if TARGET_OS_IOS || TARGET_OS_OSX
	// zprint is not mastered onto other platforms.
	int r;
	if ((r = system("zprint")) != 0) {
		T_FAIL("couldn't run zprint: %d", r);
	}
#endif
	/*
	 * Poor-man's wired memory regression test: validate that wired memory consumes
	 * no more than some outrageously high fixed percentage of total device memory.
	 */
	wired_mem_pct = (int)((stat.wire_count * page_size * 100ULL) / memsize);
	T_PERF("wired_memory_percentage", wired_mem_pct, "%", "Wired memory as percentage of device DRAM size");

	T_ASSERT_LT(wired_mem_pct, WIRED_MEM_THRESHOLD_PERCENTAGE,
	    "Wired memory percentage is below allowable threshold (%llu bytes / %u pages / %llu total device memory)",
	    (uint64_t)stat.wire_count * page_size, stat.wire_count, memsize);
}
