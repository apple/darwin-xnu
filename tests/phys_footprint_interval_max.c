
/*
 * Copyright (c) 2018 Apple Inc. All rights reserved.
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
#include <unistd.h>
#include <string.h>
#include <mach/mach_vm.h>
#include <mach/mach_init.h>
#include <sys/resource.h>
#include <libproc.h>
#include <libproc_internal.h>
#include <TargetConditionals.h>

#define ALLOC_SIZE_LARGE 5*1024*1024
#define ALLOC_SIZE_SMALL 2*1024*1024

int proc_rlimit_control(pid_t pid, int flavor, void *arg);

T_DECL(phys_footprint_interval_max,
       "Validate physical footprint interval tracking")
{
	int ret;
	struct rusage_info_v4 ru;
	mach_vm_address_t addr = (mach_vm_address_t)NULL;

	ret = proc_pid_rusage(getpid(), RUSAGE_INFO_V4, (rusage_info_t *)&ru);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "proc_pid_rusage");
	T_ASSERT_EQ(ru.ri_lifetime_max_phys_footprint, ru.ri_interval_max_phys_footprint,
		    "Max footprint and interval footprint are equal prior to dirtying memory");

	ret = mach_vm_allocate(mach_task_self(), &addr, (mach_vm_size_t)ALLOC_SIZE_LARGE, VM_FLAGS_ANYWHERE);
	T_QUIET;
	T_ASSERT_MACH_SUCCESS(ret, "mach_vm_allocate(ALLOC_SIZE_LARGE)");

	memset((void *)addr, 0xab, ALLOC_SIZE_LARGE);

	ret = proc_pid_rusage(getpid(), RUSAGE_INFO_V4, (rusage_info_t *)&ru);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "proc_pid_rusage");
	T_ASSERT_EQ(ru.ri_lifetime_max_phys_footprint, ru.ri_interval_max_phys_footprint,
		    "Max footprint and interval footprint are equal after dirtying large memory region");

	mach_vm_deallocate(mach_task_self(), addr, (mach_vm_size_t)ALLOC_SIZE_LARGE);

	ret = proc_pid_rusage(getpid(), RUSAGE_INFO_V4, (rusage_info_t *)&ru);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "proc_pid_rusage");
	T_ASSERT_EQ(ru.ri_lifetime_max_phys_footprint, ru.ri_interval_max_phys_footprint,
		    "Max footprint and interval footprint are still equal after freeing large memory region");

	ret = proc_reset_footprint_interval(getpid());
	T_ASSERT_POSIX_SUCCESS(ret, "proc_reset_footprint_interval()");

	ret = proc_pid_rusage(getpid(), RUSAGE_INFO_V4, (rusage_info_t *)&ru);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "proc_pid_rusage");
	T_ASSERT_GT(ru.ri_lifetime_max_phys_footprint, ru.ri_interval_max_phys_footprint,
		    "Max footprint is greater than interval footprint after resetting interval");

	ret = mach_vm_allocate(mach_task_self(), &addr, (mach_vm_size_t)ALLOC_SIZE_SMALL, VM_FLAGS_ANYWHERE);
	T_QUIET;
	T_ASSERT_MACH_SUCCESS(ret, "mach_vm_allocate(ALLOC_SIZE_SMALL)");
	memset((void *)addr, 0xab, ALLOC_SIZE_SMALL);

	ret = proc_pid_rusage(getpid(), RUSAGE_INFO_V4, (rusage_info_t *)&ru);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "proc_pid_rusage");
	T_ASSERT_GT(ru.ri_lifetime_max_phys_footprint, ru.ri_interval_max_phys_footprint,
		    "Max footprint is still greater than interval footprint after dirtying small memory region");
}
