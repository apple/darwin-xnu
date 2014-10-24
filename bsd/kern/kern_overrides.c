/*
 * Copyright (c) 2013 Apple Computer, Inc. All rights reserved.
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

/*
 * System Overrides syscall implementation
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/proc_internal.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/unistd.h>
#include <sys/priv.h>
#include <security/audit/audit.h>

#include <mach/mach_types.h>
#include <mach/vm_param.h>
#include <kern/task.h>
#include <kern/locks.h>
#include <kern/assert.h>
#include <kern/sched_prim.h>

#include <sys/kern_overrides.h>
#include <sys/bsdtask_info.h>
#include <sys/kdebug.h>
#include <sys/sysproto.h>
#include <sys/msgbuf.h>

/* Mutex for global system override state */
static lck_mtx_t	sys_override_lock;
static lck_grp_t        *sys_override_mtx_grp;
static lck_attr_t       *sys_override_mtx_attr;
static lck_grp_attr_t   *sys_override_mtx_grp_attr;

/* Assertion counts for system properties */
static int64_t		io_throttle_assert_cnt;
static int64_t		cpu_throttle_assert_cnt;

/* Wait Channel for system override */
static uint64_t		sys_override_wait;

/* Global variable to indicate if system_override is enabled */
int 			sys_override_enabled;

/* Sysctl definition for sys_override_enabled */
SYSCTL_INT(_debug, OID_AUTO, sys_override_enabled, CTLFLAG_RW | CTLFLAG_LOCKED, &sys_override_enabled, 0, "");

/* Forward Declarations */
static void enable_system_override(uint64_t flags);
static void disable_system_override(uint64_t flags);
static __attribute__((noinline)) void PROCESS_OVERRIDING_SYSTEM_DEFAULTS(uint64_t timeout);

/***************************** system_override ********************/
/*
 * int system_override(uint64_t timeout, uint64_t flags);
 */

void
init_system_override()
{
	sys_override_mtx_grp_attr = lck_grp_attr_alloc_init();
	sys_override_mtx_grp = lck_grp_alloc_init("system_override", sys_override_mtx_grp_attr);
	sys_override_mtx_attr = lck_attr_alloc_init();
	lck_mtx_init(&sys_override_lock, sys_override_mtx_grp, sys_override_mtx_attr);
	io_throttle_assert_cnt = cpu_throttle_assert_cnt = 0;
	sys_override_enabled = 1;
}

/* system call implementation */
int
system_override(__unused struct proc *p, struct system_override_args * uap, __unused int32_t *retval)
{
	uint64_t timeout = uap->timeout;
	uint64_t flags = uap->flags;
	int error = 0;

	/* Check credentials for caller. Only entitled processes are allowed to make this call. */
	if ((error = priv_check_cred(kauth_cred_get(), PRIV_SYSTEM_OVERRIDE, 0))) {
		goto out;
	}	

	/* Check to see if some flags are specified. */
	if ((flags & ~SYS_OVERRIDE_FLAGS_MASK) != 0) {
		error = EINVAL;
		goto out;
	}

	if (flags == SYS_OVERRIDE_DISABLE) {
		
		printf("Process %s [%d] disabling system_override()\n", current_proc()->p_comm, current_proc()->p_pid);

		lck_mtx_lock(&sys_override_lock);
		
		if (io_throttle_assert_cnt > 0)
			sys_override_io_throttle(THROTTLE_IO_ENABLE);
		if (cpu_throttle_assert_cnt > 0)
			sys_override_cpu_throttle(CPU_THROTTLE_ENABLE);

		sys_override_enabled = 0;
				
		lck_mtx_unlock(&sys_override_lock);

		goto out;
	}

	lck_mtx_lock(&sys_override_lock);

	enable_system_override(flags);

	PROCESS_OVERRIDING_SYSTEM_DEFAULTS(timeout);

	disable_system_override(flags);

	lck_mtx_unlock(&sys_override_lock);

out:
	return error;
}

/*
 * Call for enabling global system override.
 * This should be called only with the sys_override_lock held.
 */
static void
enable_system_override(uint64_t flags)
{
	
	if (flags & SYS_OVERRIDE_IO_THROTTLE) {
		if ((io_throttle_assert_cnt == 0) && sys_override_enabled) {
			/* Disable I/O Throttling */
			printf("Process %s [%d] disabling system-wide I/O Throttling\n", current_proc()->p_comm, current_proc()->p_pid);
			sys_override_io_throttle(THROTTLE_IO_DISABLE);
		}
		KERNEL_DEBUG_CONSTANT(FSDBG_CODE(DBG_THROTTLE, IO_THROTTLE_DISABLE) | DBG_FUNC_START, current_proc()->p_pid, 0, 0, 0, 0);
		io_throttle_assert_cnt++;
	}
	
	if (flags & SYS_OVERRIDE_CPU_THROTTLE) {
		if ((cpu_throttle_assert_cnt == 0) && sys_override_enabled) {
			/* Disable CPU Throttling */
			printf("Process %s [%d] disabling system-wide CPU Throttling\n", current_proc()->p_comm, current_proc()->p_pid);
			sys_override_cpu_throttle(CPU_THROTTLE_DISABLE);
		}
		KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_CPU_THROTTLE_DISABLE) | DBG_FUNC_START, current_proc()->p_pid, 0, 0, 0, 0);
		cpu_throttle_assert_cnt++;
	}

}

/*
 * Call for disabling global system override.
 * This should be called only with the sys_override_lock held.
 */
static void
disable_system_override(uint64_t flags)
{

	if (flags & SYS_OVERRIDE_IO_THROTTLE) {
		assert(io_throttle_assert_cnt > 0);
		io_throttle_assert_cnt--;
		KERNEL_DEBUG_CONSTANT(FSDBG_CODE(DBG_THROTTLE, IO_THROTTLE_DISABLE) | DBG_FUNC_END, current_proc()->p_pid, 0, 0, 0, 0);
		if ((io_throttle_assert_cnt == 0) && sys_override_enabled) {
			/* Enable I/O Throttling */
			sys_override_io_throttle(THROTTLE_IO_ENABLE);
		}
	}

	if (flags & SYS_OVERRIDE_CPU_THROTTLE) {
		assert(cpu_throttle_assert_cnt > 0);
		cpu_throttle_assert_cnt--;
		KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_CPU_THROTTLE_DISABLE) | DBG_FUNC_END, current_proc()->p_pid, 0, 0, 0, 0);
		if ((cpu_throttle_assert_cnt == 0) && sys_override_enabled) {
			/* Enable CPU Throttling */
			sys_override_cpu_throttle(CPU_THROTTLE_ENABLE);
		}
	}
}

static __attribute__((noinline)) void
PROCESS_OVERRIDING_SYSTEM_DEFAULTS(uint64_t timeout)
{
	struct timespec ts;
	ts.tv_sec = timeout / NSEC_PER_SEC;
	ts.tv_nsec = timeout - ((long)ts.tv_sec * NSEC_PER_SEC);
	msleep((caddr_t)&sys_override_wait, &sys_override_lock, PRIBIO | PCATCH, "system_override", &ts);
}

