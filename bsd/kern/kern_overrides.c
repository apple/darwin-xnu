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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/proc_internal.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/unistd.h>
#include <sys/priv.h>

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
#include <sys/kern_memorystatus.h>

/* Mutex for global system override state */
static lck_mtx_t        sys_override_lock;
static lck_grp_t        *sys_override_mtx_grp;
static lck_attr_t       *sys_override_mtx_attr;
static lck_grp_attr_t   *sys_override_mtx_grp_attr;

/*
 * Assertion counts for system properties (add new ones for each new mechanism)
 *
 * The assertion count management for system overrides is as follows:
 *
 * - All assertion counts are protected by the sys_override_lock.
 *
 * - Each caller of system_override() increments the assertion count for the
 *   mechanism it specified in the flags. The caller then blocks for the
 *   timeout specified in the system call.
 *
 * - At the end of the timeout, the caller thread wakes up and decrements the
 *   assertion count for the mechanism it originally took an assertion on.
 *
 * - If another caller calls the system_override() to disable the override
 *   for a mechanism, it simply disables the mechanism without changing any
 *   assertion counts. That way, the assertion counts are properly balanced.
 *
 * One thing to note is that a SYS_OVERRIDE_DISABLE disables the overrides
 * for a mechanism irrespective of how many clients requested that override.
 * That makes the implementation simpler and avoids keeping a lot of process
 * specific state in the kernel.
 *
 */
static int64_t          io_throttle_assert_cnt;
static int64_t          cpu_throttle_assert_cnt;
static int64_t          fast_jetsam_assert_cnt;

/* Wait Channel for system override */
static uint64_t         sys_override_wait;

/* Global variable to indicate if system_override is enabled */
int                     sys_override_enabled;

/* Helper routines */
static void system_override_begin(uint64_t flags);
static void system_override_end(uint64_t flags);
static void system_override_abort(uint64_t flags);
static void system_override_callouts(uint64_t flags, boolean_t enable_override);
static __attribute__((noinline)) void PROCESS_OVERRIDING_SYSTEM_DEFAULTS(uint64_t timeout);

void
init_system_override()
{
	sys_override_mtx_grp_attr = lck_grp_attr_alloc_init();
	sys_override_mtx_grp = lck_grp_alloc_init("system_override", sys_override_mtx_grp_attr);
	sys_override_mtx_attr = lck_attr_alloc_init();
	lck_mtx_init(&sys_override_lock, sys_override_mtx_grp, sys_override_mtx_attr);
	io_throttle_assert_cnt = cpu_throttle_assert_cnt = fast_jetsam_assert_cnt = 0;
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

	/* Check to see if sane flags are specified. */
	if ((flags & ~SYS_OVERRIDE_FLAGS_MASK) != 0) {
		error = EINVAL;
		goto out;
	}

	/* Make sure that the system override syscall has been initialized */
	if (!sys_override_enabled) {
		error = EINVAL;
		goto out;
	}

	lck_mtx_lock(&sys_override_lock);

	if (flags & SYS_OVERRIDE_DISABLE) {
		flags &= ~SYS_OVERRIDE_DISABLE;
		system_override_abort(flags);
	} else {
		system_override_begin(flags);
		PROCESS_OVERRIDING_SYSTEM_DEFAULTS(timeout);
		system_override_end(flags);
	}

	lck_mtx_unlock(&sys_override_lock);

out:
	return error;
}

/*
 * Helper routines for enabling/disabling system overrides for various mechanisms.
 * These routines should be called with the sys_override_lock held. Each subsystem
 * which is hooked into the override service provides two routines:
 *
 * - void sys_override_foo_init(void);
 * Routine to initialize the subsystem or the data needed for the override to work.
 * This routine is optional and if a subsystem needs it, it should be invoked from
 * init_system_override().
 *
 * - void sys_override_foo(boolean_t enable_override);
 * Routine to enable/disable the override mechanism for that subsystem. A value of
 * true indicates that the mechanism should be overridden and the special behavior
 * should begin. A false value indicates that the subsystem should return to default
 * behavior. This routine is mandatory and should be invoked as part of the helper
 * routines if the flags passed in the syscall match the subsystem. Also, this
 * routine should preferably be idempotent.
 */

static void
system_override_callouts(uint64_t flags, boolean_t enable_override)
{
	switch (flags) {
	case SYS_OVERRIDE_IO_THROTTLE:
		if (enable_override) {
			KERNEL_DEBUG_CONSTANT(FSDBG_CODE(DBG_THROTTLE, IO_THROTTLE_DISABLE) | DBG_FUNC_START,
			    current_proc()->p_pid, 0, 0, 0, 0);
		} else {
			KERNEL_DEBUG_CONSTANT(FSDBG_CODE(DBG_THROTTLE, IO_THROTTLE_DISABLE) | DBG_FUNC_END,
			    current_proc()->p_pid, 0, 0, 0, 0);
		}
		sys_override_io_throttle(enable_override);
		break;

	case SYS_OVERRIDE_CPU_THROTTLE:
		if (enable_override) {
			KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_CPU_THROTTLE_DISABLE) | DBG_FUNC_START,
			    current_proc()->p_pid, 0, 0, 0, 0);
		} else {
			KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_CPU_THROTTLE_DISABLE) | DBG_FUNC_END,
			    current_proc()->p_pid, 0, 0, 0, 0);
		}
		sys_override_cpu_throttle(enable_override);
		break;

	case SYS_OVERRIDE_FAST_JETSAM:
		if (enable_override) {
			KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_FAST_JETSAM) | DBG_FUNC_START,
			    current_proc()->p_pid, 0, 0, 0, 0);
		} else {
			KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_FAST_JETSAM) | DBG_FUNC_END,
			    current_proc()->p_pid, 0, 0, 0, 0);
		}
#if CONFIG_JETSAM
		memorystatus_fast_jetsam_override(enable_override);
#endif /* CONFIG_JETSAM */
		break;

	default:
		panic("Unknown option to system_override_callouts(): %llu\n", flags);
	}
}

/*
 * system_override_begin(uint64_t flags)
 *
 * Routine to start a system override if the assertion count
 * transitions from 0->1 for a specified mechanism.
 */
static void
system_override_begin(uint64_t flags)
{
	lck_mtx_assert(&sys_override_lock, LCK_MTX_ASSERT_OWNED);

	if (flags & SYS_OVERRIDE_IO_THROTTLE) {
		if (io_throttle_assert_cnt == 0) {
			system_override_callouts(SYS_OVERRIDE_IO_THROTTLE, true);
		}
		io_throttle_assert_cnt++;
	}

	if (flags & SYS_OVERRIDE_CPU_THROTTLE) {
		if (cpu_throttle_assert_cnt == 0) {
			system_override_callouts(SYS_OVERRIDE_CPU_THROTTLE, true);
		}
		cpu_throttle_assert_cnt++;
	}

	if (flags & SYS_OVERRIDE_FAST_JETSAM) {
		if (fast_jetsam_assert_cnt == 0) {
			system_override_callouts(SYS_OVERRIDE_FAST_JETSAM, true);
		}
		fast_jetsam_assert_cnt++;
	}
}

/*
 * system_override_end(uint64_t flags)
 *
 * Routine to end a system override if the assertion count
 * transitions from 1->0 for a specified mechanism.
 */
static void
system_override_end(uint64_t flags)
{
	lck_mtx_assert(&sys_override_lock, LCK_MTX_ASSERT_OWNED);

	if (flags & SYS_OVERRIDE_IO_THROTTLE) {
		assert(io_throttle_assert_cnt > 0);
		io_throttle_assert_cnt--;
		if (io_throttle_assert_cnt == 0) {
			system_override_callouts(SYS_OVERRIDE_IO_THROTTLE, false);
		}
	}

	if (flags & SYS_OVERRIDE_CPU_THROTTLE) {
		assert(cpu_throttle_assert_cnt > 0);
		cpu_throttle_assert_cnt--;
		if (cpu_throttle_assert_cnt == 0) {
			system_override_callouts(SYS_OVERRIDE_CPU_THROTTLE, false);
		}
	}

	if (flags & SYS_OVERRIDE_FAST_JETSAM) {
		assert(fast_jetsam_assert_cnt > 0);
		fast_jetsam_assert_cnt--;
		if (fast_jetsam_assert_cnt == 0) {
			system_override_callouts(SYS_OVERRIDE_FAST_JETSAM, false);
		}
	}
}

/*
 * system_override_abort(uint64_t flags)
 *
 * Routine to abort a system override (if one was active)
 * irrespective of the assertion counts and number of blocked
 * requestors.
 */
static void
system_override_abort(uint64_t flags)
{
	lck_mtx_assert(&sys_override_lock, LCK_MTX_ASSERT_OWNED);

	if ((flags & SYS_OVERRIDE_IO_THROTTLE) && (io_throttle_assert_cnt > 0)) {
		system_override_callouts(SYS_OVERRIDE_IO_THROTTLE, false);
	}

	if ((flags & SYS_OVERRIDE_CPU_THROTTLE) && (cpu_throttle_assert_cnt > 0)) {
		system_override_callouts(SYS_OVERRIDE_CPU_THROTTLE, false);
	}

	if ((flags & SYS_OVERRIDE_FAST_JETSAM) && (fast_jetsam_assert_cnt > 0)) {
		system_override_callouts(SYS_OVERRIDE_FAST_JETSAM, false);
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
