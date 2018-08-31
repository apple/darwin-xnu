/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
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

#include <kern/monotonic.h>
#include <machine/machine_routines.h>
#include <machine/monotonic.h>
#include <pexpert/pexpert.h>
#include <sys/param.h> /* NULL */
#include <sys/stat.h> /* dev_t */
#include <miscfs/devfs/devfs.h> /* must come after sys/stat.h */
#include <sys/conf.h> /* must come after sys/stat.h */
#include <sys/sysctl.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/monotonic.h>

static int mt_dev_open(dev_t dev, int flags, int devtype, struct proc *p);
static int mt_dev_close(dev_t dev, int flags, int devtype, struct proc *p);
static int mt_dev_ioctl(dev_t dev, unsigned long cmd, char *uptr, int fflag,
		struct proc *p);

static struct cdevsw mt_cdevsw = {
	.d_open = mt_dev_open,
	.d_close = mt_dev_close,
	.d_read = eno_rdwrt,
	.d_write = eno_rdwrt,
	.d_ioctl = mt_dev_ioctl,
	.d_stop = eno_stop,
	.d_reset = eno_reset,
	.d_ttys = NULL,
	.d_select = eno_select,
	.d_mmap = eno_mmap,
	.d_strategy = eno_strat,
	.d_type = 0
};

/*
 * Written at initialization, read-only thereafter.
 */
lck_grp_t *mt_lock_grp = NULL;

static int mt_dev_major;
decl_lck_mtx_data(static, mt_dev_mtxs[MT_NDEVS]);
static bool mt_dev_owned[MT_NDEVS];

static void
mt_dev_lock(dev_t dev)
{
	lck_mtx_lock(&mt_dev_mtxs[minor(dev)]);
}

static void
mt_dev_unlock(dev_t dev)
{
	lck_mtx_unlock(&mt_dev_mtxs[minor(dev)]);
}

static void
mt_dev_assert_lock_held(__assert_only dev_t dev)
{
	LCK_MTX_ASSERT(&mt_dev_mtxs[minor(dev)], LCK_MTX_ASSERT_OWNED);
}

int
mt_dev_init(void)
{
	lck_grp_attr_t *lock_grp_attr = NULL;
	int devices = 0;

	lock_grp_attr = lck_grp_attr_alloc_init();
	mt_lock_grp = lck_grp_alloc_init("monotonic", lock_grp_attr);
	lck_grp_attr_free(lock_grp_attr);

	mt_dev_major = cdevsw_add(-1 /* allocate a major number */, &mt_cdevsw);
	if (mt_dev_major < 0) {
		panic("monotonic: cdevsw_add failed: %d", mt_dev_major);
		__builtin_trap();
	}

	for (int i = 0; i < MT_NDEVS; i++) {
		dev_t dev;
		void *dn;
		int error;

		error = monotonic_devs[i].mtd_init();
		if (error) {
			continue;
		}

		dev = makedev(mt_dev_major, i);
		dn = devfs_make_node(dev,
				DEVFS_CHAR, UID_ROOT, GID_WINDOWSERVER, 0666,
				monotonic_devs[i].mtd_name);
		if (dn == NULL) {
			panic("monotonic: devfs_make_node failed for '%s'",
					monotonic_devs[i].mtd_name);
			__builtin_trap();
		}

		lck_mtx_init(&mt_dev_mtxs[i], mt_lock_grp, LCK_ATTR_NULL);

		devices++;
	}

	return 0;
}

static int
mt_dev_open(dev_t dev, __unused int flags, __unused int devtype,
		__unused struct proc *p)
{
	int error = 0;

	mt_dev_lock(dev);

	if (mt_dev_owned[minor(dev)]) {
		error = EBUSY;
		goto out;
	}

	mt_dev_owned[minor(dev)] = true;

out:
	mt_dev_unlock(dev);
	return error;
}

static int
mt_dev_close(dev_t dev, __unused int flags, __unused int devtype,
		__unused struct proc *p)
{
	mt_dev_lock(dev);

	assert(mt_dev_owned[minor(dev)]);
	mt_dev_owned[minor(dev)] = false;

	monotonic_devs[minor(dev)].mtd_reset();

	mt_dev_unlock(dev);

	return 0;
}

static int
mt_ctl_add(dev_t dev, user_addr_t uptr, __unused int flags,
		__unused struct proc *p)
{
	int error;
	uint32_t ctr;
	union monotonic_ctl_add ctl;

	mt_dev_assert_lock_held(dev);

	error = copyin(uptr, &ctl, sizeof(ctl.in));
	if (error) {
		return error;
	}

	error = monotonic_devs[minor(dev)].mtd_add(&ctl.in.config, &ctr);
	if (error) {
		return error;
	}

	ctl.out.ctr = ctr;

	error = copyout(&ctl, uptr, sizeof(ctl.out));
	if (error) {
		return error;
	}

	return 0;
}

static int
mt_ctl_counts(dev_t dev, user_addr_t uptr, __unused int flags,
		__unused struct proc *p)
{
	int error;
	uint64_t ctrs;
	union monotonic_ctl_counts ctl;

	mt_dev_assert_lock_held(dev);

	error = copyin(uptr, &ctl, sizeof(ctl.in));
	if (error) {
		return error;
	}

	if (ctl.in.ctr_mask == 0) {
		return EINVAL;
	}
	ctrs = __builtin_popcountll(ctl.in.ctr_mask);

	{
		uint64_t counts[ctrs];
		error = monotonic_devs[minor(dev)].mtd_read(ctl.in.ctr_mask, counts);
		if (error) {
			return error;
		}

		error = copyout(&counts, uptr, sizeof(counts));
		if (error) {
			return error;
		}
	}

	return 0;
}

static int
mt_ctl_enable(dev_t dev, user_addr_t uptr)
{
	int error;
	union monotonic_ctl_enable ctl;

	mt_dev_assert_lock_held(dev);

	error = copyin(uptr, &ctl, sizeof(ctl));
	if (error) {
		return error;
	}

	monotonic_devs[minor(dev)].mtd_enable(ctl.in.enable);

	return 0;
}

static int
mt_ctl_reset(dev_t dev)
{
	mt_dev_assert_lock_held(dev);
	monotonic_devs[minor(dev)].mtd_reset();
	return 0;
}

static int
mt_dev_ioctl(dev_t dev, unsigned long cmd, char *arg, int flags,
		struct proc *p)
{
	int error;
	user_addr_t uptr = *(user_addr_t *)(void *)arg;

	mt_dev_lock(dev);

	switch (cmd) {
	case MT_IOC_RESET:
		error = mt_ctl_reset(dev);
		break;

	case MT_IOC_ADD:
		error = mt_ctl_add(dev, uptr, flags, p);
		break;

	case MT_IOC_ENABLE:
		error = mt_ctl_enable(dev, uptr);
		break;

	case MT_IOC_COUNTS:
		error = mt_ctl_counts(dev, uptr, flags, p);
		break;

	default:
		error = ENODEV;
		break;
	}

	mt_dev_unlock(dev);

	return error;
}

int thread_selfcounts(__unused struct proc *p,
		struct thread_selfcounts_args *uap, __unused int *ret_out)
{
	switch (uap->type) {
	case 1: {
		uint64_t counts[2] = {};
		uint64_t thread_counts[MT_CORE_NFIXED];

		mt_cur_thread_fixed_counts(thread_counts);

#ifdef MT_CORE_INSTRS
		counts[0] = thread_counts[MT_CORE_INSTRS];
#endif /* defined(MT_CORE_INSTRS) */
		counts[1] = thread_counts[MT_CORE_CYCLES];

		return copyout(counts, uap->buf, MIN(sizeof(counts), uap->nbytes));
	}
	default:
		return EINVAL;
	}
}

enum mt_sysctl {
	MT_SUPPORTED,
	MT_PMIS,
	MT_RETROGRADE,
	MT_TASK_THREAD,
	MT_DEBUG,
	MT_KDBG_TEST,
	MT_FIX_CPU_PERF,
	MT_FIX_THREAD_PERF,
	MT_FIX_TASK_PERF,
};

static int
mt_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg2)
	uint64_t start[MT_CORE_NFIXED], end[MT_CORE_NFIXED];
	uint64_t counts[2] = {};

	switch ((enum mt_sysctl)arg1) {
	case MT_SUPPORTED:
		return sysctl_io_number(req, (int)mt_core_supported, sizeof(int), NULL, NULL);
	case MT_PMIS:
		return sysctl_io_number(req, mt_pmis, sizeof(mt_pmis), NULL, NULL);
	case MT_RETROGRADE:
		return sysctl_io_number(req, mt_retrograde, sizeof(mt_retrograde), NULL, NULL);
	case MT_TASK_THREAD:
		return sysctl_io_number(req, (int)mt_core_supported, sizeof(int), NULL, NULL);
	case MT_DEBUG: {
		int value = mt_debug;

		int r = sysctl_io_number(req, value, sizeof(value), &value, NULL);
		if (r) {
			return r;
		}
		mt_debug = value;

		return 0;
	}
	case MT_KDBG_TEST: {
		if (req->newptr == USER_ADDR_NULL) {
			return EINVAL;
		}

		int intrs_en = ml_set_interrupts_enabled(FALSE);
		MT_KDBG_TMPCPU_START(0x3fff);
		MT_KDBG_TMPCPU_END(0x3fff);

		MT_KDBG_TMPTH_START(0x3fff);
		MT_KDBG_TMPTH_END(0x3fff);
		ml_set_interrupts_enabled(intrs_en);

		return 0;
	}
	case MT_FIX_CPU_PERF: {
		int intrs_en = ml_set_interrupts_enabled(FALSE);
		mt_fixed_counts(start);
		mt_fixed_counts(end);
		ml_set_interrupts_enabled(intrs_en);

		goto copyout_counts;
	}
	case MT_FIX_THREAD_PERF: {
		int intrs_en = ml_set_interrupts_enabled(FALSE);
		mt_cur_thread_fixed_counts(start);
		mt_cur_thread_fixed_counts(end);
		ml_set_interrupts_enabled(intrs_en);

		goto copyout_counts;
	}
	case MT_FIX_TASK_PERF: {
		int intrs_en = ml_set_interrupts_enabled(FALSE);
		mt_cur_task_fixed_counts(start);
		mt_cur_task_fixed_counts(end);
		ml_set_interrupts_enabled(intrs_en);

		goto copyout_counts;
	}
	default:
		return ENOENT;
	}

copyout_counts:

#ifdef MT_CORE_INSTRS
	counts[0] = end[MT_CORE_INSTRS] - start[MT_CORE_INSTRS];
#endif /* defined(MT_CORE_INSTRS) */
	counts[1] = end[MT_CORE_CYCLES] - start[MT_CORE_CYCLES];

	return copyout(counts, req->oldptr, MIN(req->oldlen, sizeof(counts)));
}

SYSCTL_DECL(_kern_monotonic);
SYSCTL_NODE(_kern, OID_AUTO, monotonic, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
		"monotonic");

SYSCTL_PROC(_kern_monotonic, OID_AUTO, supported,
		CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MASKED | CTLFLAG_LOCKED,
		(void *)MT_SUPPORTED, sizeof(int), mt_sysctl, "I",
		"whether monotonic is supported");

SYSCTL_PROC(_kern_monotonic, OID_AUTO, debug,
		CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MASKED,
		(void *)MT_DEBUG, sizeof(int), mt_sysctl, "I",
		"whether monotonic is printing debug messages");

SYSCTL_PROC(_kern_monotonic, OID_AUTO, pmis,
		CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MASKED | CTLFLAG_LOCKED,
		(void *)MT_PMIS, sizeof(uint64_t), mt_sysctl, "Q",
		"how many PMIs have been seen");

SYSCTL_PROC(_kern_monotonic, OID_AUTO, retrograde_updates,
		CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MASKED | CTLFLAG_LOCKED,
		(void *)MT_RETROGRADE, sizeof(uint64_t), mt_sysctl, "Q",
		"how many times a counter appeared to go backwards");

SYSCTL_PROC(_kern_monotonic, OID_AUTO, task_thread_counting,
		CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MASKED,
		(void *)MT_TASK_THREAD, sizeof(int), mt_sysctl, "I",
		"task and thread counting enabled");

SYSCTL_PROC(_kern_monotonic, OID_AUTO, kdebug_test,
		CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MASKED | CTLFLAG_LOCKED,
		(void *)MT_KDBG_TEST, sizeof(int), mt_sysctl, "O",
		"test that kdebug integration works");

SYSCTL_PROC(_kern_monotonic, OID_AUTO, fixed_cpu_perf,
		CTLFLAG_RW | CTLFLAG_MASKED | CTLFLAG_LOCKED,
		(void *)MT_FIX_CPU_PERF, sizeof(uint64_t) * 2, mt_sysctl, "O",
		"overhead of accessing the current CPU's counters");

SYSCTL_PROC(_kern_monotonic, OID_AUTO, fixed_thread_perf,
		CTLFLAG_RW | CTLFLAG_MASKED | CTLFLAG_LOCKED,
		(void *)MT_FIX_THREAD_PERF, sizeof(uint64_t) * 2, mt_sysctl, "O",
		"overhead of accessing the current thread's counters");

SYSCTL_PROC(_kern_monotonic, OID_AUTO, fixed_task_perf,
		CTLFLAG_RW | CTLFLAG_MASKED | CTLFLAG_LOCKED,
		(void *)MT_FIX_TASK_PERF, sizeof(uint64_t) * 2, mt_sysctl, "O",
		"overhead of accessing the current task's counters");
