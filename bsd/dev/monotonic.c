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

static int mt_cdev_open(dev_t dev, int flags, int devtype, proc_t p);
static int mt_cdev_close(dev_t dev, int flags, int devtype, proc_t p);
static int mt_cdev_ioctl(dev_t dev, unsigned long cmd, char *uptr, int fflag,
    proc_t p);

#define MT_NODE "monotonic"

static const struct cdevsw mt_cdevsw = {
	.d_open = mt_cdev_open,
	.d_close = mt_cdev_close,
	.d_ioctl = mt_cdev_ioctl,

	.d_read = eno_rdwrt, .d_write = eno_rdwrt, .d_stop = eno_stop,
	.d_reset = eno_reset, .d_ttys = NULL, .d_select = eno_select,
	.d_mmap = eno_mmap, .d_strategy = eno_strat, .d_type = 0
};

/*
 * Written at initialization, read-only thereafter.
 */
lck_grp_t *mt_lock_grp = NULL;
static int mt_dev_major;

static mt_device_t
mt_get_device(dev_t devnum)
{
	return &mt_devices[minor(devnum)];
}

static void
mt_device_lock(mt_device_t dev)
{
	lck_mtx_lock(&dev->mtd_lock);
}

static void
mt_device_unlock(mt_device_t dev)
{
	lck_mtx_unlock(&dev->mtd_lock);
}

static void
mt_device_assert_lock_held(__assert_only mt_device_t dev)
{
	LCK_MTX_ASSERT(&dev->mtd_lock, LCK_MTX_ASSERT_OWNED);
}

static void
mt_device_assert_inuse(__assert_only mt_device_t dev)
{
	assert(dev->mtd_inuse == true);
}

int
mt_dev_init(void)
{
	mt_lock_grp = lck_grp_alloc_init(MT_NODE, LCK_GRP_ATTR_NULL);
	assert(mt_lock_grp != NULL);

	mt_dev_major = cdevsw_add(-1 /* allocate a major number */, &mt_cdevsw);
	if (mt_dev_major < 0) {
		panic("monotonic: cdevsw_add failed: %d", mt_dev_major);
		__builtin_unreachable();
	}

	for (int i = 0; i < MT_NDEVS; i++) {
		if (mt_devices[i].mtd_init(&mt_devices[i])) {
			continue;
		}

		assert(mt_devices[i].mtd_ncounters > 0);

		dev_t dev = makedev(mt_dev_major, i);
		char name[128];
		snprintf(name, sizeof(name), MT_NODE "/%s", mt_devices[i].mtd_name);
		void *node = devfs_make_node(dev, DEVFS_CHAR, UID_ROOT,
		    GID_WINDOWSERVER, 0666, name);
		if (!node) {
			panic("monotonic: devfs_make_node failed for '%s'",
			    mt_devices[i].mtd_name);
			__builtin_unreachable();
		}

		lck_mtx_init(&mt_devices[i].mtd_lock, mt_lock_grp, LCK_ATTR_NULL);
	}

	return 0;
}

static int
mt_cdev_open(dev_t devnum, __unused int flags, __unused int devtype,
    __unused proc_t p)
{
	int error = 0;

	mt_device_t dev = mt_get_device(devnum);
	mt_device_lock(dev);
	if (dev->mtd_inuse) {
		error = EBUSY;
	} else {
		dev->mtd_inuse = true;
	}
	mt_device_unlock(dev);

	return error;
}

static int
mt_cdev_close(dev_t devnum, __unused int flags, __unused int devtype,
    __unused struct proc *p)
{
	mt_device_t dev = mt_get_device(devnum);

	mt_device_lock(dev);
	mt_device_assert_inuse(dev);
	dev->mtd_inuse = false;
	dev->mtd_reset();
	mt_device_unlock(dev);

	return 0;
}

static int
mt_ctl_add(mt_device_t dev, user_addr_t uptr)
{
	int error;
	uint32_t ctr;
	union monotonic_ctl_add ctl;

	mt_device_assert_lock_held(dev);

	error = copyin(uptr, &ctl, sizeof(ctl.in));
	if (error) {
		return error;
	}

	error = dev->mtd_add(&ctl.in.config, &ctr);
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
mt_ctl_counts(mt_device_t dev, user_addr_t uptr)
{
	int error;
	union monotonic_ctl_counts ctl;

	mt_device_assert_lock_held(dev);

	error = copyin(uptr, &ctl, sizeof(ctl.in));
	if (error) {
		return error;
	}

	if (ctl.in.ctr_mask == 0) {
		return EINVAL;
	}

	{
		uint64_t counts[dev->mtd_nmonitors][dev->mtd_ncounters];
		memset(counts, 0,
		    dev->mtd_ncounters * dev->mtd_nmonitors * sizeof(counts[0][0]));
		error = dev->mtd_read(ctl.in.ctr_mask, (uint64_t *)counts);
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
mt_ctl_enable(mt_device_t dev, user_addr_t uptr)
{
	int error;
	union monotonic_ctl_enable ctl;

	mt_device_assert_lock_held(dev);

	error = copyin(uptr, &ctl, sizeof(ctl));
	if (error) {
		return error;
	}

	dev->mtd_enable(ctl.in.enable);

	return 0;
}

static int
mt_ctl_reset(mt_device_t dev)
{
	mt_device_assert_lock_held(dev);
	dev->mtd_reset();
	return 0;
}

static int
mt_cdev_ioctl(dev_t devnum, unsigned long cmd, char *arg, __unused int flags,
    __unused proc_t p)
{
	int error = ENODEV;
	user_addr_t uptr = *(user_addr_t *)(void *)arg;

	mt_device_t dev = mt_get_device(devnum);
	mt_device_lock(dev);

	switch (cmd) {
	case MT_IOC_RESET:
		error = mt_ctl_reset(dev);
		break;

	case MT_IOC_ADD:
		error = mt_ctl_add(dev, uptr);
		break;

	case MT_IOC_ENABLE:
		error = mt_ctl_enable(dev, uptr);
		break;

	case MT_IOC_COUNTS:
		error = mt_ctl_counts(dev, uptr);
		break;

	case MT_IOC_GET_INFO: {
		union monotonic_ctl_info info = {
			.out = {
				.nmonitors = dev->mtd_nmonitors,
				.ncounters = dev->mtd_ncounters,
			},
		};
		error = copyout(&info, uptr, sizeof(info));
		break;
	}

	default:
		error = ENODEV;
		break;
	}

	mt_device_unlock(dev);

	return error;
}

int
thread_selfcounts(__unused struct proc *p,
    struct thread_selfcounts_args *uap, __unused int *ret_out)
{
	switch (uap->type) {
	case 1: {
		uint64_t counts[2] = { 0 };
		uint64_t thread_counts[MT_CORE_NFIXED] = { 0 };

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
	uint64_t start[MT_CORE_NFIXED] = { 0 }, end[MT_CORE_NFIXED] = { 0 };
	uint64_t counts[2] = { 0 };

	switch ((enum mt_sysctl)arg1) {
	case MT_SUPPORTED:
		return sysctl_io_number(req, (int)mt_core_supported, sizeof(int), NULL, NULL);
	case MT_PMIS:
		return sysctl_io_number(req, mt_count_pmis(), sizeof(uint64_t), NULL, NULL);
	case MT_RETROGRADE: {
		uint64_t value = os_atomic_load_wide(&mt_retrograde, relaxed);
		return sysctl_io_number(req, value, sizeof(mt_retrograde), NULL, NULL);
	}
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

#define MT_SYSCTL(NAME, ARG, FLAGS, SIZE, SIZESTR, DESC) \
    SYSCTL_PROC(_kern_monotonic, OID_AUTO, NAME, \
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED | (FLAGS), \
    (void *)(ARG), SIZE, mt_sysctl, SIZESTR, DESC)

MT_SYSCTL(supported, MT_SUPPORTED, 0, sizeof(int), "I",
    "whether monotonic is supported");
MT_SYSCTL(debug, MT_DEBUG, CTLFLAG_MASKED, sizeof(int), "I",
    "whether monotonic is printing debug messages");
MT_SYSCTL(pmis, MT_PMIS, 0, sizeof(uint64_t), "Q",
    "number of PMIs seen");
MT_SYSCTL(retrograde_updates, MT_RETROGRADE, 0, sizeof(uint64_t), "Q",
    "number of times a counter appeared to go backwards");
MT_SYSCTL(task_thread_counting, MT_TASK_THREAD, 0, sizeof(int), "I",
    "whether task and thread counting is enabled");
MT_SYSCTL(kdebug_test, MT_KDBG_TEST, CTLFLAG_MASKED, sizeof(int), "O",
    "whether task and thread counting is enabled");
MT_SYSCTL(fixed_cpu_perf, MT_FIX_CPU_PERF, CTLFLAG_MASKED,
    sizeof(uint64_t) * 2, "O",
    "overhead of accessing the current CPU's counters");
MT_SYSCTL(fixed_thread_perf, MT_FIX_THREAD_PERF, CTLFLAG_MASKED,
    sizeof(uint64_t) * 2, "O",
    "overhead of accessing the current thread's counters");
MT_SYSCTL(fixed_task_perf, MT_FIX_TASK_PERF, CTLFLAG_MASKED,
    sizeof(uint64_t) * 2, "O",
    "overhead of accessing the current task's counters");
