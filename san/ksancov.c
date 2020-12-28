/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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

#include <string.h>
#include <stdbool.h>
#include <stdatomic.h>

#include <kern/assert.h>
#include <kern/cpu_data.h>
#include <kern/locks.h>
#include <kern/debug.h>
#include <kern/kalloc.h>
#include <kern/zalloc.h>
#include <kern/task.h>
#include <kern/thread.h>

#include <vm/vm_kern.h>
#include <vm/vm_protos.h>

#include <mach/mach_vm.h>
#include <mach/mach_types.h>
#include <mach/mach_port.h>
#include <mach/vm_map.h>
#include <mach/vm_param.h>
#include <mach/machine/vm_param.h>
#include <machine/atomic.h>

#include <sys/stat.h> /* dev_t */
#include <miscfs/devfs/devfs.h> /* must come after sys/stat.h */
#include <sys/conf.h> /* must come after sys/stat.h */

#include <libkern/libkern.h>
#include <libkern/OSAtomic.h>
#include <os/overflow.h>

#include <san/ksancov.h>

/* header mess... */
struct uthread;
typedef struct uthread * uthread_t;

#include <sys/sysproto.h>
#include <sys/queue.h>
#include <sys/sysctl.h>

#define USE_PC_TABLE 0
#define KSANCOV_MAX_DEV 64

extern boolean_t ml_at_interrupt_context(void);
extern boolean_t ml_get_interrupts_enabled(void);

static int ksancov_detach(dev_t dev);

static int dev_major;
static size_t nedges = 0;
static uint32_t __unused npcs = 0;

static _Atomic unsigned active_devs;

enum {
	KS_MODE_NONE,
	KS_MODE_TRACE,
	KS_MODE_COUNTERS,
	KS_MODE_MAX
};

struct ksancov_dev {
	unsigned mode;

	union {
		struct ksancov_trace *trace;
		struct ksancov_counters *counters;
	};
	size_t sz;     /* size of allocated trace/counters buffer */

	size_t maxpcs;

	thread_t thread;
	dev_t dev;
};

/* array of devices indexed by devnode minor */
static struct ksancov_dev *ksancov_devs[KSANCOV_MAX_DEV];

static struct ksancov_edgemap *ksancov_edgemap;

static inline struct ksancov_dev *
get_dev(dev_t dev)
{
	int mn = minor(dev);
	return ksancov_devs[mn];
}

void
__sanitizer_cov_trace_pc_indirect(void * __unused callee)
{
	return;
}

#define GUARD_SEEN     (uint32_t)0x80000000
#define GUARD_IDX_MASK (uint32_t)0x0fffffff

static inline void __attribute__((always_inline))
trace_pc_guard(uint32_t *guardp, void *caller)
{
	/* record the pc for this guard */
	if (guardp) {
		uint32_t gd = *guardp;
		if (__improbable(gd && !(gd & GUARD_SEEN) && ksancov_edgemap)) {
			size_t idx = gd & GUARD_IDX_MASK;
			if (idx < ksancov_edgemap->nedges) {
				ksancov_edgemap->addrs[idx] = (uint32_t)(VM_KERNEL_UNSLIDE(caller) - VM_MIN_KERNEL_ADDRESS - 1);
				*guardp |= GUARD_SEEN;
			}
		}
	}

	if (__probable(os_atomic_load(&active_devs, relaxed) == 0)) {
		/* early exit when nothing is active */
		return;
	}

	if (ml_at_interrupt_context()) {
		return;
	}

	uint32_t pc = (uint32_t)(VM_KERNEL_UNSLIDE(caller) - VM_MIN_KERNEL_ADDRESS - 1);

	thread_t th = current_thread();
	if (__improbable(th == THREAD_NULL)) {
		return;
	}

	struct ksancov_dev *dev = *(struct ksancov_dev **)__sanitizer_get_thread_data(th);
	if (__probable(dev == NULL)) {
		return;
	}

	if (dev->mode == KS_MODE_TRACE) {
		struct ksancov_trace *trace = dev->trace;
		if (os_atomic_load(&trace->enabled, relaxed) == 0) {
			return;
		}

		if (os_atomic_load(&trace->head, relaxed) >= dev->maxpcs) {
			return; /* overflow */
		}

		uint32_t idx = os_atomic_inc_orig(&trace->head, relaxed);
		if (__improbable(idx >= dev->maxpcs)) {
			return;
		}

		trace->pcs[idx] = pc;
	} else {
		size_t idx = *guardp & GUARD_IDX_MASK;

		struct ksancov_counters *counters = dev->counters;
		if (os_atomic_load(&counters->enabled, relaxed) == 0) {
			return;
		}

		/* saturating 8bit add */
		if (counters->hits[idx] < KSANCOV_MAX_HITS) {
			counters->hits[idx]++;
		}
	}
}

void __attribute__((noinline))
__sanitizer_cov_trace_pc(void)
{
	trace_pc_guard(NULL, __builtin_return_address(0));
}

void __attribute__((noinline))
__sanitizer_cov_trace_pc_guard(uint32_t *guardp)
{
	trace_pc_guard(guardp, __builtin_return_address(0));
}

void
__sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop)
{
	/* assign a unique number to each guard */
	for (; start != stop; start++) {
		if (*start == 0) {
			if (nedges < KSANCOV_MAX_EDGES) {
				*start = ++nedges;
			}
		}
	}
}

void
__sanitizer_cov_pcs_init(uintptr_t *start, uintptr_t *stop)
{
#if USE_PC_TABLE
	static const uintptr_t pc_table_seen_flag = 0x100;

	for (; start < stop; start += 2) {
		uintptr_t pc = start[0];
		uintptr_t flags = start[1];

		/*
		 * This function gets called multiple times on the same range, so mark the
		 * ones we've seen using unused bits in the flags field.
		 */
		if (flags & pc_table_seen_flag) {
			continue;
		}

		start[1] |= pc_table_seen_flag;
		assert(npcs < KSANCOV_MAX_EDGES - 1);
		edge_addrs[++npcs] = pc;
	}
#else
	(void)start;
	(void)stop;
#endif
}

static void *
ksancov_do_map(uintptr_t base, size_t sz, vm_prot_t prot)
{
	kern_return_t kr;
	mach_port_t mem_entry = MACH_PORT_NULL;
	mach_vm_address_t user_addr = 0;
	memory_object_size_t size = sz;

	kr = mach_make_memory_entry_64(kernel_map,
	    &size,
	    (mach_vm_offset_t)base,
	    MAP_MEM_VM_SHARE | prot,
	    &mem_entry,
	    MACH_PORT_NULL);
	if (kr != KERN_SUCCESS) {
		return NULL;
	}

	kr = mach_vm_map_kernel(get_task_map(current_task()),
	    &user_addr,
	    size,
	    0,
	    VM_FLAGS_ANYWHERE,
	    VM_MAP_KERNEL_FLAGS_NONE,
	    VM_KERN_MEMORY_NONE,
	    mem_entry,
	    0,
	    FALSE,
	    prot,
	    prot,
	    VM_INHERIT_SHARE);

	/*
	 * At this point, either vm_map() has taken a reference on the memory entry
	 * and we can release our local reference, or the map failed and the entry
	 * needs to be freed.
	 */
	mach_memory_entry_port_release(mem_entry);

	if (kr != KERN_SUCCESS) {
		return NULL;
	}

	return (void *)user_addr;
}

/*
 * map the sancov buffer into the current process
 */
static int
ksancov_map(dev_t dev, void **bufp, size_t *sizep)
{
	struct ksancov_dev *d = get_dev(dev);
	if (!d) {
		return EINVAL;
	}

	uintptr_t addr;
	size_t size = d->sz;

	if (d->mode == KS_MODE_TRACE) {
		if (!d->trace) {
			return EINVAL;
		}
		addr = (uintptr_t)d->trace;
	} else if (d->mode == KS_MODE_COUNTERS) {
		if (!d->counters) {
			return EINVAL;
		}
		addr = (uintptr_t)d->counters;
	} else {
		return EINVAL; /* not configured */
	}

	void *buf = ksancov_do_map(addr, size, VM_PROT_READ | VM_PROT_WRITE);
	if (buf == NULL) {
		return ENOMEM;
	}

	*bufp = buf;
	*sizep = size;
	return 0;
}

/*
 * map the edge -> pc mapping as read-only
 */
static int
ksancov_map_edgemap(dev_t dev, void **bufp, size_t *sizep)
{
	struct ksancov_dev *d = get_dev(dev);
	if (!d) {
		return EINVAL;
	}

	uintptr_t addr = (uintptr_t)ksancov_edgemap;
	size_t size = sizeof(struct ksancov_edgemap) + ksancov_edgemap->nedges * sizeof(uint32_t);

	void *buf = ksancov_do_map(addr, size, VM_PROT_READ);
	if (buf == NULL) {
		return ENOMEM;
	}

	*bufp = buf;
	*sizep = size;
	return 0;
}


/*
 * Device node management
 */

static int
ksancov_open(dev_t dev, int flags, int devtype, proc_t p)
{
#pragma unused(flags,devtype,p)
	if (minor(dev) >= KSANCOV_MAX_DEV) {
		return EBUSY;
	}

	/* allocate a device entry */
	struct ksancov_dev *d = kalloc_tag(sizeof(struct ksancov_dev), VM_KERN_MEMORY_DIAG);
	if (!d) {
		return ENOMEM;
	}

	d->mode = KS_MODE_NONE;
	d->trace = NULL;
	d->maxpcs = 1024U * 64; /* default to 256k buffer => 64k pcs */
	d->dev = dev;
	d->thread = THREAD_NULL;

	ksancov_devs[minor(dev)] = d;

	return 0;
}

static int
ksancov_trace_alloc(dev_t dev, size_t maxpcs)
{
	struct ksancov_dev *d = get_dev(dev);
	if (!d) {
		return EINVAL;
	}

	if (d->mode != KS_MODE_NONE) {
		return EBUSY; /* trace/counters already created */
	}
	assert(d->trace == NULL);

	uintptr_t buf;
	size_t sz;
	if (os_mul_and_add_overflow(maxpcs, sizeof(uint32_t), sizeof(struct ksancov_trace), &sz)) {
		return EINVAL;
	}

	/* allocate the shared memory buffer */
	kern_return_t kr = kmem_alloc_flags(kernel_map, &buf, sz, VM_KERN_MEMORY_DIAG, KMA_ZERO);
	if (kr != KERN_SUCCESS) {
		return ENOMEM;
	}

	struct ksancov_trace *trace = (struct ksancov_trace *)buf;
	trace->magic = KSANCOV_TRACE_MAGIC;
	trace->offset = VM_MIN_KERNEL_ADDRESS;
	trace->head = 0;
	trace->enabled = 0;
	trace->maxpcs = maxpcs;

	d->trace = trace;
	d->sz = sz;
	d->maxpcs = maxpcs;
	d->mode = KS_MODE_TRACE;

	return 0;
}

static int
ksancov_counters_alloc(dev_t dev)
{
	struct ksancov_dev *d = get_dev(dev);
	if (!d) {
		return EINVAL;
	}

	if (d->mode != KS_MODE_NONE) {
		return EBUSY; /* trace/counters already created */
	}
	assert(d->counters == NULL);

	uintptr_t buf;
	size_t sz = sizeof(struct ksancov_counters) + ksancov_edgemap->nedges * sizeof(uint8_t);

	/* allocate the shared memory buffer */
	kern_return_t kr = kmem_alloc_flags(kernel_map, &buf, sz, VM_KERN_MEMORY_DIAG, KMA_ZERO);
	if (kr != KERN_SUCCESS) {
		return ENOMEM;
	}

	struct ksancov_counters *counters = (struct ksancov_counters *)buf;
	counters->magic = KSANCOV_COUNTERS_MAGIC;
	counters->nedges = ksancov_edgemap->nedges;
	counters->enabled = 0;

	d->counters = counters;
	d->sz = sz;
	d->mode = KS_MODE_COUNTERS;

	return 0;
}

/*
 * attach a thread to a ksancov dev instance
 */
static int
ksancov_attach(dev_t dev, thread_t th)
{
	struct ksancov_dev *d = get_dev(dev);
	if (!d) {
		return EINVAL;
	}

	if (d->thread != THREAD_NULL) {
		int ret = ksancov_detach(dev);
		if (ret) {
			return ret;
		}
	}

	if (th != current_thread()) {
		/* can only attach to self presently */
		return EINVAL;
	}

	struct ksancov_dev **devp = (void *)__sanitizer_get_thread_data(th);
	if (*devp) {
		return EBUSY; /* one dev per thread */
	}

	d->thread = th;
	thread_reference(d->thread);

	os_atomic_store(devp, d, relaxed);
	os_atomic_add(&active_devs, 1, relaxed);

	return 0;
}

extern void
thread_wait(
	thread_t        thread,
	boolean_t       until_not_runnable);


/*
 * disconnect thread from ksancov dev
 */
static int
ksancov_detach(dev_t dev)
{
	struct ksancov_dev *d = get_dev(dev);
	if (!d) {
		return EINVAL;
	}

	if (d->thread == THREAD_NULL) {
		/* no thread attached */
		return 0;
	}

	/* disconnect dev from thread */
	struct ksancov_dev **devp = (void *)__sanitizer_get_thread_data(d->thread);
	if (*devp != NULL) {
		assert(*devp == d);
		os_atomic_store(devp, NULL, relaxed);
	}

	if (d->thread != current_thread()) {
		/* wait until it's safe to yank */
		thread_wait(d->thread, TRUE);
	}

	/* drop our thread reference */
	thread_deallocate(d->thread);
	d->thread = THREAD_NULL;

	return 0;
}

static int
ksancov_close(dev_t dev, int flags, int devtype, proc_t p)
{
#pragma unused(flags,devtype,p)
	struct ksancov_dev *d = get_dev(dev);
	if (!d) {
		return EINVAL;
	}

	if (d->mode == KS_MODE_TRACE) {
		struct ksancov_trace *trace = d->trace;
		if (trace) {
			/* trace allocated - delete it */

			os_atomic_sub(&active_devs, 1, relaxed);
			os_atomic_store(&trace->enabled, 0, relaxed); /* stop tracing */

			ksancov_detach(dev);

			/* free trace */
			kmem_free(kernel_map, (uintptr_t)d->trace, d->sz);
			d->trace = NULL;
			d->sz = 0;
		}
	} else if (d->mode == KS_MODE_COUNTERS) {
		struct ksancov_counters *counters = d->counters;
		if (counters) {
			os_atomic_sub(&active_devs, 1, relaxed);
			os_atomic_store(&counters->enabled, 0, relaxed); /* stop tracing */

			ksancov_detach(dev);

			/* free counters */
			kmem_free(kernel_map, (uintptr_t)d->counters, d->sz);
			d->counters = NULL;
			d->sz = 0;
		}
	}

	ksancov_devs[minor(dev)] = NULL; /* dev no longer discoverable */

	/* free the ksancov device instance */
	kfree(d, sizeof(struct ksancov_dev));

	return 0;
}

static void
ksancov_testpanic(volatile uint64_t guess)
{
	const uint64_t tgt = 0xf85de3b12891c817UL;

#define X(n) ((tgt & (0xfUL << (4*n))) == (guess & (0xfUL << (4*n))))

	if (X(0)) {
		if (X(1)) {
			if (X(2)) {
				if (X(3)) {
					if (X(4)) {
						if (X(5)) {
							if (X(6)) {
								if (X(7)) {
									if (X(8)) {
										if (X(9)) {
											if (X(10)) {
												if (X(11)) {
													if (X(12)) {
														if (X(13)) {
															if (X(14)) {
																if (X(15)) {
																	panic("ksancov: found test value\n");
																}
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
}

static int
ksancov_ioctl(dev_t dev, unsigned long cmd, caddr_t _data, int fflag, proc_t p)
{
#pragma unused(fflag,p)
	int ret = 0;
	void *data = (void *)_data;

	struct ksancov_dev *d = get_dev(dev);
	if (!d) {
		return EINVAL; /* dev not open */
	}

	if (cmd == KSANCOV_IOC_TRACE) {
		size_t maxpcs = *(size_t *)data;
		ret = ksancov_trace_alloc(dev, maxpcs);
		if (ret) {
			return ret;
		}
	} else if (cmd == KSANCOV_IOC_COUNTERS) {
		ret = ksancov_counters_alloc(dev);
		if (ret) {
			return ret;
		}
	} else if (cmd == KSANCOV_IOC_MAP) {
		struct ksancov_buf_desc *mcmd = (struct ksancov_buf_desc *)data;

		if (d->mode == KS_MODE_NONE) {
			return EINVAL; /* mode not configured */
		}

		/* map buffer into the userspace VA space */
		void *buf;
		size_t size;
		ret = ksancov_map(dev, &buf, &size);
		if (ret) {
			return ret;
		}

		mcmd->ptr = (uintptr_t)buf;
		mcmd->sz = size;
	} else if (cmd == KSANCOV_IOC_MAP_EDGEMAP) {
		struct ksancov_buf_desc *mcmd = (struct ksancov_buf_desc *)data;

		/* map buffer into the userspace VA space */
		void *buf;
		size_t size;
		ret = ksancov_map_edgemap(dev, &buf, &size);
		if (ret) {
			return ret;
		}

		mcmd->ptr = (uintptr_t)buf;
		mcmd->sz = size;
	} else if (cmd == KSANCOV_IOC_START) {
		if (d->mode == KS_MODE_NONE) {
			return EINVAL; /* not configured */
		}

		ret = ksancov_attach(dev, current_thread());
		if (ret) {
			return ret;
		}
	} else if (cmd == KSANCOV_IOC_NEDGES) {
		size_t *nptr = (size_t *)data;
		*nptr = nedges;
	} else if (cmd == KSANCOV_IOC_TESTPANIC) {
		uint64_t guess = *(uint64_t *)data;
		ksancov_testpanic(guess);
	} else {
		/* unknown ioctl */
		return ENODEV;
	}

	return ret;
}

static int
ksancov_dev_clone(dev_t dev, int action)
{
#pragma unused(dev)
	if (action == DEVFS_CLONE_ALLOC) {
		for (size_t i = 0; i < KSANCOV_MAX_DEV; i++) {
			if (ksancov_devs[i] == NULL) {
				return i;
			}
		}
	} else if (action == DEVFS_CLONE_FREE) {
		return 0;
	}

	return -1;
}

static struct cdevsw
    ksancov_cdev = {
	.d_open =  ksancov_open,
	.d_close = ksancov_close,
	.d_ioctl = ksancov_ioctl,

	.d_read = eno_rdwrt,
	.d_write = eno_rdwrt,
	.d_stop = eno_stop,
	.d_reset = eno_reset,
	.d_select = eno_select,
	.d_mmap = eno_mmap,
	.d_strategy = eno_strat,
	.d_type = 0
};

int
ksancov_init_dev(void)
{
	dev_major = cdevsw_add(-1, &ksancov_cdev);
	if (dev_major < 0) {
		printf("ksancov: failed to allocate major device node\n");
		return -1;
	}

	dev_t dev = makedev(dev_major, 0);
	void *node = devfs_make_node_clone(dev, DEVFS_CHAR, UID_ROOT, GID_WHEEL, 0666,
	    ksancov_dev_clone, KSANCOV_DEVNODE);
	if (!node) {
		printf("ksancov: failed to create device node\n");
		return -1;
	}

	/* This could be moved to the first use of /dev/ksancov to save memory */
	uintptr_t buf;
	size_t sz = sizeof(struct ksancov_edgemap) + KSANCOV_MAX_EDGES * sizeof(uint32_t);

	kern_return_t kr = kmem_alloc_flags(kernel_map, &buf, sz, VM_KERN_MEMORY_DIAG, KMA_ZERO);
	if (kr) {
		printf("ksancov: failed to allocate edge addr map\n");
		return -1;
	}

	ksancov_edgemap = (void *)buf;
	ksancov_edgemap->magic = KSANCOV_EDGEMAP_MAGIC;
	ksancov_edgemap->nedges = nedges;
	ksancov_edgemap->offset = VM_MIN_KERNEL_ADDRESS;

	return 0;
}
