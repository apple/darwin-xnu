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

#ifndef _KSANCOV_H_
#define _KSANCOV_H_

#include <stdint.h>
#include <stdatomic.h>
#include <sys/ioccom.h>

#define KSANCOV_DEVNODE "ksancov"
#define KSANCOV_PATH "/dev/" KSANCOV_DEVNODE

/*
 * ioctl
 */

struct ksancov_buf_desc {
	uintptr_t ptr;  /* ptr to shared buffer [out] */
	size_t sz;      /* size of shared buffer [out] */
};

/* Set mode */
#define KSANCOV_IOC_TRACE        _IOW('K', 1, size_t) /* number of pcs */
#define KSANCOV_IOC_COUNTERS     _IO('K', 2)

/* Establish a shared mapping of the coverage buffer. */
#define KSANCOV_IOC_MAP          _IOWR('K', 8, struct ksancov_buf_desc)

/* Establish a shared mapping of the edge address buffer. */
#define KSANCOV_IOC_MAP_EDGEMAP  _IOWR('K', 9, struct ksancov_buf_desc)

/* Log the current thread */
#define KSANCOV_IOC_START        _IOW('K', 10, uintptr_t)

#define KSANCOV_IOC_NEDGES       _IOR('K', 50, size_t)

#define KSANCOV_IOC_TESTPANIC    _IOW('K', 20, uint64_t)


/*
 * shared kernel-user mapping
 */

#define KSANCOV_MAX_EDGES       512UL*1024
#define KSANCOV_MAX_HITS        UINT8_MAX
#define KSANCOV_TRACE_MAGIC     (uint32_t)0x5AD17F5BU
#define KSANCOV_COUNTERS_MAGIC  (uint32_t)0x5AD27F6BU
#define KSANCOV_EDGEMAP_MAGIC   (uint32_t)0x5AD37F7BU

struct ksancov_header {
	uint32_t magic;
	_Atomic uint32_t enabled;
};

struct ksancov_trace {
	/* userspace R/O fields */
	union {
		struct ksancov_header hdr;
		struct {
			uint32_t magic;
			_Atomic uint32_t enabled;
		};
	};

	uintptr_t offset; /* pc entries relative to this */
	uint32_t maxpcs;
	_Atomic uint32_t head;
	uint32_t pcs[];
};

struct ksancov_counters {
	union {
		struct ksancov_header hdr;
		struct {
			uint32_t magic;
			_Atomic uint32_t enabled;
		};
	};

	uint32_t nedges; /* total number of edges */
	uint8_t hits[];  /* hits on each edge (8bit saturating) */
};

struct ksancov_edgemap {
	uint32_t magic;
	uint32_t nedges;
	uintptr_t offset; /* edge addrs relative to this */
	uint32_t addrs[]; /* address of each edge relative to 'offset' */
};

#if XNU_KERNEL_PRIVATE
/*
 * On arm64 the VIM_MIN_KERNEL_ADDRESS is too far from %pc to fit into 32-bit value. As a result
 * ksancov reports invalid %pcs. To make at least kernel %pc values corect a different base has
 * to be used for arm.
 */
#if defined(__x86_64__) || defined(__i386__)
#define KSANCOV_PC_OFFSET VM_MIN_KERNEL_ADDRESS
#elif defined(__arm__) || defined(__arm64__)
#define KSANCOV_PC_OFFSET VM_KERNEL_LINK_ADDRESS
#else
#error "Unsupported platform"
#endif

int ksancov_init_dev(void);
void **__sanitizer_get_thread_data(thread_t);

/*
 * SanitizerCoverage ABI
 */
extern void __sanitizer_cov_trace_pc_guard(uint32_t *guard);
extern void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop);
extern void __sanitizer_cov_pcs_init(uintptr_t *start, uintptr_t *stop);
extern void __sanitizer_cov_trace_pc(void);
extern void __sanitizer_cov_trace_pc_indirect(void *callee);
#endif

#ifndef KERNEL

#include <strings.h>
#include <assert.h>
#include <unistd.h>

/*
 * ksancov userspace API
 *
 * Usage:
 * 1) open the ksancov device
 * 2) set the coverage mode (trace or edge counters)
 * 3) map the coverage buffer
 * 4) start the trace on a thread
 * 5) flip the enable bit
 */

static inline int
ksancov_open(void)
{
	return open(KSANCOV_PATH, 0);
}

static inline int
ksancov_map(int fd, uintptr_t *buf, size_t *sz)
{
	int ret;
	struct ksancov_buf_desc mc = {0};

	ret = ioctl(fd, KSANCOV_IOC_MAP, &mc);
	if (ret == -1) {
		return errno;
	}

	*buf = mc.ptr;
	if (sz) {
		*sz = mc.sz;
	}

	struct ksancov_trace *trace = (void *)mc.ptr;
	assert(trace->magic == KSANCOV_TRACE_MAGIC ||
	    trace->magic == KSANCOV_COUNTERS_MAGIC);

	return 0;
}

static inline int
ksancov_map_edgemap(int fd, uintptr_t *buf, size_t *sz)
{
	int ret;
	struct ksancov_buf_desc mc = {0};

	ret = ioctl(fd, KSANCOV_IOC_MAP_EDGEMAP, &mc);
	if (ret == -1) {
		return errno;
	}

	*buf = mc.ptr;
	if (sz) {
		*sz = mc.sz;
	}

	struct ksancov_trace *trace = (void *)mc.ptr;
	assert(trace->magic == KSANCOV_EDGEMAP_MAGIC);

	return 0;
}

static inline size_t
ksancov_nedges(int fd)
{
	size_t nedges;
	int ret = ioctl(fd, KSANCOV_IOC_NEDGES, &nedges);
	if (ret == -1) {
		return SIZE_MAX;
	}
	return nedges;
}

static inline int
ksancov_mode_trace(int fd, size_t entries)
{
	int ret;
	ret = ioctl(fd, KSANCOV_IOC_TRACE, &entries);
	if (ret == -1) {
		return errno;
	}
	return 0;
}

static inline int
ksancov_mode_counters(int fd)
{
	int ret;
	ret = ioctl(fd, KSANCOV_IOC_COUNTERS);
	if (ret == -1) {
		return errno;
	}
	return 0;
}

static inline int
ksancov_thread_self(int fd)
{
	int ret;
	uintptr_t th = 0;
	ret = ioctl(fd, KSANCOV_IOC_START, &th);
	if (ret == -1) {
		return errno;
	}
	return 0;
}

static inline int
ksancov_start(void *buf)
{
	struct ksancov_header *hdr = (struct ksancov_header *)buf;
	atomic_store_explicit(&hdr->enabled, 1, memory_order_relaxed);
	return 0;
}

static inline int
ksancov_stop(void *buf)
{
	struct ksancov_header *hdr = (struct ksancov_header *)buf;
	atomic_store_explicit(&hdr->enabled, 0, memory_order_relaxed);
	return 0;
}

static inline int
ksancov_reset(void *buf)
{
	struct ksancov_header *hdr = (struct ksancov_header *)buf;
	if (hdr->magic == KSANCOV_TRACE_MAGIC) {
		struct ksancov_trace *trace = (struct ksancov_trace *)buf;
		atomic_store_explicit(&trace->head, 0, memory_order_relaxed);
	} else if (hdr->magic == KSANCOV_COUNTERS_MAGIC) {
		struct ksancov_counters *counters = (struct ksancov_counters *)buf;
		bzero(counters->hits, counters->nedges);
	} else {
		return EINVAL;
	}
	return 0;
}

static inline uintptr_t
ksancov_edge_addr(struct ksancov_edgemap *addrs, size_t idx)
{
	assert(addrs);
	if (idx >= addrs->nedges) {
		return 0;
	}
	return addrs->addrs[idx] + addrs->offset;
}

static inline size_t
ksancov_trace_max_pcs(struct ksancov_trace *trace)
{
	return trace->maxpcs;
}

static inline uintptr_t
ksancov_trace_offset(struct ksancov_trace *trace)
{
	assert(trace);
	return trace->offset;
}

static inline size_t
ksancov_trace_head(struct ksancov_trace *trace)
{
	size_t maxlen = trace->maxpcs;
	size_t head = atomic_load_explicit(&trace->head, memory_order_acquire);
	return head < maxlen ? head : maxlen;
}

static inline uintptr_t
ksancov_trace_entry(struct ksancov_trace *trace, size_t i)
{
	if (i >= trace->head) {
		return 0;
	}

	return trace->pcs[i] + trace->offset;
}

#endif

#endif /* _KSANCOV_H_ */
