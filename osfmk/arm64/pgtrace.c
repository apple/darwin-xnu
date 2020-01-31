/*
 * Copyright (c) 2015 Apple Inc. All rights reserved.
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

#if CONFIG_PGTRACE
#include <mach/mach_types.h>
#include <IOKit/IOLib.h>
#include <sys/msgbuf.h>
#include <sys/errno.h>
#include <arm64/pgtrace.h>
#include <libkern/OSDebug.h>

typedef struct {
	queue_chain_t chain;

	pmap_t      pmap;
	vm_offset_t start;
	vm_offset_t end;
} probe_t;

#if CONFIG_PGTRACE_NONKEXT
#include "pgtrace_decoder.h"

//--------------------------------------------
// Macros
//
#define RBUF_DEFAULT_SIZE   1024
#define RBUF_IDX(idx, mask) ((idx) & (mask))
#define MSG_MAX             130

//--------------------------------------------
// Types
//
typedef uint8_t RWLOCK;

typedef struct {
	uint64_t                id;
	pgtrace_run_result_t    res;
	void                    *stack[PGTRACE_STACK_DEPTH];
} log_t;

//--------------------------------------------
// Statics
//
static struct {
	log_t           *logs;          // Protect
	uint32_t        size;           // Protect
	uint64_t        rdidx, wridx;   // Protect
	decl_simple_lock_data(, loglock);

	uint64_t id;
	uint32_t option;
	uint32_t enabled;
	uint32_t bytes;

	queue_head_t    probes;         // Protect

	lck_grp_t       *lock_grp;
	lck_grp_attr_t  *lock_grp_attr;
	lck_attr_t      *lock_attr;
	lck_mtx_t       probelock;
} pgtrace = {};

//--------------------------------------------
// Globals
//
void
pgtrace_init(void)
{
	simple_lock_init(&pgtrace.loglock, 0);

	pgtrace.lock_attr = lck_attr_alloc_init();
	pgtrace.lock_grp_attr = lck_grp_attr_alloc_init();
	pgtrace.lock_grp = lck_grp_alloc_init("pgtrace_lock", pgtrace.lock_grp_attr);

	lck_mtx_init(&pgtrace.probelock, pgtrace.lock_grp, pgtrace.lock_attr);

	queue_init(&pgtrace.probes);

	pgtrace.size = RBUF_DEFAULT_SIZE;
	pgtrace.logs = kalloc(RBUF_DEFAULT_SIZE * sizeof(log_t));
}

void
pgtrace_clear_probe(void)
{
	probe_t *p, *next;
	queue_head_t *q = &pgtrace.probes;

	lck_mtx_lock(&pgtrace.probelock);

	p = (probe_t *)queue_first(q);
	while (!queue_end(q, (queue_entry_t)p)) {
		next = (probe_t *)queue_next(&(p->chain));

		queue_remove(q, p, probe_t *, chain);
		kfree(p, sizeof(probe_t));

		p = next;
	}

	lck_mtx_unlock(&pgtrace.probelock);

	return;
}

int
pgtrace_add_probe(thread_t thread, vm_offset_t start, vm_offset_t end)
{
	probe_t *p;
	queue_head_t *q = &pgtrace.probes;

	if (start > end) {
		kprintf("%s Invalid start=%lx end=%lx\n", __func__, start, end);
		return -1;
	}

	p = kalloc(sizeof(probe_t));
	p->start = start;
	p->end = end;
	if (thread == NULL) {
		p->pmap = NULL;
	} else {
		p->pmap = vm_map_pmap(thread->map);
	}

	lck_mtx_lock(&pgtrace.probelock);
	queue_enter(q, p, probe_t *, chain);
	lck_mtx_unlock(&pgtrace.probelock);

	return 0;
}

void
pgtrace_start(void)
{
	probe_t *p;
	queue_head_t *q = &pgtrace.probes;

	kprintf("%s\n", __func__);

	if (pgtrace.enabled) {
		return;
	}

	pgtrace.enabled = 1;

	lck_mtx_lock(&pgtrace.probelock);

	queue_iterate(q, p, probe_t *, chain) {
		pmap_pgtrace_add_page(p->pmap, p->start, p->end);
	}

	lck_mtx_unlock(&pgtrace.probelock);

	return;
}

void
pgtrace_stop(void)
{
	probe_t *p;
	queue_head_t *q = &pgtrace.probes;

	kprintf("%s\n", __func__);

	lck_mtx_lock(&pgtrace.probelock);

	queue_iterate(q, p, probe_t *, chain) {
		pmap_pgtrace_delete_page(p->pmap, p->start, p->end);
	}

	lck_mtx_unlock(&pgtrace.probelock);

	pgtrace.enabled = 0;
}

uint32_t
pgtrace_get_size(void)
{
	return pgtrace.size;
}

bool
pgtrace_set_size(uint32_t size)
{
	log_t *old_buf, *new_buf;
	uint32_t old_size, new_size = 1;

	// round up to next power of 2
	while (size > new_size) {
		new_size <<= 1;
		if (new_size > 0x100000) {
			// over million entries
			kprintf("%s: size=%x new_size=%x is too big\n", __func__, size, new_size);
			return false;
		}
	}

	new_buf = kalloc(new_size * sizeof(log_t));
	if (new_buf == NULL) {
		kprintf("%s: can't allocate new_size=%x\n entries", __func__, new_size);
		return false;
	}

	pgtrace_stop();

	simple_lock(&pgtrace.loglock);
	old_buf = pgtrace.logs;
	old_size = pgtrace.size;
	pgtrace.logs = new_buf;
	pgtrace.size = new_size;
	pgtrace.rdidx = pgtrace.wridx = 0;
	simple_unlock(&pgtrace.loglock);

	if (old_buf) {
		kfree(old_buf, old_size * sizeof(log_t));
	}

	return true;
}

void
pgtrace_clear_trace(void)
{
	simple_lock(&pgtrace.loglock);
	pgtrace.rdidx = pgtrace.wridx = 0;
	simple_unlock(&pgtrace.loglock);
}

boolean_t
pgtrace_active(void)
{
	return pgtrace.enabled > 0;
}

uint32_t
pgtrace_get_option(void)
{
	return pgtrace.option;
}

void
pgtrace_set_option(uint32_t option)
{
	pgtrace.option = option;
}

// pgtrace_write_log() is in interrupt disabled context
void
pgtrace_write_log(pgtrace_run_result_t res)
{
	uint8_t i;
	log_t log = {};
	const char *rwmap[] = { "R", "W", "PREFETCH" };

	log.id = pgtrace.id++;
	log.res = res;

	if (pgtrace.option & PGTRACE_OPTION_KPRINTF) {
		char msg[MSG_MAX];
		char *p;

		p = msg;

		snprintf(p, MSG_MAX, "%llu %s ", res.rr_time, rwmap[res.rr_rw]);
		p += strlen(p);

		for (i = 0; i < res.rr_num; i++) {
			snprintf(p, MSG_MAX - (p - msg), "%lx=%llx ", res.rr_addrdata[i].ad_addr, res.rr_addrdata[i].ad_data);
			p += strlen(p);
		}

		kprintf("%s %s\n", __func__, msg);
	}

	if (pgtrace.option & PGTRACE_OPTION_STACK) {
		OSBacktrace(log.stack, PGTRACE_STACK_DEPTH);
	}

	pgtrace.bytes += sizeof(log);

	simple_lock(&pgtrace.loglock);

	pgtrace.logs[RBUF_IDX(pgtrace.wridx, pgtrace.size - 1)] = log;

	// Advance rdidx if ring is full
	if (RBUF_IDX(pgtrace.wridx, pgtrace.size - 1) == RBUF_IDX(pgtrace.rdidx, pgtrace.size - 1) &&
	    (pgtrace.wridx != pgtrace.rdidx)) {
		pgtrace.rdidx++;
	}
	pgtrace.wridx++;

	// Signal if ring was empty
	if (pgtrace.wridx == (pgtrace.rdidx + 1)) {
		thread_wakeup(pgtrace.logs);
	}

	simple_unlock(&pgtrace.loglock);

	return;
}

// pgtrace_read_log() is in user thread
int64_t
pgtrace_read_log(uint8_t *buf, uint32_t size)
{
	int total, front, back;
	boolean_t ints;
	wait_result_t wr;

	if (pgtrace.enabled == FALSE) {
		return -EINVAL;
	}

	total = size / sizeof(log_t);

	// Check if buf is too small
	if (buf && total == 0) {
		return -EINVAL;
	}

	ints = ml_set_interrupts_enabled(FALSE);
	simple_lock(&pgtrace.loglock);

	// Wait if ring is empty
	if (pgtrace.rdidx == pgtrace.wridx) {
		assert_wait(pgtrace.logs, THREAD_ABORTSAFE);

		simple_unlock(&pgtrace.loglock);
		ml_set_interrupts_enabled(ints);

		wr = thread_block(NULL);
		if (wr != THREAD_AWAKENED) {
			return -EINTR;
		}

		ints = ml_set_interrupts_enabled(FALSE);
		simple_lock(&pgtrace.loglock);
	}

	// Trim the size
	if ((pgtrace.rdidx + total) > pgtrace.wridx) {
		total = (int)(pgtrace.wridx - pgtrace.rdidx);
	}

	// Copy front
	if ((RBUF_IDX(pgtrace.rdidx, pgtrace.size - 1) + total) >= pgtrace.size) {
		front = pgtrace.size - RBUF_IDX(pgtrace.rdidx, pgtrace.size - 1);
	} else {
		front = total;
	}

	memcpy(buf, &(pgtrace.logs[RBUF_IDX(pgtrace.rdidx, pgtrace.size - 1)]), front * sizeof(log_t));

	// Copy back if any
	back = total - front;
	if (back) {
		buf += front * sizeof(log_t);
		memcpy(buf, pgtrace.logs, back * sizeof(log_t));
	}

	pgtrace.rdidx += total;

	simple_unlock(&pgtrace.loglock);
	ml_set_interrupts_enabled(ints);

	return total * sizeof(log_t);
}

int
pgtrace_get_stats(pgtrace_stats_t *stats)
{
	if (!stats) {
		return -1;
	}

	stats->stat_logger.sl_bytes = pgtrace.bytes;
	pgtrace_decoder_get_stats(stats);

	return 0;
}

#else // CONFIG_PGTRACE_NONKEXT

static struct {
	bool            active;
	decoder_t       *decoder;
	logger_t        *logger;
	queue_head_t    probes;

	lck_grp_t       *lock_grp;
	lck_grp_attr_t  *lock_grp_attr;
	lck_attr_t      *lock_attr;
	lck_mtx_t       probelock;
} pgtrace = {};

//------------------------------------
// functions for pmap fault handler
// - pgtrace_decode_and_run
// - pgtrace_write_log
//------------------------------------
int
pgtrace_decode_and_run(uint32_t inst, vm_offset_t fva, vm_map_offset_t *cva_page, arm_saved_state_t *ss, pgtrace_run_result_t *res)
{
	vm_offset_t pa, cva;
	pgtrace_instruction_info_t info;
	vm_offset_t cva_front_page = cva_page[0];
	vm_offset_t cva_cur_page = cva_page[1];

	pgtrace.decoder->decode(inst, ss, &info);

	if (info.addr == fva) {
		cva = cva_cur_page + (fva & ARM_PGMASK);
	} else {
		// which means a front page is not a tracing page
		cva = cva_front_page + (fva & ARM_PGMASK);
	}

	pa = mmu_kvtop(cva);
	if (!pa) {
		panic("%s: invalid address cva=%lx fva=%lx info.addr=%lx inst=%x", __func__, cva, fva, info.addr, inst);
	}

	absolutetime_to_nanoseconds(mach_absolute_time(), &res->rr_time);

	pgtrace.decoder->run(inst, pa, cva, ss, res);

	return 0;
}

int
pgtrace_write_log(pgtrace_run_result_t res)
{
	pgtrace.logger->write(res);
	return 0;
}

//------------------------------------
// functions for kext
//  - pgtrace_init
//  - pgtrace_add_probe
//  - pgtrace_clear_probe
//  - pgtrace_start
//  - pgtrace_stop
//  - pgtrace_active
//------------------------------------
int
pgtrace_init(decoder_t *decoder, logger_t *logger)
{
	kprintf("%s decoder=%p logger=%p\n", __func__, decoder, logger);

	assert(decoder && logger);

	if (decoder->magic != 0xfeedface || logger->magic != 0xfeedface ||
	    strcmp(decoder->arch, "arm64") != 0 || strcmp(logger->arch, "arm64") != 0) {
		kprintf("%s:wrong decoder/logger magic=%llx/%llx arch=%s/%s", __func__, decoder->magic, logger->magic, decoder->arch, logger->arch);
		return EINVAL;
	}

	pgtrace.lock_attr = lck_attr_alloc_init();
	pgtrace.lock_grp_attr = lck_grp_attr_alloc_init();
	pgtrace.lock_grp = lck_grp_alloc_init("pgtrace_lock", pgtrace.lock_grp_attr);

	lck_mtx_init(&pgtrace.probelock, pgtrace.lock_grp, pgtrace.lock_attr);

	queue_init(&pgtrace.probes);
	pgtrace.decoder = decoder;
	pgtrace.logger = logger;

	return 0;
}

int
pgtrace_add_probe(thread_t thread, vm_offset_t start, vm_offset_t end)
{
	probe_t *p;
	queue_head_t *q = &pgtrace.probes;

	kprintf("%s start=%lx end=%lx\n", __func__, start, end);

	if (start > end) {
		kprintf("%s Invalid start=%lx end=%lx\n", __func__, start, end);
		return -1;
	}

	p = kalloc(sizeof(probe_t));
	p->start = start;
	p->end = end;
	if (thread == NULL) {
		p->pmap = NULL;
	} else {
		p->pmap = vm_map_pmap(thread->map);
	}

	lck_mtx_lock(&pgtrace.probelock);
	queue_enter(q, p, probe_t *, chain);
	lck_mtx_unlock(&pgtrace.probelock);

	return 0;
}

void
pgtrace_clear_probe(void)
{
	probe_t *p, *next;
	queue_head_t *q = &pgtrace.probes;

	kprintf("%s\n", __func__);

	lck_mtx_lock(&pgtrace.probelock);

	p = (probe_t *)queue_first(q);
	while (!queue_end(q, (queue_entry_t)p)) {
		next = (probe_t *)queue_next(&(p->chain));

		queue_remove(q, p, probe_t *, chain);
		kfree(p, sizeof(probe_t));

		p = next;
	}

	lck_mtx_unlock(&pgtrace.probelock);

	return;
}

void
pgtrace_start(void)
{
	probe_t *p;
	queue_head_t *q = &pgtrace.probes;

	kprintf("%s\n", __func__);

	if (pgtrace.active == true) {
		return;
	}

	pgtrace.active = true;

	lck_mtx_lock(&pgtrace.probelock);

	queue_iterate(q, p, probe_t *, chain) {
		pmap_pgtrace_add_page(p->pmap, p->start, p->end);
	}

	lck_mtx_unlock(&pgtrace.probelock);

	return;
}

void
pgtrace_stop(void)
{
	probe_t *p;
	queue_head_t *q = &pgtrace.probes;

	kprintf("%s\n", __func__);

	lck_mtx_lock(&pgtrace.probelock);

	queue_iterate(q, p, probe_t *, chain) {
		pmap_pgtrace_delete_page(p->pmap, p->start, p->end);
	}

	lck_mtx_unlock(&pgtrace.probelock);

	pgtrace.active = false;
}

bool
pgtrace_active(void)
{
	return pgtrace.active;
}
#endif // CONFIG_PGTRACE_NONKEXT
#else
// empty funcs for release kernel
extern void pgtrace_stop(void);
extern void pgtrace_start(void);
extern void pgtrace_clear_probe(void);
extern void pgtrace_add_probe(void);
extern void pgtrace_init(void);
extern void pgtrace_active(void);
void
pgtrace_stop(void)
{
}
void
pgtrace_start(void)
{
}
void
pgtrace_clear_probe(void)
{
}
void
pgtrace_add_probe(void)
{
}
void
pgtrace_init(void)
{
}
void
pgtrace_active(void)
{
}
#endif
