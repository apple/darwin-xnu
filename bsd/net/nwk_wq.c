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
#include <stddef.h>
#include <kern/debug.h>
#include <kern/locks.h>
#include <kern/thread.h>
#include <kern/thread_call.h>
#include <net/nwk_wq.h>
#include <sys/proc_internal.h>
#include <sys/systm.h>
#include <sys/mcache.h>

MALLOC_DEFINE(M_NWKWQ, "nwkwq", "Network work-queue");

static TAILQ_HEAD(, nwk_wq_entry) nwk_wq_head;
decl_lck_mtx_data(static, nwk_wq_lock);

/* Lock group and attributes */
static lck_grp_attr_t *nwk_wq_lock_grp_attributes = NULL;
static lck_grp_t *nwk_wq_lock_group = NULL;

/* Lock and lock attributes */
static lck_attr_t *nwk_wq_lock_attributes = NULL;
decl_lck_mtx_data(static, nwk_wq_lock);

/* Wait channel for Network work queue */
static void *nwk_wq_waitch = NULL;
static void nwk_wq_thread_func(void *, wait_result_t);

static int nwk_wq_thread_cont(int err);
static void nwk_wq_thread_func(void *v, wait_result_t w);

void
nwk_wq_init(void)
{
	thread_t nwk_wq_thread = THREAD_NULL;

	TAILQ_INIT(&nwk_wq_head);
	nwk_wq_lock_grp_attributes = lck_grp_attr_alloc_init();
	nwk_wq_lock_group = lck_grp_alloc_init("Network work queue lock",
	    nwk_wq_lock_grp_attributes);

	nwk_wq_lock_attributes = lck_attr_alloc_init();
	lck_mtx_init(&nwk_wq_lock, nwk_wq_lock_group, nwk_wq_lock_attributes);
	if (kernel_thread_start(nwk_wq_thread_func,
	    NULL, &nwk_wq_thread) != KERN_SUCCESS) {
		panic_plain("%s: couldn't create network work queue thread", __func__);
		/* NOTREACHED */
	}
	thread_deallocate(nwk_wq_thread);
}

static int
nwk_wq_thread_cont(int err)
{
	TAILQ_HEAD(, nwk_wq_entry) temp_nwk_wq_head;
	struct nwk_wq_entry *nwk_item;
	struct nwk_wq_entry *nwk_item_next;

#pragma unused(err)
	for (;;) {
		nwk_item = NULL;
		nwk_item_next = NULL;
		TAILQ_INIT(&temp_nwk_wq_head);

		LCK_MTX_ASSERT(&nwk_wq_lock, LCK_MTX_ASSERT_OWNED);
		while (TAILQ_FIRST(&nwk_wq_head) == NULL) {
			(void) msleep0(&nwk_wq_waitch, &nwk_wq_lock,
			    (PZERO - 1), "nwk_wq_thread_cont", 0,
			    nwk_wq_thread_cont);
			/* NOTREACHED */
		}

		TAILQ_SWAP(&temp_nwk_wq_head, &nwk_wq_head, nwk_wq_entry, nwk_wq_link);
		VERIFY(TAILQ_EMPTY(&nwk_wq_head));
		lck_mtx_unlock(&nwk_wq_lock);

		VERIFY(TAILQ_FIRST(&temp_nwk_wq_head) != NULL);
		TAILQ_FOREACH_SAFE(nwk_item, &temp_nwk_wq_head, nwk_wq_link, nwk_item_next) {
			nwk_item->func(nwk_item->arg);
			if (nwk_item->is_arg_managed == FALSE) {
				FREE(nwk_item->arg, M_NWKWQ);
			}
			FREE(nwk_item, M_NWKWQ);
		}
		lck_mtx_lock(&nwk_wq_lock);
	}
}

static void
nwk_wq_thread_func(void *v, wait_result_t w)
{
#pragma unused(v, w)
	lck_mtx_lock(&nwk_wq_lock);
	(void) msleep0(&nwk_wq_waitch, &nwk_wq_lock,
	    (PZERO - 1), "nwk_wq_thread_func", 0, nwk_wq_thread_cont);
	/*
	 * msleep0() shouldn't have returned as PCATCH was not set;
	 * therefore assert in this case.
	 */
	lck_mtx_unlock(&nwk_wq_lock);
	VERIFY(0);
}

void
nwk_wq_enqueue(struct nwk_wq_entry *nwk_item)
{
	lck_mtx_lock(&nwk_wq_lock);
	TAILQ_INSERT_TAIL(&nwk_wq_head, nwk_item, nwk_wq_link);
	lck_mtx_unlock(&nwk_wq_lock);
	wakeup((caddr_t)&nwk_wq_waitch);
}
