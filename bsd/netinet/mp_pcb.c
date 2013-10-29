/*
 * Copyright (c) 2012-2013 Apple Inc. All rights reserved.
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
#include <sys/mbuf.h>
#include <sys/mcache.h>
#include <sys/syslog.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/proc_internal.h>

#include <mach/boolean.h>
#include <kern/zalloc.h>
#include <kern/locks.h>

#include <netinet/mp_pcb.h>
#include <netinet/mptcp_var.h>

static lck_grp_t	*mp_lock_grp;
static lck_attr_t	*mp_lock_attr;
static lck_grp_attr_t	*mp_lock_grp_attr;
decl_lck_mtx_data(static, mp_lock);		/* global MULTIPATH lock */
decl_lck_mtx_data(static, mp_timeout_lock);

static TAILQ_HEAD(, mppcbinfo) mppi_head = TAILQ_HEAD_INITIALIZER(mppi_head);

static boolean_t mp_timeout_run;	/* MP timer is scheduled to run */
static boolean_t mp_garbage_collecting;
static boolean_t mp_ticking;
static void mp_sched_timeout(void);
static void mp_timeout(void *);

void
mp_pcbinit(void)
{
	static int mp_initialized = 0;

	VERIFY(!mp_initialized);
	mp_initialized = 1;

	mp_lock_grp_attr = lck_grp_attr_alloc_init();
	mp_lock_grp = lck_grp_alloc_init("multipath", mp_lock_grp_attr);
	mp_lock_attr = lck_attr_alloc_init();
	lck_mtx_init(&mp_lock, mp_lock_grp, mp_lock_attr);
	lck_mtx_init(&mp_timeout_lock, mp_lock_grp, mp_lock_attr);
}

static void
mp_timeout(void *arg)
{
#pragma unused(arg)
	struct mppcbinfo *mppi;
	boolean_t t, gc;
	uint32_t t_act = 0;
	uint32_t gc_act = 0;

	/*
	 * Update coarse-grained networking timestamp (in sec.); the idea
	 * is to piggy-back on the timeout callout to update the counter
	 * returnable via net_uptime().
	 */
	net_update_uptime();

	lck_mtx_lock_spin(&mp_timeout_lock);
	gc = mp_garbage_collecting;
	mp_garbage_collecting = FALSE;

	t = mp_ticking;
	mp_ticking = FALSE;

	if (gc || t) {
		lck_mtx_unlock(&mp_timeout_lock);

		lck_mtx_lock(&mp_lock);
		TAILQ_FOREACH(mppi, &mppi_head, mppi_entry) {
			if ((gc && mppi->mppi_gc != NULL) ||
			    (t && mppi->mppi_timer != NULL)) {
				lck_mtx_lock(&mppi->mppi_lock);
				if (gc && mppi->mppi_gc != NULL)
					gc_act += mppi->mppi_gc(mppi);
				if (t && mppi->mppi_timer != NULL)
					t_act += mppi->mppi_timer(mppi);
				lck_mtx_unlock(&mppi->mppi_lock);
			}
		}
		lck_mtx_unlock(&mp_lock);

		lck_mtx_lock_spin(&mp_timeout_lock);
	}

	/* lock was dropped above, so check first before overriding */
	if (!mp_garbage_collecting)
		mp_garbage_collecting = (gc_act != 0);
	if (!mp_ticking)
		mp_ticking = (t_act != 0);

	/* re-arm the timer if there's work to do */
	mp_timeout_run = FALSE;
	mp_sched_timeout();
	lck_mtx_unlock(&mp_timeout_lock);
}

static void
mp_sched_timeout(void)
{
	lck_mtx_assert(&mp_timeout_lock, LCK_MTX_ASSERT_OWNED);

	if (!mp_timeout_run && (mp_garbage_collecting || mp_ticking)) {
		lck_mtx_convert_spin(&mp_timeout_lock);
		mp_timeout_run = TRUE;
		timeout(mp_timeout, NULL, hz);
	}
}

void
mp_gc_sched(void)
{
	lck_mtx_lock_spin(&mp_timeout_lock);
	mp_garbage_collecting = TRUE;
	mp_sched_timeout();
	lck_mtx_unlock(&mp_timeout_lock);
}

void
mptcp_timer_sched(void)
{
	lck_mtx_lock_spin(&mp_timeout_lock);
	mp_ticking = TRUE;
	mp_sched_timeout();
	lck_mtx_unlock(&mp_timeout_lock);
}

void
mp_pcbinfo_attach(struct mppcbinfo *mppi)
{
	struct mppcbinfo *mppi0;

	lck_mtx_lock(&mp_lock);
	TAILQ_FOREACH(mppi0, &mppi_head, mppi_entry) {
		if (mppi0 == mppi) {
			panic("%s: mppi %p already in the list\n",
			    __func__, mppi);
			/* NOTREACHED */
		}
	}
	TAILQ_INSERT_TAIL(&mppi_head, mppi, mppi_entry);
	lck_mtx_unlock(&mp_lock);
}

int
mp_pcbinfo_detach(struct mppcbinfo *mppi)
{
	struct mppcbinfo *mppi0;
	int error = 0;

	lck_mtx_lock(&mp_lock);
	TAILQ_FOREACH(mppi0, &mppi_head, mppi_entry) {
		if (mppi0 == mppi)
			break;
	}
	if (mppi0 != NULL)
		TAILQ_REMOVE(&mppi_head, mppi0, mppi_entry);
	else
		error = ENXIO;
	lck_mtx_unlock(&mp_lock);

	return (error);
}

int
mp_pcballoc(struct socket *so, struct mppcbinfo *mppi)
{
	struct mppcb *mpp;

	VERIFY(sotomppcb(so) == NULL);

	lck_mtx_lock(&mppi->mppi_lock);
	if (mppi->mppi_count >= mptcp_socket_limit) {
		lck_mtx_unlock(&mppi->mppi_lock);
		mptcplog((LOG_ERR, "Reached MPTCP socket limit."));
		return (ENOBUFS);
	}
	lck_mtx_unlock(&mppi->mppi_lock);

	mpp = zalloc(mppi->mppi_zone);
	if (mpp == NULL)
		return (ENOBUFS);

	bzero(mpp, mppi->mppi_size);
	lck_mtx_init(&mpp->mpp_lock, mppi->mppi_lock_grp, mppi->mppi_lock_attr);
	mpp->mpp_pcbinfo = mppi;
	mpp->mpp_state = MPPCB_STATE_INUSE;
	mpp->mpp_socket = so;
	so->so_pcb = mpp;

	lck_mtx_lock(&mppi->mppi_lock);
	mpp->mpp_flags |= MPP_ATTACHED;
	TAILQ_INSERT_TAIL(&mppi->mppi_pcbs, mpp, mpp_entry);
	mppi->mppi_count++;
	lck_mtx_unlock(&mppi->mppi_lock);

	return (0);
}

void
mp_pcbdetach(struct mppcb *mpp)
{
	struct socket *so = mpp->mpp_socket;

	VERIFY(so->so_pcb == mpp);

	mpp->mpp_state = MPPCB_STATE_DEAD;
	if (!(so->so_flags & SOF_PCBCLEARING))
		so->so_flags |= SOF_PCBCLEARING;

	mp_gc_sched();
}

void
mp_pcbdispose(struct mppcb *mpp)
{
	struct mppcbinfo *mppi = mpp->mpp_pcbinfo;

	VERIFY(mppi != NULL);

	lck_mtx_assert(&mppi->mppi_lock, LCK_MTX_ASSERT_OWNED);
	lck_mtx_assert(&mpp->mpp_lock, LCK_MTX_ASSERT_OWNED);

	VERIFY(mpp->mpp_state == MPPCB_STATE_DEAD);

	VERIFY(mpp->mpp_flags & MPP_ATTACHED);
	mpp->mpp_flags &= ~MPP_ATTACHED;
	TAILQ_REMOVE(&mppi->mppi_pcbs, mpp, mpp_entry);
	VERIFY(mppi->mppi_count != 0);
	mppi->mppi_count--;

	VERIFY(mpp->mpp_socket != NULL);
	VERIFY(mpp->mpp_socket->so_usecount == 0);
	mpp->mpp_socket->so_pcb = NULL;
	mpp->mpp_socket = NULL;

	lck_mtx_unlock(&mpp->mpp_lock);
	lck_mtx_destroy(&mpp->mpp_lock, mppi->mppi_lock_grp);
	zfree(mppi->mppi_zone, mpp);
}
