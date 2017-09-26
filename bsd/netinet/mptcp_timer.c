/*
 * Copyright (c) 2012-2017 Apple Inc. All rights reserved.
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
#include <sys/mcache.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/syslog.h>
#include <sys/protosw.h>
#include <sys/sysctl.h>

#include <mach/sdt.h>

#include <netinet/mp_pcb.h>
#include <netinet/mptcp_var.h>
#include <netinet/mptcp_timer.h>
#include <netinet/mptcp_seq.h>

#include <kern/locks.h>

/*
 * MPTCP Retransmission Timer comes into play only when subflow level
 * data is acked, but Data ACK is not received. Time is in seconds.
 */
static u_int32_t mptcp_rto = 3;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, rto, CTLFLAG_RW | CTLFLAG_LOCKED,
	&mptcp_rto, 0, "MPTCP Retransmission Timeout");

static int mptcp_nrtos = 3;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, nrto, CTLFLAG_RW | CTLFLAG_LOCKED,
	&mptcp_rto, 0, "MPTCP Retransmissions");

/*
 * MPTCP connections timewait interval in seconds.
 */
static u_int32_t mptcp_tw = 60;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, tw, CTLFLAG_RW | CTLFLAG_LOCKED,
	&mptcp_tw, 0, "MPTCP Timewait Period");

#define	TIMEVAL_TO_HZ(_tv_)	((_tv_).tv_sec * hz + (_tv_).tv_usec / hz)

static int
mptcp_timer_demux(struct mptses *mpte, uint32_t now_msecs)
{
	struct mptcb *mp_tp = NULL;
	mp_tp = mpte->mpte_mptcb;
	int resched_timer = 0;

	DTRACE_MPTCP2(timer, struct mptses *, mpte, struct mptcb *, mp_tp);

	mpte_lock_assert_held(mpte);
	switch (mp_tp->mpt_timer_vals) {
	case MPTT_REXMT:
		if (mp_tp->mpt_rxtstart == 0)
			break;
		if ((now_msecs - mp_tp->mpt_rxtstart) >
		    (mptcp_rto*hz)) {
			if (MPTCP_SEQ_GT(mp_tp->mpt_snduna,
			    mp_tp->mpt_rtseq)) {
				mp_tp->mpt_timer_vals = 0;
				mp_tp->mpt_rtseq = 0;
				break;
			}
			mp_tp->mpt_rxtshift++;
			if (mp_tp->mpt_rxtshift > mptcp_nrtos) {
				mp_tp->mpt_softerror = ETIMEDOUT;
				DTRACE_MPTCP1(error, struct mptcb *, mp_tp);
			} else {
				mp_tp->mpt_sndnxt = mp_tp->mpt_rtseq;
				mptcplog((LOG_DEBUG, "MPTCP Socket: "
				   "%s: REXMT %d times.\n",
				    __func__, mp_tp->mpt_rxtshift),
				    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_LOG);
				mptcp_output(mpte);
			}
		} else {
			resched_timer = 1;
		}
		break;
	case MPTT_TW:
		/* Allows for break before make XXX */
		if (mp_tp->mpt_timewait == 0)
			VERIFY(0);
		if ((now_msecs - mp_tp->mpt_timewait) >
		    (mptcp_tw * hz)) {
			mp_tp->mpt_softerror = ETIMEDOUT;
			DTRACE_MPTCP1(error, struct mptcb *, mp_tp);
		} else {
			resched_timer = 1;
		}
		break;
	case MPTT_FASTCLOSE:
		/* TODO XXX */
		break;
	default:
		break;
	}

	return (resched_timer);
}

uint32_t
mptcp_timer(struct mppcbinfo *mppi)
{
	struct mppcb *mpp, *tmpp;
	struct timeval now;
	u_int32_t now_msecs;
	uint32_t resched_timer = 0;

	LCK_MTX_ASSERT(&mppi->mppi_lock, LCK_MTX_ASSERT_OWNED);

	microuptime(&now);
	now_msecs = TIMEVAL_TO_HZ(now);
	TAILQ_FOREACH_SAFE(mpp, &mppi->mppi_pcbs, mpp_entry, tmpp) {
		struct socket *mp_so;
		struct mptses *mpte;

		mp_so = mpp->mpp_socket;
		VERIFY(mp_so != NULL);
		mpte = mptompte(mpp);
		VERIFY(mpte != NULL);
		mpte_lock(mpte);
		VERIFY(mpp->mpp_flags & MPP_ATTACHED);

		if (mptcp_timer_demux(mpte, now_msecs))
			resched_timer = 1;
		mpte_unlock(mpte);
	}

	return (resched_timer);
}

void
mptcp_start_timer(struct mptses *mpte, int timer_type)
{
	struct timeval now;
	struct mptcb *mp_tp = mpte->mpte_mptcb;

	microuptime(&now);

	DTRACE_MPTCP2(start__timer, struct mptcb *, mp_tp, int, timer_type);
	mptcplog((LOG_DEBUG, "MPTCP Socket: %s: %d\n", __func__, timer_type),
	    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_VERBOSE);

	mpte_lock_assert_held(mpte);

	switch (timer_type) {
	case MPTT_REXMT:
		mp_tp->mpt_timer_vals |= MPTT_REXMT;
		mp_tp->mpt_rxtstart = TIMEVAL_TO_HZ(now);
		mp_tp->mpt_rxtshift = 0;
		mp_tp->mpt_rtseq = mp_tp->mpt_sndnxt;
		break;
	case MPTT_TW:
		/* XXX: Not implemented yet */
		mp_tp->mpt_timer_vals |= MPTT_TW;
		mp_tp->mpt_timewait = TIMEVAL_TO_HZ(now);
		break;
	case MPTT_FASTCLOSE:
		/* NO-OP */
		break;
	default:
		VERIFY(0);
		/* NOTREACHED */
	}
	mptcp_timer_sched();
}

void
mptcp_cancel_timer(struct mptcb *mp_tp, int timer_type)
{
	mpte_lock_assert_held(mp_tp->mpt_mpte);
	DTRACE_MPTCP2(cancel__timer, struct mptcb *, mp_tp, int, timer_type);

	switch (timer_type) {
	case MPTT_REXMT:
		mp_tp->mpt_rxtstart = 0;
		mp_tp->mpt_rxtshift = 0;
		mp_tp->mpt_timer_vals = 0;
		break;
	case MPTT_TW:
		/* NO-OP */
		break;
	case MPTT_FASTCLOSE:
		/* NO-OP */
		break;
	default:
		break;
	}
}

void
mptcp_cancel_all_timers(struct mptcb *mp_tp)
{
	mptcp_cancel_timer(mp_tp, MPTT_REXMT);
	mptcp_cancel_timer(mp_tp, MPTT_TW);
	mptcp_cancel_timer(mp_tp, MPTT_FASTCLOSE);
}
