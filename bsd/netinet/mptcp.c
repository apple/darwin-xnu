/*
 * Copyright (c) 2012-2015 Apple Inc. All rights reserved.
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
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/syslog.h>
#include <sys/protosw.h>

#include <kern/zalloc.h>
#include <kern/locks.h>

#include <mach/thread_act.h>
#include <mach/sdt.h>

#include <dev/random/randomdev.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_var.h>
#include <netinet/mptcp_var.h>
#include <netinet/mptcp.h>
#include <netinet/mptcp_seq.h>
#include <netinet/mptcp_opt.h>
#include <netinet/mptcp_timer.h>

int mptcp_enable = 1;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, enable, CTLFLAG_RW | CTLFLAG_LOCKED,
	&mptcp_enable, 0, "Enable Multipath TCP Support");

/* Number of times to try negotiating MPTCP on SYN retransmissions */
int mptcp_mpcap_retries = MPTCP_CAPABLE_RETRIES;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, mptcp_cap_retr,
	CTLFLAG_RW | CTLFLAG_LOCKED,
	&mptcp_mpcap_retries, 0, "Number of MP Capable SYN Retries");

/*
 * By default, DSS checksum is turned off, revisit if we ever do
 * MPTCP for non SSL Traffic.
 */
int mptcp_dss_csum = 0;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, dss_csum, CTLFLAG_RW | CTLFLAG_LOCKED,
	&mptcp_dss_csum, 0, "Enable DSS checksum");

/*
 * When mptcp_fail_thresh number of retransmissions are sent, subflow failover
 * is attempted on a different path.
 */
int mptcp_fail_thresh = 1;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, fail, CTLFLAG_RW | CTLFLAG_LOCKED,
	&mptcp_fail_thresh, 0, "Failover threshold");


/*
 * MPTCP subflows have TCP keepalives set to ON. Set a conservative keeptime
 * as carrier networks mostly have a 30 minute to 60 minute NAT Timeout.
 * Some carrier networks have a timeout of 10 or 15 minutes.
 */
int mptcp_subflow_keeptime = 60*14;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, keepalive, CTLFLAG_RW | CTLFLAG_LOCKED,
	&mptcp_subflow_keeptime, 0, "Keepalive in seconds");

/*
 * MP_PRIO option.
 */
int mptcp_mpprio_enable = 1;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, mpprio, CTLFLAG_RW | CTLFLAG_LOCKED,
	&mptcp_mpprio_enable, 0, "Enable MP_PRIO option");

/*
 * REMOVE_ADDR option.
 */
int mptcp_remaddr_enable = 1;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, remaddr, CTLFLAG_RW | CTLFLAG_LOCKED,
	&mptcp_remaddr_enable, 0, "Enable REMOVE_ADDR option");

/*
 * FastJoin Option
 */
int mptcp_fastjoin = 1;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, fastjoin, CTLFLAG_RW | CTLFLAG_LOCKED,
	&mptcp_fastjoin, 0, "Enable FastJoin Option");

int mptcp_zerortt_fastjoin = 0;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, zerortt_fastjoin, CTLFLAG_RW |
	CTLFLAG_LOCKED, &mptcp_zerortt_fastjoin, 0,
	"Enable Zero RTT Fast Join");

/*
 * R/W Notification on resume
 */
int mptcp_rwnotify = 0;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, rwnotify, CTLFLAG_RW | CTLFLAG_LOCKED,
	&mptcp_rwnotify, 0, "Enable RW notify on resume");

/*
 * Using RTT history for sending new data
 */
int mptcp_use_rtthist = 1;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, rtthist, CTLFLAG_RW | CTLFLAG_LOCKED,
	&mptcp_use_rtthist, 0, "Disable RTT History");

#define MPTCP_RTTHIST_MINTHRESH 500
int mptcp_rtthist_rtthresh = 600;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, rtthist_thresh, CTLFLAG_RW | CTLFLAG_LOCKED,
	&mptcp_rtthist_rtthresh, 0, "Rtt threshold");

/*
 * Use RTO history for sending new data
 */
int mptcp_use_rto = 1;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, userto, CTLFLAG_RW | CTLFLAG_LOCKED,
	&mptcp_use_rto, 0, "Disable RTO for subflow selection");

#define MPTCP_RTO_MINTHRESH 1000
int mptcp_rtothresh = 1500;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, rto_thresh, CTLFLAG_RW | CTLFLAG_LOCKED,
	&mptcp_rtothresh, 0, "RTO threshold");

/*
 * Use server's chosen path for sending new data
 */
int mptcp_peerswitch = 1;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, use_peer, CTLFLAG_RW | CTLFLAG_LOCKED,
	&mptcp_peerswitch, 0, "Use peer");

#define MPTCP_PEERSWITCH_CNTMIN 3
uint32_t mptcp_peerswitch_cnt = 3;
SYSCTL_UINT(_net_inet_mptcp, OID_AUTO, peerswitchno, CTLFLAG_RW | CTLFLAG_LOCKED,
	&mptcp_peerswitch_cnt, 0, "Set threshold based on peer's data arrival");

/*
 * Probe the preferred path, when it is not in use
 */
#define MPTCP_PROBETO_MIN 500
uint32_t mptcp_probeto = 1000;
SYSCTL_UINT(_net_inet_mptcp, OID_AUTO, probeto, CTLFLAG_RW | CTLFLAG_LOCKED,
	&mptcp_probeto, 0, "Disable probing by setting to 0");

#define MPTCP_PROBE_MX 15
uint32_t mptcp_probecnt = 5;
SYSCTL_UINT(_net_inet_mptcp, OID_AUTO, probecnt, CTLFLAG_RW | CTLFLAG_LOCKED,
	&mptcp_probecnt, 0, "Number of probe writes");

/*
 * Static declarations
 */
static int mptcp_validate_csum(struct tcpcb *, struct mbuf *, int);
static uint16_t mptcp_input_csum(struct tcpcb *, struct mbuf *, int);

/*
 * MPTCP input, called when data has been read from a subflow socket.
 */
void
mptcp_input(struct mptses *mpte, struct mbuf *m)
{
	struct socket *mp_so;
	struct mptcb *mp_tp = NULL;
	u_int64_t mb_dsn;
	u_int32_t mb_datalen;
	int count = 0;
	struct mbuf *save = NULL, *prev = NULL;
	struct mbuf *freelist = NULL, *tail = NULL;
	boolean_t in_fallback = FALSE;

	VERIFY(m->m_flags & M_PKTHDR);

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	mp_so = mpte->mpte_mppcb->mpp_socket;

	DTRACE_MPTCP(input);

	/*
	 * Each mbuf contains MPTCP Data Sequence Map
	 * Process the data for reassembly, delivery to MPTCP socket
	 * client, etc.
	 *
	 */
	count = mp_so->so_rcv.sb_cc;

	VERIFY(m != NULL);
	mp_tp = mpte->mpte_mptcb;
	VERIFY(mp_tp != NULL);

	/* Ok to check for this flag without lock as its set in this thread */
	in_fallback = (mp_tp->mpt_flags & MPTCPF_FALLBACK_TO_TCP);

	/*
	 * In the degraded fallback case, data is accepted without DSS map
	 */
	if (in_fallback) {
fallback: 
		/* 
		 * assume degraded flow as this may be the first packet 
		 * without DSS, and the subflow state is not updated yet. 
		 */
		if (sbappendstream(&mp_so->so_rcv, m))
			sorwakeup(mp_so);
		DTRACE_MPTCP5(receive__degraded, struct mbuf *, m,
		    struct socket *, mp_so,
		    struct sockbuf *, &mp_so->so_rcv,
		    struct sockbuf *, &mp_so->so_snd,
		    struct mptses *, mpte);
		count = mp_so->so_rcv.sb_cc - count;
		mptcplog((LOG_DEBUG, "MPTCP Receiver: Fallback read %d bytes\n",
		    count), MPTCP_RECEIVER_DBG, MPTCP_LOGLVL_VERBOSE);
		return;
	}

	MPT_LOCK(mp_tp);
	do {
		/* If fallback occurs, mbufs will not have PKTF_MPTCP set */
		if (!(m->m_pkthdr.pkt_flags & PKTF_MPTCP)) {
			MPT_UNLOCK(mp_tp);
			goto fallback;
		}

		save = m->m_next;
		/*
		 * A single TCP packet formed of multiple mbufs
		 * holds DSS mapping in the first mbuf of the chain.
		 * Other mbufs in the chain may have M_PKTHDR set
		 * even though they belong to the same TCP packet
		 * and therefore use the DSS mapping stored in the
		 * first mbuf of the mbuf chain. mptcp_input() can
		 * get an mbuf chain with multiple TCP packets.
		 */
		while (save && (!(save->m_flags & M_PKTHDR) ||
		    !(save->m_pkthdr.pkt_flags & PKTF_MPTCP))) {
			prev = save;
			save = save->m_next;
		}
		if (prev)
			prev->m_next = NULL;
		else
			m->m_next = NULL;

		mb_dsn = m->m_pkthdr.mp_dsn;
		mb_datalen = m->m_pkthdr.mp_rlen;

		if (MPTCP_SEQ_GT(mb_dsn, mp_tp->mpt_rcvatmark)) {
			tcpstat.tcps_mp_oodata++;
			MPT_UNLOCK(mp_tp);
			m_freem(m);
			return;
			/*
			 * Reassembly queue support here in future. Per spec,
			 * senders must implement retransmission timer to
			 * retransmit unacked data. Dropping out of order
			 * gives a slight hit on performance but allows us to
			 * deploy MPTCP and protects us against in-window DoS
			 * attacks that attempt to use up memory by sending
			 * out of order data. When doing load sharing across
			 * subflows, out of order support is a must.
			 */
		}

		if (MPTCP_SEQ_LT(mb_dsn, mp_tp->mpt_rcvatmark)) {
			if (MPTCP_SEQ_LEQ((mb_dsn + mb_datalen),
			    mp_tp->mpt_rcvatmark)) {
				if (freelist == NULL)
					freelist = m;
				else
					tail->m_next = m;

				if (prev != NULL)
					tail = prev;
				else
					tail = m;

				m = save;
				prev = save = NULL;
				continue;
			} else {
				m_adj(m, (mp_tp->mpt_rcvatmark - mb_dsn));
			}
			mptcplog((LOG_INFO, "MPTCP Receiver: Left Edge %llu\n",
			    mp_tp->mpt_rcvatmark),
			    MPTCP_RECEIVER_DBG, MPTCP_LOGLVL_VERBOSE);
		}

		MPT_UNLOCK(mp_tp);
		if (sbappendstream(&mp_so->so_rcv, m)) {
			sorwakeup(mp_so);
		}
		DTRACE_MPTCP6(receive, struct mbuf *, m, struct socket *, mp_so,
		    struct sockbuf *, &mp_so->so_rcv,
		    struct sockbuf *, &mp_so->so_snd,
		    struct mptses *, mpte,
		    struct mptcb *, mp_tp);
		MPT_LOCK(mp_tp);
		count = mp_so->so_rcv.sb_cc - count;
		tcpstat.tcps_mp_rcvtotal++;
		tcpstat.tcps_mp_rcvbytes += count;
		mptcplog((LOG_DEBUG, "MPTCP Receiver: Read %d bytes\n", count),
		    MPTCP_RECEIVER_DBG, MPTCP_LOGLVL_VERBOSE);

		/*
		 * The data received at the MPTCP layer will never exceed the
		 * receive window because anything to the right of the
		 * receive window will be trimmed at the subflow level.
		 */
		mp_tp->mpt_rcvwnd = mptcp_sbspace(mp_tp);
		mp_tp->mpt_rcvatmark += count;
		m = save;
		prev = save = NULL;
		count = mp_so->so_rcv.sb_cc;
	} while (m);
	MPT_UNLOCK(mp_tp);

	if (freelist)
		m_freem(freelist);
}

/*
 * MPTCP output.
 */
int
mptcp_output(struct mptses *mpte)
{
	struct mptsub *mpts;
	struct mptsub *mpts_tried = NULL;
	struct socket *mp_so;
	struct mptsub *preferred_mpts = NULL;
	int error = 0;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	mp_so = mpte->mpte_mppcb->mpp_socket;
	if (mp_so->so_state & SS_CANTSENDMORE) {
		mptcplog((LOG_DEBUG, "MPTCP Sender: cantsendmore\n"),
		    MPTCP_SENDER_DBG, MPTCP_LOGLVL_VERBOSE);
		return (EPIPE);
	}

try_again:
	/* get the "best" subflow to be used for transmission */
	mpts = mptcp_get_subflow(mpte, NULL, &preferred_mpts);
	if (mpts == NULL) {
		mptcplog((LOG_ERR, "MPTCP Sender: mp_so 0x%llx no subflow\n",
		    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so)),
		    MPTCP_SENDER_DBG, MPTCP_LOGLVL_LOG);
		goto out;
	}

	mptcplog((LOG_DEBUG, "MPTCP Sender: mp_so 0x%llx using cid %d \n",
	    (uint64_t)VM_KERNEL_ADDRPERM(mp_so), mpts->mpts_connid),
	    MPTCP_SENDER_DBG, MPTCP_LOGLVL_VERBOSE);

	/* In case there's just one flow, we reattempt later */
	MPTS_LOCK(mpts);
	if ((mpts_tried != NULL) && ((mpts == mpts_tried) ||
	    (mpts->mpts_flags & MPTSF_FAILINGOVER))) {
		MPTS_UNLOCK(mpts);
		MPTS_LOCK(mpts_tried);
		mpts_tried->mpts_flags &= ~MPTSF_FAILINGOVER;
		mpts_tried->mpts_flags |= MPTSF_ACTIVE;
		MPTS_UNLOCK(mpts_tried);
		mptcp_start_timer(mpte, MPTT_REXMT);
		mptcplog((LOG_DEBUG, "MPTCP Sender: mp_so 0x%llx retry later\n",
		    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so)),
		    MPTCP_SENDER_DBG, MPTCP_LOGLVL_VERBOSE);
		goto out;
	}

	DTRACE_MPTCP3(output, struct mptses *, mpte, struct mptsub *, mpts,
	    struct socket *, mp_so);
	error = mptcp_subflow_output(mpte, mpts);
	if (error && error != EWOULDBLOCK) {
		/* can be a temporary loss of source address or other error */
		mpts->mpts_flags |= MPTSF_FAILINGOVER;
		mpts->mpts_flags &= ~MPTSF_ACTIVE;
		mpts_tried = mpts;
		MPTS_UNLOCK(mpts);
		mptcplog((LOG_INFO, "MPTCP Sender: %s Error = %d \n",
		    __func__, error),
		    MPTCP_SENDER_DBG, MPTCP_LOGLVL_LOG);
		goto try_again;
	}
	/* The model is to have only one active flow at a time */
	mpts->mpts_flags |= MPTSF_ACTIVE;
	mpts->mpts_probesoon = mpts->mpts_probecnt = 0;
	MPTS_UNLOCK(mpts);

	/* Allows us to update the smoothed rtt */
	if ((mptcp_probeto) && (mptcp_probeto >= MPTCP_PROBETO_MIN) &&
	    (mpts != preferred_mpts) && (preferred_mpts != NULL)) {
		MPTS_LOCK(preferred_mpts);
		if (preferred_mpts->mpts_probesoon) {
			if ((tcp_now - preferred_mpts->mpts_probesoon) >
			    mptcp_probeto) {
				(void) mptcp_subflow_output(mpte, preferred_mpts);
				if (preferred_mpts->mpts_probecnt >=
				    MIN(mptcp_probecnt, MPTCP_PROBE_MX)) {
					preferred_mpts->mpts_probesoon = 0;
					preferred_mpts->mpts_probecnt = 0;
				}
			}
		} else {
			preferred_mpts->mpts_probesoon = tcp_now;
			preferred_mpts->mpts_probecnt = 0;
		}
		MPTS_UNLOCK(preferred_mpts);
	}

	if (mpte->mpte_active_sub == NULL) {
		mpte->mpte_active_sub = mpts;
	} else if (mpte->mpte_active_sub != mpts) {
		mptcplog((LOG_DEBUG, "MPTCP Sender: switch [cid %d, srtt %d]"
		    "to [cid %d, srtt %d]\n",
		    mpte->mpte_active_sub->mpts_connid,
		    mpte->mpte_active_sub->mpts_srtt >> 5,
		    mpts->mpts_connid,
		    mpts->mpts_srtt >> 5),
		    MPTCP_SENDER_DBG | MPTCP_SOCKET_DBG, MPTCP_LOGLVL_LOG);

		MPTS_LOCK(mpte->mpte_active_sub);
		mpte->mpte_active_sub->mpts_flags &= ~MPTSF_ACTIVE;
		mpts->mpts_peerswitch = 0;
		MPTS_UNLOCK(mpte->mpte_active_sub);
		mpte->mpte_active_sub = mpts;
		tcpstat.tcps_mp_switches++;
	}
out:
	/* subflow errors should not be percolated back up */
	return (0);
}

/*
 * Return the most eligible subflow to be used for sending data.
 * This function also serves to check if any alternate subflow is available
 * or not. best and second_best flows are chosen by their priority. third_best
 * could be best or second_best but is under loss at the time of evaluation.
 */
struct mptsub *
mptcp_get_subflow(struct mptses *mpte, struct mptsub *ignore, struct mptsub **preferred)
{
	struct mptsub *mpts;
	struct mptsub *best = NULL;
	struct mptsub *second_best = NULL;
	struct mptsub *third_best = NULL;
	struct mptsub *symptoms_best = NULL;
	struct socket *so = NULL;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */

	TAILQ_FOREACH(mpts, &mpte->mpte_subflows, mpts_entry) {
		MPTS_LOCK(mpts);

		if ((ignore) && (mpts == ignore)) {
			MPTS_UNLOCK(mpts);
			continue;
		}

		/* There can only be one subflow in degraded state */
		if (mpts->mpts_flags & MPTSF_MP_DEGRADED) {
			MPTS_UNLOCK(mpts);
			best = mpts;
			break;
		}

		/*
		 * Subflows with TFO or Fastjoin allow data to be written before
		 * the subflow is mp capable.
		 */
		if (!(mpts->mpts_flags & MPTSF_MP_CAPABLE) &&
		    !(mpts->mpts_flags & MPTSF_FASTJ_REQD) &&
		    !(mpts->mpts_flags & MPTSF_TFO_REQD)) {
			MPTS_UNLOCK(mpts);
			continue;
		}

		if (mpts->mpts_flags & MPTSF_SUSPENDED) {
			MPTS_UNLOCK(mpts);
			continue;
		}

		if ((mpts->mpts_flags & MPTSF_DISCONNECTED) ||
		    (mpts->mpts_flags & MPTSF_DISCONNECTING)) {
			MPTS_UNLOCK(mpts);
			continue;
		}

		if (mpts->mpts_flags & MPTSF_FAILINGOVER) {
			so = mpts->mpts_socket;
			if ((so) && (!(so->so_flags & SOF_PCBCLEARING))) {
				socket_lock(so, 1);
				if ((so->so_snd.sb_cc == 0) &&
				    (mptcp_no_rto_spike(so))) {
					mpts->mpts_flags &= ~MPTSF_FAILINGOVER;
					so->so_flags &= ~SOF_MP_TRYFAILOVER;
					socket_unlock(so, 1);
				} else {
					third_best = mpts;
					mptcplog((LOG_DEBUG, "MPTCP Sender: "
					    "%s cid %d in failover\n",
					    __func__, third_best->mpts_connid),
					    MPTCP_SENDER_DBG,
					    MPTCP_LOGLVL_VERBOSE);
					socket_unlock(so, 1);
					MPTS_UNLOCK(mpts);
					continue;
				}
			} else {
				MPTS_UNLOCK(mpts);
				continue;
			}
		}

		/* When there are no preferred flows, use first one in list */
		if ((!second_best) && !(mpts->mpts_flags & MPTSF_PREFERRED))
			second_best = mpts;

		if (mpts->mpts_flags & MPTSF_PREFERRED) {
			best = mpts;
		}

		MPTS_UNLOCK(mpts);
	}

	/*
	 * If there is no preferred or backup subflow, and there is no active
	 * subflow use the last usable subflow.
	 */
	if (best == NULL) {
		return (second_best ? second_best : third_best);
	}

	if (second_best == NULL) {
		return (best ? best : third_best);
	}

	if (preferred != NULL)
		*preferred = best;

	/* Use a hint from symptomsd if it exists */
	symptoms_best = mptcp_use_symptoms_hints(best, second_best);
	if (symptoms_best != NULL)
		return (symptoms_best);

	/* Compare RTTs, select second_best if best's rtt exceeds rttthresh */
	if ((mptcp_use_rtthist) &&
	    (best->mpts_srtt) && (second_best->mpts_srtt) &&
	    (best->mpts_srtt > second_best->mpts_srtt) &&
	    (best->mpts_srtt >= MAX((MPTCP_RTTHIST_MINTHRESH << 5),
	    (mptcp_rtthist_rtthresh << 5)))) {
		tcpstat.tcps_mp_sel_rtt++;
		mptcplog((LOG_DEBUG, "MPTCP Sender: %s best cid %d"
		    " at rtt %d,  second cid %d at rtt %d\n", __func__,
		    best->mpts_connid, best->mpts_srtt >> 5,
		    second_best->mpts_connid,
		    second_best->mpts_srtt >> 5),
		    MPTCP_SENDER_DBG, MPTCP_LOGLVL_LOG);
		return (second_best);
	}

	/* Compare RTOs, select second_best if best's rto exceeds rtothresh */
	if ((mptcp_use_rto) &&
	    (best->mpts_rxtcur) && (second_best->mpts_rxtcur) &&
	    (best->mpts_rxtcur > second_best->mpts_rxtcur) &&
	    (best->mpts_rxtcur >=
	    MAX(MPTCP_RTO_MINTHRESH, mptcp_rtothresh))) {
		tcpstat.tcps_mp_sel_rto++;
		mptcplog((LOG_DEBUG, "MPTCP Sender: %s best cid %d"
		    " at rto %d, second cid %d at rto %d\n", __func__,
		    best->mpts_connid, best->mpts_rxtcur,
		    second_best->mpts_connid, second_best->mpts_rxtcur),
		    MPTCP_SENDER_DBG, MPTCP_LOGLVL_LOG);

		return (second_best);
	}

	/* If second_best received data, use second_best */
	if (mptcp_peerswitch &&
	    (second_best->mpts_peerswitch >
	    MAX(MPTCP_PEERSWITCH_CNTMIN, mptcp_peerswitch_cnt))) {
		tcpstat.tcps_mp_sel_peer++;
		mptcplog((LOG_DEBUG, "MPTCP Sender: %s: best cid %d"
		    " but using cid %d after receiving %d segments\n",
		    __func__, best->mpts_connid, second_best->mpts_connid,
		    second_best->mpts_peerswitch), MPTCP_SENDER_DBG,
		    MPTCP_LOGLVL_LOG);
		return (second_best);
	}
	return (best);
}

struct mptsub *
mptcp_get_pending_subflow(struct mptses *mpte, struct mptsub *ignore)
{
	struct mptsub *mpts = NULL;
	
	MPTE_LOCK_ASSERT_HELD(mpte);    /* same as MP socket lock */

	TAILQ_FOREACH(mpts, &mpte->mpte_subflows, mpts_entry) {
		MPTS_LOCK(mpts);

		if ((ignore) && (mpts == ignore)) {
			MPTS_UNLOCK(mpts);
			continue;
		}

		if (mpts->mpts_flags & MPTSF_CONNECT_PENDING) {
			MPTS_UNLOCK(mpts);
			break;
		}

		MPTS_UNLOCK(mpts);
	}
	return (mpts);
}

static const char *
mptcp_event_to_str(uint32_t event)
{
	const char *c = "UNDEFINED";
	switch (event) {
	case MPCE_CLOSE:
		c = "MPCE_CLOSE";
		break;
	case MPCE_RECV_DATA_ACK:
		c = "MPCE_RECV_DATA_ACK";
		break;
	case MPCE_RECV_DATA_FIN:
		c = "MPCE_RECV_DATA_FIN";
		break;
	}
	return (c);
}

static const char *
mptcp_state_to_str(mptcp_state_t state)
{
        const char *c = "UNDEFINED";
	switch (state) {
	case MPTCPS_CLOSED:
		c = "MPTCPS_CLOSED";
		break;
	case MPTCPS_LISTEN:
		c = "MPTCPS_LISTEN";
		break;
	case MPTCPS_ESTABLISHED:
		c = "MPTCPS_ESTABLISHED";
		break;
	case MPTCPS_CLOSE_WAIT:
		c = "MPTCPS_CLOSE_WAIT";
		break;
	case MPTCPS_FIN_WAIT_1:
		c = "MPTCPS_FIN_WAIT_1";
		break;
	case MPTCPS_CLOSING:
		c = "MPTCPS_CLOSING";
		break;
	case MPTCPS_LAST_ACK:
		c = "MPTCPS_LAST_ACK";
		break;
	case MPTCPS_FIN_WAIT_2:
		c = "MPTCPS_FIN_WAIT_2";
		break;
	case MPTCPS_TIME_WAIT:
		c = "MPTCPS_TIME_WAIT";
		break;
	case MPTCPS_FASTCLOSE_WAIT:
		c = "MPTCPS_FASTCLOSE_WAIT";
		break;
	case MPTCPS_TERMINATE:
		c = "MPTCPS_TERMINATE";
		break;
	}
	return (c);
}

void
mptcp_close_fsm(struct mptcb *mp_tp, uint32_t event)
{
	MPT_LOCK_ASSERT_HELD(mp_tp);
	mptcp_state_t old_state = mp_tp->mpt_state;

	DTRACE_MPTCP2(state__change, struct mptcb *, mp_tp, 
	    uint32_t, event);

	switch (mp_tp->mpt_state) {
	case MPTCPS_CLOSED:
	case MPTCPS_LISTEN:
		mp_tp->mpt_state = MPTCPS_CLOSED;
		break;

	case MPTCPS_ESTABLISHED:
		if (event == MPCE_CLOSE) {
			mp_tp->mpt_state = MPTCPS_FIN_WAIT_1;
			mp_tp->mpt_sndmax += 1; /* adjust for Data FIN */
		}	
		else if (event == MPCE_RECV_DATA_FIN) {
			mp_tp->mpt_rcvnxt += 1; /* adj remote data FIN */
			mp_tp->mpt_state = MPTCPS_CLOSE_WAIT;
		}	
		break;

	case MPTCPS_CLOSE_WAIT:
		if (event == MPCE_CLOSE) {
			mp_tp->mpt_state = MPTCPS_LAST_ACK;
			mp_tp->mpt_sndmax += 1; /* adjust for Data FIN */
		}	
		break;

	case MPTCPS_FIN_WAIT_1:
		if (event == MPCE_RECV_DATA_ACK)
			mp_tp->mpt_state = MPTCPS_FIN_WAIT_2;
		else if (event == MPCE_RECV_DATA_FIN) {
			mp_tp->mpt_rcvnxt += 1; /* adj remote data FIN */
			mp_tp->mpt_state = MPTCPS_CLOSING;
		}	
		break;

	case MPTCPS_CLOSING:
		if (event == MPCE_RECV_DATA_ACK)
			mp_tp->mpt_state = MPTCPS_TIME_WAIT;
		break;

	case MPTCPS_LAST_ACK:
		if (event == MPCE_RECV_DATA_ACK)
			mp_tp->mpt_state = MPTCPS_TERMINATE;
		break;

	case MPTCPS_FIN_WAIT_2:
		if (event == MPCE_RECV_DATA_FIN) {
			mp_tp->mpt_rcvnxt += 1; /* adj remote data FIN */
			mp_tp->mpt_state = MPTCPS_TIME_WAIT;
		}	
		break;

	case MPTCPS_TIME_WAIT:
		break;

	case MPTCPS_FASTCLOSE_WAIT:
		if (event == MPCE_CLOSE) {
			/* no need to adjust for data FIN */
			mp_tp->mpt_state = MPTCPS_TERMINATE;
		}
		break;
	case MPTCPS_TERMINATE:
		break;
	default:
		VERIFY(0);
		/* NOTREACHED */
	}
	DTRACE_MPTCP2(state__change, struct mptcb *, mp_tp, 
	    uint32_t, event);
	mptcplog((LOG_INFO, "MPTCP State: %s to %s on event %s\n",
	    mptcp_state_to_str(old_state),
	    mptcp_state_to_str(mp_tp->mpt_state),
	    mptcp_event_to_str(event)),
	    MPTCP_STATE_DBG, MPTCP_LOGLVL_LOG);
}

/*
 * Update the mptcb send state variables, but the actual sbdrop occurs
 * in MPTCP layer
 */
void
mptcp_data_ack_rcvd(struct mptcb *mp_tp, struct tcpcb *tp, u_int64_t full_dack)
{
	u_int64_t acked = 0;

	acked = full_dack - mp_tp->mpt_snduna;

	if (acked) {
		mp_tp->mpt_snduna += acked;
		/* In degraded mode, we may get some Data ACKs */
		if ((tp->t_mpflags & TMPF_TCP_FALLBACK) &&
			!(mp_tp->mpt_flags & MPTCPF_POST_FALLBACK_SYNC) &&
			MPTCP_SEQ_GT(mp_tp->mpt_sndnxt, mp_tp->mpt_snduna)) {
			/* bring back sndnxt to retransmit MPTCP data */
			mp_tp->mpt_sndnxt = mp_tp->mpt_dsn_at_csum_fail;
			mp_tp->mpt_flags |= MPTCPF_POST_FALLBACK_SYNC;
			tp->t_inpcb->inp_socket->so_flags1 |= 
			    SOF1_POST_FALLBACK_SYNC;
		}
	}
	if ((full_dack == mp_tp->mpt_sndmax) &&
	    (mp_tp->mpt_state >= MPTCPS_FIN_WAIT_1)) {
		mptcp_close_fsm(mp_tp, MPCE_RECV_DATA_ACK);
		tp->t_mpflags &= ~TMPF_SEND_DFIN;
	}
}

/* If you change this function, match up mptcp_update_rcv_state_f */
void
mptcp_update_dss_rcv_state(struct mptcp_dsn_opt *dss_info, struct tcpcb *tp,
    uint16_t csum)
{
	struct mptcb *mp_tp = tptomptp(tp);
	u_int64_t full_dsn = 0;

	NTOHL(dss_info->mdss_dsn);
	NTOHL(dss_info->mdss_subflow_seqn);
	NTOHS(dss_info->mdss_data_len);

	/* XXX for autosndbuf grow sb here */
	MPT_LOCK(mp_tp);
	MPTCP_EXTEND_DSN(mp_tp->mpt_rcvnxt, dss_info->mdss_dsn, full_dsn);
	MPT_UNLOCK(mp_tp);
	mptcp_update_rcv_state_meat(mp_tp, tp,
	    full_dsn, dss_info->mdss_subflow_seqn, dss_info->mdss_data_len,
	    csum);

}

void
mptcp_update_rcv_state_meat(struct mptcb *mp_tp, struct tcpcb *tp,
    u_int64_t full_dsn, u_int32_t seqn, u_int16_t mdss_data_len,
    uint16_t csum)
{
	if (mdss_data_len == 0) {
		mptcplog((LOG_INFO, "MPTCP Receiver: Infinite Mapping.\n"),
		    MPTCP_RECEIVER_DBG, MPTCP_LOGLVL_LOG);

		if ((mp_tp->mpt_flags & MPTCPF_CHECKSUM) && (csum != 0)) {
			mptcplog((LOG_ERR, "MPTCP Receiver: Bad checksum %x \n",
			    csum), MPTCP_RECEIVER_DBG, MPTCP_LOGLVL_ERR);
		}
		mptcp_notify_mpfail(tp->t_inpcb->inp_socket);
		return;
	}
	MPT_LOCK(mp_tp);
		mptcplog((LOG_DEBUG,
		    "MPTCP Receiver: seqn = %x len = %x full = %llx "
		    "rcvnxt = %llu \n",
		    seqn, mdss_data_len, full_dsn, mp_tp->mpt_rcvnxt),
		    MPTCP_RECEIVER_DBG, MPTCP_LOGLVL_VERBOSE);

	/* Process a Data FIN packet , handled in mptcp_do_fin_opt */
	if ((seqn == 0) && (mdss_data_len == 1)) {
		mptcplog((LOG_INFO, "MPTCP Receiver: Data FIN in %s state \n",
		    mptcp_state_to_str(mp_tp->mpt_state)),
		    MPTCP_RECEIVER_DBG, MPTCP_LOGLVL_LOG);
		MPT_UNLOCK(mp_tp);
		return;
	}
	MPT_UNLOCK(mp_tp);
	mptcp_notify_mpready(tp->t_inpcb->inp_socket);
	tp->t_rcv_map.mpt_dsn = full_dsn;
	tp->t_rcv_map.mpt_sseq = seqn;
	tp->t_rcv_map.mpt_len = mdss_data_len;
	tp->t_rcv_map.mpt_csum = csum;
	tp->t_mpflags |= TMPF_EMBED_DSN;
}


void
mptcp_update_rcv_state_f(struct mptcp_dss_ack_opt *dss_info, struct tcpcb *tp,
    uint16_t csum)
{
	u_int64_t full_dsn = 0;
	struct mptcb *mp_tp = tptomptp(tp);

	/*
	 * May happen, because the caller of this function does an soevent.
	 * Review after rdar://problem/24083886
	 */
	if (!mp_tp)
		return;

	NTOHL(dss_info->mdss_dsn);
	NTOHL(dss_info->mdss_subflow_seqn);
	NTOHS(dss_info->mdss_data_len);
	MPT_LOCK(mp_tp);
	MPTCP_EXTEND_DSN(mp_tp->mpt_rcvnxt, dss_info->mdss_dsn, full_dsn);
	MPT_UNLOCK(mp_tp);
	mptcp_update_rcv_state_meat(mp_tp, tp,
	    full_dsn,
	    dss_info->mdss_subflow_seqn,
	    dss_info->mdss_data_len,
	    csum);
}

void
mptcp_update_rcv_state_g(struct mptcp_dss64_ack32_opt *dss_info,
    struct tcpcb *tp, uint16_t csum)
{
	u_int64_t dsn = mptcp_ntoh64(dss_info->mdss_dsn);
	struct mptcb *mp_tp = tptomptp(tp);

	/*
	 * May happen, because the caller of this function does an soevent.
	 * Review after rdar://problem/24083886
	 */
	if (!mp_tp)
		return;

	NTOHL(dss_info->mdss_subflow_seqn);
	NTOHS(dss_info->mdss_data_len);
	mptcp_update_rcv_state_meat(mp_tp, tp,
	    dsn,
	    dss_info->mdss_subflow_seqn,
	    dss_info->mdss_data_len,
	    csum);
}

static int
mptcp_validate_dss_map(struct socket *so, struct tcpcb *tp, struct mbuf *m,
    int hdrlen)
{
	u_int32_t sseq, datalen;

	if (!(m->m_pkthdr.pkt_flags & PKTF_MPTCP))
		return 0;

	sseq = m->m_pkthdr.mp_rseq + tp->irs;
	datalen = m->m_pkthdr.mp_rlen;

#if 0
	/* enable this to test TCP fallback post connection establishment */
	if (SEQ_GT(sseq, (tp->irs+1)))
		datalen = m->m_pkthdr.len - hdrlen - 1;
#endif

	/* unacceptable DSS option, fallback to TCP */
	if (m->m_pkthdr.len > ((int) datalen + hdrlen)) {
		mptcplog((LOG_ERR, "MPTCP Receiver: "
		    "%s: mbuf len %d, MPTCP expected %d",
		    __func__, m->m_pkthdr.len, datalen),
		    MPTCP_RECEIVER_DBG, MPTCP_LOGLVL_LOG);
	} else {
		return 0;
	}
	tp->t_mpflags |= TMPF_SND_MPFAIL;
	mptcp_notify_mpfail(so);
	m_freem(m);
	return -1;
}

int
mptcp_input_preproc(struct tcpcb *tp, struct mbuf *m, int drop_hdrlen)
{
	if (mptcp_validate_csum(tp, m, drop_hdrlen) != 0)
		return -1;

	mptcp_insert_rmap(tp, m);
	if (mptcp_validate_dss_map(tp->t_inpcb->inp_socket, tp, m,
	    drop_hdrlen) != 0)
		return -1;
	return 0;
}

/*
 * MPTCP Checksum support
 * The checksum is calculated whenever the MPTCP DSS option is included
 * in the TCP packet. The checksum includes the sum of the MPTCP psuedo
 * header and the actual data indicated by the length specified in the
 * DSS option.
 */

static int
mptcp_validate_csum(struct tcpcb *tp, struct mbuf *m, int drop_hdrlen)
{
	uint16_t mptcp_csum = 0;
	mptcp_csum = mptcp_input_csum(tp, m, drop_hdrlen);
	if (mptcp_csum) {
		tp->t_mpflags |= TMPF_SND_MPFAIL;
		tp->t_mpflags &= ~TMPF_EMBED_DSN;
		mptcp_notify_mpfail(tp->t_inpcb->inp_socket);
		m_freem(m);
		tcpstat.tcps_mp_badcsum++;
		return -1;
	}
	return 0;
}

static uint16_t
mptcp_input_csum(struct tcpcb *tp, struct mbuf *m, int off)
{
	struct mptcb *mp_tp = tptomptp(tp);
	uint32_t sum = 0;
	uint64_t dsn;
	uint32_t sseq;
	uint16_t len;
	uint16_t csum;

	if (mp_tp == NULL)
		return (0);

	if (!(mp_tp->mpt_flags & MPTCPF_CHECKSUM))
		return (0);

	if (!(tp->t_mpflags & TMPF_EMBED_DSN))
		return (0);

	if (tp->t_mpflags & TMPF_TCP_FALLBACK)
		return (0);

	/* 
	 * The remote side may send a packet with fewer bytes than the
	 * claimed DSS checksum length.
	 */
	if ((int)m_length2(m, NULL) < (off + tp->t_rcv_map.mpt_len))
		return (0xffff);

	if (tp->t_rcv_map.mpt_len != 0)
		sum = m_sum16(m, off, tp->t_rcv_map.mpt_len);

	dsn = mptcp_hton64(tp->t_rcv_map.mpt_dsn);
	sseq = htonl(tp->t_rcv_map.mpt_sseq);
	len = htons(tp->t_rcv_map.mpt_len);
	csum = tp->t_rcv_map.mpt_csum;
	sum += in_pseudo64(dsn, sseq, (len + csum));
	ADDCARRY(sum);
	DTRACE_MPTCP3(checksum__result, struct tcpcb *, tp, struct mbuf *, m,
	    uint32_t, sum);
	mptcplog((LOG_DEBUG, "MPTCP Receiver: sum = %x \n", sum),
	    MPTCP_RECEIVER_DBG, MPTCP_LOGLVL_VERBOSE);
	return (~sum & 0xffff);
}

void
mptcp_output_csum(struct tcpcb *tp, struct mbuf *m, int32_t len,
    unsigned hdrlen, u_int64_t dss_val, u_int32_t *sseqp)
{
	struct mptcb *mp_tp = tptomptp(tp);
	u_int32_t sum = 0;
	uint32_t sseq;
	uint16_t dss_len;
	uint16_t csum = 0;
	uint16_t *csump = NULL;

	if (mp_tp == NULL)
		return;

	if (!(mp_tp->mpt_flags & MPTCPF_CHECKSUM))
		return;

	if (sseqp == NULL)
		return;

	if (len)
		sum = m_sum16(m, hdrlen, len);

	dss_val = mptcp_hton64(dss_val);
	sseq = *sseqp;
	dss_len = *(uint16_t *)(void *)((u_char*)sseqp + sizeof (u_int32_t));
	sum += in_pseudo64(dss_val, sseq, (dss_len + csum));

	ADDCARRY(sum);
	sum = ~sum & 0xffff;
	csump = (uint16_t *)(void *)((u_char*)sseqp + sizeof (u_int32_t) +
	    sizeof (uint16_t));
	DTRACE_MPTCP3(checksum__result, struct tcpcb *, tp, struct mbuf *, m,
	    uint32_t, sum);
	*csump = sum;
	mptcplog((LOG_DEBUG, "MPTCP Sender: sum = %x \n", sum),
	    MPTCP_SENDER_DBG, MPTCP_LOGLVL_VERBOSE);
}

/*
 * When WiFi signal starts fading, there's more loss and RTT spikes.
 * Check if there has been a large spike by comparing against
 * a tolerable RTT spike threshold.
 */
boolean_t
mptcp_no_rto_spike(struct socket *so)
{
	struct tcpcb *tp = intotcpcb(sotoinpcb(so));
	int32_t spike = 0;

	if (tp->t_rxtcur > MAX(mptcp_rtothresh, MPTCP_RTO_MINTHRESH)) {
		spike = tp->t_rxtcur - mptcp_rtothresh;

		mptcplog((LOG_DEBUG, "MPTCP Socket: %s: spike = %d rto = %d"
		    "best = %d cur = %d\n", __func__, spike,
		    tp->t_rxtcur, tp->t_rttbest >> TCP_RTT_SHIFT,
		    tp->t_rttcur),
		    (MPTCP_SOCKET_DBG|MPTCP_SENDER_DBG), MPTCP_LOGLVL_LOG);

	}

	if (spike > 0 ) {
		return (FALSE);
	} else {
		return (TRUE);
	}
}
