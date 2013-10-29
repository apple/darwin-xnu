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

int mptcp_dbg = 0;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, debug, CTLFLAG_RW | CTLFLAG_LOCKED,
	&mptcp_dbg, 0, "Enable Multipath TCP Debugging");

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
 * MPTCP subflows have TCP keepalives set to ON
 */
int mptcp_subflow_keeptime = 60;
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
	struct mbuf *save = NULL;
	struct mbuf *freelist = NULL, *tail = NULL;

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
	/*
	 * In the degraded fallback case, data is accepted without DSS map
	 */
	if (!(m->m_pkthdr.pkt_flags & PKTF_MPTCP)) {
		/* XXX need a check that this is indeed degraded */
		if (sbappendstream(&mp_so->so_rcv, m))
			sorwakeup(mp_so);
		DTRACE_MPTCP5(receive__degraded, struct mbuf *, m,
		    struct socket *, mp_so,
		    struct sockbuf *, &mp_so->so_rcv,
		    struct sockbuf *, &mp_so->so_snd,
		    struct mptses *, mpte);
		count = mp_so->so_rcv.sb_cc - count;
		mptcplog3((LOG_DEBUG, "%s: fread %d bytes\n", __func__, count));
		return;
	}

	mp_tp = mpte->mpte_mptcb;
	VERIFY(mp_tp != NULL);

	MPT_LOCK(mp_tp);
	do {
		save = m->m_next;
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
			VERIFY(m->m_pkthdr.pkt_flags & PKTF_MPTCP);
			VERIFY(m->m_flags & M_PKTHDR);
			VERIFY(m->m_len >= (int)mb_datalen);
			VERIFY(m->m_pkthdr.len >= (int)mb_datalen);
			if (MPTCP_SEQ_LEQ((mb_dsn + mb_datalen),
			    mp_tp->mpt_rcvatmark)) {
				if (freelist == NULL)
					freelist = tail = m;
				else {
					tail->m_next = m;
					tail = m;
				}
				m = save;
				continue;
			} else {
				m_adj(m, (mp_tp->mpt_rcvatmark - mb_dsn));
			}
			mptcplog((LOG_INFO, "%s: %llu %d 2 \n", __func__,
			    mp_tp->mpt_rcvatmark, m->m_pkthdr.len));
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
		mptcplog3((LOG_DEBUG, "%s: read %d bytes\n", __func__, count));
		/*
		 * The data received at the MPTCP layer will never exceed the
		 * receive window because anything to the right of the
		 * receive window will be trimmed at the subflow level.
		 */
		mp_tp->mpt_rcvwnd = mptcp_sbspace(mp_tp);
		mp_tp->mpt_rcvatmark += count;
		m = save;
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
	int error = 0;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	mp_so = mpte->mpte_mppcb->mpp_socket;
	if (mp_so->so_state & SS_CANTSENDMORE) {
		return (EPIPE);
	}

try_again:
	/* get the "best" subflow to be used for transmission */
	mpts = mptcp_get_subflow(mpte, NULL);
	if (mpts == NULL) {
		mptcplog((LOG_ERR, "%s: mp_so 0x%llx has no usable subflow\n",
		    __func__, (u_int64_t)VM_KERNEL_ADDRPERM(mp_so)));
		goto out;
	}

	mptcplog3((LOG_INFO, "%s: mp_so 0x%llx cid %d \n", __func__,
	    (uint64_t)VM_KERNEL_ADDRPERM(mp_so), mpts->mpts_connid));

	/* In case there's just one flow, we reattempt later */
	MPTS_LOCK(mpts);
	if ((mpts_tried != NULL) && ((mpts == mpts_tried) ||
	    (mpts->mpts_flags & MPTSF_FAILINGOVER))) {
		MPTS_UNLOCK(mpts);
		MPTS_LOCK(mpts_tried);
		mpts_tried->mpts_flags &= ~MPTSF_FAILINGOVER;
		mpts_tried->mpts_flags |= MPTSF_ACTIVE;
		MPTS_UNLOCK(mpts_tried);
		MPT_LOCK(mpte->mpte_mptcb);
		mptcp_start_timer(mpte->mpte_mptcb, MPTT_REXMT);
		MPT_UNLOCK(mpte->mpte_mptcb);
		mptcplog((LOG_INFO, "%s: mp_so 0x%llx retry later\n",
		    __func__, (u_int64_t)VM_KERNEL_ADDRPERM(mp_so)));
		goto out;
	}

	DTRACE_MPTCP3(output, struct mptses *, mpte, struct mptsub *, mpts,
	    struct socket *, mp_so);
	error = mptcp_subflow_output(mpte, mpts);
	if (error) {
		/* can be a temporary loss of source address or other error */
		mpts->mpts_flags |= MPTSF_FAILINGOVER;
		mpts->mpts_flags &= ~MPTSF_ACTIVE;
		mpts_tried = mpts;
		MPTS_UNLOCK(mpts);
		mptcplog((LOG_INFO, "%s: error = %d \n", __func__, error));
		goto try_again;
	}
	/* The model is to have only one active flow at a time */
	mpts->mpts_flags |= MPTSF_ACTIVE;
	MPTS_UNLOCK(mpts);
	if (mpte->mpte_active_sub == NULL) {
		mpte->mpte_active_sub = mpts;
	} else if (mpte->mpte_active_sub != mpts) {
		MPTS_LOCK(mpte->mpte_active_sub);
		mpte->mpte_active_sub->mpts_flags &= ~MPTSF_ACTIVE;
		MPTS_UNLOCK(mpte->mpte_active_sub);
		mpte->mpte_active_sub = mpts;
	}
out:
	/* subflow errors should not be percolated back up */
	return (0);
}

/*
 * Return the most eligible subflow to be used for sending data.
 * This function also serves to check if any alternate subflow is available
 * or not.
 */
struct mptsub *
mptcp_get_subflow(struct mptses *mpte, struct mptsub *ignore)
{
	struct mptsub *mpts;
	struct mptsub *fallback = NULL;
	struct socket *so = NULL;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */

	TAILQ_FOREACH(mpts, &mpte->mpte_subflows, mpts_entry) {
		MPTS_LOCK_SPIN(mpts);

		if ((ignore) && (mpts == ignore)) {
			MPTS_UNLOCK(mpts);
			continue;
		}

		/* There can only be one subflow in degraded state */
		if (mpts->mpts_flags & MPTSF_MP_DEGRADED) {
			MPTS_UNLOCK(mpts);
			break;
		}

		if (!(mpts->mpts_flags & MPTSF_MP_CAPABLE)) {
			MPTS_UNLOCK(mpts);
			continue;
		}

		if (mpts->mpts_flags & MPTSF_SUSPENDED) {
			MPTS_UNLOCK(mpts);
			continue;
		}

		if (mpts->mpts_flags & MPTSF_FAILINGOVER) {
			so = mpts->mpts_socket;
			if ((so) && (!(so->so_flags & SOF_PCBCLEARING))) {
				socket_lock(so, 1);
				if (so->so_snd.sb_cc == 0) {
					mpts->mpts_flags &= ~MPTSF_FAILINGOVER;
					so->so_flags &= ~SOF_MP_TRYFAILOVER;
					fallback = mpts;
					socket_unlock(so, 1);
				} else {
					fallback = mpts;
					socket_unlock(so, 1);
					MPTS_UNLOCK(mpts);
					continue;
				}
			} else {
				MPTS_UNLOCK(mpts);
				continue;
			}
		}

		if (mpts->mpts_flags & MPTSF_PREFERRED) {
			MPTS_UNLOCK(mpts);
			break;
		}

		/* When there are no preferred flows, use first one in list */
		if (fallback == NULL)
			fallback = mpts;

		MPTS_UNLOCK(mpts);
	}
	/*
	 * If there is no preferred or backup subflow, and there is no active
	 * subflow use the last usable subflow.
	 */
	if (mpts == NULL) {
		return (fallback);
	}

	return (mpts);
}

void
mptcp_close_fsm(struct mptcb *mp_tp, uint32_t event)
{
	MPT_LOCK_ASSERT_HELD(mp_tp);

	DTRACE_MPTCP2(state__change, struct mptcb *, mp_tp, 
	    uint32_t, event);

	switch (mp_tp->mpt_state) {
	case MPTCPS_CLOSED:
	case MPTCPS_LISTEN:
		mp_tp->mpt_state = MPTCPS_CLOSED;
		break;

	case MPTCPS_ESTABLISHED:
		if (event == MPCE_CLOSE)
			mp_tp->mpt_state = MPTCPS_FIN_WAIT_1;
		else if (event == MPCE_RECV_DATA_FIN)
			mp_tp->mpt_state = MPTCPS_CLOSE_WAIT;
		break;

	case MPTCPS_CLOSE_WAIT:
		if (event == MPCE_CLOSE)
			mp_tp->mpt_state = MPTCPS_LAST_ACK;
		break;

	case MPTCPS_FIN_WAIT_1:
		if (event == MPCE_RECV_DATA_ACK)
			mp_tp->mpt_state = MPTCPS_FIN_WAIT_2;
		else if (event == MPCE_RECV_DATA_FIN)
			mp_tp->mpt_state = MPTCPS_CLOSING;
		break;

	case MPTCPS_CLOSING:
		if (event == MPCE_RECV_DATA_ACK)
			mp_tp->mpt_state = MPTCPS_TIME_WAIT;
		break;

	case MPTCPS_LAST_ACK:
		if (event == MPCE_RECV_DATA_ACK)
			mp_tp->mpt_state = MPTCPS_CLOSED;
		break;

	case MPTCPS_FIN_WAIT_2:
		if (event == MPCE_RECV_DATA_FIN)
			mp_tp->mpt_state = MPTCPS_TIME_WAIT;
		break;

	case MPTCPS_TIME_WAIT:
		break;

	case MPTCPS_FASTCLOSE_WAIT:
		if (event == MPCE_CLOSE)
			mp_tp->mpt_state = MPTCPS_CLOSED;
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
	}
	DTRACE_MPTCP2(state__change, struct mptcb *, mp_tp, 
	    uint32_t, event);
	mptcplog((LOG_INFO, "%s: state = %d\n",
	    __func__, mp_tp->mpt_state));
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
		mptcplog((LOG_INFO, "%s: Received infinite mapping.",
		    __func__));
		if ((mp_tp->mpt_flags & MPTCPF_CHECKSUM) && (csum != 0)) {
			mptcplog((LOG_ERR, "%s: Bad checksum value %x \n",
			    __func__, csum));
		}
		mptcp_notify_mpfail(tp->t_inpcb->inp_socket);
		return;
	}
	MPT_LOCK(mp_tp);
	if (mptcp_dbg >= MP_VERBOSE_DEBUG_1)
		printf("%s: seqn = %x len = %x full = %llx rcvnxt = %llu \n",
		    __func__, seqn, mdss_data_len, full_dsn,
		    mp_tp->mpt_rcvnxt);

	/* Process a Data FIN packet , handled in mptcp_do_fin_opt */
	if ((seqn == 0) && (mdss_data_len == 1)) {
		mptcplog((LOG_INFO, "%s: Data FIN DSS opt state = %d \n",
		    __func__, mp_tp->mpt_state));
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

	NTOHL(dss_info->mdss_subflow_seqn);
	NTOHS(dss_info->mdss_data_len);
	mptcp_update_rcv_state_meat(mp_tp, tp,
	    dsn,
	    dss_info->mdss_subflow_seqn,
	    dss_info->mdss_data_len,
	    csum);
}

/*
 * MPTCP Checksum support
 * The checksum is calculated whenever the MPTCP DSS option is included
 * in the TCP packet. The checksum includes the sum of the MPTCP psuedo
 * header and the actual data indicated by the length specified in the
 * DSS option.
 */

uint16_t
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
	mptcplog((LOG_INFO, "%s: sum = %x \n", __func__, sum));
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
	mptcplog3((LOG_INFO, "%s: sum = %x \n", __func__, sum));
}
