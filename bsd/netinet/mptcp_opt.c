/*
 * Copyright (c) 2012-2016 Apple Inc. All rights reserved.
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
#include <netinet/in_systm.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/syslog.h>
#include <net/route.h>
#include <netinet/in.h>
#include <net/if.h>

#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/in_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_cache.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcpip.h>
#include <netinet/tcp_fsm.h>
#include <netinet/mptcp_var.h>
#include <netinet/mptcp.h>
#include <netinet/mptcp_opt.h>
#include <netinet/mptcp_seq.h>

#include <libkern/crypto/sha1.h>
#include <netinet/mptcp_timer.h>

#include <mach/sdt.h>

/*
 * SYSCTL for enforcing 64 bit dsn
 */
int32_t force_64bit_dsn = 0;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, force_64bit_dsn,
    CTLFLAG_RW|CTLFLAG_LOCKED, &force_64bit_dsn, 0,
    "Force MPTCP 64bit dsn");


static int mptcp_validate_join_hmac(struct tcpcb *, u_char*, int);
static int mptcp_snd_mpprio(struct tcpcb *tp, u_char *cp, int optlen);

/*
 * MPTCP Options Output Processing
 */

static unsigned
mptcp_setup_first_subflow_syn_opts(struct socket *so, int flags, u_char *opt,
    unsigned optlen)
{
	struct tcpcb *tp = sototcpcb(so);
	struct mptcb *mp_tp = NULL;
	mp_tp = tptomptp(tp);

	/*
	 * Avoid retransmitting the MP_CAPABLE option.
	 */
	if (tp->t_rxtshift > mptcp_mpcap_retries) {
		if (!(mp_tp->mpt_flags & (MPTCPF_FALLBACK_HEURISTIC | MPTCPF_HEURISTIC_TRAC))) {
			mp_tp->mpt_flags |= MPTCPF_HEURISTIC_TRAC;
			tcp_heuristic_mptcp_loss(tp);
		}
		return (optlen);
	}

	if (!tcp_heuristic_do_mptcp(tp)) {
		mp_tp->mpt_flags |= MPTCPF_FALLBACK_HEURISTIC;
		return (optlen);
	}

	if ((flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
		struct mptcp_mpcapable_opt_rsp mptcp_opt;
		mptcp_key_t mp_localkey = 0;

		mp_localkey = mptcp_get_localkey(mp_tp);
		if (mp_localkey == 0) {
			/* an embryonic connection was closed from above */
			return (optlen);
		}
		bzero(&mptcp_opt,
		    sizeof (struct mptcp_mpcapable_opt_rsp));
		mptcp_opt.mmc_common.mmco_kind = TCPOPT_MULTIPATH;
		mptcp_opt.mmc_common.mmco_len =
		    sizeof (struct mptcp_mpcapable_opt_rsp);
		mptcp_opt.mmc_common.mmco_subtype = MPO_CAPABLE;
		MPT_LOCK_SPIN(mp_tp);
		mptcp_opt.mmc_common.mmco_version = mp_tp->mpt_version;
		mptcp_opt.mmc_common.mmco_flags |= MPCAP_PROPOSAL_SBIT;
		if (mp_tp->mpt_flags & MPTCPF_CHECKSUM)
			mptcp_opt.mmc_common.mmco_flags |=
			    MPCAP_CHECKSUM_CBIT;
		MPT_UNLOCK(mp_tp);
		mptcp_opt.mmc_localkey = mp_localkey;
		memcpy(opt + optlen, &mptcp_opt,
		    mptcp_opt.mmc_common.mmco_len);
		optlen += mptcp_opt.mmc_common.mmco_len;
	} else {
		/* Only the SYN flag is set */
		struct mptcp_mpcapable_opt_common mptcp_opt;
		mptcp_key_t mp_localkey = 0;
		mp_localkey = mptcp_get_localkey(mp_tp);
		so->so_flags |= SOF_MPTCP_CLIENT;
		if (mp_localkey == 0) {
			/* an embryonic connection was closed */
			return (optlen);
		}
		bzero(&mptcp_opt,
		    sizeof (struct mptcp_mpcapable_opt_common));
		mptcp_opt.mmco_kind = TCPOPT_MULTIPATH;
		mptcp_opt.mmco_len =
		    sizeof (struct mptcp_mpcapable_opt_common) +
		    sizeof (mptcp_key_t);
		mptcp_opt.mmco_subtype = MPO_CAPABLE;
		MPT_LOCK_SPIN(mp_tp);
		mptcp_opt.mmco_version = mp_tp->mpt_version;
		mptcp_opt.mmco_flags |= MPCAP_PROPOSAL_SBIT;
		if (mp_tp->mpt_flags & MPTCPF_CHECKSUM)
			mptcp_opt.mmco_flags |= MPCAP_CHECKSUM_CBIT;
		MPT_UNLOCK(mp_tp);
		(void) memcpy(opt + optlen, &mptcp_opt,
		    sizeof (struct mptcp_mpcapable_opt_common));
		optlen += sizeof (struct mptcp_mpcapable_opt_common);
		(void) memcpy(opt + optlen, &mp_localkey,
		    sizeof (mptcp_key_t));
		optlen += sizeof (mptcp_key_t);
	}

	return (optlen);
}

static unsigned
mptcp_setup_join_subflow_syn_opts(struct socket *so, int flags, u_char *opt,
    unsigned optlen)
{
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp = NULL;

	if (!inp)
		return (optlen);

	tp = intotcpcb(inp);
	if (!tp)
		return (optlen);

	if (!tp->t_mptcb)
		return (optlen);

	if ((flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
		struct mptcp_mpjoin_opt_rsp mpjoin_rsp;
		struct mptcb *mp_tp = tptomptp(tp);

		if (mp_tp == NULL)
			return (optlen);

		MPT_LOCK(mp_tp);
		if (mptcp_get_localkey(mp_tp) == 0) {
			MPT_UNLOCK(mp_tp);
			return (optlen);
		}
		MPT_UNLOCK(mp_tp);
		bzero(&mpjoin_rsp, sizeof (mpjoin_rsp));
		mpjoin_rsp.mmjo_kind = TCPOPT_MULTIPATH;
		mpjoin_rsp.mmjo_len = sizeof (mpjoin_rsp);
		mpjoin_rsp.mmjo_subtype_bkp = MPO_JOIN << 4;
		if (tp->t_mpflags & TMPF_BACKUP_PATH)
			mpjoin_rsp.mmjo_subtype_bkp |= MPTCP_BACKUP;
		mpjoin_rsp.mmjo_addr_id = tp->t_local_aid;
		mptcp_get_rands(tp->t_local_aid, tptomptp(tp),
		    &mpjoin_rsp.mmjo_rand, NULL);
		mpjoin_rsp.mmjo_mac = mptcp_get_trunced_hmac(tp->t_local_aid,
		    mp_tp);
		memcpy(opt + optlen, &mpjoin_rsp, mpjoin_rsp.mmjo_len);
		optlen += mpjoin_rsp.mmjo_len;
	} else {
		struct mptcp_mpjoin_opt_req mpjoin_req;

		bzero(&mpjoin_req, sizeof (mpjoin_req));
		mpjoin_req.mmjo_kind = TCPOPT_MULTIPATH;
		mpjoin_req.mmjo_len = sizeof (mpjoin_req);
		mpjoin_req.mmjo_subtype_bkp = MPO_JOIN << 4;
		if (tp->t_mpflags & TMPF_BACKUP_PATH)
			mpjoin_req.mmjo_subtype_bkp |= MPTCP_BACKUP;
		mpjoin_req.mmjo_addr_id = tp->t_local_aid;
		mpjoin_req.mmjo_peer_token = mptcp_get_remotetoken(tp->t_mptcb);
		if (mpjoin_req.mmjo_peer_token == 0) {
			mptcplog((LOG_DEBUG, "MPTCP Socket: %s: peer token 0",
				__func__),
				MPTCP_SOCKET_DBG, MPTCP_LOGLVL_ERR);
		}
		mptcp_get_rands(tp->t_local_aid, tptomptp(tp),
		    &mpjoin_req.mmjo_rand, NULL);
		memcpy(opt + optlen, &mpjoin_req, mpjoin_req.mmjo_len);
		optlen += mpjoin_req.mmjo_len;
		/* send an event up, if Fast Join is requested */
		if (mptcp_zerortt_fastjoin &&
		    (so->so_flags & SOF_MPTCP_FASTJOIN)) {
			soevent(so, (SO_FILT_HINT_LOCKED | SO_FILT_HINT_MPFASTJ));
		}
	}
	return (optlen);
}

unsigned
mptcp_setup_join_ack_opts(struct tcpcb *tp, u_char *opt, unsigned optlen)
{
	unsigned new_optlen;
	struct mptcp_mpjoin_opt_rsp2 join_rsp2;

	if ((MAX_TCPOPTLEN - optlen) < sizeof (struct mptcp_mpjoin_opt_rsp2)) {
		printf("%s: no space left %d \n", __func__, optlen);
		return (optlen);
	}

	bzero(&join_rsp2, sizeof (struct mptcp_mpjoin_opt_rsp2));
	join_rsp2.mmjo_kind = TCPOPT_MULTIPATH;
	join_rsp2.mmjo_len = sizeof (struct mptcp_mpjoin_opt_rsp2);
	join_rsp2.mmjo_subtype = MPO_JOIN;
	mptcp_get_hmac(tp->t_local_aid, tptomptp(tp),
	    (u_char*)&join_rsp2.mmjo_mac,
	    sizeof (join_rsp2.mmjo_mac));
	memcpy(opt + optlen, &join_rsp2, join_rsp2.mmjo_len);
	new_optlen = optlen + join_rsp2.mmjo_len;
	tp->t_mpflags |= TMPF_FASTJOINBY2_SEND;
	return (new_optlen);
}

unsigned
mptcp_setup_syn_opts(struct socket *so, int flags, u_char *opt, unsigned optlen)
{
	unsigned new_optlen;

	if (!(so->so_flags & SOF_MP_SEC_SUBFLOW)) {
		new_optlen = mptcp_setup_first_subflow_syn_opts(so, flags, opt,
		    optlen);
	} else {
		/*
		 * To simulate SYN_ACK with no join opt, comment this line on
		 * OS X server side. This serves as a testing hook.
		 */
		new_optlen = mptcp_setup_join_subflow_syn_opts(so, flags, opt,
		    optlen);
	}
	return (new_optlen);
}

static int
mptcp_send_mpfail(struct tcpcb *tp, u_char *opt, unsigned int optlen)
{
#pragma unused(tp, opt, optlen)

	struct mptcb *mp_tp = NULL;
	struct mptcp_mpfail_opt fail_opt;
	uint64_t dsn;
	int len = sizeof (struct mptcp_mpfail_opt);

	mp_tp = tptomptp(tp);
	if (mp_tp == NULL) {
		tp->t_mpflags &= ~TMPF_SND_MPFAIL;
		return (optlen);
	}

	/* if option space low give up */
	if ((MAX_TCPOPTLEN - optlen) < sizeof (struct mptcp_mpfail_opt)) {
		tp->t_mpflags &= ~TMPF_SND_MPFAIL;
		return (optlen);
	}

	MPT_LOCK(mp_tp);
	dsn = mp_tp->mpt_rcvnxt;
	MPT_UNLOCK(mp_tp);

	bzero(&fail_opt, sizeof (fail_opt));
	fail_opt.mfail_kind = TCPOPT_MULTIPATH;
	fail_opt.mfail_len = len;
	fail_opt.mfail_subtype = MPO_FAIL;
	fail_opt.mfail_dsn = mptcp_hton64(dsn);
	memcpy(opt + optlen, &fail_opt, len);
	optlen += len;
	tp->t_mpflags &= ~TMPF_SND_MPFAIL;
	mptcplog((LOG_DEBUG, "MPTCP Socket: %s: %d \n", __func__,
	    tp->t_local_aid), (MPTCP_SOCKET_DBG | MPTCP_SENDER_DBG),
	    MPTCP_LOGLVL_LOG);
	return (optlen);
}

static int
mptcp_send_infinite_mapping(struct tcpcb *tp, u_char *opt, unsigned int optlen)
{
	struct mptcp_dsn_opt infin_opt;
	struct mptcb *mp_tp = NULL;
	size_t len = sizeof (struct mptcp_dsn_opt);
	struct socket *so = tp->t_inpcb->inp_socket;
	int error = 0;
	int csum_len = 0;

	if (!so)
		return (optlen);

	mp_tp = tptomptp(tp);
	if (mp_tp == NULL)
		return (optlen);

	MPT_LOCK(mp_tp);
	if (mp_tp->mpt_flags & MPTCPF_CHECKSUM)
		csum_len = 2;

	/* try later */
	if ((MAX_TCPOPTLEN - optlen) < (len + csum_len)) {
		MPT_UNLOCK(mp_tp);
		return (optlen);
	}
	bzero(&infin_opt, sizeof (infin_opt));
	infin_opt.mdss_copt.mdss_kind = TCPOPT_MULTIPATH;
	infin_opt.mdss_copt.mdss_len = len + csum_len;
	infin_opt.mdss_copt.mdss_subtype = MPO_DSS;
	infin_opt.mdss_copt.mdss_flags |= MDSS_M;
	if (mp_tp->mpt_flags & MPTCPF_RECVD_MPFAIL) {
		infin_opt.mdss_dsn = (u_int32_t)
		    MPTCP_DATASEQ_LOW32(mp_tp->mpt_dsn_at_csum_fail);
		infin_opt.mdss_subflow_seqn = mp_tp->mpt_ssn_at_csum_fail;
	} else {
		/*
		 * If MPTCP fallback happens, but TFO succeeds, the data on the
		 * SYN does not belong to the MPTCP data sequence space.
		 */
		if ((tp->t_tfo_stats & TFO_S_SYN_DATA_ACKED) &&
		    ((mp_tp->mpt_local_idsn + 1) == mp_tp->mpt_snduna)) {
			infin_opt.mdss_subflow_seqn = 1;

			mptcplog((LOG_DEBUG, "MPTCP Socket: %s: idsn %llu"
			    "snduna %llu \n", __func__, mp_tp->mpt_local_idsn,
			    mp_tp->mpt_snduna),
			    (MPTCP_SOCKET_DBG | MPTCP_SENDER_DBG),
			    MPTCP_LOGLVL_LOG);
		} else {
			infin_opt.mdss_subflow_seqn = tp->snd_una - tp->iss;
		}
		infin_opt.mdss_dsn = (u_int32_t)
		    MPTCP_DATASEQ_LOW32(mp_tp->mpt_snduna);
	}
	MPT_UNLOCK(mp_tp);
	if (error != 0)
		return (optlen);
	if ((infin_opt.mdss_dsn == 0) || (infin_opt.mdss_subflow_seqn == 0)) {
		return (optlen);
	}
	infin_opt.mdss_dsn = htonl(infin_opt.mdss_dsn);
	infin_opt.mdss_subflow_seqn = htonl(infin_opt.mdss_subflow_seqn);
	infin_opt.mdss_data_len = 0;

	memcpy(opt + optlen, &infin_opt, len);
	optlen += len;
	if (csum_len != 0) {
		/* The checksum field is set to 0 for infinite mapping */
		uint16_t csum = 0;
		memcpy(opt + optlen, &csum, csum_len);
		optlen += csum_len;
	}

	mptcplog((LOG_DEBUG, "MPTCP Socket: %s: dsn = %x, seq = %x len = %x\n",
	    __func__,
	    ntohl(infin_opt.mdss_dsn),
	    ntohl(infin_opt.mdss_subflow_seqn),
	    ntohs(infin_opt.mdss_data_len)),
	    (MPTCP_SOCKET_DBG | MPTCP_SENDER_DBG),
	    MPTCP_LOGLVL_LOG);

	/* so->so_flags &= ~SOF_MPTCP_CLIENT; */
	tp->t_mpflags |= TMPF_INFIN_SENT;
	tcpstat.tcps_estab_fallback++;
	return (optlen);
}


static int
mptcp_ok_to_fin(struct tcpcb *tp, u_int64_t dsn, u_int32_t datalen)
{
	struct mptcb *mp_tp = NULL;
	mp_tp = tptomptp(tp);

	MPT_LOCK(mp_tp);
	dsn = (mp_tp->mpt_sndmax & MPTCP_DATASEQ_LOW32_MASK) | dsn;
	if ((dsn + datalen) == mp_tp->mpt_sndmax) {
		MPT_UNLOCK(mp_tp);
		return (1);
	}
	MPT_UNLOCK(mp_tp);
	return (0);
}

unsigned int
mptcp_setup_opts(struct tcpcb *tp, int32_t off, u_char *opt,
    unsigned int optlen, int flags, int datalen,
    unsigned int **dss_lenp, u_int8_t **finp, u_int64_t *dss_valp,
    u_int32_t **sseqp, boolean_t *p_mptcp_acknow)
{
	struct inpcb *inp = (struct inpcb *)tp->t_inpcb;
	struct socket *so = inp->inp_socket;
	struct mptcb *mp_tp = tptomptp(tp);
	boolean_t do_csum = FALSE;
	boolean_t send_64bit_dsn = FALSE;
	boolean_t send_64bit_ack = FALSE;
	u_int32_t old_mpt_flags = tp->t_mpflags &
	    (TMPF_SND_MPPRIO | TMPF_SND_REM_ADDR | TMPF_SND_MPFAIL |
	    TMPF_MPCAP_RETRANSMIT);

	if ((mptcp_enable == 0) ||
	    (mp_tp == NULL) ||
	    (mp_tp->mpt_flags & MPTCPF_PEEL_OFF) ||
	    (tp->t_state == TCPS_CLOSED)) {
		/* do nothing */
		goto ret_optlen;
	}

	if (mp_tp->mpt_flags & MPTCPF_CHECKSUM) {
		do_csum = TRUE;
	}

	/* tcp_output handles the SYN path separately */
	if (flags & TH_SYN) {
		goto ret_optlen;
	}

	if ((MAX_TCPOPTLEN - optlen) <
	    sizeof (struct mptcp_mpcapable_opt_common)) {
		mptcplog((LOG_ERR, "MPTCP Socket:  "
		    "%s: no space left %d flags %x "
		    "tp->t_mpflags %x "
		    "len %d\n", __func__, optlen, flags, tp->t_mpflags,
		    datalen), MPTCP_SOCKET_DBG, MPTCP_LOGLVL_ERR);
		goto ret_optlen;
	}

	if (tp->t_mpflags & TMPF_TCP_FALLBACK) {
		if (tp->t_mpflags & TMPF_SND_MPFAIL)
			optlen = mptcp_send_mpfail(tp, opt, optlen);
		else if (!(tp->t_mpflags & TMPF_INFIN_SENT))
			optlen = mptcp_send_infinite_mapping(tp, opt, optlen);
		goto ret_optlen;
	}

	if (((tp->t_mpflags & TMPF_FASTJOINBY2_SEND) ||
	    (tp->t_mpflags & TMPF_FASTJOIN_SEND )) &&
	    (datalen > 0)) {
		tp->t_mpflags &= ~TMPF_FASTJOINBY2_SEND;
		tp->t_mpflags &= ~TMPF_FASTJOIN_SEND;
		goto fastjoin_send;
	}

	if (((tp->t_mpflags & TMPF_PREESTABLISHED) &&
	    (!(tp->t_mpflags & TMPF_SENT_KEYS)) &&
	    (!(tp->t_mpflags & TMPF_JOINED_FLOW))) ||
	    (tp->t_mpflags & TMPF_MPCAP_RETRANSMIT)) {
		struct mptcp_mpcapable_opt_rsp1 mptcp_opt;
		if ((MAX_TCPOPTLEN - optlen) <
		    sizeof (struct mptcp_mpcapable_opt_rsp1))
			goto ret_optlen;
		bzero(&mptcp_opt, sizeof (struct mptcp_mpcapable_opt_rsp1));
		mptcp_opt.mmc_common.mmco_kind = TCPOPT_MULTIPATH;
		mptcp_opt.mmc_common.mmco_len =
		    sizeof (struct mptcp_mpcapable_opt_rsp1);
		mptcp_opt.mmc_common.mmco_subtype = MPO_CAPABLE;
		mptcp_opt.mmc_common.mmco_version = mp_tp->mpt_version;
		/* HMAC-SHA1 is the proposal */
		mptcp_opt.mmc_common.mmco_flags |= MPCAP_PROPOSAL_SBIT;
		MPT_LOCK(mp_tp);
		if (mp_tp->mpt_flags & MPTCPF_CHECKSUM)
			mptcp_opt.mmc_common.mmco_flags |= MPCAP_CHECKSUM_CBIT;
		mptcp_opt.mmc_localkey = mptcp_get_localkey(mp_tp);
		mptcp_opt.mmc_remotekey = mptcp_get_remotekey(mp_tp);
		MPT_UNLOCK(mp_tp);
		memcpy(opt + optlen, &mptcp_opt, mptcp_opt.mmc_common.mmco_len);
		optlen += mptcp_opt.mmc_common.mmco_len;
		tp->t_mpflags |= TMPF_SENT_KEYS | TMPF_MPTCP_TRUE;
		so->so_flags |= SOF_MPTCP_TRUE;
		tp->t_mpflags &= ~TMPF_PREESTABLISHED;
		tp->t_mpflags &= ~TMPF_MPCAP_RETRANSMIT;

		if (!tp->t_mpuna) {
			tp->t_mpuna = tp->snd_una;
		} else {
			/* its a retransmission of the MP_CAPABLE ACK */
		}
		goto ret_optlen;
	}

	if ((tp->t_mpflags & TMPF_JOINED_FLOW) &&
	    (tp->t_mpflags & TMPF_PREESTABLISHED) &&
	    (!(tp->t_mpflags & TMPF_RECVD_JOIN)) &&
	    (tp->t_mpflags & TMPF_SENT_JOIN) &&
	    (!(tp->t_mpflags & TMPF_MPTCP_TRUE))) {
		MPT_LOCK(mp_tp);
		if (mptcp_get_localkey(mp_tp) == 0) {
			MPT_UNLOCK(mp_tp);
			goto ret_optlen;
		}
		MPT_UNLOCK(mp_tp);
		/* Do the ACK part */
		optlen = mptcp_setup_join_ack_opts(tp, opt, optlen);
		if (!tp->t_mpuna) {
			tp->t_mpuna = tp->snd_una;
		}
		/* Start a timer to retransmit the ACK */
		tp->t_timer[TCPT_JACK_RXMT] =
			    OFFSET_FROM_START(tp, tcp_jack_rxmt);
		goto ret_optlen;
	}

	if (!(tp->t_mpflags & TMPF_MPTCP_TRUE))
		goto ret_optlen;
fastjoin_send:
	/*
	 * From here on, all options are sent only if MPTCP_TRUE
	 * or when data is sent early on as in Fast Join
	 */

	if ((tp->t_mpflags & TMPF_MPTCP_TRUE) &&
	    (tp->t_mpflags & TMPF_SND_REM_ADDR)) {
		int rem_opt_len = sizeof (struct mptcp_remaddr_opt);
		if ((optlen + rem_opt_len) <= MAX_TCPOPTLEN) {
			mptcp_send_remaddr_opt(tp,
			    (struct mptcp_remaddr_opt *)(opt + optlen));
			optlen += rem_opt_len;
		} else {
			tp->t_mpflags &= ~TMPF_SND_REM_ADDR;
		}
	}

	if (tp->t_mpflags & TMPF_SND_MPPRIO) {
		optlen = mptcp_snd_mpprio(tp, opt, optlen);
	}

	MPT_LOCK(mp_tp);
	if ((mp_tp->mpt_flags & MPTCPF_SND_64BITDSN) || force_64bit_dsn) {
		send_64bit_dsn = TRUE;
	}
	if (mp_tp->mpt_flags & MPTCPF_SND_64BITACK)
		send_64bit_ack = TRUE;

	MPT_UNLOCK(mp_tp);

#define	CHECK_OPTLEN	{						\
	if ((MAX_TCPOPTLEN - optlen) < len) {				\
		mptcplog((LOG_ERR, "MPTCP Socket:  "			\
		    "%s: len %d optlen %d \n", __func__, len, optlen),	\
		    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_ERR);		\
		goto ret_optlen;					\
	}								\
}

#define	DO_FIN(dsn_opt) {						\
	int sndfin = 0;							\
	sndfin = mptcp_ok_to_fin(tp, dsn_opt.mdss_dsn, datalen);	\
	if (sndfin) {							\
		dsn_opt.mdss_copt.mdss_flags |= MDSS_F;			\
		*finp = opt + optlen + offsetof(struct mptcp_dss_copt,	\
		    mdss_flags);					\
		dsn_opt.mdss_data_len += 1;				\
	}								\
}

#define	CHECK_DATALEN {							\
	/* MPTCP socket does not support IP options */			\
	if ((datalen + optlen + len) > tp->t_maxopd) {			\
		mptcplog((LOG_ERR, "MPTCP Socket:  "			\
		    "%s: nosp %d len %d opt %d %d %d\n",		\
		    __func__, datalen, len, optlen,			\
		    tp->t_maxseg, tp->t_maxopd),			\
		    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_ERR);		\
		/* remove option length from payload len */		\
		datalen = tp->t_maxopd - optlen - len;			\
	}								\
}

	if ((tp->t_mpflags & TMPF_SEND_DSN) &&
	    (send_64bit_dsn)) {
		/*
		 * If there was the need to send 64-bit Data ACK along
		 * with 64-bit DSN, then 26 or 28 bytes would be used.
		 * With timestamps and NOOP padding that will cause
		 * overflow. Hence, in the rare event that both 64-bit
		 * DSN and 64-bit ACK have to be sent, delay the send of
		 * 64-bit ACK until our 64-bit DSN is acked with a 64-bit ack.
		 * XXX If this delay causes issue, remove the 2-byte padding.
		 */
		struct mptcp_dss64_ack32_opt dsn_ack_opt;
		unsigned int len = sizeof (dsn_ack_opt);

		if (do_csum) {
			len += 2;
		}

		CHECK_OPTLEN;

		bzero(&dsn_ack_opt, sizeof (dsn_ack_opt));
		dsn_ack_opt.mdss_copt.mdss_kind = TCPOPT_MULTIPATH;
		dsn_ack_opt.mdss_copt.mdss_subtype = MPO_DSS;
		dsn_ack_opt.mdss_copt.mdss_len = len;
		dsn_ack_opt.mdss_copt.mdss_flags |=
		    MDSS_M | MDSS_m | MDSS_A;

		CHECK_DATALEN;

		mptcp_output_getm_dsnmap64(so, off, (u_int32_t)datalen,
		    &dsn_ack_opt.mdss_dsn,
		    &dsn_ack_opt.mdss_subflow_seqn,
		    &dsn_ack_opt.mdss_data_len);

		*dss_valp = dsn_ack_opt.mdss_dsn;

		if ((dsn_ack_opt.mdss_data_len == 0) ||
		    (dsn_ack_opt.mdss_dsn == 0)) {
			goto ret_optlen;
		}

		if (tp->t_mpflags & TMPF_SEND_DFIN) {
			DO_FIN(dsn_ack_opt);
		}

		MPT_LOCK(mp_tp);
		dsn_ack_opt.mdss_ack =
		    htonl(MPTCP_DATAACK_LOW32(mp_tp->mpt_rcvnxt));
		MPT_UNLOCK(mp_tp);

		dsn_ack_opt.mdss_dsn = mptcp_hton64(dsn_ack_opt.mdss_dsn);
		dsn_ack_opt.mdss_subflow_seqn = htonl(
		    dsn_ack_opt.mdss_subflow_seqn);
		dsn_ack_opt.mdss_data_len = htons(
		    dsn_ack_opt.mdss_data_len);
		*dss_lenp = (unsigned int *)(void *)(opt + optlen +
		    offsetof(struct mptcp_dss64_ack32_opt, mdss_data_len));

		memcpy(opt + optlen, &dsn_ack_opt, sizeof (dsn_ack_opt));

		if (do_csum) {
			*sseqp = (u_int32_t *)(void *)(opt + optlen +
			    offsetof(struct mptcp_dss64_ack32_opt,
			    mdss_subflow_seqn));
		}
		optlen += len;
		mptcplog((LOG_DEBUG,"MPTCP Socket: "
		    "%s: long DSS = %llx ACK = %llx \n",
		    __func__,
		    mptcp_ntoh64(dsn_ack_opt.mdss_dsn),
		    mptcp_ntoh64(dsn_ack_opt.mdss_ack)),
		    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_LOG);

		tp->t_mpflags &= ~TMPF_MPTCP_ACKNOW;
		goto ret_optlen;
	}

	if ((tp->t_mpflags & TMPF_SEND_DSN) &&
	    (!send_64bit_dsn) &&
	    !(tp->t_mpflags & TMPF_MPTCP_ACKNOW))  {
		struct mptcp_dsn_opt dsn_opt;
		unsigned int len = sizeof (struct mptcp_dsn_opt);

		if (do_csum) {
			len += 2;
		}

		CHECK_OPTLEN;

		bzero(&dsn_opt, sizeof (dsn_opt));
		dsn_opt.mdss_copt.mdss_kind = TCPOPT_MULTIPATH;
		dsn_opt.mdss_copt.mdss_subtype = MPO_DSS;
		dsn_opt.mdss_copt.mdss_len = len;
		dsn_opt.mdss_copt.mdss_flags |= MDSS_M;

		CHECK_DATALEN;

		mptcp_output_getm_dsnmap32(so, off, (u_int32_t)datalen,
		    &dsn_opt.mdss_dsn,
		    &dsn_opt.mdss_subflow_seqn, &dsn_opt.mdss_data_len,
		    dss_valp);

		if ((dsn_opt.mdss_data_len == 0) ||
		    (dsn_opt.mdss_dsn == 0)) {
			goto ret_optlen;
		}

		if (tp->t_mpflags & TMPF_SEND_DFIN) {
			DO_FIN(dsn_opt);
		}

		dsn_opt.mdss_dsn = htonl(dsn_opt.mdss_dsn);
		dsn_opt.mdss_subflow_seqn = htonl(dsn_opt.mdss_subflow_seqn);
		dsn_opt.mdss_data_len = htons(dsn_opt.mdss_data_len);
		*dss_lenp = (unsigned int *)(void *)(opt + optlen +
		    offsetof(struct mptcp_dsn_opt, mdss_data_len));
		memcpy(opt + optlen, &dsn_opt, sizeof (dsn_opt));
		if (do_csum) {
			*sseqp = (u_int32_t *)(void *)(opt + optlen +
			    offsetof(struct mptcp_dsn_opt, mdss_subflow_seqn));
		}
		optlen += len;
		tp->t_mpflags &= ~TMPF_MPTCP_ACKNOW;
		goto ret_optlen;
	}

	/* 32-bit Data ACK option */
	if ((tp->t_mpflags & TMPF_MPTCP_ACKNOW) &&
	    (!send_64bit_ack) &&
	    !(tp->t_mpflags & TMPF_SEND_DSN) &&
	    !(tp->t_mpflags & TMPF_SEND_DFIN)) {

		struct mptcp_data_ack_opt dack_opt;
		unsigned int len = 0;
do_ack32_only:
		len = sizeof (dack_opt);

		CHECK_OPTLEN;

		bzero(&dack_opt, len);
		dack_opt.mdss_copt.mdss_kind = TCPOPT_MULTIPATH;
		dack_opt.mdss_copt.mdss_len = len;
		dack_opt.mdss_copt.mdss_subtype = MPO_DSS;
		dack_opt.mdss_copt.mdss_flags |= MDSS_A;
		MPT_LOCK_SPIN(mp_tp);
		dack_opt.mdss_ack =
		    htonl(MPTCP_DATAACK_LOW32(mp_tp->mpt_rcvnxt));
		MPT_UNLOCK(mp_tp);
		memcpy(opt + optlen, &dack_opt, len);
		optlen += len;
		VERIFY(optlen <= MAX_TCPOPTLEN);
		tp->t_mpflags &= ~TMPF_MPTCP_ACKNOW;
		goto ret_optlen;
	}

	/* 64-bit Data ACK option */
	if ((tp->t_mpflags & TMPF_MPTCP_ACKNOW) &&
	    (send_64bit_ack) &&
	    !(tp->t_mpflags & TMPF_SEND_DSN) &&
	    !(tp->t_mpflags & TMPF_SEND_DFIN)) {
		struct mptcp_data_ack64_opt dack_opt;
		unsigned int len = 0;
do_ack64_only:
		len = sizeof (dack_opt);

		CHECK_OPTLEN;

		bzero(&dack_opt, len);
		dack_opt.mdss_copt.mdss_kind = TCPOPT_MULTIPATH;
		dack_opt.mdss_copt.mdss_len = len;
		dack_opt.mdss_copt.mdss_subtype = MPO_DSS;
		dack_opt.mdss_copt.mdss_flags |= (MDSS_A | MDSS_a);
		MPT_LOCK_SPIN(mp_tp);
		dack_opt.mdss_ack = mptcp_hton64(mp_tp->mpt_rcvnxt);
		/*
		 * The other end should retransmit 64-bit DSN until it
		 * receives a 64-bit ACK.
		 */
		mp_tp->mpt_flags &= ~MPTCPF_SND_64BITACK;
		MPT_UNLOCK(mp_tp);
		memcpy(opt + optlen, &dack_opt, len);
		optlen += len;
		VERIFY(optlen <= MAX_TCPOPTLEN);
		tp->t_mpflags &= ~TMPF_MPTCP_ACKNOW;
		goto ret_optlen;
	}

	/* 32-bit DSS+Data ACK option */
	if ((tp->t_mpflags & TMPF_SEND_DSN) &&
	    (!send_64bit_dsn) &&
	    (!send_64bit_ack) &&
	    (tp->t_mpflags & TMPF_MPTCP_ACKNOW)) {
		struct mptcp_dss_ack_opt dss_ack_opt;
		unsigned int len = sizeof (dss_ack_opt);

		if (do_csum)
			len += 2;

		CHECK_OPTLEN;

		bzero(&dss_ack_opt, sizeof (dss_ack_opt));
		dss_ack_opt.mdss_copt.mdss_kind = TCPOPT_MULTIPATH;
		dss_ack_opt.mdss_copt.mdss_len = len;
		dss_ack_opt.mdss_copt.mdss_subtype = MPO_DSS;
		dss_ack_opt.mdss_copt.mdss_flags |= MDSS_A | MDSS_M;
		MPT_LOCK_SPIN(mp_tp);
		dss_ack_opt.mdss_ack =
		    htonl(MPTCP_DATAACK_LOW32(mp_tp->mpt_rcvnxt));
		MPT_UNLOCK(mp_tp);

		CHECK_DATALEN;

		mptcp_output_getm_dsnmap32(so, off, (u_int32_t)datalen,
		    &dss_ack_opt.mdss_dsn,
		    &dss_ack_opt.mdss_subflow_seqn,
		    &dss_ack_opt.mdss_data_len,
		    dss_valp);

		if ((dss_ack_opt.mdss_data_len == 0) ||
		    (dss_ack_opt.mdss_dsn == 0)) {
			goto do_ack32_only;
		}

		if (tp->t_mpflags & TMPF_SEND_DFIN) {
			DO_FIN(dss_ack_opt);
		}

		dss_ack_opt.mdss_dsn = htonl(dss_ack_opt.mdss_dsn);
		dss_ack_opt.mdss_subflow_seqn =
		    htonl(dss_ack_opt.mdss_subflow_seqn);
		dss_ack_opt.mdss_data_len = htons(dss_ack_opt.mdss_data_len);
		*dss_lenp = (unsigned int *)(void *)(opt + optlen +
		    offsetof(struct mptcp_dss_ack_opt, mdss_data_len));
		memcpy(opt + optlen, &dss_ack_opt, sizeof (dss_ack_opt));
		if (do_csum) {
			*sseqp = (u_int32_t *)(void *)(opt + optlen +
			    offsetof(struct mptcp_dss_ack_opt,
			    mdss_subflow_seqn));
		}

		optlen += len;

		if (optlen > MAX_TCPOPTLEN)
			panic("optlen too large");
		tp->t_mpflags &= ~TMPF_MPTCP_ACKNOW;
		goto ret_optlen;
	}

	/* 32-bit DSS + 64-bit DACK option */
	if ((tp->t_mpflags & TMPF_SEND_DSN) &&
	    (!send_64bit_dsn) &&
	    (send_64bit_ack) &&
	    (tp->t_mpflags & TMPF_MPTCP_ACKNOW)) {
		struct mptcp_dss32_ack64_opt dss_ack_opt;
		unsigned int len = sizeof (dss_ack_opt);

		if (do_csum)
			len += 2;

		CHECK_OPTLEN;

		bzero(&dss_ack_opt, sizeof (dss_ack_opt));
		dss_ack_opt.mdss_copt.mdss_kind = TCPOPT_MULTIPATH;
		dss_ack_opt.mdss_copt.mdss_len = len;
		dss_ack_opt.mdss_copt.mdss_subtype = MPO_DSS;
		dss_ack_opt.mdss_copt.mdss_flags |= MDSS_M | MDSS_A | MDSS_a;
		MPT_LOCK_SPIN(mp_tp);
		dss_ack_opt.mdss_ack =
		    mptcp_hton64(mp_tp->mpt_rcvnxt);
		MPT_UNLOCK(mp_tp);

		CHECK_DATALEN;

		mptcp_output_getm_dsnmap32(so, off, (u_int32_t)datalen,
		    &dss_ack_opt.mdss_dsn, &dss_ack_opt.mdss_subflow_seqn,
		    &dss_ack_opt.mdss_data_len, dss_valp);

		if ((dss_ack_opt.mdss_data_len == 0) ||
		    (dss_ack_opt.mdss_dsn == 0)) {
			goto do_ack64_only;
		}

		if (tp->t_mpflags & TMPF_SEND_DFIN) {
			DO_FIN(dss_ack_opt);
		}

		dss_ack_opt.mdss_dsn = htonl(dss_ack_opt.mdss_dsn);
		dss_ack_opt.mdss_subflow_seqn =
		    htonl(dss_ack_opt.mdss_subflow_seqn);
		dss_ack_opt.mdss_data_len = htons(dss_ack_opt.mdss_data_len);
		*dss_lenp = (unsigned int *)(void *)(opt + optlen +
		    offsetof(struct mptcp_dss32_ack64_opt, mdss_data_len));
		memcpy(opt + optlen, &dss_ack_opt, sizeof (dss_ack_opt));
		if (do_csum) {
			*sseqp = (u_int32_t *)(void *)(opt + optlen +
			    offsetof(struct mptcp_dss32_ack64_opt,
			    mdss_subflow_seqn));
		}

		optlen += len;

		if (optlen > MAX_TCPOPTLEN)
			panic("optlen too large");
		tp->t_mpflags &= ~TMPF_MPTCP_ACKNOW;
		goto ret_optlen;
	}

	if (tp->t_mpflags & TMPF_SEND_DFIN) {
		struct mptcp_dss_ack_opt dss_ack_opt;
		unsigned int len = sizeof (struct mptcp_dss_ack_opt);

		if (do_csum)
			len += 2;

		CHECK_OPTLEN;

		bzero(&dss_ack_opt, sizeof (dss_ack_opt));

		MPT_LOCK(mp_tp);
		/*
		 * Data FIN occupies one sequence space.
		 * Don't send it if it has been Acked.
		 */
		if (((mp_tp->mpt_sndnxt + 1) != mp_tp->mpt_sndmax) ||
		    (mp_tp->mpt_snduna == mp_tp->mpt_sndmax)) {
			MPT_UNLOCK(mp_tp);
			goto ret_optlen;
		}

		dss_ack_opt.mdss_copt.mdss_kind = TCPOPT_MULTIPATH;
		dss_ack_opt.mdss_copt.mdss_len = len;
		dss_ack_opt.mdss_copt.mdss_subtype = MPO_DSS;
		dss_ack_opt.mdss_copt.mdss_flags |= MDSS_A | MDSS_M | MDSS_F;
		dss_ack_opt.mdss_ack =
		    htonl(MPTCP_DATAACK_LOW32(mp_tp->mpt_rcvnxt));
		dss_ack_opt.mdss_dsn =
		    htonl(MPTCP_DATASEQ_LOW32(mp_tp->mpt_sndnxt));
		MPT_UNLOCK(mp_tp);
		dss_ack_opt.mdss_subflow_seqn = 0;
		dss_ack_opt.mdss_data_len = 1;
		dss_ack_opt.mdss_data_len = htons(dss_ack_opt.mdss_data_len);
		memcpy(opt + optlen, &dss_ack_opt, sizeof (dss_ack_opt));
		if (do_csum) {
			*dss_valp = mp_tp->mpt_sndnxt;
			*sseqp = (u_int32_t *)(void *)(opt + optlen +
			    offsetof(struct mptcp_dss_ack_opt,
			    mdss_subflow_seqn));
		}
		optlen += len;
	}

ret_optlen:
	if (TRUE == *p_mptcp_acknow ) {
		VERIFY(old_mpt_flags != 0);
		u_int32_t new_mpt_flags = tp->t_mpflags &
		    (TMPF_SND_MPPRIO | TMPF_SND_REM_ADDR | TMPF_SND_MPFAIL |
		    TMPF_MPCAP_RETRANSMIT);

		/*
		 * If none of the above mpflags were acted on by
		 * this routine, reset these flags and set p_mptcp_acknow
		 * to false.
		 * XXX The reset value of p_mptcp_acknow can be used
		 * to communicate tcp_output to NOT send a pure ack without any
		 * MPTCP options as it will be treated as a dup ack.
		 * Since the instances of mptcp_setup_opts not acting on
		 * these options are mostly corner cases and sending a dup
		 * ack here would only have an impact if the system
		 * has sent consecutive dup acks before this false one,
		 * we haven't modified the logic in tcp_output to avoid
		 * that.
		 */
		if ((old_mpt_flags == new_mpt_flags) || (new_mpt_flags == 0)) {
			tp->t_mpflags &= ~(TMPF_SND_MPPRIO
			    | TMPF_SND_REM_ADDR | TMPF_SND_MPFAIL |
			    TMPF_MPCAP_RETRANSMIT);
			*p_mptcp_acknow = FALSE;
			mptcplog((LOG_DEBUG, "MPTCP Sender: %s: no action \n",
			    __func__), MPTCP_SENDER_DBG, MPTCP_LOGLVL_LOG);
		} else {
			mptcplog((LOG_DEBUG, "MPTCP Sender: acknow set, "
			    "old flags %x new flags %x \n",
			    old_mpt_flags, new_mpt_flags),
			    MPTCP_SENDER_DBG, MPTCP_LOGLVL_LOG);
		}
	}

	return optlen;
}

/*
 * MPTCP Options Input Processing
 */

static int
mptcp_sanitize_option(struct tcpcb *tp, int mptcp_subtype)
{
	struct mptcb *mp_tp = tptomptp(tp);
	int ret = 1;

	if (mp_tp == NULL) {
		mptcplog((LOG_ERR, "MPTCP Socket: %s: NULL mpsocket \n",
		    __func__), MPTCP_SOCKET_DBG, MPTCP_LOGLVL_ERR);
		return (0);
	}

	switch (mptcp_subtype) {
		case MPO_CAPABLE:
			break;
		case MPO_JOIN:		/* fall through */
		case MPO_DSS:		/* fall through */
		case MPO_FASTCLOSE:	/* fall through */
		case MPO_FAIL:		/* fall through */
		case MPO_REMOVE_ADDR:	/* fall through */
		case MPO_ADD_ADDR:	/* fall through */
		case MPO_PRIO:		/* fall through */
			if (mp_tp->mpt_state < MPTCPS_ESTABLISHED)
				ret = 0;
			break;
		default:
			ret = 0;
			mptcplog((LOG_ERR, "MPTCP Socket: "
			    "%s: type = %d \n", __func__,
			    mptcp_subtype),
			    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_ERR);
			break;
	}
	return (ret);
}

static int
mptcp_valid_mpcapable_common_opt(u_char *cp)
{
	struct mptcp_mpcapable_opt_common *rsp =
	    (struct mptcp_mpcapable_opt_common *)cp;

	/* mmco_kind, mmco_len and mmco_subtype are validated before */

	if (!(rsp->mmco_flags & MPCAP_PROPOSAL_SBIT))
		return (0);

	if (rsp->mmco_flags & (MPCAP_BBIT | MPCAP_CBIT | MPCAP_DBIT |
	    MPCAP_EBIT | MPCAP_FBIT | MPCAP_GBIT))
		return (0);

	return (1);
}


static void
mptcp_do_mpcapable_opt(struct tcpcb *tp, u_char *cp, struct tcphdr *th,
    int optlen)
{
	struct mptcp_mpcapable_opt_rsp *rsp = NULL;
	struct mptcb *mp_tp = tptomptp(tp);

	/* Only valid on SYN/ACK */
	if ((th->th_flags & (TH_SYN | TH_ACK)) != (TH_SYN | TH_ACK))
		return;

	/* Validate the kind, len, flags */
	if (mptcp_valid_mpcapable_common_opt(cp) != 1) {
		tcpstat.tcps_invalid_mpcap++;
		return;
	}

	/* Handle old duplicate SYN/ACK retransmission */
	if (SEQ_GT(tp->rcv_nxt, (tp->irs + 1)))
		return;

	/* handle SYN/ACK retransmission by acknowledging with ACK */
	if (mp_tp->mpt_state >= MPTCPS_ESTABLISHED) {
		tp->t_mpflags |= TMPF_MPCAP_RETRANSMIT;
		return;
	}

	/* A SYN/ACK contains peer's key and flags */
	if (optlen != sizeof (struct mptcp_mpcapable_opt_rsp)) {
		/* complain */
		mptcplog((LOG_ERR, "MPTCP Socket: "
		    "%s: SYN_ACK optlen = %d, sizeof mp opt = %lu \n",
		    __func__, optlen,
		    sizeof (struct mptcp_mpcapable_opt_rsp)),
		    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_ERR);
		tcpstat.tcps_invalid_mpcap++;
		return;
	}

	/*
	 * If checksum flag is set, enable MPTCP checksum, even if
	 * it was not negotiated on the first SYN.
	 */
	if (((struct mptcp_mpcapable_opt_common *)cp)->mmco_flags &
	    MPCAP_CHECKSUM_CBIT)
		mp_tp->mpt_flags |= MPTCPF_CHECKSUM;

	rsp = (struct mptcp_mpcapable_opt_rsp *)cp;
	MPT_LOCK(mp_tp);
	mp_tp->mpt_remotekey = rsp->mmc_localkey;
	/* For now just downgrade to the peer's version */
	mp_tp->mpt_peer_version = rsp->mmc_common.mmco_version;
	if (rsp->mmc_common.mmco_version < mp_tp->mpt_version) {
		mp_tp->mpt_version = rsp->mmc_common.mmco_version;
		tcpstat.tcps_mp_verdowngrade++;
	}
	if (mptcp_init_remote_parms(mp_tp) != 0) {
		tcpstat.tcps_invalid_mpcap++;
		MPT_UNLOCK(mp_tp);
		return;
	}
	MPT_UNLOCK(mp_tp);
	tcp_heuristic_mptcp_success(tp);
	tp->t_mpflags |= TMPF_PREESTABLISHED;
}


static void
mptcp_do_mpjoin_opt(struct tcpcb *tp, u_char *cp, struct tcphdr *th, int optlen)
{
#define	MPTCP_JOPT_ERROR_PATH(tp) {					\
	tp->t_mpflags |= TMPF_RESET;					\
	tcpstat.tcps_invalid_joins++;					\
	if (tp->t_inpcb->inp_socket != NULL) {				\
		soevent(tp->t_inpcb->inp_socket,			\
		    SO_FILT_HINT_LOCKED | SO_FILT_HINT_MUSTRST);	\
	}								\
}
	int error = 0;
	struct mptcp_mpjoin_opt_rsp *join_rsp =
	    (struct mptcp_mpjoin_opt_rsp *)cp;

	/* Only valid on SYN/ACK */
	if ((th->th_flags & (TH_SYN | TH_ACK)) != (TH_SYN | TH_ACK))
		return;

	if (optlen != sizeof (struct mptcp_mpjoin_opt_rsp)) {
		mptcplog((LOG_ERR, "MPTCP Socket: "
		    "SYN_ACK: unexpected optlen = %d mp "
		    "option = %lu\n", optlen,
		    sizeof (struct mptcp_mpjoin_opt_rsp)),
		    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_ERR);
		tp->t_mpflags &= ~TMPF_PREESTABLISHED;
		/* send RST and close */
		MPTCP_JOPT_ERROR_PATH(tp);
		return;
	}

	mptcp_set_raddr_rand(tp->t_local_aid, tptomptp(tp),
	    join_rsp->mmjo_addr_id, join_rsp->mmjo_rand);
	error = mptcp_validate_join_hmac(tp,
	    (u_char*)&join_rsp->mmjo_mac, SHA1_TRUNCATED);
	if (error) {
		mptcplog((LOG_ERR, "MPTCP Socket: %s: "
		    "SYN_ACK error = %d \n", __func__, error),
		    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_ERR);
		tp->t_mpflags &= ~TMPF_PREESTABLISHED;
		/* send RST and close */
		MPTCP_JOPT_ERROR_PATH(tp);
		return;
	}
	tp->t_mpflags |= TMPF_SENT_JOIN;
}

static int
mptcp_validate_join_hmac(struct tcpcb *tp, u_char* hmac, int mac_len)
{
	u_char digest[SHA1_RESULTLEN] = {0};
	struct mptcb *mp_tp = NULL;
	mptcp_key_t rem_key, loc_key;
	u_int32_t rem_rand, loc_rand;

	mp_tp = tp->t_mptcb;

	rem_rand = loc_rand = 0;

	MPT_LOCK(mp_tp);
	rem_key = mp_tp->mpt_remotekey;

	/*
	 * Can happen if the MPTCP-connection is about to be closed and we
	 * receive an MP_JOIN in-between the events are being handled by the
	 * worker thread.
	 */
	if (mp_tp->mpt_localkey == NULL) {
		MPT_UNLOCK(mp_tp);
		return (-1);
	}

	loc_key = *mp_tp->mpt_localkey;
	MPT_UNLOCK(mp_tp);

	mptcp_get_rands(tp->t_local_aid, mp_tp, &loc_rand, &rem_rand);
	if ((rem_rand == 0) || (loc_rand == 0))
		return (-1);

	mptcp_hmac_sha1(rem_key, loc_key, rem_rand, loc_rand,
	    digest, sizeof (digest));

	if (bcmp(digest, hmac, mac_len) == 0)
		return (0); /* matches */
	else {
		printf("%s: remote key %llx local key %llx remote rand %x "
		    "local rand %x \n", __func__, rem_key, loc_key,
		    rem_rand, loc_rand);
		return (-1);
	}
}

static void
mptcp_do_dss_opt_ack_meat(u_int64_t full_dack, struct tcpcb *tp)
{
	struct mptcb *mp_tp = tptomptp(tp);
	int close_notify = 0;

	tp->t_mpflags |= TMPF_RCVD_DACK;

	MPT_LOCK(mp_tp);
	if (MPTCP_SEQ_LEQ(full_dack, mp_tp->mpt_sndmax) &&
	    MPTCP_SEQ_GEQ(full_dack, mp_tp->mpt_snduna)) {
		mptcp_data_ack_rcvd(mp_tp, tp, full_dack);
		if (mp_tp->mpt_state > MPTCPS_FIN_WAIT_2)
			close_notify = 1;
		MPT_UNLOCK(mp_tp);
		if (mp_tp->mpt_flags & MPTCPF_RCVD_64BITACK) {
			mp_tp->mpt_flags &= ~MPTCPF_RCVD_64BITACK;
			mp_tp->mpt_flags &= ~MPTCPF_SND_64BITDSN;
		}
		mptcp_notify_mpready(tp->t_inpcb->inp_socket);
		if (close_notify)
			mptcp_notify_close(tp->t_inpcb->inp_socket);
	} else {
		MPT_UNLOCK(mp_tp);
		mptcplog((LOG_ERR,"MPTCP Socket: "
		    "%s: unexpected dack %llx snduna %llx "
		    "sndmax %llx\n", __func__, full_dack,
		    mp_tp->mpt_snduna, mp_tp->mpt_sndmax),
		    (MPTCP_SOCKET_DBG|MPTCP_RECEIVER_DBG),
		    MPTCP_LOGLVL_LOG);
	}
}

static void
mptcp_do_dss_opt_meat(u_char *cp, struct tcpcb *tp)
{
	struct mptcp_dss_copt *dss_rsp = (struct mptcp_dss_copt *)cp;
	u_int64_t full_dack = 0;
	struct mptcb *mp_tp = tptomptp(tp);
	int csum_len = 0;

#define	MPTCP_DSS_OPT_SZ_CHK(len, expected_len) {		\
	if (len != expected_len) {				\
		mptcplog((LOG_ERR, "MPTCP Socket: "		\
		    "%s: bad len = %d dss: %x \n", __func__,	\
		    len, dss_rsp->mdss_flags),			\
		    (MPTCP_SOCKET_DBG|MPTCP_RECEIVER_DBG),	\
		    MPTCP_LOGLVL_LOG);				\
		return;						\
	}							\
}

	/*
	 * mp_tp might become NULL after the call to mptcp_do_fin_opt().
	 * Review after rdar://problem/24083886
	 */
	if (!mp_tp)
		return;

	if (mp_tp->mpt_flags & MPTCPF_CHECKSUM)
		csum_len = 2;

	dss_rsp->mdss_flags &= (MDSS_A|MDSS_a|MDSS_M|MDSS_m);
	switch (dss_rsp->mdss_flags) {
		case (MDSS_M):
		{
			/* 32-bit DSS, No Data ACK */
			struct mptcp_dsn_opt *dss_rsp1;
			dss_rsp1 = (struct mptcp_dsn_opt *)cp;

			MPTCP_DSS_OPT_SZ_CHK(dss_rsp1->mdss_copt.mdss_len,
			    sizeof (struct mptcp_dsn_opt) + csum_len);
			if (csum_len == 0)
				mptcp_update_dss_rcv_state(dss_rsp1, tp, 0);
			else
				mptcp_update_dss_rcv_state(dss_rsp1, tp,
				    *(uint16_t *)(void *)(cp +
				    (dss_rsp1->mdss_copt.mdss_len - csum_len)));
			break;
		}
		case (MDSS_A):
		{
			/* 32-bit Data ACK, no DSS */
			struct mptcp_data_ack_opt *dack_opt;
			dack_opt = (struct mptcp_data_ack_opt *)cp;

			MPTCP_DSS_OPT_SZ_CHK(dack_opt->mdss_copt.mdss_len,
			    sizeof (struct mptcp_data_ack_opt));

			u_int32_t dack = dack_opt->mdss_ack;
			NTOHL(dack);
			MPT_LOCK_SPIN(mp_tp);
			MPTCP_EXTEND_DSN(mp_tp->mpt_snduna, dack, full_dack);
			MPT_UNLOCK(mp_tp);
			mptcp_do_dss_opt_ack_meat(full_dack, tp);
			break;
		}
		case (MDSS_M | MDSS_A):
		{
			/* 32-bit Data ACK + 32-bit DSS */
			struct mptcp_dss_ack_opt *dss_ack_rsp;
			dss_ack_rsp = (struct mptcp_dss_ack_opt *)cp;

			MPTCP_DSS_OPT_SZ_CHK(dss_ack_rsp->mdss_copt.mdss_len,
			    sizeof (struct mptcp_dss_ack_opt) + csum_len);

			u_int32_t dack = dss_ack_rsp->mdss_ack;
			NTOHL(dack);
			MPT_LOCK_SPIN(mp_tp);
			MPTCP_EXTEND_DSN(mp_tp->mpt_snduna, dack, full_dack);
			MPT_UNLOCK(mp_tp);
			mptcp_do_dss_opt_ack_meat(full_dack, tp);
			if (csum_len == 0)
				mptcp_update_rcv_state_f(dss_ack_rsp, tp, 0);
			else
				mptcp_update_rcv_state_f(dss_ack_rsp, tp,
				    *(uint16_t *)(void *)(cp +
				    (dss_ack_rsp->mdss_copt.mdss_len -
				    csum_len)));
			break;
		}
		case (MDSS_M | MDSS_m):
		{
			/* 64-bit DSS , No Data ACK */
			struct mptcp_dsn64_opt *dsn64;
			dsn64 = (struct mptcp_dsn64_opt *)cp;
			u_int64_t full_dsn;

			MPTCP_DSS_OPT_SZ_CHK(dsn64->mdss_copt.mdss_len,
			    sizeof (struct mptcp_dsn64_opt) + csum_len);

			mptcplog((LOG_DEBUG,"MPTCP Socket: "
			    "%s: 64-bit M present.\n", __func__),
			    (MPTCP_SOCKET_DBG|MPTCP_RECEIVER_DBG),
			    MPTCP_LOGLVL_LOG);

			MPT_LOCK_SPIN(mp_tp);
			mp_tp->mpt_flags |= MPTCPF_SND_64BITACK;
			MPT_UNLOCK(mp_tp);

			full_dsn = mptcp_ntoh64(dsn64->mdss_dsn);
			NTOHL(dsn64->mdss_subflow_seqn);
			NTOHS(dsn64->mdss_data_len);
			if (csum_len == 0)
				mptcp_update_rcv_state_meat(mp_tp, tp, full_dsn,
				    dsn64->mdss_subflow_seqn,
				    dsn64->mdss_data_len,
				    0);
			else
				mptcp_update_rcv_state_meat(mp_tp, tp, full_dsn,
				    dsn64->mdss_subflow_seqn,
				    dsn64->mdss_data_len,
				    *(uint16_t *)(void *)(cp +
				    dsn64->mdss_copt.mdss_len - csum_len));
			break;
		}
		case (MDSS_A | MDSS_a):
		{
			/* 64-bit Data ACK, no DSS */
			struct mptcp_data_ack64_opt *dack64;
			dack64 = (struct mptcp_data_ack64_opt *)cp;

			MPTCP_DSS_OPT_SZ_CHK(dack64->mdss_copt.mdss_len,
			    sizeof (struct mptcp_data_ack64_opt));

			mptcplog((LOG_DEBUG,"MPTCP Socket: "
			    "%s: 64-bit A present. \n", __func__),
			    (MPTCP_SOCKET_DBG|MPTCP_RECEIVER_DBG),
			    MPTCP_LOGLVL_LOG);

			MPT_LOCK_SPIN(mp_tp);
			mp_tp->mpt_flags |= MPTCPF_RCVD_64BITACK;
			MPT_UNLOCK(mp_tp);

			full_dack = mptcp_ntoh64(dack64->mdss_ack);
			mptcp_do_dss_opt_ack_meat(full_dack, tp);
			break;
		}
		case (MDSS_M | MDSS_m | MDSS_A):
		{
			/* 64-bit DSS + 32-bit Data ACK */
			struct mptcp_dss64_ack32_opt *dss_ack_rsp;
			dss_ack_rsp = (struct mptcp_dss64_ack32_opt *)cp;

			MPTCP_DSS_OPT_SZ_CHK(dss_ack_rsp->mdss_copt.mdss_len,
			    sizeof (struct mptcp_dss64_ack32_opt) + csum_len);

			mptcplog((LOG_DEBUG,"MPTCP Socket: "
			    "%s: 64-bit M and 32-bit A present.\n", __func__),
			    (MPTCP_SOCKET_DBG|MPTCP_RECEIVER_DBG),
			    MPTCP_LOGLVL_LOG);

			u_int32_t dack = dss_ack_rsp->mdss_ack;
			NTOHL(dack);
			MPT_LOCK_SPIN(mp_tp);
			mp_tp->mpt_flags |= MPTCPF_SND_64BITACK;
			MPTCP_EXTEND_DSN(mp_tp->mpt_snduna, dack, full_dack);
			MPT_UNLOCK(mp_tp);
			mptcp_do_dss_opt_ack_meat(full_dack, tp);
			if (csum_len == 0)
				mptcp_update_rcv_state_g(dss_ack_rsp, tp, 0);
			else
				mptcp_update_rcv_state_g(dss_ack_rsp, tp,
				    *(uint16_t *)(void *)(cp +
				    dss_ack_rsp->mdss_copt.mdss_len -
				    csum_len));
			break;
		}
		case (MDSS_M | MDSS_A | MDSS_a):
		{
			/* 32-bit DSS + 64-bit Data ACK */
			struct mptcp_dss32_ack64_opt *dss32_ack64_opt;
			dss32_ack64_opt = (struct mptcp_dss32_ack64_opt *)cp;
			u_int64_t full_dsn;

			MPTCP_DSS_OPT_SZ_CHK(
			    dss32_ack64_opt->mdss_copt.mdss_len,
			    sizeof (struct mptcp_dss32_ack64_opt) + csum_len);

			mptcplog((LOG_DEBUG,"MPTCP Socket: "
			    "%s: 32-bit M and 64-bit A present.\n", __func__),
			    (MPTCP_SOCKET_DBG|MPTCP_RECEIVER_DBG),
			    MPTCP_LOGLVL_LOG);

			full_dack = mptcp_ntoh64(dss32_ack64_opt->mdss_ack);
			mptcp_do_dss_opt_ack_meat(full_dack, tp);
			NTOHL(dss32_ack64_opt->mdss_dsn);
			MPT_LOCK_SPIN(mp_tp);
			mp_tp->mpt_flags |= MPTCPF_RCVD_64BITACK;
			MPTCP_EXTEND_DSN(mp_tp->mpt_rcvnxt,
				dss32_ack64_opt->mdss_dsn, full_dsn);
			MPT_UNLOCK(mp_tp);
			NTOHL(dss32_ack64_opt->mdss_subflow_seqn);
			NTOHS(dss32_ack64_opt->mdss_data_len);
			if (csum_len == 0)
				mptcp_update_rcv_state_meat(mp_tp, tp, full_dsn,
				    dss32_ack64_opt->mdss_subflow_seqn,
				    dss32_ack64_opt->mdss_data_len, 0);
			else
				mptcp_update_rcv_state_meat(mp_tp, tp, full_dsn,
				    dss32_ack64_opt->mdss_subflow_seqn,
				    dss32_ack64_opt->mdss_data_len,
				    *(uint16_t *)(void *)(cp +
				    dss32_ack64_opt->mdss_copt.mdss_len -
				    csum_len));
			break;
		}
		case (MDSS_M | MDSS_m | MDSS_A | MDSS_a):
		{
			/* 64-bit DSS + 64-bit Data ACK */
			struct mptcp_dss64_ack64_opt *dss64_ack64;
			dss64_ack64 = (struct mptcp_dss64_ack64_opt *)cp;
			u_int64_t full_dsn;

			MPTCP_DSS_OPT_SZ_CHK(dss64_ack64->mdss_copt.mdss_len,
			    sizeof (struct mptcp_dss64_ack64_opt) + csum_len);

			mptcplog((LOG_DEBUG,"MPTCP Socket: "
			    "%s: 64-bit M and 64-bit A present.\n", __func__),
			    (MPTCP_SOCKET_DBG|MPTCP_RECEIVER_DBG),
			    MPTCP_LOGLVL_LOG);

			MPT_LOCK_SPIN(mp_tp);
			mp_tp->mpt_flags |= MPTCPF_RCVD_64BITACK;
			mp_tp->mpt_flags |= MPTCPF_SND_64BITACK;
			MPT_UNLOCK(mp_tp);
			full_dsn = mptcp_ntoh64(dss64_ack64->mdss_dsn);
			full_dack = mptcp_ntoh64(dss64_ack64->mdss_dsn);
			mptcp_do_dss_opt_ack_meat(full_dack, tp);
			NTOHL(dss64_ack64->mdss_subflow_seqn);
			NTOHS(dss64_ack64->mdss_data_len);
			if (csum_len == 0)
				mptcp_update_rcv_state_meat(mp_tp, tp, full_dsn,
				    dss64_ack64->mdss_subflow_seqn,
				    dss64_ack64->mdss_data_len, 0);
			else
				mptcp_update_rcv_state_meat(mp_tp, tp, full_dsn,
				    dss64_ack64->mdss_subflow_seqn,
				    dss64_ack64->mdss_data_len,
				    *(uint16_t *)(void *)(cp +
				    dss64_ack64->mdss_copt.mdss_len -
				    csum_len));
			break;
		}
		default:
			mptcplog((LOG_DEBUG,"MPTCP Socket: "
			    "%s: File bug, DSS flags = %x\n", __func__,
			    dss_rsp->mdss_flags),
			    (MPTCP_SOCKET_DBG|MPTCP_RECEIVER_DBG),
			    MPTCP_LOGLVL_LOG);
			break;
	}
}


static void
mptcp_do_fin_opt(struct tcpcb *tp)
{
	struct mptcb *mp_tp = (struct mptcb *)tp->t_mptcb;

	mptcplog((LOG_DEBUG,"MPTCP Socket: %s \n", __func__),
	    (MPTCP_SOCKET_DBG|MPTCP_RECEIVER_DBG),
	    MPTCP_LOGLVL_LOG);

	if (!(tp->t_mpflags & TMPF_RECV_DFIN)) {
		if (mp_tp != NULL) {
			MPT_LOCK(mp_tp);
			mptcp_close_fsm(mp_tp, MPCE_RECV_DATA_FIN);
			MPT_UNLOCK(mp_tp);

			if (tp->t_inpcb->inp_socket != NULL) {
				soevent(tp->t_inpcb->inp_socket,
				    SO_FILT_HINT_LOCKED |
				    SO_FILT_HINT_MPCANTRCVMORE);
			}

		}
		tp->t_mpflags |= TMPF_RECV_DFIN;
	}

	tp->t_mpflags |= TMPF_MPTCP_ACKNOW;
	/*
	 * Since this is a data level FIN, TCP needs to be explicitly told
	 * to send back an ACK on which the Data ACK is piggybacked.
	 */
	tp->t_flags |= TF_ACKNOW;
}

static void
mptcp_do_dss_opt(struct tcpcb *tp, u_char *cp, struct tcphdr *th, int optlen)
{
#pragma unused(th, optlen)
	struct mptcb *mp_tp = (struct mptcb *)tp->t_mptcb;

	if (!mp_tp)
		return;

	/* We may get Data ACKs just during fallback, so don't ignore those */
	if ((tp->t_mpflags & TMPF_MPTCP_TRUE) ||
	    (tp->t_mpflags & TMPF_TCP_FALLBACK)) {
		struct mptcp_dss_copt *dss_rsp = (struct mptcp_dss_copt *)cp;

		if (dss_rsp->mdss_subtype == MPO_DSS) {
			if (dss_rsp->mdss_flags & MDSS_F) {
				mptcp_do_fin_opt(tp);
			}

			mptcp_do_dss_opt_meat(cp, tp);
		}
	}
}

static void
mptcp_do_fastclose_opt(struct tcpcb *tp, u_char *cp, struct tcphdr *th)
{
	struct mptcb *mp_tp = NULL;
	struct mptcp_fastclose_opt *fc_opt = (struct mptcp_fastclose_opt *)cp;

	if (th->th_flags != TH_ACK)
		return;

	mptcplog((LOG_DEBUG,"MPTCP Socket: %s: \n", __func__),
	    (MPTCP_SOCKET_DBG|MPTCP_RECEIVER_DBG),
	    MPTCP_LOGLVL_LOG);

	if (fc_opt->mfast_len != sizeof (struct mptcp_fastclose_opt)) {
		tcpstat.tcps_invalid_opt++;
		return;
	}

	mp_tp = (struct mptcb *)tp->t_mptcb;
	if (!mp_tp)
		return;

	if (fc_opt->mfast_key != mptcp_get_localkey(mp_tp)) {
		tcpstat.tcps_invalid_opt++;
		return;
	}

	/*
	 * fastclose could make us more vulnerable to attacks, hence
	 * accept only those that are at the next expected sequence number.
	 */
	if (th->th_seq != tp->rcv_nxt) {
		tcpstat.tcps_invalid_opt++;
		return;
	}

	/* Reset this flow */
	tp->t_mpflags |= (TMPF_RESET | TMPF_FASTCLOSERCV);

	if (tp->t_inpcb->inp_socket != NULL) {
		soevent(tp->t_inpcb->inp_socket,
		    SO_FILT_HINT_LOCKED | SO_FILT_HINT_MUSTRST);
	}
}


static void
mptcp_do_mpfail_opt(struct tcpcb *tp, u_char *cp, struct tcphdr *th)
{
	struct mptcb *mp_tp = NULL;
	struct mptcp_mpfail_opt *fail_opt = (struct mptcp_mpfail_opt *)cp;
	u_int32_t mdss_subflow_seqn = 0;
	int error = 0;

	/*
	 * mpfail could make us more vulnerable to attacks. Hence accept
	 * only those that are the next expected sequence number.
	 */
	if (th->th_seq != tp->rcv_nxt) {
		tcpstat.tcps_invalid_opt++;
		return;
	}

	/* A packet without RST, must atleast have the ACK bit set */
	if ((th->th_flags != TH_ACK) && (th->th_flags != TH_RST))
		return;

	mptcplog((LOG_DEBUG, "MPTCP Socket: %s: \n", __func__),
	    (MPTCP_SOCKET_DBG|MPTCP_RECEIVER_DBG), MPTCP_LOGLVL_LOG);

	if (fail_opt->mfail_len != sizeof (struct mptcp_mpfail_opt))
		return;

	mp_tp = (struct mptcb *)tp->t_mptcb;
	MPT_LOCK(mp_tp);
	mp_tp->mpt_flags |= MPTCPF_RECVD_MPFAIL;
	mp_tp->mpt_dsn_at_csum_fail = mptcp_hton64(fail_opt->mfail_dsn);
	MPT_UNLOCK(mp_tp);
	error = mptcp_get_map_for_dsn(tp->t_inpcb->inp_socket, 
	    mp_tp->mpt_dsn_at_csum_fail, &mdss_subflow_seqn);
	if (error == 0) {
		mp_tp->mpt_ssn_at_csum_fail = mdss_subflow_seqn;
	}

	mptcp_notify_mpfail(tp->t_inpcb->inp_socket);
}

void
tcp_do_mptcp_options(struct tcpcb *tp, u_char *cp, struct tcphdr *th,
    struct tcpopt *to, int optlen)
{
	int mptcp_subtype;

	/* All MPTCP options have atleast 4 bytes */
	if (optlen < 4)
		return;

	mptcp_subtype = (cp[2] >> 4);

	if (mptcp_sanitize_option(tp, mptcp_subtype) == 0)
		return;

	switch (mptcp_subtype) {
		case MPO_CAPABLE:
			mptcp_do_mpcapable_opt(tp, cp, th, optlen);
			break;
		case MPO_JOIN:
			mptcp_do_mpjoin_opt(tp, cp, th, optlen);
			break;
		case MPO_DSS:
			mptcp_do_dss_opt(tp, cp, th, optlen);
			break;
		case MPO_FASTCLOSE:
			mptcp_do_fastclose_opt(tp, cp, th);
			break;
		case MPO_FAIL:
			mptcp_do_mpfail_opt(tp, cp, th);
			break;
		case MPO_ADD_ADDR:	/* fall through */
		case MPO_REMOVE_ADDR:	/* fall through */
		case MPO_PRIO:
			to->to_flags |= TOF_MPTCP;
			break;
		default:
			break;
	}
	return;
}

/*
 * MPTCP ADD_ADDR and REMOVE_ADDR options
 */

/*
 * ADD_ADDR is only placeholder code - not sent on wire
 * The ADD_ADDR option is not sent on wire because of security issues
 * around connection hijacking.
 */
void
mptcp_send_addaddr_opt(struct tcpcb *tp, struct mptcp_addaddr_opt *opt)
{

	opt->ma_kind = TCPOPT_MULTIPATH;
	opt->ma_len = sizeof (struct mptcp_addaddr_opt);
	opt->ma_subtype = MPO_ADD_ADDR;
	opt->ma_addr_id = tp->t_local_aid;
#ifdef MPTCP_NOTYET
	struct inpcb *inp = tp->t_inpcb;
	if (inp->inp_vflag == AF_INET) {
		opt->ma_ipver = MA_IPVer_V4;
		bcopy((char *)&sin->sin_addr.s_addr, (char *)opt + opt->ma_len,
		    sizeof (in_addr_t));
		opt->ma_len += sizeof (in_addr_t);
	} else if (inp->inp_vflag == AF_INET6) {
		opt->ma_ipver = MA_IPVer_V6;
		bcopy((char *)&sin6->sin6_addr, (char *)opt + opt->ma_len,
		    sizeof (struct in6_addr));
		opt->ma_len += sizeof (struct in6_addr);
	}
#if 0
	if (tp->t_mp_port) {
		/* add ports XXX */
	}
#endif
#endif
}

/* REMOVE_ADDR option is sent when a source address goes away */
void
mptcp_send_remaddr_opt(struct tcpcb *tp, struct mptcp_remaddr_opt *opt)
{
	mptcplog((LOG_DEBUG,"MPTCP Socket: %s: local id %d remove id %d \n",
	    __func__, tp->t_local_aid, tp->t_rem_aid),
	    (MPTCP_SOCKET_DBG|MPTCP_SENDER_DBG), MPTCP_LOGLVL_LOG);

	bzero(opt, sizeof (*opt));
	opt->mr_kind = TCPOPT_MULTIPATH;
	opt->mr_len = sizeof (*opt);
	opt->mr_subtype = MPO_REMOVE_ADDR;
	opt->mr_addr_id = tp->t_rem_aid;
	tp->t_mpflags &= ~TMPF_SND_REM_ADDR;
}

/*
 * MPTCP MP_PRIO option
 */

#if 0
/*
 * Current implementation drops incoming MP_PRIO option and this code is
 * just a placeholder. The option is dropped because only the mobile client can
 * decide which of the subflows is preferred (usually wifi is preferred
 * over Cellular).
 */
void
mptcp_do_mpprio_opt(struct tcpcb *tp, u_char *cp, struct tcphdr *th,
    int optlen)
{
	int bkp = 0;
	struct mptcp_mpprio_opt *mpprio = (struct mptcp_mpprio_opt *)cp;

	if ((tp == NULL) || !(tp->t_mpflags & TMPF_MPTCP_TRUE))
		return;

	if ((mpprio->mpprio_len != sizeof (struct mptcp_mpprio_addr_opt)) &&
	    (mpprio->mpprio_len != sizeof (struct mptcp_mpprio_opt)))
		return;
}
#endif

/* We send MP_PRIO option based on the values set by the SIOCSCONNORDER ioctl */
static int
mptcp_snd_mpprio(struct tcpcb *tp, u_char *cp, int optlen)
{
	struct mptcp_mpprio_addr_opt mpprio;

	if (tp->t_state != TCPS_ESTABLISHED) {
		tp->t_mpflags &= ~TMPF_SND_MPPRIO;
		return (optlen);
	}

	if (mptcp_mpprio_enable != 1) {
		tp->t_mpflags &= ~TMPF_SND_MPPRIO;
		return (optlen);
	}

	if ((MAX_TCPOPTLEN - optlen) <
	    (int)sizeof (mpprio))
		return (optlen);

	bzero(&mpprio, sizeof (mpprio));
	mpprio.mpprio_kind = TCPOPT_MULTIPATH;
	mpprio.mpprio_len = sizeof (mpprio);
	mpprio.mpprio_subtype = MPO_PRIO;
	if (tp->t_mpflags & TMPF_BACKUP_PATH)
		mpprio.mpprio_flags |= MPTCP_MPPRIO_BKP;
	mpprio.mpprio_addrid = tp->t_local_aid;
	memcpy(cp + optlen, &mpprio, sizeof (mpprio));
	optlen += sizeof (mpprio);
	tp->t_mpflags &= ~TMPF_SND_MPPRIO;
	mptcplog((LOG_DEBUG, "MPTCP Socket: %s: aid = %d \n", __func__,
	    tp->t_local_aid), 
	    (MPTCP_SOCKET_DBG|MPTCP_SENDER_DBG), MPTCP_LOGLVL_LOG);
	return (optlen);
}
