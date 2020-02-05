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

static int mptcp_validate_join_hmac(struct tcpcb *, u_char*, int);
static int mptcp_snd_mpprio(struct tcpcb *tp, u_char *cp, int optlen);
static void mptcp_send_remaddr_opt(struct tcpcb *, struct mptcp_remaddr_opt *);

/*
 * MPTCP Options Output Processing
 */

static unsigned
mptcp_setup_first_subflow_syn_opts(struct socket *so, u_char *opt, unsigned optlen)
{
	struct mptcp_mpcapable_opt_common mptcp_opt;
	struct tcpcb *tp = sototcpcb(so);
	struct mptcb *mp_tp = tptomptp(tp);
	int ret;

	ret = tcp_heuristic_do_mptcp(tp);
	if (ret > 0) {
		os_log_info(mptcp_log_handle, "%s - %lx: Not doing MPTCP due to heuristics",
		    __func__, (unsigned long)VM_KERNEL_ADDRPERM(mp_tp->mpt_mpte));
		mp_tp->mpt_flags |= MPTCPF_FALLBACK_HEURISTIC;
		return optlen;
	}

	/*
	 * Avoid retransmitting the MP_CAPABLE option.
	 */
	if (ret == 0 &&
	    tp->t_rxtshift > mptcp_mpcap_retries &&
	    !(tptomptp(tp)->mpt_mpte->mpte_flags & MPTE_FORCE_ENABLE)) {
		if (!(mp_tp->mpt_flags & (MPTCPF_FALLBACK_HEURISTIC | MPTCPF_HEURISTIC_TRAC))) {
			mp_tp->mpt_flags |= MPTCPF_HEURISTIC_TRAC;
			tcp_heuristic_mptcp_loss(tp);
		}
		return optlen;
	}

	bzero(&mptcp_opt, sizeof(struct mptcp_mpcapable_opt_common));

	mptcp_opt.mmco_kind = TCPOPT_MULTIPATH;
	mptcp_opt.mmco_len =
	    sizeof(struct mptcp_mpcapable_opt_common) +
	    sizeof(mptcp_key_t);
	mptcp_opt.mmco_subtype = MPO_CAPABLE;
	mptcp_opt.mmco_version = mp_tp->mpt_version;
	mptcp_opt.mmco_flags |= MPCAP_PROPOSAL_SBIT;
	if (mp_tp->mpt_flags & MPTCPF_CHECKSUM) {
		mptcp_opt.mmco_flags |= MPCAP_CHECKSUM_CBIT;
	}
	memcpy(opt + optlen, &mptcp_opt, sizeof(struct mptcp_mpcapable_opt_common));
	optlen += sizeof(struct mptcp_mpcapable_opt_common);
	memcpy(opt + optlen, &mp_tp->mpt_localkey, sizeof(mptcp_key_t));
	optlen += sizeof(mptcp_key_t);

	return optlen;
}

static unsigned
mptcp_setup_join_subflow_syn_opts(struct socket *so, u_char *opt, unsigned optlen)
{
	struct mptcp_mpjoin_opt_req mpjoin_req;
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp = NULL;
	struct mptsub *mpts;

	if (!inp) {
		return optlen;
	}

	tp = intotcpcb(inp);
	if (!tp) {
		return optlen;
	}

	mpts = tp->t_mpsub;

	bzero(&mpjoin_req, sizeof(mpjoin_req));
	mpjoin_req.mmjo_kind = TCPOPT_MULTIPATH;
	mpjoin_req.mmjo_len = sizeof(mpjoin_req);
	mpjoin_req.mmjo_subtype_bkp = MPO_JOIN << 4;

	if (tp->t_mpflags & TMPF_BACKUP_PATH) {
		mpjoin_req.mmjo_subtype_bkp |= MPTCP_BACKUP;
	} else if (inp->inp_boundifp && IFNET_IS_CELLULAR(inp->inp_boundifp) &&
	    mpts->mpts_mpte->mpte_svctype < MPTCP_SVCTYPE_AGGREGATE) {
		mpjoin_req.mmjo_subtype_bkp |= MPTCP_BACKUP;
		tp->t_mpflags |= TMPF_BACKUP_PATH;
	} else {
		mpts->mpts_flags |= MPTSF_PREFERRED;
	}

	mpjoin_req.mmjo_addr_id = tp->t_local_aid;
	mpjoin_req.mmjo_peer_token = tptomptp(tp)->mpt_remotetoken;
	if (mpjoin_req.mmjo_peer_token == 0) {
		mptcplog((LOG_DEBUG, "%s: peer token 0", __func__),
		    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_ERR);
	}
	mptcp_get_rands(tp->t_local_aid, tptomptp(tp),
	    &mpjoin_req.mmjo_rand, NULL);
	memcpy(opt + optlen, &mpjoin_req, mpjoin_req.mmjo_len);
	optlen += mpjoin_req.mmjo_len;

	return optlen;
}

unsigned
mptcp_setup_join_ack_opts(struct tcpcb *tp, u_char *opt, unsigned optlen)
{
	unsigned new_optlen;
	struct mptcp_mpjoin_opt_rsp2 join_rsp2;

	if ((MAX_TCPOPTLEN - optlen) < sizeof(struct mptcp_mpjoin_opt_rsp2)) {
		printf("%s: no space left %d \n", __func__, optlen);
		return optlen;
	}

	bzero(&join_rsp2, sizeof(struct mptcp_mpjoin_opt_rsp2));
	join_rsp2.mmjo_kind = TCPOPT_MULTIPATH;
	join_rsp2.mmjo_len = sizeof(struct mptcp_mpjoin_opt_rsp2);
	join_rsp2.mmjo_subtype = MPO_JOIN;
	mptcp_get_hmac(tp->t_local_aid, tptomptp(tp),
	    (u_char*)&join_rsp2.mmjo_mac);
	memcpy(opt + optlen, &join_rsp2, join_rsp2.mmjo_len);
	new_optlen = optlen + join_rsp2.mmjo_len;
	return new_optlen;
}

unsigned
mptcp_setup_syn_opts(struct socket *so, u_char *opt, unsigned optlen)
{
	unsigned new_optlen;

	if (!(so->so_flags & SOF_MP_SEC_SUBFLOW)) {
		new_optlen = mptcp_setup_first_subflow_syn_opts(so, opt, optlen);
	} else {
		new_optlen = mptcp_setup_join_subflow_syn_opts(so, opt, optlen);
	}

	return new_optlen;
}

static int
mptcp_send_mpfail(struct tcpcb *tp, u_char *opt, unsigned int optlen)
{
#pragma unused(tp, opt, optlen)

	struct mptcb *mp_tp = NULL;
	struct mptcp_mpfail_opt fail_opt;
	uint64_t dsn;
	int len = sizeof(struct mptcp_mpfail_opt);

	mp_tp = tptomptp(tp);
	if (mp_tp == NULL) {
		tp->t_mpflags &= ~TMPF_SND_MPFAIL;
		return optlen;
	}

	/* if option space low give up */
	if ((MAX_TCPOPTLEN - optlen) < sizeof(struct mptcp_mpfail_opt)) {
		tp->t_mpflags &= ~TMPF_SND_MPFAIL;
		return optlen;
	}

	dsn = mp_tp->mpt_rcvnxt;

	bzero(&fail_opt, sizeof(fail_opt));
	fail_opt.mfail_kind = TCPOPT_MULTIPATH;
	fail_opt.mfail_len = len;
	fail_opt.mfail_subtype = MPO_FAIL;
	fail_opt.mfail_dsn = mptcp_hton64(dsn);
	memcpy(opt + optlen, &fail_opt, len);
	optlen += len;
	tp->t_mpflags &= ~TMPF_SND_MPFAIL;
	mptcplog((LOG_DEBUG, "%s: %d \n", __func__,
	    tp->t_local_aid), (MPTCP_SOCKET_DBG | MPTCP_SENDER_DBG),
	    MPTCP_LOGLVL_LOG);
	return optlen;
}

static int
mptcp_send_infinite_mapping(struct tcpcb *tp, u_char *opt, unsigned int optlen)
{
	struct mptcp_dsn_opt infin_opt;
	struct mptcb *mp_tp = NULL;
	size_t len = sizeof(struct mptcp_dsn_opt);
	struct socket *so = tp->t_inpcb->inp_socket;
	int csum_len = 0;

	if (!so) {
		return optlen;
	}

	mp_tp = tptomptp(tp);
	if (mp_tp == NULL) {
		return optlen;
	}

	if (mp_tp->mpt_flags & MPTCPF_CHECKSUM) {
		csum_len = 2;
	}

	/* try later */
	if ((MAX_TCPOPTLEN - optlen) < (len + csum_len)) {
		return optlen;
	}

	bzero(&infin_opt, sizeof(infin_opt));
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

			mptcplog((LOG_DEBUG, "%s: idsn %llu snduna %llu \n",
			    __func__, mp_tp->mpt_local_idsn,
			    mp_tp->mpt_snduna),
			    (MPTCP_SOCKET_DBG | MPTCP_SENDER_DBG),
			    MPTCP_LOGLVL_LOG);
		} else {
			infin_opt.mdss_subflow_seqn = tp->snd_una - tp->t_mpsub->mpts_iss;
		}
		infin_opt.mdss_dsn = (u_int32_t)
		    MPTCP_DATASEQ_LOW32(mp_tp->mpt_snduna);
	}

	if ((infin_opt.mdss_dsn == 0) || (infin_opt.mdss_subflow_seqn == 0)) {
		return optlen;
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

	mptcplog((LOG_DEBUG, "%s: dsn = %x, seq = %x len = %x\n", __func__,
	    ntohl(infin_opt.mdss_dsn),
	    ntohl(infin_opt.mdss_subflow_seqn),
	    ntohs(infin_opt.mdss_data_len)),
	    (MPTCP_SOCKET_DBG | MPTCP_SENDER_DBG),
	    MPTCP_LOGLVL_LOG);

	tp->t_mpflags |= TMPF_INFIN_SENT;
	tcpstat.tcps_estab_fallback++;
	return optlen;
}


static int
mptcp_ok_to_fin(struct tcpcb *tp, u_int64_t dsn, u_int32_t datalen)
{
	struct mptcb *mp_tp = tptomptp(tp);

	dsn = (mp_tp->mpt_sndmax & MPTCP_DATASEQ_LOW32_MASK) | dsn;
	if ((dsn + datalen) == mp_tp->mpt_sndmax) {
		return 1;
	}

	return 0;
}

unsigned int
mptcp_setup_opts(struct tcpcb *tp, int32_t off, u_char *opt,
    unsigned int optlen, int flags, int len,
    boolean_t *p_mptcp_acknow)
{
	struct inpcb *inp = (struct inpcb *)tp->t_inpcb;
	struct socket *so = inp->inp_socket;
	struct mptcb *mp_tp = tptomptp(tp);
	boolean_t do_csum = FALSE;
	boolean_t send_64bit_dsn = FALSE;
	boolean_t send_64bit_ack = FALSE;
	u_int32_t old_mpt_flags = tp->t_mpflags & TMPF_MPTCP_SIGNALS;

	if (mptcp_enable == 0 || mp_tp == NULL || tp->t_state == TCPS_CLOSED) {
		/* do nothing */
		goto ret_optlen;
	}

	socket_lock_assert_owned(mptetoso(mp_tp->mpt_mpte));

	if (mp_tp->mpt_flags & MPTCPF_CHECKSUM) {
		do_csum = TRUE;
	}

	/* tcp_output handles the SYN path separately */
	if (flags & TH_SYN) {
		goto ret_optlen;
	}

	if ((MAX_TCPOPTLEN - optlen) <
	    sizeof(struct mptcp_mpcapable_opt_common)) {
		mptcplog((LOG_ERR, "%s: no space left %d flags %x tp->t_mpflags %x len %d\n",
		    __func__, optlen, flags, tp->t_mpflags, len),
		    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_ERR);
		goto ret_optlen;
	}

	if (tp->t_mpflags & TMPF_TCP_FALLBACK) {
		if (tp->t_mpflags & TMPF_SND_MPFAIL) {
			optlen = mptcp_send_mpfail(tp, opt, optlen);
		} else if (!(tp->t_mpflags & TMPF_INFIN_SENT)) {
			optlen = mptcp_send_infinite_mapping(tp, opt, optlen);
		}
		goto ret_optlen;
	}

	if (tp->t_mpflags & TMPF_SND_KEYS) {
		struct mptcp_mpcapable_opt_rsp1 mptcp_opt;
		if ((MAX_TCPOPTLEN - optlen) <
		    sizeof(struct mptcp_mpcapable_opt_rsp1)) {
			goto ret_optlen;
		}
		bzero(&mptcp_opt, sizeof(struct mptcp_mpcapable_opt_rsp1));
		mptcp_opt.mmc_common.mmco_kind = TCPOPT_MULTIPATH;
		mptcp_opt.mmc_common.mmco_len =
		    sizeof(struct mptcp_mpcapable_opt_rsp1);
		mptcp_opt.mmc_common.mmco_subtype = MPO_CAPABLE;
		mptcp_opt.mmc_common.mmco_version = mp_tp->mpt_version;
		/* HMAC-SHA1 is the proposal */
		mptcp_opt.mmc_common.mmco_flags |= MPCAP_PROPOSAL_SBIT;
		if (mp_tp->mpt_flags & MPTCPF_CHECKSUM) {
			mptcp_opt.mmc_common.mmco_flags |= MPCAP_CHECKSUM_CBIT;
		}
		mptcp_opt.mmc_localkey = mp_tp->mpt_localkey;
		mptcp_opt.mmc_remotekey = mp_tp->mpt_remotekey;
		memcpy(opt + optlen, &mptcp_opt, mptcp_opt.mmc_common.mmco_len);
		optlen += mptcp_opt.mmc_common.mmco_len;
		tp->t_mpflags &= ~TMPF_SND_KEYS;

		if (!tp->t_mpuna) {
			tp->t_mpuna = tp->snd_una;
		} else {
			/* its a retransmission of the MP_CAPABLE ACK */
		}
		goto ret_optlen;
	}

	if (tp->t_mpflags & TMPF_SND_JACK) {
		/* Do the ACK part */
		optlen = mptcp_setup_join_ack_opts(tp, opt, optlen);
		if (!tp->t_mpuna) {
			tp->t_mpuna = tp->snd_una;
		}
		/* Start a timer to retransmit the ACK */
		tp->t_timer[TCPT_JACK_RXMT] =
		    OFFSET_FROM_START(tp, tcp_jack_rxmt);

		tp->t_mpflags &= ~TMPF_SND_JACK;
		goto ret_optlen;
	}

	if (!(tp->t_mpflags & TMPF_MPTCP_TRUE)) {
		goto ret_optlen;
	}
	/*
	 * From here on, all options are sent only if MPTCP_TRUE
	 * or when data is sent early on as in Fast Join
	 */

	if ((tp->t_mpflags & TMPF_MPTCP_TRUE) &&
	    (tp->t_mpflags & TMPF_SND_REM_ADDR)) {
		int rem_opt_len = sizeof(struct mptcp_remaddr_opt);
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

	if (mp_tp->mpt_flags & MPTCPF_SND_64BITDSN) {
		send_64bit_dsn = TRUE;
	}
	if (mp_tp->mpt_flags & MPTCPF_SND_64BITACK) {
		send_64bit_ack = TRUE;
	}

#define CHECK_OPTLEN    {                                                       \
	if ((MAX_TCPOPTLEN - optlen) < dssoptlen) {                             \
	        mptcplog((LOG_ERR, "%s: dssoptlen %d optlen %d \n", __func__,   \
	            dssoptlen, optlen),                                         \
	            MPTCP_SOCKET_DBG, MPTCP_LOGLVL_ERR);                        \
	        goto ret_optlen;                                                \
	}                                                                       \
}

#define DO_FIN(dsn_opt) {                                               \
	int sndfin = 0;                                                 \
	sndfin = mptcp_ok_to_fin(tp, dsn_opt.mdss_dsn, len);            \
	if (sndfin) {                                                   \
	        dsn_opt.mdss_copt.mdss_flags |= MDSS_F;                 \
	        dsn_opt.mdss_data_len += 1;                             \
	        if (do_csum)                                            \
	                dss_csum = in_addword(dss_csum, 1);             \
	}                                                               \
}

#define CHECK_DATALEN {                                                 \
	/* MPTCP socket does not support IP options */                  \
	if ((len + optlen + dssoptlen) > tp->t_maxopd) {                \
	        mptcplog((LOG_ERR, "%s: nosp %d len %d opt %d %d %d\n", \
	            __func__, len, dssoptlen, optlen,                   \
	            tp->t_maxseg, tp->t_maxopd),                        \
	            MPTCP_SOCKET_DBG, MPTCP_LOGLVL_ERR);                \
	/* remove option length from payload len */             \
	        len = tp->t_maxopd - optlen - dssoptlen;                \
	}                                                               \
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
		unsigned int dssoptlen = sizeof(dsn_ack_opt);
		uint16_t dss_csum;

		if (do_csum) {
			dssoptlen += 2;
		}

		CHECK_OPTLEN;

		bzero(&dsn_ack_opt, sizeof(dsn_ack_opt));
		dsn_ack_opt.mdss_copt.mdss_kind = TCPOPT_MULTIPATH;
		dsn_ack_opt.mdss_copt.mdss_subtype = MPO_DSS;
		dsn_ack_opt.mdss_copt.mdss_len = dssoptlen;
		dsn_ack_opt.mdss_copt.mdss_flags |=
		    MDSS_M | MDSS_m | MDSS_A;

		CHECK_DATALEN;

		mptcp_output_getm_dsnmap64(so, off,
		    &dsn_ack_opt.mdss_dsn,
		    &dsn_ack_opt.mdss_subflow_seqn,
		    &dsn_ack_opt.mdss_data_len,
		    &dss_csum);

		if ((dsn_ack_opt.mdss_data_len == 0) ||
		    (dsn_ack_opt.mdss_dsn == 0)) {
			goto ret_optlen;
		}

		if (tp->t_mpflags & TMPF_SEND_DFIN) {
			DO_FIN(dsn_ack_opt);
		}

		dsn_ack_opt.mdss_ack =
		    htonl(MPTCP_DATAACK_LOW32(mp_tp->mpt_rcvnxt));

		dsn_ack_opt.mdss_dsn = mptcp_hton64(dsn_ack_opt.mdss_dsn);
		dsn_ack_opt.mdss_subflow_seqn = htonl(
			dsn_ack_opt.mdss_subflow_seqn);
		dsn_ack_opt.mdss_data_len = htons(
			dsn_ack_opt.mdss_data_len);

		memcpy(opt + optlen, &dsn_ack_opt, sizeof(dsn_ack_opt));
		if (do_csum) {
			*((uint16_t *)(void *)(opt + optlen + sizeof(dsn_ack_opt))) = dss_csum;
		}

		optlen += dssoptlen;
		mptcplog((LOG_DEBUG, "%s: long DSS = %llx ACK = %llx \n", __func__,
		    mptcp_ntoh64(dsn_ack_opt.mdss_dsn),
		    mptcp_ntoh64(dsn_ack_opt.mdss_ack)),
		    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_LOG);

		tp->t_mpflags &= ~TMPF_MPTCP_ACKNOW;
		goto ret_optlen;
	}

	if ((tp->t_mpflags & TMPF_SEND_DSN) &&
	    (!send_64bit_dsn) &&
	    !(tp->t_mpflags & TMPF_MPTCP_ACKNOW)) {
		struct mptcp_dsn_opt dsn_opt;
		unsigned int dssoptlen = sizeof(struct mptcp_dsn_opt);
		uint16_t dss_csum;

		if (do_csum) {
			dssoptlen += 2;
		}

		CHECK_OPTLEN;

		bzero(&dsn_opt, sizeof(dsn_opt));
		dsn_opt.mdss_copt.mdss_kind = TCPOPT_MULTIPATH;
		dsn_opt.mdss_copt.mdss_subtype = MPO_DSS;
		dsn_opt.mdss_copt.mdss_len = dssoptlen;
		dsn_opt.mdss_copt.mdss_flags |= MDSS_M;

		CHECK_DATALEN;

		mptcp_output_getm_dsnmap32(so, off, &dsn_opt.mdss_dsn,
		    &dsn_opt.mdss_subflow_seqn,
		    &dsn_opt.mdss_data_len,
		    &dss_csum);

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
		memcpy(opt + optlen, &dsn_opt, sizeof(dsn_opt));
		if (do_csum) {
			*((uint16_t *)(void *)(opt + optlen + sizeof(dsn_opt))) = dss_csum;
		}

		optlen += dssoptlen;
		tp->t_mpflags &= ~TMPF_MPTCP_ACKNOW;
		goto ret_optlen;
	}

	/* 32-bit Data ACK option */
	if ((tp->t_mpflags & TMPF_MPTCP_ACKNOW) &&
	    (!send_64bit_ack) &&
	    !(tp->t_mpflags & TMPF_SEND_DSN) &&
	    !(tp->t_mpflags & TMPF_SEND_DFIN)) {
		struct mptcp_data_ack_opt dack_opt;
		unsigned int dssoptlen = 0;
do_ack32_only:
		dssoptlen = sizeof(dack_opt);

		CHECK_OPTLEN;

		bzero(&dack_opt, dssoptlen);
		dack_opt.mdss_copt.mdss_kind = TCPOPT_MULTIPATH;
		dack_opt.mdss_copt.mdss_len = dssoptlen;
		dack_opt.mdss_copt.mdss_subtype = MPO_DSS;
		dack_opt.mdss_copt.mdss_flags |= MDSS_A;
		dack_opt.mdss_ack =
		    htonl(MPTCP_DATAACK_LOW32(mp_tp->mpt_rcvnxt));
		memcpy(opt + optlen, &dack_opt, dssoptlen);
		optlen += dssoptlen;
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
		unsigned int dssoptlen = 0;
do_ack64_only:
		dssoptlen = sizeof(dack_opt);

		CHECK_OPTLEN;

		bzero(&dack_opt, dssoptlen);
		dack_opt.mdss_copt.mdss_kind = TCPOPT_MULTIPATH;
		dack_opt.mdss_copt.mdss_len = dssoptlen;
		dack_opt.mdss_copt.mdss_subtype = MPO_DSS;
		dack_opt.mdss_copt.mdss_flags |= (MDSS_A | MDSS_a);
		dack_opt.mdss_ack = mptcp_hton64(mp_tp->mpt_rcvnxt);
		/*
		 * The other end should retransmit 64-bit DSN until it
		 * receives a 64-bit ACK.
		 */
		mp_tp->mpt_flags &= ~MPTCPF_SND_64BITACK;
		memcpy(opt + optlen, &dack_opt, dssoptlen);
		optlen += dssoptlen;
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
		unsigned int dssoptlen = sizeof(dss_ack_opt);
		uint16_t dss_csum;

		if (do_csum) {
			dssoptlen += 2;
		}

		CHECK_OPTLEN;

		bzero(&dss_ack_opt, sizeof(dss_ack_opt));
		dss_ack_opt.mdss_copt.mdss_kind = TCPOPT_MULTIPATH;
		dss_ack_opt.mdss_copt.mdss_len = dssoptlen;
		dss_ack_opt.mdss_copt.mdss_subtype = MPO_DSS;
		dss_ack_opt.mdss_copt.mdss_flags |= MDSS_A | MDSS_M;
		dss_ack_opt.mdss_ack =
		    htonl(MPTCP_DATAACK_LOW32(mp_tp->mpt_rcvnxt));

		CHECK_DATALEN;

		mptcp_output_getm_dsnmap32(so, off, &dss_ack_opt.mdss_dsn,
		    &dss_ack_opt.mdss_subflow_seqn,
		    &dss_ack_opt.mdss_data_len,
		    &dss_csum);

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
		memcpy(opt + optlen, &dss_ack_opt, sizeof(dss_ack_opt));
		if (do_csum) {
			*((uint16_t *)(void *)(opt + optlen + sizeof(dss_ack_opt))) = dss_csum;
		}

		optlen += dssoptlen;

		if (optlen > MAX_TCPOPTLEN) {
			panic("optlen too large");
		}
		tp->t_mpflags &= ~TMPF_MPTCP_ACKNOW;
		goto ret_optlen;
	}

	/* 32-bit DSS + 64-bit DACK option */
	if ((tp->t_mpflags & TMPF_SEND_DSN) &&
	    (!send_64bit_dsn) &&
	    (send_64bit_ack) &&
	    (tp->t_mpflags & TMPF_MPTCP_ACKNOW)) {
		struct mptcp_dss32_ack64_opt dss_ack_opt;
		unsigned int dssoptlen = sizeof(dss_ack_opt);
		uint16_t dss_csum;

		if (do_csum) {
			dssoptlen += 2;
		}

		CHECK_OPTLEN;

		bzero(&dss_ack_opt, sizeof(dss_ack_opt));
		dss_ack_opt.mdss_copt.mdss_kind = TCPOPT_MULTIPATH;
		dss_ack_opt.mdss_copt.mdss_len = dssoptlen;
		dss_ack_opt.mdss_copt.mdss_subtype = MPO_DSS;
		dss_ack_opt.mdss_copt.mdss_flags |= MDSS_M | MDSS_A | MDSS_a;
		dss_ack_opt.mdss_ack =
		    mptcp_hton64(mp_tp->mpt_rcvnxt);

		CHECK_DATALEN;

		mptcp_output_getm_dsnmap32(so, off, &dss_ack_opt.mdss_dsn,
		    &dss_ack_opt.mdss_subflow_seqn,
		    &dss_ack_opt.mdss_data_len,
		    &dss_csum);

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
		memcpy(opt + optlen, &dss_ack_opt, sizeof(dss_ack_opt));
		if (do_csum) {
			*((uint16_t *)(void *)(opt + optlen + sizeof(dss_ack_opt))) = dss_csum;
		}

		optlen += dssoptlen;

		if (optlen > MAX_TCPOPTLEN) {
			panic("optlen too large");
		}
		tp->t_mpflags &= ~TMPF_MPTCP_ACKNOW;
		goto ret_optlen;
	}

	if (tp->t_mpflags & TMPF_SEND_DFIN) {
		unsigned int dssoptlen = sizeof(struct mptcp_dss_ack_opt);
		struct mptcp_dss_ack_opt dss_ack_opt;
		uint16_t dss_csum;

		if (do_csum) {
			uint64_t dss_val = mptcp_hton64(mp_tp->mpt_sndmax - 1);
			uint16_t dlen = htons(1);
			uint32_t sseq = 0;
			uint32_t sum;


			dssoptlen += 2;

			sum = in_pseudo64(dss_val, sseq, dlen);
			ADDCARRY(sum);
			dss_csum = ~sum & 0xffff;
		}

		CHECK_OPTLEN;

		bzero(&dss_ack_opt, sizeof(dss_ack_opt));

		/*
		 * Data FIN occupies one sequence space.
		 * Don't send it if it has been Acked.
		 */
		if ((mp_tp->mpt_sndnxt + 1 != mp_tp->mpt_sndmax) ||
		    (mp_tp->mpt_snduna == mp_tp->mpt_sndmax)) {
			goto ret_optlen;
		}

		dss_ack_opt.mdss_copt.mdss_kind = TCPOPT_MULTIPATH;
		dss_ack_opt.mdss_copt.mdss_len = dssoptlen;
		dss_ack_opt.mdss_copt.mdss_subtype = MPO_DSS;
		dss_ack_opt.mdss_copt.mdss_flags |= MDSS_A | MDSS_M | MDSS_F;
		dss_ack_opt.mdss_ack =
		    htonl(MPTCP_DATAACK_LOW32(mp_tp->mpt_rcvnxt));
		dss_ack_opt.mdss_dsn =
		    htonl(MPTCP_DATASEQ_LOW32(mp_tp->mpt_sndmax - 1));
		dss_ack_opt.mdss_subflow_seqn = 0;
		dss_ack_opt.mdss_data_len = 1;
		dss_ack_opt.mdss_data_len = htons(dss_ack_opt.mdss_data_len);
		memcpy(opt + optlen, &dss_ack_opt, sizeof(dss_ack_opt));
		if (do_csum) {
			*((uint16_t *)(void *)(opt + optlen + sizeof(dss_ack_opt))) = dss_csum;
		}

		optlen += dssoptlen;
	}

ret_optlen:
	if (TRUE == *p_mptcp_acknow) {
		VERIFY(old_mpt_flags != 0);
		u_int32_t new_mpt_flags = tp->t_mpflags & TMPF_MPTCP_SIGNALS;

		/*
		 * If none of the above mpflags were acted on by
		 * this routine, reset these flags and set p_mptcp_acknow
		 * to false.
		 *
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
		if (old_mpt_flags == new_mpt_flags) {
			tp->t_mpflags &= ~TMPF_MPTCP_SIGNALS;
			*p_mptcp_acknow = FALSE;
			mptcplog((LOG_DEBUG, "%s: no action \n", __func__),
			    MPTCP_SENDER_DBG, MPTCP_LOGLVL_LOG);
		} else {
			mptcplog((LOG_DEBUG, "%s: acknow set, old flags %x new flags %x \n",
			    __func__, old_mpt_flags, new_mpt_flags),
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

	switch (mptcp_subtype) {
	case MPO_CAPABLE:
		break;
	case MPO_JOIN:                  /* fall through */
	case MPO_DSS:                   /* fall through */
	case MPO_FASTCLOSE:             /* fall through */
	case MPO_FAIL:                  /* fall through */
	case MPO_REMOVE_ADDR:           /* fall through */
	case MPO_ADD_ADDR:              /* fall through */
	case MPO_PRIO:                  /* fall through */
		if (mp_tp->mpt_state < MPTCPS_ESTABLISHED) {
			ret = 0;
		}
		break;
	default:
		ret = 0;
		os_log_error(mptcp_log_handle, "%s - %lx: type = %d \n", __func__,
		    (unsigned long)VM_KERNEL_ADDRPERM(mp_tp->mpt_mpte), mptcp_subtype);
		break;
	}
	return ret;
}

static int
mptcp_valid_mpcapable_common_opt(u_char *cp)
{
	struct mptcp_mpcapable_opt_common *rsp =
	    (struct mptcp_mpcapable_opt_common *)cp;

	/* mmco_kind, mmco_len and mmco_subtype are validated before */

	if (!(rsp->mmco_flags & MPCAP_PROPOSAL_SBIT)) {
		return 0;
	}

	if (rsp->mmco_flags & (MPCAP_BBIT | MPCAP_DBIT |
	    MPCAP_EBIT | MPCAP_FBIT | MPCAP_GBIT)) {
		return 0;
	}

	return 1;
}


static void
mptcp_do_mpcapable_opt(struct tcpcb *tp, u_char *cp, struct tcphdr *th,
    int optlen)
{
	struct mptcp_mpcapable_opt_rsp *rsp = NULL;
	struct mptcb *mp_tp = tptomptp(tp);
	struct mptses *mpte = mp_tp->mpt_mpte;

	/* Only valid on SYN/ACK */
	if ((th->th_flags & (TH_SYN | TH_ACK)) != (TH_SYN | TH_ACK)) {
		return;
	}

	/* Validate the kind, len, flags */
	if (mptcp_valid_mpcapable_common_opt(cp) != 1) {
		tcpstat.tcps_invalid_mpcap++;
		return;
	}

	/* handle SYN/ACK retransmission by acknowledging with ACK */
	if (mp_tp->mpt_state >= MPTCPS_ESTABLISHED) {
		return;
	}

	/* A SYN/ACK contains peer's key and flags */
	if (optlen != sizeof(struct mptcp_mpcapable_opt_rsp)) {
		/* complain */
		os_log_error(mptcp_log_handle, "%s - %lx: SYN_ACK optlen = %d, sizeof mp opt = %lu \n",
		    __func__, (unsigned long)VM_KERNEL_ADDRPERM(mpte), optlen,
		    sizeof(struct mptcp_mpcapable_opt_rsp));
		tcpstat.tcps_invalid_mpcap++;
		return;
	}

	/*
	 * If checksum flag is set, enable MPTCP checksum, even if
	 * it was not negotiated on the first SYN.
	 */
	if (((struct mptcp_mpcapable_opt_common *)cp)->mmco_flags &
	    MPCAP_CHECKSUM_CBIT) {
		mp_tp->mpt_flags |= MPTCPF_CHECKSUM;
	}

	if (((struct mptcp_mpcapable_opt_common *)cp)->mmco_flags &
	    MPCAP_UNICAST_IPBIT) {
		mpte->mpte_flags |= MPTE_UNICAST_IP;
	}

	rsp = (struct mptcp_mpcapable_opt_rsp *)cp;
	mp_tp->mpt_remotekey = rsp->mmc_localkey;
	/* For now just downgrade to the peer's version */
	mp_tp->mpt_peer_version = rsp->mmc_common.mmco_version;
	if (rsp->mmc_common.mmco_version < mp_tp->mpt_version) {
		mp_tp->mpt_version = rsp->mmc_common.mmco_version;
		tcpstat.tcps_mp_verdowngrade++;
	}
	if (mptcp_init_remote_parms(mp_tp) != 0) {
		tcpstat.tcps_invalid_mpcap++;
		return;
	}
	tcp_heuristic_mptcp_success(tp);
	tp->t_mpflags |= (TMPF_SND_KEYS | TMPF_MPTCP_TRUE);
}


static void
mptcp_do_mpjoin_opt(struct tcpcb *tp, u_char *cp, struct tcphdr *th, int optlen)
{
#define MPTCP_JOPT_ERROR_PATH(tp) {                                     \
	tcpstat.tcps_invalid_joins++;                                   \
	if (tp->t_inpcb->inp_socket != NULL) {                          \
	        soevent(tp->t_inpcb->inp_socket,                        \
	            SO_FILT_HINT_LOCKED | SO_FILT_HINT_MUSTRST);        \
	}                                                               \
}
	int error = 0;
	struct mptcp_mpjoin_opt_rsp *join_rsp =
	    (struct mptcp_mpjoin_opt_rsp *)cp;

	/* Only valid on SYN/ACK */
	if ((th->th_flags & (TH_SYN | TH_ACK)) != (TH_SYN | TH_ACK)) {
		return;
	}

	if (optlen != sizeof(struct mptcp_mpjoin_opt_rsp)) {
		os_log_error(mptcp_log_handle, "%s - %lx: SYN_ACK: unexpected optlen = %d mp option = %lu\n",
		    __func__, (unsigned long)VM_KERNEL_ADDRPERM(tptomptp(tp)->mpt_mpte),
		    optlen, sizeof(struct mptcp_mpjoin_opt_rsp));
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
		os_log_error(mptcp_log_handle, "%s - %lx: SYN_ACK error = %d \n",
		    __func__, (unsigned long)VM_KERNEL_ADDRPERM(tptomptp(tp)->mpt_mpte),
		    error);
		tp->t_mpflags &= ~TMPF_PREESTABLISHED;
		/* send RST and close */
		MPTCP_JOPT_ERROR_PATH(tp);
		return;
	}
	tp->t_mpflags |= (TMPF_SENT_JOIN | TMPF_SND_JACK);
}

static int
mptcp_validate_join_hmac(struct tcpcb *tp, u_char* hmac, int mac_len)
{
	u_char digest[SHA1_RESULTLEN] = {0};
	struct mptcb *mp_tp = tptomptp(tp);
	u_int32_t rem_rand, loc_rand;

	rem_rand = loc_rand = 0;

	mptcp_get_rands(tp->t_local_aid, mp_tp, &loc_rand, &rem_rand);
	if ((rem_rand == 0) || (loc_rand == 0)) {
		return -1;
	}

	mptcp_hmac_sha1(mp_tp->mpt_remotekey, mp_tp->mpt_localkey, rem_rand, loc_rand,
	    digest);

	if (bcmp(digest, hmac, mac_len) == 0) {
		return 0; /* matches */
	} else {
		printf("%s: remote key %llx local key %llx remote rand %x "
		    "local rand %x \n", __func__, mp_tp->mpt_remotekey, mp_tp->mpt_localkey,
		    rem_rand, loc_rand);
		return -1;
	}
}

/*
 * Update the mptcb send state variables, but the actual sbdrop occurs
 * in MPTCP layer
 */
void
mptcp_data_ack_rcvd(struct mptcb *mp_tp, struct tcpcb *tp, u_int64_t full_dack)
{
	uint64_t acked = full_dack - mp_tp->mpt_snduna;

	if (acked) {
		struct socket *mp_so = mptetoso(mp_tp->mpt_mpte);

		if (acked > mp_so->so_snd.sb_cc) {
			if (acked > mp_so->so_snd.sb_cc + 1 ||
			    mp_tp->mpt_state < MPTCPS_FIN_WAIT_1) {
				os_log_error(mptcp_log_handle, "%s - %lx: acked %u, sb_cc %u full %u suna %u state %u\n",
				    __func__, (unsigned long)VM_KERNEL_ADDRPERM(mp_tp->mpt_mpte),
				    (uint32_t)acked, mp_so->so_snd.sb_cc,
				    (uint32_t)full_dack, (uint32_t)mp_tp->mpt_snduna,
				    mp_tp->mpt_state);
			}

			sbdrop(&mp_so->so_snd, (int)mp_so->so_snd.sb_cc);
		} else {
			sbdrop(&mp_so->so_snd, acked);
		}

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

		mptcp_clean_reinjectq(mp_tp->mpt_mpte);

		sowwakeup(mp_so);
	}
	if (full_dack == mp_tp->mpt_sndmax &&
	    mp_tp->mpt_state >= MPTCPS_FIN_WAIT_1) {
		mptcp_close_fsm(mp_tp, MPCE_RECV_DATA_ACK);
		tp->t_mpflags &= ~TMPF_SEND_DFIN;
	}
}

void
mptcp_update_window_wakeup(struct tcpcb *tp)
{
	struct mptcb *mp_tp = tptomptp(tp);

	socket_lock_assert_owned(mptetoso(mp_tp->mpt_mpte));

	if (mp_tp->mpt_flags & MPTCPF_FALLBACK_TO_TCP) {
		mp_tp->mpt_sndwnd = tp->snd_wnd;
		mp_tp->mpt_sndwl1 = mp_tp->mpt_rcvnxt;
		mp_tp->mpt_sndwl2 = mp_tp->mpt_snduna;
	}

	sowwakeup(tp->t_inpcb->inp_socket);
}

static void
mptcp_update_window(struct mptcb *mp_tp, u_int64_t ack, u_int64_t seq, u_int32_t tiwin)
{
	if (MPTCP_SEQ_LT(mp_tp->mpt_sndwl1, seq) ||
	    (mp_tp->mpt_sndwl1 == seq &&
	    (MPTCP_SEQ_LT(mp_tp->mpt_sndwl2, ack) ||
	    (mp_tp->mpt_sndwl2 == ack && tiwin > mp_tp->mpt_sndwnd)))) {
		mp_tp->mpt_sndwnd = tiwin;
		mp_tp->mpt_sndwl1 = seq;
		mp_tp->mpt_sndwl2 = ack;
	}
}

static void
mptcp_do_dss_opt_ack_meat(u_int64_t full_dack, u_int64_t full_dsn,
    struct tcpcb *tp, u_int32_t tiwin)
{
	struct mptcb *mp_tp = tptomptp(tp);
	int close_notify = 0;

	tp->t_mpflags |= TMPF_RCVD_DACK;

	if (MPTCP_SEQ_LEQ(full_dack, mp_tp->mpt_sndmax) &&
	    MPTCP_SEQ_GEQ(full_dack, mp_tp->mpt_snduna)) {
		mptcp_data_ack_rcvd(mp_tp, tp, full_dack);
		if (mp_tp->mpt_state > MPTCPS_FIN_WAIT_2) {
			close_notify = 1;
		}
		if (mp_tp->mpt_flags & MPTCPF_RCVD_64BITACK) {
			mp_tp->mpt_flags &= ~MPTCPF_RCVD_64BITACK;
			mp_tp->mpt_flags &= ~MPTCPF_SND_64BITDSN;
		}
		mptcp_notify_mpready(tp->t_inpcb->inp_socket);
		if (close_notify) {
			mptcp_notify_close(tp->t_inpcb->inp_socket);
		}
	}

	mptcp_update_window(mp_tp, full_dack, full_dsn, tiwin);
}

static void
mptcp_do_dss_opt_meat(u_char *cp, struct tcpcb *tp, struct tcphdr *th)
{
	struct mptcp_dss_copt *dss_rsp = (struct mptcp_dss_copt *)cp;
	u_int64_t full_dack = 0;
	u_int32_t tiwin = th->th_win << tp->snd_scale;
	struct mptcb *mp_tp = tptomptp(tp);
	int csum_len = 0;

#define MPTCP_DSS_OPT_SZ_CHK(len, expected_len) {                               \
	if (len != expected_len) {                                              \
	        mptcplog((LOG_ERR, "%s: bad len = %d dss: %x \n", __func__,     \
	            len, dss_rsp->mdss_flags),                                  \
	            (MPTCP_SOCKET_DBG|MPTCP_RECEIVER_DBG),                      \
	            MPTCP_LOGLVL_LOG);                                          \
	        return;                                                         \
	}                                                                       \
}

	if (mp_tp->mpt_flags & MPTCPF_CHECKSUM) {
		csum_len = 2;
	}

	dss_rsp->mdss_flags &= (MDSS_A | MDSS_a | MDSS_M | MDSS_m);
	switch (dss_rsp->mdss_flags) {
	case (MDSS_M):
	{
		/* 32-bit DSS, No Data ACK */
		struct mptcp_dsn_opt *dss_rsp1;
		dss_rsp1 = (struct mptcp_dsn_opt *)cp;

		MPTCP_DSS_OPT_SZ_CHK(dss_rsp1->mdss_copt.mdss_len,
		    sizeof(struct mptcp_dsn_opt) + csum_len);
		if (csum_len == 0) {
			mptcp_update_dss_rcv_state(dss_rsp1, tp, 0);
		} else {
			mptcp_update_dss_rcv_state(dss_rsp1, tp,
			    *(uint16_t *)(void *)(cp +
			    (dss_rsp1->mdss_copt.mdss_len - csum_len)));
		}
		break;
	}
	case (MDSS_A):
	{
		/* 32-bit Data ACK, no DSS */
		struct mptcp_data_ack_opt *dack_opt;
		dack_opt = (struct mptcp_data_ack_opt *)cp;

		MPTCP_DSS_OPT_SZ_CHK(dack_opt->mdss_copt.mdss_len,
		    sizeof(struct mptcp_data_ack_opt));

		u_int32_t dack = dack_opt->mdss_ack;
		NTOHL(dack);
		MPTCP_EXTEND_DSN(mp_tp->mpt_snduna, dack, full_dack);
		mptcp_do_dss_opt_ack_meat(full_dack, mp_tp->mpt_sndwl1, tp, tiwin);
		break;
	}
	case (MDSS_M | MDSS_A):
	{
		/* 32-bit Data ACK + 32-bit DSS */
		struct mptcp_dss_ack_opt *dss_ack_rsp;
		dss_ack_rsp = (struct mptcp_dss_ack_opt *)cp;
		u_int64_t full_dsn;
		uint16_t csum = 0;

		MPTCP_DSS_OPT_SZ_CHK(dss_ack_rsp->mdss_copt.mdss_len,
		    sizeof(struct mptcp_dss_ack_opt) + csum_len);

		u_int32_t dack = dss_ack_rsp->mdss_ack;
		NTOHL(dack);
		MPTCP_EXTEND_DSN(mp_tp->mpt_snduna, dack, full_dack);

		NTOHL(dss_ack_rsp->mdss_dsn);
		NTOHL(dss_ack_rsp->mdss_subflow_seqn);
		NTOHS(dss_ack_rsp->mdss_data_len);
		MPTCP_EXTEND_DSN(mp_tp->mpt_rcvnxt, dss_ack_rsp->mdss_dsn, full_dsn);

		mptcp_do_dss_opt_ack_meat(full_dack, full_dsn, tp, tiwin);

		if (csum_len != 0) {
			csum = *(uint16_t *)(void *)(cp + (dss_ack_rsp->mdss_copt.mdss_len - csum_len));
		}

		mptcp_update_rcv_state_meat(mp_tp, tp,
		    full_dsn,
		    dss_ack_rsp->mdss_subflow_seqn,
		    dss_ack_rsp->mdss_data_len,
		    csum);
		break;
	}
	case (MDSS_M | MDSS_m):
	{
		/* 64-bit DSS , No Data ACK */
		struct mptcp_dsn64_opt *dsn64;
		dsn64 = (struct mptcp_dsn64_opt *)cp;
		u_int64_t full_dsn;
		uint16_t csum = 0;

		MPTCP_DSS_OPT_SZ_CHK(dsn64->mdss_copt.mdss_len,
		    sizeof(struct mptcp_dsn64_opt) + csum_len);

		mp_tp->mpt_flags |= MPTCPF_SND_64BITACK;

		full_dsn = mptcp_ntoh64(dsn64->mdss_dsn);
		NTOHL(dsn64->mdss_subflow_seqn);
		NTOHS(dsn64->mdss_data_len);

		if (csum_len != 0) {
			csum = *(uint16_t *)(void *)(cp + dsn64->mdss_copt.mdss_len - csum_len);
		}

		mptcp_update_rcv_state_meat(mp_tp, tp, full_dsn,
		    dsn64->mdss_subflow_seqn,
		    dsn64->mdss_data_len,
		    csum);
		break;
	}
	case (MDSS_A | MDSS_a):
	{
		/* 64-bit Data ACK, no DSS */
		struct mptcp_data_ack64_opt *dack64;
		dack64 = (struct mptcp_data_ack64_opt *)cp;

		MPTCP_DSS_OPT_SZ_CHK(dack64->mdss_copt.mdss_len,
		    sizeof(struct mptcp_data_ack64_opt));

		mp_tp->mpt_flags |= MPTCPF_RCVD_64BITACK;

		full_dack = mptcp_ntoh64(dack64->mdss_ack);
		mptcp_do_dss_opt_ack_meat(full_dack, mp_tp->mpt_sndwl1, tp, tiwin);
		break;
	}
	case (MDSS_M | MDSS_m | MDSS_A):
	{
		/* 64-bit DSS + 32-bit Data ACK */
		struct mptcp_dss64_ack32_opt *dss_ack_rsp;
		dss_ack_rsp = (struct mptcp_dss64_ack32_opt *)cp;
		u_int64_t full_dsn;
		uint16_t csum = 0;

		MPTCP_DSS_OPT_SZ_CHK(dss_ack_rsp->mdss_copt.mdss_len,
		    sizeof(struct mptcp_dss64_ack32_opt) + csum_len);

		u_int32_t dack = dss_ack_rsp->mdss_ack;
		NTOHL(dack);
		mp_tp->mpt_flags |= MPTCPF_SND_64BITACK;
		MPTCP_EXTEND_DSN(mp_tp->mpt_snduna, dack, full_dack);

		full_dsn = mptcp_ntoh64(dss_ack_rsp->mdss_dsn);
		NTOHL(dss_ack_rsp->mdss_subflow_seqn);
		NTOHS(dss_ack_rsp->mdss_data_len);

		mptcp_do_dss_opt_ack_meat(full_dack, full_dsn, tp, tiwin);

		if (csum_len != 0) {
			csum = *(uint16_t *)(void *)(cp + dss_ack_rsp->mdss_copt.mdss_len - csum_len);
		}

		mptcp_update_rcv_state_meat(mp_tp, tp, full_dsn,
		    dss_ack_rsp->mdss_subflow_seqn,
		    dss_ack_rsp->mdss_data_len,
		    csum);

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
			sizeof(struct mptcp_dss32_ack64_opt) + csum_len);

		full_dack = mptcp_ntoh64(dss32_ack64_opt->mdss_ack);
		NTOHL(dss32_ack64_opt->mdss_dsn);
		mp_tp->mpt_flags |= MPTCPF_RCVD_64BITACK;
		MPTCP_EXTEND_DSN(mp_tp->mpt_rcvnxt,
		    dss32_ack64_opt->mdss_dsn, full_dsn);
		NTOHL(dss32_ack64_opt->mdss_subflow_seqn);
		NTOHS(dss32_ack64_opt->mdss_data_len);

		mptcp_do_dss_opt_ack_meat(full_dack, full_dsn, tp, tiwin);
		if (csum_len == 0) {
			mptcp_update_rcv_state_meat(mp_tp, tp, full_dsn,
			    dss32_ack64_opt->mdss_subflow_seqn,
			    dss32_ack64_opt->mdss_data_len, 0);
		} else {
			mptcp_update_rcv_state_meat(mp_tp, tp, full_dsn,
			    dss32_ack64_opt->mdss_subflow_seqn,
			    dss32_ack64_opt->mdss_data_len,
			    *(uint16_t *)(void *)(cp +
			    dss32_ack64_opt->mdss_copt.mdss_len -
			    csum_len));
		}
		break;
	}
	case (MDSS_M | MDSS_m | MDSS_A | MDSS_a):
	{
		/* 64-bit DSS + 64-bit Data ACK */
		struct mptcp_dss64_ack64_opt *dss64_ack64;
		dss64_ack64 = (struct mptcp_dss64_ack64_opt *)cp;
		u_int64_t full_dsn;

		MPTCP_DSS_OPT_SZ_CHK(dss64_ack64->mdss_copt.mdss_len,
		    sizeof(struct mptcp_dss64_ack64_opt) + csum_len);

		mp_tp->mpt_flags |= MPTCPF_RCVD_64BITACK;
		mp_tp->mpt_flags |= MPTCPF_SND_64BITACK;
		full_dsn = mptcp_ntoh64(dss64_ack64->mdss_dsn);
		full_dack = mptcp_ntoh64(dss64_ack64->mdss_dsn);
		mptcp_do_dss_opt_ack_meat(full_dack, full_dsn, tp, tiwin);
		NTOHL(dss64_ack64->mdss_subflow_seqn);
		NTOHS(dss64_ack64->mdss_data_len);
		if (csum_len == 0) {
			mptcp_update_rcv_state_meat(mp_tp, tp, full_dsn,
			    dss64_ack64->mdss_subflow_seqn,
			    dss64_ack64->mdss_data_len, 0);
		} else {
			mptcp_update_rcv_state_meat(mp_tp, tp, full_dsn,
			    dss64_ack64->mdss_subflow_seqn,
			    dss64_ack64->mdss_data_len,
			    *(uint16_t *)(void *)(cp +
			    dss64_ack64->mdss_copt.mdss_len -
			    csum_len));
		}
		break;
	}
	default:
		mptcplog((LOG_DEBUG, "%s: File bug, DSS flags = %x\n",
		    __func__, dss_rsp->mdss_flags),
		    (MPTCP_SOCKET_DBG | MPTCP_RECEIVER_DBG),
		    MPTCP_LOGLVL_LOG);
		break;
	}
}

static void
mptcp_do_dss_opt(struct tcpcb *tp, u_char *cp, struct tcphdr *th)
{
	struct mptcp_dss_copt *dss_rsp = (struct mptcp_dss_copt *)cp;
	struct mptcb *mp_tp = tptomptp(tp);

	if (!mp_tp) {
		return;
	}

	if (dss_rsp->mdss_subtype == MPO_DSS) {
		if (dss_rsp->mdss_flags & MDSS_F) {
			tp->t_rcv_map.mpt_dfin = 1;
		}

		mptcp_do_dss_opt_meat(cp, tp, th);
	}
}

static void
mptcp_do_fastclose_opt(struct tcpcb *tp, u_char *cp, struct tcphdr *th)
{
	struct mptcb *mp_tp = NULL;
	struct mptcp_fastclose_opt *fc_opt = (struct mptcp_fastclose_opt *)cp;

	if (th->th_flags != TH_ACK) {
		return;
	}

	if (fc_opt->mfast_len != sizeof(struct mptcp_fastclose_opt)) {
		tcpstat.tcps_invalid_opt++;
		return;
	}

	mp_tp = tptomptp(tp);
	if (!mp_tp) {
		return;
	}

	if (fc_opt->mfast_key != mp_tp->mpt_localkey) {
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
	tp->t_mpflags |= TMPF_FASTCLOSERCV;

	if (tp->t_inpcb->inp_socket != NULL) {
		soevent(tp->t_inpcb->inp_socket,
		    SO_FILT_HINT_LOCKED | SO_FILT_HINT_MUSTRST);
	}
}


static void
mptcp_do_mpfail_opt(struct tcpcb *tp, u_char *cp, struct tcphdr *th)
{
	struct mptcp_mpfail_opt *fail_opt = (struct mptcp_mpfail_opt *)cp;
	u_int32_t mdss_subflow_seqn = 0;
	struct mptcb *mp_tp;
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
	if ((th->th_flags != TH_ACK) && (th->th_flags != TH_RST)) {
		return;
	}

	if (fail_opt->mfail_len != sizeof(struct mptcp_mpfail_opt)) {
		return;
	}

	mp_tp = tptomptp(tp);

	mp_tp->mpt_flags |= MPTCPF_RECVD_MPFAIL;
	mp_tp->mpt_dsn_at_csum_fail = mptcp_hton64(fail_opt->mfail_dsn);
	error = mptcp_get_map_for_dsn(tp->t_inpcb->inp_socket,
	    mp_tp->mpt_dsn_at_csum_fail, &mdss_subflow_seqn);
	if (error == 0) {
		mp_tp->mpt_ssn_at_csum_fail = mdss_subflow_seqn;
	}

	mptcp_notify_mpfail(tp->t_inpcb->inp_socket);
}

static void
mptcp_do_add_addr_opt(struct mptses *mpte, u_char *cp)
{
	struct mptcp_add_addr_opt *addr_opt = (struct mptcp_add_addr_opt *)cp;

	if (addr_opt->maddr_len != MPTCP_ADD_ADDR_OPT_LEN_V4 &&
	    addr_opt->maddr_len != MPTCP_ADD_ADDR_OPT_LEN_V6) {
		os_log_info(mptcp_log_handle, "%s - %lx: Wrong ADD_ADDR length %u\n",
		    __func__, (unsigned long)VM_KERNEL_ADDRPERM(mpte),
		    addr_opt->maddr_len);

		return;
	}

	if (addr_opt->maddr_len == MPTCP_ADD_ADDR_OPT_LEN_V4 &&
	    addr_opt->maddr_ipversion != 4) {
		os_log_info(mptcp_log_handle, "%s - %lx: ADD_ADDR length for v4 but version is %u\n",
		    __func__, (unsigned long)VM_KERNEL_ADDRPERM(mpte),
		    addr_opt->maddr_ipversion);

		return;
	}

	if (addr_opt->maddr_len == MPTCP_ADD_ADDR_OPT_LEN_V6 &&
	    addr_opt->maddr_ipversion != 6) {
		os_log_info(mptcp_log_handle, "%s - %lx: ADD_ADDR length for v6 but version is %u\n",
		    __func__, (unsigned long)VM_KERNEL_ADDRPERM(mpte),
		    addr_opt->maddr_ipversion);

		return;
	}

	if (addr_opt->maddr_len == MPTCP_ADD_ADDR_OPT_LEN_V4) {
		struct sockaddr_in *dst = &mpte->mpte_dst_unicast_v4;
		struct in_addr *addr = &addr_opt->maddr_u.maddr_addrv4;
		in_addr_t haddr = ntohl(addr->s_addr);

		if (IN_ZERONET(haddr) ||
		    IN_LOOPBACK(haddr) ||
		    IN_LINKLOCAL(haddr) ||
		    IN_DS_LITE(haddr) ||
		    IN_6TO4_RELAY_ANYCAST(haddr) ||
		    IN_MULTICAST(haddr) ||
		    INADDR_BROADCAST == haddr ||
		    IN_PRIVATE(haddr) ||
		    IN_SHARED_ADDRESS_SPACE(haddr)) {
			os_log_info(mptcp_log_handle, "%s - %lx: ADD_ADDR invalid addr: %x\n",
			    __func__, (unsigned long)VM_KERNEL_ADDRPERM(mpte),
			    addr->s_addr);

			return;
		}

		dst->sin_len = sizeof(*dst);
		dst->sin_family = AF_INET;
		dst->sin_port = mpte->__mpte_dst_v4.sin_port;
		dst->sin_addr.s_addr = addr->s_addr;
	} else {
		struct sockaddr_in6 *dst = &mpte->mpte_dst_unicast_v6;
		struct in6_addr *addr = &addr_opt->maddr_u.maddr_addrv6;

		if (IN6_IS_ADDR_LINKLOCAL(addr) ||
		    IN6_IS_ADDR_MULTICAST(addr) ||
		    IN6_IS_ADDR_UNSPECIFIED(addr) ||
		    IN6_IS_ADDR_LOOPBACK(addr) ||
		    IN6_IS_ADDR_V4COMPAT(addr) ||
		    IN6_IS_ADDR_V4MAPPED(addr)) {
			char dbuf[MAX_IPv6_STR_LEN];

			inet_ntop(AF_INET6, &dst->sin6_addr, dbuf, sizeof(dbuf));
			os_log_info(mptcp_log_handle, "%s - %lx: ADD_ADDRv6 invalid addr: %s\n",
			    __func__, (unsigned long)VM_KERNEL_ADDRPERM(mpte),
			    dbuf);

			return;
		}

		dst->sin6_len = sizeof(*dst);
		dst->sin6_family = AF_INET6;
		dst->sin6_port = mpte->__mpte_dst_v6.sin6_port;
		memcpy(&dst->sin6_addr, addr, sizeof(*addr));
	}

	os_log_info(mptcp_log_handle, "%s - %lx: Received ADD_ADDRv%u\n",
	    __func__, (unsigned long)VM_KERNEL_ADDRPERM(mpte),
	    addr_opt->maddr_ipversion);

	mptcp_sched_create_subflows(mpte);
}

void
tcp_do_mptcp_options(struct tcpcb *tp, u_char *cp, struct tcphdr *th,
    struct tcpopt *to, int optlen)
{
	int mptcp_subtype;
	struct mptcb *mp_tp = tptomptp(tp);

	if (mp_tp == NULL) {
		return;
	}

	socket_lock_assert_owned(mptetoso(mp_tp->mpt_mpte));

	/* All MPTCP options have atleast 4 bytes */
	if (optlen < 4) {
		return;
	}

	mptcp_subtype = (cp[2] >> 4);

	if (mptcp_sanitize_option(tp, mptcp_subtype) == 0) {
		return;
	}

	switch (mptcp_subtype) {
	case MPO_CAPABLE:
		mptcp_do_mpcapable_opt(tp, cp, th, optlen);
		break;
	case MPO_JOIN:
		mptcp_do_mpjoin_opt(tp, cp, th, optlen);
		break;
	case MPO_DSS:
		mptcp_do_dss_opt(tp, cp, th);
		break;
	case MPO_FASTCLOSE:
		mptcp_do_fastclose_opt(tp, cp, th);
		break;
	case MPO_FAIL:
		mptcp_do_mpfail_opt(tp, cp, th);
		break;
	case MPO_ADD_ADDR:
		mptcp_do_add_addr_opt(mp_tp->mpt_mpte, cp);
		break;
	case MPO_REMOVE_ADDR:           /* fall through */
	case MPO_PRIO:
		to->to_flags |= TOF_MPTCP;
		break;
	default:
		break;
	}
	return;
}

/* REMOVE_ADDR option is sent when a source address goes away */
static void
mptcp_send_remaddr_opt(struct tcpcb *tp, struct mptcp_remaddr_opt *opt)
{
	mptcplog((LOG_DEBUG, "%s: local id %d remove id %d \n",
	    __func__, tp->t_local_aid, tp->t_rem_aid),
	    (MPTCP_SOCKET_DBG | MPTCP_SENDER_DBG), MPTCP_LOGLVL_LOG);

	bzero(opt, sizeof(*opt));
	opt->mr_kind = TCPOPT_MULTIPATH;
	opt->mr_len = sizeof(*opt);
	opt->mr_subtype = MPO_REMOVE_ADDR;
	opt->mr_addr_id = tp->t_rem_aid;
	tp->t_mpflags &= ~TMPF_SND_REM_ADDR;
}

/* We send MP_PRIO option based on the values set by the SIOCSCONNORDER ioctl */
static int
mptcp_snd_mpprio(struct tcpcb *tp, u_char *cp, int optlen)
{
	struct mptcp_mpprio_addr_opt mpprio;

	if (tp->t_state != TCPS_ESTABLISHED) {
		tp->t_mpflags &= ~TMPF_SND_MPPRIO;
		return optlen;
	}

	if ((MAX_TCPOPTLEN - optlen) <
	    (int)sizeof(mpprio)) {
		return optlen;
	}

	bzero(&mpprio, sizeof(mpprio));
	mpprio.mpprio_kind = TCPOPT_MULTIPATH;
	mpprio.mpprio_len = sizeof(mpprio);
	mpprio.mpprio_subtype = MPO_PRIO;
	if (tp->t_mpflags & TMPF_BACKUP_PATH) {
		mpprio.mpprio_flags |= MPTCP_MPPRIO_BKP;
	}
	mpprio.mpprio_addrid = tp->t_local_aid;
	memcpy(cp + optlen, &mpprio, sizeof(mpprio));
	optlen += sizeof(mpprio);
	tp->t_mpflags &= ~TMPF_SND_MPPRIO;
	mptcplog((LOG_DEBUG, "%s: aid = %d \n", __func__,
	    tp->t_local_aid),
	    (MPTCP_SOCKET_DBG | MPTCP_SENDER_DBG), MPTCP_LOGLVL_LOG);
	return optlen;
}
