/*
 * Copyright (c) 2011-2013 Apple Inc. All rights reserved.
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
#include <sys/sysctl.h>
#include <sys/mbuf.h>
#include <sys/mcache.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <net/if.h>
#include <net/dlil.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/in_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcpip.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_lro.h>
#include <netinet/lro_ext.h>
#include <kern/locks.h>

unsigned int lrocount = 0; /* A counter used for debugging only */
unsigned int lro_seq_outoforder = 0; /* Counter for debugging */
unsigned int lro_seq_mismatch = 0; /* Counter for debugging */
unsigned int lro_flushes = 0; /* Counter for tracking number of flushes */
unsigned int lro_single_flushes = 0;
unsigned int lro_double_flushes = 0;
unsigned int lro_good_flushes = 0;

unsigned int coalesc_sz = LRO_MX_COALESCE_PKTS;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, lro_sz, CTLFLAG_RW | CTLFLAG_LOCKED,
    &coalesc_sz, 0, "Max coalescing size");

unsigned int coalesc_time = LRO_MX_TIME_TO_BUFFER;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, lro_time, CTLFLAG_RW | CTLFLAG_LOCKED,
    &coalesc_time, 0, "Max coalescing time");

struct lro_flow lro_flow_list[TCP_LRO_NUM_FLOWS];

char lro_flow_map[TCP_LRO_FLOW_MAP];

static lck_attr_t *tcp_lro_mtx_attr = NULL;             /* mutex attributes */
static lck_grp_t *tcp_lro_mtx_grp = NULL;               /* mutex group */
static lck_grp_attr_t *tcp_lro_mtx_grp_attr = NULL;     /* mutex group attrs */
decl_lck_mtx_data(, tcp_lro_lock);      /* Used to synchronize updates */

unsigned int lro_byte_count = 0;

uint64_t lro_deadline = 0; /* LRO's sense of time - protected by tcp_lro_lock */
uint32_t lro_timer_set = 0;

/* Some LRO stats */
u_int32_t lro_pkt_count = 0; /* Number of packets encountered in an LRO period */
thread_call_t tcp_lro_timer;

extern u_int32_t kipf_count;

static void     tcp_lro_timer_proc(void*, void*);
static void     lro_update_stats(struct mbuf*);
static void     lro_update_flush_stats(struct mbuf *);
static void     tcp_lro_flush_flows(void);
static void     tcp_lro_sched_timer(uint64_t);
static void     lro_proto_input(struct mbuf *);

static struct mbuf *lro_tcp_xsum_validate(struct mbuf*, struct ip *,
    struct tcphdr*);
static struct mbuf *tcp_lro_process_pkt(struct mbuf*, int);

void
tcp_lro_init(void)
{
	int i;

	bzero(lro_flow_list, sizeof(struct lro_flow) * TCP_LRO_NUM_FLOWS);
	for (i = 0; i < TCP_LRO_FLOW_MAP; i++) {
		lro_flow_map[i] = TCP_LRO_FLOW_UNINIT;
	}

	/*
	 * allocate lock group attribute, group and attribute for tcp_lro_lock
	 */
	tcp_lro_mtx_grp_attr = lck_grp_attr_alloc_init();
	tcp_lro_mtx_grp = lck_grp_alloc_init("tcplro", tcp_lro_mtx_grp_attr);
	tcp_lro_mtx_attr = lck_attr_alloc_init();
	lck_mtx_init(&tcp_lro_lock, tcp_lro_mtx_grp, tcp_lro_mtx_attr);

	tcp_lro_timer = thread_call_allocate(tcp_lro_timer_proc, NULL);
	if (tcp_lro_timer == NULL) {
		panic_plain("%s: unable to allocate lro timer", __func__);
	}

	return;
}

static int
tcp_lro_matching_tuple(struct ip* ip_hdr, struct tcphdr *tcp_hdr, int *hash,
    int *flow_id )
{
	struct lro_flow *flow;
	tcp_seq seqnum;
	unsigned int off = 0;
	int payload_len = 0;

	*hash = LRO_HASH(ip_hdr->ip_src.s_addr, ip_hdr->ip_dst.s_addr,
	    tcp_hdr->th_sport, tcp_hdr->th_dport, (TCP_LRO_FLOW_MAP - 1));

	*flow_id = lro_flow_map[*hash];
	if (*flow_id == TCP_LRO_FLOW_NOTFOUND) {
		return TCP_LRO_NAN;
	}

	seqnum = tcp_hdr->th_seq;
	off = tcp_hdr->th_off << 2;
	payload_len = ip_hdr->ip_len - off;

	flow = &lro_flow_list[*flow_id];

	if ((flow->lr_faddr.s_addr == ip_hdr->ip_src.s_addr) &&
	    (flow->lr_laddr.s_addr == ip_hdr->ip_dst.s_addr) &&
	    (flow->lr_fport == tcp_hdr->th_sport) &&
	    (flow->lr_lport == tcp_hdr->th_dport)) {
		if (flow->lr_tcphdr == NULL) {
			if (ntohl(seqnum) == flow->lr_seq) {
				return TCP_LRO_COALESCE;
			}
			if (lrodebug >= 4) {
				printf("%s: seqnum = %x, lr_seq = %x\n",
				    __func__, ntohl(seqnum), flow->lr_seq);
			}
			lro_seq_mismatch++;
			if (SEQ_GT(ntohl(seqnum), flow->lr_seq)) {
				lro_seq_outoforder++;
				/*
				 * Whenever we receive out of order packets it
				 * signals loss and recovery and LRO doesn't
				 * let flows recover quickly. So eject.
				 */
				flow->lr_flags |= LRO_EJECT_REQ;
			}
			return TCP_LRO_NAN;
		}

		if (flow->lr_flags & LRO_EJECT_REQ) {
			if (lrodebug) {
				printf("%s: eject. \n", __func__);
			}
			return TCP_LRO_EJECT_FLOW;
		}
		if (SEQ_GT(tcp_hdr->th_ack, flow->lr_tcphdr->th_ack)) {
			if (lrodebug) {
				printf("%s: th_ack = %x flow_ack = %x \n",
				    __func__, tcp_hdr->th_ack,
				    flow->lr_tcphdr->th_ack);
			}
			return TCP_LRO_EJECT_FLOW;
		}

		if (ntohl(seqnum) == (ntohl(lro_flow_list[*flow_id].lr_tcphdr->th_seq) + lro_flow_list[*flow_id].lr_len)) {
			return TCP_LRO_COALESCE;
		} else {
			/* LRO does not handle loss recovery well, eject */
			flow->lr_flags |= LRO_EJECT_REQ;
			return TCP_LRO_EJECT_FLOW;
		}
	}
	if (lrodebug) {
		printf("tcp_lro_matching_tuple: collision \n");
	}
	return TCP_LRO_COLLISION;
}

static void
tcp_lro_init_flow(int flow_id, struct ip* ip_hdr, struct tcphdr *tcp_hdr,
    int hash, u_int32_t timestamp, int payload_len)
{
	struct lro_flow *flow = NULL;

	flow = &lro_flow_list[flow_id];

	flow->lr_hash_map = hash;
	flow->lr_faddr.s_addr = ip_hdr->ip_src.s_addr;
	flow->lr_laddr.s_addr = ip_hdr->ip_dst.s_addr;
	flow->lr_fport = tcp_hdr->th_sport;
	flow->lr_lport = tcp_hdr->th_dport;
	lro_flow_map[hash] = flow_id;
	flow->lr_timestamp = timestamp;
	flow->lr_seq = ntohl(tcp_hdr->th_seq) + payload_len;
	flow->lr_flags = 0;
	return;
}

static void
tcp_lro_coalesce(int flow_id, struct mbuf *lro_mb, struct tcphdr *tcphdr,
    int payload_len, int drop_hdrlen, struct tcpopt *topt,
    u_int32_t* tsval, u_int32_t* tsecr, int thflags)
{
	struct lro_flow *flow = NULL;
	struct mbuf *last;
	struct ip *ip = NULL;

	flow =  &lro_flow_list[flow_id];
	if (flow->lr_mhead) {
		if (lrodebug) {
			printf("%s: lr_mhead %x %d \n", __func__, flow->lr_seq,
			    payload_len);
		}
		m_adj(lro_mb, drop_hdrlen);

		last = flow->lr_mtail;
		while (last->m_next != NULL) {
			last = last->m_next;
		}
		last->m_next = lro_mb;

		flow->lr_mtail = lro_mb;

		ip = mtod(flow->lr_mhead, struct ip *);
		ip->ip_len += lro_mb->m_pkthdr.len;
		flow->lr_mhead->m_pkthdr.len += lro_mb->m_pkthdr.len;

		if (flow->lr_len == 0) {
			panic_plain("%s: Inconsistent LRO flow state", __func__);
		}
		flow->lr_len += payload_len;
		flow->lr_seq += payload_len;
		/*
		 * This bit is re-OR'd each time a packet is added to the
		 * large coalesced packet.
		 */
		flow->lr_mhead->m_pkthdr.pkt_flags |= PKTF_SW_LRO_PKT;
		flow->lr_mhead->m_pkthdr.lro_npkts++; /* for tcpstat.tcps_rcvpack */
		if (flow->lr_mhead->m_pkthdr.lro_pktlen <
		    lro_mb->m_pkthdr.lro_pktlen) {
			/*
			 * For TCP Inter Arrival Jitter calculation, return max
			 * size encountered while coalescing a stream of pkts.
			 */
			flow->lr_mhead->m_pkthdr.lro_pktlen =
			    lro_mb->m_pkthdr.lro_pktlen;
		}
		/* Update the timestamp value */
		if (topt->to_flags & TOF_TS) {
			if ((flow->lr_tsval) &&
			    (TSTMP_GT(topt->to_tsval, ntohl(*(flow->lr_tsval))))) {
				*(flow->lr_tsval) = htonl(topt->to_tsval);
			}
			if ((flow->lr_tsecr) &&
			    (topt->to_tsecr != 0) &&
			    (TSTMP_GT(topt->to_tsecr, ntohl(*(flow->lr_tsecr))))) {
				if (lrodebug >= 2) {
					printf("%s: instantaneous RTT = %d \n", __func__,
					    topt->to_tsecr - ntohl(*(flow->lr_tsecr)));
				}
				*(flow->lr_tsecr) = htonl(topt->to_tsecr);
			}
		}
		/* Coalesce the flags */
		if (thflags) {
			flow->lr_tcphdr->th_flags |= thflags;
		}
		/* Update receive window */
		flow->lr_tcphdr->th_win = tcphdr->th_win;
	} else {
		if (lro_mb) {
			flow->lr_mhead = flow->lr_mtail = lro_mb;
			flow->lr_mhead->m_pkthdr.pkt_flags |= PKTF_SW_LRO_PKT;
			flow->lr_tcphdr = tcphdr;
			if ((topt) && (topt->to_flags & TOF_TS)) {
				ASSERT(tsval != NULL);
				ASSERT(tsecr != NULL);
				flow->lr_tsval = tsval;
				flow->lr_tsecr = tsecr;
			}
			flow->lr_len = payload_len;
			calculate_tcp_clock();
			flow->lr_timestamp = tcp_now;
			tcp_lro_sched_timer(0);
		}
		flow->lr_seq = ntohl(tcphdr->th_seq) + payload_len;
	}
	if (lro_mb) {
		tcpstat.tcps_coalesced_pack++;
	}
	return;
}

static struct mbuf *
tcp_lro_eject_flow(int flow_id)
{
	struct mbuf *mb = NULL;

	mb = lro_flow_list[flow_id].lr_mhead;
	ASSERT(lro_flow_map[lro_flow_list[flow_id].lr_hash_map] == flow_id);
	lro_flow_map[lro_flow_list[flow_id].lr_hash_map] = TCP_LRO_FLOW_UNINIT;
	bzero(&lro_flow_list[flow_id], sizeof(struct lro_flow));

	return mb;
}

static struct mbuf*
tcp_lro_eject_coalesced_pkt(int flow_id)
{
	struct mbuf *mb = NULL;
	mb = lro_flow_list[flow_id].lr_mhead;
	lro_flow_list[flow_id].lr_mhead =
	    lro_flow_list[flow_id].lr_mtail = NULL;
	lro_flow_list[flow_id].lr_tcphdr = NULL;
	return mb;
}

static struct mbuf*
tcp_lro_insert_flow(struct mbuf *lro_mb, struct ip *ip_hdr,
    struct tcphdr *tcp_hdr, int payload_len,
    int drop_hdrlen, int hash, struct tcpopt *topt,
    u_int32_t *tsval, u_int32_t *tsecr)
{
	int i;
	int slot_available = 0;
	int candidate_flow = 0;
	u_int32_t oldest_timestamp;
	struct mbuf *mb = NULL;
	int collision = 0;

	oldest_timestamp = tcp_now;

	/* handle collision */
	if (lro_flow_map[hash] != TCP_LRO_FLOW_UNINIT) {
		if (lrodebug) {
			collision = 1;
		}
		candidate_flow = lro_flow_map[hash];
		tcpstat.tcps_flowtbl_collision++;
		goto kick_flow;
	}

	for (i = 0; i < TCP_LRO_NUM_FLOWS; i++) {
		if (lro_flow_list[i].lr_mhead == NULL) {
			candidate_flow = i;
			slot_available = 1;
			break;
		}
		if (oldest_timestamp >= lro_flow_list[i].lr_timestamp) {
			candidate_flow = i;
			oldest_timestamp = lro_flow_list[i].lr_timestamp;
		}
	}

	if (!slot_available) {
		tcpstat.tcps_flowtbl_full++;
kick_flow:
		/* kick the oldest flow */
		mb = tcp_lro_eject_flow(candidate_flow);

		if (lrodebug) {
			if (!slot_available) {
				printf("%s: slot unavailable.\n", __func__);
			}
			if (collision) {
				printf("%s: collision.\n", __func__);
			}
		}
	} else {
		candidate_flow = i; /* this is now the flow to be used */
	}

	tcp_lro_init_flow(candidate_flow, ip_hdr, tcp_hdr, hash,
	    tcp_now, payload_len);
	tcp_lro_coalesce(candidate_flow, lro_mb, tcp_hdr, payload_len,
	    drop_hdrlen, topt, tsval, tsecr, 0);
	return mb;
}

struct mbuf*
tcp_lro_process_pkt(struct mbuf *lro_mb, int drop_hdrlen)
{
	int flow_id = TCP_LRO_FLOW_UNINIT;
	int hash;
	unsigned int off = 0;
	int eject_flow = 0;
	int optlen;
	int retval = 0;
	struct mbuf *mb = NULL;
	int payload_len = 0;
	u_char *optp = NULL;
	int thflags = 0;
	struct tcpopt to;
	int ret_response = TCP_LRO_CONSUMED;
	int coalesced = 0, tcpflags = 0, unknown_tcpopts = 0;
	u_int8_t ecn;
	struct ip *ip_hdr;
	struct tcphdr *tcp_hdr;

	if (lro_mb->m_len < drop_hdrlen) {
		if ((lro_mb = m_pullup(lro_mb, drop_hdrlen)) == NULL) {
			tcpstat.tcps_rcvshort++;
			m_freem(lro_mb);
			if (lrodebug) {
				printf("tcp_lro_process_pkt:mbuf too short.\n");
			}
			return NULL;
		}
	}

	ip_hdr = mtod(lro_mb, struct ip*);
	tcp_hdr = (struct tcphdr *)((caddr_t)ip_hdr + sizeof(struct ip));

	/* Just in case */
	lro_mb->m_pkthdr.pkt_flags &= ~PKTF_SW_LRO_DID_CSUM;

	if ((lro_mb = lro_tcp_xsum_validate(lro_mb, ip_hdr, tcp_hdr)) == NULL) {
		if (lrodebug) {
			printf("tcp_lro_process_pkt: TCP xsum failed.\n");
		}
		return NULL;
	}

	/* Update stats */
	lro_pkt_count++;

	/* Avoids checksumming in tcp_input */
	lro_mb->m_pkthdr.pkt_flags |= PKTF_SW_LRO_DID_CSUM;

	off = tcp_hdr->th_off << 2;
	optlen = off - sizeof(struct tcphdr);
	payload_len = ip_hdr->ip_len - off;
	optp = (u_char *)(tcp_hdr + 1);
	/*
	 * Do quick retrieval of timestamp options ("options
	 * prediction?").  If timestamp is the only option and it's
	 * formatted as recommended in RFC 1323 appendix A, we
	 * quickly get the values now and not bother calling
	 * tcp_dooptions(), etc.
	 */
	bzero(&to, sizeof(to));
	if ((optlen == TCPOLEN_TSTAMP_APPA ||
	    (optlen > TCPOLEN_TSTAMP_APPA &&
	    optp[TCPOLEN_TSTAMP_APPA] == TCPOPT_EOL)) &&
	    *(u_int32_t *)optp == htonl(TCPOPT_TSTAMP_HDR) &&
	    (tcp_hdr->th_flags & TH_SYN) == 0) {
		to.to_flags |= TOF_TS;
		to.to_tsval = ntohl(*(u_int32_t *)(void *)(optp + 4));
		to.to_tsecr = ntohl(*(u_int32_t *)(void *)(optp + 8));
	} else {
		/*
		 * If TCP timestamps are not in use, or not the first option,
		 * skip LRO path since timestamps are used to avoid LRO
		 * from introducing additional latencies for retransmissions
		 * and other slow-paced transmissions.
		 */
		to.to_flags = to.to_tsecr = 0;
		eject_flow = 1;
	}

	/* list all the conditions that can trigger a flow ejection here */

	thflags = tcp_hdr->th_flags;
	if (thflags & (TH_SYN | TH_URG | TH_ECE | TH_CWR | TH_PUSH | TH_RST | TH_FIN)) {
		eject_flow = tcpflags = 1;
	}

	if (optlen && !((optlen == TCPOLEN_TSTAMP_APPA) &&
	    (to.to_flags & TOF_TS))) {
		eject_flow = unknown_tcpopts = 1;
	}

	if (payload_len <= LRO_MIN_COALESC_SZ) { /* zero payload ACK */
		eject_flow = 1;
	}

	/* Can't coalesce ECN marked packets. */
	ecn = ip_hdr->ip_tos & IPTOS_ECN_MASK;
	if (ecn == IPTOS_ECN_CE) {
		/*
		 * ECN needs quick notification
		 */
		if (lrodebug) {
			printf("%s: ECE bits set.\n", __func__);
		}
		eject_flow = 1;
	}

	lck_mtx_lock_spin(&tcp_lro_lock);

	retval = tcp_lro_matching_tuple(ip_hdr, tcp_hdr, &hash, &flow_id);

	switch (retval) {
	case TCP_LRO_NAN:
		lck_mtx_unlock(&tcp_lro_lock);
		ret_response = TCP_LRO_FLOW_NOTFOUND;
		break;

	case TCP_LRO_COALESCE:
		if ((payload_len != 0) && (unknown_tcpopts == 0) &&
		    (tcpflags == 0) && (ecn != IPTOS_ECN_CE) && (to.to_flags & TOF_TS)) {
			tcp_lro_coalesce(flow_id, lro_mb, tcp_hdr, payload_len,
			    drop_hdrlen, &to,
			    (to.to_flags & TOF_TS) ? (u_int32_t *)(void *)(optp + 4) : NULL,
			    (to.to_flags & TOF_TS) ? (u_int32_t *)(void *)(optp + 8) : NULL,
			    thflags);
			if (lrodebug >= 2) {
				printf("tcp_lro_process_pkt: coalesce len = %d. flow_id = %d payload_len = %d drop_hdrlen = %d optlen = %d lport = %d seqnum = %x.\n",
				    lro_flow_list[flow_id].lr_len, flow_id,
				    payload_len, drop_hdrlen, optlen,
				    ntohs(lro_flow_list[flow_id].lr_lport),
				    ntohl(tcp_hdr->th_seq));
			}
			if (lro_flow_list[flow_id].lr_mhead->m_pkthdr.lro_npkts >= coalesc_sz) {
				eject_flow = 1;
			}
			coalesced = 1;
		}
		if (eject_flow) {
			mb = tcp_lro_eject_coalesced_pkt(flow_id);
			lro_flow_list[flow_id].lr_seq = ntohl(tcp_hdr->th_seq) +
			    payload_len;
			calculate_tcp_clock();
			u_int8_t timestamp = tcp_now - lro_flow_list[flow_id].lr_timestamp;
			lck_mtx_unlock(&tcp_lro_lock);
			if (mb) {
				mb->m_pkthdr.lro_elapsed = timestamp;
				lro_proto_input(mb);
			}
			if (!coalesced) {
				if (lrodebug >= 2) {
					printf("%s: pkt payload_len = %d \n", __func__, payload_len);
				}
				lro_proto_input(lro_mb);
			}
		} else {
			lck_mtx_unlock(&tcp_lro_lock);
		}
		break;

	case TCP_LRO_EJECT_FLOW:
		mb = tcp_lro_eject_coalesced_pkt(flow_id);
		calculate_tcp_clock();
		u_int8_t timestamp = tcp_now - lro_flow_list[flow_id].lr_timestamp;
		lck_mtx_unlock(&tcp_lro_lock);
		if (mb) {
			if (lrodebug) {
				printf("tcp_lro_process_pkt eject_flow, len = %d\n", mb->m_pkthdr.len);
			}
			mb->m_pkthdr.lro_elapsed = timestamp;
			lro_proto_input(mb);
		}

		lro_proto_input(lro_mb);
		break;

	case TCP_LRO_COLLISION:
		lck_mtx_unlock(&tcp_lro_lock);
		ret_response = TCP_LRO_FLOW_NOTFOUND;
		break;

	default:
		lck_mtx_unlock(&tcp_lro_lock);
		panic_plain("%s: unrecognized type %d", __func__, retval);
	}

	if (ret_response == TCP_LRO_FLOW_NOTFOUND) {
		lro_proto_input(lro_mb);
	}
	return NULL;
}

static void
tcp_lro_timer_proc(void *arg1, void *arg2)
{
#pragma unused(arg1, arg2)

	lck_mtx_lock_spin(&tcp_lro_lock);
	lro_timer_set = 0;
	lck_mtx_unlock(&tcp_lro_lock);
	tcp_lro_flush_flows();
}

static void
tcp_lro_flush_flows(void)
{
	int i = 0;
	struct mbuf *mb;
	struct lro_flow *flow;
	int tcpclock_updated = 0;

	lck_mtx_lock(&tcp_lro_lock);

	while (i < TCP_LRO_NUM_FLOWS) {
		flow = &lro_flow_list[i];
		if (flow->lr_mhead != NULL) {
			if (!tcpclock_updated) {
				calculate_tcp_clock();
				tcpclock_updated = 1;
			}

			if (lrodebug >= 2) {
				printf("tcp_lro_flush_flows: len =%d n_pkts = %d %d %d \n",
				    flow->lr_len,
				    flow->lr_mhead->m_pkthdr.lro_npkts,
				    flow->lr_timestamp, tcp_now);
			}

			u_int8_t timestamp = tcp_now - flow->lr_timestamp;

			mb = tcp_lro_eject_flow(i);

			if (mb) {
				mb->m_pkthdr.lro_elapsed = timestamp;
				lck_mtx_unlock(&tcp_lro_lock);
				lro_update_flush_stats(mb);
				lro_proto_input(mb);
				lck_mtx_lock(&tcp_lro_lock);
			}
		}
		i++;
	}
	lck_mtx_unlock(&tcp_lro_lock);
}

/*
 * Must be called with tcp_lro_lock held.
 * The hint is non-zero for longer waits. The wait time dictated by coalesc_time
 * takes precedence, so lro_timer_set is not set for the hint case
 */
static void
tcp_lro_sched_timer(uint64_t hint)
{
	if (lro_timer_set) {
		return;
	}

	lro_timer_set = 1;
	if (!hint) {
		/* the intent is to wake up every coalesc_time msecs */
		clock_interval_to_deadline(coalesc_time,
		    (NSEC_PER_SEC / TCP_RETRANSHZ), &lro_deadline);
	} else {
		clock_interval_to_deadline(hint, NSEC_PER_SEC / TCP_RETRANSHZ,
		    &lro_deadline);
	}
	thread_call_enter_delayed(tcp_lro_timer, lro_deadline);
}

struct mbuf*
tcp_lro(struct mbuf *m, unsigned int hlen)
{
	struct ip *ip_hdr;
	unsigned int tlen;
	struct tcphdr * tcp_hdr = NULL;
	unsigned int off = 0;

	if (kipf_count != 0) {
		return m;
	}

	/*
	 * Experiments on cellular show that the RTT is much higher
	 * than the coalescing time of 5 msecs, causing lro to flush
	 * 80% of the time on a single packet. Increasing
	 * coalescing time for cellular does not show marked
	 * improvement to throughput either. Loopback perf is hurt
	 * by the 5 msec latency and it already sends large packets.
	 */
	if (IFNET_IS_CELLULAR(m->m_pkthdr.rcvif) ||
	    (m->m_pkthdr.rcvif->if_type == IFT_LOOP)) {
		return m;
	}

	ip_hdr = mtod(m, struct ip*);

	/* don't deal with IP options */
	if (hlen != sizeof(struct ip)) {
		return m;
	}

	/* only TCP is coalesced */
	if (ip_hdr->ip_p != IPPROTO_TCP) {
		return m;
	}

	if (m->m_len < (int32_t) sizeof(struct tcpiphdr)) {
		if (lrodebug) {
			printf("tcp_lro m_pullup \n");
		}
		if ((m = m_pullup(m, sizeof(struct tcpiphdr))) == NULL) {
			tcpstat.tcps_rcvshort++;
			if (lrodebug) {
				printf("ip_lro: rcvshort.\n");
			}
			return NULL;
		}
		ip_hdr = mtod(m, struct ip*);
	}

	tcp_hdr = (struct tcphdr *)((caddr_t)ip_hdr + hlen);
	tlen = ip_hdr->ip_len;  //ignore IP header bytes len
	m->m_pkthdr.lro_pktlen = tlen; /* Used to return max pkt encountered to tcp */
	m->m_pkthdr.lro_npkts = 1; /* Initialize a counter to hold num pkts coalesced */
	m->m_pkthdr.lro_elapsed = 0; /* Initialize the field to carry elapsed time */
	off = tcp_hdr->th_off << 2;
	if (off < sizeof(struct tcphdr) || off > tlen) {
		tcpstat.tcps_rcvbadoff++;
		if (lrodebug) {
			printf("ip_lro: TCP off greater than TCP header.\n");
		}
		return m;
	}

	return tcp_lro_process_pkt(m, hlen + off);
}

static void
lro_proto_input(struct mbuf *m)
{
	struct ip* ip_hdr = mtod(m, struct ip*);

	if (lrodebug >= 3) {
		printf("lro_proto_input: ip_len = %d \n",
		    ip_hdr->ip_len);
	}
	lro_update_stats(m);
	ip_proto_dispatch_in_wrapper(m, ip_hdr->ip_hl << 2, ip_hdr->ip_p);
}

static struct mbuf *
lro_tcp_xsum_validate(struct mbuf *m, struct ip *ip, struct tcphdr * th)
{
	/* Expect 32-bit aligned data pointer on strict-align platforms */
	MBUF_STRICT_DATA_ALIGNMENT_CHECK_32(m);

	/* we shouldn't get here for IP with options; hence sizeof (ip) */
	if (tcp_input_checksum(AF_INET, m, th, sizeof(*ip), ip->ip_len)) {
		if (lrodebug) {
			printf("%s: bad xsum and drop m = 0x%llx.\n", __func__,
			    (uint64_t)VM_KERNEL_ADDRPERM(m));
		}
		m_freem(m);
		return NULL;
	}

	return m;
}

/*
 * When TCP detects a stable, steady flow without out of ordering,
 * with a sufficiently high cwnd, it invokes LRO.
 */
int
tcp_start_coalescing(struct ip *ip_hdr, struct tcphdr *tcp_hdr, int tlen)
{
	int hash;
	int flow_id;
	struct mbuf *eject_mb;
	struct lro_flow *lf;

	hash = LRO_HASH(ip_hdr->ip_src.s_addr, ip_hdr->ip_dst.s_addr,
	    tcp_hdr->th_sport, tcp_hdr->th_dport,
	    (TCP_LRO_FLOW_MAP - 1));


	lck_mtx_lock_spin(&tcp_lro_lock);
	flow_id = lro_flow_map[hash];
	if (flow_id != TCP_LRO_FLOW_NOTFOUND) {
		lf = &lro_flow_list[flow_id];
		if ((lf->lr_faddr.s_addr == ip_hdr->ip_src.s_addr) &&
		    (lf->lr_laddr.s_addr == ip_hdr->ip_dst.s_addr) &&
		    (lf->lr_fport == tcp_hdr->th_sport) &&
		    (lf->lr_lport == tcp_hdr->th_dport)) {
			if ((lf->lr_tcphdr == NULL) &&
			    (lf->lr_seq != (tcp_hdr->th_seq + tlen))) {
				lf->lr_seq = tcp_hdr->th_seq + tlen;
			}
			lf->lr_flags &= ~LRO_EJECT_REQ;
		}
		lck_mtx_unlock(&tcp_lro_lock);
		return 0;
	}

	HTONL(tcp_hdr->th_seq);
	HTONL(tcp_hdr->th_ack);
	eject_mb =
	    tcp_lro_insert_flow(NULL, ip_hdr, tcp_hdr, tlen, 0, hash,
	    NULL, NULL, NULL);

	lck_mtx_unlock(&tcp_lro_lock);

	NTOHL(tcp_hdr->th_seq);
	NTOHL(tcp_hdr->th_ack);
	if (lrodebug >= 3) {
		printf("%s: src = %x dst = %x sport = %d dport = %d seq %x \n",
		    __func__, ip_hdr->ip_src.s_addr, ip_hdr->ip_dst.s_addr,
		    tcp_hdr->th_sport, tcp_hdr->th_dport, tcp_hdr->th_seq);
	}
	ASSERT(eject_mb == NULL);
	return 0;
}

/*
 * When TCP detects loss or idle condition, it stops offloading
 * to LRO.
 */
int
tcp_lro_remove_state(struct in_addr saddr, struct in_addr daddr,
    unsigned short sport, unsigned short dport)
{
	int hash, flow_id;
	struct lro_flow *lf;

	hash = LRO_HASH(daddr.s_addr, saddr.s_addr, dport, sport,
	    (TCP_LRO_FLOW_MAP - 1));
	lck_mtx_lock_spin(&tcp_lro_lock);
	flow_id = lro_flow_map[hash];
	if (flow_id == TCP_LRO_FLOW_UNINIT) {
		lck_mtx_unlock(&tcp_lro_lock);
		return 0;
	}
	lf = &lro_flow_list[flow_id];
	if ((lf->lr_faddr.s_addr == daddr.s_addr) &&
	    (lf->lr_laddr.s_addr == saddr.s_addr) &&
	    (lf->lr_fport == dport) &&
	    (lf->lr_lport == sport)) {
		if (lrodebug) {
			printf("%s: %x %x\n", __func__,
			    lf->lr_flags, lf->lr_seq);
		}
		lf->lr_flags |= LRO_EJECT_REQ;
	}
	lck_mtx_unlock(&tcp_lro_lock);
	return 0;
}

void
tcp_update_lro_seq(__uint32_t rcv_nxt, struct in_addr saddr, struct in_addr daddr,
    unsigned short sport, unsigned short dport)
{
	int hash, flow_id;
	struct lro_flow *lf;

	hash = LRO_HASH(daddr.s_addr, saddr.s_addr, dport, sport,
	    (TCP_LRO_FLOW_MAP - 1));
	lck_mtx_lock_spin(&tcp_lro_lock);
	flow_id = lro_flow_map[hash];
	if (flow_id == TCP_LRO_FLOW_UNINIT) {
		lck_mtx_unlock(&tcp_lro_lock);
		return;
	}
	lf = &lro_flow_list[flow_id];
	if ((lf->lr_faddr.s_addr == daddr.s_addr) &&
	    (lf->lr_laddr.s_addr == saddr.s_addr) &&
	    (lf->lr_fport == dport) &&
	    (lf->lr_lport == sport) &&
	    (lf->lr_tcphdr == NULL)) {
		lf->lr_seq = (tcp_seq)rcv_nxt;
	}
	lck_mtx_unlock(&tcp_lro_lock);
	return;
}

static void
lro_update_stats(struct mbuf *m)
{
	switch (m->m_pkthdr.lro_npkts) {
	case 0: /* fall through */
	case 1:
		break;

	case 2:
		tcpstat.tcps_lro_twopack++;
		break;

	case 3: /* fall through */
	case 4:
		tcpstat.tcps_lro_multpack++;
		break;

	default:
		tcpstat.tcps_lro_largepack++;
		break;
	}
	return;
}

static void
lro_update_flush_stats(struct mbuf *m)
{
	lro_flushes++;
	switch (m->m_pkthdr.lro_npkts) {
	case 0: ASSERT(0);
	case 1: lro_single_flushes++;
		break;
	case 2: lro_double_flushes++;
		break;
	default: lro_good_flushes++;
		break;
	}
	return;
}
