/*
 * Copyright (c) 2007-2013 Apple Inc. All rights reserved.
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

/*	$apfw: git commit 6602420f2f101b74305cd78f7cd9e0c8fdedae97 $ */
/*	$OpenBSD: pf.c,v 1.567 2008/02/20 23:40:13 henning Exp $ */

/*
 * Copyright (c) 2001 Daniel Hartmeier
 * Copyright (c) 2002,2003 Henning Brauer
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Effort sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F30602-01-2-0537.
 *
 */

#include <machine/endian.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/filio.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/kernel.h>
#include <sys/time.h>
#include <sys/proc.h>
#include <sys/random.h>
#include <sys/mcache.h>
#include <sys/protosw.h>

#include <libkern/crypto/md5.h>
#include <libkern/libkern.h>

#include <mach/thread_act.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/bpf.h>
#include <net/route.h>
#include <net/dlil.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_seq.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_fsm.h>
#include <netinet/udp_var.h>
#include <netinet/icmp_var.h>
#include <net/if_ether.h>
#include <net/ethernet.h>
#include <net/flowhash.h>
#include <net/pfvar.h>
#include <net/if_pflog.h>

#if NPFSYNC
#include <net/if_pfsync.h>
#endif /* NPFSYNC */

#if INET6
#include <netinet/ip6.h>
#include <netinet6/in6_pcb.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>
#include <netinet6/nd6.h>
#endif /* INET6 */

#if DUMMYNET
#include <netinet/ip_dummynet.h>
#endif /* DUMMYNET */

/*
 * For RandomULong(), to get a 32 bits random value 
 * Note that random() returns a 31 bits value, see rdar://11159750
 */
#include <dev/random/randomdev.h>

#define DPFPRINTF(n, x)	(pf_status.debug >= (n) ? printf x : ((void)0))

/*
 * On Mac OS X, the rtableid value is treated as the interface scope
 * value that is equivalent to the interface index used for scoped
 * routing.  A valid scope value is anything but IFSCOPE_NONE (0),
 * as per definition of ifindex which is a positive, non-zero number.
 * The other BSDs treat a negative rtableid value as invalid, hence
 * the test against INT_MAX to handle userland apps which initialize
 * the field with a negative number.
 */
#define	PF_RTABLEID_IS_VALID(r) \
	((r) > IFSCOPE_NONE && (r) <= INT_MAX)

/*
 * Global variables
 */
decl_lck_mtx_data(,pf_lock_data);
decl_lck_rw_data(,pf_perim_lock_data);
lck_mtx_t *pf_lock = &pf_lock_data;
lck_rw_t *pf_perim_lock = &pf_perim_lock_data;

/* state tables */
struct pf_state_tree_lan_ext	 pf_statetbl_lan_ext;
struct pf_state_tree_ext_gwy	 pf_statetbl_ext_gwy;

struct pf_palist	 pf_pabuf;
struct pf_status	 pf_status;

#if PF_ALTQ
struct pf_altqqueue	 pf_altqs[2];
struct pf_altqqueue	*pf_altqs_active;
struct pf_altqqueue	*pf_altqs_inactive;
u_int32_t		 ticket_altqs_active;
u_int32_t		 ticket_altqs_inactive;
int			 altqs_inactive_open;
#endif /* PF_ALTQ */
u_int32_t		 ticket_pabuf;

static MD5_CTX		 pf_tcp_secret_ctx;
static u_char		 pf_tcp_secret[16];
static int		 pf_tcp_secret_init;
static int		 pf_tcp_iss_off;

static struct pf_anchor_stackframe {
	struct pf_ruleset			*rs;
	struct pf_rule				*r;
	struct pf_anchor_node			*parent;
	struct pf_anchor			*child;
} pf_anchor_stack[64];

struct pool		 pf_src_tree_pl, pf_rule_pl, pf_pooladdr_pl;
struct pool		 pf_state_pl, pf_state_key_pl;
#if PF_ALTQ
struct pool		 pf_altq_pl;
#endif /* PF_ALTQ */

typedef void (*hook_fn_t)(void *);

struct hook_desc {
	TAILQ_ENTRY(hook_desc) hd_list;
	hook_fn_t hd_fn;
	void *hd_arg;
};

#define	HOOK_REMOVE	0x01
#define	HOOK_FREE	0x02
#define	HOOK_ABORT	0x04

static void		*hook_establish(struct hook_desc_head *, int,
			    hook_fn_t, void *);
static void		hook_runloop(struct hook_desc_head *, int flags);

struct pool		 pf_app_state_pl;
static void		 pf_print_addr(struct pf_addr *addr, sa_family_t af);
static void		 pf_print_sk_host(struct pf_state_host *, u_int8_t, int,
			    u_int8_t);

static void		 pf_print_host(struct pf_addr *, u_int16_t, u_int8_t);

static void		 pf_init_threshold(struct pf_threshold *, u_int32_t,
			    u_int32_t);
static void		 pf_add_threshold(struct pf_threshold *);
static int		 pf_check_threshold(struct pf_threshold *);

static void		 pf_change_ap(int, struct mbuf *, struct pf_addr *,
			    u_int16_t *, u_int16_t *, u_int16_t *,
			    struct pf_addr *, u_int16_t, u_int8_t, sa_family_t);
static int		 pf_modulate_sack(struct mbuf *, int, struct pf_pdesc *,
			    struct tcphdr *, struct pf_state_peer *);
#if INET6
static void		 pf_change_a6(struct pf_addr *, u_int16_t *,
			    struct pf_addr *, u_int8_t);
#endif /* INET6 */
static void		 pf_change_icmp(struct pf_addr *, u_int16_t *,
			    struct pf_addr *, struct pf_addr *, u_int16_t,
			    u_int16_t *, u_int16_t *, u_int16_t *,
			    u_int16_t *, u_int8_t, sa_family_t);
static void		 pf_send_tcp(const struct pf_rule *, sa_family_t,
			    const struct pf_addr *, const struct pf_addr *,
			    u_int16_t, u_int16_t, u_int32_t, u_int32_t,
			    u_int8_t, u_int16_t, u_int16_t, u_int8_t, int,
			    u_int16_t, struct ether_header *, struct ifnet *);
static void		 pf_send_icmp(struct mbuf *, u_int8_t, u_int8_t,
			    sa_family_t, struct pf_rule *);
static struct pf_rule	*pf_match_translation(struct pf_pdesc *, struct mbuf *,
			    int, int, struct pfi_kif *, struct pf_addr *,
			    union pf_state_xport *, struct pf_addr *,
			    union pf_state_xport *, int);
static struct pf_rule	*pf_get_translation_aux(struct pf_pdesc *,
			    struct mbuf *, int, int, struct pfi_kif *,
			    struct pf_src_node **, struct pf_addr *,
			    union pf_state_xport *, struct pf_addr *,
			    union pf_state_xport *, struct pf_addr *,
			    union pf_state_xport *);
static void		 pf_attach_state(struct pf_state_key *,
			    struct pf_state *, int);
static void		 pf_detach_state(struct pf_state *, int);
static u_int32_t	 pf_tcp_iss(struct pf_pdesc *);
static int		 pf_test_rule(struct pf_rule **, struct pf_state **,
			    int, struct pfi_kif *, struct mbuf *, int,
			    void *, struct pf_pdesc *, struct pf_rule **,
			    struct pf_ruleset **, struct ifqueue *);
#if DUMMYNET
static int		 pf_test_dummynet(struct pf_rule **, int, 
			    struct pfi_kif *, struct mbuf **, 
			    struct pf_pdesc *, struct ip_fw_args *);
#endif /* DUMMYNET */
static int		 pf_test_fragment(struct pf_rule **, int,
			    struct pfi_kif *, struct mbuf *, void *,
			    struct pf_pdesc *, struct pf_rule **,
			    struct pf_ruleset **);
static int		 pf_test_state_tcp(struct pf_state **, int,
			    struct pfi_kif *, struct mbuf *, int,
			    void *, struct pf_pdesc *, u_short *);
static int		 pf_test_state_udp(struct pf_state **, int,
			    struct pfi_kif *, struct mbuf *, int,
			    void *, struct pf_pdesc *, u_short *);
static int		 pf_test_state_icmp(struct pf_state **, int,
			    struct pfi_kif *, struct mbuf *, int,
			    void *, struct pf_pdesc *, u_short *);
static int		 pf_test_state_other(struct pf_state **, int,
			    struct pfi_kif *, struct pf_pdesc *);
static int		 pf_match_tag(struct mbuf *, struct pf_rule *,
			    struct pf_mtag *, int *);
static void		 pf_hash(struct pf_addr *, struct pf_addr *,
			    struct pf_poolhashkey *, sa_family_t);
static int		 pf_map_addr(u_int8_t, struct pf_rule *,
			    struct pf_addr *, struct pf_addr *,
			    struct pf_addr *, struct pf_src_node **);
static int		 pf_get_sport(struct pf_pdesc *, struct pfi_kif *,
			    struct pf_rule *, struct pf_addr *,
			    union pf_state_xport *, struct pf_addr *,
			    union pf_state_xport *, struct pf_addr *,
			    union pf_state_xport *, struct pf_src_node **);
static void		 pf_route(struct mbuf **, struct pf_rule *, int,
			    struct ifnet *, struct pf_state *,
			    struct pf_pdesc *);
#if INET6
static void		 pf_route6(struct mbuf **, struct pf_rule *, int,
			    struct ifnet *, struct pf_state *,
			    struct pf_pdesc *);
#endif /* INET6 */
static u_int8_t		 pf_get_wscale(struct mbuf *, int, u_int16_t,
			    sa_family_t);
static u_int16_t	 pf_get_mss(struct mbuf *, int, u_int16_t,
			    sa_family_t);
static u_int16_t	 pf_calc_mss(struct pf_addr *, sa_family_t,
				u_int16_t);
static void		 pf_set_rt_ifp(struct pf_state *,
			    struct pf_addr *);
static int		 pf_check_proto_cksum(struct mbuf *, int, int,
			    u_int8_t, sa_family_t);
static int		 pf_addr_wrap_neq(struct pf_addr_wrap *,
			    struct pf_addr_wrap *);
static struct pf_state	*pf_find_state(struct pfi_kif *,
			    struct pf_state_key_cmp *, u_int);
static int		 pf_src_connlimit(struct pf_state **);
static void		 pf_stateins_err(const char *, struct pf_state *,
			    struct pfi_kif *);
static int		 pf_check_congestion(struct ifqueue *);

#if 0
static const char *pf_pptp_ctrl_type_name(u_int16_t code);
#endif
static void		pf_pptp_handler(struct pf_state *, int, int,
			    struct pf_pdesc *, struct pfi_kif *);
static void		pf_pptp_unlink(struct pf_state *);
static void		pf_grev1_unlink(struct pf_state *);
static int		pf_test_state_grev1(struct pf_state **, int,
			    struct pfi_kif *, int, struct pf_pdesc *);
static int		pf_ike_compare(struct pf_app_state *,
			    struct pf_app_state *);
static int		pf_test_state_esp(struct pf_state **, int,
			    struct pfi_kif *, int, struct pf_pdesc *);

extern struct pool pfr_ktable_pl;
extern struct pool pfr_kentry_pl;
extern int path_mtu_discovery;

struct pf_pool_limit pf_pool_limits[PF_LIMIT_MAX] = {
	{ &pf_state_pl, PFSTATE_HIWAT },
	{ &pf_app_state_pl, PFAPPSTATE_HIWAT },
	{ &pf_src_tree_pl, PFSNODE_HIWAT },
	{ &pf_frent_pl, PFFRAG_FRENT_HIWAT },
	{ &pfr_ktable_pl, PFR_KTABLE_HIWAT },
	{ &pfr_kentry_pl, PFR_KENTRY_HIWAT },
};

struct mbuf *
pf_lazy_makewritable(struct pf_pdesc *pd, struct mbuf *m, int len)
{
	if (pd->lmw < 0)
		return (0);

	VERIFY(m == pd->mp);

	if (len > pd->lmw) {
		if (m_makewritable(&m, 0, len, M_DONTWAIT))
			len = -1;
		pd->lmw = len;
		if (len >= 0 && m != pd->mp) {
			pd->mp = m;
			pd->pf_mtag = pf_find_mtag(m);

			switch (pd->af) {
			case AF_INET: {
				struct ip *h = mtod(m, struct ip *);
				pd->src = (struct pf_addr *)&h->ip_src;
				pd->dst = (struct pf_addr *)&h->ip_dst;
				pd->ip_sum = &h->ip_sum;
				break;
			}
#if INET6
			case AF_INET6: {
				struct ip6_hdr *h = mtod(m, struct ip6_hdr *);
				pd->src = (struct pf_addr *)&h->ip6_src;
				pd->dst = (struct pf_addr *)&h->ip6_dst;
				break;
			}
#endif /* INET6 */
			}
		}
	}

	return (len < 0 ? 0 : m);
}

static const int *
pf_state_lookup_aux(struct pf_state **state, struct pfi_kif *kif,
	int direction, int *action)
{
	if (*state == NULL || (*state)->timeout == PFTM_PURGE) {
		*action = PF_DROP;
		return (action);
	}

	if (direction == PF_OUT &&
	    (((*state)->rule.ptr->rt == PF_ROUTETO &&
	    (*state)->rule.ptr->direction == PF_OUT) ||
	    ((*state)->rule.ptr->rt == PF_REPLYTO &&
	    (*state)->rule.ptr->direction == PF_IN)) &&
	    (*state)->rt_kif != NULL && (*state)->rt_kif != kif) {
		*action = PF_PASS;
		return (action);
	}

	return (0);
}

#define STATE_LOOKUP()							 \
	do {								 \
		int action;						 \
		*state = pf_find_state(kif, &key, direction);		 \
		if (*state != NULL && pd != NULL &&			 \
		    !(pd->pktflags & PKTF_FLOW_ID)) {			 \
			pd->flowsrc = (*state)->state_key->flowsrc;	 \
			pd->flowhash = (*state)->state_key->flowhash;	 \
			if (pd->flowhash != 0) {			 \
				pd->pktflags |= PKTF_FLOW_ID;		 \
				pd->pktflags &= ~PKTF_FLOW_ADV;		 \
			}						 \
		}							 \
		if (pf_state_lookup_aux(state, kif, direction, &action)) \
			return (action);				 \
	} while (0)

#define	STATE_ADDR_TRANSLATE(sk)					\
	(sk)->lan.addr.addr32[0] != (sk)->gwy.addr.addr32[0] ||		\
	((sk)->af == AF_INET6 &&					\
	((sk)->lan.addr.addr32[1] != (sk)->gwy.addr.addr32[1] ||	\
	(sk)->lan.addr.addr32[2] != (sk)->gwy.addr.addr32[2] ||		\
	(sk)->lan.addr.addr32[3] != (sk)->gwy.addr.addr32[3]))

#define STATE_TRANSLATE(sk)						\
	(STATE_ADDR_TRANSLATE(sk) ||					\
	(sk)->lan.xport.port != (sk)->gwy.xport.port)

#define STATE_GRE_TRANSLATE(sk)						\
	(STATE_ADDR_TRANSLATE(sk) ||					\
	(sk)->lan.xport.call_id != (sk)->gwy.xport.call_id)

#define BOUND_IFACE(r, k) \
	((r)->rule_flag & PFRULE_IFBOUND) ? (k) : pfi_all

#define STATE_INC_COUNTERS(s)					\
	do {							\
		s->rule.ptr->states++;				\
		VERIFY(s->rule.ptr->states != 0);		\
		if (s->anchor.ptr != NULL) {			\
			s->anchor.ptr->states++;		\
			VERIFY(s->anchor.ptr->states != 0);	\
		}						\
		if (s->nat_rule.ptr != NULL) {			\
			s->nat_rule.ptr->states++;		\
			VERIFY(s->nat_rule.ptr->states != 0);	\
		}						\
	} while (0)

#define STATE_DEC_COUNTERS(s)					\
	do {							\
		if (s->nat_rule.ptr != NULL) {			\
			VERIFY(s->nat_rule.ptr->states > 0);	\
			s->nat_rule.ptr->states--;		\
		}						\
		if (s->anchor.ptr != NULL) {			\
			VERIFY(s->anchor.ptr->states > 0);	\
			s->anchor.ptr->states--;		\
		}						\
		VERIFY(s->rule.ptr->states > 0);		\
		s->rule.ptr->states--;				\
	} while (0)

static __inline int pf_src_compare(struct pf_src_node *, struct pf_src_node *);
static __inline int pf_state_compare_lan_ext(struct pf_state_key *,
	struct pf_state_key *);
static __inline int pf_state_compare_ext_gwy(struct pf_state_key *,
	struct pf_state_key *);
static __inline int pf_state_compare_id(struct pf_state *,
	struct pf_state *);

struct pf_src_tree tree_src_tracking;

struct pf_state_tree_id tree_id;
struct pf_state_queue state_list;

RB_GENERATE(pf_src_tree, pf_src_node, entry, pf_src_compare);
RB_GENERATE(pf_state_tree_lan_ext, pf_state_key,
    entry_lan_ext, pf_state_compare_lan_ext);
RB_GENERATE(pf_state_tree_ext_gwy, pf_state_key,
    entry_ext_gwy, pf_state_compare_ext_gwy);
RB_GENERATE(pf_state_tree_id, pf_state,
    entry_id, pf_state_compare_id);

#define	PF_DT_SKIP_LANEXT	0x01
#define	PF_DT_SKIP_EXTGWY	0x02

static const u_int16_t PF_PPTP_PORT = 1723;
static const u_int32_t PF_PPTP_MAGIC_NUMBER = 0x1A2B3C4D;

struct pf_pptp_hdr {
	u_int16_t	length;
	u_int16_t	type;
	u_int32_t	magic;
};

struct pf_pptp_ctrl_hdr {
	u_int16_t	type;
	u_int16_t	reserved_0;
};

struct pf_pptp_ctrl_generic {
	u_int16_t	data[0];
};

#define PF_PPTP_CTRL_TYPE_START_REQ	1
struct pf_pptp_ctrl_start_req {
	u_int16_t	protocol_version;
	u_int16_t	reserved_1;
	u_int32_t	framing_capabilities;
	u_int32_t	bearer_capabilities;
	u_int16_t	maximum_channels;
	u_int16_t	firmware_revision;
	u_int8_t	host_name[64];
	u_int8_t	vendor_string[64];
};

#define PF_PPTP_CTRL_TYPE_START_RPY	2
struct pf_pptp_ctrl_start_rpy {
	u_int16_t	protocol_version;
	u_int8_t	result_code;
	u_int8_t	error_code;
	u_int32_t	framing_capabilities;
	u_int32_t	bearer_capabilities;
	u_int16_t	maximum_channels;
	u_int16_t	firmware_revision;
	u_int8_t	host_name[64];
	u_int8_t	vendor_string[64];
};

#define PF_PPTP_CTRL_TYPE_STOP_REQ	3
struct pf_pptp_ctrl_stop_req {
	u_int8_t	reason;
	u_int8_t	reserved_1;
	u_int16_t	reserved_2;
};

#define PF_PPTP_CTRL_TYPE_STOP_RPY	4
struct pf_pptp_ctrl_stop_rpy {
	u_int8_t	reason;
	u_int8_t	error_code;
	u_int16_t	reserved_1;
};

#define PF_PPTP_CTRL_TYPE_ECHO_REQ	5
struct pf_pptp_ctrl_echo_req {
	u_int32_t	identifier;
};

#define PF_PPTP_CTRL_TYPE_ECHO_RPY	6
struct pf_pptp_ctrl_echo_rpy {
	u_int32_t	identifier;
	u_int8_t	result_code;
	u_int8_t	error_code;
	u_int16_t	reserved_1;
};

#define PF_PPTP_CTRL_TYPE_CALL_OUT_REQ	7
struct pf_pptp_ctrl_call_out_req {
	u_int16_t	call_id;
	u_int16_t	call_sernum;
	u_int32_t	min_bps;
	u_int32_t	bearer_type;
	u_int32_t	framing_type;
	u_int16_t	rxwindow_size;
	u_int16_t	proc_delay;
	u_int8_t	phone_num[64];
	u_int8_t	sub_addr[64];
};

#define PF_PPTP_CTRL_TYPE_CALL_OUT_RPY	8
struct pf_pptp_ctrl_call_out_rpy {
	u_int16_t	call_id;
	u_int16_t	peer_call_id;
	u_int8_t	result_code;
	u_int8_t	error_code;
	u_int16_t	cause_code;
	u_int32_t	connect_speed;
	u_int16_t	rxwindow_size;
	u_int16_t	proc_delay;
	u_int32_t	phy_channel_id;
};

#define PF_PPTP_CTRL_TYPE_CALL_IN_1ST	9
struct pf_pptp_ctrl_call_in_1st {
	u_int16_t	call_id;
	u_int16_t	call_sernum;
	u_int32_t	bearer_type;
	u_int32_t	phy_channel_id;
	u_int16_t	dialed_number_len;
	u_int16_t	dialing_number_len;
	u_int8_t	dialed_num[64];
	u_int8_t	dialing_num[64];
	u_int8_t	sub_addr[64];
};

#define PF_PPTP_CTRL_TYPE_CALL_IN_2ND	10
struct pf_pptp_ctrl_call_in_2nd {
	u_int16_t	call_id;
	u_int16_t	peer_call_id;
	u_int8_t	result_code;
	u_int8_t	error_code;
	u_int16_t	rxwindow_size;
	u_int16_t	txdelay;
	u_int16_t	reserved_1;
};

#define PF_PPTP_CTRL_TYPE_CALL_IN_3RD	11
struct pf_pptp_ctrl_call_in_3rd {
	u_int16_t	call_id;
	u_int16_t	reserved_1;
	u_int32_t	connect_speed;
	u_int16_t	rxwindow_size;
	u_int16_t	txdelay;
	u_int32_t	framing_type;
};

#define PF_PPTP_CTRL_TYPE_CALL_CLR	12
struct pf_pptp_ctrl_call_clr {
	u_int16_t	call_id;
	u_int16_t	reserved_1;
};

#define PF_PPTP_CTRL_TYPE_CALL_DISC	13
struct pf_pptp_ctrl_call_disc {
	u_int16_t	call_id;
	u_int8_t	result_code;
	u_int8_t	error_code;
	u_int16_t	cause_code;
	u_int16_t	reserved_1;
	u_int8_t	statistics[128];
};

#define PF_PPTP_CTRL_TYPE_ERROR	14
struct pf_pptp_ctrl_error {
	u_int16_t	peer_call_id;
	u_int16_t	reserved_1;
	u_int32_t	crc_errors;
	u_int32_t	fr_errors;
	u_int32_t	hw_errors;
	u_int32_t	buf_errors;
	u_int32_t	tim_errors;
	u_int32_t	align_errors;
};

#define PF_PPTP_CTRL_TYPE_SET_LINKINFO	15
struct pf_pptp_ctrl_set_linkinfo {
	u_int16_t	peer_call_id;
	u_int16_t	reserved_1;
	u_int32_t	tx_accm;
	u_int32_t	rx_accm;
};

#if 0
static const char *pf_pptp_ctrl_type_name(u_int16_t code)
{
	code = ntohs(code);

	if (code < PF_PPTP_CTRL_TYPE_START_REQ ||
	    code > PF_PPTP_CTRL_TYPE_SET_LINKINFO) {
		static char reserved[] = "reserved-00";

		sprintf(&reserved[9], "%02x", code);
		return (reserved);
	} else {
		static const char *name[] = {
			"start_req", "start_rpy", "stop_req", "stop_rpy",
			"echo_req", "echo_rpy", "call_out_req", "call_out_rpy",
			"call_in_1st", "call_in_2nd", "call_in_3rd",
			"call_clr", "call_disc", "error", "set_linkinfo"
		};

		return (name[code - 1]);
	}
};
#endif

static const size_t PF_PPTP_CTRL_MSG_MINSIZE =
	sizeof (struct pf_pptp_hdr) +
	sizeof (struct pf_pptp_ctrl_hdr) +
	MIN(sizeof (struct pf_pptp_ctrl_start_req),
	MIN(sizeof (struct pf_pptp_ctrl_start_rpy),
	MIN(sizeof (struct pf_pptp_ctrl_stop_req),
	MIN(sizeof (struct pf_pptp_ctrl_stop_rpy),
	MIN(sizeof (struct pf_pptp_ctrl_echo_req),
	MIN(sizeof (struct pf_pptp_ctrl_echo_rpy),
	MIN(sizeof (struct pf_pptp_ctrl_call_out_req),
	MIN(sizeof (struct pf_pptp_ctrl_call_out_rpy),
	MIN(sizeof (struct pf_pptp_ctrl_call_in_1st),
	MIN(sizeof (struct pf_pptp_ctrl_call_in_2nd),
	MIN(sizeof (struct pf_pptp_ctrl_call_in_3rd),
	MIN(sizeof (struct pf_pptp_ctrl_call_clr),
	MIN(sizeof (struct pf_pptp_ctrl_call_disc),
	MIN(sizeof (struct pf_pptp_ctrl_error),
	sizeof (struct pf_pptp_ctrl_set_linkinfo)
	))))))))))))));

union pf_pptp_ctrl_msg_union {
	struct pf_pptp_ctrl_start_req		start_req;
	struct pf_pptp_ctrl_start_rpy		start_rpy;
	struct pf_pptp_ctrl_stop_req		stop_req;
	struct pf_pptp_ctrl_stop_rpy		stop_rpy;
	struct pf_pptp_ctrl_echo_req		echo_req;
	struct pf_pptp_ctrl_echo_rpy		echo_rpy;
	struct pf_pptp_ctrl_call_out_req	call_out_req;
	struct pf_pptp_ctrl_call_out_rpy	call_out_rpy;
	struct pf_pptp_ctrl_call_in_1st		call_in_1st;
	struct pf_pptp_ctrl_call_in_2nd		call_in_2nd;
	struct pf_pptp_ctrl_call_in_3rd		call_in_3rd;
	struct pf_pptp_ctrl_call_clr		call_clr;
	struct pf_pptp_ctrl_call_disc		call_disc;
	struct pf_pptp_ctrl_error			error;
	struct pf_pptp_ctrl_set_linkinfo	set_linkinfo;
	u_int8_t							data[0];
};

struct pf_pptp_ctrl_msg {
	struct pf_pptp_hdr				hdr;
	struct pf_pptp_ctrl_hdr			ctrl;
	union pf_pptp_ctrl_msg_union	msg;
};

#define PF_GRE_FLAG_CHECKSUM_PRESENT	0x8000
#define PF_GRE_FLAG_VERSION_MASK		0x0007
#define PF_GRE_PPP_ETHERTYPE			0x880B

struct pf_grev1_hdr {
	u_int16_t flags;
	u_int16_t protocol_type;
	u_int16_t payload_length;
	u_int16_t call_id;
	/*
	u_int32_t seqno;
	u_int32_t ackno;
	*/
};

static const u_int16_t PF_IKE_PORT = 500;

struct pf_ike_hdr {
	u_int64_t initiator_cookie, responder_cookie;
	u_int8_t next_payload, version, exchange_type, flags;
	u_int32_t message_id, length;
};

#define PF_IKE_PACKET_MINSIZE	(sizeof (struct pf_ike_hdr))

#define PF_IKEv1_EXCHTYPE_BASE				 1
#define PF_IKEv1_EXCHTYPE_ID_PROTECT		 2
#define PF_IKEv1_EXCHTYPE_AUTH_ONLY			 3
#define PF_IKEv1_EXCHTYPE_AGGRESSIVE		 4
#define PF_IKEv1_EXCHTYPE_INFORMATIONAL		 5
#define PF_IKEv2_EXCHTYPE_SA_INIT			34
#define PF_IKEv2_EXCHTYPE_AUTH				35
#define PF_IKEv2_EXCHTYPE_CREATE_CHILD_SA	36
#define PF_IKEv2_EXCHTYPE_INFORMATIONAL		37

#define PF_IKEv1_FLAG_E		0x01
#define PF_IKEv1_FLAG_C		0x02
#define PF_IKEv1_FLAG_A		0x04
#define PF_IKEv2_FLAG_I		0x08
#define PF_IKEv2_FLAG_V		0x10
#define PF_IKEv2_FLAG_R		0x20

struct pf_esp_hdr {
	u_int32_t spi;
	u_int32_t seqno;
	u_int8_t payload[];
};

static __inline int
pf_src_compare(struct pf_src_node *a, struct pf_src_node *b)
{
	int	diff;

	if (a->rule.ptr > b->rule.ptr)
		return (1);
	if (a->rule.ptr < b->rule.ptr)
		return (-1);
	if ((diff = a->af - b->af) != 0)
		return (diff);
	switch (a->af) {
#if INET
	case AF_INET:
		if (a->addr.addr32[0] > b->addr.addr32[0])
			return (1);
		if (a->addr.addr32[0] < b->addr.addr32[0])
			return (-1);
		break;
#endif /* INET */
#if INET6
	case AF_INET6:
		if (a->addr.addr32[3] > b->addr.addr32[3])
			return (1);
		if (a->addr.addr32[3] < b->addr.addr32[3])
			return (-1);
		if (a->addr.addr32[2] > b->addr.addr32[2])
			return (1);
		if (a->addr.addr32[2] < b->addr.addr32[2])
			return (-1);
		if (a->addr.addr32[1] > b->addr.addr32[1])
			return (1);
		if (a->addr.addr32[1] < b->addr.addr32[1])
			return (-1);
		if (a->addr.addr32[0] > b->addr.addr32[0])
			return (1);
		if (a->addr.addr32[0] < b->addr.addr32[0])
			return (-1);
		break;
#endif /* INET6 */
	}
	return (0);
}

static __inline int
pf_state_compare_lan_ext(struct pf_state_key *a, struct pf_state_key *b)
{
	int	diff;
	int	extfilter;

	if ((diff = a->proto - b->proto) != 0)
		return (diff);
	if ((diff = a->af - b->af) != 0)
		return (diff);

	extfilter = PF_EXTFILTER_APD;

	switch (a->proto) {
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		if ((diff = a->lan.xport.port - b->lan.xport.port) != 0)
			return (diff);
		break;

	case IPPROTO_TCP:
		if ((diff = a->lan.xport.port - b->lan.xport.port) != 0)
			return (diff);
		if ((diff = a->ext.xport.port - b->ext.xport.port) != 0)
			return (diff);
		break;

	case IPPROTO_UDP:
		if ((diff = a->proto_variant - b->proto_variant))
			return (diff);
		extfilter = a->proto_variant;
		if ((diff = a->lan.xport.port - b->lan.xport.port) != 0)
			return (diff);
		if ((extfilter < PF_EXTFILTER_AD) &&
		    (diff = a->ext.xport.port - b->ext.xport.port) != 0)
			return (diff);
		break;

	case IPPROTO_GRE:
		if (a->proto_variant == PF_GRE_PPTP_VARIANT &&
		    a->proto_variant == b->proto_variant) {
			if (!!(diff = a->ext.xport.call_id -
			    b->ext.xport.call_id))
				return (diff);
		}
		break;

	case IPPROTO_ESP:
		if (!!(diff = a->ext.xport.spi - b->ext.xport.spi))
			return (diff);
		break;

	default:
		break;
	}

	switch (a->af) {
#if INET
	case AF_INET:
		if (a->lan.addr.addr32[0] > b->lan.addr.addr32[0])
			return (1);
		if (a->lan.addr.addr32[0] < b->lan.addr.addr32[0])
			return (-1);
		if (extfilter < PF_EXTFILTER_EI) {
			if (a->ext.addr.addr32[0] > b->ext.addr.addr32[0])
				return (1);
			if (a->ext.addr.addr32[0] < b->ext.addr.addr32[0])
				return (-1);
		}
		break;
#endif /* INET */
#if INET6
	case AF_INET6:
		if (a->lan.addr.addr32[3] > b->lan.addr.addr32[3])
			return (1);
		if (a->lan.addr.addr32[3] < b->lan.addr.addr32[3])
			return (-1);
		if (a->lan.addr.addr32[2] > b->lan.addr.addr32[2])
			return (1);
		if (a->lan.addr.addr32[2] < b->lan.addr.addr32[2])
			return (-1);
		if (a->lan.addr.addr32[1] > b->lan.addr.addr32[1])
			return (1);
		if (a->lan.addr.addr32[1] < b->lan.addr.addr32[1])
			return (-1);
		if (a->lan.addr.addr32[0] > b->lan.addr.addr32[0])
			return (1);
		if (a->lan.addr.addr32[0] < b->lan.addr.addr32[0])
			return (-1);
		if (extfilter < PF_EXTFILTER_EI ||
		    !PF_AZERO(&b->ext.addr, AF_INET6)) {
			if (a->ext.addr.addr32[3] > b->ext.addr.addr32[3])
				return (1);
			if (a->ext.addr.addr32[3] < b->ext.addr.addr32[3])
				return (-1);
			if (a->ext.addr.addr32[2] > b->ext.addr.addr32[2])
				return (1);
			if (a->ext.addr.addr32[2] < b->ext.addr.addr32[2])
				return (-1);
			if (a->ext.addr.addr32[1] > b->ext.addr.addr32[1])
				return (1);
			if (a->ext.addr.addr32[1] < b->ext.addr.addr32[1])
				return (-1);
			if (a->ext.addr.addr32[0] > b->ext.addr.addr32[0])
				return (1);
			if (a->ext.addr.addr32[0] < b->ext.addr.addr32[0])
				return (-1);
		}
		break;
#endif /* INET6 */
	}

	if (a->app_state && b->app_state) {
		if (a->app_state->compare_lan_ext &&
		    b->app_state->compare_lan_ext) {
			diff = (const char *)b->app_state->compare_lan_ext -
			    (const char *)a->app_state->compare_lan_ext;
			if (diff != 0)
				return (diff);
			diff = a->app_state->compare_lan_ext(a->app_state,
			    b->app_state);
			if (diff != 0)
				return (diff);
		}
	}

	return (0);
}

static __inline int
pf_state_compare_ext_gwy(struct pf_state_key *a, struct pf_state_key *b)
{
	int	diff;
	int	extfilter;

	if ((diff = a->proto - b->proto) != 0)
		return (diff);

	if ((diff = a->af - b->af) != 0)
		return (diff);

	extfilter = PF_EXTFILTER_APD;

	switch (a->proto) {
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		if ((diff = a->gwy.xport.port - b->gwy.xport.port) != 0)
			return (diff);
		break;

	case IPPROTO_TCP:
		if ((diff = a->ext.xport.port - b->ext.xport.port) != 0)
			return (diff);
		if ((diff = a->gwy.xport.port - b->gwy.xport.port) != 0)
			return (diff);
		break;

	case IPPROTO_UDP:
		if ((diff = a->proto_variant - b->proto_variant))
			return (diff);
		extfilter = a->proto_variant;
		if ((diff = a->gwy.xport.port - b->gwy.xport.port) != 0)
			return (diff);
		if ((extfilter < PF_EXTFILTER_AD) &&
		    (diff = a->ext.xport.port - b->ext.xport.port) != 0)
			return (diff);
		break;

	case IPPROTO_GRE:
		if (a->proto_variant == PF_GRE_PPTP_VARIANT &&
		    a->proto_variant == b->proto_variant) {
			if (!!(diff = a->gwy.xport.call_id -
			    b->gwy.xport.call_id))
				return (diff);
		}
		break;

	case IPPROTO_ESP:
		if (!!(diff = a->gwy.xport.spi - b->gwy.xport.spi))
			return (diff);
		break;

	default:
		break;
	}

	switch (a->af) {
#if INET
	case AF_INET:
		if (a->gwy.addr.addr32[0] > b->gwy.addr.addr32[0])
			return (1);
		if (a->gwy.addr.addr32[0] < b->gwy.addr.addr32[0])
			return (-1);
		if (extfilter < PF_EXTFILTER_EI) {
			if (a->ext.addr.addr32[0] > b->ext.addr.addr32[0])
				return (1);
			if (a->ext.addr.addr32[0] < b->ext.addr.addr32[0])
				return (-1);
		}
		break;
#endif /* INET */
#if INET6
	case AF_INET6:
		if (a->gwy.addr.addr32[3] > b->gwy.addr.addr32[3])
			return (1);
		if (a->gwy.addr.addr32[3] < b->gwy.addr.addr32[3])
			return (-1);
		if (a->gwy.addr.addr32[2] > b->gwy.addr.addr32[2])
			return (1);
		if (a->gwy.addr.addr32[2] < b->gwy.addr.addr32[2])
			return (-1);
		if (a->gwy.addr.addr32[1] > b->gwy.addr.addr32[1])
			return (1);
		if (a->gwy.addr.addr32[1] < b->gwy.addr.addr32[1])
			return (-1);
		if (a->gwy.addr.addr32[0] > b->gwy.addr.addr32[0])
			return (1);
		if (a->gwy.addr.addr32[0] < b->gwy.addr.addr32[0])
			return (-1);
		if (extfilter < PF_EXTFILTER_EI ||
		    !PF_AZERO(&b->ext.addr, AF_INET6)) {
			if (a->ext.addr.addr32[3] > b->ext.addr.addr32[3])
				return (1);
			if (a->ext.addr.addr32[3] < b->ext.addr.addr32[3])
				return (-1);
			if (a->ext.addr.addr32[2] > b->ext.addr.addr32[2])
				return (1);
			if (a->ext.addr.addr32[2] < b->ext.addr.addr32[2])
				return (-1);
			if (a->ext.addr.addr32[1] > b->ext.addr.addr32[1])
				return (1);
			if (a->ext.addr.addr32[1] < b->ext.addr.addr32[1])
				return (-1);
			if (a->ext.addr.addr32[0] > b->ext.addr.addr32[0])
				return (1);
			if (a->ext.addr.addr32[0] < b->ext.addr.addr32[0])
				return (-1);
		}
		break;
#endif /* INET6 */
	}

	if (a->app_state && b->app_state) {
		if (a->app_state->compare_ext_gwy &&
		    b->app_state->compare_ext_gwy) {
			diff = (const char *)b->app_state->compare_ext_gwy -
			    (const char *)a->app_state->compare_ext_gwy;
			if (diff != 0)
				return (diff);
			diff = a->app_state->compare_ext_gwy(a->app_state,
			    b->app_state);
			if (diff != 0)
				return (diff);
		}
	}

	return (0);
}

static __inline int
pf_state_compare_id(struct pf_state *a, struct pf_state *b)
{
	if (a->id > b->id)
		return (1);
	if (a->id < b->id)
		return (-1);
	if (a->creatorid > b->creatorid)
		return (1);
	if (a->creatorid < b->creatorid)
		return (-1);

	return (0);
}

#if INET6
void
pf_addrcpy(struct pf_addr *dst, struct pf_addr *src, sa_family_t af)
{
	switch (af) {
#if INET
	case AF_INET:
		dst->addr32[0] = src->addr32[0];
		break;
#endif /* INET */
	case AF_INET6:
		dst->addr32[0] = src->addr32[0];
		dst->addr32[1] = src->addr32[1];
		dst->addr32[2] = src->addr32[2];
		dst->addr32[3] = src->addr32[3];
		break;
	}
}
#endif /* INET6 */

struct pf_state *
pf_find_state_byid(struct pf_state_cmp *key)
{
	pf_status.fcounters[FCNT_STATE_SEARCH]++;

	return (RB_FIND(pf_state_tree_id, &tree_id,
	    (struct pf_state *)(void *)key));
}

static struct pf_state *
pf_find_state(struct pfi_kif *kif, struct pf_state_key_cmp *key, u_int dir)
{
	struct pf_state_key	*sk = NULL;
	struct pf_state		*s;

	pf_status.fcounters[FCNT_STATE_SEARCH]++;

	switch (dir) {
	case PF_OUT:
		sk = RB_FIND(pf_state_tree_lan_ext, &pf_statetbl_lan_ext,
		    (struct pf_state_key *)key);
		break;
	case PF_IN:
		sk = RB_FIND(pf_state_tree_ext_gwy, &pf_statetbl_ext_gwy,
		    (struct pf_state_key *)key);
		break;
	default:
		panic("pf_find_state");
	}

	/* list is sorted, if-bound states before floating ones */
	if (sk != NULL)
		TAILQ_FOREACH(s, &sk->states, next)
			if (s->kif == pfi_all || s->kif == kif)
				return (s);

	return (NULL);
}

struct pf_state *
pf_find_state_all(struct pf_state_key_cmp *key, u_int dir, int *more)
{
	struct pf_state_key	*sk = NULL;
	struct pf_state		*s, *ret = NULL;

	pf_status.fcounters[FCNT_STATE_SEARCH]++;

	switch (dir) {
	case PF_OUT:
		sk = RB_FIND(pf_state_tree_lan_ext,
		    &pf_statetbl_lan_ext, (struct pf_state_key *)key);
		break;
	case PF_IN:
		sk = RB_FIND(pf_state_tree_ext_gwy,
		    &pf_statetbl_ext_gwy, (struct pf_state_key *)key);
		break;
	default:
		panic("pf_find_state_all");
	}

	if (sk != NULL) {
		ret = TAILQ_FIRST(&sk->states);
		if (more == NULL)
			return (ret);

		TAILQ_FOREACH(s, &sk->states, next)
			(*more)++;
	}

	return (ret);
}

static void
pf_init_threshold(struct pf_threshold *threshold,
    u_int32_t limit, u_int32_t seconds)
{
	threshold->limit = limit * PF_THRESHOLD_MULT;
	threshold->seconds = seconds;
	threshold->count = 0;
	threshold->last = pf_time_second();
}

static void
pf_add_threshold(struct pf_threshold *threshold)
{
	u_int32_t t = pf_time_second(), diff = t - threshold->last;

	if (diff >= threshold->seconds)
		threshold->count = 0;
	else
		threshold->count -= threshold->count * diff /
		    threshold->seconds;
	threshold->count += PF_THRESHOLD_MULT;
	threshold->last = t;
}

static int
pf_check_threshold(struct pf_threshold *threshold)
{
	return (threshold->count > threshold->limit);
}

static int
pf_src_connlimit(struct pf_state **state)
{
	int bad = 0;

	(*state)->src_node->conn++;
	VERIFY((*state)->src_node->conn != 0);
	(*state)->src.tcp_est = 1;
	pf_add_threshold(&(*state)->src_node->conn_rate);

	if ((*state)->rule.ptr->max_src_conn &&
	    (*state)->rule.ptr->max_src_conn <
	    (*state)->src_node->conn) {
		pf_status.lcounters[LCNT_SRCCONN]++;
		bad++;
	}

	if ((*state)->rule.ptr->max_src_conn_rate.limit &&
	    pf_check_threshold(&(*state)->src_node->conn_rate)) {
		pf_status.lcounters[LCNT_SRCCONNRATE]++;
		bad++;
	}

	if (!bad)
		return (0);

	if ((*state)->rule.ptr->overload_tbl) {
		struct pfr_addr p;
		u_int32_t	killed = 0;

		pf_status.lcounters[LCNT_OVERLOAD_TABLE]++;
		if (pf_status.debug >= PF_DEBUG_MISC) {
			printf("pf_src_connlimit: blocking address ");
			pf_print_host(&(*state)->src_node->addr, 0,
			    (*state)->state_key->af);
		}

		bzero(&p, sizeof (p));
		p.pfra_af = (*state)->state_key->af;
		switch ((*state)->state_key->af) {
#if INET
		case AF_INET:
			p.pfra_net = 32;
			p.pfra_ip4addr = (*state)->src_node->addr.v4;
			break;
#endif /* INET */
#if INET6
		case AF_INET6:
			p.pfra_net = 128;
			p.pfra_ip6addr = (*state)->src_node->addr.v6;
			break;
#endif /* INET6 */
		}

		pfr_insert_kentry((*state)->rule.ptr->overload_tbl,
		    &p, pf_calendar_time_second());

		/* kill existing states if that's required. */
		if ((*state)->rule.ptr->flush) {
			struct pf_state_key *sk;
			struct pf_state *st;

			pf_status.lcounters[LCNT_OVERLOAD_FLUSH]++;
			RB_FOREACH(st, pf_state_tree_id, &tree_id) {
				sk = st->state_key;
				/*
				 * Kill states from this source.  (Only those
				 * from the same rule if PF_FLUSH_GLOBAL is not
				 * set)
				 */
				if (sk->af ==
				    (*state)->state_key->af &&
				    (((*state)->state_key->direction ==
				        PF_OUT &&
				    PF_AEQ(&(*state)->src_node->addr,
				        &sk->lan.addr, sk->af)) ||
				    ((*state)->state_key->direction == PF_IN &&
				    PF_AEQ(&(*state)->src_node->addr,
				        &sk->ext.addr, sk->af))) &&
				    ((*state)->rule.ptr->flush &
				    PF_FLUSH_GLOBAL ||
				    (*state)->rule.ptr == st->rule.ptr)) {
					st->timeout = PFTM_PURGE;
					st->src.state = st->dst.state =
					    TCPS_CLOSED;
					killed++;
				}
			}
			if (pf_status.debug >= PF_DEBUG_MISC)
				printf(", %u states killed", killed);
		}
		if (pf_status.debug >= PF_DEBUG_MISC)
			printf("\n");
	}

	/* kill this state */
	(*state)->timeout = PFTM_PURGE;
	(*state)->src.state = (*state)->dst.state = TCPS_CLOSED;
	return (1);
}

int
pf_insert_src_node(struct pf_src_node **sn, struct pf_rule *rule,
    struct pf_addr *src, sa_family_t af)
{
	struct pf_src_node	k;

	if (*sn == NULL) {
		k.af = af;
		PF_ACPY(&k.addr, src, af);
		if (rule->rule_flag & PFRULE_RULESRCTRACK ||
		    rule->rpool.opts & PF_POOL_STICKYADDR)
			k.rule.ptr = rule;
		else
			k.rule.ptr = NULL;
		pf_status.scounters[SCNT_SRC_NODE_SEARCH]++;
		*sn = RB_FIND(pf_src_tree, &tree_src_tracking, &k);
	}
	if (*sn == NULL) {
		if (!rule->max_src_nodes ||
		    rule->src_nodes < rule->max_src_nodes)
			(*sn) = pool_get(&pf_src_tree_pl, PR_WAITOK);
		else
			pf_status.lcounters[LCNT_SRCNODES]++;
		if ((*sn) == NULL)
			return (-1);
		bzero(*sn, sizeof (struct pf_src_node));

		pf_init_threshold(&(*sn)->conn_rate,
		    rule->max_src_conn_rate.limit,
		    rule->max_src_conn_rate.seconds);

		(*sn)->af = af;
		if (rule->rule_flag & PFRULE_RULESRCTRACK ||
		    rule->rpool.opts & PF_POOL_STICKYADDR)
			(*sn)->rule.ptr = rule;
		else
			(*sn)->rule.ptr = NULL;
		PF_ACPY(&(*sn)->addr, src, af);
		if (RB_INSERT(pf_src_tree,
		    &tree_src_tracking, *sn) != NULL) {
			if (pf_status.debug >= PF_DEBUG_MISC) {
				printf("pf: src_tree insert failed: ");
				pf_print_host(&(*sn)->addr, 0, af);
				printf("\n");
			}
			pool_put(&pf_src_tree_pl, *sn);
			return (-1);
		}
		(*sn)->creation = pf_time_second();
		(*sn)->ruletype = rule->action;
		if ((*sn)->rule.ptr != NULL)
			(*sn)->rule.ptr->src_nodes++;
		pf_status.scounters[SCNT_SRC_NODE_INSERT]++;
		pf_status.src_nodes++;
	} else {
		if (rule->max_src_states &&
		    (*sn)->states >= rule->max_src_states) {
			pf_status.lcounters[LCNT_SRCSTATES]++;
			return (-1);
		}
	}
	return (0);
}

static void
pf_stateins_err(const char *tree, struct pf_state *s, struct pfi_kif *kif)
{
	struct pf_state_key	*sk = s->state_key;

	if (pf_status.debug >= PF_DEBUG_MISC) {
		printf("pf: state insert failed: %s %s ", tree, kif->pfik_name);
		switch (sk->proto) {
		case IPPROTO_TCP:
			printf("TCP");
			break;
		case IPPROTO_UDP:
			printf("UDP");
			break;
		case IPPROTO_ICMP:
			printf("ICMP4");
			break;
		case IPPROTO_ICMPV6:
			printf("ICMP6");
			break;
		default:
			printf("PROTO=%u", sk->proto);
			break;
		}
		printf(" lan: ");
		pf_print_sk_host(&sk->lan, sk->af, sk->proto,
		    sk->proto_variant);
		printf(" gwy: ");
		pf_print_sk_host(&sk->gwy, sk->af, sk->proto,
		    sk->proto_variant);
		printf(" ext: ");
		pf_print_sk_host(&sk->ext, sk->af, sk->proto,
		    sk->proto_variant);
		if (s->sync_flags & PFSTATE_FROMSYNC)
			printf(" (from sync)");
		printf("\n");
	}
}

int
pf_insert_state(struct pfi_kif *kif, struct pf_state *s)
{
	struct pf_state_key	*cur;
	struct pf_state		*sp;

	VERIFY(s->state_key != NULL);
	s->kif = kif;

	if ((cur = RB_INSERT(pf_state_tree_lan_ext, &pf_statetbl_lan_ext,
	    s->state_key)) != NULL) {
		/* key exists. check for same kif, if none, add to key */
		TAILQ_FOREACH(sp, &cur->states, next)
			if (sp->kif == kif) {	/* collision! */
				pf_stateins_err("tree_lan_ext", s, kif);
				pf_detach_state(s,
				    PF_DT_SKIP_LANEXT|PF_DT_SKIP_EXTGWY);
				return (-1);
			}
		pf_detach_state(s, PF_DT_SKIP_LANEXT|PF_DT_SKIP_EXTGWY);
		pf_attach_state(cur, s, kif == pfi_all ? 1 : 0);
	}

	/* if cur != NULL, we already found a state key and attached to it */
	if (cur == NULL && (cur = RB_INSERT(pf_state_tree_ext_gwy,
	    &pf_statetbl_ext_gwy, s->state_key)) != NULL) {
		/* must not happen. we must have found the sk above! */
		pf_stateins_err("tree_ext_gwy", s, kif);
		pf_detach_state(s, PF_DT_SKIP_EXTGWY);
		return (-1);
	}

	if (s->id == 0 && s->creatorid == 0) {
		s->id = htobe64(pf_status.stateid++);
		s->creatorid = pf_status.hostid;
	}
	if (RB_INSERT(pf_state_tree_id, &tree_id, s) != NULL) {
		if (pf_status.debug >= PF_DEBUG_MISC) {
			printf("pf: state insert failed: "
			    "id: %016llx creatorid: %08x",
			    be64toh(s->id), ntohl(s->creatorid));
			if (s->sync_flags & PFSTATE_FROMSYNC)
				printf(" (from sync)");
			printf("\n");
		}
		pf_detach_state(s, 0);
		return (-1);
	}
	TAILQ_INSERT_TAIL(&state_list, s, entry_list);
	pf_status.fcounters[FCNT_STATE_INSERT]++;
	pf_status.states++;
	VERIFY(pf_status.states != 0);
	pfi_kif_ref(kif, PFI_KIF_REF_STATE);
#if NPFSYNC
	pfsync_insert_state(s);
#endif
	return (0);
}

static int
pf_purge_thread_cont(int err)
{
#pragma unused(err)
	static u_int32_t nloops = 0;
	int t = 1;	/* 1 second */

	/*
	 * Update coarse-grained networking timestamp (in sec.); the idea
	 * is to piggy-back on the periodic timeout callout to update
	 * the counter returnable via net_uptime().
	 */
	net_update_uptime();

	lck_rw_lock_shared(pf_perim_lock);
	lck_mtx_lock(pf_lock);

	/* purge everything if not running */
	if (!pf_status.running) {
		pf_purge_expired_states(pf_status.states);
		pf_purge_expired_fragments();
		pf_purge_expired_src_nodes();

		/* terminate thread (we don't currently do this) */
		if (pf_purge_thread == NULL) {
			lck_mtx_unlock(pf_lock);
			lck_rw_done(pf_perim_lock);

			thread_deallocate(current_thread());
			thread_terminate(current_thread());
			/* NOTREACHED */
			return (0);
		} else {
			/* if there's nothing left, sleep w/o timeout */
			if (pf_status.states == 0 &&
			    pf_normalize_isempty() &&
			    RB_EMPTY(&tree_src_tracking)) {
				nloops = 0;
				t = 0;
			}
			goto done;
		}
	}

	/* process a fraction of the state table every second */
	pf_purge_expired_states(1 + (pf_status.states
	    / pf_default_rule.timeout[PFTM_INTERVAL]));

	/* purge other expired types every PFTM_INTERVAL seconds */
	if (++nloops >= pf_default_rule.timeout[PFTM_INTERVAL]) {
		pf_purge_expired_fragments();
		pf_purge_expired_src_nodes();
		nloops = 0;
	}
done:
	lck_mtx_unlock(pf_lock);
	lck_rw_done(pf_perim_lock);

	(void) tsleep0(pf_purge_thread_fn, PWAIT, "pf_purge_cont",
	    t * hz, pf_purge_thread_cont);
	/* NOTREACHED */
	VERIFY(0);

	return (0);
}

void
pf_purge_thread_fn(void *v, wait_result_t w)
{
#pragma unused(v, w)
	(void) tsleep0(pf_purge_thread_fn, PWAIT, "pf_purge", 0,
	    pf_purge_thread_cont);
	/*
	 * tsleep0() shouldn't have returned as PCATCH was not set;
	 * therefore assert in this case.
	 */
	VERIFY(0);
}

u_int64_t
pf_state_expires(const struct pf_state *state)
{
	u_int32_t	t;
	u_int32_t	start;
	u_int32_t	end;
	u_int32_t	states;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	/* handle all PFTM_* > PFTM_MAX here */
	if (state->timeout == PFTM_PURGE)
		return (pf_time_second());
	if (state->timeout == PFTM_UNTIL_PACKET)
		return (0);
	VERIFY(state->timeout != PFTM_UNLINKED);
	VERIFY(state->timeout < PFTM_MAX);
	t = state->rule.ptr->timeout[state->timeout];
	if (!t)
		t = pf_default_rule.timeout[state->timeout];
	start = state->rule.ptr->timeout[PFTM_ADAPTIVE_START];
	if (start) {
		end = state->rule.ptr->timeout[PFTM_ADAPTIVE_END];
		states = state->rule.ptr->states;
	} else {
		start = pf_default_rule.timeout[PFTM_ADAPTIVE_START];
		end = pf_default_rule.timeout[PFTM_ADAPTIVE_END];
		states = pf_status.states;
	}
	if (end && states > start && start < end) {
		if (states < end)
			return (state->expire + t * (end - states) /
			    (end - start));
		else
			return (pf_time_second());
	}
	return (state->expire + t);
}

void
pf_purge_expired_src_nodes(void)
{
	struct pf_src_node		*cur, *next;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	for (cur = RB_MIN(pf_src_tree, &tree_src_tracking); cur; cur = next) {
		next = RB_NEXT(pf_src_tree, &tree_src_tracking, cur);

		if (cur->states <= 0 && cur->expire <= pf_time_second()) {
			if (cur->rule.ptr != NULL) {
				cur->rule.ptr->src_nodes--;
				if (cur->rule.ptr->states <= 0 &&
				    cur->rule.ptr->max_src_nodes <= 0)
					pf_rm_rule(NULL, cur->rule.ptr);
			}
			RB_REMOVE(pf_src_tree, &tree_src_tracking, cur);
			pf_status.scounters[SCNT_SRC_NODE_REMOVALS]++;
			pf_status.src_nodes--;
			pool_put(&pf_src_tree_pl, cur);
		}
	}
}

void
pf_src_tree_remove_state(struct pf_state *s)
{
	u_int32_t t;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if (s->src_node != NULL) {
		if (s->src.tcp_est) {
			VERIFY(s->src_node->conn > 0);
			--s->src_node->conn;
		}
		VERIFY(s->src_node->states > 0);
		if (--s->src_node->states <= 0) {
			t = s->rule.ptr->timeout[PFTM_SRC_NODE];
			if (!t)
				t = pf_default_rule.timeout[PFTM_SRC_NODE];
			s->src_node->expire = pf_time_second() + t;
		}
	}
	if (s->nat_src_node != s->src_node && s->nat_src_node != NULL) {
		VERIFY(s->nat_src_node->states > 0);
		if (--s->nat_src_node->states <= 0) {
			t = s->rule.ptr->timeout[PFTM_SRC_NODE];
			if (!t)
				t = pf_default_rule.timeout[PFTM_SRC_NODE];
			s->nat_src_node->expire = pf_time_second() + t;
		}
	}
	s->src_node = s->nat_src_node = NULL;
}

void
pf_unlink_state(struct pf_state *cur)
{
	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if (cur->src.state == PF_TCPS_PROXY_DST) {
		pf_send_tcp(cur->rule.ptr, cur->state_key->af,
		    &cur->state_key->ext.addr, &cur->state_key->lan.addr,
		    cur->state_key->ext.xport.port,
		    cur->state_key->lan.xport.port,
		    cur->src.seqhi, cur->src.seqlo + 1,
		    TH_RST|TH_ACK, 0, 0, 0, 1, cur->tag, NULL, NULL);
	}

	hook_runloop(&cur->unlink_hooks, HOOK_REMOVE|HOOK_FREE);
	RB_REMOVE(pf_state_tree_id, &tree_id, cur);
#if NPFSYNC
	if (cur->creatorid == pf_status.hostid)
		pfsync_delete_state(cur);
#endif
	cur->timeout = PFTM_UNLINKED;
	pf_src_tree_remove_state(cur);
	pf_detach_state(cur, 0);
}

/* callers should be at splpf and hold the
 * write_lock on pf_consistency_lock */
void
pf_free_state(struct pf_state *cur)
{
	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);
#if NPFSYNC
	if (pfsyncif != NULL &&
	    (pfsyncif->sc_bulk_send_next == cur ||
	    pfsyncif->sc_bulk_terminator == cur))
		return;
#endif
	VERIFY(cur->timeout == PFTM_UNLINKED);
	VERIFY(cur->rule.ptr->states > 0);
	if (--cur->rule.ptr->states <= 0 &&
	    cur->rule.ptr->src_nodes <= 0)
		pf_rm_rule(NULL, cur->rule.ptr);
	if (cur->nat_rule.ptr != NULL) {
		VERIFY(cur->nat_rule.ptr->states > 0);
		if (--cur->nat_rule.ptr->states <= 0 &&
		    cur->nat_rule.ptr->src_nodes <= 0)
			pf_rm_rule(NULL, cur->nat_rule.ptr);
	}
	if (cur->anchor.ptr != NULL) {
		VERIFY(cur->anchor.ptr->states > 0);
		if (--cur->anchor.ptr->states <= 0)
			pf_rm_rule(NULL, cur->anchor.ptr);
	}
	pf_normalize_tcp_cleanup(cur);
	pfi_kif_unref(cur->kif, PFI_KIF_REF_STATE);
	TAILQ_REMOVE(&state_list, cur, entry_list);
	if (cur->tag)
		pf_tag_unref(cur->tag);
	pool_put(&pf_state_pl, cur);
	pf_status.fcounters[FCNT_STATE_REMOVALS]++;
	VERIFY(pf_status.states > 0);
	pf_status.states--;
}

void
pf_purge_expired_states(u_int32_t maxcheck)
{
	static struct pf_state	*cur = NULL;
	struct pf_state		*next;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	while (maxcheck--) {
		/* wrap to start of list when we hit the end */
		if (cur == NULL) {
			cur = TAILQ_FIRST(&state_list);
			if (cur == NULL)
				break;	/* list empty */
		}

		/* get next state, as cur may get deleted */
		next = TAILQ_NEXT(cur, entry_list);

		if (cur->timeout == PFTM_UNLINKED) {
			pf_free_state(cur);
		} else if (pf_state_expires(cur) <= pf_time_second()) {
			/* unlink and free expired state */
			pf_unlink_state(cur);
			pf_free_state(cur);
		}
		cur = next;
	}
}

int
pf_tbladdr_setup(struct pf_ruleset *rs, struct pf_addr_wrap *aw)
{
	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if (aw->type != PF_ADDR_TABLE)
		return (0);
	if ((aw->p.tbl = pfr_attach_table(rs, aw->v.tblname)) == NULL)
		return (1);
	return (0);
}

void
pf_tbladdr_remove(struct pf_addr_wrap *aw)
{
	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if (aw->type != PF_ADDR_TABLE || aw->p.tbl == NULL)
		return;
	pfr_detach_table(aw->p.tbl);
	aw->p.tbl = NULL;
}

void
pf_tbladdr_copyout(struct pf_addr_wrap *aw)
{
	struct pfr_ktable *kt = aw->p.tbl;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if (aw->type != PF_ADDR_TABLE || kt == NULL)
		return;
	if (!(kt->pfrkt_flags & PFR_TFLAG_ACTIVE) && kt->pfrkt_root != NULL)
		kt = kt->pfrkt_root;
	aw->p.tbl = NULL;
	aw->p.tblcnt = (kt->pfrkt_flags & PFR_TFLAG_ACTIVE) ?
	    kt->pfrkt_cnt : -1;
}

static void
pf_print_addr(struct pf_addr *addr, sa_family_t af)
{
	switch (af) {
#if INET
	case AF_INET: {
		u_int32_t a = ntohl(addr->addr32[0]);
		printf("%u.%u.%u.%u", (a>>24)&255, (a>>16)&255,
		    (a>>8)&255, a&255);
		break;
	}
#endif /* INET */
#if INET6
	case AF_INET6: {
		u_int16_t b;
		u_int8_t i, curstart = 255, curend = 0,
		    maxstart = 0, maxend = 0;
		for (i = 0; i < 8; i++) {
			if (!addr->addr16[i]) {
				if (curstart == 255)
					curstart = i;
				else
					curend = i;
			} else {
				if (curstart) {
					if ((curend - curstart) >
					    (maxend - maxstart)) {
						maxstart = curstart;
						maxend = curend;
						curstart = 255;
					}
				}
			}
		}
		for (i = 0; i < 8; i++) {
			if (i >= maxstart && i <= maxend) {
				if (maxend != 7) {
					if (i == maxstart)
						printf(":");
				} else {
					if (i == maxend)
						printf(":");
				}
			} else {
				b = ntohs(addr->addr16[i]);
				printf("%x", b);
				if (i < 7)
					printf(":");
			}
		}
		break;
	}
#endif /* INET6 */
	}
}

static void
pf_print_sk_host(struct pf_state_host *sh, sa_family_t af, int proto,
	u_int8_t proto_variant)
{
	pf_print_addr(&sh->addr, af);

	switch (proto) {
	case IPPROTO_ESP:
		if (sh->xport.spi)
			printf("[%08x]", ntohl(sh->xport.spi));
		break;

	case IPPROTO_GRE:
		if (proto_variant == PF_GRE_PPTP_VARIANT)
			printf("[%u]", ntohs(sh->xport.call_id));
		break;

	case IPPROTO_TCP:
	case IPPROTO_UDP:
		printf("[%u]", ntohs(sh->xport.port));
		break;

	default:
		break;
	}
}

static void
pf_print_host(struct pf_addr *addr, u_int16_t p, sa_family_t af)
{
	pf_print_addr(addr, af);
	if (p)
		printf("[%u]", ntohs(p));
}

void
pf_print_state(struct pf_state *s)
{
	struct pf_state_key *sk = s->state_key;
	switch (sk->proto) {
	case IPPROTO_ESP:
		printf("ESP ");
		break;
	case IPPROTO_GRE:
		printf("GRE%u ", sk->proto_variant);
		break;
	case IPPROTO_TCP:
		printf("TCP ");
		break;
	case IPPROTO_UDP:
		printf("UDP ");
		break;
	case IPPROTO_ICMP:
		printf("ICMP ");
		break;
	case IPPROTO_ICMPV6:
		printf("ICMPV6 ");
		break;
	default:
		printf("%u ", sk->proto);
		break;
	}
	pf_print_sk_host(&sk->lan, sk->af, sk->proto, sk->proto_variant);
	printf(" ");
	pf_print_sk_host(&sk->gwy, sk->af, sk->proto, sk->proto_variant);
	printf(" ");
	pf_print_sk_host(&sk->ext, sk->af, sk->proto, sk->proto_variant);
	printf(" [lo=%u high=%u win=%u modulator=%u", s->src.seqlo,
	    s->src.seqhi, s->src.max_win, s->src.seqdiff);
	if (s->src.wscale && s->dst.wscale)
		printf(" wscale=%u", s->src.wscale & PF_WSCALE_MASK);
	printf("]");
	printf(" [lo=%u high=%u win=%u modulator=%u", s->dst.seqlo,
	    s->dst.seqhi, s->dst.max_win, s->dst.seqdiff);
	if (s->src.wscale && s->dst.wscale)
		printf(" wscale=%u", s->dst.wscale & PF_WSCALE_MASK);
	printf("]");
	printf(" %u:%u", s->src.state, s->dst.state);
}

void
pf_print_flags(u_int8_t f)
{
	if (f)
		printf(" ");
	if (f & TH_FIN)
		printf("F");
	if (f & TH_SYN)
		printf("S");
	if (f & TH_RST)
		printf("R");
	if (f & TH_PUSH)
		printf("P");
	if (f & TH_ACK)
		printf("A");
	if (f & TH_URG)
		printf("U");
	if (f & TH_ECE)
		printf("E");
	if (f & TH_CWR)
		printf("W");
}

#define	PF_SET_SKIP_STEPS(i)					\
	do {							\
		while (head[i] != cur) {			\
			head[i]->skip[i].ptr = cur;		\
			head[i] = TAILQ_NEXT(head[i], entries);	\
		}						\
	} while (0)

void
pf_calc_skip_steps(struct pf_rulequeue *rules)
{
	struct pf_rule *cur, *prev, *head[PF_SKIP_COUNT];
	int i;

	cur = TAILQ_FIRST(rules);
	prev = cur;
	for (i = 0; i < PF_SKIP_COUNT; ++i)
		head[i] = cur;
	while (cur != NULL) {

		if (cur->kif != prev->kif || cur->ifnot != prev->ifnot)
			PF_SET_SKIP_STEPS(PF_SKIP_IFP);
		if (cur->direction != prev->direction)
			PF_SET_SKIP_STEPS(PF_SKIP_DIR);
		if (cur->af != prev->af)
			PF_SET_SKIP_STEPS(PF_SKIP_AF);
		if (cur->proto != prev->proto)
			PF_SET_SKIP_STEPS(PF_SKIP_PROTO);
		if (cur->src.neg != prev->src.neg ||
		    pf_addr_wrap_neq(&cur->src.addr, &prev->src.addr))
			PF_SET_SKIP_STEPS(PF_SKIP_SRC_ADDR);
		{
			union pf_rule_xport *cx = &cur->src.xport;
			union pf_rule_xport *px = &prev->src.xport;

			switch (cur->proto) {
			case IPPROTO_GRE:
			case IPPROTO_ESP:
				PF_SET_SKIP_STEPS(PF_SKIP_SRC_PORT);
				break;
			default:
				if (prev->proto == IPPROTO_GRE ||
				    prev->proto == IPPROTO_ESP ||
				    cx->range.op != px->range.op ||
				    cx->range.port[0] != px->range.port[0] ||
				    cx->range.port[1] != px->range.port[1])
					PF_SET_SKIP_STEPS(PF_SKIP_SRC_PORT);
				break;
			}
		}
		if (cur->dst.neg != prev->dst.neg ||
		    pf_addr_wrap_neq(&cur->dst.addr, &prev->dst.addr))
			PF_SET_SKIP_STEPS(PF_SKIP_DST_ADDR);
		{
			union pf_rule_xport *cx = &cur->dst.xport;
			union pf_rule_xport *px = &prev->dst.xport;

			switch (cur->proto) {
			case IPPROTO_GRE:
				if (cur->proto != prev->proto ||
				    cx->call_id != px->call_id)
					PF_SET_SKIP_STEPS(PF_SKIP_DST_PORT);
				break;
			case IPPROTO_ESP:
				if (cur->proto != prev->proto ||
				    cx->spi != px->spi)
					PF_SET_SKIP_STEPS(PF_SKIP_DST_PORT);
				break;
			default:
				if (prev->proto == IPPROTO_GRE ||
				    prev->proto == IPPROTO_ESP ||
				    cx->range.op != px->range.op ||
				    cx->range.port[0] != px->range.port[0] ||
				    cx->range.port[1] != px->range.port[1])
					PF_SET_SKIP_STEPS(PF_SKIP_DST_PORT);
				break;
			}
		}

		prev = cur;
		cur = TAILQ_NEXT(cur, entries);
	}
	for (i = 0; i < PF_SKIP_COUNT; ++i)
		PF_SET_SKIP_STEPS(i);
}

u_int32_t
pf_calc_state_key_flowhash(struct pf_state_key *sk)
{
	struct pf_flowhash_key fh __attribute__((aligned(8)));
	uint32_t flowhash = 0;

	bzero(&fh, sizeof (fh));
	if (PF_ALEQ(&sk->lan.addr, &sk->ext.addr, sk->af)) {
		bcopy(&sk->lan.addr, &fh.ap1.addr, sizeof (fh.ap1.addr));
		bcopy(&sk->ext.addr, &fh.ap2.addr, sizeof (fh.ap2.addr));
	} else {
		bcopy(&sk->ext.addr, &fh.ap1.addr, sizeof (fh.ap1.addr));
		bcopy(&sk->lan.addr, &fh.ap2.addr, sizeof (fh.ap2.addr));
	}
	if (sk->lan.xport.spi <= sk->ext.xport.spi) {
		fh.ap1.xport.spi = sk->lan.xport.spi;
		fh.ap2.xport.spi = sk->ext.xport.spi;
	} else {
		fh.ap1.xport.spi = sk->ext.xport.spi;
		fh.ap2.xport.spi = sk->lan.xport.spi;
	}
	fh.af = sk->af;
	fh.proto = sk->proto;

try_again:
	flowhash = net_flowhash(&fh, sizeof (fh), pf_hash_seed);
	if (flowhash == 0) {
		/* try to get a non-zero flowhash */
		pf_hash_seed = RandomULong();
		goto try_again;
	}

	return (flowhash);
}

static int
pf_addr_wrap_neq(struct pf_addr_wrap *aw1, struct pf_addr_wrap *aw2)
{
	if (aw1->type != aw2->type)
		return (1);
	switch (aw1->type) {
	case PF_ADDR_ADDRMASK:
	case PF_ADDR_RANGE:
		if (PF_ANEQ(&aw1->v.a.addr, &aw2->v.a.addr, 0))
			return (1);
		if (PF_ANEQ(&aw1->v.a.mask, &aw2->v.a.mask, 0))
			return (1);
		return (0);
	case PF_ADDR_DYNIFTL:
		return (aw1->p.dyn == NULL || aw2->p.dyn == NULL ||
		    aw1->p.dyn->pfid_kt != aw2->p.dyn->pfid_kt);
	case PF_ADDR_NOROUTE:
	case PF_ADDR_URPFFAILED:
		return (0);
	case PF_ADDR_TABLE:
		return (aw1->p.tbl != aw2->p.tbl);
	case PF_ADDR_RTLABEL:
		return (aw1->v.rtlabel != aw2->v.rtlabel);
	default:
		printf("invalid address type: %d\n", aw1->type);
		return (1);
	}
}

u_int16_t
pf_cksum_fixup(u_int16_t cksum, u_int16_t old, u_int16_t new, u_int8_t udp)
{
	u_int32_t	l;

	if (udp && !cksum)
		return (0);
	l = cksum + old - new;
	l = (l >> 16) + (l & 0xffff);
	l = l & 0xffff;
	if (udp && !l)
		return (0xffff);
	return (l);
}

static void
pf_change_ap(int dir, struct mbuf *m, struct pf_addr *a, u_int16_t *p,
    u_int16_t *ic, u_int16_t *pc, struct pf_addr *an, u_int16_t pn,
    u_int8_t u, sa_family_t af)
{
	struct pf_addr	ao;
	u_int16_t	po = *p;

	PF_ACPY(&ao, a, af);
	PF_ACPY(a, an, af);

	*p = pn;

	switch (af) {
#if INET
	case AF_INET:
		*ic = pf_cksum_fixup(pf_cksum_fixup(*ic,
		    ao.addr16[0], an->addr16[0], 0),
		    ao.addr16[1], an->addr16[1], 0);
		*p = pn;
		/*
		 * If the packet is originated from an ALG on the NAT gateway
		 * (source address is loopback or local), in which case the
		 * TCP/UDP checksum field contains the pseudo header checksum
		 * that's not yet complemented.
		 */
		if (dir == PF_OUT && m != NULL &&
		    (m->m_flags & M_PKTHDR) &&
		    (m->m_pkthdr.csum_flags & (CSUM_TCP | CSUM_UDP))) {
			/* Pseudo-header checksum does not include ports */
			*pc = ~pf_cksum_fixup(pf_cksum_fixup(~*pc,
			    ao.addr16[0], an->addr16[0], u),
			    ao.addr16[1], an->addr16[1], u);
		} else {
			*pc = pf_cksum_fixup(pf_cksum_fixup(pf_cksum_fixup(*pc,
			    ao.addr16[0], an->addr16[0], u),
			    ao.addr16[1], an->addr16[1], u),
			    po, pn, u);
		}
		break;
#endif /* INET */
#if INET6
	case AF_INET6:
		/*
		 * If the packet is originated from an ALG on the NAT gateway
		 * (source address is loopback or local), in which case the
		 * TCP/UDP checksum field contains the pseudo header checksum
		 * that's not yet complemented.
		 */
		if (dir == PF_OUT && m != NULL &&
		    (m->m_flags & M_PKTHDR) &&
		    (m->m_pkthdr.csum_flags & (CSUM_TCPIPV6 | CSUM_UDPIPV6))) {
			/* Pseudo-header checksum does not include ports */
			*pc = ~pf_cksum_fixup(pf_cksum_fixup(pf_cksum_fixup(
		    		pf_cksum_fixup(pf_cksum_fixup(pf_cksum_fixup(
		    		pf_cksum_fixup(pf_cksum_fixup(pf_cksum_fixup(~*pc,
		    		ao.addr16[0], an->addr16[0], u),
		    		ao.addr16[1], an->addr16[1], u),
		    		ao.addr16[2], an->addr16[2], u),
		    		ao.addr16[3], an->addr16[3], u),
		    		ao.addr16[4], an->addr16[4], u),
		    		ao.addr16[5], an->addr16[5], u),
		    		ao.addr16[6], an->addr16[6], u),
		    		ao.addr16[7], an->addr16[7], u),
		    		po, pn, u);
		} else {
			*pc = pf_cksum_fixup(pf_cksum_fixup(pf_cksum_fixup(
		    		pf_cksum_fixup(pf_cksum_fixup(pf_cksum_fixup(
		    		pf_cksum_fixup(pf_cksum_fixup(pf_cksum_fixup(*pc,
		    		ao.addr16[0], an->addr16[0], u),
		    		ao.addr16[1], an->addr16[1], u),
		    		ao.addr16[2], an->addr16[2], u),
		    		ao.addr16[3], an->addr16[3], u),
		    		ao.addr16[4], an->addr16[4], u),
		    		ao.addr16[5], an->addr16[5], u),
		    		ao.addr16[6], an->addr16[6], u),
		    		ao.addr16[7], an->addr16[7], u),
		    		po, pn, u);
		}
		break;
#endif /* INET6 */
	}
}


/* Changes a u_int32_t.  Uses a void * so there are no align restrictions */
void
pf_change_a(void *a, u_int16_t *c, u_int32_t an, u_int8_t u)
{
	u_int32_t	ao;

	memcpy(&ao, a, sizeof (ao));
	memcpy(a, &an, sizeof (u_int32_t));
	*c = pf_cksum_fixup(pf_cksum_fixup(*c, ao / 65536, an / 65536, u),
	    ao % 65536, an % 65536, u);
}

#if INET6
static void
pf_change_a6(struct pf_addr *a, u_int16_t *c, struct pf_addr *an, u_int8_t u)
{
	struct pf_addr	ao;

	PF_ACPY(&ao, a, AF_INET6);
	PF_ACPY(a, an, AF_INET6);

	*c = pf_cksum_fixup(pf_cksum_fixup(pf_cksum_fixup(
	    pf_cksum_fixup(pf_cksum_fixup(pf_cksum_fixup(
	    pf_cksum_fixup(pf_cksum_fixup(*c,
	    ao.addr16[0], an->addr16[0], u),
	    ao.addr16[1], an->addr16[1], u),
	    ao.addr16[2], an->addr16[2], u),
	    ao.addr16[3], an->addr16[3], u),
	    ao.addr16[4], an->addr16[4], u),
	    ao.addr16[5], an->addr16[5], u),
	    ao.addr16[6], an->addr16[6], u),
	    ao.addr16[7], an->addr16[7], u);
}
#endif /* INET6 */

static void
pf_change_icmp(struct pf_addr *ia, u_int16_t *ip, struct pf_addr *oa,
    struct pf_addr *na, u_int16_t np, u_int16_t *pc, u_int16_t *h2c,
    u_int16_t *ic, u_int16_t *hc, u_int8_t u, sa_family_t af)
{
	struct pf_addr	oia, ooa;

	PF_ACPY(&oia, ia, af);
	PF_ACPY(&ooa, oa, af);

	/* Change inner protocol port, fix inner protocol checksum. */
	if (ip != NULL) {
		u_int16_t	oip = *ip;
		u_int32_t	opc = 0;

		if (pc != NULL)
			opc = *pc;
		*ip = np;
		if (pc != NULL)
			*pc = pf_cksum_fixup(*pc, oip, *ip, u);
		*ic = pf_cksum_fixup(*ic, oip, *ip, 0);
		if (pc != NULL)
			*ic = pf_cksum_fixup(*ic, opc, *pc, 0);
	}
	/* Change inner ip address, fix inner ip and icmp checksums. */
	PF_ACPY(ia, na, af);
	switch (af) {
#if INET
	case AF_INET: {
		u_int32_t	 oh2c = *h2c;

		*h2c = pf_cksum_fixup(pf_cksum_fixup(*h2c,
		    oia.addr16[0], ia->addr16[0], 0),
		    oia.addr16[1], ia->addr16[1], 0);
		*ic = pf_cksum_fixup(pf_cksum_fixup(*ic,
		    oia.addr16[0], ia->addr16[0], 0),
		    oia.addr16[1], ia->addr16[1], 0);
		*ic = pf_cksum_fixup(*ic, oh2c, *h2c, 0);
		break;
	}
#endif /* INET */
#if INET6
	case AF_INET6:
		*ic = pf_cksum_fixup(pf_cksum_fixup(pf_cksum_fixup(
		    pf_cksum_fixup(pf_cksum_fixup(pf_cksum_fixup(
		    pf_cksum_fixup(pf_cksum_fixup(*ic,
		    oia.addr16[0], ia->addr16[0], u),
		    oia.addr16[1], ia->addr16[1], u),
		    oia.addr16[2], ia->addr16[2], u),
		    oia.addr16[3], ia->addr16[3], u),
		    oia.addr16[4], ia->addr16[4], u),
		    oia.addr16[5], ia->addr16[5], u),
		    oia.addr16[6], ia->addr16[6], u),
		    oia.addr16[7], ia->addr16[7], u);
		break;
#endif /* INET6 */
	}
	/* Change outer ip address, fix outer ip or icmpv6 checksum. */
	PF_ACPY(oa, na, af);
	switch (af) {
#if INET
	case AF_INET:
		*hc = pf_cksum_fixup(pf_cksum_fixup(*hc,
		    ooa.addr16[0], oa->addr16[0], 0),
		    ooa.addr16[1], oa->addr16[1], 0);
		break;
#endif /* INET */
#if INET6
	case AF_INET6:
		*ic = pf_cksum_fixup(pf_cksum_fixup(pf_cksum_fixup(
		    pf_cksum_fixup(pf_cksum_fixup(pf_cksum_fixup(
		    pf_cksum_fixup(pf_cksum_fixup(*ic,
		    ooa.addr16[0], oa->addr16[0], u),
		    ooa.addr16[1], oa->addr16[1], u),
		    ooa.addr16[2], oa->addr16[2], u),
		    ooa.addr16[3], oa->addr16[3], u),
		    ooa.addr16[4], oa->addr16[4], u),
		    ooa.addr16[5], oa->addr16[5], u),
		    ooa.addr16[6], oa->addr16[6], u),
		    ooa.addr16[7], oa->addr16[7], u);
		break;
#endif /* INET6 */
	}
}


/*
 * Need to modulate the sequence numbers in the TCP SACK option
 * (credits to Krzysztof Pfaff for report and patch)
 */
static int
pf_modulate_sack(struct mbuf *m, int off, struct pf_pdesc *pd,
    struct tcphdr *th, struct pf_state_peer *dst)
{
	int hlen = (th->th_off << 2) - sizeof (*th), thoptlen = hlen;
	u_int8_t opts[MAX_TCPOPTLEN], *opt = opts;
	int copyback = 0, i, olen;
	struct sackblk sack;

#define TCPOLEN_SACKLEN	(TCPOLEN_SACK + 2)
	if (hlen < TCPOLEN_SACKLEN ||
	    !pf_pull_hdr(m, off + sizeof (*th), opts, hlen, NULL, NULL, pd->af))
		return (0);

	while (hlen >= TCPOLEN_SACKLEN) {
		olen = opt[1];
		switch (*opt) {
		case TCPOPT_EOL:	/* FALLTHROUGH */
		case TCPOPT_NOP:
			opt++;
			hlen--;
			break;
		case TCPOPT_SACK:
			if (olen > hlen)
				olen = hlen;
			if (olen >= TCPOLEN_SACKLEN) {
				for (i = 2; i + TCPOLEN_SACK <= olen;
				    i += TCPOLEN_SACK) {
					memcpy(&sack, &opt[i], sizeof (sack));
					pf_change_a(&sack.start, &th->th_sum,
					    htonl(ntohl(sack.start) -
					    dst->seqdiff), 0);
					pf_change_a(&sack.end, &th->th_sum,
					    htonl(ntohl(sack.end) -
					    dst->seqdiff), 0);
					memcpy(&opt[i], &sack, sizeof (sack));
				}
				copyback = off + sizeof (*th) + thoptlen;
			}
			/* FALLTHROUGH */
		default:
			if (olen < 2)
				olen = 2;
			hlen -= olen;
			opt += olen;
		}
	}

	if (copyback) {
		m = pf_lazy_makewritable(pd, m, copyback);
		if (!m)
			return (-1);
		m_copyback(m, off + sizeof (*th), thoptlen, opts);
	}
	return (copyback);
}

static void
pf_send_tcp(const struct pf_rule *r, sa_family_t af,
    const struct pf_addr *saddr, const struct pf_addr *daddr,
    u_int16_t sport, u_int16_t dport, u_int32_t seq, u_int32_t ack,
    u_int8_t flags, u_int16_t win, u_int16_t mss, u_int8_t ttl, int tag,
    u_int16_t rtag, struct ether_header *eh, struct ifnet *ifp)
{
#pragma unused(eh, ifp)
	struct mbuf	*m;
	int		 len, tlen;
#if INET
	struct ip	*h = NULL;
#endif /* INET */
#if INET6
	struct ip6_hdr	*h6 = NULL;
#endif /* INET6 */
	struct tcphdr	*th = NULL;
	char		*opt;
	struct pf_mtag	*pf_mtag;

	/* maximum segment size tcp option */
	tlen = sizeof (struct tcphdr);
	if (mss)
		tlen += 4;

	switch (af) {
#if INET
	case AF_INET:
		len = sizeof (struct ip) + tlen;
		break;
#endif /* INET */
#if INET6
	case AF_INET6:
		len = sizeof (struct ip6_hdr) + tlen;
		break;
#endif /* INET6 */
	default:
		panic("pf_send_tcp: not AF_INET or AF_INET6!");
		return;
	}

	/* create outgoing mbuf */
	m = m_gethdr(M_DONTWAIT, MT_HEADER);
	if (m == NULL)
		return;

	if ((pf_mtag = pf_get_mtag(m)) == NULL) {
		m_free(m);
		return;
	}

	if (tag)
		pf_mtag->pftag_flags |= PF_TAG_GENERATED;
	pf_mtag->pftag_tag = rtag;

	if (r != NULL && PF_RTABLEID_IS_VALID(r->rtableid))
		pf_mtag->pftag_rtableid = r->rtableid;

#if PF_ALTQ
	if (altq_allowed && r != NULL && r->qid)
		pf_mtag->pftag_qid = r->qid;
#endif /* PF_ALTQ */

#if PF_ECN
	/* add hints for ecn */
	pf_mtag->pftag_hdr = mtod(m, struct ip *);
	/* record address family */
	pf_mtag->pftag_flags &= ~(PF_TAG_HDR_INET | PF_TAG_HDR_INET6);
	switch (af) {
#if INET
	case AF_INET:
		pf_mtag->pftag_flags |= PF_TAG_HDR_INET;
		break;
#endif /* INET */
#if INET6
	case AF_INET6:
		pf_mtag->pftag_flags |= PF_TAG_HDR_INET6;
		break;
#endif /* INET6 */
	}
#endif /* PF_ECN */

	/* indicate this is TCP */
	m->m_pkthdr.pkt_proto = IPPROTO_TCP;

	/* Make sure headers are 32-bit aligned */
	m->m_data += max_linkhdr;
	m->m_pkthdr.len = m->m_len = len;
	m->m_pkthdr.rcvif = NULL;
	bzero(m->m_data, len);
	switch (af) {
#if INET
	case AF_INET:
		h = mtod(m, struct ip *);

		/* IP header fields included in the TCP checksum */
		h->ip_p = IPPROTO_TCP;
		h->ip_len = htons(tlen);
		h->ip_src.s_addr = saddr->v4.s_addr;
		h->ip_dst.s_addr = daddr->v4.s_addr;

		th = (struct tcphdr *)(void *)((caddr_t)h + sizeof (struct ip));
		break;
#endif /* INET */
#if INET6
	case AF_INET6:
		h6 = mtod(m, struct ip6_hdr *);

		/* IP header fields included in the TCP checksum */
		h6->ip6_nxt = IPPROTO_TCP;
		h6->ip6_plen = htons(tlen);
		memcpy(&h6->ip6_src, &saddr->v6, sizeof (struct in6_addr));
		memcpy(&h6->ip6_dst, &daddr->v6, sizeof (struct in6_addr));

		th = (struct tcphdr *)(void *)
		    ((caddr_t)h6 + sizeof (struct ip6_hdr));
		break;
#endif /* INET6 */
	}

	/* TCP header */
	th->th_sport = sport;
	th->th_dport = dport;
	th->th_seq = htonl(seq);
	th->th_ack = htonl(ack);
	th->th_off = tlen >> 2;
	th->th_flags = flags;
	th->th_win = htons(win);

	if (mss) {
		opt = (char *)(th + 1);
		opt[0] = TCPOPT_MAXSEG;
		opt[1] = 4;
#if BYTE_ORDER != BIG_ENDIAN
		HTONS(mss);
#endif
		bcopy((caddr_t)&mss, (caddr_t)(opt + 2), 2);
	}

	switch (af) {
#if INET
	case AF_INET: {
		struct route ro;

		/* TCP checksum */
		th->th_sum = in_cksum(m, len);

		/* Finish the IP header */
		h->ip_v = 4;
		h->ip_hl = sizeof (*h) >> 2;
		h->ip_tos = IPTOS_LOWDELAY;
		/*
		 * ip_output() expects ip_len and ip_off to be in host order.
		 */
		h->ip_len = len;
		h->ip_off = (path_mtu_discovery ? IP_DF : 0);
		h->ip_ttl = ttl ? ttl : ip_defttl;
		h->ip_sum = 0;

		bzero(&ro, sizeof (ro));
		ip_output(m, NULL, &ro, 0, NULL, NULL);
		ROUTE_RELEASE(&ro);
		break;
	}
#endif /* INET */
#if INET6
	case AF_INET6: {
		struct route_in6 ro6;

		/* TCP checksum */
		th->th_sum = in6_cksum(m, IPPROTO_TCP,
		    sizeof (struct ip6_hdr), tlen);

		h6->ip6_vfc |= IPV6_VERSION;
		h6->ip6_hlim = IPV6_DEFHLIM;

		bzero(&ro6, sizeof (ro6));
		ip6_output(m, NULL, &ro6, 0, NULL, NULL, NULL);
		ROUTE_RELEASE(&ro6);
		break;
	}
#endif /* INET6 */
	}
}

static void
pf_send_icmp(struct mbuf *m, u_int8_t type, u_int8_t code, sa_family_t af,
    struct pf_rule *r)
{
	struct mbuf	*m0;
	struct pf_mtag	*pf_mtag;

	m0 = m_copy(m, 0, M_COPYALL);
	if (m0 == NULL)
		return;

	if ((pf_mtag = pf_get_mtag(m0)) == NULL)
		return;

	pf_mtag->pftag_flags |= PF_TAG_GENERATED;

	if (PF_RTABLEID_IS_VALID(r->rtableid))
		pf_mtag->pftag_rtableid = r->rtableid;

#if PF_ALTQ
	if (altq_allowed && r->qid)
		pf_mtag->pftag_qid = r->qid;
#endif /* PF_ALTQ */

#if PF_ECN
	/* add hints for ecn */
	pf_mtag->pftag_hdr = mtod(m0, struct ip *);
	/* record address family */
	pf_mtag->pftag_flags &= ~(PF_TAG_HDR_INET | PF_TAG_HDR_INET6);
	switch (af) {
#if INET
	case AF_INET:
		pf_mtag->pftag_flags |= PF_TAG_HDR_INET;
		m0->m_pkthdr.pkt_proto = IPPROTO_ICMP;
		break;
#endif /* INET */
#if INET6
	case AF_INET6:
		pf_mtag->pftag_flags |= PF_TAG_HDR_INET6;
		m0->m_pkthdr.pkt_proto = IPPROTO_ICMPV6;
		break;
#endif /* INET6 */
	}
#endif /* PF_ECN */

	switch (af) {
#if INET
	case AF_INET:
		icmp_error(m0, type, code, 0, 0);
		break;
#endif /* INET */
#if INET6
	case AF_INET6:
		icmp6_error(m0, type, code, 0);
		break;
#endif /* INET6 */
	}
}

/*
 * Return 1 if the addresses a and b match (with mask m), otherwise return 0.
 * If n is 0, they match if they are equal. If n is != 0, they match if they
 * are different.
 */
int
pf_match_addr(u_int8_t n, struct pf_addr *a, struct pf_addr *m,
    struct pf_addr *b, sa_family_t af)
{
	int	match = 0;

	switch (af) {
#if INET
	case AF_INET:
		if ((a->addr32[0] & m->addr32[0]) ==
		    (b->addr32[0] & m->addr32[0]))
			match++;
		break;
#endif /* INET */
#if INET6
	case AF_INET6:
		if (((a->addr32[0] & m->addr32[0]) ==
		     (b->addr32[0] & m->addr32[0])) &&
		    ((a->addr32[1] & m->addr32[1]) ==
		     (b->addr32[1] & m->addr32[1])) &&
		    ((a->addr32[2] & m->addr32[2]) ==
		     (b->addr32[2] & m->addr32[2])) &&
		    ((a->addr32[3] & m->addr32[3]) ==
		     (b->addr32[3] & m->addr32[3])))
			match++;
		break;
#endif /* INET6 */
	}
	if (match) {
		if (n)
			return (0);
		else
			return (1);
	} else {
		if (n)
			return (1);
		else
			return (0);
	}
}

/*
 * Return 1 if b <= a <= e, otherwise return 0.
 */
int
pf_match_addr_range(struct pf_addr *b, struct pf_addr *e,
    struct pf_addr *a, sa_family_t af)
{
	switch (af) {
#if INET
	case AF_INET:
		if ((a->addr32[0] < b->addr32[0]) ||
		    (a->addr32[0] > e->addr32[0]))
			return (0);
		break;
#endif /* INET */
#if INET6
	case AF_INET6: {
		int	i;

		/* check a >= b */
		for (i = 0; i < 4; ++i)
			if (a->addr32[i] > b->addr32[i])
				break;
			else if (a->addr32[i] < b->addr32[i])
				return (0);
		/* check a <= e */
		for (i = 0; i < 4; ++i)
			if (a->addr32[i] < e->addr32[i])
				break;
			else if (a->addr32[i] > e->addr32[i])
				return (0);
		break;
	}
#endif /* INET6 */
	}
	return (1);
}

int
pf_match(u_int8_t op, u_int32_t a1, u_int32_t a2, u_int32_t p)
{
	switch (op) {
	case PF_OP_IRG:
		return ((p > a1) && (p < a2));
	case PF_OP_XRG:
		return ((p < a1) || (p > a2));
	case PF_OP_RRG:
		return ((p >= a1) && (p <= a2));
	case PF_OP_EQ:
		return (p == a1);
	case PF_OP_NE:
		return (p != a1);
	case PF_OP_LT:
		return (p < a1);
	case PF_OP_LE:
		return (p <= a1);
	case PF_OP_GT:
		return (p > a1);
	case PF_OP_GE:
		return (p >= a1);
	}
	return (0); /* never reached */
}

int
pf_match_port(u_int8_t op, u_int16_t a1, u_int16_t a2, u_int16_t p)
{
#if BYTE_ORDER != BIG_ENDIAN
	NTOHS(a1);
	NTOHS(a2);
	NTOHS(p);
#endif
	return (pf_match(op, a1, a2, p));
}

int
pf_match_xport(u_int8_t proto, u_int8_t proto_variant, union pf_rule_xport *rx,
    union pf_state_xport *sx)
{
	int d = !0;

	if (sx) {
		switch (proto) {
		case IPPROTO_GRE:
			if (proto_variant == PF_GRE_PPTP_VARIANT)
				d = (rx->call_id == sx->call_id);
			break;

		case IPPROTO_ESP:
			d = (rx->spi == sx->spi);
			break;

		case IPPROTO_TCP:
		case IPPROTO_UDP:
		case IPPROTO_ICMP:
		case IPPROTO_ICMPV6:
			if (rx->range.op)
				d = pf_match_port(rx->range.op,
				    rx->range.port[0], rx->range.port[1],
				    sx->port);
			break;

		default:
			break;
		}
	}

	return (d);
}

int
pf_match_uid(u_int8_t op, uid_t a1, uid_t a2, uid_t u)
{
	if (u == UID_MAX && op != PF_OP_EQ && op != PF_OP_NE)
		return (0);
	return (pf_match(op, a1, a2, u));
}

int
pf_match_gid(u_int8_t op, gid_t a1, gid_t a2, gid_t g)
{
	if (g == GID_MAX && op != PF_OP_EQ && op != PF_OP_NE)
		return (0);
	return (pf_match(op, a1, a2, g));
}

static int
pf_match_tag(struct mbuf *m, struct pf_rule *r, struct pf_mtag *pf_mtag,
    int *tag)
{
#pragma unused(m)
	if (*tag == -1)
		*tag = pf_mtag->pftag_tag;

	return ((!r->match_tag_not && r->match_tag == *tag) ||
	    (r->match_tag_not && r->match_tag != *tag));
}

int
pf_tag_packet(struct mbuf *m, struct pf_mtag *pf_mtag, int tag,
    unsigned int rtableid, struct pf_pdesc *pd)
{
	if (tag <= 0 && !PF_RTABLEID_IS_VALID(rtableid) &&
	    (pd == NULL || !(pd->pktflags & PKTF_FLOW_ID)))
		return (0);

	if (pf_mtag == NULL && (pf_mtag = pf_get_mtag(m)) == NULL)
		return (1);

	if (tag > 0)
		pf_mtag->pftag_tag = tag;
	if (PF_RTABLEID_IS_VALID(rtableid))
		pf_mtag->pftag_rtableid = rtableid;
	if (pd != NULL && (pd->pktflags & PKTF_FLOW_ID)) {
		m->m_pkthdr.pkt_flowsrc = pd->flowsrc;
		m->m_pkthdr.pkt_flowid = pd->flowhash;
		m->m_pkthdr.pkt_flags |= pd->pktflags;
		m->m_pkthdr.pkt_proto = pd->proto;
	}

	return (0);
}

void
pf_step_into_anchor(int *depth, struct pf_ruleset **rs, int n,
    struct pf_rule **r, struct pf_rule **a,  int *match)
{
	struct pf_anchor_stackframe	*f;

	(*r)->anchor->match = 0;
	if (match)
		*match = 0;
	if (*depth >= (int)sizeof (pf_anchor_stack) /
	    (int)sizeof (pf_anchor_stack[0])) {
		printf("pf_step_into_anchor: stack overflow\n");
		*r = TAILQ_NEXT(*r, entries);
		return;
	} else if (*depth == 0 && a != NULL)
		*a = *r;
	f = pf_anchor_stack + (*depth)++;
	f->rs = *rs;
	f->r = *r;
	if ((*r)->anchor_wildcard) {
		f->parent = &(*r)->anchor->children;
		if ((f->child = RB_MIN(pf_anchor_node, f->parent)) ==
		    NULL) {
			*r = NULL;
			return;
		}
		*rs = &f->child->ruleset;
	} else {
		f->parent = NULL;
		f->child = NULL;
		*rs = &(*r)->anchor->ruleset;
	}
	*r = TAILQ_FIRST((*rs)->rules[n].active.ptr);
}

int
pf_step_out_of_anchor(int *depth, struct pf_ruleset **rs, int n,
    struct pf_rule **r, struct pf_rule **a, int *match)
{
	struct pf_anchor_stackframe	*f;
	int quick = 0;

	do {
		if (*depth <= 0)
			break;
		f = pf_anchor_stack + *depth - 1;
		if (f->parent != NULL && f->child != NULL) {
			if (f->child->match ||
			    (match != NULL && *match)) {
				f->r->anchor->match = 1;
				*match = 0;
			}
			f->child = RB_NEXT(pf_anchor_node, f->parent, f->child);
			if (f->child != NULL) {
				*rs = &f->child->ruleset;
				*r = TAILQ_FIRST((*rs)->rules[n].active.ptr);
				if (*r == NULL)
					continue;
				else
					break;
			}
		}
		(*depth)--;
		if (*depth == 0 && a != NULL)
			*a = NULL;
		*rs = f->rs;
		if (f->r->anchor->match || (match  != NULL && *match))
			quick = f->r->quick;
		*r = TAILQ_NEXT(f->r, entries);
	} while (*r == NULL);

	return (quick);
}

#if INET6
void
pf_poolmask(struct pf_addr *naddr, struct pf_addr *raddr,
    struct pf_addr *rmask, struct pf_addr *saddr, sa_family_t af)
{
	switch (af) {
#if INET
	case AF_INET:
		naddr->addr32[0] = (raddr->addr32[0] & rmask->addr32[0]) |
		    ((rmask->addr32[0] ^ 0xffffffff) & saddr->addr32[0]);
		break;
#endif /* INET */
	case AF_INET6:
		naddr->addr32[0] = (raddr->addr32[0] & rmask->addr32[0]) |
		    ((rmask->addr32[0] ^ 0xffffffff) & saddr->addr32[0]);
		naddr->addr32[1] = (raddr->addr32[1] & rmask->addr32[1]) |
		    ((rmask->addr32[1] ^ 0xffffffff) & saddr->addr32[1]);
		naddr->addr32[2] = (raddr->addr32[2] & rmask->addr32[2]) |
		    ((rmask->addr32[2] ^ 0xffffffff) & saddr->addr32[2]);
		naddr->addr32[3] = (raddr->addr32[3] & rmask->addr32[3]) |
		    ((rmask->addr32[3] ^ 0xffffffff) & saddr->addr32[3]);
		break;
	}
}

void
pf_addr_inc(struct pf_addr *addr, sa_family_t af)
{
	switch (af) {
#if INET
	case AF_INET:
		addr->addr32[0] = htonl(ntohl(addr->addr32[0]) + 1);
		break;
#endif /* INET */
	case AF_INET6:
		if (addr->addr32[3] == 0xffffffff) {
			addr->addr32[3] = 0;
			if (addr->addr32[2] == 0xffffffff) {
				addr->addr32[2] = 0;
				if (addr->addr32[1] == 0xffffffff) {
					addr->addr32[1] = 0;
					addr->addr32[0] =
					    htonl(ntohl(addr->addr32[0]) + 1);
				} else
					addr->addr32[1] =
					    htonl(ntohl(addr->addr32[1]) + 1);
			} else
				addr->addr32[2] =
				    htonl(ntohl(addr->addr32[2]) + 1);
		} else
			addr->addr32[3] =
			    htonl(ntohl(addr->addr32[3]) + 1);
		break;
	}
}
#endif /* INET6 */

#define mix(a, b, c) \
	do {					\
		a -= b; a -= c; a ^= (c >> 13);	\
		b -= c; b -= a; b ^= (a << 8);	\
		c -= a; c -= b; c ^= (b >> 13);	\
		a -= b; a -= c; a ^= (c >> 12);	\
		b -= c; b -= a; b ^= (a << 16);	\
		c -= a; c -= b; c ^= (b >> 5);	\
		a -= b; a -= c; a ^= (c >> 3);	\
		b -= c; b -= a; b ^= (a << 10);	\
		c -= a; c -= b; c ^= (b >> 15);	\
	} while (0)

/*
 * hash function based on bridge_hash in if_bridge.c
 */
static void
pf_hash(struct pf_addr *inaddr, struct pf_addr *hash,
    struct pf_poolhashkey *key, sa_family_t af)
{
	u_int32_t	a = 0x9e3779b9, b = 0x9e3779b9, c = key->key32[0];

	switch (af) {
#if INET
	case AF_INET:
		a += inaddr->addr32[0];
		b += key->key32[1];
		mix(a, b, c);
		hash->addr32[0] = c + key->key32[2];
		break;
#endif /* INET */
#if INET6
	case AF_INET6:
		a += inaddr->addr32[0];
		b += inaddr->addr32[2];
		mix(a, b, c);
		hash->addr32[0] = c;
		a += inaddr->addr32[1];
		b += inaddr->addr32[3];
		c += key->key32[1];
		mix(a, b, c);
		hash->addr32[1] = c;
		a += inaddr->addr32[2];
		b += inaddr->addr32[1];
		c += key->key32[2];
		mix(a, b, c);
		hash->addr32[2] = c;
		a += inaddr->addr32[3];
		b += inaddr->addr32[0];
		c += key->key32[3];
		mix(a, b, c);
		hash->addr32[3] = c;
		break;
#endif /* INET6 */
	}
}

static int
pf_map_addr(sa_family_t af, struct pf_rule *r, struct pf_addr *saddr,
    struct pf_addr *naddr, struct pf_addr *init_addr, struct pf_src_node **sn)
{
	unsigned char		 hash[16];
	struct pf_pool		*rpool = &r->rpool;
	struct pf_addr		*raddr = &rpool->cur->addr.v.a.addr;
	struct pf_addr		*rmask = &rpool->cur->addr.v.a.mask;
	struct pf_pooladdr	*acur = rpool->cur;
	struct pf_src_node	 k;

	if (*sn == NULL && r->rpool.opts & PF_POOL_STICKYADDR &&
	    (r->rpool.opts & PF_POOL_TYPEMASK) != PF_POOL_NONE) {
		k.af = af;
		PF_ACPY(&k.addr, saddr, af);
		if (r->rule_flag & PFRULE_RULESRCTRACK ||
		    r->rpool.opts & PF_POOL_STICKYADDR)
			k.rule.ptr = r;
		else
			k.rule.ptr = NULL;
		pf_status.scounters[SCNT_SRC_NODE_SEARCH]++;
		*sn = RB_FIND(pf_src_tree, &tree_src_tracking, &k);
		if (*sn != NULL && !PF_AZERO(&(*sn)->raddr, af)) {
			PF_ACPY(naddr, &(*sn)->raddr, af);
			if (pf_status.debug >= PF_DEBUG_MISC) {
				printf("pf_map_addr: src tracking maps ");
				pf_print_host(&k.addr, 0, af);
				printf(" to ");
				pf_print_host(naddr, 0, af);
				printf("\n");
			}
			return (0);
		}
	}

	if (rpool->cur->addr.type == PF_ADDR_NOROUTE)
		return (1);
	if (rpool->cur->addr.type == PF_ADDR_DYNIFTL) {
		if (rpool->cur->addr.p.dyn == NULL)
			return (1);
		switch (af) {
#if INET
		case AF_INET:
			if (rpool->cur->addr.p.dyn->pfid_acnt4 < 1 &&
			    (rpool->opts & PF_POOL_TYPEMASK) !=
			    PF_POOL_ROUNDROBIN)
				return (1);
			raddr = &rpool->cur->addr.p.dyn->pfid_addr4;
			rmask = &rpool->cur->addr.p.dyn->pfid_mask4;
			break;
#endif /* INET */
#if INET6
		case AF_INET6:
			if (rpool->cur->addr.p.dyn->pfid_acnt6 < 1 &&
			    (rpool->opts & PF_POOL_TYPEMASK) !=
			    PF_POOL_ROUNDROBIN)
				return (1);
			raddr = &rpool->cur->addr.p.dyn->pfid_addr6;
			rmask = &rpool->cur->addr.p.dyn->pfid_mask6;
			break;
#endif /* INET6 */
		}
	} else if (rpool->cur->addr.type == PF_ADDR_TABLE) {
		if ((rpool->opts & PF_POOL_TYPEMASK) != PF_POOL_ROUNDROBIN)
			return (1); /* unsupported */
	} else {
		raddr = &rpool->cur->addr.v.a.addr;
		rmask = &rpool->cur->addr.v.a.mask;
	}

	switch (rpool->opts & PF_POOL_TYPEMASK) {
	case PF_POOL_NONE:
		PF_ACPY(naddr, raddr, af);
		break;
	case PF_POOL_BITMASK:
		PF_POOLMASK(naddr, raddr, rmask, saddr, af);
		break;
	case PF_POOL_RANDOM:
		if (init_addr != NULL && PF_AZERO(init_addr, af)) {
			switch (af) {
#if INET
			case AF_INET:
				rpool->counter.addr32[0] = htonl(random());
				break;
#endif /* INET */
#if INET6
			case AF_INET6:
				if (rmask->addr32[3] != 0xffffffff)
					rpool->counter.addr32[3] =
					    RandomULong();
				else
					break;
				if (rmask->addr32[2] != 0xffffffff)
					rpool->counter.addr32[2] =
					    RandomULong();
				else
					break;
				if (rmask->addr32[1] != 0xffffffff)
					rpool->counter.addr32[1] =
					    RandomULong();
				else
					break;
				if (rmask->addr32[0] != 0xffffffff)
					rpool->counter.addr32[0] =
					    RandomULong();
				break;
#endif /* INET6 */
			}
			PF_POOLMASK(naddr, raddr, rmask, &rpool->counter, af);
			PF_ACPY(init_addr, naddr, af);

		} else {
			PF_AINC(&rpool->counter, af);
			PF_POOLMASK(naddr, raddr, rmask, &rpool->counter, af);
		}
		break;
	case PF_POOL_SRCHASH:
		pf_hash(saddr, (struct pf_addr *)(void *)&hash,
		    &rpool->key, af);
		PF_POOLMASK(naddr, raddr, rmask,
		    (struct pf_addr *)(void *)&hash, af);
		break;
	case PF_POOL_ROUNDROBIN:
		if (rpool->cur->addr.type == PF_ADDR_TABLE) {
			if (!pfr_pool_get(rpool->cur->addr.p.tbl,
			    &rpool->tblidx, &rpool->counter,
			    &raddr, &rmask, af))
				goto get_addr;
		} else if (rpool->cur->addr.type == PF_ADDR_DYNIFTL) {
			if (rpool->cur->addr.p.dyn != NULL &&
			    !pfr_pool_get(rpool->cur->addr.p.dyn->pfid_kt,
			    &rpool->tblidx, &rpool->counter,
			    &raddr, &rmask, af))
				goto get_addr;
		} else if (pf_match_addr(0, raddr, rmask, &rpool->counter, af))
			goto get_addr;

	try_next:
		if ((rpool->cur = TAILQ_NEXT(rpool->cur, entries)) == NULL)
			rpool->cur = TAILQ_FIRST(&rpool->list);
		if (rpool->cur->addr.type == PF_ADDR_TABLE) {
			rpool->tblidx = -1;
			if (pfr_pool_get(rpool->cur->addr.p.tbl,
			    &rpool->tblidx, &rpool->counter,
			    &raddr, &rmask, af)) {
				/* table contains no address of type 'af' */
				if (rpool->cur != acur)
					goto try_next;
				return (1);
			}
		} else if (rpool->cur->addr.type == PF_ADDR_DYNIFTL) {
			rpool->tblidx = -1;
			if (rpool->cur->addr.p.dyn == NULL)
				return (1);
			if (pfr_pool_get(rpool->cur->addr.p.dyn->pfid_kt,
			    &rpool->tblidx, &rpool->counter,
			    &raddr, &rmask, af)) {
				/* table contains no address of type 'af' */
				if (rpool->cur != acur)
					goto try_next;
				return (1);
			}
		} else {
			raddr = &rpool->cur->addr.v.a.addr;
			rmask = &rpool->cur->addr.v.a.mask;
			PF_ACPY(&rpool->counter, raddr, af);
		}

	get_addr:
		PF_ACPY(naddr, &rpool->counter, af);
		if (init_addr != NULL && PF_AZERO(init_addr, af))
			PF_ACPY(init_addr, naddr, af);
		PF_AINC(&rpool->counter, af);
		break;
	}
	if (*sn != NULL)
		PF_ACPY(&(*sn)->raddr, naddr, af);

	if (pf_status.debug >= PF_DEBUG_MISC &&
	    (rpool->opts & PF_POOL_TYPEMASK) != PF_POOL_NONE) {
		printf("pf_map_addr: selected address ");
		pf_print_host(naddr, 0, af);
		printf("\n");
	}

	return (0);
}

static int
pf_get_sport(struct pf_pdesc *pd, struct pfi_kif *kif, struct pf_rule *r,
    struct pf_addr *saddr, union pf_state_xport *sxport, struct pf_addr *daddr,
    union pf_state_xport *dxport, struct pf_addr *naddr,
    union pf_state_xport *nxport, struct pf_src_node **sn)
{
#pragma unused(kif)
	struct pf_state_key_cmp	key;
	struct pf_addr		init_addr;
	unsigned int cut;
	sa_family_t af = pd->af;
	u_int8_t proto = pd->proto;
	unsigned int low = r->rpool.proxy_port[0];
	unsigned int high = r->rpool.proxy_port[1];

	bzero(&init_addr, sizeof (init_addr));
	if (pf_map_addr(af, r, saddr, naddr, &init_addr, sn))
		return (1);

	if (proto == IPPROTO_ICMP) {
		low = 1;
		high = 65535;
	}

	if (!nxport)
		return (0); /* No output necessary. */

	/*--- Special mapping rules for UDP ---*/
	if (proto == IPPROTO_UDP) {

		/*--- Never float IKE source port ---*/
		if (ntohs(sxport->port) == PF_IKE_PORT) {
			nxport->port = sxport->port;
			return (0);
		}

		/*--- Apply exterior mapping options ---*/
		if (r->extmap > PF_EXTMAP_APD) {
			struct pf_state *s;

			TAILQ_FOREACH(s, &state_list, entry_list) {
				struct pf_state_key *sk = s->state_key;
				if (!sk)
					continue;
				if (s->nat_rule.ptr != r)
					continue;
				if (sk->proto != IPPROTO_UDP || sk->af != af)
					continue;
				if (sk->lan.xport.port != sxport->port)
					continue;
				if (PF_ANEQ(&sk->lan.addr, saddr, af))
					continue;
				if (r->extmap < PF_EXTMAP_EI &&
				    PF_ANEQ(&sk->ext.addr, daddr, af))
					continue;

				nxport->port = sk->gwy.xport.port;
				return (0);
			}
		}
	} else if (proto == IPPROTO_TCP) {
		struct pf_state* s;
		/*
		 * APPLE MODIFICATION: <rdar://problem/6546358>
		 * Fix allows....NAT to use a single binding for TCP session
		 * with same source IP and source port
		 */
		TAILQ_FOREACH(s, &state_list, entry_list) {
			struct pf_state_key* sk = s->state_key;
			if (!sk)
				continue;
			if (s->nat_rule.ptr != r)
				continue;
			if (sk->proto != IPPROTO_TCP || sk->af != af)
				 continue;
			if (sk->lan.xport.port != sxport->port)
				continue;
			if (!(PF_AEQ(&sk->lan.addr, saddr, af)))
				continue;
			nxport->port = sk->gwy.xport.port;
			return (0);
		}
	}
	do {
		key.af = af;
		key.proto = proto;
		PF_ACPY(&key.ext.addr, daddr, key.af);
		PF_ACPY(&key.gwy.addr, naddr, key.af);
		switch (proto) {
			case IPPROTO_UDP:
				key.proto_variant = r->extfilter;
				break;
			default:
				key.proto_variant = 0;
				break;
		}
		if (dxport)
			key.ext.xport = *dxport;
		else
			memset(&key.ext.xport, 0, sizeof (key.ext.xport));
		/*
		 * port search; start random, step;
		 * similar 2 portloop in in_pcbbind
		 */
		if (!(proto == IPPROTO_TCP || proto == IPPROTO_UDP ||
		    proto == IPPROTO_ICMP)) {
			if (dxport)
				key.gwy.xport = *dxport;
			else
				memset(&key.gwy.xport, 0,
				    sizeof (key.ext.xport));
			if (pf_find_state_all(&key, PF_IN, NULL) == NULL)
				return (0);
		} else if (low == 0 && high == 0) {
			key.gwy.xport = *nxport;
			if (pf_find_state_all(&key, PF_IN, NULL) == NULL)
				return (0);
		} else if (low == high) {
			key.gwy.xport.port = htons(low);
			if (pf_find_state_all(&key, PF_IN, NULL) == NULL) {
				nxport->port = htons(low);
				return (0);
			}
		} else {
			unsigned int tmp;
			if (low > high) {
				tmp = low;
				low = high;
				high = tmp;
			}
			/* low < high */
			cut = htonl(random()) % (1 + high - low) + low;
			/* low <= cut <= high */
			for (tmp = cut; tmp <= high; ++(tmp)) {
				key.gwy.xport.port = htons(tmp);
				if (pf_find_state_all(&key, PF_IN, NULL) ==
				    NULL) {
					nxport->port = htons(tmp);
					return (0);
				}
			}
			for (tmp = cut - 1; tmp >= low; --(tmp)) {
				key.gwy.xport.port = htons(tmp);
				if (pf_find_state_all(&key, PF_IN, NULL) ==
				    NULL) {
					nxport->port = htons(tmp);
					return (0);
				}
			}
		}

		switch (r->rpool.opts & PF_POOL_TYPEMASK) {
		case PF_POOL_RANDOM:
		case PF_POOL_ROUNDROBIN:
			if (pf_map_addr(af, r, saddr, naddr, &init_addr, sn))
				return (1);
			break;
		case PF_POOL_NONE:
		case PF_POOL_SRCHASH:
		case PF_POOL_BITMASK:
		default:
			return (1);
		}
	} while (!PF_AEQ(&init_addr, naddr, af));

	return (1);					/* none available */
}

static struct pf_rule *
pf_match_translation(struct pf_pdesc *pd, struct mbuf *m, int off,
    int direction, struct pfi_kif *kif, struct pf_addr *saddr,
    union pf_state_xport *sxport, struct pf_addr *daddr,
    union pf_state_xport *dxport, int rs_num)
{
	struct pf_rule		*r, *rm = NULL;
	struct pf_ruleset	*ruleset = NULL;
	int			 tag = -1;
	unsigned int		 rtableid = IFSCOPE_NONE;
	int			 asd = 0;

	r = TAILQ_FIRST(pf_main_ruleset.rules[rs_num].active.ptr);
	while (r && rm == NULL) {
		struct pf_rule_addr	*src = NULL, *dst = NULL;
		struct pf_addr_wrap	*xdst = NULL;
		struct pf_addr_wrap	*xsrc = NULL;
		union pf_rule_xport	rdrxport;

		if (r->action == PF_BINAT && direction == PF_IN) {
			src = &r->dst;
			if (r->rpool.cur != NULL)
				xdst = &r->rpool.cur->addr;
		} else if (r->action == PF_RDR && direction == PF_OUT) {
			dst = &r->src;
			src = &r->dst;
			if (r->rpool.cur != NULL) {
				rdrxport.range.op = PF_OP_EQ;
				rdrxport.range.port[0] =
				    htons(r->rpool.proxy_port[0]);
				xsrc = &r->rpool.cur->addr;
			}
		} else {
			src = &r->src;
			dst = &r->dst;
		}

		r->evaluations++;
		if (pfi_kif_match(r->kif, kif) == r->ifnot)
			r = r->skip[PF_SKIP_IFP].ptr;
		else if (r->direction && r->direction != direction)
			r = r->skip[PF_SKIP_DIR].ptr;
		else if (r->af && r->af != pd->af)
			r = r->skip[PF_SKIP_AF].ptr;
		else if (r->proto && r->proto != pd->proto)
			r = r->skip[PF_SKIP_PROTO].ptr;
		else if (xsrc && PF_MISMATCHAW(xsrc, saddr, pd->af, 0, NULL))
			r = TAILQ_NEXT(r, entries);
		else if (!xsrc && PF_MISMATCHAW(&src->addr, saddr, pd->af,
		    src->neg, kif))
			r = TAILQ_NEXT(r, entries);
		else if (xsrc && (!rdrxport.range.port[0] ||
		    !pf_match_xport(r->proto, r->proto_variant, &rdrxport,
		    sxport)))
			r = TAILQ_NEXT(r, entries);
		else if (!xsrc && !pf_match_xport(r->proto,
		    r->proto_variant, &src->xport, sxport))
			r = r->skip[src == &r->src ? PF_SKIP_SRC_PORT :
			    PF_SKIP_DST_PORT].ptr;
		else if (dst != NULL &&
		    PF_MISMATCHAW(&dst->addr, daddr, pd->af, dst->neg, NULL))
			r = r->skip[PF_SKIP_DST_ADDR].ptr;
		else if (xdst != NULL && PF_MISMATCHAW(xdst, daddr, pd->af,
		    0, NULL))
			r = TAILQ_NEXT(r, entries);
		else if (dst && !pf_match_xport(r->proto, r->proto_variant,
		    &dst->xport, dxport))
			r = r->skip[PF_SKIP_DST_PORT].ptr;
		else if (r->match_tag && !pf_match_tag(m, r, pd->pf_mtag, &tag))
			r = TAILQ_NEXT(r, entries);
		else if (r->os_fingerprint != PF_OSFP_ANY && (pd->proto !=
		    IPPROTO_TCP || !pf_osfp_match(pf_osfp_fingerprint(pd, m,
		    off, pd->hdr.tcp), r->os_fingerprint)))
			r = TAILQ_NEXT(r, entries);
		else {
			if (r->tag)
				tag = r->tag;
			if (PF_RTABLEID_IS_VALID(r->rtableid))
				rtableid = r->rtableid;
			if (r->anchor == NULL) {
				rm = r;
			} else
				pf_step_into_anchor(&asd, &ruleset, rs_num,
				    &r, NULL, NULL);
		}
		if (r == NULL)
			pf_step_out_of_anchor(&asd, &ruleset, rs_num, &r,
			    NULL, NULL);
	}
	if (pf_tag_packet(m, pd->pf_mtag, tag, rtableid, NULL))
		return (NULL);
	if (rm != NULL && (rm->action == PF_NONAT ||
	    rm->action == PF_NORDR || rm->action == PF_NOBINAT))
		return (NULL);
	return (rm);
}

static struct pf_rule *
pf_get_translation_aux(struct pf_pdesc *pd, struct mbuf *m, int off,
    int direction, struct pfi_kif *kif, struct pf_src_node **sn,
    struct pf_addr *saddr, union pf_state_xport *sxport, struct pf_addr *daddr,
    union pf_state_xport *dxport, struct pf_addr *naddr,
    union pf_state_xport *nxport)
{
	struct pf_rule	*r = NULL;

	if (direction == PF_OUT) {
		r = pf_match_translation(pd, m, off, direction, kif, saddr,
		    sxport, daddr, dxport, PF_RULESET_BINAT);
		if (r == NULL)
			r = pf_match_translation(pd, m, off, direction, kif,
			    saddr, sxport, daddr, dxport, PF_RULESET_RDR);
		if (r == NULL)
			r = pf_match_translation(pd, m, off, direction, kif,
			    saddr, sxport, daddr, dxport, PF_RULESET_NAT);
	} else {
		r = pf_match_translation(pd, m, off, direction, kif, saddr,
		    sxport, daddr, dxport, PF_RULESET_RDR);
		if (r == NULL)
			r = pf_match_translation(pd, m, off, direction, kif,
			    saddr, sxport, daddr, dxport, PF_RULESET_BINAT);
	}

	if (r != NULL) {
		switch (r->action) {
		case PF_NONAT:
		case PF_NOBINAT:
		case PF_NORDR:
			return (NULL);
		case PF_NAT:
			if (pf_get_sport(pd, kif, r, saddr, sxport, daddr,
			    dxport, naddr, nxport, sn)) {
				DPFPRINTF(PF_DEBUG_MISC,
				    ("pf: NAT proxy port allocation "
				    "(%u-%u) failed\n",
				    r->rpool.proxy_port[0],
				    r->rpool.proxy_port[1]));
				return (NULL);
			}
			break;
		case PF_BINAT:
			switch (direction) {
			case PF_OUT:
				if (r->rpool.cur->addr.type ==
				    PF_ADDR_DYNIFTL) {
					if (r->rpool.cur->addr.p.dyn == NULL)
						return (NULL);
					switch (pd->af) {
#if INET
					case AF_INET:
						if (r->rpool.cur->addr.p.dyn->
						    pfid_acnt4 < 1)
							return (NULL);
						PF_POOLMASK(naddr,
						    &r->rpool.cur->addr.p.dyn->
						    pfid_addr4,
						    &r->rpool.cur->addr.p.dyn->
						    pfid_mask4,
						    saddr, AF_INET);
						break;
#endif /* INET */
#if INET6
					case AF_INET6:
						if (r->rpool.cur->addr.p.dyn->
						    pfid_acnt6 < 1)
							return (NULL);
						PF_POOLMASK(naddr,
						    &r->rpool.cur->addr.p.dyn->
						    pfid_addr6,
						    &r->rpool.cur->addr.p.dyn->
						    pfid_mask6,
						    saddr, AF_INET6);
						break;
#endif /* INET6 */
					}
				} else {
					PF_POOLMASK(naddr,
					    &r->rpool.cur->addr.v.a.addr,
					    &r->rpool.cur->addr.v.a.mask,
					    saddr, pd->af);
				}
				break;
			case PF_IN:
				if (r->src.addr.type == PF_ADDR_DYNIFTL) {
					if (r->src.addr.p.dyn == NULL)
						return (NULL);
					switch (pd->af) {
#if INET
					case AF_INET:
						if (r->src.addr.p.dyn->
						    pfid_acnt4 < 1)
							return (NULL);
						PF_POOLMASK(naddr,
						    &r->src.addr.p.dyn->
						    pfid_addr4,
						    &r->src.addr.p.dyn->
						    pfid_mask4,
						    daddr, AF_INET);
						break;
#endif /* INET */
#if INET6
					case AF_INET6:
						if (r->src.addr.p.dyn->
						    pfid_acnt6 < 1)
							return (NULL);
						PF_POOLMASK(naddr,
						    &r->src.addr.p.dyn->
						    pfid_addr6,
						    &r->src.addr.p.dyn->
						    pfid_mask6,
						    daddr, AF_INET6);
						break;
#endif /* INET6 */
					}
				} else
					PF_POOLMASK(naddr,
					    &r->src.addr.v.a.addr,
					    &r->src.addr.v.a.mask, daddr,
					    pd->af);
				break;
			}
			break;
		case PF_RDR: {
			switch (direction) {
			case PF_OUT:
				if (r->dst.addr.type == PF_ADDR_DYNIFTL) {
					if (r->dst.addr.p.dyn == NULL)
						return (NULL);
					switch (pd->af) {
#if INET
					case AF_INET:
						if (r->dst.addr.p.dyn->
						    pfid_acnt4 < 1)
							return (NULL);
						PF_POOLMASK(naddr,
						    &r->dst.addr.p.dyn->
						    pfid_addr4,
						    &r->dst.addr.p.dyn->
						    pfid_mask4,
						    daddr, AF_INET);
						break;
#endif /* INET */
#if INET6
					case AF_INET6:
						if (r->dst.addr.p.dyn->
						    pfid_acnt6 < 1)
							return (NULL);
						PF_POOLMASK(naddr,
						    &r->dst.addr.p.dyn->
						    pfid_addr6,
						    &r->dst.addr.p.dyn->
						    pfid_mask6,
						    daddr, AF_INET6);
						break;
#endif /* INET6 */
					}
				} else {
					PF_POOLMASK(naddr,
					    &r->dst.addr.v.a.addr,
					    &r->dst.addr.v.a.mask,
					    daddr, pd->af);
				}
				if (nxport && r->dst.xport.range.port[0])
					nxport->port =
					    r->dst.xport.range.port[0];
				break;
			case PF_IN:
				if (pf_map_addr(pd->af, r, saddr,
				    naddr, NULL, sn))
					return (NULL);
				if ((r->rpool.opts & PF_POOL_TYPEMASK) ==
				    PF_POOL_BITMASK)
					PF_POOLMASK(naddr, naddr,
					    &r->rpool.cur->addr.v.a.mask, daddr,
					    pd->af);

				if (nxport && dxport) {
					if (r->rpool.proxy_port[1]) {
						u_int32_t	tmp_nport;

						tmp_nport =
						    ((ntohs(dxport->port) -
						    ntohs(r->dst.xport.range.
						    port[0])) %
						    (r->rpool.proxy_port[1] -
						    r->rpool.proxy_port[0] +
						    1)) + r->rpool.proxy_port[0];

						/* wrap around if necessary */
						if (tmp_nport > 65535)
							tmp_nport -= 65535;
						nxport->port =
						    htons((u_int16_t)tmp_nport);
					} else if (r->rpool.proxy_port[0]) {
						nxport->port = htons(r->rpool.
						    proxy_port[0]);
					}
				}
				break;
			}
			break;
		}
		default:
			return (NULL);
		}
	}

	return (r);
}

int
pf_socket_lookup(int direction, struct pf_pdesc *pd)
{
	struct pf_addr		*saddr, *daddr;
	u_int16_t		 sport, dport;
	struct inpcbinfo	*pi; 
	int 			inp = 0;

	if (pd == NULL)
		return (-1);
	pd->lookup.uid = UID_MAX;
	pd->lookup.gid = GID_MAX;
	pd->lookup.pid = NO_PID;

	switch (pd->proto) {
	case IPPROTO_TCP:
		if (pd->hdr.tcp == NULL)
			return (-1);
		sport = pd->hdr.tcp->th_sport;
		dport = pd->hdr.tcp->th_dport;
		pi = &tcbinfo;
		break;
	case IPPROTO_UDP:
		if (pd->hdr.udp == NULL)
			return (-1);
		sport = pd->hdr.udp->uh_sport;
		dport = pd->hdr.udp->uh_dport;
		pi = &udbinfo;
		break;
	default:
		return (-1);
	}
	if (direction == PF_IN) {
		saddr = pd->src;
		daddr = pd->dst;
	} else {
		u_int16_t	p;

		p = sport;
		sport = dport;
		dport = p;
		saddr = pd->dst;
		daddr = pd->src;
	}
	switch (pd->af) {
#if INET
	case AF_INET:
		inp = in_pcblookup_hash_exists(pi, saddr->v4, sport, daddr->v4, dport,
		    0, &pd->lookup.uid, &pd->lookup.gid, NULL);
#if INET6
		if (inp == 0) {
			struct in6_addr s6, d6;

			memset(&s6, 0, sizeof (s6));
			s6.s6_addr16[5] = htons(0xffff);
			memcpy(&s6.s6_addr32[3], &saddr->v4,
			    sizeof (saddr->v4));

			memset(&d6, 0, sizeof (d6));
			d6.s6_addr16[5] = htons(0xffff);
			memcpy(&d6.s6_addr32[3], &daddr->v4,
			    sizeof (daddr->v4));

			inp = in6_pcblookup_hash_exists(pi, &s6, sport,
			    &d6, dport, 0, &pd->lookup.uid, &pd->lookup.gid, NULL);
			if (inp == 0) {
				inp = in_pcblookup_hash_exists(pi, saddr->v4, sport,
				    daddr->v4, dport, INPLOOKUP_WILDCARD, &pd->lookup.uid, &pd->lookup.gid, NULL);
				if (inp == 0) {
					inp = in6_pcblookup_hash_exists(pi, &s6, sport,
					    &d6, dport, INPLOOKUP_WILDCARD,
					    &pd->lookup.uid, &pd->lookup.gid, NULL);
					if (inp == 0)
						return (-1);
				}
			}
		}
#else
		if (inp == 0) {
			inp = in_pcblookup_hash_exists(pi, saddr->v4, sport,
			    daddr->v4, dport, INPLOOKUP_WILDCARD, 
			    &pd->lookup.uid, &pd->lookup.gid, NULL);
			if (inp == 0)
				return (-1);
		}
#endif /* !INET6 */
		break;
#endif /* INET */
#if INET6
	case AF_INET6:
		inp = in6_pcblookup_hash_exists(pi, &saddr->v6, sport, &daddr->v6,
		    dport, 0, &pd->lookup.uid, &pd->lookup.gid, NULL);
		if (inp == 0) {
			inp = in6_pcblookup_hash_exists(pi, &saddr->v6, sport,
			    &daddr->v6, dport, INPLOOKUP_WILDCARD,
			    &pd->lookup.uid, &pd->lookup.gid, NULL);
			if (inp == 0)
				return (-1);
		}
		break;
#endif /* INET6 */
                            
	default:
		return (-1);
	}

	return (1);
}

static u_int8_t
pf_get_wscale(struct mbuf *m, int off, u_int16_t th_off, sa_family_t af)
{
	int		 hlen;
	u_int8_t	 hdr[60];
	u_int8_t	*opt, optlen;
	u_int8_t	 wscale = 0;

	hlen = th_off << 2;		/* hlen <= sizeof (hdr) */
	if (hlen <= (int)sizeof (struct tcphdr))
		return (0);
	if (!pf_pull_hdr(m, off, hdr, hlen, NULL, NULL, af))
		return (0);
	opt = hdr + sizeof (struct tcphdr);
	hlen -= sizeof (struct tcphdr);
	while (hlen >= 3) {
		switch (*opt) {
		case TCPOPT_EOL:
		case TCPOPT_NOP:
			++opt;
			--hlen;
			break;
		case TCPOPT_WINDOW:
			wscale = opt[2];
			if (wscale > TCP_MAX_WINSHIFT)
				wscale = TCP_MAX_WINSHIFT;
			wscale |= PF_WSCALE_FLAG;
			/* FALLTHROUGH */
		default:
			optlen = opt[1];
			if (optlen < 2)
				optlen = 2;
			hlen -= optlen;
			opt += optlen;
			break;
		}
	}
	return (wscale);
}

static u_int16_t
pf_get_mss(struct mbuf *m, int off, u_int16_t th_off, sa_family_t af)
{
	int		 hlen;
	u_int8_t	 hdr[60];
	u_int8_t	*opt, optlen;
	u_int16_t	 mss = tcp_mssdflt;

	hlen = th_off << 2;	/* hlen <= sizeof (hdr) */
	if (hlen <= (int)sizeof (struct tcphdr))
		return (0);
	if (!pf_pull_hdr(m, off, hdr, hlen, NULL, NULL, af))
		return (0);
	opt = hdr + sizeof (struct tcphdr);
	hlen -= sizeof (struct tcphdr);
	while (hlen >= TCPOLEN_MAXSEG) {
		switch (*opt) {
		case TCPOPT_EOL:
		case TCPOPT_NOP:
			++opt;
			--hlen;
			break;
		case TCPOPT_MAXSEG:
			bcopy((caddr_t)(opt + 2), (caddr_t)&mss, 2);
#if BYTE_ORDER != BIG_ENDIAN
			NTOHS(mss);
#endif
			/* FALLTHROUGH */
		default:
			optlen = opt[1];
			if (optlen < 2)
				optlen = 2;
			hlen -= optlen;
			opt += optlen;
			break;
		}
	}
	return (mss);
}

static u_int16_t
pf_calc_mss(struct pf_addr *addr, sa_family_t af, u_int16_t offer)
{
#if INET
	struct sockaddr_in	*dst;
	struct route		 ro;
#endif /* INET */
#if INET6
	struct sockaddr_in6	*dst6;
	struct route_in6	 ro6;
#endif /* INET6 */
	struct rtentry		*rt = NULL;
	int			 hlen;
	u_int16_t		 mss = tcp_mssdflt;

	switch (af) {
#if INET
	case AF_INET:
		hlen = sizeof (struct ip);
		bzero(&ro, sizeof (ro));
		dst = (struct sockaddr_in *)(void *)&ro.ro_dst;
		dst->sin_family = AF_INET;
		dst->sin_len = sizeof (*dst);
		dst->sin_addr = addr->v4;
		rtalloc(&ro);
		rt = ro.ro_rt;
		break;
#endif /* INET */
#if INET6
	case AF_INET6:
		hlen = sizeof (struct ip6_hdr);
		bzero(&ro6, sizeof (ro6));
		dst6 = (struct sockaddr_in6 *)(void *)&ro6.ro_dst;
		dst6->sin6_family = AF_INET6;
		dst6->sin6_len = sizeof (*dst6);
		dst6->sin6_addr = addr->v6;
		rtalloc((struct route *)&ro);
		rt = ro6.ro_rt;
		break;
#endif /* INET6 */
	default:
		panic("pf_calc_mss: not AF_INET or AF_INET6!");
		return (0);
	}

	if (rt && rt->rt_ifp) {
		mss = rt->rt_ifp->if_mtu - hlen - sizeof (struct tcphdr);
		mss = max(tcp_mssdflt, mss);
		rtfree(rt);
	}
	mss = min(mss, offer);
	mss = max(mss, 64);		/* sanity - at least max opt space */
	return (mss);
}

static void
pf_set_rt_ifp(struct pf_state *s, struct pf_addr *saddr)
{
	struct pf_rule *r = s->rule.ptr;

	s->rt_kif = NULL;
	if (!r->rt || r->rt == PF_FASTROUTE)
		return;
	switch (s->state_key->af) {
#if INET
	case AF_INET:
		pf_map_addr(AF_INET, r, saddr, &s->rt_addr, NULL,
		    &s->nat_src_node);
		s->rt_kif = r->rpool.cur->kif;
		break;
#endif /* INET */
#if INET6
	case AF_INET6:
		pf_map_addr(AF_INET6, r, saddr, &s->rt_addr, NULL,
		    &s->nat_src_node);
		s->rt_kif = r->rpool.cur->kif;
		break;
#endif /* INET6 */
	}
}

static void
pf_attach_state(struct pf_state_key *sk, struct pf_state *s, int tail)
{
	s->state_key = sk;
	sk->refcnt++;

	/* list is sorted, if-bound states before floating */
	if (tail)
		TAILQ_INSERT_TAIL(&sk->states, s, next);
	else
		TAILQ_INSERT_HEAD(&sk->states, s, next);
}

static void
pf_detach_state(struct pf_state *s, int flags)
{
	struct pf_state_key	*sk = s->state_key;

	if (sk == NULL)
		return;

	s->state_key = NULL;
	TAILQ_REMOVE(&sk->states, s, next);
	if (--sk->refcnt == 0) {
		if (!(flags & PF_DT_SKIP_EXTGWY))
			RB_REMOVE(pf_state_tree_ext_gwy,
			    &pf_statetbl_ext_gwy, sk);
		if (!(flags & PF_DT_SKIP_LANEXT))
			RB_REMOVE(pf_state_tree_lan_ext,
			    &pf_statetbl_lan_ext, sk);
		if (sk->app_state)
			pool_put(&pf_app_state_pl, sk->app_state);
		pool_put(&pf_state_key_pl, sk);
	}
}

struct pf_state_key *
pf_alloc_state_key(struct pf_state *s, struct pf_state_key *psk)
{
	struct pf_state_key	*sk;

	if ((sk = pool_get(&pf_state_key_pl, PR_WAITOK)) == NULL)
		return (NULL);
	bzero(sk, sizeof (*sk));
	TAILQ_INIT(&sk->states);
	pf_attach_state(sk, s, 0);

	/* initialize state key from psk, if provided */
	if (psk != NULL) {
		bcopy(&psk->lan, &sk->lan, sizeof (sk->lan));
		bcopy(&psk->gwy, &sk->gwy, sizeof (sk->gwy));
		bcopy(&psk->ext, &sk->ext, sizeof (sk->ext));
		sk->af = psk->af;
		sk->proto = psk->proto;
		sk->direction = psk->direction;
		sk->proto_variant = psk->proto_variant;
		VERIFY(psk->app_state == NULL);
		sk->flowsrc = psk->flowsrc;
		sk->flowhash = psk->flowhash;
		/* don't touch tree entries, states and refcnt on sk */
	}

	return (sk);
}

static u_int32_t
pf_tcp_iss(struct pf_pdesc *pd)
{
	MD5_CTX ctx;
	u_int32_t digest[4];

	if (pf_tcp_secret_init == 0) {
		read_random(pf_tcp_secret, sizeof (pf_tcp_secret));
		MD5Init(&pf_tcp_secret_ctx);
		MD5Update(&pf_tcp_secret_ctx, pf_tcp_secret,
		    sizeof (pf_tcp_secret));
		pf_tcp_secret_init = 1;
	}
	ctx = pf_tcp_secret_ctx;

	MD5Update(&ctx, (char *)&pd->hdr.tcp->th_sport, sizeof (u_short));
	MD5Update(&ctx, (char *)&pd->hdr.tcp->th_dport, sizeof (u_short));
	if (pd->af == AF_INET6) {
		MD5Update(&ctx, (char *)&pd->src->v6, sizeof (struct in6_addr));
		MD5Update(&ctx, (char *)&pd->dst->v6, sizeof (struct in6_addr));
	} else {
		MD5Update(&ctx, (char *)&pd->src->v4, sizeof (struct in_addr));
		MD5Update(&ctx, (char *)&pd->dst->v4, sizeof (struct in_addr));
	}
	MD5Final((u_char *)digest, &ctx);
	pf_tcp_iss_off += 4096;
	return (digest[0] + random() + pf_tcp_iss_off);
}

static int
pf_test_rule(struct pf_rule **rm, struct pf_state **sm, int direction,
    struct pfi_kif *kif, struct mbuf *m, int off, void *h,
    struct pf_pdesc *pd, struct pf_rule **am, struct pf_ruleset **rsm,
    struct ifqueue *ifq)
{
#pragma unused(h)
	struct pf_rule		*nr = NULL;
	struct pf_addr		*saddr = pd->src, *daddr = pd->dst;
	sa_family_t		 af = pd->af;
	struct pf_rule		*r, *a = NULL;
	struct pf_ruleset	*ruleset = NULL;
	struct pf_src_node	*nsn = NULL;
	struct tcphdr		*th = pd->hdr.tcp;
	u_short			 reason;
	int			 rewrite = 0, hdrlen = 0;
	int			 tag = -1;
	unsigned int		 rtableid = IFSCOPE_NONE;
	int			 asd = 0;
	int			 match = 0;
	int			 state_icmp = 0;
	u_int16_t		 mss = tcp_mssdflt;
	u_int8_t		 icmptype = 0, icmpcode = 0;

	struct pf_grev1_hdr	*grev1 = pd->hdr.grev1;
	union pf_state_xport bxport, nxport, sxport, dxport;
	struct pf_state_key	 psk;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if (direction == PF_IN && pf_check_congestion(ifq)) {
		REASON_SET(&reason, PFRES_CONGEST);
		return (PF_DROP);
	}

	hdrlen = 0;
	sxport.spi = 0;
	dxport.spi = 0;
	nxport.spi = 0;

	switch (pd->proto) {
	case IPPROTO_TCP:
		sxport.port = th->th_sport;
		dxport.port = th->th_dport;
		hdrlen = sizeof (*th);
		break;
	case IPPROTO_UDP:
		sxport.port = pd->hdr.udp->uh_sport;
		dxport.port = pd->hdr.udp->uh_dport;
		hdrlen = sizeof (*pd->hdr.udp);
		break;
#if INET
	case IPPROTO_ICMP:
		if (pd->af != AF_INET)
			break;
		sxport.port = dxport.port = pd->hdr.icmp->icmp_id;
		hdrlen = ICMP_MINLEN;
		icmptype = pd->hdr.icmp->icmp_type;
		icmpcode = pd->hdr.icmp->icmp_code;

		if (icmptype == ICMP_UNREACH ||
		    icmptype == ICMP_SOURCEQUENCH ||
		    icmptype == ICMP_REDIRECT ||
		    icmptype == ICMP_TIMXCEED ||
		    icmptype == ICMP_PARAMPROB)
			state_icmp++;
		break;
#endif /* INET */
#if INET6
	case IPPROTO_ICMPV6:
		if (pd->af != AF_INET6)
			break;
		sxport.port = dxport.port = pd->hdr.icmp6->icmp6_id;
		hdrlen = sizeof (*pd->hdr.icmp6);
		icmptype = pd->hdr.icmp6->icmp6_type;
		icmpcode = pd->hdr.icmp6->icmp6_code;

		if (icmptype == ICMP6_DST_UNREACH ||
		    icmptype == ICMP6_PACKET_TOO_BIG ||
		    icmptype == ICMP6_TIME_EXCEEDED ||
		    icmptype == ICMP6_PARAM_PROB)
			state_icmp++;
		break;
#endif /* INET6 */
	case IPPROTO_GRE:
		if (pd->proto_variant == PF_GRE_PPTP_VARIANT) {
			sxport.call_id = dxport.call_id =
			    pd->hdr.grev1->call_id;
			hdrlen = sizeof (*pd->hdr.grev1);
		}
		break;
	case IPPROTO_ESP:
		sxport.spi = 0;
		dxport.spi = pd->hdr.esp->spi;
		hdrlen = sizeof (*pd->hdr.esp);
		break;
	}

	r = TAILQ_FIRST(pf_main_ruleset.rules[PF_RULESET_FILTER].active.ptr);

	if (direction == PF_OUT) {
		bxport = nxport = sxport;
		/* check outgoing packet for BINAT/NAT */
		if ((nr = pf_get_translation_aux(pd, m, off, PF_OUT, kif, &nsn,
		    saddr, &sxport, daddr, &dxport, &pd->naddr, &nxport)) !=
		    NULL) {
			PF_ACPY(&pd->baddr, saddr, af);
			switch (pd->proto) {
			case IPPROTO_TCP:
				pf_change_ap(direction, pd->mp, saddr,
				    &th->th_sport, pd->ip_sum, &th->th_sum,
				    &pd->naddr, nxport.port, 0, af);
				sxport.port = th->th_sport;
				rewrite++;
				break;
			case IPPROTO_UDP:
				pf_change_ap(direction, pd->mp, saddr,
				    &pd->hdr.udp->uh_sport, pd->ip_sum,
				    &pd->hdr.udp->uh_sum, &pd->naddr,
				    nxport.port, 1, af);
				sxport.port = pd->hdr.udp->uh_sport;
				rewrite++;
				break;
#if INET
			case IPPROTO_ICMP:
				if (pd->af == AF_INET) {
					pf_change_a(&saddr->v4.s_addr, pd->ip_sum,
					    pd->naddr.v4.s_addr, 0);
					pd->hdr.icmp->icmp_cksum = pf_cksum_fixup(
					    pd->hdr.icmp->icmp_cksum, sxport.port,
					    nxport.port, 0);
					pd->hdr.icmp->icmp_id = nxport.port;
					++rewrite;
				}
				break;
#endif /* INET */
#if INET6
			case IPPROTO_ICMPV6:
				if (pd->af == AF_INET6) {
					pf_change_a6(saddr, &pd->hdr.icmp6->icmp6_cksum,
					    &pd->naddr, 0);
					rewrite++;
				}
				break;
#endif /* INET */
			case IPPROTO_GRE:
				switch (af) {
#if INET
				case AF_INET:
					pf_change_a(&saddr->v4.s_addr,
					    pd->ip_sum, pd->naddr.v4.s_addr, 0);
					break;
#endif /* INET */
#if INET6
				case AF_INET6:
					PF_ACPY(saddr, &pd->naddr, AF_INET6);
					break;
#endif /* INET6 */
				}
				++rewrite;
				break;
			case IPPROTO_ESP:
				bxport.spi = 0;
				switch (af) {
#if INET
				case AF_INET:
					pf_change_a(&saddr->v4.s_addr,
					    pd->ip_sum, pd->naddr.v4.s_addr, 0);
					break;
#endif /* INET */
#if INET6
				case AF_INET6:
					PF_ACPY(saddr, &pd->naddr, AF_INET6);
					break;
#endif /* INET6 */
				}
				break;
			default:
				switch (af) {
#if INET
				case AF_INET:
					pf_change_a(&saddr->v4.s_addr,
					    pd->ip_sum, pd->naddr.v4.s_addr, 0);
					break;
#endif /* INET */
#if INET6
				case AF_INET6:
					PF_ACPY(saddr, &pd->naddr, af);
					break;
#endif /* INET */
				}
				break;
			}

			if (nr->natpass)
				r = NULL;
			pd->nat_rule = nr;
		}
	} else {
		bxport.port = nxport.port = dxport.port;
		/* check incoming packet for BINAT/RDR */
		if ((nr = pf_get_translation_aux(pd, m, off, PF_IN, kif, &nsn,
		    saddr, &sxport, daddr, &dxport, &pd->naddr, &nxport)) !=
		    NULL) {
			PF_ACPY(&pd->baddr, daddr, af);
			switch (pd->proto) {
			case IPPROTO_TCP:
				pf_change_ap(direction, pd->mp, daddr,
				    &th->th_dport, pd->ip_sum, &th->th_sum,
				    &pd->naddr, nxport.port, 0, af);
				dxport.port = th->th_dport;
				rewrite++;
				break;
			case IPPROTO_UDP:
				pf_change_ap(direction, pd->mp, daddr,
				    &pd->hdr.udp->uh_dport, pd->ip_sum,
				    &pd->hdr.udp->uh_sum, &pd->naddr,
				    nxport.port, 1, af);
				dxport.port = pd->hdr.udp->uh_dport;
				rewrite++;
				break;
#if INET
			case IPPROTO_ICMP:
				if (pd->af == AF_INET) {
					pf_change_a(&daddr->v4.s_addr, pd->ip_sum,
					    pd->naddr.v4.s_addr, 0);
				}
				break;
#endif /* INET */
#if INET6
			case IPPROTO_ICMPV6:
				if (pd->af == AF_INET6) {
					pf_change_a6(daddr, &pd->hdr.icmp6->icmp6_cksum,
					    &pd->naddr, 0);
					rewrite++;
				}
				break;
#endif /* INET6 */
			case IPPROTO_GRE:
				if (pd->proto_variant == PF_GRE_PPTP_VARIANT)
					grev1->call_id = nxport.call_id;

				switch (af) {
#if INET
				case AF_INET:
					pf_change_a(&daddr->v4.s_addr,
					    pd->ip_sum, pd->naddr.v4.s_addr, 0);
					break;
#endif /* INET */
#if INET6
				case AF_INET6:
					PF_ACPY(daddr, &pd->naddr, AF_INET6);
					break;
#endif /* INET6 */
				}
				++rewrite;
				break;
			case IPPROTO_ESP:
				switch (af) {
#if INET
				case AF_INET:
					pf_change_a(&daddr->v4.s_addr,
					    pd->ip_sum, pd->naddr.v4.s_addr, 0);
					break;
#endif /* INET */
#if INET6
				case AF_INET6:
					PF_ACPY(daddr, &pd->naddr, AF_INET6);
					break;
#endif /* INET6 */
				}
				break;
			default:
				switch (af) {
#if INET
				case AF_INET:
					pf_change_a(&daddr->v4.s_addr,
					    pd->ip_sum, pd->naddr.v4.s_addr, 0);
					break;
#endif /* INET */
#if INET6
				case AF_INET6:
					PF_ACPY(daddr, &pd->naddr, af);
					break;
#endif /* INET */
				}
				break;
			}

			if (nr->natpass)
				r = NULL;
			pd->nat_rule = nr;
		}
	}

	if (nr && nr->tag > 0)
		tag = nr->tag;

	while (r != NULL) {
		r->evaluations++;
		if (pfi_kif_match(r->kif, kif) == r->ifnot)
			r = r->skip[PF_SKIP_IFP].ptr;
		else if (r->direction && r->direction != direction)
			r = r->skip[PF_SKIP_DIR].ptr;
		else if (r->af && r->af != af)
			r = r->skip[PF_SKIP_AF].ptr;
		else if (r->proto && r->proto != pd->proto)
			r = r->skip[PF_SKIP_PROTO].ptr;
		else if (PF_MISMATCHAW(&r->src.addr, saddr, af,
		    r->src.neg, kif))
			r = r->skip[PF_SKIP_SRC_ADDR].ptr;
		/* tcp/udp only. port_op always 0 in other cases */
		else if (r->proto == pd->proto &&
		    (r->proto == IPPROTO_TCP || r->proto == IPPROTO_UDP) &&
		    r->src.xport.range.op &&
		    !pf_match_port(r->src.xport.range.op,
		    r->src.xport.range.port[0], r->src.xport.range.port[1],
		    th->th_sport))
			r = r->skip[PF_SKIP_SRC_PORT].ptr;
		else if (PF_MISMATCHAW(&r->dst.addr, daddr, af,
		    r->dst.neg, NULL))
			r = r->skip[PF_SKIP_DST_ADDR].ptr;
		/* tcp/udp only. port_op always 0 in other cases */
		else if (r->proto == pd->proto &&
		    (r->proto == IPPROTO_TCP || r->proto == IPPROTO_UDP) &&
		    r->dst.xport.range.op &&
		    !pf_match_port(r->dst.xport.range.op,
		    r->dst.xport.range.port[0], r->dst.xport.range.port[1],
		    th->th_dport))
			r = r->skip[PF_SKIP_DST_PORT].ptr;
		/* icmp only. type always 0 in other cases */
		else if (r->type && r->type != icmptype + 1)
			r = TAILQ_NEXT(r, entries);
		/* icmp only. type always 0 in other cases */
		else if (r->code && r->code != icmpcode + 1)
			r = TAILQ_NEXT(r, entries);
		else if ((r->rule_flag & PFRULE_TOS) && r->tos &&
		    !(r->tos & pd->tos))
			r = TAILQ_NEXT(r, entries);
		else if ((r->rule_flag & PFRULE_DSCP) && r->tos &&
		    !(r->tos & (pd->tos & DSCP_MASK)))
			r = TAILQ_NEXT(r, entries);
		else if ((r->rule_flag & PFRULE_SC) && r->tos &&
		    ((r->tos & SCIDX_MASK) != pd->sc))
			r = TAILQ_NEXT(r, entries);
		else if (r->rule_flag & PFRULE_FRAGMENT)
			r = TAILQ_NEXT(r, entries);
		else if (pd->proto == IPPROTO_TCP &&
		    (r->flagset & th->th_flags) != r->flags)
			r = TAILQ_NEXT(r, entries);
		/* tcp/udp only. uid.op always 0 in other cases */
		else if (r->uid.op && (pd->lookup.done || (pd->lookup.done =
		    pf_socket_lookup(direction, pd), 1)) &&
		    !pf_match_uid(r->uid.op, r->uid.uid[0], r->uid.uid[1],
		    pd->lookup.uid))
			r = TAILQ_NEXT(r, entries);
		/* tcp/udp only. gid.op always 0 in other cases */
		else if (r->gid.op && (pd->lookup.done || (pd->lookup.done =
		    pf_socket_lookup(direction, pd), 1)) &&
		    !pf_match_gid(r->gid.op, r->gid.gid[0], r->gid.gid[1],
		    pd->lookup.gid))
			r = TAILQ_NEXT(r, entries);
		else if (r->prob && r->prob <= (RandomULong() % (UINT_MAX - 1) + 1))
			r = TAILQ_NEXT(r, entries);
		else if (r->match_tag && !pf_match_tag(m, r, pd->pf_mtag, &tag))
			r = TAILQ_NEXT(r, entries);
		else if (r->os_fingerprint != PF_OSFP_ANY &&
		    (pd->proto != IPPROTO_TCP || !pf_osfp_match(
		    pf_osfp_fingerprint(pd, m, off, th),
		    r->os_fingerprint)))
			r = TAILQ_NEXT(r, entries);
		else {
			if (r->tag)
				tag = r->tag;
			if (PF_RTABLEID_IS_VALID(r->rtableid))
				rtableid = r->rtableid;
			if (r->anchor == NULL) {
				match = 1;
				*rm = r;
				*am = a;
				*rsm = ruleset;
				if ((*rm)->quick)
					break;
				r = TAILQ_NEXT(r, entries);
			} else
				pf_step_into_anchor(&asd, &ruleset,
				    PF_RULESET_FILTER, &r, &a, &match);
		}
		if (r == NULL && pf_step_out_of_anchor(&asd, &ruleset,
		    PF_RULESET_FILTER, &r, &a, &match))
			break;
	}
	r = *rm;
	a = *am;
	ruleset = *rsm;

	REASON_SET(&reason, PFRES_MATCH);

	if (r->log || (nr != NULL && nr->log)) {
		if (rewrite > 0) {
			if (rewrite < off + hdrlen)
				rewrite = off + hdrlen;

			m = pf_lazy_makewritable(pd, m, rewrite);
			if (!m) {
				REASON_SET(&reason, PFRES_MEMORY);
				return (PF_DROP);
			}

			m_copyback(m, off, hdrlen, pd->hdr.any);
		}
		PFLOG_PACKET(kif, h, m, af, direction, reason, r->log ? r : nr,
		    a, ruleset, pd);
	}

	if ((r->action == PF_DROP) &&
	    ((r->rule_flag & PFRULE_RETURNRST) ||
	    (r->rule_flag & PFRULE_RETURNICMP) ||
	    (r->rule_flag & PFRULE_RETURN))) {
		/* undo NAT changes, if they have taken place */
		if (nr != NULL) {
			if (direction == PF_OUT) {
				switch (pd->proto) {
				case IPPROTO_TCP:
					pf_change_ap(direction, pd->mp, saddr,
					    &th->th_sport, pd->ip_sum,
					    &th->th_sum, &pd->baddr,
					    bxport.port, 0, af);
					sxport.port = th->th_sport;
					rewrite++;
					break;
				case IPPROTO_UDP:
					pf_change_ap(direction, pd->mp, saddr,
					    &pd->hdr.udp->uh_sport, pd->ip_sum,
					    &pd->hdr.udp->uh_sum, &pd->baddr,
					    bxport.port, 1, af);
					sxport.port = pd->hdr.udp->uh_sport;
					rewrite++;
					break;
				case IPPROTO_ICMP:
#if INET6
				case IPPROTO_ICMPV6:
#endif
					/* nothing! */
					break;
				case IPPROTO_GRE:
					PF_ACPY(&pd->baddr, saddr, af);
					++rewrite;
					switch (af) {
#if INET
					case AF_INET:
						pf_change_a(&saddr->v4.s_addr,
						    pd->ip_sum,
						    pd->baddr.v4.s_addr, 0);
						break;
#endif /* INET */
#if INET6
					case AF_INET6:
						PF_ACPY(saddr, &pd->baddr,
						    AF_INET6);
						break;
#endif /* INET6 */
					}
					break;
				case IPPROTO_ESP:
					PF_ACPY(&pd->baddr, saddr, af);
					switch (af) {
#if INET
					case AF_INET:
						pf_change_a(&saddr->v4.s_addr,
						    pd->ip_sum,
						    pd->baddr.v4.s_addr, 0);
						break;
#endif /* INET */
#if INET6
					case AF_INET6:
						PF_ACPY(saddr, &pd->baddr,
						    AF_INET6);
						break;
#endif /* INET6 */
					}
					break;
				default:
					switch (af) {
					case AF_INET:
						pf_change_a(&saddr->v4.s_addr,
						    pd->ip_sum,
						    pd->baddr.v4.s_addr, 0);
						break;
					case AF_INET6:
						PF_ACPY(saddr, &pd->baddr, af);
						break;
					}
				}
			} else {
				switch (pd->proto) {
				case IPPROTO_TCP:
					pf_change_ap(direction, pd->mp, daddr,
					    &th->th_dport, pd->ip_sum,
					    &th->th_sum, &pd->baddr,
					    bxport.port, 0, af);
					dxport.port = th->th_dport;
					rewrite++;
					break;
				case IPPROTO_UDP:
					pf_change_ap(direction, pd->mp, daddr,
					    &pd->hdr.udp->uh_dport, pd->ip_sum,
					    &pd->hdr.udp->uh_sum, &pd->baddr,
					    bxport.port, 1, af);
					dxport.port = pd->hdr.udp->uh_dport;
					rewrite++;
					break;
				case IPPROTO_ICMP:
#if INET6
				case IPPROTO_ICMPV6:
#endif
					/* nothing! */
					break;
				case IPPROTO_GRE:
					if (pd->proto_variant ==
					    PF_GRE_PPTP_VARIANT)
						grev1->call_id = bxport.call_id;
					++rewrite;
					switch (af) {
#if INET
					case AF_INET:
						pf_change_a(&daddr->v4.s_addr,
						    pd->ip_sum,
						    pd->baddr.v4.s_addr, 0);
						break;
#endif /* INET */
#if INET6
					case AF_INET6:
						PF_ACPY(daddr, &pd->baddr,
						    AF_INET6);
						break;
#endif /* INET6 */
					}
					break;
				case IPPROTO_ESP:
					switch (af) {
#if INET
					case AF_INET:
						pf_change_a(&daddr->v4.s_addr,
						    pd->ip_sum,
						    pd->baddr.v4.s_addr, 0);
						break;
#endif /* INET */
#if INET6
					case AF_INET6:
						PF_ACPY(daddr, &pd->baddr,
						    AF_INET6);
						break;
#endif /* INET6 */
					}
					break;
				default:
					switch (af) {
					case AF_INET:
						pf_change_a(&daddr->v4.s_addr,
						    pd->ip_sum,
						    pd->baddr.v4.s_addr, 0);
						break;
#if INET6
					case AF_INET6:
						PF_ACPY(daddr, &pd->baddr, af);
						break;
#endif /* INET6 */
					}
				}
			}
		}
		if (pd->proto == IPPROTO_TCP &&
		    ((r->rule_flag & PFRULE_RETURNRST) ||
		    (r->rule_flag & PFRULE_RETURN)) &&
		    !(th->th_flags & TH_RST)) {
			u_int32_t	 ack = ntohl(th->th_seq) + pd->p_len;
			int		 len = 0;
			struct ip	*h4;
#if INET6
			struct ip6_hdr	*h6;
#endif /* INET6 */

			switch (af) {
			case AF_INET:
				h4 = mtod(m, struct ip *);
				len = ntohs(h4->ip_len) - off;
				break;
#if INET6
			case AF_INET6:
				h6 = mtod(m, struct ip6_hdr *);
				len = ntohs(h6->ip6_plen) -
				    (off - sizeof (*h6));
				break;
#endif /* INET6 */
			}

			if (pf_check_proto_cksum(m, off, len, IPPROTO_TCP, af))
				REASON_SET(&reason, PFRES_PROTCKSUM);
			else {
				if (th->th_flags & TH_SYN)
					ack++;
				if (th->th_flags & TH_FIN)
					ack++;
				pf_send_tcp(r, af, pd->dst,
				    pd->src, th->th_dport, th->th_sport,
				    ntohl(th->th_ack), ack, TH_RST|TH_ACK, 0, 0,
				    r->return_ttl, 1, 0, pd->eh, kif->pfik_ifp);
			}
		} else if (pd->proto != IPPROTO_ICMP && af == AF_INET &&
		    pd->proto != IPPROTO_ESP && pd->proto != IPPROTO_AH &&
		    r->return_icmp)
			pf_send_icmp(m, r->return_icmp >> 8,
			    r->return_icmp & 255, af, r);
		else if (pd->proto != IPPROTO_ICMPV6 && af == AF_INET6 &&
		    pd->proto != IPPROTO_ESP && pd->proto != IPPROTO_AH &&
		    r->return_icmp6)
			pf_send_icmp(m, r->return_icmp6 >> 8,
			    r->return_icmp6 & 255, af, r);
	}

	if (r->action == PF_DROP)
		return (PF_DROP);

	/* prepare state key, for flowhash and/or the state (if created) */
	bzero(&psk, sizeof (psk));
	psk.proto = pd->proto;
	psk.direction = direction;
	psk.af = af;
	if (pd->proto == IPPROTO_UDP) {
		if (ntohs(pd->hdr.udp->uh_sport) == PF_IKE_PORT &&
		    ntohs(pd->hdr.udp->uh_dport) == PF_IKE_PORT) {
			psk.proto_variant = PF_EXTFILTER_APD;
		} else {
			psk.proto_variant = nr ? nr->extfilter : r->extfilter;
			if (psk.proto_variant < PF_EXTFILTER_APD)
				psk.proto_variant = PF_EXTFILTER_APD;
		}
	} else if (pd->proto == IPPROTO_GRE) {
		psk.proto_variant = pd->proto_variant;
	}
	if (direction == PF_OUT) {
		PF_ACPY(&psk.gwy.addr, saddr, af);
		PF_ACPY(&psk.ext.addr, daddr, af);
		switch (pd->proto) {
		case IPPROTO_UDP:
			psk.gwy.xport = sxport;
			psk.ext.xport = dxport;
			break;
		case IPPROTO_ESP:
			psk.gwy.xport.spi = 0;
			psk.ext.xport.spi = pd->hdr.esp->spi;
			break;
		case IPPROTO_ICMP:
#if INET6
		case IPPROTO_ICMPV6:
#endif
			psk.gwy.xport.port = nxport.port;
			psk.ext.xport.spi = 0;
			break;
		default:
			psk.gwy.xport = sxport;
			psk.ext.xport = dxport;
			break;
		}
		if (nr != NULL) {
			PF_ACPY(&psk.lan.addr, &pd->baddr, af);
			psk.lan.xport = bxport;
		} else {
			PF_ACPY(&psk.lan.addr, &psk.gwy.addr, af);
			psk.lan.xport = psk.gwy.xport;
		}
	} else {
		PF_ACPY(&psk.lan.addr, daddr, af);
		PF_ACPY(&psk.ext.addr, saddr, af);
		switch (pd->proto) {
		case IPPROTO_ICMP:
#if INET6
		case IPPROTO_ICMPV6:
#endif
			psk.lan.xport = nxport;
			psk.ext.xport.spi = 0;
			break;
		case IPPROTO_ESP:
			psk.ext.xport.spi = 0;
			psk.lan.xport.spi = pd->hdr.esp->spi;
			break;
		default:
			psk.lan.xport = dxport;
			psk.ext.xport = sxport;
			break;
		}
		if (nr != NULL) {
			PF_ACPY(&psk.gwy.addr, &pd->baddr, af);
			psk.gwy.xport = bxport;
		} else {
			PF_ACPY(&psk.gwy.addr, &psk.lan.addr, af);
			psk.gwy.xport = psk.lan.xport;
		}
	}
	if (pd->pktflags & PKTF_FLOW_ID) {
		/* flow hash was already computed outside of PF */
		psk.flowsrc = pd->flowsrc;
		psk.flowhash = pd->flowhash;
	} else {
		/* compute flow hash and store it in state key */
		psk.flowsrc = FLOWSRC_PF;
		psk.flowhash = pf_calc_state_key_flowhash(&psk);
		pd->flowsrc = psk.flowsrc;
		pd->flowhash = psk.flowhash;
		pd->pktflags |= PKTF_FLOW_ID;
		pd->pktflags &= ~PKTF_FLOW_ADV;
	}

	if (pf_tag_packet(m, pd->pf_mtag, tag, rtableid, pd)) {
		REASON_SET(&reason, PFRES_MEMORY);
		return (PF_DROP);
	}

	if (!state_icmp && (r->keep_state || nr != NULL ||
	    (pd->flags & PFDESC_TCP_NORM))) {
		/* create new state */
		struct pf_state	*s = NULL;
		struct pf_state_key *sk = NULL;
		struct pf_src_node *sn = NULL;
		struct pf_ike_hdr ike;

		if (pd->proto == IPPROTO_UDP) {
			struct udphdr *uh = pd->hdr.udp;
			size_t plen = m->m_pkthdr.len - off - sizeof (*uh);

			if (ntohs(uh->uh_sport) == PF_IKE_PORT &&
			    ntohs(uh->uh_dport) == PF_IKE_PORT &&
			    plen >= PF_IKE_PACKET_MINSIZE) {
				if (plen > PF_IKE_PACKET_MINSIZE)
					plen = PF_IKE_PACKET_MINSIZE;
				m_copydata(m, off + sizeof (*uh), plen, &ike);
			}
		}

		if (nr != NULL && pd->proto == IPPROTO_ESP &&
		    direction == PF_OUT) {
			struct pf_state_key_cmp	sk0;
			struct pf_state *s0;

			/*
			 * <jhw@apple.com>
			 * This squelches state creation if the external
			 * address matches an existing incomplete state with a
			 * different internal address.  Only one 'blocking'
			 * partial state is allowed for each external address.
			 */
			memset(&sk0, 0, sizeof (sk0));
			sk0.af = pd->af;
			sk0.proto = IPPROTO_ESP;
			PF_ACPY(&sk0.gwy.addr, saddr, sk0.af);
			PF_ACPY(&sk0.ext.addr, daddr, sk0.af);
			s0 = pf_find_state(kif, &sk0, PF_IN);

			if (s0 && PF_ANEQ(&s0->state_key->lan.addr,
			    pd->src, pd->af)) {
				nsn = 0;
				goto cleanup;
			}
		}

		/* check maximums */
		if (r->max_states && (r->states >= r->max_states)) {
			pf_status.lcounters[LCNT_STATES]++;
			REASON_SET(&reason, PFRES_MAXSTATES);
			goto cleanup;
		}
		/* src node for filter rule */
		if ((r->rule_flag & PFRULE_SRCTRACK ||
		    r->rpool.opts & PF_POOL_STICKYADDR) &&
		    pf_insert_src_node(&sn, r, saddr, af) != 0) {
			REASON_SET(&reason, PFRES_SRCLIMIT);
			goto cleanup;
		}
		/* src node for translation rule */
		if (nr != NULL && (nr->rpool.opts & PF_POOL_STICKYADDR) &&
		    ((direction == PF_OUT &&
		    nr->action != PF_RDR &&
		    pf_insert_src_node(&nsn, nr, &pd->baddr, af) != 0) ||
		    (pf_insert_src_node(&nsn, nr, saddr, af) != 0))) {
			REASON_SET(&reason, PFRES_SRCLIMIT);
			goto cleanup;
		}
		s = pool_get(&pf_state_pl, PR_WAITOK);
		if (s == NULL) {
			REASON_SET(&reason, PFRES_MEMORY);
cleanup:
			if (sn != NULL && sn->states == 0 && sn->expire == 0) {
				RB_REMOVE(pf_src_tree, &tree_src_tracking, sn);
				pf_status.scounters[SCNT_SRC_NODE_REMOVALS]++;
				pf_status.src_nodes--;
				pool_put(&pf_src_tree_pl, sn);
			}
			if (nsn != sn && nsn != NULL && nsn->states == 0 &&
			    nsn->expire == 0) {
				RB_REMOVE(pf_src_tree, &tree_src_tracking, nsn);
				pf_status.scounters[SCNT_SRC_NODE_REMOVALS]++;
				pf_status.src_nodes--;
				pool_put(&pf_src_tree_pl, nsn);
			}
			if (sk != NULL) {
				if (sk->app_state)
					pool_put(&pf_app_state_pl,
					    sk->app_state);
				pool_put(&pf_state_key_pl, sk);
			}
			return (PF_DROP);
		}
		bzero(s, sizeof (*s));
		TAILQ_INIT(&s->unlink_hooks);
		s->rule.ptr = r;
		s->nat_rule.ptr = nr;
		s->anchor.ptr = a;
		STATE_INC_COUNTERS(s);
		s->allow_opts = r->allow_opts;
		s->log = r->log & PF_LOG_ALL;
		if (nr != NULL)
			s->log |= nr->log & PF_LOG_ALL;
		switch (pd->proto) {
		case IPPROTO_TCP:
			s->src.seqlo = ntohl(th->th_seq);
			s->src.seqhi = s->src.seqlo + pd->p_len + 1;
			if ((th->th_flags & (TH_SYN|TH_ACK)) ==
			    TH_SYN && r->keep_state == PF_STATE_MODULATE) {
				/* Generate sequence number modulator */
				if ((s->src.seqdiff = pf_tcp_iss(pd) -
				    s->src.seqlo) == 0)
					s->src.seqdiff = 1;
				pf_change_a(&th->th_seq, &th->th_sum,
				    htonl(s->src.seqlo + s->src.seqdiff), 0);
				rewrite = off + sizeof (*th);
			} else
				s->src.seqdiff = 0;
			if (th->th_flags & TH_SYN) {
				s->src.seqhi++;
				s->src.wscale = pf_get_wscale(m, off,
				    th->th_off, af);
			}
			s->src.max_win = MAX(ntohs(th->th_win), 1);
			if (s->src.wscale & PF_WSCALE_MASK) {
				/* Remove scale factor from initial window */
				int win = s->src.max_win;
				win += 1 << (s->src.wscale & PF_WSCALE_MASK);
				s->src.max_win = (win - 1) >>
				    (s->src.wscale & PF_WSCALE_MASK);
			}
			if (th->th_flags & TH_FIN)
				s->src.seqhi++;
			s->dst.seqhi = 1;
			s->dst.max_win = 1;
			s->src.state = TCPS_SYN_SENT;
			s->dst.state = TCPS_CLOSED;
			s->timeout = PFTM_TCP_FIRST_PACKET;
			break;
		case IPPROTO_UDP:
			s->src.state = PFUDPS_SINGLE;
			s->dst.state = PFUDPS_NO_TRAFFIC;
			s->timeout = PFTM_UDP_FIRST_PACKET;
			break;
		case IPPROTO_ICMP:
#if INET6
		case IPPROTO_ICMPV6:
#endif
			s->timeout = PFTM_ICMP_FIRST_PACKET;
			break;
		case IPPROTO_GRE:
			s->src.state = PFGRE1S_INITIATING;
			s->dst.state = PFGRE1S_NO_TRAFFIC;
			s->timeout = PFTM_GREv1_INITIATING;
			break;
		case IPPROTO_ESP:
			s->src.state = PFESPS_INITIATING;
			s->dst.state = PFESPS_NO_TRAFFIC;
			s->timeout = PFTM_ESP_FIRST_PACKET;
			break;
		default:
			s->src.state = PFOTHERS_SINGLE;
			s->dst.state = PFOTHERS_NO_TRAFFIC;
			s->timeout = PFTM_OTHER_FIRST_PACKET;
		}

		s->creation = pf_time_second();
		s->expire = pf_time_second();

		if (sn != NULL) {
			s->src_node = sn;
			s->src_node->states++;
			VERIFY(s->src_node->states != 0);
		}
		if (nsn != NULL) {
			PF_ACPY(&nsn->raddr, &pd->naddr, af);
			s->nat_src_node = nsn;
			s->nat_src_node->states++;
			VERIFY(s->nat_src_node->states != 0);
		}
		if (pd->proto == IPPROTO_TCP) {
			if ((pd->flags & PFDESC_TCP_NORM) &&
			    pf_normalize_tcp_init(m, off, pd, th, &s->src,
			    &s->dst)) {
				REASON_SET(&reason, PFRES_MEMORY);
				pf_src_tree_remove_state(s);
				STATE_DEC_COUNTERS(s);
				pool_put(&pf_state_pl, s);
				return (PF_DROP);
			}
			if ((pd->flags & PFDESC_TCP_NORM) && s->src.scrub &&
			    pf_normalize_tcp_stateful(m, off, pd, &reason,
			    th, s, &s->src, &s->dst, &rewrite)) {
				/* This really shouldn't happen!!! */
				DPFPRINTF(PF_DEBUG_URGENT,
				    ("pf_normalize_tcp_stateful failed on "
				    "first pkt"));
				pf_normalize_tcp_cleanup(s);
				pf_src_tree_remove_state(s);
				STATE_DEC_COUNTERS(s);
				pool_put(&pf_state_pl, s);
				return (PF_DROP);
			}
		}

		/* allocate state key and import values from psk */
		if ((sk = pf_alloc_state_key(s, &psk)) == NULL) {
			REASON_SET(&reason, PFRES_MEMORY);
			goto cleanup;
		}

		pf_set_rt_ifp(s, saddr);	/* needs s->state_key set */

		m = pd->mp;

		if (sk->app_state == 0) {
			switch (pd->proto) {
			case IPPROTO_TCP: {
				u_int16_t dport = (direction == PF_OUT) ?
				    sk->ext.xport.port : sk->gwy.xport.port;

				if (nr != NULL &&
				    ntohs(dport) == PF_PPTP_PORT) {
					struct pf_app_state *as;

					as = pool_get(&pf_app_state_pl,
					    PR_WAITOK);
					if (!as) {
						REASON_SET(&reason,
						    PFRES_MEMORY);
						goto cleanup;
					}

					bzero(as, sizeof (*as));
					as->handler = pf_pptp_handler;
					as->compare_lan_ext = 0;
					as->compare_ext_gwy = 0;
					as->u.pptp.grev1_state = 0;
					sk->app_state = as;
					(void) hook_establish(&s->unlink_hooks,
					    0, (hook_fn_t) pf_pptp_unlink, s);
				}
				break;
			}

			case IPPROTO_UDP: {
				struct udphdr *uh = pd->hdr.udp;

				if (nr != NULL &&
				    ntohs(uh->uh_sport) == PF_IKE_PORT &&
				    ntohs(uh->uh_dport) == PF_IKE_PORT) {
					struct pf_app_state *as;

					as = pool_get(&pf_app_state_pl,
					    PR_WAITOK);
					if (!as) {
						REASON_SET(&reason,
						    PFRES_MEMORY);
						goto cleanup;
					}

					bzero(as, sizeof (*as));
					as->compare_lan_ext = pf_ike_compare;
					as->compare_ext_gwy = pf_ike_compare;
					as->u.ike.cookie = ike.initiator_cookie;
					sk->app_state = as;
				}
				break;
			}

			default:
				break;
			}
		}

		if (pf_insert_state(BOUND_IFACE(r, kif), s)) {
			if (pd->proto == IPPROTO_TCP)
				pf_normalize_tcp_cleanup(s);
			REASON_SET(&reason, PFRES_STATEINS);
			pf_src_tree_remove_state(s);
			STATE_DEC_COUNTERS(s);
			pool_put(&pf_state_pl, s);
			return (PF_DROP);
		} else
			*sm = s;
		if (tag > 0) {
			pf_tag_ref(tag);
			s->tag = tag;
		}
		if (pd->proto == IPPROTO_TCP &&
		    (th->th_flags & (TH_SYN|TH_ACK)) == TH_SYN &&
		    r->keep_state == PF_STATE_SYNPROXY) {
			s->src.state = PF_TCPS_PROXY_SRC;
			if (nr != NULL) {
				if (direction == PF_OUT) {
					pf_change_ap(direction, pd->mp, saddr,
					    &th->th_sport, pd->ip_sum,
					    &th->th_sum, &pd->baddr,
					    bxport.port, 0, af);
					sxport.port = th->th_sport;
				} else {
					pf_change_ap(direction, pd->mp, daddr,
					    &th->th_dport, pd->ip_sum,
					    &th->th_sum, &pd->baddr,
					    bxport.port, 0, af);
					sxport.port = th->th_dport;
				}
			}
			s->src.seqhi = htonl(random());
			/* Find mss option */
			mss = pf_get_mss(m, off, th->th_off, af);
			mss = pf_calc_mss(saddr, af, mss);
			mss = pf_calc_mss(daddr, af, mss);
			s->src.mss = mss;
			pf_send_tcp(r, af, daddr, saddr, th->th_dport,
			    th->th_sport, s->src.seqhi, ntohl(th->th_seq) + 1,
			    TH_SYN|TH_ACK, 0, s->src.mss, 0, 1, 0, NULL, NULL);
			REASON_SET(&reason, PFRES_SYNPROXY);
			return (PF_SYNPROXY_DROP);
		}

		if (sk->app_state && sk->app_state->handler) {
			int offx = off;

			switch (pd->proto) {
			case IPPROTO_TCP:
				offx += th->th_off << 2;
				break;
			case IPPROTO_UDP:
				offx += pd->hdr.udp->uh_ulen << 2;
				break;
			default:
				/* ALG handlers only apply to TCP and UDP rules */
				break;
			}

			if (offx > off) {
				sk->app_state->handler(s, direction, offx,
				    pd, kif);
				if (pd->lmw < 0) {
					REASON_SET(&reason, PFRES_MEMORY);
					return (PF_DROP);
				}
				m = pd->mp;
			}
		}
	}

	/* copy back packet headers if we performed NAT operations */
	if (rewrite) {
		if (rewrite < off + hdrlen)
			rewrite = off + hdrlen;

		m = pf_lazy_makewritable(pd, pd->mp, rewrite);
		if (!m) {
			REASON_SET(&reason, PFRES_MEMORY);
			return (PF_DROP);
		}

		m_copyback(m, off, hdrlen, pd->hdr.any);
	}

	return (PF_PASS);
}

#if DUMMYNET
/*
 * When pf_test_dummynet() returns PF_PASS, the rule matching parameter "rm" 
 * remains unchanged, meaning the packet did not match a dummynet rule.
 * when the packet does match a dummynet rule, pf_test_dummynet() returns 
 * PF_PASS and zero out the mbuf rule as the packet is effectively siphoned 
 * out by dummynet.
 */
static int
pf_test_dummynet(struct pf_rule **rm, int direction, struct pfi_kif *kif, 
    struct mbuf **m0, struct pf_pdesc *pd, struct ip_fw_args *fwa)
{
	struct mbuf		*m = *m0;
	struct pf_rule		*am = NULL;
	struct pf_ruleset	*rsm = NULL;
	struct pf_addr		*saddr = pd->src, *daddr = pd->dst;
	sa_family_t		 af = pd->af;
	struct pf_rule		*r, *a = NULL;
	struct pf_ruleset	*ruleset = NULL;
	struct tcphdr		*th = pd->hdr.tcp;
	u_short			 reason;
	int			 hdrlen = 0;
	int			 tag = -1;
	unsigned int		 rtableid = IFSCOPE_NONE;
	int			 asd = 0;
	int			 match = 0;
	u_int8_t		 icmptype = 0, icmpcode = 0;
	struct ip_fw_args	dnflow;
	struct pf_rule		*prev_matching_rule = fwa ? fwa->fwa_pf_rule : NULL;
	int			found_prev_rule = (prev_matching_rule) ? 0 : 1;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if (!DUMMYNET_LOADED)
		return (PF_PASS);
	
	if (TAILQ_EMPTY(pf_main_ruleset.rules[PF_RULESET_DUMMYNET].active.ptr))
		return (PF_PASS);
	
	bzero(&dnflow, sizeof(dnflow));

	hdrlen = 0;

	/* Fragments don't gave protocol headers */
	if (!(pd->flags & PFDESC_IP_FRAG))	
		switch (pd->proto) {
		case IPPROTO_TCP:
			dnflow.fwa_id.flags = pd->hdr.tcp->th_flags;
			dnflow.fwa_id.dst_port = ntohs(pd->hdr.tcp->th_dport);
			dnflow.fwa_id.src_port = ntohs(pd->hdr.tcp->th_sport);
			hdrlen = sizeof (*th);
			break;
		case IPPROTO_UDP:
			dnflow.fwa_id.dst_port = ntohs(pd->hdr.udp->uh_dport);
			dnflow.fwa_id.src_port = ntohs(pd->hdr.udp->uh_sport);
			hdrlen = sizeof (*pd->hdr.udp);
			break;
#if INET
		case IPPROTO_ICMP:
			if (af != AF_INET)
				break;
			hdrlen = ICMP_MINLEN;
			icmptype = pd->hdr.icmp->icmp_type;
			icmpcode = pd->hdr.icmp->icmp_code;
			break;
#endif /* INET */
#if INET6
		case IPPROTO_ICMPV6:
			if (af != AF_INET6)
				break;
			hdrlen = sizeof (*pd->hdr.icmp6);
			icmptype = pd->hdr.icmp6->icmp6_type;
			icmpcode = pd->hdr.icmp6->icmp6_code;
			break;
#endif /* INET6 */
		case IPPROTO_GRE:
			if (pd->proto_variant == PF_GRE_PPTP_VARIANT)
				hdrlen = sizeof (*pd->hdr.grev1);
			break;
		case IPPROTO_ESP:
			hdrlen = sizeof (*pd->hdr.esp);
			break;
		}

	r = TAILQ_FIRST(pf_main_ruleset.rules[PF_RULESET_DUMMYNET].active.ptr);

	while (r != NULL) {
		r->evaluations++;
		if (pfi_kif_match(r->kif, kif) == r->ifnot)
			r = r->skip[PF_SKIP_IFP].ptr;
		else if (r->direction && r->direction != direction)
			r = r->skip[PF_SKIP_DIR].ptr;
		else if (r->af && r->af != af)
			r = r->skip[PF_SKIP_AF].ptr;
		else if (r->proto && r->proto != pd->proto)
			r = r->skip[PF_SKIP_PROTO].ptr;
		else if (PF_MISMATCHAW(&r->src.addr, saddr, af,
		    r->src.neg, kif))
			r = r->skip[PF_SKIP_SRC_ADDR].ptr;
		/* tcp/udp only. port_op always 0 in other cases */
		else if (r->proto == pd->proto && 
		    (r->proto == IPPROTO_TCP || r->proto == IPPROTO_UDP) &&
		    ((pd->flags & PFDESC_IP_FRAG) ||
		    ((r->src.xport.range.op &&
		    !pf_match_port(r->src.xport.range.op,
		    r->src.xport.range.port[0], r->src.xport.range.port[1],
		    th->th_sport)))))
			r = r->skip[PF_SKIP_SRC_PORT].ptr;
		else if (PF_MISMATCHAW(&r->dst.addr, daddr, af,
		    r->dst.neg, NULL))
			r = r->skip[PF_SKIP_DST_ADDR].ptr;
		/* tcp/udp only. port_op always 0 in other cases */
		else if (r->proto == pd->proto &&
		    (r->proto == IPPROTO_TCP || r->proto == IPPROTO_UDP) &&
		    r->dst.xport.range.op &&
		    ((pd->flags & PFDESC_IP_FRAG) ||
		    !pf_match_port(r->dst.xport.range.op,
		    r->dst.xport.range.port[0], r->dst.xport.range.port[1],
		    th->th_dport)))
			r = r->skip[PF_SKIP_DST_PORT].ptr;
		/* icmp only. type always 0 in other cases */
		else if (r->type && 
			((pd->flags & PFDESC_IP_FRAG) ||
			r->type != icmptype + 1))
			r = TAILQ_NEXT(r, entries);
		/* icmp only. type always 0 in other cases */
		else if (r->code && 
			((pd->flags & PFDESC_IP_FRAG) ||
			r->code != icmpcode + 1))
			r = TAILQ_NEXT(r, entries);
		else if (r->tos && !(r->tos == pd->tos))
			r = TAILQ_NEXT(r, entries);
		else if (r->rule_flag & PFRULE_FRAGMENT)
			r = TAILQ_NEXT(r, entries);
		else if (pd->proto == IPPROTO_TCP &&
		    ((pd->flags & PFDESC_IP_FRAG) ||
		    (r->flagset & th->th_flags) != r->flags))
			r = TAILQ_NEXT(r, entries);
		else if (r->prob && r->prob <= (RandomULong() % (UINT_MAX - 1) + 1))
			r = TAILQ_NEXT(r, entries);
		else if (r->match_tag && !pf_match_tag(m, r, pd->pf_mtag, &tag))
			r = TAILQ_NEXT(r, entries);
		else {
			/* 
			 * Need to go past the previous dummynet matching rule	
			 */
			if (r->anchor == NULL) {
				if (found_prev_rule) {
					if (r->tag)
						tag = r->tag;
					if (PF_RTABLEID_IS_VALID(r->rtableid))
						rtableid = r->rtableid;
					match = 1;
					*rm = r;
					am = a;
					rsm = ruleset;
					if ((*rm)->quick)
						break;
				} else if (r == prev_matching_rule) {
					found_prev_rule = 1;
				}
				r = TAILQ_NEXT(r, entries);
			} else {
				pf_step_into_anchor(&asd, &ruleset,
				    PF_RULESET_DUMMYNET, &r, &a, &match);
			}
		}
		if (r == NULL && pf_step_out_of_anchor(&asd, &ruleset,
		    PF_RULESET_DUMMYNET, &r, &a, &match))
			break;
	}
	r = *rm;
	a = am;
	ruleset = rsm;

	if (!match)
		return (PF_PASS);

	REASON_SET(&reason, PFRES_DUMMYNET);

	if (r->log) {
		PFLOG_PACKET(kif, h, m, af, direction, reason, r,
		    a, ruleset, pd);
	}

	if (r->action == PF_NODUMMYNET) {
		int dirndx = (direction == PF_OUT);
		
		r->packets[dirndx]++;
		r->bytes[dirndx] += pd->tot_len;

		return (PF_PASS);
	}
	if (pf_tag_packet(m, pd->pf_mtag, tag, rtableid, pd)) {
		REASON_SET(&reason, PFRES_MEMORY);

		return (PF_DROP);
	}

	if (r->dnpipe && ip_dn_io_ptr != NULL) {
		int dirndx = (direction == PF_OUT);
		
		r->packets[dirndx]++;
		r->bytes[dirndx] += pd->tot_len;
		
		dnflow.fwa_cookie = r->dnpipe;
		dnflow.fwa_pf_rule = r;
		dnflow.fwa_id.proto = pd->proto;
		dnflow.fwa_flags = r->dntype;
		switch (af) {
			case AF_INET:
				dnflow.fwa_id.addr_type = 4;
				dnflow.fwa_id.src_ip = ntohl(saddr->v4.s_addr);
				dnflow.fwa_id.dst_ip = ntohl(daddr->v4.s_addr);
				break;
			case AF_INET6:
				dnflow.fwa_id.addr_type = 6;
				dnflow.fwa_id.src_ip6 = saddr->v6;
				dnflow.fwa_id.dst_ip6 = saddr->v6;
				break;
			}

		if (fwa != NULL) {
			dnflow.fwa_oif = fwa->fwa_oif;
			dnflow.fwa_oflags = fwa->fwa_oflags;
			/*
			 * Note that fwa_ro, fwa_dst and fwa_ipoa are 
			 * actually in a union so the following does work  
			 * for both IPv4 and IPv6
			 */
			dnflow.fwa_ro = fwa->fwa_ro;
			dnflow.fwa_dst = fwa->fwa_dst;
			dnflow.fwa_ipoa = fwa->fwa_ipoa;
			dnflow.fwa_ro6_pmtu = fwa->fwa_ro6_pmtu;
			dnflow.fwa_origifp = fwa->fwa_origifp;
			dnflow.fwa_mtu = fwa->fwa_mtu;
			dnflow.fwa_alwaysfrag = fwa->fwa_alwaysfrag;
			dnflow.fwa_unfragpartlen = fwa->fwa_unfragpartlen;
			dnflow.fwa_exthdrs = fwa->fwa_exthdrs;
		}
		
		if (af == AF_INET) {
			struct ip *iphdr = mtod(m, struct ip *);
			NTOHS(iphdr->ip_len);
			NTOHS(iphdr->ip_off);
		}
		/* 
		 * Don't need to unlock pf_lock as NET_THREAD_HELD_PF 
		 * allows for recursive behavior
		 */
		ip_dn_io_ptr(m,
			dnflow.fwa_cookie,
			af == AF_INET ? 
				direction == PF_IN ? DN_TO_IP_IN : DN_TO_IP_OUT :
				direction == PF_IN ? DN_TO_IP6_IN : DN_TO_IP6_OUT,
			&dnflow, DN_CLIENT_PF);
		
		/*
		 * The packet is siphoned out by dummynet so return a NULL 
		 * mbuf so the caller can still return success.
		 */
		*m0 = NULL;
		 
		return (PF_PASS);
	}

	return (PF_PASS);
}
#endif /* DUMMYNET */

static int
pf_test_fragment(struct pf_rule **rm, int direction, struct pfi_kif *kif,
    struct mbuf *m, void *h, struct pf_pdesc *pd, struct pf_rule **am,
    struct pf_ruleset **rsm)
{
#pragma unused(h)
	struct pf_rule		*r, *a = NULL;
	struct pf_ruleset	*ruleset = NULL;
	sa_family_t		 af = pd->af;
	u_short			 reason;
	int			 tag = -1;
	int			 asd = 0;
	int			 match = 0;

	r = TAILQ_FIRST(pf_main_ruleset.rules[PF_RULESET_FILTER].active.ptr);
	while (r != NULL) {
		r->evaluations++;
		if (pfi_kif_match(r->kif, kif) == r->ifnot)
			r = r->skip[PF_SKIP_IFP].ptr;
		else if (r->direction && r->direction != direction)
			r = r->skip[PF_SKIP_DIR].ptr;
		else if (r->af && r->af != af)
			r = r->skip[PF_SKIP_AF].ptr;
		else if (r->proto && r->proto != pd->proto)
			r = r->skip[PF_SKIP_PROTO].ptr;
		else if (PF_MISMATCHAW(&r->src.addr, pd->src, af,
		    r->src.neg, kif))
			r = r->skip[PF_SKIP_SRC_ADDR].ptr;
		else if (PF_MISMATCHAW(&r->dst.addr, pd->dst, af,
		    r->dst.neg, NULL))
			r = r->skip[PF_SKIP_DST_ADDR].ptr;
                else if ((r->rule_flag & PFRULE_TOS) && r->tos &&
		    !(r->tos & pd->tos))
			r = TAILQ_NEXT(r, entries);
                else if ((r->rule_flag & PFRULE_DSCP) && r->tos &&
		    !(r->tos & (pd->tos & DSCP_MASK)))
			r = TAILQ_NEXT(r, entries);
                else if ((r->rule_flag & PFRULE_SC) && r->tos &&
		    ((r->tos & SCIDX_MASK) != pd->sc))
			r = TAILQ_NEXT(r, entries);
		else if (r->os_fingerprint != PF_OSFP_ANY)
			r = TAILQ_NEXT(r, entries);
		else if (pd->proto == IPPROTO_UDP &&
		    (r->src.xport.range.op || r->dst.xport.range.op))
			r = TAILQ_NEXT(r, entries);
		else if (pd->proto == IPPROTO_TCP &&
		    (r->src.xport.range.op || r->dst.xport.range.op ||
		    r->flagset))
			r = TAILQ_NEXT(r, entries);
		else if ((pd->proto == IPPROTO_ICMP ||
		    pd->proto == IPPROTO_ICMPV6) &&
		    (r->type || r->code))
			r = TAILQ_NEXT(r, entries);
		else if (r->prob && r->prob <= (RandomULong() % (UINT_MAX - 1) + 1))
			r = TAILQ_NEXT(r, entries);
		else if (r->match_tag && !pf_match_tag(m, r, pd->pf_mtag, &tag))
			r = TAILQ_NEXT(r, entries);
		else {
			if (r->anchor == NULL) {
				match = 1;
				*rm = r;
				*am = a;
				*rsm = ruleset;
				if ((*rm)->quick)
					break;
				r = TAILQ_NEXT(r, entries);
			} else
				pf_step_into_anchor(&asd, &ruleset,
				    PF_RULESET_FILTER, &r, &a, &match);
		}
		if (r == NULL && pf_step_out_of_anchor(&asd, &ruleset,
		    PF_RULESET_FILTER, &r, &a, &match))
			break;
	}
	r = *rm;
	a = *am;
	ruleset = *rsm;

	REASON_SET(&reason, PFRES_MATCH);

	if (r->log)
		PFLOG_PACKET(kif, h, m, af, direction, reason, r, a, ruleset,
		    pd);

	if (r->action != PF_PASS)
		return (PF_DROP);

	if (pf_tag_packet(m, pd->pf_mtag, tag, -1, NULL)) {
		REASON_SET(&reason, PFRES_MEMORY);
		return (PF_DROP);
	}

	return (PF_PASS);
}

static void
pf_pptp_handler(struct pf_state *s, int direction, int off,
    struct pf_pdesc *pd, struct pfi_kif *kif)
{
#pragma unused(direction)
	struct tcphdr *th;
	struct pf_pptp_state *pptps;
	struct pf_pptp_ctrl_msg cm;
	size_t plen;
	struct pf_state *gs;
	u_int16_t ct;
	u_int16_t *pac_call_id;
	u_int16_t *pns_call_id;
	u_int16_t *spoof_call_id;
	u_int8_t *pac_state;
	u_int8_t *pns_state;
	enum { PF_PPTP_PASS, PF_PPTP_INSERT_GRE, PF_PPTP_REMOVE_GRE } op;
	struct mbuf *m;
	struct pf_state_key *sk;
	struct pf_state_key *gsk;
	struct pf_app_state *gas;

	sk = s->state_key;
	pptps = &sk->app_state->u.pptp;
	gs = pptps->grev1_state;

	if (gs)
		gs->expire = pf_time_second();

	m = pd->mp;
	plen = min(sizeof (cm), m->m_pkthdr.len - off);
	if (plen < PF_PPTP_CTRL_MSG_MINSIZE)
		return;

	m_copydata(m, off, plen, &cm);

	if (ntohl(cm.hdr.magic) != PF_PPTP_MAGIC_NUMBER)
		return;
	if (ntohs(cm.hdr.type) != 1)
		return;

	if (!gs) {
		gs = pool_get(&pf_state_pl, PR_WAITOK);
		if (!gs)
			return;

		memcpy(gs, s, sizeof (*gs));

		memset(&gs->entry_id, 0, sizeof (gs->entry_id));
		memset(&gs->entry_list, 0, sizeof (gs->entry_list));

		TAILQ_INIT(&gs->unlink_hooks);
		gs->rt_kif = NULL;
		gs->creation = 0;
		gs->pfsync_time = 0;
		gs->packets[0] = gs->packets[1] = 0;
		gs->bytes[0] = gs->bytes[1] = 0;
		gs->timeout = PFTM_UNLINKED;
		gs->id = gs->creatorid = 0;
		gs->src.state = gs->dst.state = PFGRE1S_NO_TRAFFIC;
		gs->src.scrub = gs->dst.scrub = 0;

		gas = pool_get(&pf_app_state_pl, PR_NOWAIT);
		if (!gas) {
			pool_put(&pf_state_pl, gs);
			return;
		}

		gsk = pf_alloc_state_key(gs, NULL);
		if (!gsk) {
			pool_put(&pf_app_state_pl, gas);
			pool_put(&pf_state_pl, gs);
			return;
		}

		memcpy(&gsk->lan, &sk->lan, sizeof (gsk->lan));
		memcpy(&gsk->gwy, &sk->gwy, sizeof (gsk->gwy));
		memcpy(&gsk->ext, &sk->ext, sizeof (gsk->ext));
		gsk->af = sk->af;
		gsk->proto = IPPROTO_GRE;
		gsk->proto_variant = PF_GRE_PPTP_VARIANT;
		gsk->app_state = gas;
		gsk->lan.xport.call_id = 0;
		gsk->gwy.xport.call_id = 0;
		gsk->ext.xport.call_id = 0;
		gsk->flowsrc = FLOWSRC_PF;
		gsk->flowhash = pf_calc_state_key_flowhash(gsk);
		memset(gas, 0, sizeof (*gas));
		gas->u.grev1.pptp_state = s;
		STATE_INC_COUNTERS(gs);
		pptps->grev1_state = gs;
		(void) hook_establish(&gs->unlink_hooks, 0,
		    (hook_fn_t) pf_grev1_unlink, gs);
	} else {
		gsk = gs->state_key;
	}

	switch (sk->direction) {
	case PF_IN:
		pns_call_id = &gsk->ext.xport.call_id;
		pns_state = &gs->dst.state;
		pac_call_id = &gsk->lan.xport.call_id;
		pac_state = &gs->src.state;
		break;

	case PF_OUT:
		pns_call_id = &gsk->lan.xport.call_id;
		pns_state = &gs->src.state;
		pac_call_id = &gsk->ext.xport.call_id;
		pac_state = &gs->dst.state;
		break;

	default:
		DPFPRINTF(PF_DEBUG_URGENT,
		    ("pf_pptp_handler: bad directional!\n"));
		return;
	}

	spoof_call_id = 0;
	op = PF_PPTP_PASS;

	ct = ntohs(cm.ctrl.type);

	switch (ct) {
	case PF_PPTP_CTRL_TYPE_CALL_OUT_REQ:
		*pns_call_id = cm.msg.call_out_req.call_id;
		*pns_state = PFGRE1S_INITIATING;
		if (s->nat_rule.ptr && pns_call_id == &gsk->lan.xport.call_id)
			spoof_call_id = &cm.msg.call_out_req.call_id;
		break;

	case PF_PPTP_CTRL_TYPE_CALL_OUT_RPY:
		*pac_call_id = cm.msg.call_out_rpy.call_id;
		if (s->nat_rule.ptr)
			spoof_call_id =
			    (pac_call_id == &gsk->lan.xport.call_id) ?
			    &cm.msg.call_out_rpy.call_id :
			    &cm.msg.call_out_rpy.peer_call_id;
		if (gs->timeout == PFTM_UNLINKED) {
			*pac_state = PFGRE1S_INITIATING;
			op = PF_PPTP_INSERT_GRE;
		}
		break;

	case PF_PPTP_CTRL_TYPE_CALL_IN_1ST:
		*pns_call_id = cm.msg.call_in_1st.call_id;
		*pns_state = PFGRE1S_INITIATING;
		if (s->nat_rule.ptr && pns_call_id == &gsk->lan.xport.call_id)
			spoof_call_id = &cm.msg.call_in_1st.call_id;
		break;

	case PF_PPTP_CTRL_TYPE_CALL_IN_2ND:
		*pac_call_id = cm.msg.call_in_2nd.call_id;
		*pac_state = PFGRE1S_INITIATING;
		if (s->nat_rule.ptr)
			spoof_call_id =
			    (pac_call_id == &gsk->lan.xport.call_id) ?
			    &cm.msg.call_in_2nd.call_id :
			    &cm.msg.call_in_2nd.peer_call_id;
		break;

	case PF_PPTP_CTRL_TYPE_CALL_IN_3RD:
		if (s->nat_rule.ptr && pns_call_id == &gsk->lan.xport.call_id)
			spoof_call_id = &cm.msg.call_in_3rd.call_id;
		if (cm.msg.call_in_3rd.call_id != *pns_call_id) {
			break;
		}
		if (gs->timeout == PFTM_UNLINKED)
			op = PF_PPTP_INSERT_GRE;
		break;

	case PF_PPTP_CTRL_TYPE_CALL_CLR:
		if (cm.msg.call_clr.call_id != *pns_call_id)
			op = PF_PPTP_REMOVE_GRE;
		break;

	case PF_PPTP_CTRL_TYPE_CALL_DISC:
		if (cm.msg.call_clr.call_id != *pac_call_id)
			op = PF_PPTP_REMOVE_GRE;
		break;

	case PF_PPTP_CTRL_TYPE_ERROR:
		if (s->nat_rule.ptr && pns_call_id == &gsk->lan.xport.call_id)
			spoof_call_id = &cm.msg.error.peer_call_id;
		break;

	case PF_PPTP_CTRL_TYPE_SET_LINKINFO:
		if (s->nat_rule.ptr && pac_call_id == &gsk->lan.xport.call_id)
			spoof_call_id = &cm.msg.set_linkinfo.peer_call_id;
		break;

	default:
		op = PF_PPTP_PASS;
		break;
	}

	if (!gsk->gwy.xport.call_id && gsk->lan.xport.call_id) {
		gsk->gwy.xport.call_id = gsk->lan.xport.call_id;
		if (spoof_call_id) {
			u_int16_t call_id = 0;
			int n = 0;
			struct pf_state_key_cmp key;

			key.af = gsk->af;
			key.proto = IPPROTO_GRE;
			key.proto_variant = PF_GRE_PPTP_VARIANT;
			PF_ACPY(&key.gwy.addr, &gsk->gwy.addr, key.af);
			PF_ACPY(&key.ext.addr, &gsk->ext.addr, key.af);
			key.gwy.xport.call_id = gsk->gwy.xport.call_id;
			key.ext.xport.call_id = gsk->ext.xport.call_id;
			do {
				call_id = htonl(random());
			} while (!call_id);

			while (pf_find_state_all(&key, PF_IN, 0)) {
				call_id = ntohs(call_id);
				--call_id;
				if (--call_id == 0) call_id = 0xffff;
				call_id = htons(call_id);

				key.gwy.xport.call_id = call_id;

				if (++n > 65535) {
					DPFPRINTF(PF_DEBUG_URGENT,
					    ("pf_pptp_handler: failed to spoof "
					    "call id\n"));
					key.gwy.xport.call_id = 0;
					break;
				}
			}

			gsk->gwy.xport.call_id = call_id;
		}
	}

	th = pd->hdr.tcp;

	if (spoof_call_id && gsk->lan.xport.call_id != gsk->gwy.xport.call_id) {
		if (*spoof_call_id == gsk->gwy.xport.call_id) {
			*spoof_call_id = gsk->lan.xport.call_id;
			th->th_sum = pf_cksum_fixup(th->th_sum,
			    gsk->gwy.xport.call_id, gsk->lan.xport.call_id, 0);
		} else {
			*spoof_call_id = gsk->gwy.xport.call_id;
			th->th_sum = pf_cksum_fixup(th->th_sum,
			    gsk->lan.xport.call_id, gsk->gwy.xport.call_id, 0);
		}

		m = pf_lazy_makewritable(pd, m, off + plen);
		if (!m) {
			pptps->grev1_state = NULL;
			STATE_DEC_COUNTERS(gs);
			pool_put(&pf_state_pl, gs);
			return;
		}
		m_copyback(m, off, plen, &cm);
	}

	switch (op) {
	case PF_PPTP_REMOVE_GRE:
		gs->timeout = PFTM_PURGE;
		gs->src.state = gs->dst.state = PFGRE1S_NO_TRAFFIC;
		gsk->lan.xport.call_id = 0;
		gsk->gwy.xport.call_id = 0;
		gsk->ext.xport.call_id = 0;
		gs->id = gs->creatorid = 0;
		break;

	case PF_PPTP_INSERT_GRE:
		gs->creation = pf_time_second();
		gs->expire = pf_time_second();
		gs->timeout = PFTM_TCP_ESTABLISHED;
		if (gs->src_node != NULL) {
			++gs->src_node->states;
			VERIFY(gs->src_node->states != 0);
		}
		if (gs->nat_src_node != NULL) {
			++gs->nat_src_node->states;
			VERIFY(gs->nat_src_node->states != 0);
		}
		pf_set_rt_ifp(gs, &sk->lan.addr);
		if (pf_insert_state(BOUND_IFACE(s->rule.ptr, kif), gs)) {

			/*
			 * <jhw@apple.com>
			 * FIX ME: insertion can fail when multiple PNS
			 * behind the same NAT open calls to the same PAC
			 * simultaneously because spoofed call ID numbers
			 * are chosen before states are inserted.  This is
			 * hard to fix and happens infrequently enough that
			 * users will normally try again and this ALG will
			 * succeed.  Failures are expected to be rare enough
			 * that fixing this is a low priority.
			 */
			pptps->grev1_state = NULL;
			pd->lmw = -1;	/* Force PF_DROP on PFRES_MEMORY */
			pf_src_tree_remove_state(gs);
			STATE_DEC_COUNTERS(gs);
			pool_put(&pf_state_pl, gs);
			DPFPRINTF(PF_DEBUG_URGENT, ("pf_pptp_handler: error "
			    "inserting GREv1 state.\n"));
		}
		break;

	default:
		break;
	}
}

static void
pf_pptp_unlink(struct pf_state *s)
{
	struct pf_app_state *as = s->state_key->app_state;
	struct pf_state *grev1s = as->u.pptp.grev1_state;

	if (grev1s) {
		struct pf_app_state *gas = grev1s->state_key->app_state;

		if (grev1s->timeout < PFTM_MAX)
			grev1s->timeout = PFTM_PURGE;
		gas->u.grev1.pptp_state = NULL;
		as->u.pptp.grev1_state = NULL;
	}
}

static void
pf_grev1_unlink(struct pf_state *s)
{
	struct pf_app_state *as = s->state_key->app_state;
	struct pf_state *pptps = as->u.grev1.pptp_state;

	if (pptps) {
		struct pf_app_state *pas = pptps->state_key->app_state;

		pas->u.pptp.grev1_state = NULL;
		as->u.grev1.pptp_state = NULL;
	}
}

static int
pf_ike_compare(struct pf_app_state *a, struct pf_app_state *b)
{
	int64_t d = a->u.ike.cookie - b->u.ike.cookie;
	return ((d > 0) ? 1 : ((d < 0) ? -1 : 0));
}

static int
pf_test_state_tcp(struct pf_state **state, int direction, struct pfi_kif *kif,
    struct mbuf *m, int off, void *h, struct pf_pdesc *pd,
    u_short *reason)
{
#pragma unused(h)
	struct pf_state_key_cmp	 key;
	struct tcphdr		*th = pd->hdr.tcp;
	u_int16_t		 win = ntohs(th->th_win);
	u_int32_t		 ack, end, seq, orig_seq;
	u_int8_t		 sws, dws;
	int			 ackskew;
	int			 copyback = 0;
	struct pf_state_peer	*src, *dst;

	key.app_state = 0;
	key.af = pd->af;
	key.proto = IPPROTO_TCP;
	if (direction == PF_IN)	{
		PF_ACPY(&key.ext.addr, pd->src, key.af);
		PF_ACPY(&key.gwy.addr, pd->dst, key.af);
		key.ext.xport.port = th->th_sport;
		key.gwy.xport.port = th->th_dport;
	} else {
		PF_ACPY(&key.lan.addr, pd->src, key.af);
		PF_ACPY(&key.ext.addr, pd->dst, key.af);
		key.lan.xport.port = th->th_sport;
		key.ext.xport.port = th->th_dport;
	}

	STATE_LOOKUP();

	if (direction == (*state)->state_key->direction) {
		src = &(*state)->src;
		dst = &(*state)->dst;
	} else {
		src = &(*state)->dst;
		dst = &(*state)->src;
	}

	if ((*state)->src.state == PF_TCPS_PROXY_SRC) {
		if (direction != (*state)->state_key->direction) {
			REASON_SET(reason, PFRES_SYNPROXY);
			return (PF_SYNPROXY_DROP);
		}
		if (th->th_flags & TH_SYN) {
			if (ntohl(th->th_seq) != (*state)->src.seqlo) {
				REASON_SET(reason, PFRES_SYNPROXY);
				return (PF_DROP);
			}
			pf_send_tcp((*state)->rule.ptr, pd->af, pd->dst,
			    pd->src, th->th_dport, th->th_sport,
			    (*state)->src.seqhi, ntohl(th->th_seq) + 1,
			    TH_SYN|TH_ACK, 0, (*state)->src.mss, 0, 1,
			    0, NULL, NULL);
			REASON_SET(reason, PFRES_SYNPROXY);
			return (PF_SYNPROXY_DROP);
		} else if (!(th->th_flags & TH_ACK) ||
		    (ntohl(th->th_ack) != (*state)->src.seqhi + 1) ||
		    (ntohl(th->th_seq) != (*state)->src.seqlo + 1)) {
			REASON_SET(reason, PFRES_SYNPROXY);
			return (PF_DROP);
		} else if ((*state)->src_node != NULL &&
		    pf_src_connlimit(state)) {
			REASON_SET(reason, PFRES_SRCLIMIT);
			return (PF_DROP);
		} else
			(*state)->src.state = PF_TCPS_PROXY_DST;
	}
	if ((*state)->src.state == PF_TCPS_PROXY_DST) {
		struct pf_state_host *psrc, *pdst;

		if (direction == PF_OUT) {
			psrc = &(*state)->state_key->gwy;
			pdst = &(*state)->state_key->ext;
		} else {
			psrc = &(*state)->state_key->ext;
			pdst = &(*state)->state_key->lan;
		}
		if (direction == (*state)->state_key->direction) {
			if (((th->th_flags & (TH_SYN|TH_ACK)) != TH_ACK) ||
			    (ntohl(th->th_ack) != (*state)->src.seqhi + 1) ||
			    (ntohl(th->th_seq) != (*state)->src.seqlo + 1)) {
				REASON_SET(reason, PFRES_SYNPROXY);
				return (PF_DROP);
			}
			(*state)->src.max_win = MAX(ntohs(th->th_win), 1);
			if ((*state)->dst.seqhi == 1)
				(*state)->dst.seqhi = htonl(random());
			pf_send_tcp((*state)->rule.ptr, pd->af, &psrc->addr,
			    &pdst->addr, psrc->xport.port, pdst->xport.port,
			    (*state)->dst.seqhi, 0, TH_SYN, 0,
			    (*state)->src.mss, 0, 0, (*state)->tag, NULL, NULL);
			REASON_SET(reason, PFRES_SYNPROXY);
			return (PF_SYNPROXY_DROP);
		} else if (((th->th_flags & (TH_SYN|TH_ACK)) !=
		    (TH_SYN|TH_ACK)) ||
		    (ntohl(th->th_ack) != (*state)->dst.seqhi + 1)) {
			REASON_SET(reason, PFRES_SYNPROXY);
			return (PF_DROP);
		} else {
			(*state)->dst.max_win = MAX(ntohs(th->th_win), 1);
			(*state)->dst.seqlo = ntohl(th->th_seq);
			pf_send_tcp((*state)->rule.ptr, pd->af, pd->dst,
			    pd->src, th->th_dport, th->th_sport,
			    ntohl(th->th_ack), ntohl(th->th_seq) + 1,
			    TH_ACK, (*state)->src.max_win, 0, 0, 0,
			    (*state)->tag, NULL, NULL);
			pf_send_tcp((*state)->rule.ptr, pd->af, &psrc->addr,
			    &pdst->addr, psrc->xport.port, pdst->xport.port,
			    (*state)->src.seqhi + 1, (*state)->src.seqlo + 1,
			    TH_ACK, (*state)->dst.max_win, 0, 0, 1,
			    0, NULL, NULL);
			(*state)->src.seqdiff = (*state)->dst.seqhi -
			    (*state)->src.seqlo;
			(*state)->dst.seqdiff = (*state)->src.seqhi -
			    (*state)->dst.seqlo;
			(*state)->src.seqhi = (*state)->src.seqlo +
			    (*state)->dst.max_win;
			(*state)->dst.seqhi = (*state)->dst.seqlo +
			    (*state)->src.max_win;
			(*state)->src.wscale = (*state)->dst.wscale = 0;
			(*state)->src.state = (*state)->dst.state =
			    TCPS_ESTABLISHED;
			REASON_SET(reason, PFRES_SYNPROXY);
			return (PF_SYNPROXY_DROP);
		}
	}

	if (((th->th_flags & (TH_SYN|TH_ACK)) == TH_SYN) &&
	    dst->state >= TCPS_FIN_WAIT_2 &&
	    src->state >= TCPS_FIN_WAIT_2) {
		if (pf_status.debug >= PF_DEBUG_MISC) {
			printf("pf: state reuse ");
			pf_print_state(*state);
			pf_print_flags(th->th_flags);
			printf("\n");
		}
		/* XXX make sure it's the same direction ?? */
		(*state)->src.state = (*state)->dst.state = TCPS_CLOSED;
		pf_unlink_state(*state);
		*state = NULL;
		return (PF_DROP);
	}

	if ((th->th_flags & TH_SYN) == 0) {
		sws = (src->wscale & PF_WSCALE_FLAG) ?
		    (src->wscale & PF_WSCALE_MASK) : TCP_MAX_WINSHIFT;
		dws = (dst->wscale & PF_WSCALE_FLAG) ?
		    (dst->wscale & PF_WSCALE_MASK) : TCP_MAX_WINSHIFT;
	}
	else
		sws = dws = 0;

	/*
	 * Sequence tracking algorithm from Guido van Rooij's paper:
	 *   http://www.madison-gurkha.com/publications/tcp_filtering/
	 *	tcp_filtering.ps
	 */

	orig_seq = seq = ntohl(th->th_seq);
	if (src->seqlo == 0) {
		/* First packet from this end. Set its state */

		if ((pd->flags & PFDESC_TCP_NORM || dst->scrub) &&
		    src->scrub == NULL) {
			if (pf_normalize_tcp_init(m, off, pd, th, src, dst)) {
				REASON_SET(reason, PFRES_MEMORY);
				return (PF_DROP);
			}
		}

		/* Deferred generation of sequence number modulator */
		if (dst->seqdiff && !src->seqdiff) {
			/* use random iss for the TCP server */
			while ((src->seqdiff = random() - seq) == 0)
				;
			ack = ntohl(th->th_ack) - dst->seqdiff;
			pf_change_a(&th->th_seq, &th->th_sum, htonl(seq +
			    src->seqdiff), 0);
			pf_change_a(&th->th_ack, &th->th_sum, htonl(ack), 0);
			copyback = off + sizeof (*th);
		} else {
			ack = ntohl(th->th_ack);
		}

		end = seq + pd->p_len;
		if (th->th_flags & TH_SYN) {
			end++;
			if (dst->wscale & PF_WSCALE_FLAG) {
				src->wscale = pf_get_wscale(m, off, th->th_off,
				    pd->af);
				if (src->wscale & PF_WSCALE_FLAG) {
					/*
					 * Remove scale factor from initial
					 * window
					 */
					sws = src->wscale & PF_WSCALE_MASK;
					win = ((u_int32_t)win + (1 << sws) - 1)
					    >> sws;
					dws = dst->wscale & PF_WSCALE_MASK;
				} else {
					/*
					 * Window scale negotiation has failed,
					 * therefore we must restore the window
					 * scale in the state record that we
					 * optimistically removed in
					 * pf_test_rule().  Care is required to
					 * prevent arithmetic overflow from
					 * zeroing the window when it's
					 * truncated down to 16-bits.
					 */
					u_int32_t max_win = dst->max_win;
					max_win <<=
					    dst->wscale & PF_WSCALE_MASK;
					dst->max_win = MIN(0xffff, max_win);
					/* in case of a retrans SYN|ACK */
					dst->wscale = 0;
				}
			}
		}
		if (th->th_flags & TH_FIN)
			end++;

		src->seqlo = seq;
		if (src->state < TCPS_SYN_SENT)
			src->state = TCPS_SYN_SENT;

		/*
		 * May need to slide the window (seqhi may have been set by
		 * the crappy stack check or if we picked up the connection
		 * after establishment)
		 */
		if (src->seqhi == 1 ||
		    SEQ_GEQ(end + MAX(1, (u_int32_t)dst->max_win << dws),
		    src->seqhi))
			src->seqhi = end + MAX(1, (u_int32_t)dst->max_win << dws);
		if (win > src->max_win)
			src->max_win = win;

	} else {
		ack = ntohl(th->th_ack) - dst->seqdiff;
		if (src->seqdiff) {
			/* Modulate sequence numbers */
			pf_change_a(&th->th_seq, &th->th_sum, htonl(seq +
			    src->seqdiff), 0);
			pf_change_a(&th->th_ack, &th->th_sum, htonl(ack), 0);
			copyback = off+ sizeof (*th);
		}
		end = seq + pd->p_len;
		if (th->th_flags & TH_SYN)
			end++;
		if (th->th_flags & TH_FIN)
			end++;
	}

	if ((th->th_flags & TH_ACK) == 0) {
		/* Let it pass through the ack skew check */
		ack = dst->seqlo;
	} else if ((ack == 0 &&
	    (th->th_flags & (TH_ACK|TH_RST)) == (TH_ACK|TH_RST)) ||
	    /* broken tcp stacks do not set ack */
	    (dst->state < TCPS_SYN_SENT)) {
		/*
		 * Many stacks (ours included) will set the ACK number in an
		 * FIN|ACK if the SYN times out -- no sequence to ACK.
		 */
		ack = dst->seqlo;
	}

	if (seq == end) {
		/* Ease sequencing restrictions on no data packets */
		seq = src->seqlo;
		end = seq;
	}

	ackskew = dst->seqlo - ack;


	/*
	 * Need to demodulate the sequence numbers in any TCP SACK options
	 * (Selective ACK). We could optionally validate the SACK values
	 * against the current ACK window, either forwards or backwards, but
	 * I'm not confident that SACK has been implemented properly
	 * everywhere. It wouldn't surprise me if several stacks accidently
	 * SACK too far backwards of previously ACKed data. There really aren't
	 * any security implications of bad SACKing unless the target stack
	 * doesn't validate the option length correctly. Someone trying to
	 * spoof into a TCP connection won't bother blindly sending SACK
	 * options anyway.
	 */
	if (dst->seqdiff && (th->th_off << 2) > (int)sizeof (struct tcphdr)) {
		copyback = pf_modulate_sack(m, off, pd, th, dst);
		if (copyback == -1) {
			REASON_SET(reason, PFRES_MEMORY);
			return (PF_DROP);
		}

		m = pd->mp;
	}


#define MAXACKWINDOW (0xffff + 1500)	/* 1500 is an arbitrary fudge factor */
	if (SEQ_GEQ(src->seqhi, end) &&
	    /* Last octet inside other's window space */
	    SEQ_GEQ(seq, src->seqlo - ((u_int32_t)dst->max_win << dws)) &&
	    /* Retrans: not more than one window back */
	    (ackskew >= -MAXACKWINDOW) &&
	    /* Acking not more than one reassembled fragment backwards */
	    (ackskew <= (MAXACKWINDOW << sws)) &&
	    /* Acking not more than one window forward */
	    ((th->th_flags & TH_RST) == 0 || orig_seq == src->seqlo ||
	    (orig_seq == src->seqlo + 1) || (orig_seq + 1 == src->seqlo) ||
	    (pd->flags & PFDESC_IP_REAS) == 0)) {
	    /* Require an exact/+1 sequence match on resets when possible */

		if (dst->scrub || src->scrub) {
			if (pf_normalize_tcp_stateful(m, off, pd, reason, th,
			    *state, src, dst, &copyback))
				return (PF_DROP);

			m = pd->mp;
		}

		/* update max window */
		if (src->max_win < win)
			src->max_win = win;
		/* synchronize sequencing */
		if (SEQ_GT(end, src->seqlo))
			src->seqlo = end;
		/* slide the window of what the other end can send */
		if (SEQ_GEQ(ack + ((u_int32_t)win << sws), dst->seqhi))
			dst->seqhi = ack + MAX(((u_int32_t)win << sws), 1);

		/* update states */
		if (th->th_flags & TH_SYN)
			if (src->state < TCPS_SYN_SENT)
				src->state = TCPS_SYN_SENT;
		if (th->th_flags & TH_FIN)
			if (src->state < TCPS_CLOSING)
				src->state = TCPS_CLOSING;
		if (th->th_flags & TH_ACK) {
			if (dst->state == TCPS_SYN_SENT) {
				dst->state = TCPS_ESTABLISHED;
				if (src->state == TCPS_ESTABLISHED &&
				    (*state)->src_node != NULL &&
				    pf_src_connlimit(state)) {
					REASON_SET(reason, PFRES_SRCLIMIT);
					return (PF_DROP);
				}
			} else if (dst->state == TCPS_CLOSING)
				dst->state = TCPS_FIN_WAIT_2;
		}
		if (th->th_flags & TH_RST)
			src->state = dst->state = TCPS_TIME_WAIT;

		/* update expire time */
		(*state)->expire = pf_time_second();
		if (src->state >= TCPS_FIN_WAIT_2 &&
		    dst->state >= TCPS_FIN_WAIT_2)
			(*state)->timeout = PFTM_TCP_CLOSED;
		else if (src->state >= TCPS_CLOSING &&
		    dst->state >= TCPS_CLOSING)
			(*state)->timeout = PFTM_TCP_FIN_WAIT;
		else if (src->state < TCPS_ESTABLISHED ||
		    dst->state < TCPS_ESTABLISHED)
			(*state)->timeout = PFTM_TCP_OPENING;
		else if (src->state >= TCPS_CLOSING ||
		    dst->state >= TCPS_CLOSING)
			(*state)->timeout = PFTM_TCP_CLOSING;
		else
			(*state)->timeout = PFTM_TCP_ESTABLISHED;

		/* Fall through to PASS packet */

	} else if ((dst->state < TCPS_SYN_SENT ||
	    dst->state >= TCPS_FIN_WAIT_2 || src->state >= TCPS_FIN_WAIT_2) &&
	    SEQ_GEQ(src->seqhi + MAXACKWINDOW, end) &&
	    /* Within a window forward of the originating packet */
	    SEQ_GEQ(seq, src->seqlo - MAXACKWINDOW)) {
	    /* Within a window backward of the originating packet */

		/*
		 * This currently handles three situations:
		 *  1) Stupid stacks will shotgun SYNs before their peer
		 *     replies.
		 *  2) When PF catches an already established stream (the
		 *     firewall rebooted, the state table was flushed, routes
		 *     changed...)
		 *  3) Packets get funky immediately after the connection
		 *     closes (this should catch Solaris spurious ACK|FINs
		 *     that web servers like to spew after a close)
		 *
		 * This must be a little more careful than the above code
		 * since packet floods will also be caught here. We don't
		 * update the TTL here to mitigate the damage of a packet
		 * flood and so the same code can handle awkward establishment
		 * and a loosened connection close.
		 * In the establishment case, a correct peer response will
		 * validate the connection, go through the normal state code
		 * and keep updating the state TTL.
		 */

		if (pf_status.debug >= PF_DEBUG_MISC) {
			printf("pf: loose state match: ");
			pf_print_state(*state);
			pf_print_flags(th->th_flags);
			printf(" seq=%u (%u) ack=%u len=%u ackskew=%d "
			    "pkts=%llu:%llu dir=%s,%s\n", seq, orig_seq, ack,
			    pd->p_len, ackskew, (*state)->packets[0],
			    (*state)->packets[1],
			    direction == PF_IN ? "in" : "out",
			    direction == (*state)->state_key->direction ?
			    "fwd" : "rev");
		}

		if (dst->scrub || src->scrub) {
			if (pf_normalize_tcp_stateful(m, off, pd, reason, th,
			    *state, src, dst, &copyback))
				return (PF_DROP);
			m = pd->mp;
		}

		/* update max window */
		if (src->max_win < win)
			src->max_win = win;
		/* synchronize sequencing */
		if (SEQ_GT(end, src->seqlo))
			src->seqlo = end;
		/* slide the window of what the other end can send */
		if (SEQ_GEQ(ack + ((u_int32_t)win << sws), dst->seqhi))
			dst->seqhi = ack + MAX(((u_int32_t)win << sws), 1);

		/*
		 * Cannot set dst->seqhi here since this could be a shotgunned
		 * SYN and not an already established connection.
		 */

		if (th->th_flags & TH_FIN)
			if (src->state < TCPS_CLOSING)
				src->state = TCPS_CLOSING;
		if (th->th_flags & TH_RST)
			src->state = dst->state = TCPS_TIME_WAIT;

		/* Fall through to PASS packet */

	} else {
		if ((*state)->dst.state == TCPS_SYN_SENT &&
		    (*state)->src.state == TCPS_SYN_SENT) {
			/* Send RST for state mismatches during handshake */
			if (!(th->th_flags & TH_RST))
				pf_send_tcp((*state)->rule.ptr, pd->af,
				    pd->dst, pd->src, th->th_dport,
				    th->th_sport, ntohl(th->th_ack), 0,
				    TH_RST, 0, 0,
				    (*state)->rule.ptr->return_ttl, 1, 0,
				    pd->eh, kif->pfik_ifp);
			src->seqlo = 0;
			src->seqhi = 1;
			src->max_win = 1;
		} else if (pf_status.debug >= PF_DEBUG_MISC) {
			printf("pf: BAD state: ");
			pf_print_state(*state);
			pf_print_flags(th->th_flags);
			printf("\n   seq=%u (%u) ack=%u len=%u ackskew=%d "
			    "sws=%u dws=%u pkts=%llu:%llu dir=%s,%s\n",
			    seq, orig_seq, ack, pd->p_len, ackskew,
			    (unsigned int)sws, (unsigned int)dws,
			    (*state)->packets[0], (*state)->packets[1],
			    direction == PF_IN ? "in" : "out",
			    direction == (*state)->state_key->direction ?
			    "fwd" : "rev");
			printf("pf: State failure on: %c %c %c %c | %c %c\n",
			    SEQ_GEQ(src->seqhi, end) ? ' ' : '1',
			    SEQ_GEQ(seq,
			    src->seqlo - ((u_int32_t)dst->max_win << dws)) ?
			    ' ': '2',
			    (ackskew >= -MAXACKWINDOW) ? ' ' : '3',
			    (ackskew <= (MAXACKWINDOW << sws)) ? ' ' : '4',
			    SEQ_GEQ(src->seqhi + MAXACKWINDOW, end) ?' ' :'5',
			    SEQ_GEQ(seq, src->seqlo - MAXACKWINDOW) ?' ' :'6');
		}
		REASON_SET(reason, PFRES_BADSTATE);
		return (PF_DROP);
	}

	/* Any packets which have gotten here are to be passed */

	if ((*state)->state_key->app_state &&
	    (*state)->state_key->app_state->handler) {
		(*state)->state_key->app_state->handler(*state, direction,
		    off + (th->th_off << 2), pd, kif);
		if (pd->lmw < 0) {
			REASON_SET(reason, PFRES_MEMORY);
			return (PF_DROP);
		}
		m = pd->mp;
	}

	/* translate source/destination address, if necessary */
	if (STATE_TRANSLATE((*state)->state_key)) {
		if (direction == PF_OUT)
			pf_change_ap(direction, pd->mp, pd->src, &th->th_sport,
			    pd->ip_sum, &th->th_sum,
			    &(*state)->state_key->gwy.addr,
			    (*state)->state_key->gwy.xport.port, 0, pd->af);
		else
			pf_change_ap(direction, pd->mp, pd->dst, &th->th_dport,
			    pd->ip_sum, &th->th_sum,
			    &(*state)->state_key->lan.addr,
			    (*state)->state_key->lan.xport.port, 0, pd->af);
		copyback = off + sizeof (*th);
	}

	if (copyback) {
		m = pf_lazy_makewritable(pd, m, copyback);
		if (!m) {
			REASON_SET(reason, PFRES_MEMORY);
			return (PF_DROP);
		}

		/* Copyback sequence modulation or stateful scrub changes */
		m_copyback(m, off, sizeof (*th), th);
	}

	return (PF_PASS);
}

static int
pf_test_state_udp(struct pf_state **state, int direction, struct pfi_kif *kif,
    struct mbuf *m, int off, void *h, struct pf_pdesc *pd, u_short *reason)
{
#pragma unused(h)
	struct pf_state_peer	*src, *dst;
	struct pf_state_key_cmp	 key;
	struct udphdr		*uh = pd->hdr.udp;
	struct pf_app_state as;
	int dx, action, extfilter;
	key.app_state = 0;
	key.proto_variant = PF_EXTFILTER_APD;

	key.af = pd->af;
	key.proto = IPPROTO_UDP;
	if (direction == PF_IN)	{
		PF_ACPY(&key.ext.addr, pd->src, key.af);
		PF_ACPY(&key.gwy.addr, pd->dst, key.af);
		key.ext.xport.port = uh->uh_sport;
		key.gwy.xport.port = uh->uh_dport;
		dx = PF_IN;
	} else {
		PF_ACPY(&key.lan.addr, pd->src, key.af);
		PF_ACPY(&key.ext.addr, pd->dst, key.af);
		key.lan.xport.port = uh->uh_sport;
		key.ext.xport.port = uh->uh_dport;
		dx = PF_OUT;
	}

	if (ntohs(uh->uh_sport) == PF_IKE_PORT &&
	    ntohs(uh->uh_dport) == PF_IKE_PORT) {
		struct pf_ike_hdr ike;
		size_t plen = m->m_pkthdr.len - off - sizeof (*uh);
		if (plen < PF_IKE_PACKET_MINSIZE) {
			DPFPRINTF(PF_DEBUG_MISC,
			    ("pf: IKE message too small.\n"));
			return (PF_DROP);
		}

		if (plen > sizeof (ike))
			plen = sizeof (ike);
		m_copydata(m, off + sizeof (*uh), plen, &ike);

		if (ike.initiator_cookie) {
			key.app_state = &as;
			as.compare_lan_ext = pf_ike_compare;
			as.compare_ext_gwy = pf_ike_compare;
			as.u.ike.cookie = ike.initiator_cookie;
		} else {
			/*
			 * <http://tools.ietf.org/html/\
			 *    draft-ietf-ipsec-nat-t-ike-01>
			 * Support non-standard NAT-T implementations that
			 * push the ESP packet over the top of the IKE packet.
			 * Do not drop packet.
			 */
			DPFPRINTF(PF_DEBUG_MISC,
			    ("pf: IKE initiator cookie = 0.\n"));
		}
	}

	*state = pf_find_state(kif, &key, dx);

	if (!key.app_state && *state == 0) {
		key.proto_variant = PF_EXTFILTER_AD;
		*state = pf_find_state(kif, &key, dx);
	}

	if (!key.app_state && *state == 0) {
		key.proto_variant = PF_EXTFILTER_EI;
		*state = pf_find_state(kif, &key, dx);
	}

	/* similar to STATE_LOOKUP() */
	if (*state != NULL && pd != NULL && !(pd->pktflags & PKTF_FLOW_ID)) {
		pd->flowsrc = (*state)->state_key->flowsrc;
		pd->flowhash = (*state)->state_key->flowhash;
		if (pd->flowhash != 0) {
			pd->pktflags |= PKTF_FLOW_ID;
			pd->pktflags &= ~PKTF_FLOW_ADV;
		}
	}

	if (pf_state_lookup_aux(state, kif, direction, &action))
		return (action);

	if (direction == (*state)->state_key->direction) {
		src = &(*state)->src;
		dst = &(*state)->dst;
	} else {
		src = &(*state)->dst;
		dst = &(*state)->src;
	}

	/* update states */
	if (src->state < PFUDPS_SINGLE)
		src->state = PFUDPS_SINGLE;
	if (dst->state == PFUDPS_SINGLE)
		dst->state = PFUDPS_MULTIPLE;

	/* update expire time */
	(*state)->expire = pf_time_second();
	if (src->state == PFUDPS_MULTIPLE && dst->state == PFUDPS_MULTIPLE)
		(*state)->timeout = PFTM_UDP_MULTIPLE;
	else
		(*state)->timeout = PFTM_UDP_SINGLE;

	extfilter = (*state)->state_key->proto_variant;
	if (extfilter > PF_EXTFILTER_APD) {
		(*state)->state_key->ext.xport.port = key.ext.xport.port;
		if (extfilter > PF_EXTFILTER_AD)
			PF_ACPY(&(*state)->state_key->ext.addr,
			    &key.ext.addr, key.af);
	}

	if ((*state)->state_key->app_state &&
	    (*state)->state_key->app_state->handler) {
		(*state)->state_key->app_state->handler(*state, direction,
		    off + uh->uh_ulen, pd, kif);
		if (pd->lmw < 0) {
			REASON_SET(reason, PFRES_MEMORY);
			return (PF_DROP);
		}
		m = pd->mp;
	}

	/* translate source/destination address, if necessary */
	if (STATE_TRANSLATE((*state)->state_key)) {
		m = pf_lazy_makewritable(pd, m, off + sizeof (*uh));
		if (!m) {
			REASON_SET(reason, PFRES_MEMORY);
			return (PF_DROP);
		}

		if (direction == PF_OUT)
			pf_change_ap(direction, pd->mp, pd->src, &uh->uh_sport,
			    pd->ip_sum, &uh->uh_sum,
			    &(*state)->state_key->gwy.addr,
			    (*state)->state_key->gwy.xport.port, 1, pd->af);
		else
			pf_change_ap(direction, pd->mp, pd->dst, &uh->uh_dport,
			    pd->ip_sum, &uh->uh_sum,
			    &(*state)->state_key->lan.addr,
			    (*state)->state_key->lan.xport.port, 1, pd->af);
		m_copyback(m, off, sizeof (*uh), uh);
	}

	return (PF_PASS);
}

static int
pf_test_state_icmp(struct pf_state **state, int direction, struct pfi_kif *kif,
    struct mbuf *m, int off, void *h, struct pf_pdesc *pd, u_short *reason)
{
#pragma unused(h)
	struct pf_addr	*saddr = pd->src, *daddr = pd->dst;
	u_int16_t	 icmpid = 0, *icmpsum;
	u_int8_t	 icmptype;
	int		 state_icmp = 0;
	struct pf_state_key_cmp key;

	struct pf_app_state as;
	key.app_state = 0;

	switch (pd->proto) {
#if INET
	case IPPROTO_ICMP:
		icmptype = pd->hdr.icmp->icmp_type;
		icmpid = pd->hdr.icmp->icmp_id;
		icmpsum = &pd->hdr.icmp->icmp_cksum;

		if (icmptype == ICMP_UNREACH ||
		    icmptype == ICMP_SOURCEQUENCH ||
		    icmptype == ICMP_REDIRECT ||
		    icmptype == ICMP_TIMXCEED ||
		    icmptype == ICMP_PARAMPROB)
			state_icmp++;
		break;
#endif /* INET */
#if INET6
	case IPPROTO_ICMPV6:
		icmptype = pd->hdr.icmp6->icmp6_type;
		icmpid = pd->hdr.icmp6->icmp6_id;
		icmpsum = &pd->hdr.icmp6->icmp6_cksum;

		if (icmptype == ICMP6_DST_UNREACH ||
		    icmptype == ICMP6_PACKET_TOO_BIG ||
		    icmptype == ICMP6_TIME_EXCEEDED ||
		    icmptype == ICMP6_PARAM_PROB)
			state_icmp++;
		break;
#endif /* INET6 */
	}

	if (!state_icmp) {

		/*
		 * ICMP query/reply message not related to a TCP/UDP packet.
		 * Search for an ICMP state.
		 */
		key.af = pd->af;
		key.proto = pd->proto;
		if (direction == PF_IN)	{
			PF_ACPY(&key.ext.addr, pd->src, key.af);
			PF_ACPY(&key.gwy.addr, pd->dst, key.af);
			key.ext.xport.port = 0;
			key.gwy.xport.port = icmpid;
		} else {
			PF_ACPY(&key.lan.addr, pd->src, key.af);
			PF_ACPY(&key.ext.addr, pd->dst, key.af);
			key.lan.xport.port = icmpid;
			key.ext.xport.port = 0;
		}

		STATE_LOOKUP();

		(*state)->expire = pf_time_second();
		(*state)->timeout = PFTM_ICMP_ERROR_REPLY;

		/* translate source/destination address, if necessary */
		if (STATE_TRANSLATE((*state)->state_key)) {
			if (direction == PF_OUT) {
				switch (pd->af) {
#if INET
				case AF_INET:
					pf_change_a(&saddr->v4.s_addr,
					    pd->ip_sum,
					    (*state)->state_key->gwy.addr.v4.s_addr, 0);
					pd->hdr.icmp->icmp_cksum =
					    pf_cksum_fixup(
					    pd->hdr.icmp->icmp_cksum, icmpid,
					    (*state)->state_key->gwy.xport.port, 0);
					pd->hdr.icmp->icmp_id =
					    (*state)->state_key->gwy.xport.port;
					m = pf_lazy_makewritable(pd, m,
					    off + ICMP_MINLEN);
					if (!m)
						return (PF_DROP);
					m_copyback(m, off, ICMP_MINLEN,
					    pd->hdr.icmp);
					break;
#endif /* INET */
#if INET6
				case AF_INET6:
					pf_change_a6(saddr,
					    &pd->hdr.icmp6->icmp6_cksum,
					    &(*state)->state_key->gwy.addr, 0);
					m = pf_lazy_makewritable(pd, m,
					    off + sizeof (struct icmp6_hdr));
					if (!m)
						return (PF_DROP);
					m_copyback(m, off,
					    sizeof (struct icmp6_hdr),
					    pd->hdr.icmp6);
					break;
#endif /* INET6 */
				}
			} else {
				switch (pd->af) {
#if INET
				case AF_INET:
					pf_change_a(&daddr->v4.s_addr,
					    pd->ip_sum,
					    (*state)->state_key->lan.addr.v4.s_addr, 0);
					pd->hdr.icmp->icmp_cksum =
					    pf_cksum_fixup(
					    pd->hdr.icmp->icmp_cksum, icmpid,
					    (*state)->state_key->lan.xport.port, 0);
					pd->hdr.icmp->icmp_id =
					    (*state)->state_key->lan.xport.port;
					m = pf_lazy_makewritable(pd, m,
					    off + ICMP_MINLEN);
					if (!m)
						return (PF_DROP);
					m_copyback(m, off, ICMP_MINLEN,
					    pd->hdr.icmp);
					break;
#endif /* INET */
#if INET6
				case AF_INET6:
					pf_change_a6(daddr,
					    &pd->hdr.icmp6->icmp6_cksum,
					    &(*state)->state_key->lan.addr, 0);
					m = pf_lazy_makewritable(pd, m,
					    off + sizeof (struct icmp6_hdr));
					if (!m)
						return (PF_DROP);
					m_copyback(m, off,
					    sizeof (struct icmp6_hdr),
					    pd->hdr.icmp6);
					break;
#endif /* INET6 */
				}
			}
		}

		return (PF_PASS);

	} else {
		/*
		 * ICMP error message in response to a TCP/UDP packet.
		 * Extract the inner TCP/UDP header and search for that state.
		 */

		struct pf_pdesc	pd2;
#if INET
		struct ip	h2;
#endif /* INET */
#if INET6
		struct ip6_hdr	h2_6;
		int		terminal = 0;
#endif /* INET6 */
		int		ipoff2 = 0;
		int		off2 = 0;

		memset(&pd2, 0, sizeof (pd2));

		pd2.af = pd->af;
		switch (pd->af) {
#if INET
		case AF_INET:
			/* offset of h2 in mbuf chain */
			ipoff2 = off + ICMP_MINLEN;

			if (!pf_pull_hdr(m, ipoff2, &h2, sizeof (h2),
			    NULL, reason, pd2.af)) {
				DPFPRINTF(PF_DEBUG_MISC,
				    ("pf: ICMP error message too short "
				    "(ip)\n"));
				return (PF_DROP);
			}
			/*
			 * ICMP error messages don't refer to non-first
			 * fragments
			 */
			if (h2.ip_off & htons(IP_OFFMASK)) {
				REASON_SET(reason, PFRES_FRAG);
				return (PF_DROP);
			}

			/* offset of protocol header that follows h2 */
			off2 = ipoff2 + (h2.ip_hl << 2);

			pd2.proto = h2.ip_p;
			pd2.src = (struct pf_addr *)&h2.ip_src;
			pd2.dst = (struct pf_addr *)&h2.ip_dst;
			pd2.ip_sum = &h2.ip_sum;
			break;
#endif /* INET */
#if INET6
		case AF_INET6:
			ipoff2 = off + sizeof (struct icmp6_hdr);

			if (!pf_pull_hdr(m, ipoff2, &h2_6, sizeof (h2_6),
			    NULL, reason, pd2.af)) {
				DPFPRINTF(PF_DEBUG_MISC,
				    ("pf: ICMP error message too short "
				    "(ip6)\n"));
				return (PF_DROP);
			}
			pd2.proto = h2_6.ip6_nxt;
			pd2.src = (struct pf_addr *)&h2_6.ip6_src;
			pd2.dst = (struct pf_addr *)&h2_6.ip6_dst;
			pd2.ip_sum = NULL;
			off2 = ipoff2 + sizeof (h2_6);
			do {
				switch (pd2.proto) {
				case IPPROTO_FRAGMENT:
					/*
					 * ICMPv6 error messages for
					 * non-first fragments
					 */
					REASON_SET(reason, PFRES_FRAG);
					return (PF_DROP);
				case IPPROTO_AH:
				case IPPROTO_HOPOPTS:
				case IPPROTO_ROUTING:
				case IPPROTO_DSTOPTS: {
					/* get next header and header length */
					struct ip6_ext opt6;

					if (!pf_pull_hdr(m, off2, &opt6,
					    sizeof (opt6), NULL, reason,
					    pd2.af)) {
						DPFPRINTF(PF_DEBUG_MISC,
						    ("pf: ICMPv6 short opt\n"));
						return (PF_DROP);
					}
					if (pd2.proto == IPPROTO_AH)
						off2 += (opt6.ip6e_len + 2) * 4;
					else
						off2 += (opt6.ip6e_len + 1) * 8;
					pd2.proto = opt6.ip6e_nxt;
					/* goto the next header */
					break;
				}
				default:
					terminal++;
					break;
				}
			} while (!terminal);
			break;
#endif /* INET6 */
		}

		switch (pd2.proto) {
		case IPPROTO_TCP: {
			struct tcphdr		 th;
			u_int32_t		 seq;
			struct pf_state_peer	*src, *dst;
			u_int8_t		 dws;
			int			 copyback = 0;

			/*
			 * Only the first 8 bytes of the TCP header can be
			 * expected. Don't access any TCP header fields after
			 * th_seq, an ackskew test is not possible.
			 */
			if (!pf_pull_hdr(m, off2, &th, 8, NULL, reason,
			    pd2.af)) {
				DPFPRINTF(PF_DEBUG_MISC,
				    ("pf: ICMP error message too short "
				    "(tcp)\n"));
				return (PF_DROP);
			}

			key.af = pd2.af;
			key.proto = IPPROTO_TCP;
			if (direction == PF_IN)	{
				PF_ACPY(&key.ext.addr, pd2.dst, key.af);
				PF_ACPY(&key.gwy.addr, pd2.src, key.af);
				key.ext.xport.port = th.th_dport;
				key.gwy.xport.port = th.th_sport;
			} else {
				PF_ACPY(&key.lan.addr, pd2.dst, key.af);
				PF_ACPY(&key.ext.addr, pd2.src, key.af);
				key.lan.xport.port = th.th_dport;
				key.ext.xport.port = th.th_sport;
			}

			STATE_LOOKUP();

			if (direction == (*state)->state_key->direction) {
				src = &(*state)->dst;
				dst = &(*state)->src;
			} else {
				src = &(*state)->src;
				dst = &(*state)->dst;
			}

			if (src->wscale && (dst->wscale & PF_WSCALE_FLAG))
				dws = dst->wscale & PF_WSCALE_MASK;
			else
				dws = TCP_MAX_WINSHIFT;

			/* Demodulate sequence number */
			seq = ntohl(th.th_seq) - src->seqdiff;
			if (src->seqdiff) {
				pf_change_a(&th.th_seq, icmpsum,
				    htonl(seq), 0);
				copyback = 1;
			}

			if (!SEQ_GEQ(src->seqhi, seq) ||
			    !SEQ_GEQ(seq,
			    src->seqlo - ((u_int32_t)dst->max_win << dws))) {
				if (pf_status.debug >= PF_DEBUG_MISC) {
					printf("pf: BAD ICMP %d:%d ",
					    icmptype, pd->hdr.icmp->icmp_code);
					pf_print_host(pd->src, 0, pd->af);
					printf(" -> ");
					pf_print_host(pd->dst, 0, pd->af);
					printf(" state: ");
					pf_print_state(*state);
					printf(" seq=%u\n", seq);
				}
				REASON_SET(reason, PFRES_BADSTATE);
				return (PF_DROP);
			}

			if (STATE_TRANSLATE((*state)->state_key)) {
				if (direction == PF_IN) {
					pf_change_icmp(pd2.src, &th.th_sport,
					    daddr, &(*state)->state_key->lan.addr,
					    (*state)->state_key->lan.xport.port, NULL,
					    pd2.ip_sum, icmpsum,
					    pd->ip_sum, 0, pd2.af);
				} else {
					pf_change_icmp(pd2.dst, &th.th_dport,
					    saddr, &(*state)->state_key->gwy.addr,
					    (*state)->state_key->gwy.xport.port, NULL,
					    pd2.ip_sum, icmpsum,
					    pd->ip_sum, 0, pd2.af);
				}
				copyback = 1;
			}

			if (copyback) {
				m = pf_lazy_makewritable(pd, m, off2 + 8);
				if (!m)
					return (PF_DROP);
				switch (pd2.af) {
#if INET
				case AF_INET:
					m_copyback(m, off, ICMP_MINLEN,
					    pd->hdr.icmp);
					m_copyback(m, ipoff2, sizeof (h2),
					    &h2);
					break;
#endif /* INET */
#if INET6
				case AF_INET6:
					m_copyback(m, off,
					    sizeof (struct icmp6_hdr),
					    pd->hdr.icmp6);
					m_copyback(m, ipoff2, sizeof (h2_6),
					    &h2_6);
					break;
#endif /* INET6 */
				}
				m_copyback(m, off2, 8, &th);
			}

			return (PF_PASS);
			break;
		}
		case IPPROTO_UDP: {
			struct udphdr		uh;
			int dx, action;
			if (!pf_pull_hdr(m, off2, &uh, sizeof (uh),
			    NULL, reason, pd2.af)) {
				DPFPRINTF(PF_DEBUG_MISC,
				    ("pf: ICMP error message too short "
				    "(udp)\n"));
				return (PF_DROP);
			}

			key.af = pd2.af;
			key.proto = IPPROTO_UDP;
			if (direction == PF_IN)	{
				PF_ACPY(&key.ext.addr, pd2.dst, key.af);
				PF_ACPY(&key.gwy.addr, pd2.src, key.af);
				key.ext.xport.port = uh.uh_dport;
				key.gwy.xport.port = uh.uh_sport;
				dx = PF_IN;
			} else {
				PF_ACPY(&key.lan.addr, pd2.dst, key.af);
				PF_ACPY(&key.ext.addr, pd2.src, key.af);
				key.lan.xport.port = uh.uh_dport;
				key.ext.xport.port = uh.uh_sport;
				dx = PF_OUT;
			}

			key.proto_variant = PF_EXTFILTER_APD;

			if (ntohs(uh.uh_sport) == PF_IKE_PORT &&
			    ntohs(uh.uh_dport) == PF_IKE_PORT) {
				struct pf_ike_hdr ike;
				size_t plen =
				    m->m_pkthdr.len - off2 - sizeof (uh);
				if (direction == PF_IN &&
				    plen < 8 /* PF_IKE_PACKET_MINSIZE */) {
					DPFPRINTF(PF_DEBUG_MISC, ("pf: "
					    "ICMP error, embedded IKE message "
					    "too small.\n"));
					return (PF_DROP);
				}

				if (plen > sizeof (ike))
					plen = sizeof (ike);
				m_copydata(m, off + sizeof (uh), plen, &ike);

				key.app_state = &as;
				as.compare_lan_ext = pf_ike_compare;
				as.compare_ext_gwy = pf_ike_compare;
				as.u.ike.cookie = ike.initiator_cookie;
			}

			*state = pf_find_state(kif, &key, dx);

			if (key.app_state && *state == 0) {
				key.app_state = 0;
				*state = pf_find_state(kif, &key, dx);
			}

			if (*state == 0) {
				key.proto_variant = PF_EXTFILTER_AD;
				*state = pf_find_state(kif, &key, dx);
			}

			if (*state == 0) {
				key.proto_variant = PF_EXTFILTER_EI;
				*state = pf_find_state(kif, &key, dx);
			}

			/* similar to STATE_LOOKUP() */
			if (*state != NULL && pd != NULL &&
			    !(pd->pktflags & PKTF_FLOW_ID)) {
				pd->flowsrc = (*state)->state_key->flowsrc;
				pd->flowhash = (*state)->state_key->flowhash;
				if (pd->flowhash != 0) {
					pd->pktflags |= PKTF_FLOW_ID;
					pd->pktflags &= ~PKTF_FLOW_ADV;
				}
			}

			if (pf_state_lookup_aux(state, kif, direction, &action))
				return (action);

			if (STATE_TRANSLATE((*state)->state_key)) {
				if (direction == PF_IN) {
					pf_change_icmp(pd2.src, &uh.uh_sport,
					    daddr, &(*state)->state_key->lan.addr,
					    (*state)->state_key->lan.xport.port, &uh.uh_sum,
					    pd2.ip_sum, icmpsum,
					    pd->ip_sum, 1, pd2.af);
				} else {
					pf_change_icmp(pd2.dst, &uh.uh_dport,
					    saddr, &(*state)->state_key->gwy.addr,
					    (*state)->state_key->gwy.xport.port, &uh.uh_sum,
					    pd2.ip_sum, icmpsum,
					    pd->ip_sum, 1, pd2.af);
				}
				m = pf_lazy_makewritable(pd, m,
				    off2 + sizeof (uh));
				if (!m)
					return (PF_DROP);
				switch (pd2.af) {
#if INET
				case AF_INET:
					m_copyback(m, off, ICMP_MINLEN,
					    pd->hdr.icmp);
					m_copyback(m, ipoff2, sizeof (h2), &h2);
					break;
#endif /* INET */
#if INET6
				case AF_INET6:
					m_copyback(m, off,
					    sizeof (struct icmp6_hdr),
					    pd->hdr.icmp6);
					m_copyback(m, ipoff2, sizeof (h2_6),
					    &h2_6);
					break;
#endif /* INET6 */
				}
				m_copyback(m, off2, sizeof (uh), &uh);
			}

			return (PF_PASS);
			break;
		}
#if INET
		case IPPROTO_ICMP: {
			struct icmp		iih;

			if (!pf_pull_hdr(m, off2, &iih, ICMP_MINLEN,
			    NULL, reason, pd2.af)) {
				DPFPRINTF(PF_DEBUG_MISC,
				    ("pf: ICMP error message too short i"
				    "(icmp)\n"));
				return (PF_DROP);
			}

			key.af = pd2.af;
			key.proto = IPPROTO_ICMP;
			if (direction == PF_IN)	{
				PF_ACPY(&key.ext.addr, pd2.dst, key.af);
				PF_ACPY(&key.gwy.addr, pd2.src, key.af);
				key.ext.xport.port = 0;
				key.gwy.xport.port = iih.icmp_id;
			} else {
				PF_ACPY(&key.lan.addr, pd2.dst, key.af);
				PF_ACPY(&key.ext.addr, pd2.src, key.af);
				key.lan.xport.port = iih.icmp_id;
				key.ext.xport.port = 0;
			}

			STATE_LOOKUP();

			if (STATE_TRANSLATE((*state)->state_key)) {
				if (direction == PF_IN) {
					pf_change_icmp(pd2.src, &iih.icmp_id,
					    daddr, &(*state)->state_key->lan.addr,
					    (*state)->state_key->lan.xport.port, NULL,
					    pd2.ip_sum, icmpsum,
					    pd->ip_sum, 0, AF_INET);
				} else {
					pf_change_icmp(pd2.dst, &iih.icmp_id,
					    saddr, &(*state)->state_key->gwy.addr,
					    (*state)->state_key->gwy.xport.port, NULL,
					    pd2.ip_sum, icmpsum,
					    pd->ip_sum, 0, AF_INET);
				}
				m = pf_lazy_makewritable(pd, m, off2 + ICMP_MINLEN);
				if (!m)
					return (PF_DROP);
				m_copyback(m, off, ICMP_MINLEN, pd->hdr.icmp);
				m_copyback(m, ipoff2, sizeof (h2), &h2);
				m_copyback(m, off2, ICMP_MINLEN, &iih);
			}

			return (PF_PASS);
			break;
		}
#endif /* INET */
#if INET6
		case IPPROTO_ICMPV6: {
			struct icmp6_hdr	iih;

			if (!pf_pull_hdr(m, off2, &iih,
			    sizeof (struct icmp6_hdr), NULL, reason, pd2.af)) {
				DPFPRINTF(PF_DEBUG_MISC,
				    ("pf: ICMP error message too short "
				    "(icmp6)\n"));
				return (PF_DROP);
			}

			key.af = pd2.af;
			key.proto = IPPROTO_ICMPV6;
			if (direction == PF_IN)	{
				PF_ACPY(&key.ext.addr, pd2.dst, key.af);
				PF_ACPY(&key.gwy.addr, pd2.src, key.af);
				key.ext.xport.port = 0;
				key.gwy.xport.port = iih.icmp6_id;
			} else {
				PF_ACPY(&key.lan.addr, pd2.dst, key.af);
				PF_ACPY(&key.ext.addr, pd2.src, key.af);
				key.lan.xport.port = iih.icmp6_id;
				key.ext.xport.port = 0;
			}

			STATE_LOOKUP();

			if (STATE_TRANSLATE((*state)->state_key)) {
				if (direction == PF_IN) {
					pf_change_icmp(pd2.src, &iih.icmp6_id,
					    daddr, &(*state)->state_key->lan.addr,
					    (*state)->state_key->lan.xport.port, NULL,
					    pd2.ip_sum, icmpsum,
					    pd->ip_sum, 0, AF_INET6);
				} else {
					pf_change_icmp(pd2.dst, &iih.icmp6_id,
					    saddr, &(*state)->state_key->gwy.addr,
					    (*state)->state_key->gwy.xport.port, NULL,
					    pd2.ip_sum, icmpsum,
					    pd->ip_sum, 0, AF_INET6);
				}
				m = pf_lazy_makewritable(pd, m, off2 +
				    sizeof (struct icmp6_hdr));
				if (!m)
					return (PF_DROP);
				m_copyback(m, off, sizeof (struct icmp6_hdr),
				    pd->hdr.icmp6);
				m_copyback(m, ipoff2, sizeof (h2_6), &h2_6);
				m_copyback(m, off2, sizeof (struct icmp6_hdr),
				    &iih);
			}

			return (PF_PASS);
			break;
		}
#endif /* INET6 */
		default: {
			key.af = pd2.af;
			key.proto = pd2.proto;
			if (direction == PF_IN)	{
				PF_ACPY(&key.ext.addr, pd2.dst, key.af);
				PF_ACPY(&key.gwy.addr, pd2.src, key.af);
				key.ext.xport.port = 0;
				key.gwy.xport.port = 0;
			} else {
				PF_ACPY(&key.lan.addr, pd2.dst, key.af);
				PF_ACPY(&key.ext.addr, pd2.src, key.af);
				key.lan.xport.port = 0;
				key.ext.xport.port = 0;
			}

			STATE_LOOKUP();

			if (STATE_TRANSLATE((*state)->state_key)) {
				if (direction == PF_IN) {
					pf_change_icmp(pd2.src, NULL,
					    daddr, &(*state)->state_key->lan.addr,
					    0, NULL,
					    pd2.ip_sum, icmpsum,
					    pd->ip_sum, 0, pd2.af);
				} else {
					pf_change_icmp(pd2.dst, NULL,
					    saddr, &(*state)->state_key->gwy.addr,
					    0, NULL,
					    pd2.ip_sum, icmpsum,
					    pd->ip_sum, 0, pd2.af);
				}
				switch (pd2.af) {
#if INET
				case AF_INET:
					m = pf_lazy_makewritable(pd, m,
					    ipoff2 + sizeof (h2));
					if (!m)
						return (PF_DROP);
#endif /* INET */
#if INET6
				case AF_INET6:
					m = pf_lazy_makewritable(pd, m,
					    ipoff2 + sizeof (h2_6));
					if (!m)
						return (PF_DROP);
					m_copyback(m, off,
					    sizeof (struct icmp6_hdr),
					    pd->hdr.icmp6);
					m_copyback(m, ipoff2, sizeof (h2_6),
					    &h2_6);
					break;
#endif /* INET6 */
				}
			}

			return (PF_PASS);
			break;
		}
		}
	}
}

static int
pf_test_state_grev1(struct pf_state **state, int direction,
    struct pfi_kif *kif, int off, struct pf_pdesc *pd)
{
	struct pf_state_peer *src;
	struct pf_state_peer *dst;
	struct pf_state_key_cmp key;
	struct pf_grev1_hdr *grev1 = pd->hdr.grev1;
	struct mbuf *m;

	key.app_state = 0;
	key.af = pd->af;
	key.proto = IPPROTO_GRE;
	key.proto_variant = PF_GRE_PPTP_VARIANT;
	if (direction == PF_IN)	{
		PF_ACPY(&key.ext.addr, pd->src, key.af);
		PF_ACPY(&key.gwy.addr, pd->dst, key.af);
		key.gwy.xport.call_id = grev1->call_id;
	} else {
		PF_ACPY(&key.lan.addr, pd->src, key.af);
		PF_ACPY(&key.ext.addr, pd->dst, key.af);
		key.ext.xport.call_id = grev1->call_id;
	}

	STATE_LOOKUP();

	if (direction == (*state)->state_key->direction) {
		src = &(*state)->src;
		dst = &(*state)->dst;
	} else {
		src = &(*state)->dst;
		dst = &(*state)->src;
	}

	/* update states */
	if (src->state < PFGRE1S_INITIATING)
		src->state = PFGRE1S_INITIATING;

	/* update expire time */
	(*state)->expire = pf_time_second();
	if (src->state >= PFGRE1S_INITIATING &&
	    dst->state >= PFGRE1S_INITIATING) {
		if ((*state)->timeout != PFTM_TCP_ESTABLISHED)
			(*state)->timeout = PFTM_GREv1_ESTABLISHED;
		src->state = PFGRE1S_ESTABLISHED;
		dst->state = PFGRE1S_ESTABLISHED;
	} else {
		(*state)->timeout = PFTM_GREv1_INITIATING;
	}

	if ((*state)->state_key->app_state)
		(*state)->state_key->app_state->u.grev1.pptp_state->expire =
		    pf_time_second();

	/* translate source/destination address, if necessary */
	if (STATE_GRE_TRANSLATE((*state)->state_key)) {
		if (direction == PF_OUT) {
			switch (pd->af) {
#if INET
			case AF_INET:
				pf_change_a(&pd->src->v4.s_addr,
				    pd->ip_sum,
				    (*state)->state_key->gwy.addr.v4.s_addr, 0);
				break;
#endif /* INET */
#if INET6
			case AF_INET6:
				PF_ACPY(pd->src, &(*state)->state_key->gwy.addr,
				    pd->af);
				break;
#endif /* INET6 */
			}
		} else {
			grev1->call_id = (*state)->state_key->lan.xport.call_id;

			switch (pd->af) {
#if INET
			case AF_INET:
				pf_change_a(&pd->dst->v4.s_addr,
				    pd->ip_sum,
				    (*state)->state_key->lan.addr.v4.s_addr, 0);
				break;
#endif /* INET */
#if INET6
			case AF_INET6:
				PF_ACPY(pd->dst, &(*state)->state_key->lan.addr,
				    pd->af);
				break;
#endif /* INET6 */
			}
		}

		m = pf_lazy_makewritable(pd, pd->mp, off + sizeof (*grev1));
		if (!m)
			return (PF_DROP);
		m_copyback(m, off, sizeof (*grev1), grev1);
	}

	return (PF_PASS);
}

static int
pf_test_state_esp(struct pf_state **state, int direction, struct pfi_kif *kif,
    int off, struct pf_pdesc *pd)
{
#pragma unused(off)
	struct pf_state_peer *src;
	struct pf_state_peer *dst;
	struct pf_state_key_cmp key;
	struct pf_esp_hdr *esp = pd->hdr.esp;
	int action;

	memset(&key, 0, sizeof (key));
	key.af = pd->af;
	key.proto = IPPROTO_ESP;
	if (direction == PF_IN)	{
		PF_ACPY(&key.ext.addr, pd->src, key.af);
		PF_ACPY(&key.gwy.addr, pd->dst, key.af);
		key.gwy.xport.spi = esp->spi;
	} else {
		PF_ACPY(&key.lan.addr, pd->src, key.af);
		PF_ACPY(&key.ext.addr, pd->dst, key.af);
		key.ext.xport.spi = esp->spi;
	}

	*state = pf_find_state(kif, &key, direction);

	if (*state == 0) {
		struct pf_state *s;

		/*
		 * <jhw@apple.com>
		 * No matching state.  Look for a blocking state.  If we find
		 * one, then use that state and move it so that it's keyed to
		 * the SPI in the current packet.
		 */
		if (direction == PF_IN) {
			key.gwy.xport.spi = 0;

			s = pf_find_state(kif, &key, direction);
			if (s) {
				struct pf_state_key *sk = s->state_key;

				RB_REMOVE(pf_state_tree_ext_gwy,
				    &pf_statetbl_ext_gwy, sk);
				sk->lan.xport.spi = sk->gwy.xport.spi =
				    esp->spi;

				if (RB_INSERT(pf_state_tree_ext_gwy,
				    &pf_statetbl_ext_gwy, sk))
					pf_detach_state(s, PF_DT_SKIP_EXTGWY);
				else
					*state = s;
			}
		} else {
			key.ext.xport.spi = 0;

			s = pf_find_state(kif, &key, direction);
			if (s) {
				struct pf_state_key *sk = s->state_key;

				RB_REMOVE(pf_state_tree_lan_ext,
				    &pf_statetbl_lan_ext, sk);
				sk->ext.xport.spi = esp->spi;

				if (RB_INSERT(pf_state_tree_lan_ext,
				    &pf_statetbl_lan_ext, sk))
					pf_detach_state(s, PF_DT_SKIP_LANEXT);
				else
					*state = s;
			}
		}

		if (s) {
			if (*state == 0) {
#if NPFSYNC
				if (s->creatorid == pf_status.hostid)
					pfsync_delete_state(s);
#endif
				s->timeout = PFTM_UNLINKED;
				hook_runloop(&s->unlink_hooks,
				    HOOK_REMOVE|HOOK_FREE);
				pf_src_tree_remove_state(s);
				pf_free_state(s);
				return (PF_DROP);
			}
		}
	}

	/* similar to STATE_LOOKUP() */
	if (*state != NULL && pd != NULL && !(pd->pktflags & PKTF_FLOW_ID)) {
		pd->flowsrc = (*state)->state_key->flowsrc;
		pd->flowhash = (*state)->state_key->flowhash;
		if (pd->flowhash != 0) {
			pd->pktflags |= PKTF_FLOW_ID;
			pd->pktflags &= ~PKTF_FLOW_ADV;
		}
	}

	if (pf_state_lookup_aux(state, kif, direction, &action))
		return (action);

	if (direction == (*state)->state_key->direction) {
		src = &(*state)->src;
		dst = &(*state)->dst;
	} else {
		src = &(*state)->dst;
		dst = &(*state)->src;
	}

	/* update states */
	if (src->state < PFESPS_INITIATING)
		src->state = PFESPS_INITIATING;

	/* update expire time */
	(*state)->expire = pf_time_second();
	if (src->state >= PFESPS_INITIATING &&
	    dst->state >= PFESPS_INITIATING) {
		(*state)->timeout = PFTM_ESP_ESTABLISHED;
		src->state = PFESPS_ESTABLISHED;
		dst->state = PFESPS_ESTABLISHED;
	} else {
		(*state)->timeout = PFTM_ESP_INITIATING;
	}
	/* translate source/destination address, if necessary */
	if (STATE_ADDR_TRANSLATE((*state)->state_key)) {
		if (direction == PF_OUT) {
			switch (pd->af) {
#if INET
			case AF_INET:
				pf_change_a(&pd->src->v4.s_addr,
				    pd->ip_sum,
				    (*state)->state_key->gwy.addr.v4.s_addr, 0);
				break;
#endif /* INET */
#if INET6
			case AF_INET6:
				PF_ACPY(pd->src, &(*state)->state_key->gwy.addr,
				    pd->af);
				break;
#endif /* INET6 */
			}
		} else {
			switch (pd->af) {
#if INET
			case AF_INET:
				pf_change_a(&pd->dst->v4.s_addr,
				    pd->ip_sum,
				    (*state)->state_key->lan.addr.v4.s_addr, 0);
				break;
#endif /* INET */
#if INET6
			case AF_INET6:
				PF_ACPY(pd->dst, &(*state)->state_key->lan.addr,
				    pd->af);
				break;
#endif /* INET6 */
			}
		}
	}

	return (PF_PASS);
}

static int
pf_test_state_other(struct pf_state **state, int direction, struct pfi_kif *kif,
    struct pf_pdesc *pd)
{
	struct pf_state_peer	*src, *dst;
	struct pf_state_key_cmp	 key;

	key.app_state = 0;
	key.af = pd->af;
	key.proto = pd->proto;
	if (direction == PF_IN)	{
		PF_ACPY(&key.ext.addr, pd->src, key.af);
		PF_ACPY(&key.gwy.addr, pd->dst, key.af);
		key.ext.xport.port = 0;
		key.gwy.xport.port = 0;
	} else {
		PF_ACPY(&key.lan.addr, pd->src, key.af);
		PF_ACPY(&key.ext.addr, pd->dst, key.af);
		key.lan.xport.port = 0;
		key.ext.xport.port = 0;
	}

	STATE_LOOKUP();

	if (direction == (*state)->state_key->direction) {
		src = &(*state)->src;
		dst = &(*state)->dst;
	} else {
		src = &(*state)->dst;
		dst = &(*state)->src;
	}

	/* update states */
	if (src->state < PFOTHERS_SINGLE)
		src->state = PFOTHERS_SINGLE;
	if (dst->state == PFOTHERS_SINGLE)
		dst->state = PFOTHERS_MULTIPLE;

	/* update expire time */
	(*state)->expire = pf_time_second();
	if (src->state == PFOTHERS_MULTIPLE && dst->state == PFOTHERS_MULTIPLE)
		(*state)->timeout = PFTM_OTHER_MULTIPLE;
	else
		(*state)->timeout = PFTM_OTHER_SINGLE;

	/* translate source/destination address, if necessary */
	if (STATE_ADDR_TRANSLATE((*state)->state_key)) {
		if (direction == PF_OUT) {
			switch (pd->af) {
#if INET
			case AF_INET:
				pf_change_a(&pd->src->v4.s_addr,
				    pd->ip_sum,
				    (*state)->state_key->gwy.addr.v4.s_addr,
				    0);
				break;
#endif /* INET */
#if INET6
			case AF_INET6:
				PF_ACPY(pd->src,
				    &(*state)->state_key->gwy.addr, pd->af);
				break;
#endif /* INET6 */
			}
		} else {
			switch (pd->af) {
#if INET
			case AF_INET:
				pf_change_a(&pd->dst->v4.s_addr,
				    pd->ip_sum,
				    (*state)->state_key->lan.addr.v4.s_addr,
				    0);
				break;
#endif /* INET */
#if INET6
			case AF_INET6:
				PF_ACPY(pd->dst,
				    &(*state)->state_key->lan.addr, pd->af);
				break;
#endif /* INET6 */
			}
		}
	}

	return (PF_PASS);
}

/*
 * ipoff and off are measured from the start of the mbuf chain.
 * h must be at "ipoff" on the mbuf chain.
 */
void *
pf_pull_hdr(struct mbuf *m, int off, void *p, int len,
    u_short *actionp, u_short *reasonp, sa_family_t af)
{
	switch (af) {
#if INET
	case AF_INET: {
		struct ip	*h = mtod(m, struct ip *);
		u_int16_t	 fragoff = (ntohs(h->ip_off) & IP_OFFMASK) << 3;

		if (fragoff) {
			if (fragoff >= len) {
				ACTION_SET(actionp, PF_PASS);
			} else {
				ACTION_SET(actionp, PF_DROP);
				REASON_SET(reasonp, PFRES_FRAG);
			}
			return (NULL);
		}
		if (m->m_pkthdr.len < off + len ||
		    ntohs(h->ip_len) < off + len) {
			ACTION_SET(actionp, PF_DROP);
			REASON_SET(reasonp, PFRES_SHORT);
			return (NULL);
		}
		break;
	}
#endif /* INET */
#if INET6
	case AF_INET6: {
		struct ip6_hdr	*h = mtod(m, struct ip6_hdr *);

		if (m->m_pkthdr.len < off + len ||
		    (ntohs(h->ip6_plen) + sizeof (struct ip6_hdr)) <
		    (unsigned)(off + len)) {
			ACTION_SET(actionp, PF_DROP);
			REASON_SET(reasonp, PFRES_SHORT);
			return (NULL);
		}
		break;
	}
#endif /* INET6 */
	}
	m_copydata(m, off, len, p);
	return (p);
}

int
pf_routable(struct pf_addr *addr, sa_family_t af, struct pfi_kif *kif)
{
#pragma unused(kif)
	struct sockaddr_in	*dst;
	int			 ret = 1;
#if INET6
	struct sockaddr_in6	*dst6;
	struct route_in6	 ro;
#else
	struct route		 ro;
#endif

	bzero(&ro, sizeof (ro));
	switch (af) {
	case AF_INET:
		dst = satosin(&ro.ro_dst);
		dst->sin_family = AF_INET;
		dst->sin_len = sizeof (*dst);
		dst->sin_addr = addr->v4;
		break;
#if INET6
	case AF_INET6:
		dst6 = (struct sockaddr_in6 *)&ro.ro_dst;
		dst6->sin6_family = AF_INET6;
		dst6->sin6_len = sizeof (*dst6);
		dst6->sin6_addr = addr->v6;
		break;
#endif /* INET6 */
	default:
		return (0);
	}

	/* XXX: IFT_ENC is not currently used by anything*/
	/* Skip checks for ipsec interfaces */
	if (kif != NULL && kif->pfik_ifp->if_type == IFT_ENC)
		goto out;

	/* XXX: what is the point of this? */
	rtalloc((struct route *)&ro);

out:
	ROUTE_RELEASE(&ro);
	return (ret);
}

int
pf_rtlabel_match(struct pf_addr *addr, sa_family_t af, struct pf_addr_wrap *aw)
{
#pragma unused(aw)
	struct sockaddr_in	*dst;
#if INET6
	struct sockaddr_in6	*dst6;
	struct route_in6	 ro;
#else
	struct route		 ro;
#endif
	int			 ret = 0;

	bzero(&ro, sizeof (ro));
	switch (af) {
	case AF_INET:
		dst = satosin(&ro.ro_dst);
		dst->sin_family = AF_INET;
		dst->sin_len = sizeof (*dst);
		dst->sin_addr = addr->v4;
		break;
#if INET6
	case AF_INET6:
		dst6 = (struct sockaddr_in6 *)&ro.ro_dst;
		dst6->sin6_family = AF_INET6;
		dst6->sin6_len = sizeof (*dst6);
		dst6->sin6_addr = addr->v6;
		break;
#endif /* INET6 */
	default:
		return (0);
	}

	/* XXX: what is the point of this? */
	rtalloc((struct route *)&ro);

	ROUTE_RELEASE(&ro);

	return (ret);
}

#if INET
static void
pf_route(struct mbuf **m, struct pf_rule *r, int dir, struct ifnet *oifp,
    struct pf_state *s, struct pf_pdesc *pd)
{
#pragma unused(pd)
	struct mbuf		*m0, *m1;
	struct route		 iproute;
	struct route		*ro = &iproute;
	struct sockaddr_in	*dst;
	struct ip		*ip;
	struct ifnet		*ifp = NULL;
	struct pf_addr		 naddr;
	struct pf_src_node	*sn = NULL;
	int			 error = 0;
	uint32_t		 sw_csum;

	bzero(&iproute, sizeof (iproute));

	if (m == NULL || *m == NULL || r == NULL ||
	    (dir != PF_IN && dir != PF_OUT) || oifp == NULL)
		panic("pf_route: invalid parameters");

	if (pd->pf_mtag->pftag_routed++ > 3) {
		m0 = *m;
		*m = NULL;
		goto bad;
	}

	if (r->rt == PF_DUPTO) {
		if ((m0 = m_copym(*m, 0, M_COPYALL, M_NOWAIT)) == NULL)
			return;
	} else {
		if ((r->rt == PF_REPLYTO) == (r->direction == dir))
			return;
		m0 = *m;
	}

	if (m0->m_len < (int)sizeof (struct ip)) {
		DPFPRINTF(PF_DEBUG_URGENT,
		    ("pf_route: m0->m_len < sizeof (struct ip)\n"));
		goto bad;
	}

	ip = mtod(m0, struct ip *);

	dst = satosin((void *)&ro->ro_dst);
	dst->sin_family = AF_INET;
	dst->sin_len = sizeof (*dst);
	dst->sin_addr = ip->ip_dst;

	if (r->rt == PF_FASTROUTE) {
		rtalloc(ro);
		if (ro->ro_rt == NULL) {
			ipstat.ips_noroute++;
			goto bad;
		}

		ifp = ro->ro_rt->rt_ifp;
		RT_LOCK(ro->ro_rt);
		ro->ro_rt->rt_use++;

		if (ro->ro_rt->rt_flags & RTF_GATEWAY)
			dst = satosin((void *)ro->ro_rt->rt_gateway);
		RT_UNLOCK(ro->ro_rt);
	} else {
		if (TAILQ_EMPTY(&r->rpool.list)) {
			DPFPRINTF(PF_DEBUG_URGENT,
			    ("pf_route: TAILQ_EMPTY(&r->rpool.list)\n"));
			goto bad;
		}
		if (s == NULL) {
			pf_map_addr(AF_INET, r, (struct pf_addr *)&ip->ip_src,
			    &naddr, NULL, &sn);
			if (!PF_AZERO(&naddr, AF_INET))
				dst->sin_addr.s_addr = naddr.v4.s_addr;
			ifp = r->rpool.cur->kif ?
			    r->rpool.cur->kif->pfik_ifp : NULL;
		} else {
			if (!PF_AZERO(&s->rt_addr, AF_INET))
				dst->sin_addr.s_addr =
				    s->rt_addr.v4.s_addr;
			ifp = s->rt_kif ? s->rt_kif->pfik_ifp : NULL;
		}
	}
	if (ifp == NULL)
		goto bad;

	if (oifp != ifp) {
		if (pf_test(PF_OUT, ifp, &m0, NULL, NULL) != PF_PASS)
			goto bad;
		else if (m0 == NULL)
			goto done;
		if (m0->m_len < (int)sizeof (struct ip)) {
			DPFPRINTF(PF_DEBUG_URGENT,
			    ("pf_route: m0->m_len < sizeof (struct ip)\n"));
			goto bad;
		}
		ip = mtod(m0, struct ip *);
	}

	/* Catch routing changes wrt. hardware checksumming for TCP or UDP. */
	ip_output_checksum(ifp, m0, ((ip->ip_hl) << 2), ntohs(ip->ip_len),
	    &sw_csum);

	if (ntohs(ip->ip_len) <= ifp->if_mtu || TSO_IPV4_OK(ifp, m0) ||
	    (!(ip->ip_off & htons(IP_DF)) &&
	    (ifp->if_hwassist & CSUM_FRAGMENT))) {
		ip->ip_sum = 0;
		if (sw_csum & CSUM_DELAY_IP) {
			ip->ip_sum = in_cksum(m0, ip->ip_hl << 2);
			sw_csum &= ~CSUM_DELAY_IP;
			m0->m_pkthdr.csum_flags &= ~CSUM_DELAY_IP;
		}
		error = ifnet_output(ifp, PF_INET, m0, ro->ro_rt, sintosa(dst));
		goto done;
	}

	/*
	 * Too large for interface; fragment if possible.
	 * Must be able to put at least 8 bytes per fragment.
	 * Balk when DF bit is set or the interface didn't support TSO.
	 */
	if ((ip->ip_off & htons(IP_DF)) ||
	    (m0->m_pkthdr.csum_flags & CSUM_TSO_IPV4)) {
		ipstat.ips_cantfrag++;
		if (r->rt != PF_DUPTO) {
			icmp_error(m0, ICMP_UNREACH, ICMP_UNREACH_NEEDFRAG, 0,
			    ifp->if_mtu);
			goto done;
		} else
			goto bad;
	}

	m1 = m0;

	/* PR-8933605: send ip_len,ip_off to ip_fragment in host byte order */
#if BYTE_ORDER != BIG_ENDIAN
	NTOHS(ip->ip_off);
	NTOHS(ip->ip_len);
#endif
	error = ip_fragment(m0, ifp, ifp->if_mtu, sw_csum);

	if (error) {
		m0 = NULL;
		goto bad;
	}

	for (m0 = m1; m0; m0 = m1) {
		m1 = m0->m_nextpkt;
		m0->m_nextpkt = 0;
		if (error == 0)
			error = ifnet_output(ifp, PF_INET, m0, ro->ro_rt,
			    sintosa(dst));
		else
			m_freem(m0);
	}

	if (error == 0)
		ipstat.ips_fragmented++;

done:
	if (r->rt != PF_DUPTO)
		*m = NULL;

	ROUTE_RELEASE(&iproute);
	return;

bad:
	m_freem(m0);
	goto done;
}
#endif /* INET */

#if INET6
static void
pf_route6(struct mbuf **m, struct pf_rule *r, int dir, struct ifnet *oifp,
    struct pf_state *s, struct pf_pdesc *pd)
{
#pragma unused(pd)
	struct mbuf		*m0;
	struct route_in6	 ip6route;
	struct route_in6	*ro;
	struct sockaddr_in6	*dst;
	struct ip6_hdr		*ip6;
	struct ifnet		*ifp = NULL;
	struct pf_addr		 naddr;
	struct pf_src_node	*sn = NULL;
	int			 error = 0;

	if (m == NULL || *m == NULL || r == NULL ||
	    (dir != PF_IN && dir != PF_OUT) || oifp == NULL)
		panic("pf_route6: invalid parameters");

	if (pd->pf_mtag->pftag_routed++ > 3) {
		m0 = *m;
		*m = NULL;
		goto bad;
	}

	if (r->rt == PF_DUPTO) {
		if ((m0 = m_copym(*m, 0, M_COPYALL, M_NOWAIT)) == NULL)
			return;
	} else {
		if ((r->rt == PF_REPLYTO) == (r->direction == dir))
			return;
		m0 = *m;
	}

	if (m0->m_len < (int)sizeof (struct ip6_hdr)) {
		DPFPRINTF(PF_DEBUG_URGENT,
		    ("pf_route6: m0->m_len < sizeof (struct ip6_hdr)\n"));
		goto bad;
	}
	ip6 = mtod(m0, struct ip6_hdr *);

	ro = &ip6route;
	bzero((caddr_t)ro, sizeof (*ro));
	dst = (struct sockaddr_in6 *)&ro->ro_dst;
	dst->sin6_family = AF_INET6;
	dst->sin6_len = sizeof (*dst);
	dst->sin6_addr = ip6->ip6_dst;

	/* Cheat. XXX why only in the v6 case??? */
	if (r->rt == PF_FASTROUTE) {
		struct pf_mtag *pf_mtag;

		if ((pf_mtag = pf_get_mtag(m0)) == NULL)
			goto bad;
		pf_mtag->pftag_flags |= PF_TAG_GENERATED;
		ip6_output(m0, NULL, NULL, 0, NULL, NULL, NULL);
		return;
	}

	if (TAILQ_EMPTY(&r->rpool.list)) {
		DPFPRINTF(PF_DEBUG_URGENT,
		    ("pf_route6: TAILQ_EMPTY(&r->rpool.list)\n"));
		goto bad;
	}
	if (s == NULL) {
		pf_map_addr(AF_INET6, r, (struct pf_addr *)&ip6->ip6_src,
		    &naddr, NULL, &sn);
		if (!PF_AZERO(&naddr, AF_INET6))
			PF_ACPY((struct pf_addr *)&dst->sin6_addr,
			    &naddr, AF_INET6);
		ifp = r->rpool.cur->kif ? r->rpool.cur->kif->pfik_ifp : NULL;
	} else {
		if (!PF_AZERO(&s->rt_addr, AF_INET6))
			PF_ACPY((struct pf_addr *)&dst->sin6_addr,
			    &s->rt_addr, AF_INET6);
		ifp = s->rt_kif ? s->rt_kif->pfik_ifp : NULL;
	}
	if (ifp == NULL)
		goto bad;

	if (oifp != ifp) {
		if (pf_test6(PF_OUT, ifp, &m0, NULL, NULL) != PF_PASS)
			goto bad;
		else if (m0 == NULL)
			goto done;
		if (m0->m_len < (int)sizeof (struct ip6_hdr)) {
			DPFPRINTF(PF_DEBUG_URGENT, ("pf_route6: m0->m_len "
			    "< sizeof (struct ip6_hdr)\n"));
			goto bad;
		}
		ip6 = mtod(m0, struct ip6_hdr *);
	}

	/*
	 * If the packet is too large for the outgoing interface,
	 * send back an icmp6 error.
	 */
	if (IN6_IS_SCOPE_EMBED(&dst->sin6_addr))
		dst->sin6_addr.s6_addr16[1] = htons(ifp->if_index);
	if ((unsigned)m0->m_pkthdr.len <= ifp->if_mtu) {
		error = nd6_output(ifp, ifp, m0, dst, NULL, NULL);
	} else {
		in6_ifstat_inc(ifp, ifs6_in_toobig);
		if (r->rt != PF_DUPTO)
			icmp6_error(m0, ICMP6_PACKET_TOO_BIG, 0, ifp->if_mtu);
		else
			goto bad;
	}

done:
	if (r->rt != PF_DUPTO)
		*m = NULL;
	return;

bad:
	m_freem(m0);
	goto done;
}
#endif /* INET6 */


/*
 * check protocol (tcp/udp/icmp/icmp6) checksum and set mbuf flag
 *   off is the offset where the protocol header starts
 *   len is the total length of protocol header plus payload
 * returns 0 when the checksum is valid, otherwise returns 1.
 */
static int
pf_check_proto_cksum(struct mbuf *m, int off, int len, u_int8_t p,
    sa_family_t af)
{
	u_int16_t sum;

	switch (p) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		/*
		 * Optimize for the common case; if the hardware calculated
		 * value doesn't include pseudo-header checksum, or if it
		 * is partially-computed (only 16-bit summation), do it in
		 * software below.
		 */
		if ((m->m_pkthdr.csum_flags &
		    (CSUM_DATA_VALID | CSUM_PSEUDO_HDR)) ==
		    (CSUM_DATA_VALID | CSUM_PSEUDO_HDR) &&
		    (m->m_pkthdr.csum_data ^ 0xffff) == 0) {
			return (0);
		}
		break;
	case IPPROTO_ICMP:
#if INET6
	case IPPROTO_ICMPV6:
#endif /* INET6 */
		break;
	default:
		return (1);
	}
	if (off < (int)sizeof (struct ip) || len < (int)sizeof (struct udphdr))
		return (1);
	if (m->m_pkthdr.len < off + len)
		return (1);
	switch (af) {
#if INET
	case AF_INET:
		if (p == IPPROTO_ICMP) {
			if (m->m_len < off)
				return (1);
			m->m_data += off;
			m->m_len -= off;
			sum = in_cksum(m, len);
			m->m_data -= off;
			m->m_len += off;
		} else {
			if (m->m_len < (int)sizeof (struct ip))
				return (1);
			sum = inet_cksum(m, p, off, len);
		}
		break;
#endif /* INET */
#if INET6
	case AF_INET6:
		if (m->m_len < (int)sizeof (struct ip6_hdr))
			return (1);
		sum = inet6_cksum(m, p, off, len);
		break;
#endif /* INET6 */
	default:
		return (1);
	}
	if (sum) {
		switch (p) {
		case IPPROTO_TCP:
			tcpstat.tcps_rcvbadsum++;
			break;
		case IPPROTO_UDP:
			udpstat.udps_badsum++;
			break;
		case IPPROTO_ICMP:
			icmpstat.icps_checksum++;
			break;
#if INET6
		case IPPROTO_ICMPV6:
			icmp6stat.icp6s_checksum++;
			break;
#endif /* INET6 */
		}
		return (1);
	}
	return (0);
}

#if INET
#define PF_APPLE_UPDATE_PDESC_IPv4()				\
	do {							\
		if (m && pd.mp && m != pd.mp) {			\
			m = pd.mp;				\
			h = mtod(m, struct ip *);		\
			pd.pf_mtag = pf_get_mtag(m);		\
		}						\
	} while (0)

int
pf_test(int dir, struct ifnet *ifp, struct mbuf **m0,
    struct ether_header *eh, struct ip_fw_args *fwa)
{
#if !DUMMYNET
#pragma unused(fwa)
#endif
	struct pfi_kif		*kif;
	u_short			 action = PF_PASS, reason = 0, log = 0;
	struct mbuf		*m = *m0;
	struct ip		*h = 0;
	struct pf_rule		*a = NULL, *r = &pf_default_rule, *tr, *nr;
	struct pf_state		*s = NULL;
	struct pf_state_key	*sk = NULL;
	struct pf_ruleset	*ruleset = NULL;
	struct pf_pdesc		 pd;
	int			 off, dirndx, pqid = 0;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if (!pf_status.running)
		return (PF_PASS);

	memset(&pd, 0, sizeof (pd));

	if ((pd.pf_mtag = pf_get_mtag(m)) == NULL) {
		DPFPRINTF(PF_DEBUG_URGENT,
		    ("pf_test: pf_get_mtag returned NULL\n"));
		return (PF_DROP);
	}

	if (pd.pf_mtag->pftag_flags & PF_TAG_GENERATED)
		return (PF_PASS);

	kif = (struct pfi_kif *)ifp->if_pf_kif;

	if (kif == NULL) {
		DPFPRINTF(PF_DEBUG_URGENT,
		    ("pf_test: kif == NULL, if_name %s\n", ifp->if_name));
		return (PF_DROP);
	}
	if (kif->pfik_flags & PFI_IFLAG_SKIP)
		return (PF_PASS);

	VERIFY(m->m_flags & M_PKTHDR);

	/* initialize enough of pd for the done label */
	h = mtod(m, struct ip *);
	pd.mp = m;
	pd.lmw = 0;
	pd.pf_mtag = pf_get_mtag(m);
	pd.src = (struct pf_addr *)&h->ip_src;
	pd.dst = (struct pf_addr *)&h->ip_dst;
	PF_ACPY(&pd.baddr, dir == PF_OUT ? pd.src : pd.dst, AF_INET);
	pd.ip_sum = &h->ip_sum;
	pd.proto = h->ip_p;
	pd.proto_variant = 0;
	pd.af = AF_INET;
	pd.tos = h->ip_tos;
	pd.tot_len = ntohs(h->ip_len);
	pd.eh = eh;

	if (m->m_pkthdr.len < (int)sizeof (*h)) {
		action = PF_DROP;
		REASON_SET(&reason, PFRES_SHORT);
		log = 1;
		goto done;
	}

#if DUMMYNET
	if (fwa != NULL && fwa->fwa_pf_rule != NULL)
		goto nonormalize;
#endif /* DUMMYNET */

	/* We do IP header normalization and packet reassembly here */
	action = pf_normalize_ip(m0, dir, kif, &reason, &pd);
	pd.mp = m = *m0;
	if (action != PF_PASS || pd.lmw < 0) {
		action = PF_DROP;
		goto done;
	}

#if DUMMYNET
nonormalize:
#endif /* DUMMYNET */
	m = *m0;	/* pf_normalize messes with m0 */
	h = mtod(m, struct ip *);

	off = h->ip_hl << 2;
	if (off < (int)sizeof (*h)) {
		action = PF_DROP;
		REASON_SET(&reason, PFRES_SHORT);
		log = 1;
		goto done;
	}

	pd.src = (struct pf_addr *)&h->ip_src;
	pd.dst = (struct pf_addr *)&h->ip_dst;
	PF_ACPY(&pd.baddr, dir == PF_OUT ? pd.src : pd.dst, AF_INET);
	pd.ip_sum = &h->ip_sum;
	pd.proto = h->ip_p;
	pd.proto_variant = 0;
	pd.mp = m;
	pd.lmw = 0;
	pd.pf_mtag = pf_get_mtag(m);
	pd.af = AF_INET;
	pd.tos = h->ip_tos;
	pd.sc = MBUF_SCIDX(mbuf_get_service_class(m));
	pd.tot_len = ntohs(h->ip_len);
	pd.eh = eh;

	if (m->m_pkthdr.pkt_flags & PKTF_FLOW_ID) {
		pd.flowsrc = m->m_pkthdr.pkt_flowsrc;
		pd.flowhash = m->m_pkthdr.pkt_flowid;
		pd.pktflags = (m->m_pkthdr.pkt_flags & PKTF_FLOW_MASK);
	}

	/* handle fragments that didn't get reassembled by normalization */
	if (h->ip_off & htons(IP_MF | IP_OFFMASK)) {
		pd.flags |= PFDESC_IP_FRAG;
#if DUMMYNET
		/* Traffic goes through dummynet first */
		action = pf_test_dummynet(&r, dir, kif, &m, &pd, fwa);
		if (action == PF_DROP || m == NULL) {
			*m0 = NULL;
			return (action);
		}
#endif /* DUMMYNET */
		action = pf_test_fragment(&r, dir, kif, m, h,
		    &pd, &a, &ruleset);
		goto done;
	}

	switch (h->ip_p) {

	case IPPROTO_TCP: {
		struct tcphdr	th;
		pd.hdr.tcp = &th;
		if (!pf_pull_hdr(m, off, &th, sizeof (th),
		    &action, &reason, AF_INET)) {
			log = action != PF_PASS;
			goto done;
		}
		pd.p_len = pd.tot_len - off - (th.th_off << 2);
		if ((th.th_flags & TH_ACK) && pd.p_len == 0)
			pqid = 1;
#if DUMMYNET
		/* Traffic goes through dummynet first */
		action = pf_test_dummynet(&r, dir, kif, &m, &pd, fwa);
		if (action == PF_DROP || m == NULL) {
			*m0 = NULL;
			return (action);
		}
#endif /* DUMMYNET */
		action = pf_normalize_tcp(dir, kif, m, 0, off, h, &pd);
		if (pd.lmw < 0)
			goto done;
		PF_APPLE_UPDATE_PDESC_IPv4();
		if (action == PF_DROP)
			goto done;
		action = pf_test_state_tcp(&s, dir, kif, m, off, h, &pd,
		    &reason);
		if (pd.lmw < 0)
			goto done;
		PF_APPLE_UPDATE_PDESC_IPv4();
		if (action == PF_PASS) {
#if NPFSYNC
			pfsync_update_state(s);
#endif /* NPFSYNC */
			r = s->rule.ptr;
			a = s->anchor.ptr;
			log = s->log;
		} else if (s == NULL)
			action = pf_test_rule(&r, &s, dir, kif,
			    m, off, h, &pd, &a, &ruleset, NULL);
		break;
	}

	case IPPROTO_UDP: {
		struct udphdr	uh;

		pd.hdr.udp = &uh;
		if (!pf_pull_hdr(m, off, &uh, sizeof (uh),
		    &action, &reason, AF_INET)) {
			log = action != PF_PASS;
			goto done;
		}
		if (uh.uh_dport == 0 ||
		    ntohs(uh.uh_ulen) > m->m_pkthdr.len - off ||
		    ntohs(uh.uh_ulen) < sizeof (struct udphdr)) {
			action = PF_DROP;
			REASON_SET(&reason, PFRES_SHORT);
			goto done;
		}
#if DUMMYNET
		/* Traffic goes through dummynet first */
		action = pf_test_dummynet(&r, dir, kif, &m, &pd, fwa);
		if (action == PF_DROP || m == NULL) {
			*m0 = NULL;
			return (action);
		}
#endif /* DUMMYNET */
		action = pf_test_state_udp(&s, dir, kif, m, off, h, &pd,
		    &reason);
		if (pd.lmw < 0)
			goto done;
		PF_APPLE_UPDATE_PDESC_IPv4();
		if (action == PF_PASS) {
#if NPFSYNC
			pfsync_update_state(s);
#endif /* NPFSYNC */
			r = s->rule.ptr;
			a = s->anchor.ptr;
			log = s->log;
		} else if (s == NULL)
			action = pf_test_rule(&r, &s, dir, kif,
			    m, off, h, &pd, &a, &ruleset, NULL);
		break;
	}

	case IPPROTO_ICMP: {
		struct icmp	ih;

		pd.hdr.icmp = &ih;
		if (!pf_pull_hdr(m, off, &ih, ICMP_MINLEN,
		    &action, &reason, AF_INET)) {
			log = action != PF_PASS;
			goto done;
		}
#if DUMMYNET
		/* Traffic goes through dummynet first */
		action = pf_test_dummynet(&r, dir, kif, &m, &pd, fwa);
		if (action == PF_DROP || m == NULL) {
			*m0 = NULL;
			return (action);
		}
#endif /* DUMMYNET */
		action = pf_test_state_icmp(&s, dir, kif, m, off, h, &pd,
		    &reason);
		if (pd.lmw < 0)
			goto done;
		PF_APPLE_UPDATE_PDESC_IPv4();
		if (action == PF_PASS) {
#if NPFSYNC
			pfsync_update_state(s);
#endif /* NPFSYNC */
			r = s->rule.ptr;
			a = s->anchor.ptr;
			log = s->log;
		} else if (s == NULL)
			action = pf_test_rule(&r, &s, dir, kif,
			    m, off, h, &pd, &a, &ruleset, NULL);
		break;
	}

	case IPPROTO_ESP: {
		struct pf_esp_hdr	esp;

		pd.hdr.esp = &esp;
		if (!pf_pull_hdr(m, off, &esp, sizeof (esp), &action, &reason,
		    AF_INET)) {
			log = action != PF_PASS;
			goto done;
		}
#if DUMMYNET
		/* Traffic goes through dummynet first */
		action = pf_test_dummynet(&r, dir, kif, &m, &pd, fwa);
		if (action == PF_DROP || m == NULL) {
			*m0 = NULL;
			return (action);
		}
#endif /* DUMMYNET */
		action = pf_test_state_esp(&s, dir, kif, off, &pd);
		if (pd.lmw < 0)
			goto done;
		PF_APPLE_UPDATE_PDESC_IPv4();
		if (action == PF_PASS) {
#if NPFSYNC
			pfsync_update_state(s);
#endif /* NPFSYNC */
			r = s->rule.ptr;
			a = s->anchor.ptr;
			log = s->log;
		} else if (s == NULL)
			action = pf_test_rule(&r, &s, dir, kif,
			    m, off, h, &pd, &a, &ruleset, NULL);
		break;
	}

	case IPPROTO_GRE: {
		struct pf_grev1_hdr	grev1;
		pd.hdr.grev1 = &grev1;
		if (!pf_pull_hdr(m, off, &grev1, sizeof (grev1), &action,
		    &reason, AF_INET)) {
			log = (action != PF_PASS);
			goto done;
		}
#if DUMMYNET
		/* Traffic goes through dummynet first */
		action = pf_test_dummynet(&r, dir, kif, &m, &pd, fwa);
		if (action == PF_DROP || m == NULL) {
			*m0 = NULL;
			return (action);
		}
#endif /* DUMMYNET */
		if ((ntohs(grev1.flags) & PF_GRE_FLAG_VERSION_MASK) == 1 &&
		    ntohs(grev1.protocol_type) == PF_GRE_PPP_ETHERTYPE) {
			if (ntohs(grev1.payload_length) >
			    m->m_pkthdr.len - off) {
				action = PF_DROP;
				REASON_SET(&reason, PFRES_SHORT);
				goto done;
			}
			pd.proto_variant = PF_GRE_PPTP_VARIANT;
			action = pf_test_state_grev1(&s, dir, kif, off, &pd);
			if (pd.lmw < 0) goto done;
			PF_APPLE_UPDATE_PDESC_IPv4();
			if (action == PF_PASS) {
#if NPFSYNC
				pfsync_update_state(s);
#endif /* NPFSYNC */
				r = s->rule.ptr;
				a = s->anchor.ptr;
				log = s->log;
				break;
			} else if (s == NULL) {
				action = pf_test_rule(&r, &s, dir, kif, m, off,
				    h, &pd, &a, &ruleset, NULL);
				if (action == PF_PASS)
					break;
			}
		}

		/* not GREv1/PPTP, so treat as ordinary GRE... */
	}

	default:
#if DUMMYNET
		/* Traffic goes through dummynet first */
		action = pf_test_dummynet(&r, dir, kif, &m, &pd, fwa);
		if (action == PF_DROP || m == NULL) {
			*m0 = NULL;
			return (action);
		}
#endif /* DUMMYNET */
		action = pf_test_state_other(&s, dir, kif, &pd);
		if (pd.lmw < 0)
			goto done;
		PF_APPLE_UPDATE_PDESC_IPv4();
		if (action == PF_PASS) {
#if NPFSYNC
			pfsync_update_state(s);
#endif /* NPFSYNC */
			r = s->rule.ptr;
			a = s->anchor.ptr;
			log = s->log;
		} else if (s == NULL)
			action = pf_test_rule(&r, &s, dir, kif, m, off, h,
			    &pd, &a, &ruleset, NULL);
		break;
	}

done:
	*m0 = pd.mp;
	PF_APPLE_UPDATE_PDESC_IPv4();

	if (action == PF_PASS && h->ip_hl > 5 &&
	    !((s && s->allow_opts) || r->allow_opts)) {
		action = PF_DROP;
		REASON_SET(&reason, PFRES_IPOPTIONS);
		log = 1;
		DPFPRINTF(PF_DEBUG_MISC,
		    ("pf: dropping packet with ip options [hlen=%u]\n",
		    (unsigned int) h->ip_hl));
	}

	if ((s && s->tag) || PF_RTABLEID_IS_VALID(r->rtableid) ||
	    (pd.pktflags & PKTF_FLOW_ID))
		(void) pf_tag_packet(m, pd.pf_mtag, s ? s->tag : 0,
		    r->rtableid, &pd);

	if (action == PF_PASS) {
#if PF_ALTQ
		if (altq_allowed && r->qid) {
			if (pqid || (pd.tos & IPTOS_LOWDELAY))
				pd.pf_mtag->pftag_qid = r->pqid;
			else
				pd.pf_mtag->pftag_qid = r->qid;
		}
#endif /* PF_ALTQ */
#if PF_ECN
		/* add hints for ecn */
		pd.pf_mtag->pftag_hdr = h;
		/* record address family */
		pd.pf_mtag->pftag_flags &= ~PF_TAG_HDR_INET6;
		pd.pf_mtag->pftag_flags |= PF_TAG_HDR_INET;
#endif /* PF_ECN */
		/* record protocol */
		m->m_pkthdr.pkt_proto = pd.proto;
	}

	/*
	 * connections redirected to loopback should not match sockets
	 * bound specifically to loopback due to security implications,
	 * see tcp_input() and in_pcblookup_listen().
	 */
	if (dir == PF_IN && action == PF_PASS && (pd.proto == IPPROTO_TCP ||
	    pd.proto == IPPROTO_UDP) && s != NULL && s->nat_rule.ptr != NULL &&
	    (s->nat_rule.ptr->action == PF_RDR ||
	    s->nat_rule.ptr->action == PF_BINAT) &&
	    (ntohl(pd.dst->v4.s_addr) >> IN_CLASSA_NSHIFT) == IN_LOOPBACKNET)
		pd.pf_mtag->pftag_flags |= PF_TAG_TRANSLATE_LOCALHOST;

	if (log) {
		struct pf_rule *lr;

		if (s != NULL && s->nat_rule.ptr != NULL &&
		    s->nat_rule.ptr->log & PF_LOG_ALL)
			lr = s->nat_rule.ptr;
		else
			lr = r;
		PFLOG_PACKET(kif, h, m, AF_INET, dir, reason, lr, a, ruleset,
		    &pd);
	}

	kif->pfik_bytes[0][dir == PF_OUT][action != PF_PASS] += pd.tot_len;
	kif->pfik_packets[0][dir == PF_OUT][action != PF_PASS]++;

	if (action == PF_PASS || r->action == PF_DROP) {
		dirndx = (dir == PF_OUT);
		r->packets[dirndx]++;
		r->bytes[dirndx] += pd.tot_len;
		if (a != NULL) {
			a->packets[dirndx]++;
			a->bytes[dirndx] += pd.tot_len;
		}
		if (s != NULL) {
			sk = s->state_key;
			if (s->nat_rule.ptr != NULL) {
				s->nat_rule.ptr->packets[dirndx]++;
				s->nat_rule.ptr->bytes[dirndx] += pd.tot_len;
			}
			if (s->src_node != NULL) {
				s->src_node->packets[dirndx]++;
				s->src_node->bytes[dirndx] += pd.tot_len;
			}
			if (s->nat_src_node != NULL) {
				s->nat_src_node->packets[dirndx]++;
				s->nat_src_node->bytes[dirndx] += pd.tot_len;
			}
			dirndx = (dir == sk->direction) ? 0 : 1;
			s->packets[dirndx]++;
			s->bytes[dirndx] += pd.tot_len;
		}
		tr = r;
		nr = (s != NULL) ? s->nat_rule.ptr : pd.nat_rule;
		if (nr != NULL) {
			struct pf_addr *x;
			/*
			 * XXX: we need to make sure that the addresses
			 * passed to pfr_update_stats() are the same than
			 * the addresses used during matching (pfr_match)
			 */
			if (r == &pf_default_rule) {
				tr = nr;
				x = (sk == NULL || sk->direction == dir) ?
				    &pd.baddr : &pd.naddr;
			} else
				x = (sk == NULL || sk->direction == dir) ?
				    &pd.naddr : &pd.baddr;
			if (x == &pd.baddr || s == NULL) {
				/* we need to change the address */
				if (dir == PF_OUT)
					pd.src = x;
				else
					pd.dst = x;
			}
		}
		if (tr->src.addr.type == PF_ADDR_TABLE)
			pfr_update_stats(tr->src.addr.p.tbl, (sk == NULL ||
			    sk->direction == dir) ?
			    pd.src : pd.dst, pd.af,
			    pd.tot_len, dir == PF_OUT, r->action == PF_PASS,
			    tr->src.neg);
		if (tr->dst.addr.type == PF_ADDR_TABLE)
			pfr_update_stats(tr->dst.addr.p.tbl, (sk == NULL ||
			    sk->direction == dir) ? pd.dst : pd.src, pd.af,
			    pd.tot_len, dir == PF_OUT, r->action == PF_PASS,
			    tr->dst.neg);
	}

	VERIFY(m == NULL || pd.mp == NULL || pd.mp == m);

	if (*m0) {
		if (pd.lmw < 0) {
			REASON_SET(&reason, PFRES_MEMORY);
			action = PF_DROP;
		}

		if (action == PF_DROP) {
			m_freem(*m0);
			*m0 = NULL;
			return (PF_DROP);
		}

		*m0 = m;
	}

	if (action == PF_SYNPROXY_DROP) {
		m_freem(*m0);
		*m0 = NULL;
		action = PF_PASS;
	} else if (r->rt)
		/* pf_route can free the mbuf causing *m0 to become NULL */
		pf_route(m0, r, dir, kif->pfik_ifp, s, &pd);

	return (action);
}
#endif /* INET */

#if INET6
#define PF_APPLE_UPDATE_PDESC_IPv6()				\
	do {							\
		if (m && pd.mp && m != pd.mp) {			\
			if (n == m)				\
				n = pd.mp;			\
			m = pd.mp;				\
			h = mtod(m, struct ip6_hdr *);		\
		}						\
	} while (0)

int
pf_test6(int dir, struct ifnet *ifp, struct mbuf **m0,
    struct ether_header *eh, struct ip_fw_args *fwa)
{
#if !DUMMYNET
#pragma unused(fwa)
#endif
	struct pfi_kif		*kif;
	u_short			 action = PF_PASS, reason = 0, log = 0;
	struct mbuf		*m = *m0, *n = NULL;
	struct ip6_hdr		*h;
	struct pf_rule		*a = NULL, *r = &pf_default_rule, *tr, *nr;
	struct pf_state		*s = NULL;
	struct pf_state_key	*sk = NULL;
	struct pf_ruleset	*ruleset = NULL;
	struct pf_pdesc		 pd;
	int			 off, terminal = 0, dirndx, rh_cnt = 0;
	u_int8_t		 nxt;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if (!pf_status.running)
		return (PF_PASS);

	memset(&pd, 0, sizeof (pd));

	if ((pd.pf_mtag = pf_get_mtag(m)) == NULL) {
		DPFPRINTF(PF_DEBUG_URGENT,
		    ("pf_test6: pf_get_mtag returned NULL\n"));
		return (PF_DROP);
	}

	if (pd.pf_mtag->pftag_flags & PF_TAG_GENERATED)
		return (PF_PASS);

	kif = (struct pfi_kif *)ifp->if_pf_kif;

	if (kif == NULL) {
		DPFPRINTF(PF_DEBUG_URGENT,
		    ("pf_test6: kif == NULL, if_name %s\n", ifp->if_name));
		return (PF_DROP);
	}
	if (kif->pfik_flags & PFI_IFLAG_SKIP)
		return (PF_PASS);

	VERIFY(m->m_flags & M_PKTHDR);

	h = mtod(m, struct ip6_hdr *);

	nxt = h->ip6_nxt;
	off = ((caddr_t)h - m->m_data) + sizeof(struct ip6_hdr);
	pd.mp = m;
	pd.lmw = 0;
	pd.pf_mtag = pf_get_mtag(m);
	pd.src = (struct pf_addr *)&h->ip6_src;
	pd.dst = (struct pf_addr *)&h->ip6_dst;
	PF_ACPY(&pd.baddr, dir == PF_OUT ? pd.src : pd.dst, AF_INET6);
	pd.ip_sum = NULL;
	pd.af = AF_INET6;
	pd.proto = nxt;
	pd.proto_variant = 0;
	pd.tos = 0;
	pd.sc = MBUF_SCIDX(mbuf_get_service_class(m));
	pd.tot_len = ntohs(h->ip6_plen) + sizeof(struct ip6_hdr);
	pd.eh = eh;

	if (m->m_pkthdr.pkt_flags & PKTF_FLOW_ID) {
		pd.flowsrc = m->m_pkthdr.pkt_flowsrc;
		pd.flowhash = m->m_pkthdr.pkt_flowid;
		pd.pktflags = (m->m_pkthdr.pkt_flags & PKTF_FLOW_MASK);
	}

	if (m->m_pkthdr.len < (int)sizeof (*h)) {
		action = PF_DROP;
		REASON_SET(&reason, PFRES_SHORT);
		log = 1;
		goto done;
	}

#if DUMMYNET
	if (fwa != NULL && fwa->fwa_pf_rule != NULL)
		goto nonormalize;
#endif /* DUMMYNET */

	/* We do IP header normalization and packet reassembly here */
	action = pf_normalize_ip6(m0, dir, kif, &reason, &pd);
	pd.mp = m = *m0;
	if (action != PF_PASS || pd.lmw < 0) {
		action = PF_DROP;
		goto done;
	}

#if DUMMYNET
nonormalize:
#endif /* DUMMYNET */
	h = mtod(m, struct ip6_hdr *);

#if 1
	/*
	 * we do not support jumbogram yet.  if we keep going, zero ip6_plen
	 * will do something bad, so drop the packet for now.
	 */
	if (htons(h->ip6_plen) == 0) {
		action = PF_DROP;
		REASON_SET(&reason, PFRES_NORM);	/*XXX*/
		goto done;
	}
#endif

	pd.src = (struct pf_addr *)&h->ip6_src;
	pd.dst = (struct pf_addr *)&h->ip6_dst;
	PF_ACPY(&pd.baddr, dir == PF_OUT ? pd.src : pd.dst, AF_INET6);
	pd.ip_sum = NULL;
	pd.af = AF_INET6;
	pd.tos = 0;
	pd.tot_len = ntohs(h->ip6_plen) + sizeof (struct ip6_hdr);
	pd.eh = eh;

	off = ((caddr_t)h - m->m_data) + sizeof (struct ip6_hdr);
	pd.proto = h->ip6_nxt;
	pd.proto_variant = 0;
	pd.mp = m;
	pd.lmw = 0;
	pd.pf_mtag = pf_get_mtag(m);

	do {
		switch (nxt) {
		case IPPROTO_FRAGMENT: {
			struct ip6_frag ip6f;

			pd.flags |= PFDESC_IP_FRAG;
			if (!pf_pull_hdr(m, off, &ip6f, sizeof ip6f, NULL,
			    &reason, pd.af)) {
				DPFPRINTF(PF_DEBUG_MISC,
				    ("pf: IPv6 short fragment header\n"));
				action = PF_DROP;
				REASON_SET(&reason, PFRES_SHORT);
				log = 1;
				goto done;
			}
			pd.proto = nxt = ip6f.ip6f_nxt;
#if DUMMYNET
			/* Traffic goes through dummynet first */
			action = pf_test_dummynet(&r, dir, kif, &m, &pd, fwa);
			if (action == PF_DROP || m == NULL) {
				*m0 = NULL;
				return (action);
			}
#endif /* DUMMYNET */
			action = pf_test_fragment(&r, dir, kif, m, h, &pd, &a,
			    &ruleset);
			if (action == PF_DROP) {
				REASON_SET(&reason, PFRES_FRAG);
				log = 1;
			}
			goto done;
		}
		case IPPROTO_ROUTING:
			++rh_cnt;
			/* FALL THROUGH */

		case IPPROTO_AH:
		case IPPROTO_HOPOPTS:
		case IPPROTO_DSTOPTS: {
			/* get next header and header length */
			struct ip6_ext	opt6;

			if (!pf_pull_hdr(m, off, &opt6, sizeof(opt6),
			    NULL, &reason, pd.af)) {
				DPFPRINTF(PF_DEBUG_MISC,
				    ("pf: IPv6 short opt\n"));
				action = PF_DROP;
				log = 1;
				goto done;
			}
			if (pd.proto == IPPROTO_AH)
				off += (opt6.ip6e_len + 2) * 4;
			else
				off += (opt6.ip6e_len + 1) * 8;
			nxt = opt6.ip6e_nxt;
			/* goto the next header */
			break;
		}
		default:
			terminal++;
			break;
		}
	} while (!terminal);

	/* if there's no routing header, use unmodified mbuf for checksumming */
	if (!n)
		n = m;

	switch (pd.proto) {

	case IPPROTO_TCP: {
		struct tcphdr	th;

		pd.hdr.tcp = &th;
		if (!pf_pull_hdr(m, off, &th, sizeof (th),
		    &action, &reason, AF_INET6)) {
			log = action != PF_PASS;
			goto done;
		}
		pd.p_len = pd.tot_len - off - (th.th_off << 2);
#if DUMMYNET
		/* Traffic goes through dummynet first */
		action = pf_test_dummynet(&r, dir, kif, &m, &pd, fwa);
		if (action == PF_DROP || m == NULL) {
			*m0 = NULL;
			return (action);
		}
#endif /* DUMMYNET */
		action = pf_normalize_tcp(dir, kif, m, 0, off, h, &pd);
		if (pd.lmw < 0)
			goto done;
		PF_APPLE_UPDATE_PDESC_IPv6();
		if (action == PF_DROP)
			goto done;
		action = pf_test_state_tcp(&s, dir, kif, m, off, h, &pd,
		    &reason);
		if (pd.lmw < 0)
			goto done;
		PF_APPLE_UPDATE_PDESC_IPv6();
		if (action == PF_PASS) {
#if NPFSYNC
			pfsync_update_state(s);
#endif /* NPFSYNC */
			r = s->rule.ptr;
			a = s->anchor.ptr;
			log = s->log;
		} else if (s == NULL)
			action = pf_test_rule(&r, &s, dir, kif,
			    m, off, h, &pd, &a, &ruleset, NULL);
		break;
	}

	case IPPROTO_UDP: {
		struct udphdr	uh;

		pd.hdr.udp = &uh;
		if (!pf_pull_hdr(m, off, &uh, sizeof (uh),
		    &action, &reason, AF_INET6)) {
			log = action != PF_PASS;
			goto done;
		}
		if (uh.uh_dport == 0 ||
		    ntohs(uh.uh_ulen) > m->m_pkthdr.len - off ||
		    ntohs(uh.uh_ulen) < sizeof (struct udphdr)) {
			action = PF_DROP;
			REASON_SET(&reason, PFRES_SHORT);
			goto done;
		}
#if DUMMYNET
		/* Traffic goes through dummynet first */
		action = pf_test_dummynet(&r, dir, kif, &m, &pd, fwa);
		if (action == PF_DROP || m == NULL) {
			*m0 = NULL;
			return (action);
		}
#endif /* DUMMYNET */
		action = pf_test_state_udp(&s, dir, kif, m, off, h, &pd,
		    &reason);
		if (pd.lmw < 0)
			goto done;
		PF_APPLE_UPDATE_PDESC_IPv6();
		if (action == PF_PASS) {
#if NPFSYNC
			pfsync_update_state(s);
#endif /* NPFSYNC */
			r = s->rule.ptr;
			a = s->anchor.ptr;
			log = s->log;
		} else if (s == NULL)
			action = pf_test_rule(&r, &s, dir, kif,
			    m, off, h, &pd, &a, &ruleset, NULL);
		break;
	}

	case IPPROTO_ICMPV6: {
		struct icmp6_hdr	ih;

		pd.hdr.icmp6 = &ih;
		if (!pf_pull_hdr(m, off, &ih, sizeof (ih),
		    &action, &reason, AF_INET6)) {
			log = action != PF_PASS;
			goto done;
		}
#if DUMMYNET
		/* Traffic goes through dummynet first */
		action = pf_test_dummynet(&r, dir, kif, &m, &pd, fwa);
		if (action == PF_DROP || m == NULL) {
			*m0 = NULL;
			return (action);
		}
#endif /* DUMMYNET */
		action = pf_test_state_icmp(&s, dir, kif,
		    m, off, h, &pd, &reason);
		if (pd.lmw < 0)
			goto done;
		PF_APPLE_UPDATE_PDESC_IPv6();
		if (action == PF_PASS) {
#if NPFSYNC
			pfsync_update_state(s);
#endif /* NPFSYNC */
			r = s->rule.ptr;
			a = s->anchor.ptr;
			log = s->log;
		} else if (s == NULL)
			action = pf_test_rule(&r, &s, dir, kif,
			    m, off, h, &pd, &a, &ruleset, NULL);
		break;
	}

	case IPPROTO_ESP: {
		struct pf_esp_hdr	esp;

		pd.hdr.esp = &esp;
		if (!pf_pull_hdr(m, off, &esp, sizeof (esp), &action, &reason,
		    AF_INET6)) {
			log = action != PF_PASS;
			goto done;
		}
#if DUMMYNET
		/* Traffic goes through dummynet first */
		action = pf_test_dummynet(&r, dir, kif, &m, &pd, fwa);
		if (action == PF_DROP || m == NULL) {
			*m0 = NULL;
			return (action);
		}
#endif /* DUMMYNET */
		action = pf_test_state_esp(&s, dir, kif, off, &pd);
		if (pd.lmw < 0)
			goto done;
		PF_APPLE_UPDATE_PDESC_IPv6();
		if (action == PF_PASS) {
#if NPFSYNC
			pfsync_update_state(s);
#endif /* NPFSYNC */
			r = s->rule.ptr;
			a = s->anchor.ptr;
			log = s->log;
		} else if (s == NULL)
			action = pf_test_rule(&r, &s, dir, kif,
			    m, off, h, &pd, &a, &ruleset, NULL);
		break;
	}

	case IPPROTO_GRE: {
		struct pf_grev1_hdr	grev1;

		pd.hdr.grev1 = &grev1;
		if (!pf_pull_hdr(m, off, &grev1, sizeof (grev1), &action,
		    &reason, AF_INET6)) {
			log = (action != PF_PASS);
			goto done;
		}
#if DUMMYNET
		/* Traffic goes through dummynet first */
		action = pf_test_dummynet(&r, dir, kif, &m, &pd, fwa);
		if (action == PF_DROP || m == NULL) {
			*m0 = NULL;
			return (action);
		}
#endif /* DUMMYNET */
		if ((ntohs(grev1.flags) & PF_GRE_FLAG_VERSION_MASK) == 1 &&
		    ntohs(grev1.protocol_type) == PF_GRE_PPP_ETHERTYPE) {
			if (ntohs(grev1.payload_length) >
			    m->m_pkthdr.len - off) {
				action = PF_DROP;
				REASON_SET(&reason, PFRES_SHORT);
				goto done;
			}
			action = pf_test_state_grev1(&s, dir, kif, off, &pd);
			if (pd.lmw < 0)
				goto done;
			PF_APPLE_UPDATE_PDESC_IPv6();
			if (action == PF_PASS) {
#if NPFSYNC
				pfsync_update_state(s);
#endif /* NPFSYNC */
				r = s->rule.ptr;
				a = s->anchor.ptr;
				log = s->log;
				break;
			} else if (s == NULL) {
				action = pf_test_rule(&r, &s, dir, kif, m, off,
				    h, &pd, &a, &ruleset, NULL);
				if (action == PF_PASS)
					break;
			}
		}

		/* not GREv1/PPTP, so treat as ordinary GRE... */
	}

	default:
#if DUMMYNET
		/* Traffic goes through dummynet first */
		action = pf_test_dummynet(&r, dir, kif, &m, &pd, fwa);
		if (action == PF_DROP || m == NULL) {
			*m0 = NULL;
			return (action);
		}
#endif /* DUMMYNET */
		action = pf_test_state_other(&s, dir, kif, &pd);
		if (pd.lmw < 0)
			goto done;
		PF_APPLE_UPDATE_PDESC_IPv6();
		if (action == PF_PASS) {
#if NPFSYNC
			pfsync_update_state(s);
#endif /* NPFSYNC */
			r = s->rule.ptr;
			a = s->anchor.ptr;
			log = s->log;
		} else if (s == NULL)
			action = pf_test_rule(&r, &s, dir, kif, m, off, h,
			    &pd, &a, &ruleset, NULL);
		break;
	}

done:
	*m0 = pd.mp;
	PF_APPLE_UPDATE_PDESC_IPv6();

	if (n != m) {
		m_freem(n);
		n = NULL;
	}

	/* handle dangerous IPv6 extension headers. */
	if (action == PF_PASS && rh_cnt &&
	    !((s && s->allow_opts) || r->allow_opts)) {
		action = PF_DROP;
		REASON_SET(&reason, PFRES_IPOPTIONS);
		log = 1;
		DPFPRINTF(PF_DEBUG_MISC,
		    ("pf: dropping packet with dangerous v6 headers\n"));
	}

	if ((s && s->tag) || PF_RTABLEID_IS_VALID(r->rtableid) ||
	    (pd.pktflags & PKTF_FLOW_ID))
		(void) pf_tag_packet(m, pd.pf_mtag, s ? s->tag : 0,
		    r->rtableid, &pd);

	if (action == PF_PASS) {
#if PF_ALTQ
		if (altq_allowed && r->qid) {
			if (pd.tos & IPTOS_LOWDELAY)
				pd.pf_mtag->pftag_qid = r->pqid;
			else
				pd.pf_mtag->pftag_qid = r->qid;
		}
#endif /* PF_ALTQ */
#if PF_ECN
		/* add hints for ecn */
		pd.pf_mtag->pftag_hdr = h;
		/* record address family */
		pd.pf_mtag->pftag_flags &= ~PF_TAG_HDR_INET;
		pd.pf_mtag->pftag_flags |= PF_TAG_HDR_INET6;
#endif /* PF_ECN */
		/* record protocol */
		m->m_pkthdr.pkt_proto = pd.proto;
	}

	if (dir == PF_IN && action == PF_PASS && (pd.proto == IPPROTO_TCP ||
	    pd.proto == IPPROTO_UDP) && s != NULL && s->nat_rule.ptr != NULL &&
	    (s->nat_rule.ptr->action == PF_RDR ||
	    s->nat_rule.ptr->action == PF_BINAT) &&
	    IN6_IS_ADDR_LOOPBACK(&pd.dst->v6))
		pd.pf_mtag->pftag_flags |= PF_TAG_TRANSLATE_LOCALHOST;

	if (log) {
		struct pf_rule *lr;

		if (s != NULL && s->nat_rule.ptr != NULL &&
		    s->nat_rule.ptr->log & PF_LOG_ALL)
			lr = s->nat_rule.ptr;
		else
			lr = r;
		PFLOG_PACKET(kif, h, m, AF_INET6, dir, reason, lr, a, ruleset,
		    &pd);
	}

	kif->pfik_bytes[1][dir == PF_OUT][action != PF_PASS] += pd.tot_len;
	kif->pfik_packets[1][dir == PF_OUT][action != PF_PASS]++;

	if (action == PF_PASS || r->action == PF_DROP) {
		dirndx = (dir == PF_OUT);
		r->packets[dirndx]++;
		r->bytes[dirndx] += pd.tot_len;
		if (a != NULL) {
			a->packets[dirndx]++;
			a->bytes[dirndx] += pd.tot_len;
		}
		if (s != NULL) {
			sk = s->state_key;
			if (s->nat_rule.ptr != NULL) {
				s->nat_rule.ptr->packets[dirndx]++;
				s->nat_rule.ptr->bytes[dirndx] += pd.tot_len;
			}
			if (s->src_node != NULL) {
				s->src_node->packets[dirndx]++;
				s->src_node->bytes[dirndx] += pd.tot_len;
			}
			if (s->nat_src_node != NULL) {
				s->nat_src_node->packets[dirndx]++;
				s->nat_src_node->bytes[dirndx] += pd.tot_len;
			}
			dirndx = (dir == sk->direction) ? 0 : 1;
			s->packets[dirndx]++;
			s->bytes[dirndx] += pd.tot_len;
		}
		tr = r;
		nr = (s != NULL) ? s->nat_rule.ptr : pd.nat_rule;
		if (nr != NULL) {
			struct pf_addr *x;
			/*
			 * XXX: we need to make sure that the addresses
			 * passed to pfr_update_stats() are the same than
			 * the addresses used during matching (pfr_match)
			 */
			if (r == &pf_default_rule) {
				tr = nr;
				x = (s == NULL || sk->direction == dir) ?
				    &pd.baddr : &pd.naddr;
			} else {
				x = (s == NULL || sk->direction == dir) ?
				    &pd.naddr : &pd.baddr;
			}
			if (x == &pd.baddr || s == NULL) {
				if (dir == PF_OUT)
					pd.src = x;
				else
					pd.dst = x;
			}
		}
		if (tr->src.addr.type == PF_ADDR_TABLE)
			pfr_update_stats(tr->src.addr.p.tbl, (sk == NULL ||
			    sk->direction == dir) ? pd.src : pd.dst, pd.af,
			    pd.tot_len, dir == PF_OUT, r->action == PF_PASS,
			    tr->src.neg);
		if (tr->dst.addr.type == PF_ADDR_TABLE)
			pfr_update_stats(tr->dst.addr.p.tbl, (sk == NULL ||
			    sk->direction == dir) ? pd.dst : pd.src, pd.af,
			    pd.tot_len, dir == PF_OUT, r->action == PF_PASS,
			    tr->dst.neg);
	}

#if 0
	if (action == PF_SYNPROXY_DROP) {
		m_freem(*m0);
		*m0 = NULL;
		action = PF_PASS;
	} else if (r->rt)
		/* pf_route6 can free the mbuf causing *m0 to become NULL */
		pf_route6(m0, r, dir, kif->pfik_ifp, s, &pd);
#else
	VERIFY(m == NULL || pd.mp == NULL || pd.mp == m);

	if (*m0) {
		if (pd.lmw < 0) {
			REASON_SET(&reason, PFRES_MEMORY);
			action = PF_DROP;
		}

		if (action == PF_DROP) {
			m_freem(*m0);
			*m0 = NULL;
			return (PF_DROP);
		}

		*m0 = m;
	}

	if (action == PF_SYNPROXY_DROP) {
		m_freem(*m0);
		*m0 = NULL;
		action = PF_PASS;
	} else if (r->rt) {
		if (action == PF_PASS) {
			m = *m0;
			h = mtod(m, struct ip6_hdr *);
		}

		/* pf_route6 can free the mbuf causing *m0 to become NULL */
		pf_route6(m0, r, dir, kif->pfik_ifp, s, &pd);
	}
#endif /* 0 */

	return (action);
}
#endif /* INET6 */

static int
pf_check_congestion(struct ifqueue *ifq)
{
#pragma unused(ifq)
	return (0);
}

void
pool_init(struct pool *pp, size_t size, unsigned int align, unsigned int ioff,
    int flags, const char *wchan, void *palloc)
{
#pragma unused(align, ioff, flags, palloc)
	bzero(pp, sizeof (*pp));
	pp->pool_zone = zinit(size, 1024 * size, PAGE_SIZE, wchan);
	if (pp->pool_zone != NULL) {
		zone_change(pp->pool_zone, Z_EXPAND, TRUE);
		zone_change(pp->pool_zone, Z_CALLERACCT, FALSE);
		pp->pool_hiwat = pp->pool_limit = (unsigned int)-1;
		pp->pool_name = wchan;
	}
}

/* Zones cannot be currently destroyed */
void
pool_destroy(struct pool *pp)
{
#pragma unused(pp)
}

void
pool_sethiwat(struct pool *pp, int n)
{
	pp->pool_hiwat = n;	/* Currently unused */
}

void
pool_sethardlimit(struct pool *pp, int n, const char *warnmess, int ratecap)
{
#pragma unused(warnmess, ratecap)
	pp->pool_limit = n;
}

void *
pool_get(struct pool *pp, int flags)
{
	void *buf;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if (pp->pool_count > pp->pool_limit) {
		DPFPRINTF(PF_DEBUG_NOISY,
		    ("pf: pool %s hard limit reached (%d)\n",
		    pp->pool_name != NULL ? pp->pool_name : "unknown",
		    pp->pool_limit));
		pp->pool_fails++;
		return (NULL);
	}

	buf = zalloc_canblock(pp->pool_zone, (flags & (PR_NOWAIT | PR_WAITOK)));
	if (buf != NULL) {
		pp->pool_count++;
		VERIFY(pp->pool_count != 0);
	}
	return (buf);
}

void
pool_put(struct pool *pp, void *v)
{
	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	zfree(pp->pool_zone, v);
	VERIFY(pp->pool_count != 0);
	pp->pool_count--;
}

struct pf_mtag *
pf_find_mtag(struct mbuf *m)
{
	if (!(m->m_flags & M_PKTHDR))
		return (NULL);

	return (m_pftag(m));
}

struct pf_mtag *
pf_get_mtag(struct mbuf *m)
{
	return (pf_find_mtag(m));
}

uint64_t
pf_time_second(void)
{
	struct timeval t;

	microuptime(&t);
	return (t.tv_sec);
}

uint64_t
pf_calendar_time_second(void)
{
	struct timeval t;

	getmicrotime(&t);
	return (t.tv_sec);
}

static void *
hook_establish(struct hook_desc_head *head, int tail, hook_fn_t fn, void *arg)
{
	struct hook_desc *hd;

	hd = _MALLOC(sizeof(*hd), M_DEVBUF, M_WAITOK);
	if (hd == NULL)
		return (NULL);

	hd->hd_fn = fn;
	hd->hd_arg = arg;
	if (tail)
		TAILQ_INSERT_TAIL(head, hd, hd_list);
	else
		TAILQ_INSERT_HEAD(head, hd, hd_list);

	return (hd);
}

static void
hook_runloop(struct hook_desc_head *head, int flags)
{
	struct hook_desc *hd;

	if (!(flags & HOOK_REMOVE)) {
		if (!(flags & HOOK_ABORT))
			TAILQ_FOREACH(hd, head, hd_list)
				hd->hd_fn(hd->hd_arg);
	} else {
		while (!!(hd = TAILQ_FIRST(head))) {
			TAILQ_REMOVE(head, hd, hd_list);
			if (!(flags & HOOK_ABORT))
				hd->hd_fn(hd->hd_arg);
			if (flags & HOOK_FREE)
				_FREE(hd, M_DEVBUF);
		}
	}
}
