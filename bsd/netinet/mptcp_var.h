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

#ifndef _NETINET_MPTCP_VAR_H_
#define	_NETINET_MPTCP_VAR_H_

#ifdef PRIVATE
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif

#ifdef BSD_KERNEL_PRIVATE
#include <sys/queue.h>
#include <sys/protosw.h>
#include <kern/locks.h>
#include <mach/boolean.h>
#include <netinet/mp_pcb.h>

/*
 * MPTCP Session
 *
 * This is an extension to the multipath PCB specific for MPTCP, protected by
 * the per-PCB mpp_lock (also the socket's lock); MPTCP thread signalling uses
 * its own mpte_thread_lock due to lock ordering constraints.
 */
struct mptses {
	struct mppcb	*mpte_mppcb;		/* back ptr to multipath PCB */
	struct mptcb	*mpte_mptcb;		/* ptr to MPTCP PCB */
	TAILQ_HEAD(, mptopt) mpte_sopts;	/* list of socket options */
	TAILQ_HEAD(, mptsub) mpte_subflows;	/* list of subflows */
	uint16_t	mpte_numflows;		/* # of subflows in list */
	uint16_t	mpte_nummpcapflows;	/* # of MP_CAP subflows */
	sae_associd_t	mpte_associd;		/* MPTCP association ID */
	sae_connid_t	mpte_connid_last;	/* last used connection ID */
	/*
	 * Threading (protected by mpte_thread_lock)
	 */
	decl_lck_mtx_data(, mpte_thread_lock);	/* thread lock */
	struct thread	*mpte_thread;		/* worker thread */
	uint32_t	mpte_thread_active;	/* thread is running */
	uint32_t	mpte_thread_reqs;	/* # of requests for thread */
	struct mptsub	*mpte_active_sub;	/* ptr to last active subf */
	uint8_t	mpte_flags;			/* per mptcp session flags */
	uint8_t	mpte_lost_aid;			/* storing lost address id */
	uint8_t	mpte_addrid_last;		/* storing address id parm */
};

/*
 * Valid values for mpte_flags.
 */
#define	MPTE_SND_REM_ADDR	0x01		/* Send Remove_addr option */

#define	mptompte(mp)	((struct mptses *)(mp)->mpp_pcbe)

#define	MPTE_LOCK_ASSERT_HELD(_mpte)					\
	lck_mtx_assert(&(_mpte)->mpte_mppcb->mpp_lock, LCK_MTX_ASSERT_OWNED)

#define	MPTE_LOCK_ASSERT_NOTHELD(_mpte)					\
	lck_mtx_assert(&(_mpte)->mpte_mppcb->mpp_lock, LCK_MTX_ASSERT_NOTOWNED)

#define	MPTE_LOCK(_mpte)						\
	lck_mtx_lock(&(_mpte)->mpte_mppcb->mpp_lock)

#define	MPTE_LOCK_SPIN(_mpte)						\
	lck_mtx_lock_spin(&(_mpte)->mpte_mppcb->mpp_lock)

#define	MPTE_CONVERT_LOCK(_mpte) do {					\
	MPTE_LOCK_ASSERT_HELD(_mpte);					\
	lck_mtx_convert_spin(&(_mpte)->mpte_mppcb->mpp_lock);		\
} while (0)

#define	MPTE_UNLOCK(_mpte)						\
	lck_mtx_unlock(&(_mpte)->mpte_mppcb->mpp_lock)

/*
 * MPTCP socket options
 */
struct mptopt {
	TAILQ_ENTRY(mptopt)	mpo_entry;	/* glue to other options */
	uint32_t		mpo_flags;	/* see flags below */
	int			mpo_level;	/* sopt_level */
	int			mpo_name;	/* sopt_name */
	int			mpo_intval;	/* sopt_val */
};

#define	MPOF_ATTACHED		0x1	/* attached to MP socket */
#define	MPOF_SUBFLOW_OK		0x2	/* can be issued on subflow socket */
#define	MPOF_INTERIM		0x4	/* has not been issued on any subflow */

/*
 * Structure passed down to TCP during subflow connection establishment
 * containing information pertaining to the MPTCP.
 */
struct mptsub_connreq {
	uint32_t	mpcr_type;	/* see MPTSUB_CONNREQ_* below */
	uint32_t	mpcr_ifscope;	/* ifscope parameter to connectx(2) */
	struct proc	*mpcr_proc;	/* process issuing connectx(2) */
};

/* valid values for mpcr_type */
#define	MPTSUB_CONNREQ_MP_ENABLE	1	/* enable MPTCP */
#define	MPTSUB_CONNREQ_MP_ADD		2	/* join an existing MPTCP */

/*
 * MPTCP subflow
 *
 * Protected by the the per-subflow mpts_lock.  Note that mpts_flags
 * and mpts_evctl are modified via atomic operations.
 */
struct mptsub {
	decl_lck_mtx_data(, mpts_lock);		/* per-subflow lock */
	TAILQ_ENTRY(mptsub)	mpts_entry;	/* glue to peer subflows */
	uint32_t		mpts_refcnt;	/* reference count */
	uint32_t		mpts_flags;	/* see flags below */
	uint32_t		mpts_evctl;	/* subflow control events */
	uint32_t		mpts_family;	/* address family */
	sae_connid_t		mpts_connid;	/* subflow connection ID */
	int			mpts_oldintval;	/* sopt_val before sosetopt  */
	uint32_t		mpts_rank;	/* subflow priority/rank */
	int32_t			mpts_soerror;	/* most recent subflow error */
	struct mptses		*mpts_mpte;	/* back ptr to MPTCP session */
	struct socket		*mpts_socket;	/* subflow socket */
	struct sockaddr		*mpts_src;	/* source address */
	struct sockaddr		*mpts_dst;	/* destination address */
	struct ifnet		*mpts_outif;	/* outbound interface */
	u_int64_t		mpts_sndnxt;	/* next byte to send in mp so */
	u_int32_t		mpts_rel_seq;	/* running count of subflow # */
	struct protosw		*mpts_oprotosw;	/* original protosw */
	struct mptsub_connreq	mpts_mpcr;	/* connection request */
	int32_t			mpts_srtt;	/* tcp's rtt estimate */
	int32_t			mpts_rxtcur;	/* tcp's rto estimate */
	uint32_t		mpts_probesoon;	/* send probe after probeto */
	uint32_t		mpts_probecnt;	/* number of probes sent */
	uint32_t		mpts_maxseg;	/* cached value of t_maxseg */
	uint32_t		mpts_peerswitch;/* no of uses of backup so */
#define MPTSL_WIRED		0x01
#define MPTSL_WIFI		0x02
#define MPTSL_CELL		0x04
	uint32_t		mpts_linktype;	/* wired, wifi, cell */
};

/*
 * Valid values for mpts_flags.  In particular:
 *
 *    - MP_CAPABLE means that the connection is successfully established as
 *	MPTCP and data transfer may occur, but is not yet ready for multipath-
 *	related semantics until MP_READY.  I.e. if this is on the first subflow,
 *	it causes the MPTCP socket to transition to a connected state, except
 *	that additional subflows will not be established; they will be marked
 *	with PENDING and will be processed when the first subflow is marked
 *	with MP_READY.
 *
 *    - MP_READY implies that an MP_CAPABLE connection has been confirmed as
 *	an MPTCP connection.  See notes above.
 *
 *    - MP_DEGRADED implies that the connection has lost its MPTCP capabilities
 *	but data transfer on the MPTCP socket is unaffected.  Any existing
 *	PENDING subflows will be disconnected, and further attempts to connect
 *	additional subflows will be rejected.
 *
 * Note that these are per-subflow flags.  The setting and clearing of MP_READY
 * reflects the state of the MPTCP connection with regards to its multipath
 * semantics, via the MPTCPF_JOIN_READY flag.  Until that flag is set (meaning
 * until at least a subflow is marked with MP_READY), further connectx(2)
 * attempts to join will be queued.  When the flag is cleared (after it has
 * been set), further connectx(2) will fail (and existing queued ones will be
 * aborted) and the MPTCP connection loses all of its multipath semantics.
 *
 * Keep in sync with bsd/dev/dtrace/scripts/mptcp.d.
 */
#define	MPTSF_ATTACHED		0x1	/* attached to MPTCP PCB */
#define	MPTSF_CONNECTING	0x2	/* connection was attempted */
#define	MPTSF_CONNECT_PENDING	0x4	/* will connect when MPTCP is ready */
#define	MPTSF_CONNECTED		0x8	/* connection is established */
#define	MPTSF_DISCONNECTING	0x10	/* disconnection was attempted */
#define	MPTSF_DISCONNECTED	0x20	/* has been disconnected */
#define	MPTSF_MP_CAPABLE	0x40	/* connected as a MPTCP subflow */
#define	MPTSF_MP_READY		0x80	/* MPTCP has been confirmed */
#define	MPTSF_MP_DEGRADED	0x100	/* has lost its MPTCP capabilities */
#define	MPTSF_SUSPENDED		0x200	/* write-side is flow controlled */
#define	MPTSF_BOUND_IF		0x400	/* subflow bound to an interface */
#define	MPTSF_BOUND_IP		0x800	/* subflow bound to a src address */
#define	MPTSF_BOUND_PORT	0x1000	/* subflow bound to a src port */
#define	MPTSF_PREFERRED		0x2000	/* primary/preferred subflow */
#define	MPTSF_SOPT_OLDVAL	0x4000	/* old option value is valid */
#define	MPTSF_SOPT_INPROG	0x8000	/* sosetopt in progress */
#define	MPTSF_DELETEOK		0x10000	/* subflow can be deleted */
#define	MPTSF_FAILINGOVER	0x20000	/* subflow not used for output */
#define	MPTSF_ACTIVE		0x40000	/* subflow currently in use */
#define	MPTSF_MPCAP_CTRSET	0x80000	/* mpcap counter */
#define MPTSF_FASTJ_SEND	0x100000 /* send data after SYN in MP_JOIN */
#define MPTSF_FASTJ_REQD	0x200000 /* fastjoin required */
#define MPTSF_USER_DISCONNECT	0x400000 /* User triggered disconnect */
#define MPTSF_TFO_REQD		0x800000 /* TFO requested */

#define	MPTSF_BITS \
	"\020\1ATTACHED\2CONNECTING\3PENDING\4CONNECTED\5DISCONNECTING" \
	"\6DISCONNECTED\7MP_CAPABLE\10MP_READY\11MP_DEGRADED\12SUSPENDED" \
	"\13BOUND_IF\14BOUND_IP\15BOUND_PORT\16PREFERRED\17SOPT_OLDVAL" \
	"\20SOPT_INPROG\21NOLINGER\22FAILINGOVER\23ACTIVE\24MPCAP_CTRSET" \
	"\25FASTJ_SEND\26FASTJ_REQD\27USER_DISCONNECT"

#define	MPTS_LOCK_ASSERT_HELD(_mpts)					\
	lck_mtx_assert(&(_mpts)->mpts_lock, LCK_MTX_ASSERT_OWNED)

#define	MPTS_LOCK_ASSERT_NOTHELD(_mpts)					\
	lck_mtx_assert(&(_mpts)->mpts_lock, LCK_MTX_ASSERT_NOTOWNED)

#define	MPTS_LOCK(_mpts)						\
	lck_mtx_lock(&(_mpts)->mpts_lock)

#define	MPTS_UNLOCK(_mpts)						\
	lck_mtx_unlock(&(_mpts)->mpts_lock)

#define	MPTS_ADDREF(_mpts)						\
	mptcp_subflow_addref(_mpts, 0)

#define	MPTS_ADDREF_LOCKED(_mpts)					\
	mptcp_subflow_addref(_mpts, 1)

#define	MPTS_REMREF(_mpts)						\
	mptcp_subflow_remref(_mpts)

/*
 * MPTCP states
 * Keep in sync with bsd/dev/dtrace/mptcp.d
 */
typedef enum mptcp_state {
	MPTCPS_CLOSED		= 0,	/* closed */
	MPTCPS_LISTEN		= 1,	/* not yet implemented */
	MPTCPS_ESTABLISHED	= 2,	/* MPTCP connection established */
	MPTCPS_CLOSE_WAIT	= 3,	/* rcvd DFIN, waiting for close */
	MPTCPS_FIN_WAIT_1	= 4,	/* have closed, sent DFIN */
	MPTCPS_CLOSING		= 5,	/* closed xchd DFIN, waiting DFIN ACK */
	MPTCPS_LAST_ACK		= 6,	/* had DFIN and close; await DFIN ACK */
	MPTCPS_FIN_WAIT_2	= 7,	/* have closed, DFIN is acked */
	MPTCPS_TIME_WAIT	= 8,	/* in 2*MSL quiet wait after close */
	MPTCPS_TERMINATE	= 9,	/* terminal state */
} mptcp_state_t;

typedef u_int64_t	mptcp_key_t;
typedef u_int32_t	mptcp_token_t;
typedef u_int8_t	mptcp_addr_id;


/* Address ID list */
struct mptcp_subf_auth_entry {
	LIST_ENTRY(mptcp_subf_auth_entry) msae_next;
	u_int32_t	msae_laddr_rand;	/* Local nonce */
	u_int32_t	msae_raddr_rand;	/* Remote nonce */
	mptcp_addr_id	msae_laddr_id;		/* Local addr ID */
	mptcp_addr_id	msae_raddr_id;		/* Remote addr ID */
};

/*
 * MPTCP Protocol Control Block
 *
 * Protected by per-MPTCP mpt_lock.
 * Keep in sync with bsd/dev/dtrace/scripts/mptcp.d.
 */
struct mptcb {
	decl_lck_mtx_data(, mpt_lock);		/* per MPTCP PCB lock */
	struct mptses	*mpt_mpte;		/* back ptr to MPTCP session */
	mptcp_state_t	mpt_state;		/* MPTCP state */
	u_int32_t	mpt_flags;		/* see flags below */
	u_int32_t	mpt_refcnt;		/* references held on mptcb */
	u_int32_t	mpt_version;		/* MPTCP proto version */
	int		mpt_softerror;		/* error not yet reported */
	/*
	 * Authentication and metadata invariants
	 */
	mptcp_key_t	*mpt_localkey;		/* in network byte order */
	mptcp_key_t	mpt_remotekey;		/* in network byte order */
	mptcp_token_t	mpt_localtoken;		/* HMAC SHA1 of local key */
	mptcp_token_t	mpt_remotetoken;	/* HMAC SHA1 of remote key */

	/*
	 * Timer vars for scenarios where subflow level acks arrive, but
	 * Data ACKs do not.
	 */
	int		mpt_rxtshift;		/* num of consecutive retrans */
	u_int32_t	mpt_rxtstart;		/* time at which rxt started */
	u_int64_t	mpt_rtseq;		/* seq # being tracked */
	u_int32_t	mpt_timer_vals;		/* timer related values */
	u_int32_t	mpt_timewait;		/* timewait */
	/*
	 * Sending side
	 */
	u_int64_t	mpt_snduna;		/* DSN of last unacked byte */
	u_int64_t	mpt_sndnxt;		/* DSN of next byte to send */
	u_int64_t	mpt_sndmax;		/* DSN of max byte sent */
	u_int64_t	mpt_local_idsn;		/* First byte's DSN */
	u_int32_t	mpt_sndwnd;
	/*
	 * Receiving side
	 */
	u_int64_t	mpt_rcvnxt;		/* Next expected DSN */
	u_int64_t	mpt_rcvatmark;		/* mpsocket marker of rcvnxt */
	u_int64_t	mpt_remote_idsn;	/* Peer's IDSN */
	u_int32_t	mpt_rcvwnd;
	LIST_HEAD(, mptcp_subf_auth_entry) mpt_subauth_list; /* address IDs */
	/*
	 * Fastclose
	 */
	u_int64_t	mpt_dsn_at_csum_fail;   /* MPFail Opt DSN */
	u_int32_t	mpt_ssn_at_csum_fail;	/* MPFail Subflow Seq */
	/*
	 * Zombie handling
	 */
#define	MPT_GC_TICKS		(30)
#define MPT_GC_TICKS_FAST	(10)
	int32_t		mpt_gc_ticks;		/* Used for zombie deletion */

	u_int32_t	mpt_notsent_lowat;	/* TCP_NOTSENT_LOWAT support */
	u_int32_t	mpt_peer_version;	/* Version from peer */
};

/* valid values for mpt_flags (see also notes on mpts_flags above) */
#define	MPTCPF_CHECKSUM		0x1	/* checksum DSS option */
#define	MPTCPF_FALLBACK_TO_TCP	0x2	/* Fallback to TCP */
#define	MPTCPF_JOIN_READY	0x4	/* Ready to start 2 or more subflows */
#define	MPTCPF_RECVD_MPFAIL	0x8	/* Received MP_FAIL option */
#define	MPTCPF_PEEL_OFF		0x10	/* Peel off this socket */
#define	MPTCPF_SND_64BITDSN	0x20	/* Send full 64-bit DSN */
#define	MPTCPF_SND_64BITACK	0x40	/* Send 64-bit ACK response */
#define	MPTCPF_RCVD_64BITACK	0x80	/* Received 64-bit Data ACK */
#define	MPTCPF_POST_FALLBACK_SYNC	0x100	/* Post fallback resend data */
#define	MPTCPF_FALLBACK_HEURISTIC	0x200	/* Send SYN without MP_CAPABLE due to heuristic */
#define	MPTCPF_HEURISTIC_TRAC		0x400	/* Tracked this connection in the heuristics as a failure */

#define	MPTCPF_BITS \
	"\020\1CHECKSUM\2FALLBACK_TO_TCP\3JOIN_READY\4RECVD_MPFAIL\5PEEL_OFF" \
	"\6SND_64BITDSN\7SND_64BITACK\10RCVD_64BITACK\11POST_FALLBACK_SYNC" \
	"\12FALLBACK_HEURISTIC\13HEURISTIC_TRAC"

/* valid values for mpt_timer_vals */
#define	MPTT_REXMT		0x01	/* Starting Retransmit Timer */
#define	MPTT_TW			0x02	/* Starting Timewait Timer */
#define	MPTT_FASTCLOSE		0x04	/* Starting Fastclose wait timer */
//#define MPTT_PROBE_TIMER	0x08	/* Timer for probing preferred path */

#define	MPT_LOCK_ASSERT_HELD(_mpt)					\
	lck_mtx_assert(&(_mpt)->mpt_lock, LCK_MTX_ASSERT_OWNED)

#define	MPT_LOCK_ASSERT_NOTHELD(_mpt)					\
	lck_mtx_assert(&(_mpt)->mpt_lock, LCK_MTX_ASSERT_NOTOWNED)

#define	MPT_LOCK(_mpt)							\
	lck_mtx_lock(&(_mpt)->mpt_lock)

#define	MPT_LOCK_SPIN(_mpt)						\
	lck_mtx_lock_spin(&(_mpt)->mpt_lock)

#define	MPT_CONVERT_LOCK(_mpt) do {					\
	MPT_LOCK_ASSERT_HELD(_mpt);					\
	lck_mtx_convert_spin(&(_mpt)->mpt_lock);			\
} while (0)

#define	MPT_UNLOCK(_mpt)						\
	lck_mtx_unlock(&(_mpt)->mpt_lock)

/* events for close FSM */
#define	MPCE_CLOSE		0x1
#define	MPCE_RECV_DATA_ACK	0x2
#define	MPCE_RECV_DATA_FIN	0x4

/* mptcb manipulation */
#define	tptomptp(tp)	((struct mptcb *)((tp)->t_mptcb))

/*
 * MPTCP control block and state structures are allocated along with
 * the MP protocol control block; the folllowing represents the layout.
 */
struct mpp_mtp {
	struct mppcb		mpp;		/* Multipath PCB */
	struct mptses		mpp_ses;	/* MPTCP session */
	struct mptcb		mtcb;		/* MPTCP PCB */
};

#ifdef SYSCTL_DECL
SYSCTL_DECL(_net_inet_mptcp);
#endif /* SYSCTL_DECL */

extern struct mppcbinfo mtcbinfo;
extern struct pr_usrreqs mptcp_usrreqs;

/* Encryption algorithm related definitions */
#define	MPTCP_SHA1_RESULTLEN    20
#define	SHA1_TRUNCATED		8

/* List of valid keys to use for MPTCP connections */
#define	MPTCP_KEY_DIGEST_LEN		(MPTCP_SHA1_RESULTLEN)
#define	MPTCP_MX_KEY_ALLOCS		(256)
#define	MPTCP_KEY_PREALLOCS_MX		(16)
#define	MPTCP_MX_PREALLOC_ZONE_SZ	(8192)

struct mptcp_key_entry {
	LIST_ENTRY(mptcp_key_entry)	mkey_next;
	mptcp_key_t			mkey_value;
#define	MKEYF_FREE	0x0
#define	MKEYF_INUSE	0x1
	u_int32_t			mkey_flags;
	char				mkey_digest[MPTCP_KEY_DIGEST_LEN];
};

/* structure for managing unique key list */
struct mptcp_keys_pool_head {
	struct mptcp_key_entry *lh_first;	/* list of keys */
	u_int32_t	mkph_count;		/* total keys in pool */
	vm_size_t	mkph_key_elm_sz;	/* size of key entry */
	struct zone	*mkph_key_entry_zone;	/* zone for key entry */
	decl_lck_mtx_data(, mkph_lock);		/* lock for key list */
};

/* MPTCP Receive Window */
#define	MPTCP_RWIN_MAX	(1<<16)

/* MPTCP Debugging Levels */
#define	MPTCP_LOGLVL_NONE	0x0	/* No debug logging */
#define	MPTCP_LOGLVL_ERR	0x1	/* Errors in execution are logged */
#define	MPTCP_LOGLVL_LOG	0x2	/* Important logs */
#define	MPTCP_LOGLVL_VERBOSE	0x3	/* Verbose logs */

/* MPTCP sub-components for debug logging */
#define MPTCP_NO_DBG		0x00	/* No areas are logged */
#define MPTCP_STATE_DBG		0x01	/* State machine logging */
#define MPTCP_SOCKET_DBG	0x02	/* Socket call logging */
#define MPTCP_SENDER_DBG	0x04	/* Sender side logging */
#define MPTCP_RECEIVER_DBG	0x08	/* Receiver logging */
#define MPTCP_EVENTS_DBG	0x10	/* Subflow events logging */
#define MPTCP_ALL_DBG		(MPTCP_STATE_DBG | MPTCP_SOCKET_DBG | \
    MPTCP_SENDER_DBG | MPTCP_RECEIVER_DBG | MPTCP_EVENTS_DBG)

/* Mask to obtain 32-bit portion of data sequence number */
#define	MPTCP_DATASEQ_LOW32_MASK	(0xffffffff)
#define	MPTCP_DATASEQ_LOW32(seq)	(seq & MPTCP_DATASEQ_LOW32_MASK)

/* Mask to obtain upper 32-bit portion of data sequence number */
#define	MPTCP_DATASEQ_HIGH32_MASK	(0xffffffff00000000)
#define	MPTCP_DATASEQ_HIGH32(seq)	(seq & MPTCP_DATASEQ_HIGH32_MASK)

/* Mask to obtain 32-bit portion of data ack */
#define	MPTCP_DATAACK_LOW32_MASK	(0xffffffff)
#define	MPTCP_DATAACK_LOW32(ack)	(ack & MPTCP_DATAACK_LOW32_MASK)

/* Mask to obtain upper 32-bit portion of data ack */
#define	MPTCP_DATAACK_HIGH32_MASK	(0xffffffff00000000)
#define	MPTCP_DATAACK_HIGH32(ack)	(ack & MPTCP_DATAACK_HIGH32_MASK)

/*
 * x is the 64-bit data sequence number, y the 32-bit data seq number to be
 * extended. z is y extended to the appropriate 64-bit value.
 * This algorithm is based on the fact that subflow level window sizes are
 * at the maximum 2**30 (in reality, they are a lot lesser). A high throughput
 * application sending on a large number of subflows can in theory have very
 * large MPTCP level send and receive windows. In which case, 64 bit DSNs
 * must be sent in place of 32 bit DSNs on wire. For us, with 2 subflows at
 * 512K each, sequence wraparound detection can be done by checking whether
 * the 32-bit value obtained on wire is 2**31 bytes apart from the stored
 * lower 32-bits of the Data Sequence Number. Bogus DSNs are dropped by
 * comparing against rwnd. Bogus DSNs within rwnd cannot be protected against
 * and are as weak as bogus TCP sequence numbers.
 */
#define	MPTCP_EXTEND_DSN(x, y, z) {					\
	if ((MPTCP_DATASEQ_LOW32(x) > y) &&				\
	    ((((u_int32_t)MPTCP_DATASEQ_LOW32(x)) - (u_int32_t)y) >=	\
	    (u_int32_t)(1 << 31))) {					\
		/*							\
		 * y wrapped around and x and y are 2**31 bytes  apart	\
		 */							\
		z = MPTCP_DATASEQ_HIGH32(x) + 0x100000000;		\
		z |= y;							\
	} else if ((MPTCP_DATASEQ_LOW32(x) < y) &&			\
	    (((u_int32_t)y -						\
	    ((u_int32_t)MPTCP_DATASEQ_LOW32(x))) >=			\
	    (u_int32_t)(1 << 31))) {					\
		/*							\
		 * x wrapped around and x and y are 2**31 apart		\
		 */							\
		z = MPTCP_DATASEQ_HIGH32(x) - 0x100000000;		\
		z |= y;							\
	} else {							\
		z = MPTCP_DATASEQ_HIGH32(x) | y;			\
	}								\
}

#define	mptcplog(x, y, z)	do {					\
	if ((mptcp_dbg_area & y) &&					\
	    (mptcp_dbg_level >= z))					\
		log x;							\
} while (0)

extern int mptcp_enable;	/* Multipath TCP */
extern int mptcp_mpcap_retries;	/* Multipath TCP retries */
extern int mptcp_join_retries;	/* Multipath TCP Join retries */
extern int mptcp_dss_csum;	/* Multipath DSS Option checksum */
extern int mptcp_fail_thresh;	/* Multipath failover thresh of retransmits */
extern int mptcp_subflow_keeptime; /* Multipath subflow TCP_KEEPALIVE opt */
extern int mptcp_mpprio_enable;	/* MP_PRIO option enable/disable */
extern int mptcp_remaddr_enable;/* REMOVE_ADDR option enable/disable */
extern int mptcp_fastjoin;	/* Enable FastJoin */
extern int mptcp_zerortt_fastjoin; /* Enable Data after SYN Fast Join */
extern int mptcp_rwnotify;	/* Enable RW notification on resume */
extern uint32_t mptcp_dbg_level;	/* Multipath TCP debugging level */
extern uint32_t mptcp_dbg_area;	/* Multipath TCP debugging area */

#define MPPCB_LIMIT	32
extern uint32_t mptcp_socket_limit; /* max number of mptcp sockets allowed */
extern uint32_t mptcp_delayed_subf_start; /* delayed cellular subflow start */
extern int tcp_jack_rxmt;	/* Join ACK retransmission value in msecs */

__BEGIN_DECLS
extern void mptcp_init(struct protosw *, struct domain *);
extern int mptcp_ctloutput(struct socket *, struct sockopt *);
extern void *mptcp_sescreate(struct socket *, struct mppcb *);
extern void mptcp_drain(void);
extern struct mptses *mptcp_drop(struct mptses *, struct mptcb *, int);
extern struct mptses *mptcp_close(struct mptses *, struct mptcb *);
extern int mptcp_lock(struct socket *, int, void *);
extern int mptcp_unlock(struct socket *, int, void *);
extern lck_mtx_t *mptcp_getlock(struct socket *, int);
extern void mptcp_thread_signal(struct mptses *);
extern void mptcp_flush_sopts(struct mptses *);
extern int mptcp_setconnorder(struct mptses *, sae_connid_t, uint32_t);
extern int mptcp_getconnorder(struct mptses *, sae_connid_t, uint32_t *);

extern struct mptopt *mptcp_sopt_alloc(int);
extern const char *mptcp_sopt2str(int, int, char *, int);
extern void mptcp_sopt_free(struct mptopt *);
extern void mptcp_sopt_insert(struct mptses *, struct mptopt *);
extern void mptcp_sopt_remove(struct mptses *, struct mptopt *);
extern struct mptopt *mptcp_sopt_find(struct mptses *, struct sockopt *);

extern struct mptsub *mptcp_subflow_alloc(int);
extern void mptcp_subflow_free(struct mptsub *);
extern void mptcp_subflow_addref(struct mptsub *, int);
extern int mptcp_subflow_add(struct mptses *, struct mptsub *,
    struct proc *, uint32_t);
extern void mptcp_subflow_del(struct mptses *, struct mptsub *, boolean_t);
extern void mptcp_subflow_remref(struct mptsub *);
extern int mptcp_subflow_output(struct mptses *, struct mptsub *);
extern void mptcp_subflow_disconnect(struct mptses *, struct mptsub *,
    boolean_t);
extern void mptcp_subflow_sopeeloff(struct mptses *, struct mptsub *,
    struct socket *);
extern int mptcp_subflow_sosetopt(struct mptses *, struct socket *,
    struct mptopt *);
extern int mptcp_subflow_sogetopt(struct mptses *, struct socket *,
    struct mptopt *);

extern void mptcp_input(struct mptses *, struct mbuf *);
extern int mptcp_output(struct mptses *);
extern void mptcp_close_fsm(struct mptcb *, uint32_t);

extern mptcp_token_t mptcp_get_localtoken(void *);
extern mptcp_token_t mptcp_get_remotetoken(void *);

extern u_int64_t mptcp_get_localkey(void *);
extern u_int64_t mptcp_get_remotekey(void *);

extern void mptcp_free_key(mptcp_key_t *key);
extern void mptcp_hmac_sha1(mptcp_key_t, mptcp_key_t, u_int32_t, u_int32_t,
    u_char*, int);
extern void mptcp_get_hmac(mptcp_addr_id, struct mptcb *, u_char *, int);
extern void mptcp_get_rands(mptcp_addr_id, struct mptcb *, u_int32_t *,
    u_int32_t *);
extern void mptcp_set_raddr_rand(mptcp_addr_id, struct mptcb *, mptcp_addr_id,
    u_int32_t);
extern u_int64_t mptcp_get_trunced_hmac(mptcp_addr_id, struct mptcb *mp_tp);
extern void mptcp_generate_token(char *, int, caddr_t, int);
extern void mptcp_generate_idsn(char *, int, caddr_t, int);
extern int mptcp_init_remote_parms(struct mptcb *);
extern boolean_t mptcp_ok_to_keepalive(struct mptcb *);
extern void mptcp_insert_dsn(struct mppcb *, struct mbuf *);
extern void  mptcp_output_getm_dsnmap32(struct socket *, int, uint32_t,
    u_int32_t *, u_int32_t *, u_int16_t *, u_int64_t *);
extern void  mptcp_output_getm_dsnmap64(struct socket *, int, uint32_t,
    u_int64_t *, u_int32_t *, u_int16_t *);
extern void mptcp_send_dfin(struct socket *);
extern void mptcp_act_on_txfail(struct socket *);
extern struct mptsub *mptcp_get_subflow(struct mptses *, struct mptsub *,
    struct mptsub **);
extern struct mptsub *mptcp_get_pending_subflow(struct mptses *,
    struct mptsub *);
extern struct mptsub* mptcp_use_symptoms_hints(struct mptsub*,
    struct mptsub *);
extern int mptcp_get_map_for_dsn(struct socket *, u_int64_t, u_int32_t *);
extern int32_t mptcp_adj_sendlen(struct socket *so, int32_t off, int32_t len);
extern int32_t mptcp_sbspace(struct mptcb *);
extern void mptcp_notify_mpready(struct socket *);
extern void mptcp_notify_mpfail(struct socket *);
extern void mptcp_notify_close(struct socket *);
extern boolean_t mptcp_no_rto_spike(struct socket*);
extern int mptcp_set_notsent_lowat(struct mptses *mpte, int optval);
extern u_int32_t mptcp_get_notsent_lowat(struct mptses *mpte);
extern int mptcp_notsent_lowat_check(struct socket *so);
extern void mptcp_control_register(void);
extern int mptcp_is_wifi_unusable(void);
extern int mptcp_is_cell_unusable(void);
__END_DECLS

#endif /* BSD_KERNEL_PRIVATE */
#ifdef PRIVATE

typedef struct mptcp_flow {
	size_t			flow_len;
	size_t			flow_tcpci_offset;
	uint32_t		flow_flags;
	sae_connid_t		flow_cid;
	struct sockaddr_storage flow_src;
	struct sockaddr_storage flow_dst;
	uint64_t		flow_sndnxt;	/* subflow's sndnxt snapshot */
	uint32_t		flow_relseq;	/* last subflow rel seq# */
	int32_t			flow_soerror;	/* subflow level error */
	uint32_t		flow_probecnt;	/* number of probes sent */
	uint32_t		flow_peerswitch;/* did peer switch */
	conninfo_tcp_t		flow_ci;	/* must be the last field */
} mptcp_flow_t;

typedef struct conninfo_mptcp {
	size_t		mptcpci_len;
	size_t		mptcpci_flow_offset;	/* offsetof first flow */
	size_t		mptcpci_nflows;		/* number of subflows */
	uint32_t	mptcpci_state;		/* MPTCP level state */
	uint32_t	mptcpci_mpte_flags;	/* Session flags */
	uint32_t	mptcpci_flags;		/* MPTCB flags */
	uint32_t	mptcpci_ltoken;		/* local token */
	uint32_t	mptcpci_rtoken;		/* remote token */
	uint32_t        mptcpci_notsent_lowat;	/* NOTSENT_LOWAT */

	/* Send side */
	uint64_t	mptcpci_snduna;		/* DSN of last unacked byte */
	uint64_t	mptcpci_sndnxt;		/* DSN of next byte to send */
	uint64_t	mptcpci_sndmax;		/* DSN of max byte sent */
	uint64_t	mptcpci_lidsn;		/* Local IDSN */
	uint32_t	mptcpci_sndwnd;		/* Send window snapshot */

	/* Receive side */
	uint64_t	mptcpci_rcvnxt;		/* Next expected DSN */
	uint64_t	mptcpci_rcvatmark;	/* Session level rcvnxt */
	uint64_t	mptcpci_ridsn;		/* Peer's IDSN */
	uint32_t	mptcpci_rcvwnd;		/* Receive window */

	uint8_t		mptcpci_mpte_addrid;	/* last addr id */

	mptcp_flow_t	mptcpci_flows[1];
} conninfo_mptcp_t;

/* Use SymptomsD notifications of wifi and cell status in subflow selection */
#define MPTCP_KERN_CTL_NAME    "com.apple.network.advisory"
typedef struct symptoms_advisory {
	union {
		uint32_t	sa_nwk_status_int;
		struct {
			union {
#define SYMPTOMS_ADVISORY_NOCOMMENT    0x00
				uint16_t	sa_nwk_status;
				struct {
#define SYMPTOMS_ADVISORY_WIFI_BAD     0x01
#define SYMPTOMS_ADVISORY_WIFI_OK      0x02
					uint8_t	sa_wifi_status;
#define SYMPTOMS_ADVISORY_CELL_BAD     0x01
#define SYMPTOMS_ADVISORY_CELL_OK      0x02
					uint8_t	sa_cell_status;
				};
			};
			uint16_t	sa_unused;
		};
	};
} symptoms_advisory_t;


#endif /* PRIVATE */
#endif /* _NETINET_MPTCP_VAR_H_ */
