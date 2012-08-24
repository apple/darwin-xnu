/*
 * Copyright (c) 1999-2012 Apple Inc. All rights reserved.
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
#ifndef DLIL_H
#define DLIL_H
#ifdef KERNEL

#include <sys/kernel_types.h>
#include <net/kpi_interface.h>

enum {
	BPF_TAP_DISABLE,
	BPF_TAP_INPUT,
	BPF_TAP_OUTPUT,
	BPF_TAP_INPUT_OUTPUT
};

/*
 * DLIL_DESC_ETYPE2 - native_type must point to 2 byte ethernet raw protocol,
 *                    variants.native_type_length must be set to 2
 * DLIL_DESC_SAP - native_type must point to 3 byte SAP protocol
 *                 variants.native_type_length must be set to 3
 * DLIL_DESC_SNAP - native_type must point to 5 byte SNAP protocol
 *                  variants.native_type_length must be set to 5
 *
 * All protocols must be in Network byte order.
 *
 * Future interface families may define more protocol types they know about.
 * The type implies the offset and context of the protocol data at native_type.
 * The length of the protocol data specified at native_type must be set in
 * variants.native_type_length.
 */
/* Ethernet specific types */
#define DLIL_DESC_ETYPE2	4
#define DLIL_DESC_SAP		5
#define DLIL_DESC_SNAP		6

#ifdef KERNEL_PRIVATE
#include <net/if.h>
#include <net/if_var.h>
#include <net/classq/classq.h>
#include <net/flowadv.h>
#include <sys/kern_event.h>
#include <kern/thread.h>
#include <kern/locks.h>

#ifdef BSD_KERNEL_PRIVATE
/* Operations on timespecs. */
#define	net_timerclear(tvp)	(tvp)->tv_sec = (tvp)->tv_nsec = 0

#define	net_timerisset(tvp)	((tvp)->tv_sec || (tvp)->tv_nsec)

#define	net_timercmp(tvp, uvp, cmp)					\
	(((tvp)->tv_sec == (uvp)->tv_sec) ?				\
	    ((tvp)->tv_nsec cmp (uvp)->tv_nsec) :			\
	    ((tvp)->tv_sec cmp (uvp)->tv_sec))

#define	net_timeradd(tvp, uvp, vvp) do {				\
	(vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec;			\
	(vvp)->tv_nsec = (tvp)->tv_nsec + (uvp)->tv_nsec;		\
	if ((vvp)->tv_nsec >= NSEC_PER_SEC) {				\
		(vvp)->tv_sec++;					\
		(vvp)->tv_nsec -= NSEC_PER_SEC;				\
	}								\
} while (0)

#define	net_timersub(tvp, uvp, vvp) do {				\
	(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;			\
	(vvp)->tv_nsec = (tvp)->tv_nsec - (uvp)->tv_nsec;		\
	if ((vvp)->tv_nsec < 0) {					\
		(vvp)->tv_sec--;					\
		(vvp)->tv_nsec += NSEC_PER_SEC;				\
	}								\
} while (0)

#define	net_timernsec(tvp, nsp) do {					\
	*(nsp) = (tvp)->tv_nsec;					\
	if ((tvp)->tv_sec > 0)						\
		*(nsp) += ((tvp)->tv_sec * NSEC_PER_SEC);		\
} while (0)

#define	net_nsectimer(nsp, tvp) do {					\
	u_int64_t __nsp = *(nsp);					\
	net_timerclear(tvp);						\
	while ((__nsp) >= NSEC_PER_SEC) {				\
		(tvp)->tv_sec++;					\
		(__nsp) -= NSEC_PER_SEC;				\
	}								\
	(tvp)->tv_nsec = (__nsp);					\
} while (0)

struct ifnet;
struct mbuf;
struct ether_header;
struct sockaddr_dl;
struct iff_filter;

#define	DLIL_THREADNAME_LEN	32

/*
 * DLIL input thread info
 */
struct dlil_threading_info {
	decl_lck_mtx_data(, input_lck);
	lck_grp_t	*lck_grp;	/* lock group (for lock stats) */
	u_int32_t	input_waiting;	/* DLIL condition of thread */
	u_int32_t	wtot;		/* # of wakeup requests */
	char		input_name[DLIL_THREADNAME_LEN]; /* name storage */
	struct ifnet	*ifp;		/* pointer to interface */
	class_queue_t	rcvq_pkts;	/* queue of pkts */
	struct ifnet_stat_increment_param stats; /* incremental statistics */
	/*
	 * Thread affinity (workloop and DLIL threads).
	 */
	boolean_t	net_affinity;	/* affinity set is available */
	struct thread	*input_thr;	/* input thread */
	struct thread	*wloop_thr;	/* workloop thread */
	struct thread	*poll_thr;	/* poll thread */
	u_int32_t	tag;		/* affinity tag */
	/*
	 * Opportunistic polling.
	 */
	ifnet_model_t	mode;		/* current mode */
	struct pktcntr	tstats;		/* incremental polling statistics */
	struct if_rxpoll_stats pstats;	/* polling statistics */
#define	rxpoll_offreq	pstats.ifi_poll_off_req
#define	rxpoll_offerr	pstats.ifi_poll_off_err
#define	rxpoll_onreq	pstats.ifi_poll_on_req
#define	rxpoll_onerr	pstats.ifi_poll_on_err
#define	rxpoll_wavg	pstats.ifi_poll_wakeups_avg
#define	rxpoll_wlowat	pstats.ifi_poll_wakeups_lowat
#define	rxpoll_whiwat	pstats.ifi_poll_wakeups_hiwat
#define	rxpoll_pavg	pstats.ifi_poll_packets_avg
#define	rxpoll_pmin	pstats.ifi_poll_packets_min
#define	rxpoll_pmax	pstats.ifi_poll_packets_max
#define	rxpoll_plowat	pstats.ifi_poll_packets_lowat
#define	rxpoll_phiwat	pstats.ifi_poll_packets_hiwat
#define	rxpoll_bavg	pstats.ifi_poll_bytes_avg
#define	rxpoll_bmin	pstats.ifi_poll_bytes_min
#define	rxpoll_bmax	pstats.ifi_poll_bytes_max
#define	rxpoll_blowat	pstats.ifi_poll_bytes_lowat
#define	rxpoll_bhiwat	pstats.ifi_poll_bytes_hiwat
	struct pktcntr	sstats;		/* packets and bytes per sampling */
	struct timespec	mode_holdtime;	/* mode holdtime in nsec */
	struct timespec	mode_lasttime;	/* last mode change time in nsec */
	struct timespec	sample_holdtime; /* sampling holdtime in nsec */
	struct timespec	sample_lasttime; /* last sampling time in nsec */
	struct timespec	dbg_lasttime;	/* last debug message time in nsec */
#if IFNET_INPUT_SANITY_CHK
	/*
	 * For debugging.
	 */
	u_int64_t	input_mbuf_cnt;	/* total # of packets processed */
#endif
};

/*
 * DLIL input thread info (for main/loopback input thread)
 */
struct dlil_main_threading_info {
	struct dlil_threading_info	inp;
	class_queue_t			lo_rcvq_pkts; /* queue of lo0 pkts */
};

/*
 * The following are shared with kpi_protocol.c so that it may wakeup
 * the input thread to run through packets queued for protocol input.
*/
#define	DLIL_INPUT_RUNNING	0x80000000
#define	DLIL_INPUT_WAITING	0x40000000
#define	DLIL_PROTO_REGISTER	0x20000000
#define	DLIL_PROTO_WAITING	0x10000000
#define	DLIL_INPUT_TERMINATE	0x08000000

__private_extern__ struct dlil_threading_info *dlil_main_input_thread;

extern void dlil_init(void);

extern errno_t ifp_if_ioctl(struct ifnet *, unsigned long, void *);

extern errno_t dlil_set_bpf_tap(ifnet_t, bpf_tap_mode, bpf_packet_func);

/*
 * Send arp internal bypasses the check for IPv4LL.
 */
extern errno_t dlil_send_arp_internal(ifnet_t, u_int16_t,
    const struct sockaddr_dl *, const struct sockaddr *,
    const struct sockaddr_dl *, const struct sockaddr *);

/*
 * The following flags used to check if a network thread already
 * owns the lock
 */
#define	NET_THREAD_HELD_PF	0x1	/* thread is holding PF lock */
#define	NET_THREAD_HELD_DOMAIN	0x2     /* thread is holding domain_proto_mtx */

extern errno_t net_thread_check_lock(u_int32_t);
extern void net_thread_set_lock(u_int32_t);
extern void net_thread_unset_lock(u_int32_t);

extern int dlil_output(ifnet_t, protocol_family_t, mbuf_t, void *,
    const struct sockaddr *, int, struct flowadv *);

extern void dlil_input_packet_list(struct ifnet *, struct mbuf *);
extern void dlil_input_packet_list_extended(struct ifnet *, struct mbuf *,
    u_int32_t, ifnet_model_t);

extern errno_t dlil_resolve_multi(struct ifnet *,
    const struct sockaddr *, struct sockaddr *, size_t);

extern errno_t dlil_send_arp(ifnet_t, u_int16_t, const struct sockaddr_dl *,
    const struct sockaddr *, const struct sockaddr_dl *,
    const struct sockaddr *, u_int32_t);

extern int dlil_attach_filter(ifnet_t, const struct iff_filter *,
    interface_filter_t *);
extern void dlil_detach_filter(interface_filter_t);

extern void dlil_proto_unplumb_all(ifnet_t);

extern void dlil_post_msg(struct ifnet *, u_int32_t, u_int32_t,
    struct net_event_data *, u_int32_t);

extern int dlil_alloc_local_stats(struct ifnet *);

/*
 * dlil_if_acquire is obsolete. Use ifnet_allocate.
 */
extern int dlil_if_acquire(u_int32_t, const void *, size_t, struct ifnet **);
/*
 * dlil_if_release is obsolete. The equivalent is called automatically when
 * an interface is detached.
 */
extern void dlil_if_release(struct ifnet *ifp);

extern u_int32_t ifnet_aggressive_drainers;

extern errno_t dlil_if_ref(struct ifnet *);
extern errno_t dlil_if_free(struct ifnet *);

extern void dlil_node_present(struct ifnet *, struct sockaddr *, int32_t, int,
    int, u_int8_t[48]);
extern void dlil_node_absent(struct ifnet *, struct sockaddr *);

#endif /* BSD_KERNEL_PRIVATE */
#endif /* KERNEL_PRIVATE */
#endif /* KERNEL */
#endif /* DLIL_H */
