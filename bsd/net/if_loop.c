/*
 * Copyright (c) 2000-2013 Apple Inc. All rights reserved.
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
/*
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)if_loop.c	8.1 (Berkeley) 6/10/93
 * $FreeBSD: src/sys/net/if_loop.c,v 1.47.2.5 2001/07/03 11:01:41 ume Exp $
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2006 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

/*
 * Loopback interface driver for protocol testing and timing.
 */
#include "loop.h"
#if NLOOP > 0

#if NLOOP != 1
#error "More than one loopback interface is not supported."
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/mcache.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/bpf.h>
#include <sys/malloc.h>

#if INET
#include <netinet/in.h>
#include <netinet/in_var.h>
#endif

#if INET6
#if !INET
#include <netinet/in.h>
#endif
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#endif

#include <net/dlil.h>
#include <net/kpi_protocol.h>

#if CONFIG_MACF_NET
#include <security/mac_framework.h>
#endif

#include <pexpert/pexpert.h>

#define	LOMTU		16384
#define	LOSNDQ_MAXLEN	256

#define	LO_BPF_TAP_OUT(_m) {						\
	if (lo_statics[0].bpf_callback != NULL) {			\
		bpf_tap_out(lo_ifp, DLT_NULL, _m,			\
		    &((struct loopback_header *)_m->m_pkthdr.pkt_hdr)->	\
		    protocol, sizeof (u_int32_t));			\
	}								\
}

#define	LO_BPF_TAP_OUT_MULTI(_m) {					\
	if (lo_statics[0].bpf_callback != NULL) {			\
		struct mbuf *_n;					\
		for (_n = _m; _n != NULL; _n = _n->m_nextpkt)		\
			LO_BPF_TAP_OUT(_n);				\
	}								\
}

struct lo_statics_str {
	int		bpf_mode;
	bpf_packet_func	bpf_callback;
};

static struct lo_statics_str lo_statics[NLOOP];
static int lo_txstart = 0;

struct ifnet *lo_ifp = NULL;

struct	loopback_header {
	protocol_family_t	protocol;
};

/* Local forward declerations */
void loopattach(void);
static errno_t lo_demux(struct ifnet *, struct mbuf *, char *,
    protocol_family_t *);
static errno_t
lo_framer(struct ifnet *, struct mbuf **, const struct sockaddr *,
    const char *, const char *, u_int32_t *, u_int32_t *);
static errno_t lo_add_proto(struct ifnet *, protocol_family_t,
    const struct ifnet_demux_desc *, u_int32_t);
static errno_t lo_del_proto(struct ifnet *, protocol_family_t);
static int lo_output(struct ifnet *, struct mbuf *);
static errno_t lo_pre_enqueue(struct ifnet *, struct mbuf *);
static void lo_start(struct ifnet *);
static errno_t lo_pre_output(struct ifnet *, protocol_family_t, struct mbuf **,
    const struct sockaddr *, void *, char *, char *);
static errno_t lo_input(struct ifnet *, protocol_family_t, struct mbuf *);
static void lo_rtrequest(int, struct rtentry *, struct sockaddr *);
static errno_t lo_ioctl(struct ifnet *, u_long, void *);
static errno_t lo_attach_proto(struct ifnet *, protocol_family_t);
static void lo_reg_if_mods(void);
static errno_t lo_set_bpf_tap(struct ifnet *, bpf_tap_mode, bpf_packet_func);
static int sysctl_dequeue_max SYSCTL_HANDLER_ARGS;
static int sysctl_sched_model SYSCTL_HANDLER_ARGS;
static int sysctl_dequeue_scidx SYSCTL_HANDLER_ARGS;

SYSCTL_DECL(_net_link);

SYSCTL_NODE(_net_link, OID_AUTO, loopback, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "loopback interface");

static u_int32_t lo_dequeue_max = LOSNDQ_MAXLEN;
SYSCTL_PROC(_net_link_loopback, OID_AUTO, max_dequeue,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &lo_dequeue_max, LOSNDQ_MAXLEN,
    sysctl_dequeue_max, "I", "Maximum number of packets dequeued at a time");

static u_int32_t lo_sched_model = IFNET_SCHED_MODEL_NORMAL;
SYSCTL_PROC(_net_link_loopback, OID_AUTO, sched_model,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &lo_sched_model,
    IFNET_SCHED_MODEL_NORMAL, sysctl_sched_model, "I", "Scheduling model");

static u_int32_t lo_dequeue_sc = MBUF_SC_BE;
static int lo_dequeue_scidx = MBUF_SCIDX(MBUF_SC_BE);
SYSCTL_PROC(_net_link_loopback, OID_AUTO, dequeue_sc,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &lo_dequeue_scidx,
    MBUF_SC_BE, sysctl_dequeue_scidx, "I", "Dequeue a specific SC index");

static errno_t
lo_demux(struct ifnet *ifp, struct mbuf *m, char *frame_header,
    protocol_family_t *protocol_family)
{
#pragma unused(ifp, m)
	struct loopback_header *header =
	    (struct loopback_header *)(void *)frame_header;

	*protocol_family = header->protocol;

	return (0);
}

static errno_t
lo_framer(struct ifnet *ifp, struct mbuf **m, const struct sockaddr *dest,
    const char *dest_linkaddr, const char *frame_type,
    u_int32_t *prepend_len, u_int32_t *postpend_len)
{
#pragma unused(ifp, dest, dest_linkaddr)
	struct loopback_header  *header;

	M_PREPEND(*m, sizeof (struct loopback_header), M_WAITOK, 1);
	if (*m == NULL) {
		/* Tell caller not to try to free passed-in mbuf */
		return (EJUSTRETURN);
	}

	if (prepend_len != NULL)
		*prepend_len = sizeof (struct loopback_header);
	if (postpend_len != NULL)
		*postpend_len = 0;

	header = mtod(*m, struct loopback_header *);
	bcopy(frame_type, &header->protocol, sizeof (u_int32_t));
	return (0);
}

static errno_t
lo_add_proto(struct ifnet *interface, protocol_family_t protocol_family,
    const struct ifnet_demux_desc *demux_array, u_int32_t demux_count)
{
#pragma unused(interface, protocol_family, demux_array, demux_count)
	return (0);
}

static errno_t
lo_del_proto(struct ifnet *ifp, protocol_family_t protocol)
{
#pragma unused(ifp, protocol)
	return (0);
}

static void
lo_tx_compl(struct ifnet *ifp, struct mbuf *m)
{
	errno_t error;

	if ((ifp->if_xflags & IFXF_TIMESTAMP_ENABLED) != 0) {
		boolean_t requested;

		error = mbuf_get_timestamp_requested(m, &requested);
		if (requested) {
			struct timespec now;
			u_int64_t ts;

			nanouptime(&now);
			net_timernsec(&now, &ts);

			error = mbuf_set_timestamp(m, ts, TRUE);
			if (error != 0)
				printf("%s: mbuf_set_timestamp() failed %d\n",
					__func__, error);
		}
	}
	error = mbuf_set_status(m, KERN_SUCCESS);
	if (error != 0)
		printf("%s: mbuf_set_status() failed %d\n",
			__func__, error);

	ifnet_tx_compl(ifp, m);
}

/*
 * Output callback.
 *
 * This routine is called only when lo_txstart is disabled.
 */
static int
lo_output(struct ifnet *ifp, struct mbuf *m_list)
{
	struct mbuf *m, *m_tail = NULL;
	struct ifnet_stat_increment_param s;
	u_int32_t cnt = 0, len = 0;

	bzero(&s, sizeof(s));

	for (m = m_list; m; m = m->m_nextpkt) {
		VERIFY(m->m_flags & M_PKTHDR);
		cnt++;
		len += m->m_pkthdr.len;

		/*
		 * Don't overwrite the rcvif field if it is in use.
		 *  This is used to match multicast packets, sent looping
		 *  back, with the appropriate group record on input.
		 */
		if (m->m_pkthdr.rcvif == NULL)
			m->m_pkthdr.rcvif = ifp;

		m->m_pkthdr.pkt_flags |= PKTF_LOOP;
		m->m_pkthdr.pkt_hdr = mtod(m, char *);

		/* loopback checksums are always OK */
		m->m_pkthdr.csum_data = 0xffff;
		m->m_pkthdr.csum_flags =
		    CSUM_DATA_VALID | CSUM_PSEUDO_HDR |
		    CSUM_IP_CHECKED | CSUM_IP_VALID;

		m_adj(m, sizeof (struct loopback_header));

		LO_BPF_TAP_OUT(m);
		if (m->m_nextpkt == NULL) {
			m_tail = m;
		}
		lo_tx_compl(ifp, m);
	}

	s.packets_in = cnt;
	s.packets_out = cnt;
	s.bytes_in = len;
	s.bytes_out = len;

	return (ifnet_input_extended(ifp, m_list, m_tail, &s));
}

/*
 * Pre-enqueue callback.
 *
 * This routine is called only when lo_txstart is enabled.
 */
static errno_t
lo_pre_enqueue(struct ifnet *ifp, struct mbuf *m0)
{
	struct mbuf *m = m0, *n;
	int error = 0;

	while (m != NULL) {
		VERIFY(m->m_flags & M_PKTHDR);

		n = m->m_nextpkt;
		m->m_nextpkt = NULL;

		/*
		 * Don't overwrite the rcvif field if it is in use.
		 *  This is used to match multicast packets, sent looping
		 *  back, with the appropriate group record on input.
		 */
		if (m->m_pkthdr.rcvif == NULL)
			m->m_pkthdr.rcvif = ifp;

		m->m_pkthdr.pkt_flags |= PKTF_LOOP;
		m->m_pkthdr.pkt_hdr = mtod(m, char *);

		/* loopback checksums are always OK */
		m->m_pkthdr.csum_data = 0xffff;
		m->m_pkthdr.csum_flags =
		    CSUM_DATA_VALID | CSUM_PSEUDO_HDR |
		    CSUM_IP_CHECKED | CSUM_IP_VALID;

		m_adj(m, sizeof (struct loopback_header));

		/*
		 * Let the callee free it in case of error,
		 * and perform any necessary accounting.
		 */
		(void) ifnet_enqueue(ifp, m);

		m = n;
	}

	return (error);
}

/*
 * Start output callback.
 *
 * This routine is invoked by the start worker thread; because we never call
 * it directly, there is no need do deploy any serialization mechanism other
 * than what's already used by the worker thread, i.e. this is already single
 * threaded.
 *
 * This routine is called only when lo_txstart is enabled.
 */
static void
lo_start(struct ifnet *ifp)
{
	struct ifnet_stat_increment_param s;

	bzero(&s, sizeof (s));

	for (;;) {
		struct mbuf *m = NULL, *m_tail = NULL;
		u_int32_t cnt, len = 0;

		if (lo_sched_model == IFNET_SCHED_MODEL_NORMAL) {
			if (ifnet_dequeue_multi(ifp, lo_dequeue_max, &m,
			    &m_tail, &cnt, &len) != 0)
				break;
		} else {
			if (ifnet_dequeue_service_class_multi(ifp,
			    lo_dequeue_sc, lo_dequeue_max, &m,
			    &m_tail, &cnt, &len) != 0)
				break;
		}

		LO_BPF_TAP_OUT_MULTI(m);
		lo_tx_compl(ifp, m);

		/* stats are required for extended variant */
		s.packets_in = cnt;
		s.packets_out = cnt;
		s.bytes_in = len;
		s.bytes_out = len;

		(void) ifnet_input_extended(ifp, m, m_tail, &s);
	}
}

/*
 * This is a common pre-output route used by INET and INET6. This could
 * (should?) be split into separate pre-output routines for each protocol.
 */
static errno_t
lo_pre_output(struct ifnet *ifp, protocol_family_t protocol_family,
    struct mbuf **m, const struct sockaddr *dst, void *route, char *frame_type,
    char *dst_addr)
{
#pragma unused(ifp, dst, dst_addr)
	struct rtentry *rt = route;

	VERIFY((*m)->m_flags & M_PKTHDR);

	(*m)->m_flags |= M_LOOP;

	if (rt != NULL) {
		u_int32_t rt_flags = rt->rt_flags;
		if (rt_flags & (RTF_REJECT | RTF_BLACKHOLE)) {
			if (rt_flags & RTF_BLACKHOLE) {
				m_freem(*m);
				return (EJUSTRETURN);
			} else {
				return ((rt_flags & RTF_HOST) ?
				    EHOSTUNREACH : ENETUNREACH);
			}
		}
	}

	bcopy(&protocol_family, frame_type, sizeof (protocol_family));

	return (0);
}

/*
 *  lo_input - This should work for all attached protocols that use the
 *             ifq/schednetisr input mechanism.
 */
static errno_t
lo_input(struct ifnet *ifp, protocol_family_t protocol_family, struct mbuf *m)
{
#pragma unused(ifp, protocol_family)

	if ((ifp->if_xflags & IFXF_TIMESTAMP_ENABLED) != 0) {
		errno_t error;
		struct timespec now;
		u_int64_t ts;

		nanouptime(&now);
		net_timernsec(&now, &ts);

		error = mbuf_set_timestamp(m, ts, TRUE);
		if (error != 0)
			printf("%s: mbuf_set_timestamp() failed %d\n",
				__func__, error);
	}

	if (proto_input(protocol_family, m) != 0)
		m_freem(m);
	return (0);
}

/* ARGSUSED */
static void
lo_rtrequest(int cmd, struct rtentry *rt, struct sockaddr *sa)
{
#pragma unused(cmd, sa)
	if (rt != NULL) {
		RT_LOCK_ASSERT_HELD(rt);
		rt->rt_rmx.rmx_mtu = rt->rt_ifp->if_mtu; /* for ISO */
		/*
		 * For optimal performance, the send and receive buffers
		 * should be at least twice the MTU plus a little more for
		 * overhead.
		 */
		rt->rt_rmx.rmx_recvpipe = rt->rt_rmx.rmx_sendpipe = 3 * LOMTU;
	}
}

/*
 * Process an ioctl request.
 */
static errno_t
lo_ioctl(struct ifnet *ifp, u_long cmd, void *data)
{
	int error = 0;

	switch (cmd) {

	case SIOCSIFADDR: {		/* struct ifaddr pointer */
		struct ifaddr *ifa = data;

		ifnet_set_flags(ifp, IFF_UP|IFF_RUNNING, IFF_UP|IFF_RUNNING);
		IFA_LOCK_SPIN(ifa);
		ifa->ifa_rtrequest = lo_rtrequest;
		IFA_UNLOCK(ifa);
		/*
		 * Everything else is done at a higher level.
		 */
		break;
	}

	case SIOCADDMULTI:		/* struct ifreq */
	case SIOCDELMULTI: {		/* struct ifreq */
		struct ifreq *ifr = data;

		if (ifr == NULL) {
			error = EAFNOSUPPORT;		/* XXX */
			break;
		}
		switch (ifr->ifr_addr.sa_family) {

#if INET
		case AF_INET:
			break;
#endif
#if INET6
		case AF_INET6:
			break;
#endif

		default:
			error = EAFNOSUPPORT;
			break;
		}
		break;
	}

	case SIOCSIFMTU: {		/* struct ifreq */
		struct ifreq *ifr = data;

		bcopy(&ifr->ifr_mtu, &ifp->if_mtu, sizeof (int));
		break;
	}

	case SIOCSIFFLAGS:		/* struct ifreq */
	case SIOCSIFTIMESTAMPENABLE:
	case SIOCSIFTIMESTAMPDISABLE:
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}
	return (error);
}
#endif /* NLOOP > 0 */


static errno_t
lo_attach_proto(struct ifnet *ifp, protocol_family_t protocol_family)
{
	struct ifnet_attach_proto_param_v2	proto;
	errno_t							result = 0;

	bzero(&proto, sizeof (proto));
	proto.input = lo_input;
	proto.pre_output = lo_pre_output;

	result = ifnet_attach_protocol_v2(ifp, protocol_family, &proto);

	if (result && result != EEXIST) {
		printf("lo_attach_proto: ifnet_attach_protocol for %u "
		    "returned=%d\n", protocol_family, result);
	}

	return (result);
}

static void
lo_reg_if_mods(void)
{
	int error;

	/* Register protocol registration functions */
	if ((error = proto_register_plumber(PF_INET,
	    APPLE_IF_FAM_LOOPBACK, lo_attach_proto, NULL)) != 0)
		printf("proto_register_plumber failed for AF_INET "
		    "error=%d\n", error);

	if ((error = proto_register_plumber(PF_INET6,
	    APPLE_IF_FAM_LOOPBACK, lo_attach_proto, NULL)) != 0)
		printf("proto_register_plumber failed for AF_INET6 "
		    "error=%d\n", error);
}

static errno_t
lo_set_bpf_tap(struct ifnet *ifp, bpf_tap_mode mode,
    bpf_packet_func bpf_callback)
{
	VERIFY(ifp == lo_ifp);

	lo_statics[0].bpf_mode = mode;

	switch (mode) {
		case BPF_TAP_DISABLE:
		case BPF_TAP_INPUT:
			lo_statics[0].bpf_callback = NULL;
			break;

		case BPF_TAP_OUTPUT:
		case BPF_TAP_INPUT_OUTPUT:
			lo_statics[0].bpf_callback = bpf_callback;
			break;
	}

	return (0);
}

/* ARGSUSED */
void
loopattach(void)
{
	struct ifnet_init_eparams lo_init;
	errno_t	result = 0;

	PE_parse_boot_argn("lo_txstart", &lo_txstart, sizeof (lo_txstart));

	lo_reg_if_mods();

	lo_statics[0].bpf_callback = NULL;
	lo_statics[0].bpf_mode = BPF_TAP_DISABLE;

	bzero(&lo_init, sizeof (lo_init));
	lo_init.ver			= IFNET_INIT_CURRENT_VERSION;
	lo_init.len			= sizeof (lo_init);
	lo_init.sndq_maxlen		= LOSNDQ_MAXLEN;
	if (lo_txstart) {
		lo_init.flags		= 0;
		lo_init.pre_enqueue	= lo_pre_enqueue;
		lo_init.start		= lo_start;
		lo_init.output_sched_model = lo_sched_model;
	} else {
		lo_init.flags		= IFNET_INIT_LEGACY;
		lo_init.output		= lo_output;
	}
	lo_init.flags			|= IFNET_INIT_NX_NOAUTO;
	lo_init.name			= "lo";
	lo_init.unit			= 0;
	lo_init.family			= IFNET_FAMILY_LOOPBACK;
	lo_init.type			= IFT_LOOP;
	lo_init.demux			= lo_demux;
	lo_init.add_proto		= lo_add_proto;
	lo_init.del_proto		= lo_del_proto;
	lo_init.framer_extended		= lo_framer;
	lo_init.softc			= &lo_statics[0];
	lo_init.ioctl			= lo_ioctl;
	lo_init.set_bpf_tap		= lo_set_bpf_tap;

	result = ifnet_allocate_extended(&lo_init, &lo_ifp);
	if (result != 0) {
		panic("%s: couldn't allocate loopback ifnet (%d)\n",
		    __func__, result);
		/* NOTREACHED */
	}

	ifnet_set_mtu(lo_ifp, LOMTU);
	ifnet_set_flags(lo_ifp, IFF_LOOPBACK | IFF_MULTICAST,
	    IFF_LOOPBACK | IFF_MULTICAST);
	ifnet_set_offload(lo_ifp,
	    IFNET_CSUM_IP | IFNET_CSUM_TCP | IFNET_CSUM_UDP |
	    IFNET_CSUM_TCPIPV6 | IFNET_CSUM_UDPIPV6 | IFNET_IPV6_FRAGMENT |
	    IFNET_CSUM_FRAGMENT | IFNET_IP_FRAGMENT | IFNET_MULTIPAGES |
	    IFNET_TX_STATUS | IFNET_SW_TIMESTAMP);
	ifnet_set_hdrlen(lo_ifp, sizeof (struct loopback_header));
	ifnet_set_eflags(lo_ifp, IFEF_SENDLIST, IFEF_SENDLIST);

#if CONFIG_MACF_NET
	mac_ifnet_label_init(ifp);
#endif

	result = ifnet_attach(lo_ifp, NULL);
	if (result != 0) {
		panic("%s: couldn't attach loopback ifnet (%d)\n",
		    __func__, result);
		/* NOTREACHED */
	}
	bpfattach(lo_ifp, DLT_NULL, sizeof (u_int32_t));
}

static int
sysctl_dequeue_max SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	u_int32_t i;
	int err;

	i = lo_dequeue_max;

	err = sysctl_handle_int(oidp, &i, 0, req);
	if (err != 0 || req->newptr == USER_ADDR_NULL)
		return (err);

	if (i < 1)
		i = 1;
	else if (i > LOSNDQ_MAXLEN)
		i = LOSNDQ_MAXLEN;

	lo_dequeue_max = i;

	return (err);
}

static int
sysctl_sched_model SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	u_int32_t i;
	int err;

	i = lo_sched_model;

	err = sysctl_handle_int(oidp, &i, 0, req);
	if (err != 0 || req->newptr == USER_ADDR_NULL)
		return (err);

	switch (i) {
	case IFNET_SCHED_MODEL_NORMAL:
	case IFNET_SCHED_MODEL_DRIVER_MANAGED:
	case IFNET_SCHED_MODEL_FQ_CODEL:
		break;

	default:
		err = EINVAL;
		break;
	}

	if (err == 0 && (err = ifnet_set_output_sched_model(lo_ifp, i)) == 0)
		lo_sched_model = i;

	return (err);
}

static int
sysctl_dequeue_scidx SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	u_int32_t i;
	int err;

	i = lo_dequeue_scidx;

	err = sysctl_handle_int(oidp, &i, 0, req);
	if (err != 0 || req->newptr == USER_ADDR_NULL)
		return (err);

	if (!MBUF_VALID_SCIDX(i))
		return (EINVAL);

	if (lo_sched_model != IFNET_SCHED_MODEL_DRIVER_MANAGED)
		return (ENODEV);

	lo_dequeue_sc = m_service_class_from_idx(i);
	lo_dequeue_scidx = MBUF_SCIDX(lo_dequeue_sc);

	return (err);
}
