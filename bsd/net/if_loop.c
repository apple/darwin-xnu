/*
 * Copyright (c) 2000-2010 Apple Inc. All rights reserved.
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/mcache.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/bpf.h>
#include <sys/malloc.h>

#if	INET
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

#if NETAT
extern struct ifqueue atalkintrq;
#endif

#if CONFIG_MACF_NET
#include <security/mac_framework.h>
#endif

#define NLOOP_ATTACHMENTS (NLOOP * 12)

struct lo_statics_str {
	int				bpf_mode;
	bpf_packet_func	bpf_callback;
};

void loopattach(void);

static struct lo_statics_str lo_statics[NLOOP];
int loopattach_done = 0; /* used to sync ip6_init2 loopback configuration */

#ifdef TINY_LOMTU
#define	LOMTU	(1024+512)
#else
#define LOMTU	16384
#endif

ifnet_t	lo_ifp = NULL;

struct	loopback_header {
	protocol_family_t	protocol;
};

static void lo_reg_if_mods(void);

/* Local forward declerations */

static errno_t
lo_demux(
    __unused ifnet_t	ifp,
    __unused mbuf_t		m,
    char				*frame_header,
    protocol_family_t	*protocol_family)
{
	struct loopback_header *header = (struct loopback_header *)frame_header;
	
	*protocol_family = header->protocol;
	
	return 0;
}


static errno_t
lo_framer(
    __unused ifnet_t				ifp,
    mbuf_t							*m,
    __unused const struct sockaddr	*dest,
    __unused const char            	*dest_linkaddr,
    const char						*frame_type)
{
	struct loopback_header  *header;

	M_PREPEND(*m, sizeof(struct loopback_header), M_WAITOK);
	if (*m == NULL)
		return EJUSTRETURN; /* Tell caller not to try to free passed-in mbuf */
	header = mtod(*m, struct loopback_header*);
	header->protocol = *(const u_int32_t*)frame_type;
	return 0;
}

static errno_t
lo_add_proto(
    __unused ifnet_t						interface,
	__unused protocol_family_t				protocol_family,
	__unused const struct ifnet_demux_desc	*demux_array,
	__unused u_int32_t						demux_count)
{
    return 0;
}


static errno_t
lo_del_proto(
	__unused ifnet_t			ifp,
	__unused protocol_family_t	protocol)
{
	return 0;
}

static int
lo_output(
	ifnet_t	ifp,
	mbuf_t	m_list)
{
	mbuf_t	m;
	
	for (m = m_list; m; m = m->m_nextpkt) {
		if ((m->m_flags & M_PKTHDR) == 0)
			panic("lo_output: no HDR");

		/*
		 * Don't overwrite the rcvif field if it is in use.
		 *  This is used to match multicast packets, sent looping
		 *  back, with the appropriate group record on input.
		 */
		if (m->m_pkthdr.rcvif == NULL)
			m->m_pkthdr.rcvif = ifp;

		atomic_add_64(&ifp->if_ibytes, m->m_pkthdr.len);
		atomic_add_64(&ifp->if_obytes, m->m_pkthdr.len);

		atomic_add_64(&ifp->if_opackets, 1);
		atomic_add_64(&ifp->if_ipackets, 1);

		m->m_pkthdr.header = mtod(m, char *);
		if (apple_hwcksum_tx != 0) {
			/* loopback checksums are always OK */
			m->m_pkthdr.csum_data = 0xffff;
			m->m_pkthdr.csum_flags = CSUM_DATA_VALID | CSUM_PSEUDO_HDR |
				CSUM_IP_CHECKED | CSUM_IP_VALID;
		}
		m_adj(m, sizeof(struct loopback_header));

		{
			/* We need to prepend the address family as a four byte field. */
			u_int32_t protocol_family =
				((struct loopback_header*)m->m_pkthdr.header)->protocol;
		
			bpf_tap_out(ifp, DLT_NULL, m, &protocol_family, sizeof(protocol_family));
		}
	}

	return ifnet_input(ifp, m_list, NULL);
}


/*
 * This is a common pre-output route used by INET and INET6. This could
 * (should?) be split into separate pre-output routines for each protocol.
 */

static errno_t
lo_pre_output(
	__unused ifnet_t	ifp,
	protocol_family_t	protocol_family,
	mbuf_t				*m,
	__unused const struct sockaddr	*dst,
	void				*route,
	char				*frame_type,
	__unused char		*dst_addr)

{
	register struct rtentry *rt = route;

	(*m)->m_flags |= M_LOOP;

	if (((*m)->m_flags & M_PKTHDR) == 0)
		panic("looutput no HDR");

	if (rt != NULL) {
		u_int32_t rt_flags = rt->rt_flags;
		if (rt_flags & (RTF_REJECT | RTF_BLACKHOLE)) {
			if (rt_flags & RTF_BLACKHOLE) {
				m_freem(*m);
				return EJUSTRETURN;
			} else {
				return ((rt_flags & RTF_HOST) ?
				    EHOSTUNREACH : ENETUNREACH);
			}
		}
	}

	*(protocol_family_t*)frame_type = protocol_family;

	return 0;
}

/*
 *  lo_input - This should work for all attached protocols that use the
 *             ifq/schednetisr input mechanism.
 */
static errno_t
lo_input(
	__unused ifnet_t			ifp,
	__unused protocol_family_t	protocol_family,
	mbuf_t						m)
{
	if (proto_input(protocol_family, m) != 0)
		m_freem(m);
	return (0);
}




/* ARGSUSED */
static void
lortrequest(
	__unused int cmd,
	struct rtentry *rt,
	__unused struct sockaddr *sa)
{
	if (rt != NULL) {
		RT_LOCK_ASSERT_HELD(rt);
		rt->rt_rmx.rmx_mtu = rt->rt_ifp->if_mtu; /* for ISO */
		/*
		 * For optimal performance, the send and receive buffers
		 * should be at least twice the MTU plus a little more for
		 * overhead.
		 */
		rt->rt_rmx.rmx_recvpipe = 
			rt->rt_rmx.rmx_sendpipe = 3 * LOMTU;
	}
}

/*
 * Process an ioctl request.
 */
static errno_t
loioctl(
	ifnet_t		ifp,
	u_long		cmd,
	void*		data)
{
	register struct ifaddr *ifa;
	register struct ifreq *ifr = (struct ifreq *)data;
	register int error = 0;

	switch (cmd) {

	case SIOCSIFADDR:
		ifnet_set_flags(ifp, IFF_UP | IFF_RUNNING, IFF_UP | IFF_RUNNING);
		ifa = (struct ifaddr *)data;
		IFA_LOCK_SPIN(ifa);
		ifa->ifa_rtrequest = lortrequest;
		IFA_UNLOCK(ifa);
		/*
		 * Everything else is done at a higher level.
		 */
		break;

	case SIOCADDMULTI:
	case SIOCDELMULTI:
		if (ifr == 0) {
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

	case SIOCSIFMTU:
		ifp->if_mtu = ifr->ifr_mtu;
		break;

	case SIOCSIFFLAGS:
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}
	return (error);
}
#endif /* NLOOP > 0 */


static errno_t  lo_attach_proto(ifnet_t ifp, protocol_family_t protocol_family)
{
	struct ifnet_attach_proto_param_v2	proto;
	errno_t							result = 0;
	
	bzero(&proto, sizeof(proto));
	proto.input = lo_input;
	proto.pre_output = lo_pre_output;
	
	result = ifnet_attach_protocol_v2(ifp, protocol_family, &proto);

	if (result && result != EEXIST) {
		printf("lo_attach_proto: ifnet_attach_protocol for %u returned=%d\n",
			   protocol_family, result);
	}
	
	return result;
}

static void lo_reg_if_mods(void)
{
     int error;

	/* Register protocol registration functions */
	if ((error = proto_register_plumber(PF_INET, APPLE_IF_FAM_LOOPBACK, lo_attach_proto, NULL)) != 0)
		printf("proto_register_plumber failed for AF_INET error=%d\n", error);

	if ((error = proto_register_plumber(PF_INET6, APPLE_IF_FAM_LOOPBACK, lo_attach_proto, NULL)) != 0)
		printf("proto_register_plumber failed for AF_INET6 error=%d\n", error);
}

static errno_t
lo_set_bpf_tap(
	ifnet_t			ifp,
	bpf_tap_mode	mode,
	bpf_packet_func	bpf_callback)
{

  /*
   * NEED MUTEX HERE XXX
   */
	if (mode == BPF_TAP_DISABLE) {
		lo_statics[ifp->if_unit].bpf_mode = mode;
		lo_statics[ifp->if_unit].bpf_callback = bpf_callback;
	}
	else {
		lo_statics[ifp->if_unit].bpf_callback = bpf_callback;
		lo_statics[ifp->if_unit].bpf_mode = mode;		
	}

	return 0;
}


/* ARGSUSED */
void
loopattach(void)
{
	struct ifnet_init_params	lo_init;
	errno_t	result = 0;

#if NLOOP != 1
More than one loopback interface is not supported.
#endif

	lo_reg_if_mods();
	
	lo_statics[0].bpf_callback = 0;
	lo_statics[0].bpf_mode      = BPF_TAP_DISABLE;
	
	bzero(&lo_init, sizeof(lo_init));
	lo_init.name = "lo";
	lo_init.unit = 0;
	lo_init.family = IFNET_FAMILY_LOOPBACK;
	lo_init.type = IFT_LOOP;
	lo_init.output = lo_output;
	lo_init.demux = lo_demux;
	lo_init.add_proto = lo_add_proto;
	lo_init.del_proto = lo_del_proto;
	lo_init.framer = lo_framer;
	lo_init.softc = &lo_statics[0];
	lo_init.ioctl = loioctl;
	lo_init.set_bpf_tap = lo_set_bpf_tap;
	result = ifnet_allocate(&lo_init, &lo_ifp);
	if (result != 0) {
		printf("ifnet_allocate for lo0 failed - %d\n", result);
		return;
	}
	
	ifnet_set_mtu(lo_ifp, LOMTU);
	ifnet_set_flags(lo_ifp, IFF_LOOPBACK | IFF_MULTICAST, IFF_LOOPBACK | IFF_MULTICAST);
	ifnet_set_offload(lo_ifp, IFNET_CSUM_IP | IFNET_CSUM_TCP | IFNET_CSUM_UDP |
		IFNET_CSUM_TCPIPV6 | IFNET_CSUM_UDPIPV6 | IFNET_IPV6_FRAGMENT |
		IFNET_CSUM_FRAGMENT | IFNET_IP_FRAGMENT | IFNET_MULTIPAGES);
	ifnet_set_hdrlen(lo_ifp, sizeof(struct loopback_header));
	ifnet_set_eflags(lo_ifp, IFEF_SENDLIST, IFEF_SENDLIST);

#if CONFIG_MACF_NET
		mac_ifnet_label_init(ifp);
#endif

	result = ifnet_attach(lo_ifp, NULL);
	if (result != 0) {
		printf("ifnet_attach lo0 failed - %d\n", result);
		return;
	}
	bpfattach(lo_ifp, DLT_NULL, sizeof(u_int));
	
	loopattach_done = 1;
}
