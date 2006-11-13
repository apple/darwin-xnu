/*
 * Copyright (c) 2006 Apple Computer, Inc. All Rights Reserved.
 * 
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
 * http://www.opensource.apple.com/apsl/ and read it before using this 
 * file.
 *
 * The Original Code and all software distributed under the License are 
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, 
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. 
 * Please see the License for the specific language governing rights and 
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
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

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/bpf.h>
#include <sys/malloc.h>

#if	INET
#include <netinet/in.h>
#include <netinet/in_var.h>
#endif

#if IPX
#include <netipx/ipx.h>
#include <netipx/ipx_if.h>
#endif

#if INET6
#ifndef INET
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

#include "bpfilter.h"
#if NBPFILTER > 0
#include <net/bpfdesc.h>
#endif

#define NLOOP_ATTACHMENTS (NLOOP * 12)

struct lo_statics_str {
	int				bpf_mode;
	bpf_packet_func	bpf_callback;
};

void loopattach(void *dummy);

static struct lo_statics_str lo_statics[NLOOP];
int loopattach_done = 0; /* used to sync ip6_init2 loopback configuration */

#ifdef TINY_LOMTU
#define	LOMTU	(1024+512)
#else
#define LOMTU	16384
#endif

struct	ifnet loif[NLOOP];
struct ifnet *lo_ifp = &loif[0];

struct	loopback_header {
	u_long		protocol;
};

void lo_reg_if_mods(void);

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
	header = mtod(*m, struct loopback_header*);
	header->protocol = *(const u_long*)frame_type;
	return 0;
}

static errno_t
lo_add_proto(
	__unused struct ifnet			*ifp,
	__unused u_long					protocol_family,
	__unused struct ddesc_head_str	*demux_desc_head)
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
	struct ifnet *ifp,
	struct mbuf *m)
{

	if ((m->m_flags & M_PKTHDR) == 0)
		panic("lo_output: no HDR");

	/*
	 * Don't overwrite the rcvif field if it is in use.
	 *  This is used to match multicast packets, sent looping
	 *  back, with the appropriate group record on input.
	 */
	if (m->m_pkthdr.rcvif == NULL)
		m->m_pkthdr.rcvif = ifp;

	ifp->if_ibytes += m->m_pkthdr.len;
	ifp->if_obytes += m->m_pkthdr.len;

	ifp->if_opackets++;
	ifp->if_ipackets++;

	m->m_pkthdr.header = mtod(m, char *);
	m->m_pkthdr.csum_data = 0xffff; /* loopback checksums are always OK */
	m->m_pkthdr.csum_flags = CSUM_DATA_VALID | CSUM_PSEUDO_HDR | 
							 CSUM_IP_CHECKED | CSUM_IP_VALID;
	m_adj(m, sizeof(struct loopback_header));

#if NBPFILTER > 0
	if (lo_statics[ifp->if_unit].bpf_mode != BPF_TAP_DISABLE) {
		struct mbuf m0, *n;

		n = m;
		if (ifp->if_bpf->bif_dlt == DLT_NULL) {
			struct loopback_header  *header;
			/*
			 * We need to prepend the address family as
			 * a four byte field.  Cons up a dummy header
			 * to pacify bpf.  This is safe because bpf
			 * will only read from the mbuf (i.e., it won't
			 * try to free it or keep a pointer a to it).
			 */
			header = (struct loopback_header*)m->m_pkthdr.header;
			m0.m_next = m;
			m0.m_len = 4;
			m0.m_data = (char *)&header->protocol;
			n = &m0;
		}

		lo_statics[ifp->if_unit].bpf_callback(ifp, n);
	}
#endif

	return dlil_input(ifp, m, m);
}


/*
 * This is a common pre-output route used by INET and INET6. This could
 * (should?) be split into separate pre-output routines for each protocol.
 */

static int
lo_pre_output(
	__unused struct ifnet	*ifp,
	u_long			protocol_family,
	struct mbuf		**m,
	__unused const struct sockaddr	*dst,
	caddr_t			route,
	char			*frame_type,
	__unused char	*dst_addr)

{
	register struct rtentry *rt = (struct rtentry *) route;

	if (((*m)->m_flags & M_PKTHDR) == 0)
		panic("looutput no HDR");

	if (rt && rt->rt_flags & (RTF_REJECT|RTF_BLACKHOLE)) {
		if (rt->rt_flags & RTF_BLACKHOLE) {
			m_freem(*m);
			return EJUSTRETURN;
		}
		else
			return ((rt->rt_flags & RTF_HOST) ? EHOSTUNREACH : ENETUNREACH);
	}
	
	*(u_long *)frame_type = protocol_family;

	return 0;
}

/*
 *  lo_input - This should work for all attached protocols that use the
 *             ifq/schednetisr input mechanism.
 */
static int
lo_input(
	struct mbuf				*m,
	__unused char			*fh,
	__unused struct ifnet	*ifp,
	__unused u_long			protocol_family,
	__unused int			sync_ok)
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
	if (rt) {
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
	u_int32_t	cmd,
	void*		data)
{
	register struct ifaddr *ifa;
	register struct ifreq *ifr = (struct ifreq *)data;
	register int error = 0;

	switch (cmd) {

	case SIOCSIFADDR:
		ifnet_set_flags(ifp, IFF_UP | IFF_RUNNING, IFF_UP | IFF_RUNNING);
		ifa = (struct ifaddr *)data;
		ifa->ifa_rtrequest = lortrequest;
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


static int  lo_attach_proto(struct ifnet *ifp, u_long protocol_family)
{
	struct dlil_proto_reg_str   reg;
	int   stat =0 ;
	
	bzero(&reg, sizeof(reg));
	TAILQ_INIT(&reg.demux_desc_head);
	reg.interface_family = ifp->if_family;
	reg.unit_number      = ifp->if_unit;
	reg.input			 = lo_input;
	reg.pre_output       = lo_pre_output;
	reg.protocol_family  = protocol_family;
	
	stat = dlil_attach_protocol(&reg);

	if (stat && stat != EEXIST) {
		printf("lo_attach_proto: dlil_attach_protocol for %d returned=%d\n",
			   protocol_family, stat);
	}
	
	return stat;
}

void lo_reg_if_mods()
{
     int error;

	/* Register protocol registration functions */
	if ((error = dlil_reg_proto_module(PF_INET, APPLE_IF_FAM_LOOPBACK, lo_attach_proto, NULL)) != 0)
		printf("dlil_reg_proto_module failed for AF_INET error=%d\n", error);

	if ((error = dlil_reg_proto_module(PF_INET6, APPLE_IF_FAM_LOOPBACK, lo_attach_proto, NULL)) != 0)
		printf("dlil_reg_proto_module failed for AF_INET6 error=%d\n", error);
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
loopattach(
	__unused void *dummy)
{
	struct ifnet *ifp;
	int i = 0;

	lo_reg_if_mods();

	for (ifp = loif; i < NLOOP; ifp++) {
		lo_statics[i].bpf_callback = 0;
		lo_statics[i].bpf_mode      = BPF_TAP_DISABLE;
		bzero(ifp, sizeof(struct ifnet));
		ifp->if_name = "lo";
		ifp->if_family = APPLE_IF_FAM_LOOPBACK;
		ifp->if_unit = i++;
		ifp->if_mtu = LOMTU;
		ifp->if_flags = IFF_LOOPBACK | IFF_MULTICAST;
		ifp->if_ioctl = loioctl;
		ifp->if_demux = lo_demux;
		ifp->if_framer = lo_framer;
		ifp->if_add_proto = lo_add_proto;
		ifp->if_del_proto = lo_del_proto;
		ifp->if_set_bpf_tap = lo_set_bpf_tap;
		ifp->if_output = lo_output;
		ifp->if_type = IFT_LOOP;
		ifp->if_hwassist = IF_HWASSIST_CSUM_IP | IF_HWASSIST_CSUM_TCP | IF_HWASSIST_CSUM_UDP;
		ifp->if_hdrlen = sizeof(struct loopback_header);
		lo_ifp = ifp;
		dlil_if_attach(ifp);
#if NBPFILTER > 0
		bpfattach(ifp, DLT_NULL, sizeof(u_int));
#endif
	}
	loopattach_done = 1;
}
