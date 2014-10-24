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
 * Copyright (c) 1982, 1989, 1993
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
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/socketvar.h>

#include <net/dlil.h>
#include <net/if.h>
#include <net/route.h>
#include <net/if_llc.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/ndrv.h>
#include <net/kpi_protocol.h>
#include <net/dlil.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/if_ether.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>

#if INET6
#include <netinet6/nd6.h>
#include <netinet6/in6_ifattach.h>
#include <netinet6/ip6_var.h>
#endif

/* #include "vlan.h" */
#if NVLAN > 0
#include <net/if_vlan_var.h>
#endif /* NVLAN > 0 */

#include <net/ether_if_module.h>

static const u_char etherip6allnodes[ETHER_ADDR_LEN] =
	{ 0x33, 0x33, 0, 0, 0, 1 };

/*
 * Process a received Ethernet packet;
 * the packet is in the mbuf chain m without
 * the ether header, which is provided separately.
 */
static errno_t
ether_inet6_input(ifnet_t ifp, protocol_family_t protocol,
    mbuf_t packet, char *header)
{
#pragma unused(ifp, protocol)
	struct ether_header *eh = (struct ether_header *)(void *)header;
	u_int16_t ether_type;

	bcopy(&eh->ether_type, &ether_type, sizeof (ether_type));

	if (ether_type == htons(ETHERTYPE_IPV6)) {
		struct ifnet *mifp;
		/*
		 * Trust the ifp in the mbuf, rather than ifproto's
		 * since the packet could have been injected via
		 * a dlil_input_packet_list() using an ifp that is
		 * different than the one where the packet really
		 * came from.
		 */
		mifp = mbuf_pkthdr_rcvif(packet);

		/* Update L2 reachability record, if present (and not bcast) */
		if (bcmp(eh->ether_shost, etherbroadcastaddr,
		    ETHER_ADDR_LEN) != 0) {
			nd6_llreach_set_reachable(mifp, eh->ether_shost,
			    ETHER_ADDR_LEN);
		}

		/* Save the Ethernet source address for all-nodes multicasts */
		if (!bcmp(eh->ether_dhost, etherip6allnodes, ETHER_ADDR_LEN)) {
			struct ip6aux *ip6a;

			ip6a = ip6_addaux(packet);
			if (ip6a) {
				ip6a->ip6a_flags |= IP6A_HASEEN;
				bcopy(eh->ether_shost, ip6a->ip6a_ehsrc,
				    ETHER_ADDR_LEN);
			}
		}

		if (proto_input(protocol, packet) != 0)
			m_freem(packet);
	} else {
		m_freem(packet);
	}

	return (EJUSTRETURN);
}

static errno_t
ether_inet6_pre_output(ifnet_t ifp, protocol_family_t protocol_family,
    mbuf_t *m0, const struct sockaddr *dst_netaddr, void *route,
    char *type, char *edst)
{
#pragma unused(protocol_family)
	errno_t	result;
	struct sockaddr_dl sdl;
	struct mbuf *m = *m0;

	/*
	 * Tell ether_frameout it's ok to loop packet if necessary
	 */
	m->m_flags |= M_LOOP;

	result = nd6_lookup_ipv6(ifp, (const struct sockaddr_in6 *)
	    (uintptr_t)(size_t)dst_netaddr, &sdl, sizeof (sdl), route, *m0);

	if (result == 0) {
		u_int16_t ethertype_ipv6 = htons(ETHERTYPE_IPV6);

		bcopy(&ethertype_ipv6, type, sizeof (ethertype_ipv6));
		bcopy(LLADDR(&sdl), edst, sdl.sdl_alen);
	}

	return (result);
}

static int
ether_inet6_resolve_multi(ifnet_t ifp, const struct sockaddr *proto_addr,
    struct sockaddr_dl *out_ll, size_t ll_len)
{
	static const size_t minsize =
	    offsetof(struct sockaddr_dl, sdl_data[0]) + ETHER_ADDR_LEN;
	const struct sockaddr_in6 *sin6 =
	    (const struct sockaddr_in6 *)(uintptr_t)(size_t)proto_addr;

	if (proto_addr->sa_family != AF_INET6)
		return (EAFNOSUPPORT);

	if (proto_addr->sa_len < sizeof (struct sockaddr_in6))
		return (EINVAL);

	if (ll_len < minsize)
		return (EMSGSIZE);

	bzero(out_ll, minsize);
	out_ll->sdl_len = minsize;
	out_ll->sdl_family = AF_LINK;
	out_ll->sdl_index = ifp->if_index;
	out_ll->sdl_type = IFT_ETHER;
	out_ll->sdl_nlen = 0;
	out_ll->sdl_alen = ETHER_ADDR_LEN;
	out_ll->sdl_slen = 0;
	ETHER_MAP_IPV6_MULTICAST(&sin6->sin6_addr, LLADDR(out_ll));

	return (0);
}

static errno_t
ether_inet6_prmod_ioctl(ifnet_t ifp, protocol_family_t protocol_family,
    u_long command, void *data)
{
#pragma unused(protocol_family)
	int error = 0;

	switch (command) {
	case SIOCSIFADDR:		/* struct ifaddr pointer */
		/*
		 * Note: caller of ifnet_ioctl() passes in pointer to
		 * struct ifaddr as parameter to SIOCSIFADDR, for legacy
		 * reasons.
		 */
		if ((ifp->if_flags & IFF_RUNNING) == 0) {
			ifnet_set_flags(ifp, IFF_UP, IFF_UP);
			ifnet_ioctl(ifp, 0, SIOCSIFFLAGS, NULL);
		}
		break;

	case SIOCGIFADDR: {		/* struct ifreq */
		struct ifreq *ifr = (struct ifreq *)(void *)data;
		(void) ifnet_guarded_lladdr_copy_bytes(ifp,
		    ifr->ifr_addr.sa_data, ETHER_ADDR_LEN);
		break;
	}

	default:
		error = EOPNOTSUPP;
		break;
	}
	return (error);
}

errno_t
ether_attach_inet6(struct ifnet *ifp, protocol_family_t protocol_family)
{
#pragma unused(protocol_family)
	struct ifnet_attach_proto_param	proto;
	struct ifnet_demux_desc demux[1];
	u_short en_6native = htons(ETHERTYPE_IPV6);
	errno_t	error;

	bzero(&proto, sizeof (proto));
	demux[0].type = DLIL_DESC_ETYPE2;
	demux[0].data = &en_6native;
	demux[0].datalen = sizeof (en_6native);
	proto.demux_list = demux;
	proto.demux_count = 1;
	proto.input = ether_inet6_input;
	proto.pre_output = ether_inet6_pre_output;
	proto.ioctl = ether_inet6_prmod_ioctl;
	proto.resolve = ether_inet6_resolve_multi;
	error = ifnet_attach_protocol(ifp, protocol_family, &proto);
	if (error && error != EEXIST) {
		printf("WARNING: %s can't attach ipv6 to %s\n", __func__,
		    if_name(ifp));
	}

	return (error);
}

void
ether_detach_inet6(struct ifnet *ifp, protocol_family_t protocol_family)
{
	(void) ifnet_detach_protocol(ifp, protocol_family);
}
