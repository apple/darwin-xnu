/*
 * Copyright (c) 2000-2012 Apple Inc. All rights reserved.
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
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2006 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */


#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <kern/lock.h>

#include <net/if.h>
#include <net/route.h>
#include <net/if_llc.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/kpi_protocol.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/if_ether.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_arp.h>

#include <sys/socketvar.h>

#include <net/dlil.h>

/* #include "vlan.h" */
#if NVLAN > 0
#include <net/if_vlan_var.h>
#endif /* NVLAN > 0 */
#include <net/ether_if_module.h>
#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

/* Local function declarations */
extern void *kdp_get_interface(void);
extern void kdp_set_ip_and_mac_addresses(struct in_addr *ipaddr,
    struct ether_addr *macaddr);

#define	_ip_copy(dst, src)	\
	bcopy(src, dst, sizeof (struct in_addr))

static void
ether_inet_arp_input(struct ifnet *ifp, struct mbuf *m)
{
	struct ether_arp *ea;
	struct sockaddr_dl	sender_hw;
	struct sockaddr_in	sender_ip;
	struct sockaddr_in	target_ip;

	if (mbuf_len(m) < sizeof (*ea) && mbuf_pullup(&m, sizeof (*ea)) != 0)
		return;

	ea = mbuf_data(m);

	/* Verify this is an ethernet/ip arp and address lengths are correct */
	if (ntohs(ea->arp_hrd) != ARPHRD_ETHER ||
	    ntohs(ea->arp_pro) != ETHERTYPE_IP ||
	    ea->arp_pln != sizeof (struct in_addr) ||
	    ea->arp_hln != ETHER_ADDR_LEN) {
		mbuf_freem(m);
		return;
	}

	/* Verify the sender is not broadcast */
	if (bcmp(ea->arp_sha, etherbroadcastaddr, ETHER_ADDR_LEN) == 0) {
		mbuf_freem(m);
		return;
	}

	bzero(&sender_ip, sizeof (sender_ip));
	sender_ip.sin_len = sizeof (sender_ip);
	sender_ip.sin_family = AF_INET;
	_ip_copy(&sender_ip.sin_addr, ea->arp_spa);
	target_ip = sender_ip;
	_ip_copy(&target_ip.sin_addr, ea->arp_tpa);

	bzero(&sender_hw, sizeof (sender_hw));
	sender_hw.sdl_len = sizeof (sender_hw);
	sender_hw.sdl_family = AF_LINK;
	sender_hw.sdl_type = IFT_ETHER;
	sender_hw.sdl_alen = ETHER_ADDR_LEN;
	bcopy(ea->arp_sha, LLADDR(&sender_hw), ETHER_ADDR_LEN);

	/* update L2 reachability record, if present */
	arp_llreach_set_reachable(ifp, LLADDR(&sender_hw), ETHER_ADDR_LEN);

	arp_ip_handle_input(ifp, ntohs(ea->arp_op), &sender_hw, &sender_ip,
	    &target_ip);
	mbuf_freem(m);
}

/*
 * Process a received Ethernet packet;
 * the packet is in the mbuf chain m without
 * the ether header, which is provided separately.
 */
static errno_t
ether_inet_input(ifnet_t ifp, protocol_family_t	protocol_family,
    mbuf_t m_list)
{
#pragma unused(ifp, protocol_family)
	mbuf_t	m;
	mbuf_t	*tailptr = &m_list;
	mbuf_t	nextpkt;

	/* Strip ARP and non-IP packets out of the list */
	for (m = m_list; m; m = nextpkt) {
		struct ether_header *eh = mbuf_pkthdr_header(m);
		struct ifnet *mifp;

		/*
		 * Trust the ifp in the mbuf, rather than ifproto's
		 * since the packet could have been injected via
		 * a dlil_input_packet_list() using an ifp that is
		 * different than the one where the packet really
		 * came from.
		 */
		mifp = mbuf_pkthdr_rcvif(m);

		nextpkt = m->m_nextpkt;

		if (eh->ether_type == htons(ETHERTYPE_IP)) {
			/*
			 * Update L2 reachability record, if present
			 * (and if not a broadcast sender).
			 */
			if (bcmp(eh->ether_shost, etherbroadcastaddr,
			    ETHER_ADDR_LEN) != 0) {
				arp_llreach_set_reachable(mifp, eh->ether_shost,
				    ETHER_ADDR_LEN);
			}
			/* put this packet in the list */
			*tailptr = m;
			tailptr = &m->m_nextpkt;
		} else {
			/* Pass ARP packets to arp input */
			m->m_nextpkt = NULL;
			if (eh->ether_type == htons(ETHERTYPE_ARP))
				ether_inet_arp_input(mifp, m);
			else
				mbuf_freem(m);
		}
	}

	*tailptr = NULL;

	/* Pass IP list to ip input */
	if (m_list != NULL && proto_input(PF_INET, m_list) != 0) {
		mbuf_freem_list(m_list);
	}

	return (EJUSTRETURN);
}

static errno_t
ether_inet_pre_output(ifnet_t ifp, protocol_family_t protocol_family,
    mbuf_t *m0, const struct sockaddr *dst_netaddr,
    void *route, char *type, char *edst)
{
#pragma unused(protocol_family)
	struct mbuf *m = *m0;
	const struct ether_header *eh;
	errno_t result = 0;

	if ((ifp->if_flags & (IFF_UP|IFF_RUNNING)) != (IFF_UP|IFF_RUNNING))
		return (ENETDOWN);

	/*
	 * Tell ether_frameout it's ok to loop packet unless negated below.
	 */
	m->m_flags |= M_LOOP;

	switch (dst_netaddr->sa_family) {
	case AF_INET: {
		struct sockaddr_dl ll_dest;

		result = arp_lookup_ip(ifp,
		    (const struct sockaddr_in *)(uintptr_t)(size_t)dst_netaddr,
		    &ll_dest, sizeof (ll_dest), (route_t)route, *m0);
		if (result == 0) {
			u_int16_t ethertype_ip = htons(ETHERTYPE_IP);

			bcopy(LLADDR(&ll_dest), edst, ETHER_ADDR_LEN);
			bcopy(&ethertype_ip, type, sizeof (ethertype_ip));
		}
		break;
	}

	case pseudo_AF_HDRCMPLT:
	case AF_UNSPEC:
		m->m_flags &= ~M_LOOP;
		eh = (const struct ether_header *)(uintptr_t)(size_t)
		    dst_netaddr->sa_data;
		(void) memcpy(edst, eh->ether_dhost, 6);
		bcopy(&eh->ether_type, type, sizeof (u_short));
		break;

	default:
		printf("%s%d: can't handle af%d\n", ifp->if_name, ifp->if_unit,
		    dst_netaddr->sa_family);

		result = EAFNOSUPPORT;
		break;
	}

	return (result);
}

static errno_t
ether_inet_resolve_multi(ifnet_t ifp, const struct sockaddr *proto_addr,
    struct sockaddr_dl *out_ll, size_t ll_len)
{
	static const size_t minsize =
	    offsetof(struct sockaddr_dl, sdl_data[0]) + ETHER_ADDR_LEN;
	const struct sockaddr_in *sin =
	    (const struct sockaddr_in *)(uintptr_t)(size_t)proto_addr;

	if (proto_addr->sa_family != AF_INET)
		return (EAFNOSUPPORT);

	if (proto_addr->sa_len < sizeof (struct sockaddr_in))
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
	ETHER_MAP_IP_MULTICAST(&sin->sin_addr, LLADDR(out_ll));

	return (0);
}

static errno_t
ether_inet_prmod_ioctl(ifnet_t ifp, protocol_family_t protocol_family,
    u_long command, void *data)
{
#pragma unused(protocol_family)
	int error = 0;

	switch (command) {
	case SIOCSIFADDR:		/* struct ifaddr pointer */
	case SIOCAIFADDR: {		/* struct ifaddr pointer */
		/*
		 * Note: caller of ifnet_ioctl() passes in pointer to
		 * struct ifaddr as parameter to SIOC{A,S}IFADDR, for
		 * legacy reasons.
		 */
		struct ifaddr *ifa = data;

		if (!(ifnet_flags(ifp) & IFF_RUNNING)) {
			ifnet_set_flags(ifp, IFF_UP, IFF_UP);
			ifnet_ioctl(ifp, 0, SIOCSIFFLAGS, NULL);
		}

		if (ifaddr_address_family(ifa) != AF_INET)
			break;

		inet_arp_init_ifaddr(ifp, ifa);

		if (command != SIOCSIFADDR)
			break;

		/*
		 * Register new IP and MAC addresses with the kernel
		 * debugger if the interface is the same as was registered
		 * by IOKernelDebugger. If no interface was registered,
		 * fall back and just match against en0 interface.
		 * Do this only for the first address of the interface
		 * and not for aliases.
		 */
		if ((kdp_get_interface() != 0 &&
		    kdp_get_interface() == ifp->if_softc) ||
		    (kdp_get_interface() == 0 && ifp->if_unit == 0))
			kdp_set_ip_and_mac_addresses(&(IA_SIN(ifa)->sin_addr),
			    ifnet_lladdr(ifp));
		break;
	}

	case SIOCGIFADDR: {		/* struct ifreq */
		struct ifreq *ifr = data;

		ifnet_lladdr_copy_bytes(ifp, ifr->ifr_addr.sa_data,
		    ETHER_ADDR_LEN);
		break;
	}

	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

static void
ether_inet_event(ifnet_t ifp, protocol_family_t protocol,
    const struct kev_msg *event)
{
#pragma unused(protocol)
	ifaddr_t *addresses;

	if (event->vendor_code !=  KEV_VENDOR_APPLE ||
	    event->kev_class != KEV_NETWORK_CLASS ||
	    event->kev_subclass != KEV_DL_SUBCLASS ||
	    event->event_code != KEV_DL_LINK_ADDRESS_CHANGED) {
		return;
	}

	if (ifnet_get_address_list_family(ifp, &addresses, AF_INET) == 0) {
		int i;

		for (i = 0; addresses[i] != NULL; i++) {
			inet_arp_init_ifaddr(ifp, addresses[i]);
		}

		ifnet_free_address_list(addresses);
	}
}

static errno_t
ether_inet_arp(ifnet_t ifp, u_short arpop, const struct sockaddr_dl *sender_hw,
    const struct sockaddr *sender_proto, const struct sockaddr_dl *target_hw,
    const struct sockaddr *target_proto)
{
	mbuf_t	m;
	errno_t	result;
	struct ether_header *eh;
	struct ether_arp *ea;
	const struct sockaddr_in *sender_ip =
	    (const struct sockaddr_in *)(uintptr_t)(size_t)sender_proto;
	const struct sockaddr_inarp *target_ip =
	    (const struct sockaddr_inarp *)(uintptr_t)(size_t)target_proto;
	char *datap;

	if (target_ip == NULL)
		return (EINVAL);

	if ((sender_ip && sender_ip->sin_family != AF_INET) ||
	    target_ip->sin_family != AF_INET)
		return (EAFNOSUPPORT);

	result = mbuf_gethdr(MBUF_DONTWAIT, MBUF_TYPE_DATA, &m);
	if (result != 0)
		return (result);

	mbuf_setlen(m, sizeof (*ea));
	mbuf_pkthdr_setlen(m, sizeof (*ea));

	/* Move the data pointer in the mbuf to the end, aligned to 4 bytes */
	datap = mbuf_datastart(m);
	datap += mbuf_trailingspace(m);
	datap -= (((uintptr_t)datap) & 0x3);
	mbuf_setdata(m, datap, sizeof (*ea));
	ea = mbuf_data(m);

	/*
	 * Prepend the ethernet header, we will send the raw frame;
	 * callee frees the original mbuf when allocation fails.
	 */
	result = mbuf_prepend(&m, sizeof (*eh), MBUF_DONTWAIT);
	if (result != 0)
		return (result);

	eh = mbuf_data(m);
	eh->ether_type = htons(ETHERTYPE_ARP);

#if CONFIG_MACF_NET
	mac_mbuf_label_associate_linklayer(ifp, m);
#endif

	/* Fill out the arp header */
	ea->arp_pro = htons(ETHERTYPE_IP);
	ea->arp_hln = sizeof (ea->arp_sha);
	ea->arp_pln = sizeof (ea->arp_spa);
	ea->arp_hrd = htons(ARPHRD_ETHER);
	ea->arp_op = htons(arpop);

	/* Sender Hardware */
	if (sender_hw != NULL) {
		bcopy(CONST_LLADDR(sender_hw), ea->arp_sha,
		    sizeof (ea->arp_sha));
	} else {
		ifnet_lladdr_copy_bytes(ifp, ea->arp_sha, ETHER_ADDR_LEN);
	}
	ifnet_lladdr_copy_bytes(ifp, eh->ether_shost, sizeof (eh->ether_shost));

	/* Sender IP */
	if (sender_ip != NULL) {
		bcopy(&sender_ip->sin_addr, ea->arp_spa, sizeof (ea->arp_spa));
	} else {
		struct ifaddr *ifa;

		/* Look for an IP address to use as our source */
		ifnet_lock_shared(ifp);
		TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
			IFA_LOCK(ifa);
			if (ifa->ifa_addr != NULL &&
			    ifa->ifa_addr->sa_family == AF_INET) {
				bcopy(&((struct sockaddr_in *)(void *)
				    ifa->ifa_addr)->sin_addr, ea->arp_spa,
				    sizeof (ea->arp_spa));
				IFA_UNLOCK(ifa);
				break;
			}
			IFA_UNLOCK(ifa);
		}
		ifnet_lock_done(ifp);

		if (ifa == NULL) {
			mbuf_freem(m);
			return (ENXIO);
		}
	}

	/* Target Hardware */
	if (target_hw == NULL) {
		bzero(ea->arp_tha, sizeof (ea->arp_tha));
		bcopy(etherbroadcastaddr, eh->ether_dhost,
		    sizeof (eh->ether_dhost));
	} else {
		bcopy(CONST_LLADDR(target_hw), ea->arp_tha,
		    sizeof (ea->arp_tha));
		bcopy(CONST_LLADDR(target_hw), eh->ether_dhost,
		    sizeof (eh->ether_dhost));
	}

	/* Target IP */
	bcopy(&target_ip->sin_addr, ea->arp_tpa, sizeof (ea->arp_tpa));

	/*
	 * If this is an ARP request for a (default) router, mark
	 * the packet accordingly so that the driver can find out,
	 * in case it needs to perform driver-specific action(s).
	 */
	if (arpop == ARPOP_REQUEST && (target_ip->sin_other & SIN_ROUTER)) {
		m->m_pkthdr.aux_flags |= MAUXF_INET_RESOLVE_RTR;
		VERIFY(!(m->m_pkthdr.aux_flags & MAUXF_INET6_RESOLVE_RTR));
	}

	if (ifp->if_eflags & IFEF_TXSTART) {
		/* Use control service class if the interface 
		 * supports transmit-start model
		 */
		(void) m_set_service_class(m, MBUF_SC_CTL);
	}

	ifnet_output_raw(ifp, PF_INET, m);

	return (0);
}

errno_t
ether_attach_inet(struct ifnet *ifp, protocol_family_t proto_family)
{
#pragma unused(proto_family)
	struct ifnet_attach_proto_param_v2 proto;
	struct ifnet_demux_desc demux[2];
	u_short en_native = htons(ETHERTYPE_IP);
	u_short arp_native = htons(ETHERTYPE_ARP);
	errno_t	error;

	bzero(&demux[0], sizeof (demux));
	demux[0].type = DLIL_DESC_ETYPE2;
	demux[0].data = &en_native;
	demux[0].datalen = sizeof (en_native);
	demux[1].type = DLIL_DESC_ETYPE2;
	demux[1].data = &arp_native;
	demux[1].datalen = sizeof (arp_native);

	bzero(&proto, sizeof (proto));
	proto.demux_list = demux;
	proto.demux_count = sizeof (demux) / sizeof (demux[0]);
	proto.input = ether_inet_input;
	proto.pre_output = ether_inet_pre_output;
	proto.ioctl = ether_inet_prmod_ioctl;
	proto.event = ether_inet_event;
	proto.resolve = ether_inet_resolve_multi;
	proto.send_arp = ether_inet_arp;

	error = ifnet_attach_protocol_v2(ifp, proto_family, &proto);
	if (error && error != EEXIST) {
		printf("WARNING: %s can't attach ip to %s%d\n", __func__,
		    ifp->if_name, ifp->if_unit);
	}
	return (error);
}

void
ether_detach_inet(struct ifnet *ifp, protocol_family_t proto_family)
{
	(void) ifnet_detach_protocol(ifp, proto_family);
}
