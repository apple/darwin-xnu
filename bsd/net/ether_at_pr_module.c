/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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

#include <net/if.h>
#include <net/route.h>
#include <net/if_llc.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <netinet/if_ether.h>
#include <net/kpi_interface.h>
#include <net/kpi_protocol.h>

#include <sys/socketvar.h>

#include <net/dlil.h>
#include <netat/at_pat.h>
#if NETAT
extern struct ifqueue atalkintrq;
#endif


#if BRIDGE
#include <net/bridge.h>
#endif

/* #include "vlan.h" */
#if NVLAN > 0
#include <net/if_vlan_var.h>
#endif /* NVLAN > 0 */

#include <net/ether_if_module.h>

/*
 * Process a received Ethernet packet;
 * the packet is in the mbuf chain m without
 * the ether header, which is provided separately.
 */
static errno_t
ether_at_input(
	__unused ifnet_t			ifp,
	__unused protocol_family_t	protocol_family,
	mbuf_t				m,
	__unused char			*frame_header)
{
	errno_t error;
	/*
	 * note: for AppleTalk we need to pass the enet header of the
	 * packet up stack. To do so, we made sure in that the FULL packet
	 * is copied in the mbuf by the driver, and only the m_data and
	 * length have been shifted to make IP and the other guys happy.
	 */

	m->m_data -= sizeof(struct ether_header);
	m->m_len += sizeof(struct ether_header);
	m->m_pkthdr.len += sizeof(struct ether_header);

	error = proto_input(PF_APPLETALK, m);
	
	if (error)
		m_freem(m);

	return error;
}



static errno_t
ether_at_pre_output(
	ifnet_t						ifp,
	__unused protocol_family_t	protocol_family,
	mbuf_t						*m0,
	const struct sockaddr		*dst_netaddr,
	__unused void				*route,
	char						*type,
	char						*edst)
{
    struct mbuf *m = *m0;
    const struct ether_header *eh;
    int hlen;	/* link layer header length */

	if ((ifp->if_flags & (IFF_UP|IFF_RUNNING)) != (IFF_UP|IFF_RUNNING)) 
		return ENETDOWN;

	hlen = ETHER_HDR_LEN;

	/*
	 * Tell ether_frameout it's ok to loop packet unless negated below.
	 */
	m->m_flags |= M_LOOP;

	switch (dst_netaddr->sa_family) {
		case AF_UNSPEC:
			m->m_flags &= ~M_LOOP;
			eh = (const struct ether_header *)dst_netaddr->sa_data;
			(void)memcpy(edst, eh->ether_dhost, 6);
			*(u_short *)type = eh->ether_type;
			break;
	
		case AF_APPLETALK:
			eh = (const struct ether_header *)dst_netaddr->sa_data;
			(void)memcpy(edst, eh->ether_dhost, 6);
			*(u_short *)type = htons(m->m_pkthdr.len);
			break;
		
		default:
			printf("%s%d: can't handle af%d\n", ifp->if_name, ifp->if_unit,
				   dst_netaddr->sa_family);
			return EAFNOSUPPORT;
	}
	
	return (0);
}




static errno_t
ether_at_prmod_ioctl(
    ifnet_t						ifp,
    __unused protocol_family_t	protocol_family,
    u_int32_t					command,
    void						*data)
{
    struct ifreq *ifr = data;
    int error = 0;

    switch (command) {

    case SIOCSIFADDR:
	 if ((ifp->if_flags & IFF_RUNNING) == 0) {
	      ifnet_set_flags(ifp, IFF_UP, IFF_UP);
	      ifnet_ioctl(ifp, 0, SIOCSIFFLAGS, NULL);
	 }

	break;

    case SIOCGIFADDR:
	ifnet_lladdr_copy_bytes(ifp, ifr->ifr_addr.sa_data, ETHER_ADDR_LEN);
	break;

    default:
	error = EOPNOTSUPP;
	break;
    }
    return (error);
}



__private_extern__ errno_t
ether_attach_at(
	ifnet_t	ifp,
	__unused protocol_family_t proto_family)
{
	struct ifnet_attach_proto_param proto;
	struct ifnet_demux_desc demux[2];
    u_int8_t	atalk_snap[5] = {0x08, 0x00, 0x07, 0x80, 0x9b};
    u_int8_t	aarp_snap[5] = {0x00, 0x00, 0x00, 0x80, 0xf3};
	int 		error;

	bzero(demux, sizeof(demux));
	demux[0].type = DLIL_DESC_SNAP;
	demux[0].data = atalk_snap;
	demux[0].datalen = sizeof(atalk_snap);
	demux[1].type = DLIL_DESC_SNAP;
	demux[1].data = aarp_snap;
	demux[1].datalen = sizeof(aarp_snap);

	bzero(&proto, sizeof(proto));
	proto.demux_list	= demux;
	proto.demux_count	= sizeof(demux) / sizeof(demux[0]);
	proto.input			= ether_at_input;
	proto.pre_output	= ether_at_pre_output;
	proto.ioctl			= ether_at_prmod_ioctl;
	
	error = ifnet_attach_protocol(ifp, PF_APPLETALK, &proto);
	if (error && error != EEXIST) {
		printf("WARNING: ether_attach_at failed to attach"
		       " AppleTalk to %s%d\n", ifp->if_name, ifp->if_unit);
	}
	return (error);
}

__private_extern__ void
ether_detach_at(
	ifnet_t ifp,
	__unused protocol_family_t proto_family)
{
	(void)ifnet_detach_protocol(ifp, PF_APPLETALK);
}
