/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
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
#include <net/netisr.h>
#include <net/route.h>
#include <net/if_llc.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/ndrv.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/if_ether.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>

#if INET6
#include <netinet6/nd6.h>
#include <netinet6/in6_ifattach.h>
#endif



#include <sys/socketvar.h>

#include <net/dlil.h>


#if LLC && CCITT
extern struct ifqueue pkintrq;
#endif


#if BRIDGE
#include <net/bridge.h>
#endif

/* #include "vlan.h" */
#if NVLAN > 0
#include <net/if_vlan_var.h>
#endif /* NVLAN > 0 */

static u_long lo_dlt = 0;
static ivedonethis = 0;
static u_char	etherbroadcastaddr[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

#define IFP2AC(IFP) ((struct arpcom *)IFP)




/*
 * Process a received Ethernet packet;
 * the packet is in the mbuf chain m without
 * the ether header, which is provided separately.
 */
int
inet6_ether_input(m, frame_header, ifp, dl_tag, sync_ok)
    struct mbuf  *m;
    char         *frame_header;
    struct ifnet *ifp;
    u_long	     dl_tag;
    int          sync_ok;

{
    register struct ether_header *eh = (struct ether_header *) frame_header;
    register struct ifqueue *inq=0;
    u_short ether_type;
    int s;
    u_int16_t ptype = -1;
    unsigned char buf[18];



    if ((ifp->if_flags & IFF_UP) == 0) {
	 m_freem(m);
	 return EJUSTRETURN;
    }

    ifp->if_lastchange = time;

    if (eh->ether_dhost[0] & 1) {
	if (bcmp((caddr_t)etherbroadcastaddr, (caddr_t)eh->ether_dhost,
		 sizeof(etherbroadcastaddr)) == 0)
	    m->m_flags |= M_BCAST;
	else
	    m->m_flags |= M_MCAST;
    }
    if (m->m_flags & (M_BCAST|M_MCAST))
	ifp->if_imcasts++;

    ether_type = ntohs(eh->ether_type);


    switch (ether_type) {

    case ETHERTYPE_IPV6:
        schednetisr(NETISR_IPV6);
        inq = &ip6intrq;
        break;

    default: {
	return ENOENT;
	}
    }

    if (inq == 0)
	return ENOENT;

	s = splimp();
	if (IF_QFULL(inq)) {
		IF_DROP(inq);
		m_freem(m);
		splx(s);
		return EJUSTRETURN;
	} else
		IF_ENQUEUE(inq, m);
	splx(s);


    return 0;
}




int
inet6_ether_pre_output(ifp, m0, dst_netaddr, route, type, edst, dl_tag )
    struct ifnet    *ifp;
    struct mbuf     **m0;
    struct sockaddr *dst_netaddr;
    caddr_t	    route;
    char	    *type;
    char            *edst;
    u_long	    dl_tag;
{
    struct rtentry  *rt0 = (struct rtentry *) route;
    int s;
    register struct mbuf *m = *m0;
    register struct rtentry *rt;
    register struct ether_header *eh;
    int hlen;	/* link layer header lenght */
    struct arpcom *ac = IFP2AC(ifp);



    if ((ifp->if_flags & (IFF_UP|IFF_RUNNING)) != (IFF_UP|IFF_RUNNING)) 
	return ENETDOWN;

    rt = rt0;
    if (rt) {
	if ((rt->rt_flags & RTF_UP) == 0) {
	    rt0 = rt = rtalloc1(dst_netaddr, 1, 0UL);
	    if (rt0)
		rtunref(rt);
	    else
		return EHOSTUNREACH;
	}

	if (rt->rt_flags & RTF_GATEWAY) {
	    if (rt->rt_gwroute == 0)
		goto lookup;
	    if (((rt = rt->rt_gwroute)->rt_flags & RTF_UP) == 0) {
		rtfree(rt); rt = rt0;
	    lookup: rt->rt_gwroute = rtalloc1(rt->rt_gateway, 1,
					      0UL);
		if ((rt = rt->rt_gwroute) == 0)
		    return (EHOSTUNREACH);
	    }
	}

	
	if (rt->rt_flags & RTF_REJECT)
	    if (rt->rt_rmx.rmx_expire == 0 ||
		time_second < rt->rt_rmx.rmx_expire)
		return (rt == rt0 ? EHOSTDOWN : EHOSTUNREACH);
    }

    hlen = ETHER_HDR_LEN;

    /*
     * Tell ether_frameout it's ok to loop packet unless negated below.
     */
    m->m_flags |= M_LOOP;

    switch (dst_netaddr->sa_family) {


    case AF_INET6:
        if (!nd6_storelladdr(&ac->ac_if, rt, m, dst_netaddr, (u_char *)edst)) {
             /* this must be impossible, so we bark */
             printf("nd6_storelladdr failed\n");
             return(EADDRNOTAVAIL); /* dlil_output will free the mbuf */
                }
       *(u_short *)type = htons(ETHERTYPE_IPV6);
       break;

    default:
	printf("%s%d: can't handle af%d\n", ifp->if_name, ifp->if_unit,
	       dst_netaddr->sa_family);

	/* dlil_output will free the mbuf */
        return EAFNOSUPPORT;
    }

    return (0);
}


int
ether_inet6_prmod_ioctl(dl_tag, ifp, command, data)
    u_long       dl_tag;
    struct ifnet *ifp;
    int          command;
    caddr_t      data;
{
    struct ifaddr *ifa = (struct ifaddr *) data;
    struct ifreq *ifr = (struct ifreq *) data;
    struct rslvmulti_req *rsreq = (struct rslvmulti_req *) data;
    int error = 0;
    boolean_t funnel_state;
    struct arpcom *ac = (struct arpcom *) ifp;
    struct sockaddr_dl *sdl;
    struct sockaddr_in *sin;
    struct sockaddr_in6 *sin6;

    u_char *e_addr;


    switch (command) {
    case SIOCRSLVMULTI: {
	switch(rsreq->sa->sa_family) {

        case AF_INET6:
                sin6 = (struct sockaddr_in6 *)rsreq->sa;
                if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
                        /*
                         * An IP6 address of 0 means listen to all
                         * of the Ethernet multicast address used for IP6.
                         * (This is used for multicast routers.)
                         */
                        ifp->if_flags |= IFF_ALLMULTI;
                        *rsreq->llsa = 0;
                        return 0;
                }
                MALLOC(sdl, struct sockaddr_dl *, sizeof *sdl, M_IFMADDR,
                       M_WAITOK);
                sdl->sdl_len = sizeof *sdl;
                sdl->sdl_family = AF_LINK;
                sdl->sdl_index = ifp->if_index;
                sdl->sdl_type = IFT_ETHER;
                sdl->sdl_nlen = 0;
                sdl->sdl_alen = ETHER_ADDR_LEN;
                sdl->sdl_slen = 0;
                e_addr = LLADDR(sdl);
                ETHER_MAP_IPV6_MULTICAST(&sin6->sin6_addr, e_addr);
#ifndef __APPLE__
                printf("ether_resolvemulti AF_INET6 Adding %x:%x:%x:%x:%x:%x\n",
                                e_addr[0], e_addr[1], e_addr[2], e_addr[3], e_addr[4], e_addr[5]);
#endif
                *rsreq->llsa = (struct sockaddr *)sdl;
                return 0;

	default:
		/* 
		 * Well, the text isn't quite right, but it's the name
		 * that counts...
		 */
		return EAFNOSUPPORT;
	}

    }
    case SIOCSIFADDR:
	 if ((ifp->if_flags & IFF_RUNNING) == 0) {
	      ifp->if_flags |= IFF_UP;
	      dlil_ioctl(0, ifp, SIOCSIFFLAGS, (caddr_t) 0);
	 }

	break;

    case SIOCGIFADDR:
    {
	struct sockaddr *sa;

	sa = (struct sockaddr *) & ifr->ifr_data;
	bcopy(IFP2AC(ifp)->ac_enaddr,
	      (caddr_t) sa->sa_data, ETHER_ADDR_LEN);
    }
    break;

    case SIOCSIFMTU:
	/*
	 * IOKit IONetworkFamily will set the right MTU according to the driver
	 */

	 return (0);

    default:
	 return EOPNOTSUPP;
    }

    return (error);
}





int  ether_attach_inet6(struct ifnet *ifp, u_long *dl_tag)
{
    struct dlil_proto_reg_str   reg;
    struct dlil_demux_desc      desc;
    u_short en_6native=ETHERTYPE_IPV6;
    int   stat;
    int i;


    stat = dlil_find_dltag(ifp->if_family, ifp->if_unit, PF_INET6, dl_tag);
    if (stat == 0)
	 return stat;

    TAILQ_INIT(&reg.demux_desc_head);
    desc.type = DLIL_DESC_RAW;
    desc.variants.bitmask.proto_id_length = 0;
    desc.variants.bitmask.proto_id = 0;
    desc.variants.bitmask.proto_id_mask = 0;
    desc.native_type = (char *) &en_6native;
    TAILQ_INSERT_TAIL(&reg.demux_desc_head, &desc, next);
    reg.interface_family = ifp->if_family;
    reg.unit_number      = ifp->if_unit;
    reg.input            = inet6_ether_input;
    reg.pre_output       = inet6_ether_pre_output;
    reg.event            = 0;
    reg.offer            = 0;
    reg.ioctl            = ether_inet6_prmod_ioctl;
    reg.default_proto    = 0;
    reg.protocol_family  = PF_INET6;

    stat = dlil_attach_protocol(&reg, dl_tag);
    if (stat) {
	printf("WARNING: ether_attach_inet6 can't attach ip to interface\n");
    }

    return stat;
}

int  ether_detach_inet6(struct ifnet *ifp, u_long dl_tag)
{
    int         stat;

    stat = dlil_find_dltag(ifp->if_family, ifp->if_unit, PF_INET6, &dl_tag);
    if (stat == 0) {
        stat = dlil_detach_protocol(dl_tag);
        if (stat) {
            printf("WARNING: ether_detach_inet6 can't detach ip6 from interface\n");
        }
    }
    return stat;
}

