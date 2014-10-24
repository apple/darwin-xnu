/*
 * Copyright (c) 2000-2014 Apple Inc. All rights reserved.
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


/*	$FreeBSD: src/sys/netinet6/udp6_output.c,v 1.1.2.3 2001/08/31 13:49:58 jlemon Exp $	*/
/*	$KAME: udp6_output.c,v 1.31 2001/05/21 16:39:15 jinmei Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Copyright (c) 1982, 1986, 1989, 1993
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
 *	@(#)udp_var.h	8.1 (Berkeley) 6/10/93
 */

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/syslog.h>

#include <machine/endian.h>

#include <net/if.h>
#include <net/route.h>
#include <net/if_types.h>
#include <net/ntstat.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/in_pcb.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_pcb.h>
#include <netinet6/udp6_var.h>
#include <netinet/icmp6.h>
#include <netinet6/ip6protosw.h>

#if NECP
#include <net/necp.h>
#endif /* NECP */

#include <net/net_osdep.h>

/*
 * UDP protocol inplementation.
 * Per RFC 768, August, 1980.
 */

int
udp6_output(struct in6pcb *in6p, struct mbuf *m, struct sockaddr *addr6,
    struct mbuf *control, struct proc *p)
{
	u_int32_t ulen = m->m_pkthdr.len;
	u_int32_t plen = sizeof (struct udphdr) + ulen;
	struct ip6_hdr *ip6;
	struct udphdr *udp6;
	struct in6_addr *laddr, *faddr;
	u_short fport;
	int error = 0;
	struct ip6_pktopts opt, *optp = NULL;
	struct ip6_moptions *im6o;
	int af = AF_INET6, hlen = sizeof (struct ip6_hdr);
	int flags;
	struct sockaddr_in6 tmp;
	struct	in6_addr storage;
	mbuf_svc_class_t msc = MBUF_SC_UNSPEC;
	struct ip6_out_args ip6oa =
	    { IFSCOPE_NONE, { 0 }, IP6OAF_SELECT_SRCIF, 0 };
	struct flowadv *adv = &ip6oa.ip6oa_flowadv;
	struct socket *so = in6p->in6p_socket;
	struct route_in6 ro;
	int flowadv = 0;

	/* Enable flow advisory only when connected */
	flowadv = (so->so_state & SS_ISCONNECTED) ? 1 : 0;

	if (flowadv && INP_WAIT_FOR_IF_FEEDBACK(in6p)) {
		error = ENOBUFS;
		goto release;
	}

	if (in6p->inp_flags & INP_BOUND_IF) {
		ip6oa.ip6oa_boundif = in6p->inp_boundifp->if_index;
		ip6oa.ip6oa_flags |= IP6OAF_BOUND_IF;
	}
	if (INP_NO_CELLULAR(in6p))
		ip6oa.ip6oa_flags |= IP6OAF_NO_CELLULAR;
	if (INP_NO_EXPENSIVE(in6p))
		ip6oa.ip6oa_flags |= IP6OAF_NO_EXPENSIVE;
	if (INP_AWDL_UNRESTRICTED(in6p))
		ip6oa.ip6oa_flags |= IP6OAF_AWDL_UNRESTRICTED;

	if (control) {
		msc = mbuf_service_class_from_control(control);
		if ((error = ip6_setpktopts(control, &opt,
		    NULL, IPPROTO_UDP)) != 0)
			goto release;
		optp = &opt;
	} else
		optp = in6p->in6p_outputopts;

	if (addr6) {
		/*
		 * IPv4 version of udp_output calls in_pcbconnect in this case,
		 * which has its costs.
		 *
		 * Since we saw no essential reason for calling in_pcbconnect,
		 * we get rid of such kind of logic, and call in6_selectsrc
		 * and in6_pcbsetport in order to fill in the local address
		 * and the local port.
		 */
		struct sockaddr_in6 *sin6 =
		    (struct sockaddr_in6 *)(void *)addr6;

		if (sin6->sin6_port == 0) {
			error = EADDRNOTAVAIL;
			goto release;
		}

		if (!IN6_IS_ADDR_UNSPECIFIED(&in6p->in6p_faddr)) {
			/* how about ::ffff:0.0.0.0 case? */
			error = EISCONN;
			goto release;
		}

		/* protect *sin6 from overwrites */
		tmp = *sin6;
		sin6 = &tmp;

		faddr = &sin6->sin6_addr;
		fport = sin6->sin6_port; /* allow 0 port */

		if (IN6_IS_ADDR_V4MAPPED(faddr)) {
			if ((in6p->in6p_flags & IN6P_IPV6_V6ONLY)) {
				/*
				 * I believe we should explicitly discard the
				 * packet when mapped addresses are disabled,
				 * rather than send the packet as an IPv6 one.
				 * If we chose the latter approach, the packet
				 * might be sent out on the wire based on the
				 * default route, the situation which we'd
				 * probably want to avoid.
				 * (20010421 jinmei@kame.net)
				 */
				error = EINVAL;
				goto release;
			} else {
				af = AF_INET;
			}
		}

		/* KAME hack: embed scopeid */
		if (in6_embedscope(&sin6->sin6_addr, sin6, in6p, NULL,
		    optp) != 0) {
			error = EINVAL;
			goto release;
		}

		if (!IN6_IS_ADDR_V4MAPPED(faddr)) {
			laddr = in6_selectsrc(sin6, optp,
			    in6p, &in6p->in6p_route, NULL, &storage,
			    ip6oa.ip6oa_boundif, &error);
		} else
			laddr = &in6p->in6p_laddr;	/* XXX */
		if (laddr == NULL) {
			if (error == 0)
				error = EADDRNOTAVAIL;
			goto release;
		}
		if (in6p->in6p_lport == 0 &&
		    (error = in6_pcbsetport(laddr, in6p, p, 0)) != 0)
			goto release;
	} else {
		if (IN6_IS_ADDR_UNSPECIFIED(&in6p->in6p_faddr)) {
			error = ENOTCONN;
			goto release;
		}
		if (IN6_IS_ADDR_V4MAPPED(&in6p->in6p_faddr)) {
			if ((in6p->in6p_flags & IN6P_IPV6_V6ONLY)) {
				/*
				 * XXX: this case would happen when the
				 * application sets the V6ONLY flag after
				 * connecting the foreign address.
				 * Such applications should be fixed,
				 * so we bark here.
				 */
				log(LOG_INFO, "udp6_output: IPV6_V6ONLY "
				    "option was set for a connected socket\n");
				error = EINVAL;
				goto release;
			} else
				af = AF_INET;
		}
		laddr = &in6p->in6p_laddr;
		faddr = &in6p->in6p_faddr;
		fport = in6p->in6p_fport;
	}

	if (in6p->inp_flowhash == 0)
		in6p->inp_flowhash = inp_calc_flowhash(in6p);
	/* update flowinfo - RFC 6437 */
	if (in6p->inp_flow == 0 && in6p->in6p_flags & IN6P_AUTOFLOWLABEL) {
		in6p->inp_flow &= ~IPV6_FLOWLABEL_MASK;
		in6p->inp_flow |=
		    (htonl(in6p->inp_flowhash) & IPV6_FLOWLABEL_MASK);
	}

	if (af == AF_INET)
		hlen = sizeof (struct ip);

	/*
	 * Calculate data length and get a mbuf
	 * for UDP and IP6 headers.
	 */
	M_PREPEND(m, hlen + sizeof (struct udphdr), M_DONTWAIT);
	if (m == 0) {
		error = ENOBUFS;
		goto release;
	}

	/*
	 * Stuff checksum and output datagram.
	 */
	udp6 = (struct udphdr *)(void *)(mtod(m, caddr_t) + hlen);
	udp6->uh_sport = in6p->in6p_lport; /* lport is always set in the PCB */
	udp6->uh_dport = fport;
	if (plen <= 0xffff)
		udp6->uh_ulen = htons((u_short)plen);
	else
		udp6->uh_ulen = 0;
	udp6->uh_sum = 0;

	switch (af) {
	case AF_INET6:
		ip6 = mtod(m, struct ip6_hdr *);
		ip6->ip6_flow	= in6p->inp_flow & IPV6_FLOWINFO_MASK;
		ip6->ip6_vfc	&= ~IPV6_VERSION_MASK;
		ip6->ip6_vfc	|= IPV6_VERSION;
#if 0		/* ip6_plen will be filled in ip6_output. */
		ip6->ip6_plen	= htons((u_short)plen);
#endif
		ip6->ip6_nxt	= IPPROTO_UDP;
		ip6->ip6_hlim	= in6_selecthlim(in6p, in6p->in6p_route.ro_rt ?
		    in6p->in6p_route.ro_rt->rt_ifp : NULL);
		ip6->ip6_src	= *laddr;
		ip6->ip6_dst	= *faddr;

		udp6->uh_sum = in6_pseudo(laddr, faddr,
		    htonl(plen + IPPROTO_UDP));
		m->m_pkthdr.csum_flags = CSUM_UDPIPV6;
		m->m_pkthdr.csum_data = offsetof(struct udphdr, uh_sum);

		if (!IN6_IS_ADDR_UNSPECIFIED(laddr))
			ip6oa.ip6oa_flags |= IP6OAF_BOUND_SRCADDR;

		flags = IPV6_OUTARGS;

		udp6stat.udp6s_opackets++;
			
#if NECP
		{
			necp_kernel_policy_id policy_id;
			if (!necp_socket_is_allowed_to_send_recv_v6(in6p, in6p->in6p_lport, fport, laddr, faddr, NULL, &policy_id)) {
				error = EHOSTUNREACH;
				goto release;
			}

			necp_mark_packet_from_socket(m, in6p, policy_id);
		}
#endif /* NECP */
			
#if IPSEC
		if (in6p->in6p_sp != NULL && ipsec_setsocket(m, so) != 0) {
			error = ENOBUFS;
			goto release;
		}
#endif /*IPSEC*/

		/* In case of IPv4-mapped address used in previous send */
		if (ROUTE_UNUSABLE(&in6p->in6p_route) ||
		    rt_key(in6p->in6p_route.ro_rt)->sa_family != AF_INET6)
			ROUTE_RELEASE(&in6p->in6p_route);

		/* Copy the cached route and take an extra reference */
		in6p_route_copyout(in6p, &ro);

		set_packet_service_class(m, so, msc, PKT_SCF_IPV6);

		m->m_pkthdr.pkt_flowsrc = FLOWSRC_INPCB;
		m->m_pkthdr.pkt_flowid = in6p->inp_flowhash;
		m->m_pkthdr.pkt_proto = IPPROTO_UDP;
		m->m_pkthdr.pkt_flags |= (PKTF_FLOW_ID | PKTF_FLOW_LOCALSRC);
		if (flowadv)
			m->m_pkthdr.pkt_flags |= PKTF_FLOW_ADV;

		im6o = in6p->in6p_moptions;
		if (im6o != NULL) {
			IM6O_LOCK(im6o);
			IM6O_ADDREF_LOCKED(im6o);
			if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst) &&
			    im6o->im6o_multicast_ifp != NULL) {
				in6p->in6p_last_outifp =
				    im6o->im6o_multicast_ifp;
			}
			IM6O_UNLOCK(im6o);
		}

		in6p->inp_sndinprog_cnt++;

		socket_unlock(so, 0);
		error = ip6_output(m, optp, &ro, flags, im6o, NULL, &ip6oa);
		m = NULL;
		socket_lock(so, 0);

		if (im6o != NULL)
			IM6O_REMREF(im6o);

		if (error == 0 && nstat_collect) {
			boolean_t cell, wifi, wired;

			if (in6p->in6p_route.ro_rt != NULL) {
				cell = IFNET_IS_CELLULAR(in6p->in6p_route.
				    ro_rt->rt_ifp);
				wifi = (!cell && IFNET_IS_WIFI(in6p->in6p_route.
				    ro_rt->rt_ifp));
				wired = (!wifi && IFNET_IS_WIRED(in6p->in6p_route.
				    ro_rt->rt_ifp));
			} else {
				cell = wifi = wired = FALSE;
			}
			INP_ADD_STAT(in6p, cell, wifi, wired, txpackets, 1);
			INP_ADD_STAT(in6p, cell, wifi, wired, txbytes, ulen);
		}

		if (flowadv && (adv->code == FADV_FLOW_CONTROLLED ||
		    adv->code == FADV_SUSPENDED)) {
			/*
			 * Return an error to indicate
			 * that the packet has been dropped.
			 */
			error = ENOBUFS;
			inp_set_fc_state(in6p, adv->code);
		}

		VERIFY(in6p->inp_sndinprog_cnt > 0);
		if ( --in6p->inp_sndinprog_cnt == 0)
			in6p->inp_flags &= ~(INP_FC_FEEDBACK);

		/* Synchronize PCB cached route */
		in6p_route_copyin(in6p, &ro);

		if (in6p->in6p_route.ro_rt != NULL) {
			struct rtentry *rt = in6p->in6p_route.ro_rt;
			struct ifnet *outif;

			if (rt->rt_flags & RTF_MULTICAST)
				rt = NULL;	/* unusable */

			/*
			 * Always discard the cached route for unconnected
			 * socket or if it is a multicast route.
			 */
			if (rt == NULL)
				ROUTE_RELEASE(&in6p->in6p_route);

			/*
			 * If the destination route is unicast, update outif
			 * with that of the route interface used by IP.
			 */
			if (rt != NULL &&
			    (outif = rt->rt_ifp) != in6p->in6p_last_outifp)
				in6p->in6p_last_outifp = outif;
		} else {
			ROUTE_RELEASE(&in6p->in6p_route);
		}

		/*
		 * If output interface was cellular/expensive, and this
		 * socket is denied access to it, generate an event.
		 */
		if (error != 0 && (ip6oa.ip6oa_retflags & IP6OARF_IFDENIED) &&
		    (INP_NO_CELLULAR(in6p) || INP_NO_EXPENSIVE(in6p)))
			soevent(in6p->inp_socket, (SO_FILT_HINT_LOCKED|
			    SO_FILT_HINT_IFDENIED));
		break;
	case AF_INET:
		error = EAFNOSUPPORT;
		goto release;
	}
	goto releaseopt;

release:
	if (m != NULL)
		m_freem(m);

releaseopt:
	if (control != NULL) {
		if (optp == &opt)
			ip6_clearpktopts(optp, -1);
		m_freem(control);
	}
	return (error);
}
