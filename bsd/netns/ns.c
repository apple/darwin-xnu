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
 * Copyright (c) 1984, 1985, 1986, 1987, 1993
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
 *	@(#)ns.c	8.2 (Berkeley) 11/15/93
 */

#include <sys/param.h>
#include <sys/mbuf.h>
#include <sys/ioctl.h>
#include <sys/protosw.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/socketvar.h>

#include <net/if.h>
#include <net/route.h>

#include <netns/ns.h>
#include <netns/ns_if.h>

#ifdef NS

struct ns_ifaddr *ns_ifaddr;
int ns_interfaces;
extern struct sockaddr_ns ns_netmask, ns_hostmask;

/*
 * Generic internet control operations (ioctl's).
 */
/* ARGSUSED */
ns_control(so, cmd, data, ifp)
	struct socket *so;
	int cmd;
	caddr_t data;
	register struct ifnet *ifp;
{
	register struct ifreq *ifr = (struct ifreq *)data;
	register struct ns_aliasreq *ifra = (struct ns_aliasreq *)data;
	register struct ns_ifaddr *ia;
	struct ifaddr *ifa;
	struct ns_ifaddr *oia;
	int error, dstIsNew, hostIsNew;

	/*
	 * Find address for this interface, if it exists.
	 */
	if (ifp == 0)
		return (EADDRNOTAVAIL);
	for (ia = ns_ifaddr; ia; ia = ia->ia_next)
		if (ia->ia_ifp == ifp)
			break;

	switch (cmd) {

	case SIOCGIFADDR:
		if (ia == (struct ns_ifaddr *)0)
			return (EADDRNOTAVAIL);
		*(struct sockaddr_ns *)&ifr->ifr_addr = ia->ia_addr;
		return (0);


	case SIOCGIFBRDADDR:
		if (ia == (struct ns_ifaddr *)0)
			return (EADDRNOTAVAIL);
		if ((ifp->if_flags & IFF_BROADCAST) == 0)
			return (EINVAL);
		*(struct sockaddr_ns *)&ifr->ifr_dstaddr = ia->ia_broadaddr;
		return (0);

	case SIOCGIFDSTADDR:
		if (ia == (struct ns_ifaddr *)0)
			return (EADDRNOTAVAIL);
		if ((ifp->if_flags & IFF_POINTOPOINT) == 0)
			return (EINVAL);
		*(struct sockaddr_ns *)&ifr->ifr_dstaddr = ia->ia_dstaddr;
		return (0);
	}

	if ((so->so_state & SS_PRIV) == 0)
		return (EPERM);

	switch (cmd) {
	case SIOCAIFADDR:
	case SIOCDIFADDR:
		if (ifra->ifra_addr.sns_family == AF_NS)
		    for (oia = ia; ia; ia = ia->ia_next) {
			if (ia->ia_ifp == ifp  &&
			    ns_neteq(ia->ia_addr.sns_addr,
				  ifra->ifra_addr.sns_addr))
			    break;
		    }
		if (cmd == SIOCDIFADDR && ia == 0)
			return (EADDRNOTAVAIL);
		/* FALLTHROUGH */

	case SIOCSIFADDR:
	case SIOCSIFDSTADDR:
		if (ia == (struct ns_ifaddr *)0) {
//			oia = (struct ns_ifaddr *)
//				malloc(sizeof *ia, M_IFADDR, M_WAITOK);
			MALLOC(oia, struct ns_ifaddr *, sizeof *ia, M_IFADDR, M_WAITOK);
			if (oia == (struct ns_ifaddr *)NULL)
				return (ENOBUFS);
			bzero((caddr_t)oia, sizeof(*oia));
			if (ia = ns_ifaddr) {
				for ( ; ia->ia_next; ia = ia->ia_next)
					;
				ia->ia_next = oia;
			} else
				ns_ifaddr = oia;
			ia = oia;
			if (ifa = ifp->if_addrlist) {
				for ( ; ifa->ifa_next; ifa = ifa->ifa_next)
					;
				ifa->ifa_next = (struct ifaddr *) ia;
			} else
				ifp->if_addrlist = (struct ifaddr *) ia;
			ia->ia_ifp = ifp;
			ia->ia_ifa.ifa_addr = (struct sockaddr *)&ia->ia_addr;

			ia->ia_ifa.ifa_netmask =
				(struct sockaddr *)&ns_netmask;

			ia->ia_ifa.ifa_dstaddr =
				(struct sockaddr *)&ia->ia_dstaddr;
			if (ifp->if_flags & IFF_BROADCAST) {
				ia->ia_broadaddr.sns_family = AF_NS;
				ia->ia_broadaddr.sns_len = sizeof(ia->ia_addr);
				ia->ia_broadaddr.sns_addr.x_host = ns_broadhost;
			}
			ns_interfaces++;
		}
	}

	switch (cmd) {
		int error;

	case SIOCSIFDSTADDR:
		if ((ifp->if_flags & IFF_POINTOPOINT) == 0)
			return (EINVAL);
		if (ia->ia_flags & IFA_ROUTE) {
			rtinit(&(ia->ia_ifa), (int)RTM_DELETE, RTF_HOST);
			ia->ia_flags &= ~IFA_ROUTE;
		}
		if (ifp->if_ioctl) {
			error = (*ifp->if_ioctl)(ifp, SIOCSIFDSTADDR, ia);
			if (error)
				return (error);
		}
		*(struct sockaddr *)&ia->ia_dstaddr = ifr->ifr_dstaddr;
		return (0);

	case SIOCSIFADDR:
		return (ns_ifinit(ifp, ia,
				(struct sockaddr_ns *)&ifr->ifr_addr, 1));

	case SIOCDIFADDR:
		ns_ifscrub(ifp, ia);
		if ((ifa = ifp->if_addrlist) == (struct ifaddr *)ia)
			ifp->if_addrlist = ifa->ifa_next;
		else {
			while (ifa->ifa_next &&
			       (ifa->ifa_next != (struct ifaddr *)ia))
				    ifa = ifa->ifa_next;
			if (ifa->ifa_next)
			    ifa->ifa_next = ((struct ifaddr *)ia)->ifa_next;
			else
				printf("Couldn't unlink nsifaddr from ifp\n");
		}
		oia = ia;
		if (oia == (ia = ns_ifaddr)) {
			ns_ifaddr = ia->ia_next;
		} else {
			while (ia->ia_next && (ia->ia_next != oia)) {
				ia = ia->ia_next;
			}
			if (ia->ia_next)
			    ia->ia_next = oia->ia_next;
			else
				printf("Didn't unlink nsifadr from list\n");
		}
		IFAFREE((&oia->ia_ifa));
		if (0 == --ns_interfaces) {
			/*
			 * We reset to virginity and start all over again
			 */
			ns_thishost = ns_zerohost;
		}
		return (0);
	
	case SIOCAIFADDR:
		dstIsNew = 0; hostIsNew = 1;
		if (ia->ia_addr.sns_family == AF_NS) {
			if (ifra->ifra_addr.sns_len == 0) {
				ifra->ifra_addr = ia->ia_addr;
				hostIsNew = 0;
			} else if (ns_neteq(ifra->ifra_addr.sns_addr,
					 ia->ia_addr.sns_addr))
				hostIsNew = 0;
		}
		if ((ifp->if_flags & IFF_POINTOPOINT) &&
		    (ifra->ifra_dstaddr.sns_family == AF_NS)) {
			if (hostIsNew == 0)
				ns_ifscrub(ifp, ia);
			ia->ia_dstaddr = ifra->ifra_dstaddr;
			dstIsNew  = 1;
		}
		if (ifra->ifra_addr.sns_family == AF_NS &&
					    (hostIsNew || dstIsNew))
			error = ns_ifinit(ifp, ia, &ifra->ifra_addr, 0);
		return (error);

	default:
		if (ifp->if_ioctl == 0)
			return (EOPNOTSUPP);
		return ((*ifp->if_ioctl)(ifp, cmd, data));
	}
}

/*
* Delete any previous route for an old address.
*/
ns_ifscrub(ifp, ia)
	register struct ifnet *ifp;
	register struct ns_ifaddr *ia; 
{
	if (ia->ia_flags & IFA_ROUTE) {
		if (ifp->if_flags & IFF_POINTOPOINT) {
			rtinit(&(ia->ia_ifa), (int)RTM_DELETE, RTF_HOST);
		} else
			rtinit(&(ia->ia_ifa), (int)RTM_DELETE, 0);
		ia->ia_flags &= ~IFA_ROUTE;
	}
}
/*
 * Initialize an interface's internet address
 * and routing table entry.
 */
ns_ifinit(ifp, ia, sns, scrub)
	register struct ifnet *ifp;
	register struct ns_ifaddr *ia;
	register struct sockaddr_ns *sns;
{
	struct sockaddr_ns oldaddr;
	register union ns_host *h = &ia->ia_addr.sns_addr.x_host;
	int s = splimp(), error;

	/*
	 * Set up new addresses.
	 */
	oldaddr = ia->ia_addr;
	ia->ia_addr = *sns;
	/*
	 * The convention we shall adopt for naming is that
	 * a supplied address of zero means that "we don't care".
	 * if there is a single interface, use the address of that
	 * interface as our 6 byte host address.
	 * if there are multiple interfaces, use any address already
	 * used.
	 *
	 * Give the interface a chance to initialize
	 * if this is its first address,
	 * and to validate the address if necessary.
	 */
	if (ns_hosteqnh(ns_thishost, ns_zerohost)) {
		if (ifp->if_ioctl &&
		     (error = (*ifp->if_ioctl)(ifp, SIOCSIFADDR, ia))) {
			ia->ia_addr = oldaddr;
			splx(s);
			return (error);
		}
		ns_thishost = *h;
	} else if (ns_hosteqnh(sns->sns_addr.x_host, ns_zerohost)
	    || ns_hosteqnh(sns->sns_addr.x_host, ns_thishost)) {
		*h = ns_thishost;
		if (ifp->if_ioctl &&
		     (error = (*ifp->if_ioctl)(ifp, SIOCSIFADDR, ia))) {
			ia->ia_addr = oldaddr;
			splx(s);
			return (error);
		}
		if (!ns_hosteqnh(ns_thishost,*h)) {
			ia->ia_addr = oldaddr;
			splx(s);
			return (EINVAL);
		}
	} else {
		ia->ia_addr = oldaddr;
		splx(s);
		return (EINVAL);
	}
	ia->ia_ifa.ifa_metric = ifp->if_metric;
	/*
	 * Add route for the network.
	 */
	if (scrub) {
		ia->ia_ifa.ifa_addr = (struct sockaddr *)&oldaddr;
		ns_ifscrub(ifp, ia);
		ia->ia_ifa.ifa_addr = (struct sockaddr *)&ia->ia_addr;
	}
	if (ifp->if_flags & IFF_POINTOPOINT)
		rtinit(&(ia->ia_ifa), (int)RTM_ADD, RTF_HOST|RTF_UP);
	else {
		ia->ia_broadaddr.sns_addr.x_net = ia->ia_addr.sns_addr.x_net;
		rtinit(&(ia->ia_ifa), (int)RTM_ADD, RTF_UP);
	}
	ia->ia_flags |= IFA_ROUTE;
	return (0);
}

/*
 * Return address info for specified internet network.
 */
struct ns_ifaddr *
ns_iaonnetof(dst)
	register struct ns_addr *dst;
{
	register struct ns_ifaddr *ia;
	register struct ns_addr *compare;
	register struct ifnet *ifp;
	struct ns_ifaddr *ia_maybe = 0;
	union ns_net net = dst->x_net;

	for (ia = ns_ifaddr; ia; ia = ia->ia_next) {
		if (ifp = ia->ia_ifp) {
			if (ifp->if_flags & IFF_POINTOPOINT) {
				compare = &satons_addr(ia->ia_dstaddr);
				if (ns_hosteq(*dst, *compare))
					return (ia);
				if (ns_neteqnn(net, ia->ia_addr.sns_addr.x_net))
					ia_maybe = ia;
			} else {
				if (ns_neteqnn(net, ia->ia_addr.sns_addr.x_net))
					return (ia);
			}
		}
	}
	return (ia_maybe);
}
#endif
