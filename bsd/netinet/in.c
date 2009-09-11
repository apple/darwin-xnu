/*
 * Copyright (c) 2000-2008 Apple Inc. All rights reserved.
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
 * Copyright (c) 1982, 1986, 1991, 1993
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
 *	@(#)in.c	8.4 (Berkeley) 1/9/95
 * $FreeBSD: src/sys/netinet/in.c,v 1.44.2.5 2001/08/13 16:26:17 ume Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sockio.h>
#include <sys/socketvar.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/kern_event.h>
#include <sys/syslog.h>
#include <kern/zalloc.h>

#include <pexpert/pexpert.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/kpi_protocol.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_pcb.h>

#include <netinet/igmp_var.h>
#include <net/dlil.h>

#include <netinet/ip_var.h>

#include <netinet/tcp.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>

#include <sys/file.h>

#if PF
#include <net/pfvar.h>
#endif /* PF */

static int in_mask2len(struct in_addr *);
static void in_len2mask(struct in_addr *, int);
static int in_lifaddr_ioctl(struct socket *, u_long, caddr_t,
	struct ifnet *, struct proc *);

static void	in_socktrim(struct sockaddr_in *);
static int	in_ifinit(struct ifnet *,
	    struct in_ifaddr *, struct sockaddr_in *, int);

#define	IA_HASH_INIT(ia) {					\
	(ia)->ia_hash.tqe_next = (void *)(uintptr_t)-1;		\
	(ia)->ia_hash.tqe_prev = (void *)(uintptr_t)-1;		\
}

#define	IA_IS_HASHED(ia)					\
	(!((ia)->ia_hash.tqe_next == (void *)(uintptr_t)-1 ||	\
	(ia)->ia_hash.tqe_prev == (void *)(uintptr_t)-1))

static void in_iahash_remove(struct in_ifaddr *);
static void in_iahash_insert(struct in_ifaddr *);
static void in_iahash_insert_ptp(struct in_ifaddr *);
static struct in_ifaddr *in_ifaddr_alloc(int);
static void in_ifaddr_free(struct ifaddr *);
static void in_ifaddr_trace(struct ifaddr *, int);

static int subnetsarelocal = 0;
SYSCTL_INT(_net_inet_ip, OID_AUTO, subnets_are_local, CTLFLAG_RW, 
	&subnetsarelocal, 0, "");

struct in_multihead in_multihead; /* XXX BSS initialization */

/* Track whether or not the SIOCARPIPLL ioctl has been called */
__private_extern__	u_int32_t	ipv4_ll_arp_aware = 0;

struct in_ifaddr_dbg {
	struct in_ifaddr	inifa;			/* in_ifaddr */
	struct in_ifaddr	inifa_old;		/* saved in_ifaddr */
	u_int16_t		inifa_refhold_cnt;	/* # of ifaref */
	u_int16_t		inifa_refrele_cnt;	/* # of ifafree */
	/*
	 * Alloc and free callers.
	 */
	ctrace_t		inifa_alloc;
	ctrace_t		inifa_free;
	/*
	 * Circular lists of ifaref and ifafree callers.
	 */
	ctrace_t		inifa_refhold[CTRACE_HIST_SIZE];
	ctrace_t		inifa_refrele[CTRACE_HIST_SIZE];
};

static unsigned int inifa_debug;		/* debug flags */
static unsigned int inifa_size;			/* size of zone element */
static struct zone *inifa_zone;			/* zone for in_ifaddr */

#define	INIFA_ZONE_MAX		64		/* maximum elements in zone */
#define	INIFA_ZONE_NAME		"in_ifaddr"	/* zone name */

int
inaddr_local(struct in_addr in)
{
	struct rtentry *rt;
	struct sockaddr_in sin;
	int local = 0;

	sin.sin_family = AF_INET;
	sin.sin_len = sizeof (sin);
	sin.sin_addr = in;
	rt = rtalloc1((struct sockaddr *)&sin, 0, 0);

	if (rt != NULL) {
		RT_LOCK_SPIN(rt);
		if (rt->rt_gateway->sa_family == AF_LINK ||
		    (rt->rt_ifp->if_flags & IFF_LOOPBACK))
			local = 1;
		RT_UNLOCK(rt);
		rtfree(rt);
	} else {
		local = in_localaddr(in);
	}
	return (local);
}

/*
 * Return 1 if an internet address is for a ``local'' host
 * (one to which we have a connection).  If subnetsarelocal
 * is true, this includes other subnets of the local net.
 * Otherwise, it includes only the directly-connected (sub)nets.
 */
int
in_localaddr(struct in_addr in)
{
	u_int32_t i = ntohl(in.s_addr);
	struct in_ifaddr *ia;

	if (subnetsarelocal) {
		lck_rw_lock_shared(in_ifaddr_rwlock);
		for (ia = in_ifaddrhead.tqh_first; ia; 
		     ia = ia->ia_link.tqe_next)
			if ((i & ia->ia_netmask) == ia->ia_net) {
				lck_rw_done(in_ifaddr_rwlock);
				return (1);
			}
		lck_rw_done(in_ifaddr_rwlock);
	} else {
		lck_rw_lock_shared(in_ifaddr_rwlock);
		for (ia = in_ifaddrhead.tqh_first; ia;
		     ia = ia->ia_link.tqe_next)
			if ((i & ia->ia_subnetmask) == ia->ia_subnet) {
				lck_rw_done(in_ifaddr_rwlock);
				return (1);
			}
		lck_rw_done(in_ifaddr_rwlock);
	}
	return (0);
}

/*
 * Determine whether an IP address is in a reserved set of addresses
 * that may not be forwarded, or whether datagrams to that destination
 * may be forwarded.
 */
int
in_canforward(struct in_addr in)
{
	u_int32_t i = ntohl(in.s_addr);
	u_int32_t net;

	if (IN_EXPERIMENTAL(i) || IN_MULTICAST(i))
		return (0);
	if (IN_CLASSA(i)) {
		net = i & IN_CLASSA_NET;
		if (net == 0 || net == (IN_LOOPBACKNET << IN_CLASSA_NSHIFT))
			return (0);
	}
	return (1);
}

/*
 * Trim a mask in a sockaddr
 */
static void
in_socktrim(struct sockaddr_in *ap)
{
    char *cplim = (char *) &ap->sin_addr;
    char *cp = (char *) (&ap->sin_addr + 1);

    ap->sin_len = 0;
    while (--cp >= cplim)
        if (*cp) {
	    (ap)->sin_len = cp - (char *) (ap) + 1;
	    break;
	}
}

static int
in_mask2len(struct in_addr *mask)
{
	size_t x, y;
	u_char *p;

	p = (u_char *)mask;
	for (x = 0; x < sizeof(*mask); x++) {
		if (p[x] != 0xff)
			break;
	}
	y = 0;
	if (x < sizeof(*mask)) {
		for (y = 0; y < 8; y++) {
			if ((p[x] & (0x80 >> y)) == 0)
				break;
		}
	}
	return x * 8 + y;
}

static void
in_len2mask(struct in_addr *mask, int len)
{
	int i;
	u_char *p;

	p = (u_char *)mask;
	bzero(mask, sizeof(*mask));
	for (i = 0; i < len / 8; i++)
		p[i] = 0xff;
	if (len % 8)
		p[i] = (0xff00 >> (len % 8)) & 0xff;
}

static int in_interfaces;	/* number of external internet interfaces */

/*
 * Generic internet control operations (ioctl's).
 * Ifp is 0 if not an interface-specific ioctl.
 *
 * Returns:	0			Success
 *		EINVAL
 *		EADDRNOTAVAIL
 *		EDESTADDRREQ
 *		EPERM
 *		ENOBUFS
 *		EBUSY
 *		EOPNOTSUPP
 *	proc_suser:EPERM
 *	suser:EPERM
 *	in_lifaddr_ioctl:???
 *	dlil_ioctl:???
 *	in_ifinit:???
 *	dlil_plumb_protocol:???
 *	dlil_unplumb_protocol:???
 */
/* ARGSUSED */
int
in_control(
	struct socket *so,
	u_long cmd,
	caddr_t data,
	struct ifnet *ifp,
	struct proc *p)
{
	struct ifreq *ifr = (struct ifreq *)data;
	struct in_ifaddr *ia = NULL, *iap;
	struct ifaddr *ifa;
	struct in_aliasreq *ifra = (struct in_aliasreq *)data;
	struct sockaddr_in oldaddr;
	int error = 0;
	int hostIsNew, maskIsNew;
	struct kev_msg        ev_msg;
	struct kev_in_data    in_event_data;

	switch (cmd) {
	case SIOCALIFADDR:
	case SIOCDLIFADDR:
		if ((error = proc_suser(p)) != 0)
			return error;
		/*fall through*/
	case SIOCGLIFADDR:
		if (!ifp)
			return EINVAL;
		return in_lifaddr_ioctl(so, cmd, data, ifp, p);
	}

	/*
	 * Find address for this interface, if it exists.
	 *
	 * If an alias address was specified, find that one instead of
	 * the first one on the interface.
	 */
	if (ifp) {
		lck_rw_lock_shared(in_ifaddr_rwlock);
		for (iap = in_ifaddrhead.tqh_first; iap; 
		     iap = iap->ia_link.tqe_next)
			if (iap->ia_ifp == ifp) {
				if (((struct sockaddr_in *)&ifr->ifr_addr)->sin_addr.s_addr ==
				    iap->ia_addr.sin_addr.s_addr) {
					ia = iap;
					break;
				} else if (ia == NULL) {
					ia = iap;
					if (ifr->ifr_addr.sa_family != AF_INET)
						break;
				}
			}
		/* take a reference on ia before releasing lock */
		if (ia != NULL) {
			ifaref(&ia->ia_ifa);
		}
		lck_rw_done(in_ifaddr_rwlock);
	}
	switch (cmd) {
	case SIOCAUTOADDR:
	case SIOCARPIPLL:
		if ((error = proc_suser(p)) != 0) {
			goto done;
		}
		if (ifp == 0) {
			error = EADDRNOTAVAIL;
			goto done;
		}
		break;

	case SIOCAIFADDR:
	case SIOCDIFADDR:
		if (ifp == 0) {
			error = EADDRNOTAVAIL;
			goto done;
		}
		if (ifra->ifra_addr.sin_family == AF_INET) {
			struct in_ifaddr *oia;

			lck_rw_lock_shared(in_ifaddr_rwlock);
			for (oia = ia; ia; ia = ia->ia_link.tqe_next) {
				if (ia->ia_ifp == ifp  &&
				    ia->ia_addr.sin_addr.s_addr ==
				    ifra->ifra_addr.sin_addr.s_addr)
					break;
			}
			/* take a reference on ia before releasing lock */
			if (ia != NULL && ia != oia) {
				ifaref(&ia->ia_ifa);
			}
			lck_rw_done(in_ifaddr_rwlock);
			if (oia != NULL && oia != ia) {
				ifafree(&oia->ia_ifa);
			}
			if ((ifp->if_flags & IFF_POINTOPOINT)
			    && (cmd == SIOCAIFADDR)
			    && (ifra->ifra_dstaddr.sin_addr.s_addr
				== INADDR_ANY)) {
				error = EDESTADDRREQ;
				goto done;
			}
		}
		else if (cmd == SIOCAIFADDR) {
			error = EINVAL;
			goto done;
		}
		if (cmd == SIOCDIFADDR && ia == 0) {
			error = EADDRNOTAVAIL;
			goto done;
		}
		/* FALLTHROUGH */
	case SIOCSIFADDR:
	case SIOCSIFNETMASK:
	case SIOCSIFDSTADDR:
		if ((so->so_state & SS_PRIV) == 0) {
			error = EPERM;
			goto done;
		}
		if (ifp == 0) {
			error = EADDRNOTAVAIL;
			goto done;
		}
		if (ifra->ifra_addr.sin_family != AF_INET 
		    && cmd == SIOCSIFADDR) {
			error = EINVAL;
			goto done;
		}
		if (ia == (struct in_ifaddr *)0) {
			ia = in_ifaddr_alloc(M_WAITOK);
			if (ia == (struct in_ifaddr *)NULL) {
				error = ENOBUFS;
				goto done;
			}
			IA_HASH_INIT(ia);
			ifa = &ia->ia_ifa;
			/* Hold a reference for this routine */
			ifaref(ifa);
			ifa->ifa_addr = (struct sockaddr *)&ia->ia_addr;
			ifa->ifa_dstaddr = (struct sockaddr *)&ia->ia_dstaddr;
			ifa->ifa_netmask = (struct sockaddr *)&ia->ia_sockmask;
			ia->ia_sockmask.sin_len = 8;
			ifnet_lock_exclusive(ifp);
			if (ifp->if_flags & IFF_BROADCAST) {
				ia->ia_broadaddr.sin_len = sizeof(ia->ia_addr);
				ia->ia_broadaddr.sin_family = AF_INET;
			}
			ia->ia_ifp = ifp;
			if (!(ifp->if_flags & IFF_LOOPBACK))
				in_interfaces++;
			/* if_attach_ifa() holds a reference for ifa_link */
			if_attach_ifa(ifp, ifa);
			ifnet_lock_done(ifp);
			lck_rw_lock_exclusive(in_ifaddr_rwlock);
			/* Hold a reference for ia_link */
			ifaref(ifa);
			TAILQ_INSERT_TAIL(&in_ifaddrhead, ia, ia_link);
			lck_rw_done(in_ifaddr_rwlock);

			/* Generic protocol plumbing */

			if ((error = proto_plumb(PF_INET, ifp))) {
				if (error != EEXIST) {
					kprintf("in.c: warning can't plumb proto if=%s%d type %d error=%d\n",
						ifp->if_name, ifp->if_unit, ifp->if_type, error);
				}
				error = 0; /*discard error, can be cold with unsupported interfaces */
			}
		}
		break;

	case SIOCPROTOATTACH:
	case SIOCPROTODETACH:
		if ((error = proc_suser(p)) != 0) {
			goto done;
		}
		if (ifp == 0) {
			error = EADDRNOTAVAIL;
			goto done;
		}
		break;

	case SIOCSIFBRDADDR:
		if ((so->so_state & SS_PRIV) == 0) {
			error = EPERM;
			goto done;
		}
		/* FALLTHROUGH */

	case SIOCGIFADDR:
	case SIOCGIFNETMASK:
	case SIOCGIFDSTADDR:
	case SIOCGIFBRDADDR:
		if (ia == (struct in_ifaddr *)0) {
			error = EADDRNOTAVAIL;
			goto done;
		}
		break;
	}
	switch (cmd) {
	case SIOCAUTOADDR:
		ifnet_lock_exclusive(ifp);
		if (ifr->ifr_intval)
			ifp->if_eflags |= IFEF_AUTOCONFIGURING;
		else
			ifp->if_eflags &= ~IFEF_AUTOCONFIGURING;
		ifnet_lock_done(ifp);
		break;
	
	case SIOCARPIPLL:
		ipv4_ll_arp_aware = 1;
		ifnet_lock_exclusive(ifp);
		if (ifr->ifr_data)
			ifp->if_eflags |= IFEF_ARPLL;
		else
			ifp->if_eflags &= ~IFEF_ARPLL;
		ifnet_lock_done(ifp);
		break;

	case SIOCGIFADDR:
		*((struct sockaddr_in *)&ifr->ifr_addr) = ia->ia_addr;
		break;

	case SIOCGIFBRDADDR:
		if ((ifp->if_flags & IFF_BROADCAST) == 0) {
			error = EINVAL;
			break;
		}
		*((struct sockaddr_in *)&ifr->ifr_dstaddr) = ia->ia_broadaddr;
		break;

	case SIOCGIFDSTADDR:
		if ((ifp->if_flags & IFF_POINTOPOINT) == 0) {
			error = EINVAL;
			break;
		}
		*((struct sockaddr_in *)&ifr->ifr_dstaddr) = ia->ia_dstaddr;
		break;

	case SIOCGIFNETMASK:
		*((struct sockaddr_in *)&ifr->ifr_addr) = ia->ia_sockmask;
		break;

	case SIOCSIFDSTADDR:
		if ((ifp->if_flags & IFF_POINTOPOINT) == 0) {
			error = EINVAL;
			break;
		}
		oldaddr = ia->ia_dstaddr;
		ia->ia_dstaddr = *(struct sockaddr_in *)&ifr->ifr_dstaddr;
		if (ia->ia_dstaddr.sin_family == AF_INET)
			ia->ia_dstaddr.sin_len = sizeof (struct sockaddr_in);
		error = ifnet_ioctl(ifp, PF_INET, SIOCSIFDSTADDR, ia);
		if (error == EOPNOTSUPP) {
			error = 0;
		}
		if (error) {
			ia->ia_dstaddr = oldaddr;
			break;
		}

		ev_msg.vendor_code    = KEV_VENDOR_APPLE;
		ev_msg.kev_class      = KEV_NETWORK_CLASS;
		ev_msg.kev_subclass   = KEV_INET_SUBCLASS;
	
		ev_msg.event_code = KEV_INET_SIFDSTADDR;

		if (ia->ia_ifa.ifa_dstaddr)
		     in_event_data.ia_dstaddr = 
			  ((struct sockaddr_in *)ia->ia_ifa.ifa_dstaddr)->sin_addr;
		else
		     in_event_data.ia_dstaddr.s_addr  = 0;

		in_event_data.ia_addr         = ia->ia_addr.sin_addr;
		in_event_data.ia_net          = ia->ia_net;
		in_event_data.ia_netmask      = ia->ia_netmask;
		in_event_data.ia_subnet       = ia->ia_subnet;
		in_event_data.ia_subnetmask   = ia->ia_subnetmask;
		in_event_data.ia_netbroadcast = ia->ia_netbroadcast;
		strncpy(&in_event_data.link_data.if_name[0], ifp->if_name, IFNAMSIZ);
		in_event_data.link_data.if_family = ifp->if_family;
		in_event_data.link_data.if_unit  = (u_int32_t) ifp->if_unit;

		ev_msg.dv[0].data_ptr    = &in_event_data;
		ev_msg.dv[0].data_length      = sizeof(struct kev_in_data);
		ev_msg.dv[1].data_length = 0;

		kev_post_msg(&ev_msg);


		if (ia->ia_flags & IFA_ROUTE) {
			ia->ia_ifa.ifa_dstaddr = (struct sockaddr *)&oldaddr;
			rtinit(&(ia->ia_ifa), (int)RTM_DELETE, RTF_HOST);
			ia->ia_ifa.ifa_dstaddr =
					(struct sockaddr *)&ia->ia_dstaddr;
			rtinit(&(ia->ia_ifa), (int)RTM_ADD, RTF_HOST|RTF_UP);
		}
		break;

	case SIOCSIFBRDADDR:
		if ((ifp->if_flags & IFF_BROADCAST) == 0) {
			error = EINVAL;
			break;
		}
		ia->ia_broadaddr = *(struct sockaddr_in *)&ifr->ifr_broadaddr;

		ev_msg.vendor_code    = KEV_VENDOR_APPLE;
		ev_msg.kev_class      = KEV_NETWORK_CLASS;
		ev_msg.kev_subclass   = KEV_INET_SUBCLASS;
	
		ev_msg.event_code = KEV_INET_SIFBRDADDR;

		if (ia->ia_ifa.ifa_dstaddr)
		     in_event_data.ia_dstaddr = 
			  ((struct sockaddr_in *)ia->ia_ifa.ifa_dstaddr)->sin_addr;
		else
		     in_event_data.ia_dstaddr.s_addr  = 0;

		in_event_data.ia_addr         = ia->ia_addr.sin_addr;
		in_event_data.ia_net          = ia->ia_net;
		in_event_data.ia_netmask      = ia->ia_netmask;
		in_event_data.ia_subnet       = ia->ia_subnet;
		in_event_data.ia_subnetmask   = ia->ia_subnetmask;
		in_event_data.ia_netbroadcast = ia->ia_netbroadcast;
		strncpy(&in_event_data.link_data.if_name[0], ifp->if_name, IFNAMSIZ);
		in_event_data.link_data.if_family = ifp->if_family;
		in_event_data.link_data.if_unit  = (u_int32_t) ifp->if_unit;

		ev_msg.dv[0].data_ptr    = &in_event_data;
		ev_msg.dv[0].data_length      = sizeof(struct kev_in_data);
		ev_msg.dv[1].data_length = 0;

		kev_post_msg(&ev_msg);

		break;

	case SIOCSIFADDR:
		/*
		 * If this is a new address, the reference count for the
		 * hash table has been taken at creation time above.
		 */
		error = in_ifinit(ifp, ia,
		    (struct sockaddr_in *)&ifr->ifr_addr, 1);
#if PF
		if (!error)
			(void) pf_ifaddr_hook(ifp, cmd);
#endif /* PF */
		break;

	case SIOCPROTOATTACH:
		error = proto_plumb(PF_INET, ifp);
		break;
                
	case SIOCPROTODETACH:
                // if an ip address is still present, refuse to detach
		ifnet_lock_shared(ifp);
		TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) 
			if (ifa->ifa_addr->sa_family == AF_INET)
				break;
		ifnet_lock_done(ifp);
		if (ifa != 0) {
			error =  EBUSY;
			break;
		}

		error = proto_unplumb(PF_INET, ifp);
		break;
		

	case SIOCSIFNETMASK: {
		u_long i;
		
		i = ifra->ifra_addr.sin_addr.s_addr;
		ia->ia_subnetmask = ntohl(ia->ia_sockmask.sin_addr.s_addr = i);
		ev_msg.vendor_code    = KEV_VENDOR_APPLE;
		ev_msg.kev_class      = KEV_NETWORK_CLASS;
		ev_msg.kev_subclass   = KEV_INET_SUBCLASS;
	
		ev_msg.event_code = KEV_INET_SIFNETMASK;

		if (ia->ia_ifa.ifa_dstaddr)
		     in_event_data.ia_dstaddr = 
			  ((struct sockaddr_in *)ia->ia_ifa.ifa_dstaddr)->sin_addr;
		else
		     in_event_data.ia_dstaddr.s_addr  = 0;

		in_event_data.ia_addr         = ia->ia_addr.sin_addr;
		in_event_data.ia_net          = ia->ia_net;
		in_event_data.ia_netmask      = ia->ia_netmask;
		in_event_data.ia_subnet       = ia->ia_subnet;
		in_event_data.ia_subnetmask   = ia->ia_subnetmask;
		in_event_data.ia_netbroadcast = ia->ia_netbroadcast;
		strncpy(&in_event_data.link_data.if_name[0], ifp->if_name, IFNAMSIZ);
		in_event_data.link_data.if_family = ifp->if_family;
		in_event_data.link_data.if_unit  = (u_int32_t) ifp->if_unit;

		ev_msg.dv[0].data_ptr    = &in_event_data;
		ev_msg.dv[0].data_length      = sizeof(struct kev_in_data);
		ev_msg.dv[1].data_length = 0;

		kev_post_msg(&ev_msg);

		break;
	}
	case SIOCAIFADDR:
		maskIsNew = 0;
		hostIsNew = 1;
		error = 0;

		if (ia->ia_addr.sin_family == AF_INET) {
			if (ifra->ifra_addr.sin_len == 0) {
				ifra->ifra_addr = ia->ia_addr;
				hostIsNew = 0;
			} else if (ifra->ifra_addr.sin_addr.s_addr ==
					       ia->ia_addr.sin_addr.s_addr)
				hostIsNew = 0;
		}
		if (ifra->ifra_mask.sin_len) {
			in_ifscrub(ifp, ia, 0);
			ia->ia_sockmask = ifra->ifra_mask;
			ia->ia_subnetmask =
			     ntohl(ia->ia_sockmask.sin_addr.s_addr);
			maskIsNew = 1;
		}
		if ((ifp->if_flags & IFF_POINTOPOINT) &&
		    (ifra->ifra_dstaddr.sin_family == AF_INET)) {
			in_ifscrub(ifp, ia, 0);
			ia->ia_dstaddr = ifra->ifra_dstaddr;
			ia->ia_dstaddr.sin_len = sizeof (struct sockaddr_in);
			maskIsNew  = 1; /* We lie; but the effect's the same */
		}
		if (ifra->ifra_addr.sin_family == AF_INET &&
		    (hostIsNew || maskIsNew)) {
			error = in_ifinit(ifp, ia, &ifra->ifra_addr, 0);
		}
#if PF
		if (!error)
			(void) pf_ifaddr_hook(ifp, cmd);
#endif /* PF */
		if ((ifp->if_flags & IFF_BROADCAST) &&
		    (ifra->ifra_broadaddr.sin_family == AF_INET))
			ia->ia_broadaddr = ifra->ifra_broadaddr;

		/*
		 * Report event.
		 */

		if ((error == 0) || (error == EEXIST)) {
		     ev_msg.vendor_code    = KEV_VENDOR_APPLE;
		     ev_msg.kev_class      = KEV_NETWORK_CLASS;
		     ev_msg.kev_subclass   = KEV_INET_SUBCLASS;

		     if (hostIsNew)
			  ev_msg.event_code = KEV_INET_NEW_ADDR;
		     else
			  ev_msg.event_code = KEV_INET_CHANGED_ADDR;

		     if (ia->ia_ifa.ifa_dstaddr)
			  in_event_data.ia_dstaddr = 
			       ((struct sockaddr_in *)ia->ia_ifa.ifa_dstaddr)->sin_addr;
		     else
			  in_event_data.ia_dstaddr.s_addr  = 0;

		     in_event_data.ia_addr         = ia->ia_addr.sin_addr;
		     in_event_data.ia_net          = ia->ia_net;
		     in_event_data.ia_netmask      = ia->ia_netmask;
		     in_event_data.ia_subnet       = ia->ia_subnet;
		     in_event_data.ia_subnetmask   = ia->ia_subnetmask;
		     in_event_data.ia_netbroadcast = ia->ia_netbroadcast;
		     strncpy(&in_event_data.link_data.if_name[0], ifp->if_name, IFNAMSIZ);
		     in_event_data.link_data.if_family = ifp->if_family;
		     in_event_data.link_data.if_unit  = (u_int32_t) ifp->if_unit;

		     ev_msg.dv[0].data_ptr    = &in_event_data;
		     ev_msg.dv[0].data_length      = sizeof(struct kev_in_data);
		     ev_msg.dv[1].data_length = 0;

		     kev_post_msg(&ev_msg);
		}
		break;

	case SIOCDIFADDR:
		error = ifnet_ioctl(ifp, PF_INET, SIOCDIFADDR, ia);
		if (error == EOPNOTSUPP)
			error = 0;
		if (error != 0) {
			break;
		}

		/* Fill out the kernel event information */
		ev_msg.vendor_code    = KEV_VENDOR_APPLE;
		ev_msg.kev_class      = KEV_NETWORK_CLASS;
		ev_msg.kev_subclass   = KEV_INET_SUBCLASS;
		
		ev_msg.event_code = KEV_INET_ADDR_DELETED;

		if (ia->ia_ifa.ifa_dstaddr)
		     in_event_data.ia_dstaddr = 
			  ((struct sockaddr_in *)ia->ia_ifa.ifa_dstaddr)->sin_addr;
		else
		     in_event_data.ia_dstaddr.s_addr  = 0;

		in_event_data.ia_addr         = ia->ia_addr.sin_addr;
		in_event_data.ia_net          = ia->ia_net;
		in_event_data.ia_netmask      = ia->ia_netmask;
		in_event_data.ia_subnet       = ia->ia_subnet;
		in_event_data.ia_subnetmask   = ia->ia_subnetmask;
		in_event_data.ia_netbroadcast = ia->ia_netbroadcast;
		strncpy(&in_event_data.link_data.if_name[0], ifp->if_name, IFNAMSIZ);
		in_event_data.link_data.if_family = ifp->if_family;
		in_event_data.link_data.if_unit  = (u_int32_t) ifp->if_unit;

		ev_msg.dv[0].data_ptr    = &in_event_data;
		ev_msg.dv[0].data_length = sizeof(struct kev_in_data);
		ev_msg.dv[1].data_length = 0;

		ifa = &ia->ia_ifa;
		lck_rw_lock_exclusive(in_ifaddr_rwlock);
		/* Release ia_link reference */
		ifafree(ifa);
		TAILQ_REMOVE(&in_ifaddrhead, ia, ia_link);
		if (IA_IS_HASHED(ia))
			in_iahash_remove(ia);
		lck_rw_done(in_ifaddr_rwlock);

		/*
		 * in_ifscrub kills the interface route.
		 */
		in_ifscrub(ifp, ia, 0);
		ifnet_lock_exclusive(ifp);
		/* if_detach_ifa() releases ifa_link reference */
		if_detach_ifa(ifp, ifa);
#ifdef __APPLE__
	       /*
		* If the interface supports multicast, and no address is left,
		* remove the "all hosts" multicast group from that interface.
		*/
		if (ifp->if_flags & IFF_MULTICAST) {
			struct in_addr addr;
			struct in_multi *inm = NULL;

			TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) 
				if (ifa->ifa_addr->sa_family == AF_INET)
					break;

			if (ifa == 0) {
				addr.s_addr = htonl(INADDR_ALLHOSTS_GROUP);
				IN_LOOKUP_MULTI(addr, ifp, inm);
			}
			ifnet_lock_done(ifp);
			if (inm)
		  	  	in_delmulti(&inm);
		} else 
			ifnet_lock_done(ifp);
#endif

		/* Post the kernel event */
		kev_post_msg(&ev_msg);

		/*
		 * See if there is any IPV4 address left and if so,
		 * reconfigure KDP to use current primary address.
		 */
		ifa = ifa_ifpgetprimary(ifp, AF_INET);
		if (ifa != NULL) {
			error = ifnet_ioctl(ifp, PF_INET, SIOCSIFADDR, ifa);
			if (error == EOPNOTSUPP)
				error = 0;

			/* Release reference from ifa_ifpgetprimary() */
			ifafree(ifa);
		}
#if PF
		(void) pf_ifaddr_hook(ifp, cmd);
#endif /* PF */
		break;

#ifdef __APPLE__
    case SIOCSETOT: {
        /*
         * Inspiration from tcp_ctloutput() and ip_ctloutput()
         * Special ioctl for OpenTransport sockets
         */
        struct	inpcb	*inp, *cloned_inp;
        int 			error2 = 0;
        int 			cloned_fd = *(int *)data;

        inp = sotoinpcb(so);
        if (inp == NULL) {
            break;
        }

        /* let's make sure it's either -1 or a valid file descriptor */
        if (cloned_fd != -1) {
            struct socket	*cloned_so;
            error2 = file_socket(cloned_fd, &cloned_so);
            if (error2){
                break;
            }
            cloned_inp = sotoinpcb(cloned_so);
			file_drop(cloned_fd);
        } else {
            cloned_inp = NULL;
        }

        if (cloned_inp == NULL) {
            /* OT always uses IP_PORTRANGE_HIGH */
            inp->inp_flags &= ~(INP_LOWPORT);
            inp->inp_flags |= INP_HIGHPORT;
            /* For UDP, OT allows broadcast by default */
            if (so->so_type == SOCK_DGRAM)
                so->so_options |= SO_BROADCAST;
            /* For TCP we want to see MSG_OOB when receive urgent data */
            else if (so->so_type == SOCK_STREAM)
                so->so_options |= SO_WANTOOBFLAG;
        } else {
            inp->inp_ip_tos = cloned_inp->inp_ip_tos;
            inp->inp_ip_ttl = cloned_inp->inp_ip_ttl;
            inp->inp_flags = cloned_inp->inp_flags;

            /* Multicast options */
            if (cloned_inp->inp_moptions != NULL) {
                int			i;
                struct ip_moptions	*cloned_imo = cloned_inp->inp_moptions;
                struct ip_moptions	*imo = inp->inp_moptions;

                if (imo == NULL) {
                    /*
                     * No multicast option buffer attached to the pcb;
                     * allocate one.
                     */
                    imo = (struct ip_moptions*)
                        _MALLOC(sizeof(*imo), M_IPMOPTS, M_WAITOK);
                    if (imo == NULL) {
                        error2 = ENOBUFS;
                        break;
                    }
                    inp->inp_moptions = imo;
                }
                imo->imo_multicast_ifp = cloned_imo->imo_multicast_ifp;
                imo->imo_multicast_vif = cloned_imo->imo_multicast_vif;
                imo->imo_multicast_ttl = cloned_imo->imo_multicast_ttl;
                imo->imo_multicast_loop = cloned_imo->imo_multicast_loop;
                imo->imo_num_memberships = cloned_imo->imo_num_memberships;
                for (i = 0; i < cloned_imo->imo_num_memberships; i++) {
                    imo->imo_membership[i] =
                    in_addmulti(&cloned_imo->imo_membership[i]->inm_addr,
                                cloned_imo->imo_membership[i]->inm_ifp);
					if (imo->imo_membership[i] == NULL) {
						error2 = ENOBUFS;
						break;
					}
                }
                if (i < cloned_imo->imo_num_memberships) {
                	/* Failed, perform cleanup */
                	for (i--; i >= 0; i--)
                		in_delmulti(&imo->imo_membership[i]);
                	imo->imo_num_memberships = 0;
                	break;
                }
            }
        }
        break;
    }
#endif /* __APPLE__ */

	default:
		error = EOPNOTSUPP;
	}
 done:
	if (ia != NULL) {
		ifafree(&ia->ia_ifa);
	}
	return (error);
}

/*
 * SIOC[GAD]LIFADDR.
 *	SIOCGLIFADDR: get first address. (?!?)
 *	SIOCGLIFADDR with IFLR_PREFIX:
 *		get first address that matches the specified prefix.
 *	SIOCALIFADDR: add the specified address.
 *	SIOCALIFADDR with IFLR_PREFIX:
 *		EINVAL since we can't deduce hostid part of the address.
 *	SIOCDLIFADDR: delete the specified address.
 *	SIOCDLIFADDR with IFLR_PREFIX:
 *		delete the first address that matches the specified prefix.
 * return values:
 *	EINVAL on invalid parameters
 *	EADDRNOTAVAIL on prefix match failed/specified address not found
 *	other values may be returned from in_ioctl()
 */
static int
in_lifaddr_ioctl(
	struct socket *so,
	u_long cmd,
	caddr_t	data,
	struct ifnet *ifp,
	struct proc *p)
{
	struct if_laddrreq *iflr = (struct if_laddrreq *)data;
	struct ifaddr *ifa;

	/* sanity checks */
	if (!data || !ifp) {
		panic("invalid argument to in_lifaddr_ioctl");
		/*NOTRECHED*/
	}

	switch (cmd) {
	case SIOCGLIFADDR:
		/* address must be specified on GET with IFLR_PREFIX */
		if ((iflr->flags & IFLR_PREFIX) == 0)
			break;
		/*FALLTHROUGH*/
	case SIOCALIFADDR:
	case SIOCDLIFADDR:
		/* address must be specified on ADD and DELETE */
		if (iflr->addr.ss_family != AF_INET)
			return EINVAL;
		if (iflr->addr.ss_len != sizeof(struct sockaddr_in))
			return EINVAL;
		/* XXX need improvement */
		if (iflr->dstaddr.ss_family
		 && iflr->dstaddr.ss_family != AF_INET)
			return EINVAL;
		if (iflr->dstaddr.ss_family
		 && iflr->dstaddr.ss_len != sizeof(struct sockaddr_in))
			return EINVAL;
		break;
	default: /*shouldn't happen*/
		return EOPNOTSUPP;
	}
	if (sizeof(struct in_addr) * 8 < iflr->prefixlen)
		return EINVAL;

	switch (cmd) {
	case SIOCALIFADDR:
	    {
		struct in_aliasreq ifra;

		if (iflr->flags & IFLR_PREFIX)
			return EINVAL;

		/* copy args to in_aliasreq, perform ioctl(SIOCAIFADDR_IN6). */
		bzero(&ifra, sizeof(ifra));
		bcopy(iflr->iflr_name, ifra.ifra_name,
			sizeof(ifra.ifra_name));

		bcopy(&iflr->addr, &ifra.ifra_addr, iflr->addr.ss_len);

		if (iflr->dstaddr.ss_family) {	/*XXX*/
			bcopy(&iflr->dstaddr, &ifra.ifra_dstaddr,
				iflr->dstaddr.ss_len);
		}

		ifra.ifra_mask.sin_family = AF_INET;
		ifra.ifra_mask.sin_len = sizeof(struct sockaddr_in);
		in_len2mask(&ifra.ifra_mask.sin_addr, iflr->prefixlen);

		return in_control(so, SIOCAIFADDR, (caddr_t)&ifra, ifp, p);
	    }
	case SIOCGLIFADDR:
	case SIOCDLIFADDR:
	    {
		struct in_ifaddr *ia;
		struct in_addr mask, candidate;
		struct in_addr match = { 0 };
		struct sockaddr_in *sin;
		int cmp;

		bzero(&mask, sizeof(mask));
		if (iflr->flags & IFLR_PREFIX) {
			/* lookup a prefix rather than address. */
			in_len2mask(&mask, iflr->prefixlen);

			sin = (struct sockaddr_in *)&iflr->addr;
			match.s_addr = sin->sin_addr.s_addr;
			match.s_addr &= mask.s_addr;

			/* if you set extra bits, that's wrong */
			if (match.s_addr != sin->sin_addr.s_addr)
				return EINVAL;

			cmp = 1;
		} else {
			if (cmd == SIOCGLIFADDR) {
				/* on getting an address, take the 1st match */
				cmp = 0;	/*XXX*/
			} else {
				/* on deleting an address, do exact match */
				in_len2mask(&mask, 32);
				sin = (struct sockaddr_in *)&iflr->addr;
				match.s_addr = sin->sin_addr.s_addr;

				cmp = 1;
			}
		}

		ifnet_lock_shared(ifp);
		TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link)	{
			if (ifa->ifa_addr->sa_family != AF_INET6)
				continue;
			if (!cmp)
				break;
			candidate.s_addr = ((struct sockaddr_in *)&ifa->ifa_addr)->sin_addr.s_addr;
			candidate.s_addr &= mask.s_addr;
			if (candidate.s_addr == match.s_addr)
				break;
		}
		ifnet_lock_done(ifp);
		if (!ifa)
			return EADDRNOTAVAIL;
		ia = (struct in_ifaddr *)ifa;

		if (cmd == SIOCGLIFADDR) {
			/* fill in the if_laddrreq structure */
			bcopy(&ia->ia_addr, &iflr->addr, ia->ia_addr.sin_len);

			if ((ifp->if_flags & IFF_POINTOPOINT) != 0) {
				bcopy(&ia->ia_dstaddr, &iflr->dstaddr,
					ia->ia_dstaddr.sin_len);
			} else
				bzero(&iflr->dstaddr, sizeof(iflr->dstaddr));

			iflr->prefixlen =
				in_mask2len(&ia->ia_sockmask.sin_addr);

			iflr->flags = 0;	/*XXX*/

			return 0;
		} else {
			struct in_aliasreq ifra;

			/* fill in_aliasreq and do ioctl(SIOCDIFADDR_IN6) */
			bzero(&ifra, sizeof(ifra));
			bcopy(iflr->iflr_name, ifra.ifra_name,
				sizeof(ifra.ifra_name));

			bcopy(&ia->ia_addr, &ifra.ifra_addr,
				ia->ia_addr.sin_len);
			if ((ifp->if_flags & IFF_POINTOPOINT) != 0) {
				bcopy(&ia->ia_dstaddr, &ifra.ifra_dstaddr,
					ia->ia_dstaddr.sin_len);
			}
			bcopy(&ia->ia_sockmask, &ifra.ifra_dstaddr,
				ia->ia_sockmask.sin_len);

			return in_control(so, SIOCDIFADDR, (caddr_t)&ifra,
					  ifp, p);
		}
	    }
	}

	return EOPNOTSUPP;	/*just for safety*/
}

/*
 * Delete any existing route for an interface.
 */
void
in_ifscrub(
	struct ifnet *ifp,
	struct in_ifaddr *ia,
	int locked)
{

	if ((ia->ia_flags & IFA_ROUTE) == 0)
		return;
	if (!locked)
		lck_mtx_lock(rnh_lock);
	if (ifp->if_flags & (IFF_LOOPBACK|IFF_POINTOPOINT))
		rtinit_locked(&(ia->ia_ifa), (int)RTM_DELETE, RTF_HOST);
	else
		rtinit_locked(&(ia->ia_ifa), (int)RTM_DELETE, 0);
	ia->ia_flags &= ~IFA_ROUTE;
	if (!locked)
		lck_mtx_unlock(rnh_lock);
}

/*
 * Caller must hold in_ifaddr_rwlock as writer.
 */
static void
in_iahash_remove(struct in_ifaddr *ia)
{
	if (!IA_IS_HASHED(ia))
		panic("attempt to remove wrong ia %p from hash table\n", ia);

	TAILQ_REMOVE(INADDR_HASH(ia->ia_addr.sin_addr.s_addr), ia, ia_hash);
	IA_HASH_INIT(ia);
	ifafree(&ia->ia_ifa);
}

/*
 * Caller must hold in_ifaddr_rwlock as writer.
 */
static void
in_iahash_insert(struct in_ifaddr *ia)
{
	if (ia->ia_addr.sin_family != AF_INET)
		panic("attempt to insert wrong ia %p into hash table\n", ia);
	else if (IA_IS_HASHED(ia))
		panic("attempt to double-insert ia %p into hash table\n", ia);

	TAILQ_INSERT_HEAD(INADDR_HASH(ia->ia_addr.sin_addr.s_addr), ia, ia_hash);
	ifaref(&ia->ia_ifa);
}

/*
 * Some point to point interfaces that are tunnels
 * borrow the address from an underlying interface (e.g.
 * VPN server). In order for source address selection logic to 
 * find the underlying interface first, we add the address 
 * of borrowing point to point interfaces at the end of the list.
 * (see rdar://6733789)
 *
 * Caller must hold in_ifaddr_rwlock as writer.
 */
static void
in_iahash_insert_ptp(struct in_ifaddr *ia)
{
	struct in_ifaddr *tmp_ifa;
	struct ifnet *tmp_ifp;

	if (ia->ia_addr.sin_family != AF_INET)
		panic("attempt to insert wrong ia %p into hash table\n", ia);
	else if (IA_IS_HASHED(ia))
		panic("attempt to double-insert ia %p into hash table\n", ia);
        
	TAILQ_FOREACH(tmp_ifa, INADDR_HASH(ia->ia_addr.sin_addr.s_addr), ia_hash)
		if (IA_SIN(tmp_ifa)->sin_addr.s_addr == ia->ia_addr.sin_addr.s_addr)
			break;
	tmp_ifp = (tmp_ifa == NULL) ? NULL : tmp_ifa->ia_ifp;

	if (tmp_ifp == NULL)
		TAILQ_INSERT_HEAD(INADDR_HASH(ia->ia_addr.sin_addr.s_addr), ia, ia_hash);
	else
		TAILQ_INSERT_TAIL(INADDR_HASH(ia->ia_addr.sin_addr.s_addr), ia, ia_hash);
	
	ifaref(&ia->ia_ifa);
}

/*
 * Initialize an interface's internet address
 * and routing table entry.
 */
static int
in_ifinit(
	struct ifnet *ifp,
	struct in_ifaddr *ia,
	struct sockaddr_in *sin,
	int scrub)
{
	u_int32_t i = ntohl(sin->sin_addr.s_addr);
	struct sockaddr_in oldaddr;
	int flags = RTF_UP, error;
	struct ifaddr *ifa0;
	unsigned int cmd;
	int oldremoved = 0;

	/* Take an extra reference for this routine */
	ifaref(&ia->ia_ifa);

	lck_rw_lock_exclusive(in_ifaddr_rwlock);
	oldaddr = ia->ia_addr;
	if (IA_IS_HASHED(ia)) {
		oldremoved = 1;
		in_iahash_remove(ia);
	}
	ia->ia_addr = *sin;
	ia->ia_addr.sin_len = sizeof (*sin);
	if ((ifp->if_flags & IFF_POINTOPOINT))
		in_iahash_insert_ptp(ia);
	else	
		in_iahash_insert(ia);
	lck_rw_done(in_ifaddr_rwlock);

	/*
	 * Give the interface a chance to initialize if this is its first
	 * address, and to validate the address if necessary.  Send down
	 * SIOCSIFADDR for first address, and SIOCAIFADDR for alias(es).
	 * We find the first IPV4 address assigned to it and check if this
	 * is the same as the one passed into this routine.
	 */
	ifa0 = ifa_ifpgetprimary(ifp, AF_INET);
	cmd = (&ia->ia_ifa == ifa0) ? SIOCSIFADDR : SIOCAIFADDR;
	error = ifnet_ioctl(ifp, PF_INET, cmd, ia);
	if (error == EOPNOTSUPP)
		error = 0;
	/*
	 * If we've just sent down SIOCAIFADDR, send another ioctl down
	 * for SIOCSIFADDR for the first IPV4 address of the interface,
	 * because an address change on one of the addresses will result
	 * in the removal of the previous first IPV4 address.  KDP needs
	 * be reconfigured with the current primary IPV4 address.
	 */
	if (error == 0 && cmd == SIOCAIFADDR) {
		error = ifnet_ioctl(ifp, PF_INET, SIOCSIFADDR, ifa0);
		if (error == EOPNOTSUPP)
			error = 0;
	}

	/* Release reference from ifa_ifpgetprimary() */
	ifafree(ifa0);

	if (error) {
		lck_rw_lock_exclusive(in_ifaddr_rwlock);
		if (IA_IS_HASHED(ia))
			in_iahash_remove(ia);
		ia->ia_addr = oldaddr;
		if (oldremoved) {
			if ((ifp->if_flags & IFF_POINTOPOINT))
				in_iahash_insert_ptp(ia);
			else
				in_iahash_insert(ia);
		}
		lck_rw_done(in_ifaddr_rwlock);
		/* Release extra reference taken above */
		ifafree(&ia->ia_ifa);
		return (error);
	}
	lck_mtx_lock(rnh_lock);
	if (scrub) {
		ia->ia_ifa.ifa_addr = (struct sockaddr *)&oldaddr;
		in_ifscrub(ifp, ia, 1);
		ia->ia_ifa.ifa_addr = (struct sockaddr *)&ia->ia_addr;
	}
	if (IN_CLASSA(i))
		ia->ia_netmask = IN_CLASSA_NET;
	else if (IN_CLASSB(i))
		ia->ia_netmask = IN_CLASSB_NET;
	else
		ia->ia_netmask = IN_CLASSC_NET;
	/*
	 * The subnet mask usually includes at least the standard network part,
	 * but may may be smaller in the case of supernetting.
	 * If it is set, we believe it.
	 */
	if (ia->ia_subnetmask == 0) {
		ia->ia_subnetmask = ia->ia_netmask;
		ia->ia_sockmask.sin_addr.s_addr = htonl(ia->ia_subnetmask);
	} else
		ia->ia_netmask &= ia->ia_subnetmask;
	ia->ia_net = i & ia->ia_netmask;
	ia->ia_subnet = i & ia->ia_subnetmask;
	in_socktrim(&ia->ia_sockmask);
	/*
	 * Add route for the network.
	 */
	ia->ia_ifa.ifa_metric = ifp->if_metric;
	if (ifp->if_flags & IFF_BROADCAST) {
		ia->ia_broadaddr.sin_addr.s_addr =
			htonl(ia->ia_subnet | ~ia->ia_subnetmask);
		ia->ia_netbroadcast.s_addr =
			htonl(ia->ia_net | ~ ia->ia_netmask);
	} else if (ifp->if_flags & IFF_LOOPBACK) {
		ia->ia_ifa.ifa_dstaddr = ia->ia_ifa.ifa_addr;
		flags |= RTF_HOST;
	} else if (ifp->if_flags & IFF_POINTOPOINT) {
		if (ia->ia_dstaddr.sin_family != AF_INET) {
			lck_mtx_unlock(rnh_lock);
			/* Release extra reference taken above */
			ifafree(&ia->ia_ifa);
			return (0);
		}
		ia->ia_dstaddr.sin_len = sizeof (*sin);
		flags |= RTF_HOST;
	}
	if ((error = rtinit_locked(&(ia->ia_ifa), (int)RTM_ADD, flags)) == 0)
		ia->ia_flags |= IFA_ROUTE;
	lck_mtx_unlock(rnh_lock);

	/* XXX check if the subnet route points to the same interface */
	if (error == EEXIST)
		error = 0;

	/*
	 * If the interface supports multicast, join the "all hosts"
	 * multicast group on that interface.
	 */
	if (ifp->if_flags & IFF_MULTICAST) {
		struct in_multi *inm;
		struct in_addr addr;

		addr.s_addr = htonl(INADDR_ALLHOSTS_GROUP);
		ifnet_lock_shared(ifp);
		IN_LOOKUP_MULTI(addr, ifp, inm);
		ifnet_lock_done(ifp);
		if (inm == 0)
			in_addmulti(&addr, ifp);
	}

	/* Release extra reference taken above */
	ifafree(&ia->ia_ifa);
	return (error);
}


/*
 * Return 1 if the address might be a local broadcast address.
 */
int
in_broadcast(
	struct in_addr in,
	struct ifnet *ifp)
{
	struct ifaddr *ifa;
	u_int32_t t;

	if (in.s_addr == INADDR_BROADCAST ||
	    in.s_addr == INADDR_ANY)
		return 1;
	if ((ifp->if_flags & IFF_BROADCAST) == 0)
		return 0;
	t = ntohl(in.s_addr);
	/*
	 * Look through the list of addresses for a match
	 * with a broadcast address.
	 */
#define ia ((struct in_ifaddr *)ifa)
	ifnet_lock_shared(ifp);
	TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
		if (ifa->ifa_addr == NULL) {
			ifnet_lock_done(ifp);
			return (0);
		}
		if (ifa->ifa_addr->sa_family == AF_INET &&
		    (in.s_addr == ia->ia_broadaddr.sin_addr.s_addr ||
		     in.s_addr == ia->ia_netbroadcast.s_addr ||
		     /*
		      * Check for old-style (host 0) broadcast.
		      */
		     t == ia->ia_subnet || t == ia->ia_net) &&
		     /*
		      * Check for an all one subnetmask. These
		      * only exist when an interface gets a secondary
		      * address.
		      */
		     ia->ia_subnetmask != (u_int32_t)0xffffffff) {
			ifnet_lock_done(ifp);
			return 1;
		}
	}
	ifnet_lock_done(ifp);
	return (0);
#undef ia
}

static void
in_free_inm(
	void*	ifma_protospec)
{
	struct in_multi *inm = ifma_protospec;
	
	/*
	 * No remaining claims to this record; let IGMP know that
	 * we are leaving the multicast group.
	 */
	igmp_leavegroup(inm);
	lck_mtx_lock(rnh_lock);
	LIST_REMOVE(inm, inm_link);
	lck_mtx_unlock(rnh_lock);
	FREE(inm, M_IPMADDR);
}

/*
 * Add an address to the list of IP multicast addresses for a given interface.
 */
struct in_multi *
in_addmulti(
	struct in_addr *ap,
	struct ifnet *ifp)
{
	struct in_multi *inm;
	int error;
	struct sockaddr_in sin;
	struct ifmultiaddr *ifma;

	/*
	 * Call generic routine to add membership or increment
	 * refcount.  It wants addresses in the form of a sockaddr,
	 * so we build one here (being careful to zero the unused bytes).
	 */
	bzero(&sin, sizeof sin);
	sin.sin_family = AF_INET;
	sin.sin_len = sizeof sin;
	sin.sin_addr = *ap;
	error = if_addmulti(ifp, (struct sockaddr *)&sin, &ifma);
	if (error) {
		return 0;
	}

	/*
	 * If ifma->ifma_protospec is null, then if_addmulti() created
	 * a new record.  Otherwise, we are done.
	 */
	if (ifma->ifma_protospec != 0) {
		return ifma->ifma_protospec;
	}

	inm = (struct in_multi *) _MALLOC(sizeof(*inm), M_IPMADDR, M_WAITOK);
	if (inm == NULL) {
		return (NULL);
	}

	bzero(inm, sizeof *inm);
	inm->inm_addr = *ap;
	inm->inm_ifp = ifp;
	inm->inm_ifma = ifma;
	lck_mtx_lock(rnh_lock);
	if (ifma->ifma_protospec == NULL) {
		ifma->ifma_protospec = inm;
		ifma->ifma_free = in_free_inm;
		LIST_INSERT_HEAD(&in_multihead, inm, inm_link);
	}
	lck_mtx_unlock(rnh_lock);
	
	if (ifma->ifma_protospec != inm) {
		_FREE(inm, M_IPMADDR);
		return ifma->ifma_protospec;
	}

	/*
	 * Let IGMP know that we have joined a new IP multicast group.
	 */
	error = igmp_joingroup(inm);
	if (error) {
		char addrbuf[16];
		
		/*
		 * We can't free the inm because someone else may already be
		 * using it. Once we put it in to ifma->ifma_protospec, it
		 * must exist as long as the ifma does. Might be nice to flag
		 * the error so we can try igmp_joingroup the next time through.
		 */
		log(LOG_ERR, "igmp_joingroup error %d joining multicast %s on %s%d\n",
			error, inet_ntop(AF_INET, &sin.sin_addr, addrbuf, sizeof(addrbuf)),
			ifp->if_name, ifp->if_unit);
	}
	
	return (inm);
}

/*
 * Delete a multicast address record.
 */
void
in_delmulti(
	struct in_multi **inm)
{
	struct in_multi	*inm2;
	
	lck_mtx_lock(rnh_lock);
	LIST_FOREACH(inm2, &in_multihead, inm_link) {
		if (inm2 == *inm)
			break;
	}
	if (inm2 != *inm) {
		lck_mtx_unlock(rnh_lock);
		printf("in_delmulti - ignoring invalid inm (%p)\n", *inm);
		return;
	}
	lck_mtx_unlock(rnh_lock);
	
	/* We intentionally do this a bit differently than BSD */
	if ((*inm)->inm_ifma) {
		if_delmultiaddr((*inm)->inm_ifma, 0);
		ifma_release((*inm)->inm_ifma);
	}
	*inm = NULL;
}

#if !NFSCLIENT
int inet_aton(char *cp, struct in_addr *pin);
int
inet_aton(char * cp, struct in_addr * pin)
{
    u_char * b = (unsigned char *)pin;
    int	   i;
    char * p;

    for (p = cp, i = 0; i < 4; i++) {
	u_int32_t l = strtoul(p, 0, 0);
	if (l > 255)
	    return (FALSE);
	b[i] = l;
	p = strchr(p, '.');
	if (i < 3 && p == NULL)
	    return (FALSE);
	p++;
    }
    return (TRUE);
}
#endif

/*
 * Called as part of ip_init
 */
void
in_ifaddr_init(void)
{
	PE_parse_boot_argn("ifa_debug", &inifa_debug, sizeof (inifa_debug));

	inifa_size = (inifa_debug == 0) ? sizeof (struct in_ifaddr) :
	    sizeof (struct in_ifaddr_dbg);

	inifa_zone = zinit(inifa_size, INIFA_ZONE_MAX * inifa_size,
	    0, INIFA_ZONE_NAME);
	if (inifa_zone == NULL)
		panic("%s: failed allocating %s", __func__, INIFA_ZONE_NAME);

	zone_change(inifa_zone, Z_EXPAND, TRUE);
}

static struct in_ifaddr *
in_ifaddr_alloc(int how)
{
	struct in_ifaddr *inifa;

	inifa = (how == M_WAITOK) ? zalloc(inifa_zone) :
	    zalloc_noblock(inifa_zone);
	if (inifa != NULL) {
		bzero(inifa, inifa_size);
		inifa->ia_ifa.ifa_free = in_ifaddr_free;
		inifa->ia_ifa.ifa_debug |= IFD_ALLOC;
		if (inifa_debug != 0) {
			struct in_ifaddr_dbg *inifa_dbg =
			    (struct in_ifaddr_dbg *)inifa;
			inifa->ia_ifa.ifa_debug |= IFD_DEBUG;
			inifa->ia_ifa.ifa_trace = in_ifaddr_trace;
			ctrace_record(&inifa_dbg->inifa_alloc);
		}
	}
	return (inifa);
}

static void
in_ifaddr_free(struct ifaddr *ifa)
{
	if (ifa->ifa_refcnt != 0)
		panic("%s: ifa %p bad ref cnt", __func__, ifa);
	if (!(ifa->ifa_debug & IFD_ALLOC))
		panic("%s: ifa %p cannot be freed", __func__, ifa);

	if (ifa->ifa_debug & IFD_DEBUG) {
		struct in_ifaddr_dbg *inifa_dbg = (struct in_ifaddr_dbg *)ifa;
		ctrace_record(&inifa_dbg->inifa_free);
		bcopy(&inifa_dbg->inifa, &inifa_dbg->inifa_old,
		    sizeof (struct in_ifaddr));
	}
	bzero(ifa, sizeof (struct in_ifaddr));
	zfree(inifa_zone, ifa);
}

static void
in_ifaddr_trace(struct ifaddr *ifa, int refhold)
{
	struct in_ifaddr_dbg *inifa_dbg = (struct in_ifaddr_dbg *)ifa;
	ctrace_t *tr;
	u_int32_t idx;
	u_int16_t *cnt;

	if (!(ifa->ifa_debug & IFD_DEBUG))
		panic("%s: ifa %p has no debug structure", __func__, ifa);

	if (refhold) {
		cnt = &inifa_dbg->inifa_refhold_cnt;
		tr = inifa_dbg->inifa_refhold;
	} else {
		cnt = &inifa_dbg->inifa_refrele_cnt;
		tr = inifa_dbg->inifa_refrele;
	}

	idx = OSAddAtomic16(1, (volatile SInt16 *)cnt) % CTRACE_HIST_SIZE;
	ctrace_record(&tr[idx]);
}
