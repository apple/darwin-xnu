/*
 * Copyright (c) 2000-2011 Apple Inc. All rights reserved.
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
#include <sys/mcache.h>
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
static int in_lifaddr_ioctl(struct socket *, u_long, struct if_laddrreq *,
    struct ifnet *, struct proc *);
static int in_setrouter(struct ifnet *, int);

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
static void in_ifaddr_attached(struct ifaddr *);
static void in_ifaddr_detached(struct ifaddr *);
static void in_ifaddr_free(struct ifaddr *);
static void in_ifaddr_trace(struct ifaddr *, int);

static int subnetsarelocal = 0;
SYSCTL_INT(_net_inet_ip, OID_AUTO, subnets_are_local, CTLFLAG_RW | CTLFLAG_LOCKED,
	&subnetsarelocal, 0, "");

/* Track whether or not the SIOCARPIPLL ioctl has been called */
__private_extern__	u_int32_t	ipv4_ll_arp_aware = 0;

#define	INIFA_TRACE_HIST_SIZE	32	/* size of trace history */

/* For gdb */
__private_extern__ unsigned int inifa_trace_hist_size = INIFA_TRACE_HIST_SIZE;

struct in_ifaddr_dbg {
	struct in_ifaddr	inifa;			/* in_ifaddr */
	struct in_ifaddr	inifa_old;		/* saved in_ifaddr */
	u_int16_t		inifa_refhold_cnt;	/* # of IFA_ADDREF */
	u_int16_t		inifa_refrele_cnt;	/* # of IFA_REMREF */
	/*
	 * Alloc and free callers.
	 */
	ctrace_t		inifa_alloc;
	ctrace_t		inifa_free;
	/*
	 * Circular lists of IFA_ADDREF and IFA_REMREF callers.
	 */
	ctrace_t		inifa_refhold[INIFA_TRACE_HIST_SIZE];
	ctrace_t		inifa_refrele[INIFA_TRACE_HIST_SIZE];
	/*
	 * Trash list linkage
	 */
	TAILQ_ENTRY(in_ifaddr_dbg) inifa_trash_link;
};

/* List of trash in_ifaddr entries protected by inifa_trash_lock */
static TAILQ_HEAD(, in_ifaddr_dbg) inifa_trash_head;
static decl_lck_mtx_data(, inifa_trash_lock);

#if DEBUG
static unsigned int inifa_debug = 1;		/* debugging (enabled) */
#else
static unsigned int inifa_debug;		/* debugging (disabled) */
#endif /* !DEBUG */
static unsigned int inifa_size;			/* size of zone element */
static struct zone *inifa_zone;			/* zone for in_ifaddr */

#define	INIFA_ZONE_MAX		64		/* maximum elements in zone */
#define	INIFA_ZONE_NAME		"in_ifaddr"	/* zone name */

/*
 * Return 1 if the address is
 * - loopback
 * - unicast or multicast link local
 * - routed via a link level gateway
 * - belongs to a directly connected (sub)net
 */
int
inaddr_local(struct in_addr in)
{
	struct rtentry *rt;
	struct sockaddr_in sin;
	int local = 0;

	if (ntohl(in.s_addr) == INADDR_LOOPBACK || IN_LINKLOCAL(ntohl(in.s_addr))) {
		local = 1;
	} else if (ntohl(in.s_addr) >= INADDR_UNSPEC_GROUP &&
		ntohl(in.s_addr) <= INADDR_MAX_LOCAL_GROUP) {
			local = 1;
	} else {
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
		     ia = ia->ia_link.tqe_next) {
			IFA_LOCK(&ia->ia_ifa);
			if ((i & ia->ia_netmask) == ia->ia_net) {
				IFA_UNLOCK(&ia->ia_ifa);
				lck_rw_done(in_ifaddr_rwlock);
				return (1);
			}
			IFA_UNLOCK(&ia->ia_ifa);
		}
		lck_rw_done(in_ifaddr_rwlock);
	} else {
		lck_rw_lock_shared(in_ifaddr_rwlock);
		for (ia = in_ifaddrhead.tqh_first; ia;
		     ia = ia->ia_link.tqe_next) {
			IFA_LOCK(&ia->ia_ifa);
			if ((i & ia->ia_subnetmask) == ia->ia_subnet) {
				IFA_UNLOCK(&ia->ia_ifa);
				lck_rw_done(in_ifaddr_rwlock);
				return (1);
			}
			IFA_UNLOCK(&ia->ia_ifa);
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

static int
in_domifattach(struct ifnet *ifp)
{
	int error;

	if ((error = proto_plumb(PF_INET, ifp)) && error != EEXIST)
		log(LOG_ERR, "%s: proto_plumb returned %d if=%s%d\n",
		    __func__, error, ifp->if_name, ifp->if_unit);

	return (error);
}

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
in_control(struct socket *so, u_long cmd, caddr_t data, struct ifnet *ifp,
    struct proc *p)
{
	struct in_ifaddr *ia = NULL;
	struct ifaddr *ifa;
	struct sockaddr_in oldaddr;
	int error = 0;
	int hostIsNew, maskIsNew;
	struct kev_msg ev_msg;
	struct kev_in_data in_event_data;

	bzero(&in_event_data, sizeof (struct kev_in_data));
	bzero(&ev_msg, sizeof (struct kev_msg));

	switch (cmd) {
	case SIOCALIFADDR:		/* struct if_laddrreq */
	case SIOCDLIFADDR:		/* struct if_laddrreq */
		if ((error = proc_suser(p)) != 0)
			return (error);
		/* FALLTHRU */
	case SIOCGLIFADDR: {		/* struct if_laddrreq */
		struct if_laddrreq iflr;

		if (ifp == NULL)
			return (EINVAL);

		bcopy(data, &iflr, sizeof (iflr));
		error = in_lifaddr_ioctl(so, cmd, &iflr, ifp, p);
		bcopy(&iflr, data, sizeof (iflr));
		return (error);
	}
	}

	/*
	 * Find address for this interface, if it exists.
	 *
	 * If an alias address was specified, find that one instead of
	 * the first one on the interface.
	 */
	if (ifp != NULL) {
		struct in_ifaddr *iap;
		struct sockaddr_in sin;

		bcopy(&((struct ifreq *)(void *)data)->ifr_addr,
		    &sin, sizeof (sin));

		lck_rw_lock_shared(in_ifaddr_rwlock);
		for (iap = in_ifaddrhead.tqh_first; iap != NULL;
		     iap = iap->ia_link.tqe_next) {
			if (iap->ia_ifp != ifp)
				continue;

			IFA_LOCK(&iap->ia_ifa);
			if (sin.sin_addr.s_addr ==
			    iap->ia_addr.sin_addr.s_addr) {
				ia = iap;
				IFA_UNLOCK(&iap->ia_ifa);
				break;
			} else if (ia == NULL) {
				ia = iap;
				if (sin.sin_family != AF_INET) {
					IFA_UNLOCK(&iap->ia_ifa);
					break;
				}
			}
			IFA_UNLOCK(&iap->ia_ifa);
		}
		/* take a reference on ia before releasing lock */
		if (ia != NULL)
			IFA_ADDREF(&ia->ia_ifa);
		lck_rw_done(in_ifaddr_rwlock);
	}

	switch (cmd) {
	case SIOCAUTOADDR:		/* struct ifreq */
	case SIOCARPIPLL:		/* struct ifreq */
	case SIOCSETROUTERMODE:		/* struct ifreq */
		if ((error = proc_suser(p)) != 0) {
			goto done;
		}
		if (ifp == NULL) {
			error = EADDRNOTAVAIL;
			goto done;
		}
		break;

	case SIOCAIFADDR:		/* struct ifaliasreq */
	case SIOCDIFADDR: {		/* struct ifreq */
		struct sockaddr_in addr, dstaddr;

		if (ifp == NULL) {
			error = EADDRNOTAVAIL;
			goto done;
		}

		if (cmd == SIOCAIFADDR) {
			bcopy(&((struct in_aliasreq *)(void *)data)->
			    ifra_addr, &addr, sizeof (addr));
			bcopy(&((struct in_aliasreq *)(void *)data)->
			    ifra_dstaddr, &dstaddr, sizeof (dstaddr));
		} else {
			VERIFY(cmd == SIOCDIFADDR);
			bcopy(&((struct ifreq *)(void *)data)->ifr_addr,
			    &addr, sizeof (addr));
			bzero(&dstaddr, sizeof (dstaddr));
		}

		if (addr.sin_family == AF_INET) {
			struct in_ifaddr *oia;

			lck_rw_lock_shared(in_ifaddr_rwlock);
			for (oia = ia; ia; ia = ia->ia_link.tqe_next) {
				IFA_LOCK(&ia->ia_ifa);
				if (ia->ia_ifp == ifp  &&
				    ia->ia_addr.sin_addr.s_addr ==
				    addr.sin_addr.s_addr) {
					IFA_ADDREF_LOCKED(&ia->ia_ifa);
					IFA_UNLOCK(&ia->ia_ifa);
					break;
				}
				IFA_UNLOCK(&ia->ia_ifa);
			}
			lck_rw_done(in_ifaddr_rwlock);
			if (oia != NULL)
				IFA_REMREF(&oia->ia_ifa);
			if ((ifp->if_flags & IFF_POINTOPOINT) &&
			    (cmd == SIOCAIFADDR) &&
			    (dstaddr.sin_addr.s_addr == INADDR_ANY)) {
				error = EDESTADDRREQ;
				goto done;
			}
		} else if (cmd == SIOCAIFADDR) {
			error = EINVAL;
			goto done;
		}
		if (cmd == SIOCDIFADDR && ia == NULL) {
			error = EADDRNOTAVAIL;
			goto done;
		}
		/* FALLTHROUGH */
	}
	case SIOCSIFADDR:		/* struct ifreq */
	case SIOCSIFNETMASK:		/* struct ifreq */
	case SIOCSIFDSTADDR: {		/* struct ifreq */
		struct sockaddr_in addr;

		if (cmd == SIOCAIFADDR) {
			/* fell thru from above; just repeat it */
			bcopy(&((struct in_aliasreq *)(void *)data)->
			    ifra_addr, &addr, sizeof (addr));
		} else {
			VERIFY(cmd == SIOCDIFADDR || cmd == SIOCSIFADDR ||
			    cmd == SIOCSIFNETMASK || cmd == SIOCSIFDSTADDR);
			bcopy(&((struct ifreq *)(void *)data)->ifr_addr,
			    &addr, sizeof (addr));
		}

		/* socket is NULL if called from in_purgeaddrs() */
		if (so != NULL && (so->so_state & SS_PRIV) == 0) {
			error = EPERM;
			goto done;
		}
		/* in case it's NULL, make sure it came from the kernel */
		if (so == NULL && p != kernproc) {
			error = EPERM;
			goto done;
		}
		if (ifp == NULL) {
			error = EADDRNOTAVAIL;
			goto done;
		}
		if (addr.sin_family != AF_INET && cmd == SIOCSIFADDR) {
			error = EINVAL;
			goto done;
		}
		if (ia == NULL) {
			ia = in_ifaddr_alloc(M_WAITOK);
			if (ia == NULL) {
				error = ENOBUFS;
				goto done;
			}
			ifnet_lock_exclusive(ifp);
			ifa = &ia->ia_ifa;
			IFA_LOCK(ifa);
			/* Hold a reference for this routine */
			IFA_ADDREF_LOCKED(ifa);
			IA_HASH_INIT(ia);
			ifa->ifa_addr = (struct sockaddr *)&ia->ia_addr;
			ifa->ifa_dstaddr = (struct sockaddr *)&ia->ia_dstaddr;
			ifa->ifa_netmask = (struct sockaddr *)&ia->ia_sockmask;
			ia->ia_sockmask.sin_len = 8;
			if (ifp->if_flags & IFF_BROADCAST) {
				ia->ia_broadaddr.sin_len = sizeof (ia->ia_addr);
				ia->ia_broadaddr.sin_family = AF_INET;
			}
			ia->ia_ifp = ifp;
			if (!(ifp->if_flags & IFF_LOOPBACK))
				in_interfaces++;
			/* if_attach_ifa() holds a reference for ifa_link */
			if_attach_ifa(ifp, ifa);
			/*
			 * If we have to go through in_ifinit(), make sure
			 * to avoid installing route(s) based on this address
			 * via PFC_IFUP event, before the link resolver (ARP)
			 * initializes it.
			 */
			if (cmd == SIOCAIFADDR || cmd == SIOCSIFADDR)
				ifa->ifa_debug |= IFD_NOTREADY;
			IFA_UNLOCK(ifa);
			ifnet_lock_done(ifp);
			lck_rw_lock_exclusive(in_ifaddr_rwlock);
			/* Hold a reference for ia_link */
			IFA_ADDREF(ifa);
			TAILQ_INSERT_TAIL(&in_ifaddrhead, ia, ia_link);
			lck_rw_done(in_ifaddr_rwlock);
			/* discard error */
			(void) in_domifattach(ifp);
			error = 0;
		}
		break;
	}

	case SIOCPROTOATTACH:		/* struct ifreq */
	case SIOCPROTODETACH:		/* struct ifreq */
		if ((error = proc_suser(p)) != 0) {
			goto done;
		}
		if (ifp == NULL) {
			error = EADDRNOTAVAIL;
			goto done;
		}
		break;

	case SIOCSIFBRDADDR:		/* struct ifreq */
		if ((so->so_state & SS_PRIV) == 0) {
			error = EPERM;
			goto done;
		}
		/* FALLTHROUGH */
	case SIOCGIFADDR:		/* struct ifreq */
	case SIOCGIFNETMASK:		/* struct ifreq */
	case SIOCGIFDSTADDR:		/* struct ifreq */
	case SIOCGIFBRDADDR:		/* struct ifreq */
		if (ia == NULL) {
			error = EADDRNOTAVAIL;
			goto done;
		}
		break;
	}

	switch (cmd) {
	case SIOCAUTOADDR: {		/* struct ifreq */
		int intval;

		VERIFY(ifp != NULL);
		bcopy(&((struct ifreq *)(void *)data)->ifr_intval,
		    &intval, sizeof (intval));

		ifnet_lock_exclusive(ifp);
		if (intval) {
			/*
			 * An interface in IPv4 router mode implies that it
			 * is configured with a static IP address and should
			 * not act as a DHCP client; prevent SIOCAUTOADDR from
			 * being set in that mode.
			 */
			if (ifp->if_eflags & IFEF_IPV4_ROUTER) {
				intval = 0;	/* be safe; clear flag if set */
				error = EBUSY;
			} else {
				ifp->if_eflags |= IFEF_AUTOCONFIGURING;
			}
		}
		if (!intval)
			ifp->if_eflags &= ~IFEF_AUTOCONFIGURING;
		ifnet_lock_done(ifp);
		break;
	}

	case SIOCARPIPLL: {		/* struct ifreq */
		int intval;

		VERIFY(ifp != NULL);
		bcopy(&((struct ifreq *)(void *)data)->ifr_intval,
		    &intval, sizeof (intval));
		ipv4_ll_arp_aware = 1;

		ifnet_lock_exclusive(ifp);
		if (intval) {
			/*
			 * An interface in IPv4 router mode implies that it
			 * is configured with a static IP address and should
			 * not have to deal with IPv4 Link-Local Address;
			 * prevent SIOCARPIPLL from being set in that mode.
			 */
			if (ifp->if_eflags & IFEF_IPV4_ROUTER) {
				intval = 0;	/* be safe; clear flag if set */
				error = EBUSY;
			} else {
				ifp->if_eflags |= IFEF_ARPLL;
			}
		}
		if (!intval)
			ifp->if_eflags &= ~IFEF_ARPLL;
		ifnet_lock_done(ifp);
		break;
	}

	case SIOCGIFADDR:		/* struct ifreq */
		VERIFY(ia != NULL);
		IFA_LOCK(&ia->ia_ifa);
		bcopy(&ia->ia_addr, &((struct ifreq *)(void *)data)->ifr_addr,
		    sizeof (struct sockaddr_in));
		IFA_UNLOCK(&ia->ia_ifa);
		break;

	case SIOCGIFBRDADDR:		/* struct ifreq */
		VERIFY(ia != NULL);
		if ((ifp->if_flags & IFF_BROADCAST) == 0) {
			error = EINVAL;
			break;
		}
		IFA_LOCK(&ia->ia_ifa);
		bcopy(&ia->ia_broadaddr,
		    &((struct ifreq *)(void *)data)->ifr_broadaddr,
		    sizeof (struct sockaddr_in));
		IFA_UNLOCK(&ia->ia_ifa);
		break;

	case SIOCGIFDSTADDR:		/* struct ifreq */
		VERIFY(ia != NULL);
		if ((ifp->if_flags & IFF_POINTOPOINT) == 0) {
			error = EINVAL;
			break;
		}
		IFA_LOCK(&ia->ia_ifa);
		bcopy(&ia->ia_dstaddr,
		    &((struct ifreq *)(void *)data)->ifr_dstaddr,
		    sizeof (struct sockaddr_in));
		IFA_UNLOCK(&ia->ia_ifa);
		break;

	case SIOCGIFNETMASK:		/* struct ifreq */
		VERIFY(ia != NULL);
		IFA_LOCK(&ia->ia_ifa);
		bcopy(&ia->ia_sockmask,
		    &((struct ifreq *)(void *)data)->ifr_addr,
		    sizeof (struct sockaddr_in));
		IFA_UNLOCK(&ia->ia_ifa);
		break;

	case SIOCSIFDSTADDR:		/* struct ifreq */
		VERIFY(ifp != NULL && ia != NULL);
		if ((ifp->if_flags & IFF_POINTOPOINT) == 0) {
			error = EINVAL;
			break;
		}
		IFA_LOCK(&ia->ia_ifa);
		oldaddr = ia->ia_dstaddr;
		bcopy(&((struct ifreq *)(void *)data)->ifr_dstaddr,
		    &ia->ia_dstaddr, sizeof (struct sockaddr_in));
		if (ia->ia_dstaddr.sin_family == AF_INET)
			ia->ia_dstaddr.sin_len = sizeof (struct sockaddr_in);
		IFA_UNLOCK(&ia->ia_ifa);
		/*
		 * NOTE: SIOCSIFDSTADDR is defined with struct ifreq
		 * as parameter, but here we are sending it down
		 * to the interface with a pointer to struct ifaddr,
		 * for legacy reasons.
		 */
		error = ifnet_ioctl(ifp, PF_INET, SIOCSIFDSTADDR, ia);
		IFA_LOCK(&ia->ia_ifa);
		if (error == EOPNOTSUPP) {
			error = 0;
		}
		if (error) {
			ia->ia_dstaddr = oldaddr;
			IFA_UNLOCK(&ia->ia_ifa);
			break;
		}
		IFA_LOCK_ASSERT_HELD(&ia->ia_ifa);

		ev_msg.vendor_code    = KEV_VENDOR_APPLE;
		ev_msg.kev_class      = KEV_NETWORK_CLASS;
		ev_msg.kev_subclass   = KEV_INET_SUBCLASS;

		ev_msg.event_code = KEV_INET_SIFDSTADDR;

		if (ia->ia_ifa.ifa_dstaddr) {
			in_event_data.ia_dstaddr = ((struct sockaddr_in *)
			    (void *)ia->ia_ifa.ifa_dstaddr)->sin_addr;
		} else {
			in_event_data.ia_dstaddr.s_addr = INADDR_ANY;
		}

		in_event_data.ia_addr         = ia->ia_addr.sin_addr;
		in_event_data.ia_net          = ia->ia_net;
		in_event_data.ia_netmask      = ia->ia_netmask;
		in_event_data.ia_subnet       = ia->ia_subnet;
		in_event_data.ia_subnetmask   = ia->ia_subnetmask;
		in_event_data.ia_netbroadcast = ia->ia_netbroadcast;
		IFA_UNLOCK(&ia->ia_ifa);
		(void) strncpy(&in_event_data.link_data.if_name[0],
		    ifp->if_name, IFNAMSIZ);
		in_event_data.link_data.if_family = ifp->if_family;
		in_event_data.link_data.if_unit  = (u_int32_t) ifp->if_unit;

		ev_msg.dv[0].data_ptr    = &in_event_data;
		ev_msg.dv[0].data_length = sizeof (struct kev_in_data);
		ev_msg.dv[1].data_length = 0;

		kev_post_msg(&ev_msg);

		lck_mtx_lock(rnh_lock);
		IFA_LOCK(&ia->ia_ifa);
		if (ia->ia_flags & IFA_ROUTE) {
			ia->ia_ifa.ifa_dstaddr = (struct sockaddr *)&oldaddr;
			IFA_UNLOCK(&ia->ia_ifa);
			rtinit_locked(&(ia->ia_ifa), (int)RTM_DELETE, RTF_HOST);
			IFA_LOCK(&ia->ia_ifa);
			ia->ia_ifa.ifa_dstaddr =
			    (struct sockaddr *)&ia->ia_dstaddr;
			IFA_UNLOCK(&ia->ia_ifa);
			rtinit_locked(&(ia->ia_ifa), (int)RTM_ADD,
			    RTF_HOST|RTF_UP);
		} else {
			IFA_UNLOCK(&ia->ia_ifa);
		}
		lck_mtx_unlock(rnh_lock);
		break;

	case SIOCSIFBRDADDR:		/* struct ifreq */
		VERIFY(ia != NULL);
		if ((ifp->if_flags & IFF_BROADCAST) == 0) {
			error = EINVAL;
			break;
		}
		IFA_LOCK(&ia->ia_ifa);
		bcopy(&((struct ifreq *)(void *)data)->ifr_broadaddr,
		    &ia->ia_broadaddr, sizeof (struct sockaddr_in));

		ev_msg.vendor_code    = KEV_VENDOR_APPLE;
		ev_msg.kev_class      = KEV_NETWORK_CLASS;
		ev_msg.kev_subclass   = KEV_INET_SUBCLASS;

		ev_msg.event_code = KEV_INET_SIFBRDADDR;

		if (ia->ia_ifa.ifa_dstaddr) {
			in_event_data.ia_dstaddr = ((struct sockaddr_in *)
			    (void *)ia->ia_ifa.ifa_dstaddr)->sin_addr;
		} else {
			in_event_data.ia_dstaddr.s_addr = INADDR_ANY;
		}
		in_event_data.ia_addr         = ia->ia_addr.sin_addr;
		in_event_data.ia_net          = ia->ia_net;
		in_event_data.ia_netmask      = ia->ia_netmask;
		in_event_data.ia_subnet       = ia->ia_subnet;
		in_event_data.ia_subnetmask   = ia->ia_subnetmask;
		in_event_data.ia_netbroadcast = ia->ia_netbroadcast;
		IFA_UNLOCK(&ia->ia_ifa);
		(void) strncpy(&in_event_data.link_data.if_name[0],
		    ifp->if_name, IFNAMSIZ);
		in_event_data.link_data.if_family = ifp->if_family;
		in_event_data.link_data.if_unit  = (u_int32_t) ifp->if_unit;

		ev_msg.dv[0].data_ptr    = &in_event_data;
		ev_msg.dv[0].data_length = sizeof (struct kev_in_data);
		ev_msg.dv[1].data_length = 0;

		kev_post_msg(&ev_msg);
		break;

	case SIOCSIFADDR: {		/* struct ifreq */
		struct sockaddr_in addr;

		VERIFY(ifp != NULL && ia != NULL);
		bcopy(&((struct ifreq *)(void *)data)->ifr_addr,
		    &addr, sizeof (addr));
		/*
		 * If this is a new address, the reference count for the
		 * hash table has been taken at creation time above.
		 */
		error = in_ifinit(ifp, ia, &addr, 1);
#if PF
		if (!error)
			(void) pf_ifaddr_hook(ifp, cmd);
#endif /* PF */
		break;
	}

	case SIOCPROTOATTACH:		/* struct ifreq */
		VERIFY(ifp != NULL);
		error = in_domifattach(ifp);
		break;

	case SIOCPROTODETACH:		/* struct ifreq */
		VERIFY(ifp != NULL);
                /*
		 * If an IPv4 address is still present, refuse to detach.
		 */
		ifnet_lock_shared(ifp);
		TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
			IFA_LOCK(ifa);
			if (ifa->ifa_addr->sa_family == AF_INET) {
				IFA_UNLOCK(ifa);
				break;
			}
			IFA_UNLOCK(ifa);
		}
		ifnet_lock_done(ifp);
		if (ifa != NULL) {
			error =  EBUSY;
			break;
		}

		error = proto_unplumb(PF_INET, ifp);
		break;

	case SIOCSETROUTERMODE: {	/* struct ifreq */
		int intval;

		VERIFY(ifp != NULL);
		bcopy(&((struct ifreq *)(void *)data)->ifr_intval,
		    &intval, sizeof (intval));

		error = in_setrouter(ifp, intval);
		break;
	}

	case SIOCSIFNETMASK: {		/* struct ifreq */
		struct sockaddr_in addr;
		in_addr_t i;

		VERIFY(ifp != NULL && ia != NULL);
		bcopy(&((struct ifreq *)(void *)data)->ifr_addr,
		    &addr, sizeof (addr));
		i = addr.sin_addr.s_addr;

		IFA_LOCK(&ia->ia_ifa);
		ia->ia_subnetmask = ntohl(ia->ia_sockmask.sin_addr.s_addr = i);
		ev_msg.vendor_code    = KEV_VENDOR_APPLE;
		ev_msg.kev_class      = KEV_NETWORK_CLASS;
		ev_msg.kev_subclass   = KEV_INET_SUBCLASS;

		ev_msg.event_code = KEV_INET_SIFNETMASK;

		if (ia->ia_ifa.ifa_dstaddr) {
		     in_event_data.ia_dstaddr = ((struct sockaddr_in *)
		         (void *)ia->ia_ifa.ifa_dstaddr)->sin_addr;
		} else {
			in_event_data.ia_dstaddr.s_addr = INADDR_ANY;
		}
		in_event_data.ia_addr         = ia->ia_addr.sin_addr;
		in_event_data.ia_net          = ia->ia_net;
		in_event_data.ia_netmask      = ia->ia_netmask;
		in_event_data.ia_subnet       = ia->ia_subnet;
		in_event_data.ia_subnetmask   = ia->ia_subnetmask;
		in_event_data.ia_netbroadcast = ia->ia_netbroadcast;
		IFA_UNLOCK(&ia->ia_ifa);
		(void) strncpy(&in_event_data.link_data.if_name[0],
		    ifp->if_name, IFNAMSIZ);
		in_event_data.link_data.if_family = ifp->if_family;
		in_event_data.link_data.if_unit  = (u_int32_t) ifp->if_unit;

		ev_msg.dv[0].data_ptr    = &in_event_data;
		ev_msg.dv[0].data_length = sizeof (struct kev_in_data);
		ev_msg.dv[1].data_length = 0;

		kev_post_msg(&ev_msg);
		break;
	}

	case SIOCAIFADDR: {		/* struct ifaliasreq */
		struct sockaddr_in addr, broadaddr, mask;

		VERIFY(ifp != NULL && ia != NULL);
		bcopy(&((struct ifaliasreq *)(void *)data)->ifra_addr,
		    &addr, sizeof (addr));
		bcopy(&((struct ifaliasreq *)(void *)data)->ifra_broadaddr,
		    &broadaddr, sizeof (broadaddr));
		bcopy(&((struct ifaliasreq *)(void *)data)->ifra_mask,
		    &mask, sizeof (mask));

		maskIsNew = 0;
		hostIsNew = 1;
		error = 0;

		IFA_LOCK(&ia->ia_ifa);
		if (ia->ia_addr.sin_family == AF_INET) {
			if (addr.sin_len == 0) {
				addr = ia->ia_addr;
				hostIsNew = 0;
			} else if (addr.sin_addr.s_addr ==
			    ia->ia_addr.sin_addr.s_addr) {
				hostIsNew = 0;
			}
		}
		if (mask.sin_len) {
			IFA_UNLOCK(&ia->ia_ifa);
			in_ifscrub(ifp, ia, 0);
			IFA_LOCK(&ia->ia_ifa);
			ia->ia_sockmask = mask;
			ia->ia_subnetmask =
			     ntohl(ia->ia_sockmask.sin_addr.s_addr);
			maskIsNew = 1;
		}
		if ((ifp->if_flags & IFF_POINTOPOINT) &&
		    (broadaddr.sin_family == AF_INET)) {
			IFA_UNLOCK(&ia->ia_ifa);
			in_ifscrub(ifp, ia, 0);
			IFA_LOCK(&ia->ia_ifa);
			ia->ia_dstaddr = broadaddr;
			ia->ia_dstaddr.sin_len = sizeof (struct sockaddr_in);
			maskIsNew  = 1; /* We lie; but the effect's the same */
		}
		if (addr.sin_family == AF_INET && (hostIsNew || maskIsNew)) {
			IFA_UNLOCK(&ia->ia_ifa);
			error = in_ifinit(ifp, ia, &addr, 0);
		} else {
			IFA_UNLOCK(&ia->ia_ifa);
		}
#if PF
		if (!error)
			(void) pf_ifaddr_hook(ifp, cmd);
#endif /* PF */
		IFA_LOCK(&ia->ia_ifa);
		if ((ifp->if_flags & IFF_BROADCAST) &&
		    (broadaddr.sin_family == AF_INET))
			ia->ia_broadaddr = broadaddr;

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

			if (ia->ia_ifa.ifa_dstaddr) {
				in_event_data.ia_dstaddr =
				    ((struct sockaddr_in *)(void *)ia->
				    ia_ifa.ifa_dstaddr)->sin_addr;
			} else {
				in_event_data.ia_dstaddr.s_addr = INADDR_ANY;
			}
			in_event_data.ia_addr         = ia->ia_addr.sin_addr;
			in_event_data.ia_net          = ia->ia_net;
			in_event_data.ia_netmask      = ia->ia_netmask;
			in_event_data.ia_subnet       = ia->ia_subnet;
			in_event_data.ia_subnetmask   = ia->ia_subnetmask;
			in_event_data.ia_netbroadcast = ia->ia_netbroadcast;
			IFA_UNLOCK(&ia->ia_ifa);
			(void) strncpy(&in_event_data.link_data.if_name[0],
			    ifp->if_name, IFNAMSIZ);
			in_event_data.link_data.if_family = ifp->if_family;
			in_event_data.link_data.if_unit = ifp->if_unit;

			ev_msg.dv[0].data_ptr	 = &in_event_data;
			ev_msg.dv[0].data_length = sizeof (struct kev_in_data);
			ev_msg.dv[1].data_length = 0;

			kev_post_msg(&ev_msg);
		} else {
			IFA_UNLOCK(&ia->ia_ifa);
		}
		break;
	}

	case SIOCDIFADDR:		/* struct ifreq */
		VERIFY(ifp != NULL && ia != NULL);
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

		IFA_LOCK(&ia->ia_ifa);
		if (ia->ia_ifa.ifa_dstaddr) {
		     in_event_data.ia_dstaddr = ((struct sockaddr_in *)
		         (void *)ia->ia_ifa.ifa_dstaddr)->sin_addr;
		} else {
			in_event_data.ia_dstaddr.s_addr = INADDR_ANY;
		}
		in_event_data.ia_addr         = ia->ia_addr.sin_addr;
		in_event_data.ia_net          = ia->ia_net;
		in_event_data.ia_netmask      = ia->ia_netmask;
		in_event_data.ia_subnet       = ia->ia_subnet;
		in_event_data.ia_subnetmask   = ia->ia_subnetmask;
		in_event_data.ia_netbroadcast = ia->ia_netbroadcast;
		IFA_UNLOCK(&ia->ia_ifa);
		(void) strncpy(&in_event_data.link_data.if_name[0],
		    ifp->if_name, IFNAMSIZ);
		in_event_data.link_data.if_family = ifp->if_family;
		in_event_data.link_data.if_unit  = (u_int32_t) ifp->if_unit;

		ev_msg.dv[0].data_ptr    = &in_event_data;
		ev_msg.dv[0].data_length = sizeof(struct kev_in_data);
		ev_msg.dv[1].data_length = 0;

		ifa = &ia->ia_ifa;
		lck_rw_lock_exclusive(in_ifaddr_rwlock);
		/* Release ia_link reference */
		IFA_REMREF(ifa);
		TAILQ_REMOVE(&in_ifaddrhead, ia, ia_link);
		IFA_LOCK(ifa);
		if (IA_IS_HASHED(ia))
			in_iahash_remove(ia);
		IFA_UNLOCK(ifa);
		lck_rw_done(in_ifaddr_rwlock);

		/*
		 * in_ifscrub kills the interface route.
		 */
		in_ifscrub(ifp, ia, 0);
		ifnet_lock_exclusive(ifp);
		IFA_LOCK(ifa);
		/* if_detach_ifa() releases ifa_link reference */
		if_detach_ifa(ifp, ifa);
		/* Our reference to this address is dropped at the bottom */
		IFA_UNLOCK(ifa);

	       /*
		* If the interface supports multicast, and no address is left,
		* remove the "all hosts" multicast group from that interface.
		*/
		if ((ifp->if_flags & IFF_MULTICAST) != 0 ||
			ifp->if_allhostsinm != NULL ) {

			TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
				IFA_LOCK(ifa);
				if (ifa->ifa_addr->sa_family == AF_INET) {
					IFA_UNLOCK(ifa);
					break;
				}
				IFA_UNLOCK(ifa);
			}
			ifnet_lock_done(ifp);

			lck_mtx_lock(&ifp->if_addrconfig_lock);
			if (ifa == NULL && ifp->if_allhostsinm != NULL) {
				struct in_multi *inm = ifp->if_allhostsinm;
				ifp->if_allhostsinm = NULL;

				in_delmulti(inm);
				/* release the reference for allhostsinm */
				INM_REMREF(inm);
			}
			lck_mtx_unlock(&ifp->if_addrconfig_lock);
		} else {
			ifnet_lock_done(ifp);
		}

		/* Post the kernel event */
		kev_post_msg(&ev_msg);

		/*
		 * See if there is any IPV4 address left and if so,
		 * reconfigure KDP to use current primary address.
		 */
		ifa = ifa_ifpgetprimary(ifp, AF_INET);
		if (ifa != NULL) {
			/*
			 * NOTE: SIOCSIFADDR is defined with struct ifreq
			 * as parameter, but here we are sending it down
			 * to the interface with a pointer to struct ifaddr,
			 * for legacy reasons.
			 */
			error = ifnet_ioctl(ifp, PF_INET, SIOCSIFADDR, ifa);
			if (error == EOPNOTSUPP)
				error = 0;

			/* Release reference from ifa_ifpgetprimary() */
			IFA_REMREF(ifa);
		}
#if PF
		(void) pf_ifaddr_hook(ifp, cmd);
#endif /* PF */
		break;

#ifdef __APPLE__
	case SIOCSETOT: {		/* int */
		/*
		 * Inspiration from tcp_ctloutput() and ip_ctloutput()
		 * Special ioctl for OpenTransport sockets
		 */
		struct inpcb *inp, *cloned_inp;
		int error2 = 0;
		int cloned_fd;

		bcopy(data, &cloned_fd, sizeof (cloned_fd));

		inp = sotoinpcb(so);
		if (inp == NULL) {
			break;
		}

		/* let's make sure it's either -1 or a valid file descriptor */
		if (cloned_fd != -1) {
			struct socket	*cloned_so;
			error2 = file_socket(cloned_fd, &cloned_so);
			if (error2) {
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
			/*
			 * For UDP, OT allows broadcast by default;
			 * for TCP we want to see MSG_OOB when we
			 * receive urgent data.
			 */
			if (so->so_type == SOCK_DGRAM)
				so->so_options |= SO_BROADCAST;
			else if (so->so_type == SOCK_STREAM)
				so->so_options |= SO_WANTOOBFLAG;
		} else {
			inp->inp_ip_tos = cloned_inp->inp_ip_tos;
			inp->inp_ip_ttl = cloned_inp->inp_ip_ttl;
			inp->inp_flags = cloned_inp->inp_flags;

			/* Multicast options */
			if (cloned_inp->inp_moptions != NULL)
				error2 = imo_clone(cloned_inp, inp);
		}
		break;
	}
#endif /* __APPLE__ */

	default:
		error = EOPNOTSUPP;
	}
 done:
	if (ia != NULL) {
		IFA_REMREF(&ia->ia_ifa);
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
in_lifaddr_ioctl(struct socket *so, u_long cmd, struct if_laddrreq *iflr,
    struct ifnet *ifp, struct proc *p)
{
	struct ifaddr *ifa;

	VERIFY(ifp != NULL);

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
			IFA_LOCK(ifa);
			if (ifa->ifa_addr->sa_family != AF_INET6) {
				IFA_UNLOCK(ifa);
				continue;
			}
			if (!cmp) {
				IFA_UNLOCK(ifa);
				break;
			}
			candidate.s_addr = ((struct sockaddr_in *)&ifa->ifa_addr)->sin_addr.s_addr;
			candidate.s_addr &= mask.s_addr;
			IFA_UNLOCK(ifa);
			if (candidate.s_addr == match.s_addr)
				break;
		}
		if (ifa != NULL)
			IFA_ADDREF(ifa);
		ifnet_lock_done(ifp);
		if (!ifa)
			return EADDRNOTAVAIL;
		ia = (struct in_ifaddr *)ifa;

		if (cmd == SIOCGLIFADDR) {
			IFA_LOCK(ifa);
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

			IFA_UNLOCK(ifa);
			IFA_REMREF(ifa);
			return 0;
		} else {
			struct in_aliasreq ifra;

			/* fill in_aliasreq and do ioctl(SIOCDIFADDR_IN6) */
			bzero(&ifra, sizeof(ifra));
			bcopy(iflr->iflr_name, ifra.ifra_name,
				sizeof(ifra.ifra_name));

			IFA_LOCK(ifa);
			bcopy(&ia->ia_addr, &ifra.ifra_addr,
				ia->ia_addr.sin_len);
			if ((ifp->if_flags & IFF_POINTOPOINT) != 0) {
				bcopy(&ia->ia_dstaddr, &ifra.ifra_dstaddr,
					ia->ia_dstaddr.sin_len);
			}
			bcopy(&ia->ia_sockmask, &ifra.ifra_dstaddr,
				ia->ia_sockmask.sin_len);
			IFA_UNLOCK(ifa);
			IFA_REMREF(ifa);
			return in_control(so, SIOCDIFADDR, (caddr_t)&ifra,
					  ifp, p);
		}
	    }
	}

	return EOPNOTSUPP;	/*just for safety*/
}

/*
 * Handle SIOCSETROUTERMODE to set or clear the IPv4 router mode flag on
 * the interface.  When in this mode, IPv4 Link-Local Address support is
 * disabled in ARP, and DHCP client support is disabled in IP input; turning
 * any of them on would cause an error to be returned.  Entering or exiting
 * this mode will result in the removal of IPv4 addresses currently configured
 * on the interface.
 */
static int
in_setrouter(struct ifnet *ifp, int enable)
{
	if (ifp->if_flags & IFF_LOOPBACK)
		return (ENODEV);

	ifnet_lock_exclusive(ifp);
	if (enable) {
		ifp->if_eflags |= IFEF_IPV4_ROUTER;
		ifp->if_eflags &= ~(IFEF_ARPLL | IFEF_AUTOCONFIGURING);
	} else {
		ifp->if_eflags &= ~IFEF_IPV4_ROUTER;
	}
	ifnet_lock_done(ifp);

	/* purge all IPv4 addresses configured on this interface */
	in_purgeaddrs(ifp);

	return (0);
}

/*
 * Delete any existing route for an interface.
 */
void
in_ifscrub(struct ifnet *ifp, struct in_ifaddr *ia, int locked)
{
	IFA_LOCK(&ia->ia_ifa);
	if ((ia->ia_flags & IFA_ROUTE) == 0) {
		IFA_UNLOCK(&ia->ia_ifa);
		return;
	}
	IFA_UNLOCK(&ia->ia_ifa);
	if (!locked)
		lck_mtx_lock(rnh_lock);
	if (ifp->if_flags & (IFF_LOOPBACK|IFF_POINTOPOINT))
		rtinit_locked(&(ia->ia_ifa), (int)RTM_DELETE, RTF_HOST);
	else
		rtinit_locked(&(ia->ia_ifa), (int)RTM_DELETE, 0);
	IFA_LOCK(&ia->ia_ifa);
	ia->ia_flags &= ~IFA_ROUTE;
	IFA_UNLOCK(&ia->ia_ifa);
	if (!locked)
		lck_mtx_unlock(rnh_lock);
}

/*
 * Caller must hold in_ifaddr_rwlock as writer.
 */
static void
in_iahash_remove(struct in_ifaddr *ia)
{
        lck_rw_assert(in_ifaddr_rwlock, LCK_RW_ASSERT_EXCLUSIVE);
	IFA_LOCK_ASSERT_HELD(&ia->ia_ifa);

	if (!IA_IS_HASHED(ia)) {
		panic("attempt to remove wrong ia %p from hash table\n", ia);
		/* NOTREACHED */
	}
	TAILQ_REMOVE(INADDR_HASH(ia->ia_addr.sin_addr.s_addr), ia, ia_hash);
	IA_HASH_INIT(ia);
	if (IFA_REMREF_LOCKED(&ia->ia_ifa) == NULL) {
		panic("%s: unexpected (missing) refcnt ifa=%p", __func__,
		    &ia->ia_ifa);
		/* NOTREACHED */
	}
}

/*
 * Caller must hold in_ifaddr_rwlock as writer.
 */
static void
in_iahash_insert(struct in_ifaddr *ia)
{
        lck_rw_assert(in_ifaddr_rwlock, LCK_RW_ASSERT_EXCLUSIVE);
	IFA_LOCK_ASSERT_HELD(&ia->ia_ifa);

	if (ia->ia_addr.sin_family != AF_INET) {
		panic("attempt to insert wrong ia %p into hash table\n", ia);
		/* NOTREACHED */
	} else if (IA_IS_HASHED(ia)) {
		panic("attempt to double-insert ia %p into hash table\n", ia);
		/* NOTREACHED */
	}
	TAILQ_INSERT_HEAD(INADDR_HASH(ia->ia_addr.sin_addr.s_addr), ia, ia_hash);
	IFA_ADDREF_LOCKED(&ia->ia_ifa);
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

        lck_rw_assert(in_ifaddr_rwlock, LCK_RW_ASSERT_EXCLUSIVE);
	IFA_LOCK_ASSERT_HELD(&ia->ia_ifa);

	if (ia->ia_addr.sin_family != AF_INET) {
		panic("attempt to insert wrong ia %p into hash table\n", ia);
		/* NOTREACHED */
	} else if (IA_IS_HASHED(ia)) {
		panic("attempt to double-insert ia %p into hash table\n", ia);
		/* NOTREACHED */
	}
	IFA_UNLOCK(&ia->ia_ifa);
	TAILQ_FOREACH(tmp_ifa, INADDR_HASH(ia->ia_addr.sin_addr.s_addr),
	    ia_hash) {
		IFA_LOCK(&tmp_ifa->ia_ifa);
		/* ia->ia_addr won't change, so check without lock */
		if (IA_SIN(tmp_ifa)->sin_addr.s_addr ==
		    ia->ia_addr.sin_addr.s_addr) {
			IFA_UNLOCK(&tmp_ifa->ia_ifa);
			break;
		}
		IFA_UNLOCK(&tmp_ifa->ia_ifa);
	}
	tmp_ifp = (tmp_ifa == NULL) ? NULL : tmp_ifa->ia_ifp;

	IFA_LOCK(&ia->ia_ifa);
	if (tmp_ifp == NULL) {
		TAILQ_INSERT_HEAD(INADDR_HASH(ia->ia_addr.sin_addr.s_addr),
		    ia, ia_hash);
	} else {
		TAILQ_INSERT_TAIL(INADDR_HASH(ia->ia_addr.sin_addr.s_addr),
		    ia, ia_hash);
	}
	IFA_ADDREF_LOCKED(&ia->ia_ifa);
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
	IFA_ADDREF(&ia->ia_ifa);

	lck_rw_lock_exclusive(in_ifaddr_rwlock);
	IFA_LOCK(&ia->ia_ifa);
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
	IFA_UNLOCK(&ia->ia_ifa);
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
		/*
		 * NOTE: SIOCSIFADDR is defined with struct ifreq
		 * as parameter, but here we are sending it down
		 * to the interface with a pointer to struct ifaddr,
		 * for legacy reasons.
		 */
		error = ifnet_ioctl(ifp, PF_INET, SIOCSIFADDR, ifa0);
		if (error == EOPNOTSUPP)
			error = 0;
	}

	/* Release reference from ifa_ifpgetprimary() */
	IFA_REMREF(ifa0);

	if (error) {
		lck_rw_lock_exclusive(in_ifaddr_rwlock);
		IFA_LOCK(&ia->ia_ifa);
		if (IA_IS_HASHED(ia))
			in_iahash_remove(ia);
		ia->ia_addr = oldaddr;
		if (oldremoved) {
			if ((ifp->if_flags & IFF_POINTOPOINT))
				in_iahash_insert_ptp(ia);
			else
				in_iahash_insert(ia);
		}
		IFA_UNLOCK(&ia->ia_ifa);
		lck_rw_done(in_ifaddr_rwlock);
		/* Release extra reference taken above */
		IFA_REMREF(&ia->ia_ifa);
		return (error);
	}
	lck_mtx_lock(rnh_lock);
	IFA_LOCK(&ia->ia_ifa);
	/*
	 * Address has been initialized by the link resolver (ARP)
	 * via ifnet_ioctl() above; it may now generate route(s).
	 */
	ia->ia_ifa.ifa_debug &= ~IFD_NOTREADY;
	if (scrub) {
		ia->ia_ifa.ifa_addr = (struct sockaddr *)&oldaddr;
		IFA_UNLOCK(&ia->ia_ifa);
		in_ifscrub(ifp, ia, 1);
		IFA_LOCK(&ia->ia_ifa);
		ia->ia_ifa.ifa_addr = (struct sockaddr *)&ia->ia_addr;
	}
	IFA_LOCK_ASSERT_HELD(&ia->ia_ifa);
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
			IFA_UNLOCK(&ia->ia_ifa);
			lck_mtx_unlock(rnh_lock);
			/* Release extra reference taken above */
			IFA_REMREF(&ia->ia_ifa);
			return (0);
		}
		ia->ia_dstaddr.sin_len = sizeof (*sin);
		flags |= RTF_HOST;
	}
	IFA_UNLOCK(&ia->ia_ifa);
	if ((error = rtinit_locked(&(ia->ia_ifa), (int)RTM_ADD, flags)) == 0) {
		IFA_LOCK(&ia->ia_ifa);
		ia->ia_flags |= IFA_ROUTE;
		IFA_UNLOCK(&ia->ia_ifa);
	}
	lck_mtx_unlock(rnh_lock);

	/* XXX check if the subnet route points to the same interface */
	if (error == EEXIST)
		error = 0;

	/*
	 * If the interface supports multicast, join the "all hosts"
	 * multicast group on that interface.
	 */
	if (ifp->if_flags & IFF_MULTICAST) {
		struct in_addr addr;

		lck_mtx_lock(&ifp->if_addrconfig_lock);
		addr.s_addr = htonl(INADDR_ALLHOSTS_GROUP);
		if (ifp->if_allhostsinm == NULL) {
			struct in_multi *inm;
			inm = in_addmulti(&addr, ifp);

			if (inm != NULL) {
				/* keep the reference on inm added by 
				 * in_addmulti above for storing the 
				 * pointer in allhostsinm 
				 */
				ifp->if_allhostsinm = inm;
			} else {
				printf("Failed to add membership to all-hosts multicast address on interface %s%d\n", ifp->if_name, ifp->if_unit);
			}
		}
		lck_mtx_unlock(&ifp->if_addrconfig_lock);
	}

	/* Release extra reference taken above */
	IFA_REMREF(&ia->ia_ifa);
	return (error);
}


/*
 * Return 1 if the address might be a local broadcast address.
 */
int
in_broadcast(struct in_addr in, struct ifnet *ifp)
{
	struct ifaddr *ifa;
	u_int32_t t;

	if (in.s_addr == INADDR_BROADCAST || in.s_addr == INADDR_ANY)
		return (1);
	if ((ifp->if_flags & IFF_BROADCAST) == 0)
		return (0);
	t = ntohl(in.s_addr);
	/*
	 * Look through the list of addresses for a match
	 * with a broadcast address.
	 */
#define ia ((struct in_ifaddr *)ifa)
	ifnet_lock_shared(ifp);
	TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
		IFA_LOCK(ifa);
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
			IFA_UNLOCK(ifa);
			ifnet_lock_done(ifp);
			return (1);
		}
		IFA_UNLOCK(ifa);
	}
	ifnet_lock_done(ifp);
	return (0);
#undef ia
}

void
in_purgeaddrs(struct ifnet *ifp)
{
	struct ifaddr **ifap;
	int err, i;

	/*
	 * Be nice, and try the civilized way first.  If we can't get
	 * rid of them this way, then do it the rough way.  We must
	 * only get here during detach time, after the ifnet has been
	 * removed from the global list and arrays.
	 */
	err = ifnet_get_address_list_family_internal(ifp, &ifap, AF_INET, 1,
	    M_WAITOK);
	if (err == 0 && ifap != NULL) {
		for (i = 0; ifap[i] != NULL; i++) {
			struct ifaliasreq ifr;
			struct ifaddr *ifa;

			ifa = ifap[i];
			bzero(&ifr, sizeof (ifr));
			IFA_LOCK(ifa);
			ifr.ifra_addr = *ifa->ifa_addr;
			if (ifa->ifa_dstaddr != NULL)
				ifr.ifra_broadaddr = *ifa->ifa_dstaddr;
			IFA_UNLOCK(ifa);
			err = in_control(NULL, SIOCDIFADDR, (caddr_t)&ifr, ifp,
			    kernproc);
			/* if we lost the race, ignore it */
			if (err == EADDRNOTAVAIL)
				err = 0;
			if (err != 0) {
				char s_addr[MAX_IPv4_STR_LEN];
				char s_dstaddr[MAX_IPv4_STR_LEN];
				struct in_addr *s, *d;

				IFA_LOCK(ifa);
				s = &((struct sockaddr_in *)
				    (void *)ifa->ifa_addr)->sin_addr;
				d = &((struct sockaddr_in *)
				    (void *)ifa->ifa_dstaddr)->sin_addr;
				(void) inet_ntop(AF_INET, &s->s_addr, s_addr,
				    sizeof (s_addr));
				(void) inet_ntop(AF_INET, &d->s_addr, s_dstaddr,
				    sizeof (s_dstaddr));
				IFA_UNLOCK(ifa);

				printf("%s: SIOCDIFADDR ifp=%p ifa_addr=%s "
				    "ifa_dstaddr=%s (err=%d)\n", __func__, ifp,
				    s_addr, s_dstaddr, err);
			}
		}
		ifnet_free_address_list(ifap);
	} else if (err != 0 && err != ENXIO) {
		printf("%s: error retrieving list of AF_INET addresses for "
		    "ifp=%p (err=%d)\n", __func__, ifp, err);
	}
}

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

int inet_ntoa2(struct in_addr * pin, char * cp, const int len);
int inet_ntoa2(struct in_addr * pin, char * cp, const int len)
{
    int ret;

    /* address is in network byte order */
   ret = snprintf(cp, len, "%u.%u.%u.%u", pin->s_addr & 0xFF, 
                  (pin->s_addr >> 8) & 0xFF, (pin->s_addr >> 16) & 0xFF,
                  (pin->s_addr >> 24) & 0xFF);

   return ret < len ? TRUE : FALSE;
}

/*
 * Called as part of ip_init
 */
void
in_ifaddr_init(void)
{
	in_multi_init();

	PE_parse_boot_argn("ifa_debug", &inifa_debug, sizeof (inifa_debug));

	inifa_size = (inifa_debug == 0) ? sizeof (struct in_ifaddr) :
	    sizeof (struct in_ifaddr_dbg);

	inifa_zone = zinit(inifa_size, INIFA_ZONE_MAX * inifa_size,
	    0, INIFA_ZONE_NAME);
	if (inifa_zone == NULL) {
		panic("%s: failed allocating %s", __func__, INIFA_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(inifa_zone, Z_EXPAND, TRUE);
	zone_change(inifa_zone, Z_CALLERACCT, FALSE);

	lck_mtx_init(&inifa_trash_lock, ifa_mtx_grp, ifa_mtx_attr);
	TAILQ_INIT(&inifa_trash_head);
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
		ifa_lock_init(&inifa->ia_ifa);
		if (inifa_debug != 0) {
			struct in_ifaddr_dbg *inifa_dbg =
			    (struct in_ifaddr_dbg *)inifa;
			inifa->ia_ifa.ifa_debug |= IFD_DEBUG;
			inifa->ia_ifa.ifa_trace = in_ifaddr_trace;
			inifa->ia_ifa.ifa_attached = in_ifaddr_attached;
			inifa->ia_ifa.ifa_detached = in_ifaddr_detached;
			ctrace_record(&inifa_dbg->inifa_alloc);
		}
	}
	return (inifa);
}

static void
in_ifaddr_free(struct ifaddr *ifa)
{
	IFA_LOCK_ASSERT_HELD(ifa);

	if (ifa->ifa_refcnt != 0) {
		panic("%s: ifa %p bad ref cnt", __func__, ifa);
		/* NOTREACHED */
	} if (!(ifa->ifa_debug & IFD_ALLOC)) {
		panic("%s: ifa %p cannot be freed", __func__, ifa);
		/* NOTREACHED */
	}
	if (ifa->ifa_debug & IFD_DEBUG) {
		struct in_ifaddr_dbg *inifa_dbg = (struct in_ifaddr_dbg *)ifa;
		ctrace_record(&inifa_dbg->inifa_free);
		bcopy(&inifa_dbg->inifa, &inifa_dbg->inifa_old,
		    sizeof (struct in_ifaddr));
		if (ifa->ifa_debug & IFD_TRASHED) {
			/* Become a regular mutex, just in case */
			IFA_CONVERT_LOCK(ifa);
			lck_mtx_lock(&inifa_trash_lock);
			TAILQ_REMOVE(&inifa_trash_head, inifa_dbg,
			    inifa_trash_link);
			lck_mtx_unlock(&inifa_trash_lock);
			ifa->ifa_debug &= ~IFD_TRASHED;
		}
	}
	IFA_UNLOCK(ifa);
	ifa_lock_destroy(ifa);
	bzero(ifa, sizeof (struct in_ifaddr));
	zfree(inifa_zone, ifa);
}

static void
in_ifaddr_attached(struct ifaddr *ifa)
{
	struct in_ifaddr_dbg *inifa_dbg = (struct in_ifaddr_dbg *)ifa;

	IFA_LOCK_ASSERT_HELD(ifa);

	if (!(ifa->ifa_debug & IFD_DEBUG)) {
		panic("%s: ifa %p has no debug structure", __func__, ifa);
		/* NOTREACHED */
	}
	if (ifa->ifa_debug & IFD_TRASHED) {
		/* Become a regular mutex, just in case */
		IFA_CONVERT_LOCK(ifa);
		lck_mtx_lock(&inifa_trash_lock);
		TAILQ_REMOVE(&inifa_trash_head, inifa_dbg, inifa_trash_link);
		lck_mtx_unlock(&inifa_trash_lock);
		ifa->ifa_debug &= ~IFD_TRASHED;
	}
}

static void
in_ifaddr_detached(struct ifaddr *ifa)
{
	struct in_ifaddr_dbg *inifa_dbg = (struct in_ifaddr_dbg *)ifa;

	IFA_LOCK_ASSERT_HELD(ifa);

	if (!(ifa->ifa_debug & IFD_DEBUG)) {
		panic("%s: ifa %p has no debug structure", __func__, ifa);
		/* NOTREACHED */
	} else if (ifa->ifa_debug & IFD_TRASHED) {
		panic("%s: ifa %p is already in trash list", __func__, ifa);
		/* NOTREACHED */
	}
	ifa->ifa_debug |= IFD_TRASHED;
	/* Become a regular mutex, just in case */
	IFA_CONVERT_LOCK(ifa);
	lck_mtx_lock(&inifa_trash_lock);
	TAILQ_INSERT_TAIL(&inifa_trash_head, inifa_dbg, inifa_trash_link);
	lck_mtx_unlock(&inifa_trash_lock);
}

static void
in_ifaddr_trace(struct ifaddr *ifa, int refhold)
{
	struct in_ifaddr_dbg *inifa_dbg = (struct in_ifaddr_dbg *)ifa;
	ctrace_t *tr;
	u_int32_t idx;
	u_int16_t *cnt;

	if (!(ifa->ifa_debug & IFD_DEBUG)) {
		panic("%s: ifa %p has no debug structure", __func__, ifa);
		/* NOTREACHED */
	}
	if (refhold) {
		cnt = &inifa_dbg->inifa_refhold_cnt;
		tr = inifa_dbg->inifa_refhold;
	} else {
		cnt = &inifa_dbg->inifa_refrele_cnt;
		tr = inifa_dbg->inifa_refrele;
	}

	idx = atomic_add_16_ov(cnt, 1) % INIFA_TRACE_HIST_SIZE;
	ctrace_record(&tr[idx]);
}
