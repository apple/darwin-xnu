/*
 * Copyright (c) 2003-2012 Apple Inc. All rights reserved.
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
/*	$FreeBSD: src/sys/netinet6/ip6_mroute.c,v 1.16.2.1 2002/12/18 21:39:40 suz Exp $	*/
/*	$KAME: ip6_mroute.c,v 1.58 2001/12/18 02:36:31 itojun Exp $	*/

/*
 * Copyright (C) 1998 WIDE Project.
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
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

/*	BSDI ip_mroute.c,v 2.10 1996/11/14 00:29:52 jch Exp	*/

/*
 * IP multicast forwarding procedures
 *
 * Written by David Waitzman, BBN Labs, August 1988.
 * Modified by Steve Deering, Stanford, February 1989.
 * Modified by Mark J. Steiglitz, Stanford, May, 1991
 * Modified by Van Jacobson, LBL, January 1993
 * Modified by Ajit Thyagarajan, PARC, August 1993
 * Modified by Bill Fenenr, PARC, April 1994
 *
 * MROUTING Revision: 3.5.1.2 + PIM-SMv2 (pimd) Support
 */


#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <sys/protosw.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/syslog.h>
#include <kern/locks.h>

#include <net/if.h>
#include <net/route.h>
#include <net/raw_cb.h>
#include <net/dlil.h>
#include <net/net_osdep.h>

#include <netinet/in.h>
#include <netinet/in_var.h>

#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/scope6_var.h>
#include <netinet6/ip6_mroute.h>
#include <netinet/icmp6.h>
#include <netinet6/pim6.h>
#include <netinet6/pim6_var.h>

#if CONFIG_MACF_NET
#include <security/mac.h>
#endif /* MAC_NET */

#ifndef __APPLE__
static MALLOC_DEFINE(M_MRTABLE, "mf6c", "multicast forwarding cache entry");
#endif

#define M_HASCL(m) ((m)->m_flags & M_EXT)

static int ip6_mdq(struct mbuf *, struct ifnet *, struct mf6c *);
static void phyint_send(struct ip6_hdr *, struct mif6 *, struct mbuf *);

static int set_pim6(int *);
static int socket_send(struct socket *, struct mbuf *,
			    struct sockaddr_in6 *);
static int register_send(struct ip6_hdr *, struct mif6 *,
			      struct mbuf *);

/*
 * Globals.  All but ip6_mrouter, ip6_mrtproto and mrt6stat could be static,
 * except for netstat or debugging purposes.
 */
struct socket  *ip6_mrouter  = NULL;
int		ip6_mrouter_ver = 0;
int		ip6_mrtproto = IPPROTO_PIM;    /* for netstat only */

#if MROUTING

struct mrt6stat	mrt6stat;

#define NO_RTE_FOUND 	0x1
#define RTE_FOUND	0x2

struct mf6c	*mf6ctable[MF6CTBLSIZ];
u_char		n6expire[MF6CTBLSIZ];
static struct mif6 mif6table[MAXMIFS];
#if MRT6DEBUG
u_int		mrt6debug = 0;	  /* debug level 	*/
#define		DEBUG_MFC	0x02
#define		DEBUG_FORWARD	0x04
#define		DEBUG_EXPIRE	0x08
#define		DEBUG_XMIT	0x10
#define         DEBUG_REG       0x20
#define         DEBUG_PIM       0x40
#endif

static void	expire_upcalls(void *);

#define		EXPIRE_TIMEOUT	(hz / 4)	/* 4x / second */
#define		UPCALL_EXPIRE	6		/* number of timeouts */

#if INET
#if MROUTING
extern struct socket *ip_mrouter;
#endif
#endif

/*
 * 'Interfaces' associated with decapsulator (so we can tell
 * packets that went through it from ones that get reflected
 * by a broken gateway).  These interfaces are never linked into
 * the system ifnet list & no routes point to them.  I.e., packets
 * can't be sent this way.  They only exist as a placeholder for
 * multicast source verification.
 */
struct ifnet multicast_register_if;

#define ENCAP_HOPS 64

/*
 * Private variables.
 */
static mifi_t nummifs = 0;
static mifi_t reg_mif_num = (mifi_t)-1;

static struct pim6stat pim6stat;
static int pim6;

/*
 * Hash function for a source, group entry
 */
#define MF6CHASH(a, g) MF6CHASHMOD((a).s6_addr32[0] ^ (a).s6_addr32[1] ^ \
				   (a).s6_addr32[2] ^ (a).s6_addr32[3] ^ \
				   (g).s6_addr32[0] ^ (g).s6_addr32[1] ^ \
				   (g).s6_addr32[2] ^ (g).s6_addr32[3])

/*
 * Find a route for a given origin IPv6 address and Multicast group address.
 * Quality of service parameter to be added in the future!!!
 */

#define MF6CFIND(o, g, rt) do { \
	struct mf6c *_rt = mf6ctable[MF6CHASH(o,g)]; \
	rt = NULL; \
	mrt6stat.mrt6s_mfc_lookups++; \
	while (_rt) { \
		if (IN6_ARE_ADDR_EQUAL(&_rt->mf6c_origin.sin6_addr, &(o)) && \
		    IN6_ARE_ADDR_EQUAL(&_rt->mf6c_mcastgrp.sin6_addr, &(g)) && \
		    (_rt->mf6c_stall == NULL)) { \
			rt = _rt; \
			break; \
		} \
		_rt = _rt->mf6c_next; \
	} \
	if (rt == NULL) { \
		mrt6stat.mrt6s_mfc_misses++; \
	} \
} while (0)

/*
 * Macros to compute elapsed time efficiently
 * Borrowed from Van Jacobson's scheduling code
 */
#define TV_DELTA(a, b, delta) do { \
	    int xxs; \
		\
	    delta = (a).tv_usec - (b).tv_usec; \
	    if ((xxs = (a).tv_sec - (b).tv_sec)) { \
	       switch (xxs) { \
		      case 2: \
			  delta += 1000000; \
			      /* fall through */ \
		      case 1: \
			  delta += 1000000; \
			  break; \
		      default: \
			  delta += (1000000 * xxs); \
	       } \
	    } \
} while (0)

#define TV_LT(a, b) (((a).tv_usec < (b).tv_usec && \
	      (a).tv_sec <= (b).tv_sec) || (a).tv_sec < (b).tv_sec)

#if UPCALL_TIMING
#define UPCALL_MAX	50
u_int32_t upcall_data[UPCALL_MAX + 1];
static void collate();
#endif /* UPCALL_TIMING */

static int get_sg_cnt(struct sioc_sg_req6 *);
static int get_mif6_cnt(void *, int);
static int ip6_mrouter_init(struct socket *, int, int);
static int add_m6if(struct mif6ctl *);
static int del_m6if(mifi_t *);
static int add_m6fc(struct mf6cctl *);
static int del_m6fc(struct mf6cctl *);

/*
 * Handle MRT setsockopt commands to modify the multicast routing tables.
 */
int
ip6_mrouter_set(so, sopt)
	struct socket *so;
	struct sockopt *sopt;
{
	int error = 0;
	int optval;
	struct mif6ctl mifc;
	struct mf6cctl mfcc;
	mifi_t mifi;

	if (so != ip6_mrouter && sopt->sopt_name != MRT6_INIT)
		return (EACCES);

	switch (sopt->sopt_name) {
	case MRT6_INIT:
#if MRT6_OINIT
	case MRT6_OINIT:
#endif
		error = sooptcopyin(sopt, &optval, sizeof(optval),
		    sizeof(optval));
		if (error)
			break;
		error = ip6_mrouter_init(so, optval, sopt->sopt_name);
		break;
	case MRT6_DONE:
		error = ip6_mrouter_done();
		break;
	case MRT6_ADD_MIF:
		error = sooptcopyin(sopt, &mifc, sizeof(mifc), sizeof(mifc));
		if (error)
			break;
		error = add_m6if(&mifc);
		break;
	case MRT6_ADD_MFC:
		error = sooptcopyin(sopt, &mfcc, sizeof(mfcc), sizeof(mfcc));
		if (error)
			break;
		error = add_m6fc(&mfcc);
		break;
	case MRT6_DEL_MFC:
		error = sooptcopyin(sopt, &mfcc, sizeof(mfcc), sizeof(mfcc));
		if (error)
			break;
		error = del_m6fc(&mfcc);
		break;
	case MRT6_DEL_MIF:
		error = sooptcopyin(sopt, &mifi, sizeof(mifi), sizeof(mifi));
		if (error)
			break;
		error = del_m6if(&mifi);
		break;
	case MRT6_PIM:
		error = sooptcopyin(sopt, &optval, sizeof(optval),
		    sizeof(optval));
		if (error)
			break;
		error = set_pim6(&optval);
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

/*
 * Handle MRT getsockopt commands
 */
int
ip6_mrouter_get(so, sopt)
	struct socket *so;
	struct sockopt *sopt;
{
	int error = 0;

	if (so != ip6_mrouter) return EACCES;

	switch (sopt->sopt_name) {
		case MRT6_PIM:
			error = sooptcopyout(sopt, &pim6, sizeof(pim6));
			break;
	}
	return (error);
}

/*
 * Handle ioctl commands to obtain information from the cache
 */
int
mrt6_ioctl(u_long cmd, caddr_t data)
{
	int error = 0;

	switch (cmd) {
	case SIOCGETSGCNT_IN6: {	/* struct sioc_sg_req6 */
		struct sioc_sg_req6 req;

		bcopy(data, &req, sizeof (req));
		error = get_sg_cnt(&reg);
		bcopy(&req, data, sizeof (req));
		break;
	}

	case SIOCGETMIFCNT_IN6_32:	/* struct sioc_mif_req6_32 */
	case SIOCGETMIFCNT_IN6_64:	/* struct sioc_mif_req6_64 */
		return (get_mif6_cnt(data, cmd == SIOCGETMIFCNT_IN6_64));
		/* NOTREACHED */

	default:
		error = EINVAL;
		break;
	}
	return (error);
}

/*
 * returns the packet, byte, rpf-failure count for the source group provided
 */
static int
get_sg_cnt(req)
	struct sioc_sg_req6 *req;
{
	struct mf6c *rt;

	MF6CFIND(req->src.sin6_addr, req->grp.sin6_addr, rt);
	if (rt != NULL) {
		req->pktcnt = rt->mf6c_pkt_cnt;
		req->bytecnt = rt->mf6c_byte_cnt;
		req->wrong_if = rt->mf6c_wrong_if;
	} else
		return(ESRCH);
#if 0
		req->pktcnt = req->bytecnt = req->wrong_if = 0xffffffff;
#endif

	return 0;
}

/*
 * returns the input and output packet and byte counts on the mif provided
 */
static int
get_mif6_cnt(void *data, int p64)
{
	if (p64) {
		struct sioc_mif_req6_64 *req = data;
		mifi_t mifi;

		bcopy(&req->mifi, &mifi, sizeof (mifi));
		if (mifi >= nummifs)
			return (EINVAL);

		bcopy(&mif6table[mifi].m6_pkt_in, &req->icount,
		    sizeof (req->icount));
		bcopy(&mif6table[mifi].m6_pkt_out, &req->ocount,
		    sizeof (req->ocount));
		bcopy(&mif6table[mifi].m6_bytes_in, &req->ibytes,
		    sizeof (req->ibytes));
		bcopy(&mif6table[mifi].m6_bytes_out, &req->obytes,
		    sizeof (req->obytes));
	} else {
		struct sioc_mif_req6_32 *req = data;
		mifi_t mifi;

		bcopy(&req->mifi, &mifi, sizeof (mifi));
		if (mifi >= nummifs)
			return (EINVAL);

		bcopy(&mif6table[mifi].m6_pkt_in, &req->icount,
		    sizeof (req->icount));
		bcopy(&mif6table[mifi].m6_pkt_out, &req->ocount,
		    sizeof (req->ocount));
		bcopy(&mif6table[mifi].m6_bytes_in, &req->ibytes,
		    sizeof (req->ibytes));
		bcopy(&mif6table[mifi].m6_bytes_out, &req->obytes,
		    sizeof (req->obytes));
	}
	return (0);
}

static int
set_pim6(i)
	int *i;
{
	if ((*i != 1) && (*i != 0))
		return EINVAL;

	pim6 = *i;

	return 0;
}

/*
 * Enable multicast routing
 */
static int
ip6_mrouter_init(so, v, cmd)
	struct socket *so;
	int v;
	int cmd;
{
#if MRT6DEBUG
	if (mrt6debug)
		log(LOG_DEBUG,
		    "ip6_mrouter_init: so_type = %d, pr_protocol = %d\n",
		    so->so_type, so->so_proto->pr_protocol);
#endif

	if (so->so_type != SOCK_RAW ||
	    so->so_proto->pr_protocol != IPPROTO_ICMPV6)
		return EOPNOTSUPP;

	if (v != 1)
		return (ENOPROTOOPT);

	if (ip6_mrouter != NULL) return EADDRINUSE;

	ip6_mrouter = so;
	ip6_mrouter_ver = cmd;

	bzero((caddr_t)mf6ctable, sizeof(mf6ctable));
	bzero((caddr_t)n6expire, sizeof(n6expire));

	pim6 = 0;/* used for stubbing out/in pim stuff */

	timeout(expire_upcalls, (caddr_t)NULL, EXPIRE_TIMEOUT);

#if MRT6DEBUG
	if (mrt6debug)
		log(LOG_DEBUG, "ip6_mrouter_init\n");
#endif

	return 0;
}

/*
 * Disable multicast routing
 */
int
ip6_mrouter_done()
{
	mifi_t mifi;
	int i;
	struct mf6c *rt;
	struct rtdetq *rte;


	/*
	 * For each phyint in use, disable promiscuous reception of all IPv6
	 * multicasts.
	 */
#if INET
#if MROUTING
	/*
	 * If there is still IPv4 multicast routing daemon,
	 * we remain interfaces to receive all muliticasted packets.
	 * XXX: there may be an interface in which the IPv4 multicast
	 * daemon is not interested...
	 */
	if (!ip_mrouter)
#endif
#endif
	{
		for (mifi = 0; mifi < nummifs; mifi++) {
			if (mif6table[mifi].m6_ifp &&
			    !(mif6table[mifi].m6_flags & MIFF_REGISTER)) {
#ifdef __APPLE__
				if_allmulti(mif6table[mifi].m6_ifp, 0);
#else
				{
					struct ifnet *ifp;
					struct in6_ifreq ifr;
			
					ifr.ifr_addr.sin6_family = AF_INET6;
					ifr.ifr_addr.sin6_addr= in6addr_any;
					ifp = mif6table[mifi].m6_ifp;
					ifnet_ioctl(ifp, 0, SIOCDELMULTI, &ifr);
				}
#endif
			}
		}
	}
	bzero((caddr_t)mif6table, sizeof(mif6table));
	nummifs = 0;

	pim6 = 0; /* used to stub out/in pim specific code */

	untimeout(expire_upcalls, (caddr_t)NULL);

	/*
	 * Free all multicast forwarding cache entries.
	 *###LD 5/27 needs locking
	 */
	for (i = 0; i < MF6CTBLSIZ; i++) {
		rt = mf6ctable[i];
		while (rt) {
			struct mf6c *frt;

			for (rte = rt->mf6c_stall; rte != NULL; ) {
				struct rtdetq *n = rte->next;

				m_free(rte->m);
				FREE(rte, M_MRTABLE);
				rte = n;
			}
			frt = rt;
			rt = rt->mf6c_next;
			FREE(frt, M_MRTABLE);
		}
	}

	bzero((caddr_t)mf6ctable, sizeof(mf6ctable));

	/*
	 * Reset de-encapsulation cache
	 */
	reg_mif_num = -1;

	ip6_mrouter = NULL;
	ip6_mrouter_ver = 0;


#if MRT6DEBUG
	if (mrt6debug)
		log(LOG_DEBUG, "ip6_mrouter_done\n");
#endif

	return 0;
}

static struct sockaddr_in6 sin6 = { sizeof(sin6), AF_INET6 ,
                                     0, 0, IN6ADDR_ANY_INIT, 0};

/*
 * Add a mif to the mif table
 */
static int
add_m6if(mifcp)
	struct mif6ctl *mifcp;
{
	struct mif6 *mifp;
	struct ifnet *ifp;
	int error;
#if notyet
	struct tbf *m_tbf = tbftable + mifcp->mif6c_mifi;
#endif

	if (mifcp->mif6c_mifi >= MAXMIFS)
		return EINVAL;
	mifp = mif6table + mifcp->mif6c_mifi;
	if (mifp->m6_ifp)
		return (EADDRINUSE); /* XXX: is it appropriate? */
	if (mifcp->mif6c_pifi == 0 || mifcp->mif6c_pifi > if_index)
		return (ENXIO);

	ifnet_head_lock_shared();
	if (mifcp->mif6c_pifi == 0 || mifcp->mif6c_pifi > if_index) {
		ifnet_head_done();
		return ENXIO;
	}
	ifp = ifindex2ifnet[mifcp->mif6c_pifi];
	ifnet_head_done();

	if (ifp == NULL) {
		return ENXIO;
	}
	if (mifcp->mif6c_flags & MIFF_REGISTER) {
		if (reg_mif_num == (mifi_t)-1) {
			multicast_register_if.if_name = "register_mif";
			multicast_register_if.if_flags |= IFF_LOOPBACK;
			multicast_register_if.if_index = mifcp->mif6c_mifi;
			reg_mif_num = mifcp->mif6c_mifi;
		}

		ifp = &multicast_register_if;

	} /* if REGISTER */
	else {
		/* Make sure the interface supports multicast */
		if ((ifp->if_flags & IFF_MULTICAST) == 0)
			return EOPNOTSUPP;

		error = if_allmulti(ifp, 1);
		if (error)
			return error;
	}

	mifp->m6_flags     = mifcp->mif6c_flags;
	mifp->m6_ifp       = ifp;

	/* initialize per mif pkt counters */
	mifp->m6_pkt_in    = 0;
	mifp->m6_pkt_out   = 0;
	mifp->m6_bytes_in  = 0;
	mifp->m6_bytes_out = 0;

	/* Adjust nummifs up if the mifi is higher than nummifs */
	if (nummifs <= mifcp->mif6c_mifi)
		nummifs = mifcp->mif6c_mifi + 1;

#if MRT6DEBUG
	if (mrt6debug)
		log(LOG_DEBUG,
		    "add_mif #%d, phyint %s%d\n",
		    mifcp->mif6c_mifi,
		    ifp->if_name, ifp->if_unit);
#endif

	return 0;
}

/*
 * Delete a mif from the mif table
 */
static int
del_m6if(mifip)
	mifi_t *mifip;
{
	struct mif6 *mifp = mif6table + *mifip;
	mifi_t mifi;
	struct ifnet *ifp;

	if (*mifip >= nummifs)
		return EINVAL;
	if (mifp->m6_ifp == NULL)
		return EINVAL;


	if (!(mifp->m6_flags & MIFF_REGISTER)) {
		/*
		 * XXX: what if there is yet IPv4 multicast daemon
		 *      using the interface?
		 */
		ifp = mifp->m6_ifp;

		if_allmulti(ifp, 0);
	}

	bzero((caddr_t)mifp, sizeof(*mifp));

	/* Adjust nummifs down */
	for (mifi = nummifs; mifi > 0; mifi--)
		if (mif6table[mifi - 1].m6_ifp)
			break;
	nummifs = mifi;


#if MRT6DEBUG
	if (mrt6debug)
		log(LOG_DEBUG, "del_m6if %d, nummifs %d\n", *mifip, nummifs);
#endif

	return 0;
}

/*
 * Add an mfc entry
 */
static int
add_m6fc(mfccp)
	struct mf6cctl *mfccp;
{
	struct mf6c *rt;
	u_int32_t hash;
	struct rtdetq *rte;
	u_short nstl;

	MF6CFIND(mfccp->mf6cc_origin.sin6_addr,
		 mfccp->mf6cc_mcastgrp.sin6_addr, rt);

	/* If an entry already exists, just update the fields */
	if (rt) {
#if MRT6DEBUG
		if (mrt6debug & DEBUG_MFC)
			log(LOG_DEBUG,
			    "add_m6fc no upcall h %d o %s g %s p %x\n",
			    ip6_sprintf(&mfccp->mf6cc_origin.sin6_addr),
			    ip6_sprintf(&mfccp->mf6cc_mcastgrp.sin6_addr),
			    mfccp->mf6cc_parent);
#endif

		rt->mf6c_parent = mfccp->mf6cc_parent;
		rt->mf6c_ifset = mfccp->mf6cc_ifset;
		return 0;
	}

	/*
	 * Find the entry for which the upcall was made and update
	 */
	hash = MF6CHASH(mfccp->mf6cc_origin.sin6_addr,
			mfccp->mf6cc_mcastgrp.sin6_addr);
	for (rt = mf6ctable[hash], nstl = 0; rt; rt = rt->mf6c_next) {
		if (IN6_ARE_ADDR_EQUAL(&rt->mf6c_origin.sin6_addr,
				       &mfccp->mf6cc_origin.sin6_addr) &&
		    IN6_ARE_ADDR_EQUAL(&rt->mf6c_mcastgrp.sin6_addr,
				       &mfccp->mf6cc_mcastgrp.sin6_addr) &&
		    (rt->mf6c_stall != NULL)) {

			if (nstl++)
				log(LOG_ERR,
				    "add_m6fc: %s o %s g %s p %x dbx %p\n",
				    "multiple kernel entries",
				    ip6_sprintf(&mfccp->mf6cc_origin.sin6_addr),
				    ip6_sprintf(&mfccp->mf6cc_mcastgrp.sin6_addr),
				    mfccp->mf6cc_parent, rt->mf6c_stall);

#if MRT6DEBUG
			if (mrt6debug & DEBUG_MFC)
				log(LOG_DEBUG,
				    "add_m6fc o %s g %s p %x dbg %x\n",
				    ip6_sprintf(&mfccp->mf6cc_origin.sin6_addr),
				    ip6_sprintf(&mfccp->mf6cc_mcastgrp.sin6_addr),
				    mfccp->mf6cc_parent, rt->mf6c_stall);
#endif

			rt->mf6c_origin     = mfccp->mf6cc_origin;
			rt->mf6c_mcastgrp   = mfccp->mf6cc_mcastgrp;
			rt->mf6c_parent     = mfccp->mf6cc_parent;
			rt->mf6c_ifset	    = mfccp->mf6cc_ifset;
			/* initialize pkt counters per src-grp */
			rt->mf6c_pkt_cnt    = 0;
			rt->mf6c_byte_cnt   = 0;
			rt->mf6c_wrong_if   = 0;

			rt->mf6c_expire = 0;	/* Don't clean this guy up */
			n6expire[hash]--;

			/* free packets Qed at the end of this entry */
			for (rte = rt->mf6c_stall; rte != NULL; ) {
				struct rtdetq *n = rte->next;
				ip6_mdq(rte->m, rte->ifp, rt);
				m_freem(rte->m);
#if UPCALL_TIMING
				collate(&(rte->t));
#endif /* UPCALL_TIMING */
				FREE(rte, M_MRTABLE);
				rte = n;
			}
			rt->mf6c_stall = NULL;
		}
	}

	/*
	 * It is possible that an entry is being inserted without an upcall
	 */
	if (nstl == 0) {
#if MRT6DEBUG
		if (mrt6debug & DEBUG_MFC)
			log(LOG_DEBUG,"add_mfc no upcall h %d o %s g %s p %x\n",
			    hash,
			    ip6_sprintf(&mfccp->mf6cc_origin.sin6_addr),
			    ip6_sprintf(&mfccp->mf6cc_mcastgrp.sin6_addr),
			    mfccp->mf6cc_parent);
#endif

		for (rt = mf6ctable[hash]; rt; rt = rt->mf6c_next) {
	
			if (IN6_ARE_ADDR_EQUAL(&rt->mf6c_origin.sin6_addr,
					       &mfccp->mf6cc_origin.sin6_addr)&&
			    IN6_ARE_ADDR_EQUAL(&rt->mf6c_mcastgrp.sin6_addr,
					       &mfccp->mf6cc_mcastgrp.sin6_addr)) {

				rt->mf6c_origin     = mfccp->mf6cc_origin;
				rt->mf6c_mcastgrp   = mfccp->mf6cc_mcastgrp;
				rt->mf6c_parent     = mfccp->mf6cc_parent;
				rt->mf6c_ifset	    = mfccp->mf6cc_ifset;
				/* initialize pkt counters per src-grp */
				rt->mf6c_pkt_cnt    = 0;
				rt->mf6c_byte_cnt   = 0;
				rt->mf6c_wrong_if   = 0;

				if (rt->mf6c_expire)
					n6expire[hash]--;
				rt->mf6c_expire	   = 0;
			}
		}
		if (rt == NULL) {
			/* no upcall, so make a new entry */
			rt = (struct mf6c *)_MALLOC(sizeof(*rt), M_MRTABLE,
						  M_NOWAIT);
			if (rt == NULL) {
				return ENOBUFS;
			}
	
			/* insert new entry at head of hash chain */
			rt->mf6c_origin     = mfccp->mf6cc_origin;
			rt->mf6c_mcastgrp   = mfccp->mf6cc_mcastgrp;
			rt->mf6c_parent     = mfccp->mf6cc_parent;
			rt->mf6c_ifset	    = mfccp->mf6cc_ifset;
			/* initialize pkt counters per src-grp */
			rt->mf6c_pkt_cnt    = 0;
			rt->mf6c_byte_cnt   = 0;
			rt->mf6c_wrong_if   = 0;
			rt->mf6c_expire     = 0;
			rt->mf6c_stall = NULL;
	
			/* link into table */
			rt->mf6c_next  = mf6ctable[hash];
			mf6ctable[hash] = rt;
		}
	}
	return 0;
}

#if UPCALL_TIMING
/*
 * collect delay statistics on the upcalls
 */
static void
collate(t)
	struct timeval *t;
{
	u_int32_t d;
	struct timeval tp;
	u_int32_t delta;

	GET_TIME(tp);

	if (TV_LT(*t, tp))
	{
		TV_DELTA(tp, *t, delta);
	
		d = delta >> 10;
		if (d > UPCALL_MAX)
			d = UPCALL_MAX;
	
		++upcall_data[d];
	}
}
#endif /* UPCALL_TIMING */

/*
 * Delete an mfc entry
 */
static int
del_m6fc(mfccp)
	struct mf6cctl *mfccp;
{
	struct sockaddr_in6 	origin;
	struct sockaddr_in6 	mcastgrp;
	struct mf6c 		*rt;
	struct mf6c	 	**nptr;
	u_int32_t 		hash;

	origin = mfccp->mf6cc_origin;
	mcastgrp = mfccp->mf6cc_mcastgrp;
	hash = MF6CHASH(origin.sin6_addr, mcastgrp.sin6_addr);

#if MRT6DEBUG
	if (mrt6debug & DEBUG_MFC)
		log(LOG_DEBUG,"del_m6fc orig %s mcastgrp %s\n",
		    ip6_sprintf(&origin.sin6_addr),
		    ip6_sprintf(&mcastgrp.sin6_addr));
#endif


	nptr = &mf6ctable[hash];
	while ((rt = *nptr) != NULL) {
		if (IN6_ARE_ADDR_EQUAL(&origin.sin6_addr,
				       &rt->mf6c_origin.sin6_addr) &&
		    IN6_ARE_ADDR_EQUAL(&mcastgrp.sin6_addr,
				       &rt->mf6c_mcastgrp.sin6_addr) &&
		    rt->mf6c_stall == NULL)
			break;

		nptr = &rt->mf6c_next;
	}
	if (rt == NULL) {
		return EADDRNOTAVAIL;
	}

	*nptr = rt->mf6c_next;
	FREE(rt, M_MRTABLE);


	return 0;
}

static int
socket_send(s, mm, src)
	struct socket *s;
	struct mbuf *mm;
	struct sockaddr_in6 *src;
{
//### LD 5/27/04 needs locking!
//
	if (s) {
		if (sbappendaddr(&s->so_rcv,
				 (struct sockaddr *)src,
				 mm, (struct mbuf *)0, NULL) != 0) {
			sorwakeup(s);
			return 0;
		}
	}
	return -1;
}

/*
 * IPv6 multicast forwarding function. This function assumes that the packet
 * pointed to by "ip6" has arrived on (or is about to be sent to) the interface
 * pointed to by "ifp", and the packet is to be relayed to other networks
 * that have members of the packet's destination IPv6 multicast group.
 *
 * The packet is returned unscathed to the caller, unless it is
 * erroneous, in which case a non-zero return value tells the caller to
 * discard it.
 */

int
ip6_mforward(ip6, ifp, m)
	struct ip6_hdr *ip6;
	struct ifnet *ifp;
	struct mbuf *m;
{
	struct mf6c *rt;
	struct mif6 *mifp;
	struct mbuf *mm;
	mifi_t mifi;
	struct timeval timenow;

#if MRT6DEBUG
	if (mrt6debug & DEBUG_FORWARD)
		log(LOG_DEBUG, "ip6_mforward: src %s, dst %s, ifindex %d\n",
		    ip6_sprintf(&ip6->ip6_src), ip6_sprintf(&ip6->ip6_dst),
		    ifp->if_index);
#endif

	/*
	 * Don't forward a packet with Hop limit of zero or one,
	 * or a packet destined to a local-only group.
	 */
	if (ip6->ip6_hlim <= 1 || IN6_IS_ADDR_MC_NODELOCAL(&ip6->ip6_dst) ||
	    IN6_IS_ADDR_MC_LINKLOCAL(&ip6->ip6_dst))
		return 0;
	ip6->ip6_hlim--;

	/*
	 * Source address check: do not forward packets with unspecified
	 * source. It was discussed in July 2000, on ipngwg mailing list.
	 * This is rather more serious than unicast cases, because some
	 * MLD packets can be sent with the unspecified source address
	 * (although such packets must normally set 1 to the hop limit field).
	 */
	getmicrotime(&timenow);
	if (IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src)) {
		ip6stat.ip6s_cantforward++;
		if (ip6_log_time + ip6_log_interval < timenow.tv_sec) {
			ip6_log_time = timenow.tv_sec;
			log(LOG_DEBUG,
			    "cannot forward "
			    "from %s to %s nxt %d received on %s\n",
			    ip6_sprintf(&ip6->ip6_src),
			    ip6_sprintf(&ip6->ip6_dst),
			    ip6->ip6_nxt,
			    if_name(m->m_pkthdr.rcvif));
		}
		return 0;
	}

	/*
	 * Determine forwarding mifs from the forwarding cache table
	 */
	MF6CFIND(ip6->ip6_src, ip6->ip6_dst, rt);

	/* Entry exists, so forward if necessary */
	if (rt) {
		return (ip6_mdq(m, ifp, rt));
	} else {
		/*
		 * If we don't have a route for packet's origin,
		 * Make a copy of the packet &
		 * send message to routing daemon
		 */

		struct mbuf *mb0;
		struct rtdetq *rte;
		u_int32_t hash;
/*		int i, npkts;*/
#if UPCALL_TIMING
		struct timeval tp;

		GET_TIME(tp);
#endif /* UPCALL_TIMING */

		mrt6stat.mrt6s_no_route++;
#if MRT6DEBUG
		if (mrt6debug & (DEBUG_FORWARD | DEBUG_MFC))
			log(LOG_DEBUG, "ip6_mforward: no rte s %s g %s\n",
			    ip6_sprintf(&ip6->ip6_src),
			    ip6_sprintf(&ip6->ip6_dst));
#endif

		/*
		 * Allocate mbufs early so that we don't do extra work if we
		 * are just going to fail anyway.
		 */
		rte = (struct rtdetq *)_MALLOC(sizeof(*rte), M_MRTABLE,
					      M_NOWAIT);
		if (rte == NULL) {
			return ENOBUFS;
		}
		mb0 = m_copy(m, 0, M_COPYALL);
		/*
		 * Pullup packet header if needed before storing it,
		 * as other references may modify it in the meantime.
		 */
		if (mb0 &&
		    (M_HASCL(mb0) || mb0->m_len < sizeof(struct ip6_hdr)))
			mb0 = m_pullup(mb0, sizeof(struct ip6_hdr));
		if (mb0 == NULL) {
			FREE(rte, M_MRTABLE);
			return ENOBUFS;
		}
	
		/* is there an upcall waiting for this packet? */
		hash = MF6CHASH(ip6->ip6_src, ip6->ip6_dst);
		for (rt = mf6ctable[hash]; rt; rt = rt->mf6c_next) {
			if (IN6_ARE_ADDR_EQUAL(&ip6->ip6_src,
					       &rt->mf6c_origin.sin6_addr) &&
			    IN6_ARE_ADDR_EQUAL(&ip6->ip6_dst,
					       &rt->mf6c_mcastgrp.sin6_addr) &&
			    (rt->mf6c_stall != NULL))
				break;
		}

		if (rt == NULL) {
			struct mrt6msg *im;
#if MRT6_OINIT
			struct omrt6msg *oim;
#endif

			/* no upcall, so make a new entry */
			rt = (struct mf6c *)_MALLOC(sizeof(*rt), M_MRTABLE,
						  M_NOWAIT);
			if (rt == NULL) {
				FREE(rte, M_MRTABLE);
				m_freem(mb0);
				return ENOBUFS;
			}
			/*
			 * Make a copy of the header to send to the user
			 * level process
			 */
			mm = m_copy(mb0, 0, sizeof(struct ip6_hdr));

			if (mm == NULL) {
				FREE(rte, M_MRTABLE);
				m_freem(mb0);
				FREE(rt, M_MRTABLE);
				return ENOBUFS;
			}

			/*
			 * Send message to routing daemon
			 */
			sin6.sin6_addr = ip6->ip6_src;
	
			im = NULL;
#if MRT6_OINIT
			oim = NULL;
#endif
			switch (ip6_mrouter_ver) {
#if MRT6_OINIT
			case MRT6_OINIT:
				oim = mtod(mm, struct omrt6msg *);
				oim->im6_msgtype = MRT6MSG_NOCACHE;
				oim->im6_mbz = 0;
				break;
#endif
			case MRT6_INIT:
				im = mtod(mm, struct mrt6msg *);
				im->im6_msgtype = MRT6MSG_NOCACHE;
				im->im6_mbz = 0;
				break;
			default:
				FREE(rte, M_MRTABLE);
				m_freem(mb0);
				FREE(rt, M_MRTABLE);
				return EINVAL;
			}

#if MRT6DEBUG
			if (mrt6debug & DEBUG_FORWARD)
				log(LOG_DEBUG,
				    "getting the iif info in the kernel\n");
#endif

			for (mifp = mif6table, mifi = 0;
			     mifi < nummifs && mifp->m6_ifp != ifp;
			     mifp++, mifi++)
				;

			switch (ip6_mrouter_ver) {
#if MRT6_OINIT
			case MRT6_OINIT:
				oim->im6_mif = mifi;
				break;
#endif
			case MRT6_INIT:
				im->im6_mif = mifi;
				break;
			}

			if (socket_send(ip6_mrouter, mm, &sin6) < 0) {
				log(LOG_WARNING, "ip6_mforward: ip6_mrouter "
				    "socket queue full\n");
				mrt6stat.mrt6s_upq_sockfull++;
				FREE(rte, M_MRTABLE);
				m_freem(mb0);
				FREE(rt, M_MRTABLE);
				return ENOBUFS;
			}

			mrt6stat.mrt6s_upcalls++;

			/* insert new entry at head of hash chain */
			bzero(rt, sizeof(*rt));
			rt->mf6c_origin.sin6_family = AF_INET6;
			rt->mf6c_origin.sin6_len = sizeof(struct sockaddr_in6);
			rt->mf6c_origin.sin6_addr = ip6->ip6_src;
			rt->mf6c_mcastgrp.sin6_family = AF_INET6;
			rt->mf6c_mcastgrp.sin6_len = sizeof(struct sockaddr_in6);
			rt->mf6c_mcastgrp.sin6_addr = ip6->ip6_dst;
			rt->mf6c_expire = UPCALL_EXPIRE;
			n6expire[hash]++;
			rt->mf6c_parent = MF6C_INCOMPLETE_PARENT;

			/* link into table */
			rt->mf6c_next  = mf6ctable[hash];
			mf6ctable[hash] = rt;
			/* Add this entry to the end of the queue */
			rt->mf6c_stall = rte;
		} else {
			/* determine if q has overflowed */
			struct rtdetq **p;
			int npkts = 0;

			for (p = &rt->mf6c_stall; *p != NULL; p = &(*p)->next)
				if (++npkts > MAX_UPQ6) {
					mrt6stat.mrt6s_upq_ovflw++;
					FREE(rte, M_MRTABLE);
					m_freem(mb0);
					return 0;
				}

			/* Add this entry to the end of the queue */
			*p = rte;
		}

		rte->next = NULL;
		rte->m = mb0;
		rte->ifp = ifp;
#if UPCALL_TIMING
		rte->t = tp;
#endif /* UPCALL_TIMING */


		return 0;
	}
}

/*
 * Clean up cache entries if upcalls are not serviced
 * Call from the Slow Timeout mechanism, every half second.
 */
static void
expire_upcalls(
	__unused void *unused)
{
	struct rtdetq *rte;
	struct mf6c *mfc, **nptr;
	int i;

	for (i = 0; i < MF6CTBLSIZ; i++) {
		if (n6expire[i] == 0)
			continue;
		nptr = &mf6ctable[i];
		while ((mfc = *nptr) != NULL) {
			rte = mfc->mf6c_stall;
			/*
			 * Skip real cache entries
			 * Make sure it wasn't marked to not expire (shouldn't happen)
			 * If it expires now
			 */
			if (rte != NULL &&
			    mfc->mf6c_expire != 0 &&
			    --mfc->mf6c_expire == 0) {
#if MRT6DEBUG
				if (mrt6debug & DEBUG_EXPIRE)
					log(LOG_DEBUG, "expire_upcalls: expiring (%s %s)\n",
					    ip6_sprintf(&mfc->mf6c_origin.sin6_addr),
					    ip6_sprintf(&mfc->mf6c_mcastgrp.sin6_addr));
#endif
				/*
				 * drop all the packets
				 * free the mbuf with the pkt, if, timing info
				 */
				do {
					struct rtdetq *n = rte->next;
					m_freem(rte->m);
					FREE(rte, M_MRTABLE);
					rte = n;
				} while (rte != NULL);
				mrt6stat.mrt6s_cache_cleanups++;
				n6expire[i]--;

				*nptr = mfc->mf6c_next;
				FREE(mfc, M_MRTABLE);
			} else {
				nptr = &mfc->mf6c_next;
			}
		}
	}

	timeout(expire_upcalls, (caddr_t)NULL, EXPIRE_TIMEOUT);
}

/*
 * Packet forwarding routine once entry in the cache is made
 */
static int
ip6_mdq(m, ifp, rt)
	struct mbuf *m;
	struct ifnet *ifp;
	struct mf6c *rt;
{
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
	mifi_t mifi, iif;
	struct mif6 *mifp;
	int plen = m->m_pkthdr.len;
	struct in6_addr src0, dst0; /* copies for local work */
	u_int32_t iszone, idzone, oszone, odzone;
	int error = 0;

/*
 * Macro to send packet on mif.  Since RSVP packets don't get counted on
 * input, they shouldn't get counted on output, so statistics keeping is
 * separate.
 */

#define MC6_SEND(ip6, mifp, m) do {				\
		if ((mifp)->m6_flags & MIFF_REGISTER)		\
		    register_send((ip6), (mifp), (m));		\
		else						\
		    phyint_send((ip6), (mifp), (m));		\
} while (0)

	/*
	 * Don't forward if it didn't arrive from the parent mif
	 * for its origin.
	 */
	mifi = rt->mf6c_parent;
	if ((mifi >= nummifs) || (mif6table[mifi].m6_ifp != ifp)) {
		/* came in the wrong interface */
#if MRT6DEBUG
		if (mrt6debug & DEBUG_FORWARD)
			log(LOG_DEBUG,
			    "wrong if: ifid %d mifi %d mififid %x\n",
			    ifp->if_index, mifi,
			    mif6table[mifi].m6_ifp->if_index);
#endif
		mrt6stat.mrt6s_wrong_if++;
		rt->mf6c_wrong_if++;
		/*
		 * If we are doing PIM processing, and we are forwarding
		 * packets on this interface, send a message to the
		 * routing daemon.
		 */
		/* have to make sure this is a valid mif */
		if (mifi < nummifs && mif6table[mifi].m6_ifp)
			if (pim6 && (m->m_flags & M_LOOP) == 0) {
				/*
				 * Check the M_LOOP flag to avoid an
				 * unnecessary PIM assert.
				 * XXX: M_LOOP is an ad-hoc hack...
				 */
				static struct sockaddr_in6 addr =
				{ sizeof(addr), AF_INET6 , 0, 0, IN6ADDR_ANY_INIT, 0};

				struct mbuf *mm;
				struct mrt6msg *im;
#if MRT6_OINIT
				struct omrt6msg *oim;
#endif

				mm = m_copy(m, 0, sizeof(struct ip6_hdr));
				if (mm &&
				    (M_HASCL(mm) ||
				     mm->m_len < sizeof(struct ip6_hdr)))
					mm = m_pullup(mm, sizeof(struct ip6_hdr));
				if (mm == NULL)
					return ENOBUFS;
	
#if MRT6_OINIT
				oim = NULL;
#endif
				im = NULL;
				switch (ip6_mrouter_ver) {
#if MRT6_OINIT
				case MRT6_OINIT:
					oim = mtod(mm, struct omrt6msg *);
					oim->im6_msgtype = MRT6MSG_WRONGMIF;
					oim->im6_mbz = 0;
					break;
#endif
				case MRT6_INIT:
					im = mtod(mm, struct mrt6msg *);
					im->im6_msgtype = MRT6MSG_WRONGMIF;
					im->im6_mbz = 0;
					break;
				default:
					m_freem(mm);
					return EINVAL;
				}

				for (mifp = mif6table, iif = 0;
				     iif < nummifs && mifp &&
					     mifp->m6_ifp != ifp;
				     mifp++, iif++)
					;

				switch (ip6_mrouter_ver) {
#if MRT6_OINIT
				case MRT6_OINIT:
					oim->im6_mif = iif;
					addr.sin6_addr = oim->im6_src;
					break;
#endif
				case MRT6_INIT:
					im->im6_mif = iif;
					addr.sin6_addr = im->im6_src;
					break;
				}

				mrt6stat.mrt6s_upcalls++;

				if (socket_send(ip6_mrouter, mm, &addr) < 0) {
#if MRT6DEBUG
					if (mrt6debug)
						log(LOG_WARNING, "mdq, ip6_mrouter socket queue full\n");
#endif
					++mrt6stat.mrt6s_upq_sockfull;
					return ENOBUFS;
				}	/* if socket Q full */
			}		/* if PIM */
		return 0;
	}			/* if wrong iif */

	/* If I sourced this packet, it counts as output, else it was input. */
	if (m->m_pkthdr.rcvif == NULL) {
		/* XXX: is rcvif really NULL when output?? */
		mif6table[mifi].m6_pkt_out++;
		mif6table[mifi].m6_bytes_out += plen;
	} else {
		mif6table[mifi].m6_pkt_in++;
		mif6table[mifi].m6_bytes_in += plen;
	}
	rt->mf6c_pkt_cnt++;
	rt->mf6c_byte_cnt += plen;

	/*
	 * For each mif, forward a copy of the packet if there are group
	 * members downstream on the interface.
	 */
	src0 = ip6->ip6_src;
	dst0 = ip6->ip6_dst;
	if ((error = in6_setscope(&src0, ifp, &iszone)) != 0 ||
	    (error = in6_setscope(&dst0, ifp, &idzone)) != 0) {
		ip6stat.ip6s_badscope++;
		return (error);
	}
	for (mifp = mif6table, mifi = 0; mifi < nummifs; mifp++, mifi++) {
		if (IF_ISSET(mifi, &rt->mf6c_ifset)) {
			/*
			 * check if the outgoing packet is going to break
			 * a scope boundary.
			 * XXX For packets through PIM register tunnel
			 * interface, we believe a routing daemon.
			 */
			if (!(mif6table[rt->mf6c_parent].m6_flags &
			      MIFF_REGISTER) &&
			    !(mif6table[mifi].m6_flags & MIFF_REGISTER)) {
				if (in6_setscope(&src0, mif6table[mifi].m6_ifp,
				    &oszone) ||
				    in6_setscope(&dst0, mif6table[mifi].m6_ifp,
				    &odzone) ||
				    iszone != oszone ||
				    idzone != odzone) {
					ip6stat.ip6s_badscope++;
					continue;
				}
			}

			mifp->m6_pkt_out++;
			mifp->m6_bytes_out += plen;
			MC6_SEND(ip6, mifp, m);
		}
	}
	return 0;
}

static void
phyint_send(ip6, mifp, m)
    struct ip6_hdr *ip6;
    struct mif6 *mifp;
    struct mbuf *m;
{
	struct mbuf *mb_copy;
	struct ifnet *ifp = mifp->m6_ifp;
	int error = 0;
	static struct route_in6 ro;
	struct	in6_multi *in6m;
	struct sockaddr_in6 *dst6;

	/*
	 * Make a new reference to the packet; make sure that
	 * the IPv6 header is actually copied, not just referenced,
	 * so that ip6_output() only scribbles on the copy.
	 */
	mb_copy = m_copy(m, 0, M_COPYALL);
	if (mb_copy &&
	    (M_HASCL(mb_copy) || mb_copy->m_len < sizeof(struct ip6_hdr)))
		mb_copy = m_pullup(mb_copy, sizeof(struct ip6_hdr));
	if (mb_copy == NULL) {
		return;
	}
	/* set MCAST flag to the outgoing packet */
	mb_copy->m_flags |= M_MCAST;

	/*
	 * If we sourced the packet, call ip6_output since we may devide
	 * the packet into fragments when the packet is too big for the
	 * outgoing interface.
	 * Otherwise, we can simply send the packet to the interface
	 * sending queue.
	 */
	if (m->m_pkthdr.rcvif == NULL) {
		struct ip6_moptions *im6o;

		im6o = ip6_allocmoptions(M_DONTWAIT);
		if (im6o == NULL) {
			m_freem(mb_copy);
			return;
		}

		im6o->im6o_multicast_ifp = ifp;
		/* XXX: ip6_output will override ip6->ip6_hlim */
		im6o->im6o_multicast_hlim = ip6->ip6_hlim;
		im6o->im6o_multicast_loop = 1;
		error = ip6_output(mb_copy, NULL, &ro, IPV6_FORWARDING,
		    im6o, NULL, NULL);

		IM6O_REMREF(im6o);
#if MRT6DEBUG
		if (mrt6debug & DEBUG_XMIT)
			log(LOG_DEBUG, "phyint_send on mif %d err %d\n",
			    mifp - mif6table, error);
#endif
		return;
	}

	/*
	 * If we belong to the destination multicast group
	 * on the outgoing interface, loop back a copy.
	 */
	dst6 = (struct sockaddr_in6 *)&ro.ro_dst;
	in6_multihead_lock_shared();
	IN6_LOOKUP_MULTI(ip6->ip6_dst, ifp, in6m);
	in6_multihead_lock_done();
	if (in6m != NULL) {
		IN6M_REMREF(in6m);
		dst6->sin6_len = sizeof(struct sockaddr_in6);
		dst6->sin6_family = AF_INET6;
		dst6->sin6_addr = ip6->ip6_dst;
		ip6_mloopback(ifp, m, (struct sockaddr_in6 *)&ro.ro_dst);
	}
	/*
	 * Put the packet into the sending queue of the outgoing interface
	 * if it would fit in the MTU of the interface.
	 */
	if (mb_copy->m_pkthdr.len <= ifp->if_mtu || ifp->if_mtu < IPV6_MMTU) {
		dst6->sin6_len = sizeof(struct sockaddr_in6);
		dst6->sin6_family = AF_INET6;
		dst6->sin6_addr = ip6->ip6_dst;
		/*
		 * We just call if_output instead of nd6_output here, since
		 * we need no ND for a multicast forwarded packet...right?
		 */
#ifdef __APPLE__
		/* Make sure the HW checksum flags are cleaned before sending the packet */

		mb_copy->m_pkthdr.rcvif = 0;
		mb_copy->m_pkthdr.csum_data = 0;
		mb_copy->m_pkthdr.csum_flags = 0;

		error = dlil_output(ifp, PF_INET6, mb_copy,
				NULL, (struct sockaddr *)&ro.ro_dst, 0, NULL);
#else
		error = (*ifp->if_output)(ifp, mb_copy,
					  (struct sockaddr *)&ro.ro_dst,
					  NULL);
#endif
#if MRT6DEBUG
		if (mrt6debug & DEBUG_XMIT)
			log(LOG_DEBUG, "phyint_send on mif %d err %d\n",
			    mifp - mif6table, error);
#endif
	} else {
		/*
		 * pMTU discovery is intentionally disabled by default, since
		 * various router may notify pMTU in multicast, which can be
		 * a DDoS to a router
		 */
		if (ip6_mcast_pmtu)
			icmp6_error(mb_copy, ICMP6_PACKET_TOO_BIG, 0, ifp->if_mtu);
#if MRT6DEBUG
		else {
			if (mrt6debug & DEBUG_XMIT) {
				log(LOG_DEBUG,
				    "phyint_send: packet too big on %s o %s "
				    "g %s size %d(discarded)\n",
				    if_name(ifp),
				    ip6_sprintf(&ip6->ip6_src),
				    ip6_sprintf(&ip6->ip6_dst),
				    mb_copy->m_pkthdr.len);
			}
		}
#endif /* MRT6DEBUG */
		m_freem(mb_copy); /* simply discard the packet */
		
	}
}

static int
register_send(ip6, mif, m)
	struct ip6_hdr *ip6;
	struct mif6 *mif;
	struct mbuf *m;
{
	struct mbuf *mm;
	int i, len = m->m_pkthdr.len;
	static struct sockaddr_in6 addr = { sizeof(addr), AF_INET6 ,
                                     0, 0, IN6ADDR_ANY_INIT, 0};
	struct mrt6msg *im6;

#if MRT6DEBUG
	if (mrt6debug)
		log(LOG_DEBUG, "** IPv6 register_send **\n src %s dst %s\n",
		    ip6_sprintf(&ip6->ip6_src), ip6_sprintf(&ip6->ip6_dst));
#endif
	++pim6stat.pim6s_snd_registers;

	/* Make a copy of the packet to send to the user level process */
	MGETHDR(mm, M_DONTWAIT, MT_HEADER);
	if (mm == NULL)
		return ENOBUFS;
#ifdef __darwin8_notyet
#if CONFIG_MACF_NET
	mac_create_mbuf_multicast_encap(m, mif->m6_ifp, mm);
#endif
#endif
	mm->m_pkthdr.rcvif = NULL;
	mm->m_data += max_linkhdr;
	mm->m_len = sizeof(struct ip6_hdr);

	if ((mm->m_next = m_copy(m, 0, M_COPYALL)) == NULL) {
		m_freem(mm);
		return ENOBUFS;
	}
	i = MHLEN - M_LEADINGSPACE(mm);
	if (i > len)
		i = len;
	mm = m_pullup(mm, i);
	if (mm == NULL){
		m_freem(mm);
		return ENOBUFS;
	}
/* TODO: check it! */
	mm->m_pkthdr.len = len + sizeof(struct ip6_hdr);

	/*
	 * Send message to routing daemon
	 */
	addr.sin6_addr = ip6->ip6_src;

	im6 = mtod(mm, struct mrt6msg *);
	im6->im6_msgtype      = MRT6MSG_WHOLEPKT;
	im6->im6_mbz          = 0;

	im6->im6_mif = mif - mif6table;

	/* iif info is not given for reg. encap.n */
	mrt6stat.mrt6s_upcalls++;

	if (socket_send(ip6_mrouter, mm, &addr) < 0) {
#if MRT6DEBUG
		if (mrt6debug)
			log(LOG_WARNING,
			    "register_send: ip6_mrouter socket queue full\n");
#endif
		++mrt6stat.mrt6s_upq_sockfull;
		return ENOBUFS;
	}
	return 0;
}

/*
 * PIM sparse mode hook
 * Receives the pim control messages, and passes them up to the listening
 * socket, using rip6_input.
 * The only message processed is the REGISTER pim message; the pim header
 * is stripped off, and the inner packet is passed to register_mforward.
 */
int
pim6_input(struct mbuf **mp, int *offp, int proto)
{
	struct pim *pim; /* pointer to a pim struct */
	struct ip6_hdr *ip6;
	int pimlen;
	struct mbuf *m = *mp;
	int minlen;
	int off = *offp;

	++pim6stat.pim6s_rcv_total;

	/* Expect 32-bit aligned data pointer on strict-align platforms */
	MBUF_STRICT_DATA_ALIGNMENT_CHECK_32(m);

	ip6 = mtod(m, struct ip6_hdr *);
	pimlen = m->m_pkthdr.len - *offp;

	/*
	 * Validate lengths
	 */
	if (pimlen < PIM_MINLEN) {
		++pim6stat.pim6s_rcv_tooshort;
#if MRT6DEBUG
		if (mrt6debug & DEBUG_PIM)
			log(LOG_DEBUG,"pim6_input: PIM packet too short\n");
#endif
		m_freem(m);
		return(IPPROTO_DONE);
	}

	/*
	 * if the packet is at least as big as a REGISTER, go ahead
	 * and grab the PIM REGISTER header size, to avoid another
	 * possible m_pullup() later.
	 *
	 * PIM_MINLEN       == pimhdr + u_int32 == 8
	 * PIM6_REG_MINLEN   == pimhdr + reghdr + eip6hdr == 4 + 4 + 40
	 */
	minlen = (pimlen >= PIM6_REG_MINLEN) ? PIM6_REG_MINLEN : PIM_MINLEN;

	/*
	 * Make sure that the IP6 and PIM headers in contiguous memory, and
	 * possibly the PIM REGISTER header
	 */
#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, off, minlen, return IPPROTO_DONE);
	/* adjust pointer */
	ip6 = mtod(m, struct ip6_hdr *);

	/* adjust mbuf to point to the PIM header */
	pim = (struct pim *)((caddr_t)ip6 + off);
#else
	IP6_EXTHDR_GET(pim, struct pim *, m, off, minlen);
	if (pim == NULL) {
		pim6stat.pim6s_rcv_tooshort++;
		return IPPROTO_DONE;
	}
#endif

#define PIM6_CHECKSUM
#ifdef PIM6_CHECKSUM
	{
		int cksumlen;

		/*
		 * Validate checksum.
		 * If PIM REGISTER, exclude the data packet
		 */
		if (pim->pim_type == PIM_REGISTER)
			cksumlen = PIM_MINLEN;
		else
			cksumlen = pimlen;

		if (in6_cksum(m, IPPROTO_PIM, off, cksumlen)) {
			++pim6stat.pim6s_rcv_badsum;
#if MRT6DEBUG
			if (mrt6debug & DEBUG_PIM)
				log(LOG_DEBUG,
				    "pim6_input: invalid checksum\n");
#endif
			m_freem(m);
			return(IPPROTO_DONE);
		}
	}
#endif /* PIM_CHECKSUM */

	/* PIM version check */
	if (pim->pim_ver != PIM_VERSION) {
		++pim6stat.pim6s_rcv_badversion;
#if MRT6DEBUG
		log(LOG_ERR,
		    "pim6_input: incorrect version %d, expecting %d\n",
		    pim->pim_ver, PIM_VERSION);
#endif
		m_freem(m);
		return(IPPROTO_DONE);
	}

	if (pim->pim_type == PIM_REGISTER) {
		/*
		 * since this is a REGISTER, we'll make a copy of the register
		 * headers ip6+pim+u_int32_t+encap_ip6, to be passed up to the
		 * routing daemon.
		 */
		static struct sockaddr_in6 dst = { sizeof(dst), AF_INET6 , 
											0, 0, IN6ADDR_ANY_INIT, 0 };

		struct mbuf *mcp;
		struct ip6_hdr *eip6;
		u_int32_t *reghdr;
	
		++pim6stat.pim6s_rcv_registers;

		if ((reg_mif_num >= nummifs) || (reg_mif_num == (mifi_t) -1)) {
#if MRT6DEBUG
			if (mrt6debug & DEBUG_PIM)
				log(LOG_DEBUG,
				    "pim6_input: register mif not set: %d\n",
				    reg_mif_num);
#endif
			m_freem(m);
			return(IPPROTO_DONE);
		}
	
		reghdr = (u_int32_t *)(pim + 1);
	
		if ((ntohl(*reghdr) & PIM_NULL_REGISTER))
			goto pim6_input_to_daemon;

		/*
		 * Validate length
		 */
		if (pimlen < PIM6_REG_MINLEN) {
			++pim6stat.pim6s_rcv_tooshort;
			++pim6stat.pim6s_rcv_badregisters;
#if MRT6DEBUG
			log(LOG_ERR,
			    "pim6_input: register packet size too "
			    "small %d from %s\n",
			    pimlen, ip6_sprintf(&ip6->ip6_src));
#endif
			m_freem(m);
			return(IPPROTO_DONE);
		}
	
		eip6 = (struct ip6_hdr *) (reghdr + 1);
#if MRT6DEBUG	
		if (mrt6debug & DEBUG_PIM)
			log(LOG_DEBUG,
			    "pim6_input[register], eip6: %s -> %s, "
			    "eip6 plen %d\n",
			    ip6_sprintf(&eip6->ip6_src),
			    ip6_sprintf(&eip6->ip6_dst),
			    ntohs(eip6->ip6_plen));
#endif

		/* verify the version number of the inner packet */
		if ((eip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION) {
			++pim6stat.pim6s_rcv_badregisters;
#if MRT6DEBUG
			log(LOG_DEBUG, "pim6_input: invalid IP version (%d) "
			    "of the inner packet\n",
			    (eip6->ip6_vfc & IPV6_VERSION));
#endif
			m_freem(m);
			return(IPPROTO_NONE);
		}
	
		/* verify the inner packet is destined to a mcast group */
		if (!IN6_IS_ADDR_MULTICAST(&eip6->ip6_dst)) {
			++pim6stat.pim6s_rcv_badregisters;
#if MRT6DEBUG
			if (mrt6debug & DEBUG_PIM)
				log(LOG_DEBUG,
				    "pim6_input: inner packet of register "
				    "is not multicast %s\n",
				    ip6_sprintf(&eip6->ip6_dst));
#endif
			m_freem(m);
			return(IPPROTO_DONE);
		}
	
		/*
		 * make a copy of the whole header to pass to the daemon later.
		 */
		mcp = m_copy(m, 0, off + PIM6_REG_MINLEN);
		if (mcp == NULL) {
#if MRT6DEBUG
			log(LOG_ERR,
			    "pim6_input: pim register: "
			    "could not copy register head\n");
#endif
			m_freem(m);
			return(IPPROTO_DONE);
		}
	
		/*
		 * forward the inner ip6 packet; point m_data at the inner ip6.
		 */
		m_adj(m, off + PIM_MINLEN);
#if MRT6DEBUG
		if (mrt6debug & DEBUG_PIM) {
			log(LOG_DEBUG,
			    "pim6_input: forwarding decapsulated register: "
			    "src %s, dst %s, mif %d\n",
			    ip6_sprintf(&eip6->ip6_src),
			    ip6_sprintf(&eip6->ip6_dst),
			    reg_mif_num);
		}
#endif

#ifdef __APPLE__

                if (lo_ifp) {
                    dlil_output(lo_ifp, PF_INET6, m, 0, (struct sockaddr *)&dst, 0, NULL);
		}
                else {
                    printf("Warning: pim6_input call to dlil_find_dltag failed!\n");
                    m_freem(m);
                }
#else
 		(void) if_simloop(mif6table[reg_mif_num].m6_ifp, m,
				dst.sin6_family, NULL);
#endif
	
		/* prepare the register head to send to the mrouting daemon */
		m = mcp;
	}

	/*
	 * Pass the PIM message up to the daemon; if it is a register message
	 * pass the 'head' only up to the daemon. This includes the
	 * encapsulator ip6 header, pim header, register header and the
	 * encapsulated ip6 header.
	 */
  pim6_input_to_daemon:
	rip6_input(&m, offp);
	return(IPPROTO_DONE);
}
#endif
