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
/*-
 * Copyright (c) 1991, 1993
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
 *	@(#)clnp_subr.c	8.1 (Berkeley) 6/10/93
 */

/***********************************************************
		Copyright IBM Corporation 1987

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its 
documentation for any purpose and without fee is hereby granted, 
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in 
supporting documentation, and that the name of IBM not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.  

IBM DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
IBM BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.

******************************************************************/

/*
 * ARGO Project, Computer Sciences Dept., University of Wisconsin - Madison
 */

#if ISO

#include <sys/param.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/time.h>

#include <net/if.h>
#include <net/route.h>
#include <net/if_dl.h>

#include <netiso/iso.h>
#include <netiso/iso_var.h>
#include <netiso/iso_pcb.h>
#include <netiso/iso_snpac.h>
#include <netiso/clnp.h>
#include <netiso/clnp_stat.h>
#include <netiso/argo_debug.h>

/*
 * FUNCTION:		clnp_data_ck
 *
 * PURPOSE:			Check that the amount of data in the mbuf chain is
 *					at least as much as the clnp header would have us
 *					expect. Trim mbufs if longer than expected, drop
 *					packet if shorter than expected.
 *
 * RETURNS:			success - ptr to mbuf chain
 *					failure - 0
 *
 * SIDE EFFECTS:	
 *
 * NOTES:			
 */
struct mbuf *
clnp_data_ck(m, length)
register struct mbuf	*m;		/* ptr to mbuf chain containing hdr & data */
int						length;	/* length (in bytes) of packet */
 {
	register int 			len;		/* length of data */
	register struct mbuf	*mhead;		/* ptr to head of chain */

	len = -length;
	mhead = m;
	for (;;) {
		len += m->m_len;
		if (m->m_next == 0)
			break;
		m = m->m_next;
	}
	if (len != 0) {
		if (len < 0) {
			INCSTAT(cns_toosmall);
			clnp_discard(mhead, GEN_INCOMPLETE);
			return 0;
		}
		if (len <= m->m_len)
			m->m_len -= len;
		else
			m_adj(mhead, -len);
	}
	return mhead;
}

#ifdef notdef
/*
 * FUNCTION:		clnp_extract_addr
 *
 * PURPOSE:			Extract the source and destination address from the
 *					supplied buffer. Place them in the supplied address buffers.
 *					If insufficient data is supplied, then fail.
 *
 * RETURNS:			success - Address of first byte in the packet past 
 *						the address part.
 *					failure - 0
 *
 * SIDE EFFECTS:	
 *
 * NOTES:			
 */
caddr_t
clnp_extract_addr(bufp, buflen, srcp, destp)
caddr_t					bufp;		/* ptr to buffer containing addresses */
int						buflen;		/* length of buffer */
register struct iso_addr	*srcp;		/* ptr to source address buffer */
register struct iso_addr	*destp;		/* ptr to destination address buffer */
 {
	int	len;		/* argument to bcopy */

	/* 
	 *	check that we have enough data. Plus1 is for length octet
	 */
	if ((u_char)*bufp + 1 > buflen) {
		return((caddr_t)0);
	}
	len = destp->isoa_len = (u_char)*bufp++;
	(void) bcopy(bufp, (caddr_t)destp, len);
	buflen -= len;
	bufp += len;

	/* 
	 *	check that we have enough data. Plus1 is for length octet
	 */
	if ((u_char)*bufp + 1 > buflen) {
		return((caddr_t)0);
	}
	len = srcp->isoa_len = (u_char)* bufp++;
	(void) bcopy(bufp, (caddr_t)srcp, len);
	bufp += len;

	/*
	 *	Insure that the addresses make sense
	 */
	if (iso_ck_addr(srcp) && iso_ck_addr(destp))
		return bufp;
	else
		return (caddr_t) 0;
}
#endif	/* notdef */

/*
 * FUNCTION:		clnp_ours
 *
 * PURPOSE:			Decide whether the supplied packet is destined for
 *					us, or that it should be forwarded on.
 *
 * RETURNS:			packet is for us - 1
 *					packet is not for us - 0
 *
 * SIDE EFFECTS:	
 *
 * NOTES:			
 */
clnp_ours(dst)
register struct iso_addr *dst;		/* ptr to destination address */
{
	register struct iso_ifaddr *ia;	/* scan through interface addresses */

	for (ia = iso_ifaddr; ia; ia = ia->ia_next) {
		IFDEBUG(D_ROUTE)
			printf("clnp_ours: ia_sis x%x, dst x%x\n", &ia->ia_addr, 
				dst);
		ENDDEBUG
		/*
		 * XXX Warning:
		 * We are overloading siso_tlen in the if's address, as an nsel length.
		 */
		if (dst->isoa_len == ia->ia_addr.siso_nlen &&
			bcmp((caddr_t)ia->ia_addr.siso_addr.isoa_genaddr,
				 (caddr_t)dst->isoa_genaddr,
				 ia->ia_addr.siso_nlen - ia->ia_addr.siso_tlen) == 0)
					return 1;
	}
	return 0;
}

/* Dec bit set if ifp qlen is greater than congest_threshold */
int congest_threshold = 0;

/*
 * FUNCTION:		clnp_forward
 *
 * PURPOSE:			Forward the datagram passed
 *					clnpintr guarantees that the header will be
 *					contigious (a cluster mbuf will be used if necessary).
 *
 *					If oidx is NULL, no options are present.
 *
 * RETURNS:			nothing
 *
 * SIDE EFFECTS:	
 *
 * NOTES:			
 */
clnp_forward(m, len, dst, oidx, seg_off, inbound_shp)
struct mbuf			*m;		/* pkt to forward */
int					len;	/* length of pkt */
struct iso_addr		*dst;	/* destination address */
struct clnp_optidx	*oidx;	/* option index */
int					seg_off;/* offset of segmentation part */
struct snpa_hdr		*inbound_shp;	/* subnetwork header of inbound packet */
{
	struct clnp_fixed		*clnp;	/* ptr to fixed part of header */
	int						error;	/* return value of route function */
	struct sockaddr			*next_hop;	/* next hop for dgram */
	struct ifnet			*ifp;	/* ptr to outgoing interface */
	struct iso_ifaddr		*ia = 0;/* ptr to iso name for ifp */
	struct route_iso		route;	/* filled in by clnp_route */
	extern int				iso_systype;

	clnp = mtod(m, struct clnp_fixed *);
	bzero((caddr_t)&route, sizeof(route)); /* MUST be done before "bad:" */

	/*
	 *	Don't forward multicast or broadcast packets
	 */
	if ((inbound_shp) && (IS_MULTICAST(inbound_shp->snh_dhost))) {
		IFDEBUG(D_FORWARD)
			printf("clnp_forward: dropping multicast packet\n");
		ENDDEBUG
		clnp->cnf_type &= ~CNF_ERR_OK; /* so we don't generate an ER */
		clnp_discard(m, 0);
		INCSTAT(cns_cantforward);
		goto done;
	}

	IFDEBUG(D_FORWARD)
		printf("clnp_forward: %d bytes, to %s, options x%x\n", len,
			clnp_iso_addrp(dst), oidx);
	ENDDEBUG

	/*
	 *	Decrement ttl, and if zero drop datagram
	 *	Can't compare ttl as less than zero 'cause its a unsigned
	 */
	if ((clnp->cnf_ttl == 0) || (--clnp->cnf_ttl == 0)) {
		IFDEBUG(D_FORWARD)
			printf("clnp_forward: discarding datagram because ttl is zero\n");
		ENDDEBUG
		INCSTAT(cns_ttlexpired);
		clnp_discard(m, TTL_EXPTRANSIT);
		goto done;
	}
	/*
	 *	Route packet; special case for source rt
	 */
	if CLNPSRCRT_VALID(oidx) {
		/*
		 *	Update src route first
		 */
		clnp_update_srcrt(m, oidx);
		error = clnp_srcroute(m, oidx, &route, &next_hop, &ia, dst);
	} else {
		error = clnp_route(dst, &route, 0, &next_hop, &ia);
	}
	if (error || ia == 0) {
		IFDEBUG(D_FORWARD)
			printf("clnp_forward: can't route packet (errno %d)\n", error);
		ENDDEBUG
		clnp_discard(m, ADDR_DESTUNREACH);
		INCSTAT(cns_cantforward);
		goto done;
	}
	ifp = ia->ia_ifp;

	IFDEBUG(D_FORWARD)
		printf("clnp_forward: packet routed to %s\n", 
			clnp_iso_addrp(&((struct sockaddr_iso *)next_hop)->siso_addr));
	ENDDEBUG

	INCSTAT(cns_forward);

	/*
	 *	If we are an intermediate system and
	 *	we are routing outbound on the same ifp that the packet
	 *	arrived upon, and we know the next hop snpa, 
	 *	then generate a redirect request
	 */
	if ((iso_systype & SNPA_IS) && (inbound_shp) && 
		(ifp == inbound_shp->snh_ifp))
		    esis_rdoutput(inbound_shp, m, oidx, dst, route.ro_rt);
	/*
	 *	If options are present, update them
	 */
	if (oidx) {
		struct iso_addr	*mysrc = &ia->ia_addr.siso_addr;
		if (mysrc == NULL) {
			clnp_discard(m, ADDR_DESTUNREACH);
			INCSTAT(cns_cantforward);
			clnp_stat.cns_forward--;
			goto done;
		} else {
			(void) clnp_dooptions(m, oidx, ifp, mysrc);
		}
	}

#ifdef	DECBIT
	if (ifp->if_snd.ifq_len > congest_threshold) {
		/*
		 *	Congestion! Set the Dec Bit and thank Dave Oran
		 */
		IFDEBUG(D_FORWARD)
			printf("clnp_forward: congestion experienced\n");
		ENDDEBUG
		if ((oidx) && (oidx->cni_qos_formatp)) {
			caddr_t	qosp = CLNP_OFFTOOPT(m, oidx->cni_qos_formatp);
			u_char	qos = *qosp;
			IFDEBUG(D_FORWARD)
				printf("clnp_forward: setting congestion bit (qos x%x)\n", qos);
			ENDDEBUG
			if ((qos & CLNPOVAL_GLOBAL) == CLNPOVAL_GLOBAL) {
				qos |= CLNPOVAL_CONGESTED;
				INCSTAT(cns_congest_set);
				*qosp = qos;
			}
		}
	}
#endif	/* DECBIT */
	
	/*
	 *	Dispatch the datagram if it is small enough, otherwise fragment
	 */
	if (len <= SN_MTU(ifp, route.ro_rt)) {
		iso_gen_csum(m, CLNP_CKSUM_OFF, (int)clnp->cnf_hdr_len);
		(void) (*ifp->if_output)(ifp, m, next_hop, route.ro_rt);
	} else {
		(void) clnp_fragment(ifp, m, next_hop, len, seg_off, /* flags */0, route.ro_rt);
	}
	
done:
	/*
	 *	Free route
	 */
	if (route.ro_rt != NULL) {
		RTFREE(route.ro_rt);
	}
}

#ifdef	notdef
/*
 * FUNCTION:		clnp_insert_addr
 *
 * PURPOSE:			Insert the address part into a clnp datagram.
 *
 * RETURNS:			Address of first byte after address part in datagram.
 *
 * SIDE EFFECTS:	
 *
 * NOTES:			Assume that there is enough space for the address part.
 */
caddr_t
clnp_insert_addr(bufp, srcp, dstp)
caddr_t						bufp;	/* address of where addr part goes */
register struct iso_addr	*srcp;	/* ptr to src addr */
register struct iso_addr	*dstp;	/* ptr to dst addr */
{
	*bufp++ = dstp->isoa_len;
	(void) bcopy((caddr_t)dstp, bufp, dstp->isoa_len);
	bufp += dstp->isoa_len;

	*bufp++ = srcp->isoa_len;
	(void) bcopy((caddr_t)srcp, bufp, srcp->isoa_len);
	bufp += srcp->isoa_len;

	return bufp;
}

#endif	/* notdef */

/*
 * FUNCTION:		clnp_route
 *
 * PURPOSE:			Route a clnp datagram to the first hop toward its 
 *					destination. In many cases, the first hop will be
 *					the destination. The address of a route
 *					is specified. If a routing entry is present in
 *					that route, and it is still up to the same destination,
 *					then no further action is necessary. Otherwise, a
 *					new routing entry will be allocated.
 *
 * RETURNS:			route found - 0
 *					unix error code
 *
 * SIDE EFFECTS:	
 *
 * NOTES:			It is up to the caller to free the routing entry
 *					allocated in route.
 */
clnp_route(dst, ro, flags, first_hop, ifa)
	struct iso_addr	*dst;			/* ptr to datagram destination */
	register struct	route_iso *ro;	/* existing route structure */
	int flags;						/* flags for routing */
	struct sockaddr **first_hop;	/* result: fill in with ptr to firsthop */
	struct iso_ifaddr **ifa;		/* result: fill in with ptr to interface */
{
	if (flags & SO_DONTROUTE) {
		struct iso_ifaddr *ia;

		if (ro->ro_rt) {
			RTFREE(ro->ro_rt);
			ro->ro_rt = 0;
		}
		bzero((caddr_t)&ro->ro_dst, sizeof(ro->ro_dst));
		bcopy((caddr_t)dst, (caddr_t)&ro->ro_dst.siso_addr,
			1 + (unsigned)dst->isoa_len);
		ro->ro_dst.siso_family = AF_ISO;
		ro->ro_dst.siso_len = sizeof(ro->ro_dst);
		ia = iso_localifa(&ro->ro_dst);
		if (ia == 0)
			return EADDRNOTAVAIL;
		if (ifa)
			*ifa = ia;
		if (first_hop)
			*first_hop = (struct sockaddr *)&ro->ro_dst;
		return 0;
	}
	/*
	 *	If there is a cached route, check that it is still up and to
	 *	the same destination. If not, free it and try again.
	 */
	if (ro->ro_rt && ((ro->ro_rt->rt_flags & RTF_UP) == 0 ||
		(Bcmp(ro->ro_dst.siso_data, dst->isoa_genaddr, dst->isoa_len)))) {
		IFDEBUG(D_ROUTE)
			printf("clnp_route: freeing old route: ro->ro_rt 0x%x\n",
				ro->ro_rt);
			printf("clnp_route: old route refcnt: 0x%x\n",
				ro->ro_rt->rt_refcnt);
		ENDDEBUG

		/* free old route entry */
		RTFREE(ro->ro_rt);
		ro->ro_rt = (struct rtentry *)0;
	} else {
		IFDEBUG(D_ROUTE)
			printf("clnp_route: OK route exists\n");
		ENDDEBUG
	}

	if (ro->ro_rt == 0) {
		/* set up new route structure */
		bzero((caddr_t)&ro->ro_dst, sizeof(ro->ro_dst));
		ro->ro_dst.siso_len = sizeof(ro->ro_dst);
		ro->ro_dst.siso_family = AF_ISO;
		Bcopy(dst, &ro->ro_dst.siso_addr, 1 + dst->isoa_len);
		/* allocate new route */
		IFDEBUG(D_ROUTE)
			printf("clnp_route: allocating new route to %s\n",
				clnp_iso_addrp(dst));
		ENDDEBUG
		rtalloc((struct route *)ro);
	}
	if (ro->ro_rt == 0)
		return(ENETUNREACH);	/* rtalloc failed */
	ro->ro_rt->rt_use++;
	if (ifa)
		if ((*ifa = (struct iso_ifaddr *)ro->ro_rt->rt_ifa) == 0)
			panic("clnp_route");
	if (first_hop) {
		if (ro->ro_rt->rt_flags & RTF_GATEWAY)
			*first_hop = ro->ro_rt->rt_gateway;
		else
			*first_hop = (struct sockaddr *)&ro->ro_dst;
	}
	return(0);
}

/*
 * FUNCTION:		clnp_srcroute
 *
 * PURPOSE:			Source route the datagram. If complete source
 *					routing is specified but not possible, then
 *					return an error. If src routing is terminated, then
 *					try routing on destination.
 *					Usage of first_hop,
 *					ifp, and error return is identical to clnp_route.
 *
 * RETURNS:			0 or unix error code
 *
 * SIDE EFFECTS:	
 *
 * NOTES:			Remember that option index pointers are really
 *					offsets from the beginning of the mbuf.
 */
clnp_srcroute(options, oidx, ro, first_hop, ifa, final_dst)
struct mbuf			*options;		/* ptr to options */
struct clnp_optidx	*oidx;			/* index to options */
struct route_iso	*ro;			/* route structure */
struct sockaddr		**first_hop;	/* RETURN: fill in with ptr to firsthop */
struct iso_ifaddr	**ifa;			/* RETURN: fill in with ptr to interface */
struct iso_addr		*final_dst;		/* final destination */
{
	struct iso_addr	dst;		/* first hop specified by src rt */
	int				error = 0;	/* return code */

	/*
	 *	Check if we have run out of routes 
	 *	If so, then try to route on destination.
	 */
	if CLNPSRCRT_TERM(oidx, options) {
		dst.isoa_len = final_dst->isoa_len;
		bcopy(final_dst->isoa_genaddr, dst.isoa_genaddr, dst.isoa_len);
	} else {
		/*
		 * setup dst based on src rt specified
		 */
		dst.isoa_len = CLNPSRCRT_CLEN(oidx, options);
		bcopy(CLNPSRCRT_CADDR(oidx, options), dst.isoa_genaddr, dst.isoa_len);
	}

	/*
	 *	try to route it
	 */
	error = clnp_route(&dst, ro, 0, first_hop, ifa);
	if (error != 0)
		return error;
	
	/*
	 *	If complete src rt, first hop must be equal to dst
	 */
	if ((CLNPSRCRT_TYPE(oidx, options) == CLNPOVAL_COMPRT) &&
	 (!iso_addrmatch1(&(*(struct sockaddr_iso **)first_hop)->siso_addr,&dst))){
		IFDEBUG(D_OPTIONS)
			printf("clnp_srcroute: complete src route failed\n");
		ENDDEBUG
		return EHOSTUNREACH; /* RAH? would like ESRCRTFAILED */
	}
	
	return error;
}

/*
 * FUNCTION:		clnp_echoreply
 *
 * PURPOSE:			generate an echo reply packet and transmit
 *
 * RETURNS:			result of clnp_output
 *
 * SIDE EFFECTS:	
 */
clnp_echoreply(ec_m, ec_len, ec_src, ec_dst, ec_oidxp)
struct mbuf			*ec_m;		/* echo request */
int					ec_len;		/* length of ec */
struct sockaddr_iso	*ec_src;		/* src of ec */
struct sockaddr_iso	*ec_dst; 	/* destination of ec (i.e., us) */
struct clnp_optidx	*ec_oidxp;	/* options index to ec packet */
{
	struct isopcb	isopcb;
	int				flags = CLNP_NOCACHE|CLNP_ECHOR;
	int				ret;

	/* fill in fake isopcb to pass to output function */
	bzero(&isopcb, sizeof(isopcb));
	isopcb.isop_laddr = ec_dst;
	isopcb.isop_faddr = ec_src;

	/* forget copying the options for now. If implemented, need only
	 * copy record route option, but it must be reset to zero length */

	ret = clnp_output(ec_m, &isopcb, ec_len, flags);

	IFDEBUG(D_OUTPUT)
		printf("clnp_echoreply: output returns %d\n", ret);
	ENDDEBUG
	return ret;
}

/*
 * FUNCTION:		clnp_badmtu
 *
 * PURPOSE:			print notice of route with mtu not initialized.
 *
 * RETURNS:			mtu of ifp.
 *
 * SIDE EFFECTS:	prints notice, slows down system.
 */
clnp_badmtu(ifp, rt, line, file)
struct ifnet *ifp;	/* outgoing interface */
struct rtentry *rt; /* dst route */
int line;			/* where the dirty deed occured */
char *file;			/* where the dirty deed occured */
{
	printf("sending on route 0x%x with no mtu, line %d of file %s\n",
		rt, line, file);
#ifdef ARGO_DEBUG
	printf("route dst is ");
	dump_isoaddr(rt_key(rt));
#endif
	return ifp->if_mtu;
}

/*
 * FUNCTION:		clnp_ypocb - backwards bcopy
 *
 * PURPOSE:			bcopy starting at end of src rather than beginning.
 *
 * RETURNS:			none
 *
 * SIDE EFFECTS:	
 *
 * NOTES:			No attempt has been made to make this efficient
 */
clnp_ypocb(from, to, len)
caddr_t from;		/* src buffer */
caddr_t to;			/* dst buffer */
u_int	len;		/* number of bytes */
{
	while (len--)
		*(to + len) = *(from + len);
}
#endif	/* ISO */
