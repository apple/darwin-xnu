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
 *	@(#)clnp_output.c	8.1 (Berkeley) 6/10/93
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

#include <netiso/iso.h>
#include <netiso/iso_var.h>
#include <netiso/iso_pcb.h>
#include <netiso/clnp.h>
#include <netiso/clnp_stat.h>
#include <netiso/argo_debug.h>

static struct clnp_fixed dt_template = {
	ISO8473_CLNP,	/* network identifier */
	0,				/* length */
	ISO8473_V1,		/* version */
	CLNP_TTL,		/* ttl */
	CLNP_DT|CNF_SEG_OK|CNF_ERR_OK,		/* type */
	0,				/* segment length */
	0				/* checksum */
};

static struct clnp_fixed raw_template = {
	ISO8473_CLNP,	/* network identifier */
	0,				/* length */
	ISO8473_V1,		/* version */
	CLNP_TTL,		/* ttl */
	CLNP_RAW|CNF_SEG_OK|CNF_ERR_OK,		/* type */
	0,				/* segment length */
	0				/* checksum */
};

static struct clnp_fixed echo_template = {
	ISO8473_CLNP,	/* network identifier */
	0,				/* length */
	ISO8473_V1,		/* version */
	CLNP_TTL,		/* ttl */
	CLNP_EC|CNF_SEG_OK|CNF_ERR_OK,		/* type */
	0,				/* segment length */
	0				/* checksum */
};

static struct clnp_fixed echor_template = {
	ISO8473_CLNP,	/* network identifier */
	0,				/* length */
	ISO8473_V1,		/* version */
	CLNP_TTL,		/* ttl */
	CLNP_ECR|CNF_SEG_OK|CNF_ERR_OK,		/* type */
	0,				/* segment length */
	0				/* checksum */
};

#ifdef	DECBIT
u_char qos_option[] = {CLNPOVAL_QOS, 1, 
	CLNPOVAL_GLOBAL|CLNPOVAL_SEQUENCING|CLNPOVAL_LOWDELAY};
#endif	/* DECBIT */

int				clnp_id = 0;		/* id for segmented dgrams */

/*
 * FUNCTION:		clnp_output
 *
 * PURPOSE:			output the data in the mbuf as a clnp datagram
 *
 *					The data specified by m0 is sent as a clnp datagram. 
 *					The mbuf chain m0 will be freed when this routine has
 *					returned.
 *
 *					If options is non-null, it points to an mbuf which contains
 *					options to be sent with the datagram. The options must
 *					be formatted in the mbuf according to clnp rules. Options
 *					will not be freed.
 *
 *					Datalen specifies the length of the data in m0. 
 *
 *					Src and dst are the addresses for the packet. 
 *
 *					If route is non-null, it is used as the route for 
 *					the packet. 
 *
 *					By default, a DT is sent. However, if flags & CNLP_SEND_ER
 *					then an ER will be sent. If flags & CLNP_SEND_RAW, then
 *					the packet will be send as raw clnp.
 *
 * RETURNS:			0	success
 *					appropriate error code
 *
 * SIDE EFFECTS:	none
 *
 * NOTES:			
 *					Flags are interpretated as follows:
 *						CLNP_NO_SEG - do not allow this pkt to be segmented.
 *						CLNP_NO_ER  - have pkt request ER suppression.
 *						CLNP_SEND_RAW - send pkt as RAW DT rather than TP DT
 *						CLNP_NO_CKSUM - don't compute clnp checksum
 *						CLNP_ECHO - send as ECHO packet
 *
 *					When checking for a cached packet, clnp checks
 *					that the route taken is still up. It does not
 *					check that the route is still to the same destination.
 *					This means that any entity that alters an existing
 *					route for an isopcb (such as when a redirect arrives)
 *					must invalidate the clnp cache. It might be perferable
 *					to have clnp check that the route has the same dest, but
 *					by avoiding this check, we save a call to iso_addrmatch1.
 */
clnp_output(m0, isop, datalen, flags)
struct mbuf			*m0;		/* data for the packet */
struct isopcb		*isop;		/* iso pcb */
int					datalen;	/* number of bytes of data in m0 */
int					flags;		/* flags */
{
	int							error = 0;		/* return value of function */
	register struct mbuf		*m = m0;		/* mbuf for clnp header chain */
	register struct clnp_fixed	*clnp;			/* ptr to fixed part of hdr */
	register caddr_t			hoff;			/* offset into header */
	int							total_len;		/* total length of packet */
	struct iso_addr				*src;		/* ptr to source address */
	struct iso_addr				*dst;		/* ptr to destination address */
	struct clnp_cache			clc;		/* storage for cache information */
	struct clnp_cache			*clcp = NULL;	/* ptr to clc */
	int							hdrlen = 0;

	dst = &isop->isop_faddr->siso_addr;
	if (isop->isop_laddr == 0) {
		struct iso_ifaddr *ia = 0;
		clnp_route(dst, &isop->isop_route, flags, 0, &ia);
		if (ia == 0 || ia->ia_ifa.ifa_addr->sa_family != AF_ISO)
			return (ENETUNREACH);
		src = &ia->ia_addr.siso_addr;
	} else
		src = &isop->isop_laddr->siso_addr;

	IFDEBUG(D_OUTPUT)
		printf("clnp_output: to %s", clnp_iso_addrp(dst));
		printf(" from %s of %d bytes\n", clnp_iso_addrp(src), datalen);
		printf("\toptions x%x, flags x%x, isop_clnpcache x%x\n", 
			isop->isop_options, flags, isop->isop_clnpcache);
	ENDDEBUG

	if (isop->isop_clnpcache != NULL) {
		clcp = mtod(isop->isop_clnpcache, struct clnp_cache *);
	}
	
	/*
	 *	Check if cache is valid ...
	 */
	IFDEBUG(D_OUTPUT)
		printf("clnp_output: ck cache: clcp %x\n", clcp);
		if (clcp != NULL) {
			printf("\tclc_dst %s\n", clnp_iso_addrp(&clcp->clc_dst));
			printf("\tisop_opts x%x, clc_opts x%x\n", isop->isop_options,
				clcp->clc_options);
			if (isop->isop_route.ro_rt)
				printf("\tro_rt x%x, rt_flags x%x\n",
					isop->isop_route.ro_rt, isop->isop_route.ro_rt->rt_flags);
			printf("\tflags x%x, clc_flags x%x\n", flags, clcp->clc_flags);
			printf("\tclc_hdr x%x\n", clcp->clc_hdr);
		}
	ENDDEBUG
	if ((clcp != NULL) &&								/* cache exists */
		(isop->isop_options == clcp->clc_options) && 	/* same options */
		(iso_addrmatch1(dst, &clcp->clc_dst)) &&		/* dst still same */
		(isop->isop_route.ro_rt != NULL) &&				/* route exists */
		(isop->isop_route.ro_rt == clcp->clc_rt) &&		/* and is cached */
		(isop->isop_route.ro_rt->rt_flags & RTF_UP) &&	/* route still up */
		(flags == clcp->clc_flags) &&					/* same flags */
		(clcp->clc_hdr != NULL)) {						/* hdr mbuf exists */
		/*
		 *	The cache is valid
		 */

		IFDEBUG(D_OUTPUT)
			printf("clnp_output: using cache\n");
		ENDDEBUG

		m = m_copy(clcp->clc_hdr, 0, (int)M_COPYALL);
		if (m == NULL) {
			/*
			 *	No buffers left to copy cached packet header. Use
			 *	the cached packet header this time, and
			 *	mark the hdr as vacant
			 */
			m = clcp->clc_hdr;
			clcp->clc_hdr = NULL;
		}
		m->m_next = m0;	/* ASSUMES pkt hdr is 1 mbuf long */
		clnp = mtod(m, struct clnp_fixed *);
	} else {
		struct clnp_optidx	*oidx = NULL;		/* index to clnp options */

		/*
		 *	The cache is not valid. Allocate an mbuf (if necessary)
		 *	to hold cached info. If one is not available, then
		 *	don't bother with the cache
		 */
		INCSTAT(cns_cachemiss);
		if (flags & CLNP_NOCACHE) {
			clcp = &clc;
		} else {
			if (isop->isop_clnpcache == NULL) {
				/*
				 *	There is no clnpcache. Allocate an mbuf to hold one
				 */
				if ((isop->isop_clnpcache = m_get(M_DONTWAIT, MT_HEADER))
					== NULL) {
					/*
					 *	No mbufs available. Pretend that we don't want
					 *	caching this time.
					 */
					IFDEBUG(D_OUTPUT)
						printf("clnp_output: no mbufs to allocate to cache\n");
					ENDDEBUG
					flags  |= CLNP_NOCACHE;
					clcp = &clc;
				} else {
					clcp = mtod(isop->isop_clnpcache, struct clnp_cache *);
				}
			} else {
				/*
				 *	A clnpcache mbuf exists. If the clc_hdr is not null,
				 *	we must free it, as a new one is about to be created.
				 */
				clcp = mtod(isop->isop_clnpcache, struct clnp_cache *);
				if (clcp->clc_hdr != NULL) {
					/*
					 *	The clc_hdr is not null but a clnpcache mbuf exists.
					 *	This means that there was a cache, but the existing
					 *	copy of the hdr is no longer valid. Free it now
					 *	before we lose the pointer to it.
					 */
					IFDEBUG(D_OUTPUT)
						printf("clnp_output: freeing old clc_hdr 0x%x\n",
						clcp->clc_hdr);
					ENDDEBUG
					m_free(clcp->clc_hdr);
					IFDEBUG(D_OUTPUT)
						printf("clnp_output: freed old clc_hdr (done)\n");
					ENDDEBUG
				}
			}
		}
		IFDEBUG(D_OUTPUT)
			printf("clnp_output: NEW clcp x%x\n",clcp);
		ENDDEBUG
		bzero((caddr_t)clcp, sizeof(struct clnp_cache));

		if (isop->isop_optindex)
			oidx = mtod(isop->isop_optindex, struct clnp_optidx *);

		/*
		 *	Don't allow packets with security, quality of service,
		 *	priority, or error report options to be sent.
		 */
		if ((isop->isop_options) && (oidx)) {
			if ((oidx->cni_securep) ||
				(oidx->cni_priorp) ||
				(oidx->cni_qos_formatp) ||
				(oidx->cni_er_reason != ER_INVALREAS)) {
				IFDEBUG(D_OUTPUT)
					printf("clnp_output: pkt dropped - option unsupported\n");
				ENDDEBUG
				m_freem(m0);
				return(EINVAL);
			}
		}

		/*
		 *	Don't allow any invalid flags to be set
		 */
		if ((flags & (CLNP_VFLAGS)) != flags) {
			IFDEBUG(D_OUTPUT)
				printf("clnp_output: packet dropped - flags unsupported\n");
			ENDDEBUG
			INCSTAT(cns_odropped);
			m_freem(m0);
			return(EINVAL);
		}

		/*
		 *	Don't allow funny lengths on dst; src may be zero in which
		 *	case we insert the source address based upon the interface
		 */
		if ((src->isoa_len > sizeof(struct iso_addr)) || 
			(dst->isoa_len == 0) ||
			(dst->isoa_len > sizeof(struct iso_addr))) {
			m_freem(m0);
			INCSTAT(cns_odropped);
			return(ENAMETOOLONG);
		}

		/*
		 *	Grab mbuf to contain header
		 */
		MGETHDR(m, M_DONTWAIT, MT_HEADER);
		if (m == 0) {
			m_freem(m0);
			INCSTAT(cns_odropped);
			return(ENOBUFS);
		}
		INCSTAT(cns_sent);
		m->m_next = m0;
		clnp = mtod(m, struct clnp_fixed *);
		clcp->clc_segoff = 0;

		/*
		 *	Fill in all of fixed hdr except lengths and checksum
		 */
		if (flags & CLNP_SEND_RAW) {
			*clnp = raw_template;
		} else if (flags & CLNP_ECHO) {
			*clnp = echo_template;
		} else if (flags & CLNP_ECHOR) {
			*clnp = echor_template;
		} else {
			*clnp = dt_template;
		}
		if (flags & CLNP_NO_SEG)
			clnp->cnf_type &= ~CNF_SEG_OK;
		if (flags & CLNP_NO_ER)
			clnp->cnf_type &= ~CNF_ERR_OK;

		/*
		 *	Route packet; special case for source rt
		 */
		if ((isop->isop_options) && CLNPSRCRT_VALID(oidx)) {
			IFDEBUG(D_OUTPUT)
				printf("clnp_output: calling clnp_srcroute\n");
			ENDDEBUG
			error = clnp_srcroute(isop->isop_options, oidx, &isop->isop_route,
				&clcp->clc_firsthop, &clcp->clc_ifa, dst);
		} else {
			IFDEBUG(D_OUTPUT)
			ENDDEBUG
			error = clnp_route(dst, &isop->isop_route, flags, 
				&clcp->clc_firsthop, &clcp->clc_ifa);
		}
		if (error || (clcp->clc_ifa == 0)) {
			IFDEBUG(D_OUTPUT)
				printf("clnp_output: route failed, errno %d\n", error);
				printf("@clcp:\n");
				dump_buf(clcp, sizeof (struct clnp_cache));
			ENDDEBUG
			goto bad;
		}
		clcp->clc_rt = isop->isop_route.ro_rt;	/* XXX */
		clcp->clc_ifp = clcp->clc_ifa->ia_ifp;  /* XXX */

		IFDEBUG(D_OUTPUT)
			printf("clnp_output: packet routed to %s\n", 
				clnp_iso_addrp(
					&((struct sockaddr_iso *)clcp->clc_firsthop)->siso_addr));
		ENDDEBUG
		
		/*
		 *	If src address is not yet specified, use address of 
		 *	interface. NOTE: this will now update the laddr field in
		 *	the isopcb. Is this desirable? RAH?
		 */
		if (src->isoa_len == 0) {
			src = &(clcp->clc_ifa->ia_addr.siso_addr);
			IFDEBUG(D_OUTPUT)
				printf("clnp_output: new src %s\n", clnp_iso_addrp(src));
			ENDDEBUG
		}

		/*
		 *	Insert the source and destination address,
		 */
		hoff = (caddr_t)clnp + sizeof(struct clnp_fixed);
		CLNP_INSERT_ADDR(hoff, *dst);
		CLNP_INSERT_ADDR(hoff, *src);

		/*
		 *	Leave room for the segment part, if segmenting is selected
		 */
		if (clnp->cnf_type & CNF_SEG_OK) {
			clcp->clc_segoff = hoff - (caddr_t)clnp;
			hoff += sizeof(struct clnp_segment);
		}

		clnp->cnf_hdr_len = m->m_len = (u_char)(hoff - (caddr_t)clnp);
		hdrlen = clnp->cnf_hdr_len;

#ifdef	DECBIT
		/*
		 *	Add the globally unique QOS (with room for congestion experienced
		 *	bit). I can safely assume that this option is not in the options
		 *	mbuf below because I checked that the option was not specified
		 *	previously
		 */
		if ((m->m_len + sizeof(qos_option)) < MLEN) {
			bcopy((caddr_t)qos_option, hoff, sizeof(qos_option));
			clnp->cnf_hdr_len += sizeof(qos_option);
			hdrlen += sizeof(qos_option);
			m->m_len += sizeof(qos_option);
		}
#endif	/* DECBIT */

		/*
		 *	If an options mbuf is present, concatenate a copy to the hdr mbuf.
		 */
		if (isop->isop_options) {
			struct mbuf *opt_copy = m_copy(isop->isop_options, 0, (int)M_COPYALL);
			if (opt_copy == NULL) {
				error = ENOBUFS;
				goto bad;
			}
			/* Link in place */
			opt_copy->m_next = m->m_next;
			m->m_next = opt_copy;

			/* update size of header */
			clnp->cnf_hdr_len += opt_copy->m_len;
			hdrlen += opt_copy->m_len;
		}

		if (hdrlen > CLNP_HDR_MAX) {
			error = EMSGSIZE;
			goto bad;
		}

		/*
		 *	Now set up the cache entry in the pcb
		 */
		if ((flags & CLNP_NOCACHE) == 0) {
			if (clcp->clc_hdr = m_copy(m, 0, (int)clnp->cnf_hdr_len)) {
				clcp->clc_dst  = *dst;
				clcp->clc_flags = flags;
				clcp->clc_options = isop->isop_options;
			}
		}
	}
	/*
	 *	If small enough for interface, send directly
	 *	Fill in segmentation part of hdr if using the full protocol
	 */
	total_len = clnp->cnf_hdr_len + datalen;
	if (clnp->cnf_type & CNF_SEG_OK) {
		struct clnp_segment	seg_part;		/* segment part of hdr */
		seg_part.cng_id = htons(clnp_id++);
		seg_part.cng_off = htons(0);
		seg_part.cng_tot_len = htons(total_len);
		(void) bcopy((caddr_t)&seg_part, (caddr_t) clnp + clcp->clc_segoff, 
			sizeof(seg_part));
	}
	if (total_len <= SN_MTU(clcp->clc_ifp, clcp->clc_rt)) {
		HTOC(clnp->cnf_seglen_msb, clnp->cnf_seglen_lsb, total_len);
		m->m_pkthdr.len = total_len;
		/*
		 *	Compute clnp checksum (on header only)
		 */
		if (flags & CLNP_NO_CKSUM) {
			HTOC(clnp->cnf_cksum_msb, clnp->cnf_cksum_lsb, 0);
		} else {
			iso_gen_csum(m, CLNP_CKSUM_OFF, (int)clnp->cnf_hdr_len);
		}

		IFDEBUG(D_DUMPOUT)
			struct mbuf *mdump = m;
			printf("clnp_output: sending dg:\n");
			while (mdump != NULL) {
				dump_buf(mtod(mdump, caddr_t), mdump->m_len);
				mdump = mdump->m_next;
			}
		ENDDEBUG

		error = SN_OUTPUT(clcp, m);
		goto done;
	} else {
		/*
		 * Too large for interface; fragment if possible.
		 */
		error = clnp_fragment(clcp->clc_ifp, m, clcp->clc_firsthop,
							total_len, clcp->clc_segoff, flags, clcp->clc_rt);
		goto done;
	}
bad:
	m_freem(m);
done:
	if (error) {
		clnp_stat.cns_sent--;
		clnp_stat.cns_odropped++;
	}
	return (error);
}

int clnp_ctloutput()
{
}
