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
 *	@(#)clnp_raw.c	8.1 (Berkeley) 6/10/93
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
#include <sys/malloc.h>

#include <net/if.h>
#include <net/route.h>
#include <net/raw_cb.h>

#include <netiso/iso.h>
#include <netiso/iso_pcb.h>
#include <netiso/clnp.h>
#include <netiso/clnp_stat.h>
#include <netiso/argo_debug.h>

#include <netiso/tp_user.h>		/* XXX -- defines SOL_NETWORK */

struct sockproto	rclnp_proto	= { PF_ISO, 0 };
/*
 * FUNCTION:		rclnp_input
 *
 * PURPOSE:			Setup generic address an protocol structures for
 *					raw input routine, then pass them along with the
 *					mbuf chain.
 *
 * RETURNS:			none
 *
 * SIDE EFFECTS:	
 *
 * NOTES:			The protocol field of rclnp_proto is set to zero indicating
 *					no protocol.
 */
rclnp_input(m, src, dst, hdrlen)
struct mbuf 		*m;		/* ptr to packet */
struct sockaddr_iso	*src;	/* ptr to src address */
struct sockaddr_iso	*dst;	/* ptr to dest address */
int					hdrlen; /* length (in bytes) of clnp header */
{
#ifdef	TROLL
	if (trollctl.tr_ops & TR_CHUCK) {
		m_freem(m);
		return;
	}
#endif	/* TROLL */

	raw_input(m, &rclnp_proto, (struct sockaddr *)src, (struct sockaddr *)dst);
}

/*
 * FUNCTION:		rclnp_output
 *
 * PURPOSE:			Prepare to send a raw clnp packet. Setup src and dest
 *					addresses, count the number of bytes to send, and
 *					call clnp_output.
 *
 * RETURNS:			success - 0
 *					failure - an appropriate error code
 *
 * SIDE EFFECTS:	
 *
 * NOTES:			
 */
rclnp_output(m0, so)
struct mbuf		*m0;		/* packet to send */
struct socket	*so;	/* socket to send from */
{
	register struct mbuf	*m;			/* used to scan a chain */
	int						len = 0;	/* store length of chain here */
	struct rawisopcb		*rp = sotorawisopcb(so); /* ptr to raw cb */
	int						error;		/* return value of function */
	int						flags;		/* flags for clnp_output */

	if (0 == (m0->m_flags & M_PKTHDR))
		return (EINVAL);
	/*
	 *	Set up src address. If user has bound socket to an address, use it.
	 *	Otherwise, do not specify src (clnp_output will fill it in).
	 */
	if (rp->risop_rcb.rcb_laddr) {
		if (rp->risop_isop.isop_sladdr.siso_family != AF_ISO) {
bad:
			m_freem(m0);
			return(EAFNOSUPPORT);
		}
	}
	/* set up dest address */
	if (rp->risop_rcb.rcb_faddr == 0)
		goto bad;
	rp->risop_isop.isop_sfaddr =
				*(struct sockaddr_iso *)rp->risop_rcb.rcb_faddr;
	rp->risop_isop.isop_faddr = &rp->risop_isop.isop_sfaddr;

	/* get flags and ship it off */
	flags = rp->risop_flags & CLNP_VFLAGS;

	error = clnp_output(m0, &rp->risop_isop, m0->m_pkthdr.len,
												flags|CLNP_NOCACHE);

	return (error);
}

/*
 * FUNCTION:		rclnp_ctloutput
 *
 * PURPOSE:			Raw clnp socket option processing
 *					All options are stored inside an mbuf. 
 *
 * RETURNS:			success - 0
 *					failure - unix error code
 *
 * SIDE EFFECTS:	If the options mbuf does not exist, it the mbuf passed
 *					is used.
 *
 * NOTES:			
 */
rclnp_ctloutput(op, so, level, optname, m)
int				op;				/* type of operation */
struct socket	*so;			/* ptr to socket */
int 			level;			/* level of option */
int				optname;		/* name of option */
struct mbuf		**m;			/* ptr to ptr to option data */
{
	int						error = 0;
	register struct rawisopcb	*rp = sotorawisopcb(so);/* raw cb ptr */

	IFDEBUG(D_CTLOUTPUT)
		printf("rclnp_ctloutput: op = x%x, level = x%x, name = x%x\n",
			op, level, optname);
		if (*m != NULL) {
			printf("rclnp_ctloutput: %d bytes of mbuf data\n", (*m)->m_len);
			dump_buf(mtod((*m), caddr_t), (*m)->m_len);
		}
	ENDDEBUG

#ifdef SOL_NETWORK
	if (level != SOL_NETWORK)
		error = EINVAL;
	else switch (op) {
#else
	switch (op) {
#endif /* SOL_NETWORK */
		case PRCO_SETOPT:
			switch (optname) {
				case CLNPOPT_FLAGS: {
					u_short	usr_flags;
					/* 
					 *	Insure that the data passed has exactly one short in it 
					 */
					if ((*m == NULL) || ((*m)->m_len != sizeof(short))) {
						error = EINVAL;
						break;
					}
					 
					/*
					 *	Don't allow invalid flags to be set
					 */
					usr_flags = (*mtod((*m), short *));

					if ((usr_flags & (CLNP_VFLAGS)) != usr_flags) {
						error = EINVAL;
					} else
						rp->risop_flags |= usr_flags;

					} break;
			
				case CLNPOPT_OPTS:
					if (error = clnp_set_opts(&rp->risop_isop.isop_options, m))
						break;
					rp->risop_isop.isop_optindex = m_get(M_WAIT, MT_SOOPTS);
					(void) clnp_opt_sanity(rp->risop_isop.isop_options, 
						mtod(rp->risop_isop.isop_options, caddr_t),
						rp->risop_isop.isop_options->m_len, 
						mtod(rp->risop_isop.isop_optindex,
							struct clnp_optidx *));
					break;
			} 
			break;

		case PRCO_GETOPT:
#ifdef notdef
			/* commented out to keep hi C quiet */
			switch (optname) {
				default:
					error = EINVAL;
					break;
			}
#endif /* notdef */
			break;
		default:
			error = EINVAL;
			break;
	}
	if (op == PRCO_SETOPT) {
		/* note: m_freem does not barf is *m is NULL */
		m_freem(*m);
		*m = NULL;
	}
	
	return error;
}

/*ARGSUSED*/
clnp_usrreq(so, req, m, nam, control)
	register struct socket *so;
	int req;
	struct mbuf *m, *nam, *control;
{
	register int error = 0;
	register struct rawisopcb *rp = sotorawisopcb(so);

	rp = sotorawisopcb(so);
	switch (req) {

	case PRU_ATTACH:
		if (rp)
			panic("rip_attach");
		MALLOC(rp, struct rawisopcb *, sizeof *rp, M_PCB, M_WAITOK);
		if (rp == 0)
			return (ENOBUFS);
		bzero((caddr_t)rp, sizeof *rp);
		so->so_pcb = (caddr_t)rp;
		break;

	case PRU_DETACH:
		if (rp == 0)
			panic("rip_detach");
		if (rp->risop_isop.isop_options)
			m_freem(rp->risop_isop.isop_options);
		if (rp->risop_isop.isop_route.ro_rt)
			RTFREE(rp->risop_isop.isop_route.ro_rt);
		if (rp->risop_rcb.rcb_laddr)
			rp->risop_rcb.rcb_laddr = 0;
		/* free clnp cached hdr if necessary */
		if (rp->risop_isop.isop_clnpcache != NULL) {
			struct clnp_cache *clcp = 
				mtod(rp->risop_isop.isop_clnpcache, struct clnp_cache *);
			if (clcp->clc_hdr != NULL) {
				m_free(clcp->clc_hdr);
			}
			m_free(rp->risop_isop.isop_clnpcache);
		}
		if (rp->risop_isop.isop_optindex != NULL)
			m_free(rp->risop_isop.isop_optindex);

		break;

	case PRU_BIND:
	    {
		struct sockaddr_iso *addr = mtod(nam, struct sockaddr_iso *);

		if (nam->m_len != sizeof(*addr))
			return (EINVAL);
		if ((ifnet == 0) ||
		    (addr->siso_family != AF_ISO) ||
		    (addr->siso_addr.isoa_len  &&
		     ifa_ifwithaddr((struct sockaddr *)addr) == 0))
			return (EADDRNOTAVAIL);
		rp->risop_isop.isop_sladdr = *addr;
		rp->risop_rcb.rcb_laddr = (struct sockaddr *)
			(rp->risop_isop.isop_laddr = &rp->risop_isop.isop_sladdr);
		return (0);
	    }
	case PRU_CONNECT:
	    {
		struct sockaddr_iso *addr = mtod(nam, struct sockaddr_iso *);

		if ((nam->m_len > sizeof(*addr)) || (addr->siso_len > sizeof(*addr)))
			return (EINVAL);
		if (ifnet == 0)
			return (EADDRNOTAVAIL);
		if (addr->siso_family != AF_ISO)
		rp->risop_isop.isop_sfaddr = *addr;
		rp->risop_rcb.rcb_faddr = (struct sockaddr *)
			(rp->risop_isop.isop_faddr = &rp->risop_isop.isop_sfaddr);
		soisconnected(so);
		return (0);
	    }
	}
	error =  raw_usrreq(so, req, m, nam, control);

	if (error && req == PRU_ATTACH && so->so_pcb)
		FREE((caddr_t)rp, M_PCB);
	return (error);
}
