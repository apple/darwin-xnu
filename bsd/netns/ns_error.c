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
 * Copyright (c) 1984, 1988, 1993
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
 *	@(#)ns_error.c	8.1 (Berkeley) 6/10/93
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/kernel.h>

#include <net/route.h>

#include <netns/ns.h>
#include <netns/ns_pcb.h>
#include <netns/idp.h>
#include <netns/ns_error.h>

#ifdef lint
#define NS_ERRPRINTFS 1
#endif

#ifdef NS_ERRPRINTFS
/*
 * NS_ERR routines: error generation, receive packet processing, and
 * routines to turnaround packets back to the originator.
 */
int	ns_errprintfs = 0;
#endif

ns_err_x(c)
{
	register u_short *w, *lim, *base = ns_errstat.ns_es_codes;
	u_short x = c;

	/*
	 * zero is a legit error code, handle specially
	 */
	if (x == 0)
		return (0);
	lim = base + NS_ERR_MAX - 1;
	for (w = base + 1; w < lim; w++) {
		if (*w == 0)
			*w = x;
		if (*w == x)
			break;
	}
	return (w - base);
}

/*
 * Generate an error packet of type error
 * in response to bad packet.
 */

ns_error(om, type, param)
	struct mbuf *om;
	int type;
{
	register struct ns_epidp *ep;
	struct mbuf *m;
	struct idp *nip;
	register struct idp *oip = mtod(om, struct idp *);
	extern int idpcksum;

	/*
	 * If this packet was sent to the echo port,
	 * and nobody was there, just echo it.
	 * (Yes, this is a wart!)
	 */
	if (type == NS_ERR_NOSOCK &&
	    oip->idp_dna.x_port == htons(2) &&
	    (type = ns_echo(om))==0)
		return;

#ifdef NS_ERRPRINTFS
	if (ns_errprintfs)
		printf("ns_err_error(%x, %d, %d)\n", oip, type, param);
#endif
	/*
	 * Don't Generate error packets in response to multicasts.
	 */
	if (oip->idp_dna.x_host.c_host[0] & 1)
		goto freeit;

	ns_errstat.ns_es_error++;
	/*
	 * Make sure that the old IDP packet had 30 bytes of data to return;
	 * if not, don't bother.  Also don't EVER error if the old
	 * packet protocol was NS_ERR.
	 */
	if (oip->idp_len < sizeof(struct idp)) {
		ns_errstat.ns_es_oldshort++;
		goto freeit;
	}
	if (oip->idp_pt == NSPROTO_ERROR) {
		ns_errstat.ns_es_oldns_err++;
		goto freeit;
	}

	/*
	 * First, formulate ns_err message
	 */
	m = m_gethdr(M_DONTWAIT, MT_HEADER);
	if (m == NULL)
		goto freeit;
	m->m_len = sizeof(*ep);
	MH_ALIGN(m, m->m_len);
	ep = mtod(m, struct ns_epidp *);
	if ((u_int)type > NS_ERR_TOO_BIG)
		panic("ns_err_error");
	ns_errstat.ns_es_outhist[ns_err_x(type)]++;
	ep->ns_ep_errp.ns_err_num = htons((u_short)type);
	ep->ns_ep_errp.ns_err_param = htons((u_short)param);
	bcopy((caddr_t)oip, (caddr_t)&ep->ns_ep_errp.ns_err_idp, 42);
	nip = &ep->ns_ep_idp;
	nip->idp_len = sizeof(*ep);
	nip->idp_len = htons((u_short)nip->idp_len);
	nip->idp_pt = NSPROTO_ERROR;
	nip->idp_tc = 0;
	nip->idp_dna = oip->idp_sna;
	nip->idp_sna = oip->idp_dna;
	if (idpcksum) {
		nip->idp_sum = 0;
		nip->idp_sum = ns_cksum(m, sizeof(*ep));
	} else 
		nip->idp_sum = 0xffff;
	(void) ns_output(m, (struct route *)0, 0);

freeit:
	m_freem(om);
}

ns_printhost(p)
register struct ns_addr *p;
{

	printf("<net:%x%x,host:%x%x%x,port:%x>",
			p->x_net.s_net[0],
			p->x_net.s_net[1],
			p->x_host.s_host[0],
			p->x_host.s_host[1],
			p->x_host.s_host[2],
			p->x_port);

}

/*
 * Process a received NS_ERR message.
 */
ns_err_input(m)
	struct mbuf *m;
{
	register struct ns_errp *ep;
	register struct ns_epidp *epidp = mtod(m, struct ns_epidp *);
	register int i;
	int type, code, param;

	/*
	 * Locate ns_err structure in mbuf, and check
	 * that not corrupted and of at least minimum length.
	 */
#ifdef NS_ERRPRINTFS
	if (ns_errprintfs) {
		printf("ns_err_input from ");
		ns_printhost(&epidp->ns_ep_idp.idp_sna);
		printf("len %d\n", ntohs(epidp->ns_ep_idp.idp_len));
	}
#endif
	i = sizeof (struct ns_epidp);
 	if (((m->m_flags & M_EXT) || m->m_len < i) &&
 		(m = m_pullup(m, i)) == 0)  {
		ns_errstat.ns_es_tooshort++;
		return;
	}
	ep = &(mtod(m, struct ns_epidp *)->ns_ep_errp);
	type = ntohs(ep->ns_err_num);
	param = ntohs(ep->ns_err_param);
	ns_errstat.ns_es_inhist[ns_err_x(type)]++;

#ifdef NS_ERRPRINTFS
	/*
	 * Message type specific processing.
	 */
	if (ns_errprintfs)
		printf("ns_err_input, type %d param %d\n", type, param);
#endif
	if (type >= NS_ERR_TOO_BIG) {
		goto badcode;
	}
	ns_errstat.ns_es_outhist[ns_err_x(type)]++;
	switch (type) {

	case NS_ERR_UNREACH_HOST:
		code = PRC_UNREACH_NET;
		goto deliver;

	case NS_ERR_TOO_OLD:
		code = PRC_TIMXCEED_INTRANS;
		goto deliver;

	case NS_ERR_TOO_BIG:
		code = PRC_MSGSIZE;
		goto deliver;

	case NS_ERR_FULLUP:
		code = PRC_QUENCH;
		goto deliver;

	case NS_ERR_NOSOCK:
		code = PRC_UNREACH_PORT;
		goto deliver;

	case NS_ERR_UNSPEC_T:
	case NS_ERR_BADSUM_T:
	case NS_ERR_BADSUM:
	case NS_ERR_UNSPEC:
		code = PRC_PARAMPROB;
		goto deliver;

	deliver:
		/*
		 * Problem with datagram; advise higher level routines.
		 */
#ifdef NS_ERRPRINTFS
		if (ns_errprintfs)
			printf("deliver to protocol %d\n",
				       ep->ns_err_idp.idp_pt);
#endif
		switch(ep->ns_err_idp.idp_pt) {
		case NSPROTO_SPP:
			spp_ctlinput(code, (caddr_t)ep);
			break;

		default:
			idp_ctlinput(code, (caddr_t)ep);
		}
		
		goto freeit;

	default:
	badcode:
		ns_errstat.ns_es_badcode++;
		goto freeit;

	}
freeit:
	m_freem(m);
}

#ifdef notdef
u_long
nstime()
{
	int s = splclock();
	u_long t;

	t = (time.tv_sec % (24*60*60)) * 1000 + time.tv_usec / 1000;
	splx(s);
	return (htonl(t));
}
#endif

ns_echo(m)
struct mbuf *m;
{
	register struct idp *idp = mtod(m, struct idp *);
	register struct echo {
	    struct idp	ec_idp;
	    u_short		ec_op; /* Operation, 1 = request, 2 = reply */
	} *ec = (struct echo *)idp;
	struct ns_addr temp;

	if (idp->idp_pt!=NSPROTO_ECHO) return(NS_ERR_NOSOCK);
	if (ec->ec_op!=htons(1)) return(NS_ERR_UNSPEC);

	ec->ec_op = htons(2);

	temp = idp->idp_dna;
	idp->idp_dna = idp->idp_sna;
	idp->idp_sna = temp;

	if (idp->idp_sum != 0xffff) {
		idp->idp_sum = 0;
		idp->idp_sum = ns_cksum(m,
		    (int)(((ntohs(idp->idp_len) - 1)|1)+1));
	}
	(void) ns_output(m, (struct route *)0, NS_FORWARDING);
	return(0);
}
