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
 *	@(#)ns_input.c	8.1 (Berkeley) 6/10/93
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kernel.h>

#include <net/if.h>
#include <net/route.h>
#include <net/raw_cb.h>

#include <netns/ns.h>
#include <netns/ns_if.h>
#include <netns/ns_pcb.h>
#include <netns/idp.h>
#include <netns/idp_var.h>
#include <netns/ns_error.h>

/*
 * NS initialization.
 */
union ns_host	ns_thishost;
union ns_host	ns_zerohost;
union ns_host	ns_broadhost;
union ns_net	ns_zeronet;
union ns_net	ns_broadnet;
struct sockaddr_ns ns_netmask, ns_hostmask;

static u_short allones[] = {-1, -1, -1};

struct nspcb nspcb;
struct nspcb nsrawpcb;

struct ifqueue	nsintrq;
int	nsqmaxlen = IFQ_MAXLEN;

int	idpcksum = 1;
long	ns_pexseq;

ns_init()
{
	extern struct timeval time;

	ns_broadhost = * (union ns_host *) allones;
	ns_broadnet = * (union ns_net *) allones;
	nspcb.nsp_next = nspcb.nsp_prev = &nspcb;
	nsrawpcb.nsp_next = nsrawpcb.nsp_prev = &nsrawpcb;
	nsintrq.ifq_maxlen = nsqmaxlen;
	ns_pexseq = time.tv_usec;
	ns_netmask.sns_len = 6;
	ns_netmask.sns_addr.x_net = ns_broadnet;
	ns_hostmask.sns_len = 12;
	ns_hostmask.sns_addr.x_net = ns_broadnet;
	ns_hostmask.sns_addr.x_host = ns_broadhost;
}

/*
 * Idp input routine.  Pass to next level.
 */
int nsintr_getpck = 0;
int nsintr_swtch = 0;
nsintr()
{
	register struct idp *idp;
	register struct mbuf *m;
	register struct nspcb *nsp;
	register int i;
	int len, s, error;
	char oddpacketp;

next:
	/*
	 * Get next datagram off input queue and get IDP header
	 * in first mbuf.
	 */
	s = splimp();
	IF_DEQUEUE(&nsintrq, m);
	splx(s);
	nsintr_getpck++;
	if (m == 0)
		return;
	if ((m->m_flags & M_EXT || m->m_len < sizeof (struct idp)) &&
	    (m = m_pullup(m, sizeof (struct idp))) == 0) {
		idpstat.idps_toosmall++;
		goto next;
	}

	/*
	 * Give any raw listeners a crack at the packet
	 */
	for (nsp = nsrawpcb.nsp_next; nsp != &nsrawpcb; nsp = nsp->nsp_next) {
		struct mbuf *m1 = m_copy(m, 0, (int)M_COPYALL);
		if (m1) idp_input(m1, nsp);
	}

	idp = mtod(m, struct idp *);
	len = ntohs(idp->idp_len);
	if (oddpacketp = len & 1) {
		len++;		/* If this packet is of odd length,
				   preserve garbage byte for checksum */
	}

	/*
	 * Check that the amount of data in the buffers
	 * is as at least much as the IDP header would have us expect.
	 * Trim mbufs if longer than we expect.
	 * Drop packet if shorter than we expect.
	 */
	if (m->m_pkthdr.len < len) {
		idpstat.idps_tooshort++;
		goto bad;
	}
	if (m->m_pkthdr.len > len) {
		if (m->m_len == m->m_pkthdr.len) {
			m->m_len = len;
			m->m_pkthdr.len = len;
		} else
			m_adj(m, len - m->m_pkthdr.len);
	}
	if (idpcksum && ((i = idp->idp_sum)!=0xffff)) {
		idp->idp_sum = 0;
		if (i != (idp->idp_sum = ns_cksum(m, len))) {
			idpstat.idps_badsum++;
			idp->idp_sum = i;
			if (ns_hosteqnh(ns_thishost, idp->idp_dna.x_host))
				error = NS_ERR_BADSUM;
			else
				error = NS_ERR_BADSUM_T;
			ns_error(m, error, 0);
			goto next;
		}
	}
	/*
	 * Is this a directed broadcast?
	 */
	if (ns_hosteqnh(ns_broadhost,idp->idp_dna.x_host)) {
		if ((!ns_neteq(idp->idp_dna, idp->idp_sna)) &&
		    (!ns_neteqnn(idp->idp_dna.x_net, ns_broadnet)) &&
		    (!ns_neteqnn(idp->idp_sna.x_net, ns_zeronet)) &&
		    (!ns_neteqnn(idp->idp_dna.x_net, ns_zeronet)) ) {
			/*
			 * Look to see if I need to eat this packet.
			 * Algorithm is to forward all young packets
			 * and prematurely age any packets which will
			 * by physically broadcasted.
			 * Any very old packets eaten without forwarding
			 * would die anyway.
			 *
			 * Suggestion of Bill Nesheim, Cornell U.
			 */
			if (idp->idp_tc < NS_MAXHOPS) {
				idp_forward(m);
				goto next;
			}
		}
	/*
	 * Is this our packet? If not, forward.
	 */
	} else if (!ns_hosteqnh(ns_thishost,idp->idp_dna.x_host)) {
		idp_forward(m);
		goto next;
	}
	/*
	 * Locate pcb for datagram.
	 */
	nsp = ns_pcblookup(&idp->idp_sna, idp->idp_dna.x_port, NS_WILDCARD);
	/*
	 * Switch out to protocol's input routine.
	 */
	nsintr_swtch++;
	if (nsp) {
		if (oddpacketp) {
			m_adj(m, -1);
		}
		if ((nsp->nsp_flags & NSP_ALL_PACKETS)==0)
			switch (idp->idp_pt) {

			    case NSPROTO_SPP:
				    spp_input(m, nsp);
				    goto next;

			    case NSPROTO_ERROR:
				    ns_err_input(m);
				    goto next;
			}
		idp_input(m, nsp);
	} else {
		ns_error(m, NS_ERR_NOSOCK, 0);
	}
	goto next;

bad:
	m_freem(m);
	goto next;
}

u_char nsctlerrmap[PRC_NCMDS] = {
	ECONNABORTED,	ECONNABORTED,	0,		0,
	0,		0,		EHOSTDOWN,	EHOSTUNREACH,
	ENETUNREACH,	EHOSTUNREACH,	ECONNREFUSED,	ECONNREFUSED,
	EMSGSIZE,	0,		0,		0,
	0,		0,		0,		0
};

int idp_donosocks = 1;

idp_ctlinput(cmd, arg)
	int cmd;
	caddr_t arg;
{
	struct ns_addr *ns;
	struct nspcb *nsp;
	struct ns_errp *errp;
	int idp_abort();
	extern struct nspcb *idp_drop();
	int type;

	if (cmd < 0 || cmd > PRC_NCMDS)
		return;
	if (nsctlerrmap[cmd] == 0)
		return;		/* XXX */
	type = NS_ERR_UNREACH_HOST;
	switch (cmd) {
		struct sockaddr_ns *sns;

	case PRC_IFDOWN:
	case PRC_HOSTDEAD:
	case PRC_HOSTUNREACH:
		sns = (struct sockaddr_ns *)arg;
		if (sns->sns_family != AF_NS)
			return;
		ns = &sns->sns_addr;
		break;

	default:
		errp = (struct ns_errp *)arg;
		ns = &errp->ns_err_idp.idp_dna;
		type = errp->ns_err_num;
		type = ntohs((u_short)type);
	}
	switch (type) {

	case NS_ERR_UNREACH_HOST:
		ns_pcbnotify(ns, (int)nsctlerrmap[cmd], idp_abort, (long)0);
		break;

	case NS_ERR_NOSOCK:
		nsp = ns_pcblookup(ns, errp->ns_err_idp.idp_sna.x_port,
			NS_WILDCARD);
		if(nsp && idp_donosocks && ! ns_nullhost(nsp->nsp_faddr))
			(void) idp_drop(nsp, (int)nsctlerrmap[cmd]);
	}
}

int	idpprintfs = 0;
int	idpforwarding = 1;
/*
 * Forward a packet.  If some error occurs return the sender
 * an error packet.  Note we can't always generate a meaningful
 * error message because the NS errors don't have a large enough repetoire
 * of codes and types.
 */
struct route idp_droute;
struct route idp_sroute;

idp_forward(m)
struct mbuf *m;
{
	register struct idp *idp = mtod(m, struct idp *);
	register int error, type, code;
	struct mbuf *mcopy = NULL;
	int agedelta = 1;
	int flags = NS_FORWARDING;
	int ok_there = 0;
	int ok_back = 0;

	if (idpprintfs) {
		printf("forward: src ");
		ns_printhost(&idp->idp_sna);
		printf(", dst ");
		ns_printhost(&idp->idp_dna);
		printf("hop count %d\n", idp->idp_tc);
	}
	if (idpforwarding == 0) {
		/* can't tell difference between net and host */
		type = NS_ERR_UNREACH_HOST, code = 0;
		goto senderror;
	}
	idp->idp_tc++;
	if (idp->idp_tc > NS_MAXHOPS) {
		type = NS_ERR_TOO_OLD, code = 0;
		goto senderror;
	}
	/*
	 * Save at most 42 bytes of the packet in case
	 * we need to generate an NS error message to the src.
	 */
	mcopy = m_copy(m, 0, imin((int)ntohs(idp->idp_len), 42));

	if ((ok_there = idp_do_route(&idp->idp_dna,&idp_droute))==0) {
		type = NS_ERR_UNREACH_HOST, code = 0;
		goto senderror;
	}
	/*
	 * Here we think about  forwarding  broadcast packets,
	 * so we try to insure that it doesn't go back out
	 * on the interface it came in on.  Also, if we
	 * are going to physically broadcast this, let us
	 * age the packet so we can eat it safely the second time around.
	 */
	if (idp->idp_dna.x_host.c_host[0] & 0x1) {
		struct ns_ifaddr *ia = ns_iaonnetof(&idp->idp_dna);
		struct ifnet *ifp;
		if (ia) {
			/* I'm gonna hafta eat this packet */
			agedelta += NS_MAXHOPS - idp->idp_tc;
			idp->idp_tc = NS_MAXHOPS;
		}
		if ((ok_back = idp_do_route(&idp->idp_sna,&idp_sroute))==0) {
			/* error = ENETUNREACH; He'll never get it! */
			m_freem(m);
			goto cleanup;
		}
		if (idp_droute.ro_rt &&
		    (ifp=idp_droute.ro_rt->rt_ifp) &&
		    idp_sroute.ro_rt &&
		    (ifp!=idp_sroute.ro_rt->rt_ifp)) {
			flags |= NS_ALLOWBROADCAST;
		} else {
			type = NS_ERR_UNREACH_HOST, code = 0;
			goto senderror;
		}
	}
	/* need to adjust checksum */
	if (idp->idp_sum!=0xffff) {
		union bytes {
			u_char c[4];
			u_short s[2];
			long l;
		} x;
		register int shift;
		x.l = 0; x.c[0] = agedelta;
		shift = (((((int)ntohs(idp->idp_len))+1)>>1)-2) & 0xf;
		x.l = idp->idp_sum + (x.s[0] << shift);
		x.l = x.s[0] + x.s[1];
		x.l = x.s[0] + x.s[1];
		if (x.l==0xffff) idp->idp_sum = 0; else idp->idp_sum = x.l;
	}
	if ((error = ns_output(m, &idp_droute, flags)) && 
	    (mcopy!=NULL)) {
		idp = mtod(mcopy, struct idp *);
		type = NS_ERR_UNSPEC_T, code = 0;
		switch (error) {

		case ENETUNREACH:
		case EHOSTDOWN:
		case EHOSTUNREACH:
		case ENETDOWN:
		case EPERM:
			type = NS_ERR_UNREACH_HOST;
			break;

		case EMSGSIZE:
			type = NS_ERR_TOO_BIG;
			code = 576; /* too hard to figure out mtu here */
			break;

		case ENOBUFS:
			type = NS_ERR_UNSPEC_T;
			break;
		}
		mcopy = NULL;
	senderror:
		ns_error(m, type, code);
	}
cleanup:
	if (ok_there)
		idp_undo_route(&idp_droute);
	if (ok_back)
		idp_undo_route(&idp_sroute);
	if (mcopy != NULL)
		m_freem(mcopy);
}

idp_do_route(src, ro)
struct ns_addr *src;
struct route *ro;
{
	
	struct sockaddr_ns *dst;

	bzero((caddr_t)ro, sizeof (*ro));
	dst = (struct sockaddr_ns *)&ro->ro_dst;

	dst->sns_len = sizeof(*dst);
	dst->sns_family = AF_NS;
	dst->sns_addr = *src;
	dst->sns_addr.x_port = 0;
	rtalloc(ro);
	if (ro->ro_rt == 0 || ro->ro_rt->rt_ifp == 0) {
		return (0);
	}
	ro->ro_rt->rt_use++;
	return (1);
}

idp_undo_route(ro)
register struct route *ro;
{
	if (ro->ro_rt) {RTFREE(ro->ro_rt);}
}

ns_watch_output(m, ifp)
struct mbuf *m;
struct ifnet *ifp;
{
	register struct nspcb *nsp;
	register struct ifaddr *ifa;
	/*
	 * Give any raw listeners a crack at the packet
	 */
	for (nsp = nsrawpcb.nsp_next; nsp != &nsrawpcb; nsp = nsp->nsp_next) {
		struct mbuf *m0 = m_copy(m, 0, (int)M_COPYALL);
		if (m0) {
			register struct idp *idp;

			M_PREPEND(m0, sizeof (*idp), M_DONTWAIT);
			if (m0 == NULL)
				continue;
			idp = mtod(m0, struct idp *);
			idp->idp_sna.x_net = ns_zeronet;
			idp->idp_sna.x_host = ns_thishost;
			if (ifp && (ifp->if_flags & IFF_POINTOPOINT))
			    for(ifa = ifp->if_addrlist; ifa;
						ifa = ifa->ifa_next) {
				if (ifa->ifa_addr->sa_family==AF_NS) {
				    idp->idp_sna = IA_SNS(ifa)->sns_addr;
				    break;
				}
			    }
			idp->idp_len = ntohl(m0->m_pkthdr.len);
			idp_input(m0, nsp);
		}
	}
}
