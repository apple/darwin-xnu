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
 * Copyright (c) 1990, 1993
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
 *	@(#)if_x25subr.c	8.1 (Berkeley) 6/10/93
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <sys/syslog.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/netisr.h>
#include <net/route.h>

#include <netccitt/x25.h>
#include <netccitt/x25err.h>
#include <netccitt/pk.h>
#include <netccitt/pk_var.h>

#if INET
#include <netinet/in.h>
#include <netinet/in_var.h>
#endif

#if NS
#include <netns/ns.h>
#include <netns/ns_if.h>
#endif

#if ISO
int tp_incoming();
#include <netiso/argo_debug.h>
#include <netiso/iso.h>
#include <netiso/iso_var.h>
#endif

extern	struct ifnet loif;
struct llinfo_x25 llinfo_x25 = {&llinfo_x25, &llinfo_x25};
#ifndef _offsetof
#define _offsetof(t, m) ((int)((caddr_t)&((t *)0)->m))
#endif
struct sockaddr *x25_dgram_sockmask;
struct sockaddr_x25 x25_dgmask = {
 _offsetof(struct sockaddr_x25, x25_udata[1]),			/* _len */
 0,								/* _family */
 0,								/* _net */
 { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1}, /* _addr */
 {0},								/* opts */
 -1,								/* _udlen */
 {-1}								/* _udata */
};
 
struct if_x25stats {
	int	ifx_wrongplen;
	int	ifx_nophdr;
} if_x25stats;
int x25_autoconnect = 0;

#define senderr(x) {error = x; goto bad;}
/*
 * Ancillary routines
 */
static struct llinfo_x25 *
x25_lxalloc(rt)
register struct rtentry *rt;
{
	register struct llinfo_x25 *lx;
	register struct sockaddr *dst = rt_key(rt);
	register struct ifaddr *ifa;

	MALLOC(lx, struct llinfo_x25 *, sizeof (*lx), M_PCB, M_NOWAIT);
	if (lx == 0)
		return lx;
	Bzero(lx, sizeof(*lx));
	lx->lx_rt = rt;
	lx->lx_family = dst->sa_family;
	RTHOLD(rt);
	if (rt->rt_llinfo)
		insque(lx, (struct llinfo_x25 *)rt->rt_llinfo);
	else {
		rt->rt_llinfo = (caddr_t)lx;
		insque(lx, &llinfo_x25);
	}
	for (ifa = rt->rt_ifp->if_addrlist; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family == AF_CCITT)
			lx->lx_ia = (struct x25_ifaddr *)ifa;
	}
	return lx;
}
x25_lxfree(lx)
register struct llinfo_x25 *lx;
{
	register struct rtentry *rt = lx->lx_rt;
	register struct pklcd *lcp = lx->lx_lcd;

	if (lcp) {
		lcp->lcd_upper = 0;
		pk_disconnect(lcp);
	}
	if ((rt->rt_llinfo == (caddr_t)lx) && (lx->lx_next->lx_rt == rt))
		rt->rt_llinfo = (caddr_t)lx->lx_next;
	else
		rt->rt_llinfo = 0;
	RTFREE(rt);
	remque(lx);
	FREE(lx, M_PCB);
}
/*
 * Process a x25 packet as datagram;
 */
x25_ifinput(lcp, m)
struct pklcd *lcp;
register struct mbuf *m;
{
	struct llinfo_x25 *lx = (struct llinfo_x25 *)lcp->lcd_upnext;
	register struct ifnet *ifp;
	struct ifqueue *inq;
	extern struct timeval time;
	int s, len, isr;
 
	if (m == 0 || lcp->lcd_state != DATA_TRANSFER) {
		x25_connect_callback(lcp, 0);
		return;
	}
	pk_flowcontrol(lcp, 0, 1); /* Generate RR */
	ifp = m->m_pkthdr.rcvif;
	ifp->if_lastchange = time;
	switch (m->m_type) {
	default:
		if (m)
			m_freem(m);
		return;

	case MT_DATA:
		/* FALLTHROUGH */;
	}
	switch (lx->lx_family) {
#if INET
	case AF_INET:
		isr = NETISR_IP;
		inq = &ipintrq;
		break;

#endif
#if NS
	case AF_NS:
		isr = NETISR_NS;
		inq = &nsintrq;
		break;

#endif
#if	ISO
	case AF_ISO:
		isr = NETISR_ISO;
		inq = &clnlintrq;
		break;
#endif
	default:
		m_freem(m);
		ifp->if_noproto++;
		return;
	}
	s = splimp();
	schednetisr(isr);
	if (IF_QFULL(inq)) {
		IF_DROP(inq);
		m_freem(m);
	} else {
		IF_ENQUEUE(inq, m);
		ifp->if_ibytes += m->m_pkthdr.len;
	}
	splx(s);
}
x25_connect_callback(lcp, m)
register struct pklcd *lcp;
register struct mbuf *m;
{
	register struct llinfo_x25 *lx = (struct llinfo_x25 *)lcp->lcd_upnext;
	int do_clear = 1;
	if (m == 0)
		goto refused;
	if (m->m_type != MT_CONTROL) {
		printf("x25_connect_callback: should panic\n");
		goto refused;
	}
	switch (pk_decode(mtod(m, struct x25_packet *))) {
	case CALL_ACCEPTED:
		lcp->lcd_upper = x25_ifinput;
		if (lcp->lcd_sb.sb_mb)
			lcp->lcd_send(lcp); /* XXX start queued packets */
		return;
	default:
		do_clear = 0;
	refused:
		lcp->lcd_upper = 0;
		lx->lx_lcd = 0;
		if (do_clear)
			pk_disconnect(lcp);
		return;
	}
}
#define SA(p) ((struct sockaddr *)(p))
#define RT(p) ((struct rtentry *)(p))

x25_dgram_incoming(lcp, m0)
register struct pklcd *lcp;
struct mbuf *m0;
{
	register struct rtentry *rt, *nrt;
	register struct mbuf *m = m0->m_next; /* m0 has calling sockaddr_x25 */
	void x25_rtrequest();

	rt = rtalloc1(SA(&lcp->lcd_faddr), 0);
	if (rt == 0) {
refuse: 	lcp->lcd_upper = 0;
		pk_close(lcp);
		return;
	}
	rt->rt_refcnt--;
	if ((nrt = RT(rt->rt_llinfo)) == 0 || rt_mask(rt) != x25_dgram_sockmask)
		goto refuse;
	if ((nrt->rt_flags & RTF_UP) == 0) {
		rt->rt_llinfo = (caddr_t)rtalloc1(rt->rt_gateway, 0);
		rtfree(nrt);
		if ((nrt = RT(rt->rt_llinfo)) == 0)
			goto refuse;
		nrt->rt_refcnt--;
	}
	if (nrt->rt_ifa == 0 || nrt->rt_ifa->ifa_rtrequest != x25_rtrequest)
		goto refuse;
	lcp->lcd_send(lcp); /* confirm call */
	x25_rtattach(lcp, nrt);
	m_freem(m);
}

/*
 * X.25 output routine.
 */
x25_ifoutput(ifp, m0, dst, rt)
struct	ifnet *ifp;
struct	mbuf *m0;
struct	sockaddr *dst;
register struct	rtentry *rt;
{
	register struct	mbuf *m = m0;
	register struct	llinfo_x25 *lx;
	struct pklcd *lcp;
	int             s, error = 0;

int plen;
for (plen = 0; m; m = m->m_next)
	plen += m->m_len;
m = m0;

	if ((ifp->if_flags & IFF_UP) == 0)
		senderr(ENETDOWN);
	while (rt == 0 || (rt->rt_flags & RTF_GATEWAY)) {
		if (rt) {
			if (rt->rt_llinfo) {
				rt = (struct rtentry *)rt->rt_llinfo;
				continue;
			}
			dst = rt->rt_gateway;
		}
		if ((rt = rtalloc1(dst, 1)) == 0)
			senderr(EHOSTUNREACH);
		rt->rt_refcnt--;
	}
	/*
	 * Sanity checks.
	 */
	if ((rt->rt_ifp != ifp) ||
	    (rt->rt_flags & (RTF_CLONING | RTF_GATEWAY)) ||
	    ((lx = (struct llinfo_x25 *)rt->rt_llinfo) == 0)) {
		senderr(ENETUNREACH);
	}
if ((m->m_flags & M_PKTHDR) == 0) {
	if_x25stats.ifx_nophdr++;
	m = m_gethdr(M_NOWAIT, MT_HEADER);
	if (m == 0)
		senderr(ENOBUFS);
	m->m_pkthdr.len = plen;
	m->m_next = m0;
}
if (plen != m->m_pkthdr.len) {
	if_x25stats.ifx_wrongplen++;
	m->m_pkthdr.len = plen;
}
next_circuit:
	lcp = lx->lx_lcd;
	if (lcp == 0) {
		lx->lx_lcd = lcp = pk_attach((struct socket *)0);
		if (lcp == 0)
			senderr(ENOBUFS);
		lcp->lcd_upper = x25_connect_callback;
		lcp->lcd_upnext = (caddr_t)lx;
		lcp->lcd_packetsize = lx->lx_ia->ia_xc.xc_psize;
		lcp->lcd_flags = X25_MBS_HOLD;
	}
	switch (lcp->lcd_state) {
	case READY:
		if (dst->sa_family == AF_INET &&
		    ifp->if_type == IFT_X25DDN &&
		    rt->rt_gateway->sa_family != AF_CCITT)
			x25_ddnip_to_ccitt(dst, rt);
		if (rt->rt_gateway->sa_family != AF_CCITT) {
			if ((rt->rt_flags & RTF_XRESOLVE) == 0)
				senderr(EHOSTUNREACH);
		} else if (x25_autoconnect)
			error = pk_connect(lcp,
					(struct sockaddr_x25 *)rt->rt_gateway);
		if (error)
			senderr(error);
		/* FALLTHROUGH */
	case SENT_CALL:
	case DATA_TRANSFER:
		if (sbspace(&lcp->lcd_sb) < 0) {
			lx = lx->lx_next;
			if (lx->lx_rt != rt)
				senderr(ENOSPC);
			goto next_circuit;
		}
		if (lx->lx_ia)
			lcp->lcd_dg_timer =
				       lx->lx_ia->ia_xc.xc_dg_idletimo;
		pk_send(lcp, m);
		break;
	default:
		/*
		 * We count on the timer routine to close idle
		 * connections, if there are not enough circuits to go
		 * around.
		 *
		 * So throw away data for now.
		 * After we get it all working, we'll rewrite to handle
		 * actively closing connections (other than by timers),
		 * when circuits get tight.
		 *
		 * In the DDN case, the imp itself closes connections
		 * under heavy load.
		 */
		error = ENOBUFS;
	bad:
		if (m)
			m_freem(m);
	}
	return (error);
}

/*
 * Simpleminded timer routine.
 */
x25_iftimeout(ifp)
struct ifnet *ifp;
{
	register struct pkcb *pkcb = 0;
	register struct pklcd **lcpp, *lcp;
	int s = splimp();

	FOR_ALL_PKCBS(pkcb)
	    if (pkcb->pk_ia->ia_ifp == ifp)
		for (lcpp = pkcb->pk_chan + pkcb->pk_maxlcn;
		     --lcpp > pkcb->pk_chan;)
			if ((lcp = *lcpp) &&
			    lcp->lcd_state == DATA_TRANSFER &&
			    (lcp->lcd_flags & X25_DG_CIRCUIT) &&
			    (lcp->lcd_dg_timer && --lcp->lcd_dg_timer == 0)) {
				lcp->lcd_upper(lcp, 0);
			}
	splx(s);
}
/*
 * This routine gets called when validating additions of new routes
 * or deletions of old ones.
 */
x25_rtrequest(cmd, rt, dst)
register struct rtentry *rt;
struct sockaddr *dst;
{
	register struct llinfo_x25 *lx = (struct llinfo_x25 *)rt->rt_llinfo;
	register struct sockaddr_x25 *sa =(struct sockaddr_x25 *)rt->rt_gateway;
	register struct pklcd *lcp;

	/* would put this pk_init, except routing table doesn't
	   exist yet. */
	if (x25_dgram_sockmask == 0) {
		struct radix_node *rn_addmask();
		x25_dgram_sockmask =
			SA(rn_addmask((caddr_t)&x25_dgmask, 0, 4)->rn_key);
	}
	if (rt->rt_flags & RTF_GATEWAY) {
		if (rt->rt_llinfo)
			RTFREE((struct rtentry *)rt->rt_llinfo);
		rt->rt_llinfo = (cmd == RTM_ADD) ? 
			(caddr_t)rtalloc1(rt->rt_gateway, 1) : 0;
		return;
	}
	if ((rt->rt_flags & RTF_HOST) == 0)
		return;
	if (cmd == RTM_DELETE) {
		while (rt->rt_llinfo)
			x25_lxfree((struct llinfo *)rt->rt_llinfo);
		x25_rtinvert(RTM_DELETE, rt->rt_gateway, rt);
		return;
	}
	if (lx == 0 && (lx = x25_lxalloc(rt)) == 0)
		return;
	if ((lcp = lx->lx_lcd) && lcp->lcd_state != READY) {
		/*
		 * This can only happen on a RTM_CHANGE operation
		 * though cmd will be RTM_ADD.
		 */
		if (lcp->lcd_ceaddr &&
		    Bcmp(rt->rt_gateway, lcp->lcd_ceaddr,
					 lcp->lcd_ceaddr->x25_len) != 0) {
			x25_rtinvert(RTM_DELETE, lcp->lcd_ceaddr, rt);
			lcp->lcd_upper = 0;
			pk_disconnect(lcp);
		}
		lcp = 0;
	}
	x25_rtinvert(RTM_ADD, rt->rt_gateway, rt);
}

int x25_dont_rtinvert = 0;

x25_rtinvert(cmd, sa, rt)
register struct sockaddr *sa;
register struct rtentry *rt;
{
	struct rtentry *rt2 = 0;
	/*
	 * rt_gateway contains PID indicating which proto
	 * family on the other end, so will be different
	 * from general host route via X.25.
	 */
	if (rt->rt_ifp->if_type == IFT_X25DDN || x25_dont_rtinvert)
		return;
	if (sa->sa_family != AF_CCITT)
		return;
	if (cmd != RTM_DELETE) {
		rtrequest(RTM_ADD, sa, rt_key(rt), x25_dgram_sockmask,
				RTF_PROTO2, &rt2);
		if (rt2) {
			rt2->rt_llinfo = (caddr_t) rt;
			RTHOLD(rt);
		}
		return;
	}
	rt2 = rt;
	if ((rt = rtalloc1(sa, 0)) == 0 ||
	    (rt->rt_flags & RTF_PROTO2) == 0 ||
	    rt->rt_llinfo != (caddr_t)rt2) {
		printf("x25_rtchange: inverse route foulup\n");
		return;
	} else
		rt2->rt_refcnt--;
	rtrequest(RTM_DELETE, sa, rt_key(rt2), x25_dgram_sockmask,
				0, (struct rtentry **) 0);
}

static struct sockaddr_x25 blank_x25 = {sizeof blank_x25, AF_CCITT};
/*
 * IP to X25 address routine copyright ACC, used by permission.
 */
union imp_addr {
	struct in_addr  ip;
	struct imp {
		u_char		s_net;
		u_char		s_host;
		u_char		s_lh;
		u_char		s_impno;
	}		    imp;
};

/*
 * The following is totally bogus and here only to preserve
 * the IP to X.25 translation.
 */
x25_ddnip_to_ccitt(src, rt)
struct sockaddr_in *src;
register struct rtentry *rt;
{
	register struct sockaddr_x25 *dst = (struct sockaddr_x25 *)rt->rt_gateway;
	union imp_addr imp_addr;
	int             imp_no, imp_port, temp;
	char *x25addr = dst->x25_addr;


	imp_addr.ip = src->sin_addr;
	*dst = blank_x25;
	if ((imp_addr.imp.s_net & 0x80) == 0x00) {	/* class A */
	    imp_no = imp_addr.imp.s_impno;
	    imp_port = imp_addr.imp.s_host;
	} else if ((imp_addr.imp.s_net & 0xc0) == 0x80) {	/* class B */
	    imp_no = imp_addr.imp.s_impno;
	    imp_port = imp_addr.imp.s_lh;
	} else {		/* class C */
	    imp_no = imp_addr.imp.s_impno / 32;
	    imp_port = imp_addr.imp.s_impno % 32;
	}

	x25addr[0] = 12; /* length */
	/* DNIC is cleared by struct copy above */

	if (imp_port < 64) {	/* Physical:  0000 0 IIIHH00 [SS] *//* s_impno
				 *  -> III, s_host -> HH */
	    x25addr[5] = 0;	/* set flag bit */
	    x25addr[6] = imp_no / 100;
	    x25addr[7] = (imp_no % 100) / 10;
	    x25addr[8] = imp_no % 10;
	    x25addr[9] = imp_port / 10;
	    x25addr[10] = imp_port % 10;
	} else {		/* Logical:   0000 1 RRRRR00 [SS]	 *//* s
				 * _host * 256 + s_impno -> RRRRR */
	    temp = (imp_port << 8) + imp_no;
	    x25addr[5] = 1;
	    x25addr[6] = temp / 10000;
	    x25addr[7] = (temp % 10000) / 1000;
	    x25addr[8] = (temp % 1000) / 100;
	    x25addr[9] = (temp % 100) / 10;
	    x25addr[10] = temp % 10;
	}
}

/*
 * This routine is a sketch and is not to be believed!!!!!
 *
 * This is a utility routine to be called by x25 devices when a
 * call request is honored with the intent of starting datagram forwarding.
 */
x25_dg_rtinit(dst, ia, af)
struct sockaddr_x25 *dst;
register struct x25_ifaddr *ia;
{
	struct sockaddr *sa = 0;
	struct rtentry *rt;
	struct in_addr my_addr;
	static struct sockaddr_in sin = {sizeof(sin), AF_INET};

	if (ia->ia_ifp->if_type == IFT_X25DDN && af == AF_INET) {
	/*
	 * Inverse X25 to IP mapping copyright and courtesy ACC.
	 */
		int             imp_no, imp_port, temp;
		union imp_addr imp_addr;
	    {
		/*
		 * First determine our IP addr for network
		 */
		register struct in_ifaddr *ina;
		extern struct in_ifaddr *in_ifaddr;

		for (ina = in_ifaddr; ina; ina = ina->ia_next)
			if (ina->ia_ifp == ia->ia_ifp) {
				my_addr = ina->ia_addr.sin_addr;
				break;
			}
	    }
	    {

		register char *x25addr = dst->x25_addr;

		switch (x25addr[5] & 0x0f) {
		  case 0:	/* Physical:  0000 0 IIIHH00 [SS]	 */
		    imp_no =
			((int) (x25addr[6] & 0x0f) * 100) +
			((int) (x25addr[7] & 0x0f) * 10) +
			((int) (x25addr[8] & 0x0f));


		    imp_port =
			((int) (x25addr[9] & 0x0f) * 10) +
			((int) (x25addr[10] & 0x0f));
		    break;
		  case 1:	/* Logical:   0000 1 RRRRR00 [SS]	 */
		    temp = ((int) (x25addr[6] & 0x0f) * 10000)
			+ ((int) (x25addr[7] & 0x0f) * 1000)
			+ ((int) (x25addr[8] & 0x0f) * 100)
			+ ((int) (x25addr[9] & 0x0f) * 10)
			+ ((int) (x25addr[10] & 0x0f));

		    imp_port = temp >> 8;
		    imp_no = temp & 0xff;
		    break;
		  default:
		    return (0L);
		}
		imp_addr.ip = my_addr;
		if ((imp_addr.imp.s_net & 0x80) == 0x00) {
		/* class A */
		    imp_addr.imp.s_host = imp_port;
		    imp_addr.imp.s_impno = imp_no;
		    imp_addr.imp.s_lh = 0;
		} else if ((imp_addr.imp.s_net & 0xc0) == 0x80) {
		/* class B */
		    imp_addr.imp.s_lh = imp_port;
		    imp_addr.imp.s_impno = imp_no;
		} else {
		/* class C */
		    imp_addr.imp.s_impno = (imp_no << 5) + imp_port;
		}
	    }
		sin.sin_addr = imp_addr.ip;
		sa = (struct sockaddr *)&sin;
	} else {
		/*
		 * This uses the X25 routing table to do inverse
		 * lookup of x25 address to sockaddr.
		 */
		if (rt = rtalloc1(SA(dst), 0)) {
			sa = rt->rt_gateway;
			rt->rt_refcnt--;
		}
	}
	/* 
	 * Call to rtalloc1 will create rtentry for reverse path
	 * to callee by virtue of cloning magic and will allocate
	 * space for local control block.
	 */
	if (sa && (rt = rtalloc1(sa, 1)))
		rt->rt_refcnt--;
}
int x25_startproto = 1;

pk_init()
{
	/*
	 * warning, sizeof (struct sockaddr_x25) > 32,
	 * but contains no data of interest beyond 32
	 */
	if (x25_startproto) {
		pk_protolisten(0xcc, 1, x25_dgram_incoming);
		pk_protolisten(0x81, 1, x25_dgram_incoming);
	}
}

struct x25_dgproto {
	u_char spi;
	u_char spilen;
	int (*f)();
} x25_dgprototab[] = {
#if (ISO) && (TPCONS)
{ 0x0, 0, tp_incoming},
#endif
{ 0xcc, 1, x25_dgram_incoming},
{ 0xcd, 1, x25_dgram_incoming},
{ 0x81, 1, x25_dgram_incoming},
};

pk_user_protolisten(info)
register u_char *info;
{
	register struct x25_dgproto *dp = x25_dgprototab
		    + ((sizeof x25_dgprototab) / (sizeof *dp));
	register struct pklcd *lcp;
	
	while (dp > x25_dgprototab)
		if ((--dp)->spi == info[0])
			goto gotspi;
	return ESRCH;

gotspi:	if (info[1])
		return pk_protolisten(dp->spi, dp->spilen, dp->f);
	for (lcp = pk_listenhead; lcp; lcp = lcp->lcd_listen)
		if (lcp->lcd_laddr.x25_udlen == dp->spilen &&
		    Bcmp(&dp->spi, lcp->lcd_laddr.x25_udata, dp->spilen) == 0) {
			pk_disconnect(lcp);
			return 0;
		}
	return ESRCH;
}

/*
 * This routine transfers an X.25 circuit to or from a routing entry.
 * If the supplied circuit is * in DATA_TRANSFER state, it is added to the
 * routing entry.  If freshly allocated, it glues back the vc from
 * the rtentry to the socket.
 */
pk_rtattach(so, m0)
register struct socket *so;
struct mbuf *m0;
{
	register struct pklcd *lcp = (struct pklcd *)so->so_pcb;
	register struct mbuf *m = m0;
	struct sockaddr *dst = mtod(m, struct sockaddr *);
	register struct rtentry *rt = rtalloc1(dst, 0);
	register struct llinfo_x25 *lx;
	caddr_t cp;
#define ROUNDUP(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#define transfer_sockbuf(s, f, l) \
	while (m = (s)->sb_mb)\
		{(s)->sb_mb = m->m_act; m->m_act = 0; sbfree((s), m); f(l, m);}

	if (rt)
		rt->rt_refcnt--;
	cp = (dst->sa_len < m->m_len) ? ROUNDUP(dst->sa_len) + (caddr_t)dst : 0;
	while (rt &&
	       ((cp == 0 && rt_mask(rt) != 0) ||
		(cp != 0 && (rt_mask(rt) == 0 ||
			     Bcmp(cp, rt_mask(rt), rt_mask(rt)->sa_len)) != 0)))
			rt = (struct rtentry *)rt->rt_nodes->rn_dupedkey;
	if (rt == 0 || (rt->rt_flags & RTF_GATEWAY) ||
	    (lx = (struct llinfo_x25 *)rt->rt_llinfo) == 0)
		return ESRCH;
	if (lcp == 0)
		return ENOTCONN;
	switch (lcp->lcd_state) {
	default:
		return ENOTCONN;

	case READY:
		/* Detach VC from rtentry */
		if (lx->lx_lcd == 0)
			return ENOTCONN;
		lcp->lcd_so = 0;
		pk_close(lcp);
		lcp = lx->lx_lcd;
		if (lx->lx_next->lx_rt == rt)
			x25_lxfree(lx);
		lcp->lcd_so = so;
		lcp->lcd_upper = 0;
		lcp->lcd_upnext = 0;
		transfer_sockbuf(&lcp->lcd_sb, sbappendrecord, &so->so_snd);
		soisconnected(so);
		return 0;

	case DATA_TRANSFER:
		/* Add VC to rtentry */
		lcp->lcd_so = 0;
		lcp->lcd_sb = so->so_snd; /* structure copy */
		bzero((caddr_t)&so->so_snd, sizeof(so->so_snd)); /* XXXXXX */
		so->so_pcb = 0;
		x25_rtattach(lcp, rt);
		transfer_sockbuf(&so->so_rcv, x25_ifinput, lcp);
		soisdisconnected(so);
	}
	return 0;
}
x25_rtattach(lcp0, rt)
register struct pklcd *lcp0;
struct rtentry *rt;
{
	register struct llinfo_x25 *lx = (struct llinfo_x25 *)rt->rt_llinfo;
	register struct pklcd *lcp;
	register struct mbuf *m;
	if (lcp = lx->lx_lcd) { /* adding an additional VC */
		if (lcp->lcd_state == READY) {
			transfer_sockbuf(&lcp->lcd_sb, pk_output, lcp0);
			lcp->lcd_upper = 0;
			pk_close(lcp);
		} else {
			lx = x25_lxalloc(rt);
			if (lx == 0)
				return ENOBUFS;
		}
	}
	lx->lx_lcd = lcp = lcp0;
	lcp->lcd_upper = x25_ifinput;
	lcp->lcd_upnext = (caddr_t)lx;
}
