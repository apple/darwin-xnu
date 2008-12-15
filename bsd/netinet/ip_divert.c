/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
 * Copyright (c) 1982, 1986, 1988, 1993
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
 * $FreeBSD: src/sys/netinet/ip_divert.c,v 1.98 2004/08/17 22:05:54 andre Exp $
 */

#if !INET
#error "IPDIVERT requires INET."
#endif

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/proc.h>


#include <net/if.h>
#include <net/route.h>
#include <net/kpi_protocol.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#include <netinet/ip_fw.h>
#include <netinet/ip_divert.h>

#include <kern/zalloc.h>
#include <libkern/OSAtomic.h>

/*
 * Divert sockets
 */

/*
 * Allocate enough space to hold a full IP packet
 */
#define	DIVSNDQ		(65536 + 100)
#define	DIVRCVQ		(65536 + 100)

/*
 * Divert sockets work in conjunction with ipfw, see the divert(4)
 * manpage for features.
 * Internally, packets selected by ipfw in ip_input() or ip_output(),
 * and never diverted before, are passed to the input queue of the
 * divert socket with a given 'divert_port' number (as specified in
 * the matching ipfw rule), and they are tagged with a 16 bit cookie
 * (representing the rule number of the matching ipfw rule), which
 * is passed to process reading from the socket.
 *
 * Packets written to the divert socket are again tagged with a cookie
 * (usually the same as above) and a destination address.
 * If the destination address is INADDR_ANY then the packet is
 * treated as outgoing and sent to ip_output(), otherwise it is
 * treated as incoming and sent to ip_input().
 * In both cases, the packet is tagged with the cookie.
 *
 * On reinjection, processing in ip_input() and ip_output()
 * will be exactly the same as for the original packet, except that
 * ipfw processing will start at the rule number after the one
 * written in the cookie (so, tagging a packet with a cookie of 0
 * will cause it to be effectively considered as a standard packet).
 */

/* Internal variables */
static struct inpcbhead divcb;
static struct inpcbinfo divcbinfo;

static u_long	div_sendspace = DIVSNDQ;	/* XXX sysctl ? */
static u_long	div_recvspace = DIVRCVQ;	/* XXX sysctl ? */

/* Optimization: have this preinitialized */
static struct sockaddr_in divsrc = { sizeof(divsrc), AF_INET, 0, { 0 }, { 0,0,0,0,0,0,0,0 } };

/* Internal functions */
static int div_output(struct socket *so,
		struct mbuf *m, struct sockaddr *addr, struct mbuf *control);

extern int load_ipfw(void);
/*
 * Initialize divert connection block queue.
 */
void
div_init(void)
{
	struct inpcbinfo *pcbinfo;
	LIST_INIT(&divcb);
	divcbinfo.listhead = &divcb;
	/*
	 * XXX We don't use the hash list for divert IP, but it's easier
	 * to allocate a one entry hash list than it is to check all
	 * over the place for hashbase == NULL.
	 */
	divcbinfo.hashbase = hashinit(1, M_PCB, &divcbinfo.hashmask);
	divcbinfo.porthashbase = hashinit(1, M_PCB, &divcbinfo.porthashmask);
	divcbinfo.ipi_zone = (void *) zinit(sizeof(struct inpcb),(maxsockets * sizeof(struct inpcb)),
				   4096, "divzone");
	pcbinfo = &divcbinfo;
        /*
	 * allocate lock group attribute and group for udp pcb mutexes
	 */
	pcbinfo->mtx_grp_attr = lck_grp_attr_alloc_init();

	pcbinfo->mtx_grp = lck_grp_alloc_init("divcb", pcbinfo->mtx_grp_attr);
		
	/*
	 * allocate the lock attribute for divert pcb mutexes
	 */
	pcbinfo->mtx_attr = lck_attr_alloc_init();

	if ((pcbinfo->mtx = lck_rw_alloc_init(pcbinfo->mtx_grp, pcbinfo->mtx_attr)) == NULL)
		return;	/* pretty much dead if this fails... */

#if IPFIREWALL
	if (!IPFW_LOADED) {
		load_ipfw();
	}
#endif
}

/*
 * IPPROTO_DIVERT is not a real IP protocol; don't allow any packets
 * with that protocol number to enter the system from the outside.
 */
void
div_input(struct mbuf *m, __unused int off)
{
	OSAddAtomic(1, (SInt32*)&ipstat.ips_noproto);
	m_freem(m);
}

/*
 * Divert a packet by passing it up to the divert socket at port 'port'.
 *
 * Setup generic address and protocol structures for div_input routine,
 * then pass them along with mbuf chain.
 * ###LOCK  called in ip_mutex from ip_output/ip_input
 */
void
divert_packet(struct mbuf *m, int incoming, int port, int rule)
{
	struct ip *ip;
	struct inpcb *inp;
	struct socket *sa;
	u_int16_t nport;

	/* Sanity check */
	KASSERT(port != 0, ("%s: port=0", __FUNCTION__));

	divsrc.sin_port = rule;		/* record matching rule */

	/* Assure header */
	if (m->m_len < sizeof(struct ip) &&
	    (m = m_pullup(m, sizeof(struct ip))) == 0) {
		return;
	}
	ip = mtod(m, struct ip *);

	/*
	 * Record receive interface address, if any.
	 * But only for incoming packets.
	 */
	divsrc.sin_addr.s_addr = 0;
	if (incoming) {
		struct ifaddr *ifa;

		/* Sanity check */
		KASSERT((m->m_flags & M_PKTHDR), ("%s: !PKTHDR", __FUNCTION__));

		/* Find IP address for receive interface */
		ifnet_lock_shared(m->m_pkthdr.rcvif);
		TAILQ_FOREACH(ifa, &m->m_pkthdr.rcvif->if_addrhead, ifa_link) {
			if (ifa->ifa_addr == NULL)
				continue;
			if (ifa->ifa_addr->sa_family != AF_INET)
				continue;
			divsrc.sin_addr =
			    ((struct sockaddr_in *) ifa->ifa_addr)->sin_addr;
			break;
		}
		ifnet_lock_done(m->m_pkthdr.rcvif);
	}
	/*
	 * Record the incoming interface name whenever we have one.
	 */
	bzero(&divsrc.sin_zero, sizeof(divsrc.sin_zero));
	if (m->m_pkthdr.rcvif) {
		/*
		 * Hide the actual interface name in there in the 
		 * sin_zero array. XXX This needs to be moved to a
		 * different sockaddr type for divert, e.g.
		 * sockaddr_div with multiple fields like 
		 * sockaddr_dl. Presently we have only 7 bytes
		 * but that will do for now as most interfaces
		 * are 4 or less + 2 or less bytes for unit.
		 * There is probably a faster way of doing this,
		 * possibly taking it from the sockaddr_dl on the iface.
		 * This solves the problem of a P2P link and a LAN interface
		 * having the same address, which can result in the wrong
		 * interface being assigned to the packet when fed back
		 * into the divert socket. Theoretically if the daemon saves
		 * and re-uses the sockaddr_in as suggested in the man pages,
		 * this iface name will come along for the ride.
		 * (see div_output for the other half of this.)
		 */ 
		snprintf(divsrc.sin_zero, sizeof(divsrc.sin_zero),
			"%s%d", m->m_pkthdr.rcvif->if_name,
			m->m_pkthdr.rcvif->if_unit);
	}

	/* Put packet on socket queue, if any */
	sa = NULL;
	nport = htons((u_int16_t)port);
	lck_rw_lock_shared(divcbinfo.mtx); 	
	LIST_FOREACH(inp, &divcb, inp_list) {
		if (inp->inp_lport == nport)
			sa = inp->inp_socket;
	}
	if (sa) {
		int error = 0;
		
		socket_lock(sa, 1);
		if (sbappendaddr(&sa->so_rcv, (struct sockaddr *)&divsrc,
				m, (struct mbuf *)0, &error) != 0)
			sorwakeup(sa);
		socket_unlock(sa, 1);
	} else {
		m_freem(m);
		OSAddAtomic(1, (SInt32*)&ipstat.ips_noproto);
		OSAddAtomic(-1, (SInt32*)&ipstat.ips_delivered);
        }
	lck_rw_done(divcbinfo.mtx); 	
}

/*
 * Deliver packet back into the IP processing machinery.
 *
 * If no address specified, or address is 0.0.0.0, send to ip_output();
 * otherwise, send to ip_input() and mark as having been received on
 * the interface with that address.
 * ###LOCK  called in inet_proto mutex when from div_send. 
 */
static int
div_output(struct socket *so, struct mbuf *m, struct sockaddr *addr,
	   struct mbuf *control)
{
	struct inpcb *const inp = sotoinpcb(so);
	struct ip *const ip = mtod(m, struct ip *);
	struct sockaddr_in *sin = (struct sockaddr_in *)addr;
	int error = 0;

	if (control)
		m_freem(control);		/* XXX */

	/* Loopback avoidance and state recovery */
	if (sin) {
		struct m_tag *mtag;
		struct divert_tag *dt;
		int	len = 0;
		char	*c = sin->sin_zero;

		mtag = m_tag_alloc(KERNEL_MODULE_TAG_ID, KERNEL_TAG_TYPE_DIVERT,
				sizeof(struct divert_tag), M_NOWAIT);
		if (mtag == NULL) {
			error = ENOBUFS;
			goto cantsend;
		}
		dt = (struct divert_tag *)(mtag+1);
		dt->info = 0;
		dt->cookie = sin->sin_port;
		m_tag_prepend(m, mtag);

		/*
		 * Find receive interface with the given name or IP address.
		 * The name is user supplied data so don't trust it's size or 
		 * that it is zero terminated. The name has priority.
		 * We are presently assuming that the sockaddr_in 
		 * has not been replaced by a sockaddr_div, so we limit it
		 * to 16 bytes in total. the name is stuffed (if it exists)
		 * in the sin_zero[] field.
		 */
		while (*c++ && (len++ < sizeof(sin->sin_zero)));
		if ((len > 0) && (len < sizeof(sin->sin_zero)))
			m->m_pkthdr.rcvif = ifunit(sin->sin_zero);
	}

	/* Reinject packet into the system as incoming or outgoing */
	if (!sin || sin->sin_addr.s_addr == 0) {
		/*
		 * Don't allow both user specified and setsockopt options,
		 * and don't allow packet length sizes that will crash
		 */
		if (((ip->ip_hl != (sizeof (*ip) >> 2)) && inp->inp_options) ||
		     ((u_short)ntohs(ip->ip_len) > m->m_pkthdr.len)) {
			error = EINVAL;
			goto cantsend;
		}

		/* Convert fields to host order for ip_output() */
		NTOHS(ip->ip_len);
		NTOHS(ip->ip_off);

		/* Send packet to output processing */
		OSAddAtomic(1, (SInt32*)&ipstat.ips_rawout);
		socket_unlock(so, 0);
#if CONFIG_MACF_NET
		mac_mbuf_label_associate_inpcb(inp, m);
#endif
#if CONFIG_IP_EDGEHOLE
		ip_edgehole_mbuf_tag(inp, m);
#endif
		error = ip_output(m,
			    inp->inp_options, &inp->inp_route,
			(so->so_options & SO_DONTROUTE) |
			IP_ALLOWBROADCAST | IP_RAWOUTPUT,
			inp->inp_moptions, NULL);
		socket_lock(so, 0);
	} else {
		struct	ifaddr *ifa;

		/* If no luck with the name above. check by IP address.  */
		if (m->m_pkthdr.rcvif == NULL) {
			/*
			 * Make sure there are no distractions
			 * for ifa_ifwithaddr. Clear the port and the ifname.
			 * Maybe zap all 8 bytes at once using a 64bit write?
			 */
			bzero(sin->sin_zero, sizeof(sin->sin_zero));
			/* *((u_int64_t *)sin->sin_zero) = 0; */ /* XXX ?? */
			sin->sin_port = 0;
			if (!(ifa = ifa_ifwithaddr((struct sockaddr *) sin))) {
				error = EADDRNOTAVAIL;
				goto cantsend;
			}
			m->m_pkthdr.rcvif = ifa->ifa_ifp;
			ifafree(ifa);
		}
#if CONFIG_MACF_NET
		mac_mbuf_label_associate_socket(so, m);
#endif
		/* Send packet to input processing */
		proto_inject(PF_INET, m);
	}

	return error;

cantsend:
	m_freem(m);
	return error;
}

static int
div_attach(struct socket *so, int proto, struct proc *p)
{
	struct inpcb *inp;
	int error;


	inp  = sotoinpcb(so);
	if (inp)
		panic("div_attach");
	if (p && (error = proc_suser(p)) != 0)
		return error;

	error = soreserve(so, div_sendspace, div_recvspace);
	if (error)
		return error;
	error = in_pcballoc(so, &divcbinfo, p);
	if (error)
		return error;
	inp = (struct inpcb *)so->so_pcb;
	inp->inp_ip_p = proto;
	inp->inp_vflag |= INP_IPV4;
	inp->inp_flags |= INP_HDRINCL;
	/* The socket is always "connected" because
	   we always know "where" to send the packet */
	so->so_state |= SS_ISCONNECTED;

#ifdef MORE_DICVLOCK_DEBUG
	printf("div_attach: so=%p sopcb=%p lock=%x ref=%x\n",
			so, so->so_pcb, ((struct inpcb *)so->so_pcb)->inpcb_mtx, so->so_usecount);
#endif
	return 0;
}

static int
div_detach(struct socket *so)
{
	struct inpcb *inp;

#ifdef MORE_DICVLOCK_DEBUG
	printf("div_detach: so=%p sopcb=%p lock=%x ref=%x\n",
			so, so->so_pcb, ((struct inpcb *)so->so_pcb)->inpcb_mtx, so->so_usecount);
#endif
	inp = sotoinpcb(so);
	if (inp == 0)
		panic("div_detach: so=%p null inp\n", so);
	in_pcbdetach(inp);
	inp->inp_state = INPCB_STATE_DEAD;
	return 0;
}

static int
div_abort(struct socket *so)
{
	soisdisconnected(so);
	return div_detach(so);
}

static int
div_disconnect(struct socket *so)
{
	if ((so->so_state & SS_ISCONNECTED) == 0)
		return ENOTCONN;
	return div_abort(so);
}

static int
div_bind(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	struct inpcb *inp;
	int error;

	inp = sotoinpcb(so);
	/* in_pcbbind assumes that the socket is a sockaddr_in
	* and in_pcbbind requires a valid address. Since divert
	* sockets don't we need to make sure the address is
	* filled in properly.
	* XXX -- divert should not be abusing in_pcbind
	* and should probably have its own family.
	*/
	if (nam->sa_family != AF_INET) {
		error = EAFNOSUPPORT;
	} else {
               ((struct sockaddr_in *)nam)->sin_addr.s_addr = INADDR_ANY;
		error = in_pcbbind(inp, nam, p);
	}
	return error;
}

static int
div_shutdown(struct socket *so)
{
	socantsendmore(so);
	return 0;
}

static int
div_send(struct socket *so, __unused int flags, struct mbuf *m, struct sockaddr *nam,
	 struct mbuf *control, __unused struct proc *p)
{
	/* Packet must have a header (but that's about it) */
	if (m->m_len < sizeof (struct ip) &&
	    (m = m_pullup(m, sizeof (struct ip))) == 0) {
		OSAddAtomic(1, (SInt32*)&ipstat.ips_toosmall);
		m_freem(m);
		return EINVAL;
	}

	/* Send packet */
	return div_output(so, m, nam, control);
}

static int
div_pcblist SYSCTL_HANDLER_ARGS
{
	int error, i, n;
	struct inpcb *inp, **inp_list;
	inp_gen_t gencnt;
	struct xinpgen xig;

	/*
	 * The process of preparing the TCB list is too time-consuming and
	 * resource-intensive to repeat twice on every request.
	 */
	lck_rw_lock_exclusive(divcbinfo.mtx);
	if (req->oldptr == USER_ADDR_NULL) {
		n = divcbinfo.ipi_count;
		req->oldidx = 2 * (sizeof xig)
			+ (n + n/8) * sizeof(struct xinpcb);
		lck_rw_done(divcbinfo.mtx);
		return 0;
	}

	if (req->newptr != USER_ADDR_NULL) {
		lck_rw_done(divcbinfo.mtx);
		return EPERM;
	}

	/*
	 * OK, now we're committed to doing something.
	 */
	gencnt = divcbinfo.ipi_gencnt;
	n = divcbinfo.ipi_count;

	bzero(&xig, sizeof(xig));
	xig.xig_len = sizeof xig;
	xig.xig_count = n;
	xig.xig_gen = gencnt;
	xig.xig_sogen = so_gencnt;
	error = SYSCTL_OUT(req, &xig, sizeof xig);
	if (error) {
		lck_rw_done(divcbinfo.mtx);
		return error;
	}

	inp_list = _MALLOC(n * sizeof *inp_list, M_TEMP, M_WAITOK);
	if (inp_list == 0) {
		lck_rw_done(divcbinfo.mtx);
		return ENOMEM;
	}
	
	for (inp = LIST_FIRST(divcbinfo.listhead), i = 0; inp && i < n;
	     inp = LIST_NEXT(inp, inp_list)) {
#ifdef __APPLE__
		if (inp->inp_gencnt <= gencnt && inp->inp_state != INPCB_STATE_DEAD)
#else
		if (inp->inp_gencnt <= gencnt && !prison_xinpcb(req->p, inp))
#endif
			inp_list[i++] = inp;
	}
	n = i;

	error = 0;
	for (i = 0; i < n; i++) {
		inp = inp_list[i];
		if (inp->inp_gencnt <= gencnt && inp->inp_state != INPCB_STATE_DEAD) {
			struct xinpcb xi;

			bzero(&xi, sizeof(xi));
			xi.xi_len = sizeof xi;
			/* XXX should avoid extra copy */
			inpcb_to_compat(inp, &xi.xi_inp);
			if (inp->inp_socket)
				sotoxsocket(inp->inp_socket, &xi.xi_socket);
			error = SYSCTL_OUT(req, &xi, sizeof xi);
		}
	}
	if (!error) {
		/*
		 * Give the user an updated idea of our state.
		 * If the generation differs from what we told
		 * her before, she knows that something happened
		 * while we were processing this request, and it
		 * might be necessary to retry.
		 */
		bzero(&xig, sizeof(xig));
		xig.xig_len = sizeof xig;
		xig.xig_gen = divcbinfo.ipi_gencnt;
		xig.xig_sogen = so_gencnt;
		xig.xig_count = divcbinfo.ipi_count;
		error = SYSCTL_OUT(req, &xig, sizeof xig);
	}
	FREE(inp_list, M_TEMP);
	lck_rw_done(divcbinfo.mtx);
	return error;
}

__private_extern__ int
div_lock(struct socket *so, int refcount, int lr)
 {
	int lr_saved;
	if (lr == 0) 
		lr_saved = (unsigned int) __builtin_return_address(0);
	else lr_saved = lr;
	
#ifdef MORE_DICVLOCK_DEBUG
	printf("div_lock: so=%p sopcb=%p lock=%x ref=%x lr=%x\n",
			so, 
			so->so_pcb, 
			so->so_pcb ? ((struct inpcb *)so->so_pcb)->inpcb_mtx : 0, 
			so->so_usecount, 
			lr_saved);
#endif
	if (so->so_pcb) {
		lck_mtx_lock(((struct inpcb *)so->so_pcb)->inpcb_mtx);
	} else  {
		panic("div_lock: so=%p NO PCB! lr=%x\n", so, lr_saved);
		lck_mtx_lock(so->so_proto->pr_domain->dom_mtx);
	}
	
	if (so->so_usecount < 0)
		panic("div_lock: so=%p so_pcb=%p lr=%x ref=%x\n",
		so, so->so_pcb, lr_saved, so->so_usecount);
	
	if (refcount)
		so->so_usecount++;
	so->lock_lr[so->next_lock_lr] = (u_int32_t)lr_saved;
	so->next_lock_lr = (so->next_lock_lr+1) % SO_LCKDBG_MAX;

	return (0);
}

__private_extern__ int
div_unlock(struct socket *so, int refcount, int lr)
{
	int lr_saved;
	lck_mtx_t * mutex_held;
	struct inpcb *inp = sotoinpcb(so);	

	if (lr == 0) 
		lr_saved = (unsigned int) __builtin_return_address(0);
	else lr_saved = lr;

	
#ifdef MORE_DICVLOCK_DEBUG
	printf("div_unlock: so=%p sopcb=%p lock=%x ref=%x lr=%x\n",
			so, 
			so->so_pcb, 
			so->so_pcb ? ((struct inpcb *)so->so_pcb)->inpcb_mtx : 0, 
			so->so_usecount, 
			lr_saved);
#endif
	if (refcount)
		so->so_usecount--;
	
	if (so->so_usecount < 0)
		panic("div_unlock: so=%p usecount=%x\n", so, so->so_usecount);
	if (so->so_pcb == NULL) {
		panic("div_unlock: so=%p NO PCB usecount=%x lr=%x\n", so, so->so_usecount, lr_saved);
		mutex_held = so->so_proto->pr_domain->dom_mtx;
	} else {
		mutex_held = ((struct inpcb *)so->so_pcb)->inpcb_mtx;
	}

	if (so->so_usecount == 0 && (inp->inp_wantcnt == WNT_STOPUSING)) {
		lck_rw_lock_exclusive(divcbinfo.mtx);
		in_pcbdispose(inp);
		lck_rw_done(divcbinfo.mtx);
		return (0);
	}
	lck_mtx_assert(mutex_held, LCK_MTX_ASSERT_OWNED);
	so->unlock_lr[so->next_unlock_lr] = (u_int32_t) lr_saved;
	so->next_unlock_lr = (so->next_unlock_lr+1) % SO_LCKDBG_MAX;
	lck_mtx_unlock(mutex_held);
	return (0);
}

__private_extern__ lck_mtx_t *
div_getlock(struct socket *so, __unused int locktype)
{
	struct inpcb *inpcb = (struct inpcb *)so->so_pcb;
	
	if (so->so_pcb)  {
		if (so->so_usecount < 0)
			panic("div_getlock: so=%p usecount=%x\n", so, so->so_usecount);
		return(inpcb->inpcb_mtx);
	} else {
		panic("div_getlock: so=%p NULL so_pcb\n", so);
		return (so->so_proto->pr_domain->dom_mtx);
	}
}


struct pr_usrreqs div_usrreqs = {
	div_abort, pru_accept_notsupp, div_attach, div_bind,
	pru_connect_notsupp, pru_connect2_notsupp, in_control, div_detach,
	div_disconnect, pru_listen_notsupp, in_setpeeraddr, pru_rcvd_notsupp,
	pru_rcvoob_notsupp, div_send, pru_sense_null, div_shutdown,
	in_setsockaddr, sosend, soreceive, pru_sopoll_notsupp
};

