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
 * Copyright (c) 1988, 1991, 1993
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
 *	@(#)rtsock.c	8.5 (Berkeley) 11/2/94
 */


#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/syslog.h>

#include <net/if.h>
#include <net/route.h>
#include <net/raw_cb.h>
#include <netinet/in.h>

MALLOC_DEFINE(M_RTABLE, "routetbl", "routing tables");

static struct	sockaddr route_dst = { 2, PF_ROUTE, };
static struct	sockaddr route_src = { 2, PF_ROUTE, };
static struct	sockaddr sa_zero   = { sizeof(sa_zero), AF_INET, };
static struct	sockproto route_proto = { PF_ROUTE, };

struct walkarg {
	int	w_tmemsize;
	int	w_op, w_arg;
	caddr_t	w_tmem;
	struct sysctl_req *w_req;
};

static struct mbuf *
		rt_msg1 __P((int, struct rt_addrinfo *));
static int	rt_msg2 __P((int,
		    struct rt_addrinfo *, caddr_t, struct walkarg *));
static int	rt_xaddrs __P((caddr_t, caddr_t, struct rt_addrinfo *));
static int	sysctl_dumpentry __P((struct radix_node *rn, void *vw));
static int	sysctl_iflist __P((int af, struct walkarg *w));
static int	 route_output __P((struct mbuf *, struct socket *));
static void	 rt_setmetrics __P((u_long, struct rt_metrics *, struct rt_metrics *));
static void	rt_setif __P((struct rtentry *, struct sockaddr *, struct sockaddr *,
			      struct sockaddr *));

/* Sleazy use of local variables throughout file, warning!!!! */
#define dst	info.rti_info[RTAX_DST]
#define gate	info.rti_info[RTAX_GATEWAY]
#define netmask	info.rti_info[RTAX_NETMASK]
#define genmask	info.rti_info[RTAX_GENMASK]
#define ifpaddr	info.rti_info[RTAX_IFP]
#define ifaaddr	info.rti_info[RTAX_IFA]
#define brdaddr	info.rti_info[RTAX_BRD]

/*
 * It really doesn't make any sense at all for this code to share much
 * with raw_usrreq.c, since its functionality is so restricted.  XXX
 */
static int
rts_abort(struct socket *so)
{
	int s, error;
	s = splnet();
	error = raw_usrreqs.pru_abort(so);
	splx(s);
	return error;
}

/* pru_accept is EOPNOTSUPP */

static int
rts_attach(struct socket *so, int proto, struct proc *p)
{
	struct rawcb *rp;
	int s, error;

	if (sotorawcb(so) != 0)
		return EISCONN;	/* XXX panic? */
	MALLOC(rp, struct rawcb *, sizeof *rp, M_PCB, M_WAITOK); /* XXX */
	if (rp == 0)
		return ENOBUFS;
	bzero(rp, sizeof *rp);

	/*
	 * The splnet() is necessary to block protocols from sending
	 * error notifications (like RTM_REDIRECT or RTM_LOSING) while
	 * this PCB is extant but incompletely initialized.
	 * Probably we should try to do more of this work beforehand and
	 * eliminate the spl.
	 */
	s = splnet();
	so->so_pcb = (caddr_t)rp;
	error = raw_usrreqs.pru_attach(so, proto, p);
	rp = sotorawcb(so);
	if (error) {
		splx(s);
		FREE(rp, M_PCB);
		return error;
	}
	switch(rp->rcb_proto.sp_protocol) {
	case AF_INET:
		route_cb.ip_count++;
		break;
	case AF_INET6:
		route_cb.ip6_count++;
		break;
	case AF_IPX:
		route_cb.ipx_count++;
		break;
	case AF_NS:
		route_cb.ns_count++;
		break;
	}
	rp->rcb_faddr = &route_src;
	route_cb.any_count++;
	soisconnected(so);
	so->so_options |= SO_USELOOPBACK;
	splx(s);
	return 0;
}

static int
rts_bind(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	int s, error;
	s = splnet();
	error = raw_usrreqs.pru_bind(so, nam, p); /* xxx just EINVAL */
	splx(s);
	return error;
}

static int
rts_connect(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	int s, error;
	s = splnet();
	error = raw_usrreqs.pru_connect(so, nam, p); /* XXX just EINVAL */
	splx(s);
	return error;
}

/* pru_connect2 is EOPNOTSUPP */
/* pru_control is EOPNOTSUPP */

static int
rts_detach(struct socket *so)
{
	struct rawcb *rp = sotorawcb(so);
	int s, error;

	s = splnet();
	if (rp != 0) {
		switch(rp->rcb_proto.sp_protocol) {
		case AF_INET:
			route_cb.ip_count--;
			break;
		case AF_INET6:
			route_cb.ip6_count--;
			break;
		case AF_IPX:
			route_cb.ipx_count--;
			break;
		case AF_NS:
			route_cb.ns_count--;
			break;
		}
		route_cb.any_count--;
	}
	error = raw_usrreqs.pru_detach(so);
	splx(s);
	return error;
}

static int
rts_disconnect(struct socket *so)
{
	int s, error;
	s = splnet();
	error = raw_usrreqs.pru_disconnect(so);
	splx(s);
	return error;
}

/* pru_listen is EOPNOTSUPP */

static int
rts_peeraddr(struct socket *so, struct sockaddr **nam)
{
	int s, error;
	s = splnet();
	error = raw_usrreqs.pru_peeraddr(so, nam);
	splx(s);
	return error;
}

/* pru_rcvd is EOPNOTSUPP */
/* pru_rcvoob is EOPNOTSUPP */

static int
rts_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *nam,
	 struct mbuf *control, struct proc *p)
{
	int s, error;
	s = splnet();
	error = raw_usrreqs.pru_send(so, flags, m, nam, control, p);
	splx(s);
	return error;
}

/* pru_sense is null */

static int
rts_shutdown(struct socket *so)
{
	int s, error;
	s = splnet();
	error = raw_usrreqs.pru_shutdown(so);
	splx(s);
	return error;
}

static int
rts_sockaddr(struct socket *so, struct sockaddr **nam)
{
	int s, error;
	s = splnet();
	error = raw_usrreqs.pru_sockaddr(so, nam);
	splx(s);
	return error;
}

static struct pr_usrreqs route_usrreqs = {
	rts_abort, pru_accept_notsupp, rts_attach, rts_bind, rts_connect,
	pru_connect2_notsupp, pru_control_notsupp, rts_detach, rts_disconnect,
	pru_listen_notsupp, rts_peeraddr, pru_rcvd_notsupp, pru_rcvoob_notsupp,
	rts_send, pru_sense_null, rts_shutdown, rts_sockaddr,
	sosend, soreceive, sopoll
};

/*ARGSUSED*/
static int
route_output(m, so)
	register struct mbuf *m;
	struct socket *so;
{
	register struct rt_msghdr *rtm = 0;
	register struct rtentry *rt = 0;
	struct rtentry *saved_nrt = 0;
	struct radix_node_head *rnh;
	struct rt_addrinfo info;
	int len, error = 0;
	struct ifnet *ifp = 0;
	struct ifaddr *ifa = 0;
	struct proc  *curproc = current_proc();

#define senderr(e) { error = e; goto flush;}
	if (m == 0 || ((m->m_len < sizeof(long)) &&
		       (m = m_pullup(m, sizeof(long))) == 0))
		return (ENOBUFS);
	if ((m->m_flags & M_PKTHDR) == 0)
		panic("route_output");
	len = m->m_pkthdr.len;
	if (len < sizeof(*rtm) ||
	    len != mtod(m, struct rt_msghdr *)->rtm_msglen) {
		dst = 0;
		senderr(EINVAL);
	}
	R_Malloc(rtm, struct rt_msghdr *, len);
	if (rtm == 0) {
		dst = 0;
		senderr(ENOBUFS);
	}
	m_copydata(m, 0, len, (caddr_t)rtm);
	if (rtm->rtm_version != RTM_VERSION) {
		dst = 0;
		senderr(EPROTONOSUPPORT);
	}
	rtm->rtm_pid = curproc->p_pid;
	info.rti_addrs = rtm->rtm_addrs;
	if (rt_xaddrs((caddr_t)(rtm + 1), len + (caddr_t)rtm, &info)) {
		dst = 0;
		senderr(EINVAL);
	}
	if (dst == 0 || (dst->sa_family >= AF_MAX)
	    || (gate != 0 && (gate->sa_family >= AF_MAX)))
		senderr(EINVAL);
	if (genmask) {
		struct radix_node *t;
		t = rn_addmask((caddr_t)genmask, 0, 1);
		if (t && Bcmp(genmask, t->rn_key, *(u_char *)genmask) == 0)
			genmask = (struct sockaddr *)(t->rn_key);
		else
			senderr(ENOBUFS);
	}
	switch (rtm->rtm_type) {

	case RTM_ADD:
		if (gate == 0)
			senderr(EINVAL);

#ifdef __APPLE__
/* XXX LD11JUL02 Special case for AOL 5.1.2 connectivity issue to AirPort BS (Radar 2969954)
 * AOL is adding a circular route ("10.0.1.1/32 10.0.1.1") when establishing its ppp tunnel
 * to the AP BaseStation by removing the default gateway and replacing it with their tunnel entry point.
 * There is no apparent reason to add this route as there is a valid 10.0.1.1/24 route to the BS.
 * That circular route was ignored on previous version of MacOS X because of a routing bug
 * corrected with the merge to FreeBSD4.4 (a route generated from an RTF_CLONING route had the RTF_WASCLONED
 * flag set but did not have a reference to the parent route) and that entry was left in the RT. This workaround is
 * made in order to provide binary compatibility with AOL. 
 * If we catch a process adding a circular route with a /32 from the routing socket, we error it out instead of
 * confusing the routing table with a wrong route to the previous default gateway
 */
{
		extern int check_routeselfref;
#define satosinaddr(sa) (((struct sockaddr_in *)sa)->sin_addr.s_addr)

		if (check_routeselfref && (dst && dst->sa_family == AF_INET) && 
			(netmask && satosinaddr(netmask) == INADDR_BROADCAST) &&
			(gate && satosinaddr(dst) == satosinaddr(gate))) {
				log(LOG_WARNING, "route_output: circular route %ld.%ld.%ld.%ld/32 ignored\n",
					(ntohl(satosinaddr(gate)>>24))&0xff,
					(ntohl(satosinaddr(gate)>>16))&0xff,
					(ntohl(satosinaddr(gate)>>8))&0xff,
					(ntohl(satosinaddr(gate)))&0xff);
					
				senderr(EINVAL);
		}
}
#endif	
		error = rtrequest(RTM_ADD, dst, gate, netmask,
					rtm->rtm_flags, &saved_nrt);
		if (error == 0 && saved_nrt) {
#ifdef __APPLE__
		    /* 
		     * If the route request specified an interface with
		     * IFA and/or IFP, we set the requested interface on
		     * the route with rt_setif.  It would be much better
		     * to do this inside rtrequest, but that would
		     * require passing the desired interface, in some
		     * form, to rtrequest.  Since rtrequest is called in
		     * so many places (roughly 40 in our source), adding
		     * a parameter is to much for us to swallow; this is
		     * something for the FreeBSD developers to tackle.
		     * Instead, we let rtrequest compute whatever
		     * interface it wants, then come in behind it and
		     * stick in the interface that we really want.  This
		     * works reasonably well except when rtrequest can't
		     * figure out what interface to use (with
		     * ifa_withroute) and returns ENETUNREACH.  Ideally
		     * it shouldn't matter if rtrequest can't figure out
		     * the interface if we're going to explicitly set it
		     * ourselves anyway.  But practically we can't
		     * recover here because rtrequest will not do any of
		     * the work necessary to add the route if it can't
		     * find an interface.  As long as there is a default
		     * route that leads to some interface, rtrequest will
		     * find an interface, so this problem should be
		     * rarely encountered.
		     * dwiggins@bbn.com
		     */

			rt_setif(saved_nrt, ifpaddr, ifaaddr, gate);
#endif
			rt_setmetrics(rtm->rtm_inits,
				&rtm->rtm_rmx, &saved_nrt->rt_rmx);
			saved_nrt->rt_rmx.rmx_locks &= ~(rtm->rtm_inits);
			saved_nrt->rt_rmx.rmx_locks |=
				(rtm->rtm_inits & rtm->rtm_rmx.rmx_locks);
			rtunref(saved_nrt);
			saved_nrt->rt_genmask = genmask;
		}
		break;

	case RTM_DELETE:
		error = rtrequest(RTM_DELETE, dst, gate, netmask,
				rtm->rtm_flags, &saved_nrt);
		if (error == 0) {
			if ((rt = saved_nrt))
				rtref(rt);
			goto report;
		}
		break;

	case RTM_GET:
	case RTM_CHANGE:
	case RTM_LOCK:
		if ((rnh = rt_tables[dst->sa_family]) == 0) {
			senderr(EAFNOSUPPORT);
		} else if ((rt = (struct rtentry *)
				rnh->rnh_lookup(dst, netmask, rnh)) != NULL)
			rtref(rt);
		else
			senderr(ESRCH);
		switch(rtm->rtm_type) {

		case RTM_GET:
		report:
			dst = rt_key(rt);
			gate = rt->rt_gateway;
			netmask = rt_mask(rt);
			genmask = rt->rt_genmask;
			if (rtm->rtm_addrs & (RTA_IFP | RTA_IFA)) {
				ifp = rt->rt_ifp;
				if (ifp) {
					ifpaddr = ifp->if_addrhead.tqh_first->ifa_addr;
					ifaaddr = rt->rt_ifa->ifa_addr;
					rtm->rtm_index = ifp->if_index;
				} else {
					ifpaddr = 0;
					ifaaddr = 0;
			    }
			}
			len = rt_msg2(rtm->rtm_type, &info, (caddr_t)0,
				(struct walkarg *)0);
			if (len > rtm->rtm_msglen) {
				struct rt_msghdr *new_rtm;
				R_Malloc(new_rtm, struct rt_msghdr *, len);
				if (new_rtm == 0)
					senderr(ENOBUFS);
				Bcopy(rtm, new_rtm, rtm->rtm_msglen);
				Free(rtm); rtm = new_rtm;
			}
			(void)rt_msg2(rtm->rtm_type, &info, (caddr_t)rtm,
				(struct walkarg *)0);
			rtm->rtm_flags = rt->rt_flags;
			rtm->rtm_rmx = rt->rt_rmx;
			rtm->rtm_addrs = info.rti_addrs;
			break;

		case RTM_CHANGE:
			if (gate && (error = rt_setgate(rt, rt_key(rt), gate)))
				senderr(error);

			/*
			 * If they tried to change things but didn't specify
			 * the required gateway, then just use the old one.
			 * This can happen if the user tries to change the
			 * flags on the default route without changing the
			 * default gateway.  Changing flags still doesn't work.
			 */
			if ((rt->rt_flags & RTF_GATEWAY) && !gate)
				gate = rt->rt_gateway;

#ifdef __APPLE__
			/*
			 * On Darwin, we call rt_setif which contains the
			 * equivalent to the code found at this very spot
			 * in BSD.
			 */
			rt_setif(rt, ifpaddr, ifaaddr, gate);
#endif

			rt_setmetrics(rtm->rtm_inits, &rtm->rtm_rmx,
					&rt->rt_rmx);
#ifndef __APPLE__
			/* rt_setif, called above does this for us on darwin */
			if (rt->rt_ifa && rt->rt_ifa->ifa_rtrequest)
			       rt->rt_ifa->ifa_rtrequest(RTM_ADD, rt, gate);
#endif
			if (genmask)
				rt->rt_genmask = genmask;
			/*
			 * Fall into
			 */
		case RTM_LOCK:
			rt->rt_rmx.rmx_locks &= ~(rtm->rtm_inits);
			rt->rt_rmx.rmx_locks |=
				(rtm->rtm_inits & rtm->rtm_rmx.rmx_locks);
			break;
		}
		break;

	default:
		senderr(EOPNOTSUPP);
	}

flush:
	if (rtm) {
		if (error)
			rtm->rtm_errno = error;
		else
			rtm->rtm_flags |= RTF_DONE;
	}
	if (rt)
		rtfree(rt);
    {
	register struct rawcb *rp = 0;
	/*
	 * Check to see if we don't want our own messages.
	 */
	if ((so->so_options & SO_USELOOPBACK) == 0) {
		if (route_cb.any_count <= 1) {
			if (rtm)
				Free(rtm);
			m_freem(m);
			return (error);
		}
		/* There is another listener, so construct message */
		rp = sotorawcb(so);
	}
	if (rtm) {
		m_copyback(m, 0, rtm->rtm_msglen, (caddr_t)rtm);
		if (m->m_pkthdr.len < rtm->rtm_msglen) {
			m_freem(m);
			m = NULL;
		} else if (m->m_pkthdr.len > rtm->rtm_msglen)
			m_adj(m, rtm->rtm_msglen - m->m_pkthdr.len);
		Free(rtm);
	}
	if (rp)
		rp->rcb_proto.sp_family = 0; /* Avoid us */
	if (dst)
		route_proto.sp_protocol = dst->sa_family;
	if (m)
		raw_input(m, &route_proto, &route_src, &route_dst);
	if (rp)
		rp->rcb_proto.sp_family = PF_ROUTE;
    }
	return (error);
}

static void
rt_setmetrics(which, in, out)
	u_long which;
	register struct rt_metrics *in, *out;
{
#define metric(f, e) if (which & (f)) out->e = in->e;
	metric(RTV_RPIPE, rmx_recvpipe);
	metric(RTV_SPIPE, rmx_sendpipe);
	metric(RTV_SSTHRESH, rmx_ssthresh);
	metric(RTV_RTT, rmx_rtt);
	metric(RTV_RTTVAR, rmx_rttvar);
	metric(RTV_HOPCOUNT, rmx_hopcount);
	metric(RTV_MTU, rmx_mtu);
	metric(RTV_EXPIRE, rmx_expire);
#undef metric
}

/*
 * Set route's interface given ifpaddr, ifaaddr, and gateway.
 */
static void
rt_setif(rt, Ifpaddr, Ifaaddr, Gate)
	struct rtentry *rt;
	struct sockaddr *Ifpaddr, *Ifaaddr, *Gate;
{
	struct ifaddr *ifa = 0;
	struct ifnet  *ifp = 0;

	/* new gateway could require new ifaddr, ifp;
	   flags may also be different; ifp may be specified
	   by ll sockaddr when protocol address is ambiguous */
	if (Ifpaddr && (ifa = ifa_ifwithnet(Ifpaddr)) &&
	    (ifp = ifa->ifa_ifp) && (Ifaaddr || Gate))
		ifa = ifaof_ifpforaddr(Ifaaddr ? Ifaaddr : Gate,
					ifp);
	else if (Ifpaddr && (ifp = if_withname(Ifpaddr)) ) {
		ifa = Gate ? ifaof_ifpforaddr(Gate, ifp) :
				TAILQ_FIRST(&ifp->if_addrhead);
	}
	else if ((Ifaaddr && (ifa = ifa_ifwithaddr(Ifaaddr))) ||
		 (Gate && (ifa = ifa_ifwithroute(rt->rt_flags,
					rt_key(rt), Gate))))
		ifp = ifa->ifa_ifp;
	if (ifa) {
		register struct ifaddr *oifa = rt->rt_ifa;
		if (oifa != ifa) {
		    if (oifa && oifa->ifa_rtrequest)
			oifa->ifa_rtrequest(RTM_DELETE,
						rt, Gate);
			rtsetifa(rt, ifa);
		    rt->rt_ifp = ifp;
		    rt->rt_rmx.rmx_mtu = ifp->if_mtu;
		    if (rt->rt_ifa && rt->rt_ifa->ifa_rtrequest)
				rt->rt_ifa->ifa_rtrequest(RTM_ADD, rt, Gate);
		} else
			goto call_ifareq;
		return;
	}
      call_ifareq:
	/* XXX: to reset gateway to correct value, at RTM_CHANGE */
	if (rt->rt_ifa && rt->rt_ifa->ifa_rtrequest)
		rt->rt_ifa->ifa_rtrequest(RTM_ADD, rt, Gate);
}


#define ROUNDUP(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))


/*
 * Extract the addresses of the passed sockaddrs.
 * Do a little sanity checking so as to avoid bad memory references.
 * This data is derived straight from userland.
 */
static int
rt_xaddrs(cp, cplim, rtinfo)
	register caddr_t cp, cplim;
	register struct rt_addrinfo *rtinfo;
{
	register struct sockaddr *sa;
	register int i;

	bzero(rtinfo->rti_info, sizeof(rtinfo->rti_info));
	for (i = 0; (i < RTAX_MAX) && (cp < cplim); i++) {
		if ((rtinfo->rti_addrs & (1 << i)) == 0)
			continue;
		sa = (struct sockaddr *)cp;
		/*
		 * It won't fit.
		 */
		if ( (cp + sa->sa_len) > cplim ) {
			return (EINVAL);
		}

		/*
		 * there are no more.. quit now
		 * If there are more bits, they are in error.
		 * I've seen this. route(1) can evidently generate these. 
		 * This causes kernel to core dump.
		 * for compatibility, If we see this, point to a safe address.
		 */
		if (sa->sa_len == 0) {
			rtinfo->rti_info[i] = &sa_zero;
			return (0); /* should be EINVAL but for compat */
		}

		/* accept it */
		rtinfo->rti_info[i] = sa;
		ADVANCE(cp, sa);
	}
	return (0);
}

static struct mbuf *
rt_msg1(type, rtinfo)
	int type;
	register struct rt_addrinfo *rtinfo;
{
	register struct rt_msghdr *rtm;
	register struct mbuf *m;
	register int i;
	register struct sockaddr *sa;
	int len, dlen;

	switch (type) {

	case RTM_DELADDR:
	case RTM_NEWADDR:
		len = sizeof(struct ifa_msghdr);
		break;

	case RTM_DELMADDR:
	case RTM_NEWMADDR:
		len = sizeof(struct ifma_msghdr);
		break;

	case RTM_IFINFO:
		len = sizeof(struct if_msghdr);
		break;

	default:
		len = sizeof(struct rt_msghdr);
	}
	if (len > MCLBYTES)
		panic("rt_msg1");
	m = m_gethdr(M_DONTWAIT, MT_DATA);
	if (m && len > MHLEN) {
		MCLGET(m, M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_free(m);
			m = NULL;
		}
	}
	if (m == 0)
		return (m);
	m->m_pkthdr.len = m->m_len = len;
	m->m_pkthdr.rcvif = 0;
	rtm = mtod(m, struct rt_msghdr *);
	bzero((caddr_t)rtm, len);
	for (i = 0; i < RTAX_MAX; i++) {
		if ((sa = rtinfo->rti_info[i]) == NULL)
			continue;
		rtinfo->rti_addrs |= (1 << i);
		dlen = ROUNDUP(sa->sa_len);
		m_copyback(m, len, dlen, (caddr_t)sa);
		len += dlen;
	}
	if (m->m_pkthdr.len != len) {
		m_freem(m);
		return (NULL);
	}
	rtm->rtm_msglen = len;
	rtm->rtm_version = RTM_VERSION;
	rtm->rtm_type = type;
	return (m);
}

static int
rt_msg2(type, rtinfo, cp, w)
	int type;
	register struct rt_addrinfo *rtinfo;
	caddr_t cp;
	struct walkarg *w;
{
	register int i;
	int len, dlen, second_time = 0;
	caddr_t cp0;

	rtinfo->rti_addrs = 0;
again:
	switch (type) {

	case RTM_DELADDR:
	case RTM_NEWADDR:
		len = sizeof(struct ifa_msghdr);
		break;

	case RTM_IFINFO:
		len = sizeof(struct if_msghdr);
		break;

	default:
		len = sizeof(struct rt_msghdr);
	}
	cp0 = cp;
	if (cp0)
		cp += len;
	for (i = 0; i < RTAX_MAX; i++) {
		register struct sockaddr *sa;

		if ((sa = rtinfo->rti_info[i]) == 0)
			continue;
		rtinfo->rti_addrs |= (1 << i);
		dlen = ROUNDUP(sa->sa_len);
		if (cp) {
			bcopy((caddr_t)sa, cp, (unsigned)dlen);
			cp += dlen;
		}
		len += dlen;
	}
	if (cp == 0 && w != NULL && !second_time) {
		register struct walkarg *rw = w;

		if (rw->w_req) {
			if (rw->w_tmemsize < len) {
				if (rw->w_tmem)
					FREE(rw->w_tmem, M_RTABLE);
				rw->w_tmem = (caddr_t)
					_MALLOC(len, M_RTABLE, M_WAITOK); /*###LD0412 was NOWAIT */
				if (rw->w_tmem)
					rw->w_tmemsize = len;
			}
			if (rw->w_tmem) {
				cp = rw->w_tmem;
				second_time = 1;
				goto again;
			}
		}
	}
	if (cp) {
		register struct rt_msghdr *rtm = (struct rt_msghdr *)cp0;

		rtm->rtm_version = RTM_VERSION;
		rtm->rtm_type = type;
		rtm->rtm_msglen = len;
	}
	return (len);
}

/*
 * This routine is called to generate a message from the routing
 * socket indicating that a redirect has occured, a routing lookup
 * has failed, or that a protocol has detected timeouts to a particular
 * destination.
 */
void
rt_missmsg(type, rtinfo, flags, error)
	int type, flags, error;
	register struct rt_addrinfo *rtinfo;
{
	register struct rt_msghdr *rtm;
	register struct mbuf *m;
	struct sockaddr *sa = rtinfo->rti_info[RTAX_DST];

	if (route_cb.any_count == 0)
		return;
	m = rt_msg1(type, rtinfo);
	if (m == 0)
		return;
	rtm = mtod(m, struct rt_msghdr *);
	rtm->rtm_flags = RTF_DONE | flags;
	rtm->rtm_errno = error;
	rtm->rtm_addrs = rtinfo->rti_addrs;
	route_proto.sp_protocol = sa ? sa->sa_family : 0;
	raw_input(m, &route_proto, &route_src, &route_dst);
}

/*
 * This routine is called to generate a message from the routing
 * socket indicating that the status of a network interface has changed.
 */
void
rt_ifmsg(ifp)
	register struct ifnet *ifp;
{
	register struct if_msghdr *ifm;
	struct mbuf *m;
	struct rt_addrinfo info;

	if (route_cb.any_count == 0)
		return;
	bzero((caddr_t)&info, sizeof(info));
	m = rt_msg1(RTM_IFINFO, &info);
	if (m == 0)
		return;
	ifm = mtod(m, struct if_msghdr *);
	ifm->ifm_index = ifp->if_index;
	ifm->ifm_flags = (u_short)ifp->if_flags;
	ifm->ifm_data = ifp->if_data;
	ifm->ifm_addrs = 0;
	route_proto.sp_protocol = 0;
	raw_input(m, &route_proto, &route_src, &route_dst);
}

/*
 * This is called to generate messages from the routing socket
 * indicating a network interface has had addresses associated with it.
 * if we ever reverse the logic and replace messages TO the routing
 * socket indicate a request to configure interfaces, then it will
 * be unnecessary as the routing socket will automatically generate
 * copies of it.
 */
void
rt_newaddrmsg(cmd, ifa, error, rt)
	int cmd, error;
	register struct ifaddr *ifa;
	register struct rtentry *rt;
{
	struct rt_addrinfo info;
	struct sockaddr *sa = 0;
	int pass;
	struct mbuf *m = 0;
	struct ifnet *ifp = ifa->ifa_ifp;

	if (route_cb.any_count == 0)
		return;
	for (pass = 1; pass < 3; pass++) {
		bzero((caddr_t)&info, sizeof(info));
		if ((cmd == RTM_ADD && pass == 1) ||
		    (cmd == RTM_DELETE && pass == 2)) {
			register struct ifa_msghdr *ifam;
			int ncmd = cmd == RTM_ADD ? RTM_NEWADDR : RTM_DELADDR;

			ifaaddr = sa = ifa->ifa_addr;
			ifpaddr = ifp->if_addrhead.tqh_first->ifa_addr;
			netmask = ifa->ifa_netmask;
			brdaddr = ifa->ifa_dstaddr;
			if ((m = rt_msg1(ncmd, &info)) == NULL)
				continue;
			ifam = mtod(m, struct ifa_msghdr *);
			ifam->ifam_index = ifp->if_index;
			ifam->ifam_metric = ifa->ifa_metric;
			ifam->ifam_flags = ifa->ifa_flags;
			ifam->ifam_addrs = info.rti_addrs;
		}
		if ((cmd == RTM_ADD && pass == 2) ||
		    (cmd == RTM_DELETE && pass == 1)) {
			register struct rt_msghdr *rtm;

			if (rt == 0)
				continue;
			netmask = rt_mask(rt);
			dst = sa = rt_key(rt);
			gate = rt->rt_gateway;
			if ((m = rt_msg1(cmd, &info)) == NULL)
				continue;
			rtm = mtod(m, struct rt_msghdr *);
			rtm->rtm_index = ifp->if_index;
			rtm->rtm_flags |= rt->rt_flags;
			rtm->rtm_errno = error;
			rtm->rtm_addrs = info.rti_addrs;
		}
		route_proto.sp_protocol = sa ? sa->sa_family : 0;
		raw_input(m, &route_proto, &route_src, &route_dst);
	}
}

/*
 * This is the analogue to the rt_newaddrmsg which performs the same
 * function but for multicast group memberhips.  This is easier since
 * there is no route state to worry about.
 */
void
rt_newmaddrmsg(cmd, ifma)
	int cmd;
	struct ifmultiaddr *ifma;
{
	struct rt_addrinfo info;
	struct mbuf *m = 0;
	struct ifnet *ifp = ifma->ifma_ifp;
	struct ifma_msghdr *ifmam;

	if (route_cb.any_count == 0)
		return;

	bzero((caddr_t)&info, sizeof(info));
	ifaaddr = ifma->ifma_addr;
	if (ifp && ifp->if_addrhead.tqh_first)
		ifpaddr = ifp->if_addrhead.tqh_first->ifa_addr;
	else
		ifpaddr = NULL;
	/*
	 * If a link-layer address is present, present it as a ``gateway''
	 * (similarly to how ARP entries, e.g., are presented).
	 */
	gate = ifma->ifma_lladdr;
	if ((m = rt_msg1(cmd, &info)) == NULL)
		return;
	ifmam = mtod(m, struct ifma_msghdr *);
	ifmam->ifmam_index = ifp->if_index;
	ifmam->ifmam_addrs = info.rti_addrs;
	route_proto.sp_protocol = ifma->ifma_addr->sa_family;
	raw_input(m, &route_proto, &route_src, &route_dst);
}

/*
 * This is used in dumping the kernel table via sysctl().
 */
int
sysctl_dumpentry(rn, vw)
	struct radix_node *rn;
	void *vw;
{
	register struct walkarg *w = vw;
	register struct rtentry *rt = (struct rtentry *)rn;
	int error = 0, size;
	struct rt_addrinfo info;

	if (w->w_op == NET_RT_FLAGS && !(rt->rt_flags & w->w_arg))
		return 0;
	bzero((caddr_t)&info, sizeof(info));
	dst = rt_key(rt);
	gate = rt->rt_gateway;
	netmask = rt_mask(rt);
	genmask = rt->rt_genmask;
	size = rt_msg2(RTM_GET, &info, 0, w);
	if (w->w_req && w->w_tmem) {
		register struct rt_msghdr *rtm = (struct rt_msghdr *)w->w_tmem;

		rtm->rtm_flags = rt->rt_flags;
		rtm->rtm_use = rt->rt_use;
		rtm->rtm_rmx = rt->rt_rmx;
		rtm->rtm_index = rt->rt_ifp->if_index;
		rtm->rtm_errno = rtm->rtm_pid = rtm->rtm_seq = 0;
		rtm->rtm_addrs = info.rti_addrs;
		error = SYSCTL_OUT(w->w_req, (caddr_t)rtm, size);
		return (error);
	}
	return (error);
}

int
sysctl_iflist(af, w)
	int	af;
	register struct	walkarg *w;
{
	register struct ifnet *ifp;
	register struct ifaddr *ifa;
	struct	rt_addrinfo info;
	int	len, error = 0;

	bzero((caddr_t)&info, sizeof(info));
	for (ifp = ifnet.tqh_first; ifp; ifp = ifp->if_link.tqe_next) {
		if (w->w_arg && w->w_arg != ifp->if_index)
			continue;
		ifa = ifp->if_addrhead.tqh_first;
		ifpaddr = ifa->ifa_addr;
		len = rt_msg2(RTM_IFINFO, &info, (caddr_t)0, w);
		ifpaddr = 0;
		if (w->w_req && w->w_tmem) {
			register struct if_msghdr *ifm;

			ifm = (struct if_msghdr *)w->w_tmem;
			ifm->ifm_index = ifp->if_index;
			ifm->ifm_flags = (u_short)ifp->if_flags;
			ifm->ifm_data = ifp->if_data;
			ifm->ifm_addrs = info.rti_addrs;
			error = SYSCTL_OUT(w->w_req,(caddr_t)ifm, len);
			if (error)
				return (error);
		}
		while ((ifa = ifa->ifa_link.tqe_next) != 0) {
			if (af && af != ifa->ifa_addr->sa_family)
				continue;
#ifndef __APPLE__
			if (curproc->p_prison && prison_if(curproc, ifa->ifa_addr))
				continue;
#endif
			ifaaddr = ifa->ifa_addr;
			netmask = ifa->ifa_netmask;
			brdaddr = ifa->ifa_dstaddr;
			len = rt_msg2(RTM_NEWADDR, &info, 0, w);
			if (w->w_req && w->w_tmem) {
				register struct ifa_msghdr *ifam;

				ifam = (struct ifa_msghdr *)w->w_tmem;
				ifam->ifam_index = ifa->ifa_ifp->if_index;
				ifam->ifam_flags = ifa->ifa_flags;
				ifam->ifam_metric = ifa->ifa_metric;
				ifam->ifam_addrs = info.rti_addrs;
				error = SYSCTL_OUT(w->w_req, w->w_tmem, len);
				if (error)
					return (error);
			}
		}
		ifaaddr = netmask = brdaddr = 0;
	}
	return (0);
}

static int
sysctl_rtsock SYSCTL_HANDLER_ARGS
{
	int	*name = (int *)arg1;
	u_int	namelen = arg2;
	register struct radix_node_head *rnh;
	int	i, s, error = EINVAL;
	u_char  af;
	struct	walkarg w;

	name ++;
	namelen--;
	if (req->newptr)
		return (EPERM);
	if (namelen != 3)
		return (EINVAL);
	af = name[0];
	Bzero(&w, sizeof(w));
	w.w_op = name[1];
	w.w_arg = name[2];
	w.w_req = req;

	s = splnet();
	switch (w.w_op) {

	case NET_RT_DUMP:
	case NET_RT_FLAGS:
		for (i = 1; i <= AF_MAX; i++)
			if ((rnh = rt_tables[i]) && (af == 0 || af == i) &&
			    (error = rnh->rnh_walktree(rnh,
							sysctl_dumpentry, &w)))
				break;
		break;

	case NET_RT_IFLIST:
		error = sysctl_iflist(af, &w);
	}
	splx(s);
	if (w.w_tmem)
		FREE(w.w_tmem, M_RTABLE);
	return (error);
}

SYSCTL_NODE(_net, PF_ROUTE, routetable, CTLFLAG_RD, sysctl_rtsock, "");

/*
 * Definitions of protocols supported in the ROUTE domain.
 */

struct domain routedomain;		/* or at least forward */

static struct protosw routesw[] = {
{ SOCK_RAW,	&routedomain,	0,		PR_ATOMIC|PR_ADDR,
  0,		route_output,	raw_ctlinput,	0,
  0,
  raw_init,	0,		0,		0,
  0, &route_usrreqs, 0, 0
}
};

struct domain routedomain =
    { PF_ROUTE, "route", route_init, 0, 0,
      routesw};

DOMAIN_SET(route);

