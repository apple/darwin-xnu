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
/*	$FreeBSD: src/sys/net/if_gif.c,v 1.4.2.6 2001/07/24 19:10:18 brooks Exp $	*/
/*	$KAME: if_gif.c,v 1.47 2001/05/01 05:28:42 itojun Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/syslog.h>
#include <sys/protosw.h>
#include <kern/cpu_number.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/bpf.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#if	INET
#include <netinet/in_var.h>
#include <netinet/in_gif.h>
#include <netinet/ip_var.h>
#endif	/* INET */

#if INET6
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_gif.h>
#include <netinet6/ip6protosw.h>
#endif /* INET6 */

#include <netinet/ip_encap.h>
#include <net/dlil.h>
#include <net/if_gif.h>

#include <net/net_osdep.h>

#define GIFNAME		"gif"
#define GIFDEV		"if_gif"
#define GIF_MAXUNIT	0x7fff	/* ifp->if_unit is only 15 bits */

#ifndef __APPLE__
static MALLOC_DEFINE(M_GIF, "gif", "Generic Tunnel Interface");
#endif

TAILQ_HEAD(gifhead, gif_softc) gifs = TAILQ_HEAD_INITIALIZER(gifs);

#ifdef __APPLE__
void gifattach(void);
int gif_pre_output(struct ifnet *ifp, u_long protocol_family, struct mbuf **m0,
				   const struct sockaddr *dst, caddr_t rt, char *frame, char *address);
static void gif_create_dev(void);
static int gif_encapcheck(const struct mbuf*, int, int, void*);


int ngif = 0;		/* number of interfaces */
#endif

#if INET
struct protosw in_gif_protosw =
{ SOCK_RAW,	0,	0/*IPPROTO_IPV[46]*/,	PR_ATOMIC|PR_ADDR,
  in_gif_input,	0,	0,		0,
  0,
  0,		0,	0,	0,	
  0,
  &rip_usrreqs,
  0,		rip_unlock,	0
};
#endif
#if INET6
struct ip6protosw in6_gif_protosw =
{ SOCK_RAW,	0,	0/*IPPROTO_IPV[46]*/,	PR_ATOMIC|PR_ADDR,
  in6_gif_input, 0,		0,		0,
  0,
  0,		0,		0,		0,
  0,  
  &rip6_usrreqs,
  0,		rip_unlock,		0,

};
#endif

#ifndef MAX_GIF_NEST
/*
 * This macro controls the upper limitation on nesting of gif tunnels.
 * Since, setting a large value to this macro with a careless configuration
 * may introduce system crash, we don't allow any nestings by default.
 * If you need to configure nested gif tunnels, you can define this macro
 * in your kernel configuration file. However, if you do so, please be
 * careful to configure the tunnels so that it won't make a loop.
 */
#define MAX_GIF_NEST 1
#endif
static int max_gif_nesting = MAX_GIF_NEST;



#ifdef __APPLE__
/*
 * Theory of operation: initially, one gif interface is created.
 * Any time a gif interface is configured, if there are no other
 * unconfigured gif interfaces, a new gif interface is created.
 * BSD uses the clone mechanism to dynamically create more
 * gif interfaces.
 *
 * We have some extra glue to support DLIL.
 */

/* GIF interface module support */
int gif_demux(
    struct ifnet *ifp,
    struct mbuf  *m,
    char         *frame_header,
    u_long *protocol_family)
{
	struct gif_softc* gif = (struct gif_softc*)ifp->if_softc;
	
	/* Only one protocol may be attached to a gif interface. */
	*protocol_family = gif->gif_proto;
	
	return 0;
}

static
int  gif_add_proto(struct ifnet *ifp, u_long protocol_family, struct ddesc_head_str *desc_head)
{
	/* Only one protocol may be attached at a time */
	struct gif_softc* gif = (struct gif_softc*)ifp->if_softc;

	if (gif->gif_proto != 0)
		printf("gif_add_proto: request add_proto for gif%d\n", gif->gif_if.if_unit);

	gif->gif_proto = protocol_family;

	return 0;
}

static
int  gif_del_proto(struct ifnet *ifp, u_long protocol_family)
{
	if (((struct gif_softc*)ifp)->gif_proto == protocol_family)
		((struct gif_softc*)ifp)->gif_proto = 0;
	else
		return ENOENT;

	return 0;
}

/* Glue code to attach inet to a gif interface through DLIL */
int
gif_attach_proto_family(
	struct ifnet *ifp,
	u_long protocol_family)
{
    struct dlil_proto_reg_str   reg;
    int   stat;

	bzero(&reg, sizeof(reg));
    TAILQ_INIT(&reg.demux_desc_head);
    reg.interface_family = ifp->if_family;
    reg.unit_number      = ifp->if_unit;
    reg.input            = gif_input;
    reg.pre_output       = gif_pre_output;
    reg.protocol_family  = protocol_family;

    stat = dlil_attach_protocol(&reg);
    if (stat && stat != EEXIST) {
        panic("gif_attach_proto_family can't attach interface fam=%d\n", protocol_family);
    }

    return stat;
}

#endif

/* Function to setup the first gif interface */
void
gifattach(void)
{
	int error;

	/* Init the list of interfaces */
	TAILQ_INIT(&gifs);

	/* Register protocol registration functions */
	if ( error = dlil_reg_proto_module(AF_INET, APPLE_IF_FAM_GIF, gif_attach_proto_family, NULL) != 0)
		printf("dlil_reg_proto_module failed for AF_INET error=%d\n", error);
	
	if ( error = dlil_reg_proto_module(AF_INET6, APPLE_IF_FAM_GIF, gif_attach_proto_family, NULL) != 0)
		printf("dlil_reg_proto_module failed for AF_INET6 error=%d\n", error);

	/* Create first device */
	gif_create_dev();
}

/* Creates another gif device if there are none free */
static void
gif_create_dev(void)
{
	struct gif_softc *sc;
	
	
	/* Can't create more than GIF_MAXUNIT */
	if (ngif >= GIF_MAXUNIT)
		return;
	
	/* Check for unused gif interface */
	TAILQ_FOREACH(sc, &gifs, gif_link) {
		/* If unused, return, no need to create a new interface */
		if ((sc->gif_if.if_flags & IFF_RUNNING) == 0)
			return;
	}

	sc = _MALLOC(sizeof(struct gif_softc), M_DEVBUF, M_WAITOK);
	if (sc == NULL) {
		log(LOG_ERR, "gifattach: failed to allocate gif%d\n", ngif);
		return;
	}

	bzero(sc, sizeof(struct gif_softc));
	sc->gif_if.if_softc	= sc;
	sc->gif_if.if_name	= GIFNAME;
	sc->gif_if.if_unit	= ngif;
	
	sc->encap_cookie4 = sc->encap_cookie6 = NULL;
#ifdef INET
	sc->encap_cookie4 = encap_attach_func(AF_INET, -1,
	    gif_encapcheck, &in_gif_protosw, sc);
	if (sc->encap_cookie4 == NULL) {
		printf("%s: unable to attach encap4\n", if_name(&sc->gif_if));
		FREE(sc, M_DEVBUF);
		return;
	}
#endif
#ifdef INET6
	sc->encap_cookie6 = encap_attach_func(AF_INET6, -1,
	    gif_encapcheck, (struct protosw*)&in6_gif_protosw, sc);
	if (sc->encap_cookie6 == NULL) {
		if (sc->encap_cookie4) {
			encap_detach(sc->encap_cookie4);
			sc->encap_cookie4 = NULL;
		}
		printf("%s: unable to attach encap6\n", if_name(&sc->gif_if));
		FREE(sc, M_DEVBUF);
		return;
	}
#endif
	
	sc->gif_called = 0;
	sc->gif_if.if_family= APPLE_IF_FAM_GIF;
	sc->gif_if.if_mtu	= GIF_MTU;
	sc->gif_if.if_flags  = IFF_POINTOPOINT | IFF_MULTICAST;
#if 0
	/* turn off ingress filter */
	sc->gif_if.if_flags  |= IFF_LINK2;
#endif
	sc->gif_if.if_demux = gif_demux;
	sc->gif_if.if_ioctl	= gif_ioctl;
	sc->gif_if.if_output = NULL;	/* pre_output returns error or EJUSTRETURN */
	sc->gif_if.if_type   = IFT_GIF;
	sc->gif_if.if_add_proto = gif_add_proto;
	sc->gif_if.if_del_proto = gif_del_proto;
	dlil_if_attach(&sc->gif_if);
	bpfattach(&sc->gif_if, DLT_NULL, sizeof(u_int));
	TAILQ_INSERT_TAIL(&gifs, sc, gif_link);
	ngif++;
}

static int
gif_encapcheck(m, off, proto, arg)
	const struct mbuf *m;
	int off;
	int proto;
	void *arg;
{
	struct ip ip;
	struct gif_softc *sc;

	sc = (struct gif_softc *)arg;
	if (sc == NULL)
		return 0;

	if ((sc->gif_if.if_flags & IFF_UP) == 0)
		return 0;

	/* no physical address */
	if (!sc->gif_psrc || !sc->gif_pdst)
		return 0;

	switch (proto) {
#if INET
	case IPPROTO_IPV4:
		break;
#endif
#if INET6
	case IPPROTO_IPV6:
		break;
#endif
	default:
		return 0;
	}

	/* LINTED const cast */
	m_copydata((struct mbuf *)m, 0, sizeof(ip), (caddr_t)&ip);

	switch (ip.ip_v) {
#if INET
	case 4:
		if (sc->gif_psrc->sa_family != AF_INET ||
		    sc->gif_pdst->sa_family != AF_INET)
			return 0;
		return gif_encapcheck4(m, off, proto, arg);
#endif
#if INET6
	case 6:
		if (sc->gif_psrc->sa_family != AF_INET6 ||
		    sc->gif_pdst->sa_family != AF_INET6)
			return 0;
		return gif_encapcheck6(m, off, proto, arg);
#endif
	default:
		return 0;
	}
}

int
gif_pre_output(
	struct ifnet *ifp,
	u_long protocol_family,
	struct mbuf **m0,
	const struct sockaddr *dst,
	caddr_t rt,
	char *frame,
	char *address)
{
	struct gif_softc *sc = (struct gif_softc*)ifp;
	register struct mbuf * m = *m0;
	int error = 0;
	
	/*
	 * gif may cause infinite recursion calls when misconfigured.
	 * We'll prevent this by introducing upper limit.
	 * XXX: this mechanism may introduce another problem about
	 *      mutual exclusion of the variable CALLED, especially if we
	 *      use kernel thread.
	 */
	if (++sc->gif_called > max_gif_nesting) {
		log(LOG_NOTICE,
		    "gif_output: recursively called too many times(%d)\n",
		    sc->gif_called);
		m_freem(m);	/* free it here not in dlil_output*/
		error = EIO;	/* is there better errno? */
		goto end;
	}

	ifnet_touch_lastchange(ifp);
	m->m_flags &= ~(M_BCAST|M_MCAST);
	if (!(ifp->if_flags & IFF_UP) ||
	    sc->gif_psrc == NULL || sc->gif_pdst == NULL) {
		m_freem(m);	/* free it here not in dlil_output */
		error = ENETDOWN;
		goto end;
	}

	if (ifp->if_bpf) {
		/*
		 * We need to prepend the address family as
		 * a four byte field.  Cons up a dummy header
		 * to pacify bpf.  This is safe because bpf
		 * will only read from the mbuf (i.e., it won't
		 * try to free it or keep a pointer a to it).
		 */
		struct mbuf m0;
		u_int32_t protocol_family = dst->sa_family;

		m0.m_next = m;
		m0.m_len = 4;
		m0.m_data = (char *)&protocol_family;
		
		bpf_mtap(ifp, &m0);
	}
	ifp->if_opackets++;	
	ifp->if_obytes += m->m_pkthdr.len;

	/* inner AF-specific encapsulation */

	/* XXX should we check if our outer source is legal? */

	/* dispatch to output logic based on outer AF */
	switch (sc->gif_psrc->sa_family) {
#if INET
	case AF_INET:
		error = in_gif_output(ifp, dst->sa_family, m, (struct rtentry*)rt);
		break;
#endif
#if INET6
	case AF_INET6:
		error = in6_gif_output(ifp, dst->sa_family, m, (struct rtentry*)rt);
		break;
#endif
	default:
		error = ENETDOWN;
		goto end;
	}

  end:
	sc->gif_called = 0;		/* reset recursion counter */
	if (error) {
		/* the mbuf was freed either by in_gif_output or in here */
		*m0 = NULL; /* avoid getting dlil_output freeing it */
		ifp->if_oerrors++;
	}
	if (error == 0) 
		error = EJUSTRETURN; /* if no error, packet got sent already */
	return error;
}

int
gif_input(
	struct mbuf *m,
	char* frame_header,
	struct ifnet* gifp,
	u_long protocol_family,
	int sync_ok)
{

	if (gifp == NULL) {
		/* just in case */
		m_freem(m);
		return;
	}

	if (m->m_pkthdr.rcvif)
		m->m_pkthdr.rcvif = gifp;
	
	if (gifp->if_bpf) {
		/*
		 * We need to prepend the address family as
		 * a four byte field.  Cons up a dummy header
		 * to pacify bpf.  This is safe because bpf
		 * will only read from the mbuf (i.e., it won't
		 * try to free it or keep a pointer a to it).
		 */
		struct mbuf m0;
		u_int32_t protocol_family1 = protocol_family;
		
		m0.m_next = m;
		m0.m_len = 4;
		m0.m_data = (char *)&protocol_family1;
		
		bpf_mtap(gifp, &m0);
	}

	/*
	 * Put the packet to the network layer input queue according to the
	 * specified address family.
	 * Note: older versions of gif_input directly called network layer
	 * input functions, e.g. ip6_input, here. We changed the policy to
	 * prevent too many recursive calls of such input functions, which
	 * might cause kernel panic. But the change may introduce another
	 * problem; if the input queue is full, packets are discarded.
	 * We believed it rarely occurs and changed the policy. If we find
	 * it occurs more times than we thought, we may change the policy
	 * again.
	 */
	proto_input(protocol_family, m);
	gifp->if_ipackets++;
	gifp->if_ibytes += m->m_pkthdr.len;

	return (0);
}

/* XXX how should we handle IPv6 scope on SIOC[GS]IFPHYADDR? */
int
gif_ioctl(ifp, cmd, data)
	struct ifnet *ifp;
	u_long cmd;
	void* data;
{
	struct gif_softc *sc  = (struct gif_softc*)ifp;
	struct ifreq     *ifr = (struct ifreq*)data;
	int error = 0, size;
	struct sockaddr *dst, *src;
	struct sockaddr *sa;
	int s;
	struct ifnet *ifp2;
	struct gif_softc *sc2;
		
	switch (cmd) {
	case SIOCSIFADDR:
		break;
		
	case SIOCSIFDSTADDR:
		break;

	case SIOCADDMULTI:
	case SIOCDELMULTI:
		break;

#ifdef	SIOCSIFMTU /* xxx */
	case SIOCGIFMTU:
		break;

	case SIOCSIFMTU:
		{
			u_long mtu;
			mtu = ifr->ifr_mtu;
			if (mtu < GIF_MTU_MIN || mtu > GIF_MTU_MAX) {
				return (EINVAL);
			}
			ifp->if_mtu = mtu;
		}
		break;
#endif /* SIOCSIFMTU */

	case SIOCSIFPHYADDR:
#if INET6
	case SIOCSIFPHYADDR_IN6:
#endif /* INET6 */
	case SIOCSLIFPHYADDR:
		switch (cmd) {
#if INET
		case SIOCSIFPHYADDR:
			src = (struct sockaddr *)
				&(((struct in_aliasreq *)data)->ifra_addr);
			dst = (struct sockaddr *)
				&(((struct in_aliasreq *)data)->ifra_dstaddr);
			break;
#endif
#if INET6
		case SIOCSIFPHYADDR_IN6:
			src = (struct sockaddr *)
				&(((struct in6_aliasreq *)data)->ifra_addr);
			dst = (struct sockaddr *)
				&(((struct in6_aliasreq *)data)->ifra_dstaddr);
			break;
#endif
		case SIOCSLIFPHYADDR:
			src = (struct sockaddr *)
				&(((struct if_laddrreq *)data)->addr);
			dst = (struct sockaddr *)
				&(((struct if_laddrreq *)data)->dstaddr);
		}

		/* sa_family must be equal */
		if (src->sa_family != dst->sa_family)
			return EINVAL;

		/* validate sa_len */
		switch (src->sa_family) {
#if INET
		case AF_INET:
			if (src->sa_len != sizeof(struct sockaddr_in))
				return EINVAL;
			break;
#endif
#if INET6
		case AF_INET6:
			if (src->sa_len != sizeof(struct sockaddr_in6))
				return EINVAL;
			break;
#endif
		default:
			return EAFNOSUPPORT;
		}
		switch (dst->sa_family) {
#if INET
		case AF_INET:
			if (dst->sa_len != sizeof(struct sockaddr_in))
				return EINVAL;
			break;
#endif
#if INET6
		case AF_INET6:
			if (dst->sa_len != sizeof(struct sockaddr_in6))
				return EINVAL;
			break;
#endif
		default:
			return EAFNOSUPPORT;
		}

		/* check sa_family looks sane for the cmd */
		switch (cmd) {
		case SIOCSIFPHYADDR:
			if (src->sa_family == AF_INET)
				break;
			return EAFNOSUPPORT;
#if INET6
		case SIOCSIFPHYADDR_IN6:
			if (src->sa_family == AF_INET6)
				break;
			return EAFNOSUPPORT;
#endif /* INET6 */
		case SIOCSLIFPHYADDR:
			/* checks done in the above */
			break;
		}

		ifnet_head_lock_shared();
		TAILQ_FOREACH(ifp2, &ifnet_head, if_link) {
			if (strcmp(ifp2->if_name, GIFNAME) != 0)
				continue;
			sc2 = ifp2->if_softc;
			if (sc2 == sc)
				continue;
			if (!sc2->gif_pdst || !sc2->gif_psrc)
				continue;
			if (sc2->gif_pdst->sa_family != dst->sa_family ||
			    sc2->gif_pdst->sa_len != dst->sa_len ||
			    sc2->gif_psrc->sa_family != src->sa_family ||
			    sc2->gif_psrc->sa_len != src->sa_len)
				continue;
#ifndef XBONEHACK
			/* can't configure same pair of address onto two gifs */
			if (bcmp(sc2->gif_pdst, dst, dst->sa_len) == 0 &&
			    bcmp(sc2->gif_psrc, src, src->sa_len) == 0) {
				error = EADDRNOTAVAIL;
				ifnet_head_done();
				goto bad;
			}
#endif

			/* can't configure multiple multi-dest interfaces */
#define multidest(x) \
	(((struct sockaddr_in *)(x))->sin_addr.s_addr == INADDR_ANY)
#if INET6
#define multidest6(x) \
	(IN6_IS_ADDR_UNSPECIFIED(&((struct sockaddr_in6 *)(x))->sin6_addr))
#endif
			if (dst->sa_family == AF_INET &&
			    multidest(dst) && multidest(sc2->gif_pdst)) {
				error = EADDRNOTAVAIL;
				ifnet_head_done();
				goto bad;
			}
#if INET6
			if (dst->sa_family == AF_INET6 &&
			    multidest6(dst) && multidest6(sc2->gif_pdst)) {
				error = EADDRNOTAVAIL;
				ifnet_head_done();
				goto bad;
			}
#endif
		}
		ifnet_head_done();

		if (sc->gif_psrc)
			FREE((caddr_t)sc->gif_psrc, M_IFADDR);
		sa = (struct sockaddr *)_MALLOC(src->sa_len, M_IFADDR, M_WAITOK);
		bcopy((caddr_t)src, (caddr_t)sa, src->sa_len);
		sc->gif_psrc = sa;

		if (sc->gif_pdst)
			FREE((caddr_t)sc->gif_pdst, M_IFADDR);
		sa = (struct sockaddr *)_MALLOC(dst->sa_len, M_IFADDR, M_WAITOK);
		bcopy((caddr_t)dst, (caddr_t)sa, dst->sa_len);
		sc->gif_pdst = sa;

		ifp->if_flags |= IFF_RUNNING;

		s = splimp();
		if_up(ifp);	/* mark interface UP and send up RTM_IFINFO */
#ifdef __APPLE__
		/* Make sure at least one unused device is still available */
		gif_create_dev();
#endif
		splx(s);

		error = 0;
		break;

#ifdef SIOCDIFPHYADDR
	case SIOCDIFPHYADDR:
		if (sc->gif_psrc) {
			FREE((caddr_t)sc->gif_psrc, M_IFADDR);
			sc->gif_psrc = NULL;
		}
		if (sc->gif_pdst) {
			FREE((caddr_t)sc->gif_pdst, M_IFADDR);
			sc->gif_pdst = NULL;
		}
		/* change the IFF_{UP, RUNNING} flag as well? */
		break;
#endif
			
	case SIOCGIFPSRCADDR:
#if INET6
	case SIOCGIFPSRCADDR_IN6:
#endif /* INET6 */
		if (sc->gif_psrc == NULL) {
			error = EADDRNOTAVAIL;
			goto bad;
		}
		src = sc->gif_psrc;
		switch (cmd) {
#if INET
		case SIOCGIFPSRCADDR:
			dst = &ifr->ifr_addr;
			size = sizeof(ifr->ifr_addr);
			break;
#endif /* INET */
#if INET6
		case SIOCGIFPSRCADDR_IN6:
			dst = (struct sockaddr *)
				&(((struct in6_ifreq *)data)->ifr_addr);
			size = sizeof(((struct in6_ifreq *)data)->ifr_addr);
			break;
#endif /* INET6 */
		default:
			error = EADDRNOTAVAIL;
			goto bad;
		}
		if (src->sa_len > size)
			return EINVAL;
		bcopy((caddr_t)src, (caddr_t)dst, src->sa_len);
		break;
			
	case SIOCGIFPDSTADDR:
#if INET6
	case SIOCGIFPDSTADDR_IN6:
#endif /* INET6 */
		if (sc->gif_pdst == NULL) {
			error = EADDRNOTAVAIL;
			goto bad;
		}
		src = sc->gif_pdst;
		switch (cmd) {
#if INET
		case SIOCGIFPDSTADDR:
			dst = &ifr->ifr_addr;
			size = sizeof(ifr->ifr_addr);
			break;
#endif /* INET */
#if INET6
		case SIOCGIFPDSTADDR_IN6:
			dst = (struct sockaddr *)
				&(((struct in6_ifreq *)data)->ifr_addr);
			size = sizeof(((struct in6_ifreq *)data)->ifr_addr);
			break;
#endif /* INET6 */
		default:
			error = EADDRNOTAVAIL;
			goto bad;
		}
		if (src->sa_len > size)
			return EINVAL;
		bcopy((caddr_t)src, (caddr_t)dst, src->sa_len);
		break;

	case SIOCGLIFPHYADDR:
		if (sc->gif_psrc == NULL || sc->gif_pdst == NULL) {
			error = EADDRNOTAVAIL;
			goto bad;
		}

		/* copy src */
		src = sc->gif_psrc;
		dst = (struct sockaddr *)
			&(((struct if_laddrreq *)data)->addr);
		size = sizeof(((struct if_laddrreq *)data)->addr);
		if (src->sa_len > size)
			return EINVAL;
		bcopy((caddr_t)src, (caddr_t)dst, src->sa_len);

		/* copy dst */
		src = sc->gif_pdst;
		dst = (struct sockaddr *)
			&(((struct if_laddrreq *)data)->dstaddr);
		size = sizeof(((struct if_laddrreq *)data)->dstaddr);
		if (src->sa_len > size)
			return EINVAL;
		bcopy((caddr_t)src, (caddr_t)dst, src->sa_len);
		break;

	case SIOCSIFFLAGS:
		/* if_ioctl() takes care of it */
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}
 bad:
	return error;
}

#ifndef __APPLE__
/* This function is not used in our stack */
void
gif_delete_tunnel(sc)
	struct gif_softc *sc;
{
	/* XXX: NetBSD protects this function with splsoftnet() */

	if (sc->gif_psrc) {
		FREE((caddr_t)sc->gif_psrc, M_IFADDR);
		sc->gif_psrc = NULL;
	}
	if (sc->gif_pdst) {
		FREE((caddr_t)sc->gif_pdst, M_IFADDR);
		sc->gif_pdst = NULL;
	}
	/* change the IFF_UP flag as well? */
}
#endif
