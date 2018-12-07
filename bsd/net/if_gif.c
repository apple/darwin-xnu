/*
 * Copyright (c) 2000-2018 Apple Inc. All rights reserved.
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
/* $FreeBSD: src/sys/net/if_gif.c,v 1.4.2.6 2001/07/24 19:10:18 brooks Exp $ */
/* $KAME: if_gif.c,v 1.47 2001/05/01 05:28:42 itojun Exp $ */

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
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2006 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
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
#include <kern/zalloc.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/bpf.h>
#include <net/kpi_protocol.h>
#include <net/kpi_interface.h>
#include <net/init.h>

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

#if CONFIG_MACF_NET
#include <security/mac_framework.h>
#endif

#define	GIFNAME		"gif"
#define	GIFDEV		"if_gif"

#define	GIF_MAXUNIT	IF_MAXUNIT
#define	GIF_ZONE_MAX_ELEM	MIN(IFNETS_MAX, GIF_MAXUNIT)

/* gif lock variables */
static lck_grp_t	*gif_mtx_grp;
static lck_grp_attr_t	*gif_mtx_grp_attr;
static lck_attr_t	*gif_mtx_attr;
decl_lck_mtx_data(static, gif_mtx_data);
static lck_mtx_t	*gif_mtx = &gif_mtx_data;

TAILQ_HEAD(gifhead, gif_softc) gifs = TAILQ_HEAD_INITIALIZER(gifs);

static int gif_encapcheck(const struct mbuf *, int, int, void *);
static errno_t gif_output(ifnet_t ifp, mbuf_t m);
static errno_t gif_input(ifnet_t ifp, protocol_family_t protocol_family,
    mbuf_t m, char *frame_header);
static errno_t gif_ioctl(ifnet_t ifp, u_long cmd, void *data);

static int ngif = 0;		/* number of interfaces */

#if INET
static struct protosw in_gif_protosw =
{
	.pr_type =		SOCK_RAW,
	.pr_protocol =		0, /* IPPROTO_IPV[46] */
	.pr_flags =		PR_ATOMIC|PR_ADDR,
	.pr_input =		in_gif_input,
	.pr_usrreqs =		&rip_usrreqs,
	.pr_unlock =		rip_unlock,
};
#endif
#if INET6
static struct ip6protosw in6_gif_protosw =
{
	.pr_type =		SOCK_RAW,
	.pr_protocol =		0, /* IPPROTO_IPV[46] */
	.pr_flags =		PR_ATOMIC|PR_ADDR,
	.pr_input =		in6_gif_input,
	.pr_usrreqs =		&rip6_usrreqs,
	.pr_unlock =		rip_unlock,
};
#endif

static int gif_remove(struct ifnet *);
static int gif_clone_create(struct if_clone *, uint32_t, void *);
static int gif_clone_destroy(struct ifnet *);
static void gif_delete_tunnel(struct gif_softc *);
static void gif_detach(struct ifnet *);

static struct if_clone gif_cloner =
    IF_CLONE_INITIALIZER(GIFNAME, gif_clone_create, gif_clone_destroy,
        0, GIF_MAXUNIT, GIF_ZONE_MAX_ELEM, sizeof(struct gif_softc));
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
static int
gif_demux(
	ifnet_t ifp,
	__unused mbuf_t m,
	__unused char *frame_header,
	protocol_family_t *protocol_family)
{
	struct gif_softc *sc = ifnet_softc(ifp);

	GIF_LOCK(sc);
	/* Only one protocol may be attached to a gif interface. */
	*protocol_family = sc->gif_proto;
	GIF_UNLOCK(sc);

	return (0);
}

static errno_t
gif_add_proto(
	ifnet_t ifp,
	protocol_family_t protocol_family,
	__unused const struct ifnet_demux_desc *demux_array,
	__unused u_int32_t demux_count)
{
	/* Only one protocol may be attached at a time */
	struct gif_softc *sc = ifnet_softc(ifp);

	GIF_LOCK(sc);
	if (sc->gif_proto != 0)
		printf("gif_add_proto: request add_proto for gif%d\n",
		    ifnet_unit(ifp));

	sc->gif_proto = protocol_family;
	GIF_UNLOCK(sc);

	return (0);
}

static errno_t
gif_del_proto(
	ifnet_t ifp,
	protocol_family_t protocol_family)
{
	struct gif_softc *sc = ifnet_softc(ifp);

	GIF_LOCK(sc);
	if (sc->gif_proto == protocol_family)
		sc->gif_proto = 0;
	GIF_UNLOCK(sc);

	return (0);
}

/* Glue code to attach inet to a gif interface through DLIL */
static errno_t
gif_attach_proto_family(
	ifnet_t ifp,
	protocol_family_t protocol_family)
{
	struct ifnet_attach_proto_param reg;
	errno_t stat;

	bzero(&reg, sizeof (reg));
	reg.input = gif_input;

	stat = ifnet_attach_protocol(ifp, protocol_family, &reg);
	if (stat && stat != EEXIST) {
		printf("gif_attach_proto_family can't attach interface	\
		    fam=%d\n", protocol_family);
	}

	return (stat);
}

/* Function to setup the first gif interface */
void
gif_init(void)
{
	errno_t result;

	/* Initialize the list of interfaces */
	TAILQ_INIT(&gifs);

	/* Initialize the gif global lock */
	gif_mtx_grp_attr = lck_grp_attr_alloc_init();
	gif_mtx_grp = lck_grp_alloc_init("gif", gif_mtx_grp_attr);
	gif_mtx_attr = lck_attr_alloc_init();
	lck_mtx_init(gif_mtx, gif_mtx_grp, gif_mtx_attr);

	/* Register protocol registration functions */
	result = proto_register_plumber(PF_INET, APPLE_IF_FAM_GIF,
	    gif_attach_proto_family, NULL);
	if (result != 0)
		printf("proto_register_plumber failed for AF_INET error=%d\n",
		    result);

	result = proto_register_plumber(PF_INET6, APPLE_IF_FAM_GIF,
	    gif_attach_proto_family, NULL);
	if (result != 0)
		printf("proto_register_plumber failed for AF_INET6 error=%d\n",
		    result);

	result = if_clone_attach(&gif_cloner);
	if (result != 0)
		panic("%s: if_clone_attach() failed, error %d\n", __func__, result);

	gif_clone_create(&gif_cloner, 0, NULL);
}

static errno_t
gif_set_bpf_tap(
	ifnet_t ifp,
	bpf_tap_mode mode,
	bpf_packet_func callback)
{
	struct gif_softc *sc = ifnet_softc(ifp);

	GIF_LOCK(sc);
	sc->tap_mode = mode;
	sc->tap_callback = callback;
	GIF_UNLOCK(sc);

	return (0);
}

static void
gif_detach(struct ifnet *ifp)
{
	struct gif_softc *sc = ifp->if_softc;
	lck_mtx_destroy(&sc->gif_lock, gif_mtx_grp);
	if_clone_softc_deallocate(&gif_cloner, sc);
	ifp->if_softc = NULL;
	(void) ifnet_release(ifp);
}

static int
gif_clone_create(struct if_clone *ifc, uint32_t unit, __unused void *params)
{
	struct gif_softc *sc = NULL;
	struct ifnet_init_eparams gif_init_params;
	errno_t error = 0;

	lck_mtx_lock(gif_mtx);

	/* Can't create more than GIF_MAXUNIT */
	if (ngif >= GIF_MAXUNIT) {
		error = ENXIO;
		goto done;
	}

	sc = if_clone_softc_allocate(&gif_cloner);
	if (sc == NULL) {
		log(LOG_ERR, "gif_clone_create: failed to allocate gif%d\n",
		    unit);
		error = ENOBUFS;
		goto done;
	}

	/* use the interface name as the unique id for ifp recycle */
	snprintf(sc->gif_ifname, sizeof (sc->gif_ifname), "%s%d",
	    ifc->ifc_name, unit);

	lck_mtx_init(&sc->gif_lock, gif_mtx_grp, gif_mtx_attr);

	bzero(&gif_init_params, sizeof (gif_init_params));
	gif_init_params.ver = IFNET_INIT_CURRENT_VERSION;
	gif_init_params.len = sizeof (gif_init_params);
	gif_init_params.flags = IFNET_INIT_LEGACY;
	gif_init_params.uniqueid = sc->gif_ifname;
	gif_init_params.uniqueid_len = strlen(sc->gif_ifname);
	gif_init_params.name = GIFNAME;
	gif_init_params.unit = unit;
	gif_init_params.type = IFT_GIF;
	gif_init_params.family = IFNET_FAMILY_GIF;
	gif_init_params.output = gif_output;
	gif_init_params.demux = gif_demux;
	gif_init_params.add_proto = gif_add_proto;
	gif_init_params.del_proto = gif_del_proto;
	gif_init_params.softc = sc;
	gif_init_params.ioctl = gif_ioctl;
	gif_init_params.set_bpf_tap = gif_set_bpf_tap;
	gif_init_params.detach = gif_detach;

	error = ifnet_allocate_extended(&gif_init_params, &sc->gif_if);
	if (error != 0) {
		printf("gif_clone_create, ifnet_allocate failed - %d\n", error);
		if_clone_softc_deallocate(&gif_cloner, sc);
		error = ENOBUFS;
		goto done;
	}

	sc->encap_cookie4 = sc->encap_cookie6 = NULL;
#if INET
	sc->encap_cookie4 = encap_attach_func(AF_INET, -1,
			gif_encapcheck, &in_gif_protosw, sc);
	if (sc->encap_cookie4 == NULL) {
		printf("%s: unable to attach encap4\n", if_name(sc->gif_if));
		ifnet_release(sc->gif_if);
		if_clone_softc_deallocate(&gif_cloner, sc);
		error = ENOBUFS;
		goto done;
	}
#endif
#if INET6
	sc->encap_cookie6 = encap_attach_func(AF_INET6, -1,
	    gif_encapcheck, (struct protosw *)&in6_gif_protosw, sc);
	if (sc->encap_cookie6 == NULL) {
		if (sc->encap_cookie4) {
			encap_detach(sc->encap_cookie4);
			sc->encap_cookie4 = NULL;
		}
		printf("%s: unable to attach encap6\n", if_name(sc->gif_if));
		ifnet_release(sc->gif_if);
		if_clone_softc_deallocate(&gif_cloner, sc);
		error = ENOBUFS;
		goto done;
	}
#endif
	sc->gif_called = 0;
	ifnet_set_mtu(sc->gif_if, GIF_MTU);
	ifnet_set_flags(sc->gif_if, IFF_POINTOPOINT | IFF_MULTICAST, 0xffff);
#if 0
	/* turn off ingress filter */
	sc->gif_if.if_flags  |= IFF_LINK2;
#endif
	sc->gif_flags |= IFGIF_DETACHING;
	error = ifnet_attach(sc->gif_if, NULL);
	if (error != 0) {
		printf("gif_clone_create - ifnet_attach failed - %d\n", error);
		ifnet_release(sc->gif_if);
		if (sc->encap_cookie4) {
			encap_detach(sc->encap_cookie4);
			sc->encap_cookie4 = NULL;
		}
		if (sc->encap_cookie6) {
			encap_detach(sc->encap_cookie6);
			sc->encap_cookie6 = NULL;
		}
		if_clone_softc_deallocate(&gif_cloner, sc);
		goto done;
	}
#if CONFIG_MACF_NET
	mac_ifnet_label_init(&sc->gif_if);
#endif
	bpfattach(sc->gif_if, DLT_NULL, sizeof (u_int));
	sc->gif_flags &= ~IFGIF_DETACHING;
	TAILQ_INSERT_TAIL(&gifs, sc, gif_link);
	ngif++;
done:
	lck_mtx_unlock(gif_mtx);

	return (error);
}

static int
gif_remove(struct ifnet *ifp)
{
	int error = 0;
	struct gif_softc *sc = NULL;

	lck_mtx_lock(gif_mtx);
	sc = ifp->if_softc;

	if (sc == NULL) {
		error = EINVAL;
		goto done;
	}

	GIF_LOCK(sc);
	if (sc->gif_flags & IFGIF_DETACHING) {
		error = EINVAL;
		goto done;
	}

	sc->gif_flags |= IFGIF_DETACHING;
	TAILQ_REMOVE(&gifs, sc, gif_link);
	ngif--;

	gif_delete_tunnel(sc);
#ifdef INET6
	if (sc->encap_cookie6 != NULL) {
		error = encap_detach(sc->encap_cookie6);
		KASSERT(error == 0, ("gif_clone_destroy: Unexpected "
		    "error detaching encap_cookie6"));
	}
#endif
#ifdef INET
	if (sc->encap_cookie4 != NULL) {
		error = encap_detach(sc->encap_cookie4);
		KASSERT(error == 0, ("gif_clone_destroy: Unexpected "
		    "error detaching encap_cookie4"));
	}
#endif
done:
	if (sc != NULL)
		GIF_UNLOCK(sc);
	lck_mtx_unlock(gif_mtx);

	return (error);
}

static int
gif_clone_destroy(struct ifnet *ifp)
{
	int error = 0;

	error = gif_remove(ifp);
	if (error != 0) {
		printf("gif_clone_destroy: gif remove failed %d\n", error);
		return (error);
	}

	error = ifnet_set_flags(ifp, 0, IFF_UP);
	if (error != 0) {
		printf("gif_clone_destroy: ifnet_set_flags failed %d\n", error);
	}

	error = ifnet_detach(ifp);
	if (error != 0)
		panic("gif_clone_destroy: ifnet_detach(%p) failed %d\n", ifp,
		    error);
	return (0);
}

static int
gif_encapcheck(
	const struct mbuf *m,
	int off,
	int proto,
	void *arg)
{
	int error = 0;
	struct ip ip;
	struct gif_softc *sc;

	sc = (struct gif_softc *)arg;
	if (sc == NULL)
		return (error);

	GIF_LOCK(sc);
	if ((ifnet_flags(sc->gif_if) & IFF_UP) == 0)
		goto done;

	/* no physical address */
	if (!sc->gif_psrc || !sc->gif_pdst)
		goto done;

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
		goto done;
	}

	mbuf_copydata((struct mbuf *)(size_t)m, 0, sizeof (ip), &ip);

	switch (ip.ip_v) {
#if INET
	case 4:
		if (sc->gif_psrc->sa_family != AF_INET ||
		    sc->gif_pdst->sa_family != AF_INET)
			goto done;
		error = gif_encapcheck4(m, off, proto, arg);
#endif
#if INET6
	case 6:
		if (sc->gif_psrc->sa_family != AF_INET6 ||
		    sc->gif_pdst->sa_family != AF_INET6)
			goto done;
		error = gif_encapcheck6(m, off, proto, arg);
#endif
	default:
		goto done;
	}
done:
	GIF_UNLOCK(sc);
	return (error);
}

static errno_t
gif_output(
	ifnet_t ifp,
	mbuf_t m)
{
	struct gif_softc *sc = ifnet_softc(ifp);
	struct sockaddr *gif_psrc;
	struct sockaddr *gif_pdst;
	int error = 0;

	GIF_LOCK(sc);
	gif_psrc = sc->gif_psrc;
	gif_pdst = sc->gif_pdst;
	GIF_UNLOCK(sc);

	/*
	 * max_gif_nesting check used to live here. It doesn't anymore
	 * because there is no guaruntee that we won't be called
	 * concurrently from more than one thread.
	 */
	m->m_flags &= ~(M_BCAST|M_MCAST);
	if (!(ifnet_flags(ifp) & IFF_UP) ||
	    gif_psrc == NULL || gif_pdst == NULL) {
		ifnet_touch_lastchange(ifp);
		m_freem(m);	/* free it here not in dlil_output */
		error = ENETDOWN;
		goto end;
	}

	bpf_tap_out(ifp, 0, m, &sc->gif_proto, sizeof (sc->gif_proto));

	GIF_LOCK(sc);

	/* inner AF-specific encapsulation */

	/* XXX should we check if our outer source is legal? */

	/* dispatch to output logic based on outer AF */
	switch (sc->gif_psrc->sa_family) {
#if INET
	case AF_INET:
		error = in_gif_output(ifp, sc->gif_proto, m, NULL);
		break;
#endif
#if INET6
	case AF_INET6:
		error = in6_gif_output(ifp, sc->gif_proto, m, NULL);
		break;
#endif
	default:
		error = ENETDOWN;
		break;
	}

	GIF_UNLOCK(sc);
end:        
	if (error) {
		/* the mbuf was freed either by in_gif_output or in here */
		ifnet_stat_increment_out(ifp, 0, 0, 1);
	} else {
		ifnet_stat_increment_out(ifp, 1, m->m_pkthdr.len, 0);
	}
	if (error == 0)
		error = EJUSTRETURN; /* if no error, packet got sent already */
	return (error);
}

/*
 * gif_input is the input handler for IP and IPv6 attached to gif
 */
static errno_t
gif_input(
	ifnet_t ifp,
	protocol_family_t protocol_family,
	mbuf_t m,
	__unused char *frame_header)
{
	struct gif_softc *sc = ifnet_softc(ifp);

	bpf_tap_in(ifp, 0, m, &sc->gif_proto, sizeof (sc->gif_proto));

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
    int32_t pktlen = m->m_pkthdr.len;
	if (proto_input(protocol_family, m) != 0) {
		ifnet_stat_increment_in(ifp, 0, 0, 1);
		m_freem(m);
    } else {
		ifnet_stat_increment_in(ifp, 1, pktlen, 0);
    }

	return (0);
}

/* XXX how should we handle IPv6 scope on SIOC[GS]IFPHYADDR? */
static errno_t
gif_ioctl(
	ifnet_t			ifp,
	u_long			cmd,
	void			*data)
{
	struct gif_softc *sc  = ifnet_softc(ifp);
	struct ifreq *ifr = (struct ifreq *)data;
	int error = 0, size;
	struct sockaddr *dst = NULL, *src = NULL;
	struct sockaddr *sa;
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
			u_int32_t mtu;
			mtu = ifr->ifr_mtu;
			if (mtu < GIF_MTU_MIN || mtu > GIF_MTU_MAX) {
				return (EINVAL);
			}
			ifnet_set_mtu(ifp, mtu);
		}
		break;
#endif /* SIOCSIFMTU */

	case SIOCSIFPHYADDR:
#if INET6
	case SIOCSIFPHYADDR_IN6_32:
	case SIOCSIFPHYADDR_IN6_64:
#endif /* INET6 */
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
		case SIOCSIFPHYADDR_IN6_32: {
			struct in6_aliasreq_32 *ifra_32 =
			    (struct in6_aliasreq_32 *)data;

			src = (struct sockaddr *)&ifra_32->ifra_addr;
			dst = (struct sockaddr *)&ifra_32->ifra_dstaddr;
			break;
		}

		case SIOCSIFPHYADDR_IN6_64: {
			struct in6_aliasreq_64 *ifra_64 =
			    (struct in6_aliasreq_64 *)data;

			src = (struct sockaddr *)&ifra_64->ifra_addr;
			dst = (struct sockaddr *)&ifra_64->ifra_dstaddr;
			break;
		}
#endif
		}

		/* sa_family must be equal */
		if (src->sa_family != dst->sa_family)
			return (EINVAL);

		/* validate sa_len */
		switch (src->sa_family) {
#if INET
		case AF_INET:
			if (src->sa_len != sizeof (struct sockaddr_in))
				return (EINVAL);
			break;
#endif
#if INET6
		case AF_INET6:
			if (src->sa_len != sizeof (struct sockaddr_in6))
				return (EINVAL);
			break;
#endif
		default:
			return (EAFNOSUPPORT);
		}
		switch (dst->sa_family) {
#if INET
		case AF_INET:
			if (dst->sa_len != sizeof (struct sockaddr_in))
				return (EINVAL);
			break;
#endif
#if INET6
		case AF_INET6:
			if (dst->sa_len != sizeof (struct sockaddr_in6))
				return (EINVAL);
			break;
#endif
		default:
			return (EAFNOSUPPORT);
		}

		/* check sa_family looks sane for the cmd */
		switch (cmd) {
		case SIOCSIFPHYADDR:
			if (src->sa_family == AF_INET)
				break;
			return (EAFNOSUPPORT);
#if INET6
		case SIOCSIFPHYADDR_IN6_32:
		case SIOCSIFPHYADDR_IN6_64:
			if (src->sa_family == AF_INET6)
				break;
			return (EAFNOSUPPORT);
#endif /* INET6 */
		}

#define	GIF_ORDERED_LOCK(sc, sc2)	\
	if (sc < sc2) {			\
		GIF_LOCK(sc);		\
		GIF_LOCK(sc2);		\
	} else {			\
		GIF_LOCK(sc2);		\
		GIF_LOCK(sc);		\
	}

#define	GIF_ORDERED_UNLOCK(sc, sc2)	\
	if (sc > sc2) {			\
		GIF_UNLOCK(sc);		\
		GIF_UNLOCK(sc2);	\
	} else {			\
		GIF_UNLOCK(sc2);	\
		GIF_UNLOCK(sc);		\
	}

		ifnet_head_lock_shared();
		TAILQ_FOREACH(ifp2, &ifnet_head, if_link) {
			if (strcmp(ifnet_name(ifp2), GIFNAME) != 0)
				continue;
			sc2 = ifnet_softc(ifp2);
			if (sc2 == sc)
				continue;
			/* lock sc and sc2 in increasing order of ifnet index */
			GIF_ORDERED_LOCK(sc, sc2);
			if (!sc2->gif_pdst || !sc2->gif_psrc) {
				GIF_ORDERED_UNLOCK(sc, sc2);
				continue;
			}
			if (sc2->gif_pdst->sa_family != dst->sa_family ||
			    sc2->gif_pdst->sa_len != dst->sa_len ||
			    sc2->gif_psrc->sa_family != src->sa_family ||
			    sc2->gif_psrc->sa_len != src->sa_len) {
				GIF_ORDERED_UNLOCK(sc, sc2);
				continue;
			}
#ifndef XBONEHACK
			/* can't configure same pair of address onto two gifs */
			if (bcmp(sc2->gif_pdst, dst, dst->sa_len) == 0 &&
			    bcmp(sc2->gif_psrc, src, src->sa_len) == 0) {
				GIF_ORDERED_UNLOCK(sc, sc2);
				error = EADDRNOTAVAIL;
				ifnet_head_done();
				goto bad;
			}
#endif

			/* can't configure multiple multi-dest interfaces */
#define	multidest(x) \
	(((struct sockaddr_in *)(void *)(x))->sin_addr.s_addr == INADDR_ANY)
#if INET6
#define	multidest6(x) \
	(IN6_IS_ADDR_UNSPECIFIED(&((struct sockaddr_in6 *)	\
	    (void *)(x))->sin6_addr))
#endif
			if (dst->sa_family == AF_INET &&
			    multidest(dst) && multidest(sc2->gif_pdst)) {
				GIF_ORDERED_UNLOCK(sc, sc2);
				error = EADDRNOTAVAIL;
				ifnet_head_done();
				goto bad;
			}
#if INET6
			if (dst->sa_family == AF_INET6 &&
			    multidest6(dst) && multidest6(sc2->gif_pdst)) {
				GIF_ORDERED_UNLOCK(sc, sc2);
				error = EADDRNOTAVAIL;
				ifnet_head_done();
				goto bad;
			}
#endif
			GIF_ORDERED_UNLOCK(sc, sc2);
		}
		ifnet_head_done();

		GIF_LOCK(sc);
		if (sc->gif_psrc)
			FREE((caddr_t)sc->gif_psrc, M_IFADDR);
		sa = (struct sockaddr *)_MALLOC(src->sa_len, M_IFADDR,
		    M_WAITOK);
		if (sa == NULL) {
			GIF_UNLOCK(sc);
			return (ENOBUFS);
		}
		bcopy((caddr_t)src, (caddr_t)sa, src->sa_len);
		sc->gif_psrc = sa;

		if (sc->gif_pdst)
			FREE((caddr_t)sc->gif_pdst, M_IFADDR);
		sa = (struct sockaddr *)_MALLOC(dst->sa_len, M_IFADDR,
		    M_WAITOK);
		if (sa == NULL) {
			GIF_UNLOCK(sc);
			return (ENOBUFS);
		}
		bcopy((caddr_t)dst, (caddr_t)sa, dst->sa_len);
		sc->gif_pdst = sa;
		GIF_UNLOCK(sc);

		ifnet_set_flags(ifp, IFF_RUNNING | IFF_UP, IFF_RUNNING |
		    IFF_UP);

		error = 0;
		break;

#ifdef SIOCDIFPHYADDR
	case SIOCDIFPHYADDR:
		GIF_LOCK(sc);
		if (sc->gif_psrc) {
			FREE((caddr_t)sc->gif_psrc, M_IFADDR);
			sc->gif_psrc = NULL;
		}
		if (sc->gif_pdst) {
			FREE((caddr_t)sc->gif_pdst, M_IFADDR);
			sc->gif_pdst = NULL;
		}
		GIF_UNLOCK(sc);
		/* change the IFF_{UP, RUNNING} flag as well? */
		break;
#endif

	case SIOCGIFPSRCADDR:
#if INET6
	case SIOCGIFPSRCADDR_IN6:
#endif /* INET6 */
		GIF_LOCK(sc);
		if (sc->gif_psrc == NULL) {
			GIF_UNLOCK(sc);
			error = EADDRNOTAVAIL;
			goto bad;
		}
		src = sc->gif_psrc;
		switch (cmd) {
#if INET
		case SIOCGIFPSRCADDR:
			dst = &ifr->ifr_addr;
			size = sizeof (ifr->ifr_addr);
			break;
#endif /* INET */
#if INET6
		case SIOCGIFPSRCADDR_IN6:
			dst = (struct sockaddr *)
				&(((struct in6_ifreq *)data)->ifr_addr);
			size = sizeof (((struct in6_ifreq *)data)->ifr_addr);
			break;
#endif /* INET6 */
		default:
			GIF_UNLOCK(sc);
			error = EADDRNOTAVAIL;
			goto bad;
		}
		if (src->sa_len > size) {
			GIF_UNLOCK(sc);
			return (EINVAL);
		}
		bcopy((caddr_t)src, (caddr_t)dst, src->sa_len);
		GIF_UNLOCK(sc);
		break;

	case SIOCGIFPDSTADDR:
#if INET6
	case SIOCGIFPDSTADDR_IN6:
#endif /* INET6 */
		GIF_LOCK(sc);
		if (sc->gif_pdst == NULL) {
			GIF_UNLOCK(sc);
			error = EADDRNOTAVAIL;
			goto bad;
		}
		src = sc->gif_pdst;
		switch (cmd) {
#if INET
		case SIOCGIFPDSTADDR:
			dst = &ifr->ifr_addr;
			size = sizeof (ifr->ifr_addr);
			break;
#endif /* INET */
#if INET6
		case SIOCGIFPDSTADDR_IN6:
			dst = (struct sockaddr *)
				&(((struct in6_ifreq *)data)->ifr_addr);
			size = sizeof (((struct in6_ifreq *)data)->ifr_addr);
			break;
#endif /* INET6 */
		default:
			error = EADDRNOTAVAIL;
			GIF_UNLOCK(sc);
			goto bad;
		}
		if (src->sa_len > size) {
			GIF_UNLOCK(sc);
			return (EINVAL);
		}
		bcopy((caddr_t)src, (caddr_t)dst, src->sa_len);
		GIF_UNLOCK(sc);
		break;

	case SIOCSIFFLAGS:
		/* if_ioctl() takes care of it */
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}
bad:
	return (error);
}

static void
gif_delete_tunnel(struct gif_softc *sc)
{
	GIF_LOCK_ASSERT(sc);
	if (sc->gif_psrc) {
		FREE((caddr_t)sc->gif_psrc, M_IFADDR);
		sc->gif_psrc = NULL;
	}
	if (sc->gif_pdst) {
		FREE((caddr_t)sc->gif_pdst, M_IFADDR);
		sc->gif_pdst = NULL;
	}
	ROUTE_RELEASE(&sc->gif_ro);
	/* change the IFF_UP flag as well? */
}
