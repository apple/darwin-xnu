/*	$FreeBSD: src/sys/net/if_stf.c,v 1.1.2.6 2001/07/24 19:10:18 brooks Exp $	*/
/*	$KAME: if_stf.c,v 1.62 2001/06/07 22:32:16 itojun Exp $	*/

/*
 * Copyright (C) 2000 WIDE Project.
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
 * 6to4 interface, based on RFC3056.
 *
 * 6to4 interface is NOT capable of link-layer (I mean, IPv4) multicasting.
 * There is no address mapping defined from IPv6 multicast address to IPv4
 * address.  Therefore, we do not have IFF_MULTICAST on the interface.
 *
 * Due to the lack of address mapping for link-local addresses, we cannot
 * throw packets toward link-local addresses (fe80::x).  Also, we cannot throw
 * packets to link-local multicast addresses (ff02::x).
 *
 * Here are interesting symptoms due to the lack of link-local address:
 *
 * Unicast routing exchange:
 * - RIPng: Impossible.  Uses link-local multicast packet toward ff02::9,
 *   and link-local addresses as nexthop.
 * - OSPFv6: Impossible.  OSPFv6 assumes that there's link-local address
 *   assigned to the link, and makes use of them.  Also, HELLO packets use
 *   link-local multicast addresses (ff02::5 and ff02::6).
 * - BGP4+: Maybe.  You can only use global address as nexthop, and global
 *   address as TCP endpoint address.
 *
 * Multicast routing protocols:
 * - PIM: Hello packet cannot be used to discover adjacent PIM routers.
 *   Adjacent PIM routers must be configured manually (is it really spec-wise
 *   correct thing to do?).
 *
 * ICMPv6:
 * - Redirects cannot be used due to the lack of link-local address.
 *
 * stf interface does not have, and will not need, a link-local address.  
 * It seems to have no real benefit and does not help the above symptoms much.
 * Even if we assign link-locals to interface, we cannot really
 * use link-local unicast/multicast on top of 6to4 cloud (since there's no
 * encapsulation defined for link-local address), and the above analysis does
 * not change.  RFC3056 does not mandate the assignment of link-local address
 * either.
 *
 * 6to4 interface has security issues.  Refer to
 * http://playground.iijlab.net/i-d/draft-itojun-ipv6-transition-abuse-00.txt
 * for details.  The code tries to filter out some of malicious packets.
 * Note that there is no way to be 100% secure.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/errno.h>
#include <sys/protosw.h>
#include <sys/kernel.h>
#include <sys/syslog.h>
#include <machine/cpu.h>

#include <sys/malloc.h>

#include <net/if.h>
#include <net/route.h>
#include <net/netisr.h>
#include <net/if_types.h>
#include <net/if_stf.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/in_var.h>

#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_var.h>
#include <netinet/ip_ecn.h>

#include <netinet/ip_encap.h>
#include <net/dlil.h>


#include <net/net_osdep.h>

#include <net/bpf.h>

#define IN6_IS_ADDR_6TO4(x)	(ntohs((x)->s6_addr16[0]) == 0x2002)
#define GET_V4(x)	((struct in_addr *)(&(x)->s6_addr16[1]))

struct stf_softc {
	struct ifnet	sc_if;	   /* common area */
#ifdef __APPLE__
	struct if_proto *stf_proto; /* dlil protocol attached */
#endif
	union {
		struct route  __sc_ro4;
		struct route_in6 __sc_ro6; /* just for safety */
	} __sc_ro46;
#define sc_ro	__sc_ro46.__sc_ro4
	const struct encaptab *encap_cookie;
};

static struct stf_softc *stf;

#ifdef __APPLE__
void stfattach __P((void));
int stf_pre_output __P((struct ifnet *, register struct mbuf **, struct sockaddr *,
	caddr_t, char *, char *, u_long));
static u_long stf_dl_tag=0;
#endif

#ifndef __APPLE__
static MALLOC_DEFINE(M_STF, "stf", "6to4 Tunnel Interface");
#endif
static int ip_stf_ttl = 40;

extern  struct domain inetdomain;
struct protosw in_stf_protosw =
{ SOCK_RAW,	&inetdomain,	IPPROTO_IPV6,	PR_ATOMIC|PR_ADDR,
  in_stf_input, rip_output,	0,		rip_ctloutput,
  0,
  0,            0,              0,              0,
  0,
  &rip_usrreqs
};

static int stf_encapcheck __P((const struct mbuf *, int, int, void *));
static struct in6_ifaddr *stf_getsrcifa6 __P((struct ifnet *));
int stf_pre_output __P((struct ifnet *, register struct mbuf **, struct sockaddr *,
	caddr_t, char *, char *, u_long));
static int stf_checkaddr4 __P((struct stf_softc *, struct in_addr *,
	struct ifnet *));
static int stf_checkaddr6 __P((struct stf_softc *, struct in6_addr *,
	struct ifnet *));
static void stf_rtrequest __P((int, struct rtentry *, struct sockaddr *));
int stf_ioctl __P((struct ifnet *, u_long, void *));


static
int  stf_add_if(struct ifnet *ifp)
{
    ifp->if_demux  = 0;
    ifp->if_framer = 0;
    return 0;
}

static 
int  stf_del_if(struct ifnet *ifp)
{
    return 0;
}

static
int  stf_add_proto(struct ddesc_head_str *desc_head, struct if_proto *proto, u_long dl_tag)
{       
	/* Only one protocol may be attached at a time */
	struct stf_softc* stf = (struct stf_softc*)proto->ifp;
	if (stf->stf_proto == NULL)
		stf->stf_proto = proto;
	else {
		printf("stf_add_proto: stf already has a proto\n");
		return (EBUSY);
	}

    	return (0);
}

static
int  stf_del_proto(struct if_proto *proto, u_long dl_tag)
{   
	if (((struct stf_softc*)proto->ifp)->stf_proto == proto)
		((struct stf_softc*)proto->ifp)->stf_proto = NULL;
	else
		return ENOENT;

	return 0;
}

int stf_shutdown()
{
	return 0;
}

void stf_reg_if_mods()
{   
     struct dlil_ifmod_reg_str  stf_ifmod;

     bzero(&stf_ifmod, sizeof(stf_ifmod));
     stf_ifmod.add_if 	= stf_add_if;
     stf_ifmod.del_if	= stf_del_if;
     stf_ifmod.add_proto = stf_add_proto;
     stf_ifmod.del_proto = stf_del_proto;
     stf_ifmod.ifmod_ioctl = 0;
     stf_ifmod.shutdown    = stf_shutdown;

    
    if (dlil_reg_if_modules(APPLE_IF_FAM_STF, &stf_ifmod))
        panic("Couldn't register stf modules\n");
    
}   
    
u_long  stf_attach_inet6(struct ifnet *ifp)
{       
    struct dlil_proto_reg_str   reg;
    struct dlil_demux_desc      desc;
    short native=0;
    int   stat, i;

    if (stf_dl_tag != 0)
		return stf_dl_tag;

    TAILQ_INIT(&reg.demux_desc_head); 
    desc.type = DLIL_DESC_RAW;
    desc.variants.bitmask.proto_id_length = 0;
    desc.variants.bitmask.proto_id = 0;
    desc.variants.bitmask.proto_id_mask = 0;
    desc.native_type = (char *) &native;
    TAILQ_INSERT_TAIL(&reg.demux_desc_head, &desc, next);
    reg.interface_family = ifp->if_family;
    reg.unit_number      = ifp->if_unit;
    reg.input            = 0;
    reg.pre_output       = stf_pre_output;
    reg.event            = 0;
    reg.offer            = 0;
    reg.ioctl            = 0;
    reg.default_proto    = 0;
    reg.protocol_family  = PF_INET6;

    stat = dlil_attach_protocol(&reg, &stf_dl_tag);
    if (stat) {
        panic("stf_attach_inet6 can't attach interface\n");
    }

    return stf_dl_tag;
}

u_long  stf_detach_inet6(struct ifnet *ifp)
{
    u_long      ip_dl_tag = 0;
    int         stat;

    stat = dlil_find_dltag(ifp->if_family, ifp->if_unit, AF_INET6, &ip_dl_tag);
    if (stat == 0) {
        stat = dlil_detach_protocol(ip_dl_tag);
        if (stat) {
            printf("WARNING: stf_detach can't detach IP AF_INET6 from interface\n");
	}
    }
    return (stat);
}


void
stfattach(void)
{
	struct ifnet *ifp;
	struct stf_softc *sc;
	int i, error;


	int err;
	const struct encaptab *p;

	stf_reg_if_mods(); /* DLIL modules */

	sc = _MALLOC(sizeof(struct stf_softc), M_DEVBUF, M_WAITOK);
	if (sc == 0) {
		printf("stf softc attach failed\n" );
		return;
	}
		
	bzero(sc, sizeof(*sc));
	sc->sc_if.if_name = "stf";
	sc->sc_if.if_unit = 0;

	p = encap_attach_func(AF_INET, IPPROTO_IPV6, stf_encapcheck,
	    &in_stf_protosw, sc);
	if (p == NULL) {
		printf("%s: attach failed\n", if_name(&sc->sc_if));
		FREE(sc, M_DEVBUF);
		return;
	}
	sc->encap_cookie = p;
	sc->sc_if.if_mtu    = IPV6_MMTU;
	sc->sc_if.if_flags  = 0;
	sc->sc_if.if_ioctl  = stf_ioctl;
	sc->sc_if.if_output = NULL; /* processing done in pre_output */
	sc->sc_if.if_type   = IFT_STF;
	sc->sc_if.if_family= APPLE_IF_FAM_STF;
#if 0
	/* turn off ingress filter */
	sc->sc_if.if_flags  |= IFF_LINK2;
#endif
	sc->sc_if.if_snd.ifq_maxlen = IFQ_MAXLEN;

	if (error = dlil_if_attach(&sc->sc_if))
		printf("stfattach: can't dlil_if_attach error=%d\n");
	else 
		bpfattach(&sc->sc_if, DLT_NULL, sizeof(u_int));
	
	return ;
}

static int
stf_encapcheck(m, off, proto, arg)
	const struct mbuf *m;
	int off;
	int proto;
	void *arg;
{
	struct ip ip;
	struct in6_ifaddr *ia6;
	struct stf_softc *sc;
	struct in_addr a, b;

	sc = (struct stf_softc *)arg;
	if (sc == NULL)
		return 0;

	if ((sc->sc_if.if_flags & IFF_UP) == 0)
		return 0;

	/* IFF_LINK0 means "no decapsulation" */
	if ((sc->sc_if.if_flags & IFF_LINK0) != 0)
		return 0;

	if (proto != IPPROTO_IPV6)
		return 0;

	/* LINTED const cast */
	m_copydata((struct mbuf *)m, 0, sizeof(ip), (caddr_t)&ip);

	if (ip.ip_v != 4)
		return 0;

	ia6 = stf_getsrcifa6(&sc->sc_if);
	if (ia6 == NULL)
		return 0;

	/*
	 * check if IPv4 dst matches the IPv4 address derived from the
	 * local 6to4 address.
	 * success on: dst = 10.1.1.1, ia6->ia_addr = 2002:0a01:0101:...
	 */
	if (bcmp(GET_V4(&ia6->ia_addr.sin6_addr), &ip.ip_dst,
	    sizeof(ip.ip_dst)) != 0)
		return 0;

	/*
	 * check if IPv4 src matches the IPv4 address derived from the
	 * local 6to4 address masked by prefixmask.
	 * success on: src = 10.1.1.1, ia6->ia_addr = 2002:0a00:.../24
	 * fail on: src = 10.1.1.1, ia6->ia_addr = 2002:0b00:.../24
	 */
	bzero(&a, sizeof(a));
	a.s_addr = GET_V4(&ia6->ia_addr.sin6_addr)->s_addr;
	a.s_addr &= GET_V4(&ia6->ia_prefixmask.sin6_addr)->s_addr;
	b = ip.ip_src;
	b.s_addr &= GET_V4(&ia6->ia_prefixmask.sin6_addr)->s_addr;
	if (a.s_addr != b.s_addr)
		return 0;

	/* stf interface makes single side match only */
	return 32;
}

static struct in6_ifaddr *
stf_getsrcifa6(ifp)
	struct ifnet *ifp;
{
	struct ifaddr *ia;
	struct in_ifaddr *ia4;
	struct sockaddr_in6 *sin6;
	struct in_addr in;

	for (ia = ifp->if_addrlist.tqh_first;
	     ia;
	     ia = ia->ifa_list.tqe_next)
	{
		if (ia->ifa_addr == NULL)
			continue;
		if (ia->ifa_addr->sa_family != AF_INET6)
			continue;
		sin6 = (struct sockaddr_in6 *)ia->ifa_addr;
		if (!IN6_IS_ADDR_6TO4(&sin6->sin6_addr))
			continue;

		bcopy(GET_V4(&sin6->sin6_addr), &in, sizeof(in));
		for (ia4 = TAILQ_FIRST(&in_ifaddrhead);
		     ia4;
		     ia4 = TAILQ_NEXT(ia4, ia_link))
		{
			if (ia4->ia_addr.sin_addr.s_addr == in.s_addr)
				break;
		}
		if (ia4 == NULL)
			continue;

		return (struct in6_ifaddr *)ia;
	}

	return NULL;
}

int
stf_pre_output(ifp, m0, dst, rt, frame_type, address, dl_tag)
	struct ifnet *ifp;
	register struct mbuf **m0;
	struct sockaddr *dst;
	caddr_t			rt;
	char		     *frame_type;
	char		     *address;
	u_long		     dl_tag;
{
	register struct mbuf *m = *m0;
	struct stf_softc *sc;
	struct sockaddr_in6 *dst6;
	struct in_addr *in4;
	struct sockaddr_in *dst4;
	u_int8_t tos;
	struct ip *ip;
	struct ip6_hdr *ip6;
	struct in6_ifaddr *ia6;
	int error = 0 ;

	sc = (struct stf_softc*)ifp;
	dst6 = (struct sockaddr_in6 *)dst;

	/* just in case */
	if ((ifp->if_flags & IFF_UP) == 0) {
		printf("stf: IFF_DOWN\n");
		return ENETDOWN;
	}

	/*
	 * If we don't have an ip4 address that match my inner ip6 address,
	 * we shouldn't generate output.  Without this check, we'll end up
	 * using wrong IPv4 source.
	 */
	ia6 = stf_getsrcifa6(ifp);
	if (ia6 == NULL) {
		return ENETDOWN;
	}

	if (m->m_len < sizeof(*ip6)) {
		m = m_pullup(m, sizeof(*ip6));
		if (!m)
			return ENOBUFS;
	}
	ip6 = mtod(m, struct ip6_hdr *);
	tos = (ntohl(ip6->ip6_flow) >> 20) & 0xff;

	/*
	 * Pickup the right outer dst addr from the list of candidates.
	 * ip6_dst has priority as it may be able to give us shorter IPv4 hops.
	 */
	if (IN6_IS_ADDR_6TO4(&ip6->ip6_dst))
		in4 = GET_V4(&ip6->ip6_dst);
	else if (IN6_IS_ADDR_6TO4(&dst6->sin6_addr))
		in4 = GET_V4(&dst6->sin6_addr);
	else {
		return ENETUNREACH;
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
		u_int32_t af = AF_INET6;
		
		m0.m_next = m;
		m0.m_len = 4;
		m0.m_data = (char *)&af;
		
		bpf_mtap(ifp, &m0);
	}

	M_PREPEND(m, sizeof(struct ip), M_DONTWAIT);
	if (m && m->m_len < sizeof(struct ip))
		m = m_pullup(m, sizeof(struct ip));
	if (m == NULL)
		return ENOBUFS;
	ip = mtod(m, struct ip *);

	bzero(ip, sizeof(*ip));

	bcopy(GET_V4(&((struct sockaddr_in6 *)&ia6->ia_addr)->sin6_addr),
	    &ip->ip_src, sizeof(ip->ip_src));
	bcopy(in4, &ip->ip_dst, sizeof(ip->ip_dst));
	ip->ip_p = IPPROTO_IPV6;
	ip->ip_ttl = ip_stf_ttl;
	ip->ip_len = m->m_pkthdr.len;	/*host order*/
	if (ifp->if_flags & IFF_LINK1)
		ip_ecn_ingress(ECN_ALLOWED, &ip->ip_tos, &tos);
	else
		ip_ecn_ingress(ECN_NOCARE, &ip->ip_tos, &tos);

	dst4 = (struct sockaddr_in *)&sc->sc_ro.ro_dst;
	if (dst4->sin_family != AF_INET ||
	    bcmp(&dst4->sin_addr, &ip->ip_dst, sizeof(ip->ip_dst)) != 0) {
		/* cache route doesn't match */
		dst4->sin_family = AF_INET;
		dst4->sin_len = sizeof(struct sockaddr_in);
		bcopy(&ip->ip_dst, &dst4->sin_addr, sizeof(dst4->sin_addr));
		if (sc->sc_ro.ro_rt) {
			RTFREE(sc->sc_ro.ro_rt);
			sc->sc_ro.ro_rt = NULL;
		}
	}

	if (sc->sc_ro.ro_rt == NULL) {
		rtalloc(&sc->sc_ro);
		if (sc->sc_ro.ro_rt == NULL) {
			return ENETUNREACH;
		}
	}

	error = ip_output(m, NULL, &sc->sc_ro, 0, NULL);
	if (error == 0)
		return EJUSTRETURN;
}

static int
stf_checkaddr4(sc, in, inifp)
	struct stf_softc *sc;
	struct in_addr *in;
	struct ifnet *inifp;	/* incoming interface */
{
	struct in_ifaddr *ia4;

	/*
	 * reject packets with the following address:
	 * 224.0.0.0/4 0.0.0.0/8 127.0.0.0/8 255.0.0.0/8
	 */
	if (IN_MULTICAST(ntohl(in->s_addr)))
		return -1;
	switch ((ntohl(in->s_addr) & 0xff000000) >> 24) {
	case 0: case 127: case 255:
		return -1;
	}

	/*
	 * reject packets with broadcast
	 */
	for (ia4 = TAILQ_FIRST(&in_ifaddrhead);
	     ia4;
	     ia4 = TAILQ_NEXT(ia4, ia_link))
	{
		if ((ia4->ia_ifa.ifa_ifp->if_flags & IFF_BROADCAST) == 0)
			continue;
		if (in->s_addr == ia4->ia_broadaddr.sin_addr.s_addr)
			return -1;
	}

	/*
	 * perform ingress filter
	 */
	if (sc && (sc->sc_if.if_flags & IFF_LINK2) == 0 && inifp) {
		struct sockaddr_in sin;
		struct rtentry *rt;

		bzero(&sin, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_len = sizeof(struct sockaddr_in);
		sin.sin_addr = *in;
		rt = rtalloc1((struct sockaddr *)&sin, 0, 0UL);
		if (!rt || rt->rt_ifp != inifp) {
#if 1
			log(LOG_WARNING, "%s: packet from 0x%x dropped "
			    "due to ingress filter\n", if_name(&sc->sc_if),
			    (u_int32_t)ntohl(sin.sin_addr.s_addr));
#endif
			if (rt)
				rtfree(rt);
			return -1;
		}
		rtfree(rt);
	}

	return 0;
}

static int
stf_checkaddr6(sc, in6, inifp)
	struct stf_softc *sc;
	struct in6_addr *in6;
	struct ifnet *inifp;	/* incoming interface */
{
	/*
	 * check 6to4 addresses
	 */
	if (IN6_IS_ADDR_6TO4(in6))
		return stf_checkaddr4(sc, GET_V4(in6), inifp);

	/*
	 * reject anything that look suspicious.  the test is implemented
	 * in ip6_input too, but we check here as well to
	 * (1) reject bad packets earlier, and
	 * (2) to be safe against future ip6_input change.
	 */
	if (IN6_IS_ADDR_V4COMPAT(in6) || IN6_IS_ADDR_V4MAPPED(in6))
		return -1;

	return 0;
}

void
in_stf_input(m, off)
	struct mbuf *m;
	int off;
{
	struct stf_softc *sc;
	struct ip *ip;
	struct ip6_hdr *ip6;
	u_int8_t otos, itos;
	int s, isr, proto;
	struct ifqueue *ifq = NULL;
	struct ifnet *ifp;

	ip = mtod(m, struct ip *);
	proto = ip->ip_p;


	if (proto != IPPROTO_IPV6) {
		m_freem(m);
		return;
	}

	ip = mtod(m, struct ip *);

	sc = (struct stf_softc *)encap_getarg(m);

	if (sc == NULL || (sc->sc_if.if_flags & IFF_UP) == 0) {
		m_freem(m);
		return;
	}

	ifp = &sc->sc_if;

	/*
	 * perform sanity check against outer src/dst.
	 * for source, perform ingress filter as well.
	 */
	if (stf_checkaddr4(sc, &ip->ip_dst, NULL) < 0 ||
	    stf_checkaddr4(sc, &ip->ip_src, m->m_pkthdr.rcvif) < 0) {
		m_freem(m);
		return;
	}

	otos = ip->ip_tos;
	m_adj(m, off);

	if (m->m_len < sizeof(*ip6)) {
		m = m_pullup(m, sizeof(*ip6));
		if (!m)
			return;
	}
	ip6 = mtod(m, struct ip6_hdr *);

	/*
	 * perform sanity check against inner src/dst.
	 * for source, perform ingress filter as well.
	 */
	if (stf_checkaddr6(sc, &ip6->ip6_dst, NULL) < 0 ||
	    stf_checkaddr6(sc, &ip6->ip6_src, m->m_pkthdr.rcvif) < 0) {
		m_freem(m);
		return;
	}

	itos = (ntohl(ip6->ip6_flow) >> 20) & 0xff;
	if ((ifp->if_flags & IFF_LINK1) != 0)
		ip_ecn_egress(ECN_ALLOWED, &otos, &itos);
	else
		ip_ecn_egress(ECN_NOCARE, &otos, &itos);
	ip6->ip6_flow &= ~htonl(0xff << 20);
	ip6->ip6_flow |= htonl((u_int32_t)itos << 20);

	m->m_pkthdr.rcvif = ifp;
	
	if (ifp->if_bpf) {
		/*
		 * We need to prepend the address family as
		 * a four byte field.  Cons up a dummy header
		 * to pacify bpf.  This is safe because bpf
		 * will only read from the mbuf (i.e., it won't
		 * try to free it or keep a pointer a to it).
		 */
		struct mbuf m0;
		u_int32_t af = AF_INET6;
		
		m0.m_next = m;
		m0.m_len = 4;
		m0.m_data = (char *)&af;
		
#ifdef HAVE_OLD_BPF
		bpf_mtap(ifp, &m0);
#else
		bpf_mtap(ifp->if_bpf, &m0);
#endif
	}

	/*
	 * Put the packet to the network layer input queue according to the
	 * specified address family.
	 * See net/if_gif.c for possible issues with packet processing
	 * reorder due to extra queueing.
	 */
	ifq = &ip6intrq;
	isr = NETISR_IPV6;

	s = splimp();
	if (IF_QFULL(ifq)) {
		IF_DROP(ifq);	/* update statistics */
		m_freem(m);
		splx(s);
		return;
	}
	IF_ENQUEUE(ifq, m);
	schednetisr(isr);
	ifp->if_ipackets++;
	ifp->if_ibytes += m->m_pkthdr.len;
	splx(s);
}

/* ARGSUSED */
static void
stf_rtrequest(cmd, rt, sa)
	int cmd;
	struct rtentry *rt;
	struct sockaddr *sa;
{

	if (rt)
		rt->rt_rmx.rmx_mtu = IPV6_MMTU;
}

int
stf_ioctl(ifp, cmd, data)
	struct ifnet *ifp;
	u_long cmd;
	void *data;
{
	struct ifaddr *ifa;
	struct ifreq *ifr;
	struct sockaddr_in6 *sin6;
	int error;

	error = 0;
	switch (cmd) {
	case SIOCSIFADDR:
		ifa = (struct ifaddr *)data;
		if (ifa == NULL || ifa->ifa_addr->sa_family != AF_INET6) {
			error = EAFNOSUPPORT;
			break;
		}
		sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
		if (IN6_IS_ADDR_6TO4(&sin6->sin6_addr)) {
			ifa->ifa_rtrequest = stf_rtrequest;
			ifp->if_flags |= IFF_UP;
		} else
			error = EINVAL;
		break;

	case SIOCADDMULTI:
	case SIOCDELMULTI:
		ifr = (struct ifreq *)data;
		if (ifr && ifr->ifr_addr.sa_family == AF_INET6)
			;
		else
			error = EAFNOSUPPORT;
		break;

	default:
		error = EINVAL;
		break;
	}

	return error;
}
