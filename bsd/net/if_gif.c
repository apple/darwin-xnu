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
/*	$KAME: if_gif.c,v 1.15 2000/02/22 14:01:46 itojun Exp $	*/

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
 * gif.c
 */
#if BSD310
#include "opt_inet.h"
#endif

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
#include <kern/cpu_number.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/netisr.h>
#include <net/route.h>
#include <net/bpf.h>

#if	INET
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/in_gif.h>
#endif	/* INET */

#if INET6
#ifndef INET
#include <netinet/in.h>
#endif
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_gif.h>
#include <netinet6/ip6protosw.h>
#endif /* INET6 */

#include <netinet/ip_encap.h>
#include <net/dlil.h>
#include <net/if_gif.h>

#include "gif.h"
#include "bpfilter.h"

#include <net/net_osdep.h>

#if NGIF > 0

void gifattach __P((void *));
int gif_pre_output __P((struct ifnet *, register struct mbuf **, struct sockaddr *,
	register struct rtentry *, char *, char *, u_long));

/*
 * gif global variable definitions
 */
int ngif = NGIF;		/* number of interfaces */
struct gif_softc *gif = 0;
static struct if_proto *gif_array[NGIF];
static gif_count = 0 ;
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



#if 0
int gif_demux(ifp, m, frame_header, proto)
    struct ifnet *ifp;
    struct mbuf  *m;
    char         *frame_header;
    struct if_proto **proto;
{
    int i;
    return 0;
}

int gif_framer(ifp, m, dest, dest_linkaddr, frame_type)
    struct ifnet    *ifp;
    struct mbuf     **m;
    struct sockaddr *dest;
    char            *dest_linkaddr;
    char            *frame_type;
                
{                
    char  *to_ptr;
                 
        return 0;
}
#endif 
static
int  gif_add_if(struct ifnet *ifp) 
{                   
    ifp->if_demux  = 0;
    ifp->if_framer = 0;
    return 0;
}       
        
static
int  gif_del_if(struct ifnet *ifp)
{       
    return 0;
}   

static
int  gif_add_proto(struct ddesc_head_str *desc_head, struct if_proto *proto, u_long dl_tag)
{   
    int i;

    for (i=0; i < gif_count; i++)
        if (gif_array[i] == 0) {
            gif_array[gif_count] = proto;
            return 0;
        }

    if ((i == gif_count) && (gif_count == NGIF))
       panic("gif_add_proto -- Too many attachments\n");

    gif_array[gif_count++] = proto;

    return (0);
}

static
int  gif_del_proto(struct if_proto *proto, u_long dl_tag)
{       
    int i;

    for (i=0; i < gif_count; i++)
        if (gif_array[i] == proto) {
            gif_array[i] = 0;   
            return 0;
        }

    return ENOENT;
}

int gif_shutdown()
{
    return 0;
}

void gif_reg_if_mods()
{
     struct dlil_ifmod_reg_str  gif_ifmod;

     gif_ifmod.add_if = gif_add_if;
     gif_ifmod.del_if = gif_del_if;
     gif_ifmod.add_proto = gif_add_proto;
     gif_ifmod.del_proto = gif_del_proto;
     gif_ifmod.ifmod_ioctl = 0;
     gif_ifmod.shutdown    = gif_shutdown;

    if (dlil_reg_if_modules(APPLE_IF_FAM_GIF, &gif_ifmod))
        panic("Couldn't register gif modules\n");

} 

u_long  gif_attach_inet(struct ifnet *ifp)
{
    struct dlil_proto_reg_str   reg;
    struct dlil_demux_desc      desc;
    u_long                      dl_tag=0;
    short native=0;     
    int   stat;  
    int i;      
        
    for (i=0; i < gif_count; i++) {
        if (gif_array[i] && (gif_array[i]->ifp == ifp) &&
            (gif_array[i]->protocol_family == PF_INET)) {
#if 0
		kprintf("gif_attach for %s%d found dl_tag=%d\n", 
			ifp->if_name, ifp->if_unit, gif_array[i]->dl_tag);
#endif
               return gif_array[i]->dl_tag;
	    
        }
    }

    TAILQ_INIT(&reg.demux_desc_head);
    desc.type = DLIL_DESC_RAW;
    desc.variants.bitmask.proto_id_length = 0;
    desc.variants.bitmask.proto_id = 0;
    desc.variants.bitmask.proto_id_mask = 0;
    desc.native_type = (char *) &native;
    TAILQ_INSERT_TAIL(&reg.demux_desc_head, &desc, next);
    reg.interface_family = ifp->if_family;
    reg.unit_number      = ifp->if_unit;
    reg.input            = gif_input;
    reg.pre_output       = gif_pre_output;
    reg.event            = 0;
    reg.offer            = 0;
    reg.ioctl            = gif_ioctl;
    reg.default_proto    = 0;
    reg.protocol_family  = PF_INET;

    stat = dlil_attach_protocol(&reg, &dl_tag);
    if (stat) {
        panic("gif_attach_inet can't attach interface\n");
    }

    return dl_tag;
}

void
gifattach(dummy)
	void *dummy;
{
	register struct gif_softc *sc;
	register int i;

	gif_reg_if_mods(); /* DLIL modules */

	gif = sc = _MALLOC (ngif * sizeof(struct gif_softc), M_DEVBUF, M_WAITOK);
	bzero(sc, ngif * sizeof(struct gif_softc));
	for (i = 0; i < ngif; sc++, i++) {
		sc->gif_if.if_name   = "gif";
		sc->gif_if.if_unit   = i;
		sc->gif_if.if_family = APPLE_IF_FAM_GIF;
		sc->gif_if.if_mtu    = GIF_MTU;
		sc->gif_if.if_flags  = IFF_POINTOPOINT | IFF_MULTICAST;
		sc->gif_if.if_ioctl  = gif_ioctl;
		sc->gif_if.if_output = NULL;
		sc->gif_if.if_type   = IFT_GIF;
		dlil_if_attach(&sc->gif_if);
#if 0
		kprintf("gifattach: Attaching gif%d sc=%x gif_if=%x\n", i, sc, &sc->gif_if);
#endif
#if NBPFILTER > 0
#ifdef HAVE_OLD_BPF
		bpfattach(&sc->gif_if, DLT_NULL, sizeof(u_int));
#else
		bpfattach(&sc->gif_if.if_bpf, &sc->gif_if, DLT_NULL, sizeof(u_int));
#endif
#endif
	}
}

#ifdef __FreeBSD__
PSEUDO_SET(gifattach, if_gif);
#endif

int
gif_pre_output(ifp, m0, dst, rt, frame, address, dl_tag)
	struct ifnet *ifp;
	struct mbuf **m0;
	struct sockaddr *dst;
	struct rtentry *rt;	/* added in net2 */
	char *frame;
	char *address;
	u_long dl_tag;
{
	register struct gif_softc *sc = (struct gif_softc*)ifp;
	register struct mbuf * m = *m0;
	int error = 0;
	static int called = 0;	/* XXX: MUTEX */

	/*
	 * gif may cause infinite recursion calls when misconfigured.
	 * We'll prevent this by introducing upper limit.
	 * XXX: this mechanism may introduce another problem about
	 *      mutual exclusion of the variable CALLED, especially if we
	 *      use kernel thread.
	 */
	if (++called > max_gif_nesting) {
		log(LOG_NOTICE,
		    "gif_output: recursively called too many times(%d)\n",
		    called);
		m_freem(m);
		error = EIO;	/* is there better errno? */
		goto end;
	}

	getmicrotime(&ifp->if_lastchange);
	m->m_flags &= ~(M_BCAST|M_MCAST);
	if (!(ifp->if_flags & IFF_UP) ||
#if 0	
	    sc->gif_flags & GIFF_INUSE ||
#endif
	    sc->gif_psrc == NULL || sc->gif_pdst == NULL) {
		m_freem(m);
		error = ENETDOWN;
		printf("gif_output: packed discarded ENETDOWN\n");
		goto end;
	}

#if NBPFILTER > 0
	if (ifp->if_bpf) {
		/*
		 * We need to prepend the address family as
		 * a four byte field.  Cons up a dummy header
		 * to pacify bpf.  This is safe because bpf
		 * will only read from the mbuf (i.e., it won't
		 * try to free it or keep a pointer a to it).
		 */
		struct mbuf m0;
		u_int af = dst->sa_family;

		m0.m_next = m;
		m0.m_len = 4;
		m0.m_data = (char *)&af;
		
#ifdef HAVE_OLD_BPF
		bpf_mtap(ifp, &m0);
#else
		bpf_mtap(ifp->if_bpf, &m0);
#endif
	}
#endif
	ifp->if_opackets++;	
	ifp->if_obytes += m->m_pkthdr.len;
#if 0
	s = splnet();
	sc->gif_flags |= GIFF_INUSE;
#endif

	switch (sc->gif_psrc->sa_family) {
#if INET
	case AF_INET:
		error = in_gif_output(ifp, dst->sa_family, m, rt);
		if (error) 
			printf("in_gif_output returned error=%d\n", error);
		break;
#endif
#if INET6
	case AF_INET6:
		error = in6_gif_output(ifp, dst->sa_family, m, rt);
		if (error) 
			printf("in6_gif_output returned error=%d\n", error);
		break;
#endif
	default:
		m_freem(m);		
		error = ENETDOWN;
	}
#if 0
	sc->gif_flags &= ~GIFF_INUSE;
	splx(s);
#endif

  end:
	called = 0;		/* reset recursion counter */
	if (error) ifp->if_oerrors++;
	return EJUSTRETURN;
}

void
gif_input(m, af, gifp)
	struct mbuf *m;
	int af;
	struct ifnet *gifp;
{
	int s, isr;
	register struct ifqueue *ifq = 0;

	if (gifp == NULL) {
		/* just in case */
		m_freem(m);
		return;
	}

	if (m->m_pkthdr.rcvif)
		m->m_pkthdr.rcvif = gifp;
	
#if NBPFILTER > 0
	if (gifp->if_bpf) {
		/*
		 * We need to prepend the address family as
		 * a four byte field.  Cons up a dummy header
		 * to pacify bpf.  This is safe because bpf
		 * will only read from the mbuf (i.e., it won't
		 * try to free it or keep a pointer a to it).
		 */
		struct mbuf m0;
		u_int af = AF_INET6;
		
		m0.m_next = m;
		m0.m_len = 4;
		m0.m_data = (char *)&af;
		
#ifdef HAVE_OLD_BPF
		bpf_mtap(gifp, &m0);
#else
		bpf_mtap(gifp->if_bpf, &m0);
#endif
	}
#endif /*NBPFILTER > 0*/

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
	switch (af) {
#if INET
	case AF_INET:
		ifq = &ipintrq;
		isr = NETISR_IP;
		break;
#endif
#if INET6
	case AF_INET6:
		ifq = &ip6intrq;
		isr = NETISR_IPV6;
		break;
#endif
	default:
		m_freem(m);
		return;
	}

	s = splimp();
	if (IF_QFULL(ifq)) {
		IF_DROP(ifq);	/* update statistics */
		m_freem(m);
		splx(s);
		return;
	}
	IF_ENQUEUE(ifq, m);
	/* we need schednetisr since the address family may change */
	schednetisr(isr);
	gifp->if_ipackets++;
	gifp->if_ibytes += m->m_pkthdr.len;
	splx(s);

	return;
}

/* XXX how should we handle IPv6 scope on SIOC[GS]IFPHYADDR? */
int
gif_ioctl(ifp, cmd, data)
	struct ifnet *ifp;
	u_long cmd;
	caddr_t data;
{
	struct gif_softc *sc  = (struct gif_softc*)ifp;
	struct ifreq     *ifr = (struct ifreq*)data;
	int error = 0, size;
	struct sockaddr *dst, *src;
	int i;
	struct gif_softc *sc2;
		
	switch (cmd) {
	case SIOCSIFADDR:
		break;
		
	case SIOCSIFDSTADDR:
		break;

	case SIOCADDMULTI:
	case SIOCDELMULTI:
 /* Called from if_addmulti() with data == NULL if __FreeBSD__ >= 3 */
#if !defined(__APPLE__)
		switch (ifr->ifr_addr.sa_family) {
#ifdef INET
		case AF_INET:	/* IP supports Multicast */
			break;
#endif /* INET */
#ifdef INET6
		case AF_INET6:	/* IP6 supports Multicast */
			break;
#endif /* INET6 */
		default:  /* Other protocols doesn't support Multicast */
			error = EAFNOSUPPORT;
			break;
		}
#endif /*not FreeBSD3*/
		break;

#ifdef	SIOCSIFMTU /* xxx */
#ifndef __OpenBSD__
	case SIOCGIFMTU:
		break;
	case SIOCSIFMTU:
		{
#ifdef __bsdi__
			short mtu;
			mtu = *(short *)ifr->ifr_data;
#else
			u_long mtu;
			mtu = ifr->ifr_mtu;
#endif
			if (mtu < GIF_MTU_MIN || mtu > GIF_MTU_MAX) {
				return (EINVAL);
			}
			ifp->if_mtu = mtu;
		}
		break;
#endif
#endif /* SIOCSIFMTU */

	case SIOCSIFPHYADDR:
#if INET6
	case SIOCSIFPHYADDR_IN6:
#endif /* INET6 */
		/* can't configure same pair of address onto two gif */
		src = (struct sockaddr *)
			&(((struct in_aliasreq *)data)->ifra_addr);
		dst = (struct sockaddr *)
			&(((struct in_aliasreq *)data)->ifra_dstaddr);
		for (i = 0; i < ngif; i++) {
			sc2 = gif + i;
			if (sc2 == sc)
				continue;
			if (!sc2->gif_pdst || !sc2->gif_psrc)
				continue;
			if (sc2->gif_pdst->sa_family == dst->sa_family &&
			    sc2->gif_pdst->sa_len == dst->sa_family &&
			    bcmp(sc2->gif_pdst, dst, dst->sa_len) == 0 &&
			    sc2->gif_psrc->sa_family == src->sa_family &&
			    sc2->gif_psrc->sa_len == src->sa_family &&
			    bcmp(sc2->gif_psrc, src, src->sa_len) == 0) {
				error = EADDRNOTAVAIL;
				goto bad;
			}
		}

		switch (ifr->ifr_addr.sa_family) {
#if INET
		case AF_INET:
			return in_gif_ioctl(ifp, cmd, data);
#endif /* INET */
#if INET6
		case AF_INET6:
			return in6_gif_ioctl(ifp, cmd, data);
#endif /* INET6 */
		default:
			error = EPROTOTYPE;
			goto bad;
			break;
		}
		break;
			
	case SIOCGIFPSRCADDR:
#if INET6
	case SIOCGIFPSRCADDR_IN6:
#endif /* INET6 */
		if (sc->gif_psrc == NULL) {
			error = EADDRNOTAVAIL;
			goto bad;
		}
		src = sc->gif_psrc;
		switch (sc->gif_psrc->sa_family) {
#if INET
		case AF_INET:
			dst = &ifr->ifr_addr;
			size = sizeof(struct sockaddr_in);
			break;
#endif /* INET */
#if INET6
		case AF_INET6:
			dst = (struct sockaddr *)
				&(((struct in6_ifreq *)data)->ifr_addr);
			size = sizeof(struct sockaddr_in6);
			break;
#endif /* INET6 */
		default:
			error = EADDRNOTAVAIL;
			goto bad;
		}
		bcopy((caddr_t)src, (caddr_t)dst, size);
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
		switch (sc->gif_pdst->sa_family) {
#if INET
		case AF_INET:
			dst = &ifr->ifr_addr;
			size = sizeof(struct sockaddr_in);
			break;
#endif /* INET */
#if INET6
		case AF_INET6:
			dst = (struct sockaddr *)
				&(((struct in6_ifreq *)data)->ifr_addr);
			size = sizeof(struct sockaddr_in6);
			break;
#endif /* INET6 */
		default:
			error = EADDRNOTAVAIL;
			goto bad;
		}
		bcopy((caddr_t)src, (caddr_t)dst, size);
		break;

	case SIOCSIFFLAGS:
		if (sc->gif_psrc == NULL)
			break;
		switch (sc->gif_psrc->sa_family) {
#if INET
		case AF_INET:
			return in_gif_ioctl(ifp, cmd, data);
#endif /* INET */
#if INET6
		case AF_INET6:
			return in6_gif_ioctl(ifp, cmd, data);
#endif /* INET6 */
		default:
			error = EPROTOTYPE;
			goto bad;
			break;
		}
		break;

	default:
		error = EINVAL;
		break;
	}
 bad:
	return error;
}
#endif /*NGIF > 0*/
