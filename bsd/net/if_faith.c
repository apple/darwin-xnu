/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*	$KAME: if_faith.c,v 1.21 2001/02/20 07:59:26 itojun Exp $	*/

/*
 * Copyright (c) 1982, 1986, 1993
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
 * $FreeBSD: src/sys/net/if_faith.c,v 1.3.2.2 2001/07/05 14:46:25 ume Exp $
 */
/*
 * derived from
 *	@(#)if_loop.c	8.1 (Berkeley) 6/10/93
 * Id: if_loop.c,v 1.22 1996/06/19 16:24:10 wollman Exp
 */

/*
 * Loopback interface driver for protocol testing and timing.
 */

#include "faith.h"
#if NFAITH > 0

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/sockio.h>
#include <sys/time.h>
#include <sys/queue.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/bpf.h>
#include <net/if_faith.h>

#if	INET
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#endif

#if INET6
#ifndef INET
#include <netinet/in.h>
#endif
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#endif

#include <net/dlil.h>
#include "bpf.h"

#include <net/net_osdep.h>

static int faithioctl(struct ifnet *, u_long, void*);
int faith_pre_output(struct ifnet *, register struct mbuf **,
	const struct sockaddr *, caddr_t, char *, char *, u_long);
static void faithrtrequest(int, struct rtentry *, struct sockaddr *);

void faithattach(void);
#ifndef __APPLE__
PSEUDO_SET(faithattach, if_faith);
#endif

static struct ifnet faithif[NFAITH];
static struct if_proto *faith_array[NFAITH];
static int faith_count = 0;

#define	FAITHMTU	1500

static
int  faith_add_if(struct ifnet *ifp)
{
    ifp->if_demux  = 0;
    ifp->if_framer = 0;
    return 0;
}

static 
int  faith_del_if(struct ifnet *ifp)
{
    return 0;
}

static
int  faith_add_proto(struct ddesc_head_str *desc_head, struct if_proto *proto, u_long dl_tag)
{       
    int i;
    
    for (i=0; i < faith_count; i++)
        if (faith_array[i] == 0) {
            faith_array[faith_count] = proto;
            return 0;
        }
    
    if ((i == faith_count) && (faith_count == NFAITH))
       panic("faith_add_proto -- Too many attachments\n");

    faith_array[faith_count++] = proto;

    return (0);
}

static
int  faith_del_proto(struct if_proto *proto, u_long dl_tag)
{   
    int i;


    for (i=0; i < faith_count; i++)
        if (faith_array[i] == proto) {
            faith_array[i] = 0;
            return 0;
        }

    return ENOENT;
}

int faith_shutdown()
{
    return 0;
}

int  faith_attach_inet(struct ifnet *ifp, u_long *dl_tag)
{       
    struct dlil_proto_reg_str   reg;
    struct dlil_demux_desc      desc;
    short native=0;
    int   stat;
    int i;

    for (i=0; i < faith_count; i++) {
        if (faith_array[i] && (faith_array[i]->ifp == ifp) &&
            (faith_array[i]->protocol_family == PF_INET)) {
#if 0
	        kprintf("faith_array for %s%d found dl_tag=%d\n",
                       ifp->if_name, ifp->if_unit, faith_array[i]->dl_tag);
#endif
                *dl_tag = faith_array[i]->dl_tag;
		return 0;
       
        }
    }

	bzero(&reg, sizeof(reg));
	bzero(&desc, sizeof(desc));
    TAILQ_INIT(&reg.demux_desc_head); 
    desc.type = DLIL_DESC_RAW;
    desc.native_type = (char *) &native;
    TAILQ_INSERT_TAIL(&reg.demux_desc_head, &desc, next);
    reg.interface_family = ifp->if_family;
    reg.unit_number      = ifp->if_unit;
    reg.pre_output       = faith_pre_output;
    reg.protocol_family  = PF_INET;

    stat = dlil_attach_protocol(&reg, dl_tag);
    if (stat) {
        panic("faith_attach_inet can't attach interface\n");
    }

    return stat;
}

void faith_reg_if_mods()
{   
     struct dlil_ifmod_reg_str  faith_ifmod;
     struct dlil_protomod_reg_str faith_protoreg;
     int error;

     bzero(&faith_ifmod, sizeof(faith_ifmod));
     faith_ifmod.add_if = faith_add_if;
     faith_ifmod.del_if = faith_del_if;
     faith_ifmod.add_proto = faith_add_proto;
     faith_ifmod.del_proto = faith_del_proto;
     faith_ifmod.ifmod_ioctl = 0;
     faith_ifmod.shutdown    = faith_shutdown;

    
    if (dlil_reg_if_modules(APPLE_IF_FAM_FAITH, &faith_ifmod))
        panic("Couldn't register faith modules\n");

	/* Register protocol registration functions */

	bzero(&faith_protoreg, sizeof(faith_protoreg));
	faith_protoreg.attach_proto = faith_attach_inet;
	faith_protoreg.detach_proto = 0;
	
	if ( error = dlil_reg_proto_module(PF_INET, APPLE_IF_FAM_FAITH, &faith_protoreg) != 0)
		kprintf("dlil_reg_proto_module failed for AF_INET error=%d\n", error);

    
}   
    
void
faithattach(void)
{
	struct ifnet *ifp;
	int i;

	faith_reg_if_mods(); /* DLIL modules */

	for (i = 0; i < NFAITH; i++) {
		ifp = &faithif[i];
		bzero(ifp, sizeof(faithif[i]));
		ifp->if_name = "faith";
		ifp->if_unit = i;
		ifp->if_family = APPLE_IF_FAM_FAITH;
		ifp->if_mtu = FAITHMTU;
		/* LOOPBACK commented out to announce IPv6 routes to faith */
		ifp->if_flags = /* IFF_LOOPBACK | */ IFF_MULTICAST;
		ifp->if_ioctl = faithioctl;
		ifp->if_output = NULL;
		ifp->if_type = IFT_FAITH;
		ifp->if_hdrlen = 0;
		ifp->if_addrlen = 0;
		dlil_if_attach(ifp);
#if NBPFILTER > 0
#ifdef HAVE_OLD_BPF
		bpfattach(ifp, DLT_NULL, sizeof(u_int));
#else
		bpfattach(&ifp->if_bpf, ifp, DLT_NULL, sizeof(u_int));
#endif
#endif
	}
}

int
faith_pre_output(ifp, m0, dst, route_entry, frame_type, dst_addr, dl_tag)
	struct ifnet *ifp;
	register struct mbuf **m0;
	const struct sockaddr *dst;
	caddr_t			 route_entry;
	char		     *frame_type;
	char		     *dst_addr;
	u_long		     dl_tag;
{
	register struct mbuf *m = *m0;
	struct rtentry *rt = (struct rtentry*)route_entry;

	if ((m->m_flags & M_PKTHDR) == 0)
		panic("faithoutput no HDR");
#if NBPFILTER > 0
	/* BPF write needs to be handled specially */
	if (dst && dst->sa_family == AF_UNSPEC) {
		dst->sa_family = *(mtod(m, int *));
		m->m_len -= sizeof(int);
		m->m_pkthdr.len -= sizeof(int);
		m->m_data += sizeof(int);
	}

	if (ifp->if_bpf) {
		/*
		 * We need to prepend the address family as
		 * a four byte field.  Cons up a faith header
		 * to pacify bpf.  This is safe because bpf
		 * will only read from the mbuf (i.e., it won't
		 * try to free it or keep a pointer a to it).
		 */
		struct mbuf m0;
		u_int32_t af = dst->sa_family;

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

	if (rt && rt->rt_flags & (RTF_REJECT|RTF_BLACKHOLE)) {
		return (rt->rt_flags & RTF_BLACKHOLE ? 0 :
		        rt->rt_flags & RTF_HOST ? EHOSTUNREACH : ENETUNREACH);
	}
	ifp->if_opackets++;
	ifp->if_obytes += m->m_pkthdr.len;
	m->m_pkthdr.rcvif = ifp;
	proto_inject(dst->sa_family, m);
	ifp->if_ipackets++;
	ifp->if_ibytes += m->m_pkthdr.len;
	return (EJUSTRETURN);
}

/* ARGSUSED */
static void
faithrtrequest(cmd, rt, sa)
	int cmd;
	struct rtentry *rt;
	struct sockaddr *sa;
{
	if (rt) {
		rt->rt_rmx.rmx_mtu = rt->rt_ifp->if_mtu; /* for ISO */
		/*
		 * For optimal performance, the send and receive buffers
		 * should be at least twice the MTU plus a little more for
		 * overhead.
		 */
		rt->rt_rmx.rmx_recvpipe =
			rt->rt_rmx.rmx_sendpipe = 3 * FAITHMTU;
	}
}

/*
 * Process an ioctl request.
 */
/* ARGSUSED */
static int
faithioctl(ifp, cmd, data)
	struct ifnet *ifp;
	u_long cmd;
	void* data;
{
	struct ifaddr *ifa;
	struct ifreq *ifr = (struct ifreq *)data;
	int error = 0;

	switch (cmd) {

	case SIOCSIFADDR:
		ifnet_set_flags(ifp, IFF_UP | IFF_RUNNING, IFF_UP | IFF_RUNNING);
		ifa = (struct ifaddr *)data;
		ifa->ifa_rtrequest = faithrtrequest;
		/*
		 * Everything else is done at a higher level.
		 */
		break;

	case SIOCADDMULTI:
	case SIOCDELMULTI:
		if (ifr == 0) {
			error = EAFNOSUPPORT;		/* XXX */
			break;
		}
		switch (ifr->ifr_addr.sa_family) {
#if INET
		case AF_INET:
			break;
#endif
#if INET6
		case AF_INET6:
			break;
#endif

		default:
			error = EAFNOSUPPORT;
			break;
		}
		break;

#ifdef SIOCSIFMTU
	case SIOCSIFMTU:
		ifp->if_mtu = ifr->ifr_mtu;
		break;
#endif

	case SIOCSIFFLAGS:
		break;

	default:
		error = EINVAL;
	}
	return (error);
}

#if INET6
/*
 * XXX could be slow
 * XXX could be layer violation to call sys/net from sys/netinet6
 */
int
faithprefix(in6)
	struct in6_addr *in6;
{
	struct rtentry *rt;
	struct sockaddr_in6 sin6;
	int ret;

	if (ip6_keepfaith == 0)
		return 0;

	bzero(&sin6, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_len = sizeof(struct sockaddr_in6);
	sin6.sin6_addr = *in6;
	rt = rtalloc1((struct sockaddr *)&sin6, 0, 0UL);
	if (rt && rt->rt_ifp && rt->rt_ifp->if_type == IFT_FAITH &&
	    (rt->rt_ifp->if_flags & IFF_UP) != 0)
		ret = 1;
	else
		ret = 0;
	if (rt)
		rtfree(rt);
	return ret;
}
#endif
#endif /* NFAITH > 0 */
