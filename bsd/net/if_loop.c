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
 *	@(#)if_loop.c	8.1 (Berkeley) 6/10/93
 */

/*
 * Loopback interface driver for protocol testing and timing.
 */
#include "loop.h"
#if NLOOP > 0

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/netisr.h>
#include <net/route.h>
#include <net/bpf.h>
#include <sys/malloc.h>

#if	INET
#include <netinet/in.h>
#include <netinet/in_var.h>
#endif

#if IPX
#include <netipx/ipx.h>
#include <netipx/ipx_if.h>
#endif

#if INET6
#ifndef INET
#include <netinet/in.h>
#endif
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#endif

#if NS
#include <netns/ns.h>
#include <netns/ns_if.h>
#endif

#if ISO
#include <netiso/iso.h>
#include <netiso/iso_var.h>
#endif

#include <net/dlil.h>

#if NETAT
extern struct ifqueue atalkintrq;
#endif

#include "bpfilter.h"
#if NBPFILTER > 0
#include <net/bpfdesc.h>
#endif

#define NLOOP_ATTACHMENTS (NLOOP * 12)

struct lo_statics_str {
	int	bpf_mode;
	int	(*bpf_callback)(struct ifnet *, struct mbuf *);
};

static struct if_proto *lo_array[NLOOP_ATTACHMENTS];
static struct lo_statics_str lo_statics[NLOOP];
static lo_count = 0;


#ifdef TINY_LOMTU
#define	LOMTU	(1024+512)
#else
#define LOMTU	16384
#endif

struct	ifnet loif[NLOOP];

void lo_reg_if_mods();




int lo_demux(ifp, m, frame_header, proto)
    struct ifnet *ifp;
    struct mbuf  *m;
    char         *frame_header;
    struct if_proto **proto;
{
    int i;
    struct if_proto **proto_ptr;

    proto_ptr = mtod(m, struct if_proto **);
    *proto = *proto_ptr;
    m_adj(m, sizeof(u_long));
    return 0;
}


int lo_framer(ifp, m, dest, dest_linkaddr, frame_type)
    struct ifnet    *ifp;
    struct mbuf     **m;
    struct sockaddr *dest;
    char            *dest_linkaddr;
    char	    *frame_type;

{
    char  *to_ptr;

	M_PREPEND(*m, (4 * sizeof(u_long)), M_WAITOK);
	to_ptr = mtod(*m, char *);
	bcopy(dest_linkaddr, to_ptr, (4 * sizeof(u_long)));
	return 0;
}

static
int  lo_add_if(struct ifnet *ifp)
{
    ifp->if_demux  = lo_demux;
    ifp->if_framer = lo_framer;
    ifp->if_event  = 0;
    return 0;
}

static
int  lo_del_if(struct ifnet *ifp)
{
    return 0;
}




static
int  lo_add_proto(struct ddesc_head_str *desc_head, struct if_proto *proto, u_long dl_tag)
{
    int i;

    for (i=0; i < lo_count; i++)
	if (lo_array[i] == 0) {
	    lo_array[lo_count] = proto;
	    return 0;
	}

    if ((i == lo_count) && (lo_count == NLOOP_ATTACHMENTS))
       panic("lo_add_proto -- Too many attachments\n");

    lo_array[lo_count++] = proto;
    return 0;
}


static
int  lo_del_proto(struct if_proto *proto, u_long dl_tag)
{
    int i;

    for (i=0; i < lo_count; i++)
	if (lo_array[i] == proto) {
	    lo_array[i] = 0;
	    return 0;
	}

    return ENOENT;
}

static int
lo_output(ifp, m)
	struct ifnet *ifp;
	register struct mbuf *m;
{	u_int  *prepend_ptr;
	u_int  af;
	u_long saved_header[3];

	if ((m->m_flags & M_PKTHDR) == 0)
		panic("lo_output: no HDR");

	/*
	 * Don't overwrite the rcvif field if it is in use.
	 *  This is used to match multicast packets, sent looping
	 *  back, with the appropriate group record on input.
	 */
	if (m->m_pkthdr.rcvif == NULL)
		m->m_pkthdr.rcvif = ifp;
	prepend_ptr = mtod(m, u_int *);
	af = *prepend_ptr;
	m_adj(m, sizeof(u_int));


#if NBPFILTER > 0
	if (lo_statics[ifp->if_unit].bpf_mode != BPF_TAP_DISABLE) {
		struct mbuf m0, *n;

		bcopy(mtod(m, caddr_t), &saved_header[0], (3 * sizeof(u_long)));
		m_adj(m, (3 * sizeof(u_long)));

		n = m;
		if (ifp->if_bpf->bif_dlt == DLT_NULL) {
			/*
			 * We need to prepend the address family as
			 * a four byte field.  Cons up a dummy header
			 * to pacify bpf.  This is safe because bpf
			 * will only read from the mbuf (i.e., it won't
			 * try to free it or keep a pointer a to it).
			 */
			m0.m_next = m;
			m0.m_len = 4;
			m0.m_data = (char *)&af;
			n = &m0;
		}

		(*lo_statics[ifp->if_unit].bpf_callback)(ifp, n);

		M_PREPEND(m, (3 * sizeof(u_long)), M_WAITOK);
		bcopy(&saved_header[0], mtod(m, caddr_t), (3 * sizeof(u_long)));

	}
#endif

	ifp->if_ibytes += m->m_pkthdr.len;
	ifp->if_obytes += m->m_pkthdr.len;

	ifp->if_opackets++;
	ifp->if_ipackets++;

	/* WARNING
         * This won't work for loopbacked multicast 
         */
	m->m_pkthdr.header = mtod(m, char *);
        m->m_pkthdr.aux = ifp; /* HACKERY */
        m->m_pkthdr.csum_data = 0xffff; /* loopback checksums are always OK */
        m->m_pkthdr.csum_flags = CSUM_DATA_VALID | CSUM_PSEUDO_HDR | 
                               CSUM_IP_CHECKED | CSUM_IP_VALID;
	return dlil_input(ifp, m, m);
}


/*
 * This is a common pre-output route used by INET, AT, etc. This could
 * (should?) be split into separate pre-output routines for each protocol.
 */

static int
lo_pre_output(ifp, m, dst, route, frame_type, dst_addr, dl_tag)
	struct ifnet *ifp;
	register struct mbuf **m;
	struct sockaddr *dst;
	void		     *route;
	char		     *frame_type;
	char		     *dst_addr;
	u_long		     dl_tag;

{
	int s, isr;
	register struct ifqueue *ifq = 0;
	u_long *prepend_ptr;
	register struct rtentry *rt = (struct rtentry *) route;

	prepend_ptr = (u_long *) dst_addr;
	if (((*m)->m_flags & M_PKTHDR) == 0)
		panic("looutput no HDR");

	if (rt && rt->rt_flags & (RTF_REJECT|RTF_BLACKHOLE)) {
	    if (rt->rt_flags & RTF_BLACKHOLE) {
		m_freem(*m);
		return EJUSTRETURN;
	    }
	    else
		return ((rt->rt_flags & RTF_HOST) ? EHOSTUNREACH : ENETUNREACH);
	}

	switch (dst->sa_family) {
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
#if IPX
	case AF_IPX:
	    ifq = &ipxintrq;
	    isr = NETISR_IPX;
	    break;
#endif
#if NS
	case AF_NS:
	    ifq = &nsintrq;
	    isr = NETISR_NS;
	    break;
#endif
#if ISO
	case AF_ISO:
	    ifq = &clnlintrq;
	    isr = NETISR_ISO;
	    break;
#endif
#if NETAT
	case AF_APPLETALK:
	    ifq = &atalkintrq;
	    isr = NETISR_APPLETALK;
	    break;
#endif NETAT
	default:
	    return (EAFNOSUPPORT);
	}

	*prepend_ptr++ = dst->sa_family;	/* For lo_output(BPF) */
	*prepend_ptr++ = dlttoproto(dl_tag);	/* For lo_demux */
	*prepend_ptr++ = (u_long) ifq;	       	/* For lo_input */
	*prepend_ptr   = isr;			/* For lo_input */

	return 0;
}




/*
 *  lo_input - This should work for all attached protocols that use the
 *             ifq/schednetisr input mechanism.
 */


int
lo_input(m, fh, ifp, dl_tag, sync_ok)
	register struct mbuf *m;
	char         *fh;
	struct ifnet *ifp;
	u_long       dl_tag;
	int sync_ok;

{
	u_long *prepend_ptr;
	int s, isr;
	register struct ifqueue *ifq = 0;

	prepend_ptr = mtod(m, u_long *);
	ifq = (struct ifqueue *) *prepend_ptr++;
	isr = *prepend_ptr;
	m_adj(m, (2 * sizeof(u_long)));

	s = splimp();
	if (IF_QFULL(ifq)) {
		IF_DROP(ifq);
		m_freem(m);
		splx(s);
		return (EJUSTRETURN);
	}

	IF_ENQUEUE(ifq, m);
	schednetisr(isr);
	splx(s);
	return (0);
}




/* ARGSUSED */
static void
lortrequest(cmd, rt, sa)
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
			rt->rt_rmx.rmx_sendpipe = 3 * LOMTU;
	}
}

/*
 * Process an ioctl request.
 */
/* ARGSUSED */
static int
loioctl(dl_tag, ifp, cmd, data)
	u_long   dl_tag;
	register struct ifnet *ifp;
	u_long cmd;
	void   *data;
{
	register struct ifaddr *ifa;
	register struct ifreq *ifr = (struct ifreq *)data;
	register int error = 0;

	switch (cmd) {

	case SIOCSIFADDR:
		ifp->if_flags |= IFF_UP | IFF_RUNNING;
		ifa = (struct ifaddr *)data;
		ifa->ifa_rtrequest = lortrequest;
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

	case SIOCSIFMTU:
		ifp->if_mtu = ifr->ifr_mtu;
		break;

	case SIOCSIFFLAGS:
		break;

	default:
		error = EOPNOTSUPP;
	}
	return (error);
}
#endif /* NLOOP > 0 */


int lo_shutdown()
{
    return 0;
}


void lo_reg_if_mods()
{
     struct dlil_ifmod_reg_str  lo_ifmod;

     lo_ifmod.add_if = lo_add_if;
     lo_ifmod.del_if = lo_del_if;
     lo_ifmod.add_proto = lo_add_proto;
     lo_ifmod.del_proto = lo_del_proto;
     lo_ifmod.ifmod_ioctl = 0;
     lo_ifmod.shutdown    = lo_shutdown;

    if (dlil_reg_if_modules(APPLE_IF_FAM_LOOPBACK, &lo_ifmod))
	panic("Couldn't register lo modules\n");
}


u_long  lo_attach_inet(struct ifnet *ifp)
{
    struct dlil_proto_reg_str   reg;
    struct dlil_demux_desc      desc;
    u_long			dl_tag=0;
    short native=0;
    int   stat;
    int i;

    for (i=0; i < lo_count; i++) {
	if ((lo_array[i]) && (lo_array[i]->ifp == ifp)) {
	    if (lo_array[i]->protocol_family == PF_INET)
		return lo_array[i]->dl_tag;
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
    reg.input		 = lo_input;
    reg.pre_output       = lo_pre_output;
    reg.event            = 0;
    reg.offer            = 0;
    reg.ioctl            = loioctl;
    reg.default_proto    = 0;
    reg.protocol_family  = PF_INET;

    stat = dlil_attach_protocol(&reg, &dl_tag);
    if (stat) {
	panic("lo_attach_inet can't attach interface\n");
    }
    
    return dl_tag;
}


int lo_set_bpf_tap(struct ifnet *ifp, int mode, int (*bpf_callback)(struct ifnet *, struct mbuf *))
{

  /*
   * NEED MUTEX HERE XXX
   */
	if (mode == BPF_TAP_DISABLE) {
		lo_statics[ifp->if_unit].bpf_mode = mode;
		lo_statics[ifp->if_unit].bpf_callback = bpf_callback;
	}
	else {
		lo_statics[ifp->if_unit].bpf_callback = bpf_callback;
		lo_statics[ifp->if_unit].bpf_mode = mode;		
	}

	return 0;
}


/* ARGSUSED */
void
loopattach(dummy)
	void *dummy;
{
	register struct ifnet *ifp;
	register int i = 0;

	thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
	lo_reg_if_mods();

	for (ifp = loif; i < NLOOP; ifp++) {
		lo_statics[i].bpf_callback = 0;
		lo_statics[i].bpf_mode      = BPF_TAP_DISABLE;
		ifp->if_name = "lo";
		ifp->if_family = APPLE_IF_FAM_LOOPBACK;
		ifp->if_unit = i++;
		ifp->if_mtu = LOMTU;
		ifp->if_flags = IFF_LOOPBACK | IFF_MULTICAST;
		ifp->if_ioctl = 0;
		ifp->if_set_bpf_tap = lo_set_bpf_tap;
		ifp->if_output = lo_output;
		ifp->if_type = IFT_LOOP;
		ifp->if_hwassist = 0; /* HW cksum on send side breaks Classic loopback */
		dlil_if_attach(ifp);
#if NBPFILTER > 0
		bpfattach(ifp, DLT_NULL, sizeof(u_int));
#endif
	}
	thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
}
