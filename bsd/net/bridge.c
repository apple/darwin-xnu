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
 * Copyright (c) 1998 Luigi Rizzo
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND
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
 */

/*
 * This code implements bridging in FreeBSD. It only acts on ethernet
 * type of interfaces (others are still usable for routing).
 * A bridging table holds the source MAC address/dest. interface for each
 * known node. The table is indexed using an hash of the source address.
 *
 * Input packets are tapped near the end of the input routine in each
 * driver (near the call to bpf_mtap, or before the call to ether_input)
 * and analysed calling bridge_in(). Depending on the result, the packet
 * can be forwarded to one or more output interfaces using bdg_forward(),
 * and/or sent to the upper layer (e.g. in case of multicast).
 *
 * Output packets are intercepted near the end of ether_output(),
 * the correct destination is selected calling bdg_dst_lookup(),
 * and then forwarding is done using bdg_forward().
 * Bridging is controlled by the sysctl variable net.link.ether.bridge
 *
 * The arp code is also modified to let a machine answer to requests
 * irrespective of the port the request came from.
 *
 * In case of loops in the bridging topology, the bridge detects this
 * event and temporarily mutes output bridging on one of the ports.
 * Periodically, interfaces are unmuted by bdg_timeout(). (For the
 * mute flag i am temporarily using IFF_LINK2 but this has to
 * change.) Muting is only implemented as a safety measure, and also as
 * a mechanism to support a user-space implementation of the spanning
 * tree algorithm. In the final release, unmuting will only occur
 * because of explicit action of the user-level daemon.
 *
 * To build a bridging kernel, use the following option
 *    option BRIDGE
 * and then at runtime set the sysctl variable to enable bridging.
 *
 * Only one interface is supposed to have addresses set (but
 * there are no problems in practice if you set addresses for more
 * than one interface).
 * Bridging will act before routing, but nothing prevents a machine
 * from doing both (modulo bugs in the implementation...).
 *
 * THINGS TO REMEMBER
 *  - bridging requires some (small) modifications to the interface
 *    driver. Currently (980911) the "ed", "de", "tx", "lnc" drivers
 *    have been modified and tested. "fxp", "ep", "fe" have been
 *    modified but not tested. See the "ed" and "de" drivers as
 *    examples on how to operate.
 *  - bridging is incompatible with multicast routing on the same
 *    machine. There is not an easy fix to this.
 *  - loop detection is still not very robust.
 *  - the interface of bdg_forward() could be improved.
 */

#include <sys/param.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/systm.h>
#include <sys/socket.h> /* for net/if.h */
#include <sys/kernel.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_types.h>

#include <netinet/in.h> /* for struct arpcom */
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h> /* for struct arpcom */

#include "opt_ipfw.h" 
#include "opt_ipdn.h" 

#if defined(IPFIREWALL) && defined(DUMMYNET)
#include <net/route.h>
#include <netinet/ip_fw.h>
#include <netinet/ip_dummynet.h>
#endif

#include <net/bridge.h>

/*
 * For debugging, you can use the following macros.
 * remember, rdtsc() only works on Pentium-class machines

    quad_t ticks;
    DDB(ticks = rdtsc();)
    ... interesting code ...
    DDB(bdg_fw_ticks += (u_long)(rdtsc() - ticks) ; bdg_fw_count++ ;)

 *
 */

#define DDB(x) x
#define DEB(x)

/*
 * System initialization
 */

static void bdginit(void *);
static void flush_table(void);

SYSINIT(interfaces, SI_SUB_PROTO_IF, SI_ORDER_FIRST, bdginit, NULL)

static int bdg_ipfw = 0 ;
int do_bridge = 0;
bdg_hash_table *bdg_table = NULL ;

/*
 * we need additional info for the bridge. The bdg_ifp2sc[] array
 * provides a pointer to this struct using the if_index.
 * bdg_softc has a backpointer to the struct ifnet, the bridge
 * flags, and a group (bridging occurs only between port of the
 * same group).
 */
struct bdg_softc {
    struct ifnet *ifp ;
    /* ((struct arpcom *)ifp)->ac_enaddr is the eth. addr */
    int flags ;
    int group ;
} ;
    
static struct bdg_softc **ifp2sc = NULL ;

#if 0 /* new code using ifp2sc */
#define SAMEGROUP(ifp,src) (src == NULL || \
    ifp2sc[ifp->if_index]->group == ifp2sc[src->if_index]->group )
#define MUTED(ifp) (ifp2sc[ifp->if_index]->flags & IFF_MUTE)
#define MUTE(ifp) ifp2sc[ifp->if_index]->flags |= IFF_MUTE
#define UNMUTE(ifp) ifp2sc[ifp->if_index]->flags &= ~IFF_MUTE
#else
#define SAMEGROUP(a,b) 1
#define MUTED(ifp) (ifp->if_flags & IFF_MUTE)
#define MUTE(ifp) ifp->if_flags |= IFF_MUTE
#define UNMUTE(ifp) ifp->if_flags &= ~IFF_MUTE
#endif

static int
sysctl_bdg SYSCTL_HANDLER_ARGS
{
    int error, oldval = do_bridge ;

    error = sysctl_handle_int(oidp,
	oidp->oid_arg1, oidp->oid_arg2, req);
    printf("called sysctl for bridge name %s arg2 %d val %d->%d\n",
	oidp->oid_name, oidp->oid_arg2,
	oldval, do_bridge);
    if (bdg_table == NULL)
	do_bridge = 0 ;
    if (oldval != do_bridge) {
	flush_table();
    }
    return error ;
}

SYSCTL_DECL(_net_link_ether);
SYSCTL_PROC(_net_link_ether, OID_AUTO, bridge, CTLTYPE_INT|CTLFLAG_RW,
           &do_bridge, 0, &sysctl_bdg, "I", "Bridging");

SYSCTL_INT(_net_link_ether, OID_AUTO, bridge_ipfw, CTLFLAG_RW, &bdg_ipfw,0,"");
#if 1 /* diagnostic vars */
int bdg_in_count = 0 , bdg_in_ticks = 0 , bdg_fw_count = 0, bdg_fw_ticks = 0 ;
SYSCTL_INT(_net_link_ether, OID_AUTO, bdginc, CTLFLAG_RW, &bdg_in_count,0,"");
SYSCTL_INT(_net_link_ether, OID_AUTO, bdgint, CTLFLAG_RW, &bdg_in_ticks,0,"");
SYSCTL_INT(_net_link_ether, OID_AUTO, bdgfwc, CTLFLAG_RW, &bdg_fw_count,0,"");
SYSCTL_INT(_net_link_ether, OID_AUTO, bdgfwt, CTLFLAG_RW, &bdg_fw_ticks,0,"");
#endif
static struct bdg_stats bdg_stats ;
SYSCTL_STRUCT(_net_link_ether, PF_BDG, bdgstats,
        CTLFLAG_RD, &bdg_stats , bdg_stats, "bridge statistics");

static int bdg_loops ;

/*
 * completely flush the bridge table.
 */
static void
flush_table()
{   
    int s,i;

    if (bdg_table == NULL)
	return ;
    s = splimp();
    for (i=0; i< HASH_SIZE; i++)
        bdg_table[i].name= NULL; /* clear table */
    splx(s);
}

/* wrapper for funnel */
void
bdg_timeout_funneled(void * dummy)
{
    boolean_t 	funnel_state;
        
    funnel_state = thread_funnel_set(network_flock, TRUE);
    bdg_timeout(dummy);
    funnel_state = thread_funnel_set(network_flock, FALSE);
}

/*
 * called periodically to flush entries etc.
 */
static void
bdg_timeout(void *dummy)
{
    struct ifnet *ifp ;
    int s ;
    static int slowtimer = 0 ;
    boolean_t 	funnel_state;
        
    
    if (do_bridge) {
	static int age_index = 0 ; /* index of table position to age */
	int l = age_index + HASH_SIZE/4 ;
	/*
	 * age entries in the forwarding table.
	 */
	if (l > HASH_SIZE)
	    l = HASH_SIZE ;
	for (; age_index < l ; age_index++)
	    if (bdg_table[age_index].used)
		bdg_table[age_index].used = 0 ;
	    else if (bdg_table[age_index].name) {
		/* printf("xx flushing stale entry %d\n", age_index); */
		bdg_table[age_index].name = NULL ;
	    }
	if (age_index >= HASH_SIZE)
	    age_index = 0 ;

	if (--slowtimer <= 0 ) {
	    slowtimer = 5 ;

	    for (ifp = ifnet.tqh_first; ifp; ifp = ifp->if_link.tqe_next) {
		if (ifp->if_type != IFT_ETHER)
		    continue ;
		if ( 0 == ( ifp->if_flags & IFF_UP) ) {
		    s = splimp();
		    if_up(ifp);
		    splx(s);
		}
		if ( 0 == ( ifp->if_flags & IFF_PROMISC) ) {
		    int ret ;
		    s = splimp();
		    ret = ifpromisc(ifp, 1);
		    splx(s);
		    printf(">> now  %s%d flags 0x%x promisc %d\n",
			ifp->if_name, ifp->if_unit,
			ifp->if_flags, ret);
		}
		if (MUTED(ifp)) {
		    printf(">> unmuting %s%d\n", ifp->if_name, ifp->if_unit);
		    UNMUTE(ifp) ;
		}
	    }
	    bdg_loops = 0 ;
	}
    }
    timeout(bdg_timeout_funneled, (void *)0, 2*hz );

}

/*
 * local MAC addresses are held in a small array. This makes comparisons
 * much faster.
 */
unsigned char bdg_addresses[6*BDG_MAX_PORTS];
int bdg_ports ;

/*
 * initialization of bridge code.
 */
static void
bdginit(dummy)
	void *dummy;
{
    int i ;
    struct ifnet *ifp;
    struct arpcom *ac ;
    u_char *eth_addr ;
    /*
     * initialization of bridge code
     */
    if (bdg_table == NULL)
	bdg_table = (struct hash_table *)
		_MALLOC(HASH_SIZE * sizeof(struct hash_table),
		    M_IFADDR, M_WAITOK);
    if (bdg_table == NULL)
	return (ENOBUFS);
    flush_table();

    ifp2sc = _MALLOC(if_index * sizeof(struct bdg_softc *), M_IFADDR, M_WAITOK );
    if (ifp2sc == NULL)
	return (ENOBUFS);
    bzero(ifp2sc, if_index * sizeof(struct bdg_softc *) );

    bzero(&bdg_stats, sizeof(bdg_stats) );
    bdg_ports = 0 ;
    eth_addr = bdg_addresses ;

    printf("BRIDGE 981214, have %d interfaces\n", if_index);
    for (i = 0 , ifp = ifnet.tqh_first ; i < if_index ;
		i++, ifp = ifp->if_link.tqe_next)
	if (ifp->if_type == IFT_ETHER) { /* ethernet ? */
	    ac = (struct arpcom *)ifp;
	sprintf(bdg_stats.s[ifp->if_index].name,
	    "%s%d", ifp->if_name, ifp->if_unit);
	printf("-- index %d %s type %d phy %d addrl %d addr %6D\n",
	    ifp->if_index,
	    bdg_stats.s[ifp->if_index].name,
	    (int)ifp->if_type, (int) ifp->if_physical,
	    (int)ifp->if_addrlen,
	    ac->ac_enaddr, "." );
	bcopy(ac->ac_enaddr, eth_addr, 6);
	eth_addr += 6 ;

	ifp2sc[bdg_ports] = _MALLOC(sizeof(struct bdg_softc),
		M_IFADDR, M_WAITOK );
	if (ifp2sc[bdg_ports] == NULL)
		return (ENOBUFS);
	ifp2sc[bdg_ports]->ifp = ifp ;
	ifp2sc[bdg_ports]->flags = 0 ;
	ifp2sc[bdg_ports]->group = 0 ;
	bdg_ports ++ ;
    }
    bdg_timeout(0);
    do_bridge=0;
}

/*
 * bridge_in() is invoked to perform bridging decision on input packets.
 * On Input:
 *   m		packet to be bridged. The mbuf need not to hold the
 *		whole packet, only the first 14 bytes suffice. We
 *		assume them to be contiguous. No alignment assumptions
 *		because they are not a problem on i386 class machines.
 *
 * On Return: destination of packet, one of
 *   BDG_BCAST	broadcast
 *   BDG_MCAST  multicast
 *   BDG_LOCAL  is only for a local address (do not forward)
 *   BDG_DROP   drop the packet
 *   ifp	ifp of the destination interface.
 *
 * Forwarding is not done directly to give a chance to some drivers
 * to fetch more of the packet, or simply drop it completely.
 */


struct ifnet *
bridge_in(struct mbuf *m)
{
    int index;
    struct ifnet *ifp = m->m_pkthdr.rcvif,  *dst , *old ;
    int dropit = MUTED(ifp) ;
    struct ether_header *eh;

    eh = mtod(m, struct ether_header *);

    /*
     * hash the source address
     */
    index= HASH_FN(eh->ether_shost);
    bdg_table[index].used = 1 ;
    old = bdg_table[index].name ;
    if ( old ) { /* the entry is valid. */
        if (!BDG_MATCH( eh->ether_shost, bdg_table[index].etheraddr) ) {
	    printf("collision at %d\n", index);
	    bdg_table[index].name = NULL ;
        } else if (old != ifp) {
	    /*
	     * found a loop. Either a machine has moved, or there
	     * is a misconfiguration/reconfiguration of the network.
	     * First, do not forward this packet!
	     * Record the relocation anyways; then, if loops persist,
	     * suspect a reconfiguration and disable forwarding
	     * from the old interface.
	     */
	    bdg_table[index].name = ifp ; /* relocate address */
	    printf("-- loop (%d) %6D to %s%d from %s%d (%s)\n",
			bdg_loops, eh->ether_shost, ".",
			ifp->if_name, ifp->if_unit,
			old->if_name, old->if_unit,
			old->if_flags & IFF_MUTE ? "muted":"ignore");
	    dropit = 1 ;
	    if ( !MUTED(old) ) {
		if (++bdg_loops > 10)
		    MUTE(old) ;
	    }
        }
    }

    /*
     * now write the source address into the table
     */
    if (bdg_table[index].name == NULL) {
	DEB(printf("new addr %6D at %d for %s%d\n",
	    eh->ether_shost, ".", index, ifp->if_name, ifp->if_unit);)
	bcopy(eh->ether_shost, bdg_table[index].etheraddr, 6);
	bdg_table[index].name = ifp ;
    }
    dst = bridge_dst_lookup(m);
    /* Return values:
     *   BDG_BCAST, BDG_MCAST, BDG_LOCAL, BDG_UNKNOWN, BDG_DROP, ifp.
     * For muted interfaces, the first 3 are changed in BDG_LOCAL,
     * and others to BDG_DROP. Also, for incoming packets, ifp is changed
     * to BDG_DROP in case ifp == src . These mods are not necessary
     * for outgoing packets from ether_output().
     */
    BDG_STAT(ifp, BDG_IN);
    switch ((int)dst) {
    case (int)BDG_BCAST:
    case (int)BDG_MCAST:
    case (int)BDG_LOCAL:
    case (int)BDG_UNKNOWN:
    case (int)BDG_DROP:
	BDG_STAT(ifp, dst);
	break ;
    default :
	if (dst == ifp || dropit )
	    BDG_STAT(ifp, BDG_DROP);
	else
	    BDG_STAT(ifp, BDG_FORWARD);
	break ;
    }

    if ( dropit ) {
	if (dst == BDG_BCAST || dst == BDG_MCAST || dst == BDG_LOCAL)
	    return BDG_LOCAL ;
	else
	    return BDG_DROP ;
    } else {
	return (dst == ifp ? BDG_DROP : dst ) ;
    }
}

/*
 * Forward to dst, excluding src port and (if not a single interface)
 * muted interfaces. The packet is freed if marked as such
 * and not for a local destination.
 * A cleaner implementation would be to make bdg_forward()
 * always consume the packet, leaving to the caller the task
 * to make a copy if it needs it. As it is now, bdg_forward()
 * can keep a copy alive in some cases.
 */
int
bdg_forward (struct mbuf **m0, struct ifnet *dst)
{
    struct ifnet *src = (*m0)->m_pkthdr.rcvif; /* could be NULL in output */
    struct ifnet *ifp ;
    struct ip *ip;
    int error=0, s ;
    int once = 0;	/* execute the loop only once */
    int canfree = 1 ; /* can free the buf at the end */
    struct mbuf *m ;

    struct ether_header *eh = mtod(*m0, struct ether_header *); /* XXX */

    if (dst == BDG_DROP) { /* this should not happen */
	printf("xx bdg_forward for BDG_DROP)\n");
	m_freem(*m0) ;
	*m0 = NULL ;
	return 0;
    }
    if (dst == BDG_LOCAL) { /* this should not happen as well */
	printf("xx ouch, bdg_forward for local pkt\n");
	return 0;
    }
    if (dst == BDG_BCAST || dst == BDG_MCAST || dst == BDG_UNKNOWN) {
	ifp = ifnet.tqh_first ;
	once = 0 ;
	if (dst != BDG_UNKNOWN)
	    canfree = 0 ;
    } else {
	ifp = dst ;
	once = 1 ; /* and also canfree */
    }
#if IPFIREWALL
    /*
     * do filtering in a very similar way to what is done
     * in ip_output. Only for IP packets, and only pass/fail/dummynet
     * is supported. The tricky thing is to make sure that enough of
     * the packet (basically, Eth+IP+TCP/UDP headers) is contiguous
     * so that calls to m_pullup in ip_fw_chk will not kill the
     * ethernet header.
     */
    if (ip_fw_chk_ptr) {
	u_int16_t dummy ;
	struct ip_fw_chain *rule;
	int off;

	m = *m0 ;
	if (m->m_type == MT_DUMMYNET) {
	    /*
	     * the packet was already tagged, so part of the
	     * processing was already done, and we need to go down.
	     */
	    rule = (struct ip_fw_chain *)(m->m_data) ;
	    (*m0) = m = m->m_next ;

	    src = m->m_pkthdr.rcvif; /* could be NULL in output */
	    eh = mtod(m, struct ether_header *); /* XXX */
	    canfree = 1 ; /* for sure, a copy is not needed later. */
	    goto forward; /* HACK! */
	} else
	    rule = NULL ;
	if (bdg_ipfw == 0)
	    goto forward ;
	if (src == NULL)
	    goto forward ; /* do not apply to packets from ether_output */
	if (canfree == 0 ) /* need to make a copy */
	    m = m_copypacket(*m0, M_DONTWAIT);
	if (m == NULL) {
	    /* fail... */
	    return 0 ;
	}
	
	dummy = 0 ;
	/*
	 * before calling the firewall, swap fields the same as IP does.
	 * here we assume the pkt is an IP one and the header is contiguous
	 */
	eh = mtod(m, struct ether_header *);
	ip = (struct ip *)(eh + 1 ) ;
	NTOHS(ip->ip_len);
	NTOHS(ip->ip_id);
	NTOHS(ip->ip_off);

	/*
	 * The third parameter to the firewall code is the dst.  interface.
	 * Since we apply checks only on input pkts we use NULL.
	 */
	off = (*ip_fw_chk_ptr)(NULL, 0, NULL, &dummy, &m, &rule, NULL) ;
	if (m == NULL) { /* pkt discarded by firewall */
	    if (canfree)
		*m0 = NULL ;
	    return 0 ;
	}
	/*
	 * on return, the mbuf pointer might have changed. Restore
	 * *m0 (if it was the same as m), eh, ip and then
	 * restore original ordering.
	 */
	eh = mtod(m, struct ether_header *);
	ip = (struct ip *)(eh + 1 ) ;
	if (canfree) /* m was a reference to *m0, so update *m0 */
		*m0 = m ;
	HTONS(ip->ip_len);
	HTONS(ip->ip_id);
	HTONS(ip->ip_off);
	if (off == 0) {
	    if (canfree == 0)
		m_freem(m);
	    goto forward ;
	}
#if DUMMYNET
	if (off & 0x10000) {  
	    /*
	     * pass the pkt to dummynet. Need to include m, dst, rule.
	     * Dummynet consumes the packet in all cases.
	     */
	    dummynet_io((off & 0xffff), DN_TO_BDG_FWD, m, dst, NULL, 0, rule);
	    if (canfree) /* dummynet has consumed the original one */
		*m0 = NULL ;
	    return 0 ;
	}
#endif
	/* if none of the above matches, we have to drop the pkt */
	if (m)
	    m_freem(m);
	if (canfree && m != *m0) {
	    m_freem(*m0);
	    *m0 = NULL ;
	}
	return 0 ;
    }
forward:
#endif /* COMPAT_IPFW */
    if (canfree && once)
	m = *m0 ;
    else
	m = NULL ;

    for ( ; ifp ; ifp = ifp->if_link.tqe_next ) {
	if (ifp != src && ifp->if_type == IFT_ETHER &&
	    (ifp->if_flags & (IFF_UP|IFF_RUNNING)) == (IFF_UP|IFF_RUNNING) &&
	    SAMEGROUP(ifp, src) && !MUTED(ifp) ) {
	    if (m == NULL) { /* do i need to make a copy ? */
		if (canfree && ifp->if_link.tqe_next == NULL) /* last one! */
		    m = *m0 ;
		else /* on a P5-90, m_packetcopy takes 540 ticks */
		    m = m_copypacket(*m0, M_DONTWAIT);
		if (m == NULL) {
		    printf("bdg_forward: sorry, m_copy failed!\n");
		    return ENOBUFS ;
		}
	    }
	    /*
	     * execute last part of ether_output.
	     */
	    s = splimp();
	    /*
	     * Queue message on interface, and start output if interface
	     * not yet active.
	     */
	    if (IF_QFULL(&ifp->if_snd)) {
		IF_DROP(&ifp->if_snd);
		MUTE(ifp); /* good measure... */
		splx(s);
		error = ENOBUFS ;
	    } else {
		ifp->if_obytes += m->m_pkthdr.len ;
		if (m->m_flags & M_MCAST)
		    ifp->if_omcasts++;
		IF_ENQUEUE(&ifp->if_snd, m);
		if ((ifp->if_flags & IFF_OACTIVE) == 0)
		    (*ifp->if_start)(ifp);
		splx(s);
		if (m == *m0)
		    *m0 = NULL ; /* the packet is gone... */
		m = NULL ;
	    }
	    BDG_STAT(ifp, BDG_OUT);
	}
	if (once)
	    break ;
    }

    /* cleanup any mbuf leftover. */
    if (m)
	m_freem(m);
    if (m == *m0)
	*m0 = NULL ;
    if (canfree && *m0) {
	m_freem(*m0);
	*m0 = NULL ;
    }
    return error ;
}
