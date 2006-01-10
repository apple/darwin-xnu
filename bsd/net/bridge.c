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
 * $FreeBSD: src/sys/net/bridge.c,v 1.16.2.14 2001/02/09 23:13:41 luigi Exp $
 */

/*
 * This code implements bridging in FreeBSD. It only acts on ethernet
 * type of interfaces (others are still usable for routing).
 * A bridging table holds the source MAC address/dest. interface for each
 * known node. The table is indexed using an hash of the source address.
 *
 * Input packets are tapped near the beginning of ether_input(), and
 * analysed by calling bridge_in(). Depending on the result, the packet
 * can be forwarded to one or more output interfaces using bdg_forward(),
 * and/or sent to the upper layer (e.g. in case of multicast).
 *
 * Output packets are intercepted near the end of ether_output(),
 * the correct destination is selected calling bridge_dst_lookup(),
 * and then forwarding is done using bdg_forward().
 * Bridging is controlled by the sysctl variable net.link.ether.bridge
 *
 * The arp code is also modified to let a machine answer to requests
 * irrespective of the port the request came from.
 *
 * In case of loops in the bridging topology, the bridge detects this
 * event and temporarily mutes output bridging on one of the ports.
 * Periodically, interfaces are unmuted by bdg_timeout().
 * Muting is only implemented as a safety measure, and also as
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

#if defined(IPFIREWALL)
#include <net/route.h>
#include <netinet/ip_fw.h>
#if defined(DUMMYNET)
#include <netinet/ip_dummynet.h>
#endif
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

static void bdginit(void *);
static void bdgtakeifaces(void);
static void flush_table(void);
static void bdg_promisc_on(void);
static void parse_bdg_cfg(void);

static int bdg_ipfw = 0 ;
int do_bridge = 0;
bdg_hash_table *bdg_table = NULL ;

/*
 * System initialization
 */

SYSINIT(interfaces, SI_SUB_PROTO_IF, SI_ORDER_FIRST, bdginit, NULL)

static struct bdg_stats bdg_stats ;
struct bdg_softc *ifp2sc = NULL ;
/* XXX make it static of size BDG_MAX_PORTS */

#define	IFP_CHK(ifp, x) \
	if (ifp2sc[ifp->if_index].magic != 0xDEADBEEF) { x ; }

/*
 * turn off promisc mode, optionally clear the IFF_USED flag.
 * The flag is turned on by parse_bdg_config
 */
static void
bdg_promisc_off(int clear_used)
{
    struct ifnet *ifp ;
    ifnet_head_lock_shared();
    TAILQ_FOREACH(ifp, &ifnet_head, if_link) {
		if ( (ifp2sc[ifp->if_index].flags & IFF_BDG_PROMISC) ) {
			int s, ret ;
			s = splimp();
			ret = ifnet_set_promiscuous(ifp, 0);
			splx(s);
			ifp2sc[ifp->if_index].flags &= ~(IFF_BDG_PROMISC|IFF_MUTE) ;
			DEB(printf(">> now %s%d promisc OFF if_flags 0x%x bdg_flags 0x%x\n",
				ifp->if_name, ifp->if_unit,
				ifp->if_flags, ifp2sc[ifp->if_index].flags);)
		}
		if (clear_used) {
			ifp2sc[ifp->if_index].flags &= ~(IFF_USED) ;
			bdg_stats.s[ifp->if_index].name[0] = '\0';
		}
    }
    ifnet_head_done();
}

/*
 * set promisc mode on the interfaces we use.
 */
static void
bdg_promisc_on()
{
    struct ifnet *ifp ;
    int s ;

    ifnet_head_lock_shared();
    TAILQ_FOREACH(ifp, &ifnet_head, if_link) {
		if ( !BDG_USED(ifp) )
			continue ;
		if ( 0 == ( ifp->if_flags & IFF_UP) ) {
			s = splimp();
			if_up(ifp);
			splx(s);
		}
		if ( !(ifp2sc[ifp->if_index].flags & IFF_BDG_PROMISC) ) {
			int ret ;
			s = splimp();
			ret = ifnet_set_promiscuous(ifp, 1);
			splx(s);
			ifp2sc[ifp->if_index].flags |= IFF_BDG_PROMISC ;
			printf(">> now %s%d promisc ON if_flags 0x%x bdg_flags 0x%x\n",
				ifp->if_name, ifp->if_unit,
				ifp->if_flags, ifp2sc[ifp->if_index].flags);
		}
		if (BDG_MUTED(ifp)) {
			printf(">> unmuting %s%d\n", ifp->if_name, ifp->if_unit);
			BDG_UNMUTE(ifp) ;
		}
    }
    ifnet_head_done();
}

static int
sysctl_bdg(SYSCTL_HANDLER_ARGS)
{
    int error, oldval = do_bridge ;

    error = sysctl_handle_int(oidp,
	oidp->oid_arg1, oidp->oid_arg2, req);
    DEB( printf("called sysctl for bridge name %s arg2 %d val %d->%d\n",
	oidp->oid_name, oidp->oid_arg2,
	oldval, do_bridge); )

    if (bdg_table == NULL)
	do_bridge = 0 ;
    if (oldval != do_bridge) {
	bdg_promisc_off( 1 ); /* reset previously used interfaces */
	flush_table();
	if (do_bridge) {
	    parse_bdg_cfg();
	    bdg_promisc_on();
	}
    }
    return error ;
}

static char bridge_cfg[256] = { "" } ;

/*
 * parse the config string, set IFF_USED, name and cluster_id
 * for all interfaces found.
 */
static void
parse_bdg_cfg()
{
    char *p, *beg ;
    int i, l, cluster;
    struct bdg_softc *b;

    for (p= bridge_cfg; *p ; p++) {
	/* interface names begin with [a-z]  and continue up to ':' */
	if (*p < 'a' || *p > 'z')
	    continue ;
	for ( beg = p ; *p && *p != ':' ; p++ )
	    ;
	if (*p == 0) /* end of string, ':' not found */
	    return ;
	l = p - beg ; /* length of name string */
	p++ ;
	DEB(printf("-- match beg(%d) <%s> p <%s>\n", l, beg, p);)
	for (cluster = 0 ; *p && *p >= '0' && *p <= '9' ; p++)
	    cluster = cluster*10 + (*p -'0');
	/*
	 * now search in bridge strings
	 */
	for (i=0, b = ifp2sc ; i < if_index ; i++, b++) {
	    char buf[32];
	    struct ifnet *ifp = b->ifp ;

	    if (ifp == NULL)
		continue;
	    sprintf(buf, "%s%d", ifp->if_name, ifp->if_unit);
	    if (!strncmp(beg, buf, l)) { /* XXX not correct for >10 if! */
		b->cluster_id = htons(cluster) ;
		b->flags |= IFF_USED ;
		sprintf(bdg_stats.s[ifp->if_index].name,
			"%s%d:%d", ifp->if_name, ifp->if_unit, cluster);

		DEB(printf("--++  found %s\n",
		    bdg_stats.s[ifp->if_index].name);)
		break ;
	    }
	}
	if (*p == '\0')
	    break ;
    }
}

static int
sysctl_bdg_cfg(SYSCTL_HANDLER_ARGS)
{
    int error = 0 ;
    char oldval[256] ;

    strcpy(oldval, bridge_cfg) ;

    error = sysctl_handle_string(oidp,
	    bridge_cfg, oidp->oid_arg2, req);
    DEB(
	printf("called sysctl for bridge name %s arg2 %d err %d val %s->%s\n",
		oidp->oid_name, oidp->oid_arg2,
		error,
		oldval, bridge_cfg);
	)
    if (strcmp(oldval, bridge_cfg)) {
	bdg_promisc_off( 1 );  /* reset previously-used interfaces */
	flush_table();
	parse_bdg_cfg();        /* and set new ones... */
	if (do_bridge)
	    bdg_promisc_on();   /* re-enable interfaces */
    }
    return error ;
}

static int
sysctl_refresh(SYSCTL_HANDLER_ARGS)
{
    if (req->newptr)
	    bdgtakeifaces();
    
    return 0;
}


SYSCTL_DECL(_net_link_ether);
SYSCTL_PROC(_net_link_ether, OID_AUTO, bridge_cfg, CTLTYPE_STRING|CTLFLAG_RW,
	    &bridge_cfg, sizeof(bridge_cfg), &sysctl_bdg_cfg, "A",
	    "Bridge configuration");

SYSCTL_PROC(_net_link_ether, OID_AUTO, bridge, CTLTYPE_INT|CTLFLAG_RW,
	    &do_bridge, 0, &sysctl_bdg, "I", "Bridging");

SYSCTL_INT(_net_link_ether, OID_AUTO, bridge_ipfw, CTLFLAG_RW,
	    &bdg_ipfw,0,"Pass bridged pkts through firewall");

#define SY(parent, var, comment)			\
	static int var ;				\
	SYSCTL_INT(parent, OID_AUTO, var, CTLFLAG_RW, &(var), 0, comment);

int bdg_ipfw_drops;
SYSCTL_INT(_net_link_ether, OID_AUTO, bridge_ipfw_drop,
	CTLFLAG_RW, &bdg_ipfw_drops,0,"");

int bdg_ipfw_colls;
SYSCTL_INT(_net_link_ether, OID_AUTO, bridge_ipfw_collisions,
	CTLFLAG_RW, &bdg_ipfw_colls,0,"");

SYSCTL_PROC(_net_link_ether, OID_AUTO, bridge_refresh, CTLTYPE_INT|CTLFLAG_WR,
	    NULL, 0, &sysctl_refresh, "I", "iface refresh");

#if 1 /* diagnostic vars */

SY(_net_link_ether, verbose, "Be verbose");
SY(_net_link_ether, bdg_split_pkts, "Packets split in bdg_forward");

SY(_net_link_ether, bdg_thru, "Packets through bridge");

SY(_net_link_ether, bdg_copied, "Packets copied in bdg_forward");

SY(_net_link_ether, bdg_copy, "Force copy in bdg_forward");
SY(_net_link_ether, bdg_predict, "Correctly predicted header location");

SY(_net_link_ether, bdg_fw_avg, "Cycle counter avg");
SY(_net_link_ether, bdg_fw_ticks, "Cycle counter item");
SY(_net_link_ether, bdg_fw_count, "Cycle counter count");
#endif

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

/*
 * called periodically to flush entries etc.
 */
static void
bdg_timeout(void *dummy)
{
    static int slowtimer = 0 ;

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

	    bdg_promisc_on() ; /* we just need unmute, really */
	    bdg_loops = 0 ;
	}
    }
    timeout(bdg_timeout, (void *)0, 2*hz );
}

/*
 * local MAC addresses are held in a small array. This makes comparisons
 * much faster.
 */
bdg_addr bdg_addresses[BDG_MAX_PORTS];
int bdg_ports ;

/*
 * initialization of bridge code. This needs to be done after all
 * interfaces have been configured.
 */
static void
bdginit(void *dummy)
{

    if (bdg_table == NULL)
	bdg_table = (struct hash_table *)
		_MALLOC(HASH_SIZE * sizeof(struct hash_table),
		    M_IFADDR, M_WAITOK);
    flush_table();

    ifp2sc = _MALLOC(BDG_MAX_PORTS * sizeof(struct bdg_softc),
		M_IFADDR, M_WAITOK );
    bzero(ifp2sc, BDG_MAX_PORTS * sizeof(struct bdg_softc) );

    bzero(&bdg_stats, sizeof(bdg_stats) );
    bdgtakeifaces();
    bdg_timeout(0);
    do_bridge=0;
}
    
void
bdgtakeifaces(void)
{
    int i ;
    struct ifnet *ifp;
    bdg_addr *p = bdg_addresses ;
    struct bdg_softc *bp;

    bdg_ports = 0 ;
    *bridge_cfg = '\0';

    printf("BRIDGE 010131, have %d interfaces\n", if_index);
    ifnet_head_lock_shared();
    for (i = 0 , ifp = ifnet.tqh_first ; i < if_index ;
		i++, ifp = TAILQ_NEXT(ifp, if_link) )
		if (ifp->if_type == IFT_ETHER) { /* ethernet ? */
			ifnet_lladdr_copy_bytes(ifp, p->etheraddr, ETHER_ADDR_LEN);
			bp = &ifp2sc[ifp->if_index] ;
			sprintf(bridge_cfg + strlen(bridge_cfg),
			"%s%d:1,", ifp->if_name, ifp->if_unit);
			printf("-- index %d %s type %d phy %d addrl %d addr %6D\n",
				ifp->if_index,
				bdg_stats.s[ifp->if_index].name,
				(int)ifp->if_type, (int) ifp->if_physical,
				(int)ifp->if_addrlen,
				p->etheraddr, "." );
			p++ ;
			bp->ifp = ifp ;
			bp->flags = IFF_USED ;
			bp->cluster_id = htons(1) ;
			bp->magic = 0xDEADBEEF ;
	
			sprintf(bdg_stats.s[ifp->if_index].name,
			"%s%d:%d", ifp->if_name, ifp->if_unit,
			ntohs(bp->cluster_id));
			bdg_ports ++ ;
		}
	ifnet_head_done();
}

/*
 * bridge_in() is invoked to perform bridging decision on input packets.
 *
 * On Input:
 *   eh		Ethernet header of the incoming packet.
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
bridge_in(struct ifnet *ifp, struct ether_header *eh)
{
    int index;
    struct ifnet *dst , *old ;
    int dropit = BDG_MUTED(ifp) ;

    /*
     * hash the source address
     */
    index= HASH_FN(eh->ether_shost);
    bdg_table[index].used = 1 ;
    old = bdg_table[index].name ;
    if ( old ) { /* the entry is valid. */
	IFP_CHK(old, printf("bridge_in-- reading table\n") );

        if (!BDG_MATCH( eh->ether_shost, bdg_table[index].etheraddr) ) {
	    bdg_ipfw_colls++ ;
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
			BDG_MUTED(old) ? "muted":"active");
	    dropit = 1 ;
	    if ( !BDG_MUTED(old) ) {
		if (++bdg_loops > 10)
		    BDG_MUTE(old) ;
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
    dst = bridge_dst_lookup(eh);
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
 * Forward to dst, excluding src port and muted interfaces.
 * If src == NULL, the pkt comes from ether_output, and dst is the real
 * interface the packet is originally sent to. In this case we must forward
 * it to the whole cluster. We never call bdg_forward ether_output on
 * interfaces which are not part of a cluster.
 *
 * The packet is freed if possible (i.e. surely not of interest for
 * the upper layer), otherwise a copy is left for use by the caller
 * (pointer in m0).
 *
 * It would be more efficient to make bdg_forward() always consume
 * the packet, leaving to the caller the task to check if it needs a copy
 * and get one in case. As it is now, bdg_forward() can sometimes make
 * a copy whereas it is not necessary.
 *
 * XXX be careful about eh, it can be a pointer into *m
 */
struct mbuf *
bdg_forward(struct mbuf *m0, struct ether_header *const eh, struct ifnet *dst)
{
    struct ifnet *src = m0->m_pkthdr.rcvif; /* could be NULL in output */
    struct ifnet *ifp, *last = NULL ;
    int s ;
    int shared = bdg_copy ; /* someone else is using the mbuf */
    int once = 0;      /* loop only once */
    struct ifnet *real_dst = dst ; /* real dst from ether_output */
#ifdef IPFIREWALL
    struct ip_fw_chain *rule = NULL ; /* did we match a firewall rule ? */
#endif

    /*
     * XXX eh is usually a pointer within the mbuf (some ethernet drivers
     * do that), so we better copy it before doing anything with the mbuf,
     * or we might corrupt the header.
     */
    struct ether_header save_eh = *eh ;

#if defined(IPFIREWALL) && defined(DUMMYNET)
    if (m0->m_type == MT_DUMMYNET) {
	/* extract info from dummynet header */
	rule = (struct ip_fw_chain *)(m0->m_data) ;
	m0 = m0->m_next ;
	src = m0->m_pkthdr.rcvif;
	shared = 0 ; /* For sure this is our own mbuf. */
    } else
#endif
    bdg_thru++; /* only count once */

    if (src == NULL) /* packet from ether_output */
		dst = bridge_dst_lookup(eh);
    if (dst == BDG_DROP) { /* this should not happen */
		printf("xx bdg_forward for BDG_DROP\n");
		m_freem(m0);
		return NULL;
    }
    if (dst == BDG_LOCAL) { /* this should not happen as well */
		printf("xx ouch, bdg_forward for local pkt\n");
		return m0;
    }
    if (dst == BDG_BCAST || dst == BDG_MCAST || dst == BDG_UNKNOWN) {
		ifp = ifnet_head.tqh_first ; /* scan all ports */
		once = 0 ;
		if (dst != BDG_UNKNOWN) /* need a copy for the local stack */
			shared = 1 ;
    } else {
		ifp = dst ;
		once = 1 ;
    }
    if ( (u_int)(ifp) <= (u_int)BDG_FORWARD )
		panic("bdg_forward: bad dst");

#ifdef IPFIREWALL
    /*
     * Do filtering in a very similar way to what is done in ip_output.
     * Only if firewall is loaded, enabled, and the packet is not
     * from ether_output() (src==NULL, or we would filter it twice).
     * Additional restrictions may apply e.g. non-IP, short packets,
     * and pkts already gone through a pipe.
     */
    if (ip_fw_chk_ptr && bdg_ipfw != 0 && src != NULL) {
	struct ip *ip ;
	int i;

	if (rule != NULL) /* dummynet packet, already partially processed */
	    goto forward; /* HACK! I should obey the fw_one_pass */
	if (ntohs(save_eh.ether_type) != ETHERTYPE_IP)
	    goto forward ; /* not an IP packet, ipfw is not appropriate */
	if (m0->m_pkthdr.len < sizeof(struct ip) )
	    goto forward ; /* header too short for an IP pkt, cannot filter */
	/*
	 * i need some amt of data to be contiguous, and in case others need
	 * the packet (shared==1) also better be in the first mbuf.
	 */
	i = min(m0->m_pkthdr.len, max_protohdr) ;
	if ( shared || m0->m_len < i) {
	    m0 = m_pullup(m0, i) ;
	    if (m0 == NULL) {
		printf("-- bdg: pullup failed.\n") ;
		return NULL ;
	    }
	}

	/*
	 * before calling the firewall, swap fields the same as IP does.
	 * here we assume the pkt is an IP one and the header is contiguous
	 */
	ip = mtod(m0, struct ip *);
	NTOHS(ip->ip_len);
	NTOHS(ip->ip_off);

	/*
	 * The third parameter to the firewall code is the dst. interface.
	 * Since we apply checks only on input pkts we use NULL.
	 * The firewall knows this is a bridged packet as the cookie ptr
	 * is NULL.
	 */
	i = (*ip_fw_chk_ptr)(&ip, 0, NULL, NULL /* cookie */, &m0, &rule, NULL);
	if ( (i & IP_FW_PORT_DENY_FLAG) || m0 == NULL) /* drop */
	    return m0 ;
	/*
	 * If we get here, the firewall has passed the pkt, but the mbuf
	 * pointer might have changed. Restore ip and the fields NTOHS()'d.
	 */
	ip = mtod(m0, struct ip *);
	HTONS(ip->ip_len);
	HTONS(ip->ip_off);

	if (i == 0) /* a PASS rule.  */
	    goto forward ;
#ifdef DUMMYNET
	if (i & IP_FW_PORT_DYNT_FLAG) {
	    /*
	     * Pass the pkt to dummynet, which consumes it.
	     * If shared, make a copy and keep the original.
	     * Need to prepend the ethernet header, optimize the common
	     * case of eh pointing already into the original mbuf.
	     */
	    struct mbuf *m ;
	    if (shared) {
		m = m_copypacket(m0, M_DONTWAIT);
		if (m == NULL) {
		    printf("bdg_fwd: copy(1) failed\n");
		    return m0;
		}
	    } else {
		m = m0 ; /* pass the original to dummynet */
		m0 = NULL ; /* and nothing back to the caller */
	    }
	    if ( (void *)(eh + 1) == (void *)m->m_data) {
		m->m_data -= ETHER_HDR_LEN ;
		m->m_len += ETHER_HDR_LEN ;
		m->m_pkthdr.len += ETHER_HDR_LEN ;
		bdg_predict++;
	    } else {
		M_PREPEND(m, ETHER_HDR_LEN, M_DONTWAIT);
	        if (!m && verbose) printf("M_PREPEND failed\n");
		if (m == NULL) /* nope... */
		    return m0 ;
		bcopy(&save_eh, mtod(m, struct ether_header *), ETHER_HDR_LEN);
	    }
	    dummynet_io((i & 0xffff),DN_TO_BDG_FWD,m,real_dst,NULL,0,rule,0);
	    return m0 ;
	}
#endif
	/*
	 * XXX add divert/forward actions...
	 */
	/* if none of the above matches, we have to drop the pkt */
	bdg_ipfw_drops++ ;
	printf("bdg_forward: No rules match, so dropping packet!\n");
	return m0 ;
    }
forward:
#endif /* IPFIREWALL */
    /*
     * Again, bring up the headers in case of shared bufs to avoid
     * corruptions in the future.
     */
    if ( shared ) {
        int i = min(m0->m_pkthdr.len, max_protohdr) ;

	m0 = m_pullup(m0, i) ;
	if (m0 == NULL) {
	    printf("-- bdg: pullup2 failed.\n") ;
	    return NULL ;
	}
    }
    /* now real_dst is used to determine the cluster where to forward */
    if (src != NULL) /* pkt comes from ether_input */
	real_dst = src ;
    for (;;) {
	if (last) { /* need to forward packet leftover from previous loop */
	    struct mbuf *m ;
	    if (shared == 0 && once ) { /* no need to copy */
		m = m0 ;
		m0 = NULL ; /* original is gone */
	    } else {
		m = m_copypacket(m0, M_DONTWAIT);
		if (m == NULL) {
		    printf("bdg_forward: sorry, m_copypacket failed!\n");
		    return m0 ; /* the original is still there... */
		}
	    }
	    /*
	     * Add header (optimized for the common case of eh pointing
	     * already into the mbuf) and execute last part of ether_output:
	     * queue pkt and start output if interface not yet active.
	     */
	    if ( (void *)(eh + 1) == (void *)m->m_data) {
		m->m_data -= ETHER_HDR_LEN ;
		m->m_len += ETHER_HDR_LEN ;
		m->m_pkthdr.len += ETHER_HDR_LEN ;
		bdg_predict++;
	    } else {
		M_PREPEND(m, ETHER_HDR_LEN, M_DONTWAIT);
	        if (!m && verbose) printf("M_PREPEND failed\n");
		if (m == NULL)
		    return m0;
		bcopy(&save_eh, mtod(m, struct ether_header *), ETHER_HDR_LEN);
	    }
	    s = splimp();
	    if (IF_QFULL(&last->if_snd)) {
		IF_DROP(&last->if_snd);
#if 0
		BDG_MUTE(last); /* should I also mute ? */
#endif
		splx(s);
		m_freem(m); /* consume the pkt anyways */
	    } else {
		last->if_obytes += m->m_pkthdr.len ;
		if (m->m_flags & M_MCAST)
		    last->if_omcasts++;
		if (m->m_pkthdr.len != m->m_len) /* this pkt is on >1 bufs */
		    bdg_split_pkts++;

		IF_ENQUEUE(&last->if_snd, m);
		if ((last->if_flags & IFF_OACTIVE) == 0)
		    (*last->if_start)(last);
		splx(s);
	    }
	    BDG_STAT(last, BDG_OUT);
	    last = NULL ;
	    if (once)
		break ;
	}
	if (ifp == NULL)
	    break ;
	/*
	 * If the interface is used for bridging, not muted, not full,
	 * up and running, is not the source interface, and belongs to
	 * the same cluster as the 'real_dst', then send here.
	 */
	if ( BDG_USED(ifp) && !BDG_MUTED(ifp) && !IF_QFULL(&ifp->if_snd)  &&
	     (ifp->if_flags & (IFF_UP|IFF_RUNNING)) == (IFF_UP|IFF_RUNNING) &&
	     ifp != src && BDG_SAMECLUSTER(ifp, real_dst) )
	    last = ifp ;
	ifp = TAILQ_NEXT(ifp, if_link) ;
	if (ifp == NULL)
	    once = 1 ;
    }
    DEB(bdg_fw_ticks += (u_long)(rdtsc() - ticks) ; bdg_fw_count++ ;
	if (bdg_fw_count != 0) bdg_fw_avg = bdg_fw_ticks/bdg_fw_count; )
    return m0 ;
}
