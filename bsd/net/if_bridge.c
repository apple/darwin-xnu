/*
 * Copyright (c) 2004-2009 Apple Inc. All rights reserved.
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

/*	$apfw: Revision 1.19  2008/10/24 02:34:06  cbzimmer Exp $	*/
/*	$NetBSD: if_bridge.c,v 1.46 2006/11/23 04:07:07 rpaulo Exp $	*/

/*
 * Copyright 2001 Wasabi Systems, Inc.
 * All rights reserved.
 *
 * Written by Jason R. Thorpe for Wasabi Systems, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *	notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	notice, this list of conditions and the following disclaimer in the
 *	documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *	must display the following acknowledgement:
 *	This product includes software developed for the NetBSD Project by
 *	Wasabi Systems, Inc.
 * 4. The name of Wasabi Systems, Inc. may not be used to endorse
 *	or promote products derived from this software without specific prior
 *	written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY WASABI SYSTEMS, INC. ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL WASABI SYSTEMS, INC
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Copyright (c) 1999, 2000 Jason L. Wright (jason@thought.net)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *	notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	notice, this list of conditions and the following disclaimer in the
 *	documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *	must display the following acknowledgement:
 *	This product includes software developed by Jason L. Wright
 * 4. The name of the author may not be used to endorse or promote products
 *	derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * OpenBSD: if_bridge.c,v 1.60 2001/06/15 03:38:33 itojun Exp
 */

/*
 * Network interface bridge support.
 *
 * TODO:
 *
 *	- Currently only supports Ethernet-like interfaces (Ethernet,
 *	  802.11, VLANs on Ethernet, etc.)  Figure out a nice way
 *	  to bridge other types of interfaces (FDDI-FDDI, and maybe
 *	  consider heterogenous bridges).
 */

#include <sys/cdefs.h>
//_KERNEL_RCSID(0, "$NetBSD: if_bridge.c,v 1.46 2006/11/23 04:07:07 rpaulo Exp $");

//#include "opt_bridge_ipf.h"
//#include "opt_inet.h"
//#include "opt_pfil_hooks.h"
//#include "opt_wlan.h"	/* APPLE MODIFICATION <cbz@apple.com> - Proxy STA support */
//#include "bpfilter.h"
//#include "gif.h" // APPLE MODIFICATION - add gif support

#define BRIDGE_DEBUG 0

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/systm.h>
#include <sys/proc.h>
//#include <sys/pool.h>
#include <sys/kauth.h>
#include <sys/random.h>
#include <sys/kern_event.h>
#include <sys/systm.h>
#include <sys/sysctl.h>

#include <libkern/libkern.h>

#include <kern/zalloc.h>

#if NBPFILTER > 0
#include <net/bpf.h>
#endif
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_llc.h>

#include <net/if_ether.h>
#include <net/if_bridgevar.h>
#include <net/dlil.h>

#include <net/kpi_interfacefilter.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#ifdef INET6
#include <netinet/ip6.h>
#include <netinet6/in6_var.h>
#include <netinet6/ip6_var.h>
#endif

#if BRIDGE_DEBUG
#define static __private_extern__
#endif

extern void dlil_input_packet_list(struct ifnet *, struct mbuf *);

/*
 * Size of the route hash table.  Must be a power of two.
 */
/* APPLE MODIFICATION - per Wasabi performance improvement, change the hash table size */
#if 0
#ifndef BRIDGE_RTHASH_SIZE
#define	BRIDGE_RTHASH_SIZE		1024
#endif
#else
#ifndef BRIDGE_RTHASH_SIZE
#define	BRIDGE_RTHASH_SIZE		256
#endif
#endif

/* APPLE MODIFICATION - support for HW checksums */
#if APPLE_BRIDGE_HWCKSUM_SUPPORT
#include <netinet/udp.h>
#include <netinet/tcp.h>
#endif

#define	BRIDGE_RTHASH_MASK		(BRIDGE_RTHASH_SIZE - 1)

//#include "carp.h"
#if NCARP > 0
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip_carp.h>
#endif

/*
 * Maximum number of addresses to cache.
 */
#ifndef BRIDGE_RTABLE_MAX
#define	BRIDGE_RTABLE_MAX		100
#endif

/* APPLE MODIFICATION <cbz@apple.com> - add support for Proxy STA */
#if IEEE80211_PROXYSTA
/*
 * Maximum (additional to maxcache) number of proxysta addresses to cache.
 */
#ifndef BRIDGE_RTABLE_MAX_PROXYSTA
#define	BRIDGE_RTABLE_MAX_PROXYSTA		16
#endif
#endif

/*
 * Spanning tree defaults.
 */
#define	BSTP_DEFAULT_MAX_AGE		(20 * 256)
#define	BSTP_DEFAULT_HELLO_TIME		(2 * 256)
#define	BSTP_DEFAULT_FORWARD_DELAY	(15 * 256)
#define	BSTP_DEFAULT_HOLD_TIME		(1 * 256)
#define	BSTP_DEFAULT_BRIDGE_PRIORITY	0x8000
#define	BSTP_DEFAULT_PORT_PRIORITY	0x80
#define	BSTP_DEFAULT_PATH_COST		55

/*
 * Timeout (in seconds) for entries learned dynamically.
 */
#ifndef BRIDGE_RTABLE_TIMEOUT
#define	BRIDGE_RTABLE_TIMEOUT		(20 * 60)	/* same as ARP */
#endif

/*
 * Number of seconds between walks of the route list.
 */
#ifndef BRIDGE_RTABLE_PRUNE_PERIOD
#define	BRIDGE_RTABLE_PRUNE_PERIOD	(5 * 60)
#endif

/*
 * List of capabilities to mask on the member interface.
 */
#define	BRIDGE_IFCAPS_MASK	\
	(IFCAP_CSUM_IPv4_Tx |	\
	IFCAP_CSUM_TCPv4_Tx |	\
	IFCAP_CSUM_UDPv4_Tx |	\
	IFCAP_CSUM_TCPv6_Tx |	\
	IFCAP_CSUM_UDPv6_Tx)


int	bridge_rtable_prune_period = BRIDGE_RTABLE_PRUNE_PERIOD;

static zone_t bridge_rtnode_pool = NULL;

static errno_t 
bridge_iff_input(void* cookie, ifnet_t ifp, __unused protocol_family_t protocol,
                 mbuf_t *data, char **frame_ptr);
static void 
bridge_iff_event(void* cookie, ifnet_t ifp, __unused protocol_family_t protocol,
                 const struct kev_msg *event_msg);
static void 
bridge_iff_detached(void* cookie, __unused ifnet_t interface);

static uint32_t
bridge_rthash(__unused struct bridge_softc *sc, const uint8_t *addr);

static int	bridge_clone_create(struct if_clone *, int);
static void	bridge_clone_destroy(struct ifnet *);

static errno_t	bridge_ioctl(ifnet_t ifp, unsigned long cmd, void *data);
#if HAS_IF_CAP
static void	bridge_mutecaps(struct bridge_iflist *, int);
#endif
static int	bridge_init(struct ifnet *);
static void	bridge_stop(struct ifnet *, int);

#if BRIDGE_MEMBER_OUT_FILTER
static errno_t
bridge_iff_output(void *cookie, ifnet_t ifp, protocol_family_t protocol, mbuf_t *data);
static int bridge_output(struct bridge_softc *sc, ifnet_t ifp, mbuf_t m);
#endif /* BRIDGE_MEMBER_OUT_FILTER */

static errno_t	bridge_start(struct ifnet *, mbuf_t);
static errno_t bridge_set_bpf_tap(ifnet_t ifn, bpf_tap_mode mode, bpf_packet_func bpf_callback);
__private_extern__ errno_t bridge_bpf_input(ifnet_t ifp, struct mbuf *m);
__private_extern__ errno_t bridge_bpf_output(ifnet_t ifp, struct mbuf *m);

static void bridge_detach(ifnet_t ifp);

static errno_t bridge_input(struct bridge_iflist *, struct ifnet *, struct mbuf *, void *frame_header);

static void	bridge_forward(struct bridge_softc *, struct mbuf *m);

static void	bridge_timer(void *);

static void	bridge_broadcast(struct bridge_softc *, struct ifnet *,
                             struct mbuf *, int);

static int	bridge_rtupdate(struct bridge_softc *, const uint8_t *,
                            struct ifnet *, int, uint8_t);
static struct ifnet *bridge_rtlookup(struct bridge_softc *, const uint8_t *);
static void	bridge_rttrim(struct bridge_softc *);
static void	bridge_rtage(struct bridge_softc *);
static void	bridge_rtflush(struct bridge_softc *, int);
/* APPLE MODIFICATION <cbz@apple.com> - add support for Proxy STA */
#if IEEE80211_PROXYSTA
static void	bridge_rtdiscovery(struct bridge_softc *);
static void	bridge_rtpurge(struct bridge_softc *, struct ifnet *);
#endif
static int	bridge_rtdaddr(struct bridge_softc *, const uint8_t *);

static int	bridge_rtable_init(struct bridge_softc *);
static void	bridge_rtable_fini(struct bridge_softc *);

static struct bridge_rtnode *bridge_rtnode_lookup(struct bridge_softc *,
                                                  const uint8_t *);
static int	bridge_rtnode_insert(struct bridge_softc *,
                                 struct bridge_rtnode *);
static void	bridge_rtnode_destroy(struct bridge_softc *,
                                  struct bridge_rtnode *);

static struct bridge_iflist *bridge_lookup_member(struct bridge_softc *,
                                                  const char *name);
static struct bridge_iflist *bridge_lookup_member_if(struct bridge_softc *,
                                                     struct ifnet *ifp);
static void	bridge_delete_member(struct bridge_softc *,
                                 struct bridge_iflist *);

static void	bridge_ifdetach(struct bridge_iflist *bif, struct ifnet *ifp);


static int	bridge_ioctl_add(struct bridge_softc *, void *);
static int	bridge_ioctl_del(struct bridge_softc *, void *);
/* APPLE MODIFICATION <cbz@apple.com> - add support for Proxy STA */
#if IEEE80211_PROXYSTA
static int bridge_ioctl_purge(struct bridge_softc *sc, void *arg);
#endif
static int	bridge_ioctl_gifflags(struct bridge_softc *, void *);
static int	bridge_ioctl_sifflags(struct bridge_softc *, void *);
static int	bridge_ioctl_scache(struct bridge_softc *, void *);
static int	bridge_ioctl_gcache(struct bridge_softc *, void *);
static int	bridge_ioctl_gifs32(struct bridge_softc *, void *);
static int	bridge_ioctl_gifs64(struct bridge_softc *, void *);
static int	bridge_ioctl_rts32(struct bridge_softc *, void *);
static int	bridge_ioctl_rts64(struct bridge_softc *, void *);
static int	bridge_ioctl_saddr32(struct bridge_softc *, void *);
static int	bridge_ioctl_saddr64(struct bridge_softc *, void *);
static int	bridge_ioctl_sto(struct bridge_softc *, void *);
static int	bridge_ioctl_gto(struct bridge_softc *, void *);
static int	bridge_ioctl_daddr32(struct bridge_softc *, void *);
static int	bridge_ioctl_daddr64(struct bridge_softc *, void *);
static int	bridge_ioctl_flush(struct bridge_softc *, void *);
static int	bridge_ioctl_gpri(struct bridge_softc *, void *);
static int	bridge_ioctl_spri(struct bridge_softc *, void *);
static int	bridge_ioctl_ght(struct bridge_softc *, void *);
static int	bridge_ioctl_sht(struct bridge_softc *, void *);
static int	bridge_ioctl_gfd(struct bridge_softc *, void *);
static int	bridge_ioctl_sfd(struct bridge_softc *, void *);
static int	bridge_ioctl_gma(struct bridge_softc *, void *);
static int	bridge_ioctl_sma(struct bridge_softc *, void *);
static int	bridge_ioctl_sifprio(struct bridge_softc *, void *);
static int	bridge_ioctl_sifcost(struct bridge_softc *, void *);

struct bridge_control {
	int				(*bc_func)(struct bridge_softc *, void *);
	unsigned int	bc_argsize;
	unsigned int	bc_flags;
};

#define	BC_F_COPYIN		0x01	/* copy arguments in */
#define	BC_F_COPYOUT		0x02	/* copy arguments out */
#define	BC_F_SUSER		0x04	/* do super-user check */

static const struct bridge_control bridge_control_table32[] = {
	{ bridge_ioctl_add,		sizeof(struct ifbreq),
		BC_F_COPYIN|BC_F_SUSER },
	{ bridge_ioctl_del,		sizeof(struct ifbreq),
		BC_F_COPYIN|BC_F_SUSER },
	
	{ bridge_ioctl_gifflags,	sizeof(struct ifbreq),
		BC_F_COPYIN|BC_F_COPYOUT },
	{ bridge_ioctl_sifflags,	sizeof(struct ifbreq),
		BC_F_COPYIN|BC_F_SUSER },
	
	{ bridge_ioctl_scache,		sizeof(struct ifbrparam),
		BC_F_COPYIN|BC_F_SUSER },
	{ bridge_ioctl_gcache,		sizeof(struct ifbrparam),
		BC_F_COPYOUT },
	
	{ bridge_ioctl_gifs32,		sizeof(struct ifbifconf32),
		BC_F_COPYIN|BC_F_COPYOUT },
	{ bridge_ioctl_rts32,		sizeof(struct ifbaconf32),
		BC_F_COPYIN|BC_F_COPYOUT },
	
	{ bridge_ioctl_saddr32,		sizeof(struct ifbareq32),
		BC_F_COPYIN|BC_F_SUSER },
	
	{ bridge_ioctl_sto,		sizeof(struct ifbrparam),
		BC_F_COPYIN|BC_F_SUSER },
	{ bridge_ioctl_gto,		sizeof(struct ifbrparam),
		BC_F_COPYOUT },
	
	{ bridge_ioctl_daddr32,		sizeof(struct ifbareq32),
		BC_F_COPYIN|BC_F_SUSER },
	
	{ bridge_ioctl_flush,		sizeof(struct ifbreq),
		BC_F_COPYIN|BC_F_SUSER },
	
	{ bridge_ioctl_gpri,		sizeof(struct ifbrparam),
		BC_F_COPYOUT },
	{ bridge_ioctl_spri,		sizeof(struct ifbrparam),
		BC_F_COPYIN|BC_F_SUSER },
	
	{ bridge_ioctl_ght,		sizeof(struct ifbrparam),
		BC_F_COPYOUT },
	{ bridge_ioctl_sht,		sizeof(struct ifbrparam),
		BC_F_COPYIN|BC_F_SUSER },
	
	{ bridge_ioctl_gfd,		sizeof(struct ifbrparam),
		BC_F_COPYOUT },
	{ bridge_ioctl_sfd,		sizeof(struct ifbrparam),
		BC_F_COPYIN|BC_F_SUSER },
	
	{ bridge_ioctl_gma,		sizeof(struct ifbrparam),
		BC_F_COPYOUT },
	{ bridge_ioctl_sma,		sizeof(struct ifbrparam),
		BC_F_COPYIN|BC_F_SUSER },
	
	{ bridge_ioctl_sifprio,		sizeof(struct ifbreq),
		BC_F_COPYIN|BC_F_SUSER },
	
	{ bridge_ioctl_sifcost,		sizeof(struct ifbreq),
		BC_F_COPYIN|BC_F_SUSER },
	
	/* APPLE MODIFICATION <cbz@apple.com> - add support for Proxy STA */
#if IEEE80211_PROXYSTA
	{ bridge_ioctl_purge,	sizeof(struct ifbreq),
		BC_F_COPYIN|BC_F_SUSER },
#endif
};

static const struct bridge_control bridge_control_table64[] = {
	{ bridge_ioctl_add,		sizeof(struct ifbreq),
		BC_F_COPYIN|BC_F_SUSER },
	{ bridge_ioctl_del,		sizeof(struct ifbreq),
		BC_F_COPYIN|BC_F_SUSER },
	
	{ bridge_ioctl_gifflags,	sizeof(struct ifbreq),
		BC_F_COPYIN|BC_F_COPYOUT },
	{ bridge_ioctl_sifflags,	sizeof(struct ifbreq),
		BC_F_COPYIN|BC_F_SUSER },
	
	{ bridge_ioctl_scache,		sizeof(struct ifbrparam),
		BC_F_COPYIN|BC_F_SUSER },
	{ bridge_ioctl_gcache,		sizeof(struct ifbrparam),
		BC_F_COPYOUT },
	
	{ bridge_ioctl_gifs64,		sizeof(struct ifbifconf64),
		BC_F_COPYIN|BC_F_COPYOUT },
	{ bridge_ioctl_rts64,		sizeof(struct ifbaconf64),
		BC_F_COPYIN|BC_F_COPYOUT },
	
	{ bridge_ioctl_saddr64,		sizeof(struct ifbareq64),
		BC_F_COPYIN|BC_F_SUSER },
	
	{ bridge_ioctl_sto,		sizeof(struct ifbrparam),
		BC_F_COPYIN|BC_F_SUSER },
	{ bridge_ioctl_gto,		sizeof(struct ifbrparam),
		BC_F_COPYOUT },
	
	{ bridge_ioctl_daddr64,		sizeof(struct ifbareq64),
		BC_F_COPYIN|BC_F_SUSER },
	
	{ bridge_ioctl_flush,		sizeof(struct ifbreq),
		BC_F_COPYIN|BC_F_SUSER },
	
	{ bridge_ioctl_gpri,		sizeof(struct ifbrparam),
		BC_F_COPYOUT },
	{ bridge_ioctl_spri,		sizeof(struct ifbrparam),
		BC_F_COPYIN|BC_F_SUSER },
	
	{ bridge_ioctl_ght,		sizeof(struct ifbrparam),
		BC_F_COPYOUT },
	{ bridge_ioctl_sht,		sizeof(struct ifbrparam),
		BC_F_COPYIN|BC_F_SUSER },
	
	{ bridge_ioctl_gfd,		sizeof(struct ifbrparam),
		BC_F_COPYOUT },
	{ bridge_ioctl_sfd,		sizeof(struct ifbrparam),
		BC_F_COPYIN|BC_F_SUSER },
	
	{ bridge_ioctl_gma,		sizeof(struct ifbrparam),
		BC_F_COPYOUT },
	{ bridge_ioctl_sma,		sizeof(struct ifbrparam),
		BC_F_COPYIN|BC_F_SUSER },
	
	{ bridge_ioctl_sifprio,		sizeof(struct ifbreq),
		BC_F_COPYIN|BC_F_SUSER },
	
	{ bridge_ioctl_sifcost,		sizeof(struct ifbreq),
		BC_F_COPYIN|BC_F_SUSER },
	
	/* APPLE MODIFICATION <cbz@apple.com> - add support for Proxy STA */
#if IEEE80211_PROXYSTA
	{ bridge_ioctl_purge,	sizeof(struct ifbreq),
		BC_F_COPYIN|BC_F_SUSER },
#endif
};

static const unsigned int bridge_control_table_size =
sizeof(bridge_control_table32) / sizeof(bridge_control_table32[0]);

static LIST_HEAD(, bridge_softc) bridge_list = LIST_HEAD_INITIALIZER(bridge_list);

static lck_grp_t *bridge_lock_grp = NULL;
static lck_attr_t *bridge_lock_attr = NULL;

static lck_rw_t *bridge_list_lock = NULL;


static struct if_clone bridge_cloner = 
	IF_CLONE_INITIALIZER("bridge", 
						 bridge_clone_create, 
						 bridge_clone_destroy, 
						 0, 
						 IF_MAXUNIT);

#if BRIDGE_DEBUG

SYSCTL_DECL(_net_link);

SYSCTL_NODE(_net_link, IFT_BRIDGE, bridge, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "Bridge");

__private_extern__ int _if_brige_debug = 0;

SYSCTL_INT(_net_link_bridge, OID_AUTO, debug, CTLFLAG_RW,
           &_if_brige_debug, 0, "Bridge debug");

static void printf_ether_header(struct ether_header *eh);
static void printf_mbuf_data(mbuf_t m, size_t offset, size_t len);
static void printf_mbuf_pkthdr(mbuf_t m, const char *prefix, const char *suffix);
static void printf_mbuf(mbuf_t m, const char *prefix, const char *suffix);
static void link_print(struct sockaddr_dl * dl_p);

void
printf_mbuf_pkthdr(mbuf_t m, const char *prefix, const char *suffix)
{
	if (m)
		printf("%spktlen: %u rcvif: %p header: %p nextpkt: %p%s",
			   prefix ? prefix : "",
			   (unsigned int)mbuf_pkthdr_len(m), mbuf_pkthdr_rcvif(m), mbuf_pkthdr_header(m), mbuf_nextpkt(m),
			   suffix ? suffix : "");
	else
		printf("%s<NULL>%s\n", prefix, suffix);
}

void
printf_mbuf(mbuf_t m, const char *prefix, const char *suffix)
{
	if (m) {
		printf("%s%p type: %u flags: 0x%x len: %u data: %p maxlen: %u datastart: %p next: %p%s",
			   prefix ? prefix : "",
			   m, mbuf_type(m), mbuf_flags(m), (unsigned int)mbuf_len(m), mbuf_data(m), 
			   (unsigned int)mbuf_maxlen(m), mbuf_datastart(m), mbuf_next(m), 
			   !suffix || (mbuf_flags(m) & MBUF_PKTHDR) ? "" : suffix);
		if ((mbuf_flags(m) & MBUF_PKTHDR))
			printf_mbuf_pkthdr(m, " ", suffix);
	} else
		printf("%s<NULL>%s\n", prefix, suffix);
}

void
printf_mbuf_data(mbuf_t m, size_t offset, size_t len)
{
	mbuf_t			n;
	size_t			i, j;
	size_t			pktlen, mlen, maxlen;
	unsigned char	*ptr;
	
	pktlen = mbuf_pkthdr_len(m);
	
	if (offset > pktlen)
		return;
	
	maxlen = (pktlen - offset > len) ? len : pktlen;
	n = m;
	mlen = mbuf_len(n);
	ptr = mbuf_data(n);
	for (i = 0, j = 0; i < maxlen; i++, j++) {
		if (j >= mlen) {
			n = mbuf_next(n);
			if (n == 0)
				break;
			ptr = mbuf_data(n);
			mlen = mbuf_len(n);
			j = 0;
		}
		if (i >= offset) {
			printf("%02x%s", ptr[j], i % 2 ? " " : "");
		}
	}
	return;
}

static void
printf_ether_header(struct ether_header *eh)
{
	printf("%02x:%02x:%02x:%02x:%02x:%02x > %02x:%02x:%02x:%02x:%02x:%02x 0x%04x ", 
		   eh->ether_shost[0], eh->ether_shost[1], eh->ether_shost[2], 
		   eh->ether_shost[3], eh->ether_shost[4], eh->ether_shost[5], 
		   eh->ether_dhost[0], eh->ether_dhost[1], eh->ether_dhost[2], 
		   eh->ether_dhost[3], eh->ether_dhost[4], eh->ether_dhost[5], 
		   eh->ether_type);
}
#endif /* BRIDGE_DEBUG */

/*
 * bridgeattach:
 *
 *	Pseudo-device attach routine.
 */
__private_extern__ int
bridgeattach(__unused int n)
{
	int error;
	lck_grp_attr_t *lck_grp_attr = NULL;
	
	bridge_rtnode_pool = zinit(sizeof(struct bridge_rtnode), 1024 * sizeof(struct bridge_rtnode),
                               0, "bridge_rtnode");
	
	lck_grp_attr = lck_grp_attr_alloc_init();
	
	bridge_lock_grp = lck_grp_alloc_init("if_bridge", lck_grp_attr);
	
	bridge_lock_attr = lck_attr_alloc_init();
	
#if BRIDGE_DEBUG
	lck_attr_setdebug(bridge_lock_attr);
#endif

	bridge_list_lock = lck_rw_alloc_init(bridge_lock_grp, bridge_lock_attr);
	
	// can free the attributes once we've allocated the group lock
	lck_grp_attr_free(lck_grp_attr);
	
	LIST_INIT(&bridge_list);
	error = if_clone_attach(&bridge_cloner);

	return error;
}

#if BRIDGE_DEBUG

static void
link_print(struct sockaddr_dl * dl_p)
{
	int i;
	
#if 1
	printf("sdl len %d index %d family %d type 0x%x nlen %d alen %d"
           " slen %d addr ", dl_p->sdl_len,
           dl_p->sdl_index,  dl_p->sdl_family, dl_p->sdl_type,
           dl_p->sdl_nlen, dl_p->sdl_alen, dl_p->sdl_slen);
#endif
	for (i = 0; i < dl_p->sdl_alen; i++)
        printf("%s%x", i ? ":" : "",
               (CONST_LLADDR(dl_p))[i]);
	printf("\n");
	return;
}
#endif /* BRIDGE_DEBUG */


/*
 * bridge_clone_create:
 *
 *	Create a new bridge instance.
 */
/* APPLE MODIFICATION <cbz@apple.com> - add opaque <const caddr_t params> argument for cloning.  This is done for 
 net80211's VAP creation (with the Marvell codebase).  I think this could end up being useful
 for other devices, too.  This is not in an ifdef because it doesn't hurt anything to have 
 this extra param */
static int
bridge_clone_create(struct if_clone *ifc, int unit)
{
	struct bridge_softc *sc = NULL;
	struct ifnet *ifp = NULL;
	u_char eaddr[6];
	uint32_t r;
	struct ifnet_init_params init_params;
	errno_t error = 0;
	uint32_t sdl_buffer[offsetof(struct sockaddr_dl, sdl_data) + IFNAMSIZ + ETHER_ADDR_LEN];
	struct sockaddr_dl *sdl = (struct sockaddr_dl *)sdl_buffer;
	
	sc = _MALLOC(sizeof(*sc), M_DEVBUF, M_WAITOK);
	memset(sc, 0, sizeof(*sc));
	
	sc->sc_brtmax = BRIDGE_RTABLE_MAX;
	/* APPLE MODIFICATION <cbz@apple.com> - add support for Proxy STA */
#if IEEE80211_PROXYSTA
	sc->sc_brtmax_proxysta = BRIDGE_RTABLE_MAX_PROXYSTA;
#endif
	sc->sc_brttimeout = BRIDGE_RTABLE_TIMEOUT;
	sc->sc_bridge_max_age = BSTP_DEFAULT_MAX_AGE;
	sc->sc_bridge_hello_time = BSTP_DEFAULT_HELLO_TIME;
	sc->sc_bridge_forward_delay = BSTP_DEFAULT_FORWARD_DELAY;
	sc->sc_bridge_priority = BSTP_DEFAULT_BRIDGE_PRIORITY;
	sc->sc_hold_time = BSTP_DEFAULT_HOLD_TIME;
	sc->sc_filter_flags = IFBF_FILT_DEFAULT;
#ifndef BRIDGE_IPF
	/*
	 * For backwards compatibility with previous behaviour...
	 * Switch off filtering on the bridge itself if BRIDGE_IPF is
	 * not defined.
	 */
	sc->sc_filter_flags &= ~IFBF_FILT_USEIPF;
#endif
	
	/* Initialize our routing table. */
	error = bridge_rtable_init(sc);
	if (error != 0) {
		printf("bridge_clone_create: bridge_rtable_init failed %d\n", error);
		goto done;
	}
	
	LIST_INIT(&sc->sc_iflist);

	sc->sc_mtx = lck_mtx_alloc_init(bridge_lock_grp, bridge_lock_attr);
	
	/* use the interface name as the unique id for ifp recycle */
	snprintf(sc->sc_if_xname, sizeof(sc->sc_if_xname), "%s%d",
             ifc->ifc_name, unit);
	memset(&init_params, 0, sizeof(struct ifnet_init_params));
	init_params.uniqueid = sc->sc_if_xname;
	init_params.uniqueid_len = strlen(sc->sc_if_xname);
	init_params.name = ifc->ifc_name;
	init_params.unit = unit;
	init_params.family = IFNET_FAMILY_ETHERNET;
	init_params.type = IFT_BRIDGE;
	init_params.output = bridge_start;
	init_params.demux = ether_demux;
	init_params.add_proto = ether_add_proto;
	init_params.del_proto = ether_del_proto;
	init_params.check_multi = ether_check_multi;
	init_params.framer = ether_frameout;
	init_params.softc = sc;
	init_params.ioctl = bridge_ioctl;
	init_params.set_bpf_tap = bridge_set_bpf_tap;
	init_params.detach = bridge_detach;
	init_params.broadcast_addr = etherbroadcastaddr;
	init_params.broadcast_len = ETHER_ADDR_LEN;
	error = ifnet_allocate(&init_params, &ifp);
	if (error != 0) {
		printf("bridge_clone_create: ifnet_allocate failed %d\n", error);
		goto done;
	}
	sc->sc_if = ifp;
	
	error = ifnet_set_mtu(ifp, ETHERMTU);
	if (error != 0) {
		printf("bridge_clone_create: ifnet_set_mtu failed %d\n", error);
		goto done;
	}
	error = ifnet_set_addrlen(ifp, ETHER_ADDR_LEN);
	if (error != 0) {
		printf("bridge_clone_create: ifnet_set_addrlen failed %d\n", error);
		goto done;
	}
	error = ifnet_set_baudrate(ifp, 10000000) ;	// XXX: this is what IONetworking does
	if (error != 0) {
		printf("bridge_clone_create: ifnet_set_baudrate failed %d\n", error);
		goto done;
	}
	error = ifnet_set_hdrlen(ifp, ETHER_HDR_LEN);
	if (error != 0) {
		printf("bridge_clone_create: ifnet_set_hdrlen failed %d\n", error);
		goto done;
	}
	error = ifnet_set_flags(ifp, IFF_BROADCAST | IFF_SIMPLEX | IFF_NOTRAILERS | IFF_MULTICAST, 
							0xffff);
	if (error != 0) {
		printf("bridge_clone_create: ifnet_set_flags failed %d\n", error);
		goto done;
	}
	
	/*
	 * Generate a random ethernet address and use the private AC:DE:48
	 * OUI code.
	 */
	read_random(&r, sizeof(r));
	eaddr[0] = 0xAC;
	eaddr[1] = 0xDE;
	eaddr[2] = 0x48;
	eaddr[3] = (r >> 0)  & 0xffu;
	eaddr[4] = (r >> 8)  & 0xffu;
	eaddr[5] = (r >> 16) & 0xffu;
	
	memset(sdl, 0, sizeof(sdl_buffer));
	sdl->sdl_family = AF_LINK;
	sdl->sdl_nlen = strlen(sc->sc_if_xname);
	sdl->sdl_alen = ETHER_ADDR_LEN;
	sdl->sdl_len = offsetof(struct sockaddr_dl, sdl_data);
	memcpy(sdl->sdl_data, sc->sc_if_xname, sdl->sdl_nlen);
	memcpy(LLADDR(sdl), eaddr, ETHER_ADDR_LEN);
	
#if BRIDGE_DEBUG
	link_print(sdl);
#endif

	error = ifnet_attach(ifp, NULL);
	if (error != 0) {
		printf("bridge_clone_create: ifnet_attach failed %d\n", error);
		goto done;
	}
	
	error = ifnet_set_lladdr_and_type(ifp, eaddr, ETHER_ADDR_LEN, IFT_ETHER);
	if (error != 0) {
		printf("bridge_clone_create: ifnet_set_lladdr_and_type failed %d\n", error);
		goto done;
	}
	
#if APPLE_BRIDGE_HWCKSUM_SUPPORT
	/* 
	 * APPLE MODIFICATION - our bridge can support HW checksums 
	 * (useful if underlying interfaces support them) on TX,
	 * RX is not that interesting, since the stack just looks to
	 * see if the packet has been checksummed already (I think)
	 * but we might as well indicate we support it
	 */
	ifp->if_capabilities =
		IFCAP_CSUM_IPv4_Tx | IFCAP_CSUM_TCPv4_Tx | IFCAP_CSUM_UDPv4_Tx |
		IFCAP_CSUM_IPv4_Rx | IFCAP_CSUM_TCPv4_Rx | IFCAP_CSUM_UDPv4_Rx ;
#endif
	
	lck_rw_lock_exclusive(bridge_list_lock);
	LIST_INSERT_HEAD(&bridge_list, sc, sc_list);
	lck_rw_done(bridge_list_lock);

	/* attach as ethernet */
	error = bpf_attach(ifp, DLT_EN10MB, sizeof(struct ether_header), NULL, NULL);
	
done:
	if (error != 0) {
        printf("bridge_clone_create failed error %d\n", error);
		/* Cleanup TBD */
	}
	
	return error;
}

/*
 * bridge_clone_destroy:
 *
 *	Destroy a bridge instance.
 */
static void
bridge_clone_destroy(struct ifnet *ifp)
{
	struct bridge_softc *sc = (struct bridge_softc *)ifnet_softc(ifp);
	struct bridge_iflist *bif;
	int error;
	
	lck_mtx_lock(sc->sc_mtx);
	if ((sc->sc_flags & SCF_DETACHING)) {
		lck_mtx_unlock(sc->sc_mtx);
		return;
	}
	sc->sc_flags |= SCF_DETACHING;
	
	bridge_stop(ifp, 1);
	
	error = ifnet_set_flags(ifp, 0, IFF_UP);
	if (error != 0) {
		printf("bridge_clone_destroy: ifnet_set_flags failed %d\n", error);
	}
	
	while ((bif = LIST_FIRST(&sc->sc_iflist)) != NULL)
		bridge_delete_member(sc, bif);
	
	lck_mtx_unlock(sc->sc_mtx);
	
	error = ifnet_detach(ifp);
	if (error != 0) {
		printf("bridge_clone_destroy: ifnet_detach failed %d\n", error);
		if ((sc = (struct bridge_softc *)ifnet_softc(ifp)) != NULL) {
			lck_mtx_lock(sc->sc_mtx);
			sc->sc_flags &= ~SCF_DETACHING;
			lck_mtx_unlock(sc->sc_mtx);
		}
	}
	
	return;
}

#define DRVSPEC \
	if (ifd->ifd_cmd >= bridge_control_table_size) { \
		error = EINVAL; \
		break; \
	} \
	bc = &bridge_control_table[ifd->ifd_cmd]; \
	 \
	if ((cmd & IOC_DIRMASK) == IOC_INOUT && \
		(bc->bc_flags & BC_F_COPYOUT) == 0) { \
		error = EINVAL; \
		break; \
	} \
	else if (((cmd & IOC_DIRMASK) == IOC_IN) && \
			 (bc->bc_flags & BC_F_COPYOUT) != 0) { \
		error = EINVAL; \
		break; \
	} \
	 \
	if (bc->bc_flags & BC_F_SUSER) { \
		error = kauth_authorize_generic(kauth_cred_get(), KAUTH_GENERIC_ISSUSER); \
		if (error) \
			break; \
	} \
	 \
	if (ifd->ifd_len != bc->bc_argsize || \
		ifd->ifd_len > sizeof(args)) { \
		error = EINVAL; \
		break; \
	} \
	 \
	memset(&args, 0, sizeof(args)); \
	if (bc->bc_flags & BC_F_COPYIN) { \
		error = copyin(ifd->ifd_data, &args, ifd->ifd_len); \
		if (error) \
			break; \
	} \
	 \
	lck_mtx_lock(sc->sc_mtx); \
	error = (*bc->bc_func)(sc, &args); \
	lck_mtx_unlock(sc->sc_mtx); \
	if (error) \
		break; \
	 \
	if (bc->bc_flags & BC_F_COPYOUT) \
		error = copyout(&args, ifd->ifd_data, ifd->ifd_len)

/*
 * bridge_ioctl:
 *
 *	Handle a control request from the operator.
 */
static errno_t
bridge_ioctl(ifnet_t ifp, unsigned long cmd, void *data)
{
	struct bridge_softc *sc = ifnet_softc(ifp);
	struct ifreq *ifr = (struct ifreq *) data;
	int error = 0;
	
	lck_mtx_assert(sc->sc_mtx, LCK_MTX_ASSERT_NOTOWNED);

#if BRIDGE_DEBUG
	printf("bridge_ioctl: ifp %p cmd 0x%08lx (%c%c [%lu] %c %lu)\n", 
		   ifp, 
		   cmd, 
		   (cmd & IOC_IN) ? 'I' : ' ',
		   (cmd & IOC_OUT) ? 'O' : ' ',
		   IOCPARM_LEN(cmd),
		   (char)IOCGROUP(cmd),
		   cmd & 0xff);
	printf("SIOCGDRVSPEC32 %lx SIOCGDRVSPEC64 %lx\n", SIOCGDRVSPEC32, SIOCGDRVSPEC64);
#endif
	
	switch (cmd) {
		case SIOCADDMULTI:
			break;
		case SIOCDELMULTI:
			break;
			
		case SIOCSDRVSPEC32:
		case SIOCGDRVSPEC32: {
			union {
				struct ifbreq ifbreq;
				struct ifbifconf32 ifbifconf;
				struct ifbareq32 ifbareq;
				struct ifbaconf32 ifbaconf;
				struct ifbrparam ifbrparam;
			} args;
			struct ifdrv32 *ifd = (struct ifdrv32 *) data;
			const struct bridge_control *bridge_control_table = bridge_control_table32, *bc;
			
			DRVSPEC;
			
			break;
		}
		case SIOCSDRVSPEC64:
		case SIOCGDRVSPEC64: {
			union {
				struct ifbreq ifbreq;
				struct ifbifconf64 ifbifconf;
				struct ifbareq64 ifbareq;
				struct ifbaconf64 ifbaconf;
				struct ifbrparam ifbrparam;
			} args;
			struct ifdrv64 *ifd = (struct ifdrv64 *) data;
			const struct bridge_control *bridge_control_table = bridge_control_table64, *bc;
			
			DRVSPEC;
			
			break;
		}
			
		case SIOCSIFFLAGS:
			if ((ifnet_flags(ifp) & (IFF_UP|IFF_RUNNING)) == IFF_RUNNING) {
				/*
				 * If interface is marked down and it is running,
				 * then stop and disable it.
				 */
				lck_mtx_lock(sc->sc_mtx);
				bridge_stop(ifp, 1);
				lck_mtx_unlock(sc->sc_mtx);
			} else if ((ifnet_flags(ifp) & (IFF_UP|IFF_RUNNING)) == IFF_UP) {
				/*
				 * If interface is marked up and it is stopped, then
				 * start it.
				 */
				lck_mtx_lock(sc->sc_mtx);
				error = bridge_init(ifp);
				lck_mtx_unlock(sc->sc_mtx);
			}
			break;
			
		case SIOCSIFMTU:
#if 0
			/* APPLE MODIFICATION <cbz@apple.com> 
			 if we wanted to support changing the MTU */
		{
			struct ifreq *ifr = (struct ifreq *)data;
			struct bridge_iflist *bif;
			struct ifnet *dst_if;
			sc->sc_if.if_mtu = ifr->ifr_mtu;
			LIST_FOREACH(bif, &sc->sc_iflist, bif_next) {
				dst_if = bif->bif_ifp;
				error = ifnet_ioctl(dst_if, 0, cmd, data);
				if (error)
					break;
			}
		}
#else
			/* Do not allow the MTU to be changed on the bridge */
			error = EINVAL;
#endif
			break;
			
			/* APPLE MODIFICATION - don't pass this down to ether_ioctl, just indicate we don't handle it */
		case SIOCGIFMEDIA:
			error = EINVAL;
			break;
			
		case SIOCSIFLLADDR:
			error = ifnet_set_lladdr(ifp, ifr->ifr_addr.sa_data, ifr->ifr_addr.sa_len);
			if (error != 0)
				printf("bridge_ioctl: ifnet_set_lladdr failed %d\n", error);
			break;
			
		default:
			error = ether_ioctl(ifp, cmd, data);
#if BRIDGE_DEBUG
			if (error != 0)
				printf("bridge_ioctl: ether_ioctl ifp %p cmd 0x%08lx (%c%c [%lu] %c %lu) failed error: %d\n", 
					   ifp, 
					   cmd, 
					   (cmd & IOC_IN) ? 'I' : ' ',
					   (cmd & IOC_OUT) ? 'O' : ' ',
					   IOCPARM_LEN(cmd),
					   (char) IOCGROUP(cmd),
					   cmd & 0xff,
					   error);
#endif /* BRIDGE_DEBUG */
			break;
	}
	lck_mtx_assert(sc->sc_mtx, LCK_MTX_ASSERT_NOTOWNED);
	
	return (error);
}

/*
 * bridge_mutecaps:
 *
 *	Clear or restore unwanted capabilities on the member interface
 */
#if HAS_IF_CAP
void
bridge_mutecaps(struct bridge_iflist *bif, int mute)
{
	struct ifnet *ifp = bif->bif_ifp;
	struct ifcapreq ifcr;
	
	if (ifp->if_ioctl == NULL)
		return;
	
	memset(&ifcr, 0, sizeof(ifcr));
	ifcr.ifcr_capenable = ifp->if_capenable;
	
	if (mute) {
		/* mask off and save capabilities */
		bif->bif_mutecap = ifcr.ifcr_capenable & BRIDGE_IFCAPS_MASK;
		if (bif->bif_mutecap != 0)
			ifcr.ifcr_capenable &= ~BRIDGE_IFCAPS_MASK;
	} else
	/* restore muted capabilities */
		ifcr.ifcr_capenable |= bif->bif_mutecap;
	
	if (bif->bif_mutecap != 0) {
		(void) (*ifp->if_ioctl)(ifp, SIOCSIFCAP, (caddr_t)&ifcr);
	}
}
#endif /* HAS_IF_CAP */

/*
 * bridge_lookup_member:
 */
static struct bridge_iflist *
bridge_lookup_member(struct bridge_softc *sc, const char *name)
{
	struct bridge_iflist *bif;
	struct ifnet *ifp;
	char if_xname[IFNAMSIZ];
	
	lck_mtx_assert(sc->sc_mtx, LCK_MTX_ASSERT_OWNED);

	LIST_FOREACH(bif, &sc->sc_iflist, bif_next) {
		ifp = bif->bif_ifp;
		snprintf(if_xname, sizeof(if_xname), "%s%d", 
                 ifnet_name(ifp), ifnet_unit(ifp));
		if (strncmp(if_xname, name, sizeof(if_xname)) == 0)
			return (bif);
	}
	
	return (NULL);
}

/*
 * bridge_lookup_member_if:
 */
static struct bridge_iflist *
bridge_lookup_member_if(struct bridge_softc *sc, struct ifnet *member_ifp)
{
	struct bridge_iflist *bif;
	
	lck_mtx_assert(sc->sc_mtx, LCK_MTX_ASSERT_OWNED);

	LIST_FOREACH(bif, &sc->sc_iflist, bif_next) {
		if (bif->bif_ifp == member_ifp)
			return (bif);
	}
	
	return (NULL);
}

static errno_t 
bridge_iff_input(void* cookie, ifnet_t ifp, __unused protocol_family_t protocol,
                 mbuf_t *data, char **frame_ptr)
{
	errno_t error = 0;
	struct bridge_iflist *bif = (struct bridge_iflist *)cookie;
	struct bridge_softc *sc = bif->bif_sc;
	int included = 0;
	size_t frmlen = 0;
	mbuf_t m = *data;

	if ((m->m_flags & M_PROTO1))
		goto out;
	
	if (*frame_ptr >= (char *)mbuf_datastart(m) && *frame_ptr <= (char *)mbuf_data(m)) {
		included = 1;
		frmlen = (char *)mbuf_data(m) - *frame_ptr;
	}
#if BRIDGE_DEBUG
	if (_if_brige_debug) {
		printf("bridge_iff_input %s%d from %s%d m %p data %p frame %p %s frmlen %lu\n", 
			   ifnet_name(sc->sc_if), ifnet_unit(sc->sc_if),
			   ifnet_name(ifp), ifnet_unit(ifp), 
			   m, mbuf_data(m), *frame_ptr, included ? "inside" : "outside", frmlen);
		
		if (_if_brige_debug > 1) {
			printf_mbuf(m, "bridge_iff_input[", "\n");
			printf_ether_header((struct ether_header *)*frame_ptr);
			printf_mbuf_data(m, 0, 20);
			printf("\n");
		}
	}
#endif /* BRIDGE_DEBUG */

	/* Move data pointer to start of frame to the link layer header */
	if (included) {
		(void) mbuf_setdata(m, (char *)mbuf_data(m) - frmlen, mbuf_len(m) + frmlen);
		(void) mbuf_pkthdr_adjustlen(m, frmlen);
	} else {
		printf("bridge_iff_input: frame_ptr outside mbuf\n");
		goto out;
	}
	
	error = bridge_input(bif, ifp, m, *frame_ptr);
	
	/* Adjust packet back to original */
	if (error == 0) {
		(void) mbuf_setdata(m, (char *)mbuf_data(m) + frmlen, mbuf_len(m) - frmlen);
		(void) mbuf_pkthdr_adjustlen(m, -frmlen);
	}
#if BRIDGE_DEBUG
	if (_if_brige_debug > 1) {
		printf("\n");
		printf_mbuf(m, "bridge_iff_input]", "\n");
	}
#endif /* BRIDGE_DEBUG */

out:
	lck_mtx_assert(sc->sc_mtx, LCK_MTX_ASSERT_NOTOWNED);
	
	return error;
}


#if BRIDGE_MEMBER_OUT_FILTER
static errno_t
bridge_iff_output(void *cookie, ifnet_t ifp, __unused protocol_family_t protocol, mbuf_t *data)
{
	errno_t error = 0;
	struct bridge_iflist *bif = (struct bridge_iflist *)cookie;
	struct bridge_softc *sc = bif->bif_sc;
	mbuf_t m = *data;
	
	if ((m->m_flags & M_PROTO1))
		goto out;
	
#if BRIDGE_DEBUG
	if (_if_brige_debug) {
		printf("bridge_iff_output %s%d from %s%d m %p data %p\n", 
				ifnet_name(sc->sc_if), ifnet_unit(sc->sc_if),
				ifnet_name(ifp), ifnet_unit(ifp), 
				m, mbuf_data(m));
	}
#endif /* BRIDGE_DEBUG */

	error = bridge_output(sc, ifp, m);
	if (error != 0) {
		printf("bridge_iff_output: bridge_output failed error %d\n", error);
	}

out:	
	lck_mtx_assert(sc->sc_mtx, LCK_MTX_ASSERT_NOTOWNED);

	return error;
}
#endif /* BRIDGE_MEMBER_OUT_FILTER */


static void 
bridge_iff_event(void* cookie, ifnet_t ifp, __unused protocol_family_t protocol,
                 const struct kev_msg *event_msg)
{
	struct bridge_iflist *bif = (struct bridge_iflist *)cookie;
	
	if (event_msg->vendor_code == KEV_VENDOR_APPLE && 
		event_msg->kev_class == KEV_NETWORK_CLASS &&
		event_msg->kev_subclass == KEV_DL_SUBCLASS) {
		switch (event_msg->event_code) {
			case KEV_DL_IF_DETACHING:
				bridge_ifdetach(bif, ifp);
				break;
				
			default:
				break;
		}
	}		
}

static void 
bridge_iff_detached(void* cookie, __unused ifnet_t interface)
{
	struct bridge_iflist *bif = (struct bridge_iflist *)cookie;
	
	_FREE(bif, M_DEVBUF);
	
	return;
}

/*
 * bridge_delete_member:
 *
 *	Delete the specified member interface.
 */
static void
bridge_delete_member(struct bridge_softc *sc, struct bridge_iflist *bif)
{
	struct ifnet *ifs = bif->bif_ifp;
	
	switch (ifnet_type(ifs)) {
        case IFT_ETHER:
            /*
             * Take the interface out of promiscuous mode.
             */
            (void) ifnet_set_promiscuous(ifs, 0);
            break;
#if NGIF > 0
        case IFT_GIF:
            break;
#endif
        default:
#ifdef DIAGNOSTIC
            panic("bridge_delete_member: impossible");
#endif
            break;
	}

	ifs->if_bridge = NULL;
	LIST_REMOVE(bif, bif_next);

	/* Respect lock ordering with DLIL lock */
	lck_mtx_unlock(sc->sc_mtx);
	iflt_detach(bif->bif_iff_ref);
	lck_mtx_lock(sc->sc_mtx);
	
	bridge_rtdelete(sc, ifs, IFBF_FLUSHALL);
	
	if (ifnet_flags(sc->sc_if) & IFF_RUNNING)
		bstp_initialization(sc);
	
	/* On the last deleted interface revert the MTU */
	
	if (LIST_EMPTY(&sc->sc_iflist))
		(void) ifnet_set_mtu(sc->sc_if, ETHERMTU);
}

static int
bridge_ioctl_add(struct bridge_softc *sc, void *arg)
{
	struct ifbreq *req = arg;
	struct bridge_iflist *bif = NULL;
	struct ifnet *ifs;
	int error = 0;
	/* APPLE MODIFICATION <cbz@apple.com> - is this a proxy sta being added? */
#if IEEE80211_PROXYSTA
	struct bridge_rtnode *brt;
#endif
	
	error = ifnet_find_by_name(req->ifbr_ifsname, &ifs);
	if (error || ifs == NULL)
		return (ENOENT);
	
	/* Is the interface already attached to this bridge interface */
	if (ifs->if_bridge == sc)
		return (EEXIST);
	
	if (ifs->if_bridge != NULL)
		return (EBUSY);
	
	/* First added interface resets the MTU */
	
	if (LIST_EMPTY(&sc->sc_iflist))
		(void) ifnet_set_mtu(sc->sc_if, ETHERMTU);
	
	if (ifnet_mtu(sc->sc_if) != ifnet_mtu(ifs))
		return (EINVAL);

	bif = _MALLOC(sizeof(*bif), M_DEVBUF, M_WAITOK|M_ZERO);
	if (bif == NULL)
		return (ENOMEM);
	
	bif->bif_ifp = ifs;
	bif->bif_flags = IFBIF_LEARNING | IFBIF_DISCOVER;
	bif->bif_priority = BSTP_DEFAULT_PORT_PRIORITY;
	bif->bif_path_cost = BSTP_DEFAULT_PATH_COST;
	bif->bif_sc = sc;
	
	switch (ifnet_type(ifs)) {
        case IFT_ETHER:
            /*
             * Place the interface into promiscuous mode.
             */
            error = ifnet_set_promiscuous(ifs, 1);
            if (error)
                goto out;
#if HAS_IF_CAP            
            bridge_mutecaps(bif, 1);
#endif
            break;
#if NGIF > 0
            case IFT_GIF:
            break;
#endif
            default:
            error = EINVAL;
            goto out;
	}
	
	/*
	 * If the LINK0 flag is set, and this is the first member interface,
	 * attempt to inherit its link-layer address.
	 */
	if ((ifnet_flags(sc->sc_if) & IFF_LINK0) && LIST_EMPTY(&sc->sc_iflist) &&
	    ifnet_type(ifs) == IFT_ETHER) {
	    (void) ifnet_set_lladdr(sc->sc_if, ifnet_lladdr(ifs),
	    						ETHER_ADDR_LEN);
	}
	
	// install an interface filter
	{
		struct iff_filter iff;
		
		memset(&iff, 0, sizeof(struct iff_filter));
		
		iff.iff_cookie = bif;
		iff.iff_name = "com.apple.kernel.bsd.net.if_bridge";
		iff.iff_input = bridge_iff_input;
#if BRIDGE_MEMBER_OUT_FILTER
		iff.iff_output = bridge_iff_output;
#endif /* BRIDGE_MEMBER_OUT_FILTER */
		iff.iff_event = bridge_iff_event;
		iff.iff_detached = bridge_iff_detached;
		
		/* Respect lock ordering with DLIL lock */
		lck_mtx_unlock(sc->sc_mtx);
		error = iflt_attach(ifs, &iff, &bif->bif_iff_ref);
		lck_mtx_lock(sc->sc_mtx);
		if (error != 0) {
			printf("bridge_ioctl_add: iflt_attach failed %d\n", error);
			goto out;
		}
	}
	ifs->if_bridge = sc;
	LIST_INSERT_HEAD(&sc->sc_iflist, bif, bif_next);
	
	
	if (ifnet_flags(sc->sc_if) & IFF_RUNNING)
		bstp_initialization(sc);
	else
		bstp_stop(sc);
	
	/* APPLE MODIFICATION <cbz@apple.com> - is this a proxy sta being added? */
#if IEEE80211_PROXYSTA
	brt = bridge_rtnode_lookup(sc, ifnet_lladdr(ifs));
	if (brt) {
#if DIAGNOSTIC
		printf( "%s: attach %s to bridge as proxysta for %02x:%02x:%02x:%02x:%02x:%02x discovered on %s\n",
               __func__, ifs->if_xname, brt->brt_addr[0], brt->brt_addr[1], brt->brt_addr[2], 
               brt->brt_addr[3], brt->brt_addr[4], brt->brt_addr[5], brt->brt_ifp->if_xname );
#endif
		brt->brt_ifp_proxysta = ifs;
	}
#endif
	
	
out:
	if (error) {
		if (bif != NULL)
			_FREE(bif, M_DEVBUF);
	}
	return (error);
}

static int
bridge_ioctl_del(struct bridge_softc *sc, void *arg)
{
	struct ifbreq *req = arg;
	struct bridge_iflist *bif;
	
	bif = bridge_lookup_member(sc, req->ifbr_ifsname);
	if (bif == NULL)
		return (ENOENT);
	
	bridge_delete_member(sc, bif);
	
	return (0);
}

/* APPLE MODIFICATION <cbz@apple.com> - add support for Proxy STA */
#if IEEE80211_PROXYSTA
static int
bridge_ioctl_purge(struct bridge_softc *sc, void *arg)
{
	struct ifbreq *req = arg;
	struct bridge_iflist *bif;
	struct ifnet *ifs;
	
	bif = bridge_lookup_member(sc, req->ifbr_ifsname);
	if (bif == NULL)
		return (ENOENT);
	
	ifs = bif->bif_ifp;
	bridge_rtpurge(sc, ifs);
	
	return (0);
}
#endif

static int
bridge_ioctl_gifflags(struct bridge_softc *sc, void *arg)
{
	struct ifbreq *req = arg;
	struct bridge_iflist *bif;
	
	bif = bridge_lookup_member(sc, req->ifbr_ifsname);
	if (bif == NULL)
		return (ENOENT);
	
	req->ifbr_ifsflags = bif->bif_flags;
	req->ifbr_state = bif->bif_state;
	req->ifbr_priority = bif->bif_priority;
	req->ifbr_path_cost = bif->bif_path_cost;
	req->ifbr_portno = ifnet_index(bif->bif_ifp) & 0xffff;
	
	return (0);
}

static int
bridge_ioctl_sifflags(struct bridge_softc *sc, void *arg)
{
	struct ifbreq *req = arg;
	struct bridge_iflist *bif;
	
	bif = bridge_lookup_member(sc, req->ifbr_ifsname);
	if (bif == NULL)
		return (ENOENT);
	
	if (req->ifbr_ifsflags & IFBIF_STP) {
		switch (ifnet_type(bif->bif_ifp)) {
            case IFT_ETHER:
                /* These can do spanning tree. */
                break;
                
            default:
                /* Nothing else can. */
                return (EINVAL);
		}
	}
	
	/* APPLE MODIFICATION <cbz@apple.com> - add support for Proxy STA */
#if IEEE80211_PROXYSTA
	if ((bif->bif_flags & IFBIF_PROXYSTA_DISCOVER) && 
	    ((req->ifbr_ifsflags & IFBIF_PROXYSTA_DISCOVER) == 0))
		bridge_rtpurge(sc, bif->bif_ifp);
#endif
	
	bif->bif_flags = req->ifbr_ifsflags;
	
	if (ifnet_flags(sc->sc_if) & IFF_RUNNING)
		bstp_initialization(sc);
	
	/* APPLE MODIFICATION <cbz@apple.com> - add support for Proxy STA */
#if IEEE80211_PROXYSTA
	if (bif->bif_flags & IFBIF_PROXYSTA_DISCOVER)
		bridge_rtdiscovery(sc);
#endif
	
	return (0);
}

static int
bridge_ioctl_scache(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;
	
	sc->sc_brtmax = param->ifbrp_csize;
	bridge_rttrim(sc);
	
	return (0);
}

static int
bridge_ioctl_gcache(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;
	
	param->ifbrp_csize = sc->sc_brtmax;
	
	return (0);
}

#define BRIDGE_IOCTL_GIFS \
	struct bridge_iflist *bif; \
	struct ifbreq breq; \
	int count, error = 0; \
	uint32_t len; \
	\
	count = 0; \
	LIST_FOREACH(bif, &sc->sc_iflist, bif_next) \
	count++; \
	\
	if (bifc->ifbic_len == 0) { \
		bifc->ifbic_len = sizeof(breq) * count; \
		return (0); \
	} \
	\
	count = 0; \
	len = bifc->ifbic_len; \
	memset(&breq, 0, sizeof breq); \
	LIST_FOREACH(bif, &sc->sc_iflist, bif_next) { \
		if (len < sizeof(breq)) \
			break; \
	\
		snprintf(breq.ifbr_ifsname, sizeof(breq.ifbr_ifsname), "%s%d", \
                 ifnet_name(bif->bif_ifp), ifnet_unit(bif->bif_ifp)); \
		breq.ifbr_ifsflags = bif->bif_flags; \
		breq.ifbr_state = bif->bif_state; \
		breq.ifbr_priority = bif->bif_priority; \
		breq.ifbr_path_cost = bif->bif_path_cost; \
		breq.ifbr_portno = ifnet_index(bif->bif_ifp) & 0xffff; \
		error = copyout(&breq, bifc->ifbic_req + count * sizeof(breq), sizeof(breq)); \
		if (error) \
			break; \
		count++; \
		len -= sizeof(breq); \
	} \
	\
	bifc->ifbic_len = sizeof(breq) * count


static int
bridge_ioctl_gifs64(struct bridge_softc *sc, void *arg)
{
	struct ifbifconf64 *bifc = arg;
	
	BRIDGE_IOCTL_GIFS;

	return (error);
}

static int
bridge_ioctl_gifs32(struct bridge_softc *sc, void *arg)
{
	struct ifbifconf32 *bifc = arg;

	BRIDGE_IOCTL_GIFS;

	return (error);
}

#define BRIDGE_IOCTL_RTS \
	struct bridge_rtnode *brt; \
	int count = 0, error = 0; \
	uint32_t len; \
	struct timespec now; \
	 \
	if (bac->ifbac_len == 0) \
		return (0); \
	 \
	len = bac->ifbac_len; \
	LIST_FOREACH(brt, &sc->sc_rtlist, brt_list) { \
		if (len < sizeof(bareq)) \
			goto out; \
		memset(&bareq, 0, sizeof(bareq)); \
		snprintf(bareq.ifba_ifsname, sizeof(bareq.ifba_ifsname), "%s%d", \
                 ifnet_name(brt->brt_ifp), ifnet_unit(brt->brt_ifp)); \
		memcpy(bareq.ifba_dst, brt->brt_addr, sizeof(brt->brt_addr)); \
		if ((brt->brt_flags & IFBAF_TYPEMASK) == IFBAF_DYNAMIC) { \
			nanouptime(&now); \
			if (brt->brt_expire >= (unsigned long)now.tv_sec) \
				bareq.ifba_expire = brt->brt_expire - now.tv_sec; \
			else \
				bareq.ifba_expire = 0; \
		} else \
			bareq.ifba_expire = 0; \
		bareq.ifba_flags = brt->brt_flags; \
		 \
		error = copyout(&bareq, bac->ifbac_req + count * sizeof(bareq), sizeof(bareq)); \
		if (error) \
			goto out; \
		count++; \
		len -= sizeof(bareq); \
	} \
out: \
	bac->ifbac_len = sizeof(bareq) * count
	

static int
bridge_ioctl_rts64(struct bridge_softc *sc, void *arg)
{
	struct ifbaconf64 *bac = arg;
	struct ifbareq64 bareq;
	
	BRIDGE_IOCTL_RTS;

	return (error);
}

static int
bridge_ioctl_rts32(struct bridge_softc *sc, void *arg)
{
	struct ifbaconf32 *bac = arg;
	struct ifbareq32 bareq;
	
	BRIDGE_IOCTL_RTS;

	return (error);
}

static int
bridge_ioctl_saddr64(struct bridge_softc *sc, void *arg)
{
	struct ifbareq64 *req = arg;
	struct bridge_iflist *bif;
	int error;
	
	bif = bridge_lookup_member(sc, req->ifba_ifsname);
	if (bif == NULL)
		return (ENOENT);
	
	error = bridge_rtupdate(sc, req->ifba_dst, bif->bif_ifp, 1,
                            req->ifba_flags);
	
	return (error);
}

static int
bridge_ioctl_saddr32(struct bridge_softc *sc, void *arg)
{
	struct ifbareq32 *req = arg;
	struct bridge_iflist *bif;
	int error;
	
	bif = bridge_lookup_member(sc, req->ifba_ifsname);
	if (bif == NULL)
		return (ENOENT);
	
	error = bridge_rtupdate(sc, req->ifba_dst, bif->bif_ifp, 1,
                            req->ifba_flags);
	
	return (error);
}

static int
bridge_ioctl_sto(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;
	
	sc->sc_brttimeout = param->ifbrp_ctime;
	
	return (0);
}

static int
bridge_ioctl_gto(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;
	
	param->ifbrp_ctime = sc->sc_brttimeout;
	
	return (0);
}

static int
bridge_ioctl_daddr64(struct bridge_softc *sc, void *arg)
{
	struct ifbareq64 *req = arg;
	
	return (bridge_rtdaddr(sc, req->ifba_dst));
}

static int
bridge_ioctl_daddr32(struct bridge_softc *sc, void *arg)
{
	struct ifbareq32 *req = arg;
	
	return (bridge_rtdaddr(sc, req->ifba_dst));
}

static int
bridge_ioctl_flush(struct bridge_softc *sc, void *arg)
{
	struct ifbreq *req = arg;
	
	bridge_rtflush(sc, req->ifbr_ifsflags);
	
	return (0);
}

static int
bridge_ioctl_gpri(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;
	
	param->ifbrp_prio = sc->sc_bridge_priority;
	
	return (0);
}

static int
bridge_ioctl_spri(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;
	
	sc->sc_bridge_priority = param->ifbrp_prio;
	
	if (ifnet_flags(sc->sc_if) & IFF_RUNNING)
		bstp_initialization(sc);
	
	return (0);
}

static int
bridge_ioctl_ght(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;
	
	param->ifbrp_hellotime = sc->sc_bridge_hello_time >> 8;
	
	return (0);
}

static int
bridge_ioctl_sht(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;
	
	if (param->ifbrp_hellotime == 0)
		return (EINVAL);
	sc->sc_bridge_hello_time = param->ifbrp_hellotime << 8;
	
	if (ifnet_flags(sc->sc_if) & IFF_RUNNING)
		bstp_initialization(sc);
	
	return (0);
}

static int
bridge_ioctl_gfd(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;
	
	param->ifbrp_fwddelay = sc->sc_bridge_forward_delay >> 8;
	
	return (0);
}

static int
bridge_ioctl_sfd(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;
	
	if (param->ifbrp_fwddelay == 0)
		return (EINVAL);
	sc->sc_bridge_forward_delay = param->ifbrp_fwddelay << 8;
	
	if (ifnet_flags(sc->sc_if) & IFF_RUNNING)
		bstp_initialization(sc);
	
	return (0);
}

static int
bridge_ioctl_gma(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;
	
	param->ifbrp_maxage = sc->sc_bridge_max_age >> 8;
	
	return (0);
}

static int
bridge_ioctl_sma(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;
	
	if (param->ifbrp_maxage == 0)
		return (EINVAL);
	sc->sc_bridge_max_age = param->ifbrp_maxage << 8;
	
	if (ifnet_flags(sc->sc_if) & IFF_RUNNING)
		bstp_initialization(sc);
	
	return (0);
}

static int
bridge_ioctl_sifprio(struct bridge_softc *sc, void *arg)
{
	struct ifbreq *req = arg;
	struct bridge_iflist *bif;
	
	bif = bridge_lookup_member(sc, req->ifbr_ifsname);
	if (bif == NULL)
		return (ENOENT);
	
	bif->bif_priority = req->ifbr_priority;
	
	if (ifnet_flags(sc->sc_if) & IFF_RUNNING)
		bstp_initialization(sc);
	
	return (0);
}

/* APPLE MODIFICATION <cbz@apple.com> - add support for Proxy STA */
#if IEEE80211_PROXYSTA
static void
bridge_proxysta_notify_macaddr(struct ifnet *ifp, int op, const uint8_t *mac)
{
	struct proxy_sta_event iev;
	
	memset(&iev, 0, sizeof(iev));
	memcpy(iev.iev_addr, mac, ETHER_ADDR_LEN);
	
	rt_proxystamsg(ifp, op, &iev, sizeof(iev));
}

static void
bridge_proxysta_discover(struct ifnet *ifp, const uint8_t *mac)
{
	bridge_proxysta_notify_macaddr( ifp, RTM_PROXYSTA_DISCOVERY, mac );
}

static void
bridge_proxysta_idle_timeout(struct ifnet *ifp, const uint8_t *mac)
{
	bridge_proxysta_notify_macaddr( ifp, RTM_PROXYSTA_IDLE_TIMEOUT, mac );
}
#endif

static int
bridge_ioctl_sifcost(struct bridge_softc *sc, void *arg)
{
	struct ifbreq *req = arg;
	struct bridge_iflist *bif;
	
	bif = bridge_lookup_member(sc, req->ifbr_ifsname);
	if (bif == NULL)
		return (ENOENT);
	
	bif->bif_path_cost = req->ifbr_path_cost;
	
	if (ifnet_flags(sc->sc_if) & IFF_RUNNING)
		bstp_initialization(sc);
	
	return (0);
}

/*
 * bridge_ifdetach:
 *
 *	Detach an interface from a bridge.  Called when a member
 *	interface is detaching.
 */
static void
bridge_ifdetach(struct bridge_iflist *bif, struct ifnet *ifp)
{
	struct bridge_softc *sc = bif->bif_sc;
	struct ifbreq breq;
	
	memset(&breq, 0, sizeof(breq));
	snprintf(breq.ifbr_ifsname, sizeof(breq.ifbr_ifsname),  "%s%d",
             ifnet_name(ifp), ifnet_unit(ifp));
	
	lck_mtx_lock(sc->sc_mtx);
	
	(void) bridge_ioctl_del(sc, &breq);
	
	lck_mtx_unlock(sc->sc_mtx);
}

/*
 * bridge_init:
 *
 *	Initialize a bridge interface.
 */
static int
bridge_init(struct ifnet *ifp)
{
	struct bridge_softc *sc = ifnet_softc(ifp);
	struct timespec ts;
	errno_t error;
	
	if (ifnet_flags(ifp) & IFF_RUNNING)
		return (0);
	
	ts.tv_sec = bridge_rtable_prune_period;
	ts.tv_nsec = 0;
	bsd_timeout(bridge_timer, sc, &ts);
	
	error = ifnet_set_flags(ifp, IFF_RUNNING, IFF_RUNNING);
	if (error == 0)
		bstp_initialization(sc);
	
	return error;
}

/*
 * bridge_stop:
 *
 *	Stop the bridge interface.
 */
static void
bridge_stop(struct ifnet *ifp, __unused int disable)
{
	struct bridge_softc *sc = ifnet_softc(ifp);
	
	if ((ifnet_flags(ifp) & IFF_RUNNING) == 0)
		return;
	
	bsd_untimeout(bridge_timer, sc);
	bstp_stop(sc);
		
	bridge_rtflush(sc, IFBF_FLUSHDYN);
	
	(void) ifnet_set_flags(ifp, 0, IFF_RUNNING);
}

/*
 * bridge_enqueue:
 *
 *	Enqueue a packet on a bridge member interface.
 *
 *	Note: this is called both on the input and output path so this routine 
 *	cannot simply muck with the HW checksum flag. For the time being we
 *	rely on the caller to do the right thing.
 */
__private_extern__ void
bridge_enqueue(struct bridge_softc *sc, struct ifnet *dst_ifp, struct mbuf *m)
{
	int len, error;

	lck_mtx_assert(sc->sc_mtx, LCK_MTX_ASSERT_OWNED);

#if BRIDGE_DEBUG	
	if (_if_brige_debug)
		printf("bridge_enqueue sc %s%d to dst_ifp %s%d m %p\n", 
			ifnet_name(sc->sc_if), ifnet_unit(sc->sc_if), 
			ifnet_name(dst_ifp), ifnet_unit(dst_ifp), m);
#endif /* BRIDGE_DEBUG */
        
	len = m->m_pkthdr.len;
	m->m_flags |= M_PROTO1; //set to avoid loops 
	
	error = ifnet_output_raw(dst_ifp, 0, m);
	if (error == 0) {
		(void) ifnet_stat_increment_out(sc->sc_if, 1, len, 0);
	} else {
		(void) ifnet_stat_increment_out(sc->sc_if, 0, 0, 1);
	}
	
	return;
}


#if BRIDGE_MEMBER_OUT_FILTER

/*
 * bridge_output:
 *
 *	Send output from a bridge member interface.  This
 *	performs the bridging function for locally originated
 *	packets.
 *
 *	The mbuf has the Ethernet header already attached.  We must
 *	enqueue or free the mbuf before returning.
 */
static int
bridge_output(struct bridge_softc *sc, ifnet_t ifp, mbuf_t m)
{
	struct ether_header *eh;
	struct ifnet *dst_if;
	
#if BRIDGE_DEBUG
	if (_if_brige_debug)
		printf("bridge_output ifp %p %s%d\n", ifp, ifnet_name(ifp), ifnet_unit(ifp));
#endif /* BRIDGE_DEBUG */
	
	if (m->m_len < ETHER_HDR_LEN) {
		m = m_pullup(m, ETHER_HDR_LEN);
		if (m == NULL) {
			printf("bridge_output ifp %p m_pullup failed\n", ifp);
			return EJUSTRETURN;
		}
	}
	
	eh = mtod(m, struct ether_header *);

	/* APPLE MODIFICATION <jhw@apple.com>
	 * If the packet is an 802.1X ethertype, then only send on the
	 * original output interface.
	 */
	if (eh->ether_type == htons(ETHERTYPE_PAE)) {
		dst_if = ifp;
		goto sendunicast;
	}
	
	/*
	 * If bridge is down, but the original output interface is up,
	 * go ahead and send out that interface.  Otherwise, the packet
	 * is dropped below.
	 */
	if ((ifnet_flags(sc->sc_if) & IFF_RUNNING) == 0) {
		dst_if = ifp;
		goto sendunicast;
	}
	
	lck_mtx_lock(sc->sc_mtx);
	
	/*
	 * If the packet is a multicast, or we don't know a better way to
	 * get there, send to all interfaces.
	 */
	if (ETHER_IS_MULTICAST(eh->ether_dhost))
		dst_if = NULL;
	else
		dst_if = bridge_rtlookup(sc, eh->ether_dhost);
	if (dst_if == NULL) {
		struct bridge_iflist *bif;
		struct mbuf *mc;
		int used = 0;
		
		LIST_FOREACH(bif, &sc->sc_iflist, bif_next) {
			dst_if = bif->bif_ifp;
			if ((ifnet_flags(dst_if) & IFF_RUNNING) == 0)
				continue;
			
			/*
			 * If this is not the original output interface,
			 * and the interface is participating in spanning
			 * tree, make sure the port is in a state that
			 * allows forwarding.
			 */
			if (dst_if != ifp &&
				(bif->bif_flags & IFBIF_STP) != 0) {
				switch (bif->bif_state) {
					case BSTP_IFSTATE_BLOCKING:
					case BSTP_IFSTATE_LISTENING:
					case BSTP_IFSTATE_DISABLED:
						continue;
				}
			}
			
			if (LIST_NEXT(bif, bif_next) == NULL) {
				used = 1;
				mc = m;
			} else {
				mc = m_copym(m, 0, M_COPYALL, M_NOWAIT);
				if (mc == NULL) {
					printf("bridge_output ifp %p m_copym failed\n", ifp);
					(void) ifnet_stat_increment_out(sc->sc_if, 0, 0, 1);
					continue;
				}
			}
			
			bridge_enqueue(sc, dst_if, mc);
		}
		if (used == 0) {
			printf("bridge_output ifp %p not used\n", ifp);
			m_freem(m);
		}
		lck_mtx_unlock(sc->sc_mtx);
		
		return EJUSTRETURN;
	}
	
sendunicast:
	/*
	 * XXX Spanning tree consideration here?
	 */
	
	if ((ifnet_flags(dst_if) & IFF_RUNNING) == 0) {
		printf("bridge_output ifp %p dst_if %p not running\n", ifp, dst_if);
		m_freem(m);
				
		return EJUSTRETURN;
	}
	
	if (dst_if != ifp) {
		lck_mtx_lock(sc->sc_mtx);

		bridge_enqueue(sc, dst_if, m);
	
		lck_mtx_unlock(sc->sc_mtx);

		return EJUSTRETURN;
	}
		
	return (0);
}
#endif /* BRIDGE_MEMBER_OUT_FILTER */

#if APPLE_BRIDGE_HWCKSUM_SUPPORT
static struct mbuf* bridge_fix_txcsum( struct mbuf *m )
{
	// 	basic tests indicate that the vast majority of packets being processed
	//	here have an Ethernet header mbuf pre-pended to them (the first case below)
	//	the second highest are those where the Ethernet and IP/TCP/UDP headers are 
	//	all in one mbuf (second case below)
	//	the third case has, in fact, never hit for me -- although if I comment out 
	//	the first two cases, that code works for them, so I consider it a 
	//	decent general solution
	
	int amt = ETHER_HDR_LEN;
	int hlen = M_CSUM_DATA_IPv4_IPHL( m->m_pkthdr.csum_data );
	int off = M_CSUM_DATA_IPv4_OFFSET( m->m_pkthdr.csum_data );
	
	/* 
	 * NOTE we should never get vlan-attached packets here;
	 * support for those COULD be added, but we don't use them
	 * and it really kinda slows things down to worry about them
	 */
	
#ifdef DIAGNOSTIC
	if ( m_tag_find( m, PACKET_TAG_VLAN, NULL ) != NULL )
	{
		printf( "bridge: transmitting packet tagged with VLAN?\n" );
		KASSERT( 0 );
		m_freem( m );
		return NULL;
	}
#endif
	
	if ( m->m_pkthdr.csum_flags & M_CSUM_IPv4 )
	{
		amt += hlen;
	}
	if ( m->m_pkthdr.csum_flags & M_CSUM_TCPv4 )
	{
		amt += off + sizeof( uint16_t );
	}
	
	if ( m->m_pkthdr.csum_flags & M_CSUM_UDPv4 )
	{
		amt += off + sizeof( uint16_t );
	}
	
	if ( m->m_len == ETHER_HDR_LEN )
	{
		// this is the case where there's an Ethernet header in an mbuf
        
		// the first mbuf is the Ethernet header -- just strip it off and do the checksum
		struct mbuf *m_ip = m->m_next;
        
		// set up m_ip so the cksum operations work
		/* APPLE MODIFICATION 22 Apr 2008 <mvega@apple.com>
		 *  <rdar://5817385> Clear the m_tag list before setting
		 *  M_PKTHDR.
		 *
		 *  If this m_buf chain was extended via M_PREPEND(), then
		 *  m_ip->m_pkthdr is identical to m->m_pkthdr (see
		 *  M_MOVE_PKTHDR()). The only thing preventing access to this
		 *  invalid packet header data is the fact that the M_PKTHDR
		 *  flag is clear, i.e., m_ip->m_flag & M_PKTHDR == 0, but we're
		 *  about to set the M_PKTHDR flag, so to be safe we initialize,
		 *  more accurately, we clear, m_ip->m_pkthdr.tags via
		 *  m_tag_init().
		 *
		 *  Suppose that we do not do this; if m_pullup(), below, fails,
		 *  then m_ip will be freed along with m_ip->m_pkthdr.tags, but
		 *  we will also free m soon after, via m_freem(), and
		 *  consequently attempt to free m->m_pkthdr.tags in the
		 *  process. The problem is that m->m_pkthdr.tags will have
		 *  already been freed by virtue of being equal to
		 *  m_ip->m_pkthdr.tags. Attempts to dereference
		 *  m->m_pkthdr.tags in m_tag_delete_chain() will result in a
		 *  panic.
		 */
		m_tag_init(m_ip);
		/* END MODIFICATION */
		m_ip->m_flags |= M_PKTHDR;
		m_ip->m_pkthdr.csum_flags = m->m_pkthdr.csum_flags;
		m_ip->m_pkthdr.csum_data = m->m_pkthdr.csum_data;
		m_ip->m_pkthdr.len = m->m_pkthdr.len - ETHER_HDR_LEN;
        
		// set up the header mbuf so we can prepend it back on again later
		m->m_pkthdr.csum_flags = 0;
		m->m_pkthdr.csum_data = 0;
		m->m_pkthdr.len = ETHER_HDR_LEN;
		m->m_next = NULL;
        
        
		// now do the checksums we need -- first IP
		if ( m_ip->m_pkthdr.csum_flags & M_CSUM_IPv4 )
		{
			// make sure the IP header (or at least the part with the cksum) is there
			m_ip = m_pullup( m_ip, sizeof( struct ip ) );
			if ( m_ip == NULL )
			{
				printf( "bridge: failed to flatten header\n ");
				m_freem( m );
				return NULL;
			}
			
			// now do the checksum
			{
				struct ip *ip = mtod( m_ip, struct ip* );
				ip->ip_sum = in_cksum( m_ip, hlen );
                
#ifdef VERY_VERY_VERY_DIAGNOSTIC
				printf( "bridge: performed IPv4 checksum\n" );
#endif
			}
		}
        
		// now do a TCP or UDP delayed checksum
		if ( m_ip->m_pkthdr.csum_flags & (M_CSUM_TCPv4|M_CSUM_UDPv4) )
		{
			in_delayed_cksum( m_ip );
            
#ifdef VERY_VERY_VERY_DIAGNOSTIC
			printf( "bridge: performed TCPv4/UDPv4 checksum\n" );
#endif
		}
        
		// now attach the ethernet header back onto the IP packet
		m->m_next = m_ip;
		m->m_pkthdr.len += m_length( m_ip );	
        
		// clear the M_PKTHDR flags on the ip packet (again, we re-attach later)
		m_ip->m_flags &= ~M_PKTHDR;
        
		// and clear any csum flags
		m->m_pkthdr.csum_flags &= ~(M_CSUM_TCPv4|M_CSUM_UDPv4|M_CSUM_IPv4);
	}
	else if ( m->m_len >= amt )
	{
		// everything fits in the first mbuf, so futz with m->m_data, m->m_len and m->m_pkthdr.len to
		// make it work
		m->m_len -= ETHER_HDR_LEN;
		m->m_data += ETHER_HDR_LEN;
		m->m_pkthdr.len -= ETHER_HDR_LEN;
        
		// now do the checksums we need -- first IP
		if ( m->m_pkthdr.csum_flags & M_CSUM_IPv4 )
		{
			struct ip *ip = mtod( m, struct ip* );
			ip->ip_sum = in_cksum( m, hlen );
            
#ifdef VERY_VERY_VERY_DIAGNOSTIC
			printf( "bridge: performed IPv4 checksum\n" );
#endif
		}
        
		// now do a TCP or UDP delayed checksum
		if ( m->m_pkthdr.csum_flags & (M_CSUM_TCPv4|M_CSUM_UDPv4) )
		{
			in_delayed_cksum( m );
            
#ifdef VERY_VERY_VERY_DIAGNOSTIC
			printf( "bridge: performed TCPv4/UDPv4 checksum\n" );
#endif
		}
		
		// now stick the ethernet header back on
		m->m_len += ETHER_HDR_LEN;
		m->m_data -= ETHER_HDR_LEN;
		m->m_pkthdr.len += ETHER_HDR_LEN;
        
		// and clear any csum flags
		m->m_pkthdr.csum_flags &= ~(M_CSUM_TCPv4|M_CSUM_UDPv4|M_CSUM_IPv4);
	}
	else
	{
		struct mbuf *m_ip;
        
		// general case -- need to simply split it off and deal
        
		// first, calculate how much needs to be made writable (we may have a read-only mbuf here)
		hlen = M_CSUM_DATA_IPv4_IPHL( m->m_pkthdr.csum_data );
#if PARANOID
		off = M_CSUM_DATA_IPv4_OFFSET( m->m_pkthdr.csum_data );
		
		if ( m->m_pkthdr.csum_flags & M_CSUM_IPv4 )
		{
			amt += hlen;
		}
		
		if ( m->m_pkthdr.csum_flags & M_CSUM_TCPv4 )
		{
			amt += sizeof( struct tcphdr * );
			amt += off;
		}
		
		if ( m->m_pkthdr.csum_flags & M_CSUM_UDPv4 )
		{
			amt += sizeof( struct udphdr * );
			amt += off;
		}
#endif
        
		// now split the ethernet header off of the IP packet (we'll re-attach later)
		m_ip = m_split( m, ETHER_HDR_LEN, M_NOWAIT );
		if ( m_ip == NULL )
		{
			printf( "bridge_fix_txcsum: could not split ether header\n" );
            
			m_freem( m );
			return NULL;
		}
        
#if PARANOID
		// make sure that the IP packet is writable for the portion we need
		if ( m_makewritable( &m_ip, 0, amt, M_DONTWAIT ) != 0 )
		{
			printf( "bridge_fix_txcsum: could not make %d bytes writable\n", amt );
            
			m_freem( m );
			m_freem( m_ip );
			return NULL;
		}
#endif
		
		m_ip->m_pkthdr.csum_flags = m->m_pkthdr.csum_flags;
		m_ip->m_pkthdr.csum_data = m->m_pkthdr.csum_data;
        
		m->m_pkthdr.csum_flags = 0;
		m->m_pkthdr.csum_data = 0;
        
		// now do the checksums we need -- first IP
		if ( m_ip->m_pkthdr.csum_flags & M_CSUM_IPv4 )
		{
			// make sure the IP header (or at least the part with the cksum) is there
			m_ip = m_pullup( m_ip, sizeof( struct ip ) );
			if ( m_ip == NULL )
			{
				printf( "bridge: failed to flatten header\n ");
				m_freem( m );
				return NULL;
			}
			
			// now do the checksum
			{
				struct ip *ip = mtod( m_ip, struct ip* );
				ip->ip_sum = in_cksum( m_ip, hlen );
                
#ifdef VERY_VERY_VERY_DIAGNOSTIC
				printf( "bridge: performed IPv4 checksum\n" );
#endif
			}
		}
        
		// now do a TCP or UDP delayed checksum
		if ( m_ip->m_pkthdr.csum_flags & (M_CSUM_TCPv4|M_CSUM_UDPv4) )
		{
			in_delayed_cksum( m_ip );
            
#ifdef VERY_VERY_VERY_DIAGNOSTIC
			printf( "bridge: performed TCPv4/UDPv4 checksum\n" );
#endif
		}
        
		// now attach the ethernet header back onto the IP packet
		m->m_next = m_ip;
		m->m_pkthdr.len += m_length( m_ip );	
        
		// clear the M_PKTHDR flags on the ip packet (again, we re-attach later)
		m_ip->m_flags &= ~M_PKTHDR;
        
		// and clear any csum flags
		m->m_pkthdr.csum_flags &= ~(M_CSUM_TCPv4|M_CSUM_UDPv4|M_CSUM_IPv4);
	}
	
	return m;
}
#endif

/*
 * bridge_start:
 *
 *	Start output on a bridge.
 */
static errno_t
bridge_start(ifnet_t ifp, mbuf_t m)
{
	struct bridge_softc *sc = ifnet_softc(ifp);
	struct ether_header *eh;
	struct ifnet *dst_if;
	
	lck_mtx_assert(sc->sc_mtx, LCK_MTX_ASSERT_NOTOWNED);

	eh = mtod(m, struct ether_header *);
	
	if ((m->m_flags & (M_BCAST|M_MCAST)) == 0 &&
		(dst_if = bridge_rtlookup(sc, eh->ether_dhost)) != NULL) {
		
		{
#if APPLE_BRIDGE_HWCKSUM_SUPPORT
			/* 
			 * APPLE MODIFICATION - if the packet needs a checksum (i.e., 
			 * checksum has been deferred for HW support) AND the destination
			 * interface doesn't support HW checksums, then we 
			 * need to fix-up the checksum here
			 */
			if (
				( (m->m_pkthdr.csum_flags & (M_CSUM_TCPv4|M_CSUM_UDPv4|M_CSUM_IPv4) ) != 0 ) &&
				( (dst_if->if_csum_flags_tx & m->m_pkthdr.csum_flags ) != m->m_pkthdr.csum_flags )
				)
			{
				m = bridge_fix_txcsum( m );
				if ( m == NULL )
				{
					goto done;
				}
			}
			
#else
			if (eh->ether_type == htons(ETHERTYPE_IP))
				mbuf_outbound_finalize(m, PF_INET, sizeof(struct ether_header));
			else
				m->m_pkthdr.csum_flags = 0;
#endif
			lck_mtx_lock(sc->sc_mtx);
			#if NBPFILTER > 0
				if (sc->sc_bpf_output)
					bridge_bpf_output(ifp, m);
			#endif
			bridge_enqueue(sc, dst_if, m);
			lck_mtx_unlock(sc->sc_mtx);
		}
	} else
	{
#if APPLE_BRIDGE_HWCKSUM_SUPPORT
		
		/* 
		 * APPLE MODIFICATION - if the MULTICAST packet needs a checksum (i.e., 
		 * checksum has been deferred for HW support) AND at least one destination
		 * interface doesn't support HW checksums, then we go ahead and fix it up
		 * here, since it doesn't make sense to do it more than once
		 */
		
		if (
			(m->m_pkthdr.csum_flags & (M_CSUM_TCPv4|M_CSUM_UDPv4|M_CSUM_IPv4)) &&
			/*
			 * XXX FIX ME: keep track of whether or not we have any interfaces that 
			 * do not support checksums (for now, assume we do)
			 */
			( 1 )
			)
		{
			m = bridge_fix_txcsum( m );
			if ( m == NULL )
			{
				goto done;
			}
		}
#else
		if (eh->ether_type == htons(ETHERTYPE_IP))
			mbuf_outbound_finalize(m, PF_INET, sizeof(struct ether_header));
		else
			m->m_pkthdr.csum_flags = 0;
#endif
		
		lck_mtx_lock(sc->sc_mtx);
		#if NBPFILTER > 0
			if (sc->sc_bpf_output)
				bridge_bpf_output(ifp, m);
		#endif
		bridge_broadcast(sc, ifp, m, 0);
		lck_mtx_unlock(sc->sc_mtx);
	}
#if APPLE_BRIDGE_HWCKSUM_SUPPORT
done:
#endif

	return 0;
}

/*
 * bridge_forward:
 *
 *	The forwarding function of the bridge.
 */
static void
bridge_forward(struct bridge_softc *sc, struct mbuf *m)
{
	struct bridge_iflist *bif;
	struct ifnet *src_if, *dst_if;
	struct ether_header *eh;

	lck_mtx_assert(sc->sc_mtx, LCK_MTX_ASSERT_OWNED);

#if BRIDGE_DEBUG
	if (_if_brige_debug)
        printf("bridge_forward %s%d m%p\n", ifnet_name(sc->sc_if), ifnet_unit(sc->sc_if), m);
#endif /* BRIDGE_DEBUG */
	
	src_if = m->m_pkthdr.rcvif;
	
	(void) ifnet_stat_increment_in(sc->sc_if, 1, m->m_pkthdr.len, 0);
	
	/*
	 * Look up the bridge_iflist.
	 */
	bif = bridge_lookup_member_if(sc, src_if);
	if (bif == NULL) {
		/* Interface is not a bridge member (anymore?) */
		m_freem(m);
		return;
	}
	
	/* APPLE MODIFICATION <cbz@apple.com> - add the ability to block forwarding of packets; for the guest network */
#if ( APPLE_HAVE_80211_GUEST_NETWORK )
	if (bif->bif_flags & IFBIF_NO_FORWARDING) {
		/* Drop the packet and we're done. */
		m_freem(m);
		return;
	}
#endif
	
	if (bif->bif_flags & IFBIF_STP) {
		switch (bif->bif_state) {
            case BSTP_IFSTATE_BLOCKING:
            case BSTP_IFSTATE_LISTENING:
            case BSTP_IFSTATE_DISABLED:
                m_freem(m);
                return;
		}
	}
	
	eh = mtod(m, struct ether_header *);
	
	/*
	 * If the interface is learning, and the source
	 * address is valid and not multicast, record
	 * the address.
	 */
	if ((bif->bif_flags & IFBIF_LEARNING) != 0 &&
	    ETHER_IS_MULTICAST(eh->ether_shost) == 0 &&
	    (eh->ether_shost[0] | eh->ether_shost[1] |
	     eh->ether_shost[2] | eh->ether_shost[3] |
	     eh->ether_shost[4] | eh->ether_shost[5]) != 0) {
		(void) bridge_rtupdate(sc, eh->ether_shost,
                               src_if, 0, IFBAF_DYNAMIC);
	}
	
	if ((bif->bif_flags & IFBIF_STP) != 0 &&
	    bif->bif_state == BSTP_IFSTATE_LEARNING) {
		m_freem(m);
		return;
	}
	
	/*
	 * At this point, the port either doesn't participate
	 * in spanning tree or it is in the forwarding state.
	 */
	
	/*
	 * If the packet is unicast, destined for someone on
	 * "this" side of the bridge, drop it.
	 */
	if ((m->m_flags & (M_BCAST|M_MCAST)) == 0) {
        /* APPLE MODIFICATION <cbz@apple.com> - if the packet came in on a proxy sta discovery interface,
         we need to not look up the node by DA of the packet; we need to look up the proxy sta which 
         matches the SA.  If it's not found yet, drop the packet. */
#if IEEE80211_PROXYSTA
		if (bif->bif_flags & IFBIF_PROXYSTA_DISCOVER)
		{
			struct bridge_rtnode *brt;
			dst_if = NULL;
			brt = bridge_rtnode_lookup(sc, eh->ether_shost);
			if (brt) {
				dst_if = brt->brt_ifp_proxysta;
			}
			if (dst_if == NULL) {
				m_freem(m);
				return;
			}
		}
		else
#endif	
            dst_if = bridge_rtlookup(sc, eh->ether_dhost);
		if (src_if == dst_if) {
			m_freem(m);
			return;
		}
	} else {
		/* ...forward it to all interfaces. */
		sc->sc_if->if_imcasts++;
		dst_if = NULL;
	}
	
	/* APPLE MODIFICATION  
     <rnewberry@apple.com> 	- this is now handled by bridge_input
     <cbz@apple.com> 		- turning this back on because all packets are not bpf_mtap'd
     equally.  RSN Preauth were not getting through; we're 
     conditionalizing this call on 
     (eh->ether_type == htons(ETHERTYPE_RSN_PREAUTH)) 
     */
#if 1
	if (eh->ether_type == htons(ETHERTYPE_RSN_PREAUTH))
	{
        m->m_pkthdr.rcvif = sc->sc_if;
#if NBPFILTER > 0
        if (sc->sc_bpf_input)
            bridge_bpf_input(sc->sc_if, m);
#endif
	}
#endif
        
	if (dst_if == NULL) {
        
#if APPLE_BRIDGE_HWCKSUM_SUPPORT
        /*
         * Clear any in-bound checksum flags for this packet.
         */
        m->m_pkthdr.csum_flags = 0;
#else
		mbuf_inbound_modified(m);
#endif
        
        bridge_broadcast(sc, src_if, m, 1);
        return;
	}
	
	/*
	 * At this point, we're dealing with a unicast frame
	 * going to a different interface.
	 */
	if ((ifnet_flags(dst_if) & IFF_RUNNING) == 0) {
		m_freem(m);
		return;
	}
	bif = bridge_lookup_member_if(sc, dst_if);
	if (bif == NULL) {
		/* Not a member of the bridge (anymore?) */
		m_freem(m);
		return;
	}
	
	if (bif->bif_flags & IFBIF_STP) {
		switch (bif->bif_state) {
            case BSTP_IFSTATE_DISABLED:
            case BSTP_IFSTATE_BLOCKING:
                m_freem(m);
                return;
		}
	}
        
#if APPLE_BRIDGE_HWCKSUM_SUPPORT
	/*
	 * Clear any in-bound checksum flags for this packet.
	 */
	{
		m->m_pkthdr.csum_flags = 0;
	}
#else
	mbuf_inbound_modified(m);
#endif
	
	bridge_enqueue(sc, dst_if, m);
}

char * ether_ntop(char *, size_t , const u_char *);

__private_extern__ char *
ether_ntop(char *buf, size_t len, const u_char *ap)
{
	snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x", 
			 ap[0], ap[1], ap[2], ap[3], ap[4], ap[5]);
	
	return buf;
}

/*
 * bridge_input:
 *
 *	Receive input from a member interface.  Queue the packet for
 *	bridging if it is not for us.
 */
errno_t
bridge_input(struct bridge_iflist *bif, struct ifnet *ifp, struct mbuf *m, void *frame_header)
{
	struct ifnet *bifp;
	struct ether_header *eh;
	struct mbuf *mc;
	int is_for_us = 0;
	struct bridge_softc *sc = bif->bif_sc;
	struct bridge_iflist *brm;
	
#if BRIDGE_DEBUG
	if (_if_brige_debug)
		printf("bridge_input: %s%d from %s%d m %p data %p\n", 
			   ifnet_name(sc->sc_if), ifnet_unit(sc->sc_if),
			   ifnet_name(ifp), ifnet_unit(ifp), 
			   m, mbuf_data(m));
#endif /* BRIDGE_DEBUG */

	if ((ifnet_flags(sc->sc_if) & IFF_RUNNING) == 0) {
#if BRIDGE_DEBUG
		if (_if_brige_debug)
			printf( "bridge_input: %s%d not running passing along\n",
				   ifnet_name(sc->sc_if), ifnet_unit(sc->sc_if));
#endif /* BRIDGE_DEBUG */
		return 0;
	}
	
	/* Need to clear the promiscous flags otherwise it will be dropped by DLIL after processing filters */
	if ((mbuf_flags(m) & MBUF_PROMISC))
		mbuf_setflags_mask(m, 0, MBUF_PROMISC);
	
	lck_mtx_lock(sc->sc_mtx);
	
	bifp = sc->sc_if;
	
	/* Is it a good idea to reassign a new value to bif ? TBD */
	bif = bridge_lookup_member_if(sc, ifp);
	if (bif == NULL) {
		lck_mtx_unlock(sc->sc_mtx);
#if BRIDGE_DEBUG
		if (_if_brige_debug)
			printf( "bridge_input: %s%d bridge_lookup_member_if failed\n",
				   ifnet_name(sc->sc_if), ifnet_unit(sc->sc_if));
#endif /* BRIDGE_DEBUG */
		return 0;
	}
	
	eh = (struct ether_header *)mbuf_data(m);
	
	/*
	 * If the packet is for us, set the packets source as the
	 * bridge, and return the packet back to ether_input for
	 * local processing.
	 */
	if (memcmp(eh->ether_dhost, ifnet_lladdr(bifp),
			   ETHER_ADDR_LEN) == 0) {
		
		/* Mark the packet as arriving on the bridge interface */
		(void) mbuf_pkthdr_setrcvif(m, bifp);
		mbuf_pkthdr_setheader(m, frame_header);
		
		/*
		 * If the interface is learning, and the source
		 * address is valid and not multicast, record
		 * the address.
		 */
		if ((bif->bif_flags & IFBIF_LEARNING) != 0 &&
			ETHER_IS_MULTICAST(eh->ether_shost) == 0 &&
			(eh->ether_shost[0] | eh->ether_shost[1] |
			 eh->ether_shost[2] | eh->ether_shost[3] |
			 eh->ether_shost[4] | eh->ether_shost[5]) != 0) {
				(void) bridge_rtupdate(sc, eh->ether_shost,
									   ifp, 0, IFBAF_DYNAMIC);
			}
		
#if NBPFILTER > 0
		if (sc->sc_bpf_input)
			bridge_bpf_input(bifp, m);
#endif
		
		(void) mbuf_setdata(m, (char *)mbuf_data(m) + ETHER_HDR_LEN, mbuf_len(m) - ETHER_HDR_LEN);
		(void) mbuf_pkthdr_adjustlen(m, - ETHER_HDR_LEN);
		
		(void) ifnet_stat_increment_in(bifp, 1, mbuf_pkthdr_len(m), 0);

		lck_mtx_unlock(sc->sc_mtx);
				
#if BRIDGE_DEBUG
		if (_if_brige_debug)
			printf( "bridge_input: %s%d packet for bridge\n",
				   ifnet_name(sc->sc_if), ifnet_unit(sc->sc_if));
#endif /* BRIDGE_DEBUG */
		
		dlil_input_packet_list(bifp, m);
		
		return EJUSTRETURN;
	}
	
	/*
	 * if the destination of the packet is for the MAC address of 
	 * the member interface itself, then we don't need to forward
	 * it -- just pass it back.  Note that it'll likely just be
	 * dropped by the stack, but if something else is bound to 
	 * the interface directly (for example, the wireless stats
	 * protocol -- although that actually uses BPF right now), 
	 * then it will consume the packet
	 *
	 * ALSO, note that we do this check AFTER checking for the 
	 * bridge's own MAC address, because the bridge may be
	 * using the SAME MAC address as one of its interfaces
	 */
	if (memcmp(eh->ether_dhost, ifnet_lladdr(ifp),
			   ETHER_ADDR_LEN) == 0) {
		/* APPLE MODIFICATION <cbz@apple.com> - add support for Proxy STA */
#if IEEE80211_PROXYSTA
		if ((bif->bif_flags & IFBIF_PROXYSTA) == 0) {
#endif
			
#ifdef VERY_VERY_VERY_DIAGNOSTIC
			printf("bridge_input: not forwarding packet bound for member interface\n" );
#endif
			lck_mtx_unlock(sc->sc_mtx);
			return 0;
			/* APPLE MODIFICATION <cbz@apple.com> - add support for Proxy STA */
#if IEEE80211_PROXYSTA
		}
#if VERY_VERY_VERY_DIAGNOSTIC
		else {
			printf( "%s: pkt rx on %s [proxysta iface], da is %02x:%02x:%02x:%02x:%02x:%02x\n",
				   __func__, ifp->if_xname, eh->ether_dhost[0], eh->ether_dhost[1], eh->ether_dhost[2], 
				   eh->ether_dhost[3], eh->ether_dhost[4], eh->ether_dhost[5] );
		}
#endif
#endif
	}
	
	if ((m->m_flags & (M_BCAST|M_MCAST))) {
		struct ifmultiaddr *ifma = NULL;
		
		if ((m->m_flags & M_BCAST)) {
			is_for_us = 1;
		} else {
#if BRIDGE_DEBUG
			printf("mulicast: %02x:%02x:%02x:%02x:%02x:%02x\n",
				   eh->ether_dhost[0], eh->ether_dhost[1], eh->ether_dhost[2], 
				   eh->ether_dhost[3], eh->ether_dhost[4], eh->ether_dhost[5]);
			
			for (ifma = bifp->if_multiaddrs.lh_first; ifma;
				 ifma = ifma->ifma_link.le_next) {
				
				if (ifma->ifma_addr == NULL)
					printf("  <none> ");
				else if (ifma->ifma_addr->sa_family == AF_INET) {
					struct sockaddr_in *sin = (struct sockaddr_in *)ifma->ifma_addr;
					
					printf("  %u.%u.%u.%u ",
						   (sin->sin_addr.s_addr & 0xff000000) >> 24,
						   (sin->sin_addr.s_addr & 0x00ff0000) >> 16,
						   (sin->sin_addr.s_addr & 0x0000ff00) >> 8,
						   (sin->sin_addr.s_addr & 0x000000ff));
				}
				if (!ifma->ifma_ll || !ifma->ifma_ll->ifma_addr)
					printf("<none>\n");
				else {
					struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifma->ifma_ll->ifma_addr;
					
					printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
						   CONST_LLADDR(sdl)[0], CONST_LLADDR(sdl)[1], CONST_LLADDR(sdl)[2], 
						   CONST_LLADDR(sdl)[3], CONST_LLADDR(sdl)[4], CONST_LLADDR(sdl)[5]);
					
				}
			}
#endif /* BRIDGE_DEBUG */
			
			/*
			 * the upper layer of the stack have attached a list of multicast addresses to the bridge itself
			 * (for example, the IP stack has bound 01:00:5e:00:00:01 to the 224.0.0.1 all hosts address), since
			 * the IP stack is bound to the bridge.  so we need to see if the packets arriving here SHOULD be 
			 * passed up as coming from the bridge.
			 *
			 * furthermore, since we know the IP stack is attached to the bridge, and NOTHING is attached
			 * to the underlying devices themselves, we can drop packets that don't need to go up (by returning NULL
			 * from bridge_input to the caller) after we forward the packet to other interfaces
			 */
			
			for (ifma = bifp->if_multiaddrs.lh_first; ifma;
				 ifma = ifma->ifma_link.le_next) {
				if (ifma->ifma_ll && ifma->ifma_ll->ifma_addr) {
					struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifma->ifma_ll->ifma_addr;
					
					if (memcmp(eh->ether_dhost, CONST_LLADDR(sdl), ETHER_ADDR_LEN) == 0)
						break;
				}
			}
			if (ifma != NULL) {
				/* this packet matches the bridge's own filter, so pass it up as coming from us */
				
				/* Mark the packet as arriving on the bridge interface */
				// don't do this until AFTER we forward the packet -- bridge_forward uses this information
				//m->m_pkthdr.rcvif = bifp;
				
				/* keep track of this to help us decide about forwarding */
				is_for_us = 1;
				
#if BRIDGE_DEBUG
				char	addr[sizeof("XX:XX:XX:XX:XX:XX")+1];
				printf( "bridge_input: multicast frame for us (%s)\n",
					   ether_ntop(addr, sizeof(addr), eh->ether_dhost) );
#endif
			} else {
#if BRIDGE_DEBUG
				char	addr[sizeof("XX:XX:XX:XX:XX:XX")+1];
				printf( "bridge_input: multicast frame for unbound address (%s), forwarding but not passing to stack\n",
					   ether_ntop(addr, sizeof(addr), eh->ether_dhost) );
#endif
			}
		}
		/* Tap off 802.1D packets; they do not get forwarded. */
		if (memcmp(eh->ether_dhost, bstp_etheraddr,
				   ETHER_ADDR_LEN) == 0) {
			m = bstp_input(sc, ifp, m);
			if (m == NULL) {
				lck_mtx_unlock(sc->sc_mtx);
#if BRIDGE_DEBUG
				if (_if_brige_debug)
					printf( "bridge_input: %s%d mcast BSTP not forwarded\n",
						   ifnet_name(sc->sc_if), ifnet_unit(sc->sc_if));
#endif /* BRIDGE_DEBUG */
				return EJUSTRETURN;
			}
		}
		
		if (bif->bif_flags & IFBIF_STP) {
			switch (bif->bif_state) {
				case BSTP_IFSTATE_BLOCKING:
				case BSTP_IFSTATE_LISTENING:
				case BSTP_IFSTATE_DISABLED:
				{
					lck_mtx_unlock(sc->sc_mtx);
					
#if BRIDGE_DEBUG
					if (_if_brige_debug)
						printf( "bridge_input: %s%d mcast bridge not learning or forwarding \n",
							   ifnet_name(sc->sc_if), ifnet_unit(sc->sc_if));
#endif /* BRIDGE_DEBUG */
					
					m_freem(m);
					return EJUSTRETURN;
				}
			}
		}
		
		/*
		 * If the interface is learning, and the source
		 * address is valid and not multicast, record
		 * the address.
		 */
		if ((bif->bif_flags & IFBIF_LEARNING) != 0 &&
			ETHER_IS_MULTICAST(eh->ether_shost) == 0 &&
			(eh->ether_shost[0] | eh->ether_shost[1] |
			 eh->ether_shost[2] | eh->ether_shost[3] |
			 eh->ether_shost[4] | eh->ether_shost[5]) != 0) {
				(void) bridge_rtupdate(sc, eh->ether_shost,
									   ifp, 0, IFBAF_DYNAMIC);
			}
		
		if (is_for_us) {
			/*
			 * Make a deep copy of the packet and enqueue the copy
			 * for bridge processing; return the original packet for
			 * local processing.
			 */
			mc = m_dup(m, M_NOWAIT);
			if (mc == NULL) {
#ifdef DIAGNOSTIC
				printf( "bridge_input: failed to duplicate multicast frame, not forwarding\n" );
#endif
#if BRIDGE_DEBUG
			} else {
				if (_if_brige_debug) {
					printf_mbuf(mc, "mc for us: ", "\n");
					printf_mbuf_data(m, 0, 20);
					printf("\n");
				}
#endif /* BRIDGE_DEBUG */
			}
		} else {
			/*
			 * we'll just pass the original, since we don't need to pass it
			 * up the stack
			 */
			mc = m;
		}
		
		/* Perform the bridge forwarding function with the copy. */
		if (mc != NULL) {
#if BRIDGE_DEBUG
			if (_if_brige_debug)
				printf( "bridge_input: %s%d mcast forwarding \n",
					   ifnet_name(sc->sc_if), ifnet_unit(sc->sc_if));
#endif /* BRIDGE_DEBUG */			
			bridge_forward(sc, mc);
		}
		
		// TBD should have an option for type of bridge
#if 0
		/*
		 * Reinject the mbuf as arriving on the bridge so we have a
		 * chance at claiming multicast packets. We can not loop back
		 * here from ether_input as a bridge is never a member of a
		 * bridge.
		 */
		if (bifp->if_bridge != NULL)
			panic("brige_input: brige %p in a bridge %p\n", bifp, bifp->if_bridge);
		mc = m_dup(m, M_NOWAIT);
		if (mc != NULL) {
			mc->m_pkthdr.rcvif = bifp;
#if NBPFILTER > 0
			if (sc->sc_bpf_input)
				bridge_bpf_input(bifp, mc);
#endif
		}
#endif        
		/* Return the original packet for local processing. */
		if ( !is_for_us )
		{
			/* we don't free the packet -- bridge_forward already did so */
			lck_mtx_unlock(sc->sc_mtx);
			
#if BRIDGE_DEBUG
			if (_if_brige_debug)
				printf( "bridge_input: %s%d mcast local processing\n",
					   ifnet_name(sc->sc_if), ifnet_unit(sc->sc_if));
#endif
			
			return EJUSTRETURN;
		}
		
		// mark packet as arriving on the bridge
		m->m_pkthdr.rcvif = bifp;
		m->m_pkthdr.header = mbuf_data(m);
		
#if NBPFILTER > 0
		if (sc->sc_bpf_input)
			bridge_bpf_input(bifp, m);
#endif
		(void) mbuf_setdata(m, (char *)mbuf_data(m) + ETHER_HDR_LEN, mbuf_len(m) - ETHER_HDR_LEN);
		(void) mbuf_pkthdr_adjustlen(m, - ETHER_HDR_LEN);
		
		(void) ifnet_stat_increment_in(bifp, 1, mbuf_pkthdr_len(m), 0);
		
		lck_mtx_unlock(sc->sc_mtx);
		
#if BRIDGE_DEBUG
		if (_if_brige_debug)
			printf( "bridge_input: %s%d mcast for us\n",
				   ifnet_name(sc->sc_if), ifnet_unit(sc->sc_if));
#endif /* BRIDGE_DEBUG */
		
		dlil_input_packet_list(bifp, m);
		
		return EJUSTRETURN;
	}
	
	if (bif->bif_flags & IFBIF_STP) {
		switch (bif->bif_state) {
			case BSTP_IFSTATE_BLOCKING:
			case BSTP_IFSTATE_LISTENING:
			case BSTP_IFSTATE_DISABLED:
				lck_mtx_unlock(sc->sc_mtx);
				
#if BRIDGE_DEBUG
				if (_if_brige_debug)
					printf( "bridge_input: %s%d ucast bridge not learning or forwarding \n",
						   ifnet_name(sc->sc_if), ifnet_unit(sc->sc_if));
#endif /* BRIDGE_DEBUG */
				
				m_freem(m);
				return EJUSTRETURN;
		}
	}
	
	/* this code is not needed for Apple's bridge where the stack attaches directly */
#if 1 /* TBD should be an option */
	/*
	 * Unicast.  Make sure it's not for us.
	 */
	LIST_FOREACH(brm, &sc->sc_iflist, bif_next) {
		if(ifnet_type(brm->bif_ifp) != IFT_ETHER)
			continue;
		
		/* It is destined for us. */
		if (memcmp(ifnet_lladdr(brm->bif_ifp), eh->ether_dhost,
				   ETHER_ADDR_LEN) == 0) {
			if (brm->bif_flags & IFBIF_LEARNING)
				(void) bridge_rtupdate(sc,
									   eh->ether_shost, ifp, 0, IFBAF_DYNAMIC);
			m->m_pkthdr.rcvif = brm->bif_ifp;
			m->m_pkthdr.header = mbuf_data(m);
			
			(void) mbuf_setdata(m, (char *)mbuf_data(m) + ETHER_HDR_LEN, mbuf_len(m) - ETHER_HDR_LEN);
			(void) mbuf_pkthdr_adjustlen(m, - ETHER_HDR_LEN);
#if BRIDGE_SUPPORT_GIF
#if NGIF > 0
			if (ifnet_type(ifp) == IFT_GIF) {
				m->m_flags |= M_PROTO1;
				m->m_pkthdr.rcvif = brm->bif_ifp;
				(*brm->bif_ifp->if_input)(brm->bif_ifp, m);
				m = NULL;
			}
#endif
#endif
			lck_mtx_unlock(sc->sc_mtx);
			
#if BRIDGE_DEBUG
			if (_if_brige_debug)
				printf( "bridge_input: %s%d ucast to member %s%d\n",
					   ifnet_name(sc->sc_if), ifnet_unit(sc->sc_if),
					   ifnet_name(brm->bif_ifp), ifnet_unit(brm->bif_ifp));
#endif /* BRIDGE_DEBUG */
			
			dlil_input_packet_list(brm->bif_ifp, m);
			
			return EJUSTRETURN;
		}
		
		/* We just received a packet that we sent out. */
		if (memcmp(ifnet_lladdr(brm->bif_ifp), eh->ether_shost,
				   ETHER_ADDR_LEN) == 0) {
			lck_mtx_unlock(sc->sc_mtx);
			
#if BRIDGE_DEBUG
			if (_if_brige_debug)
				printf( "bridge_input: %s%d ucast drop packet we sent out\n",
					   ifnet_name(sc->sc_if), ifnet_unit(sc->sc_if));
#endif /* BRIDGE_DEBUG */
			
			m_freem(m);
			return EJUSTRETURN;
		}
	}
#endif
	
	/*
	 * If the interface is learning, and the source
	 * address is valid and not multicast, record
	 * the address.
	 */
	if ((bif->bif_flags & IFBIF_LEARNING) != 0 &&
		ETHER_IS_MULTICAST(eh->ether_shost) == 0 &&
		(eh->ether_shost[0] | eh->ether_shost[1] |
		 eh->ether_shost[2] | eh->ether_shost[3] |
		 eh->ether_shost[4] | eh->ether_shost[5]) != 0) {
			(void) bridge_rtupdate(sc, eh->ether_shost,
								   ifp, 0, IFBAF_DYNAMIC);
		}
	
	/* Perform the bridge forwarding function. */
#if BRIDGE_DEBUG
	if (_if_brige_debug)
		printf( "bridge_input: %s%d ucast forwarding\n",
			   ifnet_name(sc->sc_if), ifnet_unit(sc->sc_if));
#endif /* BRIDGE_DEBUG */
	
	bridge_forward(sc, m);
	lck_mtx_unlock(sc->sc_mtx);
	return EJUSTRETURN;
}

/*
 * bridge_broadcast:
 *
 *	Send a frame to all interfaces that are members of
 *	the bridge, except for the one on which the packet
 *	arrived.
 */
static void
bridge_broadcast(struct bridge_softc *sc, struct ifnet *src_if,
                 struct mbuf *m, __unused int runfilt)
{
	struct bridge_iflist *bif;
	struct mbuf *mc;
	struct ifnet *dst_if;
	int used = 0;
	
	lck_mtx_assert(sc->sc_mtx, LCK_MTX_ASSERT_OWNED);
	
	LIST_FOREACH(bif, &sc->sc_iflist, bif_next) {
		dst_if = bif->bif_ifp;
		if (dst_if == src_if)
			continue;
        
		if (bif->bif_flags & IFBIF_STP) {
			switch (bif->bif_state) {
                case BSTP_IFSTATE_BLOCKING:
                case BSTP_IFSTATE_DISABLED:
                    continue;
			}
		}
        
		if ((bif->bif_flags & IFBIF_DISCOVER) == 0 &&
		    (m->m_flags & (M_BCAST|M_MCAST)) == 0)
			continue;
        
		if ((ifnet_flags(dst_if) & IFF_RUNNING) == 0)
			continue;
        
		if (LIST_NEXT(bif, bif_next) == NULL) {
			mc = m;
			used = 1;
		} else {
			mc = m_copym(m, 0, M_COPYALL, M_DONTWAIT);
			if (mc == NULL) {
				(void) ifnet_stat_increment_out(sc->sc_if, 0, 0, 1);
				continue;
			}
		}
        
		bridge_enqueue(sc, dst_if, mc);
	}
	if (used == 0)
		m_freem(m);
}

/*
 * bridge_rtupdate:
 *
 *	Add a bridge routing entry.
 */
static int
bridge_rtupdate(struct bridge_softc *sc, const uint8_t *dst,
                struct ifnet *dst_if, int setflags, uint8_t flags)
{
	struct bridge_rtnode *brt;
	int error;
	/* APPLE MODIFICATION <cbz@apple.com> - add support for Proxy STA */
#if IEEE80211_PROXYSTA
	struct bridge_iflist *bif;
	int is_pds; /* are we a proxy sta discovery interface? */
#endif
	struct timespec now;
	
	/* APPLE MODIFICATION <cbz@apple.com> - add support for Proxy STA - is this an interface 
     we want to do proxy sta discovery on? */
#if IEEE80211_PROXYSTA
	bif = bridge_lookup_member_if(sc, dst_if);
	if ((bif) && (bif->bif_flags & IFBIF_PROXYSTA_DISCOVER)) {
		is_pds = 1;
	}
	else {
		is_pds = 0;
	}
#endif		
	/*
	 * A route for this destination might already exist.  If so,
	 * update it, otherwise create a new one.
	 */
	if ((brt = bridge_rtnode_lookup(sc, dst)) == NULL) {
        /* APPLE MODIFICATION <cbz@apple.com> - add support for Proxy STA */
#if IEEE80211_PROXYSTA
		/* don't count this address against the bridge cache (well, allow proxy stas to double that 
         number...put *some* boundary on it.) if we are a proxy sta discovery interface */
		if (is_pds) {
			if (sc->sc_brtcnt >= (sc->sc_brtmax+sc->sc_brtmax_proxysta))
				return (ENOSPC);
		}
		else
#endif		
            if (sc->sc_brtcnt >= sc->sc_brtmax)
                return (ENOSPC);
        
		/*
		 * Allocate a new bridge forwarding node, and
		 * initialize the expiration time and Ethernet
		 * address.
		 */
		brt = zalloc_noblock(bridge_rtnode_pool);
		if (brt == NULL)
			return (ENOMEM);
        
		memset(brt, 0, sizeof(*brt));
		nanouptime(&now);
		brt->brt_expire = now.tv_sec + sc->sc_brttimeout;
		brt->brt_flags = IFBAF_DYNAMIC;
		memcpy(brt->brt_addr, dst, ETHER_ADDR_LEN);
        
        /* APPLE MODIFICATION <cbz@apple.com> - add support for Proxy STA - is this an interface 
         we want to do proxy sta discovery on?  If so, post a monitoring event */
#if IEEE80211_PROXYSTA
		if (is_pds) {
			brt->brt_flags_ext |= IFBAF_EXT_PROXYSTA;
#if DIAGNOSTIC
			printf( "%s: proxysta %02x:%02x:%02x:%02x:%02x:%02x on %s; discovery\n",
                   __func__, dst[0], dst[1], dst[2], dst[3], dst[4], dst[5], dst_if->if_xname );
#endif
			bridge_proxysta_discover( dst_if, dst );	
		}	
#endif
        
		if ((error = bridge_rtnode_insert(sc, brt)) != 0) {
			zfree(bridge_rtnode_pool, brt);
			return (error);
		}
	}
	
	brt->brt_ifp = dst_if;
	if (setflags) {
		brt->brt_flags = flags;
		brt->brt_expire = (flags & IFBAF_STATIC) ? 0 :
        now.tv_sec + sc->sc_brttimeout;
	}
	
	/* APPLE MODIFICATION <cbz@apple.com> - add support for Proxy STA -  */
#if IEEE80211_PROXYSTA
	if (is_pds) {
#if VERY_VERY_DIAGNOSTIC
		printf( "%s: proxysta %02x:%02x:%02x:%02x:%02x:%02x on %s; reset timeout\n",
               __func__, dst[0], dst[1], dst[2], dst[3], dst[4], dst[5], dst_if->if_xname );
#endif
		brt->brt_expire = (flags & IFBAF_STATIC) ? 0 :
        now.tv_sec + sc->sc_brttimeout;
	}	
#endif
	
	return (0);
}

/*
 * bridge_rtlookup:
 *
 *	Lookup the destination interface for an address.
 */
static struct ifnet *
bridge_rtlookup(struct bridge_softc *sc, const uint8_t *addr)
{
	struct bridge_rtnode *brt;
	
	if ((brt = bridge_rtnode_lookup(sc, addr)) == NULL)
		return (NULL);
	
	return (brt->brt_ifp);
}

/*
 * bridge_rttrim:
 *
 *	Trim the routine table so that we have a number
 *	of routing entries less than or equal to the
 *	maximum number.
 */
static void
bridge_rttrim(struct bridge_softc *sc)
{
	struct bridge_rtnode *brt, *nbrt;
	
	/* Make sure we actually need to do this. */
	if (sc->sc_brtcnt <= sc->sc_brtmax)
		return;
	
	/* Force an aging cycle; this might trim enough addresses. */
	bridge_rtage(sc);
	if (sc->sc_brtcnt <= sc->sc_brtmax)
		return;
	
	for (brt = LIST_FIRST(&sc->sc_rtlist); brt != NULL; brt = nbrt) {
		nbrt = LIST_NEXT(brt, brt_list);
		if ((brt->brt_flags & IFBAF_TYPEMASK) == IFBAF_DYNAMIC) {
			bridge_rtnode_destroy(sc, brt);
			if (sc->sc_brtcnt <= sc->sc_brtmax)
				return;
		}
	}
}

/*
 * bridge_timer:
 *
 *	Aging timer for the bridge.
 */
static void
bridge_timer(void *arg)
{
	struct bridge_softc *sc = arg;
	struct timespec ts;
	
	lck_mtx_lock(sc->sc_mtx);
	
	bridge_rtage(sc);
	
	lck_mtx_unlock(sc->sc_mtx);
	
	if (ifnet_flags(sc->sc_if) & IFF_RUNNING) {
		ts.tv_sec = bridge_rtable_prune_period;
		ts.tv_nsec = 0;
		bsd_timeout(bridge_timer, sc, &ts);
	}
}

/*
 * bridge_rtage:
 *
 *	Perform an aging cycle.
 */
static void
bridge_rtage(struct bridge_softc *sc)
{
	struct bridge_rtnode *brt, *nbrt;
	struct timespec now;
	
	nanouptime(&now);
	
	for (brt = LIST_FIRST(&sc->sc_rtlist); brt != NULL; brt = nbrt) {
		nbrt = LIST_NEXT(brt, brt_list);
		if ((brt->brt_flags & IFBAF_TYPEMASK) == IFBAF_DYNAMIC) {
			if ((unsigned long)now.tv_sec >= brt->brt_expire)
				bridge_rtnode_destroy(sc, brt);
		}
	}
}

/*
 * bridge_rtflush:
 *
 *	Remove all dynamic addresses from the bridge.
 */
static void
bridge_rtflush(struct bridge_softc *sc, int full)
{
	struct bridge_rtnode *brt, *nbrt;
	
	for (brt = LIST_FIRST(&sc->sc_rtlist); brt != NULL; brt = nbrt) {
		nbrt = LIST_NEXT(brt, brt_list);
		if (full || (brt->brt_flags & IFBAF_TYPEMASK) == IFBAF_DYNAMIC)
			bridge_rtnode_destroy(sc, brt);
	}
}

/* APPLE MODIFICATION <cbz@apple.com> - add support for Proxy STA */
#if IEEE80211_PROXYSTA
/*
 * bridge_rtdiscovery:
 *
 */
static void
bridge_rtdiscovery(struct bridge_softc *sc)
{
	struct bridge_rtnode *brt, *nbrt;
	struct bridge_iflist *bif;
	
	for (brt = LIST_FIRST(&sc->sc_rtlist); brt != NULL; brt = nbrt) {
		nbrt = LIST_NEXT(brt, brt_list);
		bif = bridge_lookup_member_if(sc, brt->brt_ifp);
		if ((bif) && (bif->bif_flags & IFBIF_PROXYSTA_DISCOVER) && 
			((brt->brt_flags_ext & IFBAF_EXT_PROXYSTA) == 0)) {
#if DIAGNOSTIC
			printf( "%s: proxysta %02x:%02x:%02x:%02x:%02x:%02x on %s; found before IFBIF_PROXYSTA_DISCOVER\n",
				   __func__, brt->brt_addr[0], brt->brt_addr[1], brt->brt_addr[2], brt->brt_addr[3], 
				   brt->brt_addr[4], brt->brt_addr[5], brt->brt_ifp->if_xname );
#endif
			brt->brt_flags_ext |= IFBAF_EXT_PROXYSTA;
		}
		
		if (brt->brt_ifp_proxysta == NULL) {
#if DIAGNOSTIC
			printf( "%s: proxysta %02x:%02x:%02x:%02x:%02x:%02x on %s; discovery\n",
				   __func__, brt->brt_addr[0], brt->brt_addr[1], brt->brt_addr[2], brt->brt_addr[3], 
				   brt->brt_addr[4], brt->brt_addr[5], brt->brt_ifp->if_xname );
#endif
			bridge_proxysta_discover( brt->brt_ifp, brt->brt_addr );	
		}
	}
}

/*
 * bridge_rtpurge:
 *
 *	Remove all dynamic addresses from a specific interface on the bridge.
 */
static void
bridge_rtpurge(struct bridge_softc *sc, struct ifnet *ifs)
{
	struct bridge_rtnode *brt, *nbrt;
	
	for (brt = LIST_FIRST(&sc->sc_rtlist); brt != NULL; brt = nbrt) {
		nbrt = LIST_NEXT(brt, brt_list);
		if (brt->brt_ifp == ifs) {
#if DIAGNOSTIC
			printf( "%s: purge %s [%02x:%02x:%02x:%02x:%02x:%02x] discovered on %s\n",
                   __func__, brt->brt_ifp_proxysta ? brt->brt_ifp_proxysta->if_xname : brt->brt_ifp->if_xname, 
                   brt->brt_addr[0], brt->brt_addr[1], brt->brt_addr[2], 
                   brt->brt_addr[3], brt->brt_addr[4], brt->brt_addr[5], brt->brt_ifp->if_xname );
#endif
			bridge_rtnode_destroy(sc, brt);
		}
	}
}
#endif

/*
 * bridge_rtdaddr:
 *
 *	Remove an address from the table.
 */
static int
bridge_rtdaddr(struct bridge_softc *sc, const uint8_t *addr)
{
	struct bridge_rtnode *brt;
	
	if ((brt = bridge_rtnode_lookup(sc, addr)) == NULL)
		return (ENOENT);
	
	bridge_rtnode_destroy(sc, brt);
	return (0);
}

/*
 * bridge_rtdelete:
 *
 *	Delete routes to a speicifc member interface.
 */
__private_extern__ void
bridge_rtdelete(struct bridge_softc *sc, struct ifnet *ifp, int full)
{
	struct bridge_rtnode *brt, *nbrt;
	
	for (brt = LIST_FIRST(&sc->sc_rtlist); brt != NULL; brt = nbrt) {
		nbrt = LIST_NEXT(brt, brt_list);
		if (brt->brt_ifp == ifp && (full ||
                                    (brt->brt_flags & IFBAF_TYPEMASK) == IFBAF_DYNAMIC))
			bridge_rtnode_destroy(sc, brt);
	}
}

/*
 * bridge_rtable_init:
 *
 *	Initialize the route table for this bridge.
 */
static int
bridge_rtable_init(struct bridge_softc *sc)
{
	int i;
	
	sc->sc_rthash = _MALLOC(sizeof(*sc->sc_rthash) * BRIDGE_RTHASH_SIZE,
                            M_DEVBUF, M_WAITOK);
	if (sc->sc_rthash == NULL)
		return (ENOMEM);
	
	for (i = 0; i < BRIDGE_RTHASH_SIZE; i++)
		LIST_INIT(&sc->sc_rthash[i]);
	
	sc->sc_rthash_key = random();
	
	LIST_INIT(&sc->sc_rtlist);
	
	return (0);
}

/*
 * bridge_rtable_fini:
 *
 *	Deconstruct the route table for this bridge.
 */
static void
bridge_rtable_fini(struct bridge_softc *sc)
{
	
	_FREE(sc->sc_rthash, M_DEVBUF);
}

/*
 * The following hash function is adapted from "Hash Functions" by Bob Jenkins
 * ("Algorithm Alley", Dr. Dobbs Journal, September 1997).
 */
#define	mix(a, b, c)							\
do {									\
a -= b; a -= c; a ^= (c >> 13);					\
b -= c; b -= a; b ^= (a << 8);					\
c -= a; c -= b; c ^= (b >> 13);					\
a -= b; a -= c; a ^= (c >> 12);					\
b -= c; b -= a; b ^= (a << 16);					\
c -= a; c -= b; c ^= (b >> 5);					\
a -= b; a -= c; a ^= (c >> 3);					\
b -= c; b -= a; b ^= (a << 10);					\
c -= a; c -= b; c ^= (b >> 15);					\
} while (/*CONSTCOND*/0)

static uint32_t
bridge_rthash(__unused struct bridge_softc *sc, const uint8_t *addr)
{
	/* APPLE MODIFICATION - wasabi performance improvment - simplify the hash algorithm */
#if 0
	uint32_t a = 0x9e3779b9, b = 0x9e3779b9, c = sc->sc_rthash_key;
	
	b += addr[5] << 8;
	b += addr[4];
	a += addr[3] << 24;
	a += addr[2] << 16;
	a += addr[1] << 8;
	a += addr[0];
	
	mix(a, b, c);
	
	return (c & BRIDGE_RTHASH_MASK);
#else
	return addr[5];
#endif
}

#undef mix

/*
 * bridge_rtnode_lookup:
 *
 *	Look up a bridge route node for the specified destination.
 */
static struct bridge_rtnode *
bridge_rtnode_lookup(struct bridge_softc *sc, const uint8_t *addr)
{
	struct bridge_rtnode *brt;
	uint32_t hash;
	int dir;
	
	hash = bridge_rthash(sc, addr);
	LIST_FOREACH(brt, &sc->sc_rthash[hash], brt_hash) {
		dir = memcmp(addr, brt->brt_addr, ETHER_ADDR_LEN);
		if (dir == 0)
			return (brt);
		if (dir > 0)
			return (NULL);
	}
	
	return (NULL);
}

/*
 * bridge_rtnode_insert:
 *
 *	Insert the specified bridge node into the route table.  We
 *	assume the entry is not already in the table.
 */
static int
bridge_rtnode_insert(struct bridge_softc *sc, struct bridge_rtnode *brt)
{
	struct bridge_rtnode *lbrt;
	uint32_t hash;
	int dir;
	
	hash = bridge_rthash(sc, brt->brt_addr);
	
	lbrt = LIST_FIRST(&sc->sc_rthash[hash]);
	if (lbrt == NULL) {
		LIST_INSERT_HEAD(&sc->sc_rthash[hash], brt, brt_hash);
		goto out;
	}
	
	do {
		dir = memcmp(brt->brt_addr, lbrt->brt_addr, ETHER_ADDR_LEN);
		if (dir == 0)
			return (EEXIST);
		if (dir > 0) {
			LIST_INSERT_BEFORE(lbrt, brt, brt_hash);
			goto out;
		}
		if (LIST_NEXT(lbrt, brt_hash) == NULL) {
			LIST_INSERT_AFTER(lbrt, brt, brt_hash);
			goto out;
		}
		lbrt = LIST_NEXT(lbrt, brt_hash);
	} while (lbrt != NULL);
	
#ifdef DIAGNOSTIC
	panic("bridge_rtnode_insert: impossible");
#endif
	
out:
	LIST_INSERT_HEAD(&sc->sc_rtlist, brt, brt_list);
	sc->sc_brtcnt++;
	
	return (0);
}

/*
 * bridge_rtnode_destroy:
 *
 *	Destroy a bridge rtnode.
 */
static void
bridge_rtnode_destroy(struct bridge_softc *sc, struct bridge_rtnode *brt)
{
	lck_mtx_assert(sc->sc_mtx, LCK_MTX_ASSERT_OWNED);
	
	/* APPLE MODIFICATION <cbz@apple.com> - add support for Proxy STA */
#if IEEE80211_PROXYSTA
	if (brt->brt_flags_ext & IFBAF_EXT_PROXYSTA) {
#if DIAGNOSTIC
		printf( "%s: proxysta %02x:%02x:%02x:%02x:%02x:%02x %s from %s; idle timeout\n",
               __func__, brt->brt_addr[0], brt->brt_addr[1], brt->brt_addr[2], 
               brt->brt_addr[3], brt->brt_addr[4], brt->brt_addr[5], 
               brt->brt_ifp_proxysta ? brt->brt_ifp_proxysta->if_xname : "unknown",
               brt->brt_ifp->if_xname );
#endif
		bridge_proxysta_idle_timeout( brt->brt_ifp, brt->brt_addr );	
	}
#endif
	
	LIST_REMOVE(brt, brt_hash);
	
	LIST_REMOVE(brt, brt_list);
	sc->sc_brtcnt--;
	zfree(bridge_rtnode_pool, brt);
}

static errno_t
bridge_set_bpf_tap(ifnet_t ifp, bpf_tap_mode mode, bpf_packet_func bpf_callback)
{
	struct bridge_softc *sc = (struct bridge_softc *)ifnet_softc(ifp);
	
	//printf("bridge_set_bpf_tap ifp %p mode %d\n", ifp, mode);
	
	/* TBD locking */
	if (sc == NULL || (sc->sc_flags & SCF_DETACHING)) {
		return ENODEV;
	}
	
	switch (mode) {
		case BPF_TAP_DISABLE:
			sc->sc_bpf_input = sc->sc_bpf_output = NULL;
			break;
			
		case BPF_TAP_INPUT:
			sc->sc_bpf_input = bpf_callback;
			break;
			
		case BPF_TAP_OUTPUT:
			sc->sc_bpf_output = bpf_callback;
			break;
			
		case BPF_TAP_INPUT_OUTPUT:
			sc->sc_bpf_input = sc->sc_bpf_output = bpf_callback;
			break;
			
		default:
			break;
	}
	
	return 0;
}

static void
bridge_detach(__unused ifnet_t ifp)
{
	struct bridge_softc *sc = (struct bridge_softc *)ifnet_softc(ifp);
	
	/* Tear down the routing table. */
	bridge_rtable_fini(sc);
	
	lck_rw_lock_exclusive(bridge_list_lock);
	LIST_REMOVE(sc, sc_list);
	lck_rw_done(bridge_list_lock);
	
	ifnet_release(ifp);
	
	lck_mtx_free(sc->sc_mtx, bridge_lock_grp);
	
	_FREE(sc, M_DEVBUF);
	return;
}

__private_extern__ errno_t bridge_bpf_input(ifnet_t ifp, struct mbuf *m)
{
	struct bridge_softc *sc = (struct bridge_softc *)ifnet_softc(ifp);
	
	if (sc->sc_bpf_input) {
		if (mbuf_pkthdr_rcvif(m) != ifp)
			printf("bridge_bpf_input rcvif: %p != ifp %p\n", mbuf_pkthdr_rcvif(m), ifp);
		(*sc->sc_bpf_input)(ifp, m);
	}
	return 0;
}

__private_extern__ errno_t bridge_bpf_output(ifnet_t ifp, struct mbuf *m)
{
	struct bridge_softc *sc = (struct bridge_softc *)ifnet_softc(ifp);
	
	if (sc->sc_bpf_output) {
		(*sc->sc_bpf_output)(ifp, m);
	}
	return 0;
}

