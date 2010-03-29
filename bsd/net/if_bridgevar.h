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

/*	$apfw: if_bridgevar,v 1.7 2008/10/24 02:34:06 cbzimmer Exp $ */
/*	$NetBSD: if_bridgevar.h,v 1.8 2005/12/10 23:21:38 elad Exp $	*/

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
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed for the NetBSD Project by
 *	Wasabi Systems, Inc.
 * 4. The name of Wasabi Systems, Inc. may not be used to endorse
 *    or promote products derived from this software without specific prior
 *    written permission.
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
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by Jason L. Wright
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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
 * OpenBSD: if_bridge.h,v 1.14 2001/03/22 03:48:29 jason Exp
 */

/*
 * Data structure and control definitions for bridge interfaces.
 */

#ifndef _NET_IF_BRIDGEVAR_H_
#define _NET_IF_BRIDGEVAR_H_

#ifdef PRIVATE

#include <sys/queue.h>

#include <net/if.h>
#include <net/ethernet.h>

/*
 * Commands used in the SIOCSDRVSPEC ioctl.  Note the lookup of the
 * bridge interface itself is keyed off the ifdrv structure.
 */
#define	BRDGADD			0	/* add bridge member (ifbreq) */
#define	BRDGDEL			1	/* delete bridge member (ifbreq) */
#define	BRDGGIFFLGS		2	/* get member if flags (ifbreq) */
#define	BRDGSIFFLGS		3	/* set member if flags (ifbreq) */
#define	BRDGSCACHE		4	/* set cache size (ifbrparam) */
#define	BRDGGCACHE		5	/* get cache size (ifbrparam) */
#define	BRDGGIFS		6	/* get member list (ifbifconf) */
#define	BRDGRTS			7	/* get address list (ifbaconf) */
#define	BRDGSADDR		8	/* set static address (ifbareq) */
#define	BRDGSTO			9	/* set cache timeout (ifbrparam) */
#define	BRDGGTO			10	/* get cache timeout (ifbrparam) */
#define	BRDGDADDR		11	/* delete address (ifbareq) */
#define	BRDGFLUSH		12	/* flush address cache (ifbreq) */

#define	BRDGGPRI		13	/* get priority (ifbrparam) */
#define	BRDGSPRI		14	/* set priority (ifbrparam) */
#define	BRDGGHT			15	/* get hello time (ifbrparam) */
#define	BRDGSHT			16	/* set hello time (ifbrparam) */
#define	BRDGGFD			17	/* get forward delay (ifbrparam) */
#define	BRDGSFD			18	/* set forward delay (ifbrparam) */
#define	BRDGGMA			19	/* get max age (ifbrparam) */
#define	BRDGSMA			20	/* set max age (ifbrparam) */
#define	BRDGSIFPRIO		21	/* set if priority (ifbreq) */
#define BRDGSIFCOST		22	/* set if path cost (ifbreq) */
#define BRDGGFILT	        23	/* get filter flags (ifbrparam) */
#define BRDGSFILT	        24	/* set filter flags (ifbrparam) */
#define	BRDGPURGE		25	/* purge address cache for a particular interface (ifbreq) */

/*
 * Generic bridge control request.
 */
#pragma pack(4)

struct ifbreq {
	char		ifbr_ifsname[IFNAMSIZ];	/* member if name */
	uint32_t	ifbr_ifsflags;		/* member if flags */
        uint16_t        ifbr_portno;            /* member if port number */
	uint8_t		ifbr_state;		/* member if STP state */
	uint8_t		ifbr_priority;		/* member if STP priority */
	uint8_t		ifbr_path_cost;		/* member if STP cost */
};

#pragma pack()

/* BRDGGIFFLAGS, BRDGSIFFLAGS */
#define	IFBIF_LEARNING		0x01	/* if can learn */
#define	IFBIF_DISCOVER		0x02	/* if sends packets w/ unknown dest. */
#define	IFBIF_STP		0x04	/* if participates in spanning tree */
/* APPLE MODIFICATION <cbz@apple.com>
 add the following bits for ProxySTA:
 IFBIF_PROXYSTA, IFBIF_PROXYSTA_DISCOVER
 add the following bits for Guest Network	
 IFBIF_NO_FORWARDING
 */
#define	IFBIF_PROXYSTA				0x08	/* if interface is a proxy sta */
#define	IFBIF_PROXYSTA_DISCOVER		0x10	/* if interface is used to discover proxy sta candidates */
#define	IFBIF_NO_FORWARDING		    0x20	/* if interface cannot forward traffic from one interface to the next */

/* APPLE MODIFICATION <cbz@apple.com> 
 add the following bits for ProxySTA:
 PROXYSTA, PROXYSTA_DISCOVER
 add the following bits for Guest Network	
 NO_FORWARDING
 this was...	
 
 #define	IFBIFBITS	"\020\1LEARNING\2DISCOVER\3STP"
 */
#define	IFBIFBITS	"\020\1LEARNING\2DISCOVER\3STP\4PROXYSTA\5PROXYSTA_DISCOVER\6NO_FORWARDING"

/* BRDGFLUSH */
#define	IFBF_FLUSHDYN		0x00	/* flush learned addresses only */
#define	IFBF_FLUSHALL		0x01	/* flush all addresses */

/* BRDGSFILT */
#define IFBF_FILT_USEIPF	0x00000001 /* run pfil hooks on the bridge
interface */
#define IFBF_FILT_MEMBER	0x00000002 /* run pfil hooks on the member
interfaces */
#define IFBF_FILT_ONLYIP	0x00000004 /* only pass IP[46] packets when
pfil is enabled */
#define IFBF_FILT_MASK		0x00000007 /* mask of valid values */


/* APPLE MODIFICATION <jhw@apple.com>: Default is to pass non-IP packets. */
#define	IFBF_FILT_DEFAULT	( IFBF_FILT_USEIPF | IFBF_FILT_MEMBER )
#if 0
#define	IFBF_FILT_DEFAULT	(IFBF_FILT_USEIPF | \
IFBF_FILT_MEMBER | \
IFBF_FILT_ONLYIP)
#endif

/* STP port states */
#define	BSTP_IFSTATE_DISABLED	0
#define	BSTP_IFSTATE_LISTENING	1
#define	BSTP_IFSTATE_LEARNING	2
#define	BSTP_IFSTATE_FORWARDING	3
#define	BSTP_IFSTATE_BLOCKING	4

/*
 * Interface list structure.
 */

#pragma pack(4)

struct ifbifconf {
	uint32_t	ifbic_len;	/* buffer size */
	union {
		caddr_t	ifbicu_buf;
		struct ifbreq *ifbicu_req;
	} ifbic_ifbicu;
#define	ifbic_buf	ifbic_ifbicu.ifbicu_buf
#define	ifbic_req	ifbic_ifbicu.ifbicu_req
};

#ifdef KERNEL_PRIVATE
struct ifbifconf32 {
	uint32_t	ifbic_len;	/* buffer size */
	union {
		user32_addr_t	ifbicu_buf;
		user32_addr_t	ifbicu_req;
	} ifbic_ifbicu;
};

struct ifbifconf64 {
	uint32_t	ifbic_len;	/* buffer size */
	union {
		user64_addr_t	ifbicu_buf;
		user64_addr_t	ifbicu_req;
	} ifbic_ifbicu;
};
#endif /* KERNEL_PRIVATE */

#pragma pack()

/*
 * Bridge address request.
 */

#pragma pack(4)

struct ifbareq {
	char		ifba_ifsname[IFNAMSIZ];	/* member if name */
	unsigned long	ifba_expire;		/* address expire time */
	uint8_t		ifba_flags;		/* address flags */
	uint8_t		ifba_dst[ETHER_ADDR_LEN];/* destination address */
};

#ifdef KERNEL_PRIVATE
struct ifbareq32 {
	char		ifba_ifsname[IFNAMSIZ];	/* member if name */
	uint32_t	ifba_expire;		/* address expire time */
	uint8_t		ifba_flags;		/* address flags */
	uint8_t		ifba_dst[ETHER_ADDR_LEN];/* destination address */
};

struct ifbareq64 {
	char		ifba_ifsname[IFNAMSIZ];	/* member if name */
	uint64_t	ifba_expire;		/* address expire time */
	uint8_t		ifba_flags;		/* address flags */
	uint8_t		ifba_dst[ETHER_ADDR_LEN];/* destination address */
};
#endif /* KERNEL_PRIVATE */

#pragma pack()

#define	IFBAF_TYPEMASK	0x03	/* address type mask */
#define	IFBAF_DYNAMIC	0x00	/* dynamically learned address */
#define	IFBAF_STATIC	0x01	/* static address */

#define	IFBAFBITS	"\020\1STATIC"

/*
 * Address list structure.
 */

#pragma pack(4)

struct ifbaconf {
	uint32_t	ifbac_len;	/* buffer size */
	union {
		caddr_t ifbacu_buf;
		struct ifbareq *ifbacu_req;
	} ifbac_ifbacu;
#define	ifbac_buf	ifbac_ifbacu.ifbacu_buf
#define	ifbac_req	ifbac_ifbacu.ifbacu_req
};

#ifdef KERNEL_PRIVATE
struct ifbaconf32 {
	uint32_t	ifbac_len;	/* buffer size */
	union {
		user32_addr_t	ifbacu_buf;
		user32_addr_t	ifbacu_req;
	} ifbac_ifbacu;
};

struct ifbaconf64 {
	uint32_t	ifbac_len;	/* buffer size */
	union {
		user64_addr_t	ifbacu_buf;
		user64_addr_t	ifbacu_req;
	} ifbac_ifbacu;
};
#endif /* KERNEL_PRIVATE */

#pragma pack()

/*
 * Bridge parameter structure.
 */

#pragma pack(4)

struct ifbrparam {
	union {
		uint32_t ifbrpu_int32;
		uint16_t ifbrpu_int16;
		uint8_t ifbrpu_int8;
	} ifbrp_ifbrpu;
};

#pragma pack()

#define	ifbrp_csize	ifbrp_ifbrpu.ifbrpu_int32	/* cache size */
#define	ifbrp_ctime	ifbrp_ifbrpu.ifbrpu_int32	/* cache time (sec) */
#define	ifbrp_prio	ifbrp_ifbrpu.ifbrpu_int16	/* bridge priority */
#define	ifbrp_hellotime	ifbrp_ifbrpu.ifbrpu_int8	/* hello time (sec) */
#define	ifbrp_fwddelay	ifbrp_ifbrpu.ifbrpu_int8	/* fwd time (sec) */
#define	ifbrp_maxage	ifbrp_ifbrpu.ifbrpu_int8	/* max age (sec) */
#define	ifbrp_filter	ifbrp_ifbrpu.ifbrpu_int32	/* filtering flags */

#ifdef KERNEL
/*
 * Timekeeping structure used in spanning tree code.
 */
struct bridge_timer {
	uint16_t	active;
	uint16_t	value;
};

struct bstp_config_unit {
	uint64_t	cu_rootid;
	uint64_t	cu_bridge_id;
	uint32_t	cu_root_path_cost;
	uint16_t	cu_message_age;
	uint16_t	cu_max_age;
	uint16_t	cu_hello_time;
	uint16_t	cu_forward_delay;
	uint16_t	cu_port_id;
	uint8_t		cu_message_type;
	uint8_t		cu_topology_change_acknowledgment;
	uint8_t		cu_topology_change;
};

struct bstp_tcn_unit {
	uint8_t		tu_message_type;
};

struct bridge_softc;

/*
 * Bridge interface list entry.
 * (VL) bridge_ifmember would be a better name, more descriptive
 */
struct bridge_iflist {
	LIST_ENTRY(bridge_iflist) bif_next;
	uint64_t		bif_designated_root;
	uint64_t		bif_designated_bridge;
	uint32_t		bif_path_cost;
	uint32_t		bif_designated_cost;
	struct bridge_timer	bif_hold_timer;
	struct bridge_timer	bif_message_age_timer;
	struct bridge_timer	bif_forward_delay_timer;
	uint16_t		bif_port_id;
	uint16_t		bif_designated_port;
	struct bstp_config_unit	bif_config_bpdu;
	uint8_t			bif_state;
	uint8_t			bif_topology_change_acknowledge;
	uint8_t			bif_config_pending;
	uint8_t			bif_change_detection_enabled;
	uint8_t			bif_priority;
	struct ifnet	*bif_ifp;	/* member if */
	uint32_t		bif_flags;	/* member if flags */
	int				bif_mutecap;	/* member muted caps */
	interface_filter_t 	bif_iff_ref;
	struct bridge_softc *bif_sc;
};

/*
 * Bridge route node.
 */
struct bridge_rtnode {
	LIST_ENTRY(bridge_rtnode) brt_hash;	/* hash table linkage */
	LIST_ENTRY(bridge_rtnode) brt_list;	/* list linkage */
	struct ifnet		*brt_ifp;	/* destination if */
	unsigned long		brt_expire;	/* expiration time */
	uint8_t			brt_flags;	/* address flags */
	uint8_t			brt_addr[ETHER_ADDR_LEN];
	/* APPLE MODIFICATION <cbz@apple.com> - add the following elements:
     brt_flags_ext, brt_ifp_proxysta */
#define IFBAF_EXT_PROXYSTA  0x01
	uint8_t			brt_flags_ext;	/* extended flags */
	struct ifnet	*brt_ifp_proxysta;	/* proxy sta if */
};


/*
 * Software state for each bridge.
 */
struct bridge_softc {
	LIST_ENTRY(bridge_softc) sc_list;
	struct ifnet	*sc_if;
	uint64_t		sc_designated_root;
	uint64_t		sc_bridge_id;
	struct bridge_iflist	*sc_root_port;
	uint32_t		sc_root_path_cost;
	uint16_t		sc_max_age;
	uint16_t		sc_hello_time;
	uint16_t		sc_forward_delay;
	uint16_t		sc_bridge_max_age;
	uint16_t		sc_bridge_hello_time;
	uint16_t		sc_bridge_forward_delay;
	uint16_t		sc_topology_change_time;
	uint16_t		sc_hold_time;
	uint16_t		sc_bridge_priority;
	uint8_t			sc_topology_change_detected;
	uint8_t			sc_topology_change;
	struct bridge_timer	sc_hello_timer;
	struct bridge_timer	sc_topology_change_timer;
	struct bridge_timer	sc_tcn_timer;
	uint32_t		sc_brtmax;	/* max # of addresses */
	uint32_t		sc_brtcnt;	/* cur. # of addresses */
	/* APPLE MODIFICATION <cbz@apple.com> - add the following elements:
     sc_brtmax_proxysta */
	uint32_t		sc_brtmax_proxysta;	/* max # of proxy sta addresses */
	uint32_t		sc_brttimeout;	/* rt timeout in seconds */
	LIST_HEAD(, bridge_iflist) sc_iflist;	/* member interface list */
	LIST_HEAD(, bridge_rtnode) *sc_rthash;	/* our forwarding table */
	LIST_HEAD(, bridge_rtnode) sc_rtlist;	/* list version of above */
	uint32_t		sc_rthash_key;	/* key for hash */
	uint32_t		sc_filter_flags; /* ipf and flags */
    
	//(VL)
	char			sc_if_xname[IFNAMSIZ];
    bpf_packet_func	sc_bpf_input;
    bpf_packet_func	sc_bpf_output;
    u_int32_t		sc_flags;
    lck_mtx_t		*sc_mtx;
};

#define SCF_DETACHING 0x1

extern const uint8_t bstp_etheraddr[];

int	bridgeattach(int);
void	bridge_enqueue(struct bridge_softc *, struct ifnet *, struct mbuf *);
void	bridge_rtdelete(struct bridge_softc *, struct ifnet *, int);

void	bstp_initialization(struct bridge_softc *);
void	bstp_stop(struct bridge_softc *);
struct mbuf *bstp_input(struct bridge_softc *, struct ifnet *, struct mbuf *);


#endif /* KERNEL */
#endif /* PRIVATE */
#endif /* !_NET_IF_BRIDGEVAR_H_ */

