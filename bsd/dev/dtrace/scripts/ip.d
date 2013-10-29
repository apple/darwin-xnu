/*
 * Copyright (c) 2006-2012 Apple Inc.  All Rights Reserved.
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

#pragma D depends_on library darwin.d
#pragma D depends_on module mach_kernel
#pragma D depends_on provider ip

/* Translators for IP dtrace provider */

typedef struct pktinfo {
	struct mbuf *pkt_addr;	/* Pointer to the packet (struct mbuf) */
} pktinfo_t;

#pragma D binding "1.0" translator
translator pktinfo_t < struct mbuf *m > {
	pkt_addr = m;
};

typedef struct csinfo {
	uint8_t   ip_ver;
	uint16_t  dport;
	uint16_t  sport;
	string	  ip_daddr;
	string	  ip_saddr;
	uint8_t	  protocol;
	struct inpcb *cs_addr;	/* Pointer to inpcb (struct inpcb) */
} csinfo_t;

#pragma D binding "1.0" translator
translator csinfo_t < struct inpcb *P > {
	cs_addr = P;
	ip_ver = (P != NULL) ? (((P->inp_vflag & 0x2) != 0) ? 6 : 4) : 0;
	dport = (P != NULL) ? ntohs(P->inp_fport) : 0;
	sport = (P != NULL) ? ntohs(P->inp_lport) : 0;
	ip_saddr = (P != NULL) ? (((P->inp_vflag & 0x2) != 0) ? 
			inet_ntoa6(&P->inp_dependladdr.inp6_local) :
			inet_ntoa((uint32_t *)&P->inp_dependladdr.inp46_local.ia46_addr4.s_addr)) : "<null>";
	ip_daddr = (P != NULL) ? (((P->inp_vflag & 0x2) != 0) ?
			inet_ntoa6(&P->inp_dependfaddr.inp6_foreign) :
			inet_ntoa((uint32_t *)&P->inp_dependfaddr.inp46_foreign.ia46_addr4.s_addr)) : "<null>";
	protocol = P->inp_ip_p;
};

typedef struct ipinfo {
	uint8_t  ip_ver;		/* IP version (4, 6) */
	uint16_t ip_plength;		/* payload length */
	string   ip_saddr;		/* source address */
	string   ip_daddr;		/* destination address */
} ipinfo_t;

/*
 * The ip vhl byte is the first byte in struct ip. The type names are
 * different depending on whether _IP_VHL is defined or not and that will
 * confuse dtrace. So instead of using type names, just cast and extract
 * version and header length info from the ip structure.
 */
#pragma D binding "1.0" translator
translator ipinfo_t < struct ip * ip > {
	ip_ver = (ip != NULL) ? ((*(uint8_t *) ip) & 0xf0) >> 4 : 0;
	ip_plength = (ip != NULL) ? 
		(ntohs(ip->ip_len) - (((*(uint8_t *) ip) & 0x0f) << 2)) : 0;
	ip_saddr = (ip != NULL) ? inet_ntoa((uint32_t *)&ip->ip_src.s_addr) : "<null>";
	ip_daddr = (ip != NULL) ? inet_ntoa((uint32_t *)&ip->ip_dst.s_addr) : "<null>";
};

#pragma D binding "1.0" translator
translator ipinfo_t < struct ip6_hdr *ip6 > {
	ip_ver = (ip6 != NULL) ? (ip6->ip6_ctlun.ip6_un2_vfc & 0xf0) >> 4 : 0;
	ip_plength = (ip6 != NULL) ? (ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen)) : 0;
	ip_saddr = (ip6 != NULL) ? inet_ntoa6(&ip6->ip6_src) : "<null>";
	ip_daddr = (ip6 != NULL) ? inet_ntoa6(&ip6->ip6_dst) : "<null>";
};

/*
 * void_ip_t is a void pointer to either an IPv4 or IPv6 header. It has
 * its own type name so that a translator can be determined.
 */
typedef uintptr_t void_ip_t;
#pragma D binding "1.0" translator
translator ipinfo_t < void_ip_t *i> {
	ip_ver = (i != NULL) ? (*(uint8_t *)i >> 4) : 0;
	ip_plength = (i != NULL) ? (((*(uint8_t *)i) >> 4 == 4) ? 
		ntohs(((struct ip *)i)->ip_len) - 
		(((*(uint8_t *)i) & 0x0f) << 2): 
		(((*(uint8_t *)i) >> 4 == 6) ? 
		ntohs(((struct ip6_hdr *)i)->ip6_ctlun.ip6_un1.ip6_un1_plen) : 0)) : 0;
	ip_saddr = (i != NULL) ? ((((*(uint8_t *)i)) >> 4 == 4) ? 
		inet_ntoa((uint32_t *)&(((struct ip *)i)->ip_src.s_addr)) : 
		((((*(uint8_t *)i) >> 4) == 6) ?
		inet_ntoa6(&((struct ip6_hdr *)i)->ip6_src) : "<unknown>")) : "<null>"; 
	ip_daddr = (i != NULL) ? (((*(uint8_t *)i) >> 4 == 4) ? 
		inet_ntoa((uint32_t *)&((struct ip*)i)->ip_dst.s_addr) : ((((*(uint8_t *)i) >> 4) == 6) ?
		inet_ntoa6(&((struct ip6_hdr *)i)->ip6_dst) : "<unknown>")) : "<null>";
};

typedef struct ifinfo {
	string    if_name;		/* interface name */
	int8_t    if_local;		/* is delivered locally */
	int8_t    if_ipstack;		/* ipstack id */
	struct ifnet *if_addr;		/* pointer to raw ill_t */
	uint16_t  if_flags;		/* flags: up/down, broadcast etc. */
	uint32_t  if_eflags;		/* extended flags */
	uint16_t  if_unit;
} ifinfo_t;

#pragma D binding "1.0" translator
translator ifinfo_t < struct ifnet *ifp > {
	if_name = (ifp != NULL) ? ifp->if_name : "<null>";
	if_unit = (ifp != NULL) ? ifp->if_unit : 0;
	if_local = 0;
	if_ipstack = 0;
	if_addr = ifp;
	if_flags = (ifp != NULL) ? ifp->if_flags : 0;
	if_eflags = (ifp != NULL) ? ifp->if_eflags : 0;
	
};

typedef struct ipv4info {
	uint8_t	  ipv4_ver;		/* IP version (4) */
	uint8_t   ipv4_ihl;		/* header length, bytes */
	uint8_t   ipv4_tos;		/* type of service field */
	uint16_t  ipv4_length;		/* length (header + payload) */
	uint16_t  ipv4_ident;		/* identification */
	uint8_t   ipv4_flags;		/* IP flags */
	uint16_t  ipv4_offset;		/* fragment offset */
	uint8_t   ipv4_ttl;		/* time to live */
	uint8_t   ipv4_protocol;	/* next level protocol */
	string    ipv4_protostr;	/* next level protocol, as a string */
	uint16_t  ipv4_checksum;	/* header checksum */
	in_addr_t ipv4_src;		/* source address */
	in_addr_t ipv4_dst;		/* destination address */
	string    ipv4_saddr;		/* source address, string */
	string    ipv4_daddr;		/* destination address, string */
	struct ip *ipv4_hdr;		/* pointer to raw header */
} ipv4info_t;

#pragma D binding "1.0" translator
translator ipv4info_t < struct ip *ip > {
	ipv4_ver = (ip != NULL) ? (*(uint8_t *)ip & 0xf0) >> 4 : 0;
	ipv4_ihl = (ip != NULL) ? ((*(uint8_t *)ip & 0x0f) << 2) : 0;
	ipv4_tos = (ip!= NULL) ? ip->ip_tos : 0;
	ipv4_length = (ip != NULL) ? ntohs(ip->ip_len) : 0; 
	ipv4_ident = (ip != NULL) ? ip->ip_id : 0;
	ipv4_flags = (ip != NULL) ? (ntohs(ip->ip_off) & 0xe000) : 0;
	ipv4_offset = (ip != NULL) ? (ntohs(ip->ip_off) & 0x1fff) : 0;
	ipv4_ttl = (ip != NULL) ? ip->ip_ttl : 0;
	ipv4_protocol = (ip != NULL) ? ip->ip_p : 0;
	ipv4_protostr = (ip == NULL) ? "<null>" :
			(ip->ip_p == 1) ? "ICMP" :
			(ip->ip_p == 2) ? "IGMP" :
			(ip->ip_p == 4) ? "IP" :
			(ip->ip_p == 6) ? "TCP": 
			(ip->ip_p == 17) ? "UDP" : 
			(ip->ip_p == 50) ? "ESP": 
			(ip->ip_p == 51) ? "AH" : 
			(ip->ip_p == 58) ? "ICMPV6" : 
			(ip->ip_p == 255) ? "RAW" : stringof(ip->ip_p);
	ipv4_checksum = (ip != NULL) ? ntohs(ip->ip_sum) : 0;
	ipv4_src = (ip != NULL) ? ip->ip_src.s_addr : 0;
	ipv4_dst = (ip != NULL) ? ip->ip_dst.s_addr : 0;
	ipv4_saddr = (ip != NULL) ? inet_ntoa((uint32_t *)&ip->ip_src.s_addr) : "<null>";
	ipv4_daddr = (ip != NULL) ? inet_ntoa((uint32_t *)&ip->ip_dst.s_addr) : "<null>";
	ipv4_hdr = ip;
};

typedef struct ipv6info {
	uint8_t    ipv6_ver;		/* IP version (6) */
	uint8_t    ipv6_tclass;		/* traffic class */
	uint32_t   ipv6_flow;		/* flow label */
	uint16_t   ipv6_plen;		/* payload length */
	uint8_t    ipv6_nexthdr;	/* next header protocol */
	string     ipv6_nextstr;	/* next header protocol, as a string */
	uint8_t    ipv6_hlim;		/* hop limit */
	struct in6_addr *ipv6_src;	/* source address, pointer to struct in6_addr */
	struct in6_addr *ipv6_dst;	/* destination address, pointer to struct in6_addr */
	string     ipv6_saddr;		/* source address, string */
	string     ipv6_daddr;		/* destination address, string */
	struct ip6_hdr *ipv6_hdr;	/* pointer to raw header */
} ipv6info_t;

#pragma D binding "1.0" translator
translator ipv6info_t < struct ip6_hdr *ip6 > {
 	ipv6_ver = (ip6 != NULL) ? ip6->ip6_ctlun.ip6_un2_vfc : 10;
	ipv6_tclass = (ip6 != NULL) ? (ip6->ip6_ctlun.ip6_un1.ip6_un1_flow & 0x0ff00000) >> 20 : 0;
	ipv6_flow = (ip6 != NULL) ? (ip6->ip6_ctlun.ip6_un1.ip6_un1_flow & 0x000fffff) : 0;
	ipv6_plen = (ip6 != NULL) ? ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen) : 0;
	ipv6_nexthdr = (ip6 != NULL) ? ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt : 0;
	ipv6_nextstr = (ip6 == NULL) ? "<null>" :
			(ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == 1) ? "ICMP" :
			(ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == 2) ? "IGMP" :
			(ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == 4) ? "IP" :
			(ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == 6) ? "TCP" :
			(ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == 17) ? "UDP" :
			(ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == 50) ? "ESP" :
			(ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == 51) ? "AH" : 
			(ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == 58) ? "ICMPV6" :
			(ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == 255) ? "RAW" : 
			stringof(ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt);
	ipv6_hlim = (ip6 != NULL) ? ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim : 0;
	ipv6_src = (ip6 != NULL) ? (&ip6->ip6_src) : 0;
	ipv6_dst = (ip6 != NULL) ? (&ip6->ip6_dst) : 0;
	ipv6_saddr = (ip6 != NULL) ? inet_ntoa6(&ip6->ip6_src) : "<null>";
	ipv6_daddr = (ip6 != NULL) ? inet_ntoa6(&ip6->ip6_dst) : "<null>"; 
	ipv6_hdr = ip6;
};
