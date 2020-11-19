/*
 * Copyright (c) 2019-2020 Apple Inc. All rights reserved.
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

/*
 * net_bridge.c
 * - test if_bridge.c functionality
 */

#include <darwintest.h>
#include <stdio.h>
#include <unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/event.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/bootp.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <net/if_arp.h>
#include <net/bpf.h>
#include <net/if_bridgevar.h>
#include <net/if_fake_var.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <TargetConditionals.h>
#include <darwintest_utils.h>
#include "bpflib.h"
#include "in_cksum.h"

static bool S_debug;
static bool S_cleaning_up;

#define ALL_ADDRS (uint32_t)(-1)

#define DHCP_PAYLOAD_MIN        sizeof(struct bootp)
#define DHCP_FLAGS_BROADCAST    ((u_short)0x8000)

typedef union {
	char            bytes[DHCP_PAYLOAD_MIN];
	/* force 4-byte alignment */
	uint32_t        words[DHCP_PAYLOAD_MIN / sizeof(uint32_t)];
} dhcp_min_payload, *dhcp_min_payload_t;

#define ETHER_PKT_LEN           (ETHER_HDR_LEN + ETHERMTU)
typedef union {
	char            bytes[ETHER_PKT_LEN];
	/* force 4-byte aligment */
	uint32_t        words[ETHER_PKT_LEN / sizeof(uint32_t)];
} ether_packet, *ether_packet_t;

typedef struct {
	struct ip       ip;
	struct udphdr   udp;
} ip_udp_header_t;

typedef struct {
	struct in_addr  src_ip;
	struct in_addr  dst_ip;
	char            zero;
	char            proto;
	unsigned short  length;
} udp_pseudo_hdr_t;

typedef struct {
	struct ip       ip;
	struct tcphdr   tcp;
} ip_tcp_header_t;

typedef union {
	ip_udp_header_t udp;
	ip_tcp_header_t tcp;
} ip_udp_tcp_header_u;

typedef struct {
	struct in_addr  src_ip;
	struct in_addr  dst_ip;
	char            zero;
	char            proto;
	unsigned short  length;
} tcp_pseudo_hdr_t;

typedef struct {
	struct ip6_hdr  ip6;
	struct udphdr   udp;
} ip6_udp_header_t;

typedef struct {
	struct in6_addr src_ip;
	struct in6_addr dst_ip;
	char            zero;
	char            proto;
	unsigned short  length;
} udp6_pseudo_hdr_t;

typedef struct {
	char            ifname[IFNAMSIZ];
	char            member_ifname[IFNAMSIZ]; /* member of bridge */
	ether_addr_t    member_mac;
	int             fd;
	u_int           unit;
	u_int           num_addrs;
	void *          rx_buf;
	int             rx_buf_size;
	bool            mac_nat;

	u_int           test_count;
	u_int           test_address_count;
	uint64_t        test_address_present;
} switch_port, *switch_port_t;

typedef struct {
	u_int           size;
	u_int           count;
	bool            mac_nat;
	switch_port     list[1];
} switch_port_list, * switch_port_list_t;

static struct ifbareq *
bridge_rt_table_copy(u_int * ret_count);

static void
bridge_rt_table_log(struct ifbareq *rt_table, u_int count);

static struct ifbrmne *
bridge_mac_nat_entries_copy(u_int * ret_count);

static void
bridge_mac_nat_entries_log(struct ifbrmne * entries, u_int count);

static void
system_cmd(const char *cmd, bool fail_on_error);

static int
inet_dgram_socket(void)
{
	int     s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(s, "socket(AF_INET, SOCK_DGRAM, 0)");
	return s;
}


/**
** Packet creation/display
**/
#define BOOTP_SERVER_PORT       67
#define BOOTP_CLIENT_PORT       68

#define TEST_SOURCE_PORT        14
#define TEST_DEST_PORT          15

#define EA_UNIT_INDEX           4
#define EA_ADDR_INDEX           5

static void
set_ethernet_address(ether_addr_t *eaddr, u_int unit, u_int addr_index)
{
	u_char  *a = eaddr->octet;

	a[0] = 0x02;
	a[2] = 0x00;
	a[3] = 0x00;
	a[1] = 0x00;
	a[EA_UNIT_INDEX] = (u_char)unit;
	a[EA_ADDR_INDEX] = (u_char)addr_index;
}

#define TEN_NET                 0x0a000000
#define TEN_1_NET               (TEN_NET | 0x010000)

static void
get_ipv4_address(u_int unit, u_int addr_index, struct in_addr *ip)
{
	/* up to 255 units, 255 addresses */
	ip->s_addr = htonl(TEN_1_NET | (unit << 8) | addr_index);
	return;
}

#define IN6ADDR_ULA_INIT \
	{{{ 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }}}

static struct in6_addr ula_address = IN6ADDR_ULA_INIT;

#define ULA_UNIT_INDEX  14
#define ULA_ADDR_INDEX  15

static void
get_ipv6_address(u_int unit, u_int addr_index, struct in6_addr *ip)
{
	*ip = ula_address;
	/* up to 255 units, 255 addresses */
	ip->s6_addr[ULA_UNIT_INDEX] = (uint8_t)unit;
	ip->s6_addr[ULA_ADDR_INDEX] = (uint8_t)addr_index;
}


static void
get_ip_address(uint8_t af, u_int unit, u_int addr_index, union ifbrip *ip)
{
	switch (af) {
	case AF_INET:
		get_ipv4_address(unit, addr_index, &ip->ifbrip_addr);
		break;
	case AF_INET6:
		get_ipv6_address(unit, addr_index, &ip->ifbrip_addr6);
		break;
	default:
		T_FAIL("unrecognized address family %u", af);
		break;
	}
}

static bool
ip_addresses_are_equal(uint8_t af, union ifbrip * ip1, union ifbrip * ip2)
{
	bool    equal;

	switch (af) {
	case AF_INET:
		equal = (ip1->ifbrip_addr.s_addr == ip2->ifbrip_addr.s_addr);
		break;
	case AF_INET6:
		equal = IN6_ARE_ADDR_EQUAL(&ip1->ifbrip_addr6,
		    &ip2->ifbrip_addr6);
		break;
	default:
		T_FAIL("unrecognized address family %u", af);
		equal = false;
		break;
	}
	return equal;
}

static ether_addr_t ether_broadcast = {
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }
};

static ether_addr_t ether_external = {
	{ 0x80, 0x00, 0x00, 0x00, 0x00, 0x01 }
};

static inline struct in_addr
get_external_ipv4_address(void)
{
	struct in_addr  ip;

	/* IP 10.1.255.1 */
	ip.s_addr = htonl(TEN_1_NET | 0xff01);
	return ip;
}

static inline void
get_external_ip_address(uint8_t af, union ifbrip * ip)
{
	switch (af) {
	case AF_INET:
		/* IP 10.1.255.1 */
		ip->ifbrip_addr = get_external_ipv4_address();
		break;
	case AF_INET6:
		/* fd80::1 */
		ip->ifbrip_addr6 = ula_address;
		ip->ifbrip_addr6.s6_addr[1] = 0x80;
		ip->ifbrip_addr6.s6_addr[15] = 0x01;
		break;
	default:
		T_FAIL("unrecognized address family %u", af);
		break;
	}
}

static inline void
get_broadcast_ip_address(uint8_t af, union ifbrip * ip)
{
	switch (af) {
	case AF_INET:
		ip->ifbrip_addr.s_addr = INADDR_BROADCAST;
		break;
	case AF_INET6:
		/* 0xff0e::0 linklocal scope multicast */
		ip->ifbrip_addr6 = in6addr_any;
		ip->ifbrip_addr6.s6_addr[0] = 0xff;
		ip->ifbrip_addr6.s6_addr[1] = __IPV6_ADDR_SCOPE_LINKLOCAL;
		break;
	default:
		T_FAIL("unrecognized address family %u", af);
		break;
	}
}


#define ETHER_NTOA_BUFSIZE      (ETHER_ADDR_LEN * 3)
static const char *
ether_ntoa_buf(const ether_addr_t *n, char * buf, int buf_size)
{
	char *  str;

	str = ether_ntoa(n);
	strlcpy(buf, str, buf_size);
	return buf;
}

static const char *
inet_ptrtop(int af, const void * ptr, char * buf, socklen_t buf_size)
{
	union {
		struct in_addr  ip;
		struct in6_addr ip6;
	} u;

	switch (af) {
	case AF_INET:
		bcopy(ptr, &u.ip, sizeof(u.ip));
		break;
	case AF_INET6:
		bcopy(ptr, &u.ip6, sizeof(u.ip6));
		break;
	default:
		return NULL;
	}
	return inet_ntop(af, &u, buf, buf_size);
}

static __inline__ char *
arpop_name(u_int16_t op)
{
	switch (op) {
	case ARPOP_REQUEST:
		return "ARP REQUEST";
	case ARPOP_REPLY:
		return "ARP REPLY";
	case ARPOP_REVREQUEST:
		return "REVARP REQUEST";
	case ARPOP_REVREPLY:
		return "REVARP REPLY";
	default:
		break;
	}
	return "<unknown>";
}

static void
arp_frame_validate(const struct ether_arp * earp, u_int len, bool dump)
{
	const struct arphdr *   arp_p;
	int                     arphrd;
	char                    buf_sender_ether[ETHER_NTOA_BUFSIZE];
	char                    buf_sender_ip[INET_ADDRSTRLEN];
	char                    buf_target_ether[ETHER_NTOA_BUFSIZE];
	char                    buf_target_ip[INET_ADDRSTRLEN];

	T_QUIET;
	T_ASSERT_GE(len, (u_int)sizeof(*earp),
	    "%s ARP packet size %u need %u",
	    __func__, len, (u_int)sizeof(*earp));
	if (!dump) {
		return;
	}
	arp_p = &earp->ea_hdr;
	arphrd = ntohs(arp_p->ar_hrd);
	T_LOG("%s type=0x%x proto=0x%x", arpop_name(ntohs(arp_p->ar_op)),
	    arphrd, ntohs(arp_p->ar_pro));
	if (arp_p->ar_hln == sizeof(earp->arp_sha)) {
		ether_ntoa_buf((const ether_addr_t *)earp->arp_sha,
		    buf_sender_ether,
		    sizeof(buf_sender_ether));
		ether_ntoa_buf((const ether_addr_t *)earp->arp_tha,
		    buf_target_ether,
		    sizeof(buf_target_ether));
		T_LOG("Sender H/W\t%s", buf_sender_ether);
		T_LOG("Target H/W\t%s", buf_target_ether);
	}
	inet_ptrtop(AF_INET, earp->arp_spa,
	    buf_sender_ip, sizeof(buf_sender_ip));
	inet_ptrtop(AF_INET, earp->arp_tpa,
	    buf_target_ip, sizeof(buf_target_ip));
	T_LOG("Sender IP\t%s", buf_sender_ip);
	T_LOG("Target IP\t%s", buf_target_ip);
	return;
}

static void
ip_frame_validate(const void * buf, u_int buf_len, bool dump)
{
	char                    buf_dst[INET_ADDRSTRLEN];
	char                    buf_src[INET_ADDRSTRLEN];
	const ip_udp_header_t * ip_udp;
	u_int                   ip_len;

	T_QUIET;
	T_ASSERT_GE(buf_len, (u_int)sizeof(struct ip), NULL);
	ip_udp = (const ip_udp_header_t *)buf;
	ip_len = ntohs(ip_udp->ip.ip_len);
	inet_ptrtop(AF_INET, &ip_udp->ip.ip_src,
	    buf_src, sizeof(buf_src));
	inet_ptrtop(AF_INET, &ip_udp->ip.ip_dst,
	    buf_dst, sizeof(buf_dst));
	if (dump) {
		T_LOG("ip src %s dst %s len %u id %d",
		    buf_src, buf_dst, ip_len,
		    ntohs(ip_udp->ip.ip_id));
	}
	T_QUIET;
	T_ASSERT_GE(buf_len, ip_len, NULL);
	T_QUIET;
	T_ASSERT_EQ(ip_udp->ip.ip_v, IPVERSION, NULL);
	T_QUIET;
	T_ASSERT_EQ((u_int)(ip_udp->ip.ip_hl << 2),
	    (u_int)sizeof(struct ip), NULL);
	if (ip_udp->ip.ip_p == IPPROTO_UDP) {
		u_int   udp_len;
		u_int   data_len;

		T_QUIET;
		T_ASSERT_GE(buf_len, (u_int)sizeof(*ip_udp), NULL);
		udp_len = ntohs(ip_udp->udp.uh_ulen);
		T_QUIET;
		T_ASSERT_GE(udp_len, (u_int)sizeof(ip_udp->udp), NULL);
		data_len = udp_len - (u_int)sizeof(ip_udp->udp);
		if (dump) {
			T_LOG("udp src 0x%x dst 0x%x len %u"
			    " csum 0x%x datalen %u",
			    ntohs(ip_udp->udp.uh_sport),
			    ntohs(ip_udp->udp.uh_dport),
			    udp_len,
			    ntohs(ip_udp->udp.uh_sum),
			    data_len);
		}
	}
}

static void
ip6_frame_validate(const void * buf, u_int buf_len, bool dump)
{
	char                    buf_dst[INET6_ADDRSTRLEN];
	char                    buf_src[INET6_ADDRSTRLEN];
	const struct ip6_hdr *  ip6;
	u_int                   ip6_len;

	T_QUIET;
	T_ASSERT_GE(buf_len, (u_int)sizeof(struct ip6_hdr), NULL);
	ip6 = (const struct ip6_hdr *)buf;
	ip6_len = ntohs(ip6->ip6_plen);
	inet_ptrtop(AF_INET6, &ip6->ip6_src, buf_src, sizeof(buf_src));
	inet_ptrtop(AF_INET6, &ip6->ip6_dst, buf_dst, sizeof(buf_dst));
	if (dump) {
		T_LOG("ip6 src %s dst %s len %u", buf_src, buf_dst, ip6_len);
	}
	T_QUIET;
	T_ASSERT_GE(buf_len, ip6_len + (u_int)sizeof(struct ip6_hdr), NULL);
	T_QUIET;
	T_ASSERT_EQ((ip6->ip6_vfc & IPV6_VERSION_MASK),
	    IPV6_VERSION, NULL);
	T_QUIET;
	switch (ip6->ip6_nxt) {
	case IPPROTO_UDP: {
		u_int                   data_len;
		const ip6_udp_header_t *ip6_udp;
		u_int                   udp_len;

		ip6_udp = (const ip6_udp_header_t *)buf;
		T_QUIET;
		T_ASSERT_GE(buf_len, (u_int)sizeof(*ip6_udp), NULL);
		udp_len = ntohs(ip6_udp->udp.uh_ulen);
		T_QUIET;
		T_ASSERT_GE(udp_len, (u_int)sizeof(ip6_udp->udp), NULL);
		data_len = udp_len - (u_int)sizeof(ip6_udp->udp);
		if (dump) {
			T_LOG("udp src 0x%x dst 0x%x len %u"
			    " csum 0x%x datalen %u",
			    ntohs(ip6_udp->udp.uh_sport),
			    ntohs(ip6_udp->udp.uh_dport),
			    udp_len,
			    ntohs(ip6_udp->udp.uh_sum),
			    data_len);
		}
		break;
	}
	case IPPROTO_ICMPV6: {
		const struct icmp6_hdr *icmp6;
		u_int                   icmp6_len;

		icmp6_len = buf_len - sizeof(*ip6);
		T_QUIET;
		T_ASSERT_GE(buf_len, icmp6_len, NULL);
		icmp6 = (const struct icmp6_hdr *)(ip6 + 1);
		switch (icmp6->icmp6_type) {
		case ND_NEIGHBOR_SOLICIT:
			if (dump) {
				T_LOG("neighbor solicit");
			}
			break;
		case ND_NEIGHBOR_ADVERT:
			if (dump) {
				T_LOG("neighbor advert");
			}
			break;
		case ND_ROUTER_SOLICIT:
			if (dump) {
				T_LOG("router solicit");
			}
			break;
		default:
			if (dump) {
				T_LOG("icmp6 code 0x%x", icmp6->icmp6_type);
			}
			break;
		}
		break;
	}
	default:
		break;
	}
}

static void
ethernet_frame_validate(const void * buf, u_int buf_len, bool dump)
{
	char                    ether_dst[ETHER_NTOA_BUFSIZE];
	char                    ether_src[ETHER_NTOA_BUFSIZE];
	uint16_t                ether_type;
	const ether_header_t *  eh_p;

	T_QUIET;
	T_ASSERT_GE(buf_len, (u_int)sizeof(*eh_p), NULL);
	eh_p = (const ether_header_t *)buf;
	ether_type = ntohs(eh_p->ether_type);
	ether_ntoa_buf((const ether_addr_t *)&eh_p->ether_dhost,
	    ether_dst, sizeof(ether_dst));
	ether_ntoa_buf((const ether_addr_t *)&eh_p->ether_shost,
	    ether_src, sizeof(ether_src));
	if (dump) {
		T_LOG("ether dst %s src %s type 0x%x",
		    ether_dst, ether_src, ether_type);
	}
	switch (ether_type) {
	case ETHERTYPE_IP:
		ip_frame_validate(eh_p + 1, (u_int)(buf_len - sizeof(*eh_p)),
		    dump);
		break;
	case ETHERTYPE_ARP:
		arp_frame_validate((const struct ether_arp *)(eh_p + 1),
		    (u_int)(buf_len - sizeof(*eh_p)),
		    dump);
		break;
	case ETHERTYPE_IPV6:
		ip6_frame_validate(eh_p + 1, (u_int)(buf_len - sizeof(*eh_p)),
		    dump);
		break;
	default:
		T_FAIL("unrecognized ethertype 0x%x", ether_type);
		break;
	}
}

static u_int
ethernet_udp4_frame_populate(void * buf, size_t buf_len,
    const ether_addr_t * src,
    struct in_addr src_ip,
    uint16_t src_port,
    const ether_addr_t * dst,
    struct in_addr dst_ip,
    uint16_t dst_port,
    const void * data, u_int data_len)
{
	ether_header_t *        eh_p;
	u_int                   frame_length;
	static int              ip_id;
	ip_udp_header_t *       ip_udp;
	char *                  payload;
	udp_pseudo_hdr_t *      udp_pseudo;

	frame_length = (u_int)(sizeof(*eh_p) + sizeof(*ip_udp)) + data_len;
	if (buf_len < frame_length) {
		return 0;
	}

	/* determine frame offsets */
	eh_p = (ether_header_t *)buf;
	ip_udp = (ip_udp_header_t *)(void *)(eh_p + 1);
	udp_pseudo = (udp_pseudo_hdr_t *)(void *)
	    (((char *)&ip_udp->udp) - sizeof(*udp_pseudo));
	payload = (char *)(eh_p + 1) + sizeof(*ip_udp);

	/* ethernet_header */
	bcopy(src, eh_p->ether_shost, ETHER_ADDR_LEN);
	bcopy(dst, eh_p->ether_dhost, ETHER_ADDR_LEN);
	eh_p->ether_type = htons(ETHERTYPE_IP);

	/* copy the data */
	bcopy(data, payload, data_len);

	/* fill in UDP pseudo header (gets overwritten by IP header below) */
	bcopy(&src_ip, &udp_pseudo->src_ip, sizeof(src_ip));
	bcopy(&dst_ip, &udp_pseudo->dst_ip, sizeof(dst_ip));
	udp_pseudo->zero = 0;
	udp_pseudo->proto = IPPROTO_UDP;
	udp_pseudo->length = htons(sizeof(ip_udp->udp) + data_len);

	/* fill in UDP header */
	ip_udp->udp.uh_sport = htons(src_port);
	ip_udp->udp.uh_dport = htons(dst_port);
	ip_udp->udp.uh_ulen = htons(sizeof(ip_udp->udp) + data_len);
	ip_udp->udp.uh_sum = 0;
	ip_udp->udp.uh_sum = in_cksum(udp_pseudo, (int)(sizeof(*udp_pseudo)
	    + sizeof(ip_udp->udp) + data_len));

	/* fill in IP header */
	bzero(ip_udp, sizeof(ip_udp->ip));
	ip_udp->ip.ip_v = IPVERSION;
	ip_udp->ip.ip_hl = sizeof(struct ip) >> 2;
	ip_udp->ip.ip_ttl = MAXTTL;
	ip_udp->ip.ip_p = IPPROTO_UDP;
	bcopy(&src_ip, &ip_udp->ip.ip_src, sizeof(src_ip));
	bcopy(&dst_ip, &ip_udp->ip.ip_dst, sizeof(dst_ip));
	ip_udp->ip.ip_len = htons(sizeof(*ip_udp) + data_len);
	ip_udp->ip.ip_id = htons(ip_id++);

	/* compute the IP checksum */
	ip_udp->ip.ip_sum = 0; /* needs to be zero for checksum */
	ip_udp->ip.ip_sum = in_cksum(&ip_udp->ip, sizeof(ip_udp->ip));

	return frame_length;
}

static u_int
ethernet_udp6_frame_populate(void * buf, size_t buf_len,
    const ether_addr_t * src,
    struct in6_addr *src_ip,
    uint16_t src_port,
    const ether_addr_t * dst,
    struct in6_addr * dst_ip,
    uint16_t dst_port,
    const void * data, u_int data_len)
{
	ether_header_t *        eh_p;
	u_int                   frame_length;
	ip6_udp_header_t *      ip6_udp;
	char *                  payload;
	udp6_pseudo_hdr_t *     udp6_pseudo;

	frame_length = (u_int)(sizeof(*eh_p) + sizeof(*ip6_udp)) + data_len;
	if (buf_len < frame_length) {
		return 0;
	}

	/* determine frame offsets */
	eh_p = (ether_header_t *)buf;
	ip6_udp = (ip6_udp_header_t *)(void *)(eh_p + 1);
	udp6_pseudo = (udp6_pseudo_hdr_t *)(void *)
	    (((char *)&ip6_udp->udp) - sizeof(*udp6_pseudo));
	payload = (char *)(eh_p + 1) + sizeof(*ip6_udp);

	/* ethernet_header */
	bcopy(src, eh_p->ether_shost, ETHER_ADDR_LEN);
	bcopy(dst, eh_p->ether_dhost, ETHER_ADDR_LEN);
	eh_p->ether_type = htons(ETHERTYPE_IPV6);

	/* copy the data */
	bcopy(data, payload, data_len);

	/* fill in UDP pseudo header (gets overwritten by IP header below) */
	bcopy(src_ip, &udp6_pseudo->src_ip, sizeof(*src_ip));
	bcopy(dst_ip, &udp6_pseudo->dst_ip, sizeof(*dst_ip));
	udp6_pseudo->zero = 0;
	udp6_pseudo->proto = IPPROTO_UDP;
	udp6_pseudo->length = htons(sizeof(ip6_udp->udp) + data_len);

	/* fill in UDP header */
	ip6_udp->udp.uh_sport = htons(src_port);
	ip6_udp->udp.uh_dport = htons(dst_port);
	ip6_udp->udp.uh_ulen = htons(sizeof(ip6_udp->udp) + data_len);
	ip6_udp->udp.uh_sum = 0;
	ip6_udp->udp.uh_sum = in_cksum(udp6_pseudo, (int)(sizeof(*udp6_pseudo)
	    + sizeof(ip6_udp->udp) + data_len));

	/* fill in IP header */
	bzero(&ip6_udp->ip6, sizeof(ip6_udp->ip6));
	ip6_udp->ip6.ip6_vfc = IPV6_VERSION;
	ip6_udp->ip6.ip6_nxt = IPPROTO_UDP;
	bcopy(src_ip, &ip6_udp->ip6.ip6_src, sizeof(*src_ip));
	bcopy(dst_ip, &ip6_udp->ip6.ip6_dst, sizeof(*dst_ip));
	ip6_udp->ip6.ip6_plen = htons(sizeof(struct udphdr) + data_len);
	/* ip6_udp->ip6.ip6_flow = ? */
	return frame_length;
}

static u_int
ethernet_udp_frame_populate(void * buf, size_t buf_len,
    uint8_t af,
    const ether_addr_t * src,
    union ifbrip * src_ip,
    uint16_t src_port,
    const ether_addr_t * dst,
    union ifbrip * dst_ip,
    uint16_t dst_port,
    const void * data, u_int data_len)
{
	u_int   len;

	switch (af) {
	case AF_INET:
		len = ethernet_udp4_frame_populate(buf, buf_len,
		    src,
		    src_ip->ifbrip_addr,
		    src_port,
		    dst,
		    dst_ip->ifbrip_addr,
		    dst_port,
		    data, data_len);
		break;
	case AF_INET6:
		len = ethernet_udp6_frame_populate(buf, buf_len,
		    src,
		    &src_ip->ifbrip_addr6,
		    src_port,
		    dst,
		    &dst_ip->ifbrip_addr6,
		    dst_port,
		    data, data_len);
		break;
	default:
		T_FAIL("unrecognized address family %u", af);
		len = 0;
		break;
	}
	return len;
}

static u_int
ethernet_arp_frame_populate(void * buf, u_int buf_len,
    uint16_t op,
    const ether_addr_t * sender_hw,
    struct in_addr sender_ip,
    const ether_addr_t * target_hw,
    struct in_addr target_ip)
{
	ether_header_t *        eh_p;
	struct ether_arp *      earp;
	struct arphdr *         arp_p;
	u_int                   frame_length;

	frame_length = sizeof(*earp) + sizeof(*eh_p);
	T_QUIET;
	T_ASSERT_GE(buf_len, frame_length,
	    "%s buffer size %u needed %u",
	    __func__, buf_len, frame_length);

	/* ethernet_header */
	eh_p = (ether_header_t *)buf;
	bcopy(sender_hw, eh_p->ether_shost, ETHER_ADDR_LEN);
	if (target_hw != NULL) {
		bcopy(target_hw, eh_p->ether_dhost,
		    sizeof(eh_p->ether_dhost));
	} else {
		bcopy(&ether_broadcast, eh_p->ether_dhost,
		    sizeof(eh_p->ether_dhost));
	}
	eh_p->ether_type = htons(ETHERTYPE_ARP);

	/* ARP payload */
	earp = (struct ether_arp *)(void *)(eh_p + 1);
	arp_p = &earp->ea_hdr;
	arp_p->ar_hrd = htons(ARPHRD_ETHER);
	arp_p->ar_pro = htons(ETHERTYPE_IP);
	arp_p->ar_hln = sizeof(earp->arp_sha);
	arp_p->ar_pln = sizeof(struct in_addr);
	arp_p->ar_op = htons(op);
	bcopy(sender_hw, earp->arp_sha, sizeof(earp->arp_sha));
	bcopy(&sender_ip, earp->arp_spa, sizeof(earp->arp_spa));
	if (target_hw != NULL) {
		bcopy(target_hw, earp->arp_tha, sizeof(earp->arp_tha));
	} else {
		bzero(earp->arp_tha, sizeof(earp->arp_tha));
	}
	bcopy(&target_ip, earp->arp_tpa, sizeof(earp->arp_tpa));
	return frame_length;
}

static uint32_t G_generation;

static uint32_t
next_generation(void)
{
	return G_generation++;
}

static const void *
ethernet_frame_get_udp4_payload(void * buf, u_int buf_len,
    u_int * ret_payload_length)
{
	ether_header_t *        eh_p;
	uint16_t                ether_type;
	ip_udp_header_t *       ip_udp;
	u_int                   ip_len;
	u_int                   left;
	const void *            payload = NULL;
	u_int                   payload_length = 0;
	u_int                   udp_len;

	T_QUIET;
	T_ASSERT_GE(buf_len, (u_int)(sizeof(*eh_p) + sizeof(*ip_udp)), NULL);
	left = buf_len;
	eh_p = (ether_header_t *)buf;
	ether_type = ntohs(eh_p->ether_type);
	T_QUIET;
	T_ASSERT_EQ((int)ether_type, ETHERTYPE_IP, NULL);
	ip_udp = (ip_udp_header_t *)(void *)(eh_p + 1);
	left -= sizeof(*eh_p);
	ip_len = ntohs(ip_udp->ip.ip_len);
	T_QUIET;
	T_ASSERT_GE(left, ip_len, NULL);
	T_QUIET;
	T_ASSERT_EQ((int)ip_udp->ip.ip_v, IPVERSION, NULL);
	T_QUIET;
	T_ASSERT_EQ((u_int)ip_udp->ip.ip_hl << 2, (u_int)sizeof(struct ip),
	        NULL);
	T_QUIET;
	T_ASSERT_EQ((int)ip_udp->ip.ip_p, IPPROTO_UDP, NULL);
	T_QUIET;
	T_ASSERT_GE(buf_len, (u_int)sizeof(*ip_udp), NULL);
	udp_len = ntohs(ip_udp->udp.uh_ulen);
	T_QUIET;
	T_ASSERT_GE(udp_len, (u_int)sizeof(ip_udp->udp), NULL);
	payload_length = udp_len - (int)sizeof(ip_udp->udp);
	if (payload_length > 0) {
		payload = (ip_udp + 1);
	}
	if (payload == NULL) {
		payload_length = 0;
	}
	*ret_payload_length = payload_length;
	return payload;
}

static const void *
ethernet_frame_get_udp6_payload(void * buf, u_int buf_len,
    u_int * ret_payload_length)
{
	ether_header_t *        eh_p;
	uint16_t                ether_type;
	ip6_udp_header_t *      ip6_udp;
	u_int                   ip6_len;
	u_int                   left;
	const void *            payload = NULL;
	u_int                   payload_length = 0;
	u_int                   udp_len;

	T_QUIET;
	T_ASSERT_GE(buf_len, (u_int)(sizeof(*eh_p) + sizeof(*ip6_udp)), NULL);
	left = buf_len;
	eh_p = (ether_header_t *)buf;
	ether_type = ntohs(eh_p->ether_type);
	T_QUIET;
	T_ASSERT_EQ((int)ether_type, ETHERTYPE_IPV6, NULL);
	ip6_udp = (ip6_udp_header_t *)(void *)(eh_p + 1);
	left -= sizeof(*eh_p);
	ip6_len = ntohs(ip6_udp->ip6.ip6_plen);
	T_QUIET;
	T_ASSERT_GE(left, ip6_len + (u_int)sizeof(struct ip6_hdr), NULL);
	T_QUIET;
	T_ASSERT_EQ((int)(ip6_udp->ip6.ip6_vfc & IPV6_VERSION_MASK),
	    IPV6_VERSION, NULL);
	T_QUIET;
	T_ASSERT_EQ((int)ip6_udp->ip6.ip6_nxt, IPPROTO_UDP, NULL);
	T_QUIET;
	T_ASSERT_GE(buf_len, (u_int)sizeof(*ip6_udp), NULL);
	udp_len = ntohs(ip6_udp->udp.uh_ulen);
	T_QUIET;
	T_ASSERT_GE(udp_len, (u_int)sizeof(ip6_udp->udp), NULL);
	payload_length = udp_len - (int)sizeof(ip6_udp->udp);
	if (payload_length > 0) {
		payload = (ip6_udp + 1);
	}
	if (payload == NULL) {
		payload_length = 0;
	}
	*ret_payload_length = payload_length;
	return payload;
}

static const void *
ethernet_frame_get_udp_payload(uint8_t af, void * buf, u_int buf_len,
    u_int * ret_payload_length)
{
	const void *    payload;

	switch (af) {
	case AF_INET:
		payload = ethernet_frame_get_udp4_payload(buf, buf_len,
		    ret_payload_length);
		break;
	case AF_INET6:
		payload = ethernet_frame_get_udp6_payload(buf, buf_len,
		    ret_payload_length);
		break;
	default:
		T_FAIL("unrecognized address family %u", af);
		payload = NULL;
		break;
	}
	return payload;
}

#define MIN_ICMP6_LEN           ((u_int)(sizeof(ether_header_t) +       \
	                                 sizeof(struct ip6_hdr) +       \
	                                 sizeof(struct icmp6_hdr)))
#define ALIGNED_ND_OPT_LEN      8
#define SET_ND_OPT_LEN(a)       (u_int)((a) >> 3)
#define GET_ND_OPT_LEN(a)       (u_int)((a) << 3)
#define ALIGN_ND_OPT(a)         (u_int)roundup(a, ALIGNED_ND_OPT_LEN)
#define LINKADDR_OPT_LEN        (ALIGN_ND_OPT(sizeof(struct nd_opt_hdr) + \
	                                      sizeof(ether_addr_t)))
#define ETHER_IPV6_LEN  (sizeof(*eh_p) + sizeof(*ip6))



static u_int
ethernet_nd6_frame_populate(void * buf, u_int buf_len,
    uint8_t type,
    const ether_addr_t * sender_hw,
    struct in6_addr * sender_ip,
    const ether_addr_t * dest_ether,
    const ether_addr_t * target_hw,
    struct in6_addr * target_ip)
{
	u_int                           data_len = 0;
	ether_header_t *                eh_p;
	u_int                           frame_length;
	struct icmp6_hdr *              icmp6;
	struct ip6_hdr *                ip6;
	struct nd_opt_hdr *             nd_opt;

	switch (type) {
	case ND_ROUTER_SOLICIT:
	case ND_NEIGHBOR_ADVERT:
	case ND_NEIGHBOR_SOLICIT:
		break;
	default:
		T_FAIL("%s: unsupported type %u", __func__, type);
		return 0;
	}

	T_QUIET;
	T_ASSERT_GE(buf_len, MIN_ICMP6_LEN, NULL);

	eh_p = (ether_header_t *)buf;
	ip6 = (struct ip6_hdr *)(void *)(eh_p + 1);
	icmp6 = (struct icmp6_hdr *)(void *)(ip6 + 1);
	frame_length = sizeof(*eh_p) + sizeof(*ip6);
	switch (type) {
	case ND_NEIGHBOR_SOLICIT: {
		struct nd_neighbor_solicit *    nd_ns;
		bool                            sender_is_specified;

		sender_is_specified = !IN6_IS_ADDR_UNSPECIFIED(sender_ip);
		data_len = sizeof(*nd_ns);
		if (sender_is_specified) {
			data_len += LINKADDR_OPT_LEN;
		}
		frame_length += data_len;
		T_QUIET;
		T_ASSERT_GE(buf_len, frame_length, NULL);
		nd_ns = (struct nd_neighbor_solicit *)(void *)icmp6;
		if (sender_is_specified) {
			/* add the source lladdr option */
			nd_opt = (struct nd_opt_hdr *)(nd_ns + 1);
			nd_opt->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
			nd_opt->nd_opt_len = SET_ND_OPT_LEN(LINKADDR_OPT_LEN);
			bcopy(sender_hw, (nd_opt + 1), sizeof(*sender_hw));
		}
		bcopy(target_ip, &nd_ns->nd_ns_target,
		    sizeof(nd_ns->nd_ns_target));
		break;
	}
	case ND_NEIGHBOR_ADVERT: {
		struct nd_neighbor_advert *     nd_na;

		data_len = sizeof(*nd_na) + LINKADDR_OPT_LEN;
		frame_length += data_len;
		T_QUIET;
		T_ASSERT_GE(buf_len, frame_length, NULL);

		nd_na = (struct nd_neighbor_advert *)(void *)icmp6;
		bcopy(target_ip, &nd_na->nd_na_target,
		    sizeof(nd_na->nd_na_target));
		/* add the target lladdr option */
		nd_opt = (struct nd_opt_hdr *)(nd_na + 1);
		nd_opt->nd_opt_type = ND_OPT_TARGET_LINKADDR;
		nd_opt->nd_opt_len = SET_ND_OPT_LEN(LINKADDR_OPT_LEN);
		bcopy(target_hw, (nd_opt + 1), sizeof(*target_hw));
		break;
	}
	case ND_ROUTER_SOLICIT: {
		struct nd_router_solicit *      nd_rs;

		data_len = sizeof(*nd_rs) + LINKADDR_OPT_LEN;
		frame_length += data_len;
		T_QUIET;
		T_ASSERT_GE(buf_len, frame_length, NULL);

		nd_rs = (struct nd_router_solicit *)(void *)icmp6;

		/* add the source lladdr option */
		nd_opt = (struct nd_opt_hdr *)(nd_rs + 1);
		nd_opt->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
		nd_opt->nd_opt_len = SET_ND_OPT_LEN(LINKADDR_OPT_LEN);
		bcopy(sender_hw, (nd_opt + 1), sizeof(*sender_hw));
		break;
	}
	default:
		T_FAIL("%s: unsupported type %u", __func__, type);
		return 0;
	}
	/* icmp6 header */
	icmp6->icmp6_type = type;
	icmp6->icmp6_code = 0;
	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_data32[0] = 0;

	/* ethernet_header */
	bcopy(sender_hw, eh_p->ether_shost, ETHER_ADDR_LEN);
	if (dest_ether != NULL) {
		bcopy(dest_ether, eh_p->ether_dhost,
		    sizeof(eh_p->ether_dhost));
	} else {
		/* XXX ether_dhost should be multicast */
		bcopy(&ether_broadcast, eh_p->ether_dhost,
		    sizeof(eh_p->ether_dhost));
	}
	eh_p->ether_type = htons(ETHERTYPE_IPV6);

	/* IPv6 header */
	bzero(ip6, sizeof(*ip6));
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	ip6->ip6_vfc = IPV6_VERSION;
	bcopy(sender_ip, &ip6->ip6_src, sizeof(ip6->ip6_src));
	/* XXX ip6_dst should be specific multicast */
	bcopy(&in6addr_linklocal_allnodes, &ip6->ip6_dst, sizeof(ip6->ip6_dst));
	ip6->ip6_plen = htons(data_len);

	return frame_length;
}

/**
** Switch port
**/
static void
switch_port_check_tx(switch_port_t port)
{
	int             error;
	struct kevent   kev;
	int             kq;
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000 * 1000};

	kq = kqueue();
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(kq, "kqueue check_tx");
	EV_SET(&kev, port->fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, NULL);
	error = kevent(kq, &kev, 1, &kev, 1, &ts);
	T_QUIET;
	T_ASSERT_EQ(error, 1, "kevent");
	T_QUIET;
	T_ASSERT_EQ((int)kev.filter, EVFILT_WRITE, NULL);
	T_QUIET;
	T_ASSERT_EQ((int)kev.ident, port->fd, NULL);
	T_QUIET;
	T_ASSERT_NULL(kev.udata, NULL);
	close(kq);
	return;
}

static void
switch_port_send_arp(switch_port_t port,
    uint16_t op,
    const ether_addr_t * sender_hw,
    struct in_addr sender_ip,
    const ether_addr_t * target_hw,
    struct in_addr target_ip)
{
	u_int           frame_length;
	ether_packet    pkt;
	ssize_t         n;

	/* make sure we can send */
	switch_port_check_tx(port);
	frame_length = ethernet_arp_frame_populate(&pkt, sizeof(pkt),
	    op,
	    sender_hw,
	    sender_ip,
	    target_hw,
	    target_ip);
	T_QUIET;
	T_ASSERT_GT(frame_length, 0, "%s: frame_length %u",
	    __func__, frame_length);
	if (S_debug) {
		T_LOG("Port %s -> %s transmitting %u bytes",
		    port->ifname, port->member_ifname, frame_length);
	}
	ethernet_frame_validate(&pkt, frame_length, S_debug);
	n = write(port->fd, &pkt, frame_length);
	if (n < 0) {
		T_ASSERT_POSIX_SUCCESS(n, "%s write fd %d failed %ld",
		    port->ifname, port->fd, n);
	}
	T_QUIET;
	T_ASSERT_EQ((u_int)n, frame_length,
	    "%s fd %d wrote %ld",
	    port->ifname, port->fd, n);
}


static void
switch_port_send_nd6(switch_port_t port,
    uint8_t type,
    const ether_addr_t * sender_hw,
    struct in6_addr * sender_ip,
    const ether_addr_t * dest_ether,
    const ether_addr_t * target_hw,
    struct in6_addr * target_ip)
{
	u_int           frame_length;
	ether_packet    pkt;
	ssize_t         n;

	/* make sure we can send */
	switch_port_check_tx(port);
	frame_length = ethernet_nd6_frame_populate(&pkt, sizeof(pkt),
	    type,
	    sender_hw,
	    sender_ip,
	    dest_ether,
	    target_hw,
	    target_ip);
	T_QUIET;
	T_ASSERT_GT(frame_length, 0, "%s: frame_length %u",
	    __func__, frame_length);
	if (S_debug) {
		T_LOG("Port %s -> %s transmitting %u bytes",
		    port->ifname, port->member_ifname, frame_length);
	}
	ethernet_frame_validate(&pkt, frame_length, S_debug);
	n = write(port->fd, &pkt, frame_length);
	if (n < 0) {
		T_ASSERT_POSIX_SUCCESS(n, "%s write fd %d failed %ld",
		    port->ifname, port->fd, n);
	}
	T_QUIET;
	T_ASSERT_EQ((u_int)n, frame_length,
	    "%s fd %d wrote %ld",
	    port->ifname, port->fd, n);
}


static void
switch_port_send_udp(switch_port_t port,
    uint8_t af,
    const ether_addr_t * src_eaddr,
    union ifbrip * src_ip,
    uint16_t src_port,
    const ether_addr_t * dst_eaddr,
    union ifbrip * dst_ip,
    uint16_t dst_port,
    const void * payload, u_int payload_length)
{
	u_int                   frame_length;
	ether_packet            pkt;
	ssize_t                 n;

	/* make sure we can send */
	switch_port_check_tx(port);

	/* generate the packet */
	frame_length
	        = ethernet_udp_frame_populate((void *)&pkt,
	    (u_int)sizeof(pkt),
	    af,
	    src_eaddr,
	    src_ip,
	    src_port,
	    dst_eaddr,
	    dst_ip,
	    dst_port,
	    payload,
	    payload_length);
	T_QUIET;
	T_ASSERT_GT(frame_length, 0, NULL);
	if (S_debug) {
		T_LOG("Port %s transmitting %u bytes",
		    port->ifname, frame_length);
	}
	ethernet_frame_validate(&pkt, frame_length, S_debug);
	n = write(port->fd, &pkt, frame_length);
	if (n < 0) {
		T_ASSERT_POSIX_SUCCESS(n, "%s write fd %d failed %ld",
		    port->ifname, port->fd, n);
	}
	T_QUIET;
	T_ASSERT_EQ((u_int)n, frame_length,
	    "%s fd %d wrote %ld",
	    port->ifname, port->fd, n);
}



static void
switch_port_send_udp_addr_index(switch_port_t port,
    uint8_t af,
    u_int addr_index,
    const ether_addr_t * dst_eaddr,
    union ifbrip * dst_ip,
    const void * payload, u_int payload_length)
{
	ether_addr_t    eaddr;
	union ifbrip    ip;

	/* generate traffic for the unit and address */
	set_ethernet_address(&eaddr, port->unit, addr_index);
	get_ip_address(af, port->unit, addr_index, &ip);
	switch_port_send_udp(port, af,
	    &eaddr, &ip, TEST_SOURCE_PORT,
	    dst_eaddr, dst_ip, TEST_DEST_PORT,
	    payload, payload_length);
}

typedef void
(packet_validator)(switch_port_t port, const ether_header_t * eh_p,
    u_int pkt_len, void * context);
typedef packet_validator * packet_validator_t;

static void
switch_port_receive(switch_port_t port,
    uint8_t af,
    const void * payload, u_int payload_length,
    packet_validator_t validator,
    void * context)
{
	ether_header_t *        eh_p;
	ssize_t                 n;
	char *                  offset;

	n = read(port->fd, port->rx_buf, (unsigned)port->rx_buf_size);
	if (n < 0) {
		if (errno == EAGAIN) {
			return;
		}
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(n, "read %s port %d fd %d",
		    port->ifname, port->unit, port->fd);
		return;
	}
	for (offset = port->rx_buf; n > 0;) {
		struct bpf_hdr *        bpf = (struct bpf_hdr *)(void *)offset;
		u_int                   pkt_len;
		char *                  pkt;
		u_int                   skip;

		pkt = offset + bpf->bh_hdrlen;
		pkt_len = bpf->bh_caplen;

		eh_p = (ether_header_t *)(void *)pkt;
		T_QUIET;
		T_ASSERT_GE(pkt_len, (u_int)sizeof(*eh_p),
		    "short packet %ld", n);

		/* source shouldn't be broadcast/multicast */
		T_QUIET;
		T_ASSERT_EQ(eh_p->ether_shost[0] & 0x01, 0,
		    "broadcast/multicast source");

		if (S_debug) {
			T_LOG("Port %s [unit %d] [fd %d] Received %u bytes",
			    port->ifname, port->unit, port->fd, pkt_len);
		}
		ethernet_frame_validate(pkt, pkt_len, S_debug);

		/* call the validation function */
		(*validator)(port, eh_p, pkt_len, context);

		if (payload != NULL) {
			const void *    p;
			u_int           p_len;

			p = ethernet_frame_get_udp_payload(af, pkt, pkt_len,
			    &p_len);
			T_QUIET;
			T_ASSERT_NOTNULL(p, "ethernet_frame_get_udp_payload");
			T_QUIET;
			T_ASSERT_EQ(p_len, payload_length,
			    "payload length %u < expected %u",
			    p_len, payload_length);
			T_QUIET;
			T_ASSERT_EQ(bcmp(payload, p, payload_length), 0,
			    "unexpected payload");
		}
		skip = BPF_WORDALIGN(pkt_len + bpf->bh_hdrlen);
		if (skip == 0) {
			break;
		}
		offset += skip;
		n -= skip;
	}
	return;
}

static void
switch_port_log(switch_port_t port)
{
	T_LOG("%s [unit %d] [member %s]%s bpf fd %d bufsize %d\n",
	    port->ifname, port->unit,
	    port->member_ifname,
	    port->mac_nat ? " [mac-nat]" : "",
	    port->fd, port->rx_buf_size);
}

#define switch_port_list_size(port_count)               \
	offsetof(switch_port_list, list[port_count])

static switch_port_list_t
switch_port_list_alloc(u_int port_count, bool mac_nat)
{
	switch_port_list_t      list;

	list = (switch_port_list_t)
	    calloc(1, switch_port_list_size(port_count));;
	list->size = port_count;
	list->mac_nat = mac_nat;
	return list;
}

static void
switch_port_list_dealloc(switch_port_list_t list)
{
	u_int           i;
	switch_port_t   port;

	for (i = 0, port = list->list; i < list->count; i++, port++) {
		close(port->fd);
		free(port->rx_buf);
	}
	free(list);
	return;
}

static errno_t
switch_port_list_add_port(switch_port_list_t port_list, u_int unit,
    const char * ifname, const char * member_ifname,
    ether_addr_t * member_mac,
    u_int num_addrs, bool mac_nat)
{
	int             buf_size;
	errno_t         err = EINVAL;
	int             fd = -1;
	int             opt;
	switch_port_t   p;

	if (port_list->count >= port_list->size) {
		T_LOG("Internal error: port_list count %u >= size %u\n",
		    port_list->count, port_list->size);
		goto failed;
	}
	fd = bpf_new();
	if (fd < 0) {
		err = errno;
		T_LOG("bpf_new");
		goto failed;
	}
	opt = 1;
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ioctl(fd, FIONBIO, &opt), NULL);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(bpf_set_immediate(fd, 1), NULL);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(bpf_setif(fd, ifname), "bpf set if %s",
	    ifname);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(bpf_set_see_sent(fd, 0), NULL);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(bpf_set_header_complete(fd, 1), NULL);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(bpf_get_blen(fd, &buf_size), NULL);
	if (S_debug) {
		T_LOG("%s [unit %d] [member %s] bpf fd %d bufsize %d\n",
		    ifname, unit,
		    member_ifname, fd, buf_size);
	}
	p = port_list->list + port_list->count++;
	p->fd = fd;
	p->unit = unit;
	strlcpy(p->ifname, ifname, sizeof(p->ifname));
	strlcpy(p->member_ifname, member_ifname, sizeof(p->member_ifname));
	p->num_addrs = num_addrs;
	p->rx_buf_size = buf_size;
	p->rx_buf = malloc((unsigned)buf_size);
	p->mac_nat = mac_nat;
	p->member_mac = *member_mac;
	return 0;

failed:
	if (fd >= 0) {
		close(fd);
	}
	return err;
}

static switch_port_t
switch_port_list_find_fd(switch_port_list_t ports, int fd)
{
	u_int           i;
	switch_port_t   port;

	for (i = 0, port = ports->list; i < ports->count; i++, port++) {
		if (port->fd == fd) {
			return port;
		}
	}
	return NULL;
}

static void
switch_port_list_log(switch_port_list_t port_list)
{
	u_int           i;
	switch_port_t   port;

	for (i = 0, port = port_list->list; i < port_list->count; i++, port++) {
		switch_port_log(port);
	}
	return;
}

static switch_port_t
switch_port_list_find_member(switch_port_list_t ports, const char * member_ifname)
{
	u_int           i;
	switch_port_t   port;

	for (i = 0, port = ports->list; i < ports->count; i++, port++) {
		if (strcmp(port->member_ifname, member_ifname) == 0) {
			return port;
		}
	}
	return NULL;
}

static void
switch_port_list_check_receive(switch_port_list_t ports, uint8_t af,
    const void * payload, u_int payload_length,
    packet_validator_t validator,
    void * context)
{
	int             i;
	int             n_events;
	struct kevent   kev[ports->count];
	int             kq;
	switch_port_t   port;
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 10 * 1000 * 1000};
	u_int           u;

	kq = kqueue();
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(kq, "kqueue check_receive");
	for (u = 0, port = ports->list; u < ports->count; u++, port++) {
		port->test_count = 0;
		EV_SET(kev + u, port->fd,
		    EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
	}

	do {
		n_events = kevent(kq, kev, (int)ports->count, kev,
		    (int)ports->count, &ts);
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(n_events, "kevent receive %d", n_events);
		for (i = 0; i < n_events; i++) {
			T_QUIET;
			T_ASSERT_EQ((int)kev[i].filter, EVFILT_READ, NULL);
			T_QUIET;
			T_ASSERT_NULL(kev[i].udata, NULL);
			port = switch_port_list_find_fd(ports,
			    (int)kev[i].ident);
			T_QUIET;
			T_ASSERT_NE(port, NULL,
			    "port %p fd %d", (void *)port,
			    (int)kev[i].ident);
			switch_port_receive(port, af, payload, payload_length,
			    validator, context);
		}
	} while (n_events != 0);
	close(kq);
}

static bool
switch_port_list_verify_rt_table(switch_port_list_t port_list, bool log)
{
	bool            all_present = true;
	u_int           i;
	u_int           count;
	struct ifbareq *ifba;
	struct ifbareq *rt_table;
	switch_port_t   port;

	/* clear out current notion of how many addresses are present */
	for (i = 0, port = port_list->list; i < port_list->count; i++, port++) {
		port->test_address_count = 0;
		port->test_address_present = 0;
	}
	rt_table = bridge_rt_table_copy(&count);
	if (rt_table == NULL) {
		return false;
	}
	if (log) {
		bridge_rt_table_log(rt_table, count);
	}
	for (i = 0, ifba = rt_table; i < count; i++, ifba++) {
		uint64_t        addr_bit;
		u_int           addr_index;
		u_int           unit_index;
		u_char *        ea;
		ether_addr_t *  eaddr;

		eaddr = (ether_addr_t *)&ifba->ifba_dst;
		ea = eaddr->octet;
		addr_index = ea[EA_ADDR_INDEX];
		unit_index = ea[EA_UNIT_INDEX];
		port = switch_port_list_find_member(port_list,
		    ifba->ifba_ifsname);
		T_QUIET;
		T_ASSERT_NOTNULL(port, "switch_port_list_find_member %s",
		    ifba->ifba_ifsname);
		if (!S_cleaning_up) {
			T_QUIET;
			T_ASSERT_EQ(unit_index, port->unit, NULL);
			addr_bit = 1 << addr_index;
			T_QUIET;
			T_ASSERT_BITS_NOTSET(port->test_address_present,
			    addr_bit, "%s address %u",
			    ifba->ifba_ifsname, addr_index);
			port->test_address_present |= addr_bit;
			port->test_address_count++;
		}
	}
	for (i = 0, port = port_list->list; i < port_list->count; i++, port++) {
		if (S_debug) {
			T_LOG("%s unit %d [member %s] %u expect %u",
			    port->ifname, port->unit, port->member_ifname,
			    port->test_address_count, port->num_addrs);
		}
		if (port->test_address_count != port->num_addrs) {
			all_present = false;
		}
	}

	free(rt_table);
	return all_present;
}

static bool
switch_port_list_verify_mac_nat(switch_port_list_t port_list, bool log)
{
	bool                    all_present = true;
	u_int                   i;
	u_int                   count;
	static struct ifbrmne * entries;
	switch_port_t           port;
	struct ifbrmne *        scan;


	/* clear out current notion of how many addresses are present */
	for (i = 0, port = port_list->list; i < port_list->count; i++, port++) {
		port->test_address_count = 0;
		port->test_address_present = 0;
	}
	entries = bridge_mac_nat_entries_copy(&count);
	if (entries == NULL) {
		return false;
	}
	if (log) {
		bridge_mac_nat_entries_log(entries, count);
	}
	for (i = 0, scan = entries; i < count; i++, scan++) {
		uint8_t         af;
		uint64_t        addr_bit;
		u_int           addr_index;
		char            buf_ip1[INET6_ADDRSTRLEN];
		char            buf_ip2[INET6_ADDRSTRLEN];
		u_char *        ea;
		ether_addr_t *  eaddr;
		union ifbrip    ip;
		u_int           unit_index;

		eaddr = (ether_addr_t *)&scan->ifbmne_mac;
		ea = eaddr->octet;
		addr_index = ea[EA_ADDR_INDEX];
		unit_index = ea[EA_UNIT_INDEX];
		port = switch_port_list_find_member(port_list,
		    scan->ifbmne_ifname);
		T_QUIET;
		T_ASSERT_NOTNULL(port,
		    "switch_port_list_find_member %s",
		    scan->ifbmne_ifname);
		T_QUIET;
		T_ASSERT_EQ(unit_index, port->unit, NULL);
		af = scan->ifbmne_af;
		get_ip_address(af, port->unit, addr_index, &ip);
		addr_bit = 1 << addr_index;
		T_QUIET;
		T_ASSERT_TRUE(ip_addresses_are_equal(af, &ip, &scan->ifbmne_ip),
		    "mac nat entry IP address %s expected %s",
		    inet_ntop(af, &scan->ifbmne_ip_addr,
		    buf_ip1, sizeof(buf_ip1)),
		    inet_ntop(af, &ip,
		    buf_ip2, sizeof(buf_ip2)));
		T_QUIET;
		T_ASSERT_BITS_NOTSET(port->test_address_present,
		    addr_bit, "%s address %u",
		    scan->ifbmne_ifname, addr_index);
		port->test_address_present |= addr_bit;
		port->test_address_count++;
	}
	for (i = 0, port = port_list->list; i < port_list->count; i++, port++) {
		if (port->mac_nat) {
			/* MAC-NAT interface should have no entries */
			T_QUIET;
			T_ASSERT_EQ(port->test_address_count, 0,
			    "mac nat interface %s has %u entries",
			    port->member_ifname,
			    port->test_address_count);
		} else {
			if (S_debug) {
				T_LOG("%s unit %d [member %s] %u expect %u",
				    port->ifname, port->unit,
				    port->member_ifname,
				    port->test_address_count, port->num_addrs);
			}
			if (port->test_address_count != port->num_addrs) {
				all_present = false;
			}
		}
	}

	free(entries);

	return all_present;
}

/**
** Basic Bridge Tests
**/
static void
send_generation(switch_port_t port, uint8_t af, u_int addr_index,
    const ether_addr_t * dst_eaddr, union ifbrip * dst_ip,
    uint32_t generation)
{
	uint32_t        payload;

	payload = htonl(generation);
	switch_port_send_udp_addr_index(port, af, addr_index, dst_eaddr, dst_ip,
	    &payload, sizeof(payload));
}

static void
check_receive_generation(switch_port_list_t ports, uint8_t af,
    uint32_t generation, packet_validator_t validator,
    __unused void * context)
{
	uint32_t        payload;

	payload = htonl(generation);
	switch_port_list_check_receive(ports, af, &payload, sizeof(payload),
	    validator, context);
}

static void
validate_source_ether_mismatch(switch_port_t port, const ether_header_t * eh_p)
{
	/* source shouldn't be our own MAC addresses */
	T_QUIET;
	T_ASSERT_NE(eh_p->ether_shost[EA_UNIT_INDEX], port->unit,
	    "ether source matches unit %d", port->unit);
}

static void
validate_not_present_dhost(switch_port_t port, const ether_header_t * eh_p,
    __unused u_int pkt_len,
    __unused void * context)
{
	validate_source_ether_mismatch(port, eh_p);
	T_QUIET;
	T_ASSERT_EQ(bcmp(eh_p->ether_dhost, &ether_external,
	    sizeof(eh_p->ether_dhost)), 0,
	    "%s", __func__);
	port->test_count++;
}

static void
validate_broadcast_dhost(switch_port_t port, const ether_header_t * eh_p,
    __unused u_int pkt_len,
    __unused void * context)
{
	validate_source_ether_mismatch(port, eh_p);
	T_QUIET;
	T_ASSERT_NE((eh_p->ether_dhost[0] & 0x01), 0,
	    "%s", __func__);
	port->test_count++;
}

static void
validate_port_dhost(switch_port_t port, const ether_header_t * eh_p,
    __unused u_int pkt_len,
    __unused void * context)
{
	validate_source_ether_mismatch(port, eh_p);
	T_QUIET;
	T_ASSERT_EQ(eh_p->ether_dhost[EA_UNIT_INDEX], port->unit,
	    "wrong dhost unit %d != %d",
	    eh_p->ether_dhost[EA_UNIT_INDEX], port->unit);
	port->test_count++;
}


static void
check_received_count(switch_port_list_t port_list,
    switch_port_t port, uint32_t expected_packets)
{
	u_int           i;
	switch_port_t   scan;

	for (i = 0, scan = port_list->list; i < port_list->count; i++, scan++) {
		if (scan == port) {
			T_QUIET;
			T_ASSERT_EQ(port->test_count, 0,
			    "unexpected receive on port %d",
			    port->unit);
		} else if (expected_packets == ALL_ADDRS) {
			T_QUIET;
			T_ASSERT_EQ(scan->test_count, scan->num_addrs,
			    "didn't receive on all addrs");
		} else {
			T_QUIET;
			T_ASSERT_EQ(scan->test_count, expected_packets,
			    "wrong receive count on port %s", scan->member_ifname);
		}
	}
}

static void
unicast_send_all(switch_port_list_t port_list, uint8_t af, switch_port_t port)
{
	u_int           i;
	switch_port_t   scan;

	for (i = 0, scan = port_list->list; i < port_list->count; i++, scan++) {
		if (S_debug) {
			T_LOG("Unicast send on %s", port->ifname);
		}
		for (u_int j = 0; j < scan->num_addrs; j++) {
			ether_addr_t    eaddr;
			union ifbrip    ip;

			set_ethernet_address(&eaddr, scan->unit, j);
			get_ip_address(af, scan->unit, j, &ip);
			switch_port_send_udp_addr_index(port, af, 0, &eaddr, &ip,
			    NULL, 0);
		}
	}
}


static void
bridge_learning_test_once(switch_port_list_t port_list,
    uint8_t af,
    packet_validator_t validator,
    void * context,
    const ether_addr_t * dst_eaddr,
    bool retry)
{
	u_int           i;
	union ifbrip    dst_ip;
	switch_port_t   port;

	get_broadcast_ip_address(af, &dst_ip);
	for (i = 0, port = port_list->list; i < port_list->count; i++, port++) {
		if (port->test_address_count == port->num_addrs) {
			/* already populated */
			continue;
		}
		if (S_debug) {
			T_LOG("Sending on %s", port->ifname);
		}
		for (u_int j = 0; j < port->num_addrs; j++) {
			uint32_t        generation;

			if (retry) {
				uint64_t        addr_bit;

				addr_bit = 1 << j;
				if ((port->test_address_present & addr_bit)
				    != 0) {
					/* already present */
					continue;
				}
				T_LOG("Retry port %s unit %u address %u",
				    port->ifname, port->unit, j);
			}
			generation = next_generation();
			send_generation(port,
			    af,
			    j,
			    dst_eaddr,
			    &dst_ip,
			    generation);

			/* receive across all ports */
			check_receive_generation(port_list,
			    af,
			    generation,
			    validator,
			    context);

			/* ensure that every port saw the packet */
			check_received_count(port_list, port, 1);
		}
	}
	return;
}

static inline const char *
af_get_str(uint8_t af)
{
	return (af == AF_INET) ? "IPv4" : "IPv6";
}

static void
bridge_learning_test(switch_port_list_t port_list,
    uint8_t af,
    packet_validator_t validator,
    void * context,
    const ether_addr_t * dst_eaddr)
{
	char            ntoabuf[ETHER_NTOA_BUFSIZE];
	u_int           i;
	switch_port_t   port;
	bool            verified = false;

	ether_ntoa_buf(dst_eaddr, ntoabuf, sizeof(ntoabuf));

	/*
	 * Send a broadcast frame from every port in the list so that the bridge
	 * learns our MAC address.
	 */
#define BROADCAST_MAX_TRIES             20
	for (int try = 1; try < BROADCAST_MAX_TRIES; try++) {
		bool    retry = (try > 1);

		if (!retry) {
			T_LOG("%s: %s #ports %u #addrs %u dest %s",
			    __func__,
			    af_get_str(af),
			    port_list->count, port_list->list->num_addrs,
			    ntoabuf);
		} else {
			T_LOG("%s: %s #ports %u #addrs %u dest %s (TRY=%d)",
			    __func__,
			    af_get_str(af),
			    port_list->count, port_list->list->num_addrs,
			    ntoabuf, try);
		}
		bridge_learning_test_once(port_list, af, validator, context,
		    dst_eaddr, retry);
		/*
		 * In the event of a memory allocation failure, it's possible
		 * that the address was not learned. Figure out whether
		 * all addresses are present, and if not, we'll retry on
		 * those that are not present.
		 */
		verified = switch_port_list_verify_rt_table(port_list, false);
		if (verified) {
			break;
		}
		/* wait a short time to allow the system to recover */
		usleep(100 * 1000);
	}
	T_QUIET;
	T_ASSERT_TRUE(verified, "All addresses present");

	/*
	 * Since we just broadcast on every port in the switch, the bridge knows
	 * the port's MAC addresses. The bridge should not need to broadcast the
	 * packet to learn, which means the unicast traffic should only arrive
	 * on the intended port.
	 */
	for (i = 0, port = port_list->list; i < port_list->count; i++, port++) {
		/* send unicast packets to every other port's MAC addresses */
		unicast_send_all(port_list, af, port);

		/* receive all of that generated traffic */
		switch_port_list_check_receive(port_list, af, NULL, 0,
		    validate_port_dhost, NULL);
		/* check that we saw all of the unicast packets */
		check_received_count(port_list, port, ALL_ADDRS);
	}
	T_PASS("%s", __func__);
}

/**
** MAC-NAT tests
**/
static void
mac_nat_check_received_count(switch_port_list_t port_list, switch_port_t port)
{
	u_int           i;
	switch_port_t   scan;

	for (i = 0, scan = port_list->list; i < port_list->count; i++, scan++) {
		u_int   expected = 0;

		if (scan == port) {
			expected = scan->num_addrs;
		}
		T_QUIET;
		T_ASSERT_EQ(scan->test_count, expected,
		    "%s [member %s]%s expected %u actual %u",
		    scan->ifname, scan->member_ifname,
		    scan->mac_nat ? " [mac-nat]" : "",
		    expected, scan->test_count);
	}
}

static void
validate_mac_nat(switch_port_t port, const ether_header_t * eh_p,
    __unused u_int pkt_len,
    __unused void * context)
{
	if (port->mac_nat) {
		bool    equal;

		/* source must match MAC-NAT interface */
		equal = (bcmp(eh_p->ether_shost, &port->member_mac,
		    sizeof(port->member_mac)) == 0);
		if (!equal) {
			ethernet_frame_validate(eh_p, pkt_len, true);
		}
		T_QUIET;
		T_ASSERT_TRUE(equal, "source address match");
		port->test_count++;
	} else {
		validate_not_present_dhost(port, eh_p, pkt_len, NULL);
	}
}

static void
validate_mac_nat_in(switch_port_t port, const ether_header_t * eh_p,
    u_int pkt_len, __unused void * context)
{
	if (S_debug) {
		T_LOG("%s received %u bytes", port->member_ifname, pkt_len);
		ethernet_frame_validate(eh_p, pkt_len, true);
	}
	T_QUIET;
	T_ASSERT_EQ(eh_p->ether_dhost[EA_UNIT_INDEX], port->unit,
	    "dhost unit %u expected %u",
	    eh_p->ether_dhost[EA_UNIT_INDEX], port->unit);
	port->test_count++;
}

static void
validate_mac_nat_arp_out(switch_port_t port, const ether_header_t * eh_p,
    u_int pkt_len, void * context)
{
	const struct ether_arp *        earp;
	switch_port_t                   send_port = (switch_port_t)context;

	if (S_debug) {
		T_LOG("%s received %u bytes", port->member_ifname, pkt_len);
		ethernet_frame_validate(eh_p, pkt_len, true);
	}
	T_QUIET;
	T_ASSERT_EQ((int)ntohs(eh_p->ether_type), (int)ETHERTYPE_ARP, NULL);
	earp = (const struct ether_arp *)(const void *)(eh_p + 1);
	T_QUIET;
	T_ASSERT_GE(pkt_len, (u_int)(sizeof(*eh_p) + sizeof(*earp)), NULL);
	if (port->mac_nat) {
		bool            equal;

		/* source ethernet must match MAC-NAT interface */
		equal = (bcmp(eh_p->ether_shost, &port->member_mac,
		    sizeof(port->member_mac)) == 0);
		if (!equal) {
			ethernet_frame_validate(eh_p, pkt_len, true);
		}
		T_QUIET;
		T_ASSERT_TRUE(equal, "%s -> %s source address translated",
		    send_port->member_ifname,
		    port->member_ifname);
		/* sender hw must match MAC-NAT interface */
		equal = (bcmp(earp->arp_sha, &port->member_mac,
		    sizeof(port->member_mac)) == 0);
		if (!equal) {
			ethernet_frame_validate(eh_p, pkt_len, true);
		}
		T_QUIET;
		T_ASSERT_TRUE(equal, "%s -> %s sender hardware translated",
		    send_port->member_ifname,
		    port->member_ifname);
	} else {
		/* source ethernet must match the sender */
		T_QUIET;
		T_ASSERT_EQ(eh_p->ether_shost[EA_UNIT_INDEX], send_port->unit,
		    "%s -> %s unit %u expected %u",
		    send_port->member_ifname,
		    port->member_ifname,
		    eh_p->ether_shost[EA_UNIT_INDEX], send_port->unit);
		/* source hw must match the sender */
		T_QUIET;
		T_ASSERT_EQ(earp->arp_sha[EA_UNIT_INDEX], send_port->unit,
		    "%s -> %s unit %u expected %u",
		    send_port->member_ifname,
		    port->member_ifname,
		    earp->arp_sha[EA_UNIT_INDEX], send_port->unit);
	}
	port->test_count++;
}

static void
validate_mac_nat_arp_in(switch_port_t port, const ether_header_t * eh_p,
    u_int pkt_len, void * context)
{
	const struct ether_arp *        earp;
	switch_port_t                   send_port = (switch_port_t)context;

	if (S_debug) {
		T_LOG("%s received %u bytes", port->member_ifname, pkt_len);
		ethernet_frame_validate(eh_p, pkt_len, true);
	}
	earp = (const struct ether_arp *)(const void *)(eh_p + 1);
	T_QUIET;
	T_ASSERT_EQ((int)ntohs(eh_p->ether_type), (int)ETHERTYPE_ARP, NULL);
	T_QUIET;
	T_ASSERT_GE(pkt_len, (u_int)(sizeof(*eh_p) + sizeof(*earp)), NULL);
	T_QUIET;
	T_ASSERT_FALSE(port->mac_nat, NULL);

	/* destination ethernet must match the unit */
	T_QUIET;
	T_ASSERT_EQ(eh_p->ether_dhost[EA_UNIT_INDEX], port->unit,
	    "%s -> %s unit %u expected %u",
	    send_port->member_ifname,
	    port->member_ifname,
	    eh_p->ether_dhost[EA_UNIT_INDEX], port->unit);
	/* source hw must match the sender */
	T_QUIET;
	T_ASSERT_EQ(earp->arp_tha[EA_UNIT_INDEX], port->unit,
	    "%s -> %s unit %u expected %u",
	    send_port->member_ifname,
	    port->member_ifname,
	    earp->arp_tha[EA_UNIT_INDEX], port->unit);
	port->test_count++;
}

static void
mac_nat_test_arp_out(switch_port_list_t port_list)
{
	u_int           i;
	struct in_addr  ip_dst;
	switch_port_t   port;

	ip_dst = get_external_ipv4_address();
	for (i = 0, port = port_list->list; i < port_list->count; i++, port++) {
		if (port->mac_nat) {
			continue;
		}
		for (u_int j = 0; j < port->num_addrs; j++) {
			ether_addr_t    eaddr;
			struct in_addr  ip_src;

			set_ethernet_address(&eaddr, port->unit, j);
			get_ipv4_address(port->unit, j, &ip_src);
			switch_port_send_arp(port,
			    ARPOP_REQUEST,
			    &eaddr,
			    ip_src,
			    NULL,
			    ip_dst);
			switch_port_list_check_receive(port_list, AF_INET,
			    NULL, 0,
			    validate_mac_nat_arp_out,
			    port);
			check_received_count(port_list, port, 1);
		}
	}
	T_PASS("%s", __func__);
}

static void
mac_nat_send_arp_response(switch_port_t ext_port, switch_port_t port)
{
	struct in_addr  ip_src;

	T_QUIET;
	T_ASSERT_TRUE(ext_port->mac_nat, "%s is MAC-NAT interface",
	    ext_port->member_ifname);
	ip_src = get_external_ipv4_address();
	for (u_int j = 0; j < port->num_addrs; j++) {
		struct in_addr  ip_dst;

		get_ipv4_address(port->unit, j, &ip_dst);
		if (S_debug) {
			T_LOG("Generating ARP destined to %s %s",
			    port->ifname, inet_ntoa(ip_dst));
		}
		switch_port_send_arp(ext_port,
		    ARPOP_REPLY,
		    &ether_external,
		    ip_src,
		    &ext_port->member_mac,
		    ip_dst);
	}
}

static void
mac_nat_test_arp_in(switch_port_list_t port_list)
{
	u_int           i;
	struct in_addr  ip_src;
	switch_port_t   port;

	ip_src = get_external_ipv4_address();
	for (i = 0, port = port_list->list; i < port_list->count; i++, port++) {
		if (port->mac_nat) {
			continue;
		}
		mac_nat_send_arp_response(port_list->list, port);

		/* receive the generated traffic */
		switch_port_list_check_receive(port_list, AF_INET, NULL, 0,
		    validate_mac_nat_arp_in,
		    port_list->list);

		/* verify that only the single port got the packet */
		mac_nat_check_received_count(port_list, port);
	}
	T_PASS("%s", __func__);
}

static void
validate_mac_nat_dhcp(switch_port_t port, const ether_header_t * eh_p,
    u_int pkt_len, void * context)
{
	u_int                           dp_flags;
	const struct bootp_packet *     pkt;
	switch_port_t                   send_port = (switch_port_t)context;


	T_QUIET;
	T_ASSERT_GE(pkt_len, (u_int)sizeof(*pkt), NULL);
	T_QUIET;
	T_ASSERT_EQ((int)ntohs(eh_p->ether_type), (int)ETHERTYPE_IP, NULL);
	pkt = (const struct bootp_packet *)(const void *)(eh_p + 1);

	dp_flags = ntohs(pkt->bp_bootp.bp_unused);
	if (port->mac_nat) {
		bool            equal;

		/* Broadcast bit must be set */
		T_QUIET;
		T_ASSERT_BITS_SET(dp_flags, (u_int)DHCP_FLAGS_BROADCAST,
		    "%s -> %s: flags 0x%x must have 0x%x",
		    send_port->member_ifname,
		    port->member_ifname,
		    dp_flags, DHCP_FLAGS_BROADCAST);

		/* source must match MAC-NAT interface */
		equal = (bcmp(eh_p->ether_shost, &port->member_mac,
		    sizeof(port->member_mac)) == 0);
		if (!equal) {
			ethernet_frame_validate(eh_p, pkt_len, true);
		}
		T_QUIET;
		T_ASSERT_TRUE(equal, "%s -> %s source address translated",
		    send_port->member_ifname,
		    port->member_ifname);
	} else {
		/* Broadcast bit must not be set */
		T_QUIET;
		T_ASSERT_BITS_NOTSET(dp_flags, DHCP_FLAGS_BROADCAST,
		    "%s -> %s flags 0x%x must not have 0x%x",
		    send_port->member_ifname,
		    port->member_ifname,
		    dp_flags, DHCP_FLAGS_BROADCAST);
		T_QUIET;
		T_ASSERT_EQ(eh_p->ether_shost[EA_UNIT_INDEX], send_port->unit,
		    "%s -> %s unit %u expected %u",
		    send_port->member_ifname,
		    port->member_ifname,
		    eh_p->ether_shost[EA_UNIT_INDEX], send_port->unit);
	}
	port->test_count++;
}

static u_int
make_dhcp_payload(dhcp_min_payload_t payload, ether_addr_t *eaddr)
{
	struct bootp *  dhcp;
	u_int           payload_length;

	/* create a minimal BOOTP packet */
	payload_length = sizeof(*payload);
	dhcp = (struct bootp *)payload;
	bzero(dhcp, payload_length);
	dhcp->bp_op = BOOTREQUEST;
	dhcp->bp_htype = ARPHRD_ETHER;
	dhcp->bp_hlen = sizeof(*eaddr);
	bcopy(eaddr->octet, dhcp->bp_chaddr, sizeof(eaddr->octet));
	return payload_length;
}

static void
mac_nat_test_dhcp(switch_port_list_t port_list, bool link_layer_unicast)
{
	u_int           i;
	struct in_addr  ip_dst = { INADDR_BROADCAST };
	struct in_addr  ip_src = { INADDR_ANY };
	switch_port_t   port;
	ether_addr_t *  ether_dst;

	if (link_layer_unicast) {
		/* use link-layer address of MAC-NAT interface */
		ether_dst = &port_list->list[0].member_mac;
	} else {
		/* use link-layer broadcast address */
		ether_dst = &ether_broadcast;
	}
	for (i = 0, port = port_list->list; i < port_list->count; i++, port++) {
		ether_addr_t            eaddr;
		dhcp_min_payload        payload;
		u_int                   payload_len;

		if (!link_layer_unicast && port->mac_nat) {
			/* only send through non-MAC-NAT ports */
			continue;
		}
		set_ethernet_address(&eaddr, port->unit, 0);
		payload_len = make_dhcp_payload(&payload, &eaddr);
		if (S_debug) {
			T_LOG("%s: transmit DHCP packet (member %s)",
			    port->ifname, port->member_ifname);
		}
		switch_port_send_udp(port,
		    AF_INET,
		    &eaddr,
		    (union ifbrip *)&ip_src,
		    BOOTP_CLIENT_PORT,
		    ether_dst,
		    (union ifbrip *)&ip_dst,
		    BOOTP_SERVER_PORT,
		    &payload,
		    payload_len);

		switch_port_list_check_receive(port_list, AF_INET, NULL, 0,
		    validate_mac_nat_dhcp,
		    port);

		check_received_count(port_list, port, 1);
		if (link_layer_unicast) {
			/* send a single unicast to MAC-NAT interface */
			break;
		}
	}
	T_PASS("%s %s", __func__,
	    link_layer_unicast ? "unicast" : "broadcast");
}


static void
validate_mac_nat_nd6(switch_port_t port,
    const struct icmp6_hdr * icmp6,
    u_int icmp6_len,
    uint8_t opt_type,
    u_int nd_hdr_size,
    switch_port_t send_port)
{
	const uint8_t *                 linkaddr;
	const uint8_t *                 ptr;
	const struct nd_opt_hdr *       nd_opt;
	u_int                           nd_size;

	ptr = (const uint8_t *)icmp6;
	nd_size = nd_hdr_size + LINKADDR_OPT_LEN;
	if (icmp6_len < nd_size) {
		/* no LINKADDR option */
		return;
	}
	nd_opt = (const struct nd_opt_hdr *)(const void *)(ptr + nd_hdr_size);
	T_QUIET;
	T_ASSERT_EQ(nd_opt->nd_opt_type, opt_type, NULL);
	T_QUIET;
	T_ASSERT_EQ(GET_ND_OPT_LEN(nd_opt->nd_opt_len), LINKADDR_OPT_LEN, NULL);
	linkaddr = (const uint8_t *)(nd_opt + 1);
	if (port->mac_nat) {
		bool    equal;

		equal = (bcmp(linkaddr, &port->member_mac,
		    sizeof(port->member_mac)) == 0);
		T_QUIET;
		T_ASSERT_TRUE(equal, "%s -> %s sender hardware translated",
		    send_port->member_ifname,
		    port->member_ifname);
	} else {
		/* source hw must match the sender */
		T_QUIET;
		T_ASSERT_EQ(linkaddr[EA_UNIT_INDEX], send_port->unit,
		    "%s -> %s unit %u expected %u",
		    send_port->member_ifname,
		    port->member_ifname,
		    linkaddr[EA_UNIT_INDEX], send_port->unit);
	}
}

static void
validate_mac_nat_icmp6_out(switch_port_t port, const struct icmp6_hdr * icmp6,
    u_int icmp6_len, switch_port_t send_port)
{
	switch (icmp6->icmp6_type) {
	case ND_NEIGHBOR_ADVERT:
		validate_mac_nat_nd6(port, icmp6, icmp6_len,
		    ND_OPT_TARGET_LINKADDR,
		    sizeof(struct nd_neighbor_advert),
		    send_port);
		break;
	case ND_NEIGHBOR_SOLICIT:
		validate_mac_nat_nd6(port, icmp6, icmp6_len,
		    ND_OPT_SOURCE_LINKADDR,
		    sizeof(struct nd_neighbor_solicit),
		    send_port);
		break;
	case ND_ROUTER_SOLICIT:
		validate_mac_nat_nd6(port, icmp6, icmp6_len,
		    ND_OPT_SOURCE_LINKADDR,
		    sizeof(struct nd_router_solicit),
		    send_port);
		break;
	default:
		T_FAIL("Unsupported icmp6 type %d", icmp6->icmp6_type);
		break;
	}
}

static void
validate_mac_nat_nd6_out(switch_port_t port, const ether_header_t * eh_p,
    u_int pkt_len, void * context)
{
	const struct icmp6_hdr *        icmp6;
	const struct ip6_hdr *          ip6;
	switch_port_t                   send_port = (switch_port_t)context;

	if (S_debug) {
		T_LOG("%s received %u bytes", port->member_ifname, pkt_len);
		ethernet_frame_validate(eh_p, pkt_len, true);
	}
	T_QUIET;
	T_ASSERT_EQ(ntohs(eh_p->ether_type), (u_short)ETHERTYPE_IPV6, NULL);
	ip6 = (const struct ip6_hdr *)(const void *)(eh_p + 1);
	icmp6 = (const struct icmp6_hdr *)(const void *)(ip6 + 1);
	T_QUIET;
	T_ASSERT_GE(pkt_len, (u_int)MIN_ICMP6_LEN, NULL);
	T_QUIET;
	T_ASSERT_EQ(ip6->ip6_nxt, IPPROTO_ICMPV6, NULL);

	/* validate the ethernet header */
	if (port->mac_nat) {
		bool            equal;

		/* source ethernet must match MAC-NAT interface */
		equal = (bcmp(eh_p->ether_shost, &port->member_mac,
		    sizeof(port->member_mac)) == 0);
		if (!equal) {
			ethernet_frame_validate(eh_p, pkt_len, true);
		}
		T_QUIET;
		T_ASSERT_TRUE(equal, "%s -> %s source address translated",
		    send_port->member_ifname,
		    port->member_ifname);
	} else {
		/* source ethernet must match the sender */
		T_QUIET;
		T_ASSERT_EQ(eh_p->ether_shost[EA_UNIT_INDEX], send_port->unit,
		    "%s -> %s unit %u expected %u",
		    send_port->member_ifname,
		    port->member_ifname,
		    eh_p->ether_shost[EA_UNIT_INDEX], send_port->unit);
	}
	/* validate the icmp6 payload */
	validate_mac_nat_icmp6_out(port, icmp6,
	    pkt_len - ETHER_IPV6_LEN,
	    send_port);
	port->test_count++;
}

static void
mac_nat_test_nd6_out(switch_port_list_t port_list)
{
	ether_addr_t *  ext_mac;
	switch_port_t   ext_port;
	u_int           i;
	union ifbrip    ip_dst;
	switch_port_t   port;

	get_external_ip_address(AF_INET6, &ip_dst);
	ext_port = port_list->list;
	T_QUIET;
	T_ASSERT_TRUE(ext_port->mac_nat, NULL);
	ext_mac = &ext_port->member_mac;
	for (i = 0, port = port_list->list; i < port_list->count; i++, port++) {
		if (port->mac_nat) {
			continue;
		}
		/* neighbor solicit */
		for (u_int j = 0; j < port->num_addrs; j++) {
			ether_addr_t    eaddr;
			union ifbrip    ip_src;

			set_ethernet_address(&eaddr, port->unit, j);
			get_ip_address(AF_INET6, port->unit, j, &ip_src);
			switch_port_send_nd6(port,
			    ND_NEIGHBOR_SOLICIT,
			    &eaddr,
			    &ip_src.ifbrip_addr6,
			    NULL,
			    NULL,
			    &ip_dst.ifbrip_addr6);
			switch_port_list_check_receive(port_list, AF_INET,
			    NULL, 0,
			    validate_mac_nat_nd6_out,
			    port);
			check_received_count(port_list, port, 1);
		}
		/* neighbor advert */
		for (u_int j = 0; j < port->num_addrs; j++) {
			ether_addr_t    eaddr;
			union ifbrip    ip_src;

			set_ethernet_address(&eaddr, port->unit, j);
			get_ip_address(AF_INET6, port->unit, j, &ip_src);
			switch_port_send_nd6(port,
			    ND_NEIGHBOR_ADVERT,
			    &eaddr,
			    &ip_src.ifbrip_addr6,
			    NULL,
			    &eaddr,
			    &ip_src.ifbrip_addr6);
			switch_port_list_check_receive(port_list, AF_INET,
			    NULL, 0,
			    validate_mac_nat_nd6_out,
			    port);
			check_received_count(port_list, port, 1);
		}
		/* router solicit */
		for (u_int j = 0; j < port->num_addrs; j++) {
			ether_addr_t    eaddr;
			union ifbrip    ip_src;

			set_ethernet_address(&eaddr, port->unit, j);
			get_ip_address(AF_INET6, port->unit, j, &ip_src);
			//get_ipv6ll_address(port->unit, j, &ip_src.ifbrip_addr6);
			switch_port_send_nd6(port,
			    ND_ROUTER_SOLICIT,
			    &eaddr,
			    &ip_src.ifbrip_addr6,
			    NULL,
			    NULL,
			    NULL);
			switch_port_list_check_receive(port_list, AF_INET,
			    NULL, 0,
			    validate_mac_nat_nd6_out,
			    port);
			check_received_count(port_list, port, 1);
		}
	}
	T_PASS("%s", __func__);
}

static void
mac_nat_send_response(switch_port_t ext_port, uint8_t af, switch_port_t port)
{
	union ifbrip    src_ip;

	T_QUIET;
	T_ASSERT_TRUE(ext_port->mac_nat, "%s is MAC-NAT interface",
	    ext_port->member_ifname);
	if (S_debug) {
		T_LOG("Generating UDP traffic destined to %s", port->ifname);
	}
	get_external_ip_address(af, &src_ip);
	for (u_int j = 0; j < port->num_addrs; j++) {
		union ifbrip    ip;

		get_ip_address(af, port->unit, j, &ip);
		switch_port_send_udp(ext_port,
		    af,
		    &ether_external,
		    &src_ip,
		    TEST_DEST_PORT,
		    &ext_port->member_mac,
		    &ip,
		    TEST_SOURCE_PORT,
		    NULL, 0);
	}
}


static void
mac_nat_test_ip_once(switch_port_list_t port_list, uint8_t af, bool retry)
{
	union ifbrip    dst_ip;
	u_int           i;
	switch_port_t   port;

	get_external_ip_address(af, &dst_ip);
	for (i = 0, port = port_list->list; i < port_list->count; i++, port++) {
		if (port->test_address_count == port->num_addrs) {
			/* already populated */
			continue;
		}
		if (S_debug) {
			T_LOG("Sending on %s", port->ifname);
		}
		for (u_int j = 0; j < port->num_addrs; j++) {
			uint32_t        generation;

			if (retry) {
				uint64_t        addr_bit;

				addr_bit = 1 << j;
				if ((port->test_address_present & addr_bit)
				    != 0) {
					/* already present */
					continue;
				}
				T_LOG("Retry port %s unit %u address %u",
				    port->ifname, port->unit, j);
			}

			generation = next_generation();
			send_generation(port,
			    af,
			    j,
			    &ether_external,
			    &dst_ip,
			    generation);

			/* receive across all ports */
			check_receive_generation(port_list,
			    af,
			    generation,
			    validate_mac_nat,
			    NULL);

			/* ensure that every port saw the packet */
			check_received_count(port_list, port, 1);
		}
	}
	return;
}

static void
mac_nat_test_ip(switch_port_list_t port_list, uint8_t af)
{
	u_int           i;
	switch_port_t   port;
	bool            verified = false;

	/*
	 * Send a packet from every port in the list so that the bridge
	 * learns the MAC addresses and IP addresses.
	 */
#define MAC_NAT_MAX_TRIES               20
	for (int try = 1; try < BROADCAST_MAX_TRIES; try++) {
		bool    retry = (try > 1);

		if (!retry) {
			T_LOG("%s: #ports %u #addrs %u",
			    __func__,
			    port_list->count, port_list->list->num_addrs);
		} else {
			T_LOG("%s: #ports %u #addrs %u destination (TRY=%d)",
			    __func__,
			    port_list->count, port_list->list->num_addrs,
			    try);
		}
		mac_nat_test_ip_once(port_list, af, retry);
		/*
		 * In the event of a memory allocation failure, it's possible
		 * that the address was not learned. Figure out whether
		 * all addresses are present, and if not, we'll retry on
		 * those that are not present.
		 */
		verified = switch_port_list_verify_mac_nat(port_list, false);
		if (verified) {
			break;
		}
		/* wait a short time to allow the system to recover */
		usleep(100 * 1000);
	}
	T_QUIET;
	T_ASSERT_TRUE(verified, "All addresses present");

	/*
	 * The bridge now has an IP address <-> MAC address binding for every
	 * address on each internal interface.
	 *
	 * Generate an inbound packet on the MAC-NAT interface targeting
	 * each interface address. Verify that the packet appears on
	 * the appropriate internal address with appropriate translation.
	 */
	for (i = 0, port = port_list->list; i < port_list->count; i++, port++) {
		if (port->mac_nat) {
			continue;
		}
		mac_nat_send_response(port_list->list, af, port);

		/* receive the generated traffic */
		switch_port_list_check_receive(port_list, AF_INET, NULL, 0,
		    validate_mac_nat_in,
		    NULL);

		/* verify that only the single port got the packet */
		mac_nat_check_received_count(port_list, port);
	}
	T_PASS("%s", __func__);
}

/**
** interface management
**/

static int
ifnet_get_lladdr(int s, const char * ifname, ether_addr_t * eaddr)
{
	int err;
	struct ifreq ifr;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_addr.sa_family = AF_LINK;
	ifr.ifr_addr.sa_len = ETHER_ADDR_LEN;
	err = ioctl(s, SIOCGIFLLADDR, &ifr);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(err, "SIOCGIFLLADDR %s", ifname);
	bcopy(ifr.ifr_addr.sa_data, eaddr->octet, ETHER_ADDR_LEN);
	return err;
}


static int
ifnet_attach_ip(int s, char * name)
{
	int                     err;
	struct ifreq    ifr;

	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	err = ioctl(s, SIOCPROTOATTACH, &ifr);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(err, "SIOCPROTOATTACH %s", ifr.ifr_name);
	return err;
}

#if 0
static int
ifnet_detach_ip(int s, char * name)
{
	int                     err;
	struct ifreq    ifr;

	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	err = ioctl(s, SIOCPROTODETACH, &ifr);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(err, "SIOCPROTODETACH %s", ifr.ifr_name);
	return err;
}
#endif

static int
ifnet_destroy(int s, const char * ifname, bool fail_on_error)
{
	int             err;
	struct ifreq    ifr;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	err = ioctl(s, SIOCIFDESTROY, &ifr);
	if (fail_on_error) {
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(err, "SIOCSIFDESTROY %s", ifr.ifr_name);
	}
	if (err < 0) {
		T_LOG("SIOCSIFDESTROY %s", ifr.ifr_name);
	}
	return err;
}

static int
ifnet_set_flags(int s, const char * ifname,
    uint16_t flags_set, uint16_t flags_clear)
{
	uint16_t        flags_after;
	uint16_t        flags_before;
	struct ifreq    ifr;
	int             ret;

	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ret = ioctl(s, SIOCGIFFLAGS, (caddr_t)&ifr);
	if (ret != 0) {
		T_LOG("SIOCGIFFLAGS %s", ifr.ifr_name);
		return ret;
	}
	flags_before = (uint16_t)ifr.ifr_flags;
	ifr.ifr_flags |= flags_set;
	ifr.ifr_flags &= ~(flags_clear);
	flags_after = (uint16_t)ifr.ifr_flags;
	if (flags_before == flags_after) {
		/* nothing to do */
		ret = 0;
	} else {
		/* issue the ioctl */
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(ioctl(s, SIOCSIFFLAGS, &ifr),
		    "SIOCSIFFLAGS %s 0x%x",
		    ifr.ifr_name, (uint16_t)ifr.ifr_flags);
		if (S_debug) {
			T_LOG("setflags(%s set 0x%x clear 0x%x) 0x%x => 0x%x",
			    ifr.ifr_name, flags_set, flags_clear,
			    flags_before, flags_after);
		}
	}
	return ret;
}

#define BRIDGE_NAME     "bridge"
#define BRIDGE200       BRIDGE_NAME "200"

#define FETH_NAME       "feth"

/* On some platforms with DEBUG kernel, we need to wait a while */
#define SIFCREATE_RETRY 600

static int
ifnet_create(int s, const char * ifname)
{
	int             error = 0;
	struct ifreq    ifr;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	for (int i = 0; i < SIFCREATE_RETRY; i++) {
		if (ioctl(s, SIOCIFCREATE, &ifr) < 0) {
			error = errno;
			T_LOG("SIOCSIFCREATE %s: %s", ifname,
			    strerror(error));
			if (error == EBUSY) {
				/* interface is tearing down, try again */
				usleep(10000);
			} else if (error == EEXIST) {
				/* interface exists, try destroying it */
				(void)ifnet_destroy(s, ifname, false);
			} else {
				/* unexpected failure */
				break;
			}
		} else {
			error = 0;
			break;
		}
	}
	if (error == 0) {
		error = ifnet_set_flags(s, ifname, IFF_UP, 0);
	}
	return error;
}

static int
siocdrvspec(int s, const char * ifname,
    u_long op, void *arg, size_t argsize, bool set)
{
	struct ifdrv    ifd;

	memset(&ifd, 0, sizeof(ifd));
	strlcpy(ifd.ifd_name, ifname, sizeof(ifd.ifd_name));
	ifd.ifd_cmd = op;
	ifd.ifd_len = argsize;
	ifd.ifd_data = arg;
	return ioctl(s, set ? SIOCSDRVSPEC : SIOCGDRVSPEC, &ifd);
}


static int
fake_set_peer(int s, const char * feth, const char * feth_peer)
{
	struct if_fake_request  iffr;
	int                     ret;

	bzero((char *)&iffr, sizeof(iffr));
	if (feth_peer != NULL) {
		strlcpy(iffr.iffr_peer_name, feth_peer,
		    sizeof(iffr.iffr_peer_name));
	}
	ret = siocdrvspec(s, feth, IF_FAKE_S_CMD_SET_PEER,
	    &iffr, sizeof(iffr), true);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret,
	    "SIOCDRVSPEC(%s, IF_FAKE_S_CMD_SET_PEER, %s)",
	    feth, (feth_peer != NULL) ? feth_peer : "<none>");
	return ret;
}

static int
bridge_add_member(int s, const char * bridge, const char * member)
{
	struct ifbreq           req;
	int                     ret;

	memset(&req, 0, sizeof(req));
	strlcpy(req.ifbr_ifsname, member, sizeof(req.ifbr_ifsname));
	ret = siocdrvspec(s, bridge, BRDGADD, &req, sizeof(req), true);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "%s %s %s", __func__, bridge, member);
	return ret;
}


static int
bridge_set_mac_nat(int s, const char * bridge, const char * member, bool enable)
{
	uint32_t        flags;
	bool            need_set = false;
	struct ifbreq   req;
	int             ret;

	memset(&req, 0, sizeof(req));
	strlcpy(req.ifbr_ifsname, member, sizeof(req.ifbr_ifsname));
	ret = siocdrvspec(s, bridge, BRDGGIFFLGS, &req, sizeof(req), false);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "BRDGGIFFLGS %s %s", bridge, member);
	flags = req.ifbr_ifsflags;
	if (enable) {
		if ((flags & IFBIF_MAC_NAT) == 0) {
			need_set = true;
			req.ifbr_ifsflags |= IFBIF_MAC_NAT;
		}
		/* need to set it */
	} else if ((flags & IFBIF_MAC_NAT) != 0) {
		/* need to clear it */
		need_set = true;
		req.ifbr_ifsflags &= ~(uint32_t)IFBIF_MAC_NAT;
	}
	if (need_set) {
		ret = siocdrvspec(s, bridge, BRDGSIFFLGS,
		    &req, sizeof(req), true);
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(ret, "BRDGSIFFLGS %s %s 0x%x => 0x%x",
		    bridge, member,
		    flags, req.ifbr_ifsflags);
	}
	return ret;
}

static struct ifbareq *
bridge_rt_table_copy_common(const char * bridge, u_int * ret_count)
{
	struct ifbaconf         ifbac;
	u_int                   len = 8 * 1024;
	char *                  inbuf = NULL;
	char *                  ninbuf;
	int                     ret;
	struct ifbareq *        rt_table = NULL;
	int                     s;

	s = inet_dgram_socket();

	/*
	 * BRDGRTS should work like other ioctl's where passing in NULL
	 * for the buffer says "tell me how many there are". Unfortunately,
	 * it doesn't so we have to pass in a buffer, then check that it
	 * was too big.
	 */
	for (;;) {
		ninbuf = realloc(inbuf, len);
		T_QUIET;
		T_ASSERT_NOTNULL((void *)ninbuf, "realloc %u", len);
		ifbac.ifbac_len = len;
		ifbac.ifbac_buf = inbuf = ninbuf;
		ret = siocdrvspec(s, bridge, BRDGRTS,
		    &ifbac, sizeof(ifbac), false);
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(ret, "%s %s", __func__, bridge);
		if ((ifbac.ifbac_len + sizeof(*rt_table)) < len) {
			/* we passed a buffer larger than what was required */
			break;
		}
		len *= 2;
	}
	if (ifbac.ifbac_len == 0) {
		free(ninbuf);
		T_LOG("No bridge routing entries");
		goto done;
	}
	*ret_count = ifbac.ifbac_len / sizeof(*rt_table);
	rt_table = (struct ifbareq *)(void *)ninbuf;
done:
	if (rt_table == NULL) {
		*ret_count = 0;
	}
	if (s >= 0) {
		close(s);
	}
	return rt_table;
}

static struct ifbareq *
bridge_rt_table_copy(u_int * ret_count)
{
	return bridge_rt_table_copy_common(BRIDGE200, ret_count);
}

static void
bridge_rt_table_log(struct ifbareq *rt_table, u_int count)
{
	u_int                   i;
	char                    ntoabuf[ETHER_NTOA_BUFSIZE];
	struct ifbareq *        ifba;

	for (i = 0, ifba = rt_table; i < count; i++, ifba++) {
		ether_ntoa_buf((const ether_addr_t *)&ifba->ifba_dst,
		    ntoabuf, sizeof(ntoabuf));
		T_LOG("%s %s %lu", ifba->ifba_ifsname, ntoabuf,
		    ifba->ifba_expire);
	}
	return;
}

static struct ifbrmne *
bridge_mac_nat_entries_copy_common(const char * bridge, u_int * ret_count)
{
	char *                  buf = NULL;
	u_int                   count = 0;
	int                     err;
	u_int                   i;
	struct ifbrmnelist      mnl;
	struct ifbrmne *        ret_list = NULL;
	int                     s;
	char *                  scan;


	s = inet_dgram_socket();

	/* find out how many there are */
	bzero(&mnl, sizeof(mnl));
	err = siocdrvspec(s, bridge, BRDGGMACNATLIST, &mnl, sizeof(mnl), false);
	if (err != 0 && S_cleaning_up) {
		T_LOG("BRDGGMACNATLIST %s failed %d", bridge, errno);
		goto done;
	}
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(err, "BRDGGMACNATLIST %s", bridge);
	T_QUIET;
	T_ASSERT_GE(mnl.ifbml_elsize, (uint16_t)sizeof(struct ifbrmne),
	    "mac nat entry size %u minsize %u",
	    mnl.ifbml_elsize, (u_int)sizeof(struct ifbrmne));
	if (mnl.ifbml_len == 0) {
		goto done;
	}

	/* call again with a buffer large enough to hold them */
	buf = malloc(mnl.ifbml_len);
	T_QUIET;
	T_ASSERT_NOTNULL(buf, "mac nat entries buffer");
	mnl.ifbml_buf = buf;
	err = siocdrvspec(s, bridge, BRDGGMACNATLIST, &mnl, sizeof(mnl), false);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(err, "BRDGGMACNATLIST %s", bridge);
	count = mnl.ifbml_len / mnl.ifbml_elsize;
	if (count == 0) {
		goto done;
	}
	if (mnl.ifbml_elsize == sizeof(struct ifbrmne)) {
		/* element size is expected size, no need to "right-size" it */
		ret_list = (struct ifbrmne *)(void *)buf;
		buf = NULL;
		goto done;
	}
	/* element size is larger than we expect, create a "right-sized" array */
	ret_list = malloc(count * sizeof(*ret_list));
	T_QUIET;
	T_ASSERT_NOTNULL(ret_list, "mac nat entries list");
	for (i = 0, scan = buf; i < count; i++, scan += mnl.ifbml_elsize) {
		struct ifbrmne *        ifbmne;

		ifbmne = (struct ifbrmne *)(void *)scan;
		ret_list[i] = *ifbmne;
	}
done:
	if (s >= 0) {
		close(s);
	}
	if (buf != NULL) {
		free(buf);
	}
	*ret_count = count;
	return ret_list;
}

static struct ifbrmne *
bridge_mac_nat_entries_copy(u_int * ret_count)
{
	return bridge_mac_nat_entries_copy_common(BRIDGE200, ret_count);
}

static void
bridge_mac_nat_entries_log(struct ifbrmne * entries, u_int count)
{
	u_int                   i;
	char                    ntoabuf[ETHER_NTOA_BUFSIZE];
	char                    ntopbuf[INET6_ADDRSTRLEN];
	struct ifbrmne *        scan;

	for (i = 0, scan = entries; i < count; i++, scan++) {
		ether_ntoa_buf((const ether_addr_t *)&scan->ifbmne_mac,
		    ntoabuf, sizeof(ntoabuf));
		inet_ntop(scan->ifbmne_af, &scan->ifbmne_ip,
		    ntopbuf, sizeof(ntopbuf));
		printf("%s %s %s %lu\n",
		    scan->ifbmne_ifname, ntopbuf, ntoabuf,
		    (unsigned long)scan->ifbmne_expire);
	}
	return;
}

/**
** Test Main
**/
static u_int                    S_n_ports;
static switch_port_list_t       S_port_list;

static void
bridge_cleanup(const char * bridge, u_int n_ports, bool fail_on_error);

static void
cleanup_common(bool dump_table)
{
	if (S_n_ports == 0) {
		return;
	}
	S_cleaning_up = true;
	if ((S_port_list != NULL && S_port_list->mac_nat)
	    || (dump_table && S_port_list != NULL)) {
		switch_port_list_log(S_port_list);
		if (S_port_list->mac_nat) {
			switch_port_list_verify_mac_nat(S_port_list, true);
		}
		(void)switch_port_list_verify_rt_table(S_port_list, true);
	}
	if (S_debug) {
		T_LOG("sleeping for 5 seconds\n");
		sleep(5);
	}
	bridge_cleanup(BRIDGE200, S_n_ports, false);
	return;
}

static void
cleanup(void)
{
	cleanup_common(true);
	return;
}

static void
sigint_handler(__unused int sig)
{
	cleanup_common(false);
	signal(SIGINT, SIG_DFL);
}

static switch_port_list_t
bridge_setup(char * bridge, u_int n_ports, u_int num_addrs, bool mac_nat)
{
	errno_t                 err;
	switch_port_list_t      list = NULL;
	int                     s;

	S_n_ports = n_ports;
	T_ATEND(cleanup);
	T_SETUPBEGIN;
	s = inet_dgram_socket();
	err = ifnet_create(s, bridge);
	if (err != 0) {
		goto done;
	}
	list = switch_port_list_alloc(n_ports, mac_nat);
	for (u_int i = 0; i < n_ports; i++) {
		bool    do_mac_nat;
		char    ifname[IFNAMSIZ];
		char    member_ifname[IFNAMSIZ];
		ether_addr_t member_mac;

		snprintf(ifname, sizeof(ifname), "%s%d",
		    FETH_NAME, i);
		snprintf(member_ifname, sizeof(member_ifname), "%s%d",
		    FETH_NAME, i + n_ports);
		err = ifnet_create(s, ifname);
		if (err != 0) {
			goto done;
		}
		ifnet_attach_ip(s, ifname);
		err = ifnet_create(s, member_ifname);
		if (err != 0) {
			goto done;
		}
		err = ifnet_get_lladdr(s, member_ifname, &member_mac);
		if (err != 0) {
			goto done;
		}
		err = fake_set_peer(s, ifname, member_ifname);
		if (err != 0) {
			goto done;
		}
		/* add the interface's peer to the bridge */
		err = bridge_add_member(s, bridge, member_ifname);
		if (err != 0) {
			goto done;
		}

		do_mac_nat = (i == 0 && mac_nat);
		if (do_mac_nat) {
			/* enable MAC NAT on unit 0 */
			err = bridge_set_mac_nat(s, bridge, member_ifname,
			    true);
			if (err != 0) {
				goto done;
			}
		}
		/* we'll send/receive on the interface */
		err = switch_port_list_add_port(list, i, ifname, member_ifname,
		    &member_mac, num_addrs,
		    do_mac_nat);
		if (err != 0) {
			goto done;
		}
	}
done:
	if (s >= 0) {
		close(s);
	}
	if (err != 0 && list != NULL) {
		switch_port_list_dealloc(list);
		list = NULL;
	}
	T_SETUPEND;
	return list;
}

static void
bridge_cleanup(const char * bridge, u_int n_ports, bool fail_on_error)
{
	int s;

	s = inet_dgram_socket();
	ifnet_destroy(s, bridge, fail_on_error);
	for (u_int i = 0; i < n_ports; i++) {
		char    ifname[IFNAMSIZ];
		char    member_ifname[IFNAMSIZ];

		snprintf(ifname, sizeof(ifname), "%s%d",
		    FETH_NAME, i);
		snprintf(member_ifname, sizeof(member_ifname), "%s%d",
		    FETH_NAME, i + n_ports);
		ifnet_destroy(s, ifname, fail_on_error);
		ifnet_destroy(s, member_ifname, fail_on_error);
	}
	if (s >= 0) {
		close(s);
	}
	S_n_ports = 0;
	return;
}

/*
 *  Basic Bridge Tests
 *
 *  Broadcast
 *  - two cases: actual broadcast, unknown ethernet
 *  - send broadcast packets
 *  - verify all received
 *  - check bridge rt list contains all expected MAC addresses
 *  - send unicast ARP packets
 *  - verify packets received only on expected port
 *
 *  MAC-NAT
 *  - verify ARP translation
 *  - verify IPv4 translation
 *  - verify DHCP broadcast bit conversion
 *  - verify IPv6 translation
 *  - verify ND6 translation (Neighbor, Router)
 *  - verify IPv4 subnet-local broadcast to MAC-NAT interface link-layer
 *    address arrives on all member links
 */

static void
bridge_test(packet_validator_t validator,
    void * context,
    const ether_addr_t * dst_eaddr,
    uint8_t af, u_int n_ports, u_int num_addrs)
{
#if TARGET_OS_BRIDGE
	T_SKIP("Test uses too much memory");
#else /* TARGET_OS_BRIDGE */
	switch_port_list_t port_list;

	signal(SIGINT, sigint_handler);
	port_list = bridge_setup(BRIDGE200, n_ports, num_addrs, false);
	if (port_list == NULL) {
		T_FAIL("bridge_setup");
		return;
	}
	S_port_list = port_list;
	bridge_learning_test(port_list, af, validator, context, dst_eaddr);

	//T_LOG("Sleeping for 5 seconds");
	//sleep(5);
	bridge_cleanup(BRIDGE200, n_ports, true);
	switch_port_list_dealloc(port_list);
	return;
#endif /* TARGET_OS_BRIDGE */
}

static void
bridge_test_mac_nat_ipv4(u_int n_ports, u_int num_addrs)
{
#if TARGET_OS_BRIDGE
	T_SKIP("Test uses too much memory");
#else /* TARGET_OS_BRIDGE */
	switch_port_list_t port_list;

	signal(SIGINT, sigint_handler);
	port_list = bridge_setup(BRIDGE200, n_ports, num_addrs, true);
	if (port_list == NULL) {
		T_FAIL("bridge_setup");
		return;
	}
	S_port_list = port_list;

	/* verify that IPv4 packets get translated when necessary */
	mac_nat_test_ip(port_list, AF_INET);

	/* verify the DHCP broadcast bit gets set appropriately */
	mac_nat_test_dhcp(port_list, false);

	/* verify that ARP packet gets translated when necessary */
	mac_nat_test_arp_out(port_list);
	mac_nat_test_arp_in(port_list);

	/* verify IP broadcast to MAC-NAT interface link layer address */
	mac_nat_test_dhcp(port_list, true);

	if (S_debug) {
		T_LOG("Sleeping for 5 seconds");
		sleep(5);
	}
	bridge_cleanup(BRIDGE200, n_ports, true);
	switch_port_list_dealloc(port_list);
	return;
#endif /* TARGET_OS_BRIDGE */
}

static void
bridge_test_mac_nat_ipv6(u_int n_ports, u_int num_addrs)
{
#if TARGET_OS_BRIDGE
	T_SKIP("Test uses too much memory");
#else /* TARGET_OS_BRIDGE */
	switch_port_list_t port_list;

	signal(SIGINT, sigint_handler);
	port_list = bridge_setup(BRIDGE200, n_ports, num_addrs, true);
	if (port_list == NULL) {
		T_FAIL("bridge_setup");
		return;
	}
	S_port_list = port_list;

	/* verify that IPv6 packets get translated when necessary */
	mac_nat_test_ip(port_list, AF_INET6);

	/* verify that ND6 packet gets translated when necessary */
	mac_nat_test_nd6_out(port_list);
	if (S_debug) {
		T_LOG("Sleeping for 5 seconds");
		sleep(5);
	}
	bridge_cleanup(BRIDGE200, n_ports, true);
	switch_port_list_dealloc(port_list);
	return;
#endif /* TARGET_OS_BRIDGE */
}

static void
system_cmd(const char *cmd, bool fail_on_error)
{
	pid_t pid = -1;
	int exit_status = 0;
	const char *argv[] = {
		"/usr/local/bin/bash",
		"-c",
		cmd,
		NULL
	};

	int rc = dt_launch_tool(&pid, (char **)(void *)argv, false, NULL, NULL);
	T_QUIET;
	T_ASSERT_EQ(rc, 0, "dt_launch_tool(%s) failed", cmd);

	if (dt_waitpid(pid, &exit_status, NULL, 30)) {
		T_QUIET;
		T_ASSERT_MACH_SUCCESS(exit_status, "command(%s)", cmd);
	} else {
		if (fail_on_error) {
			T_FAIL("dt_waitpid(%s) failed", cmd);
		}
	}
}

static void
cleanup_pf(void)
{
	struct ifbrparam param;
	int s = inet_dgram_socket();

	system_cmd("pfctl -d", false);
	system_cmd("pfctl -F all", false);

	param.ifbrp_filter = 0;
	siocdrvspec(s, BRIDGE200, BRDGSFILT,
	    &param, sizeof(param), true);
	return;
}

static void
block_all_traffic(bool input, const char* infname1, const char* infname2)
{
	int s = inet_dgram_socket();
	int ret;
	struct ifbrparam param;
	char command[512];
	char *dir = input ? "in" : "out";

	snprintf(command, sizeof(command), "echo \"block %s on %s all\nblock %s on %s all\n\" | pfctl -vvv -f -",
	    dir, infname1, dir, infname2);
	/* enable block all filter */
	param.ifbrp_filter = IFBF_FILT_MEMBER | IFBF_FILT_ONLYIP;
	ret = siocdrvspec(s, BRIDGE200, BRDGSFILT,
	    &param, sizeof(param), true);
	T_ASSERT_POSIX_SUCCESS(ret,
	    "SIOCDRVSPEC(BRDGSFILT %s, 0x%x)",
	    BRIDGE200, param.ifbrp_filter);
	// ignore errors such that not having pf.os doesn't raise any issues
	system_cmd(command, false);
	system_cmd("pfctl -e", true);
	system_cmd("pfctl -s all", true);
}

/*
 *  Basic bridge filter test
 *
 *  For both broadcast and unicast transfers ensure that data can
 *  be blocked using pf on the bridge
 */

static void
filter_test(uint8_t af)
{
#if TARGET_OS_BRIDGE
	T_SKIP("pfctl isn't valid on this platform");
#else /* TARGET_OS_BRIDGE */
	switch_port_list_t port_list;
	switch_port_t   port;
	const u_int n_ports = 2;
	u_int num_addrs = 1;
	u_int i;
	char ntoabuf[ETHER_NTOA_BUFSIZE];
	union ifbrip dst_ip;
	bool blocked = true;
	bool input = true;
	const char* ifnames[2];

	signal(SIGINT, sigint_handler);

	T_ATEND(cleanup);
	T_ATEND(cleanup_pf);

	port_list = bridge_setup(BRIDGE200, n_ports, num_addrs, false);
	if (port_list == NULL) {
		T_FAIL("bridge_setup");
		return;
	}

	ether_ntoa_buf(&ether_broadcast, ntoabuf, sizeof(ntoabuf));

	S_port_list = port_list;
	for (i = 0, port = port_list->list; i < port_list->count; i++, port++) {
		ifnames[i] = port->member_ifname;
	}

	get_broadcast_ip_address(af, &dst_ip);
	do {
		do {
			if (blocked) {
				block_all_traffic(input, ifnames[0], ifnames[1]);
			}
			for (i = 0, port = port_list->list; i < port_list->count; i++, port++) {
				if (S_debug) {
					T_LOG("Sending on %s", port->ifname);
				}
				for (u_int j = 0; j < port->num_addrs; j++) {
					uint32_t        generation;

					generation = next_generation();
					send_generation(port,
					    af,
					    j,
					    &ether_broadcast,
					    &dst_ip,
					    generation);

					/* receive across all ports */
					check_receive_generation(port_list,
					    af,
					    generation,
					    validate_broadcast_dhost,
					    NULL);

					/* ensure that every port saw the right amount of packets*/
					if (blocked) {
						check_received_count(port_list, port, 0);
					} else {
						check_received_count(port_list, port, 1);
					}
				}
			}
			T_PASS("%s broadcast %s %s", __func__, blocked ? "blocked" : "not blocked", input ? "input" : "output");
			input = !input;
			cleanup_pf();
		} while (input == false && blocked);
		blocked = !blocked;
	} while (blocked == false);

	do {
		do {
			if (blocked) {
				block_all_traffic(input, ifnames[0], ifnames[1]);
			}
			for (i = 0, port = port_list->list; i < port_list->count; i++, port++) {
				/* send unicast packets to every other port's MAC addresses */
				unicast_send_all(port_list, af, port);

				/* receive all of that generated traffic */
				switch_port_list_check_receive(port_list, af, NULL, 0,
				    validate_port_dhost, NULL);

				/* ensure that every port saw the right amount of packets*/
				if (blocked) {
					check_received_count(port_list, port, 0);
				} else {
					check_received_count(port_list, port, 1);
				}
			}
			T_PASS("%s unicast %s %s", __func__, blocked ? "blocked" : "not blocked", input ? "input" : "output");
			input = !input;
			cleanup_pf();
		} while (input == false && blocked);
		blocked = !blocked;
	} while (blocked == false);

	bridge_cleanup(BRIDGE200, n_ports, true);
	switch_port_list_dealloc(port_list);
	return;
#endif /* TARGET_OS_BRIDGE */
}

T_DECL(if_bridge_bcast,
    "bridge broadcast IPv4",
    T_META_ASROOT(true))
{
	bridge_test(validate_broadcast_dhost, NULL, &ether_broadcast,
	    AF_INET, 5, 1);
}

T_DECL(if_bridge_bcast_many,
    "bridge broadcast many IPv4",
    T_META_ASROOT(true))
{
	bridge_test(validate_broadcast_dhost, NULL, &ether_broadcast,
	    AF_INET, 5, 20);
}

T_DECL(if_bridge_unknown,
    "bridge unknown host IPv4",
    T_META_ASROOT(true))
{
	bridge_test(validate_not_present_dhost, NULL, &ether_external,
	    AF_INET, 5, 1);
}

T_DECL(if_bridge_bcast_v6,
    "bridge broadcast IPv6",
    T_META_ASROOT(true))
{
	bridge_test(validate_broadcast_dhost, NULL, &ether_broadcast,
	    AF_INET6, 5, 1);
}

T_DECL(if_bridge_bcast_many_v6,
    "bridge broadcast many IPv6",
    T_META_ASROOT(true))
{
	bridge_test(validate_broadcast_dhost, NULL, &ether_broadcast,
	    AF_INET6, 5, 20);
}

T_DECL(if_bridge_unknown_v6,
    "bridge unknown host IPv6",
    T_META_ASROOT(true))
{
	bridge_test(validate_not_present_dhost, NULL, &ether_external,
	    AF_INET6, 5, 1);
}

T_DECL(if_bridge_mac_nat_ipv4,
    "bridge mac nat ipv4",
    T_META_ASROOT(true))
{
	bridge_test_mac_nat_ipv4(5, 10);
}

T_DECL(if_bridge_mac_nat_ipv6,
    "bridge mac nat ipv6",
    T_META_ASROOT(true))
{
	bridge_test_mac_nat_ipv6(5, 10);
}

T_DECL(if_bridge_filter_ipv4,
    "bridge filter ipv4",
    T_META_ASROOT(true))
{
	filter_test(AF_INET);
}

T_DECL(if_bridge_filter_ipv6,
    "bridge filter ipv6",
    T_META_ASROOT(true))
{
	filter_test(AF_INET6);
}
