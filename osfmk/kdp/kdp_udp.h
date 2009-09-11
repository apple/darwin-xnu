/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1982, 1986, 1993
 *      The Regents of the University of California.  All rights reserved.
 */

#include <libsa/types.h>
#include <libkern/OSByteOrder.h>   /* OSSwap functions */
#include <stdint.h>

#define     ETHERMTU        1500
#define     ETHERHDRSIZE    14
#define     ETHERCRC        4
#define     KDP_MAXPACKET   (ETHERHDRSIZE + ETHERMTU + ETHERCRC)

struct in_addr {
        uint32_t s_addr;
};

struct ether_addr {
        u_char ether_addr_octet[6];
};

typedef struct ether_addr enet_addr_t;

extern struct ether_addr kdp_get_mac_addr(void);
unsigned int  kdp_get_ip_address(void);

struct ipovly {
        uint32_t ih_next, ih_prev;       /* for protocol sequence q's */
        u_char  ih_x1;                  /* (unused) */
        u_char  ih_pr;                  /* protocol */
        short   ih_len;                 /* protocol length */
        struct  in_addr ih_src;         /* source internet address */
        struct  in_addr ih_dst;         /* destination internet address */
};

struct udphdr {
        u_short uh_sport;               /* source port */
        u_short uh_dport;               /* destination port */
        short   uh_ulen;                /* udp length */
        u_short uh_sum;                 /* udp checksum */
};

struct  udpiphdr {
        struct  ipovly ui_i;            /* overlaid ip structure */
        struct  udphdr ui_u;            /* udp header */
};
#define ui_next         ui_i.ih_next
#define ui_prev         ui_i.ih_prev
#define ui_x1           ui_i.ih_x1
#define ui_pr           ui_i.ih_pr
#define ui_len          ui_i.ih_len
#define ui_src          ui_i.ih_src
#define ui_dst          ui_i.ih_dst
#define ui_sport        ui_u.uh_sport
#define ui_dport        ui_u.uh_dport
#define ui_ulen         ui_u.uh_ulen
#define ui_sum          ui_u.uh_sum

struct ip { 
	union {
		uint32_t ip_w;
		struct {
			unsigned int
#ifdef __LITTLE_ENDIAN__
        		ip_xhl:4,	/* header length */   
                	ip_xv:4,		/* version */
        		ip_xtos:8,	/* type of service */
        		ip_xlen:16;	/* total length */
#endif
#ifdef __BIG_ENDIAN__
        		ip_xv:4,                 /* version */
                	ip_xhl:4,                /* header length */
        		ip_xtos:8,               /* type of service */
        		ip_xlen:16;               /* total length */
#endif
		} ip_x;
	} ip_vhltl;
        u_short ip_id;                  /* identification */
        short   ip_off;                 /* fragment offset field */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define ip_v   ip_vhltl.ip_x.ip_xv
#define ip_hl  ip_vhltl.ip_x.ip_xhl
#define ip_tos ip_vhltl.ip_x.ip_xtos
#define ip_len ip_vhltl.ip_x.ip_xlen

#define    IPPROTO_UDP     17
#define    IPVERSION       4

struct  ether_header {
        u_char  ether_dhost[6];
        u_char  ether_shost[6];
        u_short ether_type;
};

typedef struct ether_header ether_header_t;

#define ETHERTYPE_IP       0x0800  /* IP protocol */

#define ntohs(x)           OSSwapBigToHostInt16(x)
#define ntohl(x)           OSSwapBigToHostInt32(x)
#define htons(x)           OSSwapHostToBigInt16(x)
#define htonl(x)           OSSwapHostToBigInt32(x)
/*
 * Ethernet Address Resolution Protocol.
 *
 * See RFC 826 for protocol description.  Structure below is adapted
 * to resolving internet addresses.  Field names used correspond to
 * RFC 826.
 */

#define ETHERTYPE_ARP          0x0806  /* Addr. resolution protocol */

struct  arphdr {
  u_short ar_hrd;         /* format of hardware address */
#define ARPHRD_ETHER    1       /* ethernet hardware format */
#define ARPHRD_FRELAY   15      /* frame relay hardware format */
  u_short ar_pro;         /* format of protocol address */
  u_char  ar_hln;         /* length of hardware address */
  u_char  ar_pln;         /* length of protocol address */
  u_short ar_op;          /* one of: */
#define ARPOP_REQUEST   1       /* request to resolve address */
#define ARPOP_REPLY     2       /* response to previous request */
#define ARPOP_REVREQUEST 3      /* request protocol address given hardware */
#define ARPOP_REVREPLY  4       /* response giving protocol address */
#define ARPOP_INVREQUEST 8      /* request to identify peer */
#define ARPOP_INVREPLY  9       /* response identifying peer */
};

#define ETHER_ADDR_LEN 6

struct  ether_arp {
  struct  arphdr ea_hdr;  /* fixed-size header */
  u_char  arp_sha[ETHER_ADDR_LEN];        /* sender hardware address */
  u_char  arp_spa[4];     /* sender protocol address */
  u_char  arp_tha[ETHER_ADDR_LEN];        /* target hardware address */
  u_char  arp_tpa[4];     /* target protocol address */
};
#define arp_hrd ea_hdr.ar_hrd
#define arp_pro ea_hdr.ar_pro
#define arp_hln ea_hdr.ar_hln
#define arp_pln ea_hdr.ar_pln
#define arp_op  ea_hdr.ar_op
