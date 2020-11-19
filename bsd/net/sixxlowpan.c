/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
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
 * Copyright (c) 2008, Swedish Institute of Computer Science.
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
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *         Header file for the 6lowpan implementation
 *         (RFC4944 and draft-hui-6lowpan-hc-01)
 * \author Adam Dunkels <adam@sics.se>
 * \author Nicolas Tsiftes <nvt@sics.se>
 * \author Niclas Finne <nfi@sics.se>
 * \author Mathilde Durvy <mdurvy@cisco.com>
 * \author Julien Abeille <jabeille@cisco.com>
 */


#include <sys/types.h>
#include <sys/queue.h>
#include <sys/domain.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <sys/errno.h>
#include <libkern/libkern.h>


#include <net/sixxlowpan.h>
#include <net/frame802154.h>

errno_t
compress_hdr_hc1(struct frame802154 *, u_int8_t *,
    long *, size_t *, u_int8_t *);
errno_t
uncompress_hdr_hc1(struct frame802154 *, u_int8_t *,
    uint16_t, long *, size_t *, u_int8_t *);



/**
 * \addtogroup sicslowpan
 * @{
 */

/**
 * \name General sicslowpan defines
 * @{
 */
/* Min and Max compressible UDP ports - HC06 */
#define SICSLOWPAN_UDP_PORT_MIN                     0xF0B0
#define SICSLOWPAN_UDP_PORT_MAX                     0xF0BF   /* F0B0 + 15 */

/** @} */

/**
 * \name 6lowpan compressions
 * @{
 */
#define SICSLOWPAN_COMPRESSION_IPV6        0
#define SICSLOWPAN_COMPRESSION_HC1         1
#define SICSLOWPAN_COMPRESSION_HC06        2
/** @} */

/**
 * \name 6lowpan dispatches
 * @{
 */
#define SICSLOWPAN_DISPATCH_IPV6                    0x41 /* 01000001 = 65 */
#define SICSLOWPAN_DISPATCH_HC1                     0x42 /* 01000010 = 66 */
#define SICSLOWPAN_DISPATCH_IPHC                    0x60 /* 011xxxxx = ... */
#define SICSLOWPAN_DISPATCH_FRAG1                   0xc0 /* 11000xxx */
#define SICSLOWPAN_DISPATCH_FRAGN                   0xe0 /* 11100xxx */
/** @} */

/** \name HC1 encoding
 * @{
 */
#define SICSLOWPAN_HC1_NH_UDP                       0x02
#define SICSLOWPAN_HC1_NH_TCP                       0x06
#define SICSLOWPAN_HC1_NH_ICMP6                     0x04
/** @} */

/** \name HC_UDP encoding (works together with HC1)
 * @{
 */
#define SICSLOWPAN_HC_UDP_ALL_C                     0xE0
/** @} */

/**
 * \name IPHC encoding
 * @{
 */
/*
 * Values of fields within the IPHC encoding first byte
 * (C stands for compressed and I for inline)
 */
#define SICSLOWPAN_IPHC_FL_C                        0x10
#define SICSLOWPAN_IPHC_TC_C                        0x08
#define SICSLOWPAN_IPHC_NH_C                        0x04
#define SICSLOWPAN_IPHC_TTL_1                       0x01
#define SICSLOWPAN_IPHC_TTL_64                      0x02
#define SICSLOWPAN_IPHC_TTL_255                     0x03
#define SICSLOWPAN_IPHC_TTL_I                       0x00


/* Values of fields within the IPHC encoding second byte */
#define SICSLOWPAN_IPHC_CID                         0x80

#define SICSLOWPAN_IPHC_SAC                         0x40
#define SICSLOWPAN_IPHC_SAM_00                      0x00
#define SICSLOWPAN_IPHC_SAM_01                      0x10
#define SICSLOWPAN_IPHC_SAM_10                      0x20
#define SICSLOWPAN_IPHC_SAM_11                      0x30

#define SICSLOWPAN_IPHC_SAM_BIT                     4

#define SICSLOWPAN_IPHC_M                           0x08
#define SICSLOWPAN_IPHC_DAC                         0x04
#define SICSLOWPAN_IPHC_DAM_00                      0x00
#define SICSLOWPAN_IPHC_DAM_01                      0x01
#define SICSLOWPAN_IPHC_DAM_10                      0x02
#define SICSLOWPAN_IPHC_DAM_11                      0x03

#define SICSLOWPAN_IPHC_DAM_BIT                     0

/* Link local context number */
#define SICSLOWPAN_IPHC_ADDR_CONTEXT_LL             0
/* 16-bit multicast addresses compression */
#define SICSLOWPAN_IPHC_MCAST_RANGE                 0xA0
/** @} */

/* NHC_EXT_HDR */
#define SICSLOWPAN_NHC_MASK                         0xF0
#define SICSLOWPAN_NHC_EXT_HDR                      0xE0

/**
 * \name LOWPAN_UDP encoding (works together with IPHC)
 * @{
 */
/**
 * \name LOWPAN_UDP encoding (works together with IPHC)
 * @{
 */
#define SICSLOWPAN_NHC_UDP_MASK                     0xF8
#define SICSLOWPAN_NHC_UDP_ID                       0xF0
#define SICSLOWPAN_NHC_UDP_CHECKSUMC                0x04
#define SICSLOWPAN_NHC_UDP_CHECKSUMI                0x00
/* values for port compression, _with checksum_ ie bit 5 set to 0 */
#define SICSLOWPAN_NHC_UDP_CS_P_00  0xF0 /* all inline */
#define SICSLOWPAN_NHC_UDP_CS_P_01  0xF1 /* source 16bit inline, dest = 0xF0 + 8 bit inline */
#define SICSLOWPAN_NHC_UDP_CS_P_10  0xF2 /* source = 0xF0 + 8bit inline, dest = 16 bit inline */
#define SICSLOWPAN_NHC_UDP_CS_P_11  0xF3 /* source & dest = 0xF0B + 4bit inline */
/** @} */


/**
 * \name The 6lowpan "headers" length
 * @{
 */

#define SICSLOWPAN_IPV6_HDR_LEN                     1    /*one byte*/
#define SICSLOWPAN_HC1_HDR_LEN                      3
#define SICSLOWPAN_HC1_HC_UDP_HDR_LEN               7
#define SICSLOWPAN_FRAG1_HDR_LEN                    4
#define SICSLOWPAN_FRAGN_HDR_LEN                    5

// Minimum size of the compressed 6LoWPAN header length
#define SICSLOWPAN_MIN_COMP_HDR_LEN                 7

// Minimum size of the uncompressed IPv6 header length
#define SICSLOWPAN_MIN_UNCOMP_HDR_LEN               40


#define UIP_IPH_LEN    40
#define UIP_UDPH_LEN    8    /* Size of UDP header */
#define UIP_TCPH_LEN   20    /* Size of TCP header */
#define UIP_ICMPH_LEN   4    /* Size of ICMP header */

/** @} */

/**
 * \brief The header for fragments
 * \note We do not define different structures for FRAG1
 * and FRAGN headers, which are different. For FRAG1, the
 * offset field is just not used
 */
/* struct sicslowpan_frag_hdr { */
/*   uint16_t dispatch_size; */
/*   uint16_t tag; */
/*   uint8_t offset; */
/* }; */

/**
 * \brief The HC1 header when HC_UDP is not used
 *
 * When all fields are compressed and HC_UDP is not used,
 * we use this structure. If HC_UDP is used, the ttl is
 * in another spot, and we use the sicslowpan_hc1_hc_udp
 * structure
 */
/* struct sicslowpan_hc1_hdr { */
/*   uint8_t dispatch; */
/*   uint8_t encoding; */
/*   uint8_t ttl; */
/* }; */

/**
 * \brief HC1 followed by HC_UDP
 */
/* struct sicslowpan_hc1_hc_udp_hdr { */
/*   uint8_t dispatch; */
/*   uint8_t hc1_encoding; */
/*   uint8_t hc_udp_encoding; */
/*   uint8_t ttl; */
/*   uint8_t ports; */
/*   uint16_t udpchksum; */
/* }; */

/**
 * \brief An address context for IPHC address compression
 * each context can have upto 8 bytes
 */
struct sicslowpan_addr_context {
	uint8_t used; /* possibly use as prefix-length */
	uint8_t number;
	uint8_t prefix[8];
};

/**
 * \name Address compressibility test functions
 * @{
 */

/**
 * \brief check whether we can compress the IID in
 * address 'a' to 16 bits.
 * This is used for unicast addresses only, and is true
 * if the address is on the format \<PREFIX\>::0000:00ff:fe00:XXXX
 * NOTE: we currently assume 64-bits prefixes
 */
#define sicslowpan_is_iid_16_bit_compressable(a) \
((((a)->u16[4]) == 0) &&                       \
(((a)->u8[10]) == 0)&&                      \
(((a)->u8[11]) == 0xff)&&                           \
(((a)->u8[12]) == 0xfe)&&                           \
(((a)->u8[13]) == 0))

/**
 * \brief check whether the 9-bit group-id of the
 * compressed multicast address is known. It is true
 * if the 9-bit group is the all nodes or all routers
 * group.
 * \param a is typed uint8_t *
 */
#define sicslowpan_is_mcast_addr_decompressable(a) \
(((*a & 0x01) == 0) &&                           \
((*(a + 1) == 0x01) || (*(a + 1) == 0x02)))

/**
 * \brief check whether the 112-bit group-id of the
 * multicast address is mappable to a 9-bit group-id
 * It is true if the group is the all nodes or all
 * routers group.
 */
#define sicslowpan_is_mcast_addr_compressable(a) \
((((a)->u16[1]) == 0) &&                       \
(((a)->u16[2]) == 0) &&                       \
(((a)->u16[3]) == 0) &&                       \
(((a)->u16[4]) == 0) &&                       \
(((a)->u16[5]) == 0) &&                       \
(((a)->u16[6]) == 0) &&                       \
(((a)->u8[14]) == 0) &&                       \
((((a)->u8[15]) == 1) || (((a)->u8[15]) == 2)))

/* FFXX::00XX:XXXX:XXXX */
#define sicslowpan_is_mcast_addr_compressable48(a) \
((((a)->u16[1]) == 0) &&                       \
(((a)->u16[2]) == 0) &&                       \
(((a)->u16[3]) == 0) &&                       \
(((a)->u16[4]) == 0) &&                       \
(((a)->u8[10]) == 0))

/* FFXX::00XX:XXXX */
#define sicslowpan_is_mcast_addr_compressable32(a) \
((((a)->u16[1]) == 0) &&                       \
(((a)->u16[2]) == 0) &&                       \
(((a)->u16[3]) == 0) &&                       \
(((a)->u16[4]) == 0) &&                       \
(((a)->u16[5]) == 0) &&                       \
(((a)->u8[12]) == 0))

/* FF02::00XX */
#define sicslowpan_is_mcast_addr_compressable8(a) \
((((a)->u8[1]) == 2) &&                        \
(((a)->u16[1]) == 0) &&                       \
(((a)->u16[2]) == 0) &&                       \
(((a)->u16[3]) == 0) &&                       \
(((a)->u16[4]) == 0) &&                       \
(((a)->u16[5]) == 0) &&                       \
(((a)->u16[6]) == 0) &&                       \
(((a)->u8[14]) == 0))

#define uip_is_addr_mac_addr_based(a, m) \
((((a)->s6_addr[8])  == (((m)[0]) ^ 0x02)) &&        \
(((a)->s6_addr[9])  == (m)[1]) &&            \
(((a)->s6_addr[10]) == (m)[2]) &&            \
(((a)->s6_addr[11]) == (m)[3]) &&            \
(((a)->s6_addr[12]) == (m)[4]) &&            \
(((a)->s6_addr[13]) == (m)[5]) &&            \
(((a)->s6_addr[14]) == (m)[6]) &&            \
(((a)->s6_addr[15]) == (m)[7]))

/**
 * Construct an IPv6 address from eight 16-bit words.
 *
 * This function constructs an IPv6 address.
 *
 * \hideinitializer
 */
#define uip_ip6addr(addr, addr0, addr1, addr2, addr3, addr4, addr5, addr6, addr7) do {\
(addr)->s6_addr[0] = htons(addr0);                                      \
(addr)->s6_addr[1] = htons(addr1);                                      \
(addr)->s6_addr[2] = htons(addr2);                                      \
(addr)->s6_addr[3] = htons(addr3);                                      \
(addr)->s6_addr[4] = htons(addr4);                                      \
(addr)->s6_addr[5] = htons(addr5);                                      \
(addr)->s6_addr[6] = htons(addr6);                                      \
(addr)->s6_addr[7] = htons(addr7);                                      \
} while(0)

/**
 * Construct an IPv6 address from sixteen 8-bit words.
 *
 * This function constructs an IPv6 address.
 *
 * \hideinitializer
 */
#define uip_ip6addr_u8(addr, addr0, addr1, addr2, addr3, addr4, addr5, addr6, addr7, addr8, addr9, addr10, addr11, addr12, addr13, addr14, addr15) do {\
(addr)->s6_addr[0] = addr0;                                       \
(addr)->s6_addr[1] = addr1;                                       \
(addr)->s6_addr[2] = addr2;                                       \
(addr)->s6_addr[3] = addr3;                                       \
(addr)->s6_addr[4] = addr4;                                       \
(addr)->s6_addr[5] = addr5;                                       \
(addr)->s6_addr[6] = addr6;                                       \
(addr)->s6_addr[7] = addr7;                                       \
(addr)->s6_addr[8] = addr8;                                       \
(addr)->s6_addr[9] = addr9;                                       \
(addr)->s6_addr[10] = addr10;                                     \
(addr)->s6_addr[11] = addr11;                                     \
(addr)->s6_addr[12] = addr12;                                     \
(addr)->s6_addr[13] = addr13;                                     \
(addr)->s6_addr[14] = addr14;                                     \
(addr)->s6_addr[15] = addr15;                                     \
} while(0)



/** \brief 16 bit 802.15.4 address */
typedef struct uip_802154_shortaddr {
	uint8_t addr[2];
} uip_802154_shortaddr;
/** \brief 64 bit 802.15.4 address */
typedef struct uip_802154_longaddr {
	uint8_t addr[8];
} uip_802154_longaddr;

/** \brief 802.11 address */
typedef struct uip_80211_addr {
	uint8_t addr[6];
} uip_80211_addr;

/** \brief 802.3 address */
typedef struct uip_eth_addr {
	uint8_t addr[6];
} uip_eth_addr;
typedef uip_802154_longaddr uip_lladdr_t;

#define UIP_802154_SHORTADDR_LEN 2
#define UIP_802154_LONGADDR_LEN  8
#define UIP_LLADDR_LEN UIP_802154_LONGADDR_LEN


#define GET16(ptr) (((uint16_t)(((u_int8_t *)ptr)[0] << 8)) | (((u_int8_t *)ptr)[1]))
#define SET16(ptr, value) do {     \
((u_int8_t *)ptr)[0] = ((value) >> 8) & 0xff; \
((u_int8_t *)ptr)[1] = (value) & 0xff;    \
} while(0)

/** \name Pointers in the packetbuf buffer
 *  @{
 */
#define PACKETBUF_FRAG_DISPATCH_SIZE 0   /* 16 bit */
#define PACKETBUF_FRAG_TAG           2   /* 16 bit */
#define PACKETBUF_FRAG_OFFSET        4   /* 8 bit */

#define PACKETBUF_HC1_DISPATCH       0 /* 8 bit */
#define PACKETBUF_HC1_ENCODING       1 /* 8 bit */
#define PACKETBUF_HC1_TTL            2 /* 8 bit */

#define PACKETBUF_HC1_HC_UDP_DISPATCH      0 /* 8 bit */
#define PACKETBUF_HC1_HC_UDP_HC1_ENCODING  1 /* 8 bit */
#define PACKETBUF_HC1_HC_UDP_UDP_ENCODING  2 /* 8 bit */
#define PACKETBUF_HC1_HC_UDP_TTL           3 /* 8 bit */
#define PACKETBUF_HC1_HC_UDP_PORTS         4 /* 8 bit */
#define PACKETBUF_HC1_HC_UDP_CHKSUM        5 /* 16 bit */


#define LINKADDR_SIZE 8
typedef union {
	unsigned char u8[LINKADDR_SIZE];
	uint16_t u16;
} linkaddr_t;

static void
uip_ds6_set_addr_iid(struct in6_addr *ipaddr, uip_lladdr_t *lladdr)
{
	/* We consider only links with IEEE EUI-64 identifier or
	 * IEEE 48-bit MAC addresses */
#if (UIP_LLADDR_LEN == 8)
	memcpy(ipaddr->s6_addr + 8, lladdr, UIP_LLADDR_LEN);
	ipaddr->s6_addr[8] ^= 0x02;
#elif (UIP_LLADDR_LEN == 6)
	memcpy(ipaddr->s6_addr + 8, lladdr, 3);
	ipaddr->s6_addr[11] = 0xff;
	ipaddr->s6_addr[12] = 0xfe;
	memcpy(ipaddr->s6_addr + 13, (uint8_t *)lladdr + 3, 3);
	ipaddr->s6_addr[8] ^= 0x02;
#else
#error uip-ds6.c cannot build interface address when UIP_LLADDR_LEN is not 6 or 8
#endif
}

static errno_t
compress_hdr_ipv6(__unused struct frame802154 *ieee02154hdr,
    __unused u_int8_t *payload,
    long *hdroffset, size_t *hdrlen, u_int8_t *hdrbuf)
{
	/*
	 * Negative offset: 6LoWPAN header needs to ve prepended to the data
	 */
	*hdroffset = -SICSLOWPAN_IPV6_HDR_LEN;
	*hdrlen = SICSLOWPAN_IPV6_HDR_LEN;
	hdrbuf[0] = SICSLOWPAN_DISPATCH_IPV6;

	return 0;
}


#if 0
/*--------------------------------------------------------------------*/
/** \name HC1 compression and uncompression functions
 *  @{                                                                */
/*--------------------------------------------------------------------*/
/**
 * \brief Compress IP/UDP header using HC1 and HC_UDP
 *
 * This function is called by the 6lowpan code to create a compressed
 * 6lowpan packet in the packetbuf buffer from a full IPv6 packet in the
 * uip_buf buffer.
 *
 *
 * If we can compress everything, we use HC1 dispatch, if not we use
 * IPv6 dispatch.\n
 * We can compress everything if:
 *   - IP version is
 *   - Flow label and traffic class are 0
 *   - Both src and dest ip addresses are link local
 *   - Both src and dest interface ID are recoverable from lower layer
 *     header
 *   - Next header is either ICMP, UDP or TCP
 * Moreover, if next header is UDP, we try to compress it using HC_UDP.
 * This is feasible is both ports are between F0B0 and F0B0 + 15\n\n
 *
 * Resulting header structure:
 * - For ICMP, TCP, non compressed UDP\n
 *   HC1 encoding = 11111010 (UDP) 11111110 (TCP) 11111100 (ICMP)\n
 * \verbatim
 *                      1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | LoWPAN HC1 Dsp | HC1 encoding  | IPv6 Hop limit| L4 hdr + data|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * \endverbatim
 *
 * - For compressed UDP
 *   HC1 encoding = 11111011, HC_UDP encoding = 11100000\n
 * \verbatim
 *                      1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | LoWPAN HC1 Dsp| HC1 encoding  |  HC_UDP encod.| IPv6 Hop limit|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | src p.| dst p.| UDP checksum                  | L4 data...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * \endverbatim
 *
 * \param link_destaddr L2 destination address, needed to compress the
 * IP destination field
 */
#endif
errno_t
compress_hdr_hc1(struct frame802154 *ieee02154hdr, u_int8_t *payload,
    long *hdroffset, size_t *hdrlen, u_int8_t *hdrbuf)
{
	struct ip6_hdr *ip6 = (struct ip6_hdr *)(payload);

	if (*hdrlen < SICSLOWPAN_MIN_COMP_HDR_LEN) {
		return EINVAL;
	}

	*hdroffset = 0;

	/*
	 * Check if all the assumptions for full compression
	 * are valid :
	 */
	if ((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION ||
	    !IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_src) ||
	    !uip_is_addr_mac_addr_based(&ip6->ip6_src, ieee02154hdr->src_addr) ||
	    !IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_dst) ||
	    !uip_is_addr_mac_addr_based(&ip6->ip6_dst,
	    ieee02154hdr->dest_addr) ||
	    (ip6->ip6_nxt != IPPROTO_ICMPV6 &&
	    ip6->ip6_nxt != IPPROTO_UDP &&
	    ip6->ip6_nxt != IPPROTO_TCP)) {
		/*
		 * IPV6 DISPATCH
		 * Something cannot be compressed, use IPV6 DISPATCH,
		 * compress nothing, copy IPv6 header in packetbuf buffer
		 */
		return compress_hdr_ipv6(ieee02154hdr, payload, hdroffset, hdrlen, hdrbuf);
	} else {
		/*
		 * HC1 DISPATCH
		 * maximum compresssion:
		 * All fields in the IP header but Hop Limit are elided
		 * If next header is UDP, we compress UDP header using HC2
		 */
		hdrbuf[PACKETBUF_HC1_DISPATCH] = SICSLOWPAN_DISPATCH_HC1;

		switch (ip6->ip6_nxt) {
		case IPPROTO_ICMPV6:
			/* HC1 encoding and ttl */
			hdrbuf[PACKETBUF_HC1_ENCODING] = 0xFC;
			hdrbuf[PACKETBUF_HC1_TTL] = ip6->ip6_hlim;
			*hdrlen = SICSLOWPAN_HC1_HDR_LEN;
			*hdroffset = sizeof(struct ip6_hdr);
			break;

		case IPPROTO_TCP:
			/* HC1 encoding and ttl */
			hdrbuf[PACKETBUF_HC1_ENCODING] = 0xFE;
			hdrbuf[PACKETBUF_HC1_TTL] = ip6->ip6_hlim;
			*hdrlen = SICSLOWPAN_HC1_HDR_LEN;
			*hdroffset = sizeof(struct ip6_hdr);
			break;

		case IPPROTO_UDP: {
			struct udphdr *udp = (struct udphdr *)(uintptr_t)(ip6 + 1);

			/*
			 * try to compress UDP header (we do only full compression).
			 * This is feasible if both src and dest ports are between
			 * SICSLOWPAN_UDP_PORT_MIN and SICSLOWPAN_UDP_PORT_MIN + 15
			 */
			printf("source/remote ports %u/%u\n", ntohs(udp->uh_sport), ntohs(udp->uh_dport));
			if (ntohs(udp->uh_sport) >= SICSLOWPAN_UDP_PORT_MIN &&
			    ntohs(udp->uh_sport) < SICSLOWPAN_UDP_PORT_MAX &&
			    ntohs(udp->uh_dport) >= SICSLOWPAN_UDP_PORT_MIN &&
			    ntohs(udp->uh_dport) < SICSLOWPAN_UDP_PORT_MAX) {
				/* HC1 encoding */
				hdrbuf[PACKETBUF_HC1_HC_UDP_HC1_ENCODING] = 0xFB;

				/* HC_UDP encoding, ttl, src and dest ports, checksum */
				hdrbuf[PACKETBUF_HC1_HC_UDP_UDP_ENCODING] = 0xE0;
				hdrbuf[PACKETBUF_HC1_HC_UDP_TTL] = ip6->ip6_hlim;

				hdrbuf[PACKETBUF_HC1_HC_UDP_PORTS] =
				    (uint8_t)((ntohs(udp->uh_sport) - SICSLOWPAN_UDP_PORT_MIN) << 4) +
				    (uint8_t)((ntohs(udp->uh_dport) - SICSLOWPAN_UDP_PORT_MIN));

				memcpy(&hdrbuf[PACKETBUF_HC1_HC_UDP_CHKSUM], &udp->uh_sum, 2);
				*hdrlen = SICSLOWPAN_HC1_HC_UDP_HDR_LEN;
				*hdroffset = sizeof(struct ip6_hdr) + sizeof(struct udphdr);
			} else {
				/* HC1 encoding and ttl */
				hdrbuf[PACKETBUF_HC1_ENCODING] = 0xFA;
				hdrbuf[PACKETBUF_HC1_TTL] = ip6->ip6_hlim;
				*hdrlen = SICSLOWPAN_HC1_HDR_LEN;
				*hdroffset = sizeof(struct ip6_hdr);
			}
			break;
		}
		}
	}
	return 0;
}


/*--------------------------------------------------------------------*/
/**
 * \brief Uncompress HC1 (and HC_UDP) headers and put them in
 * sicslowpan_buf
 *
 * This function is called by the input function when the dispatch is
 * HC1.
 * We %process the packet in the packetbuf buffer, uncompress the header
 * fields, and copy the result in the sicslowpan buffer.
 * At the end of the decompression, packetbuf_hdr_len and uncompressed_hdr_len
 * are set to the appropriate values
 *
 * \param ip_len Equal to 0 if the packet is not a fragment (IP length
 * is then inferred from the L2 length), non 0 if the packet is a 1st
 * fragment.
 */
errno_t
uncompress_hdr_hc1(struct frame802154 *frame, u_int8_t *payload,
    uint16_t ip_len, long *hdroffset, size_t *hdrlen, u_int8_t *hdrbuf)
{
	struct ip6_hdr *ip6 = (struct ip6_hdr *)hdrbuf;

	if (payload[PACKETBUF_HC1_DISPATCH] == SICSLOWPAN_DISPATCH_IPV6) {
		*hdroffset = -SICSLOWPAN_IPV6_HDR_LEN;
		*hdrlen = SICSLOWPAN_IPV6_HDR_LEN;
		return 0;
	}

	*hdroffset = 0;

	/* version, traffic class, flow label */
	ip6->ip6_flow = 0;
	ip6->ip6_vfc = IPV6_VERSION;

	/* src and dest ip addresses */
	uip_ip6addr_u8(&ip6->ip6_src, 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	uip_ds6_set_addr_iid(&ip6->ip6_src,
	    (uip_lladdr_t *)frame->src_addr);

	uip_ip6addr_u8(&ip6->ip6_dst, 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	uip_ds6_set_addr_iid(&ip6->ip6_dst,
	    (uip_lladdr_t *)frame->dest_addr);

	*hdrlen = UIP_IPH_LEN;

	/* Next header field */
	switch (payload[PACKETBUF_HC1_ENCODING] & 0x06) {
	case SICSLOWPAN_HC1_NH_ICMP6:
		ip6->ip6_nxt = IPPROTO_ICMPV6;
		ip6->ip6_hlim = payload[PACKETBUF_HC1_TTL];
		*hdroffset = SICSLOWPAN_HC1_HDR_LEN;
		break;

	case SICSLOWPAN_HC1_NH_TCP:
		ip6->ip6_nxt = IPPROTO_TCP;
		ip6->ip6_hlim = payload[PACKETBUF_HC1_TTL];
		*hdroffset = SICSLOWPAN_HC1_HDR_LEN;
		break;

	case SICSLOWPAN_HC1_NH_UDP:
		ip6->ip6_nxt = IPPROTO_UDP;
		if (payload[PACKETBUF_HC1_HC_UDP_HC1_ENCODING] & 0x01) {
			struct udphdr *udp = (struct udphdr *)(uintptr_t)ip6;

			/* UDP header is compressed with HC_UDP */
			if (payload[PACKETBUF_HC1_HC_UDP_UDP_ENCODING] !=
			    SICSLOWPAN_HC_UDP_ALL_C) {
				printf("sicslowpan (uncompress_hdr), packet not supported");
				return EINVAL;
			}
			/* IP TTL */

			ip6->ip6_hlim = payload[PACKETBUF_HC1_HC_UDP_TTL];
			/* UDP ports, len, checksum */
			udp->uh_sport =
			    htons(SICSLOWPAN_UDP_PORT_MIN + (payload[PACKETBUF_HC1_HC_UDP_PORTS] >> 4));
			udp->uh_dport =
			    htons(SICSLOWPAN_UDP_PORT_MIN + (payload[PACKETBUF_HC1_HC_UDP_PORTS] & 0x0F));

			memcpy(&udp->uh_sum, &payload[PACKETBUF_HC1_HC_UDP_CHKSUM], 2);
			*hdrlen += UIP_UDPH_LEN;
			*hdroffset = SICSLOWPAN_HC1_HC_UDP_HDR_LEN;
		} else {
			ip6->ip6_hlim = payload[PACKETBUF_HC1_TTL];
			*hdroffset = SICSLOWPAN_HC1_HDR_LEN;
		}
		break;

	default:
		/* this shouldn't happen, drop */
		return EINVAL;
	}

	/* IP length field. */
	if (ip_len == 0) {
		size_t len = frame->payload_len - *hdroffset + *hdrlen - sizeof(struct ip6_hdr);

		/* This is not a fragmented packet */
		SET16(&ip6->ip6_plen, len);
	} else {
		/* This is a 1st fragment */
		SET16(&ip6->ip6_plen, ip_len - UIP_IPH_LEN);
	}
	/* length field in UDP header */
	if (ip6->ip6_nxt == IPPROTO_UDP) {
		struct udphdr *udp = (struct udphdr *)(uintptr_t)ip6;

		memcpy(&udp->uh_ulen, &ip6->ip6_plen, 2);
	}
	return 0;
}

errno_t
sixxlowpan_compress(struct frame802154 *ieee02154hdr, u_int8_t *payload)
{
	long hdroffset;
	size_t hdrlen;
	u_int8_t hdrbuf[128];
	errno_t error;

	bzero(hdrbuf, sizeof(hdrbuf));
	hdrlen = sizeof(hdrbuf);

	error = compress_hdr_hc1(ieee02154hdr, payload,
	    &hdroffset, &hdrlen, hdrbuf);
	if (error != 0) {
		return error;
	}

	if (hdroffset < 0) {
		/*
		 * hdroffset negative means that we have to add
		 * hdrlen of extra stuff
		 */
		memmove(&payload[hdrlen],
		    &payload[0],
		    ieee02154hdr->payload_len);
		memcpy(&payload[0], hdrbuf, hdrlen);

		ieee02154hdr->payload_len += hdrlen;
	} else if (hdroffset > 0) {
		/*
		 * hdroffset is the size of the compressed header
		 *
		 * hdrlen is the size of the data that has been compressed
		 * -- i.e. when the untouched data starts
		 */
		memmove(&payload[hdrlen],
		    &payload[hdroffset],
		    ieee02154hdr->payload_len - hdroffset);
		memcpy(&payload[0], hdrbuf, hdrlen);

		ieee02154hdr->payload_len += hdrlen - hdroffset;
	}

	return 0;
}

errno_t
sixxlowpan_uncompress(struct frame802154 *ieee02154hdr, u_int8_t *payload)
{
	long hdroffset;
	size_t hdrlen;
	u_int8_t hdrbuf[128];
	errno_t error;

	bzero(hdrbuf, sizeof(hdrbuf));
	hdrlen = sizeof(hdrbuf);

	error = uncompress_hdr_hc1(ieee02154hdr, (u_int8_t *)payload,
	    0, &hdroffset, &hdrlen, hdrbuf);

	if (error != 0) {
		return error;
	}

	if (hdroffset < 0) {
		/*
		 * hdroffset negative means that we have to remove
		 * hdrlen of extra stuff
		 */
		if (ieee02154hdr->payload_len < hdrlen) {
			return EINVAL;
		}
		memmove(&payload[0],
		    &payload[hdrlen],
		    ieee02154hdr->payload_len - hdrlen);
		ieee02154hdr->payload_len -= hdrlen;
	} else {
		/*
		 * hdroffset is the size of the compressed header
		 * -- i.e. when the untouched data starts
		 *
		 * hdrlen is the size of the decompressed header
		 * that takes the place of compressed header of size hdroffset
		 */
		if (ieee02154hdr->payload_len < hdroffset) {
			return EINVAL;
		}
		memmove(payload + hdrlen,
		    payload + hdroffset,
		    ieee02154hdr->payload_len - hdroffset);
		memcpy(payload, hdrbuf, hdrlen);
		ieee02154hdr->payload_len += hdrlen - hdroffset;
	}

	return 0;
}

errno_t
sixxlowpan_output(struct frame802154 *ieee02154hdr, u_int8_t *payload)
{
	errno_t error = 0;

	error = sixxlowpan_compress(ieee02154hdr, payload);
	if (error != 0) {
		goto done;
	}

	/*
	 * TO DO: fragmentation
	 */

done:
	return error;
}

errno_t
sixxlowpan_input(struct frame802154 *ieee02154hdr, u_int8_t *payload)
{
	errno_t error = 0;

	error = sixxlowpan_uncompress(ieee02154hdr, payload);
	if (error != 0) {
		goto done;
	}

	/*
	 * TO DO: fragmentation
	 */

done:
	return error;
}
