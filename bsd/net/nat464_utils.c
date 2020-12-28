/*
 * Copyright (c) 2018 Apple Inc. All rights reserved.
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
 * Copyright (c) 2001 Daniel Hartmeier
 * Copyright (c) 2002 - 2013 Henning Brauer
 * NAT64 - Copyright (c) 2010 Viagenie Inc. (http://www.viagenie.ca)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *	notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *	copyright notice, this list of conditions and the following
 *	disclaimer in the documentation and/or other materials provided
 *	with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Effort sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F30602-01-2-0537.
 *
 */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/mbuf.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/dlil.h>
#include <net/nat464_utils.h>
#include <net/nwk_wq.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/in_pcb.h>
#include <netinet/icmp_var.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <os/log.h>

int clat_debug = 0;

os_log_t nat_log_handle;

static void
nat464_addr_cksum_fixup(uint16_t *, struct nat464_addr *, struct nat464_addr *,
    protocol_family_t, protocol_family_t, uint8_t, boolean_t);

/* Synthesize ipv6 from ipv4 */
int
nat464_synthesize_ipv6(ifnet_t ifp, const struct in_addr *addrv4, struct in6_addr *addr)
{
	static const struct in6_addr well_known_prefix = {
		.__u6_addr.__u6_addr8 = {0x00, 0x64, 0xff, 0x9b, 0x00, 0x00,
			                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			                 0x00, 0x00, 0x00, 0x00},
	};

	struct ipv6_prefix nat64prefixes[NAT64_MAX_NUM_PREFIXES];
	int error = 0, i = 0;
	/* Below call is not optimized as it creates a copy of prefixes */
	if ((error = ifnet_get_nat64prefix(ifp, nat64prefixes)) != 0) {
		return error;
	}

	for (i = 0; i < NAT64_MAX_NUM_PREFIXES; i++) {
		if (nat64prefixes[i].prefix_len != 0) {
			break;
		}
	}

	VERIFY(i < NAT64_MAX_NUM_PREFIXES);

	struct in6_addr prefix = nat64prefixes[i].ipv6_prefix;
	int prefix_len = nat64prefixes[i].prefix_len;

	char *ptrv4 = __DECONST(char *, addrv4);
	char *ptr = __DECONST(char *, addr);

	if (IN_ZERONET(ntohl(addrv4->s_addr)) || // 0.0.0.0/8 Source hosts on local network
	    IN_LOOPBACK(ntohl(addrv4->s_addr)) || // 127.0.0.0/8 Loopback
	    IN_LINKLOCAL(ntohl(addrv4->s_addr)) || // 169.254.0.0/16 Link Local
	    IN_DS_LITE(ntohl(addrv4->s_addr)) || // 192.0.0.0/29 DS-Lite
	    IN_6TO4_RELAY_ANYCAST(ntohl(addrv4->s_addr)) || // 192.88.99.0/24 6to4 Relay Anycast
	    IN_MULTICAST(ntohl(addrv4->s_addr)) || // 224.0.0.0/4 Multicast
	    INADDR_BROADCAST == addrv4->s_addr) { // 255.255.255.255/32 Limited Broadcast
		return -1;
	}

	/* Check for the well-known prefix */
	if (prefix_len == NAT64_PREFIX_LEN_96 &&
	    IN6_ARE_ADDR_EQUAL(&prefix, &well_known_prefix)) { // https://tools.ietf.org/html/rfc6052#section-3.1
		if (IN_PRIVATE(ntohl(addrv4->s_addr)) || // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 Private-Use
		    IN_SHARED_ADDRESS_SPACE(ntohl(addrv4->s_addr))) { // 100.64.0.0/10 Shared Address Space
			return -1;
		}
	}

	memcpy(ptr, (char *)&prefix, prefix_len);

	switch (prefix_len) {
	case NAT64_PREFIX_LEN_96:
		memcpy(ptr + 12, ptrv4, 4);
		break;
	case NAT64_PREFIX_LEN_64:
		memcpy(ptr + 9, ptrv4, 4);
		break;
	case NAT64_PREFIX_LEN_56:
		memcpy(ptr + 7, ptrv4, 1);
		memcpy(ptr + 9, ptrv4 + 1, 3);
		break;
	case NAT64_PREFIX_LEN_48:
		memcpy(ptr + 6, ptrv4, 2);
		memcpy(ptr + 9, ptrv4 + 2, 2);
		break;
	case NAT64_PREFIX_LEN_40:
		memcpy(ptr + 5, ptrv4, 3);
		memcpy(ptr + 9, ptrv4 + 3, 1);
		break;
	case NAT64_PREFIX_LEN_32:
		memcpy(ptr + 4, ptrv4, 4);
		break;
	default:
		panic("NAT64-prefix len is wrong: %u\n", prefix_len);
	}

	if (clat_debug) {
		char buf[MAX_IPv6_STR_LEN];
		clat_log2((LOG_DEBUG, "%s synthesized  %s\n", __func__,
		    inet_ntop(AF_INET6, (void *)addr, buf, sizeof(buf))));
	}

	return error;
}

/* Synthesize ipv4 from ipv6 */
int
nat464_synthesize_ipv4(ifnet_t ifp, const struct in6_addr *addr, struct in_addr *addrv4)
{
	struct ipv6_prefix nat64prefixes[NAT64_MAX_NUM_PREFIXES];
	int error = 0, i = 0;

	/* Below call is not optimized as it creates a copy of prefixes */
	if ((error = ifnet_get_nat64prefix(ifp, nat64prefixes)) != 0) {
		return error;
	}

	for (i = 0; i < NAT64_MAX_NUM_PREFIXES; i++) {
		if (nat64prefixes[i].prefix_len != 0) {
			break;
		}
	}

	VERIFY(i < NAT64_MAX_NUM_PREFIXES);

	struct in6_addr prefix = nat64prefixes[i].ipv6_prefix;
	int prefix_len = nat64prefixes[i].prefix_len;

	char *ptrv4 = __DECONST(void *, addrv4);
	char *ptr = __DECONST(void *, addr);

	if (memcmp(addr, &prefix, prefix_len) != 0) {
		return -1;
	}

	switch (prefix_len) {
	case NAT64_PREFIX_LEN_96:
		memcpy(ptrv4, ptr + 12, 4);
		break;
	case NAT64_PREFIX_LEN_64:
		memcpy(ptrv4, ptr + 9, 4);
		break;
	case NAT64_PREFIX_LEN_56:
		memcpy(ptrv4, ptr + 7, 1);
		memcpy(ptrv4 + 1, ptr + 9, 3);
		break;
	case NAT64_PREFIX_LEN_48:
		memcpy(ptrv4, ptr + 6, 2);
		memcpy(ptrv4 + 2, ptr + 9, 2);
		break;
	case NAT64_PREFIX_LEN_40:
		memcpy(ptrv4, ptr + 5, 3);
		memcpy(ptrv4 + 3, ptr + 9, 1);
		break;
	case NAT64_PREFIX_LEN_32:
		memcpy(ptrv4, ptr + 4, 4);
		break;
	default:
		panic("NAT64-prefix len is wrong: %u\n",
		    prefix_len);
	}

	if (clat_debug) {
		char buf[MAX_IPv4_STR_LEN];
		clat_log2((LOG_DEBUG, "%s desynthesized to %s\n", __func__,
		    inet_ntop(AF_INET, (void *)addrv4, buf, sizeof(buf))));
	}
	return error;
}

#define PTR_IP(field)   ((int32_t)offsetof(struct ip, field))
#define PTR_IP6(field)  ((int32_t)offsetof(struct ip6_hdr, field))

/*
 *  Translate the ICMP header
 */
int
nat464_translate_icmp(int naf, void *arg)
{
	struct icmp             *icmp4;
	struct icmp6_hdr        *icmp6;
	uint32_t                 mtu;
	int32_t                  ptr = -1;
	uint8_t          type;
	uint8_t          code;

	switch (naf) {
	case AF_INET:
		icmp6 = arg;
		type  = icmp6->icmp6_type;
		code  = icmp6->icmp6_code;
		mtu   = ntohl(icmp6->icmp6_mtu);

		switch (type) {
		case ICMP6_ECHO_REQUEST:
			type = ICMP_ECHO;
			break;
		case ICMP6_ECHO_REPLY:
			type = ICMP_ECHOREPLY;
			break;
		case ICMP6_DST_UNREACH:
			type = ICMP_UNREACH;
			switch (code) {
			case ICMP6_DST_UNREACH_NOROUTE:
			case ICMP6_DST_UNREACH_BEYONDSCOPE:
			case ICMP6_DST_UNREACH_ADDR:
				code = ICMP_UNREACH_HOST;
				break;
			case ICMP6_DST_UNREACH_ADMIN:
				code = ICMP_UNREACH_HOST_PROHIB;
				break;
			case ICMP6_DST_UNREACH_NOPORT:
				code = ICMP_UNREACH_PORT;
				break;
			default:
				return -1;
			}
			break;
		case ICMP6_PACKET_TOO_BIG:
			type = ICMP_UNREACH;
			code = ICMP_UNREACH_NEEDFRAG;
			mtu -= 20;
			break;
		case ICMP6_TIME_EXCEEDED:
			type = ICMP_TIMXCEED;
			break;
		case ICMP6_PARAM_PROB:
			switch (code) {
			case ICMP6_PARAMPROB_HEADER:
				type = ICMP_PARAMPROB;
				code = ICMP_PARAMPROB_ERRATPTR;
				ptr  = ntohl(icmp6->icmp6_pptr);

				if (ptr == PTR_IP6(ip6_vfc)) {
					; /* preserve */
				} else if (ptr == PTR_IP6(ip6_vfc) + 1) {
					ptr = PTR_IP(ip_tos);
				} else if (ptr == PTR_IP6(ip6_plen) ||
				    ptr == PTR_IP6(ip6_plen) + 1) {
					ptr = PTR_IP(ip_len);
				} else if (ptr == PTR_IP6(ip6_nxt)) {
					ptr = PTR_IP(ip_p);
				} else if (ptr == PTR_IP6(ip6_hlim)) {
					ptr = PTR_IP(ip_ttl);
				} else if (ptr >= PTR_IP6(ip6_src) &&
				    ptr < PTR_IP6(ip6_dst)) {
					ptr = PTR_IP(ip_src);
				} else if (ptr >= PTR_IP6(ip6_dst) &&
				    ptr < (int32_t)sizeof(struct ip6_hdr)) {
					ptr = PTR_IP(ip_dst);
				} else {
					return -1;
				}
				break;
			case ICMP6_PARAMPROB_NEXTHEADER:
				type = ICMP_UNREACH;
				code = ICMP_UNREACH_PROTOCOL;
				break;
			default:
				return -1;
			}
			break;
		default:
			return -1;
		}
		icmp6->icmp6_type = type;
		icmp6->icmp6_code = code;
		/* aligns well with a icmpv4 nextmtu */
		icmp6->icmp6_mtu = htonl(mtu);
		/* icmpv4 pptr is a one most significant byte */
		if (ptr >= 0) {
			icmp6->icmp6_pptr = htonl(ptr << 24);
		}
		break;

	case AF_INET6:
		icmp4 = arg;
		type  = icmp4->icmp_type;
		code  = icmp4->icmp_code;
		mtu   = ntohs(icmp4->icmp_nextmtu);

		switch (type) {
		case ICMP_ECHO:
			type = ICMP6_ECHO_REQUEST;
			break;
		case ICMP_ECHOREPLY:
			type = ICMP6_ECHO_REPLY;
			break;
		case ICMP_UNREACH:
			type = ICMP6_DST_UNREACH;
			switch (code) {
			case ICMP_UNREACH_NET:
			case ICMP_UNREACH_HOST:
			case ICMP_UNREACH_NET_UNKNOWN:
			case ICMP_UNREACH_HOST_UNKNOWN:
			case ICMP_UNREACH_ISOLATED:
			case ICMP_UNREACH_TOSNET:
			case ICMP_UNREACH_TOSHOST:
				code = ICMP6_DST_UNREACH_NOROUTE;
				break;
			case ICMP_UNREACH_PORT:
				code = ICMP6_DST_UNREACH_NOPORT;
				break;
			case ICMP_UNREACH_NET_PROHIB:
			case ICMP_UNREACH_HOST_PROHIB:
			case ICMP_UNREACH_FILTER_PROHIB:
			case ICMP_UNREACH_PRECEDENCE_CUTOFF:
				code = ICMP6_DST_UNREACH_ADMIN;
				break;
			case ICMP_UNREACH_PROTOCOL:
				type = ICMP6_PARAM_PROB;
				code = ICMP6_PARAMPROB_NEXTHEADER;
				ptr  = offsetof(struct ip6_hdr, ip6_nxt);
				break;
			case ICMP_UNREACH_NEEDFRAG:
				type = ICMP6_PACKET_TOO_BIG;
				code = 0;
				mtu += 20;
				break;
			default:
				return -1;
			}
			break;
		case ICMP_TIMXCEED:
			type = ICMP6_TIME_EXCEEDED;
			break;
		case ICMP_PARAMPROB:
			type = ICMP6_PARAM_PROB;
			switch (code) {
			case ICMP_PARAMPROB_ERRATPTR:
				code = ICMP6_PARAMPROB_HEADER;
				break;
			case ICMP_PARAMPROB_LENGTH:
				code = ICMP6_PARAMPROB_HEADER;
				break;
			default:
				return -1;
			}

			ptr = icmp4->icmp_pptr;
			if (ptr == 0 || ptr == PTR_IP(ip_tos)) {
				; /* preserve */
			} else if (ptr == PTR_IP(ip_len) ||
			    ptr == PTR_IP(ip_len) + 1) {
				ptr = PTR_IP6(ip6_plen);
			} else if (ptr == PTR_IP(ip_ttl)) {
				ptr = PTR_IP6(ip6_hlim);
			} else if (ptr == PTR_IP(ip_p)) {
				ptr = PTR_IP6(ip6_nxt);
			} else if (ptr >= PTR_IP(ip_src) &&
			    ptr < PTR_IP(ip_dst)) {
				ptr = PTR_IP6(ip6_src);
			} else if (ptr >= PTR_IP(ip_dst) &&
			    ptr < (int32_t)sizeof(struct ip)) {
				ptr = PTR_IP6(ip6_dst);
			} else {
				return -1;
			}
			break;
		default:
			return -1;
		}
		icmp4->icmp_type = type;
		icmp4->icmp_code = code;
		icmp4->icmp_nextmtu = htons(mtu);
		if (ptr >= 0) {
			icmp4->icmp_void = htonl(ptr);
		}
		break;
	}

	return 0;
}

/*
 * @brief This routine is called to perform address family translation on the
 *     inner IP header (that may come as payload) of an ICMP(v4/v6) error
 *     response.
 *
 * @param pbuf Pointer to packet buffer
 * @param off Points to end of ICMP header
 * @param tot_len Pointer to total length of the outer IP header
 * @param off2 Points to end of inner IP header
 * @param proto2 Inner IP proto field
 * @param ttl2 Inner IP ttl field
 * @param tot_len2 Inner IP total length
 * @param src Pointer to the generic v4/v6 src address
 * @param dst Pointer to the generic v4/v6 dst address
 * @param af Old protocol family
 * @param naf New protocol family
 *
 * @return -1 on error and 0 on success
 */
int
nat464_translate_icmp_ip(pbuf_t *pbuf, uint32_t off, uint64_t *tot_len, uint32_t *off2,
    uint8_t proto2, uint8_t ttl2, uint64_t tot_len2, struct nat464_addr *src,
    struct nat464_addr *dst, protocol_family_t af, protocol_family_t naf)
{
	struct ip *ip4 = NULL;
	struct ip6_hdr *ip6 = NULL;
	void *hdr = NULL;
	int hlen = 0, olen = 0;

	if (af == naf || (af != AF_INET && af != AF_INET6) ||
	    (naf != AF_INET && naf != AF_INET6)) {
		return -1;
	}

	/* old header */
	olen = *off2 - off;
	/* new header */
	hlen = naf == PF_INET ? sizeof(*ip4) : sizeof(*ip6);

	/* Modify the pbuf to accommodate the new header */
	hdr = pbuf_resize_segment(pbuf, off, olen, hlen);
	if (hdr == NULL) {
		return -1;
	}

	/* translate inner ip/ip6 header */
	switch (naf) {
	case AF_INET:
		ip4 = hdr;
		bzero(ip4, sizeof(*ip4));
		ip4->ip_v = IPVERSION;
		ip4->ip_hl = sizeof(*ip4) >> 2;
		ip4->ip_len = htons(sizeof(*ip4) + tot_len2 - olen);
		ip4->ip_id = rfc6864 ? 0 : htons(ip_randomid());
		ip4->ip_off = htons(IP_DF);
		ip4->ip_ttl = ttl2;
		if (proto2 == IPPROTO_ICMPV6) {
			ip4->ip_p = IPPROTO_ICMP;
		} else {
			ip4->ip_p = proto2;
		}
		ip4->ip_src = src->natv4addr;
		ip4->ip_dst = dst->natv4addr;
		ip4->ip_sum = pbuf_inet_cksum(pbuf, 0, 0, ip4->ip_hl << 2);

		if (clat_debug) {
			char buf[MAX_IPv4_STR_LEN];
			clat_log2((LOG_DEBUG, "%s translated to IPv4 (inner) "
			    "ip_len: %#x ip_p: %d ip_sum: %#x ip_src: %s ip_dst: %s \n",
			    __func__, ntohs(ip4->ip_len), ip4->ip_p, ntohs(ip4->ip_sum),
			    inet_ntop(AF_INET, (void *)&ip4->ip_src, buf, sizeof(buf)),
			    inet_ntop(AF_INET, (void *)&ip4->ip_dst, buf, sizeof(buf))));
		}
		break;
	case AF_INET6:
		ip6 = hdr;
		bzero(ip6, sizeof(*ip6));
		ip6->ip6_vfc  = IPV6_VERSION;
		ip6->ip6_plen = htons(tot_len2 - olen);
		if (proto2 == IPPROTO_ICMP) {
			ip6->ip6_nxt = IPPROTO_ICMPV6;
		} else {
			ip6->ip6_nxt = proto2;
		}
		if (!ttl2 || ttl2 > IPV6_DEFHLIM) {
			ip6->ip6_hlim = IPV6_DEFHLIM;
		} else {
			ip6->ip6_hlim = ttl2;
		}
		ip6->ip6_src  = src->natv6addr;
		ip6->ip6_dst  = dst->natv6addr;

		if (clat_debug) {
			char buf2[MAX_IPv6_STR_LEN];
			clat_log2((LOG_DEBUG, "%s translated to IPv6 (inner) "
			    "ip6_plen: %#x ip6_nxt: %d ip6_src: %s ip6_dst: %s \n",
			    __func__, ntohs(ip6->ip6_plen), ip6->ip6_nxt,
			    inet_ntop(AF_INET6, (void *)&ip6->ip6_src, buf2, sizeof(buf2)),
			    inet_ntop(AF_INET6, (void *)&ip6->ip6_dst, buf2, sizeof(buf2))));
		}
		break;
	}

	/* adjust payload offset and total packet length */
	*off2 += hlen - olen;
	*tot_len += hlen - olen;

	return 0;
}
/*
 * @brief The function inserts IPv6 fragmentation header
 *     and populates it with the passed parameters.
 *
 * @param pbuf Pointer to the packet buffer
 * @param ip_id IP identifier (in network byte order)
 * @param frag_offset Fragment offset (in network byte order)
 * @param is_last_frag Boolean indicating if the fragment header is for
 *     last fragment or not.
 *
 * @return -1 on error and 0 on success.
 */
int
nat464_insert_frag46(pbuf_t *pbuf, uint16_t ip_id_val, uint16_t frag_offset,
    boolean_t is_last_frag)
{
	struct ip6_frag *p_ip6_frag = NULL;
	struct ip6_hdr *p_ip6h = NULL;

	/* Insert IPv6 fragmentation header */
	if (pbuf_resize_segment(pbuf, sizeof(struct ip6_hdr), 0,
	    sizeof(struct ip6_frag)) == NULL) {
		return -1;
	}

	p_ip6h = mtod(pbuf->pb_mbuf, struct ip6_hdr *);
	p_ip6_frag = (struct ip6_frag *)pbuf_contig_segment(pbuf,
	    sizeof(struct ip6_hdr), sizeof(struct ip6_frag));

	if (p_ip6_frag == NULL) {
		return -1;
	}

	/* Populate IPv6 fragmentation header */
	p_ip6_frag->ip6f_nxt = p_ip6h->ip6_nxt;
	p_ip6_frag->ip6f_reserved = 0;
	p_ip6_frag->ip6f_offlg = (frag_offset) << 3;
	if (!is_last_frag) {
		p_ip6_frag->ip6f_offlg |= 0x1;
	}
	p_ip6_frag->ip6f_offlg = htons(p_ip6_frag->ip6f_offlg);
	p_ip6_frag->ip6f_ident = ip_id_val;

	/* Update IPv6 header */
	p_ip6h->ip6_nxt = IPPROTO_FRAGMENT;
	p_ip6h->ip6_plen = htons(ntohs(p_ip6h->ip6_plen) +
	    sizeof(struct ip6_frag));

	return 0;
}

int
nat464_translate_64(pbuf_t *pbuf, int off, uint8_t tos,
    uint8_t *proto, uint8_t ttl, struct in_addr src_v4,
    struct in_addr dst_v4, uint64_t tot_len, boolean_t *p_is_first_frag)
{
	struct ip *ip4;
	struct ip6_frag *p_frag6 = NULL;
	struct ip6_frag frag6 = {};
	boolean_t is_frag = FALSE;
	uint16_t ip_frag_off = 0;

	/*
	 * ip_input asserts for rcvif to be not NULL
	 * That may not be true for two corner cases
	 * 1. If for some reason a local app sends DNS
	 * AAAA query to local host
	 * 2. If IPv6 stack in kernel internally generates a
	 * message destined for a synthesized IPv6 end-point.
	 */
	if (pbuf->pb_ifp == NULL) {
		return NT_DROP;
	}

	if (*proto == IPPROTO_FRAGMENT) {
		p_frag6 = (struct ip6_frag *)pbuf_contig_segment(pbuf,
		    sizeof(struct ip6_hdr), sizeof(struct ip6_frag));
		if (p_frag6 == NULL) {
			ip6stat.ip6s_clat464_in_64frag_transfail_drop++;
			return NT_DROP;
		}

		frag6 = *p_frag6;
		p_frag6 = NULL;
		*proto = frag6.ip6f_nxt;
		off += sizeof(struct ip6_frag);
		is_frag = TRUE;
		ip_frag_off = (ntohs(frag6.ip6f_offlg & IP6F_OFF_MASK)) >> 3;
		if (ip_frag_off != 0) {
			*p_is_first_frag = FALSE;
		}
	}

	ip4 = (struct ip *)pbuf_resize_segment(pbuf, 0, off, sizeof(*ip4));
	if (ip4 == NULL) {
		return NT_DROP;
	}
	ip4->ip_v   = 4;
	ip4->ip_hl  = 5;
	ip4->ip_tos = tos;
	ip4->ip_len = htons(sizeof(*ip4) + (tot_len - off));
	ip4->ip_id  = 0;
	ip4->ip_off = 0;
	ip4->ip_ttl = ttl;
	ip4->ip_p   = *proto;
	ip4->ip_sum = 0;
	ip4->ip_src = src_v4;
	ip4->ip_dst = dst_v4;
	if (is_frag) {
		/*
		 * https://tools.ietf.org/html/rfc7915#section-5.1.1
		 * Identification:  Copied from the low-order 16 bits in the
		 * Identification field in the Fragment Header.
		 */
		ip4->ip_id = ntohl(frag6.ip6f_ident) & 0xffff;
		ip4->ip_id = htons(ip4->ip_id);
		if (frag6.ip6f_offlg & IP6F_MORE_FRAG) {
			ip_frag_off |= IP_MF;
		}
		ip4->ip_off = htons(ip_frag_off);
	} else {
		ip4->ip_off |= htons(IP_DF);
	}

	/*
	 * Defer calculating ip_sum for ICMPv6 as we do it
	 * later in Protocol translation
	 */
	if (*proto != IPPROTO_ICMPV6) {
		ip4->ip_sum = pbuf_inet_cksum(pbuf, 0, 0, ip4->ip_hl << 2);
	}

	if (clat_debug) {
		char buf1[MAX_IPv4_STR_LEN], buf2[MAX_IPv4_STR_LEN];
		clat_log2((LOG_DEBUG, "%s translated to IPv4 ip_len: %#x "
		    "ip_p: %d ip_sum: %#x ip_src: %s ip_dst: %s \n", __func__,
		    ntohs(ip4->ip_len), ip4->ip_p, ntohs(ip4->ip_sum),
		    inet_ntop(AF_INET, (void *)&ip4->ip_src, buf1, sizeof(buf1)),
		    inet_ntop(AF_INET, (void *)&ip4->ip_dst, buf2, sizeof(buf2))));
	}
	return NT_NAT64;
}
/*
 * @brief The routine translates the IPv4 header to IPv6 header.
 *
 * @param pbuf Pointer to the generic packet buffer
 * @param off Offset to the end of IP header
 * @param tos Type of service
 * @param proto Protocol running over IP
 * @param ttl Time to live
 * @param src_v6 Source IPv6 address
 * @param dst_v6 Destination IPv6 address
 * @param tot_len Total payload length
 *
 * @return NT_NAT64 if IP header translation is successful, else error
 */
int
nat464_translate_46(pbuf_t *pbuf, int off, uint8_t tos,
    uint8_t proto, uint8_t ttl, struct in6_addr src_v6,
    struct in6_addr dst_v6, uint64_t tot_len)
{
	struct ip6_hdr *ip6;

	if (pbuf->pb_ifp == NULL) {
		return NT_DROP;
	}

	/*
	 * Trim the buffer from head of size equal to to off (which is equal to
	 * the size of IP header and prepend IPv6 header length to the buffer
	 */
	ip6 = (struct ip6_hdr *)pbuf_resize_segment(pbuf, 0, off, sizeof(*ip6));
	if (ip6 == NULL) {
		return NT_DROP;
	}
	ip6->ip6_flow = htonl((6 << 28) | (tos << 20));
	ip6->ip6_plen = htons(tot_len - off);
	ip6->ip6_nxt  = proto;
	ip6->ip6_hlim = ttl;
	ip6->ip6_src = src_v6;
	ip6->ip6_dst = dst_v6;

	if (clat_debug) {
		char buf1[MAX_IPv6_STR_LEN], buf2[MAX_IPv6_STR_LEN];
		clat_log2((LOG_DEBUG, "%s translated to IPv6 ip6_plen: %#x "
		    " ip6_nxt: %d ip6_src: %s ip6_dst: %s \n", __func__,
		    ntohs(ip6->ip6_plen), ip6->ip6_nxt,
		    inet_ntop(AF_INET6, (void *)&ip6->ip6_src, buf1, sizeof(buf1)),
		    inet_ntop(AF_INET6, (void *)&ip6->ip6_dst, buf2, sizeof(buf2))));
	}
	return NT_NAT64;
}

/* Handle the next protocol checksum */
/*
 * @brief This routine translates the Proto running over IP and updates the checksum
 *     for IP header translation. It also updates pbuf checksum flags and related fields.
 *
 * @param pbuf Pointer to protocol buffer
 * @param nsrc New source address
 * @param ndst New destination address
 * @param af Old family
 * @param naf New family
 *
 * @return void
 */
int
nat464_translate_proto(pbuf_t *pbuf, struct nat464_addr *osrc,
    struct nat464_addr *odst, uint8_t oproto, protocol_family_t af,
    protocol_family_t naf, int direction, boolean_t only_csum)
{
	struct ip *iph = NULL;
	struct ip6_hdr *ip6h = NULL;
	uint32_t hlen = 0, plen = 0;
	uint64_t tot_len = 0;
	void *nsrc = NULL, *ndst = NULL;
	uint8_t *proto = 0;
	uint16_t *psum = NULL;
	boolean_t do_ones_complement = FALSE;

	/* For now these routines only support 464 translations */
	VERIFY(af != naf);
	VERIFY(af == PF_INET || af == PF_INET6);

	/*
	 * For now out must be for v4 to v6 translation
	 * and in must be for v6 to v4 translation.
	 */
	switch (naf) {
	case PF_INET: {
		iph = pbuf->pb_data;
		hlen = iph->ip_hl << 2;
		plen = ntohs(iph->ip_len) - hlen;
		tot_len = ntohs(iph->ip_len);
		nsrc = &iph->ip_src;
		ndst = &iph->ip_dst;
		proto = &iph->ip_p;
		break;
	}
	case PF_INET6: {
		ip6h = pbuf->pb_data;
		hlen = sizeof(*ip6h);
		plen = ntohs(ip6h->ip6_plen);
		tot_len = hlen + plen;
		nsrc = &ip6h->ip6_src;
		ndst = &ip6h->ip6_dst;
		proto = &ip6h->ip6_nxt;
		break;
	}
	default:
		return NT_DROP; /* We should never come here */
	}

	if (*proto != oproto) {
		return NT_DROP;
	}

	/*
	 * We may want to manipulate csum flags in some cases
	 * and not act on the protocol header as it may not
	 * carry protocol checksums.
	 * For example, fragments other than the first one would
	 * not carry protocol headers.
	 */
	if (only_csum) {
		/*
		 * Only translate ICMP proto in the header
		 * and adjust checksums
		 */
		if (*proto == IPPROTO_ICMP) {
			if (naf != PF_INET6) {
				return NT_DROP;
			}

			*proto = IPPROTO_ICMPV6;
		} else if (*proto == IPPROTO_ICMPV6) {
			if (naf != PF_INET) {
				return NT_DROP;
			}

			*proto = IPPROTO_ICMP;
			/* Recalculate IP checksum as proto field has changed */
			iph->ip_sum = 0;
			iph->ip_sum = pbuf_inet_cksum(pbuf, 0, 0, hlen);
		}
		goto done;
	}

	switch (*proto) {
	case IPPROTO_UDP: {
		struct udphdr *uh = (struct udphdr *)pbuf_contig_segment(pbuf, hlen,
		    sizeof(*uh));

		if (uh == NULL) {
			return NT_DROP;
		}

		if (!(*pbuf->pb_csum_flags & (CSUM_UDP | CSUM_PARTIAL)) &&
		    uh->uh_sum == 0 && af == PF_INET && naf == PF_INET6) {
			uh->uh_sum = pbuf_inet6_cksum(pbuf, IPPROTO_UDP,
			    hlen, ntohs(ip6h->ip6_plen));
			if (uh->uh_sum == 0) {
				uh->uh_sum = 0xffff;
			}
			goto done;
		}

		psum = &uh->uh_sum;
		break;
	}
	case IPPROTO_TCP: {
		struct tcphdr *th = (struct tcphdr *)pbuf_contig_segment(pbuf, hlen,
		    sizeof(*th));

		if (th == NULL) {
			return NT_DROP;
		}

		psum = &th->th_sum;
		break;
	}
	}

	/*
	 * Translate the protocol header, update IP header if needed,
	 * calculate checksums and update the checksum flags.
	 */
	switch (*proto) {
	case IPPROTO_UDP:
	/* Fall through */
	case IPPROTO_TCP:
	{
		/*
		 * If it is a locally generated and has CSUM flags set
		 * for TCP and UDP it means we have pseudo header checksum
		 * that has not yet been one's complemented.
		 */
		if (direction == NT_OUT &&
		    (*pbuf->pb_csum_flags & CSUM_DELAY_DATA)) {
			do_ones_complement = TRUE;
		}

		nat464_addr_cksum_fixup(psum, osrc, (struct nat464_addr *)nsrc,
		    af, naf, (*proto == IPPROTO_UDP) ? 1 : 0, do_ones_complement);
		nat464_addr_cksum_fixup(psum, odst, (struct nat464_addr *)ndst,
		    af, naf, (*proto == IPPROTO_UDP) ? 1 : 0, do_ones_complement);

		break;
	}
	case IPPROTO_ICMP: {
		if (naf != PF_INET6) {  /* allow only v6 as naf for ICMP */
			return NT_DROP;
		}

		struct icmp *icmph = NULL;
		struct icmp6_hdr *icmp6h = NULL;
		uint32_t ip2off = 0, hlen2 = 0, tot_len2 = 0;

		icmph = (struct icmp*) pbuf_contig_segment(pbuf, hlen,
		    ICMP_MINLEN);
		if (icmph == NULL) {
			return NT_DROP;
		}

		/* Translate the ICMP header */
		if (nat464_translate_icmp(PF_INET6, icmph) != 0) {
			return NT_DROP;
		}

		*proto = IPPROTO_ICMPV6;
		icmp6h = (struct icmp6_hdr *)(uintptr_t)icmph;
		pbuf_copy_back(pbuf, hlen, sizeof(struct icmp6_hdr),
		    icmp6h);

		/*Translate the inner IP header only for error messages */
		if (ICMP6_ERRORTYPE(icmp6h->icmp6_type)) {
			ip2off = hlen + sizeof(*icmp6h);
			struct ip *iph2;
			iph2 = (struct ip*) pbuf_contig_segment(pbuf, ip2off,
			    sizeof(*iph2));
			if (iph2 == NULL) {
				return NT_DROP;
			}

			hlen2 = ip2off + (iph2->ip_hl << 2);
			tot_len2 = ntohs(iph2->ip_len);

			/* Destination in outer IP should be Source in inner IP */
			VERIFY(IN_ARE_ADDR_EQUAL(&odst->natv4addr, &iph2->ip_src));
			if (nat464_translate_icmp_ip(pbuf, ip2off, &tot_len,
			    &hlen2, iph2->ip_p, iph2->ip_ttl, tot_len2,
			    (struct nat464_addr *)ndst, (struct nat464_addr *)nsrc,
			    PF_INET, PF_INET6) != 0) {
				return NT_DROP;
			}
			/* Update total length/payload length for outer header */
			switch (naf) {
			case PF_INET:
				iph->ip_len = htons(tot_len);
				break;
			case PF_INET6:
				ip6h->ip6_plen = htons(tot_len - hlen);
				break;
			}
			iph2 = NULL;
		}

		icmp6h->icmp6_cksum = 0;
		icmp6h->icmp6_cksum = pbuf_inet6_cksum(pbuf, IPPROTO_ICMPV6, hlen,
		    ntohs(ip6h->ip6_plen));

		clat_log2((LOG_DEBUG, "%s translated to ICMPV6 type: %d "
		    "code: %d checksum: %#x \n", __func__, icmp6h->icmp6_type,
		    icmp6h->icmp6_code, icmp6h->icmp6_cksum));

		icmph = NULL;
		icmp6h = NULL;
		break;
	}
	case IPPROTO_ICMPV6:
	{       if (naf != PF_INET) {           /* allow only v4 as naf for ICMPV6 */
			return NT_DROP;
		}

		struct icmp6_hdr *icmp6h = NULL;
		struct icmp *icmph = NULL;
		uint32_t ip2off = 0, hlen2 = 0, tot_len2 = 0;

		icmp6h = (struct icmp6_hdr*) pbuf_contig_segment(pbuf, hlen,
		    sizeof(*icmp6h));
		if (icmp6h == NULL) {
			return NT_DROP;
		}

		/* Translate the ICMP header */
		if (nat464_translate_icmp(PF_INET, icmp6h) != 0) {
			return NT_DROP;
		}

		*proto = IPPROTO_ICMP;
		icmph = (struct icmp *)(uintptr_t)icmp6h;
		pbuf_copy_back(pbuf, hlen, ICMP_MINLEN,
		    icmph);

		/*Translate the inner IP header only for error messages */
		if (ICMP_ERRORTYPE(icmph->icmp_type)) {
			ip2off = hlen + ICMP_MINLEN;
			struct ip6_hdr *iph2;
			iph2 = (struct ip6_hdr*) pbuf_contig_segment(pbuf, ip2off,
			    sizeof(*iph2));
			if (iph2 == NULL) {
				return NT_DROP;
			}

			/* hlen2 points to end of inner IP header from the beginning */
			hlen2 = ip2off + sizeof(struct ip6_hdr);
			tot_len2 = ntohs(iph2->ip6_plen) + sizeof(struct ip6_hdr);

			if (nat464_translate_icmp_ip(pbuf, ip2off, &tot_len,
			    &hlen2, iph2->ip6_nxt, iph2->ip6_hlim, tot_len2,
			    (struct nat464_addr *)ndst, (struct nat464_addr *)nsrc,
			    PF_INET6, PF_INET) != 0) {
				return NT_DROP;
			}

			/* Update total length for outer header */
			switch (naf) {
			case PF_INET:
				iph->ip_len = htons(tot_len);
				break;
			case PF_INET6:
				ip6h->ip6_plen = htons(tot_len - hlen);
				break;
			}
			iph2 = NULL;
		}
		/* Recalculate IP checksum as some IP fields might have changed */
		iph->ip_sum = 0;
		iph->ip_sum = pbuf_inet_cksum(pbuf, 0, 0, iph->ip_hl << 2);
		icmph->icmp_cksum = 0;
		icmph->icmp_cksum = pbuf_inet_cksum(pbuf, 0, hlen,
		    ntohs(iph->ip_len) - hlen);

		clat_log2((LOG_DEBUG, "%s translated to ICMP type: %d "
		    "code: %d checksum: %#x \n", __func__, icmph->icmp_type,
		    icmph->icmp_code, icmph->icmp_cksum));

		icmp6h = NULL;
		icmph = NULL;
		break;}

	/*
	 * https://tools.ietf.org/html/rfc7915#section-5.1.1
	 * If the Next Header field of the Fragment Header is an
	 * extension header (except ESP, but including the Authentication
	 * Header (AH)), then the packet SHOULD be dropped and logged.
	 */
	case IPPROTO_HOPOPTS:
	case IPPROTO_ROUTING:
	case IPPROTO_DSTOPTS:
	case IPPROTO_AH:
		return NT_DROP;

	case IPPROTO_FRAGMENT:
		/*
		 * The fragment header is appended after or removed before
		 * calling into this routine.
		 */
		VERIFY(FALSE);
	case IPPROTO_ESP:
		break;

	default:
		return NT_DROP;
	}

done:
	/* Update checksum flags and offsets based on direction */
	if (direction == NT_OUT) {
		if ((*pbuf->pb_csum_flags & (CSUM_DATA_VALID | CSUM_PARTIAL)) ==
		    (CSUM_DATA_VALID | CSUM_PARTIAL)) {
			(pbuf->pb_mbuf)->m_pkthdr.csum_tx_start += CLAT46_HDR_EXPANSION_OVERHD;
			(pbuf->pb_mbuf)->m_pkthdr.csum_tx_stuff += CLAT46_HDR_EXPANSION_OVERHD;
		}

		if (*pbuf->pb_csum_flags & CSUM_TCP) {
			*pbuf->pb_csum_flags |= CSUM_TCPIPV6;
		}
		if (*pbuf->pb_csum_flags & CSUM_UDP) {
			*pbuf->pb_csum_flags |= CSUM_UDPIPV6;
		}
		if (*pbuf->pb_csum_flags & CSUM_FRAGMENT) {
			*pbuf->pb_csum_flags |= CSUM_FRAGMENT_IPV6;
		}

		/* Clear IPv4 checksum flags */
		*pbuf->pb_csum_flags &= ~(CSUM_IP | CSUM_IP_FRAGS | CSUM_DELAY_DATA | CSUM_FRAGMENT);
	} else if (direction == NT_IN) {
		/* XXX On input just reset csum flags */
		*pbuf->pb_csum_flags = 0; /* Reset all flags for now */
#if 0
		/* Update csum flags and offsets for rx */
		if (*pbuf->pb_csum_flags & CSUM_PARTIAL) {
			(pbuf->pb_mbuf)->m_pkthdr.csum_rx_start -= CLAT46_HDR_EXPANSION_OVERHD;
		}
#endif
	}
	return NT_NAT64;
}

/* Fix the proto checksum for address change */
static void
nat464_addr_cksum_fixup(uint16_t *pc, struct nat464_addr *ao, struct nat464_addr *an,
    protocol_family_t af, protocol_family_t naf, uint8_t u, boolean_t do_ones_complement)
{
	/* Currently we only support v4 to v6 and vice versa */
	VERIFY(af != naf);

	switch (af) {
	case PF_INET:
		switch (naf) {
		case PF_INET6:
			if (do_ones_complement) {
				*pc = ~nat464_cksum_fixup(nat464_cksum_fixup(
					    nat464_cksum_fixup(nat464_cksum_fixup(nat464_cksum_fixup(
						    nat464_cksum_fixup(nat464_cksum_fixup(nat464_cksum_fixup(~*pc,
						    ao->nataddr16[0], an->nataddr16[0], u),
						    ao->nataddr16[1], an->nataddr16[1], u),
						    0, an->nataddr16[2], u),
						    0, an->nataddr16[3], u),
					    0, an->nataddr16[4], u),
					    0, an->nataddr16[5], u),
					    0, an->nataddr16[6], u),
				    0, an->nataddr16[7], u);
			} else {
				*pc = nat464_cksum_fixup(nat464_cksum_fixup(
					    nat464_cksum_fixup(nat464_cksum_fixup(nat464_cksum_fixup(
						    nat464_cksum_fixup(nat464_cksum_fixup(nat464_cksum_fixup(*pc,
						    ao->nataddr16[0], an->nataddr16[0], u),
						    ao->nataddr16[1], an->nataddr16[1], u),
						    0, an->nataddr16[2], u),
						    0, an->nataddr16[3], u),
					    0, an->nataddr16[4], u),
					    0, an->nataddr16[5], u),
					    0, an->nataddr16[6], u),
				    0, an->nataddr16[7], u);
			}
			break;
		}
		break;
	case PF_INET6:
		/*
		 * XXX For NAT464 this only applies to the incoming path.
		 * The checksum therefore is already ones complemented.
		 * Therefore we just perform normal fixup.
		 */
		switch (naf) {
		case PF_INET:
			*pc = nat464_cksum_fixup(nat464_cksum_fixup(
				    nat464_cksum_fixup(nat464_cksum_fixup(nat464_cksum_fixup(
					    nat464_cksum_fixup(nat464_cksum_fixup(nat464_cksum_fixup(*pc,
					    ao->nataddr16[0], an->nataddr16[0], u),
					    ao->nataddr16[1], an->nataddr16[1], u),
					    ao->nataddr16[2], 0, u),
					    ao->nataddr16[3], 0, u),
				    ao->nataddr16[4], 0, u),
				    ao->nataddr16[5], 0, u),
				    ao->nataddr16[6], 0, u),
			    ao->nataddr16[7], 0, u);
			break;
		}
		break;
	}
}

uint16_t
nat464_cksum_fixup(uint16_t cksum, uint16_t old, uint16_t new, uint8_t udp)
{
	uint32_t l;

	if (udp && !cksum) {
		return 0;
	}
	l = cksum + old - new;
	l = (l >> 16) + (l & 0xffff);
	l = l & 0xffff;
	if (udp && !l) {
		return 0xffff;
	}
	return l;
}

/* CLAT46 event handlers */
void
in6_clat46_eventhdlr_callback(struct eventhandler_entry_arg arg0 __unused,
    in6_clat46_evhdlr_code_t in6_clat46_ev_code, pid_t epid, uuid_t euuid)
{
	struct kev_msg ev_msg;
	struct kev_netevent_clat46_data clat46_event_data;

	bzero(&ev_msg, sizeof(ev_msg));
	bzero(&clat46_event_data, sizeof(clat46_event_data));

	ev_msg.vendor_code      = KEV_VENDOR_APPLE;
	ev_msg.kev_class        = KEV_NETWORK_CLASS;
	ev_msg.kev_subclass     = KEV_NETEVENT_SUBCLASS;
	ev_msg.event_code       = KEV_NETEVENT_CLAT46_EVENT;

	bzero(&clat46_event_data, sizeof(clat46_event_data));
	clat46_event_data.clat46_event_code = in6_clat46_ev_code;
	clat46_event_data.epid = epid;
	uuid_copy(clat46_event_data.euuid, euuid);

	ev_msg.dv[0].data_ptr = &clat46_event_data;
	ev_msg.dv[0].data_length = sizeof(clat46_event_data);

	kev_post_msg(&ev_msg);
}

static void
in6_clat46_event_callback(void *arg)
{
	struct kev_netevent_clat46_data *p_in6_clat46_ev =
	    (struct kev_netevent_clat46_data *)arg;

	EVENTHANDLER_INVOKE(&in6_clat46_evhdlr_ctxt, in6_clat46_event,
	    p_in6_clat46_ev->clat46_event_code, p_in6_clat46_ev->epid,
	    p_in6_clat46_ev->euuid);
}

struct in6_clat46_event_nwk_wq_entry {
	struct nwk_wq_entry nwk_wqe;
	struct kev_netevent_clat46_data in6_clat46_ev_arg;
};

void
in6_clat46_event_enqueue_nwk_wq_entry(in6_clat46_evhdlr_code_t in6_clat46_event_code,
    pid_t epid, uuid_t euuid)
{
	struct in6_clat46_event_nwk_wq_entry *p_ev = NULL;

	MALLOC(p_ev, struct in6_clat46_event_nwk_wq_entry *,
	    sizeof(struct in6_clat46_event_nwk_wq_entry),
	    M_NWKWQ, M_WAITOK | M_ZERO);

	p_ev->nwk_wqe.func = in6_clat46_event_callback;
	p_ev->nwk_wqe.is_arg_managed = TRUE;
	p_ev->nwk_wqe.arg = &p_ev->in6_clat46_ev_arg;

	p_ev->in6_clat46_ev_arg.clat46_event_code = in6_clat46_event_code;
	p_ev->in6_clat46_ev_arg.epid = epid;
	uuid_copy(p_ev->in6_clat46_ev_arg.euuid, euuid);

	nwk_wq_enqueue((struct nwk_wq_entry*)p_ev);
}
