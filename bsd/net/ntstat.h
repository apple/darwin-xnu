/*
 * Copyright (c) 2010-2014 Apple Inc. All rights reserved.
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
#ifndef __NTSTAT_H__
#define __NTSTAT_H__
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_var.h>

#ifdef PRIVATE
#pragma pack(push, 4)
#pragma mark -- Common Data Structures --

#define __NSTAT_REVISION__	6

typedef	u_int32_t	nstat_provider_id_t;
typedef	u_int32_t	nstat_src_ref_t;

typedef struct nstat_counts
{
	/* Counters */
	u_int64_t	nstat_rxpackets	__attribute__((aligned(8)));
	u_int64_t	nstat_rxbytes	__attribute__((aligned(8)));
	u_int64_t	nstat_txpackets	__attribute__((aligned(8)));
	u_int64_t	nstat_txbytes	__attribute__((aligned(8)));

	u_int32_t	nstat_rxduplicatebytes;
	u_int32_t	nstat_rxoutoforderbytes;
	u_int32_t	nstat_txretransmit;
	
	u_int32_t	nstat_connectattempts;
	u_int32_t	nstat_connectsuccesses;
	
	u_int32_t	nstat_min_rtt;
	u_int32_t	nstat_avg_rtt;
	u_int32_t	nstat_var_rtt;

	u_int64_t	nstat_cell_rxbytes	__attribute__((aligned(8)));
	u_int64_t	nstat_cell_txbytes	__attribute__((aligned(8)));
	u_int64_t	nstat_wifi_rxbytes	__attribute__((aligned(8)));
	u_int64_t	nstat_wifi_txbytes	__attribute__((aligned(8)));
	u_int64_t	nstat_wired_rxbytes	__attribute__((aligned(8)));
	u_int64_t	nstat_wired_txbytes	__attribute__((aligned(8)));
} nstat_counts;

typedef struct nstat_sysinfo_keyval
{
	u_int32_t	nstat_sysinfo_key;
	u_int32_t	nstat_sysinfo_flags;
	union {
			int64_t	nstat_sysinfo_scalar;
			double	nstat_sysinfo_distribution;
	} u;
} nstat_sysinfo_keyval;

#define	NSTAT_SYSINFO_FLAG_SCALAR	0x0001
#define	NSTAT_SYSINFO_FLAG_DISTRIBUTION	0x0002

typedef struct nstat_sysinfo_counts
{
	/* Counters */
	u_int32_t	nstat_sysinfo_len;
	u_int32_t	pad;
	u_int8_t	nstat_sysinfo_keyvals[];
} nstat_sysinfo_counts;

enum
{
	NSTAT_SYSINFO_KEY_MBUF_256B_TOTAL	= 1
	,NSTAT_SYSINFO_KEY_MBUF_2KB_TOTAL	= 2
	,NSTAT_SYSINFO_KEY_MBUF_4KB_TOTAL	= 3
	,NSTAT_SYSINFO_KEY_SOCK_MBCNT		= 4
	,NSTAT_SYSINFO_KEY_SOCK_ATMBLIMIT	= 5
	,NSTAT_SYSINFO_KEY_IPV4_AVGRTT		= 6
	,NSTAT_SYSINFO_KEY_IPV6_AVGRTT		= 7
	,NSTAT_SYSINFO_KEY_SEND_PLR		= 8
	,NSTAT_SYSINFO_KEY_RECV_PLR		= 9
	,NSTAT_SYSINFO_KEY_SEND_TLRTO		= 10
	,NSTAT_SYSINFO_KEY_SEND_REORDERRATE	= 11

};

#pragma mark -- Network Statistics Providers --

enum
{
	NSTAT_PROVIDER_ROUTE	= 1
	,NSTAT_PROVIDER_TCP	= 2
	,NSTAT_PROVIDER_UDP	= 3
	,NSTAT_PROVIDER_IFNET	= 4
	,NSTAT_PROVIDER_SYSINFO = 5
};

typedef struct nstat_route_add_param
{
	union
	{
		struct sockaddr_in	v4;
		struct sockaddr_in6	v6;
	} dst;
	union
	{
		struct sockaddr_in	v4;
		struct sockaddr_in6	v6;
	} mask;
	u_int32_t	ifindex;
} nstat_route_add_param;

typedef struct nstat_tcp_add_param
{
	union
	{
		struct sockaddr_in	v4;
		struct sockaddr_in6	v6;
	} local;
	union
	{
		struct sockaddr_in	v4;
		struct sockaddr_in6	v6;
	} remote;
} nstat_tcp_add_param;

typedef struct nstat_tcp_descriptor
{
	union
	{
		struct sockaddr_in	v4;
		struct sockaddr_in6	v6;
	} local;
	
	union
	{
		struct sockaddr_in	v4;
		struct sockaddr_in6	v6;
	} remote;
	
	u_int32_t	ifindex;
	
	u_int32_t	state;
	
	u_int32_t	sndbufsize;
	u_int32_t	sndbufused;
	u_int32_t	rcvbufsize;
	u_int32_t	rcvbufused;
	u_int32_t	txunacked;
	u_int32_t	txwindow;
	u_int32_t	txcwindow;
	u_int32_t	traffic_class;
	u_int32_t	traffic_mgt_flags;
	char		cc_algo[16];
	
	u_int64_t	upid;
	u_int32_t	pid;
	char		pname[64];
	u_int64_t	eupid;
	u_int32_t	epid;

	uint8_t		uuid[16];
	uint8_t		euuid[16];
	uint8_t		vuuid[16];
} nstat_tcp_descriptor;

typedef struct nstat_tcp_add_param	nstat_udp_add_param;

typedef struct nstat_udp_descriptor
{
	union
	{
		struct sockaddr_in	v4;
		struct sockaddr_in6	v6;
	} local;
	
	union
	{
		struct sockaddr_in	v4;
		struct sockaddr_in6	v6;
	} remote;
	
	u_int32_t	ifindex;
	
	u_int32_t	rcvbufsize;
	u_int32_t	rcvbufused;
	u_int32_t	traffic_class;
	
	u_int64_t	upid;
	u_int32_t	pid;
	char		pname[64];
	u_int64_t	eupid;
	u_int32_t	epid;

	uint8_t		uuid[16];
	uint8_t		euuid[16];
	uint8_t		vuuid[16];
} nstat_udp_descriptor;

typedef struct nstat_route_descriptor
{
	u_int64_t	id;
	u_int64_t	parent_id;
	u_int64_t	gateway_id;
	
	union
	{
		struct sockaddr_in	v4;
		struct sockaddr_in6	v6;
		struct sockaddr		sa;
	} dst;
	
	union
	{
		struct sockaddr_in	v4;
		struct sockaddr_in6	v6;
		struct sockaddr		sa;
	} mask;
	
	union
	{
		struct sockaddr_in	v4;
		struct sockaddr_in6	v6;
		struct sockaddr		sa;
	} gateway;
	
	u_int32_t	ifindex;
	u_int32_t	flags;
	
} nstat_route_descriptor;

typedef struct nstat_ifnet_add_param
{
	u_int32_t	ifindex;
	u_int64_t	threshold;
} nstat_ifnet_add_param;

#ifndef	IF_DESCSIZE
#define	IF_DESCSIZE 128
#endif
typedef struct nstat_ifnet_descriptor
{
	char			name[IFNAMSIZ+1];
	u_int32_t		ifindex;
	u_int64_t		threshold;
	unsigned int		type;
	char 			description[IF_DESCSIZE];
} nstat_ifnet_descriptor;

typedef struct nstat_sysinfo_descriptor
{
	u_int32_t	flags;
} nstat_sysinfo_descriptor;

typedef struct nstat_sysinfo_add_param
{
	/* To indicate which system level information should be collected */
	u_int32_t	flags;
} nstat_sysinfo_add_param;

#define	NSTAT_SYSINFO_MBUF_STATS	0x0001
#define	NSTAT_SYSINFO_TCP_STATS		0x0002	

#pragma mark -- Network Statistics User Client --

#define	NET_STAT_CONTROL_NAME	"com.apple.network.statistics"

enum
{
	// generic response messages
	NSTAT_MSG_TYPE_SUCCESS			= 0
	,NSTAT_MSG_TYPE_ERROR			= 1
	
	// Requests
	,NSTAT_MSG_TYPE_ADD_SRC			= 1001
	,NSTAT_MSG_TYPE_ADD_ALL_SRCS		= 1002
	,NSTAT_MSG_TYPE_REM_SRC			= 1003
	,NSTAT_MSG_TYPE_QUERY_SRC		= 1004
	,NSTAT_MSG_TYPE_GET_SRC_DESC		= 1005
	,NSTAT_MSG_TYPE_SET_FILTER 		= 1006
	
	// Responses/Notfications
	,NSTAT_MSG_TYPE_SRC_ADDED		= 10001
	,NSTAT_MSG_TYPE_SRC_REMOVED		= 10002
	,NSTAT_MSG_TYPE_SRC_DESC		= 10003
	,NSTAT_MSG_TYPE_SRC_COUNTS		= 10004
	,NSTAT_MSG_TYPE_SYSINFO_COUNTS		= 10005
};

enum
{
	NSTAT_SRC_REF_ALL	= 0xffffffff
	,NSTAT_SRC_REF_INVALID	= 0
};

enum
{
	NSTAT_FILTER_NOZEROBYTES = 0x01,
};

typedef struct nstat_msg_hdr
{
	u_int64_t	context;
	u_int32_t	type;
	u_int32_t	pad; // unused for now
} nstat_msg_hdr;

typedef struct nstat_msg_error
{
	nstat_msg_hdr	hdr;
	u_int32_t		error;	// errno error
} nstat_msg_error;

typedef struct nstat_msg_add_src
{
	nstat_msg_hdr		hdr;
	nstat_provider_id_t	provider;
	u_int8_t			param[];
} nstat_msg_add_src_req;

typedef struct nstat_msg_add_all_srcs
{
	nstat_msg_hdr		hdr;
	nstat_provider_id_t	provider;
} nstat_msg_add_all_srcs;

typedef struct nstat_msg_src_added
{
	nstat_msg_hdr		hdr;
	nstat_provider_id_t	provider;
	nstat_src_ref_t		srcref;
} nstat_msg_src_added;

typedef struct nstat_msg_rem_src
{
	nstat_msg_hdr		hdr;
	nstat_src_ref_t		srcref;
} nstat_msg_rem_src_req;

typedef struct nstat_msg_get_src_description
{
	nstat_msg_hdr		hdr;
	nstat_src_ref_t		srcref;
} nstat_msg_get_src_description;

typedef struct nstat_msg_set_filter
{
	nstat_msg_hdr		hdr;
	nstat_src_ref_t		srcref;
	u_int32_t		filter;
} nstat_msg_set_filter;

typedef struct nstat_msg_src_description
{
	nstat_msg_hdr		hdr;
	nstat_src_ref_t		srcref;
	nstat_provider_id_t	provider;
	u_int8_t			data[];
} nstat_msg_src_description;

typedef struct nstat_msg_query_src
{
	nstat_msg_hdr		hdr;
	nstat_src_ref_t		srcref;
} nstat_msg_query_src_req;

typedef struct nstat_msg_src_counts
{
	nstat_msg_hdr		hdr;
	nstat_src_ref_t		srcref;
	nstat_counts		counts;
} nstat_msg_src_counts;

typedef struct nstat_msg_src_removed
{
	nstat_msg_hdr		hdr;
	nstat_src_ref_t		srcref;
} nstat_msg_src_removed;

typedef struct nstat_msg_sysinfo_counts
{
	nstat_msg_hdr		hdr;
	nstat_src_ref_t		srcref;
	nstat_sysinfo_counts	counts;
} nstat_msg_sysinfo_counts;

typedef struct nstat_sysinfo_mbuf_stats
{
	u_int32_t		total_256b;
	u_int32_t		total_2kb;
	u_int32_t		total_4kb;
	u_int32_t		sbmb_total;
	u_int32_t		sb_atmbuflimit;
	u_int32_t		draincnt;
	u_int32_t		memreleased;
} nstat_sysinfo_mbuf_stats;

typedef struct nstat_sysinfo_tcp_stats
{
	u_int32_t		ipv4_avgrtt;
	u_int32_t		ipv6_avgrtt;
	u_int32_t		send_plr;
	u_int32_t		recv_plr;
	u_int32_t		send_tlrto_rate;
	u_int32_t		send_reorder_rate;
} nstat_sysinfo_tcp_stats;

typedef struct nstat_sysinfo_data
{
	u_int32_t		flags;
	union {
		nstat_sysinfo_mbuf_stats mb_stats;
		nstat_sysinfo_tcp_stats tcp_stats;
	} u;
} nstat_sysinfo_data;

#pragma pack(pop)

#endif /* PRIVATE */

#ifdef XNU_KERNEL_PRIVATE
#include <sys/mcache.h>

#pragma mark -- Generic Network Statistics Provider --

typedef	void *	nstat_provider_cookie_t;

#pragma mark -- Route Statistics Gathering Functions --
struct rtentry;

enum
{
	NSTAT_TX_FLAG_RETRANSMIT	= 1
};

enum
{
	NSTAT_RX_FLAG_DUPLICATE 	= 1,
	NSTAT_RX_FLAG_OUT_OF_ORDER	= 2
};

// indicates whether or not collection of statistics is enabled
extern int	nstat_collect;

void nstat_init(void);

// Route collection routines
void nstat_route_connect_attempt(struct rtentry *rte);
void nstat_route_connect_success(struct rtentry *rte);
void nstat_route_tx(struct rtentry *rte, u_int32_t packets, u_int32_t bytes, u_int32_t flags);
void nstat_route_rx(struct rtentry *rte, u_int32_t packets, u_int32_t bytes, u_int32_t flags);
void nstat_route_rtt(struct rtentry *rte, u_int32_t rtt, u_int32_t rtt_var);
void nstat_route_detach(struct rtentry *rte);

// watcher support
struct inpcb;
void nstat_tcp_new_pcb(struct inpcb *inp);
void nstat_udp_new_pcb(struct inpcb *inp);
void nstat_route_new_entry(struct rtentry *rt);
void nstat_pcb_detach(struct inpcb *inp);
void nstat_pcb_cache(struct inpcb *inp);
void nstat_pcb_invalidate_cache(struct inpcb *inp);


void nstat_ifnet_threshold_reached(unsigned int ifindex);

void nstat_sysinfo_send_data(struct nstat_sysinfo_data *);

// locked_add_64 uses atomic operations on 32bit so the 64bit
// value can be properly read. The values are only ever incremented
// while under the socket lock, so on 64bit we don't actually need
// atomic operations to increment.
#if defined(__LP64__)
#define	locked_add_64(__addr, __count) do { \
	*(__addr) += (__count); \
} while (0)
#else
#define	locked_add_64(__addr, __count) do { \
	atomic_add_64((__addr), (__count)); \
} while (0)
#endif

#endif /* XNU_KERNEL_PRIVATE */

#endif /* __NTSTAT_H__ */
