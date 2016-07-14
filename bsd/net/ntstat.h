/*
 * Copyright (c) 2010-2015 Apple Inc. All rights reserved.
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
#include <netinet/tcp.h>

#ifdef PRIVATE
#pragma pack(push, 4)
#pragma mark -- Common Data Structures --

#define __NSTAT_REVISION__	7

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
} __attribute__((packed)) nstat_sysinfo_keyval;

#define	NSTAT_SYSINFO_FLAG_SCALAR	0x0001
#define	NSTAT_SYSINFO_FLAG_DISTRIBUTION	0x0002

#define NSTAT_MAX_MSG_SIZE	4096

typedef struct nstat_sysinfo_counts
{
	/* Counters */
	u_int32_t	nstat_sysinfo_len;
	u_int32_t	pad;
	u_int8_t	nstat_sysinfo_keyvals[];
} __attribute__((packed)) nstat_sysinfo_counts;

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
	,NSTAT_SYSINFO_CONNECTION_ATTEMPTS	= 12
	,NSTAT_SYSINFO_CONNECTION_ACCEPTS	= 13
	,NSTAT_SYSINFO_ECN_CLIENT_SETUP		= 14
	,NSTAT_SYSINFO_ECN_SERVER_SETUP		= 15
	,NSTAT_SYSINFO_ECN_CLIENT_SUCCESS	= 16
	,NSTAT_SYSINFO_ECN_SERVER_SUCCESS	= 17
	,NSTAT_SYSINFO_ECN_NOT_SUPPORTED	= 18
	,NSTAT_SYSINFO_ECN_LOST_SYN		= 19
	,NSTAT_SYSINFO_ECN_LOST_SYNACK		= 20
	,NSTAT_SYSINFO_ECN_RECV_CE		= 21
	,NSTAT_SYSINFO_ECN_RECV_ECE		= 22
	,NSTAT_SYSINFO_ECN_SENT_ECE		= 23
	,NSTAT_SYSINFO_ECN_CONN_RECV_CE		= 24
	,NSTAT_SYSINFO_ECN_CONN_PLNOCE		= 25
	,NSTAT_SYSINFO_ECN_CONN_PL_CE		= 26
	,NSTAT_SYSINFO_ECN_CONN_NOPL_CE		= 27
	,NSTAT_SYSINFO_MBUF_16KB_TOTAL		= 28
	,NSTAT_SYSINFO_ECN_CLIENT_ENABLED	= 29
	,NSTAT_SYSINFO_ECN_SERVER_ENABLED	= 30
	,NSTAT_SYSINFO_ECN_CONN_RECV_ECE	= 31
	,NSTAT_SYSINFO_MBUF_MEM_RELEASED	= 32
	,NSTAT_SYSINFO_MBUF_DRAIN_CNT		= 33
	,NSTAT_SYSINFO_TFO_SYN_DATA_RCV		= 34
	,NSTAT_SYSINFO_TFO_COOKIE_REQ_RCV	= 35
	,NSTAT_SYSINFO_TFO_COOKIE_SENT		= 36
	,NSTAT_SYSINFO_TFO_COOKIE_INVALID	= 37
	,NSTAT_SYSINFO_TFO_COOKIE_REQ		= 38
	,NSTAT_SYSINFO_TFO_COOKIE_RCV		= 39
	,NSTAT_SYSINFO_TFO_SYN_DATA_SENT	= 40
	,NSTAT_SYSINFO_TFO_SYN_DATA_ACKED	= 41
	,NSTAT_SYSINFO_TFO_SYN_LOSS		= 42
	,NSTAT_SYSINFO_TFO_BLACKHOLE		= 43
	,NSTAT_SYSINFO_ECN_FALLBACK_SYNLOSS	= 44
	,NSTAT_SYSINFO_ECN_FALLBACK_REORDER	= 45
	,NSTAT_SYSINFO_ECN_FALLBACK_CE		= 46
	,NSTAT_SYSINFO_ECN_IFNET_TYPE		= 47
	,NSTAT_SYSINFO_ECN_IFNET_PROTO		= 48
	,NSTAT_SYSINFO_ECN_IFNET_CLIENT_SETUP	= 49
	,NSTAT_SYSINFO_ECN_IFNET_SERVER_SETUP	= 50
	,NSTAT_SYSINFO_ECN_IFNET_CLIENT_SUCCESS	= 51
	,NSTAT_SYSINFO_ECN_IFNET_SERVER_SUCCESS	= 52
	,NSTAT_SYSINFO_ECN_IFNET_PEER_NOSUPPORT	= 53
	,NSTAT_SYSINFO_ECN_IFNET_SYN_LOST	= 54
	,NSTAT_SYSINFO_ECN_IFNET_SYNACK_LOST	= 55
	,NSTAT_SYSINFO_ECN_IFNET_RECV_CE	= 56
	,NSTAT_SYSINFO_ECN_IFNET_RECV_ECE	= 57
	,NSTAT_SYSINFO_ECN_IFNET_SENT_ECE	= 58
	,NSTAT_SYSINFO_ECN_IFNET_CONN_RECV_CE	= 59
	,NSTAT_SYSINFO_ECN_IFNET_CONN_RECV_ECE	= 60
	,NSTAT_SYSINFO_ECN_IFNET_CONN_PLNOCE	= 61
	,NSTAT_SYSINFO_ECN_IFNET_CONN_PLCE	= 62
	,NSTAT_SYSINFO_ECN_IFNET_CONN_NOPLCE	= 63
	,NSTAT_SYSINFO_ECN_IFNET_FALLBACK_SYNLOSS = 64
	,NSTAT_SYSINFO_ECN_IFNET_FALLBACK_REORDER = 65
	,NSTAT_SYSINFO_ECN_IFNET_FALLBACK_CE	= 66
	,NSTAT_SYSINFO_ECN_IFNET_ON_RTT_AVG	= 67
	,NSTAT_SYSINFO_ECN_IFNET_ON_RTT_VAR	= 68
	,NSTAT_SYSINFO_ECN_IFNET_ON_OOPERCENT	= 69
	,NSTAT_SYSINFO_ECN_IFNET_ON_SACK_EPISODE = 70
	,NSTAT_SYSINFO_ECN_IFNET_ON_REORDER_PERCENT = 71
	,NSTAT_SYSINFO_ECN_IFNET_ON_RXMIT_PERCENT = 72
	,NSTAT_SYSINFO_ECN_IFNET_ON_RXMIT_DROP	= 73
	,NSTAT_SYSINFO_ECN_IFNET_OFF_RTT_AVG	= 74
	,NSTAT_SYSINFO_ECN_IFNET_OFF_RTT_VAR	= 75
	,NSTAT_SYSINFO_ECN_IFNET_OFF_OOPERCENT	= 76
	,NSTAT_SYSINFO_ECN_IFNET_OFF_SACK_EPISODE = 77
	,NSTAT_SYSINFO_ECN_IFNET_OFF_REORDER_PERCENT = 78
	,NSTAT_SYSINFO_ECN_IFNET_OFF_RXMIT_PERCENT = 79
	,NSTAT_SYSINFO_ECN_IFNET_OFF_RXMIT_DROP = 80
	,NSTAT_SYSINFO_ECN_IFNET_ON_TOTAL_TXPKTS = 81
	,NSTAT_SYSINFO_ECN_IFNET_ON_TOTAL_RXMTPKTS = 82
	,NSTAT_SYSINFO_ECN_IFNET_ON_TOTAL_RXPKTS = 83
	,NSTAT_SYSINFO_ECN_IFNET_ON_TOTAL_OOPKTS = 84
	,NSTAT_SYSINFO_ECN_IFNET_ON_DROP_RST = 85
	,NSTAT_SYSINFO_ECN_IFNET_OFF_TOTAL_TXPKTS = 86
	,NSTAT_SYSINFO_ECN_IFNET_OFF_TOTAL_RXMTPKTS = 87
	,NSTAT_SYSINFO_ECN_IFNET_OFF_TOTAL_RXPKTS = 88
	,NSTAT_SYSINFO_ECN_IFNET_OFF_TOTAL_OOPKTS = 89
	,NSTAT_SYSINFO_ECN_IFNET_OFF_DROP_RST = 90
	,NSTAT_SYSINFO_ECN_IFNET_TOTAL_CONN = 91
// NSTAT_SYSINFO_ENUM_VERSION must be updated any time a value is added
#define	NSTAT_SYSINFO_ENUM_VERSION	20151208
};

#pragma mark -- Network Statistics Providers --


// Interface properties

#define NSTAT_IFNET_IS_UNKNOWN_TYPE      0x01
#define NSTAT_IFNET_IS_LOOPBACK          0x02
#define NSTAT_IFNET_IS_CELLULAR          0x04
#define NSTAT_IFNET_IS_WIFI              0x08
#define NSTAT_IFNET_IS_WIRED             0x10
#define NSTAT_IFNET_IS_AWDL              0x20
#define NSTAT_IFNET_IS_EXPENSIVE         0x40
#define NSTAT_IFNET_IS_VPN               0x80
#define NSTAT_IFNET_VIA_CELLFALLBACK     0x100


enum
{
	NSTAT_PROVIDER_NONE	= 0
	,NSTAT_PROVIDER_ROUTE	= 1
	,NSTAT_PROVIDER_TCP	= 2
	,NSTAT_PROVIDER_UDP	= 3
	,NSTAT_PROVIDER_IFNET	= 4
	,NSTAT_PROVIDER_SYSINFO = 5
};
#define NSTAT_PROVIDER_LAST NSTAT_PROVIDER_SYSINFO
#define NSTAT_PROVIDER_COUNT (NSTAT_PROVIDER_LAST+1)

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
	struct tcp_conn_status connstatus;
	uint16_t	ifnet_properties	__attribute__((aligned(4)));
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
	uint16_t	ifnet_properties;
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

typedef struct nstat_ifnet_desc_cellular_status
{
	u_int32_t valid_bitmask; /* indicates which fields are valid */
#define NSTAT_IFNET_DESC_CELL_LINK_QUALITY_METRIC_VALID		0x1
#define NSTAT_IFNET_DESC_CELL_UL_EFFECTIVE_BANDWIDTH_VALID	0x2
#define NSTAT_IFNET_DESC_CELL_UL_MAX_BANDWIDTH_VALID		0x4
#define NSTAT_IFNET_DESC_CELL_UL_MIN_LATENCY_VALID		0x8
#define NSTAT_IFNET_DESC_CELL_UL_EFFECTIVE_LATENCY_VALID	0x10
#define NSTAT_IFNET_DESC_CELL_UL_MAX_LATENCY_VALID		0x20
#define NSTAT_IFNET_DESC_CELL_UL_RETXT_LEVEL_VALID		0x40
#define NSTAT_IFNET_DESC_CELL_UL_BYTES_LOST_VALID		0x80
#define NSTAT_IFNET_DESC_CELL_UL_MIN_QUEUE_SIZE_VALID		0x100
#define NSTAT_IFNET_DESC_CELL_UL_AVG_QUEUE_SIZE_VALID		0x200
#define NSTAT_IFNET_DESC_CELL_UL_MAX_QUEUE_SIZE_VALID		0x400
#define NSTAT_IFNET_DESC_CELL_DL_EFFECTIVE_BANDWIDTH_VALID	0x800
#define NSTAT_IFNET_DESC_CELL_DL_MAX_BANDWIDTH_VALID		0x1000
#define NSTAT_IFNET_DESC_CELL_CONFIG_INACTIVITY_TIME_VALID	0x2000
#define NSTAT_IFNET_DESC_CELL_CONFIG_BACKOFF_TIME_VALID		0x4000
	u_int32_t link_quality_metric;
	u_int32_t ul_effective_bandwidth; /* Measured uplink bandwidth based on
					     current activity (bps) */
	u_int32_t ul_max_bandwidth; /* Maximum supported uplink bandwidth
				       (bps) */
	u_int32_t ul_min_latency; /* min expected uplink latency for first hop
				     (ms) */
	u_int32_t ul_effective_latency; /* current expected uplink latency for
					   first hop (ms) */
	u_int32_t ul_max_latency; /* max expected uplink latency first hop
				    (ms) */
	u_int32_t ul_retxt_level; /* Retransmission metric */
#define NSTAT_IFNET_DESC_CELL_UL_RETXT_LEVEL_NONE	1
#define NSTAT_IFNET_DESC_CELL_UL_RETXT_LEVEL_LOW	2
#define NSTAT_IFNET_DESC_CELL_UL_RETXT_LEVEL_MEDIUM	3
#define NSTAT_IFNET_DESC_CELL_UL_RETXT_LEVEL_HIGH	4

	u_int32_t ul_bytes_lost; /* % of total bytes lost on uplink in Q10
				    format */
	u_int32_t ul_min_queue_size; /* minimum bytes in queue */
	u_int32_t ul_avg_queue_size; /* average bytes in queue */
	u_int32_t ul_max_queue_size; /* maximum bytes in queue */
	u_int32_t dl_effective_bandwidth; /* Measured downlink bandwidth based
					     on current activity (bps) */
	u_int32_t dl_max_bandwidth; /* Maximum supported downlink bandwidth
				       (bps) */
	u_int32_t config_inactivity_time; /* ms */
	u_int32_t config_backoff_time; /* new connections backoff time in ms */
} nstat_ifnet_desc_cellular_status;

typedef struct nstat_ifnet_desc_wifi_status {
	u_int32_t valid_bitmask;
#define	NSTAT_IFNET_DESC_WIFI_LINK_QUALITY_METRIC_VALID		0x1
#define	NSTAT_IFNET_DESC_WIFI_UL_EFFECTIVE_BANDWIDTH_VALID	0x2
#define	NSTAT_IFNET_DESC_WIFI_UL_MAX_BANDWIDTH_VALID		0x4
#define	NSTAT_IFNET_DESC_WIFI_UL_MIN_LATENCY_VALID		0x8
#define	NSTAT_IFNET_DESC_WIFI_UL_EFFECTIVE_LATENCY_VALID	0x10
#define	NSTAT_IFNET_DESC_WIFI_UL_MAX_LATENCY_VALID		0x20
#define	NSTAT_IFNET_DESC_WIFI_UL_RETXT_LEVEL_VALID		0x40
#define	NSTAT_IFNET_DESC_WIFI_UL_ERROR_RATE_VALID		0x80
#define	NSTAT_IFNET_DESC_WIFI_UL_BYTES_LOST_VALID		0x100
#define	NSTAT_IFNET_DESC_WIFI_DL_EFFECTIVE_BANDWIDTH_VALID	0x200
#define	NSTAT_IFNET_DESC_WIFI_DL_MAX_BANDWIDTH_VALID		0x400
#define	NSTAT_IFNET_DESC_WIFI_DL_MIN_LATENCY_VALID		0x800
#define	NSTAT_IFNET_DESC_WIFI_DL_EFFECTIVE_LATENCY_VALID	0x1000
#define	NSTAT_IFNET_DESC_WIFI_DL_MAX_LATENCY_VALID		0x2000
#define	NSTAT_IFNET_DESC_WIFI_DL_ERROR_RATE_VALID		0x4000
#define	NSTAT_IFNET_DESC_WIFI_CONFIG_FREQUENCY_VALID		0x8000
#define	NSTAT_IFNET_DESC_WIFI_CONFIG_MULTICAST_RATE_VALID	0x10000
#define	NSTAT_IFNET_DESC_WIFI_CONFIG_SCAN_COUNT_VALID		0x20000
#define	NSTAT_IFNET_DESC_WIFI_CONFIG_SCAN_DURATION_VALID	0x40000
	u_int32_t link_quality_metric; /* link quality metric */
	u_int32_t ul_effective_bandwidth; /* Measured uplink bandwidth based on
					     current activity (bps) */
	u_int32_t ul_max_bandwidth; /* Maximum supported uplink bandwidth
				       (bps) */
	u_int32_t ul_min_latency; /* min expected uplink latency for first hop
				     (ms) */
	u_int32_t ul_effective_latency; /* current expected uplink latency for
					   first hop (ms) */
	u_int32_t ul_max_latency; /* max expected uplink latency for first hop
				     (ms) */
	u_int32_t ul_retxt_level; /* Retransmission metric */
#define NSTAT_IFNET_DESC_WIFI_UL_RETXT_LEVEL_NONE	1
#define NSTAT_IFNET_DESC_WIFI_UL_RETXT_LEVEL_LOW	2
#define NSTAT_IFNET_DESC_WIFI_UL_RETXT_LEVEL_MEDIUM	3
#define NSTAT_IFNET_DESC_WIFI_UL_RETXT_LEVEL_HIGH	4

	u_int32_t ul_bytes_lost; /* % of total bytes lost on uplink in Q10
				    format */
	u_int32_t ul_error_rate; /* % of bytes dropped on uplink after many
				    retransmissions in Q10 format */
	u_int32_t dl_effective_bandwidth; /* Measured downlink bandwidth based
					     on current activity (bps) */
	u_int32_t dl_max_bandwidth; /* Maximum supported downlink bandwidth
				       (bps) */
	/*
	 * The download latency values indicate the time AP may have to wait
	 * for the  driver to receive the packet. These values give the range
	 * of expected latency mainly due to co-existence events and channel
	 * hopping where the interface becomes unavailable.
	 */
	u_int32_t dl_min_latency; /* min expected latency for first hop in ms */
	u_int32_t dl_effective_latency; /* current expected latency for first
					   hop in ms */
	u_int32_t dl_max_latency; /* max expected latency for first hop in ms */
	u_int32_t dl_error_rate; /* % of CRC or other errors in Q10 format */
	u_int32_t config_frequency; /* 2.4 or 5 GHz */
#define	NSTAT_IFNET_DESC_WIFI_CONFIG_FREQUENCY_2_4_GHZ	1
#define	NSTAT_IFNET_DESC_WIFI_CONFIG_FREQUENCY_5_0_GHZ	2
	u_int32_t config_multicast_rate; /* bps */
	u_int32_t scan_count; /* scan count during the previous period */
	u_int32_t scan_duration; /* scan duration in ms */
} nstat_ifnet_desc_wifi_status;

enum
{
	NSTAT_IFNET_DESC_LINK_STATUS_TYPE_NONE = 0
	,NSTAT_IFNET_DESC_LINK_STATUS_TYPE_CELLULAR = 1
	,NSTAT_IFNET_DESC_LINK_STATUS_TYPE_WIFI	= 2
};

typedef struct nstat_ifnet_desc_link_status
{
	u_int32_t	link_status_type;
	union {
		nstat_ifnet_desc_cellular_status	cellular;
		nstat_ifnet_desc_wifi_status		wifi;
	} u;
} nstat_ifnet_desc_link_status;

#ifndef	IF_DESCSIZE
#define	IF_DESCSIZE 128
#endif
typedef struct nstat_ifnet_descriptor
{
	char				name[IFNAMSIZ+1];
	u_int32_t			ifindex;
	u_int64_t			threshold;
	unsigned int			type;
	char				description[IF_DESCSIZE];
	nstat_ifnet_desc_link_status	link_status;
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
#define NSTAT_SYSINFO_IFNET_ECN_STATS	0x0003

#pragma mark -- Network Statistics User Client --

#define	NET_STAT_CONTROL_NAME	"com.apple.network.statistics"

enum
{
	// generic response messages
	NSTAT_MSG_TYPE_SUCCESS			= 0
	,NSTAT_MSG_TYPE_ERROR			= 1
	
	// Requests
	,NSTAT_MSG_TYPE_ADD_SRC				= 1001
	,NSTAT_MSG_TYPE_ADD_ALL_SRCS		= 1002
	,NSTAT_MSG_TYPE_REM_SRC				= 1003
	,NSTAT_MSG_TYPE_QUERY_SRC			= 1004
	,NSTAT_MSG_TYPE_GET_SRC_DESC		= 1005
	,NSTAT_MSG_TYPE_SET_FILTER 			= 1006
	,NSTAT_MSG_TYPE_GET_UPDATE			= 1007
	,NSTAT_MSG_TYPE_SUBSCRIBE_SYSINFO	= 1008
	
	// Responses/Notfications
	,NSTAT_MSG_TYPE_SRC_ADDED				= 10001
	,NSTAT_MSG_TYPE_SRC_REMOVED				= 10002
	,NSTAT_MSG_TYPE_SRC_DESC				= 10003
	,NSTAT_MSG_TYPE_SRC_COUNTS				= 10004
	,NSTAT_MSG_TYPE_SYSINFO_COUNTS			= 10005
	,NSTAT_MSG_TYPE_SRC_UPDATE				= 10006
};

enum
{
	NSTAT_SRC_REF_ALL	= 0xffffffff
	,NSTAT_SRC_REF_INVALID	= 0
};

/* Source-level filters */
enum
{
	NSTAT_FILTER_NOZEROBYTES             = 0x00000001
};

/* Provider-level filters */
enum
{
	NSTAT_FILTER_ACCEPT_UNKNOWN          = 0x00000001
	,NSTAT_FILTER_ACCEPT_LOOPBACK        = 0x00000002
	,NSTAT_FILTER_ACCEPT_CELLULAR        = 0x00000004
	,NSTAT_FILTER_ACCEPT_WIFI            = 0x00000008
	,NSTAT_FILTER_ACCEPT_WIRED           = 0x00000010
	,NSTAT_FILTER_ACCEPT_ALL             = 0x0000001F
	,NSTAT_FILTER_IFNET_FLAGS            = 0x000000FF

	,NSTAT_FILTER_PROVIDER_NOZEROBYTES   = 0x00000100

	,NSTAT_FILTER_TCP_NO_LISTENER        = 0x00001000
	,NSTAT_FILTER_TCP_ONLY_LISTENER      = 0x00002000
	,NSTAT_FILTER_TCP_INTERFACE_ATTACH   = 0x00004000
	,NSTAT_FILTER_TCP_FLAGS              = 0x0000F000

	,NSTAT_FILTER_UDP_INTERFACE_ATTACH   = 0x00010000
	,NSTAT_FILTER_UDP_FLAGS              = 0x000F0000

	,NSTAT_FILTER_SUPPRESS_SRC_ADDED     = 0x00100000
	,NSTAT_FILTER_REQUIRE_SRC_ADDED      = 0x00200000
};

enum
{
	NSTAT_MSG_HDR_FLAG_SUPPORTS_AGGREGATE	= 1 << 0,
	NSTAT_MSG_HDR_FLAG_CONTINUATION		= 1 << 1,
	NSTAT_MSG_HDR_FLAG_CLOSING		= 1 << 2,
};

typedef struct nstat_msg_hdr
{
	u_int64_t	context;
	u_int32_t	type;
	u_int16_t	length;
	u_int16_t	flags;
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
	u_int64_t		filter;
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

typedef struct nstat_msg_src_update
{
	nstat_msg_hdr		hdr;
	nstat_src_ref_t		srcref;
	nstat_counts		counts;
	nstat_provider_id_t	provider;
	u_int8_t			data[];
} nstat_msg_src_update;

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
} __attribute__((packed)) nstat_msg_sysinfo_counts;

#pragma pack(pop)

#pragma mark -- Statitiscs about Network Statistics --

struct nstat_stats {
	u_int32_t nstat_successmsgfailures;
	u_int32_t nstat_sendcountfailures;
	u_int32_t nstat_sysinfofailures;
	u_int32_t nstat_srcupatefailures;
	u_int32_t nstat_descriptionfailures;
	u_int32_t nstat_msgremovedfailures;
	u_int32_t nstat_srcaddedfailures;
	u_int32_t nstat_msgerrorfailures;
	u_int32_t nstat_copy_descriptor_failures;
	u_int32_t nstat_provider_counts_failures;
	u_int32_t nstat_control_send_description_failures;
	u_int32_t nstat_control_send_goodbye_failures;
	u_int32_t nstat_flush_accumulated_msgs_failures;
	u_int32_t nstat_accumulate_msg_failures;
	u_int32_t nstat_control_cleanup_source_failures;
	u_int32_t nstat_handle_msg_failures;
};

#endif /* PRIVATE */

#ifdef XNU_KERNEL_PRIVATE
#include <sys/mcache.h>

#pragma mark -- System Information Internal Support --

typedef struct nstat_sysinfo_mbuf_stats
{
	u_int32_t		total_256b;	/* Peak usage, 256B pool */
	u_int32_t		total_2kb;	/* Peak usage, 2KB pool */
	u_int32_t		total_4kb;	/* Peak usage, 4KB pool */
	u_int32_t		total_16kb;	/* Peak usage, 16KB pool */
	u_int32_t		sbmb_total;	/* Total mbufs in sock buffer pool */
	u_int32_t		sb_atmbuflimit;	/* Memory limit reached for socket buffer autoscaling */
	u_int32_t		draincnt;	/* Number of times mbuf pool has been drained under memory pressure */
	u_int32_t		memreleased;	/* Memory (bytes) released from mbuf pool to VM */
} nstat_sysinfo_mbuf_stats;

typedef struct nstat_sysinfo_tcp_stats
{
	u_int32_t		ipv4_avgrtt; 	/* Average RTT for IPv4 */
	u_int32_t		ipv6_avgrtt;	/* Average RTT for IPv6 */
	u_int32_t		send_plr;	/* Average uplink packet loss rate */
	u_int32_t		recv_plr;	/* Average downlink packet loss rate */
	u_int32_t		send_tlrto_rate; /* Average rxt timeout after tail loss */
	u_int32_t		send_reorder_rate; /* Average packet reordering rate */
	u_int32_t		connection_attempts; /* TCP client connection attempts */
	u_int32_t		connection_accepts; /* TCP server connection accepts */
	u_int32_t		ecn_client_enabled; /* Global setting for ECN client side */
	u_int32_t		ecn_server_enabled; /* Global setting for ECN server side */
	u_int32_t		ecn_client_setup; /* Attempts to setup TCP client connection with ECN */
	u_int32_t		ecn_server_setup; /* Attempts to setup TCP server connection with ECN */
	u_int32_t		ecn_client_success; /* Number of successful negotiations of ECN for a client connection */
	u_int32_t		ecn_server_success; /* Number of successful negotiations of ECN for a server connection */
	u_int32_t		ecn_not_supported; /* Number of falbacks to Non-ECN, no support from peer */
	u_int32_t		ecn_lost_syn;	/* Number of SYNs lost with ECN bits */
	u_int32_t		ecn_lost_synack; /* Number of SYN-ACKs lost with ECN bits */
	u_int32_t		ecn_recv_ce;	/* Number of CEs received from network */
	u_int32_t		ecn_recv_ece;	/* Number of ECEs received from receiver */
	u_int32_t		ecn_sent_ece;	/* Number of ECEs sent in response to CE */
	u_int32_t		ecn_conn_recv_ce; /* Number of connections using ECN received CE at least once */
	u_int32_t		ecn_conn_recv_ece; /* Number of connections using ECN received ECE at least once */
	u_int32_t		ecn_conn_plnoce; /* Number of connections using ECN seen packet loss but never received CE */
	u_int32_t		ecn_conn_pl_ce; /* Number of connections using ECN seen packet loss and CE */
	u_int32_t		ecn_conn_nopl_ce; /* Number of connections using ECN with no packet loss but received CE */
	u_int32_t		ecn_fallback_synloss; /* Number of times we did fall back due to SYN-Loss */
	u_int32_t		ecn_fallback_reorder; /* Number of times we fallback because we detected the PAWS-issue */
	u_int32_t		ecn_fallback_ce; /* Number of times we fallback because we received too many CEs */
	u_int32_t		tfo_syn_data_rcv;	/* Number of SYN+data received with valid cookie */
	u_int32_t		tfo_cookie_req_rcv;/* Number of TFO cookie-requests received */
	u_int32_t		tfo_cookie_sent;	/* Number of TFO-cookies offered to the client */
	u_int32_t		tfo_cookie_invalid;/* Number of invalid TFO-cookies received */
	u_int32_t		tfo_cookie_req;	/* Number of SYNs with cookie request received*/
	u_int32_t		tfo_cookie_rcv;	/* Number of SYN/ACKs with Cookie received */
	u_int32_t		tfo_syn_data_sent;	/* Number of SYNs+data+cookie sent */
	u_int32_t		tfo_syn_data_acked;/* Number of times our SYN+data has been acknowledged */
	u_int32_t		tfo_syn_loss;	/* Number of times SYN+TFO has been lost and we fallback */
	u_int32_t		tfo_blackhole;	/* Number of times SYN+TFO has been lost and we fallback */
} nstat_sysinfo_tcp_stats;

enum {
	NSTAT_IFNET_ECN_PROTO_IPV4 = 1
	,NSTAT_IFNET_ECN_PROTO_IPV6
};

enum {
	NSTAT_IFNET_ECN_TYPE_CELLULAR = 1
	,NSTAT_IFNET_ECN_TYPE_WIFI
	,NSTAT_IFNET_ECN_TYPE_ETHERNET
};

typedef struct nstat_sysinfo_ifnet_ecn_stats {
	u_int32_t			ifnet_proto;
	u_int32_t			ifnet_type;
	struct if_tcp_ecn_stat		ecn_stat;
} nstat_sysinfo_ifnet_ecn_stats;

typedef struct nstat_sysinfo_data
{
	u_int32_t		flags;
	union {
		nstat_sysinfo_mbuf_stats mb_stats;
		nstat_sysinfo_tcp_stats tcp_stats;
		nstat_sysinfo_ifnet_ecn_stats ifnet_ecn_stats;
	} u;
} nstat_sysinfo_data;

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
