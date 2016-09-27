/*
 * Copyright (c) 2013-2016 Apple Inc. All rights reserved.
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

#ifndef	_NET_NECP_H_
#define	_NET_NECP_H_

#include <net/net_kev.h>
#ifdef PRIVATE

#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>

/*
 * Name registered by the ipsec kernel control
 */
#define	NECP_CONTROL_NAME "com.apple.net.necp_control"

#define NECP_TLV_LENGTH_UINT32	1

struct necp_packet_header {
    u_int8_t		packet_type;
	u_int8_t		flags;
    u_int32_t		message_id;
};

/*
 * Control message commands
 */
#define	NECP_PACKET_TYPE_POLICY_ADD				1
#define	NECP_PACKET_TYPE_POLICY_GET				2
#define	NECP_PACKET_TYPE_POLICY_DELETE			3
#define	NECP_PACKET_TYPE_POLICY_APPLY_ALL		4
#define	NECP_PACKET_TYPE_POLICY_LIST_ALL		5
#define	NECP_PACKET_TYPE_POLICY_DELETE_ALL		6
#define	NECP_PACKET_TYPE_SET_SESSION_PRIORITY	7
#define	NECP_PACKET_TYPE_LOCK_SESSION_TO_PROC	8
#define	NECP_PACKET_TYPE_REGISTER_SERVICE		9
#define	NECP_PACKET_TYPE_UNREGISTER_SERVICE		10
#define NECP_PACKET_TYPE_POLICY_DUMP_ALL		11

/*
 * Control message flags
 */
#define	NECP_PACKET_FLAGS_RESPONSE				0x01	// Used for acks, errors, and query responses

/*
 * Control message TLV types
 */
#define	NECP_TLV_NIL							0
#define	NECP_TLV_ERROR							1	// u_int32_t
#define	NECP_TLV_POLICY_ORDER					2	// u_int32_t
#define	NECP_TLV_POLICY_CONDITION				3
#define	NECP_TLV_POLICY_RESULT					4
#define	NECP_TLV_POLICY_ID						5	// u_int32_t
#define	NECP_TLV_SESSION_PRIORITY				6	// u_int32_t
#define	NECP_TLV_ATTRIBUTE_DOMAIN				7	// char[]
#define	NECP_TLV_ATTRIBUTE_ACCOUNT				8	// char[]
#define	NECP_TLV_SERVICE_UUID					9	// uuid_t
#define	NECP_TLV_ROUTE_RULE						10

/*
 * Control message TLV sent only by the kernel to userspace
 */
#define	NECP_TLV_POLICY_OWNER					100	// char []
#define	NECP_TLV_POLICY_DUMP					101
#define	NECP_TLV_POLICY_RESULT_STRING			102	// char []
#define	NECP_TLV_POLICY_SESSION_ORDER			103	// u_int32_t

/*
 * Condition flags
 */
#define	NECP_POLICY_CONDITION_FLAGS_NEGATIVE	0x01 // Negative

/*
 * Conditions
 * Used for setting policies as well as passing parameters to necp_match_policy.
 */
#define	NECP_POLICY_CONDITION_DEFAULT			0	// N/A, not valid with any other conditions
// Socket/Application conditions
#define	NECP_POLICY_CONDITION_APPLICATION		1	// uuid_t, uses effective UUID when possible
#define	NECP_POLICY_CONDITION_REAL_APPLICATION	2	// uuid_t, never uses effective UUID. Only valid with NECP_POLICY_CONDITION_APPLICATION
#define	NECP_POLICY_CONDITION_DOMAIN			3	// String, such as apple.com
#define	NECP_POLICY_CONDITION_ACCOUNT			4	// String
#define	NECP_POLICY_CONDITION_ENTITLEMENT		5	// String
#define	NECP_POLICY_CONDITION_PID				6	// pid_t
#define	NECP_POLICY_CONDITION_UID				7	// uid_t
#define	NECP_POLICY_CONDITION_ALL_INTERFACES	8	// N/A
#define	NECP_POLICY_CONDITION_BOUND_INTERFACE	9	// String
#define	NECP_POLICY_CONDITION_TRAFFIC_CLASS		10	// necp_policy_condition_tc_range
// Socket/IP conditions
#define	NECP_POLICY_CONDITION_IP_PROTOCOL		11	// u_int8_t
#define	NECP_POLICY_CONDITION_LOCAL_ADDR		12	// necp_policy_condition_addr
#define	NECP_POLICY_CONDITION_REMOTE_ADDR		13	// necp_policy_condition_addr
#define	NECP_POLICY_CONDITION_LOCAL_ADDR_RANGE	14	// necp_policy_condition_addr_range
#define	NECP_POLICY_CONDITION_REMOTE_ADDR_RANGE	15	// necp_policy_condition_addr_range

/*
 * Results
 */
#define	NECP_POLICY_RESULT_PASS					1	// N/A
#define	NECP_POLICY_RESULT_SKIP					2	// u_int32_t, policy order to skip to. 0 to skip all session policies.
#define	NECP_POLICY_RESULT_DROP					3	// N/A
#define	NECP_POLICY_RESULT_SOCKET_DIVERT		4	// u_int32_t, flow divert control unit
#define	NECP_POLICY_RESULT_SOCKET_FILTER		5	// u_int32_t, filter control unit
#define	NECP_POLICY_RESULT_IP_TUNNEL			6	// String, interface name
#define	NECP_POLICY_RESULT_IP_FILTER			7	// ?
#define	NECP_POLICY_RESULT_TRIGGER				8	// service uuid_t
#define	NECP_POLICY_RESULT_TRIGGER_IF_NEEDED	9	// service uuid_t
#define	NECP_POLICY_RESULT_TRIGGER_SCOPED		10	// service uuid_t
#define	NECP_POLICY_RESULT_NO_TRIGGER_SCOPED	11	// service uuid_t
#define	NECP_POLICY_RESULT_SOCKET_SCOPED		12	// String, interface name
#define	NECP_POLICY_RESULT_ROUTE_RULES			13	// N/A, must have route rules defined
#define	NECP_POLICY_RESULT_USE_NETAGENT			14	// netagent uuid_t

#define	NECP_POLICY_RESULT_MAX					NECP_POLICY_RESULT_USE_NETAGENT

/*
 * Route Rules
 * Detailed parameters for NECP_POLICY_RESULT_ROUTE_RULES.
 */
#define	NECP_ROUTE_RULE_NONE					0	// N/A
#define	NECP_ROUTE_RULE_DENY_INTERFACE			1	// String, or empty to match all
#define	NECP_ROUTE_RULE_ALLOW_INTERFACE			2	// String, or empty to match all
#define	NECP_ROUTE_RULE_QOS_MARKING		3	// String, or empty to match all

#define	NECP_ROUTE_RULE_FLAG_CELLULAR			0x01
#define	NECP_ROUTE_RULE_FLAG_WIFI				0x02
#define	NECP_ROUTE_RULE_FLAG_WIRED				0x04
#define	NECP_ROUTE_RULE_FLAG_EXPENSIVE			0x08

/*
 * Error types
 */
#define	NECP_ERROR_INTERNAL						0
#define	NECP_ERROR_UNKNOWN_PACKET_TYPE			1
#define	NECP_ERROR_INVALID_TLV					2
#define	NECP_ERROR_POLICY_RESULT_INVALID		3
#define	NECP_ERROR_POLICY_CONDITIONS_INVALID	4
#define	NECP_ERROR_POLICY_ID_NOT_FOUND			5
#define	NECP_ERROR_INVALID_PROCESS				6
#define	NECP_ERROR_ROUTE_RULES_INVALID			7

// Modifiers
#define	NECP_MASK_USERSPACE_ONLY	0x80000000	// on filter_control_unit value

struct necp_policy_condition_tc_range {
	u_int32_t start_tc;
	u_int32_t end_tc;
} __attribute__((__packed__));

struct necp_policy_condition_addr {
	u_int8_t		prefix;
	union {
		struct sockaddr			sa;
		struct sockaddr_in		sin;
		struct sockaddr_in6		sin6;
	} address;
} __attribute__((__packed__));

struct necp_policy_condition_addr_range {
	union {
		struct sockaddr			sa;
		struct sockaddr_in		sin;
		struct sockaddr_in6		sin6;
	} start_address;
	union {
		struct sockaddr			sa;
		struct sockaddr_in		sin;
		struct sockaddr_in6		sin6;
	} end_address;
} __attribute__((__packed__));

#define	NECP_SESSION_PRIORITY_UNKNOWN			0
#define	NECP_SESSION_PRIORITY_CONTROL			1
#define	NECP_SESSION_PRIORITY_PRIVILEGED_TUNNEL	2
#define	NECP_SESSION_PRIORITY_HIGH				3
#define	NECP_SESSION_PRIORITY_DEFAULT			4
#define	NECP_SESSION_PRIORITY_LOW				5

#define	NECP_SESSION_NUM_PRIORITIES				NECP_SESSION_PRIORITY_LOW

typedef u_int32_t necp_policy_id;
typedef u_int32_t necp_policy_order;

typedef u_int32_t necp_kernel_policy_result;
typedef u_int32_t necp_kernel_policy_filter;

typedef union {
	u_int						tunnel_interface_index;
	u_int						scoped_interface_index;
	u_int32_t					flow_divert_control_unit;
	u_int32_t					filter_control_unit;
} necp_kernel_policy_routing_result_parameter;

#define	NECP_SERVICE_FLAGS_REGISTERED			0x01
#define	NECP_MAX_NETAGENTS						8
struct necp_aggregate_result {
	necp_kernel_policy_result			routing_result;
	necp_kernel_policy_routing_result_parameter	routing_result_parameter;
	necp_kernel_policy_filter			filter_control_unit;
	necp_kernel_policy_result			service_action;
	uuid_t								service_uuid;
	u_int32_t							service_flags;
	u_int32_t							service_data;
	u_int								routed_interface_index;
	u_int32_t							policy_id;
	uuid_t								netagents[NECP_MAX_NETAGENTS];
	u_int32_t							netagent_flags[NECP_MAX_NETAGENTS];
};

/*
 * Statistics.  It would be nice if the definitions in ntstat.h could be used,
 * but they get entangled with #defines for v4 etc in pfvar.h and it may be better practice
 * to have separate definitions here.
 */
typedef struct necp_stat_counts
{
	/*	Counters	*/
	u_int64_t	necp_stat_rxpackets		__attribute__((aligned(8)));
	u_int64_t	necp_stat_rxbytes		__attribute__((aligned(8)));
	u_int64_t	necp_stat_txpackets		__attribute__((aligned(8)));
	u_int64_t	necp_stat_txbytes		__attribute__((aligned(8)));

	u_int32_t	necp_stat_rxduplicatebytes;
	u_int32_t	necp_stat_rxoutoforderbytes;
	u_int32_t	necp_stat_txretransmit;

	u_int32_t	necp_stat_connectattempts;
	u_int32_t	necp_stat_connectsuccesses;

	u_int32_t	necp_stat_min_rtt;
	u_int32_t	necp_stat_avg_rtt;
	u_int32_t	necp_stat_var_rtt;

	u_int64_t	necp_stat_cell_rxbytes	__attribute__((aligned(8)));
	u_int64_t	necp_stat_cell_txbytes	__attribute__((aligned(8)));
	u_int64_t	necp_stat_wifi_rxbytes	__attribute__((aligned(8)));
	u_int64_t	necp_stat_wifi_txbytes	__attribute__((aligned(8)));
	u_int64_t	necp_stat_wired_rxbytes	__attribute__((aligned(8)));
	u_int64_t	necp_stat_wired_txbytes	__attribute__((aligned(8)));
} necp_stat_counts;

// Note, some metadata is implicit in the necp client itself:
// From the process itself : pid, upid, uuid, proc name.
// From the necp client parameters: local and remote addresses, euuid, traffic class, ifindex
//
// The following may well be supplied via future necp client parameters,
// but they are here so they don't get forgotten.
typedef struct necp_basic_metadata
{
	u_int32_t	rcvbufsize;
	u_int32_t	rcvbufused;

	u_int64_t	eupid;	// Not currently used by NetworkStatistics, could skip.
	u_int32_t	epid;

	uuid_t		vuuid;	// Effective UUID as given from voucher
	uint16_t	ifnet_properties;
} necp_basic_metadata;

struct necp_tcp_probe_status {
	unsigned int	probe_activated : 1;
	unsigned int	write_probe_failed : 1;
	unsigned int	read_probe_failed : 1;
	unsigned int	conn_probe_failed : 1;
};

typedef struct necp_extra_tcp_metadata
{
	struct necp_tcp_probe_status probestatus;

	u_int32_t	sndbufsize;
	u_int32_t	sndbufused;
	u_int32_t	txunacked;
	u_int32_t	txwindow;
	u_int32_t	txcwindow;
	u_int32_t	traffic_mgt_flags;
	u_int32_t	cc_alg_index;
	u_int32_t	state;
} necp_extra_tcp_metadata;

typedef struct necp_stats_hdr {
	u_int32_t					necp_stats_type __attribute__((aligned(8)));
	u_int32_t					necp_stats_ver;
	u_int64_t					necp_stats_event;
} necp_stats_hdr;

#define	NECP_CLIENT_STATISTICS_TYPE_TCP				1	// Identifies use of necp_tcp_stats
#define	NECP_CLIENT_STATISTICS_TYPE_UDP				2	// Identifies use of necp_udp_stats
#define	NECP_CLIENT_STATISTICS_TYPE_TCP_VER_1		1	// Currently supported version for TCP
#define	NECP_CLIENT_STATISTICS_TYPE_UDP_VER_1		1	// Currently supported version for UDP

typedef struct necp_tcp_stats {
	necp_stats_hdr				necp_tcp_hdr;
	necp_stat_counts			necp_tcp_counts;
	necp_basic_metadata			necp_tcp_basic;
	necp_extra_tcp_metadata		necp_tcp_extra;
} necp_tcp_stats;

typedef struct necp_udp_stats {
	necp_stats_hdr				necp_udp_hdr;
	necp_stat_counts			necp_udp_counts;
	necp_basic_metadata			necp_udp_basic;
} necp_udp_stats;

typedef struct necp_all_stats {
	union {
		necp_tcp_stats			tcp_stats;
		necp_udp_stats			udp_stats;
	} all_stats_u;
} necp_all_stats;

/*
 * NECP Client definitions
 */
#define NECP_MAX_CLIENT_PARAMETERS_SIZE					1024
#define NECP_MAX_CLIENT_RESULT_SIZE						512

#define	NECP_OPEN_FLAG_OBSERVER							0x01 // Observers can query clients they don't own

#define	NECP_CLIENT_ACTION_ADD							1 // Register a new client. Input: parameters in buffer; Output: client_id
#define	NECP_CLIENT_ACTION_REMOVE						2 // Unregister a client. Input: client_id
#define	NECP_CLIENT_ACTION_COPY_PARAMETERS				3 // Copy client parameters. Input: client_id; Output: parameters in buffer
#define	NECP_CLIENT_ACTION_COPY_RESULT					4 // Copy client result. Input: client_id; Output: result in buffer
#define	NECP_CLIENT_ACTION_COPY_LIST					5 // Copy all client IDs. Output: struct necp_client_list in buffer
#define	NECP_CLIENT_ACTION_REQUEST_NEXUS_INSTANCE		6 // Request a nexus instance from a nexus provider
#define	NECP_CLIENT_ACTION_AGENT						7 // Interact with agent. Input: client_id, agent parameters
#define	NECP_CLIENT_ACTION_COPY_AGENT					8 // Copy agent content. Input: agent UUID; Output: struct netagent
#define	NECP_CLIENT_ACTION_COPY_INTERFACE				9 // Copy interface details. Input: ifindex cast to UUID; Output: struct necp_interface_details
#define	NECP_CLIENT_ACTION_SET_STATISTICS				10 // Start/update/complete per-flow statistics. Input: client_id, statistics area

#define	NECP_CLIENT_PARAMETER_APPLICATION				NECP_POLICY_CONDITION_APPLICATION		// Requires entitlement
#define	NECP_CLIENT_PARAMETER_REAL_APPLICATION			NECP_POLICY_CONDITION_REAL_APPLICATION	// Requires entitlement
#define	NECP_CLIENT_PARAMETER_DOMAIN					NECP_POLICY_CONDITION_DOMAIN
#define	NECP_CLIENT_PARAMETER_ACCOUNT					NECP_POLICY_CONDITION_ACCOUNT
#define	NECP_CLIENT_PARAMETER_PID						NECP_POLICY_CONDITION_PID				// Requires entitlement
#define	NECP_CLIENT_PARAMETER_UID						NECP_POLICY_CONDITION_UID				// Requires entitlement
#define	NECP_CLIENT_PARAMETER_BOUND_INTERFACE			NECP_POLICY_CONDITION_BOUND_INTERFACE
#define	NECP_CLIENT_PARAMETER_TRAFFIC_CLASS				NECP_POLICY_CONDITION_TRAFFIC_CLASS
#define	NECP_CLIENT_PARAMETER_IP_PROTOCOL				NECP_POLICY_CONDITION_IP_PROTOCOL
#define	NECP_CLIENT_PARAMETER_LOCAL_ADDRESS				NECP_POLICY_CONDITION_LOCAL_ADDR
#define	NECP_CLIENT_PARAMETER_REMOTE_ADDRESS			NECP_POLICY_CONDITION_REMOTE_ADDR

// "Prohibit" will never choose an interface with that property
#define	NECP_CLIENT_PARAMETER_PROHIBIT_INTERFACE		100		// String, interface name
#define	NECP_CLIENT_PARAMETER_PROHIBIT_IF_TYPE			101		// u_int8_t, see ifru_functional_type in <net/if.h>
#define	NECP_CLIENT_PARAMETER_PROHIBIT_AGENT			102		// uuid_t, network agent UUID
#define	NECP_CLIENT_PARAMETER_PROHIBIT_AGENT_TYPE		103		// struct necp_client_parameter_netagent_type

// "Require" will choose an interface with that property, or none if not found
#define	NECP_CLIENT_PARAMETER_REQUIRE_IF_TYPE			111		// u_int8_t, see ifru_functional_type in <net/if.h>
#define	NECP_CLIENT_PARAMETER_REQUIRE_AGENT				112		// uuid_t, network agent UUID
#define	NECP_CLIENT_PARAMETER_REQUIRE_AGENT_TYPE		113		// struct necp_client_parameter_netagent_type

// "Prefer" will choose an interface with that property, or best otherwise if not found
#define	NECP_CLIENT_PARAMETER_PREFER_AGENT				122		// uuid_t, network agent UUID
#define	NECP_CLIENT_PARAMETER_PREFER_AGENT_TYPE			123		// struct necp_client_parameter_netagent_type

// Use actions with NECP_CLIENT_ACTION_AGENT
#define	NECP_CLIENT_PARAMETER_TRIGGER_AGENT				130		// uuid_t, network agent UUID
#define	NECP_CLIENT_PARAMETER_ASSERT_AGENT				131		// uuid_t, network agent UUID
#define	NECP_CLIENT_PARAMETER_UNASSERT_AGENT			132		// uuid_t, network agent UUID

#define	NECP_CLIENT_PARAMETER_LOCAL_ENDPOINT			200		// struct necp_client_endpoint
#define	NECP_CLIENT_PARAMETER_REMOTE_ENDPOINT			201		// struct necp_client_endpoint
#define	NECP_CLIENT_PARAMETER_RESERVED_START			1000	// Parameters 1000 and higher are reserved for custom userspace options

#define	NECP_CLIENT_RESULT_CLIENT_ID					1		// uuid_t
#define	NECP_CLIENT_RESULT_POLICY_RESULT				2		// u_int32_t
#define	NECP_CLIENT_RESULT_POLICY_RESULT_PARAMETER		3		// u_int32_t
#define	NECP_CLIENT_RESULT_FILTER_CONTROL_UNIT			4		// u_int32_t
#define	NECP_CLIENT_RESULT_INTERFACE_INDEX				5		// u_int32_t
#define	NECP_CLIENT_RESULT_NETAGENT						6		// struct necp_client_result_netagent
#define	NECP_CLIENT_RESULT_FLAGS						7		// u_int32_t, see NECP_CLIENT_RESULT_FLAG_* values
#define	NECP_CLIENT_RESULT_INTERFACE					8		// struct necp_client_result_interface

#define	NECP_CLIENT_RESULT_NEXUS_INSTANCE				100		// uuid_t
#define	NECP_CLIENT_RESULT_NEXUS_PORT					101		// u_int16_t

#define	NECP_CLIENT_RESULT_LOCAL_ENDPOINT				200		// struct necp_client_endpoint
#define	NECP_CLIENT_RESULT_REMOTE_ENDPOINT				201		// struct necp_client_endpoint

#define	NECP_CLIENT_RESULT_FLAG_IS_LOCAL				0x0001	// Routes to this device
#define	NECP_CLIENT_RESULT_FLAG_IS_DIRECT				0x0002	// Routes to directly accessible peer
#define	NECP_CLIENT_RESULT_FLAG_HAS_IPV4				0x0004	// Supports IPv4
#define	NECP_CLIENT_RESULT_FLAG_HAS_IPV6				0x0008	// Supports IPv6

struct necp_interface_details {
	char name[IFXNAMSIZ];
	u_int32_t index;
	u_int32_t generation;
	u_int32_t functional_type;
	u_int32_t delegate_index;
	u_int32_t flags; // see NECP_INTERFACE_FLAG_*
	u_int32_t mtu;
	u_int8_t ipv4_signature[IFNET_SIGNATURELEN];
	u_int8_t ipv6_signature[IFNET_SIGNATURELEN];
};

#define	NECP_INTERFACE_FLAG_EXPENSIVE					0x0001

struct necp_client_parameter_netagent_type {
	char netagent_domain[32];
	char netagent_type[32];
};

struct necp_client_result_netagent {
	u_int32_t generation;
	uuid_t netagent_uuid;
};

struct necp_client_result_interface {
	u_int32_t generation;
	u_int32_t index;
};

struct necp_client_endpoint {
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
		struct {
			u_int8_t endpoint_length;
			u_int8_t endpoint_family; // Use AF_UNSPEC to target a name
			u_int16_t endpoint_port;
			u_int32_t endpoint_type; // Client-specific type
			char endpoint_data[0]; // Type-specific endpoint value
		} endpoint;
	} u;
};

struct necp_client_list {
	u_int32_t client_count;
	uuid_t clients[0];
};

struct kev_necp_policies_changed_data {
	u_int32_t		changed_count;	// Defaults to 0.
};

#ifdef BSD_KERNEL_PRIVATE
#include <stdbool.h>
#include <sys/socketvar.h>
#include <sys/kern_control.h>
#include <netinet/ip_var.h>
#include <netinet6/ip6_var.h>
#include <net/if_var.h>
#include <sys/syslog.h>
#include <net/network_agent.h>

#define	NECPLOG(level, format, ...) do {											\
	log((level > LOG_NOTICE ? LOG_NOTICE : level), "%s: " format "\n", __FUNCTION__, __VA_ARGS__); 	\
} while (0)

#define	NECPLOG0(level, msg) do {											\
	log((level > LOG_NOTICE ? LOG_NOTICE : level), "%s: %s\n", __FUNCTION__, msg); 	\
} while (0)

extern errno_t necp_client_init(void);
extern int necp_application_find_policy_match_internal(proc_t proc, u_int8_t *parameters, u_int32_t parameters_size,
												struct necp_aggregate_result *returned_result,
												u_int32_t *flags, u_int required_interface_index);
/*
 * TLV utilities
 *
 * Note that these functions (other than necp_buffer_find_tlv) do not check the length of the entire buffer,
 * so the caller must be sure that the entire TLV is within bounds.
 */
extern u_int8_t *necp_buffer_write_tlv(u_int8_t *buffer, u_int8_t type, u_int32_t length, const void *value);
extern u_int8_t *necp_buffer_write_tlv_if_different(u_int8_t *buffer, const u_int8_t *max, u_int8_t type,
													u_int32_t length, const void *value, bool *updated);
extern u_int8_t necp_buffer_get_tlv_type(u_int8_t *buffer, int tlv_offset);
extern u_int32_t necp_buffer_get_tlv_length(u_int8_t *buffer, int tlv_offset);
extern u_int8_t *necp_buffer_get_tlv_value(u_int8_t *buffer, int tlv_offset, u_int32_t *value_size);
extern int necp_buffer_find_tlv(u_int8_t *buffer, u_int32_t buffer_length, int offset, u_int8_t type, int next);

#define	NECPCTL_DROP_ALL_LEVEL				1	/* Drop all packets if no policy matches above this level */
#define	NECPCTL_DEBUG						2	/* Log all kernel policy matches */
#define	NECPCTL_PASS_LOOPBACK				3	/* Pass all loopback traffic */
#define	NECPCTL_PASS_KEEPALIVES				4	/* Pass all kernel-generated keepalive traffic */
#define	NECPCTL_SOCKET_POLICY_COUNT			5	/* Count of all socket-level policies */
#define	NECPCTL_SOCKET_NON_APP_POLICY_COUNT	6	/* Count of non-per-app socket-level policies */
#define	NECPCTL_IP_POLICY_COUNT				7	/* Count of all ip-level policies */
#define	NECPCTL_SESSION_COUNT				8	/* Count of NECP sessions */

#define	NECPCTL_NAMES {					\
	{ 0, 0 },							\
	{ "drop_all_level", CTLTYPE_INT },	\
	{ "debug", CTLTYPE_INT },			\
	{ "pass_loopback", CTLTYPE_INT },	\
	{ "pass_keepalives", CTLTYPE_INT },	\
}

typedef u_int32_t necp_kernel_policy_id;
#define	NECP_KERNEL_POLICY_ID_NONE			0
#define	NECP_KERNEL_POLICY_ID_NO_MATCH		1
#define	NECP_KERNEL_POLICY_ID_FIRST_VALID	2

typedef u_int32_t necp_app_id;

#define	NECP_KERNEL_POLICY_RESULT_NONE					0
#define	NECP_KERNEL_POLICY_RESULT_PASS					NECP_POLICY_RESULT_PASS
#define	NECP_KERNEL_POLICY_RESULT_SKIP					NECP_POLICY_RESULT_SKIP
#define	NECP_KERNEL_POLICY_RESULT_DROP					NECP_POLICY_RESULT_DROP
#define	NECP_KERNEL_POLICY_RESULT_SOCKET_DIVERT			NECP_POLICY_RESULT_SOCKET_DIVERT
#define	NECP_KERNEL_POLICY_RESULT_SOCKET_FILTER			NECP_POLICY_RESULT_SOCKET_FILTER
#define	NECP_KERNEL_POLICY_RESULT_IP_TUNNEL				NECP_POLICY_RESULT_IP_TUNNEL
#define	NECP_KERNEL_POLICY_RESULT_IP_FILTER				NECP_POLICY_RESULT_IP_FILTER
#define	NECP_KERNEL_POLICY_RESULT_TRIGGER				NECP_POLICY_RESULT_TRIGGER
#define	NECP_KERNEL_POLICY_RESULT_TRIGGER_IF_NEEDED		NECP_POLICY_RESULT_TRIGGER_IF_NEEDED
#define	NECP_KERNEL_POLICY_RESULT_TRIGGER_SCOPED		NECP_POLICY_RESULT_TRIGGER_SCOPED
#define	NECP_KERNEL_POLICY_RESULT_NO_TRIGGER_SCOPED		NECP_POLICY_RESULT_NO_TRIGGER_SCOPED
#define	NECP_KERNEL_POLICY_RESULT_SOCKET_SCOPED			NECP_POLICY_RESULT_SOCKET_SCOPED
#define	NECP_KERNEL_POLICY_RESULT_ROUTE_RULES			NECP_POLICY_RESULT_ROUTE_RULES
#define	NECP_KERNEL_POLICY_RESULT_USE_NETAGENT			NECP_POLICY_RESULT_USE_NETAGENT

typedef struct {
	u_int32_t identifier;
	u_int32_t data;
} necp_kernel_policy_service;

typedef union {
	u_int						tunnel_interface_index;
	u_int						scoped_interface_index;
	u_int32_t					flow_divert_control_unit;
	u_int32_t					filter_control_unit;
	u_int32_t					skip_policy_order;
	u_int32_t					route_rule_id;
	u_int32_t					netagent_id;
	necp_kernel_policy_service	service;
} necp_kernel_policy_result_parameter;

union necp_sockaddr_union {
	struct sockaddr			sa;
	struct sockaddr_in		sin;
	struct sockaddr_in6		sin6;
};

struct necp_kernel_socket_policy {
	LIST_ENTRY(necp_kernel_socket_policy)	chain;
	necp_policy_id				parent_policy_id;
	necp_kernel_policy_id		id;
	necp_policy_order			order;
	u_int32_t					session_order;
	int							session_pid;

	u_int32_t					condition_mask;
	u_int32_t					condition_negated_mask;
	necp_kernel_policy_id		cond_policy_id;
	u_int32_t					cond_app_id;					// Locally assigned ID value stored
	u_int32_t					cond_real_app_id;				// Locally assigned ID value stored
	char						*cond_custom_entitlement;		// String
	u_int32_t					cond_account_id;				// Locally assigned ID value stored
	char						*cond_domain;					// String
	u_int8_t					cond_domain_dot_count;			// Number of dots in cond_domain
	pid_t						cond_pid;
	uid_t						cond_uid;
	ifnet_t						cond_bound_interface;			// Matches specific binding only
	struct necp_policy_condition_tc_range cond_traffic_class;	// Matches traffic class in range
	u_int16_t					cond_protocol;					// Matches IP protcol number
	union necp_sockaddr_union	cond_local_start;				// Matches local IP address (or start)
	union necp_sockaddr_union	cond_local_end;					// Matches IP address range
	u_int8_t					cond_local_prefix;				// Defines subnet
	union necp_sockaddr_union	cond_remote_start;				// Matches remote IP address (or start)
	union necp_sockaddr_union	cond_remote_end;				// Matches IP address range
	u_int8_t					cond_remote_prefix;				// Defines subnet

	necp_kernel_policy_result	result;
	necp_kernel_policy_result_parameter	result_parameter;
};

struct necp_kernel_ip_output_policy {
	LIST_ENTRY(necp_kernel_ip_output_policy)	chain;
	necp_policy_id				parent_policy_id;
	necp_kernel_policy_id		id;
	necp_policy_order			suborder;
	necp_policy_order			order;
	u_int32_t					session_order;
	int							session_pid;

	u_int32_t					condition_mask;
	u_int32_t					condition_negated_mask;
	necp_kernel_policy_id		cond_policy_id;
	ifnet_t						cond_bound_interface;			// Matches specific binding only
	u_int16_t					cond_protocol;					// Matches IP protcol number
	union necp_sockaddr_union	cond_local_start;				// Matches local IP address (or start)
	union necp_sockaddr_union	cond_local_end;					// Matches IP address range
	u_int8_t					cond_local_prefix;				// Defines subnet
	union necp_sockaddr_union	cond_remote_start;				// Matches remote IP address (or start)
	union necp_sockaddr_union	cond_remote_end;				// Matches IP address range
	u_int8_t					cond_remote_prefix;				// Defines subnet
	u_int32_t					cond_last_interface_index;

	necp_kernel_policy_result	result;
	necp_kernel_policy_result_parameter	result_parameter;
};

#define	MAX_KERNEL_SOCKET_POLICIES			1
#define	MAX_KERNEL_IP_OUTPUT_POLICIES		4
struct necp_session_policy {
	LIST_ENTRY(necp_session_policy) chain;
	bool				applied;			// Applied into the kernel table
	bool				pending_deletion;	// Waiting to be removed from kernel table
	bool				pending_update;		// Policy has been modified since creation/last application
	necp_policy_id		id;
	necp_policy_order	order;
	u_int8_t			*result;
	u_int32_t			result_size;
	u_int8_t			*conditions; // Array of conditions, each with a u_int32_t length at start
	u_int32_t			conditions_size;
	u_int8_t			*route_rules; // Array of route rules, each with a u_int32_t length at start
	u_int32_t			route_rules_size;

	uuid_t				applied_app_uuid;
	uuid_t				applied_real_app_uuid;
	char				*applied_domain;
	char				*applied_account;

	uuid_t				applied_result_uuid;

	u_int32_t			applied_route_rules_id;

	necp_kernel_policy_id	kernel_socket_policies[MAX_KERNEL_SOCKET_POLICIES];
	necp_kernel_policy_id	kernel_ip_output_policies[MAX_KERNEL_IP_OUTPUT_POLICIES];
};

struct necp_aggregate_socket_result {
	necp_kernel_policy_result			result;
	necp_kernel_policy_result_parameter	result_parameter;
	necp_kernel_policy_filter			filter_control_unit;
	u_int32_t							route_rule_id;
	int32_t						qos_marking_gencount;
};

struct necp_inpcb_result {
	u_int32_t							app_id;
	necp_kernel_policy_id				policy_id;
	int32_t								policy_gencount;
	u_int32_t							flowhash;
	struct necp_aggregate_socket_result	results;
};

extern errno_t necp_init(void);

extern errno_t necp_set_socket_attributes(struct socket *so, struct sockopt *sopt);
extern errno_t necp_get_socket_attributes(struct socket *so, struct sockopt *sopt);
extern void necp_inpcb_dispose(struct inpcb *inp);

extern u_int32_t necp_socket_get_content_filter_control_unit(struct socket *so);

extern bool necp_socket_should_use_flow_divert(struct inpcb *inp);
extern u_int32_t necp_socket_get_flow_divert_control_unit(struct inpcb *inp);

extern bool necp_socket_should_rescope(struct inpcb *inp);
extern u_int necp_socket_get_rescope_if_index(struct inpcb *inp);
extern u_int32_t necp_socket_get_effective_mtu(struct inpcb *inp, u_int32_t current_mtu);

extern bool necp_socket_is_allowed_to_send_recv(struct inpcb *inp, necp_kernel_policy_id *return_policy_id,
												u_int32_t *return_route_rule_id);
extern bool necp_socket_is_allowed_to_send_recv_v4(struct inpcb *inp, u_int16_t local_port,
												   u_int16_t remote_port, struct in_addr *local_addr,
												   struct in_addr *remote_addr, ifnet_t interface,
												   necp_kernel_policy_id *return_policy_id, u_int32_t *return_route_rule_id);
extern bool necp_socket_is_allowed_to_send_recv_v6(struct inpcb *inp, u_int16_t local_port,
												   u_int16_t remote_port, struct in6_addr *local_addr,
												   struct in6_addr *remote_addr, ifnet_t interface,
												   necp_kernel_policy_id *return_policy_id, u_int32_t *return_route_rule_id);
extern void necp_socket_update_qos_marking(struct inpcb *inp, struct rtentry *route, struct ifnet *interface, u_int32_t route_rule_id);
extern int necp_mark_packet_from_socket(struct mbuf *packet, struct inpcb *inp, necp_kernel_policy_id policy_id,
										u_int32_t route_rule_id);
extern necp_kernel_policy_id necp_get_policy_id_from_packet(struct mbuf *packet);
extern u_int32_t necp_get_last_interface_index_from_packet(struct mbuf *packet);
extern u_int32_t necp_get_route_rule_id_from_packet(struct mbuf *packet);
extern int necp_get_app_uuid_from_packet(struct mbuf *packet,
										 uuid_t app_uuid);

extern necp_kernel_policy_id necp_socket_find_policy_match(struct inpcb *inp, struct sockaddr *override_local_addr,
														   struct sockaddr *override_remote_addr, u_int32_t override_bound_interface);
extern necp_kernel_policy_id necp_ip_output_find_policy_match(struct mbuf *packet, int flags, struct ip_out_args *ipoa,
															  necp_kernel_policy_result *result,
															  necp_kernel_policy_result_parameter *result_parameter);
extern necp_kernel_policy_id necp_ip6_output_find_policy_match(struct mbuf *packet, int flags, struct ip6_out_args *ip6oa,
															   necp_kernel_policy_result *result,
															   necp_kernel_policy_result_parameter *result_parameter);

extern int necp_mark_packet_from_ip(struct mbuf *packet, necp_kernel_policy_id policy_id);
extern int necp_mark_packet_from_interface(struct mbuf *packet, ifnet_t interface);

extern ifnet_t necp_get_ifnet_from_result_parameter(necp_kernel_policy_result_parameter *result_parameter);
extern bool necp_packet_can_rebind_to_ifnet(struct mbuf *packet, struct ifnet *interface, struct route *new_route, int family);

extern bool necp_packet_is_allowed_over_interface(struct mbuf *packet, struct ifnet *interface);

extern int necp_mark_packet_as_keepalive(struct mbuf *packet, bool is_keepalive);
extern bool necp_get_is_keepalive_from_packet(struct mbuf *packet);

extern void necp_update_all_clients(void); // Handle general re-evaluate event

extern void necp_force_update_client(uuid_t client_id, uuid_t remove_netagent_uuid); // Cause a single client to get an update event

extern int necp_assign_client_result(uuid_t netagent_uuid, uuid_t client_id,
									 u_int8_t *assigned_results, size_t assigned_results_length);

#endif /* BSD_KERNEL_PRIVATE */
#ifndef KERNEL

extern int necp_match_policy(const uint8_t *parameters, size_t parameters_size, struct necp_aggregate_result *returned_result);

extern int necp_open(int flags);

extern int necp_client_action(int necp_fd, uint32_t action, uuid_t client_id,
							  size_t client_id_len, uint8_t *buffer, size_t buffer_size);

#endif /* !KERNEL */

#endif /* PRIVATE */

#endif
