/*
 * Copyright (c) 2013, 2014 Apple Inc. All rights reserved.
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

#include <netinet/in.h>
#include <sys/socket.h>

/*
 * Name registered by the ipsec kernel control
 */
#define	NECP_CONTROL_NAME "com.apple.net.necp_control"

struct necp_packet_header {
    u_int8_t		packet_type;
	u_int8_t		flags;
    u_int32_t		message_id;
};
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

#define	NECP_PACKET_FLAGS_RESPONSE				0x01	// Used for acks, errors, and query responses

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

#define	NECP_POLICY_CONDITION_FLAGS_NEGATIVE	0x01 // Negative

// Conditions
#define	NECP_POLICY_CONDITION_DEFAULT			0	// N/A, not valid with any other conditions
// Socket/Application conditions
#define	NECP_POLICY_CONDITION_APPLICATION		1	// uuid_t, uses effective UUID when possible
#define	NECP_POLICY_CONDITION_REAL_APPLICATION	2	// uuid_t, never uses effective UUID. Only valid with NECP_POLICY_CONDITION_APPLICATION
// Application-only Conditions
#define	NECP_POLICY_CONDITION_DOMAIN			3	// String, such as apple.com
#define	NECP_POLICY_CONDITION_ACCOUNT			4	// String
// Socket/Application condition
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

// Results
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

#define	NECP_POLICY_RESULT_MAX					NECP_POLICY_RESULT_SOCKET_SCOPED

// Errors
#define	NECP_ERROR_INTERNAL						0
#define	NECP_ERROR_UNKNOWN_PACKET_TYPE			1
#define	NECP_ERROR_INVALID_TLV					2
#define	NECP_ERROR_POLICY_RESULT_INVALID		3
#define	NECP_ERROR_POLICY_CONDITIONS_INVALID	4
#define	NECP_ERROR_POLICY_ID_NOT_FOUND			5
#define	NECP_ERROR_INVALID_PROCESS				6

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
struct necp_aggregate_result {
	necp_kernel_policy_result			routing_result;
	necp_kernel_policy_routing_result_parameter	routing_result_parameter;
	necp_kernel_policy_filter			filter_control_unit;
	necp_kernel_policy_result			service_action;
	uuid_t								service_uuid;
	u_int32_t							service_flags;
	u_int32_t							service_data;
};

#ifdef BSD_KERNEL_PRIVATE
#include <stdbool.h>
#include <sys/socketvar.h>
#include <sys/kern_control.h>
#include <netinet/ip_var.h>
#include <netinet6/ip6_var.h>

#define	NECPCTL_DROP_ALL_LEVEL			1	/* Drop all packets if no policy matches above this level */
#define	NECPCTL_DEBUG					2	/* Log all kernel policy matches */
#define	NECPCTL_PASS_LOOPBACK			3	/* Pass all loopback traffic */
#define	NECPCTL_PASS_KEEPALIVES			4	/* Pass all kernel-generated keepalive traffic */

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
	
	u_int32_t					condition_mask;
	u_int32_t					condition_negated_mask;
	necp_kernel_policy_id		cond_policy_id;
	u_int32_t					cond_app_id;					// Locally assigned ID value stored
	u_int32_t					cond_real_app_id;				// Locally assigned ID value stored
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
	size_t				result_size;
	u_int8_t			*conditions; // Array of conditions, each with a size_t length at start
	size_t				conditions_size;
	
	uuid_t				applied_app_uuid;
	uuid_t				applied_real_app_uuid;
	char				*applied_domain;
	char				*applied_account;
	
	uuid_t				applied_service_uuid;
	
	necp_kernel_policy_id	kernel_socket_policies[MAX_KERNEL_SOCKET_POLICIES];
	necp_kernel_policy_id	kernel_ip_output_policies[MAX_KERNEL_IP_OUTPUT_POLICIES];
};

struct necp_aggregate_socket_result {
	necp_kernel_policy_result			result;
	necp_kernel_policy_result_parameter	result_parameter;
	necp_kernel_policy_filter			filter_control_unit;
};

struct necp_inpcb_result {
	char								*application_layer_domain;
	u_int32_t							application_layer_account_id;
	necp_kernel_policy_id				policy_id;
	int32_t								policy_gencount;
	u_int32_t							flowhash;
	struct necp_aggregate_socket_result	results;
};

errno_t necp_init(void);

errno_t necp_set_socket_attributes(struct socket *so, struct sockopt *sopt);
errno_t necp_get_socket_attributes(struct socket *so, struct sockopt *sopt);

u_int32_t necp_socket_get_content_filter_control_unit(struct socket *so);

bool necp_socket_should_use_flow_divert(struct inpcb *inp);
u_int32_t necp_socket_get_flow_divert_control_unit(struct inpcb *inp);

bool necp_socket_should_rescope(struct inpcb *inp);
u_int necp_socket_get_rescope_if_index(struct inpcb *inp);

bool necp_socket_is_allowed_to_send_recv(struct inpcb *inp, necp_kernel_policy_id *return_policy_id);
bool necp_socket_is_allowed_to_send_recv_v4(struct inpcb *inp, u_int16_t local_port, u_int16_t remote_port, struct in_addr *local_addr, struct in_addr *remote_addr, ifnet_t interface, necp_kernel_policy_id *return_policy_id);
bool necp_socket_is_allowed_to_send_recv_v6(struct inpcb *inp, u_int16_t local_port, u_int16_t remote_port, struct in6_addr *local_addr, struct in6_addr *remote_addr, ifnet_t interface, necp_kernel_policy_id *return_policy_id);
int necp_mark_packet_from_socket(struct mbuf *packet, struct inpcb *inp, necp_kernel_policy_id policy_id);
necp_kernel_policy_id necp_get_policy_id_from_packet(struct mbuf *packet);
u_int32_t necp_get_last_interface_index_from_packet(struct mbuf *packet);

necp_kernel_policy_id necp_socket_find_policy_match(struct inpcb *inp, struct sockaddr *override_local_addr, struct sockaddr *override_remote_addr, u_int32_t override_bound_interface);
necp_kernel_policy_id necp_ip_output_find_policy_match(struct mbuf *packet, int flags, struct ip_out_args *ipoa, necp_kernel_policy_result *result, necp_kernel_policy_result_parameter *result_parameter);
necp_kernel_policy_id necp_ip6_output_find_policy_match(struct mbuf *packet, int flags, struct ip6_out_args *ip6oa, necp_kernel_policy_result *result, necp_kernel_policy_result_parameter *result_parameter);

int necp_mark_packet_from_ip(struct mbuf *packet, necp_kernel_policy_id policy_id);
int necp_mark_packet_from_interface(struct mbuf *packet, ifnet_t interface);

ifnet_t necp_get_ifnet_from_result_parameter(necp_kernel_policy_result_parameter *result_parameter);
bool necp_packet_can_rebind_to_ifnet(struct mbuf *packet, struct ifnet *interface, struct route *new_route, int family);

int necp_mark_packet_as_keepalive(struct mbuf *packet, bool is_keepalive);
bool necp_get_is_keepalive_from_packet(struct mbuf *packet);

#endif /* BSD_KERNEL_PRIVATE */
#ifndef KERNEL
int necp_match_policy(const uint8_t *parameters, size_t parameters_size, struct necp_aggregate_result *returned_result);
#endif /* !KERNEL */

#endif
