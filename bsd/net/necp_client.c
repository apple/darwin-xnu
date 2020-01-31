/*
 * Copyright (c) 2015-2018 Apple Inc. All rights reserved.
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

#include <string.h>

#include <kern/thread_call.h>
#include <kern/zalloc.h>

#include <libkern/OSMalloc.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/net_api_stats.h>
#include <net/necp.h>
#include <net/network_agent.h>
#include <net/ntstat.h>

#include <netinet/in_pcb.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/mp_pcb.h>
#include <netinet/tcp_cc.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_cache.h>
#include <netinet6/in6_var.h>

#include <sys/domain.h>
#include <sys/file_internal.h>
#include <sys/kauth.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/poll.h>
#include <sys/priv.h>
#include <sys/protosw.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/codesign.h>
#include <libkern/section_keywords.h>


/*
 * NECP Client Architecture
 * ------------------------------------------------
 * See <net/necp.c> for a discussion on NECP database architecture.
 *
 * Each client of NECP provides a set of parameters for a connection or network state
 * evaluation, on which NECP policy evaluation is run. This produces a policy result
 * which can be accessed by the originating process, along with events for when policies
 * results have changed.
 *
 * ------------------------------------------------
 * NECP Client FD
 * ------------------------------------------------
 * A process opens an NECP file descriptor using necp_open(). This is a very simple
 * file descriptor, upon which the process may do the following operations:
 *   - necp_client_action(...), to add/remove/query clients
 *   - kqueue, to watch for readable events
 *   - close(), to close the client session and release all clients
 *
 * Client objects are allocated structures that hang off of the file descriptor. Each
 * client contains:
 *   - Client ID, a UUID that references the client across the system
 *   - Parameters, a buffer of TLVs that describe the client's connection parameters,
 *       such as the remote and local endpoints, interface requirements, etc.
 *   - Result, a buffer of TLVs containing the current policy evaluation for the client.
 *       This result will be updated whenever a network change occurs that impacts the
 *       policy result for that client.
 *
 *                   +--------------+
 *                   |   NECP fd    |
 *                   +--------------+
 *                          ||
 *          ==================================
 *          ||              ||              ||
 *  +--------------+ +--------------+ +--------------+
 *  |   Client ID  | |   Client ID  | |   Client ID  |
 *  |     ----     | |     ----     | |     ----     |
 *  |  Parameters  | |  Parameters  | |  Parameters  |
 *  |     ----     | |     ----     | |     ----     |
 *  |    Result    | |    Result    | |    Result    |
 *  +--------------+ +--------------+ +--------------+
 *
 * ------------------------------------------------
 * Client Actions
 * ------------------------------------------------
 *   - Add. Input parameters as a buffer of TLVs, and output a client ID. Allocates a
 *       new client structure on the file descriptor.
 *   - Remove. Input a client ID. Removes a client structure from the file descriptor.
 *   - Copy Parameters. Input a client ID, and output parameter TLVs.
 *   - Copy Result. Input a client ID, and output result TLVs. Alternatively, input empty
 *       client ID and get next unread client result.
 *   - Copy List. List all client IDs.
 *
 * ------------------------------------------------
 * Client Policy Evaluation
 * ------------------------------------------------
 * Policies are evaluated for clients upon client creation, and upon update events,
 * which are network/agent/policy changes coalesced by a timer.
 *
 * The policy evaluation goes through the following steps:
 *   1. Parse client parameters.
 *   2. Select a scoped interface if applicable. This involves using require/prohibit
 *      parameters, along with the local address, to select the most appropriate interface
 *      if not explicitly set by the client parameters.
 *   3. Run NECP application-level policy evalution
 *   4. Set policy result into client result buffer.
 *
 * ------------------------------------------------
 * Client Observers
 * ------------------------------------------------
 * If necp_open() is called with the NECP_OPEN_FLAG_OBSERVER flag, and the process
 * passes the necessary privilege check, the fd is allowed to use necp_client_action()
 * to copy client state attached to the file descriptors of other processes, and to
 * list all client IDs on the system.
 */

extern u_int32_t necp_debug;

static int noop_read(struct fileproc *, struct uio *, int, vfs_context_t);
static int noop_write(struct fileproc *, struct uio *, int, vfs_context_t);
static int noop_ioctl(struct fileproc *, unsigned long, caddr_t,
    vfs_context_t);
static int necpop_select(struct fileproc *, int, void *, vfs_context_t);
static int necpop_close(struct fileglob *, vfs_context_t);
static int necpop_kqfilter(struct fileproc *, struct knote *,
    struct kevent_internal_s *kev, vfs_context_t);

// Timer functions
static int necp_timeout_microseconds = 1000 * 100; // 100ms
static int necp_timeout_leeway_microseconds = 1000 * 500; // 500ms

static int necp_client_fd_count = 0;
static int necp_observer_fd_count = 0;
static int necp_client_count = 0;
static int necp_socket_flow_count = 0;
static int necp_if_flow_count = 0;
static int necp_observer_message_limit = 256;

SYSCTL_INT(_net_necp, NECPCTL_CLIENT_FD_COUNT, client_fd_count, CTLFLAG_LOCKED | CTLFLAG_RD, &necp_client_fd_count, 0, "");
SYSCTL_INT(_net_necp, NECPCTL_OBSERVER_FD_COUNT, observer_fd_count, CTLFLAG_LOCKED | CTLFLAG_RD, &necp_observer_fd_count, 0, "");
SYSCTL_INT(_net_necp, NECPCTL_CLIENT_COUNT, client_count, CTLFLAG_LOCKED | CTLFLAG_RD, &necp_client_count, 0, "");
SYSCTL_INT(_net_necp, NECPCTL_SOCKET_FLOW_COUNT, socket_flow_count, CTLFLAG_LOCKED | CTLFLAG_RD, &necp_socket_flow_count, 0, "");
SYSCTL_INT(_net_necp, NECPCTL_IF_FLOW_COUNT, if_flow_count, CTLFLAG_LOCKED | CTLFLAG_RD, &necp_if_flow_count, 0, "");
SYSCTL_INT(_net_necp, NECPCTL_OBSERVER_MESSAGE_LIMIT, observer_message_limit, CTLFLAG_LOCKED | CTLFLAG_RW, &necp_observer_message_limit, 256, "");

#define NECP_MAX_CLIENT_LIST_SIZE               1024 * 1024 // 1MB
#define NECP_MAX_AGENT_ACTION_SIZE              256

extern int tvtohz(struct timeval *);
extern unsigned int get_maxmtu(struct rtentry *);

// Parsed parameters
#define NECP_PARSED_PARAMETERS_FIELD_LOCAL_ADDR                         0x00001
#define NECP_PARSED_PARAMETERS_FIELD_REMOTE_ADDR                        0x00002
#define NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IF                        0x00004
#define NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_IF                      0x00008
#define NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IFTYPE            0x00010
#define NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_IFTYPE          0x00020
#define NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT                     0x00040
#define NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_AGENT           0x00080
#define NECP_PARSED_PARAMETERS_FIELD_PREFERRED_AGENT            0x00100
#define NECP_PARSED_PARAMETERS_FIELD_AVOIDED_AGENT                      0x00200
#define NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT_TYPE        0x00400
#define NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_AGENT_TYPE      0x00800
#define NECP_PARSED_PARAMETERS_FIELD_PREFERRED_AGENT_TYPE       0x01000
#define NECP_PARSED_PARAMETERS_FIELD_AVOIDED_AGENT_TYPE         0x02000
#define NECP_PARSED_PARAMETERS_FIELD_FLAGS                                      0x04000
#define NECP_PARSED_PARAMETERS_FIELD_IP_PROTOCOL                        0x08000
#define NECP_PARSED_PARAMETERS_FIELD_EFFECTIVE_PID                      0x10000
#define NECP_PARSED_PARAMETERS_FIELD_EFFECTIVE_UUID                     0x20000
#define NECP_PARSED_PARAMETERS_FIELD_TRAFFIC_CLASS                      0x40000
#define NECP_PARSED_PARAMETERS_FIELD_LOCAL_PORT                         0x80000

#define NECP_MAX_PARSED_PARAMETERS 16
struct necp_client_parsed_parameters {
	u_int32_t valid_fields;
	u_int32_t flags;
	union necp_sockaddr_union local_addr;
	union necp_sockaddr_union remote_addr;
	u_int32_t required_interface_index;
	char prohibited_interfaces[IFXNAMSIZ][NECP_MAX_PARSED_PARAMETERS];
	u_int8_t required_interface_type;
	u_int8_t prohibited_interface_types[NECP_MAX_PARSED_PARAMETERS];
	struct necp_client_parameter_netagent_type required_netagent_types[NECP_MAX_PARSED_PARAMETERS];
	struct necp_client_parameter_netagent_type prohibited_netagent_types[NECP_MAX_PARSED_PARAMETERS];
	struct necp_client_parameter_netagent_type preferred_netagent_types[NECP_MAX_PARSED_PARAMETERS];
	struct necp_client_parameter_netagent_type avoided_netagent_types[NECP_MAX_PARSED_PARAMETERS];
	uuid_t required_netagents[NECP_MAX_PARSED_PARAMETERS];
	uuid_t prohibited_netagents[NECP_MAX_PARSED_PARAMETERS];
	uuid_t preferred_netagents[NECP_MAX_PARSED_PARAMETERS];
	uuid_t avoided_netagents[NECP_MAX_PARSED_PARAMETERS];
	u_int16_t ip_protocol;
	pid_t effective_pid;
	uuid_t effective_uuid;
	u_int32_t traffic_class;
};

static bool
necp_find_matching_interface_index(struct necp_client_parsed_parameters *parsed_parameters,
    u_int *return_ifindex, bool *validate_agents);

static bool
necp_ifnet_matches_local_address(struct ifnet *ifp, struct sockaddr *sa);

static bool
necp_ifnet_matches_parameters(struct ifnet *ifp,
    struct necp_client_parsed_parameters *parsed_parameters,
    u_int32_t *preferred_count,
    bool secondary_interface);

static const struct fileops necp_fd_ops = {
	.fo_type = DTYPE_NETPOLICY,
	.fo_read = noop_read,
	.fo_write = noop_write,
	.fo_ioctl = noop_ioctl,
	.fo_select = necpop_select,
	.fo_close = necpop_close,
	.fo_kqfilter = necpop_kqfilter,
	.fo_drain = NULL,
};

struct necp_client_assertion {
	LIST_ENTRY(necp_client_assertion) assertion_chain;
	uuid_t asserted_netagent;
};

struct necp_client_flow_header {
	struct necp_tlv_header outer_header;
	struct necp_tlv_header flow_id_tlv_header;
	uuid_t flow_id;
	struct necp_tlv_header flags_tlv_header;
	u_int32_t flags_value;
	struct necp_tlv_header interface_tlv_header;
	struct necp_client_result_interface interface_value;
} __attribute__((__packed__));

struct necp_client_flow_protoctl_event_header {
	struct necp_tlv_header protoctl_tlv_header;
	struct necp_client_flow_protoctl_event protoctl_event;
} __attribute__((__packed__));

struct necp_client_nexus_flow_header {
	struct necp_client_flow_header flow_header;
	struct necp_tlv_header agent_tlv_header;
	struct necp_client_result_netagent agent_value;
	struct necp_tlv_header tfo_cookie_tlv_header;
	u_int8_t tfo_cookie_value[NECP_TFO_COOKIE_LEN_MAX];
} __attribute__((__packed__));


struct necp_client_flow {
	LIST_ENTRY(necp_client_flow) flow_chain;
	unsigned invalid : 1;
	unsigned nexus : 1; // If true, flow is a nexus; if false, flow is attached to socket
	unsigned socket : 1;
	unsigned viable : 1;
	unsigned assigned : 1;
	unsigned has_protoctl_event : 1;
	unsigned check_tcp_heuristics : 1;
	unsigned _reserved : 1;
	union {
		uuid_t nexus_agent;
		struct {
			void *socket_handle;
			necp_client_flow_cb cb;
		};
	} u;
	uint32_t interface_index;
	uint16_t interface_flags;
	uint32_t necp_flow_flags;
	struct necp_client_flow_protoctl_event protoctl_event;
	union necp_sockaddr_union local_addr;
	union necp_sockaddr_union remote_addr;

	size_t assigned_results_length;
	u_int8_t *assigned_results;
};

struct necp_client_flow_registration {
	RB_ENTRY(necp_client_flow_registration) fd_link;
	RB_ENTRY(necp_client_flow_registration) global_link;
	RB_ENTRY(necp_client_flow_registration) client_link;
	LIST_ENTRY(necp_client_flow_registration) collect_stats_chain;
	uuid_t registration_id;
	u_int32_t flags;
	unsigned flow_result_read : 1;
	unsigned defunct : 1;
	void *interface_handle;
	necp_client_flow_cb interface_cb;
	struct necp_client *client;
	LIST_HEAD(_necp_registration_flow_list, necp_client_flow) flow_list;
	u_int64_t last_interface_details __attribute__((aligned(sizeof(u_int64_t))));
};

static int necp_client_flow_id_cmp(struct necp_client_flow_registration *flow0, struct necp_client_flow_registration *flow1);

RB_HEAD(_necp_client_flow_tree, necp_client_flow_registration);
RB_PROTOTYPE_PREV(_necp_client_flow_tree, necp_client_flow_registration, client_link, necp_client_flow_id_cmp);
RB_GENERATE_PREV(_necp_client_flow_tree, necp_client_flow_registration, client_link, necp_client_flow_id_cmp);

#define NECP_CLIENT_INTERFACE_OPTION_STATIC_COUNT 4
#define NECP_CLIENT_MAX_INTERFACE_OPTIONS 16

#define NECP_CLIENT_INTERFACE_OPTION_EXTRA_COUNT (NECP_CLIENT_MAX_INTERFACE_OPTIONS - NECP_CLIENT_INTERFACE_OPTION_STATIC_COUNT)

struct necp_client {
	RB_ENTRY(necp_client) link;
	RB_ENTRY(necp_client) global_link;

	decl_lck_mtx_data(, lock);
	decl_lck_mtx_data(, route_lock);
	uint32_t reference_count;

	uuid_t client_id;
	unsigned result_read : 1;
	unsigned allow_multiple_flows : 1;
	unsigned legacy_client_is_flow : 1;

	unsigned background : 1;
	unsigned background_update : 1;
	unsigned platform_binary : 1;

	size_t result_length;
	u_int8_t result[NECP_MAX_CLIENT_RESULT_SIZE];

	necp_policy_id policy_id;

	u_int16_t ip_protocol;
	int proc_pid;

	struct _necp_client_flow_tree flow_registrations;
	LIST_HEAD(_necp_client_assertion_list, necp_client_assertion) assertion_list;

	struct rtentry *current_route;

	struct necp_client_interface_option interface_options[NECP_CLIENT_INTERFACE_OPTION_STATIC_COUNT];
	struct necp_client_interface_option *extra_interface_options;
	u_int8_t interface_option_count; // Number in interface_options + extra_interface_options

	struct necp_client_result_netagent failed_trigger_agent;

	void *agent_handle;

	size_t parameters_length;
	u_int8_t parameters[0];
};

#define NECP_CLIENT_LOCK(_c) lck_mtx_lock(&_c->lock)
#define NECP_CLIENT_UNLOCK(_c) lck_mtx_unlock(&_c->lock)
#define NECP_CLIENT_ASSERT_LOCKED(_c) LCK_MTX_ASSERT(&_c->lock, LCK_MTX_ASSERT_OWNED)
#define NECP_CLIENT_ASSERT_UNLOCKED(_c) LCK_MTX_ASSERT(&_c->lock, LCK_MTX_ASSERT_NOTOWNED)

#define NECP_CLIENT_ROUTE_LOCK(_c) lck_mtx_lock(&_c->route_lock)
#define NECP_CLIENT_ROUTE_UNLOCK(_c) lck_mtx_unlock(&_c->route_lock)

static void necp_client_retain_locked(struct necp_client *client);
static void necp_client_retain(struct necp_client *client);
static bool necp_client_release_locked(struct necp_client *client);

static void
necp_client_add_assertion(struct necp_client *client, uuid_t netagent_uuid);

static bool
necp_client_remove_assertion(struct necp_client *client, uuid_t netagent_uuid);

LIST_HEAD(_necp_flow_registration_list, necp_client_flow_registration);
static struct _necp_flow_registration_list necp_collect_stats_flow_list;

struct necp_flow_defunct {
	LIST_ENTRY(necp_flow_defunct) chain;

	uuid_t flow_id;
	uuid_t nexus_agent;
	void *agent_handle;
	int proc_pid;
};

LIST_HEAD(_necp_flow_defunct_list, necp_flow_defunct);

static int necp_client_id_cmp(struct necp_client *client0, struct necp_client *client1);

RB_HEAD(_necp_client_tree, necp_client);
RB_PROTOTYPE_PREV(_necp_client_tree, necp_client, link, necp_client_id_cmp);
RB_GENERATE_PREV(_necp_client_tree, necp_client, link, necp_client_id_cmp);

RB_HEAD(_necp_client_global_tree, necp_client);
RB_PROTOTYPE_PREV(_necp_client_global_tree, necp_client, global_link, necp_client_id_cmp);
RB_GENERATE_PREV(_necp_client_global_tree, necp_client, global_link, necp_client_id_cmp);

RB_HEAD(_necp_fd_flow_tree, necp_client_flow_registration);
RB_PROTOTYPE_PREV(_necp_fd_flow_tree, necp_client_flow_registration, fd_link, necp_client_flow_id_cmp);
RB_GENERATE_PREV(_necp_fd_flow_tree, necp_client_flow_registration, fd_link, necp_client_flow_id_cmp);

RB_HEAD(_necp_client_flow_global_tree, necp_client_flow_registration);
RB_PROTOTYPE_PREV(_necp_client_flow_global_tree, necp_client_flow_registration, global_link, necp_client_flow_id_cmp);
RB_GENERATE_PREV(_necp_client_flow_global_tree, necp_client_flow_registration, global_link, necp_client_flow_id_cmp);

static struct _necp_client_global_tree necp_client_global_tree;
static struct _necp_client_flow_global_tree necp_client_flow_global_tree;

struct necp_client_update {
	TAILQ_ENTRY(necp_client_update) chain;

	uuid_t client_id;

	size_t update_length;
	struct necp_client_observer_update update;
};


#define NAIF_ATTACHED   0x1     // arena is attached to list
#define NAIF_REDIRECT   0x2     // arena mmap has been redirected
#define NAIF_DEFUNCT    0x4     // arena is now defunct

struct necp_fd_data {
	u_int8_t necp_fd_type;
	LIST_ENTRY(necp_fd_data) chain;
	struct _necp_client_tree clients;
	struct _necp_fd_flow_tree flows;
	TAILQ_HEAD(_necp_client_update_list, necp_client_update) update_list;
	int update_count;
	int flags;
	int proc_pid;
	decl_lck_mtx_data(, fd_lock);
	struct selinfo si;
};

#define NECP_FD_LOCK(_f) lck_mtx_lock(&_f->fd_lock)
#define NECP_FD_UNLOCK(_f) lck_mtx_unlock(&_f->fd_lock)
#define NECP_FD_ASSERT_LOCKED(_f) LCK_MTX_ASSERT(&_f->fd_lock, LCK_MTX_ASSERT_OWNED)
#define NECP_FD_ASSERT_UNLOCKED(_f) LCK_MTX_ASSERT(&_f->fd_lock, LCK_MTX_ASSERT_NOTOWNED)

static LIST_HEAD(_necp_fd_list, necp_fd_data) necp_fd_list;
static LIST_HEAD(_necp_fd_observer_list, necp_fd_data) necp_fd_observer_list;

#define NECP_CLIENT_FD_ZONE_MAX                 128
#define NECP_CLIENT_FD_ZONE_NAME                "necp.clientfd"

static unsigned int necp_client_fd_size;        /* size of zone element */
static struct zone *necp_client_fd_zone;        /* zone for necp_fd_data */

#define NECP_FLOW_ZONE_NAME                                     "necp.flow"
#define NECP_FLOW_REGISTRATION_ZONE_NAME        "necp.flowregistration"

static unsigned int necp_flow_size;             /* size of necp_client_flow */
static struct mcache *necp_flow_cache;  /* cache for necp_client_flow */

static unsigned int necp_flow_registration_size;        /* size of necp_client_flow_registration */
static struct mcache *necp_flow_registration_cache;     /* cache for necp_client_flow_registration */

#define NECP_ARENA_INFO_ZONE_MAX                128
#define NECP_ARENA_INFO_ZONE_NAME               "necp.arenainfo"


static  lck_grp_attr_t  *necp_fd_grp_attr       = NULL;
static  lck_attr_t              *necp_fd_mtx_attr       = NULL;
static  lck_grp_t               *necp_fd_mtx_grp        = NULL;

decl_lck_rw_data(static, necp_fd_lock);
decl_lck_rw_data(static, necp_observer_lock);
decl_lck_rw_data(static, necp_client_tree_lock);
decl_lck_rw_data(static, necp_flow_tree_lock);
decl_lck_rw_data(static, necp_collect_stats_list_lock);

#define NECP_STATS_LIST_LOCK_EXCLUSIVE() lck_rw_lock_exclusive(&necp_collect_stats_list_lock)
#define NECP_STATS_LIST_LOCK_SHARED() lck_rw_lock_shared(&necp_collect_stats_list_lock)
#define NECP_STATS_LIST_UNLOCK() lck_rw_done(&necp_collect_stats_list_lock)

#define NECP_CLIENT_TREE_LOCK_EXCLUSIVE() lck_rw_lock_exclusive(&necp_client_tree_lock)
#define NECP_CLIENT_TREE_LOCK_SHARED() lck_rw_lock_shared(&necp_client_tree_lock)
#define NECP_CLIENT_TREE_UNLOCK() lck_rw_done(&necp_client_tree_lock)
#define NECP_CLIENT_TREE_ASSERT_LOCKED() LCK_RW_ASSERT(&necp_client_tree_lock, LCK_RW_ASSERT_HELD)

#define NECP_FLOW_TREE_LOCK_EXCLUSIVE() lck_rw_lock_exclusive(&necp_flow_tree_lock)
#define NECP_FLOW_TREE_LOCK_SHARED() lck_rw_lock_shared(&necp_flow_tree_lock)
#define NECP_FLOW_TREE_UNLOCK() lck_rw_done(&necp_flow_tree_lock)
#define NECP_FLOW_TREE_ASSERT_LOCKED() LCK_RW_ASSERT(&necp_flow_tree_lock, LCK_RW_ASSERT_HELD)

#define NECP_FD_LIST_LOCK_EXCLUSIVE() lck_rw_lock_exclusive(&necp_fd_lock)
#define NECP_FD_LIST_LOCK_SHARED() lck_rw_lock_shared(&necp_fd_lock)
#define NECP_FD_LIST_UNLOCK() lck_rw_done(&necp_fd_lock)

#define NECP_OBSERVER_LIST_LOCK_EXCLUSIVE() lck_rw_lock_exclusive(&necp_observer_lock)
#define NECP_OBSERVER_LIST_LOCK_SHARED() lck_rw_lock_shared(&necp_observer_lock)
#define NECP_OBSERVER_LIST_UNLOCK() lck_rw_done(&necp_observer_lock)

// Locking Notes

// Take NECP_FD_LIST_LOCK when accessing or modifying the necp_fd_list
// Take NECP_CLIENT_TREE_LOCK when accessing or modifying the necp_client_global_tree
// Take NECP_FLOW_TREE_LOCK when accessing or modifying the necp_client_flow_global_tree
// Take NECP_STATS_LIST_LOCK when accessing or modifying the necp_collect_stats_flow_list
// Take NECP_FD_LOCK when accessing or modifying an necp_fd_data entry
// Take NECP_CLIENT_LOCK when accessing or modifying a single necp_client
// Take NECP_CLIENT_ROUTE_LOCK when accessing or modifying a client's route

// Precedence, where 1 is the first lock that must be taken
// 1. NECP_FD_LIST_LOCK
// 2. NECP_FD_LOCK (any)
// 3. NECP_CLIENT_TREE_LOCK
// 4. NECP_CLIENT_LOCK (any)
// 5. NECP_FLOW_TREE_LOCK
// 6. NECP_STATS_LIST_LOCK
// 7. NECP_CLIENT_ROUTE_LOCK (any)

static thread_call_t necp_client_update_tcall;


/// NECP file descriptor functions

static int
noop_read(struct fileproc *fp, struct uio *uio, int flags, vfs_context_t ctx)
{
#pragma unused(fp, uio, flags, ctx)
	return ENXIO;
}

static int
noop_write(struct fileproc *fp, struct uio *uio, int flags,
    vfs_context_t ctx)
{
#pragma unused(fp, uio, flags, ctx)
	return ENXIO;
}

static int
noop_ioctl(struct fileproc *fp, unsigned long com, caddr_t data,
    vfs_context_t ctx)
{
#pragma unused(fp, com, data, ctx)
	return ENOTTY;
}

static void
necp_fd_notify(struct necp_fd_data *fd_data, bool locked)
{
	struct selinfo *si = &fd_data->si;

	if (!locked) {
		NECP_FD_LOCK(fd_data);
	}

	selwakeup(si);

	// use a non-zero hint to tell the notification from the
	// call done in kqueue_scan() which uses 0
	KNOTE(&si->si_note, 1); // notification

	if (!locked) {
		NECP_FD_UNLOCK(fd_data);
	}
}

static inline bool
necp_client_has_unread_flows(struct necp_client *client)
{
	NECP_CLIENT_ASSERT_LOCKED(client);
	struct necp_client_flow_registration *flow_registration = NULL;
	RB_FOREACH(flow_registration, _necp_client_flow_tree, &client->flow_registrations) {
		if (!flow_registration->flow_result_read) {
			return true;
		}
	}
	return false;
}

static int
necp_fd_poll(struct necp_fd_data *fd_data, int events, void *wql, struct proc *p, int is_kevent)
{
#pragma unused(wql, p, is_kevent)
	u_int revents = 0;

	u_int want_rx = events & (POLLIN | POLLRDNORM);
	if (want_rx) {
		if (fd_data->flags & NECP_OPEN_FLAG_PUSH_OBSERVER) {
			// Push-mode observers are readable when they have a new update
			if (!TAILQ_EMPTY(&fd_data->update_list)) {
				revents |= want_rx;
			}
		} else {
			// Standard fds are readable when some client is unread
			struct necp_client *client = NULL;
			bool has_unread_clients = FALSE;
			RB_FOREACH(client, _necp_client_tree, &fd_data->clients) {
				NECP_CLIENT_LOCK(client);
				if (!client->result_read || necp_client_has_unread_flows(client)) {
					has_unread_clients = TRUE;
				}
				NECP_CLIENT_UNLOCK(client);
				if (has_unread_clients) {
					break;
				}
			}

			if (has_unread_clients) {
				revents |= want_rx;
			}
		}
	}

	return revents;
}

static inline void
necp_generate_client_id(uuid_t client_id, bool is_flow)
{
	uuid_generate_random(client_id);

	if (is_flow) {
		client_id[9] |= 0x01;
	} else {
		client_id[9] &= ~0x01;
	}
}

static inline bool
necp_client_id_is_flow(uuid_t client_id)
{
	return client_id[9] & 0x01;
}

static struct necp_client *
necp_find_client_and_lock(uuid_t client_id)
{
	NECP_CLIENT_TREE_ASSERT_LOCKED();

	struct necp_client *client = NULL;

	if (necp_client_id_is_flow(client_id)) {
		NECP_FLOW_TREE_LOCK_SHARED();
		struct necp_client_flow_registration find;
		uuid_copy(find.registration_id, client_id);
		struct necp_client_flow_registration *flow = RB_FIND(_necp_client_flow_global_tree, &necp_client_flow_global_tree, &find);
		if (flow != NULL) {
			client = flow->client;
		}
		NECP_FLOW_TREE_UNLOCK();
	} else {
		struct necp_client find;
		uuid_copy(find.client_id, client_id);
		client = RB_FIND(_necp_client_global_tree, &necp_client_global_tree, &find);
	}

	if (client != NULL) {
		NECP_CLIENT_LOCK(client);
	}

	return client;
}

static struct necp_client_flow_registration *
necp_client_find_flow(struct necp_client *client, uuid_t flow_id)
{
	NECP_CLIENT_ASSERT_LOCKED(client);
	struct necp_client_flow_registration *flow = NULL;

	if (necp_client_id_is_flow(flow_id)) {
		struct necp_client_flow_registration find;
		uuid_copy(find.registration_id, flow_id);
		flow = RB_FIND(_necp_client_flow_tree, &client->flow_registrations, &find);
	} else {
		flow = RB_ROOT(&client->flow_registrations);
	}

	return flow;
}

static struct necp_client *
necp_client_fd_find_client_unlocked(struct necp_fd_data *client_fd, uuid_t client_id)
{
	NECP_FD_ASSERT_LOCKED(client_fd);
	struct necp_client *client = NULL;

	if (necp_client_id_is_flow(client_id)) {
		struct necp_client_flow_registration find;
		uuid_copy(find.registration_id, client_id);
		struct necp_client_flow_registration *flow = RB_FIND(_necp_fd_flow_tree, &client_fd->flows, &find);
		if (flow != NULL) {
			client = flow->client;
		}
	} else {
		struct necp_client find;
		uuid_copy(find.client_id, client_id);
		client = RB_FIND(_necp_client_tree, &client_fd->clients, &find);
	}

	return client;
}

static struct necp_client *
necp_client_fd_find_client_and_lock(struct necp_fd_data *client_fd, uuid_t client_id)
{
	struct necp_client *client = necp_client_fd_find_client_unlocked(client_fd, client_id);
	if (client != NULL) {
		NECP_CLIENT_LOCK(client);
	}

	return client;
}

static inline int
necp_client_id_cmp(struct necp_client *client0, struct necp_client *client1)
{
	return uuid_compare(client0->client_id, client1->client_id);
}

static inline int
necp_client_flow_id_cmp(struct necp_client_flow_registration *flow0, struct necp_client_flow_registration *flow1)
{
	return uuid_compare(flow0->registration_id, flow1->registration_id);
}

static int
necpop_select(struct fileproc *fp, int which, void *wql, vfs_context_t ctx)
{
#pragma unused(fp, which, wql, ctx)
	return 0;
	struct necp_fd_data *fd_data = NULL;
	int revents = 0;
	int events = 0;
	proc_t procp;

	fd_data = (struct necp_fd_data *)fp->f_fglob->fg_data;
	if (fd_data == NULL) {
		return 0;
	}

	procp = vfs_context_proc(ctx);

	switch (which) {
	case FREAD: {
		events = POLLIN;
		break;
	}

	default: {
		return 1;
	}
	}

	NECP_FD_LOCK(fd_data);
	revents = necp_fd_poll(fd_data, events, wql, procp, 0);
	NECP_FD_UNLOCK(fd_data);

	return (events & revents) ? 1 : 0;
}

static void
necp_fd_knrdetach(struct knote *kn)
{
	struct necp_fd_data *fd_data = (struct necp_fd_data *)kn->kn_hook;
	struct selinfo *si = &fd_data->si;

	NECP_FD_LOCK(fd_data);
	KNOTE_DETACH(&si->si_note, kn);
	NECP_FD_UNLOCK(fd_data);
}

static int
necp_fd_knread(struct knote *kn, long hint)
{
#pragma unused(kn, hint)
	return 1; /* assume we are ready */
}

static int
necp_fd_knrprocess(struct knote *kn, struct filt_process_s *data, struct kevent_internal_s *kev)
{
#pragma unused(data)
	struct necp_fd_data *fd_data;
	int revents;
	int res;

	fd_data = (struct necp_fd_data *)kn->kn_hook;

	NECP_FD_LOCK(fd_data);
	revents = necp_fd_poll(fd_data, POLLIN, NULL, current_proc(), 1);
	res = ((revents & POLLIN) != 0);
	if (res) {
		*kev = kn->kn_kevent;
	}
	NECP_FD_UNLOCK(fd_data);
	return res;
}

static int
necp_fd_knrtouch(struct knote *kn, struct kevent_internal_s *kev)
{
#pragma unused(kev)
	struct necp_fd_data *fd_data;
	int revents;

	fd_data = (struct necp_fd_data *)kn->kn_hook;

	NECP_FD_LOCK(fd_data);
	revents = necp_fd_poll(fd_data, POLLIN, NULL, current_proc(), 1);
	NECP_FD_UNLOCK(fd_data);

	return (revents & POLLIN) != 0;
}

SECURITY_READ_ONLY_EARLY(struct filterops) necp_fd_rfiltops = {
	.f_isfd = 1,
	.f_detach = necp_fd_knrdetach,
	.f_event = necp_fd_knread,
	.f_touch = necp_fd_knrtouch,
	.f_process = necp_fd_knrprocess,
};

static int
necpop_kqfilter(struct fileproc *fp, struct knote *kn,
    __unused struct kevent_internal_s *kev, vfs_context_t ctx)
{
#pragma unused(fp, ctx)
	struct necp_fd_data *fd_data = NULL;
	int revents;

	if (kn->kn_filter != EVFILT_READ) {
		NECPLOG(LOG_ERR, "bad filter request %d", kn->kn_filter);
		kn->kn_flags = EV_ERROR;
		kn->kn_data = EINVAL;
		return 0;
	}

	fd_data = (struct necp_fd_data *)kn->kn_fp->f_fglob->fg_data;
	if (fd_data == NULL) {
		NECPLOG0(LOG_ERR, "No channel for kqfilter");
		kn->kn_flags = EV_ERROR;
		kn->kn_data = ENOENT;
		return 0;
	}

	NECP_FD_LOCK(fd_data);
	kn->kn_filtid = EVFILTID_NECP_FD;
	kn->kn_hook = fd_data;
	KNOTE_ATTACH(&fd_data->si.si_note, kn);

	revents = necp_fd_poll(fd_data, POLLIN, NULL, current_proc(), 1);

	NECP_FD_UNLOCK(fd_data);

	return (revents & POLLIN) != 0;
}

#define INTERFACE_FLAGS_SHIFT   32
#define INTERFACE_FLAGS_MASK    0xffff
#define INTERFACE_INDEX_SHIFT   0
#define INTERFACE_INDEX_MASK    0xffffffff

static uint64_t
combine_interface_details(uint32_t interface_index, uint16_t interface_flags)
{
	return ((uint64_t)interface_flags & INTERFACE_FLAGS_MASK) << INTERFACE_FLAGS_SHIFT |
	       ((uint64_t)interface_index & INTERFACE_INDEX_MASK) << INTERFACE_INDEX_SHIFT;
}


static void
necp_defunct_flow_registration(struct necp_client *client,
    struct necp_client_flow_registration *flow_registration,
    struct _necp_flow_defunct_list *defunct_list)
{
	NECP_CLIENT_ASSERT_LOCKED(client);

	if (!flow_registration->defunct) {
		bool needs_defunct = false;
		struct necp_client_flow *search_flow = NULL;
		LIST_FOREACH(search_flow, &flow_registration->flow_list, flow_chain) {
			if (search_flow->nexus &&
			    !uuid_is_null(search_flow->u.nexus_agent)) {
				// Save defunct values for the nexus
				if (defunct_list != NULL) {
					// Sleeping alloc won't fail; copy only what's necessary
					struct necp_flow_defunct *flow_defunct = _MALLOC(sizeof(struct necp_flow_defunct),
					    M_NECP, M_WAITOK | M_ZERO);
					uuid_copy(flow_defunct->nexus_agent, search_flow->u.nexus_agent);
					uuid_copy(flow_defunct->flow_id, ((flow_registration->flags & NECP_CLIENT_FLOW_FLAGS_USE_CLIENT_ID) ?
					    client->client_id :
					    flow_registration->registration_id));
					flow_defunct->proc_pid = client->proc_pid;
					flow_defunct->agent_handle = client->agent_handle;

					// Add to the list provided by caller
					LIST_INSERT_HEAD(defunct_list, flow_defunct, chain);
				}

				needs_defunct = true;
			}
		}

		if (needs_defunct) {

			// Only set defunct if there was some assigned flow
			flow_registration->defunct = true;
		}
	}
}

static void
necp_defunct_client_for_policy(struct necp_client *client,
    struct _necp_flow_defunct_list *defunct_list)
{
	NECP_CLIENT_ASSERT_LOCKED(client);

	struct necp_client_flow_registration *flow_registration = NULL;
	RB_FOREACH(flow_registration, _necp_client_flow_tree, &client->flow_registrations) {
		necp_defunct_flow_registration(client, flow_registration, defunct_list);
	}
}

static void
necp_client_free(struct necp_client *client)
{
	NECP_CLIENT_ASSERT_LOCKED(client);

	NECP_CLIENT_UNLOCK(client);

	FREE(client->extra_interface_options, M_NECP);
	client->extra_interface_options = NULL;

	lck_mtx_destroy(&client->route_lock, necp_fd_mtx_grp);
	lck_mtx_destroy(&client->lock, necp_fd_mtx_grp);

	FREE(client, M_NECP);
}

static void
necp_client_retain_locked(struct necp_client *client)
{
	NECP_CLIENT_ASSERT_LOCKED(client);

	client->reference_count++;
	ASSERT(client->reference_count != 0);
}

static void
necp_client_retain(struct necp_client *client)
{
	NECP_CLIENT_LOCK(client);
	necp_client_retain_locked(client);
	NECP_CLIENT_UNLOCK(client);
}

static bool
necp_client_release_locked(struct necp_client *client)
{
	NECP_CLIENT_ASSERT_LOCKED(client);

	uint32_t old_ref = client->reference_count;

	ASSERT(client->reference_count != 0);
	if (--client->reference_count == 0) {
		necp_client_free(client);
	}

	return old_ref == 1;
}


static void
necp_client_update_observer_add_internal(struct necp_fd_data *observer_fd, struct necp_client *client)
{
	NECP_FD_LOCK(observer_fd);

	if (observer_fd->update_count >= necp_observer_message_limit) {
		NECP_FD_UNLOCK(observer_fd);
		return;
	}

	struct necp_client_update *client_update = _MALLOC(sizeof(struct necp_client_update) + client->parameters_length,
	    M_NECP, M_WAITOK | M_ZERO);
	if (client_update != NULL) {
		client_update->update_length = sizeof(struct necp_client_observer_update) + client->parameters_length;
		uuid_copy(client_update->client_id, client->client_id);
		client_update->update.update_type = NECP_CLIENT_UPDATE_TYPE_PARAMETERS;
		memcpy(client_update->update.tlv_buffer, client->parameters, client->parameters_length);
		TAILQ_INSERT_TAIL(&observer_fd->update_list, client_update, chain);
		observer_fd->update_count++;

		necp_fd_notify(observer_fd, true);
	}

	NECP_FD_UNLOCK(observer_fd);
}

static void
necp_client_update_observer_update_internal(struct necp_fd_data *observer_fd, struct necp_client *client)
{
	NECP_FD_LOCK(observer_fd);

	if (observer_fd->update_count >= necp_observer_message_limit) {
		NECP_FD_UNLOCK(observer_fd);
		return;
	}

	struct necp_client_update *client_update = _MALLOC(sizeof(struct necp_client_update) + client->result_length,
	    M_NECP, M_WAITOK | M_ZERO);
	if (client_update != NULL) {
		client_update->update_length = sizeof(struct necp_client_observer_update) + client->result_length;
		uuid_copy(client_update->client_id, client->client_id);
		client_update->update.update_type = NECP_CLIENT_UPDATE_TYPE_RESULT;
		memcpy(client_update->update.tlv_buffer, client->result, client->result_length);
		TAILQ_INSERT_TAIL(&observer_fd->update_list, client_update, chain);
		observer_fd->update_count++;

		necp_fd_notify(observer_fd, true);
	}

	NECP_FD_UNLOCK(observer_fd);
}

static void
necp_client_update_observer_remove_internal(struct necp_fd_data *observer_fd, struct necp_client *client)
{
	NECP_FD_LOCK(observer_fd);

	if (observer_fd->update_count >= necp_observer_message_limit) {
		NECP_FD_UNLOCK(observer_fd);
		return;
	}

	struct necp_client_update *client_update = _MALLOC(sizeof(struct necp_client_update),
	    M_NECP, M_WAITOK | M_ZERO);
	if (client_update != NULL) {
		client_update->update_length = sizeof(struct necp_client_observer_update);
		uuid_copy(client_update->client_id, client->client_id);
		client_update->update.update_type = NECP_CLIENT_UPDATE_TYPE_REMOVE;
		TAILQ_INSERT_TAIL(&observer_fd->update_list, client_update, chain);
		observer_fd->update_count++;

		necp_fd_notify(observer_fd, true);
	}

	NECP_FD_UNLOCK(observer_fd);
}

static void
necp_client_update_observer_add(struct necp_client *client)
{
	NECP_OBSERVER_LIST_LOCK_SHARED();

	if (LIST_EMPTY(&necp_fd_observer_list)) {
		// No observers, bail
		NECP_OBSERVER_LIST_UNLOCK();
		return;
	}

	struct necp_fd_data *observer_fd = NULL;
	LIST_FOREACH(observer_fd, &necp_fd_observer_list, chain) {
		necp_client_update_observer_add_internal(observer_fd, client);
	}

	NECP_OBSERVER_LIST_UNLOCK();
}

static void
necp_client_update_observer_update(struct necp_client *client)
{
	NECP_OBSERVER_LIST_LOCK_SHARED();

	if (LIST_EMPTY(&necp_fd_observer_list)) {
		// No observers, bail
		NECP_OBSERVER_LIST_UNLOCK();
		return;
	}

	struct necp_fd_data *observer_fd = NULL;
	LIST_FOREACH(observer_fd, &necp_fd_observer_list, chain) {
		necp_client_update_observer_update_internal(observer_fd, client);
	}

	NECP_OBSERVER_LIST_UNLOCK();
}

static void
necp_client_update_observer_remove(struct necp_client *client)
{
	NECP_OBSERVER_LIST_LOCK_SHARED();

	if (LIST_EMPTY(&necp_fd_observer_list)) {
		// No observers, bail
		NECP_OBSERVER_LIST_UNLOCK();
		return;
	}

	struct necp_fd_data *observer_fd = NULL;
	LIST_FOREACH(observer_fd, &necp_fd_observer_list, chain) {
		necp_client_update_observer_remove_internal(observer_fd, client);
	}

	NECP_OBSERVER_LIST_UNLOCK();
}

static void
necp_destroy_client_flow_registration(struct necp_client *client,
    struct necp_client_flow_registration *flow_registration,
    pid_t pid, bool abort)
{
	NECP_CLIENT_ASSERT_LOCKED(client);


	struct necp_client_flow *search_flow = NULL;
	struct necp_client_flow *temp_flow = NULL;
	LIST_FOREACH_SAFE(search_flow, &flow_registration->flow_list, flow_chain, temp_flow) {
		if (search_flow->nexus &&
		    !uuid_is_null(search_flow->u.nexus_agent)) {
			// Note that if we had defuncted the client earlier, this would result in a harmless ENOENT
			int netagent_error = netagent_client_message(search_flow->u.nexus_agent,
			    ((flow_registration->flags & NECP_CLIENT_FLOW_FLAGS_USE_CLIENT_ID) ?
			    client->client_id :
			    flow_registration->registration_id),
			    pid, client->agent_handle,
			    (abort ? NETAGENT_MESSAGE_TYPE_ABORT_NEXUS :
			    NETAGENT_MESSAGE_TYPE_CLOSE_NEXUS));
			if (netagent_error != 0 && netagent_error != ENOENT) {
				NECPLOG(LOG_ERR, "necp_client_remove close nexus error (%d)", netagent_error);
			}
			uuid_clear(search_flow->u.nexus_agent);
		}
		if (search_flow->assigned_results != NULL) {
			FREE(search_flow->assigned_results, M_NETAGENT);
			search_flow->assigned_results = NULL;
		}
		LIST_REMOVE(search_flow, flow_chain);
		if (search_flow->socket) {
			OSDecrementAtomic(&necp_socket_flow_count);
		} else {
			OSDecrementAtomic(&necp_if_flow_count);
		}
		mcache_free(necp_flow_cache, search_flow);
	}

	RB_REMOVE(_necp_client_flow_tree, &client->flow_registrations, flow_registration);
	flow_registration->client = NULL;

	mcache_free(necp_flow_registration_cache, flow_registration);
}

static void
necp_destroy_client(struct necp_client *client, pid_t pid, bool abort)
{
	NECP_CLIENT_ASSERT_UNLOCKED(client);

	necp_client_update_observer_remove(client);

	NECP_CLIENT_LOCK(client);

	// Free route
	NECP_CLIENT_ROUTE_LOCK(client);
	if (client->current_route != NULL) {
		rtfree(client->current_route);
		client->current_route = NULL;
	}
	NECP_CLIENT_ROUTE_UNLOCK(client);

	// Remove flow assignments
	struct necp_client_flow_registration *flow_registration = NULL;
	struct necp_client_flow_registration *temp_flow_registration = NULL;
	RB_FOREACH_SAFE(flow_registration, _necp_client_flow_tree, &client->flow_registrations, temp_flow_registration) {
		necp_destroy_client_flow_registration(client, flow_registration, pid, abort);
	}

	// Remove agent assertions
	struct necp_client_assertion *search_assertion = NULL;
	struct necp_client_assertion *temp_assertion = NULL;
	LIST_FOREACH_SAFE(search_assertion, &client->assertion_list, assertion_chain, temp_assertion) {
		int netagent_error = netagent_client_message(search_assertion->asserted_netagent, client->client_id, pid,
		    client->agent_handle, NETAGENT_MESSAGE_TYPE_CLIENT_UNASSERT);
		if (netagent_error != 0) {
			NECPLOG((netagent_error == ENOENT ? LOG_DEBUG : LOG_ERR),
			    "necp_client_remove unassert agent error (%d)", netagent_error);
		}
		LIST_REMOVE(search_assertion, assertion_chain);
		FREE(search_assertion, M_NECP);
	}

	if (!necp_client_release_locked(client)) {
		NECP_CLIENT_UNLOCK(client);
	}

	OSDecrementAtomic(&necp_client_count);
}

static int
necpop_close(struct fileglob *fg, vfs_context_t ctx)
{
#pragma unused(ctx)
	struct necp_fd_data *fd_data = NULL;
	int error = 0;

	fd_data = (struct necp_fd_data *)fg->fg_data;
	fg->fg_data = NULL;

	if (fd_data != NULL) {
		struct _necp_client_tree clients_to_close;
		RB_INIT(&clients_to_close);

		// Remove from list quickly
		if (fd_data->flags & NECP_OPEN_FLAG_PUSH_OBSERVER) {
			NECP_OBSERVER_LIST_LOCK_EXCLUSIVE();
			LIST_REMOVE(fd_data, chain);
			NECP_OBSERVER_LIST_UNLOCK();
		} else {
			NECP_FD_LIST_LOCK_EXCLUSIVE();
			LIST_REMOVE(fd_data, chain);
			NECP_FD_LIST_UNLOCK();
		}

		NECP_FD_LOCK(fd_data);
		pid_t pid = fd_data->proc_pid;

		struct necp_client_flow_registration *flow_registration = NULL;
		struct necp_client_flow_registration *temp_flow_registration = NULL;
		RB_FOREACH_SAFE(flow_registration, _necp_fd_flow_tree, &fd_data->flows, temp_flow_registration) {
			NECP_FLOW_TREE_LOCK_EXCLUSIVE();
			RB_REMOVE(_necp_client_flow_global_tree, &necp_client_flow_global_tree, flow_registration);
			NECP_FLOW_TREE_UNLOCK();
			RB_REMOVE(_necp_fd_flow_tree, &fd_data->flows, flow_registration);
		}

		struct necp_client *client = NULL;
		struct necp_client *temp_client = NULL;
		RB_FOREACH_SAFE(client, _necp_client_tree, &fd_data->clients, temp_client) {
			NECP_CLIENT_TREE_LOCK_EXCLUSIVE();
			RB_REMOVE(_necp_client_global_tree, &necp_client_global_tree, client);
			NECP_CLIENT_TREE_UNLOCK();
			RB_REMOVE(_necp_client_tree, &fd_data->clients, client);
			RB_INSERT(_necp_client_tree, &clients_to_close, client);
		}

		struct necp_client_update *client_update = NULL;
		struct necp_client_update *temp_update = NULL;
		TAILQ_FOREACH_SAFE(client_update, &fd_data->update_list, chain, temp_update) {
			// Flush pending updates
			TAILQ_REMOVE(&fd_data->update_list, client_update, chain);
			FREE(client_update, M_NECP);
		}
		fd_data->update_count = 0;


		NECP_FD_UNLOCK(fd_data);

		selthreadclear(&fd_data->si);

		lck_mtx_destroy(&fd_data->fd_lock, necp_fd_mtx_grp);

		if (fd_data->flags & NECP_OPEN_FLAG_PUSH_OBSERVER) {
			OSDecrementAtomic(&necp_observer_fd_count);
		} else {
			OSDecrementAtomic(&necp_client_fd_count);
		}

		zfree(necp_client_fd_zone, fd_data);
		fd_data = NULL;

		RB_FOREACH_SAFE(client, _necp_client_tree, &clients_to_close, temp_client) {
			RB_REMOVE(_necp_client_tree, &clients_to_close, client);
			necp_destroy_client(client, pid, true);
		}
	}

	return error;
}

/// NECP client utilities

static inline bool
necp_address_is_wildcard(const union necp_sockaddr_union * const addr)
{
	return (addr->sa.sa_family == AF_INET && addr->sin.sin_addr.s_addr == INADDR_ANY) ||
	       (addr->sa.sa_family == AF_INET6 && IN6_IS_ADDR_UNSPECIFIED(&addr->sin6.sin6_addr));
}

static int
necp_find_fd_data(int fd, struct necp_fd_data **fd_data)
{
	proc_t p = current_proc();
	struct fileproc *fp = NULL;
	int error = 0;

	proc_fdlock_spin(p);
	if ((error = fp_lookup(p, fd, &fp, 1)) != 0) {
		goto done;
	}
	if (fp->f_fglob->fg_ops->fo_type != DTYPE_NETPOLICY) {
		fp_drop(p, fd, fp, 1);
		error = ENODEV;
		goto done;
	}
	*fd_data = (struct necp_fd_data *)fp->f_fglob->fg_data;

	if ((*fd_data)->necp_fd_type != necp_fd_type_client) {
		// Not a client fd, ignore
		fp_drop(p, fd, fp, 1);
		error = EINVAL;
		goto done;
	}

done:
	proc_fdunlock(p);
	return error;
}


static struct necp_client_flow *
necp_client_add_interface_flow(struct necp_client_flow_registration *flow_registration,
    uint32_t interface_index)
{
	struct necp_client_flow *new_flow = mcache_alloc(necp_flow_cache, MCR_SLEEP);
	if (new_flow == NULL) {
		NECPLOG0(LOG_ERR, "Failed to allocate interface flow");
		return NULL;
	}

	memset(new_flow, 0, sizeof(*new_flow));

	// Neither nexus nor socket
	new_flow->interface_index = interface_index;
	new_flow->u.socket_handle = flow_registration->interface_handle;
	new_flow->u.cb = flow_registration->interface_cb;

	OSIncrementAtomic(&necp_if_flow_count);

	LIST_INSERT_HEAD(&flow_registration->flow_list, new_flow, flow_chain);

	return new_flow;
}

static struct necp_client_flow *
necp_client_add_interface_flow_if_needed(struct necp_client *client,
    struct necp_client_flow_registration *flow_registration,
    uint32_t interface_index)
{
	if (!client->allow_multiple_flows ||
	    interface_index == IFSCOPE_NONE) {
		// Interface not set, or client not allowed to use this mode
		return NULL;
	}

	struct necp_client_flow *flow = NULL;
	LIST_FOREACH(flow, &flow_registration->flow_list, flow_chain) {
		if (!flow->nexus && !flow->socket && flow->interface_index == interface_index) {
			// Already have the flow
			flow->invalid = FALSE;
			flow->u.socket_handle = flow_registration->interface_handle;
			flow->u.cb = flow_registration->interface_cb;
			return NULL;
		}
	}
	return necp_client_add_interface_flow(flow_registration, interface_index);
}

static void
necp_client_add_interface_option_if_needed(struct necp_client *client,
    uint32_t interface_index,
    uint32_t interface_generation,
    uuid_t *nexus_agent)
{
	if (interface_index == IFSCOPE_NONE ||
	    (client->interface_option_count != 0 && !client->allow_multiple_flows)) {
		// Interface not set, or client not allowed to use this mode
		return;
	}

	if (client->interface_option_count >= NECP_CLIENT_MAX_INTERFACE_OPTIONS) {
		// Cannot take any more interface options
		return;
	}

	// Check if already present
	for (u_int32_t option_i = 0; option_i < client->interface_option_count; option_i++) {
		if (option_i < NECP_CLIENT_INTERFACE_OPTION_STATIC_COUNT) {
			struct necp_client_interface_option *option = &client->interface_options[option_i];
			if (option->interface_index == interface_index) {
				if (nexus_agent == NULL) {
					return;
				}
				if (uuid_compare(option->nexus_agent, *nexus_agent) == 0) {
					return;
				}
				if (uuid_is_null(option->nexus_agent)) {
					uuid_copy(option->nexus_agent, *nexus_agent);
					return;
				}
				// If we get to this point, this is a new nexus flow
			}
		} else {
			struct necp_client_interface_option *option = &client->extra_interface_options[option_i - NECP_CLIENT_INTERFACE_OPTION_STATIC_COUNT];
			if (option->interface_index == interface_index) {
				if (nexus_agent == NULL) {
					return;
				}
				if (uuid_compare(option->nexus_agent, *nexus_agent) == 0) {
					return;
				}
				if (uuid_is_null(option->nexus_agent)) {
					uuid_copy(option->nexus_agent, *nexus_agent);
					return;
				}
				// If we get to this point, this is a new nexus flow
			}
		}
	}

	// Add a new entry
	if (client->interface_option_count < NECP_CLIENT_INTERFACE_OPTION_STATIC_COUNT) {
		// Add to static
		struct necp_client_interface_option *option = &client->interface_options[client->interface_option_count];
		option->interface_index = interface_index;
		option->interface_generation = interface_generation;
		if (nexus_agent != NULL) {
			uuid_copy(option->nexus_agent, *nexus_agent);
		}
		client->interface_option_count++;
	} else {
		// Add to extra
		if (client->extra_interface_options == NULL) {
			client->extra_interface_options = _MALLOC(sizeof(struct necp_client_interface_option) * NECP_CLIENT_INTERFACE_OPTION_EXTRA_COUNT, M_NECP, M_WAITOK | M_ZERO);
		}
		if (client->extra_interface_options != NULL) {
			struct necp_client_interface_option *option = &client->extra_interface_options[client->interface_option_count - NECP_CLIENT_INTERFACE_OPTION_STATIC_COUNT];
			option->interface_index = interface_index;
			option->interface_generation = interface_generation;
			if (nexus_agent != NULL) {
				uuid_copy(option->nexus_agent, *nexus_agent);
			}
			client->interface_option_count++;
		}
	}
}

static bool
necp_client_flow_is_viable(proc_t proc, struct necp_client *client,
    struct necp_client_flow *flow)
{
	struct necp_aggregate_result result;
	bool ignore_address = (client->allow_multiple_flows && !flow->nexus && !flow->socket);

	flow->necp_flow_flags = 0;
	int error = necp_application_find_policy_match_internal(proc, client->parameters,
	    (u_int32_t)client->parameters_length,
	    &result, &flow->necp_flow_flags,
	    flow->interface_index,
	    &flow->local_addr, &flow->remote_addr, NULL, ignore_address);

	return error == 0 &&
	       result.routed_interface_index != IFSCOPE_NONE &&
	       result.routing_result != NECP_KERNEL_POLICY_RESULT_DROP;
}

static void
necp_flow_add_interface_flows(proc_t proc,
    struct necp_client *client,
    struct necp_client_flow_registration *flow_registration,
    bool send_initial)
{
	// Traverse all interfaces and add a tracking flow if needed
	for (u_int32_t option_i = 0; option_i < client->interface_option_count; option_i++) {
		if (option_i < NECP_CLIENT_INTERFACE_OPTION_STATIC_COUNT) {
			struct necp_client_interface_option *option = &client->interface_options[option_i];
			struct necp_client_flow *flow = necp_client_add_interface_flow_if_needed(client, flow_registration, option->interface_index);
			if (flow != NULL && send_initial) {
				flow->viable = necp_client_flow_is_viable(proc, client, flow);
				if (flow->viable && flow->u.cb) {
					bool viable = flow->viable;
					flow->u.cb(flow_registration->interface_handle, NECP_CLIENT_CBACTION_INITIAL, flow->interface_index, flow->necp_flow_flags, &viable);
					flow->viable = viable;
				}
			}
		} else {
			struct necp_client_interface_option *option = &client->extra_interface_options[option_i - NECP_CLIENT_INTERFACE_OPTION_STATIC_COUNT];
			struct necp_client_flow *flow = necp_client_add_interface_flow_if_needed(client, flow_registration, option->interface_index);
			if (flow != NULL && send_initial) {
				flow->viable = necp_client_flow_is_viable(proc, client, flow);
				if (flow->viable && flow->u.cb) {
					bool viable = flow->viable;
					flow->u.cb(flow_registration->interface_handle, NECP_CLIENT_CBACTION_INITIAL, flow->interface_index, flow->necp_flow_flags, &viable);
					flow->viable = viable;
				}
			}
		}
	}
}

static bool
necp_client_update_flows(proc_t proc,
    struct necp_client *client,
    struct _necp_flow_defunct_list *defunct_list)
{
	NECP_CLIENT_ASSERT_LOCKED(client);

	bool client_updated = FALSE;
	struct necp_client_flow *flow = NULL;
	struct necp_client_flow *temp_flow = NULL;
	struct necp_client_flow_registration *flow_registration = NULL;
	RB_FOREACH(flow_registration, _necp_client_flow_tree, &client->flow_registrations) {
		if (flow_registration->interface_cb != NULL) {
			// Add any interface flows that are not already tracked
			necp_flow_add_interface_flows(proc, client, flow_registration, false);
		}

		LIST_FOREACH_SAFE(flow, &flow_registration->flow_list, flow_chain, temp_flow) {
			// Check policy result for flow
			int old_flags = flow->necp_flow_flags;
			bool viable = necp_client_flow_is_viable(proc, client, flow);

			// TODO: Defunct nexus flows that are blocked by policy

			if (flow->viable != viable) {
				flow->viable = viable;
				client_updated = TRUE;
			}

			if ((old_flags & NECP_CLIENT_RESULT_FLAG_FORCE_UPDATE) !=
			    (flow->necp_flow_flags & NECP_CLIENT_RESULT_FLAG_FORCE_UPDATE)) {
				client_updated = TRUE;
			}

			if (flow->viable && client_updated && (flow->socket || (!flow->socket && !flow->nexus)) && flow->u.cb) {
				bool flow_viable = flow->viable;
				flow->u.cb(flow->u.socket_handle, NECP_CLIENT_CBACTION_VIABLE, flow->interface_index, flow->necp_flow_flags, &viable);
				flow->viable = flow_viable;
			}

			if (!flow->viable || flow->invalid) {
				if (client_updated && (flow->socket || (!flow->socket && !flow->nexus)) && flow->u.cb) {
					bool flow_viable = flow->viable;
					flow->u.cb(flow->u.socket_handle, NECP_CLIENT_CBACTION_NONVIABLE, flow->interface_index, flow->necp_flow_flags, &viable);
					flow->viable = flow_viable;
				}
				// The callback might change the viable-flag of the
				// flow depending on its policy. Thus, we need to
				// check the flags again after the callback.
			}

			(void)defunct_list;

			// Handle flows that no longer match
			if (!flow->viable || flow->invalid) {
				// Drop them as long as they aren't assigned data
				if (!flow->nexus && !flow->assigned) {
					if (flow->assigned_results != NULL) {
						FREE(flow->assigned_results, M_NETAGENT);
						flow->assigned_results = NULL;
						client_updated = TRUE;
					}
					LIST_REMOVE(flow, flow_chain);
					if (flow->socket) {
						OSDecrementAtomic(&necp_socket_flow_count);
					} else {
						OSDecrementAtomic(&necp_if_flow_count);
					}
					mcache_free(necp_flow_cache, flow);
				}
			}
		}
	}

	return client_updated;
}

static void
necp_client_mark_all_nonsocket_flows_as_invalid(struct necp_client *client)
{
	struct necp_client_flow_registration *flow_registration = NULL;
	struct necp_client_flow *flow = NULL;
	RB_FOREACH(flow_registration, _necp_client_flow_tree, &client->flow_registrations) {
		LIST_FOREACH(flow, &flow_registration->flow_list, flow_chain) {
			if (!flow->socket) { // Socket flows are not marked as invalid
				flow->invalid = TRUE;
			}
		}
	}

	// Reset option count every update
	client->interface_option_count = 0;
}

static bool
necp_netagent_applies_to_client(struct necp_client *client,
    const struct necp_client_parsed_parameters *parameters,
    uuid_t *netagent_uuid, bool allow_nexus,
    uint32_t interface_index, uint32_t interface_generation)
{
#pragma unused(interface_index, interface_generation)
	bool applies = FALSE;
	u_int32_t flags = netagent_get_flags(*netagent_uuid);
	if (!(flags & NETAGENT_FLAG_REGISTERED)) {
		// Unregistered agents never apply
		return applies;
	}

	if (!allow_nexus &&
	    (flags & NETAGENT_FLAG_NEXUS_PROVIDER)) {
		// Hide nexus providers unless allowed
		// Direct interfaces and direct policies are allowed to use a nexus
		// Delegate interfaces or re-scoped interfaces are not allowed
		return applies;
	}

	if (uuid_compare(client->failed_trigger_agent.netagent_uuid, *netagent_uuid) == 0) {
		if (client->failed_trigger_agent.generation == netagent_get_generation(*netagent_uuid)) {
			// If this agent was triggered, and failed, and hasn't changed, keep hiding it
			return applies;
		} else {
			// Mismatch generation, clear out old trigger
			uuid_clear(client->failed_trigger_agent.netagent_uuid);
			client->failed_trigger_agent.generation = 0;
		}
	}

	if (flags & NETAGENT_FLAG_SPECIFIC_USE_ONLY) {
		// Specific use agents only apply when required
		bool required = FALSE;
		if (parameters != NULL) {
			// Check required agent UUIDs
			for (int i = 0; i < NECP_MAX_PARSED_PARAMETERS; i++) {
				if (uuid_is_null(parameters->required_netagents[i])) {
					break;
				}
				if (uuid_compare(parameters->required_netagents[i], *netagent_uuid) == 0) {
					required = TRUE;
					break;
				}
			}

			if (!required) {
				// Check required agent types
				bool fetched_type = FALSE;
				char netagent_domain[NETAGENT_DOMAINSIZE];
				char netagent_type[NETAGENT_TYPESIZE];
				memset(&netagent_domain, 0, NETAGENT_DOMAINSIZE);
				memset(&netagent_type, 0, NETAGENT_TYPESIZE);

				for (int i = 0; i < NECP_MAX_PARSED_PARAMETERS; i++) {
					if (strlen(parameters->required_netagent_types[i].netagent_domain) == 0 ||
					    strlen(parameters->required_netagent_types[i].netagent_type) == 0) {
						break;
					}

					if (!fetched_type) {
						if (netagent_get_agent_domain_and_type(*netagent_uuid, netagent_domain, netagent_type)) {
							fetched_type = TRUE;
						} else {
							break;
						}
					}

					if ((strlen(parameters->required_netagent_types[i].netagent_domain) == 0 ||
					    strncmp(netagent_domain, parameters->required_netagent_types[i].netagent_domain, NETAGENT_DOMAINSIZE) == 0) &&
					    (strlen(parameters->required_netagent_types[i].netagent_type) == 0 ||
					    strncmp(netagent_type, parameters->required_netagent_types[i].netagent_type, NETAGENT_TYPESIZE) == 0)) {
						required = TRUE;
						break;
					}
				}
			}
		}

		applies = required;
	} else {
		applies = TRUE;
	}


	return applies;
}

static void
necp_client_add_agent_interface_options(struct necp_client *client,
    const struct necp_client_parsed_parameters *parsed_parameters,
    ifnet_t ifp)
{
	if (ifp != NULL && ifp->if_agentids != NULL) {
		for (u_int32_t i = 0; i < ifp->if_agentcount; i++) {
			if (uuid_is_null(ifp->if_agentids[i])) {
				continue;
			}
			// Relies on the side effect that nexus agents that apply will create flows
			(void)necp_netagent_applies_to_client(client, parsed_parameters, &ifp->if_agentids[i], TRUE,
			    ifp->if_index, ifnet_get_generation(ifp));
		}
	}
}

static inline bool
necp_client_address_is_valid(struct sockaddr *address)
{
	if (address->sa_family == AF_INET) {
		return address->sa_len == sizeof(struct sockaddr_in);
	} else if (address->sa_family == AF_INET6) {
		return address->sa_len == sizeof(struct sockaddr_in6);
	} else {
		return FALSE;
	}
}

static int
necp_client_parse_parameters(u_int8_t *parameters,
    u_int32_t parameters_size,
    struct necp_client_parsed_parameters *parsed_parameters)
{
	int error = 0;
	size_t offset = 0;

	u_int32_t num_prohibited_interfaces = 0;
	u_int32_t num_prohibited_interface_types = 0;
	u_int32_t num_required_agents = 0;
	u_int32_t num_prohibited_agents = 0;
	u_int32_t num_preferred_agents = 0;
	u_int32_t num_avoided_agents = 0;
	u_int32_t num_required_agent_types = 0;
	u_int32_t num_prohibited_agent_types = 0;
	u_int32_t num_preferred_agent_types = 0;
	u_int32_t num_avoided_agent_types = 0;

	if (parsed_parameters == NULL) {
		return EINVAL;
	}

	memset(parsed_parameters, 0, sizeof(struct necp_client_parsed_parameters));

	while ((offset + sizeof(struct necp_tlv_header)) <= parameters_size) {
		u_int8_t type = necp_buffer_get_tlv_type(parameters, offset);
		u_int32_t length = necp_buffer_get_tlv_length(parameters, offset);

		if (length > (parameters_size - (offset + sizeof(struct necp_tlv_header)))) {
			// If the length is larger than what can fit in the remaining parameters size, bail
			NECPLOG(LOG_ERR, "Invalid TLV length (%u)", length);
			break;
		}

		if (length > 0) {
			u_int8_t *value = necp_buffer_get_tlv_value(parameters, offset, NULL);
			if (value != NULL) {
				switch (type) {
				case NECP_CLIENT_PARAMETER_BOUND_INTERFACE: {
					if (length <= IFXNAMSIZ && length > 0) {
						ifnet_t bound_interface = NULL;
						char interface_name[IFXNAMSIZ];
						memcpy(interface_name, value, length);
						interface_name[length - 1] = 0;         // Make sure the string is NULL terminated
						if (ifnet_find_by_name(interface_name, &bound_interface) == 0) {
							parsed_parameters->required_interface_index = bound_interface->if_index;
							parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IF;
							ifnet_release(bound_interface);
						}
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_LOCAL_ADDRESS: {
					if (length >= sizeof(struct necp_policy_condition_addr)) {
						struct necp_policy_condition_addr *address_struct = (struct necp_policy_condition_addr *)(void *)value;
						if (necp_client_address_is_valid(&address_struct->address.sa)) {
							memcpy(&parsed_parameters->local_addr, &address_struct->address, sizeof(address_struct->address));
							if (!necp_address_is_wildcard(&parsed_parameters->local_addr)) {
								parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_LOCAL_ADDR;
							}
							if ((parsed_parameters->local_addr.sa.sa_family == AF_INET && parsed_parameters->local_addr.sin.sin_port) ||
							    (parsed_parameters->local_addr.sa.sa_family == AF_INET6 && parsed_parameters->local_addr.sin6.sin6_port)) {
								parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_LOCAL_PORT;
							}
						}
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_LOCAL_ENDPOINT: {
					if (length >= sizeof(struct necp_client_endpoint)) {
						struct necp_client_endpoint *endpoint = (struct necp_client_endpoint *)(void *)value;
						if (necp_client_address_is_valid(&endpoint->u.sa)) {
							memcpy(&parsed_parameters->local_addr, &endpoint->u.sa, sizeof(union necp_sockaddr_union));
							if (!necp_address_is_wildcard(&parsed_parameters->local_addr)) {
								parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_LOCAL_ADDR;
							}
							if ((parsed_parameters->local_addr.sa.sa_family == AF_INET && parsed_parameters->local_addr.sin.sin_port) ||
							    (parsed_parameters->local_addr.sa.sa_family == AF_INET6 && parsed_parameters->local_addr.sin6.sin6_port)) {
								parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_LOCAL_PORT;
							}
						}
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_REMOTE_ADDRESS: {
					if (length >= sizeof(struct necp_policy_condition_addr)) {
						struct necp_policy_condition_addr *address_struct = (struct necp_policy_condition_addr *)(void *)value;
						if (necp_client_address_is_valid(&address_struct->address.sa)) {
							memcpy(&parsed_parameters->remote_addr, &address_struct->address, sizeof(address_struct->address));
							parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_REMOTE_ADDR;
						}
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_REMOTE_ENDPOINT: {
					if (length >= sizeof(struct necp_client_endpoint)) {
						struct necp_client_endpoint *endpoint = (struct necp_client_endpoint *)(void *)value;
						if (necp_client_address_is_valid(&endpoint->u.sa)) {
							memcpy(&parsed_parameters->remote_addr, &endpoint->u.sa, sizeof(union necp_sockaddr_union));
							parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_REMOTE_ADDR;
						}
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_PROHIBIT_INTERFACE: {
					if (num_prohibited_interfaces >= NECP_MAX_PARSED_PARAMETERS) {
						break;
					}
					if (length <= IFXNAMSIZ && length > 0) {
						memcpy(parsed_parameters->prohibited_interfaces[num_prohibited_interfaces], value, length);
						parsed_parameters->prohibited_interfaces[num_prohibited_interfaces][length - 1] = 0;         // Make sure the string is NULL terminated
						num_prohibited_interfaces++;
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_IF;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_REQUIRE_IF_TYPE: {
					if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IFTYPE) {
						break;
					}
					if (length >= sizeof(u_int8_t)) {
						memcpy(&parsed_parameters->required_interface_type, value, sizeof(u_int8_t));
						if (parsed_parameters->required_interface_type) {
							parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IFTYPE;
						}
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_PROHIBIT_IF_TYPE: {
					if (num_prohibited_interface_types >= NECP_MAX_PARSED_PARAMETERS) {
						break;
					}
					if (length >= sizeof(u_int8_t)) {
						memcpy(&parsed_parameters->prohibited_interface_types[num_prohibited_interface_types], value, sizeof(u_int8_t));
						num_prohibited_interface_types++;
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_IFTYPE;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_REQUIRE_AGENT: {
					if (num_required_agents >= NECP_MAX_PARSED_PARAMETERS) {
						break;
					}
					if (length >= sizeof(uuid_t)) {
						memcpy(&parsed_parameters->required_netagents[num_required_agents], value, sizeof(uuid_t));
						num_required_agents++;
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_PROHIBIT_AGENT: {
					if (num_prohibited_agents >= NECP_MAX_PARSED_PARAMETERS) {
						break;
					}
					if (length >= sizeof(uuid_t)) {
						memcpy(&parsed_parameters->prohibited_netagents[num_prohibited_agents], value, sizeof(uuid_t));
						num_prohibited_agents++;
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_AGENT;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_PREFER_AGENT: {
					if (num_preferred_agents >= NECP_MAX_PARSED_PARAMETERS) {
						break;
					}
					if (length >= sizeof(uuid_t)) {
						memcpy(&parsed_parameters->preferred_netagents[num_preferred_agents], value, sizeof(uuid_t));
						num_preferred_agents++;
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_PREFERRED_AGENT;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_AVOID_AGENT: {
					if (num_avoided_agents >= NECP_MAX_PARSED_PARAMETERS) {
						break;
					}
					if (length >= sizeof(uuid_t)) {
						memcpy(&parsed_parameters->avoided_netagents[num_avoided_agents], value, sizeof(uuid_t));
						num_avoided_agents++;
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_AVOIDED_AGENT;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_REQUIRE_AGENT_TYPE: {
					if (num_required_agent_types >= NECP_MAX_PARSED_PARAMETERS) {
						break;
					}
					if (length >= sizeof(struct necp_client_parameter_netagent_type)) {
						memcpy(&parsed_parameters->required_netagent_types[num_required_agent_types], value, sizeof(struct necp_client_parameter_netagent_type));
						num_required_agent_types++;
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT_TYPE;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_PROHIBIT_AGENT_TYPE: {
					if (num_prohibited_agent_types >= NECP_MAX_PARSED_PARAMETERS) {
						break;
					}
					if (length >= sizeof(struct necp_client_parameter_netagent_type)) {
						memcpy(&parsed_parameters->prohibited_netagent_types[num_prohibited_agent_types], value, sizeof(struct necp_client_parameter_netagent_type));
						num_prohibited_agent_types++;
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_AGENT_TYPE;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_PREFER_AGENT_TYPE: {
					if (num_preferred_agent_types >= NECP_MAX_PARSED_PARAMETERS) {
						break;
					}
					if (length >= sizeof(struct necp_client_parameter_netagent_type)) {
						memcpy(&parsed_parameters->preferred_netagent_types[num_preferred_agent_types], value, sizeof(struct necp_client_parameter_netagent_type));
						num_preferred_agent_types++;
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_PREFERRED_AGENT_TYPE;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_AVOID_AGENT_TYPE: {
					if (num_avoided_agent_types >= NECP_MAX_PARSED_PARAMETERS) {
						break;
					}
					if (length >= sizeof(struct necp_client_parameter_netagent_type)) {
						memcpy(&parsed_parameters->avoided_netagent_types[num_avoided_agent_types], value, sizeof(struct necp_client_parameter_netagent_type));
						num_avoided_agent_types++;
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_AVOIDED_AGENT_TYPE;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_FLAGS: {
					if (length >= sizeof(u_int32_t)) {
						memcpy(&parsed_parameters->flags, value, sizeof(parsed_parameters->flags));
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_FLAGS;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_IP_PROTOCOL: {
					if (length >= sizeof(parsed_parameters->ip_protocol)) {
						memcpy(&parsed_parameters->ip_protocol, value, sizeof(parsed_parameters->ip_protocol));
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_IP_PROTOCOL;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_PID: {
					if (length >= sizeof(parsed_parameters->effective_pid)) {
						memcpy(&parsed_parameters->effective_pid, value, sizeof(parsed_parameters->effective_pid));
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_EFFECTIVE_PID;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_APPLICATION: {
					if (length >= sizeof(parsed_parameters->effective_uuid)) {
						memcpy(&parsed_parameters->effective_uuid, value, sizeof(parsed_parameters->effective_uuid));
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_EFFECTIVE_UUID;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_TRAFFIC_CLASS: {
					if (length >= sizeof(parsed_parameters->traffic_class)) {
						memcpy(&parsed_parameters->traffic_class, value, sizeof(parsed_parameters->traffic_class));
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_TRAFFIC_CLASS;
					}
					break;
				}
				default: {
					break;
				}
				}
			}
		}

		offset += sizeof(struct necp_tlv_header) + length;
	}

	return error;
}

static int
necp_client_parse_result(u_int8_t *result,
    u_int32_t result_size,
    union necp_sockaddr_union *local_address,
    union necp_sockaddr_union *remote_address,
    void **flow_stats)
{
#pragma unused(flow_stats)
	int error = 0;
	size_t offset = 0;

	while ((offset + sizeof(struct necp_tlv_header)) <= result_size) {
		u_int8_t type = necp_buffer_get_tlv_type(result, offset);
		u_int32_t length = necp_buffer_get_tlv_length(result, offset);

		if (length > 0 && (offset + sizeof(struct necp_tlv_header) + length) <= result_size) {
			u_int8_t *value = necp_buffer_get_tlv_value(result, offset, NULL);
			if (value != NULL) {
				switch (type) {
				case NECP_CLIENT_RESULT_LOCAL_ENDPOINT: {
					if (length >= sizeof(struct necp_client_endpoint)) {
						struct necp_client_endpoint *endpoint = (struct necp_client_endpoint *)(void *)value;
						if (local_address != NULL && necp_client_address_is_valid(&endpoint->u.sa)) {
							memcpy(local_address, &endpoint->u.sa, endpoint->u.sa.sa_len);
						}
					}
					break;
				}
				case NECP_CLIENT_RESULT_REMOTE_ENDPOINT: {
					if (length >= sizeof(struct necp_client_endpoint)) {
						struct necp_client_endpoint *endpoint = (struct necp_client_endpoint *)(void *)value;
						if (remote_address != NULL && necp_client_address_is_valid(&endpoint->u.sa)) {
							memcpy(remote_address, &endpoint->u.sa, endpoint->u.sa.sa_len);
						}
					}
					break;
				}
				default: {
					break;
				}
				}
			}
		}

		offset += sizeof(struct necp_tlv_header) + length;
	}

	return error;
}

static struct necp_client_flow_registration *
necp_client_create_flow_registration(struct necp_fd_data *fd_data, struct necp_client *client)
{
	NECP_FD_ASSERT_LOCKED(fd_data);
	NECP_CLIENT_ASSERT_LOCKED(client);

	struct necp_client_flow_registration *new_registration = mcache_alloc(necp_flow_registration_cache, MCR_SLEEP);
	if (new_registration == NULL) {
		return NULL;
	}

	memset(new_registration, 0, sizeof(*new_registration));

	new_registration->last_interface_details = combine_interface_details(IFSCOPE_NONE, NSTAT_IFNET_IS_UNKNOWN_TYPE);

	necp_generate_client_id(new_registration->registration_id, true);
	LIST_INIT(&new_registration->flow_list);

	// Add registration to client list
	RB_INSERT(_necp_client_flow_tree, &client->flow_registrations, new_registration);

	// Add registration to fd list
	RB_INSERT(_necp_fd_flow_tree, &fd_data->flows, new_registration);

	// Add registration to global tree for lookup
	NECP_FLOW_TREE_LOCK_EXCLUSIVE();
	RB_INSERT(_necp_client_flow_global_tree, &necp_client_flow_global_tree, new_registration);
	NECP_FLOW_TREE_UNLOCK();

	new_registration->client = client;

	// Start out assuming there is nothing to read from the flow
	new_registration->flow_result_read = true;

	return new_registration;
}

static void
necp_client_add_socket_flow(struct necp_client_flow_registration *flow_registration,
    struct inpcb *inp)
{
	struct necp_client_flow *new_flow = mcache_alloc(necp_flow_cache, MCR_SLEEP);
	if (new_flow == NULL) {
		NECPLOG0(LOG_ERR, "Failed to allocate socket flow");
		return;
	}

	memset(new_flow, 0, sizeof(*new_flow));

	new_flow->socket = TRUE;
	new_flow->u.socket_handle = inp;
	new_flow->u.cb = inp->necp_cb;

	OSIncrementAtomic(&necp_socket_flow_count);

	LIST_INSERT_HEAD(&flow_registration->flow_list, new_flow, flow_chain);
}

int
necp_client_register_socket_flow(pid_t pid, uuid_t client_id, struct inpcb *inp)
{
	int error = 0;
	struct necp_fd_data *client_fd = NULL;
	bool found_client = FALSE;

	NECP_FD_LIST_LOCK_SHARED();
	LIST_FOREACH(client_fd, &necp_fd_list, chain) {
		NECP_FD_LOCK(client_fd);
		struct necp_client *client = necp_client_fd_find_client_and_lock(client_fd, client_id);
		if (client != NULL) {
			if (!pid || client->proc_pid == pid) {
				struct necp_client_flow_registration *flow_registration = necp_client_find_flow(client, client_id);
				if (flow_registration != NULL) {
					// Found the right client and flow registration, add a new flow
					found_client = TRUE;
					necp_client_add_socket_flow(flow_registration, inp);
				} else if (RB_EMPTY(&client->flow_registrations) && !necp_client_id_is_flow(client_id)) {
					// No flows yet on this client, add a new registration
					flow_registration = necp_client_create_flow_registration(client_fd, client);
					if (flow_registration == NULL) {
						error = ENOMEM;
					} else {
						// Add a new flow
						found_client = TRUE;
						necp_client_add_socket_flow(flow_registration, inp);
					}
				}
			}

			NECP_CLIENT_UNLOCK(client);
		}
		NECP_FD_UNLOCK(client_fd);

		if (found_client) {
			break;
		}
	}
	NECP_FD_LIST_UNLOCK();

	if (!found_client) {
		error = ENOENT;
	} else {
		// Count the sockets that have the NECP client UUID set
		struct socket *so = inp->inp_socket;
		if (!(so->so_flags1 & SOF1_HAS_NECP_CLIENT_UUID)) {
			so->so_flags1 |= SOF1_HAS_NECP_CLIENT_UUID;
			INC_ATOMIC_INT64_LIM(net_api_stats.nas_socket_necp_clientuuid_total);
		}
	}

	return error;
}

static void
necp_client_add_multipath_interface_flows(struct necp_client_flow_registration *flow_registration,
    struct necp_client *client,
    struct mppcb *mpp)
{
	flow_registration->interface_handle = mpp;
	flow_registration->interface_cb = mpp->necp_cb;

	proc_t proc = proc_find(client->proc_pid);
	if (proc == PROC_NULL) {
		return;
	}

	// Traverse all interfaces and add a tracking flow if needed
	necp_flow_add_interface_flows(proc, client, flow_registration, true);

	proc_rele(proc);
	proc = PROC_NULL;
}

int
necp_client_register_multipath_cb(pid_t pid, uuid_t client_id, struct mppcb *mpp)
{
	int error = 0;
	struct necp_fd_data *client_fd = NULL;
	bool found_client = FALSE;

	NECP_FD_LIST_LOCK_SHARED();
	LIST_FOREACH(client_fd, &necp_fd_list, chain) {
		NECP_FD_LOCK(client_fd);
		struct necp_client *client = necp_client_fd_find_client_and_lock(client_fd, client_id);
		if (client != NULL) {
			if (!pid || client->proc_pid == pid) {
				struct necp_client_flow_registration *flow_registration = necp_client_find_flow(client, client_id);
				if (flow_registration != NULL) {
					// Found the right client and flow registration, add a new flow
					found_client = TRUE;
					necp_client_add_multipath_interface_flows(flow_registration, client, mpp);
				} else if (RB_EMPTY(&client->flow_registrations) && !necp_client_id_is_flow(client_id)) {
					// No flows yet on this client, add a new registration
					flow_registration = necp_client_create_flow_registration(client_fd, client);
					if (flow_registration == NULL) {
						error = ENOMEM;
					} else {
						// Add a new flow
						found_client = TRUE;
						necp_client_add_multipath_interface_flows(flow_registration, client, mpp);
					}
				}
			}

			NECP_CLIENT_UNLOCK(client);
		}
		NECP_FD_UNLOCK(client_fd);

		if (found_client) {
			break;
		}
	}
	NECP_FD_LIST_UNLOCK();

	if (!found_client && error == 0) {
		error = ENOENT;
	}

	return error;
}

#define NETAGENT_DOMAIN_RADIO_MANAGER   "WirelessRadioManager"
#define NETAGENT_TYPE_RADIO_MANAGER     "WirelessRadioManager:BB Manager"

static int
necp_client_lookup_bb_radio_manager(struct necp_client *client,
    uuid_t netagent_uuid)
{
	char netagent_domain[NETAGENT_DOMAINSIZE];
	char netagent_type[NETAGENT_TYPESIZE];
	struct necp_aggregate_result result;
	proc_t proc;
	int error;

	proc = proc_find(client->proc_pid);
	if (proc == PROC_NULL) {
		return ESRCH;
	}

	error = necp_application_find_policy_match_internal(proc, client->parameters, (u_int32_t)client->parameters_length,
	    &result, NULL, 0, NULL, NULL, NULL, true);

	proc_rele(proc);
	proc = PROC_NULL;

	if (error) {
		return error;
	}

	for (int i = 0; i < NECP_MAX_NETAGENTS; i++) {
		if (uuid_is_null(result.netagents[i])) {
			// Passed end of valid agents
			break;
		}

		memset(&netagent_domain, 0, NETAGENT_DOMAINSIZE);
		memset(&netagent_type, 0, NETAGENT_TYPESIZE);
		if (netagent_get_agent_domain_and_type(result.netagents[i], netagent_domain, netagent_type) == FALSE) {
			continue;
		}

		if (strncmp(netagent_domain, NETAGENT_DOMAIN_RADIO_MANAGER, NETAGENT_DOMAINSIZE) != 0) {
			continue;
		}

		if (strncmp(netagent_type, NETAGENT_TYPE_RADIO_MANAGER, NETAGENT_TYPESIZE) != 0) {
			continue;
		}

		uuid_copy(netagent_uuid, result.netagents[i]);

		break;
	}

	return 0;
}

static int
necp_client_assert_bb_radio_manager_common(struct necp_client *client, bool assert)
{
	uuid_t netagent_uuid;
	uint8_t assert_type;
	int error;

	error = necp_client_lookup_bb_radio_manager(client, netagent_uuid);
	if (error) {
		NECPLOG0(LOG_ERR, "BB radio manager agent not found");
		return error;
	}

	// Before unasserting, verify that the assertion was already taken
	if (assert == FALSE) {
		assert_type = NETAGENT_MESSAGE_TYPE_CLIENT_UNASSERT;

		if (!necp_client_remove_assertion(client, netagent_uuid)) {
			return EINVAL;
		}
	} else {
		assert_type = NETAGENT_MESSAGE_TYPE_CLIENT_ASSERT;
	}

	error = netagent_client_message(netagent_uuid, client->client_id, client->proc_pid, client->agent_handle, assert_type);
	if (error) {
		NECPLOG0(LOG_ERR, "netagent_client_message failed");
		return error;
	}

	// Only save the assertion if the action succeeded
	if (assert == TRUE) {
		necp_client_add_assertion(client, netagent_uuid);
	}

	return 0;
}

int
necp_client_assert_bb_radio_manager(uuid_t client_id, bool assert)
{
	struct necp_client *client;
	int error = 0;

	NECP_CLIENT_TREE_LOCK_SHARED();

	client = necp_find_client_and_lock(client_id);

	if (client) {
		// Found the right client!
		error = necp_client_assert_bb_radio_manager_common(client, assert);

		NECP_CLIENT_UNLOCK(client);
	} else {
		NECPLOG0(LOG_ERR, "Couldn't find client");
		error = ENOENT;
	}

	NECP_CLIENT_TREE_UNLOCK();

	return error;
}

static int
necp_client_unregister_socket_flow(uuid_t client_id, void *handle)
{
	int error = 0;
	struct necp_fd_data *client_fd = NULL;
	bool found_client = FALSE;
	bool client_updated = FALSE;

	NECP_FD_LIST_LOCK_SHARED();
	LIST_FOREACH(client_fd, &necp_fd_list, chain) {
		NECP_FD_LOCK(client_fd);

		struct necp_client *client = necp_client_fd_find_client_and_lock(client_fd, client_id);
		if (client != NULL) {
			struct necp_client_flow_registration *flow_registration = necp_client_find_flow(client, client_id);
			if (flow_registration != NULL) {
				// Found the right client and flow!
				found_client = TRUE;

				// Remove flow assignment
				struct necp_client_flow *search_flow = NULL;
				struct necp_client_flow *temp_flow = NULL;
				LIST_FOREACH_SAFE(search_flow, &flow_registration->flow_list, flow_chain, temp_flow) {
					if (search_flow->socket && search_flow->u.socket_handle == handle) {
						if (search_flow->assigned_results != NULL) {
							FREE(search_flow->assigned_results, M_NETAGENT);
							search_flow->assigned_results = NULL;
						}
						client_updated = TRUE;
						flow_registration->flow_result_read = FALSE;
						LIST_REMOVE(search_flow, flow_chain);
						OSDecrementAtomic(&necp_socket_flow_count);
						mcache_free(necp_flow_cache, search_flow);
					}
				}
			}

			NECP_CLIENT_UNLOCK(client);
		}

		if (client_updated) {
			necp_fd_notify(client_fd, true);
		}
		NECP_FD_UNLOCK(client_fd);

		if (found_client) {
			break;
		}
	}
	NECP_FD_LIST_UNLOCK();

	if (!found_client) {
		error = ENOENT;
	}

	return error;
}

static int
necp_client_unregister_multipath_cb(uuid_t client_id, void *handle)
{
	int error = 0;
	bool found_client = FALSE;

	NECP_CLIENT_TREE_LOCK_SHARED();

	struct necp_client *client = necp_find_client_and_lock(client_id);
	if (client != NULL) {
		struct necp_client_flow_registration *flow_registration = necp_client_find_flow(client, client_id);
		if (flow_registration != NULL) {
			// Found the right client and flow!
			found_client = TRUE;

			// Remove flow assignment
			struct necp_client_flow *search_flow = NULL;
			struct necp_client_flow *temp_flow = NULL;
			LIST_FOREACH_SAFE(search_flow, &flow_registration->flow_list, flow_chain, temp_flow) {
				if (!search_flow->socket && !search_flow->nexus &&
				    search_flow->u.socket_handle == handle) {
					search_flow->u.socket_handle = NULL;
					search_flow->u.cb = NULL;
				}
			}

			flow_registration->interface_handle = NULL;
			flow_registration->interface_cb = NULL;
		}

		NECP_CLIENT_UNLOCK(client);
	}

	NECP_CLIENT_TREE_UNLOCK();

	if (!found_client) {
		error = ENOENT;
	}

	return error;
}

int
necp_client_assign_from_socket(pid_t pid, uuid_t client_id, struct inpcb *inp)
{
	int error = 0;
	struct necp_fd_data *client_fd = NULL;
	bool found_client = FALSE;
	bool client_updated = FALSE;

	NECP_FD_LIST_LOCK_SHARED();
	LIST_FOREACH(client_fd, &necp_fd_list, chain) {
		if (pid && client_fd->proc_pid != pid) {
			continue;
		}

		proc_t proc = proc_find(client_fd->proc_pid);
		if (proc == PROC_NULL) {
			continue;
		}

		NECP_FD_LOCK(client_fd);

		struct necp_client *client = necp_client_fd_find_client_and_lock(client_fd, client_id);
		if (client != NULL) {
			struct necp_client_flow_registration *flow_registration = necp_client_find_flow(client, client_id);
			if (flow_registration == NULL && RB_EMPTY(&client->flow_registrations) && !necp_client_id_is_flow(client_id)) {
				// No flows yet on this client, add a new registration
				flow_registration = necp_client_create_flow_registration(client_fd, client);
				if (flow_registration == NULL) {
					error = ENOMEM;
				}
			}
			if (flow_registration != NULL) {
				// Found the right client and flow!
				found_client = TRUE;

				struct necp_client_flow *flow = NULL;
				LIST_FOREACH(flow, &flow_registration->flow_list, flow_chain) {
					if (flow->socket && flow->u.socket_handle == inp) {
						// Release prior results and route
						if (flow->assigned_results != NULL) {
							FREE(flow->assigned_results, M_NETAGENT);
							flow->assigned_results = NULL;
						}

						ifnet_t ifp = NULL;
						if ((inp->inp_flags & INP_BOUND_IF) && inp->inp_boundifp) {
							ifp = inp->inp_boundifp;
						} else {
							ifp = inp->inp_last_outifp;
						}

						if (ifp != NULL) {
							flow->interface_index = ifp->if_index;
						} else {
							flow->interface_index = IFSCOPE_NONE;
						}

						if (inp->inp_vflag & INP_IPV4) {
							flow->local_addr.sin.sin_family = AF_INET;
							flow->local_addr.sin.sin_len = sizeof(struct sockaddr_in);
							flow->local_addr.sin.sin_port = inp->inp_lport;
							memcpy(&flow->local_addr.sin.sin_addr, &inp->inp_laddr, sizeof(struct in_addr));

							flow->remote_addr.sin.sin_family = AF_INET;
							flow->remote_addr.sin.sin_len = sizeof(struct sockaddr_in);
							flow->remote_addr.sin.sin_port = inp->inp_fport;
							memcpy(&flow->remote_addr.sin.sin_addr, &inp->inp_faddr, sizeof(struct in_addr));
						} else if (inp->inp_vflag & INP_IPV6) {
							in6_ip6_to_sockaddr(&inp->in6p_laddr, inp->inp_lport, &flow->local_addr.sin6, sizeof(flow->local_addr));
							in6_ip6_to_sockaddr(&inp->in6p_faddr, inp->inp_fport, &flow->remote_addr.sin6, sizeof(flow->remote_addr));
						}

						flow->viable = necp_client_flow_is_viable(proc, client, flow);

						uuid_t empty_uuid;
						uuid_clear(empty_uuid);
						flow->assigned = TRUE;
						flow->assigned_results = necp_create_nexus_assign_message(empty_uuid, 0, NULL, 0,
						    (struct necp_client_endpoint *)&flow->local_addr,
						    (struct necp_client_endpoint *)&flow->remote_addr,
						    0, NULL, &flow->assigned_results_length);
						flow_registration->flow_result_read = FALSE;
						client_updated = TRUE;
						break;
					}
				}
			}

			NECP_CLIENT_UNLOCK(client);
		}
		if (client_updated) {
			necp_fd_notify(client_fd, true);
		}
		NECP_FD_UNLOCK(client_fd);

		proc_rele(proc);
		proc = PROC_NULL;

		if (found_client) {
			break;
		}
	}
	NECP_FD_LIST_UNLOCK();

	if (error == 0) {
		if (!found_client) {
			error = ENOENT;
		} else if (!client_updated) {
			error = EINVAL;
		}
	}

	return error;
}

int
necp_update_flow_protoctl_event(uuid_t netagent_uuid, uuid_t client_id,
    uint32_t protoctl_event_code, uint32_t protoctl_event_val,
    uint32_t protoctl_event_tcp_seq_number)
{
	int error = 0;
	struct necp_fd_data *client_fd = NULL;
	bool found_client = FALSE;
	bool client_updated = FALSE;

	NECP_FD_LIST_LOCK_SHARED();
	LIST_FOREACH(client_fd, &necp_fd_list, chain) {
		proc_t proc = proc_find(client_fd->proc_pid);
		if (proc == PROC_NULL) {
			continue;
		}

		NECP_FD_LOCK(client_fd);

		struct necp_client *client = necp_client_fd_find_client_and_lock(client_fd, client_id);
		if (client != NULL) {
			struct necp_client_flow_registration *flow_registration = necp_client_find_flow(client, client_id);
			if (flow_registration != NULL) {
				// Found the right client and flow!
				found_client = TRUE;

				struct necp_client_flow *flow = NULL;
				LIST_FOREACH(flow, &flow_registration->flow_list, flow_chain) {
					// Verify that the client nexus agent matches
					if (flow->nexus &&
					    uuid_compare(flow->u.nexus_agent,
					    netagent_uuid) == 0) {
						flow->has_protoctl_event = TRUE;
						flow->protoctl_event.protoctl_event_code = protoctl_event_code;
						flow->protoctl_event.protoctl_event_val = protoctl_event_val;
						flow->protoctl_event.protoctl_event_tcp_seq_num = protoctl_event_tcp_seq_number;
						flow_registration->flow_result_read = FALSE;
						client_updated = TRUE;
						break;
					}
				}
			}

			NECP_CLIENT_UNLOCK(client);
		}

		if (client_updated) {
			necp_fd_notify(client_fd, true);
		}

		NECP_FD_UNLOCK(client_fd);
		proc_rele(proc);
		proc = PROC_NULL;

		if (found_client) {
			break;
		}
	}
	NECP_FD_LIST_UNLOCK();

	if (!found_client) {
		error = ENOENT;
	} else if (!client_updated) {
		error = EINVAL;
	}
	return error;
}

static bool
necp_assign_client_result_locked(struct proc *proc,
    struct necp_fd_data *client_fd,
    struct necp_client *client,
    struct necp_client_flow_registration *flow_registration,
    uuid_t netagent_uuid,
    u_int8_t *assigned_results,
    size_t assigned_results_length,
    bool notify_fd)
{
	bool client_updated = FALSE;

	NECP_FD_ASSERT_LOCKED(client_fd);
	NECP_CLIENT_ASSERT_LOCKED(client);

	struct necp_client_flow *flow = NULL;
	LIST_FOREACH(flow, &flow_registration->flow_list, flow_chain) {
		// Verify that the client nexus agent matches
		if (flow->nexus &&
		    uuid_compare(flow->u.nexus_agent, netagent_uuid) == 0) {
			// Release prior results and route
			if (flow->assigned_results != NULL) {
				FREE(flow->assigned_results, M_NETAGENT);
				flow->assigned_results = NULL;
			}

			void *nexus_stats = NULL;
			if (assigned_results != NULL && assigned_results_length > 0) {
				int error = necp_client_parse_result(assigned_results, (u_int32_t)assigned_results_length,
				    &flow->local_addr, &flow->remote_addr, &nexus_stats);
				VERIFY(error == 0);
			}

			flow->viable = necp_client_flow_is_viable(proc, client, flow);

			flow->assigned = TRUE;
			flow->assigned_results = assigned_results;
			flow->assigned_results_length = assigned_results_length;
			flow_registration->flow_result_read = FALSE;
			client_updated = TRUE;
			break;
		}
	}

	if (client_updated && notify_fd) {
		necp_fd_notify(client_fd, true);
	}

	// if not updated, client must free assigned_results
	return client_updated;
}

int
necp_assign_client_result(uuid_t netagent_uuid, uuid_t client_id,
    u_int8_t *assigned_results, size_t assigned_results_length)
{
	int error = 0;
	struct necp_fd_data *client_fd = NULL;
	bool found_client = FALSE;
	bool client_updated = FALSE;

	NECP_FD_LIST_LOCK_SHARED();

	LIST_FOREACH(client_fd, &necp_fd_list, chain) {
		proc_t proc = proc_find(client_fd->proc_pid);
		if (proc == PROC_NULL) {
			continue;
		}

		NECP_FD_LOCK(client_fd);
		struct necp_client *client = necp_client_fd_find_client_and_lock(client_fd, client_id);
		if (client != NULL) {
			struct necp_client_flow_registration *flow_registration = necp_client_find_flow(client, client_id);
			if (flow_registration != NULL) {
				// Found the right client and flow!
				found_client = TRUE;
				if (necp_assign_client_result_locked(proc, client_fd, client, flow_registration, netagent_uuid,
				    assigned_results, assigned_results_length, true)) {
					client_updated = TRUE;
				}
			}

			NECP_CLIENT_UNLOCK(client);
		}
		NECP_FD_UNLOCK(client_fd);

		proc_rele(proc);
		proc = PROC_NULL;

		if (found_client) {
			break;
		}
	}

	NECP_FD_LIST_UNLOCK();

	// upon error, client must free assigned_results
	if (!found_client) {
		error = ENOENT;
	} else if (!client_updated) {
		error = EINVAL;
	}

	return error;
}

/// Client updating

static bool
necp_update_parsed_parameters(struct necp_client_parsed_parameters *parsed_parameters,
    struct necp_aggregate_result *result)
{
	if (parsed_parameters == NULL ||
	    result == NULL) {
		return false;
	}

	bool updated = false;
	for (int i = 0; i < NECP_MAX_NETAGENTS; i++) {
		if (uuid_is_null(result->netagents[i])) {
			// Passed end of valid agents
			break;
		}

		if (!(result->netagent_use_flags[i] & NECP_AGENT_USE_FLAG_SCOPE)) {
			// Not a scoped agent, ignore
			continue;
		}

		// This is a scoped agent. Add it to the required agents.
		if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT) {
			// Already some required agents, add this at the end
			for (int j = 0; j < NECP_MAX_PARSED_PARAMETERS; j++) {
				if (uuid_compare(parsed_parameters->required_netagents[j], result->netagents[i]) == 0) {
					// Already required, break
					break;
				}
				if (uuid_is_null(parsed_parameters->required_netagents[j])) {
					// Add here
					memcpy(&parsed_parameters->required_netagents[j], result->netagents[i], sizeof(uuid_t));
					updated = true;
					break;
				}
			}
		} else {
			// No required agents yet, add this one
			parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT;
			memcpy(&parsed_parameters->required_netagents[0], result->netagents[i], sizeof(uuid_t));
			updated = true;
		}

		// Remove requirements for agents of the same type
		if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT_TYPE) {
			char remove_agent_domain[NETAGENT_DOMAINSIZE] = { 0 };
			char remove_agent_type[NETAGENT_TYPESIZE] = { 0 };
			if (netagent_get_agent_domain_and_type(result->netagents[i], remove_agent_domain, remove_agent_type)) {
				for (int j = 0; j < NECP_MAX_PARSED_PARAMETERS; j++) {
					if (strlen(parsed_parameters->required_netagent_types[j].netagent_domain) == 0 &&
					    strlen(parsed_parameters->required_netagent_types[j].netagent_type) == 0) {
						break;
					}

					if (strncmp(parsed_parameters->required_netagent_types[j].netagent_domain, remove_agent_domain, NETAGENT_DOMAINSIZE) == 0 &&
					    strncmp(parsed_parameters->required_netagent_types[j].netagent_type, remove_agent_type, NETAGENT_TYPESIZE) == 0) {
						updated = true;

						if (j == NECP_MAX_PARSED_PARAMETERS - 1) {
							// Last field, just clear and break
							memset(&parsed_parameters->required_netagent_types[NECP_MAX_PARSED_PARAMETERS - 1], 0, sizeof(struct necp_client_parameter_netagent_type));
							break;
						} else {
							// Move the parameters down, clear the last entry
							memmove(&parsed_parameters->required_netagent_types[j],
							    &parsed_parameters->required_netagent_types[j + 1],
							    sizeof(struct necp_client_parameter_netagent_type) * (NECP_MAX_PARSED_PARAMETERS - (j + 1)));
							memset(&parsed_parameters->required_netagent_types[NECP_MAX_PARSED_PARAMETERS - 1], 0, sizeof(struct necp_client_parameter_netagent_type));
							// Continue, don't increment but look at the new shifted item instead
							continue;
						}
					}

					// Increment j to look at the next agent type parameter
					j++;
				}
			}
		}
	}

	if (updated &&
	    parsed_parameters->required_interface_index != IFSCOPE_NONE &&
	    (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IF) == 0) {
		// A required interface index was added after the fact. Clear it.
		parsed_parameters->required_interface_index = IFSCOPE_NONE;
	}


	return updated;
}

static inline bool
necp_agent_types_match(const char *agent_domain1, const char *agent_type1,
    const char *agent_domain2, const char *agent_type2)
{
	return (strlen(agent_domain1) == 0 ||
	       strncmp(agent_domain2, agent_domain1, NETAGENT_DOMAINSIZE) == 0) &&
	       (strlen(agent_type1) == 0 ||
	       strncmp(agent_type2, agent_type1, NETAGENT_TYPESIZE) == 0);
}

static inline bool
necp_calculate_client_result(proc_t proc,
    struct necp_client *client,
    struct necp_client_parsed_parameters *parsed_parameters,
    struct necp_aggregate_result *result,
    u_int32_t *flags)
{
	struct rtentry *route = NULL;

	// Check parameters to find best interface
	bool validate_agents = false;
	u_int matching_if_index = 0;
	if (necp_find_matching_interface_index(parsed_parameters, &matching_if_index, &validate_agents)) {
		if (matching_if_index != 0) {
			parsed_parameters->required_interface_index = matching_if_index;
		}
		// Interface found or not needed, match policy.
		memset(result, 0, sizeof(*result));
		int error = necp_application_find_policy_match_internal(proc, client->parameters,
		    (u_int32_t)client->parameters_length,
		    result, flags, matching_if_index,
		    NULL, NULL, &route, false);
		if (error != 0) {
			if (route != NULL) {
				rtfree(route);
			}
			return FALSE;
		}

		if (validate_agents) {
			bool requirement_failed = FALSE;
			if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT) {
				for (int i = 0; i < NECP_MAX_PARSED_PARAMETERS; i++) {
					if (uuid_is_null(parsed_parameters->required_netagents[i])) {
						break;
					}

					bool requirement_found = FALSE;
					for (int j = 0; j < NECP_MAX_NETAGENTS; j++) {
						if (uuid_is_null(result->netagents[j])) {
							break;
						}

						if (uuid_compare(parsed_parameters->required_netagents[i], result->netagents[j]) == 0) {
							requirement_found = TRUE;
							break;
						}
					}

					if (!requirement_found) {
						requirement_failed = TRUE;
						break;
					}
				}
			}

			if (!requirement_failed && parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT_TYPE) {
				for (int i = 0; i < NECP_MAX_PARSED_PARAMETERS; i++) {
					if (strlen(parsed_parameters->required_netagent_types[i].netagent_domain) == 0 &&
					    strlen(parsed_parameters->required_netagent_types[i].netagent_type) == 0) {
						break;
					}

					bool requirement_found = FALSE;
					for (int j = 0; j < NECP_MAX_NETAGENTS; j++) {
						if (uuid_is_null(result->netagents[j])) {
							break;
						}

						char policy_agent_domain[NETAGENT_DOMAINSIZE] = { 0 };
						char policy_agent_type[NETAGENT_TYPESIZE] = { 0 };

						if (netagent_get_agent_domain_and_type(result->netagents[j], policy_agent_domain, policy_agent_type)) {
							if (necp_agent_types_match(parsed_parameters->required_netagent_types[i].netagent_domain,
							    parsed_parameters->required_netagent_types[i].netagent_type,
							    policy_agent_domain, policy_agent_type)) {
								requirement_found = TRUE;
								break;
							}
						}
					}

					if (!requirement_found) {
						requirement_failed = TRUE;
						break;
					}
				}
			}

			if (requirement_failed) {
				// Agent requirement failed. Clear out the whole result, make everything fail.
				memset(result, 0, sizeof(*result));
				if (route != NULL) {
					rtfree(route);
				}
				return TRUE;
			}
		}

		// Reset current route
		NECP_CLIENT_ROUTE_LOCK(client);
		if (client->current_route != NULL) {
			rtfree(client->current_route);
		}
		client->current_route = route;
		NECP_CLIENT_ROUTE_UNLOCK(client);
	} else {
		// Interface not found. Clear out the whole result, make everything fail.
		memset(result, 0, sizeof(*result));
	}

	return TRUE;
}

static bool
necp_update_client_result(proc_t proc,
    struct necp_fd_data *client_fd,
    struct necp_client *client,
    struct _necp_flow_defunct_list *defunct_list)
{
	struct necp_client_result_netagent netagent;
	struct necp_aggregate_result result;
	struct necp_client_parsed_parameters *parsed_parameters = NULL;
	u_int32_t flags = 0;

	NECP_CLIENT_ASSERT_LOCKED(client);

	MALLOC(parsed_parameters, struct necp_client_parsed_parameters *, sizeof(*parsed_parameters), M_NECP, (M_WAITOK | M_ZERO));
	if (parsed_parameters == NULL) {
		NECPLOG0(LOG_ERR, "Failed to allocate parsed parameters");
		return FALSE;
	}

	// Nexus flows will be brought back if they are still valid
	necp_client_mark_all_nonsocket_flows_as_invalid(client);

	int error = necp_client_parse_parameters(client->parameters, (u_int32_t)client->parameters_length, parsed_parameters);
	if (error != 0) {
		FREE(parsed_parameters, M_NECP);
		return FALSE;
	}

	// Update saved IP protocol
	client->ip_protocol = parsed_parameters->ip_protocol;

	// Calculate the policy result
	if (!necp_calculate_client_result(proc, client, parsed_parameters, &result, &flags)) {
		FREE(parsed_parameters, M_NECP);
		return FALSE;
	}

	if (necp_update_parsed_parameters(parsed_parameters, &result)) {
		// Changed the parameters based on result, try again (only once)
		if (!necp_calculate_client_result(proc, client, parsed_parameters, &result, &flags)) {
			FREE(parsed_parameters, M_NECP);
			return FALSE;
		}
	}

	// Save the last policy id on the client
	client->policy_id = result.policy_id;

	if ((parsed_parameters->flags & NECP_CLIENT_PARAMETER_FLAG_MULTIPATH) ||
	    ((parsed_parameters->flags & NECP_CLIENT_PARAMETER_FLAG_LISTENER) &&
	    result.routing_result != NECP_KERNEL_POLICY_RESULT_SOCKET_SCOPED)) {
		client->allow_multiple_flows = TRUE;
	} else {
		client->allow_multiple_flows = FALSE;
	}

	// If the original request was scoped, and the policy result matches, make sure the result is scoped
	if ((result.routing_result == NECP_KERNEL_POLICY_RESULT_NONE ||
	    result.routing_result == NECP_KERNEL_POLICY_RESULT_PASS) &&
	    result.routed_interface_index != IFSCOPE_NONE &&
	    parsed_parameters->required_interface_index == result.routed_interface_index) {
		result.routing_result = NECP_KERNEL_POLICY_RESULT_SOCKET_SCOPED;
		result.routing_result_parameter.scoped_interface_index = result.routed_interface_index;
	}

	if (defunct_list != NULL &&
	    result.routing_result == NECP_KERNEL_POLICY_RESULT_DROP) {
		// If we are forced to drop the client, defunct it if it has flows
		necp_defunct_client_for_policy(client, defunct_list);
	}

	// Recalculate flags
	if (parsed_parameters->flags & NECP_CLIENT_PARAMETER_FLAG_LISTENER) {
		// Listeners are valid as long as they aren't dropped
		if (result.routing_result != NECP_KERNEL_POLICY_RESULT_DROP) {
			flags |= NECP_CLIENT_RESULT_FLAG_SATISFIED;
		}
	} else if (result.routed_interface_index != 0) {
		// Clients without flows determine viability based on having some routable interface
		flags |= NECP_CLIENT_RESULT_FLAG_SATISFIED;
	}

	bool updated = FALSE;
	u_int8_t *cursor = client->result;
	cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_FLAGS, sizeof(flags), &flags, &updated, client->result, sizeof(client->result));
	cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_CLIENT_ID, sizeof(uuid_t), client->client_id, &updated,
	    client->result, sizeof(client->result));
	cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_POLICY_RESULT, sizeof(result.routing_result), &result.routing_result, &updated,
	    client->result, sizeof(client->result));
	if (result.routing_result_parameter.tunnel_interface_index != 0) {
		cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_POLICY_RESULT_PARAMETER,
		    sizeof(result.routing_result_parameter), &result.routing_result_parameter, &updated,
		    client->result, sizeof(client->result));
	}
	if (result.filter_control_unit != 0) {
		cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_FILTER_CONTROL_UNIT,
		    sizeof(result.filter_control_unit), &result.filter_control_unit, &updated,
		    client->result, sizeof(client->result));
	}
	if (result.routed_interface_index != 0) {
		u_int routed_interface_index = result.routed_interface_index;
		if (result.routing_result == NECP_KERNEL_POLICY_RESULT_IP_TUNNEL &&
		    parsed_parameters->required_interface_index != IFSCOPE_NONE &&
		    parsed_parameters->required_interface_index != result.routed_interface_index) {
			routed_interface_index = parsed_parameters->required_interface_index;
		}

		cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_INTERFACE_INDEX,
		    sizeof(routed_interface_index), &routed_interface_index, &updated,
		    client->result, sizeof(client->result));
	}
	if (client_fd && client_fd->flags & NECP_OPEN_FLAG_BACKGROUND) {
		u_int32_t effective_traffic_class = SO_TC_BK_SYS;
		cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_EFFECTIVE_TRAFFIC_CLASS,
		    sizeof(effective_traffic_class), &effective_traffic_class, &updated,
		    client->result, sizeof(client->result));
	}
	if (client->background_update) {
		u_int32_t background = client->background;
		cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_TRAFFIC_MGMT_BG,
		    sizeof(background), &background, &updated,
		    client->result, sizeof(client->result));
		if (updated) {
			client->background_update = 0;
		}
	}
	NECP_CLIENT_ROUTE_LOCK(client);
	if (client->current_route != NULL) {
		const u_int32_t route_mtu = get_maxmtu(client->current_route);
		if (route_mtu != 0) {
			cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_EFFECTIVE_MTU,
			    sizeof(route_mtu), &route_mtu, &updated,
			    client->result, sizeof(client->result));
		}
	}
	NECP_CLIENT_ROUTE_UNLOCK(client);

	if (result.mss_recommended != 0) {
		cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_RECOMMENDED_MSS,
		    sizeof(result.mss_recommended), &result.mss_recommended, &updated,
		    client->result, sizeof(client->result));
	}

	for (int i = 0; i < NECP_MAX_NETAGENTS; i++) {
		if (uuid_is_null(result.netagents[i])) {
			break;
		}
		uuid_copy(netagent.netagent_uuid, result.netagents[i]);
		netagent.generation = netagent_get_generation(netagent.netagent_uuid);
		if (necp_netagent_applies_to_client(client, parsed_parameters, &netagent.netagent_uuid, TRUE, 0, 0)) {
			cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_NETAGENT, sizeof(netagent), &netagent, &updated,
			    client->result, sizeof(client->result));
		}
	}

	ifnet_head_lock_shared();
	ifnet_t direct_interface = NULL;
	ifnet_t delegate_interface = NULL;
	ifnet_t original_scoped_interface = NULL;

	if (result.routed_interface_index != IFSCOPE_NONE && result.routed_interface_index <= (u_int32_t)if_index) {
		direct_interface = ifindex2ifnet[result.routed_interface_index];
	} else if (parsed_parameters->required_interface_index != IFSCOPE_NONE &&
	    parsed_parameters->required_interface_index <= (u_int32_t)if_index) {
		// If the request was scoped, but the route didn't match, still grab the agents
		direct_interface = ifindex2ifnet[parsed_parameters->required_interface_index];
	} else if (result.routed_interface_index == IFSCOPE_NONE &&
	    result.routing_result == NECP_KERNEL_POLICY_RESULT_SOCKET_SCOPED &&
	    result.routing_result_parameter.scoped_interface_index != IFSCOPE_NONE) {
		direct_interface = ifindex2ifnet[result.routing_result_parameter.scoped_interface_index];
	}
	if (direct_interface != NULL) {
		delegate_interface = direct_interface->if_delegated.ifp;
	}
	if (result.routing_result == NECP_KERNEL_POLICY_RESULT_IP_TUNNEL &&
	    parsed_parameters->required_interface_index != IFSCOPE_NONE &&
	    parsed_parameters->required_interface_index != result.routing_result_parameter.tunnel_interface_index &&
	    parsed_parameters->required_interface_index <= (u_int32_t)if_index) {
		original_scoped_interface = ifindex2ifnet[parsed_parameters->required_interface_index];
	}
	// Add interfaces
	if (original_scoped_interface != NULL) {
		struct necp_client_result_interface interface_struct;
		interface_struct.index = original_scoped_interface->if_index;
		interface_struct.generation = ifnet_get_generation(original_scoped_interface);
		cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_INTERFACE, sizeof(interface_struct), &interface_struct, &updated,
		    client->result, sizeof(client->result));
	}
	if (direct_interface != NULL) {
		struct necp_client_result_interface interface_struct;
		interface_struct.index = direct_interface->if_index;
		interface_struct.generation = ifnet_get_generation(direct_interface);
		cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_INTERFACE, sizeof(interface_struct), &interface_struct, &updated,
		    client->result, sizeof(client->result));

		// Set the delta time since interface up/down
		struct timeval updown_delta = {};
		if (ifnet_updown_delta(direct_interface, &updown_delta) == 0) {
			u_int32_t delta = updown_delta.tv_sec;
			bool ignore_updated = FALSE;
			cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_INTERFACE_TIME_DELTA,
			    sizeof(delta), &delta, &ignore_updated,
			    client->result, sizeof(client->result));
		}
	}
	if (delegate_interface != NULL) {
		struct necp_client_result_interface interface_struct;
		interface_struct.index = delegate_interface->if_index;
		interface_struct.generation = ifnet_get_generation(delegate_interface);
		cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_INTERFACE, sizeof(interface_struct), &interface_struct, &updated,
		    client->result, sizeof(client->result));
	}

	// Update multipath/listener interface flows
	if (parsed_parameters->flags & NECP_CLIENT_PARAMETER_FLAG_MULTIPATH) {
		// Get multipath interface options from ordered list
		struct ifnet *multi_interface = NULL;
		TAILQ_FOREACH(multi_interface, &ifnet_ordered_head, if_ordered_link) {
			if (necp_ifnet_matches_parameters(multi_interface, parsed_parameters, NULL, true)) {
				// Add multipath interface flows for kernel MPTCP
				necp_client_add_interface_option_if_needed(client, multi_interface->if_index,
				    ifnet_get_generation(multi_interface), NULL);

				// Add nexus agents for multipath
				necp_client_add_agent_interface_options(client, parsed_parameters, multi_interface);
			}
		}
	} else if ((parsed_parameters->flags & NECP_CLIENT_PARAMETER_FLAG_LISTENER) &&
	    result.routing_result != NECP_KERNEL_POLICY_RESULT_SOCKET_SCOPED) {
		// Get listener interface options from global list
		struct ifnet *listen_interface = NULL;
		TAILQ_FOREACH(listen_interface, &ifnet_head, if_link) {
			if (necp_ifnet_matches_parameters(listen_interface, parsed_parameters, NULL, true)) {
				// Add nexus agents for listeners
				necp_client_add_agent_interface_options(client, parsed_parameters, listen_interface);
			}
		}
	}

	// Add agents
	if (original_scoped_interface != NULL) {
		ifnet_lock_shared(original_scoped_interface);
		if (original_scoped_interface->if_agentids != NULL) {
			for (u_int32_t i = 0; i < original_scoped_interface->if_agentcount; i++) {
				if (uuid_is_null(original_scoped_interface->if_agentids[i])) {
					continue;
				}
				uuid_copy(netagent.netagent_uuid, original_scoped_interface->if_agentids[i]);
				netagent.generation = netagent_get_generation(netagent.netagent_uuid);
				if (necp_netagent_applies_to_client(client, parsed_parameters, &netagent.netagent_uuid, FALSE,
				    original_scoped_interface->if_index, ifnet_get_generation(original_scoped_interface))) {
					cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_NETAGENT, sizeof(netagent), &netagent, &updated,
					    client->result, sizeof(client->result));
				}
			}
		}
		ifnet_lock_done(original_scoped_interface);
	}
	if (direct_interface != NULL) {
		ifnet_lock_shared(direct_interface);
		if (direct_interface->if_agentids != NULL) {
			for (u_int32_t i = 0; i < direct_interface->if_agentcount; i++) {
				if (uuid_is_null(direct_interface->if_agentids[i])) {
					continue;
				}
				uuid_copy(netagent.netagent_uuid, direct_interface->if_agentids[i]);
				netagent.generation = netagent_get_generation(netagent.netagent_uuid);
				if (necp_netagent_applies_to_client(client, parsed_parameters, &netagent.netagent_uuid, TRUE,
				    direct_interface->if_index, ifnet_get_generation(direct_interface))) {
					cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_NETAGENT, sizeof(netagent), &netagent, &updated,
					    client->result, sizeof(client->result));
				}
			}
		}
		ifnet_lock_done(direct_interface);
	}
	if (delegate_interface != NULL) {
		ifnet_lock_shared(delegate_interface);
		if (delegate_interface->if_agentids != NULL) {
			for (u_int32_t i = 0; i < delegate_interface->if_agentcount; i++) {
				if (uuid_is_null(delegate_interface->if_agentids[i])) {
					continue;
				}
				uuid_copy(netagent.netagent_uuid, delegate_interface->if_agentids[i]);
				netagent.generation = netagent_get_generation(netagent.netagent_uuid);
				if (necp_netagent_applies_to_client(client, parsed_parameters, &netagent.netagent_uuid, FALSE,
				    delegate_interface->if_index, ifnet_get_generation(delegate_interface))) {
					cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_NETAGENT, sizeof(netagent), &netagent, &updated,
					    client->result, sizeof(client->result));
				}
			}
		}
		ifnet_lock_done(delegate_interface);
	}
	ifnet_head_done();

	// Add interface options
	for (u_int32_t option_i = 0; option_i < client->interface_option_count; option_i++) {
		if (option_i < NECP_CLIENT_INTERFACE_OPTION_STATIC_COUNT) {
			struct necp_client_interface_option *option = &client->interface_options[option_i];
			cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_INTERFACE_OPTION, sizeof(*option), option, &updated,
			    client->result, sizeof(client->result));
		} else {
			struct necp_client_interface_option *option = &client->extra_interface_options[option_i - NECP_CLIENT_INTERFACE_OPTION_STATIC_COUNT];
			cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_INTERFACE_OPTION, sizeof(*option), option, &updated,
			    client->result, sizeof(client->result));
		}
	}

	size_t new_result_length = (cursor - client->result);
	if (new_result_length != client->result_length) {
		client->result_length = new_result_length;
		updated = TRUE;
	}

	// Update flow viability/flags
	if (necp_client_update_flows(proc, client, defunct_list)) {
		updated = TRUE;
	}

	if (updated) {
		client->result_read = FALSE;
		necp_client_update_observer_update(client);
	}

	FREE(parsed_parameters, M_NECP);
	return updated;
}

static inline void
necp_defunct_client_fd_locked(struct necp_fd_data *client_fd, struct _necp_flow_defunct_list *defunct_list, struct proc *proc)
{
#pragma unused(proc)
	bool updated_result = FALSE;
	struct necp_client *client = NULL;

	NECP_FD_ASSERT_LOCKED(client_fd);

	RB_FOREACH(client, _necp_client_tree, &client_fd->clients) {
		struct necp_client_flow_registration *flow_registration = NULL;

		NECP_CLIENT_LOCK(client);

		// Prepare close events to be sent to the nexus to effectively remove the flows
		struct necp_client_flow *search_flow = NULL;
		RB_FOREACH(flow_registration, _necp_client_flow_tree, &client->flow_registrations) {
			LIST_FOREACH(search_flow, &flow_registration->flow_list, flow_chain) {
				if (search_flow->nexus &&
				    !uuid_is_null(search_flow->u.nexus_agent)) {
					struct necp_flow_defunct *flow_defunct;

					// Sleeping alloc won't fail; copy only what's necessary
					flow_defunct = _MALLOC(sizeof(struct necp_flow_defunct), M_NECP, M_WAITOK | M_ZERO);
					uuid_copy(flow_defunct->nexus_agent, search_flow->u.nexus_agent);
					uuid_copy(flow_defunct->flow_id, ((flow_registration->flags & NECP_CLIENT_FLOW_FLAGS_USE_CLIENT_ID) ?
					    client->client_id :
					    flow_registration->registration_id));
					flow_defunct->proc_pid = client->proc_pid;
					flow_defunct->agent_handle = client->agent_handle;

					// Add to the list provided by caller
					LIST_INSERT_HEAD(defunct_list, flow_defunct, chain);

					flow_registration->defunct = true;
					flow_registration->flow_result_read = false;
					updated_result = true;
				}
			}
		}
		NECP_CLIENT_UNLOCK(client);
	}


	if (updated_result) {
		necp_fd_notify(client_fd, true);
	}
}

static inline void
necp_update_client_fd_locked(struct necp_fd_data *client_fd,
    proc_t proc,
    struct _necp_flow_defunct_list *defunct_list)
{
	struct necp_client *client = NULL;
	bool updated_result = FALSE;
	NECP_FD_ASSERT_LOCKED(client_fd);
	RB_FOREACH(client, _necp_client_tree, &client_fd->clients) {
		NECP_CLIENT_LOCK(client);
		if (necp_update_client_result(proc, client_fd, client, defunct_list)) {
			updated_result = TRUE;
		}
		NECP_CLIENT_UNLOCK(client);
	}
	if (updated_result) {
		necp_fd_notify(client_fd, true);
	}
}


static void
necp_update_all_clients_callout(__unused thread_call_param_t dummy,
    __unused thread_call_param_t arg)
{
	struct necp_fd_data *client_fd = NULL;

	struct _necp_flow_defunct_list defunct_list;
	LIST_INIT(&defunct_list);

	NECP_FD_LIST_LOCK_SHARED();

	LIST_FOREACH(client_fd, &necp_fd_list, chain) {
		proc_t proc = proc_find(client_fd->proc_pid);
		if (proc == PROC_NULL) {
			continue;
		}

		// Update all clients on one fd
		NECP_FD_LOCK(client_fd);
		necp_update_client_fd_locked(client_fd, proc, &defunct_list);
		NECP_FD_UNLOCK(client_fd);

		proc_rele(proc);
		proc = PROC_NULL;
	}

	NECP_FD_LIST_UNLOCK();

	// Handle the case in which some clients became newly defunct
	if (!LIST_EMPTY(&defunct_list)) {
		struct necp_flow_defunct *flow_defunct = NULL;
		struct necp_flow_defunct *temp_flow_defunct = NULL;

		// For each newly defunct client, send a message to the nexus to remove the flow
		LIST_FOREACH_SAFE(flow_defunct, &defunct_list, chain, temp_flow_defunct) {
			if (!uuid_is_null(flow_defunct->nexus_agent)) {
				int netagent_error = netagent_client_message(flow_defunct->nexus_agent,
				    flow_defunct->flow_id,
				    flow_defunct->proc_pid,
				    flow_defunct->agent_handle,
				    NETAGENT_MESSAGE_TYPE_ABORT_NEXUS);
				if (netagent_error != 0) {
					char namebuf[MAXCOMLEN + 1];
					(void) strlcpy(namebuf, "unknown", sizeof(namebuf));
					proc_name(flow_defunct->proc_pid, namebuf, sizeof(namebuf));
					NECPLOG((netagent_error == ENOENT ? LOG_DEBUG : LOG_ERR), "necp_update_client abort nexus error (%d) for pid %d %s", netagent_error, flow_defunct->proc_pid, namebuf);
				}
			}
			LIST_REMOVE(flow_defunct, chain);
			FREE(flow_defunct, M_NECP);
		}
	}
	ASSERT(LIST_EMPTY(&defunct_list));
}

void
necp_update_all_clients(void)
{
	if (necp_client_update_tcall == NULL) {
		// Don't try to update clients if the module is not initialized
		return;
	}

	uint64_t deadline = 0;
	uint64_t leeway = 0;
	clock_interval_to_deadline(necp_timeout_microseconds, NSEC_PER_USEC, &deadline);
	clock_interval_to_absolutetime_interval(necp_timeout_leeway_microseconds, NSEC_PER_USEC, &leeway);

	thread_call_enter_delayed_with_leeway(necp_client_update_tcall, NULL,
	    deadline, leeway, THREAD_CALL_DELAY_LEEWAY);
}

void
necp_set_client_as_background(proc_t proc,
    struct fileproc *fp,
    bool background)
{
	bool updated_result = FALSE;
	struct necp_client *client = NULL;

	if (proc == PROC_NULL) {
		NECPLOG0(LOG_ERR, "NULL proc");
		return;
	}

	if (fp == NULL) {
		NECPLOG0(LOG_ERR, "NULL fp");
		return;
	}

	struct necp_fd_data *client_fd = (struct necp_fd_data *)fp->f_fglob->fg_data;
	if (client_fd == NULL) {
		NECPLOG0(LOG_ERR, "Could not find client structure for backgrounded client");
		return;
	}

	if (client_fd->necp_fd_type != necp_fd_type_client) {
		// Not a client fd, ignore
		NECPLOG0(LOG_ERR, "Not a client fd, ignore");
		return;
	}

	NECP_FD_LOCK(client_fd);

	RB_FOREACH(client, _necp_client_tree, &client_fd->clients) {
		NECP_CLIENT_LOCK(client);

		bool has_assigned_flow = FALSE;
		struct necp_client_flow_registration *flow_registration = NULL;
		struct necp_client_flow *search_flow = NULL;
		RB_FOREACH(flow_registration, _necp_client_flow_tree, &client->flow_registrations) {
			LIST_FOREACH(search_flow, &flow_registration->flow_list, flow_chain) {
				if (search_flow->assigned) {
					has_assigned_flow = TRUE;
					break;
				}
			}
		}

		if (has_assigned_flow) {
			client->background = background;
			client->background_update = TRUE;
			updated_result = TRUE;
		}

		NECP_CLIENT_UNLOCK(client);
	}
	if (updated_result) {
		necp_update_client_fd_locked(client_fd, proc, NULL);
	}
	NECP_FD_UNLOCK(client_fd);
}

void
necp_fd_memstatus(proc_t proc, uint32_t status,
    struct necp_fd_data *client_fd)
{
#pragma unused(proc, status, client_fd)
	ASSERT(proc != PROC_NULL);
	ASSERT(client_fd != NULL);

	// Nothing to reap for the process or client for now,
	// but this is where we would trigger that in future.
}

void
necp_fd_defunct(proc_t proc, struct necp_fd_data *client_fd)
{
	struct _necp_flow_defunct_list defunct_list;

	ASSERT(proc != PROC_NULL);
	ASSERT(client_fd != NULL);

	if (client_fd->necp_fd_type != necp_fd_type_client) {
		// Not a client fd, ignore
		return;
	}

	// Our local temporary list
	LIST_INIT(&defunct_list);

	// Need to hold lock so ntstats defunct the same set of clients
	NECP_FD_LOCK(client_fd);
	necp_defunct_client_fd_locked(client_fd, &defunct_list, proc);
	NECP_FD_UNLOCK(client_fd);

	if (!LIST_EMPTY(&defunct_list)) {
		struct necp_flow_defunct *flow_defunct = NULL;
		struct necp_flow_defunct *temp_flow_defunct = NULL;

		// For each defunct client, remove flow from the nexus
		LIST_FOREACH_SAFE(flow_defunct, &defunct_list, chain, temp_flow_defunct) {
			if (!uuid_is_null(flow_defunct->nexus_agent)) {
				int netagent_error = netagent_client_message(flow_defunct->nexus_agent,
				    flow_defunct->flow_id,
				    flow_defunct->proc_pid,
				    flow_defunct->agent_handle,
				    NETAGENT_MESSAGE_TYPE_ABORT_NEXUS);
				if (netagent_error != 0) {
					NECPLOG((netagent_error == ENOENT ? LOG_DEBUG : LOG_ERR), "necp_defunct_client abort nexus error (%d)", netagent_error);
				}
			}
			LIST_REMOVE(flow_defunct, chain);
			FREE(flow_defunct, M_NECP);
		}
	}
	ASSERT(LIST_EMPTY(&defunct_list));
}

static void
necp_client_remove_agent_from_result(struct necp_client *client, uuid_t netagent_uuid)
{
	size_t offset = 0;

	u_int8_t *result_buffer = client->result;
	while ((offset + sizeof(struct necp_tlv_header)) <= client->result_length) {
		u_int8_t type = necp_buffer_get_tlv_type(result_buffer, offset);
		u_int32_t length = necp_buffer_get_tlv_length(result_buffer, offset);

		size_t tlv_total_length = (sizeof(struct necp_tlv_header) + length);
		if (type == NECP_CLIENT_RESULT_NETAGENT &&
		    length == sizeof(struct necp_client_result_netagent) &&
		    (offset + tlv_total_length) <= client->result_length) {
			struct necp_client_result_netagent *value = ((struct necp_client_result_netagent *)(void *)
			    necp_buffer_get_tlv_value(result_buffer, offset, NULL));
			if (uuid_compare(value->netagent_uuid, netagent_uuid) == 0) {
				// Found a netagent to remove
				// Shift bytes down to remove the tlv, and adjust total length
				// Don't adjust the current offset
				memmove(result_buffer + offset,
				    result_buffer + offset + tlv_total_length,
				    client->result_length - (offset + tlv_total_length));
				client->result_length -= tlv_total_length;
				memset(result_buffer + client->result_length, 0, sizeof(client->result) - client->result_length);
				continue;
			}
		}

		offset += tlv_total_length;
	}
}

void
necp_force_update_client(uuid_t client_id, uuid_t remove_netagent_uuid, u_int32_t agent_generation)
{
	struct necp_fd_data *client_fd = NULL;

	NECP_FD_LIST_LOCK_SHARED();

	LIST_FOREACH(client_fd, &necp_fd_list, chain) {
		bool updated_result = FALSE;
		NECP_FD_LOCK(client_fd);
		struct necp_client *client = necp_client_fd_find_client_and_lock(client_fd, client_id);
		if (client != NULL) {
			client->failed_trigger_agent.generation = agent_generation;
			uuid_copy(client->failed_trigger_agent.netagent_uuid, remove_netagent_uuid);
			if (!uuid_is_null(remove_netagent_uuid)) {
				necp_client_remove_agent_from_result(client, remove_netagent_uuid);
			}
			client->result_read = FALSE;
			// Found the client, break
			updated_result = TRUE;
			NECP_CLIENT_UNLOCK(client);
		}
		if (updated_result) {
			necp_fd_notify(client_fd, true);
		}
		NECP_FD_UNLOCK(client_fd);
		if (updated_result) {
			// Found the client, break
			break;
		}
	}

	NECP_FD_LIST_UNLOCK();
}


/// Interface matching

#define NECP_PARSED_PARAMETERS_INTERESTING_IFNET_FIELDS (NECP_PARSED_PARAMETERS_FIELD_LOCAL_ADDR |                              \
	                                                                                                         NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_IF |                   \
	                                                                                                         NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IFTYPE |                 \
	                                                                                                         NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_IFTYPE |               \
	                                                                                                         NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT |                  \
	                                                                                                         NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_AGENT |                \
	                                                                                                         NECP_PARSED_PARAMETERS_FIELD_PREFERRED_AGENT |                 \
	                                                                                                         NECP_PARSED_PARAMETERS_FIELD_AVOIDED_AGENT |                   \
	                                                                                                         NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT_TYPE |             \
	                                                                                                         NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_AGENT_TYPE |   \
	                                                                                                         NECP_PARSED_PARAMETERS_FIELD_PREFERRED_AGENT_TYPE |    \
	                                                                                                         NECP_PARSED_PARAMETERS_FIELD_AVOIDED_AGENT_TYPE)

#define NECP_PARSED_PARAMETERS_SCOPED_FIELDS (NECP_PARSED_PARAMETERS_FIELD_LOCAL_ADDR |                 \
	                                                                                  NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IFTYPE |                \
	                                                                                  NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT |         \
	                                                                                  NECP_PARSED_PARAMETERS_FIELD_PREFERRED_AGENT |                \
	                                                                                  NECP_PARSED_PARAMETERS_FIELD_AVOIDED_AGENT |          \
	                                                                                  NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT_TYPE |    \
	                                                                                  NECP_PARSED_PARAMETERS_FIELD_PREFERRED_AGENT_TYPE |   \
	                                                                                  NECP_PARSED_PARAMETERS_FIELD_AVOIDED_AGENT_TYPE)

#define NECP_PARSED_PARAMETERS_SCOPED_IFNET_FIELDS (NECP_PARSED_PARAMETERS_FIELD_LOCAL_ADDR |           \
	                                                                                                NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IFTYPE)

#define NECP_PARSED_PARAMETERS_PREFERRED_FIELDS (NECP_PARSED_PARAMETERS_FIELD_PREFERRED_AGENT |                 \
	                                                                                         NECP_PARSED_PARAMETERS_FIELD_AVOIDED_AGENT |                   \
	                                                                                         NECP_PARSED_PARAMETERS_FIELD_PREFERRED_AGENT_TYPE |    \
	                                                                                         NECP_PARSED_PARAMETERS_FIELD_AVOIDED_AGENT_TYPE)

static bool
necp_ifnet_matches_type(struct ifnet *ifp, u_int8_t interface_type, bool check_delegates)
{
	struct ifnet *check_ifp = ifp;
	while (check_ifp) {
		if (if_functional_type(check_ifp, TRUE) == interface_type) {
			return TRUE;
		}
		if (!check_delegates) {
			break;
		}
		check_ifp = check_ifp->if_delegated.ifp;
	}
	return FALSE;
}

static bool
necp_ifnet_matches_name(struct ifnet *ifp, const char *interface_name, bool check_delegates)
{
	struct ifnet *check_ifp = ifp;
	while (check_ifp) {
		if (strncmp(check_ifp->if_xname, interface_name, IFXNAMSIZ) == 0) {
			return TRUE;
		}
		if (!check_delegates) {
			break;
		}
		check_ifp = check_ifp->if_delegated.ifp;
	}
	return FALSE;
}

static bool
necp_ifnet_matches_agent(struct ifnet *ifp, uuid_t *agent_uuid, bool check_delegates)
{
	struct ifnet *check_ifp = ifp;

	while (check_ifp != NULL) {
		ifnet_lock_shared(check_ifp);
		if (check_ifp->if_agentids != NULL) {
			for (u_int32_t index = 0; index < check_ifp->if_agentcount; index++) {
				if (uuid_compare(check_ifp->if_agentids[index], *agent_uuid) == 0) {
					ifnet_lock_done(check_ifp);
					return TRUE;
				}
			}
		}
		ifnet_lock_done(check_ifp);

		if (!check_delegates) {
			break;
		}
		check_ifp = check_ifp->if_delegated.ifp;
	}
	return FALSE;
}

static bool
necp_ifnet_matches_agent_type(struct ifnet *ifp, const char *agent_domain, const char *agent_type, bool check_delegates)
{
	struct ifnet *check_ifp = ifp;

	while (check_ifp != NULL) {
		ifnet_lock_shared(check_ifp);
		if (check_ifp->if_agentids != NULL) {
			for (u_int32_t index = 0; index < check_ifp->if_agentcount; index++) {
				if (uuid_is_null(check_ifp->if_agentids[index])) {
					continue;
				}

				char if_agent_domain[NETAGENT_DOMAINSIZE] = { 0 };
				char if_agent_type[NETAGENT_TYPESIZE] = { 0 };

				if (netagent_get_agent_domain_and_type(check_ifp->if_agentids[index], if_agent_domain, if_agent_type)) {
					if (necp_agent_types_match(agent_domain, agent_type, if_agent_domain, if_agent_type)) {
						ifnet_lock_done(check_ifp);
						return TRUE;
					}
				}
			}
		}
		ifnet_lock_done(check_ifp);

		if (!check_delegates) {
			break;
		}
		check_ifp = check_ifp->if_delegated.ifp;
	}
	return FALSE;
}

static bool
necp_ifnet_matches_local_address(struct ifnet *ifp, struct sockaddr *sa)
{
	struct ifaddr *ifa = NULL;
	bool matched_local_address = FALSE;

	// Transform sa into the ifaddr form
	// IPv6 Scope IDs are always embedded in the ifaddr list
	struct sockaddr_storage address;
	u_int ifscope = IFSCOPE_NONE;
	(void)sa_copy(sa, &address, &ifscope);
	SIN(&address)->sin_port = 0;
	if (address.ss_family == AF_INET6) {
		SIN6(&address)->sin6_scope_id = 0;
	}

	ifa = ifa_ifwithaddr_scoped_locked((struct sockaddr *)&address, ifp->if_index);
	matched_local_address = (ifa != NULL);

	if (ifa) {
		ifaddr_release(ifa);
	}

	return matched_local_address;
}

static bool
necp_interface_type_is_primary_eligible(u_int8_t interface_type)
{
	switch (interface_type) {
	// These types can never be primary, so a client requesting these types is allowed
	// to match an interface that isn't currently eligible to be primary (has default
	// route, dns, etc)
	case IFRTYPE_FUNCTIONAL_WIFI_AWDL:
	case IFRTYPE_FUNCTIONAL_INTCOPROC:
		return false;
	default:
		break;
	}
	return true;
}

#define NECP_IFP_IS_ON_ORDERED_LIST(_ifp) ((_ifp)->if_ordered_link.tqe_next != NULL || (_ifp)->if_ordered_link.tqe_prev != NULL)

// Secondary interface flag indicates that the interface is being
// used for multipath or a listener as an extra path
static bool
necp_ifnet_matches_parameters(struct ifnet *ifp,
    struct necp_client_parsed_parameters *parsed_parameters,
    u_int32_t *preferred_count,
    bool secondary_interface)
{
	if (preferred_count) {
		*preferred_count = 0;
	}

	if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_LOCAL_ADDR) {
		if (!necp_ifnet_matches_local_address(ifp, &parsed_parameters->local_addr.sa)) {
			return FALSE;
		}
	}

	if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_FLAGS) {
		if ((parsed_parameters->flags & NECP_CLIENT_PARAMETER_FLAG_PROHIBIT_EXPENSIVE) &&
		    IFNET_IS_EXPENSIVE(ifp)) {
			return FALSE;
		}
	}

	if ((!secondary_interface || // Enforce interface type if this is the primary interface
	    !(parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_FLAGS) ||      // or if there are no flags
	    !(parsed_parameters->flags & NECP_CLIENT_PARAMETER_FLAG_ONLY_PRIMARY_REQUIRES_TYPE)) &&      // or if the flags don't give an exception
	    (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IFTYPE) &&
	    !necp_ifnet_matches_type(ifp, parsed_parameters->required_interface_type, FALSE)) {
		return FALSE;
	}

	if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_IFTYPE) {
		for (int i = 0; i < NECP_MAX_PARSED_PARAMETERS; i++) {
			if (parsed_parameters->prohibited_interface_types[i] == 0) {
				break;
			}

			if (necp_ifnet_matches_type(ifp, parsed_parameters->prohibited_interface_types[i], TRUE)) {
				return FALSE;
			}
		}
	}

	if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_IF) {
		for (int i = 0; i < NECP_MAX_PARSED_PARAMETERS; i++) {
			if (strlen(parsed_parameters->prohibited_interfaces[i]) == 0) {
				break;
			}

			if (necp_ifnet_matches_name(ifp, parsed_parameters->prohibited_interfaces[i], TRUE)) {
				return FALSE;
			}
		}
	}

	if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT) {
		for (int i = 0; i < NECP_MAX_PARSED_PARAMETERS; i++) {
			if (uuid_is_null(parsed_parameters->required_netagents[i])) {
				break;
			}

			if (!necp_ifnet_matches_agent(ifp, &parsed_parameters->required_netagents[i], FALSE)) {
				return FALSE;
			}
		}
	}

	if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_AGENT) {
		for (int i = 0; i < NECP_MAX_PARSED_PARAMETERS; i++) {
			if (uuid_is_null(parsed_parameters->prohibited_netagents[i])) {
				break;
			}

			if (necp_ifnet_matches_agent(ifp, &parsed_parameters->prohibited_netagents[i], TRUE)) {
				return FALSE;
			}
		}
	}

	if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT_TYPE) {
		for (int i = 0; i < NECP_MAX_PARSED_PARAMETERS; i++) {
			if (strlen(parsed_parameters->required_netagent_types[i].netagent_domain) == 0 &&
			    strlen(parsed_parameters->required_netagent_types[i].netagent_type) == 0) {
				break;
			}

			if (!necp_ifnet_matches_agent_type(ifp, parsed_parameters->required_netagent_types[i].netagent_domain, parsed_parameters->required_netagent_types[i].netagent_type, FALSE)) {
				return FALSE;
			}
		}
	}

	if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_AGENT_TYPE) {
		for (int i = 0; i < NECP_MAX_PARSED_PARAMETERS; i++) {
			if (strlen(parsed_parameters->prohibited_netagent_types[i].netagent_domain) == 0 &&
			    strlen(parsed_parameters->prohibited_netagent_types[i].netagent_type) == 0) {
				break;
			}

			if (necp_ifnet_matches_agent_type(ifp, parsed_parameters->prohibited_netagent_types[i].netagent_domain, parsed_parameters->prohibited_netagent_types[i].netagent_type, TRUE)) {
				return FALSE;
			}
		}
	}

	// Checked preferred properties
	if (preferred_count) {
		if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_PREFERRED_AGENT) {
			for (int i = 0; i < NECP_MAX_PARSED_PARAMETERS; i++) {
				if (uuid_is_null(parsed_parameters->preferred_netagents[i])) {
					break;
				}

				if (necp_ifnet_matches_agent(ifp, &parsed_parameters->preferred_netagents[i], TRUE)) {
					(*preferred_count)++;
				}
			}
		}

		if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_PREFERRED_AGENT_TYPE) {
			for (int i = 0; i < NECP_MAX_PARSED_PARAMETERS; i++) {
				if (strlen(parsed_parameters->preferred_netagent_types[i].netagent_domain) == 0 &&
				    strlen(parsed_parameters->preferred_netagent_types[i].netagent_type) == 0) {
					break;
				}

				if (necp_ifnet_matches_agent_type(ifp, parsed_parameters->preferred_netagent_types[i].netagent_domain, parsed_parameters->preferred_netagent_types[i].netagent_type, TRUE)) {
					(*preferred_count)++;
				}
			}
		}

		if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_AVOIDED_AGENT) {
			for (int i = 0; i < NECP_MAX_PARSED_PARAMETERS; i++) {
				if (uuid_is_null(parsed_parameters->avoided_netagents[i])) {
					break;
				}

				if (!necp_ifnet_matches_agent(ifp, &parsed_parameters->avoided_netagents[i], TRUE)) {
					(*preferred_count)++;
				}
			}
		}

		if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_AVOIDED_AGENT_TYPE) {
			for (int i = 0; i < NECP_MAX_PARSED_PARAMETERS; i++) {
				if (strlen(parsed_parameters->avoided_netagent_types[i].netagent_domain) == 0 &&
				    strlen(parsed_parameters->avoided_netagent_types[i].netagent_type) == 0) {
					break;
				}

				if (!necp_ifnet_matches_agent_type(ifp, parsed_parameters->avoided_netagent_types[i].netagent_domain,
				    parsed_parameters->avoided_netagent_types[i].netagent_type, TRUE)) {
					(*preferred_count)++;
				}
			}
		}
	}

	return TRUE;
}

static bool
necp_find_matching_interface_index(struct necp_client_parsed_parameters *parsed_parameters,
    u_int *return_ifindex, bool *validate_agents)
{
	struct ifnet *ifp = NULL;
	u_int32_t best_preferred_count = 0;
	bool has_preferred_fields = FALSE;
	*return_ifindex = 0;

	if (parsed_parameters->required_interface_index != 0) {
		*return_ifindex = parsed_parameters->required_interface_index;
		return TRUE;
	}

	if (!(parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_INTERESTING_IFNET_FIELDS)) {
		return TRUE;
	}

	has_preferred_fields = (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_PREFERRED_FIELDS);

	// We have interesting parameters to parse and find a matching interface
	ifnet_head_lock_shared();

	if (!(parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_SCOPED_FIELDS)) {
		// We do have fields to match, but they are only prohibitory
		// If the first interface in the list matches, or there are no ordered interfaces, we don't need to scope
		ifp = TAILQ_FIRST(&ifnet_ordered_head);
		if (ifp == NULL || necp_ifnet_matches_parameters(ifp, parsed_parameters, NULL, false)) {
			// Don't set return_ifindex, so the client doesn't need to scope
			ifnet_head_done();
			return TRUE;
		}
	}

	// First check the ordered interface list
	TAILQ_FOREACH(ifp, &ifnet_ordered_head, if_ordered_link) {
		u_int32_t preferred_count = 0;
		if (necp_ifnet_matches_parameters(ifp, parsed_parameters, &preferred_count, false)) {
			if (preferred_count > best_preferred_count ||
			    *return_ifindex == 0) {
				// Everything matched, and is most preferred. Return this interface.
				*return_ifindex = ifp->if_index;
				best_preferred_count = preferred_count;

				if (!has_preferred_fields) {
					break;
				}
			}
		}
	}

	// Then check the remaining interfaces
	if ((parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_SCOPED_FIELDS) &&
	    ((!(parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IFTYPE)) ||
	    !necp_interface_type_is_primary_eligible(parsed_parameters->required_interface_type)) &&
	    *return_ifindex == 0) {
		TAILQ_FOREACH(ifp, &ifnet_head, if_link) {
			u_int32_t preferred_count = 0;
			if (NECP_IFP_IS_ON_ORDERED_LIST(ifp)) {
				// This interface was in the ordered list, skip
				continue;
			}
			if (necp_ifnet_matches_parameters(ifp, parsed_parameters, &preferred_count, false)) {
				if (preferred_count > best_preferred_count ||
				    *return_ifindex == 0) {
					// Everything matched, and is most preferred. Return this interface.
					*return_ifindex = ifp->if_index;
					best_preferred_count = preferred_count;

					if (!has_preferred_fields) {
						break;
					}
				}
			}
		}
	}

	ifnet_head_done();

	if ((parsed_parameters->valid_fields == (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_PREFERRED_FIELDS)) &&
	    best_preferred_count == 0) {
		// If only has preferred fields, and nothing was found, clear the interface index and return TRUE
		*return_ifindex = 0;
		return TRUE;
	}

	if (*return_ifindex == 0 &&
	    !(parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_SCOPED_IFNET_FIELDS)) {
		// Has required fields, but not including specific interface fields. Pass for now, and check
		// to see if agents are satisfied by policy.
		*validate_agents = TRUE;
		return TRUE;
	}

	return *return_ifindex != 0;
}


static int
necp_skywalk_priv_check_cred(proc_t p, kauth_cred_t cred)
{
#pragma unused(p, cred)
	return 0;
}

/// System calls

int
necp_open(struct proc *p, struct necp_open_args *uap, int *retval)
{
#pragma unused(retval)
	int error = 0;
	struct necp_fd_data *fd_data = NULL;
	struct fileproc *fp = NULL;
	int fd = -1;

	if (uap->flags & NECP_OPEN_FLAG_OBSERVER ||
	    uap->flags & NECP_OPEN_FLAG_PUSH_OBSERVER) {
		if (necp_skywalk_priv_check_cred(p, kauth_cred_get()) != 0 &&
		    priv_check_cred(kauth_cred_get(), PRIV_NET_PRIVILEGED_NETWORK_STATISTICS, 0) != 0) {
			NECPLOG0(LOG_ERR, "Client does not hold necessary entitlement to observe other NECP clients");
			error = EACCES;
			goto done;
		}
	}

	error = falloc(p, &fp, &fd, vfs_context_current());
	if (error != 0) {
		goto done;
	}

	if ((fd_data = zalloc(necp_client_fd_zone)) == NULL) {
		error = ENOMEM;
		goto done;
	}

	memset(fd_data, 0, sizeof(*fd_data));

	fd_data->necp_fd_type = necp_fd_type_client;
	fd_data->flags = uap->flags;
	RB_INIT(&fd_data->clients);
	RB_INIT(&fd_data->flows);
	TAILQ_INIT(&fd_data->update_list);
	lck_mtx_init(&fd_data->fd_lock, necp_fd_mtx_grp, necp_fd_mtx_attr);
	klist_init(&fd_data->si.si_note);
	fd_data->proc_pid = proc_pid(p);

	fp->f_fglob->fg_flag = FREAD;
	fp->f_fglob->fg_ops = &necp_fd_ops;
	fp->f_fglob->fg_data = fd_data;

	proc_fdlock(p);

	*fdflags(p, fd) |= (UF_EXCLOSE | UF_FORKCLOSE);
	procfdtbl_releasefd(p, fd, NULL);
	fp_drop(p, fd, fp, 1);

	*retval = fd;

	if (fd_data->flags & NECP_OPEN_FLAG_PUSH_OBSERVER) {
		NECP_OBSERVER_LIST_LOCK_EXCLUSIVE();
		LIST_INSERT_HEAD(&necp_fd_observer_list, fd_data, chain);
		OSIncrementAtomic(&necp_observer_fd_count);
		NECP_OBSERVER_LIST_UNLOCK();

		// Walk all existing clients and add them
		NECP_CLIENT_TREE_LOCK_SHARED();
		struct necp_client *existing_client = NULL;
		RB_FOREACH(existing_client, _necp_client_global_tree, &necp_client_global_tree) {
			NECP_CLIENT_LOCK(existing_client);
			necp_client_update_observer_add_internal(fd_data, existing_client);
			necp_client_update_observer_update_internal(fd_data, existing_client);
			NECP_CLIENT_UNLOCK(existing_client);
		}
		NECP_CLIENT_TREE_UNLOCK();
	} else {
		NECP_FD_LIST_LOCK_EXCLUSIVE();
		LIST_INSERT_HEAD(&necp_fd_list, fd_data, chain);
		OSIncrementAtomic(&necp_client_fd_count);
		NECP_FD_LIST_UNLOCK();
	}

	proc_fdunlock(p);

done:
	if (error != 0) {
		if (fp != NULL) {
			fp_free(p, fd, fp);
			fp = NULL;
		}
		if (fd_data != NULL) {
			zfree(necp_client_fd_zone, fd_data);
			fd_data = NULL;
		}
	}

	return error;
}

static int
necp_client_add(struct proc *p, struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	struct necp_client *client = NULL;

	if (fd_data->flags & NECP_OPEN_FLAG_PUSH_OBSERVER) {
		NECPLOG0(LOG_ERR, "NECP client observers with push enabled may not add their own clients");
		return EINVAL;
	}

	if (uap->client_id == 0 || uap->client_id_len != sizeof(uuid_t) ||
	    uap->buffer_size == 0 || uap->buffer_size > NECP_MAX_CLIENT_PARAMETERS_SIZE || uap->buffer == 0) {
		return EINVAL;
	}

	if ((client = _MALLOC(sizeof(struct necp_client) + uap->buffer_size, M_NECP,
	    M_WAITOK | M_ZERO)) == NULL) {
		error = ENOMEM;
		goto done;
	}

	error = copyin(uap->buffer, client->parameters, uap->buffer_size);
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_add parameters copyin error (%d)", error);
		goto done;
	}

	lck_mtx_init(&client->lock, necp_fd_mtx_grp, necp_fd_mtx_attr);
	lck_mtx_init(&client->route_lock, necp_fd_mtx_grp, necp_fd_mtx_attr);
	necp_client_retain(client); // Hold our reference until close

	client->parameters_length = uap->buffer_size;
	client->proc_pid = fd_data->proc_pid; // Save off proc pid in case the client will persist past fd
	client->agent_handle = (void *)fd_data;
	client->platform_binary = ((csproc_get_platform_binary(p) == 0) ? 0 : 1);

	necp_generate_client_id(client->client_id, false);
	LIST_INIT(&client->assertion_list);
	RB_INIT(&client->flow_registrations);

	error = copyout(client->client_id, uap->client_id, sizeof(uuid_t));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_add client_id copyout error (%d)", error);
		goto done;
	}

	necp_client_update_observer_add(client);

	NECP_FD_LOCK(fd_data);
	RB_INSERT(_necp_client_tree, &fd_data->clients, client);
	OSIncrementAtomic(&necp_client_count);
	NECP_CLIENT_TREE_LOCK_EXCLUSIVE();
	RB_INSERT(_necp_client_global_tree, &necp_client_global_tree, client);
	NECP_CLIENT_TREE_UNLOCK();

	// Prime the client result
	NECP_CLIENT_LOCK(client);
	(void)necp_update_client_result(current_proc(), fd_data, client, NULL);
	NECP_CLIENT_UNLOCK(client);
	NECP_FD_UNLOCK(fd_data);
done:
	if (error != 0) {
		if (client != NULL) {
			FREE(client, M_NECP);
			client = NULL;
		}
	}
	*retval = error;

	return error;
}

static int
necp_client_remove(struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	uuid_t client_id = {};
	struct ifnet_stats_per_flow flow_ifnet_stats = {};

	if (uap->client_id == 0 || uap->client_id_len != sizeof(uuid_t)) {
		error = EINVAL;
		goto done;
	}

	error = copyin(uap->client_id, client_id, sizeof(uuid_t));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_remove copyin client_id error (%d)", error);
		goto done;
	}

	if (uap->buffer != 0 && uap->buffer_size == sizeof(flow_ifnet_stats)) {
		error = copyin(uap->buffer, &flow_ifnet_stats, uap->buffer_size);
		if (error) {
			NECPLOG(LOG_ERR, "necp_client_remove flow_ifnet_stats copyin error (%d)", error);
			// Not fatal; make sure to zero-out stats in case of partial copy
			memset(&flow_ifnet_stats, 0, sizeof(flow_ifnet_stats));
			error = 0;
		}
	} else if (uap->buffer != 0) {
		NECPLOG(LOG_ERR, "necp_client_remove unexpected parameters length (%zu)", uap->buffer_size);
	}

	NECP_FD_LOCK(fd_data);

	pid_t pid = fd_data->proc_pid;
	struct necp_client *client = necp_client_fd_find_client_unlocked(fd_data, client_id);
	if (client != NULL) {
		// Remove any flow registrations that match
		struct necp_client_flow_registration *flow_registration = NULL;
		struct necp_client_flow_registration *temp_flow_registration = NULL;
		RB_FOREACH_SAFE(flow_registration, _necp_fd_flow_tree, &fd_data->flows, temp_flow_registration) {
			if (flow_registration->client == client) {
				NECP_FLOW_TREE_LOCK_EXCLUSIVE();
				RB_REMOVE(_necp_client_flow_global_tree, &necp_client_flow_global_tree, flow_registration);
				NECP_FLOW_TREE_UNLOCK();
				RB_REMOVE(_necp_fd_flow_tree, &fd_data->flows, flow_registration);
			}
		}
		// Remove client from lists
		NECP_CLIENT_TREE_LOCK_EXCLUSIVE();
		RB_REMOVE(_necp_client_global_tree, &necp_client_global_tree, client);
		NECP_CLIENT_TREE_UNLOCK();
		RB_REMOVE(_necp_client_tree, &fd_data->clients, client);
	}


	NECP_FD_UNLOCK(fd_data);

	if (client != NULL) {
		ASSERT(error == 0);
		necp_destroy_client(client, pid, true);
	} else {
		error = ENOENT;
		NECPLOG(LOG_ERR, "necp_client_remove invalid client_id (%d)", error);
	}
done:
	*retval = error;

	return error;
}


static int
necp_client_check_tcp_heuristics(struct necp_client *client, struct necp_client_flow *flow, u_int32_t *flags, u_int8_t *tfo_cookie, u_int8_t *tfo_cookie_len)
{
	struct necp_client_parsed_parameters parsed_parameters;
	int error = 0;

	error = necp_client_parse_parameters(client->parameters,
	    (u_int32_t)client->parameters_length,
	    &parsed_parameters);
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_parse_parameters error (%d)", error);
		return error;
	}

	if ((flow->remote_addr.sa.sa_family != AF_INET &&
	    flow->remote_addr.sa.sa_family != AF_INET6) ||
	    (flow->local_addr.sa.sa_family != AF_INET &&
	    flow->local_addr.sa.sa_family != AF_INET6)) {
		return EINVAL;
	}

	NECP_CLIENT_ROUTE_LOCK(client);

	if (client->current_route == NULL) {
		error = ENOENT;
		goto do_unlock;
	}

	bool check_ecn = false;
	do {
		if ((parsed_parameters.flags & NECP_CLIENT_PARAMETER_FLAG_ECN_ENABLE) ==
		    NECP_CLIENT_PARAMETER_FLAG_ECN_ENABLE) {
			check_ecn = true;
			break;
		}

		if ((parsed_parameters.flags & NECP_CLIENT_PARAMETER_FLAG_ECN_DISABLE) ==
		    NECP_CLIENT_PARAMETER_FLAG_ECN_DISABLE) {
			break;
		}

		if (client->current_route != NULL) {
			if (client->current_route->rt_ifp->if_eflags & IFEF_ECN_ENABLE) {
				check_ecn = true;
				break;
			}
			if (client->current_route->rt_ifp->if_eflags & IFEF_ECN_DISABLE) {
				break;
			}
		}

		bool inbound = ((parsed_parameters.flags & NECP_CLIENT_PARAMETER_FLAG_LISTENER) == 0);
		if ((inbound && tcp_ecn_inbound == 1) ||
		    (!inbound && tcp_ecn_outbound == 1)) {
			check_ecn = true;
		}
	} while (false);

	if (check_ecn) {
		if (tcp_heuristic_do_ecn_with_address(client->current_route->rt_ifp,
		    (union sockaddr_in_4_6 *)&flow->local_addr)) {
			*flags |= NECP_CLIENT_RESULT_FLAG_ECN_ENABLED;
		}
	}

	if ((parsed_parameters.flags & NECP_CLIENT_PARAMETER_FLAG_TFO_ENABLE) ==
	    NECP_CLIENT_PARAMETER_FLAG_TFO_ENABLE) {
		if (!tcp_heuristic_do_tfo_with_address(client->current_route->rt_ifp,
		    (union sockaddr_in_4_6 *)&flow->local_addr,
		    (union sockaddr_in_4_6 *)&flow->remote_addr,
		    tfo_cookie, tfo_cookie_len)) {
			*flags |= NECP_CLIENT_RESULT_FLAG_FAST_OPEN_BLOCKED;
			*tfo_cookie_len = 0;
		}
	} else {
		*flags |= NECP_CLIENT_RESULT_FLAG_FAST_OPEN_BLOCKED;
		*tfo_cookie_len = 0;
	}
do_unlock:
	NECP_CLIENT_ROUTE_UNLOCK(client);

	return error;
}

static size_t
necp_client_calculate_flow_tlv_size(struct necp_client_flow_registration *flow_registration)
{
	size_t assigned_results_size = 0;
	struct necp_client_flow *flow = NULL;
	LIST_FOREACH(flow, &flow_registration->flow_list, flow_chain) {
		if (flow->assigned) {
			size_t header_length = 0;
			if (flow->nexus) {
				header_length = sizeof(struct necp_client_nexus_flow_header);
			} else {
				header_length = sizeof(struct necp_client_flow_header);
			}
			assigned_results_size += (header_length + flow->assigned_results_length);

			if (flow->has_protoctl_event) {
				assigned_results_size += sizeof(struct necp_client_flow_protoctl_event_header);
			}
		}
	}
	return assigned_results_size;
}

static int
necp_client_fillout_flow_tlvs(struct necp_client *client,
    bool client_is_observed,
    struct necp_client_flow_registration *flow_registration,
    struct necp_client_action_args *uap,
    size_t *assigned_results_cursor)
{
	int error = 0;
	struct necp_client_flow *flow = NULL;
	LIST_FOREACH(flow, &flow_registration->flow_list, flow_chain) {
		if (flow->assigned) {
			// Write TLV headers
			struct necp_client_nexus_flow_header header = {};
			u_int32_t length = 0;
			u_int32_t flags = 0;
			u_int8_t tfo_cookie_len = 0;
			u_int8_t type = 0;

			type = NECP_CLIENT_RESULT_FLOW_ID;
			length = sizeof(header.flow_header.flow_id);
			memcpy(&header.flow_header.flow_id_tlv_header.type, &type, sizeof(type));
			memcpy(&header.flow_header.flow_id_tlv_header.length, &length, sizeof(length));
			uuid_copy(header.flow_header.flow_id, flow_registration->registration_id);

			if (flow->nexus) {
				if (flow->check_tcp_heuristics) {
					u_int8_t tfo_cookie[NECP_TFO_COOKIE_LEN_MAX];
					tfo_cookie_len = NECP_TFO_COOKIE_LEN_MAX;

					if (necp_client_check_tcp_heuristics(client, flow, &flags,
					    tfo_cookie, &tfo_cookie_len) != 0) {
						tfo_cookie_len = 0;
					} else {
						flow->check_tcp_heuristics = FALSE;

						if (tfo_cookie_len != 0) {
							type = NECP_CLIENT_RESULT_TFO_COOKIE;
							length = tfo_cookie_len;
							memcpy(&header.tfo_cookie_tlv_header.type, &type, sizeof(type));
							memcpy(&header.tfo_cookie_tlv_header.length, &length, sizeof(length));
							memcpy(&header.tfo_cookie_value, tfo_cookie, tfo_cookie_len);
						}
					}
				}
			}

			size_t header_length = 0;
			if (flow->nexus) {
				if (tfo_cookie_len != 0) {
					header_length = sizeof(struct necp_client_nexus_flow_header) - (NECP_TFO_COOKIE_LEN_MAX - tfo_cookie_len);
				} else {
					header_length = sizeof(struct necp_client_nexus_flow_header) - sizeof(struct necp_tlv_header) - NECP_TFO_COOKIE_LEN_MAX;
				}
			} else {
				header_length = sizeof(struct necp_client_flow_header);
			}

			type = NECP_CLIENT_RESULT_FLAGS;
			length = sizeof(header.flow_header.flags_value);
			memcpy(&header.flow_header.flags_tlv_header.type, &type, sizeof(type));
			memcpy(&header.flow_header.flags_tlv_header.length, &length, sizeof(length));
			if (flow->assigned) {
				flags |= NECP_CLIENT_RESULT_FLAG_FLOW_ASSIGNED;
			}
			if (flow->viable) {
				flags |= NECP_CLIENT_RESULT_FLAG_FLOW_VIABLE;
			}
			if (flow_registration->defunct) {
				flags |= NECP_CLIENT_RESULT_FLAG_DEFUNCT;
			}
			flags |= flow->necp_flow_flags;
			memcpy(&header.flow_header.flags_value, &flags, sizeof(flags));

			type = NECP_CLIENT_RESULT_INTERFACE;
			length = sizeof(header.flow_header.interface_value);
			memcpy(&header.flow_header.interface_tlv_header.type, &type, sizeof(type));
			memcpy(&header.flow_header.interface_tlv_header.length, &length, sizeof(length));

			struct necp_client_result_interface interface_struct;
			interface_struct.generation = 0;
			interface_struct.index = flow->interface_index;

			memcpy(&header.flow_header.interface_value, &interface_struct, sizeof(interface_struct));
			if (flow->nexus) {
				type = NECP_CLIENT_RESULT_NETAGENT;
				length = sizeof(header.agent_value);
				memcpy(&header.agent_tlv_header.type, &type, sizeof(type));
				memcpy(&header.agent_tlv_header.length, &length, sizeof(length));

				struct necp_client_result_netagent agent_struct;
				agent_struct.generation = 0;
				uuid_copy(agent_struct.netagent_uuid, flow->u.nexus_agent);

				memcpy(&header.agent_value, &agent_struct, sizeof(agent_struct));
			}

			// Don't include outer TLV header in length field
			type = NECP_CLIENT_RESULT_FLOW;
			length = (header_length - sizeof(struct necp_tlv_header) + flow->assigned_results_length);
			if (flow->has_protoctl_event) {
				length += sizeof(struct necp_client_flow_protoctl_event_header);
			}
			memcpy(&header.flow_header.outer_header.type, &type, sizeof(type));
			memcpy(&header.flow_header.outer_header.length, &length, sizeof(length));

			error = copyout(&header, uap->buffer + client->result_length + *assigned_results_cursor, header_length);
			if (error) {
				NECPLOG(LOG_ERR, "necp_client_copy assigned results tlv_header copyout error (%d)", error);
				return error;
			}
			*assigned_results_cursor += header_length;

			if (flow->assigned_results && flow->assigned_results_length) {
				// Write inner TLVs
				error = copyout(flow->assigned_results, uap->buffer + client->result_length + *assigned_results_cursor,
				    flow->assigned_results_length);
				if (error) {
					NECPLOG(LOG_ERR, "necp_client_copy assigned results copyout error (%d)", error);
					return error;
				}
			}
			*assigned_results_cursor += flow->assigned_results_length;

			/* Read the protocol event and reset it */
			if (flow->has_protoctl_event) {
				struct necp_client_flow_protoctl_event_header protoctl_event_header = {};

				type = NECP_CLIENT_RESULT_PROTO_CTL_EVENT;
				length = sizeof(protoctl_event_header.protoctl_event);

				memcpy(&protoctl_event_header.protoctl_tlv_header.type, &type, sizeof(type));
				memcpy(&protoctl_event_header.protoctl_tlv_header.length, &length, sizeof(length));
				memcpy(&protoctl_event_header.protoctl_event, &flow->protoctl_event,
				    sizeof(flow->protoctl_event));

				error = copyout(&protoctl_event_header, uap->buffer + client->result_length + *assigned_results_cursor,
				    sizeof(protoctl_event_header));

				if (error) {
					NECPLOG(LOG_ERR, "necp_client_copy protocol control event results"
					    " tlv_header copyout error (%d)", error);
					return error;
				}
				*assigned_results_cursor += sizeof(protoctl_event_header);
				flow->has_protoctl_event = FALSE;
				flow->protoctl_event.protoctl_event_code = 0;
				flow->protoctl_event.protoctl_event_val = 0;
				flow->protoctl_event.protoctl_event_tcp_seq_num = 0;
			}
		}
	}
	if (!client_is_observed) {
		flow_registration->flow_result_read = TRUE;
	}
	return 0;
}

static int
necp_client_copy_internal(struct necp_client *client, uuid_t client_id, bool client_is_observed, struct necp_client_action_args *uap, int *retval)
{
	NECP_CLIENT_ASSERT_LOCKED(client);
	int error = 0;
	// Copy results out
	if (uap->action == NECP_CLIENT_ACTION_COPY_PARAMETERS) {
		if (uap->buffer_size < client->parameters_length) {
			return EINVAL;
		}
		error = copyout(client->parameters, uap->buffer, client->parameters_length);
		if (error) {
			NECPLOG(LOG_ERR, "necp_client_copy parameters copyout error (%d)", error);
			return error;
		}
		*retval = client->parameters_length;
	} else if (uap->action == NECP_CLIENT_ACTION_COPY_UPDATED_RESULT &&
	    client->result_read && !necp_client_has_unread_flows(client)) {
		// Copy updates only, but nothing to read
		// Just return 0 for bytes read
		*retval = 0;
	} else if (uap->action == NECP_CLIENT_ACTION_COPY_RESULT ||
	    uap->action == NECP_CLIENT_ACTION_COPY_UPDATED_RESULT) {
		size_t assigned_results_size = 0;

		bool some_flow_is_defunct = false;
		struct necp_client_flow_registration *single_flow_registration = NULL;
		if (necp_client_id_is_flow(client_id)) {
			single_flow_registration = necp_client_find_flow(client, client_id);
			if (single_flow_registration != NULL) {
				assigned_results_size += necp_client_calculate_flow_tlv_size(single_flow_registration);
			}
		} else {
			// This request is for the client, so copy everything
			struct necp_client_flow_registration *flow_registration = NULL;
			RB_FOREACH(flow_registration, _necp_client_flow_tree, &client->flow_registrations) {
				if (flow_registration->defunct) {
					some_flow_is_defunct = true;
				}
				assigned_results_size += necp_client_calculate_flow_tlv_size(flow_registration);
			}
		}
		if (uap->buffer_size < (client->result_length + assigned_results_size)) {
			return EINVAL;
		}

		u_int32_t original_flags = 0;
		bool flags_updated = false;
		if (some_flow_is_defunct && client->legacy_client_is_flow) {
			// If our client expects the defunct flag in the client, add it now
			u_int32_t client_flags = 0;
			u_int32_t value_size = 0;
			u_int8_t *flags_pointer = necp_buffer_get_tlv_value(client->result, 0, &value_size);
			if (flags_pointer != NULL && value_size == sizeof(client_flags)) {
				memcpy(&client_flags, flags_pointer, value_size);
				original_flags = client_flags;
				client_flags |= NECP_CLIENT_RESULT_FLAG_DEFUNCT;
				(void)necp_buffer_write_tlv_if_different(client->result, NECP_CLIENT_RESULT_FLAGS,
				    sizeof(client_flags), &client_flags, &flags_updated,
				    client->result, sizeof(client->result));
			}
		}

		error = copyout(client->result, uap->buffer, client->result_length);

		if (flags_updated) {
			// Revert stored flags
			(void)necp_buffer_write_tlv_if_different(client->result, NECP_CLIENT_RESULT_FLAGS,
			    sizeof(original_flags), &original_flags, &flags_updated,
			    client->result, sizeof(client->result));
		}

		if (error) {
			NECPLOG(LOG_ERR, "necp_client_copy result copyout error (%d)", error);
			return error;
		}

		size_t assigned_results_cursor = 0;
		if (necp_client_id_is_flow(client_id)) {
			if (single_flow_registration != NULL) {
				error = necp_client_fillout_flow_tlvs(client, client_is_observed, single_flow_registration, uap, &assigned_results_cursor);
				if (error != 0) {
					return error;
				}
			}
		} else {
			// This request is for the client, so copy everything
			struct necp_client_flow_registration *flow_registration = NULL;
			RB_FOREACH(flow_registration, _necp_client_flow_tree, &client->flow_registrations) {
				error = necp_client_fillout_flow_tlvs(client, client_is_observed, flow_registration, uap, &assigned_results_cursor);
				if (error != 0) {
					return error;
				}
			}
		}

		*retval = client->result_length + assigned_results_cursor;

		if (!client_is_observed) {
			client->result_read = TRUE;
		}
	}

	return 0;
}

static int
necp_client_copy(struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	struct necp_client *client = NULL;
	uuid_t client_id;
	uuid_clear(client_id);

	*retval = 0;

	if (uap->buffer_size == 0 || uap->buffer == 0) {
		return EINVAL;
	}

	if (uap->action != NECP_CLIENT_ACTION_COPY_PARAMETERS &&
	    uap->action != NECP_CLIENT_ACTION_COPY_RESULT &&
	    uap->action != NECP_CLIENT_ACTION_COPY_UPDATED_RESULT) {
		return EINVAL;
	}

	if (uap->client_id) {
		if (uap->client_id_len != sizeof(uuid_t)) {
			NECPLOG(LOG_ERR, "Incorrect length (got %d, expected %d)", uap->client_id_len, sizeof(uuid_t));
			return ERANGE;
		}

		error = copyin(uap->client_id, client_id, sizeof(uuid_t));
		if (error) {
			NECPLOG(LOG_ERR, "necp_client_copy client_id copyin error (%d)", error);
			return error;
		}
	}

	const bool is_wildcard = (bool)uuid_is_null(client_id);

	NECP_FD_LOCK(fd_data);

	if (is_wildcard) {
		if (uap->action == NECP_CLIENT_ACTION_COPY_RESULT || uap->action == NECP_CLIENT_ACTION_COPY_UPDATED_RESULT) {
			struct necp_client *find_client = NULL;
			RB_FOREACH(find_client, _necp_client_tree, &fd_data->clients) {
				NECP_CLIENT_LOCK(find_client);
				if (!find_client->result_read || necp_client_has_unread_flows(find_client)) {
					client = find_client;
					// Leave the client locked, and break
					break;
				}
				NECP_CLIENT_UNLOCK(find_client);
			}
		}
	} else {
		client = necp_client_fd_find_client_and_lock(fd_data, client_id);
	}

	if (client != NULL) {
		// If client is set, it is locked
		error = necp_client_copy_internal(client, client_id, FALSE, uap, retval);
		NECP_CLIENT_UNLOCK(client);
	}

	// Unlock our own fd before moving on or returning
	NECP_FD_UNLOCK(fd_data);

	if (client == NULL) {
		if (fd_data->flags & NECP_OPEN_FLAG_OBSERVER) {
			// Observers are allowed to lookup clients on other fds

			// Lock tree
			NECP_CLIENT_TREE_LOCK_SHARED();

			bool found_client = FALSE;

			client = necp_find_client_and_lock(client_id);
			if (client != NULL) {
				// Matched, copy out data
				found_client = TRUE;
				error = necp_client_copy_internal(client, client_id, TRUE, uap, retval);
				NECP_CLIENT_UNLOCK(client);
			}

			// Unlock tree
			NECP_CLIENT_TREE_UNLOCK();

			// No client found, fail
			if (!found_client) {
				return ENOENT;
			}
		} else {
			// No client found, and not allowed to search other fds, fail
			return ENOENT;
		}
	}

	return error;
}

static int
necp_client_copy_client_update(struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;

	*retval = 0;

	if (!(fd_data->flags & NECP_OPEN_FLAG_PUSH_OBSERVER)) {
		NECPLOG0(LOG_ERR, "NECP fd is not observer, cannot copy client update");
		return EINVAL;
	}

	if (uap->client_id_len != sizeof(uuid_t) || uap->client_id == 0) {
		NECPLOG0(LOG_ERR, "Client id invalid, cannot copy client update");
		return EINVAL;
	}

	if (uap->buffer_size == 0 || uap->buffer == 0) {
		NECPLOG0(LOG_ERR, "Buffer invalid, cannot copy client update");
		return EINVAL;
	}

	NECP_FD_LOCK(fd_data);
	struct necp_client_update *client_update = TAILQ_FIRST(&fd_data->update_list);
	if (client_update != NULL) {
		TAILQ_REMOVE(&fd_data->update_list, client_update, chain);
		VERIFY(fd_data->update_count > 0);
		fd_data->update_count--;
	}
	NECP_FD_UNLOCK(fd_data);

	if (client_update != NULL) {
		error = copyout(client_update->client_id, uap->client_id, sizeof(uuid_t));
		if (error) {
			NECPLOG(LOG_ERR, "Copy client update copyout client id error (%d)", error);
		} else {
			if (uap->buffer_size < client_update->update_length) {
				NECPLOG(LOG_ERR, "Buffer size cannot hold update (%zu < %zu)", uap->buffer_size, client_update->update_length);
				error = EINVAL;
			} else {
				error = copyout(&client_update->update, uap->buffer, client_update->update_length);
				if (error) {
					NECPLOG(LOG_ERR, "Copy client update copyout error (%d)", error);
				} else {
					*retval = client_update->update_length;
				}
			}
		}

		FREE(client_update, M_NECP);
		client_update = NULL;
	} else {
		error = ENOENT;
	}

	return error;
}

static int
necp_client_copy_parameters_locked(struct necp_client *client,
    struct necp_client_nexus_parameters *parameters)
{
	VERIFY(parameters != NULL);

	struct necp_client_parsed_parameters parsed_parameters = {};
	int error = necp_client_parse_parameters(client->parameters, (u_int32_t)client->parameters_length, &parsed_parameters);

	parameters->pid = client->proc_pid;
	if (parsed_parameters.valid_fields & NECP_PARSED_PARAMETERS_FIELD_EFFECTIVE_PID) {
		parameters->epid = parsed_parameters.effective_pid;
	} else {
		parameters->epid = parameters->pid;
	}
	memcpy(&parameters->local_addr, &parsed_parameters.local_addr, sizeof(parameters->local_addr));
	memcpy(&parameters->remote_addr, &parsed_parameters.remote_addr, sizeof(parameters->remote_addr));
	parameters->ip_protocol = parsed_parameters.ip_protocol;
	parameters->traffic_class = parsed_parameters.traffic_class;
	uuid_copy(parameters->euuid, parsed_parameters.effective_uuid);
	parameters->is_listener = (parsed_parameters.flags & NECP_CLIENT_PARAMETER_FLAG_LISTENER) ? 1 : 0;
	parameters->policy_id = client->policy_id;

	// parse client result flag
	u_int32_t client_result_flags = 0;
	u_int32_t value_size = 0;
	u_int8_t *flags_pointer = NULL;
	flags_pointer = necp_buffer_get_tlv_value(client->result, 0, &value_size);
	if (flags_pointer && value_size == sizeof(client_result_flags)) {
		memcpy(&client_result_flags, flags_pointer, value_size);
	}
	parameters->allow_qos_marking = (client_result_flags & NECP_CLIENT_RESULT_FLAG_ALLOW_QOS_MARKING) ? 1 : 0;

	return error;
}

static int
necp_client_list(struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	struct necp_client *find_client = NULL;
	uuid_t *list = NULL;
	u_int32_t requested_client_count = 0;
	u_int32_t client_count = 0;
	size_t copy_buffer_size = 0;

	if (uap->buffer_size < sizeof(requested_client_count) || uap->buffer == 0) {
		error = EINVAL;
		goto done;
	}

	if (!(fd_data->flags & NECP_OPEN_FLAG_OBSERVER)) {
		NECPLOG0(LOG_ERR, "Client does not hold necessary entitlement to list other NECP clients");
		error = EACCES;
		goto done;
	}

	error = copyin(uap->buffer, &requested_client_count, sizeof(requested_client_count));
	if (error) {
		goto done;
	}

	if (os_mul_overflow(sizeof(uuid_t), requested_client_count, &copy_buffer_size)) {
		error = ERANGE;
		goto done;
	}

	if (uap->buffer_size - sizeof(requested_client_count) != copy_buffer_size) {
		error = EINVAL;
		goto done;
	}

	if (copy_buffer_size > NECP_MAX_CLIENT_LIST_SIZE) {
		error = EINVAL;
		goto done;
	}

	if (requested_client_count > 0) {
		if ((list = _MALLOC(copy_buffer_size, M_NECP, M_WAITOK | M_ZERO)) == NULL) {
			error = ENOMEM;
			goto done;
		}
	}

	// Lock tree
	NECP_CLIENT_TREE_LOCK_SHARED();

	find_client = NULL;
	RB_FOREACH(find_client, _necp_client_global_tree, &necp_client_global_tree) {
		NECP_CLIENT_LOCK(find_client);
		if (!uuid_is_null(find_client->client_id)) {
			if (client_count < requested_client_count) {
				uuid_copy(list[client_count], find_client->client_id);
			}
			client_count++;
		}
		NECP_CLIENT_UNLOCK(find_client);
	}

	// Unlock tree
	NECP_CLIENT_TREE_UNLOCK();

	error = copyout(&client_count, uap->buffer, sizeof(client_count));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_list buffer copyout error (%d)", error);
		goto done;
	}

	if (requested_client_count > 0 &&
	    client_count > 0 &&
	    list != NULL) {
		error = copyout(list, uap->buffer + sizeof(client_count), copy_buffer_size);
		if (error) {
			NECPLOG(LOG_ERR, "necp_client_list client count copyout error (%d)", error);
			goto done;
		}
	}
done:
	if (list != NULL) {
		FREE(list, M_NECP);
	}
	*retval = error;

	return error;
}


static void
necp_client_add_assertion(struct necp_client *client, uuid_t netagent_uuid)
{
	struct necp_client_assertion *new_assertion = NULL;

	MALLOC(new_assertion, struct necp_client_assertion *, sizeof(*new_assertion), M_NECP, M_WAITOK);
	if (new_assertion == NULL) {
		NECPLOG0(LOG_ERR, "Failed to allocate assertion");
		return;
	}

	uuid_copy(new_assertion->asserted_netagent, netagent_uuid);

	LIST_INSERT_HEAD(&client->assertion_list, new_assertion, assertion_chain);
}

static bool
necp_client_remove_assertion(struct necp_client *client, uuid_t netagent_uuid)
{
	struct necp_client_assertion *found_assertion = NULL;
	struct necp_client_assertion *search_assertion = NULL;
	LIST_FOREACH(search_assertion, &client->assertion_list, assertion_chain) {
		if (uuid_compare(search_assertion->asserted_netagent, netagent_uuid) == 0) {
			found_assertion = search_assertion;
			break;
		}
	}

	if (found_assertion == NULL) {
		NECPLOG0(LOG_ERR, "Netagent uuid not previously asserted");
		return false;
	}

	LIST_REMOVE(found_assertion, assertion_chain);
	FREE(found_assertion, M_NECP);
	return true;
}

static int
necp_client_agent_action(struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	struct necp_client *client = NULL;
	uuid_t client_id;
	bool acted_on_agent = FALSE;
	u_int8_t *parameters = NULL;
	size_t parameters_size = uap->buffer_size;

	if (uap->client_id == 0 || uap->client_id_len != sizeof(uuid_t) ||
	    uap->buffer_size == 0 || uap->buffer == 0) {
		NECPLOG0(LOG_ERR, "necp_client_agent_action invalid parameters");
		error = EINVAL;
		goto done;
	}

	error = copyin(uap->client_id, client_id, sizeof(uuid_t));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_agent_action copyin client_id error (%d)", error);
		goto done;
	}

	if (uap->buffer_size > NECP_MAX_AGENT_ACTION_SIZE) {
		NECPLOG(LOG_ERR, "necp_client_agent_action invalid buffer size (>%u)", NECP_MAX_AGENT_ACTION_SIZE);
		error = EINVAL;
		goto done;
	}

	if ((parameters = _MALLOC(uap->buffer_size, M_NECP, M_WAITOK | M_ZERO)) == NULL) {
		NECPLOG0(LOG_ERR, "necp_client_agent_action malloc failed");
		error = ENOMEM;
		goto done;
	}

	error = copyin(uap->buffer, parameters, uap->buffer_size);
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_agent_action parameters copyin error (%d)", error);
		goto done;
	}

	NECP_FD_LOCK(fd_data);
	client = necp_client_fd_find_client_and_lock(fd_data, client_id);
	if (client != NULL) {
		size_t offset = 0;
		while ((offset + sizeof(struct necp_tlv_header)) <= parameters_size) {
			u_int8_t type = necp_buffer_get_tlv_type(parameters, offset);
			u_int32_t length = necp_buffer_get_tlv_length(parameters, offset);

			if (length > (parameters_size - (offset + sizeof(struct necp_tlv_header)))) {
				// If the length is larger than what can fit in the remaining parameters size, bail
				NECPLOG(LOG_ERR, "Invalid TLV length (%u)", length);
				break;
			}

			if (length > 0) {
				u_int8_t *value = necp_buffer_get_tlv_value(parameters, offset, NULL);
				if (length >= sizeof(uuid_t) &&
				    value != NULL &&
				    (type == NECP_CLIENT_PARAMETER_TRIGGER_AGENT ||
				    type == NECP_CLIENT_PARAMETER_ASSERT_AGENT ||
				    type == NECP_CLIENT_PARAMETER_UNASSERT_AGENT)) {
					uuid_t agent_uuid;
					uuid_copy(agent_uuid, value);
					u_int8_t netagent_message_type = 0;
					if (type == NECP_CLIENT_PARAMETER_TRIGGER_AGENT) {
						netagent_message_type = NETAGENT_MESSAGE_TYPE_CLIENT_TRIGGER;
					} else if (type == NECP_CLIENT_PARAMETER_ASSERT_AGENT) {
						netagent_message_type = NETAGENT_MESSAGE_TYPE_CLIENT_ASSERT;
					} else if (type == NECP_CLIENT_PARAMETER_UNASSERT_AGENT) {
						netagent_message_type = NETAGENT_MESSAGE_TYPE_CLIENT_UNASSERT;
					}

					// Before unasserting, verify that the assertion was already taken
					if (type == NECP_CLIENT_PARAMETER_UNASSERT_AGENT) {
						if (!necp_client_remove_assertion(client, agent_uuid)) {
							error = ENOENT;
							break;
						}
					}

					struct necp_client_nexus_parameters parsed_parameters = {};
					necp_client_copy_parameters_locked(client, &parsed_parameters);

					error = netagent_client_message_with_params(agent_uuid,
					    client_id,
					    fd_data->proc_pid,
					    client->agent_handle,
					    netagent_message_type,
					    &parsed_parameters,
					    NULL, NULL);
					if (error == 0) {
						acted_on_agent = TRUE;
					} else {
						break;
					}

					// Only save the assertion if the action succeeded
					if (type == NECP_CLIENT_PARAMETER_ASSERT_AGENT) {
						necp_client_add_assertion(client, agent_uuid);
					}
				}
			}

			offset += sizeof(struct necp_tlv_header) + length;
		}

		NECP_CLIENT_UNLOCK(client);
	}
	NECP_FD_UNLOCK(fd_data);

	if (!acted_on_agent &&
	    error == 0) {
		error = ENOENT;
	}
done:
	*retval = error;
	if (parameters != NULL) {
		FREE(parameters, M_NECP);
		parameters = NULL;
	}

	return error;
}

static int
necp_client_copy_agent(__unused struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	uuid_t agent_uuid;

	if (uap->client_id == 0 || uap->client_id_len != sizeof(uuid_t) ||
	    uap->buffer_size == 0 || uap->buffer == 0) {
		NECPLOG0(LOG_ERR, "necp_client_copy_agent bad input");
		error = EINVAL;
		goto done;
	}

	error = copyin(uap->client_id, agent_uuid, sizeof(uuid_t));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_copy_agent copyin agent_uuid error (%d)", error);
		goto done;
	}

	error = netagent_copyout(agent_uuid, uap->buffer, uap->buffer_size);
	if (error) {
		// netagent_copyout already logs appropriate errors
		goto done;
	}
done:
	*retval = error;

	return error;
}

static int
necp_client_agent_use(struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	struct necp_client *client = NULL;
	uuid_t client_id;
	struct necp_agent_use_parameters parameters;

	if (uap->client_id == 0 || uap->client_id_len != sizeof(uuid_t) ||
	    uap->buffer_size != sizeof(parameters) || uap->buffer == 0) {
		error = EINVAL;
		goto done;
	}

	error = copyin(uap->client_id, client_id, sizeof(uuid_t));
	if (error) {
		NECPLOG(LOG_ERR, "Copyin client_id error (%d)", error);
		goto done;
	}

	error = copyin(uap->buffer, &parameters, uap->buffer_size);
	if (error) {
		NECPLOG(LOG_ERR, "Parameters copyin error (%d)", error);
		goto done;
	}

	NECP_FD_LOCK(fd_data);
	client = necp_client_fd_find_client_and_lock(fd_data, client_id);
	if (client != NULL) {
		error = netagent_use(parameters.agent_uuid, &parameters.out_use_count);
		NECP_CLIENT_UNLOCK(client);
	} else {
		error = ENOENT;
	}

	NECP_FD_UNLOCK(fd_data);

	if (error == 0) {
		error = copyout(&parameters, uap->buffer, uap->buffer_size);
		if (error) {
			NECPLOG(LOG_ERR, "Parameters copyout error (%d)", error);
			goto done;
		}
	}

done:
	*retval = error;

	return error;
}

static int
necp_client_copy_interface(__unused struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	u_int32_t interface_index = 0;
	struct necp_interface_details interface_details;

	if (uap->client_id == 0 || uap->client_id_len != sizeof(u_int32_t) ||
	    uap->buffer_size < sizeof(interface_details) || uap->buffer == 0) {
		NECPLOG0(LOG_ERR, "necp_client_copy_interface bad input");
		error = EINVAL;
		goto done;
	}

	error = copyin(uap->client_id, &interface_index, sizeof(u_int32_t));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_copy_interface copyin interface_index error (%d)", error);
		goto done;
	}

	if (interface_index == 0) {
		error = ENOENT;
		NECPLOG(LOG_ERR, "necp_client_copy_interface bad interface_index (%d)", interface_index);
		goto done;
	}

	memset(&interface_details, 0, sizeof(interface_details));

	ifnet_head_lock_shared();
	ifnet_t interface = NULL;
	if (interface_index != IFSCOPE_NONE && interface_index <= (u_int32_t)if_index) {
		interface = ifindex2ifnet[interface_index];
	}

	if (interface != NULL) {
		if (interface->if_xname != NULL) {
			strlcpy((char *)&interface_details.name, interface->if_xname, sizeof(interface_details.name));
		}
		interface_details.index = interface->if_index;
		interface_details.generation = ifnet_get_generation(interface);
		if (interface->if_delegated.ifp != NULL) {
			interface_details.delegate_index = interface->if_delegated.ifp->if_index;
		}
		interface_details.functional_type = if_functional_type(interface, TRUE);
		if (IFNET_IS_EXPENSIVE(interface)) {
			interface_details.flags |= NECP_INTERFACE_FLAG_EXPENSIVE;
		}
		if ((interface->if_eflags & IFEF_TXSTART) == IFEF_TXSTART) {
			interface_details.flags |= NECP_INTERFACE_FLAG_TXSTART;
		}
		if ((interface->if_eflags & IFEF_NOACKPRI) == IFEF_NOACKPRI) {
			interface_details.flags |= NECP_INTERFACE_FLAG_NOACKPRI;
		}
		if ((interface->if_eflags & IFEF_3CA) == IFEF_3CA) {
			interface_details.flags |= NECP_INTERFACE_FLAG_3CARRIERAGG;
		}
		if (IFNET_IS_LOW_POWER(interface)) {
			interface_details.flags |= NECP_INTERFACE_FLAG_IS_LOW_POWER;
		}
		interface_details.mtu = interface->if_mtu;

		u_int8_t ipv4_signature_len = sizeof(interface_details.ipv4_signature.signature);
		u_int16_t ipv4_signature_flags;
		if (ifnet_get_netsignature(interface, AF_INET, &ipv4_signature_len, &ipv4_signature_flags,
		    (u_int8_t *)&interface_details.ipv4_signature) != 0) {
			ipv4_signature_len = 0;
		}
		interface_details.ipv4_signature.signature_len = ipv4_signature_len;

		u_int8_t ipv6_signature_len = sizeof(interface_details.ipv6_signature.signature);
		u_int16_t ipv6_signature_flags;
		if (ifnet_get_netsignature(interface, AF_INET6, &ipv6_signature_len, &ipv6_signature_flags,
		    (u_int8_t *)&interface_details.ipv6_signature) != 0) {
			ipv6_signature_len = 0;
		}
		interface_details.ipv6_signature.signature_len = ipv6_signature_len;
	}

	ifnet_head_done();

	error = copyout(&interface_details, uap->buffer, sizeof(interface_details));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_copy_interface copyout error (%d)", error);
		goto done;
	}
done:
	*retval = error;

	return error;
}


static int
necp_client_copy_route_statistics(__unused struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	struct necp_client *client = NULL;
	uuid_t client_id;

	if (uap->client_id == 0 || uap->client_id_len != sizeof(uuid_t) ||
	    uap->buffer_size < sizeof(struct necp_stat_counts) || uap->buffer == 0) {
		NECPLOG0(LOG_ERR, "necp_client_copy_route_statistics bad input");
		error = EINVAL;
		goto done;
	}

	error = copyin(uap->client_id, client_id, sizeof(uuid_t));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_copy_route_statistics copyin client_id error (%d)", error);
		goto done;
	}

	// Lock
	NECP_FD_LOCK(fd_data);
	client = necp_client_fd_find_client_and_lock(fd_data, client_id);
	if (client != NULL) {
		NECP_CLIENT_ROUTE_LOCK(client);
		struct necp_stat_counts route_stats = {};
		if (client->current_route != NULL && client->current_route->rt_stats != NULL) {
			struct nstat_counts     *rt_stats = client->current_route->rt_stats;
			atomic_get_64(route_stats.necp_stat_rxpackets, &rt_stats->nstat_rxpackets);
			atomic_get_64(route_stats.necp_stat_rxbytes, &rt_stats->nstat_rxbytes);
			atomic_get_64(route_stats.necp_stat_txpackets, &rt_stats->nstat_txpackets);
			atomic_get_64(route_stats.necp_stat_txbytes, &rt_stats->nstat_txbytes);
			route_stats.necp_stat_rxduplicatebytes = rt_stats->nstat_rxduplicatebytes;
			route_stats.necp_stat_rxoutoforderbytes = rt_stats->nstat_rxoutoforderbytes;
			route_stats.necp_stat_txretransmit = rt_stats->nstat_txretransmit;
			route_stats.necp_stat_connectattempts = rt_stats->nstat_connectattempts;
			route_stats.necp_stat_connectsuccesses = rt_stats->nstat_connectsuccesses;
			route_stats.necp_stat_min_rtt = rt_stats->nstat_min_rtt;
			route_stats.necp_stat_avg_rtt = rt_stats->nstat_avg_rtt;
			route_stats.necp_stat_var_rtt = rt_stats->nstat_var_rtt;
			route_stats.necp_stat_route_flags = client->current_route->rt_flags;
		}

		// Unlock before copying out
		NECP_CLIENT_ROUTE_UNLOCK(client);
		NECP_CLIENT_UNLOCK(client);
		NECP_FD_UNLOCK(fd_data);

		error = copyout(&route_stats, uap->buffer, sizeof(route_stats));
		if (error) {
			NECPLOG(LOG_ERR, "necp_client_copy_route_statistics copyout error (%d)", error);
		}
	} else {
		// Unlock
		NECP_FD_UNLOCK(fd_data);
		error = ENOENT;
	}


done:
	*retval = error;
	return error;
}

static int
necp_client_update_cache(struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	struct necp_client *client = NULL;
	uuid_t client_id;

	if (uap->client_id == 0 || uap->client_id_len != sizeof(uuid_t)) {
		error = EINVAL;
		goto done;
	}

	error = copyin(uap->client_id, client_id, sizeof(uuid_t));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_update_cache copyin client_id error (%d)", error);
		goto done;
	}

	NECP_FD_LOCK(fd_data);
	client = necp_client_fd_find_client_and_lock(fd_data, client_id);
	if (client == NULL) {
		NECP_FD_UNLOCK(fd_data);
		error = ENOENT;
		goto done;
	}

	struct necp_client_flow_registration *flow_registration = necp_client_find_flow(client, client_id);
	if (flow_registration == NULL) {
		NECP_CLIENT_UNLOCK(client);
		NECP_FD_UNLOCK(fd_data);
		error = ENOENT;
		goto done;
	}

	NECP_CLIENT_ROUTE_LOCK(client);
	// This needs to be changed when TFO/ECN is supported by multiple flows
	struct necp_client_flow *flow = LIST_FIRST(&flow_registration->flow_list);
	if (flow == NULL ||
	    (flow->remote_addr.sa.sa_family != AF_INET &&
	    flow->remote_addr.sa.sa_family != AF_INET6) ||
	    (flow->local_addr.sa.sa_family != AF_INET &&
	    flow->local_addr.sa.sa_family != AF_INET6)) {
		error = EINVAL;
		NECPLOG(LOG_ERR, "necp_client_update_cache no flow error (%d)", error);
		goto done_unlock;
	}

	necp_cache_buffer cache_buffer;
	memset(&cache_buffer, 0, sizeof(cache_buffer));

	if (uap->buffer_size != sizeof(necp_cache_buffer) ||
	    uap->buffer == USER_ADDR_NULL) {
		error = EINVAL;
		goto done_unlock;
	}

	error = copyin(uap->buffer, &cache_buffer, sizeof(cache_buffer));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_update_cache copyin cache buffer error (%d)", error);
		goto done_unlock;
	}

	if (cache_buffer.necp_cache_buf_type == NECP_CLIENT_CACHE_TYPE_ECN &&
	    cache_buffer.necp_cache_buf_ver == NECP_CLIENT_CACHE_TYPE_ECN_VER_1) {
		if (cache_buffer.necp_cache_buf_size != sizeof(necp_tcp_ecn_cache) ||
		    cache_buffer.necp_cache_buf_addr == USER_ADDR_NULL) {
			error = EINVAL;
			goto done_unlock;
		}

		necp_tcp_ecn_cache ecn_cache_buffer;
		memset(&ecn_cache_buffer, 0, sizeof(ecn_cache_buffer));

		error = copyin(cache_buffer.necp_cache_buf_addr, &ecn_cache_buffer, sizeof(necp_tcp_ecn_cache));
		if (error) {
			NECPLOG(LOG_ERR, "necp_client_update_cache copyin ecn cache buffer error (%d)", error);
			goto done_unlock;
		}

		if (client->current_route != NULL && client->current_route->rt_ifp != NULL) {
			if (!client->platform_binary) {
				ecn_cache_buffer.necp_tcp_ecn_heuristics_success = 0;
			}
			tcp_heuristics_ecn_update(&ecn_cache_buffer, client->current_route->rt_ifp,
			    (union sockaddr_in_4_6 *)&flow->local_addr);
		}
	} else if (cache_buffer.necp_cache_buf_type == NECP_CLIENT_CACHE_TYPE_TFO &&
	    cache_buffer.necp_cache_buf_ver == NECP_CLIENT_CACHE_TYPE_TFO_VER_1) {
		if (cache_buffer.necp_cache_buf_size != sizeof(necp_tcp_tfo_cache) ||
		    cache_buffer.necp_cache_buf_addr == USER_ADDR_NULL) {
			error = EINVAL;
			goto done_unlock;
		}

		necp_tcp_tfo_cache tfo_cache_buffer;
		memset(&tfo_cache_buffer, 0, sizeof(tfo_cache_buffer));

		error = copyin(cache_buffer.necp_cache_buf_addr, &tfo_cache_buffer, sizeof(necp_tcp_tfo_cache));
		if (error) {
			NECPLOG(LOG_ERR, "necp_client_update_cache copyin tfo cache buffer error (%d)", error);
			goto done_unlock;
		}

		if (client->current_route != NULL && client->current_route->rt_ifp != NULL) {
			if (!client->platform_binary) {
				tfo_cache_buffer.necp_tcp_tfo_heuristics_success = 0;
			}
			tcp_heuristics_tfo_update(&tfo_cache_buffer, client->current_route->rt_ifp,
			    (union sockaddr_in_4_6 *)&flow->local_addr,
			    (union sockaddr_in_4_6 *)&flow->remote_addr);
		}
	} else {
		error = EINVAL;
	}
done_unlock:
	NECP_CLIENT_ROUTE_UNLOCK(client);
	NECP_CLIENT_UNLOCK(client);
	NECP_FD_UNLOCK(fd_data);
done:
	*retval = error;
	return error;
}

int
necp_client_action(struct proc *p, struct necp_client_action_args *uap, int *retval)
{
#pragma unused(p)
	int error = 0;
	int return_value = 0;
	struct necp_fd_data *fd_data = NULL;
	error = necp_find_fd_data(uap->necp_fd, &fd_data);
	if (error != 0) {
		NECPLOG(LOG_ERR, "necp_client_action find fd error (%d)", error);
		return error;
	}

	u_int32_t action = uap->action;
	switch (action) {
	case NECP_CLIENT_ACTION_ADD: {
		return_value = necp_client_add(p, fd_data, uap, retval);
		break;
	}
	case NECP_CLIENT_ACTION_REMOVE: {
		return_value = necp_client_remove(fd_data, uap, retval);
		break;
	}
	case NECP_CLIENT_ACTION_COPY_PARAMETERS:
	case NECP_CLIENT_ACTION_COPY_RESULT:
	case NECP_CLIENT_ACTION_COPY_UPDATED_RESULT: {
		return_value = necp_client_copy(fd_data, uap, retval);
		break;
	}
	case NECP_CLIENT_ACTION_COPY_LIST: {
		return_value = necp_client_list(fd_data, uap, retval);
		break;
	}
	case NECP_CLIENT_ACTION_AGENT: {
		return_value = necp_client_agent_action(fd_data, uap, retval);
		break;
	}
	case NECP_CLIENT_ACTION_COPY_AGENT: {
		return_value = necp_client_copy_agent(fd_data, uap, retval);
		break;
	}
	case NECP_CLIENT_ACTION_AGENT_USE: {
		return_value = necp_client_agent_use(fd_data, uap, retval);
		break;
	}
	case NECP_CLIENT_ACTION_COPY_INTERFACE: {
		return_value = necp_client_copy_interface(fd_data, uap, retval);
		break;
	}
	case NECP_CLIENT_ACTION_COPY_ROUTE_STATISTICS: {
		return_value = necp_client_copy_route_statistics(fd_data, uap, retval);
		break;
	}
	case NECP_CLIENT_ACTION_UPDATE_CACHE: {
		return_value = necp_client_update_cache(fd_data, uap, retval);
		break;
	}
	case NECP_CLIENT_ACTION_COPY_CLIENT_UPDATE: {
		return_value = necp_client_copy_client_update(fd_data, uap, retval);
		break;
	}
	default: {
		NECPLOG(LOG_ERR, "necp_client_action unknown action (%u)", action);
		return_value = EINVAL;
		break;
	}
	}

	file_drop(uap->necp_fd);

	return return_value;
}

#define NECP_MAX_MATCH_POLICY_PARAMETER_SIZE 1024

int
necp_match_policy(struct proc *p, struct necp_match_policy_args *uap, int32_t *retval)
{
#pragma unused(retval)
	u_int8_t *parameters = NULL;
	struct necp_aggregate_result returned_result;
	int error = 0;

	if (uap == NULL) {
		error = EINVAL;
		goto done;
	}

	if (uap->parameters == 0 || uap->parameters_size == 0 || uap->parameters_size > NECP_MAX_MATCH_POLICY_PARAMETER_SIZE || uap->returned_result == 0) {
		error = EINVAL;
		goto done;
	}

	MALLOC(parameters, u_int8_t *, uap->parameters_size, M_NECP, M_WAITOK | M_ZERO);
	if (parameters == NULL) {
		error = ENOMEM;
		goto done;
	}
	// Copy parameters in
	error = copyin(uap->parameters, parameters, uap->parameters_size);
	if (error) {
		goto done;
	}

	error = necp_application_find_policy_match_internal(p, parameters, uap->parameters_size,
	    &returned_result, NULL, 0, NULL, NULL, NULL, false);
	if (error) {
		goto done;
	}

	// Copy return value back
	error = copyout(&returned_result, uap->returned_result, sizeof(struct necp_aggregate_result));
	if (error) {
		goto done;
	}
done:
	if (parameters != NULL) {
		FREE(parameters, M_NECP);
	}
	return error;
}

/// Socket operations
#define NECP_MAX_SOCKET_ATTRIBUTE_STRING_LENGTH 253

static bool
necp_set_socket_attribute(u_int8_t *buffer, size_t buffer_length, u_int8_t type, char **buffer_p)
{
	int error = 0;
	int cursor = 0;
	size_t string_size = 0;
	char *local_string = NULL;
	u_int8_t *value = NULL;

	cursor = necp_buffer_find_tlv(buffer, buffer_length, 0, type, 0);
	if (cursor < 0) {
		// This will clear out the parameter
		goto done;
	}

	string_size = necp_buffer_get_tlv_length(buffer, cursor);
	if (string_size == 0 || string_size > NECP_MAX_SOCKET_ATTRIBUTE_STRING_LENGTH) {
		// This will clear out the parameter
		goto done;
	}

	MALLOC(local_string, char *, string_size + 1, M_NECP, M_WAITOK | M_ZERO);
	if (local_string == NULL) {
		NECPLOG(LOG_ERR, "Failed to allocate a socket attribute buffer (size %d)", string_size);
		goto fail;
	}

	value = necp_buffer_get_tlv_value(buffer, cursor, NULL);
	if (value == NULL) {
		NECPLOG0(LOG_ERR, "Failed to get socket attribute");
		goto fail;
	}

	memcpy(local_string, value, string_size);
	local_string[string_size] = 0;

done:
	if (*buffer_p != NULL) {
		FREE(*buffer_p, M_NECP);
		*buffer_p = NULL;
	}

	*buffer_p = local_string;
	return 0;
fail:
	if (local_string != NULL) {
		FREE(local_string, M_NECP);
	}
	return error;
}

errno_t
necp_set_socket_attributes(struct socket *so, struct sockopt *sopt)
{
	int error = 0;
	u_int8_t *buffer = NULL;
	struct inpcb *inp = NULL;

	if ((SOCK_DOM(so) != PF_INET
#if INET6
	    && SOCK_DOM(so) != PF_INET6
#endif
	    )) {
		error = EINVAL;
		goto done;
	}

	inp = sotoinpcb(so);

	size_t valsize = sopt->sopt_valsize;
	if (valsize == 0 ||
	    valsize > ((sizeof(struct necp_tlv_header) + NECP_MAX_SOCKET_ATTRIBUTE_STRING_LENGTH) * 2)) {
		goto done;
	}

	MALLOC(buffer, u_int8_t *, valsize, M_NECP, M_WAITOK | M_ZERO);
	if (buffer == NULL) {
		goto done;
	}

	error = sooptcopyin(sopt, buffer, valsize, 0);
	if (error) {
		goto done;
	}

	error = necp_set_socket_attribute(buffer, valsize, NECP_TLV_ATTRIBUTE_DOMAIN, &inp->inp_necp_attributes.inp_domain);
	if (error) {
		NECPLOG0(LOG_ERR, "Could not set domain TLV for socket attributes");
		goto done;
	}

	error = necp_set_socket_attribute(buffer, valsize, NECP_TLV_ATTRIBUTE_ACCOUNT, &inp->inp_necp_attributes.inp_account);
	if (error) {
		NECPLOG0(LOG_ERR, "Could not set account TLV for socket attributes");
		goto done;
	}

	if (necp_debug) {
		NECPLOG(LOG_DEBUG, "Set on socket: Domain %s, Account %s", inp->inp_necp_attributes.inp_domain, inp->inp_necp_attributes.inp_account);
	}
done:
	if (buffer != NULL) {
		FREE(buffer, M_NECP);
	}

	return error;
}

errno_t
necp_get_socket_attributes(struct socket *so, struct sockopt *sopt)
{
	int error = 0;
	u_int8_t *buffer = NULL;
	u_int8_t *cursor = NULL;
	size_t valsize = 0;
	struct inpcb *inp = NULL;

	if ((SOCK_DOM(so) != PF_INET
#if INET6
	    && SOCK_DOM(so) != PF_INET6
#endif
	    )) {
		error = EINVAL;
		goto done;
	}

	inp = sotoinpcb(so);
	if (inp->inp_necp_attributes.inp_domain != NULL) {
		valsize += sizeof(struct necp_tlv_header) + strlen(inp->inp_necp_attributes.inp_domain);
	}
	if (inp->inp_necp_attributes.inp_account != NULL) {
		valsize += sizeof(struct necp_tlv_header) + strlen(inp->inp_necp_attributes.inp_account);
	}
	if (valsize == 0) {
		goto done;
	}

	MALLOC(buffer, u_int8_t *, valsize, M_NECP, M_WAITOK | M_ZERO);
	if (buffer == NULL) {
		goto done;
	}

	cursor = buffer;
	if (inp->inp_necp_attributes.inp_domain != NULL) {
		cursor = necp_buffer_write_tlv(cursor, NECP_TLV_ATTRIBUTE_DOMAIN, strlen(inp->inp_necp_attributes.inp_domain), inp->inp_necp_attributes.inp_domain,
		    buffer, valsize);
	}

	if (inp->inp_necp_attributes.inp_account != NULL) {
		cursor = necp_buffer_write_tlv(cursor, NECP_TLV_ATTRIBUTE_ACCOUNT, strlen(inp->inp_necp_attributes.inp_account), inp->inp_necp_attributes.inp_account,
		    buffer, valsize);
	}

	error = sooptcopyout(sopt, buffer, valsize);
	if (error) {
		goto done;
	}
done:
	if (buffer != NULL) {
		FREE(buffer, M_NECP);
	}

	return error;
}

void *
necp_create_nexus_assign_message(uuid_t nexus_instance, u_int32_t nexus_port, void *key, uint32_t key_length,
    struct necp_client_endpoint *local_endpoint, struct necp_client_endpoint *remote_endpoint,
    u_int32_t flow_adv_index, void *flow_stats, size_t *message_length)
{
	u_int8_t *buffer = NULL;
	u_int8_t *cursor = NULL;
	size_t valsize = 0;
	bool has_nexus_assignment = FALSE;


	if (!uuid_is_null(nexus_instance)) {
		has_nexus_assignment = TRUE;
		valsize += sizeof(struct necp_tlv_header) + sizeof(uuid_t);
		valsize += sizeof(struct necp_tlv_header) + sizeof(u_int32_t);
	}
	if (flow_adv_index != NECP_FLOWADV_IDX_INVALID) {
		valsize += sizeof(struct necp_tlv_header) + sizeof(u_int32_t);
	}
	if (key != NULL && key_length > 0) {
		valsize += sizeof(struct necp_tlv_header) + key_length;
	}
	if (local_endpoint != NULL) {
		valsize += sizeof(struct necp_tlv_header) + sizeof(struct necp_client_endpoint);
	}
	if (remote_endpoint != NULL) {
		valsize += sizeof(struct necp_tlv_header) + sizeof(struct necp_client_endpoint);
	}
	if (flow_stats != NULL) {
		valsize += sizeof(struct necp_tlv_header) + sizeof(void *);
	}
	if (valsize == 0) {
		return NULL;
	}

	MALLOC(buffer, u_int8_t *, valsize, M_NETAGENT, M_WAITOK | M_ZERO); // Use M_NETAGENT area, since it is expected upon free
	if (buffer == NULL) {
		return NULL;
	}

	cursor = buffer;
	if (has_nexus_assignment) {
		cursor = necp_buffer_write_tlv(cursor, NECP_CLIENT_RESULT_NEXUS_INSTANCE, sizeof(uuid_t), nexus_instance, buffer, valsize);
		cursor = necp_buffer_write_tlv(cursor, NECP_CLIENT_RESULT_NEXUS_PORT, sizeof(u_int32_t), &nexus_port, buffer, valsize);
	}
	if (flow_adv_index != NECP_FLOWADV_IDX_INVALID) {
		cursor = necp_buffer_write_tlv(cursor, NECP_CLIENT_RESULT_NEXUS_PORT_FLOW_INDEX, sizeof(u_int32_t), &flow_adv_index, buffer, valsize);
	}
	if (key != NULL && key_length > 0) {
		cursor = necp_buffer_write_tlv(cursor, NECP_CLIENT_PARAMETER_NEXUS_KEY, key_length, key, buffer, valsize);
	}
	if (local_endpoint != NULL) {
		cursor = necp_buffer_write_tlv(cursor, NECP_CLIENT_RESULT_LOCAL_ENDPOINT, sizeof(struct necp_client_endpoint), local_endpoint, buffer, valsize);
	}
	if (remote_endpoint != NULL) {
		cursor = necp_buffer_write_tlv(cursor, NECP_CLIENT_RESULT_REMOTE_ENDPOINT, sizeof(struct necp_client_endpoint), remote_endpoint, buffer, valsize);
	}
	if (flow_stats != NULL) {
		cursor = necp_buffer_write_tlv(cursor, NECP_CLIENT_RESULT_NEXUS_FLOW_STATS, sizeof(void *), &flow_stats, buffer, valsize);
	}

	*message_length = valsize;

	return buffer;
}

void
necp_inpcb_remove_cb(struct inpcb *inp)
{
	if (!uuid_is_null(inp->necp_client_uuid)) {
		necp_client_unregister_socket_flow(inp->necp_client_uuid, inp);
		uuid_clear(inp->necp_client_uuid);
	}
}

void
necp_inpcb_dispose(struct inpcb *inp)
{
	necp_inpcb_remove_cb(inp); // Clear out socket registrations if not yet done
	if (inp->inp_necp_attributes.inp_domain != NULL) {
		FREE(inp->inp_necp_attributes.inp_domain, M_NECP);
		inp->inp_necp_attributes.inp_domain = NULL;
	}
	if (inp->inp_necp_attributes.inp_account != NULL) {
		FREE(inp->inp_necp_attributes.inp_account, M_NECP);
		inp->inp_necp_attributes.inp_account = NULL;
	}
}

void
necp_mppcb_dispose(struct mppcb *mpp)
{
	if (!uuid_is_null(mpp->necp_client_uuid)) {
		necp_client_unregister_multipath_cb(mpp->necp_client_uuid, mpp);
		uuid_clear(mpp->necp_client_uuid);
	}
}

/// Module init

errno_t
necp_client_init(void)
{
	necp_fd_grp_attr = lck_grp_attr_alloc_init();
	if (necp_fd_grp_attr == NULL) {
		panic("lck_grp_attr_alloc_init failed\n");
		/* NOTREACHED */
	}

	necp_fd_mtx_grp = lck_grp_alloc_init("necp_fd", necp_fd_grp_attr);
	if (necp_fd_mtx_grp == NULL) {
		panic("lck_grp_alloc_init failed\n");
		/* NOTREACHED */
	}

	necp_fd_mtx_attr = lck_attr_alloc_init();
	if (necp_fd_mtx_attr == NULL) {
		panic("lck_attr_alloc_init failed\n");
		/* NOTREACHED */
	}

	necp_client_fd_size = sizeof(struct necp_fd_data);
	necp_client_fd_zone = zinit(necp_client_fd_size,
	    NECP_CLIENT_FD_ZONE_MAX * necp_client_fd_size,
	    0, NECP_CLIENT_FD_ZONE_NAME);
	if (necp_client_fd_zone == NULL) {
		panic("zinit(necp_client_fd) failed\n");
		/* NOTREACHED */
	}

	necp_flow_size = sizeof(struct necp_client_flow);
	necp_flow_cache = mcache_create(NECP_FLOW_ZONE_NAME, necp_flow_size, sizeof(uint64_t), 0, MCR_SLEEP);
	if (necp_flow_cache == NULL) {
		panic("mcache_create(necp_flow_cache) failed\n");
		/* NOTREACHED */
	}

	necp_flow_registration_size = sizeof(struct necp_client_flow_registration);
	necp_flow_registration_cache = mcache_create(NECP_FLOW_REGISTRATION_ZONE_NAME, necp_flow_registration_size, sizeof(uint64_t), 0, MCR_SLEEP);
	if (necp_flow_registration_cache == NULL) {
		panic("mcache_create(necp_client_flow_registration) failed\n");
		/* NOTREACHED */
	}

	necp_client_update_tcall = thread_call_allocate_with_options(necp_update_all_clients_callout, NULL,
	    THREAD_CALL_PRIORITY_KERNEL, THREAD_CALL_OPTIONS_ONCE);
	VERIFY(necp_client_update_tcall != NULL);

	lck_rw_init(&necp_fd_lock, necp_fd_mtx_grp, necp_fd_mtx_attr);
	lck_rw_init(&necp_observer_lock, necp_fd_mtx_grp, necp_fd_mtx_attr);
	lck_rw_init(&necp_client_tree_lock, necp_fd_mtx_grp, necp_fd_mtx_attr);
	lck_rw_init(&necp_flow_tree_lock, necp_fd_mtx_grp, necp_fd_mtx_attr);
	lck_rw_init(&necp_collect_stats_list_lock, necp_fd_mtx_grp, necp_fd_mtx_attr);

	LIST_INIT(&necp_fd_list);
	LIST_INIT(&necp_fd_observer_list);
	LIST_INIT(&necp_collect_stats_flow_list);

	RB_INIT(&necp_client_global_tree);
	RB_INIT(&necp_client_flow_global_tree);

	return 0;
}

void
necp_client_reap_caches(boolean_t purge)
{
	mcache_reap_now(necp_flow_cache, purge);
	mcache_reap_now(necp_flow_registration_cache, purge);
}

