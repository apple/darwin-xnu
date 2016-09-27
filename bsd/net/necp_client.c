/*
 * Copyright (c) 2015-2016 Apple Inc. All rights reserved.
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
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/malloc.h>
#include <libkern/OSMalloc.h>
#include <sys/kernel.h>
#include <net/if.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in_pcb.h>
#include <net/if_var.h>
#include <netinet/tcp_cc.h>
#include <net/ntstat.h>
#include <sys/kauth.h>
#include <sys/sysproto.h>
#include <sys/priv.h>
#include <net/network_agent.h>
#include <net/necp.h>
#include <sys/file_internal.h>
#include <sys/poll.h>
#include <kern/thread_call.h>

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
static int necpop_kqfilter(struct fileproc *, struct knote *, vfs_context_t);

// Timer functions
static int necp_timeout_microseconds = 1000 * 100; // 100ms
static int necp_timeout_leeway_microseconds = 1000 * 500; // 500ms
extern int tvtohz(struct timeval *);

// Parsed parameters
#define NECP_PARSED_PARAMETERS_FIELD_LOCAL_ADDR				0x0001
#define NECP_PARSED_PARAMETERS_FIELD_REMOTE_ADDR			0x0002
#define NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IF			0x0004
#define NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_IF			0x0008
#define NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IFTYPE		0x0010
#define NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_IFTYPE		0x0020
#define NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT			0x0040
#define NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_AGENT		0x0080
#define NECP_PARSED_PARAMETERS_FIELD_PREFERRED_AGENT		0x0100
#define NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT_TYPE	0x0200
#define NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_AGENT_TYPE	0x0400
#define NECP_PARSED_PARAMETERS_FIELD_PREFERRED_AGENT_TYPE	0x0800

#define NECP_MAX_PARSED_PARAMETERS 16
struct necp_client_parsed_parameters {
	u_int32_t valid_fields;
	union necp_sockaddr_union local_addr;
	union necp_sockaddr_union remote_addr;
	u_int32_t required_interface_index;
	char prohibited_interfaces[IFXNAMSIZ][NECP_MAX_PARSED_PARAMETERS];
	u_int8_t required_interface_types[NECP_MAX_PARSED_PARAMETERS];
	u_int8_t prohibited_interface_types[NECP_MAX_PARSED_PARAMETERS];
	struct necp_client_parameter_netagent_type required_netagent_types[NECP_MAX_PARSED_PARAMETERS];
	struct necp_client_parameter_netagent_type prohibited_netagent_types[NECP_MAX_PARSED_PARAMETERS];
	struct necp_client_parameter_netagent_type preferred_netagent_types[NECP_MAX_PARSED_PARAMETERS];
	uuid_t required_netagents[NECP_MAX_PARSED_PARAMETERS];
	uuid_t prohibited_netagents[NECP_MAX_PARSED_PARAMETERS];
	uuid_t preferred_netagents[NECP_MAX_PARSED_PARAMETERS];
};

static bool necp_find_matching_interface_index(struct necp_client_parsed_parameters *parsed_parameters, u_int *return_ifindex);

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

struct necp_client {
	LIST_ENTRY(necp_client) chain;

	uuid_t client_id;
	bool result_read;
	bool assigned_result_read;

	size_t result_length;
	u_int8_t result[NECP_MAX_CLIENT_RESULT_SIZE];

	uuid_t nexus_agent;
	size_t assigned_results_length;
	u_int8_t *assigned_results;

	LIST_HEAD(_necp_client_assertion_list, necp_client_assertion) assertion_list;

	user_addr_t stats_uaddr;
	user_size_t stats_ulen;
	nstat_userland_context stats_handler_context;
	necp_stats_hdr *stats_area;

	size_t parameters_length;
	u_int8_t parameters[0];
};

struct necp_fd_data {
	LIST_ENTRY(necp_fd_data) chain;
	LIST_HEAD(_clients, necp_client) clients;
	int flags;
	int proc_pid;
	decl_lck_mtx_data(, fd_lock);
	struct selinfo si;
};

static LIST_HEAD(_necp_fd_list, necp_fd_data) necp_fd_list;

static	lck_grp_attr_t	*necp_fd_grp_attr	= NULL;
static	lck_attr_t		*necp_fd_mtx_attr	= NULL;
static	lck_grp_t		*necp_fd_mtx_grp	= NULL;
decl_lck_rw_data(static, necp_fd_lock);

static thread_call_t necp_client_tcall;

/// NECP file descriptor functions

static int
noop_read(struct fileproc *fp, struct uio *uio, int flags, vfs_context_t ctx)
{
#pragma unused(fp, uio, flags, ctx)
	return (ENXIO);
}

static int
noop_write(struct fileproc *fp, struct uio *uio, int flags,
		   vfs_context_t ctx)
{
#pragma unused(fp, uio, flags, ctx)
	return (ENXIO);
}

static int
noop_ioctl(struct fileproc *fp, unsigned long com, caddr_t data,
		   vfs_context_t ctx)
{
#pragma unused(fp, com, data, ctx)
	return (ENOTTY);
}

static void
necp_fd_notify(struct necp_fd_data *fd_data, bool locked)
{
	struct selinfo *si = &fd_data->si;

	if (!locked) {
		lck_mtx_lock(&fd_data->fd_lock);
	}

	selwakeup(si);

	// use a non-zero hint to tell the notification from the
	// call done in kqueue_scan() which uses 0
	KNOTE(&si->si_note, 1); // notification

	if (!locked) {
		lck_mtx_unlock(&fd_data->fd_lock);
	}
}

static int
necp_fd_poll(struct necp_fd_data *fd_data, int events, void *wql, struct proc *p, int is_kevent)
{
#pragma unused(wql, p, is_kevent)
	u_int revents = 0;
	struct necp_client *client = NULL;
	bool has_unread_clients = FALSE;

	u_int want_rx = events & (POLLIN | POLLRDNORM);
	if (want_rx) {

		LIST_FOREACH(client, &fd_data->clients, chain) {
			if (!client->result_read || !client->assigned_result_read) {
				has_unread_clients = TRUE;
				break;
			}
		}

		if (has_unread_clients) {
			revents |= want_rx;
		}
	}

	return (revents);
}

static int
necpop_select(struct fileproc *fp, int which, void *wql, vfs_context_t ctx)
{
#pragma unused(fp, which, wql, ctx)
	return (0);
	struct necp_fd_data *fd_data = NULL;
	int revents = 0;
	int events = 0;
	proc_t procp;

	fd_data = (struct necp_fd_data *)fp->f_fglob->fg_data;
	if (fd_data == NULL) {
		return (0);
	}

	procp = vfs_context_proc(ctx);

	switch (which) {
		case FREAD: {
			events = POLLIN;
			break;
		}

		default: {
			return (1);
		}
	}

	lck_mtx_lock(&fd_data->fd_lock);
	revents = necp_fd_poll(fd_data, events, wql, procp, 0);
	lck_mtx_unlock(&fd_data->fd_lock);

	return ((events & revents) ? 1 : 0);
}

static void
necp_fd_knrdetach(struct knote *kn)
{
	struct necp_fd_data *fd_data = (struct necp_fd_data *)kn->kn_hook;
	struct selinfo *si = &fd_data->si;

	lck_mtx_lock(&fd_data->fd_lock);
	KNOTE_DETACH(&si->si_note, kn);
	lck_mtx_unlock(&fd_data->fd_lock);
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

	lck_mtx_lock(&fd_data->fd_lock);
	revents = necp_fd_poll(fd_data, POLLIN, NULL, current_proc(), 1);
	res = ((revents & POLLIN) != 0);
	if (res) {
		*kev = kn->kn_kevent;
	}
	lck_mtx_unlock(&fd_data->fd_lock);
	return (res);
}

static int 
necp_fd_knrtouch(struct knote *kn, struct kevent_internal_s *kev)
{
#pragma unused(kev)
	struct necp_fd_data *fd_data;
	int revents;

	fd_data = (struct necp_fd_data *)kn->kn_hook;

	lck_mtx_lock(&fd_data->fd_lock);
	if ((kn->kn_status & KN_UDATA_SPECIFIC) == 0)
		kn->kn_udata = kev->udata;
	revents = necp_fd_poll(fd_data, POLLIN, NULL, current_proc(), 1);
	lck_mtx_unlock(&fd_data->fd_lock);

	return ((revents & POLLIN) != 0);
}

struct filterops necp_fd_rfiltops = {
	.f_isfd = 1,
	.f_detach = necp_fd_knrdetach,
	.f_event = necp_fd_knread,
	.f_touch = necp_fd_knrtouch,
	.f_process = necp_fd_knrprocess,
};

static int
necpop_kqfilter(struct fileproc *fp, struct knote *kn, vfs_context_t ctx)
{
#pragma unused(fp, ctx)
	struct necp_fd_data *fd_data = NULL;
	int revents;

	if (kn->kn_filter != EVFILT_READ) {
		NECPLOG(LOG_ERR, "bad filter request %d", kn->kn_filter);
		kn->kn_flags = EV_ERROR;
		kn->kn_data = EINVAL;
		return (0);
	}

	fd_data = (struct necp_fd_data *)kn->kn_fp->f_fglob->fg_data;
	if (fd_data == NULL) {
		NECPLOG0(LOG_ERR, "No channel for kqfilter");
		kn->kn_flags = EV_ERROR;
		kn->kn_data = ENOENT;
		return (0);
	}

	lck_mtx_lock(&fd_data->fd_lock);
	kn->kn_filtid = EVFILTID_NECP_FD;
	kn->kn_hook = fd_data;
	KNOTE_ATTACH(&fd_data->si.si_note, kn);

	revents = necp_fd_poll(fd_data, POLLIN, NULL, current_proc(), 1);

	lck_mtx_unlock(&fd_data->fd_lock);

	return ((revents & POLLIN) != 0);
}

static void
necp_destroy_client_stats(struct necp_client *client)
{
	if ((client->stats_area != NULL) &&
		(client->stats_handler_context != NULL) &&
		(client->stats_uaddr != 0)) {
		// Close old stats if required.
		int error = copyin(client->stats_uaddr, client->stats_area, client->stats_ulen);
		if (error) {
			NECPLOG(LOG_ERR, "necp_destroy_client_stats copyin error on close (%d)", error);
			// Not much we can for an error on an obsolete address
		}
		ntstat_userland_stats_close(client->stats_handler_context);
		FREE(client->stats_area, M_NECP);
		client->stats_area = NULL;
		client->stats_handler_context = NULL;
		client->stats_uaddr = 0;
		client->stats_ulen = 0;
	}
}

static void
necp_destroy_client(struct necp_client *client)
{
	// Remove from list
	LIST_REMOVE(client, chain);

	// Remove nexus assignment
	if (client->assigned_results != NULL) {
		if (!uuid_is_null(client->nexus_agent)) {
			int netagent_error = netagent_client_message(client->nexus_agent, client->client_id,
														 NETAGENT_MESSAGE_TYPE_CLOSE_NEXUS);
			if (netagent_error != 0) {
				NECPLOG(LOG_ERR, "necp_client_remove close nexus error (%d)", netagent_error);
			}
		}
		FREE(client->assigned_results, M_NETAGENT);
	}

	// Remove agent assertions
	struct necp_client_assertion *search_assertion = NULL;
	struct necp_client_assertion *temp_assertion = NULL;
	LIST_FOREACH_SAFE(search_assertion, &client->assertion_list, assertion_chain, temp_assertion) {
		int netagent_error = netagent_client_message(search_assertion->asserted_netagent, client->client_id, NETAGENT_MESSAGE_TYPE_CLIENT_UNASSERT);
		if (netagent_error != 0) {
			NECPLOG(LOG_ERR, "necp_client_remove unassert agent error (%d)", netagent_error);
		}
		LIST_REMOVE(search_assertion, assertion_chain);
		FREE(search_assertion, M_NECP);
	}
	necp_destroy_client_stats(client);

	FREE(client, M_NECP);
}

static int
necpop_close(struct fileglob *fg, vfs_context_t ctx)
{
#pragma unused(fg, ctx)
	struct necp_fd_data *fd_data = NULL;
	int error = 0;

	fd_data = (struct necp_fd_data *)fg->fg_data;
	fg->fg_data = NULL;

	if (fd_data != NULL) {
		lck_rw_lock_exclusive(&necp_fd_lock);

		lck_mtx_lock(&fd_data->fd_lock);
		struct necp_client *client = NULL;
		struct necp_client *temp_client = NULL;
		LIST_FOREACH_SAFE(client, &fd_data->clients, chain, temp_client) {
			necp_destroy_client(client);
		}
		lck_mtx_unlock(&fd_data->fd_lock);

		selthreadclear(&fd_data->si);

		lck_mtx_destroy(&fd_data->fd_lock, necp_fd_mtx_grp);

		LIST_REMOVE(fd_data, chain);

		lck_rw_done(&necp_fd_lock);

		FREE(fd_data, M_NECP);
		fd_data = NULL;
	}

	return (error);
}

/// NECP client utilities

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

done:
	proc_fdunlock(p);
	return (error);
}

static bool
necp_netagent_applies_to_client(__unused struct necp_client *client, struct necp_client_parsed_parameters *parameters, uuid_t netagent_uuid)
{
	bool applies = FALSE;
	u_int32_t flags = netagent_get_flags(netagent_uuid);
	if (!(flags & NETAGENT_FLAG_REGISTERED)) {
		// Unregistered agents never apply
		return (applies);
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
				if (uuid_compare(parameters->required_netagents[i], netagent_uuid) == 0) {
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
						if (netagent_get_agent_domain_and_type(netagent_uuid, netagent_domain, netagent_type)) {
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

	if (applies &&
		(flags & NETAGENT_FLAG_NEXUS_PROVIDER) &&
		uuid_is_null(client->nexus_agent)) {
		uuid_copy(client->nexus_agent, netagent_uuid);
	}

	return (applies);
}

static int
necp_client_parse_parameters(u_int8_t *parameters,
							 u_int32_t parameters_size,
							 struct necp_client_parsed_parameters *parsed_parameters)
{
	int error = 0;
	size_t offset = 0;

	u_int32_t num_prohibited_interfaces = 0;
	u_int32_t num_required_interface_types = 0;
	u_int32_t num_prohibited_interface_types = 0;
	u_int32_t num_required_agents = 0;
	u_int32_t num_prohibited_agents = 0;
	u_int32_t num_preferred_agents = 0;
	u_int32_t num_required_agent_types = 0;
	u_int32_t num_prohibited_agent_types = 0;
	u_int32_t num_preferred_agent_types = 0;

	if (parsed_parameters == NULL) {
		return (EINVAL);
	}

	memset(parsed_parameters, 0, sizeof(struct necp_client_parsed_parameters));

	while ((offset + sizeof(u_int8_t) + sizeof(u_int32_t)) <= parameters_size) {
		u_int8_t type = necp_buffer_get_tlv_type(parameters, offset);
		u_int32_t length = necp_buffer_get_tlv_length(parameters, offset);

		if (length > 0 && (offset + sizeof(u_int8_t) + sizeof(u_int32_t) + length) <= parameters_size) {
			u_int8_t *value = necp_buffer_get_tlv_value(parameters, offset, NULL);
			if (value != NULL) {
				switch (type) {
					case NECP_CLIENT_PARAMETER_BOUND_INTERFACE: {
						if (length <= IFXNAMSIZ && length > 0) {
							ifnet_t bound_interface = NULL;
							char interface_name[IFXNAMSIZ];
							memcpy(interface_name, value, length);
							interface_name[length - 1] = 0; // Make sure the string is NULL terminated
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
							if ((address_struct->address.sa.sa_family == AF_INET ||
								 address_struct->address.sa.sa_family == AF_INET6) &&
								address_struct->address.sa.sa_len <= length) {
								memcpy(&parsed_parameters->local_addr, &address_struct->address, sizeof(address_struct->address));
								parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_LOCAL_ADDR;
							}
						}
						break;
					}
					case NECP_CLIENT_PARAMETER_LOCAL_ENDPOINT: {
						if (length >= sizeof(struct necp_client_endpoint)) {
							struct necp_client_endpoint *endpoint = (struct necp_client_endpoint *)(void *)value;
							if ((endpoint->u.endpoint.endpoint_family == AF_INET ||
								 endpoint->u.endpoint.endpoint_family == AF_INET6) &&
								endpoint->u.endpoint.endpoint_length <= length) {
								memcpy(&parsed_parameters->local_addr, &endpoint->u.sa, sizeof(union necp_sockaddr_union));
								parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_LOCAL_ADDR;
							}
						}
						break;
					}
					case NECP_CLIENT_PARAMETER_REMOTE_ADDRESS: {
						if (length >= sizeof(struct necp_policy_condition_addr)) {
							struct necp_policy_condition_addr *address_struct = (struct necp_policy_condition_addr *)(void *)value;
							if ((address_struct->address.sa.sa_family == AF_INET ||
								 address_struct->address.sa.sa_family == AF_INET6) &&
								address_struct->address.sa.sa_len <= length) {
								memcpy(&parsed_parameters->remote_addr, &address_struct->address, sizeof(address_struct->address));
								parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_REMOTE_ADDR;
							}
						}
						break;
					}
					case NECP_CLIENT_PARAMETER_REMOTE_ENDPOINT: {
						if (length >= sizeof(struct necp_client_endpoint)) {
							struct necp_client_endpoint *endpoint = (struct necp_client_endpoint *)(void *)value;
							if ((endpoint->u.endpoint.endpoint_family == AF_INET ||
								 endpoint->u.endpoint.endpoint_family == AF_INET6) &&
								endpoint->u.endpoint.endpoint_length <= length) {
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
							parsed_parameters->prohibited_interfaces[num_prohibited_interfaces][length - 1] = 0; // Make sure the string is NULL terminated
							num_prohibited_interfaces++;
							parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_IF;
						}
						break;
					}
					case NECP_CLIENT_PARAMETER_REQUIRE_IF_TYPE: {
						if (num_required_interface_types >= NECP_MAX_PARSED_PARAMETERS) {
							break;
						}
						if (length >= sizeof(u_int8_t)) {
							memcpy(&parsed_parameters->required_interface_types[num_required_interface_types], value, sizeof(u_int8_t));
							num_required_interface_types++;
							parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IFTYPE;
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
					default: {
						break;
					}
				}
			}
		}

		offset += sizeof(u_int8_t) + sizeof(u_int32_t) + length;
	}

	return (error);
}

int
necp_assign_client_result(uuid_t netagent_uuid, uuid_t client_id,
						  u_int8_t *assigned_results, size_t assigned_results_length)
{
	int error = 0;
	struct necp_fd_data *client_fd = NULL;
	bool found_client = FALSE;
	bool client_updated = FALSE;

	lck_rw_lock_shared(&necp_fd_lock);

	LIST_FOREACH(client_fd, &necp_fd_list, chain) {
		struct necp_client *client = NULL;
		lck_mtx_lock(&client_fd->fd_lock);
		LIST_FOREACH(client, &client_fd->clients, chain) {
			if (uuid_compare(client->client_id, client_id) == 0) {
				// Found the right client!
				found_client = TRUE;

				if (uuid_compare(client->nexus_agent, netagent_uuid) == 0) {
					// Verify that the client nexus agent matches
					if (client->assigned_results != NULL) {
						// Release prior result
						FREE(client->assigned_results, M_NETAGENT);
					}
					client->assigned_results = assigned_results;
					client->assigned_results_length = assigned_results_length;
					client->assigned_result_read = FALSE;
					client_updated = TRUE;
				}
			}
		}
		if (client_updated) {
			necp_fd_notify(client_fd, true);
		}
		lck_mtx_unlock(&client_fd->fd_lock);

		if (found_client) {
			break;
		}
	}

	lck_rw_done(&necp_fd_lock);

	if (!found_client) {
		error = ENOENT;
	} else if (!client_updated) {
		error = EINVAL;
	}

	return (error);
}

/// Client updating

static bool
necp_update_client_result(proc_t proc,
						  struct necp_client *client)
{
	struct necp_client_result_netagent netagent;
	struct necp_aggregate_result result;
	struct necp_client_parsed_parameters parsed_parameters;
	u_int32_t flags = 0;

	uuid_clear(client->nexus_agent);

	int error = necp_client_parse_parameters(client->parameters, (u_int32_t)client->parameters_length, &parsed_parameters);
	if (error != 0) {
		return (FALSE);
	}

	// Check parameters to find best interface
	u_int matching_if_index = 0;
	if (necp_find_matching_interface_index(&parsed_parameters, &matching_if_index)) {
		if (matching_if_index != 0) {
			parsed_parameters.required_interface_index = matching_if_index;
		}
		// Interface found or not needed, match policy.
		error = necp_application_find_policy_match_internal(proc, client->parameters, (u_int32_t)client->parameters_length, &result, &flags, matching_if_index);
		if (error != 0) {
			return (FALSE);
		}
	} else {
		// Interface not found. Clear out the whole result, make everything fail.
		memset(&result, 0, sizeof(result));
	}

	// If the original request was scoped, and the policy result matches, make sure the result is scoped
	if ((result.routing_result == NECP_KERNEL_POLICY_RESULT_NONE ||
		 result.routing_result == NECP_KERNEL_POLICY_RESULT_PASS) &&
		result.routed_interface_index != IFSCOPE_NONE &&
		parsed_parameters.required_interface_index == result.routed_interface_index) {
		result.routing_result = NECP_KERNEL_POLICY_RESULT_SOCKET_SCOPED;
		result.routing_result_parameter.scoped_interface_index = result.routed_interface_index;
	}

	bool updated = FALSE;
	u_int8_t *cursor = client->result;
	const u_int8_t *max = client->result + NECP_MAX_CLIENT_RESULT_SIZE;
	cursor = necp_buffer_write_tlv_if_different(cursor, max, NECP_CLIENT_RESULT_CLIENT_ID, sizeof(uuid_t), client->client_id, &updated);
	cursor = necp_buffer_write_tlv_if_different(cursor, max, NECP_CLIENT_RESULT_POLICY_RESULT, sizeof(result.routing_result), &result.routing_result, &updated);
	if (result.routing_result_parameter.tunnel_interface_index != 0) {
		cursor = necp_buffer_write_tlv_if_different(cursor, max, NECP_CLIENT_RESULT_POLICY_RESULT_PARAMETER,
													sizeof(result.routing_result_parameter), &result.routing_result_parameter, &updated);
	}
	if (result.filter_control_unit != 0) {
		cursor = necp_buffer_write_tlv_if_different(cursor, max, NECP_CLIENT_RESULT_FILTER_CONTROL_UNIT,
													sizeof(result.filter_control_unit), &result.filter_control_unit, &updated);
	}
	if (result.routed_interface_index != 0) {
		u_int routed_interface_index = result.routed_interface_index;
		if (result.routing_result == NECP_KERNEL_POLICY_RESULT_IP_TUNNEL &&
			parsed_parameters.required_interface_index != IFSCOPE_NONE &&
			parsed_parameters.required_interface_index != result.routed_interface_index) {
			routed_interface_index = parsed_parameters.required_interface_index;
		}

		cursor = necp_buffer_write_tlv_if_different(cursor, max, NECP_CLIENT_RESULT_INTERFACE_INDEX,
													sizeof(routed_interface_index), &routed_interface_index, &updated);
	}
	if (flags != 0) {
		cursor = necp_buffer_write_tlv_if_different(cursor, max, NECP_CLIENT_RESULT_FLAGS,
													sizeof(flags), &flags, &updated);
	}
	for (int i = 0; i < NECP_MAX_NETAGENTS; i++) {
		if (uuid_is_null(result.netagents[i])) {
			break;
		}
		uuid_copy(netagent.netagent_uuid, result.netagents[i]);
		netagent.generation = netagent_get_generation(netagent.netagent_uuid);
		if (necp_netagent_applies_to_client(client, &parsed_parameters, netagent.netagent_uuid)) {
			cursor = necp_buffer_write_tlv_if_different(cursor, max, NECP_CLIENT_RESULT_NETAGENT, sizeof(netagent), &netagent, &updated);
		}
	}

	ifnet_head_lock_shared();
	ifnet_t direct_interface = NULL;
	ifnet_t delegate_interface = NULL;
	ifnet_t original_scoped_interface = NULL;

	if (result.routed_interface_index != IFSCOPE_NONE && (int)result.routed_interface_index <= if_index) {
		direct_interface = ifindex2ifnet[result.routed_interface_index];
	} else if (parsed_parameters.required_interface_index != IFSCOPE_NONE &&
			   (int)parsed_parameters.required_interface_index <= if_index) {
		// If the request was scoped, but the route didn't match, still grab the agents
		direct_interface = ifindex2ifnet[parsed_parameters.required_interface_index];
	} else if (result.routed_interface_index == IFSCOPE_NONE &&
			   result.routing_result == NECP_KERNEL_POLICY_RESULT_SOCKET_SCOPED &&
			   result.routing_result_parameter.scoped_interface_index != IFSCOPE_NONE) {
		direct_interface = ifindex2ifnet[result.routing_result_parameter.scoped_interface_index];
	}
	if (direct_interface != NULL) {
		delegate_interface = direct_interface->if_delegated.ifp;
	}
	if (result.routing_result == NECP_KERNEL_POLICY_RESULT_IP_TUNNEL &&
		parsed_parameters.required_interface_index != IFSCOPE_NONE &&
		parsed_parameters.required_interface_index != result.routing_result_parameter.tunnel_interface_index &&
		(int)parsed_parameters.required_interface_index <= if_index) {
		original_scoped_interface = ifindex2ifnet[parsed_parameters.required_interface_index];
	}
	// Add interfaces
	if (original_scoped_interface != NULL) {
		struct necp_client_result_interface interface_struct;
		interface_struct.index = original_scoped_interface->if_index;
		interface_struct.generation = ifnet_get_generation(original_scoped_interface);
		cursor = necp_buffer_write_tlv_if_different(cursor, max, NECP_CLIENT_RESULT_INTERFACE, sizeof(interface_struct), &interface_struct, &updated);
	}
	if (direct_interface != NULL) {
		struct necp_client_result_interface interface_struct;
		interface_struct.index = direct_interface->if_index;
		interface_struct.generation = ifnet_get_generation(direct_interface);
		cursor = necp_buffer_write_tlv_if_different(cursor, max, NECP_CLIENT_RESULT_INTERFACE, sizeof(interface_struct), &interface_struct, &updated);
	}
	if (delegate_interface != NULL) {
		struct necp_client_result_interface interface_struct;
		interface_struct.index = delegate_interface->if_index;
		interface_struct.generation = ifnet_get_generation(delegate_interface);
		cursor = necp_buffer_write_tlv_if_different(cursor, max, NECP_CLIENT_RESULT_INTERFACE, sizeof(interface_struct), &interface_struct, &updated);
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
				if (necp_netagent_applies_to_client(client, &parsed_parameters, netagent.netagent_uuid)) {
					cursor = necp_buffer_write_tlv_if_different(cursor, max, NECP_CLIENT_RESULT_NETAGENT, sizeof(netagent), &netagent, &updated);
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
				if (necp_netagent_applies_to_client(client, &parsed_parameters, netagent.netagent_uuid)) {
					cursor = necp_buffer_write_tlv_if_different(cursor, max, NECP_CLIENT_RESULT_NETAGENT, sizeof(netagent), &netagent, &updated);
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
				if (necp_netagent_applies_to_client(client, &parsed_parameters, netagent.netagent_uuid)) {
					cursor = necp_buffer_write_tlv_if_different(cursor, max, NECP_CLIENT_RESULT_NETAGENT, sizeof(netagent), &netagent, &updated);
				}
			}
		}
		ifnet_lock_done(delegate_interface);
	}
	ifnet_head_done();

	size_t new_result_length = (cursor - client->result);
	if (new_result_length != client->result_length) {
		client->result_length = new_result_length;
		updated = TRUE;
	}
	if (updated) {
		client->result_read = FALSE;
	}

	return (updated);
}

static void
necp_update_all_clients_callout(__unused thread_call_param_t dummy,
								__unused thread_call_param_t arg)
{
#pragma unused(arg)
	struct necp_fd_data *client_fd = NULL;

	lck_rw_lock_shared(&necp_fd_lock);

	LIST_FOREACH(client_fd, &necp_fd_list, chain) {
		bool updated_result = FALSE;
		struct necp_client *client = NULL;
		proc_t proc = proc_find(client_fd->proc_pid);
		if (proc == NULL) {
			continue;
		}

		lck_mtx_lock(&client_fd->fd_lock);
		LIST_FOREACH(client, &client_fd->clients, chain) {
			if (necp_update_client_result(proc, client)) {
				updated_result = TRUE;
			}
		}
		if (updated_result) {
			necp_fd_notify(client_fd, true);
		}
		lck_mtx_unlock(&client_fd->fd_lock);

		proc_rele(proc);
	}

	lck_rw_done(&necp_fd_lock);
}

void
necp_update_all_clients(void)
{
	if (necp_client_tcall == NULL) {
		// Don't try to update clients if the module is not initialized
		return;
	}

	uint64_t deadline = 0;
	uint64_t leeway = 0;
	clock_interval_to_deadline(necp_timeout_microseconds, NSEC_PER_USEC, &deadline);
	clock_interval_to_absolutetime_interval(necp_timeout_leeway_microseconds, NSEC_PER_USEC, &leeway);

	thread_call_enter_delayed_with_leeway(necp_client_tcall, NULL,
										  deadline, leeway, THREAD_CALL_DELAY_LEEWAY);
}

static void
necp_client_remove_agent_from_result(struct necp_client *client, uuid_t netagent_uuid)
{
	size_t offset = 0;

	u_int8_t *result_buffer = client->result;
	while ((offset + sizeof(u_int8_t) + sizeof(u_int32_t)) <= client->result_length) {
		u_int8_t type = necp_buffer_get_tlv_type(result_buffer, offset);
		u_int32_t length = necp_buffer_get_tlv_length(result_buffer, offset);

		size_t tlv_total_length = (sizeof(u_int8_t) + sizeof(u_int32_t) + length);
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
				memset(result_buffer + client->result_length, 0, NECP_MAX_CLIENT_RESULT_SIZE - client->result_length);
				continue;
			}
		}

		offset += tlv_total_length;
	}
}

void
necp_force_update_client(uuid_t client_id, uuid_t remove_netagent_uuid)
{
	struct necp_fd_data *client_fd = NULL;

	lck_rw_lock_shared(&necp_fd_lock);

	LIST_FOREACH(client_fd, &necp_fd_list, chain) {
		bool updated_result = FALSE;
		struct necp_client *client = NULL;
		lck_mtx_lock(&client_fd->fd_lock);
		LIST_FOREACH(client, &client_fd->clients, chain) {
			if (uuid_compare(client->client_id, client_id) == 0) {
				if (!uuid_is_null(remove_netagent_uuid)) {
					necp_client_remove_agent_from_result(client, remove_netagent_uuid);
				}
				client->assigned_result_read = FALSE;
				updated_result = TRUE;
				// Found the client, break
				break;
			}
		}
		if (updated_result) {
			necp_fd_notify(client_fd, true);
		}
		lck_mtx_unlock(&client_fd->fd_lock);
		if (updated_result) {
			// Found the client, break
			break;
		}
	}

	lck_rw_done(&necp_fd_lock);
}

/// Interface matching

#define NECP_PARSED_PARAMETERS_INTERESTING_IFNET_FIELDS (NECP_PARSED_PARAMETERS_FIELD_LOCAL_ADDR |				\
														 NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_IF |			\
														 NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IFTYPE |			\
														 NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_IFTYPE |		\
														 NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT |			\
														 NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_AGENT |		\
														 NECP_PARSED_PARAMETERS_FIELD_PREFERRED_AGENT |			\
														 NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT_TYPE |		\
														 NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_AGENT_TYPE |	\
														 NECP_PARSED_PARAMETERS_FIELD_PREFERRED_AGENT_TYPE)

#define NECP_PARSED_PARAMETERS_SCOPED_IFNET_FIELDS (NECP_PARSED_PARAMETERS_FIELD_LOCAL_ADDR |			\
													NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IFTYPE |		\
													NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT |		\
													NECP_PARSED_PARAMETERS_FIELD_PREFERRED_AGENT |		\
													NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT_TYPE |	\
													NECP_PARSED_PARAMETERS_FIELD_PREFERRED_AGENT_TYPE)

#define NECP_PARSED_PARAMETERS_PREFERRED_IFNET_FIELDS (NECP_PARSED_PARAMETERS_FIELD_PREFERRED_AGENT | \
													   NECP_PARSED_PARAMETERS_FIELD_PREFERRED_AGENT_TYPE)

static bool
necp_ifnet_matches_type(struct ifnet *ifp, u_int8_t interface_type, bool check_delegates)
{
	struct ifnet *check_ifp = ifp;
	while (check_ifp) {
		if (if_functional_type(check_ifp, TRUE) == interface_type) {
			return (TRUE);
		}
		if (!check_delegates) {
			break;
		}
		check_ifp = check_ifp->if_delegated.ifp;

	}
	return (FALSE);
}

static bool
necp_ifnet_matches_name(struct ifnet *ifp, const char *interface_name, bool check_delegates)
{
	struct ifnet *check_ifp = ifp;
	while (check_ifp) {
		if (strncmp(check_ifp->if_xname, interface_name, IFXNAMSIZ) == 0) {
			return (TRUE);
		}
		if (!check_delegates) {
			break;
		}
		check_ifp = check_ifp->if_delegated.ifp;
	}
	return (FALSE);
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
					return (TRUE);
				}
			}
		}
		ifnet_lock_done(check_ifp);

		if (!check_delegates) {
			break;
		}
		check_ifp = check_ifp->if_delegated.ifp;
	}
	return (FALSE);
}

static bool
necp_necp_ifnet_matches_agent_type(struct ifnet *ifp, const char *agent_domain, const char *agent_type, bool check_delegates)
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
					if ((strlen(agent_domain) == 0 ||
						 strncmp(if_agent_domain, agent_domain, NETAGENT_DOMAINSIZE) == 0) &&
						(strlen(agent_type) == 0 ||
						 strncmp(if_agent_type, agent_type, NETAGENT_TYPESIZE) == 0)) {
							ifnet_lock_done(check_ifp);
							return (TRUE);
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
	return (FALSE);
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

	return (matched_local_address);
}

static bool
necp_ifnet_matches_parameters(struct ifnet *ifp,
							  struct necp_client_parsed_parameters *parsed_parameters,
							  u_int32_t *preferred_count)
{
	if (preferred_count) {
		*preferred_count = 0;
	}

	if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_LOCAL_ADDR) {
		if (!necp_ifnet_matches_local_address(ifp, &parsed_parameters->local_addr.sa)) {
			return (FALSE);
		}
	}

	if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IFTYPE) {
		for (int i = 0; i < NECP_MAX_PARSED_PARAMETERS; i++) {
			if (parsed_parameters->required_interface_types[i] == 0) {
				break;
			}

			if (!necp_ifnet_matches_type(ifp, parsed_parameters->required_interface_types[i], FALSE)) {
				return (FALSE);
			}
		}
	}

	if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_IFTYPE) {
		for (int i = 0; i < NECP_MAX_PARSED_PARAMETERS; i++) {
			if (parsed_parameters->prohibited_interface_types[i] == 0) {
				break;
			}

			if (necp_ifnet_matches_type(ifp, parsed_parameters->prohibited_interface_types[i], TRUE)) {
				return (FALSE);
			}
		}
	}

	if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_IF) {
		for (int i = 0; i < NECP_MAX_PARSED_PARAMETERS; i++) {
			if (strlen(parsed_parameters->prohibited_interfaces[i]) == 0) {
				break;
			}

			if (necp_ifnet_matches_name(ifp, parsed_parameters->prohibited_interfaces[i], TRUE)) {
				return (FALSE);
			}
		}
	}

	if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT) {
		for (int i = 0; i < NECP_MAX_PARSED_PARAMETERS; i++) {
			if (uuid_is_null(parsed_parameters->required_netagents[i])) {
				break;
			}

			if (!necp_ifnet_matches_agent(ifp, &parsed_parameters->required_netagents[i], FALSE)) {
				return (FALSE);
			}
		}
	}

	if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_AGENT) {
		for (int i = 0; i < NECP_MAX_PARSED_PARAMETERS; i++) {
			if (uuid_is_null(parsed_parameters->prohibited_netagents[i])) {
				break;
			}

			if (necp_ifnet_matches_agent(ifp, &parsed_parameters->prohibited_netagents[i], TRUE)) {
				return (FALSE);
			}
		}
	}

	if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT_TYPE) {
		for (int i = 0; i < NECP_MAX_PARSED_PARAMETERS; i++) {
			if (strlen(parsed_parameters->required_netagent_types[i].netagent_domain) == 0 &&
				strlen(parsed_parameters->required_netagent_types[i].netagent_type) == 0) {
				break;
			}

			if (!necp_necp_ifnet_matches_agent_type(ifp, parsed_parameters->required_netagent_types[i].netagent_domain, parsed_parameters->required_netagent_types[i].netagent_type, FALSE)) {
				return (FALSE);
			}
		}
	}

	if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_AGENT_TYPE) {
		for (int i = 0; i < NECP_MAX_PARSED_PARAMETERS; i++) {
			if (strlen(parsed_parameters->prohibited_netagent_types[i].netagent_domain) == 0 &&
				strlen(parsed_parameters->prohibited_netagent_types[i].netagent_type) == 0) {
				break;
			}

			if (necp_necp_ifnet_matches_agent_type(ifp, parsed_parameters->prohibited_netagent_types[i].netagent_domain, parsed_parameters->prohibited_netagent_types[i].netagent_type, TRUE)) {
				return (FALSE);
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

				if (necp_necp_ifnet_matches_agent_type(ifp, parsed_parameters->preferred_netagent_types[i].netagent_domain, parsed_parameters->preferred_netagent_types[i].netagent_type, TRUE)) {
					(*preferred_count)++;
				}
			}
		}
	}

	return (TRUE);
}

static bool
necp_find_matching_interface_index(struct necp_client_parsed_parameters *parsed_parameters, u_int *return_ifindex)
{
	struct ifnet *ifp = NULL;
	u_int32_t best_preferred_count = 0;
	bool has_preferred_fields = FALSE;
	*return_ifindex = 0;

	if (parsed_parameters->required_interface_index != 0) {
		*return_ifindex = parsed_parameters->required_interface_index;
		return (TRUE);
	}

	if (!(parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_INTERESTING_IFNET_FIELDS)) {
		return (TRUE);
	}

	has_preferred_fields = (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_PREFERRED_IFNET_FIELDS);

	// We have interesting parameters to parse and find a matching interface
	ifnet_head_lock_shared();

	if (!(parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_SCOPED_IFNET_FIELDS)) {
		// We do have fields to match, but they are only prohibitory
		// If the first interface in the list matches, we don't need to scope
		ifp = TAILQ_FIRST(&ifnet_ordered_head);
		if (ifp && necp_ifnet_matches_parameters(ifp, parsed_parameters, NULL)) {
			// Don't set return_ifindex, so the client doesn't need to scope
			ifnet_head_done();
			return (TRUE);
		}
	}

	// First check the ordered interface list
	TAILQ_FOREACH(ifp, &ifnet_ordered_head, if_ordered_link) {
		u_int32_t preferred_count = 0;
		if (necp_ifnet_matches_parameters(ifp, parsed_parameters, &preferred_count)) {
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
	if ((parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_SCOPED_IFNET_FIELDS) &&
	    !(parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IFTYPE) &&
		*return_ifindex == 0) {
		TAILQ_FOREACH(ifp, &ifnet_head, if_link) {
			u_int32_t preferred_count = 0;
			if (ifp->if_ordered_link.tqe_next != NULL ||
				ifp->if_ordered_link.tqe_prev != NULL) {
				// This interface was in the ordered list, skip
				continue;
			}
			if (necp_ifnet_matches_parameters(ifp, parsed_parameters, &preferred_count)) {
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

	if ((parsed_parameters->valid_fields == (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_PREFERRED_IFNET_FIELDS)) &&
		best_preferred_count == 0) {
		// If only has preferred fields, and nothing was found, clear the interface index and return TRUE
		*return_ifindex = 0;
		return (TRUE);
	}

	return (*return_ifindex != 0);
}

static void
necp_find_netstat_data(struct necp_client *client, union necp_sockaddr_union *local, union necp_sockaddr_union *remote, u_int32_t *ifindex, uuid_t euuid, u_int32_t *traffic_class)
{
	size_t offset = 0;
	u_int8_t *parameters;
	u_int32_t parameters_size;

	parameters = client->parameters;
	parameters_size = (u_int32_t)client->parameters_length;

	while ((offset + sizeof(u_int8_t) + sizeof(u_int32_t)) <= parameters_size) {
		u_int8_t type = necp_buffer_get_tlv_type(parameters, offset);
		u_int32_t length = necp_buffer_get_tlv_length(parameters, offset);

		if (length > 0 && (offset + sizeof(u_int8_t) + sizeof(u_int32_t) + length) <= parameters_size) {
			u_int8_t *value = necp_buffer_get_tlv_value(parameters, offset, NULL);
			if (value != NULL) {
				switch (type) {
					case NECP_CLIENT_PARAMETER_REAL_APPLICATION: {
						if (length >= sizeof(uuid_t)) {
							uuid_copy(euuid, value);
						}
						break;
					}
					case NECP_CLIENT_PARAMETER_TRAFFIC_CLASS: {
						if (length >= sizeof(u_int32_t)) {
							memcpy(traffic_class, value, sizeof(u_int32_t));
						}
						break;
					}
					case NECP_CLIENT_PARAMETER_BOUND_INTERFACE: {
						if (length <= IFXNAMSIZ && length > 0) {
							ifnet_t bound_interface = NULL;
							char interface_name[IFXNAMSIZ];
							memcpy(interface_name, value, length);
							interface_name[length - 1] = 0; // Make sure the string is NULL terminated
							if (ifnet_find_by_name(interface_name, &bound_interface) == 0) {
								*ifindex = bound_interface->if_index;
								ifnet_release(bound_interface);
							}
						}
						break;
					}
					case NECP_CLIENT_PARAMETER_LOCAL_ADDRESS: {
						if (length >= sizeof(struct necp_policy_condition_addr)) {
							struct necp_policy_condition_addr *address_struct = (struct necp_policy_condition_addr *)(void *)value;
							memcpy(local, &address_struct->address, sizeof(address_struct->address));
						}
						break;
					}
					case NECP_CLIENT_PARAMETER_REMOTE_ADDRESS: {
						if (length >= sizeof(struct necp_policy_condition_addr)) {
							struct necp_policy_condition_addr *address_struct = (struct necp_policy_condition_addr *)(void *)value;
							memcpy(remote, &address_struct->address, sizeof(address_struct->address));
						}
						break;
					}
					default: {
						break;
					}
				}
			}
		}
		offset += sizeof(u_int8_t) + sizeof(u_int32_t) + length;
	}
}

static void
necp_fillout_current_process_details(u_int32_t *pid, u_int64_t *upid, unsigned char *uuid, char *pname, size_t len)
{
	*pid = proc_selfpid();
	*upid = proc_uniqueid(current_proc());
	proc_selfname(pname, (int) len);
	proc_getexecutableuuid(current_proc(), uuid, sizeof(uuid_t));
}

// Called from NetworkStatistics when it wishes to collect latest information for a TCP flow.
// It is a responsibility of NetworkStatistics to have previously zeroed any supplied memory.
static bool
necp_request_tcp_netstats(userland_stats_provider_context *ctx,
						  nstat_counts *countsp,
						  void *metadatap)
{
	if (ctx == NULL) {
		return false;
	}

	struct necp_client *client = (struct necp_client *)ctx;
	struct necp_tcp_stats *tcpstats = (struct necp_tcp_stats *)client->stats_area;
	if (tcpstats == NULL) {
		return false;
	}

	if (countsp) {
		*countsp = *((struct nstat_counts *)&tcpstats->necp_tcp_counts);
	}

	if (metadatap) {
		nstat_tcp_descriptor *desc = (nstat_tcp_descriptor *)metadatap;

		// Metadata for the process
		necp_fillout_current_process_details(&desc->pid, &desc->upid, desc->uuid, desc->pname, sizeof(desc->pname));

		// Metadata that the necp client should have in TLV format.
		necp_find_netstat_data(client, (union necp_sockaddr_union *)&desc->local, (union necp_sockaddr_union  *)&desc->remote, &desc->ifindex, desc->euuid, &desc->traffic_class);

		// Basic metadata
		desc->rcvbufsize = tcpstats->necp_tcp_basic.rcvbufsize;
		desc->rcvbufused = tcpstats->necp_tcp_basic.rcvbufused;
		desc->eupid = tcpstats->necp_tcp_basic.eupid;
		desc->epid = tcpstats->necp_tcp_basic.epid;
		memcpy(desc->vuuid, tcpstats->necp_tcp_basic.vuuid, sizeof(desc->vuuid));
		desc->ifnet_properties = tcpstats->necp_tcp_basic.ifnet_properties;

		// Additional TCP specific data
		desc->sndbufsize = tcpstats->necp_tcp_extra.sndbufsize;
		desc->sndbufused = tcpstats->necp_tcp_extra.sndbufused;
		desc->txunacked = tcpstats->necp_tcp_extra.txunacked;
		desc->txwindow = tcpstats->necp_tcp_extra.txwindow;
		desc->txcwindow = tcpstats->necp_tcp_extra.txcwindow;
		desc->traffic_mgt_flags = tcpstats->necp_tcp_extra.traffic_mgt_flags;

		if (tcpstats->necp_tcp_extra.cc_alg_index < TCP_CC_ALGO_COUNT) {
			strlcpy(desc->cc_algo, tcp_cc_algo_list[tcpstats->necp_tcp_extra.cc_alg_index]->name, sizeof(desc->cc_algo));
		} else {
			strlcpy(desc->cc_algo, "unknown", sizeof(desc->cc_algo));
		}

		desc->connstatus.write_probe_failed	= tcpstats->necp_tcp_extra.probestatus.write_probe_failed;
		desc->connstatus.read_probe_failed	= tcpstats->necp_tcp_extra.probestatus.read_probe_failed;
		desc->connstatus.conn_probe_failed	= tcpstats->necp_tcp_extra.probestatus.conn_probe_failed;
	}
	return true;
}

// Called from NetworkStatistics when it wishes to collect latest information for a UDP flow.
static bool
necp_request_udp_netstats(userland_stats_provider_context *ctx,
						  nstat_counts *countsp,
						  void *metadatap)
{
	if (ctx == NULL) {
		return false;
	}

	struct necp_client *client = (struct necp_client *)ctx;
	struct necp_udp_stats *udpstats = (struct necp_udp_stats *)client->stats_area;
	if (udpstats == NULL) {
		return false;
	}

	if (countsp) {
		*countsp = *((struct nstat_counts *)&udpstats->necp_udp_counts);
	}

	if (metadatap) {
		nstat_udp_descriptor *desc = (nstat_udp_descriptor *)metadatap;

		// Metadata for the process
		necp_fillout_current_process_details(&desc->pid, &desc->upid, desc->uuid, desc->pname, sizeof(desc->pname));

		// Metadata that the necp client should have in TLV format.
		necp_find_netstat_data(client, (union necp_sockaddr_union *)&desc->local, (union necp_sockaddr_union  *)&desc->remote, &desc->ifindex, desc->euuid, &desc->traffic_class);

		// Basic metadata is all that is required for UDP
		desc->rcvbufsize = udpstats->necp_udp_basic.rcvbufsize;
		desc->rcvbufused = udpstats->necp_udp_basic.rcvbufused;
		desc->eupid = udpstats->necp_udp_basic.eupid;
		desc->epid = udpstats->necp_udp_basic.epid;
		memcpy(desc->vuuid, udpstats->necp_udp_basic.vuuid, sizeof(desc->euuid));
		desc->ifnet_properties = udpstats->necp_udp_basic.ifnet_properties;
	}
	return true;
}

static int
necp_skywalk_priv_check_cred(proc_t p, kauth_cred_t cred)
{
#pragma unused(p, cred)
	return (0);
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

	if (uap->flags & NECP_OPEN_FLAG_OBSERVER) {
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

	if ((fd_data = _MALLOC(sizeof(struct necp_fd_data), M_NECP,
						   M_WAITOK | M_ZERO)) == NULL) {
		error = ENOMEM;
		goto done;
	}

	fd_data->flags = uap->flags;
	LIST_INIT(&fd_data->clients);
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
	proc_fdunlock(p);

	*retval = fd;

	lck_rw_lock_exclusive(&necp_fd_lock);
	LIST_INSERT_HEAD(&necp_fd_list, fd_data, chain);
	lck_rw_done(&necp_fd_lock);

done:
	if (error != 0) {
		if (fp != NULL) {
			fp_free(p, fd, fp);
			fp = NULL;
		}
		if (fd_data != NULL) {
			FREE(fd_data, M_NECP);
			fd_data = NULL;
		}
	}

	return (error);
}

static int
necp_client_add(struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	struct necp_client *client = NULL;

	if (uap->client_id == 0 || uap->client_id_len != sizeof(uuid_t) ||
		uap->buffer_size == 0 || uap->buffer_size > NECP_MAX_CLIENT_PARAMETERS_SIZE || uap->buffer == 0) {
		error = EINVAL;
		goto done;
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

	client->parameters_length = uap->buffer_size;

	uuid_generate_random(client->client_id);
	LIST_INIT(&client->assertion_list);

	error = copyout(client->client_id, uap->client_id, sizeof(uuid_t));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_add client_id copyout error (%d)", error);
		goto done;
	}

	lck_mtx_lock(&fd_data->fd_lock);
	LIST_INSERT_HEAD(&fd_data->clients, client, chain);

	// Prime the client result
	(void)necp_update_client_result(current_proc(), client);
	lck_mtx_unlock(&fd_data->fd_lock);
done:
	if (error != 0) {
		if (client != NULL) {
			FREE(client, M_NECP);
			client = NULL;
		}
	}
	*retval = error;

	return (error);
}

static int
necp_client_remove(struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	struct necp_client *client = NULL;
	struct necp_client *temp_client = NULL;
	uuid_t client_id;

	if (uap->client_id == 0 || uap->client_id_len != sizeof(uuid_t)) {
		error = EINVAL;
		goto done;
	}

	error = copyin(uap->client_id, client_id, sizeof(uuid_t));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_remove copyin client_id error (%d)", error);
		goto done;
	}

	lck_mtx_lock(&fd_data->fd_lock);
	LIST_FOREACH_SAFE(client, &fd_data->clients, chain, temp_client) {
		if (uuid_compare(client->client_id, client_id) == 0) {
			necp_destroy_client(client);
		}
	}
	lck_mtx_unlock(&fd_data->fd_lock);
done:
	*retval = error;

	return (error);
}

static int
necp_client_copy_internal(struct necp_client *client, bool client_is_observed, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	// Copy results out
	if (uap->action == NECP_CLIENT_ACTION_COPY_PARAMETERS) {
		if (uap->buffer_size < client->parameters_length) {
			error = EINVAL;
			goto done;
		}
		error = copyout(client->parameters, uap->buffer, client->parameters_length);
		if (error) {
			NECPLOG(LOG_ERR, "necp_client_copy parameters copyout error (%d)", error);
			goto done;
		}
		*retval = client->parameters_length;
	} else if (uap->action == NECP_CLIENT_ACTION_COPY_RESULT) {
		if (uap->buffer_size < (client->result_length + client->assigned_results_length)) {
			error = EINVAL;
			goto done;
		}
		error = copyout(client->result, uap->buffer, client->result_length);
		if (error) {
			NECPLOG(LOG_ERR, "necp_client_copy result copyout error (%d)", error);
			goto done;
		}
		if (client->assigned_results_length && client->assigned_results) {
			error = copyout(client->assigned_results, uap->buffer + client->result_length, client->assigned_results_length);
			if (error) {
				NECPLOG(LOG_ERR, "necp_client_copy assigned results copyout error (%d)", error);
				goto done;
			}
			*retval = client->result_length + client->assigned_results_length;
		} else {
			*retval = client->result_length;
		}

		if (!client_is_observed) {
			client->result_read = TRUE;
			client->assigned_result_read = TRUE;
		}
	}

done:
	return (error);
}

static int
necp_client_copy(struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	struct necp_client *find_client = NULL;
	struct necp_client *client = NULL;
	uuid_t client_id;
	uuid_clear(client_id);

	*retval = 0;

	if (uap->buffer_size == 0 || uap->buffer == 0) {
		error = EINVAL;
		goto done;
	}

	if (uap->action != NECP_CLIENT_ACTION_COPY_PARAMETERS &&
		uap->action != NECP_CLIENT_ACTION_COPY_RESULT) {
		error = EINVAL;
		goto done;
	}

	if (uap->client_id) {
		if (uap->client_id_len != sizeof(uuid_t)) {
			NECPLOG(LOG_ERR, "Incorrect length (got %d, expected %d)", uap->client_id_len, sizeof(uuid_t));
			error = ERANGE;
			goto done;
		}

		error = copyin(uap->client_id, client_id, sizeof(uuid_t));
		if (error) {
			NECPLOG(LOG_ERR, "necp_client_copy client_id copyin error (%d)", error);
			goto done;
		}
	}

	lck_mtx_lock(&fd_data->fd_lock);
	LIST_FOREACH(find_client, &fd_data->clients, chain) {
		if (uap->action == NECP_CLIENT_ACTION_COPY_RESULT &&
			uuid_is_null(client_id)) {
			if (!find_client->result_read || !find_client->assigned_result_read) {
				client = find_client;
				break;
			}
		} else if (uuid_compare(find_client->client_id, client_id) == 0) {
			client = find_client;
			break;
		}
	}

	if (client != NULL) {
		error = necp_client_copy_internal(client, FALSE, uap, retval);
	}

	// Unlock our own client before moving on or returning
	lck_mtx_unlock(&fd_data->fd_lock);

	if (client == NULL) {
		if (fd_data->flags & NECP_OPEN_FLAG_OBSERVER) {
			// Observers are allowed to lookup clients on other fds

			// Lock list
			lck_rw_lock_shared(&necp_fd_lock);
			struct necp_fd_data *client_fd = NULL;
			LIST_FOREACH(client_fd, &necp_fd_list, chain) {
				// Lock client
				lck_mtx_lock(&client_fd->fd_lock);
				find_client = NULL;
				LIST_FOREACH(find_client, &client_fd->clients, chain) {
					if (uuid_compare(find_client->client_id, client_id) == 0) {
						client = find_client;
						break;
					}
				}

				if (client != NULL) {
					// Matched, copy out data
					error = necp_client_copy_internal(client, TRUE, uap, retval);
				}

				// Unlock client
				lck_mtx_unlock(&client_fd->fd_lock);

				if (client != NULL) {
					break;
				}
			}

			// Unlock list
			lck_rw_done(&necp_fd_lock);

			// No client found, fail
			if (client == NULL) {
				error = ENOENT;
				goto done;
			}
		} else {
			// No client found, and not allowed to search other fds, fail
			error = ENOENT;
			goto done;
		}
	}

done:
	return (error);
}

static int
necp_client_list(struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	struct necp_client *find_client = NULL;
	uuid_t *list = NULL;
	u_int32_t requested_client_count = 0;
	u_int32_t client_count = 0;

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

	if (uap->buffer_size != (sizeof(requested_client_count) + requested_client_count * sizeof(uuid_t))) {
		error = EINVAL;
		goto done;
	}

	if (requested_client_count > 0) {
		if ((list = _MALLOC(requested_client_count * sizeof(uuid_t), M_NECP, M_WAITOK | M_ZERO)) == NULL) {
			error = ENOMEM;
			goto done;
		}
	}

	// Lock list
	lck_rw_lock_shared(&necp_fd_lock);
	struct necp_fd_data *client_fd = NULL;
	LIST_FOREACH(client_fd, &necp_fd_list, chain) {
		// Lock client
		lck_mtx_lock(&client_fd->fd_lock);
		find_client = NULL;
		LIST_FOREACH(find_client, &client_fd->clients, chain) {
			if (!uuid_is_null(find_client->client_id)) {
				if (client_count < requested_client_count) {
					uuid_copy(list[client_count], find_client->client_id);
				}
				client_count++;
			}
		}
		lck_mtx_unlock(&client_fd->fd_lock);
	}

	// Unlock list
	lck_rw_done(&necp_fd_lock);

	error = copyout(&client_count, uap->buffer, sizeof(client_count));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_list buffer copyout error (%d)", error);
		goto done;
	}

	if (requested_client_count > 0 &&
		client_count > 0 &&
		list != NULL) {
		error = copyout(list, uap->buffer + sizeof(client_count), requested_client_count * sizeof(uuid_t));
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
	
	return (error);
}

static int
necp_client_request_nexus(struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	struct necp_client *client = NULL;
	uuid_t client_id;
	bool requested_nexus = FALSE;

	if (uap->client_id == 0 || uap->client_id_len != sizeof(uuid_t)) {
		error = EINVAL;
		goto done;
	}

	error = copyin(uap->client_id, client_id, sizeof(uuid_t));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_request_nexus copyin client_id error (%d)", error);
		goto done;
	}

	lck_mtx_lock(&fd_data->fd_lock);
	LIST_FOREACH(client, &fd_data->clients, chain) {
		if (uuid_compare(client->client_id, client_id) == 0) {
			// Request from nexus agent
			if (!uuid_is_null(client->nexus_agent)) {
				error = netagent_client_message(client->nexus_agent, client->client_id,
												NETAGENT_MESSAGE_TYPE_REQUEST_NEXUS);
				if (error == 0) {
					requested_nexus = TRUE;
				}
			}
			break;
		}
	}
	lck_mtx_unlock(&fd_data->fd_lock);

	if (!requested_nexus &&
		error == 0) {
		error = ENOENT;
	}
done:
	*retval = error;

	return (error);
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
	struct necp_client *matched_client = NULL;
	struct necp_client *client = NULL;
	uuid_t client_id;
	bool acted_on_agent = FALSE;
	u_int8_t *parameters = NULL;
	size_t parameters_size = uap->buffer_size;

	if (uap->client_id == 0 || uap->client_id_len != sizeof(uuid_t) ||
		uap->buffer_size == 0 || uap->buffer == 0) {
		error = EINVAL;
		goto done;
	}

	error = copyin(uap->client_id, client_id, sizeof(uuid_t));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_agent_action copyin client_id error (%d)", error);
		goto done;
	}

	if ((parameters = _MALLOC(uap->buffer_size, M_NECP, M_WAITOK | M_ZERO)) == NULL) {
		error = ENOMEM;
		goto done;
	}

	error = copyin(uap->buffer, parameters, uap->buffer_size);
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_agent_action parameters copyin error (%d)", error);
		goto done;
	}

	lck_mtx_lock(&fd_data->fd_lock);
	LIST_FOREACH(client, &fd_data->clients, chain) {
		if (uuid_compare(client->client_id, client_id) == 0) {
			matched_client = client;
			break;
		}
	}
	if (matched_client) {
		size_t offset = 0;
		while ((offset + sizeof(u_int8_t) + sizeof(u_int32_t)) <= parameters_size) {
			u_int8_t type = necp_buffer_get_tlv_type(parameters, offset);
			u_int32_t length = necp_buffer_get_tlv_length(parameters, offset);

			if (length > 0 && (offset + sizeof(u_int8_t) + sizeof(u_int32_t) + length) <= parameters_size) {
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

						error = netagent_client_message(agent_uuid, client_id,
														netagent_message_type);
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

			offset += sizeof(u_int8_t) + sizeof(u_int32_t) + length;
		}
	}
	lck_mtx_unlock(&fd_data->fd_lock);

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
	
	return (error);
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
		NECPLOG(LOG_ERR, "necp_client_copy_agent netagent_copyout error (%d)", error);
		goto done;
	}
done:
	*retval = error;
	
	return (error);
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
	if (interface_index != IFSCOPE_NONE && (int)interface_index <= if_index) {
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
		interface_details.mtu = interface->if_mtu;

		u_int8_t ipv4_signature_len = sizeof(interface_details.ipv4_signature);
		u_int16_t ipv4_signature_flags;
		ifnet_get_netsignature(interface, AF_INET, &ipv4_signature_len, &ipv4_signature_flags,
							   (u_int8_t *)&interface_details.ipv4_signature);

		u_int8_t ipv6_signature_len = sizeof(interface_details.ipv6_signature);
		u_int16_t ipv6_signature_flags;
		ifnet_get_netsignature(interface, AF_INET6, &ipv6_signature_len, &ipv6_signature_flags,
							   (u_int8_t *)&interface_details.ipv6_signature);
	}

	ifnet_head_done();

	error = copyout(&interface_details, uap->buffer, sizeof(interface_details));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_copy_interface copyout error (%d)", error);
		goto done;
	}
done:
	*retval = error;

	return (error);
}

static int
necp_client_stats_action(struct necp_client *client, user_addr_t buffer, user_size_t buffer_size)
{
	int error = 0;
	struct necp_stats_hdr *stats_hdr = NULL;

	if (client->stats_area) {
		// Close old stats if required.
		if ((client->stats_uaddr != buffer) || (client->stats_ulen != buffer_size)) {
			necp_destroy_client_stats(client);
		}
	}

	if ((buffer == 0) || (buffer_size == 0)) {
		goto done;
	}

	if (client->stats_area) {
		// An update
		error = copyin(client->stats_uaddr, client->stats_area, client->stats_ulen);
		if (error) {
			NECPLOG(LOG_ERR, "necp_client_stats_action copyin error on update (%d)", error);
		} else {
			// Future use - check 
			stats_hdr = (necp_stats_hdr *)client->stats_area;
			if (stats_hdr->necp_stats_event != 0) {
				ntstat_userland_stats_event(client->stats_handler_context, (userland_stats_event_t)stats_hdr->necp_stats_event);
			}
		}
		goto done;
	}

	// A create
	if ((buffer_size > sizeof(necp_all_stats)) || (buffer_size < sizeof(necp_stats_hdr))) {
		error = EINVAL;
		goto done;
	}

	if ((stats_hdr = _MALLOC(buffer_size, M_NECP, M_WAITOK | M_ZERO)) == NULL) {
		error = ENOMEM;
		goto done;
	}

	client->stats_handler_context = NULL;
	client->stats_uaddr = buffer;
	client->stats_ulen = buffer_size;
	client->stats_area = stats_hdr;
	error = copyin(client->stats_uaddr, client->stats_area, client->stats_ulen);
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_stats_action copyin error on create (%d)", error);
		goto done;
	}

	switch (stats_hdr->necp_stats_type) {
		case NECP_CLIENT_STATISTICS_TYPE_TCP: {
			if (stats_hdr->necp_stats_ver == NECP_CLIENT_STATISTICS_TYPE_TCP_VER_1) {
				client->stats_handler_context = ntstat_userland_stats_open((userland_stats_provider_context *)client,
																			NSTAT_PROVIDER_TCP_USERLAND, 0, necp_request_tcp_netstats);
				if (client->stats_handler_context == NULL) {
					error = EIO;
				}
			} else {
				error = ENOTSUP;
			}
			break;
		}
		case NECP_CLIENT_STATISTICS_TYPE_UDP: {
			if (stats_hdr->necp_stats_ver != NECP_CLIENT_STATISTICS_TYPE_UDP_VER_1) {
				client->stats_handler_context = ntstat_userland_stats_open((userland_stats_provider_context *)client,
																			NSTAT_PROVIDER_UDP_USERLAND, 0, necp_request_udp_netstats);
				if (client->stats_handler_context == NULL) {
					error = EIO;
				}
			} else {
				error = ENOTSUP;
			}
			break;
		}
		default: {
			error = ENOTSUP;
			break;
		}
	}
done:
	if ((error) && (stats_hdr != NULL)) {
		FREE(stats_hdr, M_NECP);
		client->stats_area = NULL;
		client->stats_handler_context = NULL;
		client->stats_uaddr = 0;
		client->stats_ulen = 0;
	}

	return (error);
}

static int
necp_client_set_statistics(__unused struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	struct necp_client *find_client = NULL;
	struct necp_client *client = NULL;
	uuid_t client_id;

	if (uap->client_id == 0 || uap->client_id_len != sizeof(uuid_t)) {
		error = EINVAL;
		goto done;
	}

	error = copyin(uap->client_id, client_id, sizeof(uuid_t));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_set_statistics copyin client_id error (%d)", error);
		goto done;
	}

	lck_mtx_lock(&fd_data->fd_lock);
	LIST_FOREACH(find_client, &fd_data->clients, chain) {
		if (uuid_compare(find_client->client_id, client_id) == 0) {
			client = find_client;
			break;
		}
	}

	if (client) {
		error = necp_client_stats_action(client, uap->buffer, uap->buffer_size);
	} else {
		error = ENOENT;
	}
	lck_mtx_unlock(&fd_data->fd_lock);
done:
	*retval = error;
	return (error);
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
		return (error);
	}

	u_int32_t action = uap->action;
	switch (action) {
		case NECP_CLIENT_ACTION_ADD: {
			return_value = necp_client_add(fd_data, uap, retval);
			break;
		}
		case NECP_CLIENT_ACTION_REMOVE: {
			return_value = necp_client_remove(fd_data, uap, retval);
			break;
		}
		case NECP_CLIENT_ACTION_COPY_PARAMETERS:
		case NECP_CLIENT_ACTION_COPY_RESULT: {
			return_value = necp_client_copy(fd_data, uap, retval);
			break;
		}
		case NECP_CLIENT_ACTION_COPY_LIST: {
			return_value = necp_client_list(fd_data, uap, retval);
			break;
		}
		case NECP_CLIENT_ACTION_REQUEST_NEXUS_INSTANCE: {
			return_value = necp_client_request_nexus(fd_data, uap, retval);
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
		case NECP_CLIENT_ACTION_COPY_INTERFACE: {
			return_value = necp_client_copy_interface(fd_data, uap, retval);
			break;
		}
		case NECP_CLIENT_ACTION_SET_STATISTICS: {
			return_value = necp_client_set_statistics(fd_data, uap, retval);
			break;
		}
		default: {
			NECPLOG(LOG_ERR, "necp_client_action unknown action (%u)", action);
			return_value = EINVAL;
			break;
		}
	}

	file_drop(uap->necp_fd);

	return (return_value);
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

	error = necp_application_find_policy_match_internal(p, parameters, uap->parameters_size, &returned_result, NULL, 0);
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
	return (error);
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
	return (0);
fail:
	if (local_string != NULL) {
		FREE(local_string, M_NECP);
	}
	return (error);
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
		valsize > ((sizeof(u_int8_t) + sizeof(u_int32_t) + NECP_MAX_SOCKET_ATTRIBUTE_STRING_LENGTH) * 2)) {
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

	return (error);
}

errno_t
necp_get_socket_attributes(struct socket *so, struct sockopt *sopt)
{
	int error = 0;
	u_int8_t *buffer = NULL;
	u_int8_t *cursor = NULL;
	size_t valsize = 0;
	struct inpcb *inp = sotoinpcb(so);

	if (inp->inp_necp_attributes.inp_domain != NULL) {
		valsize += sizeof(u_int8_t) + sizeof(u_int32_t) + strlen(inp->inp_necp_attributes.inp_domain);
	}
	if (inp->inp_necp_attributes.inp_account != NULL) {
		valsize += sizeof(u_int8_t) + sizeof(u_int32_t) + strlen(inp->inp_necp_attributes.inp_account);
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
		cursor = necp_buffer_write_tlv(cursor, NECP_TLV_ATTRIBUTE_DOMAIN, strlen(inp->inp_necp_attributes.inp_domain), inp->inp_necp_attributes.inp_domain);
	}

	if (inp->inp_necp_attributes.inp_account != NULL) {
		cursor = necp_buffer_write_tlv(cursor, NECP_TLV_ATTRIBUTE_ACCOUNT, strlen(inp->inp_necp_attributes.inp_account), inp->inp_necp_attributes.inp_account);
	}

	error = sooptcopyout(sopt, buffer, valsize);
	if (error) {
		goto done;
	}
done:
	if (buffer != NULL) {
		FREE(buffer, M_NECP);
	}
	
	return (error);
}

void
necp_inpcb_dispose(struct inpcb *inp)
{
	if (inp->inp_necp_attributes.inp_domain != NULL) {
		FREE(inp->inp_necp_attributes.inp_domain, M_NECP);
		inp->inp_necp_attributes.inp_domain = NULL;
	}
	if (inp->inp_necp_attributes.inp_account != NULL) {
		FREE(inp->inp_necp_attributes.inp_account, M_NECP);
		inp->inp_necp_attributes.inp_account = NULL;
	}
}

/// Module init

errno_t
necp_client_init(void)
{
	errno_t result = 0;

	necp_fd_grp_attr = lck_grp_attr_alloc_init();
	if (necp_fd_grp_attr == NULL) {
		NECPLOG0(LOG_ERR, "lck_grp_attr_alloc_init failed");
		result = ENOMEM;
		goto done;
	}

	necp_fd_mtx_grp = lck_grp_alloc_init("necp_fd", necp_fd_grp_attr);
	if (necp_fd_mtx_grp == NULL) {
		NECPLOG0(LOG_ERR, "lck_grp_alloc_init failed");
		result = ENOMEM;
		goto done;
	}

	necp_fd_mtx_attr = lck_attr_alloc_init();
	if (necp_fd_mtx_attr == NULL) {
		NECPLOG0(LOG_ERR, "lck_attr_alloc_init failed");
		result = ENOMEM;
		goto done;
	}

	necp_client_tcall = thread_call_allocate(necp_update_all_clients_callout, NULL);
	if (necp_client_tcall == NULL) {
		NECPLOG0(LOG_ERR, "thread_call_allocate failed");
		result = ENOMEM;
		goto done;
	}

	lck_rw_init(&necp_fd_lock, necp_fd_mtx_grp, necp_fd_mtx_attr);

	LIST_INIT(&necp_fd_list);

done:
	if (result != 0) {
		if (necp_fd_mtx_attr != NULL) {
			lck_attr_free(necp_fd_mtx_attr);
			necp_fd_mtx_attr = NULL;
		}
		if (necp_fd_mtx_grp != NULL) {
			lck_grp_free(necp_fd_mtx_grp);
			necp_fd_mtx_grp = NULL;
		}
		if (necp_fd_grp_attr != NULL) {
			lck_grp_attr_free(necp_fd_grp_attr);
			necp_fd_grp_attr = NULL;
		}
	}
	return (result);
}
