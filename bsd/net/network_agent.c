/*
 * Copyright (c) 2014-2018 Apple Inc. All rights reserved.
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
#include <sys/syslog.h>
#include <sys/queue.h>
#include <sys/malloc.h>
#include <libkern/OSMalloc.h>
#include <sys/kernel.h>
#include <sys/kern_control.h>
#include <sys/mbuf.h>
#include <sys/kpi_mbuf.h>
#include <sys/sysctl.h>
#include <sys/priv.h>
#include <sys/kern_event.h>
#include <sys/sysproto.h>
#include <net/network_agent.h>
#include <net/if_var.h>
#include <net/necp.h>

u_int32_t netagent_debug = LOG_NOTICE; // 0=None, 1=Basic

SYSCTL_NODE(_net, OID_AUTO, netagent, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "NetworkAgent");
SYSCTL_INT(_net_netagent, OID_AUTO, debug, CTLFLAG_LOCKED | CTLFLAG_RW, &netagent_debug, 0, "");

static int netagent_registered_count = 0;
SYSCTL_INT(_net_netagent, OID_AUTO, registered_count , CTLFLAG_RD | CTLFLAG_LOCKED,
		   &netagent_registered_count, 0, "");

static int netagent_active_count = 0;
SYSCTL_INT(_net_netagent, OID_AUTO, active_count , CTLFLAG_RD | CTLFLAG_LOCKED,
		   &netagent_active_count, 0, "");

#define	NETAGENTLOG(level, format, ...) do {											\
	if (level <= netagent_debug)					\
		log((level > LOG_NOTICE ? LOG_NOTICE : level), "%s: " format "\n", __FUNCTION__, __VA_ARGS__);	\
} while (0)

#define	NETAGENTLOG0(level, msg) do {											\
	if (level <= netagent_debug)					\
		log((level > LOG_NOTICE ? LOG_NOTICE : level), "%s: %s\n", __FUNCTION__, msg);	\
} while (0)

struct netagent_client {
	LIST_ENTRY(netagent_client) client_chain;
	uuid_t client_id;
	uuid_t client_proc_uuid;
	pid_t client_pid;
};

LIST_HEAD(netagent_client_list_s, netagent_client);

struct netagent_wrapper {
	LIST_ENTRY(netagent_wrapper) master_chain;
	u_int32_t control_unit;
	netagent_event_f event_handler;
	void *event_context;
	u_int32_t generation;
	u_int64_t use_count;
	struct netagent_client_list_s pending_triggers_list;
	struct netagent netagent;
};

struct netagent_session {
	u_int32_t control_unit; // A control unit of 0 indicates an agent owned by the kernel
	struct netagent_wrapper *wrapper;
	netagent_event_f event_handler;
	void *event_context;
};

typedef enum {
	kNetagentErrorDomainPOSIX			= 0,
	kNetagentErrorDomainUserDefined		= 1,
} netagent_error_domain_t;

static LIST_HEAD(_netagent_list, netagent_wrapper) master_netagent_list;

// Protected by netagent_lock
static u_int32_t g_next_generation = 1;

static kern_ctl_ref	netagent_kctlref;
static u_int32_t	netagent_family;
static OSMallocTag	netagent_malloc_tag;
static	lck_grp_attr_t	*netagent_grp_attr	= NULL;
static	lck_attr_t		*netagent_mtx_attr	= NULL;
static	lck_grp_t		*netagent_mtx_grp		= NULL;
decl_lck_rw_data(static, netagent_lock);

static errno_t netagent_register_control(void);
static errno_t netagent_ctl_connect(kern_ctl_ref kctlref, struct sockaddr_ctl *sac,
									void **unitinfo);
static errno_t netagent_ctl_disconnect(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo);
static errno_t netagent_ctl_send(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,
								 mbuf_t m, int flags);
static void netagent_ctl_rcvd(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, int flags);
static errno_t netagent_ctl_getopt(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,
								   int opt, void *data, size_t *len);
static errno_t netagent_ctl_setopt(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,
								   int opt, void *data, size_t len);

static int netagent_send_ctl_data(u_int32_t control_unit, u_int8_t *buffer, size_t buffer_size);

static struct netagent_session *netagent_create_session(u_int32_t control_unit);
static void netagent_delete_session(struct netagent_session *session);

// Register
static void netagent_handle_register_message(struct netagent_session *session, u_int32_t message_id,
											 u_int32_t payload_length, mbuf_t packet, int offset);
static errno_t netagent_handle_register_setopt(struct netagent_session *session, u_int8_t *payload,
											   u_int32_t payload_length);

// Unregister
static void netagent_handle_unregister_message(struct netagent_session *session, u_int32_t message_id,
											   u_int32_t payload_length, mbuf_t packet, int offset);
static errno_t netagent_handle_unregister_setopt(struct netagent_session *session, u_int8_t *payload,
												 u_int32_t payload_length);

// Update
static void netagent_handle_update_message(struct netagent_session *session, u_int32_t message_id,
								           u_int32_t payload_length, mbuf_t packet, int offset);
static errno_t netagent_handle_update_setopt(struct netagent_session *session, u_int8_t *payload,
											 u_int32_t payload_length);

// Assign nexus
static void netagent_handle_assign_nexus_message(struct netagent_session *session, u_int32_t message_id,
												 u_int32_t payload_length, mbuf_t packet, int offset);
static errno_t netagent_handle_assign_nexus_setopt(struct netagent_session *session, u_int8_t *payload,
												   u_int32_t payload_length);

// Set/get assert count
static errno_t netagent_handle_use_count_setopt(struct netagent_session *session, u_int8_t *payload, size_t payload_length);
static errno_t netagent_handle_use_count_getopt(struct netagent_session *session, u_int8_t *buffer, size_t *buffer_length);

static void netagent_handle_get(struct netagent_session *session, u_int32_t message_id,
								u_int32_t payload_length, mbuf_t packet, int offset);

static struct netagent_wrapper *netagent_find_agent_with_uuid(uuid_t uuid);

errno_t
netagent_init(void)
{
	errno_t result = 0;

	result = netagent_register_control();
	if (result != 0) {
		goto done;
	}

	netagent_grp_attr = lck_grp_attr_alloc_init();
	if (netagent_grp_attr == NULL) {
		NETAGENTLOG0(LOG_ERR, "lck_grp_attr_alloc_init failed");
		result = ENOMEM;
		goto done;
	}

	netagent_mtx_grp = lck_grp_alloc_init(NETAGENT_CONTROL_NAME, netagent_grp_attr);
	if (netagent_mtx_grp == NULL) {
		NETAGENTLOG0(LOG_ERR, "lck_grp_alloc_init failed");
		result = ENOMEM;
		goto done;
	}

	netagent_mtx_attr = lck_attr_alloc_init();
	if (netagent_mtx_attr == NULL) {
		NETAGENTLOG0(LOG_ERR, "lck_attr_alloc_init failed");
		result = ENOMEM;
		goto done;
	}

	lck_rw_init(&netagent_lock, netagent_mtx_grp, netagent_mtx_attr);

	LIST_INIT(&master_netagent_list);

done:
	if (result != 0) {
		if (netagent_mtx_attr != NULL) {
			lck_attr_free(netagent_mtx_attr);
			netagent_mtx_attr = NULL;
		}
		if (netagent_mtx_grp != NULL) {
			lck_grp_free(netagent_mtx_grp);
			netagent_mtx_grp = NULL;
		}
		if (netagent_grp_attr != NULL) {
			lck_grp_attr_free(netagent_grp_attr);
			netagent_grp_attr = NULL;
		}
		if (netagent_kctlref != NULL) {
			ctl_deregister(netagent_kctlref);
			netagent_kctlref = NULL;
		}
	}
	return (result);
}

static errno_t
netagent_register_control(void)
{
	struct kern_ctl_reg	kern_ctl;
	errno_t				result = 0;

	// Create a tag to allocate memory
	netagent_malloc_tag = OSMalloc_Tagalloc(NETAGENT_CONTROL_NAME, OSMT_DEFAULT);

	// Find a unique value for our interface family
	result = mbuf_tag_id_find(NETAGENT_CONTROL_NAME, &netagent_family);
	if (result != 0) {
		NETAGENTLOG(LOG_ERR, "mbuf_tag_id_find_internal failed: %d", result);
		return (result);
	}

	bzero(&kern_ctl, sizeof(kern_ctl));
	strlcpy(kern_ctl.ctl_name, NETAGENT_CONTROL_NAME, sizeof(kern_ctl.ctl_name));
	kern_ctl.ctl_name[sizeof(kern_ctl.ctl_name) - 1] = 0;
	kern_ctl.ctl_flags = CTL_FLAG_PRIVILEGED; // Require root
	kern_ctl.ctl_sendsize = 64 * 1024;
	kern_ctl.ctl_recvsize = 64 * 1024;
	kern_ctl.ctl_connect = netagent_ctl_connect;
	kern_ctl.ctl_disconnect = netagent_ctl_disconnect;
	kern_ctl.ctl_send = netagent_ctl_send;
	kern_ctl.ctl_rcvd = netagent_ctl_rcvd;
	kern_ctl.ctl_setopt = netagent_ctl_setopt;
	kern_ctl.ctl_getopt = netagent_ctl_getopt;

	result = ctl_register(&kern_ctl, &netagent_kctlref);
	if (result != 0) {
		NETAGENTLOG(LOG_ERR, "ctl_register failed: %d", result);
		return (result);
	}

	return (0);
}

static errno_t
netagent_ctl_connect(kern_ctl_ref kctlref, struct sockaddr_ctl *sac, void **unitinfo)
{
#pragma unused(kctlref)
	*unitinfo = netagent_create_session(sac->sc_unit);
	if (*unitinfo == NULL) {
		// Could not allocate session
		return (ENOBUFS);
	}

	return (0);
}

static errno_t
netagent_ctl_disconnect(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo)
{
#pragma unused(kctlref, unit)
	struct netagent_session *session = (struct netagent_session *)unitinfo;
	if (session != NULL) {
		netagent_delete_session(session);
	}

	return (0);
}

// Kernel events
static void
netagent_post_event(uuid_t agent_uuid, u_int32_t event_code, bool update_necp)
{
	if (update_necp) {
		necp_update_all_clients();
	}

	struct kev_msg ev_msg;
	memset(&ev_msg, 0, sizeof(ev_msg));

	struct kev_netagent_data event_data;

	ev_msg.vendor_code	= KEV_VENDOR_APPLE;
	ev_msg.kev_class	= KEV_NETWORK_CLASS;
	ev_msg.kev_subclass	= KEV_NETAGENT_SUBCLASS;
	ev_msg.event_code	= event_code;

	uuid_copy(event_data.netagent_uuid, agent_uuid);
	ev_msg.dv[0].data_ptr	 = &event_data;
	ev_msg.dv[0].data_length = sizeof(event_data);

	kev_post_msg(&ev_msg);
}

// Message handling
static u_int8_t *
netagent_buffer_write_message_header(u_int8_t *buffer, u_int8_t message_type, u_int8_t flags,
									 u_int32_t message_id, u_int32_t error, u_int32_t payload_length)
{
	((struct netagent_message_header *)(void *)buffer)->message_type = message_type;
	((struct netagent_message_header *)(void *)buffer)->message_flags = flags;
	((struct netagent_message_header *)(void *)buffer)->message_id = message_id;
	((struct netagent_message_header *)(void *)buffer)->message_error = error;
	((struct netagent_message_header *)(void *)buffer)->message_payload_length = payload_length;
	return (buffer + sizeof(struct netagent_message_header));
}

static int
netagent_send_ctl_data(u_int32_t control_unit, u_int8_t *buffer, size_t buffer_size)
{
	if (netagent_kctlref == NULL || control_unit == 0 || buffer == NULL || buffer_size == 0) {
		return (EINVAL);
	}

	return ctl_enqueuedata(netagent_kctlref, control_unit, buffer, buffer_size, CTL_DATA_EOR);
}

static int
netagent_send_trigger(struct netagent_wrapper *wrapper, struct proc *p, u_int32_t flags, u_int32_t trigger_type)
{
	int error = 0;
	struct netagent_trigger_message *trigger_message = NULL;
	u_int8_t *trigger = NULL;
	size_t trigger_size = sizeof(struct netagent_message_header) + sizeof(struct netagent_trigger_message);

	MALLOC(trigger, u_int8_t *, trigger_size, M_NETAGENT, M_WAITOK);
	if (trigger == NULL) {
		return (ENOMEM);
	}

	(void)netagent_buffer_write_message_header(trigger, trigger_type, 0, 0, 0, sizeof(struct netagent_trigger_message));

	trigger_message = (struct netagent_trigger_message *)(void *)(trigger + sizeof(struct netagent_message_header));
	trigger_message->trigger_flags = flags;
	if (p != NULL) {
		trigger_message->trigger_pid = proc_pid(p);
		proc_getexecutableuuid(p, trigger_message->trigger_proc_uuid, sizeof(trigger_message->trigger_proc_uuid));
	} else {
		trigger_message->trigger_pid = 0;
		uuid_clear(trigger_message->trigger_proc_uuid);
	}

	if ((error = netagent_send_ctl_data(wrapper->control_unit, (u_int8_t *)trigger, trigger_size))) {
		NETAGENTLOG(LOG_ERR, "Failed to send trigger message on control unit %d", wrapper->control_unit);
	}

	FREE(trigger, M_NETAGENT);
	return (error);
}

static int
netagent_send_client_message(struct netagent_wrapper *wrapper, uuid_t client_id, u_int8_t message_type)
{
	int error = 0;
	struct netagent_client_message *client_message = NULL;
	u_int8_t *message = NULL;
	size_t message_size = sizeof(struct netagent_message_header) + sizeof(struct netagent_client_message);

	MALLOC(message, u_int8_t *, message_size, M_NETAGENT, M_WAITOK);
	if (message == NULL) {
		return (ENOMEM);
	}

	(void)netagent_buffer_write_message_header(message, message_type, 0, 0, 0, sizeof(struct netagent_client_message));

	client_message = (struct netagent_client_message *)(void *)(message + sizeof(struct netagent_message_header));
	uuid_copy(client_message->client_id, client_id);

	if ((error = netagent_send_ctl_data(wrapper->control_unit, (u_int8_t *)message, message_size))) {
		NETAGENTLOG(LOG_ERR, "Failed to send client message %d on control unit %d", message_type, wrapper->control_unit);
	}

	FREE(message, M_NETAGENT);
	return (error);
}

static int
netagent_send_success_response(struct netagent_session *session, u_int8_t message_type, u_int32_t message_id)
{
	int error = 0;
	u_int8_t *response = NULL;
	size_t response_size = sizeof(struct netagent_message_header);
	MALLOC(response, u_int8_t *, response_size, M_NETAGENT, M_WAITOK);
	if (response == NULL) {
		return (ENOMEM);
	}
	(void)netagent_buffer_write_message_header(response, message_type, NETAGENT_MESSAGE_FLAGS_RESPONSE, message_id, 0, 0);

	if ((error = netagent_send_ctl_data(session->control_unit, (u_int8_t *)response, response_size))) {
		NETAGENTLOG0(LOG_ERR, "Failed to send response");
	}

	FREE(response, M_NETAGENT);
	return (error);
}

static int
netagent_send_error_response(struct netagent_session *session, u_int8_t message_type,
							 u_int32_t message_id, u_int32_t error_code)
{
	int error = 0;
	u_int8_t *response = NULL;
	size_t response_size = sizeof(struct netagent_message_header);
	MALLOC(response, u_int8_t *, response_size, M_NETAGENT, M_WAITOK);
	if (response == NULL) {
		return (ENOMEM);
	}
	(void)netagent_buffer_write_message_header(response, message_type, NETAGENT_MESSAGE_FLAGS_RESPONSE,
											   message_id, error_code, 0);

	if ((error = netagent_send_ctl_data(session->control_unit, (u_int8_t *)response, response_size))) {
		NETAGENTLOG0(LOG_ERR, "Failed to send response");
	}

	FREE(response, M_NETAGENT);
	return (error);
}

static errno_t
netagent_ctl_send(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, mbuf_t packet, int flags)
{
#pragma unused(kctlref, unit, flags)
	struct netagent_session *session = (struct netagent_session *)unitinfo;
	struct netagent_message_header header;
	int error = 0;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Got a NULL session");
		error = EINVAL;
		goto done;
	}

	if (mbuf_pkthdr_len(packet) < sizeof(header)) {
		NETAGENTLOG(LOG_ERR, "Got a bad packet, length (%lu) < sizeof header (%lu)",
					mbuf_pkthdr_len(packet), sizeof(header));
		error = EINVAL;
		goto done;
	}

	error = mbuf_copydata(packet, 0, sizeof(header), &header);
	if (error) {
		NETAGENTLOG(LOG_ERR, "mbuf_copydata failed for the header: %d", error);
		error = ENOBUFS;
		goto done;
	}

	switch (header.message_type) {
		case NETAGENT_MESSAGE_TYPE_REGISTER: {
			netagent_handle_register_message(session, header.message_id, header.message_payload_length,
									         packet, sizeof(header));
			break;
		}
		case NETAGENT_MESSAGE_TYPE_UNREGISTER: {
			netagent_handle_unregister_message(session, header.message_id, header.message_payload_length,
											   packet, sizeof(header));
			break;
		}
		case NETAGENT_MESSAGE_TYPE_UPDATE: {
			netagent_handle_update_message(session, header.message_id, header.message_payload_length,
								   packet, sizeof(header));
			break;
		}
		case NETAGENT_MESSAGE_TYPE_GET: {
			netagent_handle_get(session, header.message_id, header.message_payload_length,
								packet, sizeof(header));
			break;
		}
		case NETAGENT_MESSAGE_TYPE_ASSERT: {
			NETAGENTLOG0(LOG_ERR, "NETAGENT_MESSAGE_TYPE_ASSERT no longer supported");
			break;
		}
		case NETAGENT_MESSAGE_TYPE_UNASSERT: {
			NETAGENTLOG0(LOG_ERR, "NETAGENT_MESSAGE_TYPE_UNASSERT no longer supported");
			break;
		}
		case NETAGENT_MESSAGE_TYPE_ASSIGN_NEXUS: {
			netagent_handle_assign_nexus_message(session, header.message_id, header.message_payload_length,
												 packet, sizeof(header));
			break;
		}
		default: {
			NETAGENTLOG(LOG_ERR, "Received unknown message type %d", header.message_type);
			netagent_send_error_response(session, header.message_type, header.message_id,
										 NETAGENT_MESSAGE_ERROR_UNKNOWN_TYPE);
			break;
		}
	}

done:
	mbuf_freem(packet);
	return (error);
}

static void
netagent_ctl_rcvd(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, int flags)
{
#pragma unused(kctlref, unit, unitinfo, flags)
	return;
}

static errno_t
netagent_ctl_getopt(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, int opt,
					void *data, size_t *len)
{
#pragma unused(kctlref, unit)
	struct netagent_session *session = (struct netagent_session *)unitinfo;
	errno_t error;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Received a NULL session");
		error = EINVAL;
		goto done;
	}

	switch (opt) {
		case NETAGENT_OPTION_TYPE_USE_COUNT: {
			NETAGENTLOG0(LOG_DEBUG, "Request to get use count");
			error = netagent_handle_use_count_getopt(session, data, len);
		}
		break;
		default:
			NETAGENTLOG0(LOG_ERR, "Received unknown option");
			error = ENOPROTOOPT;
		break;
	}

done:
	return (error);
}

static errno_t
netagent_ctl_setopt(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, int opt,
					void *data, size_t len)
{
#pragma unused(kctlref, unit)
	struct netagent_session *session = (struct netagent_session *)unitinfo;
	errno_t error;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Received a NULL session");
		error = EINVAL;
		goto done;
	}

	switch (opt) {
		case NETAGENT_OPTION_TYPE_REGISTER: {
			NETAGENTLOG0(LOG_DEBUG, "Request for registration");
			error = netagent_handle_register_setopt(session, data, len);
		}
		break;
		case NETAGENT_OPTION_TYPE_UPDATE: {
			NETAGENTLOG0(LOG_DEBUG, "Request for update");
			error = netagent_handle_update_setopt(session, data, len);
		}
		break;
		case NETAGENT_OPTION_TYPE_UNREGISTER: {
			NETAGENTLOG0(LOG_DEBUG, "Request for unregistration");
			error = netagent_handle_unregister_setopt(session, data, len);
		}
		break;
		case NETAGENT_OPTION_TYPE_ASSIGN_NEXUS: {
			NETAGENTLOG0(LOG_DEBUG, "Request for assigning nexus");
			error = netagent_handle_assign_nexus_setopt(session, data, len);
		}
		break;
		case NETAGENT_OPTION_TYPE_USE_COUNT: {
			NETAGENTLOG0(LOG_DEBUG, "Request to set use count");
			error = netagent_handle_use_count_setopt(session, data, len);
		}
		break;
		default:
			NETAGENTLOG0(LOG_ERR, "Received unknown option");
			error = ENOPROTOOPT;
		break;
	}

done:
	return (error);
}

// Session Management
static struct netagent_session *
netagent_create_session(u_int32_t control_unit)
{
	struct netagent_session *new_session = NULL;

	MALLOC(new_session, struct netagent_session *, sizeof(*new_session), M_NETAGENT, M_WAITOK);
	if (new_session == NULL) {
		goto done;
	}
	NETAGENTLOG(LOG_DEBUG, "Create agent session, control unit %d", control_unit);
	memset(new_session, 0, sizeof(*new_session));
	new_session->control_unit = control_unit;
	new_session->wrapper = NULL;
done:
	return (new_session);
}

netagent_session_t netagent_create(netagent_event_f event_handler, void *context)
{
	struct netagent_session *session = netagent_create_session(0);
	if (session == NULL) {
		return NULL;
	}

	session->event_handler = event_handler;
	session->event_context = context;
	return session;
}

static void
netagent_free_wrapper(struct netagent_wrapper *wrapper)
{
	// Free any pending client triggers
	struct netagent_client *search_client = NULL;
	struct netagent_client *temp_client = NULL;
	LIST_FOREACH_SAFE(search_client, &wrapper->pending_triggers_list, client_chain, temp_client) {
		LIST_REMOVE(search_client, client_chain);
		FREE(search_client, M_NETAGENT);
	}

	// Free wrapper itself
	FREE(wrapper, M_NETAGENT);
}

static void
netagent_unregister_session_wrapper(struct netagent_session *session)
{
	bool unregistered = FALSE;
	uuid_t unregistered_uuid;
	struct netagent_wrapper *wrapper = NULL;
	lck_rw_lock_exclusive(&netagent_lock);
	if (session != NULL) {
		wrapper = session->wrapper;
		if (wrapper != NULL) {
			if (netagent_registered_count > 0) {
				netagent_registered_count--;
			}
			if ((session->wrapper->netagent.netagent_flags & NETAGENT_FLAG_ACTIVE) &&
				netagent_active_count > 0) {
				netagent_active_count--;
			}

			LIST_REMOVE(wrapper, master_chain);

			unregistered = TRUE;
			uuid_copy(unregistered_uuid, session->wrapper->netagent.netagent_uuid);

			netagent_free_wrapper(session->wrapper);
			session->wrapper = NULL;
			NETAGENTLOG0(LOG_DEBUG, "Unregistered agent");
		}
	}
	lck_rw_done(&netagent_lock);

	if (unregistered) {
		ifnet_clear_netagent(unregistered_uuid);
		netagent_post_event(unregistered_uuid, KEV_NETAGENT_UNREGISTERED, TRUE);
	}
}

static void
netagent_delete_session(struct netagent_session *session)
{
	if (session != NULL) {
		netagent_unregister_session_wrapper(session);
		FREE(session, M_NETAGENT);
	}
}

void netagent_destroy(netagent_session_t session)
{
	return netagent_delete_session((struct netagent_session *)session);
}

static int
netagent_packet_get_netagent_data_size(mbuf_t packet, int offset, int *err)
{
	int error = 0;

	struct netagent netagent_peek;
	memset(&netagent_peek, 0, sizeof(netagent_peek));

	*err = 0;

	error = mbuf_copydata(packet, offset, sizeof(netagent_peek), &netagent_peek);
	if (error) {
		*err = ENOENT;
		return (-1);
	}

	return (netagent_peek.netagent_data_size);
}

static errno_t
netagent_handle_register_inner(struct netagent_session *session, struct netagent_wrapper *new_wrapper)
{
	lck_rw_lock_exclusive(&netagent_lock);

	new_wrapper->control_unit = session->control_unit;
	new_wrapper->event_handler = session->event_handler;
	new_wrapper->event_context = session->event_context;
	new_wrapper->generation = g_next_generation++;

	session->wrapper = new_wrapper;
	LIST_INSERT_HEAD(&master_netagent_list, new_wrapper, master_chain);
	LIST_INIT(&new_wrapper->pending_triggers_list);

	new_wrapper->netagent.netagent_flags |= NETAGENT_FLAG_REGISTERED;
	netagent_registered_count++;
	if (new_wrapper->netagent.netagent_flags & NETAGENT_FLAG_ACTIVE) {
		netagent_active_count++;
	}

	lck_rw_done(&netagent_lock);

	return 0;
}

errno_t
netagent_register(netagent_session_t _session, struct netagent *agent)
{
	int data_size = 0;
	struct netagent_wrapper *new_wrapper = NULL;

	struct netagent_session *session = (struct netagent_session *)_session;
	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Cannot register agent on NULL session");
		return EINVAL;
	}

	if (agent == NULL) {
		NETAGENTLOG0(LOG_ERR, "Cannot register NULL agent");
		return EINVAL;
	}

	if (session->wrapper != NULL) {
		NETAGENTLOG0(LOG_ERR, "Session already has a registered agent");
		return EINVAL;
	}

	data_size = agent->netagent_data_size;
	if (data_size < 0 || data_size > NETAGENT_MAX_DATA_SIZE) {
		NETAGENTLOG(LOG_ERR, "Register message size could not be read, data_size %d",
					data_size);
		return EINVAL;
	}

	MALLOC(new_wrapper, struct netagent_wrapper *, sizeof(*new_wrapper) + data_size, M_NETAGENT, M_WAITOK);
	if (new_wrapper == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to allocate agent");
		return ENOMEM;
	}

	memset(new_wrapper, 0, sizeof(*new_wrapper) + data_size);
	memcpy(&new_wrapper->netagent, agent, sizeof(struct netagent) + data_size);

	int error = netagent_handle_register_inner(session, new_wrapper);
	if (error != 0) {
		FREE(new_wrapper, M_NETAGENT);
		return error;
	}

	NETAGENTLOG0(LOG_DEBUG, "Registered new agent");
	netagent_post_event(new_wrapper->netagent.netagent_uuid, KEV_NETAGENT_REGISTERED, TRUE);

	return 0;
}

static errno_t
netagent_handle_register_setopt(struct netagent_session *session, u_int8_t *payload,
								u_int32_t payload_length)
{
	int data_size = 0;
	struct netagent_wrapper *new_wrapper = NULL;
	u_int32_t response_error = 0;
	struct netagent *register_netagent = (struct netagent *)(void *)payload;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to find session");
		response_error = EINVAL;
		goto done;
	}

	if (payload == NULL) {
		NETAGENTLOG0(LOG_ERR, "No payload received");
		response_error = EINVAL;
		goto done;
	}

	if (session->wrapper != NULL) {
		NETAGENTLOG0(LOG_ERR, "Session already has a registered agent");
		response_error = EINVAL;
		goto done;
	}

	if (payload_length < sizeof(struct netagent)) {
		NETAGENTLOG(LOG_ERR, "Register message size too small for agent: (%u < %lu)",
					payload_length, sizeof(struct netagent));
		response_error = EINVAL;
		goto done;
	}

	data_size = register_netagent->netagent_data_size;
	if (data_size < 0 || data_size > NETAGENT_MAX_DATA_SIZE) {
		NETAGENTLOG(LOG_ERR, "Register message size could not be read, data_size %d", data_size);
		response_error = EINVAL;
		goto done;
	}

	if (payload_length != (sizeof(struct netagent) + data_size)) {
		NETAGENTLOG(LOG_ERR, "Mismatch between data size and payload length (%lu != %u)", (sizeof(struct netagent) + data_size), payload_length);
		response_error = EINVAL;
		goto done;
    }

	MALLOC(new_wrapper, struct netagent_wrapper *, sizeof(*new_wrapper) + data_size, M_NETAGENT, M_WAITOK);
	if (new_wrapper == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to allocate agent");
		response_error = ENOMEM;
		goto done;
	}

	memset(new_wrapper, 0, sizeof(*new_wrapper) + data_size);
	memcpy(&new_wrapper->netagent, register_netagent, sizeof(struct netagent) + data_size);

	response_error = netagent_handle_register_inner(session, new_wrapper);
	if (response_error != 0) {
		FREE(new_wrapper, M_NETAGENT);
		goto done;
	}

	NETAGENTLOG0(LOG_DEBUG, "Registered new agent");
	netagent_post_event(new_wrapper->netagent.netagent_uuid, KEV_NETAGENT_REGISTERED, TRUE);

done:
	return response_error;
}

static void
netagent_handle_register_message(struct netagent_session *session, u_int32_t message_id,
						         u_int32_t payload_length, mbuf_t packet, int offset)
{
	int error;
	int data_size = 0;
	struct netagent_wrapper *new_wrapper = NULL;
	u_int32_t response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
	uuid_t netagent_uuid;
	uuid_clear(netagent_uuid);

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to find session");
		response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
		goto fail;
	}

	if (session->wrapper != NULL) {
		NETAGENTLOG0(LOG_ERR, "Session already has a registered agent");
		response_error = NETAGENT_MESSAGE_ERROR_ALREADY_REGISTERED;
		goto fail;
	}

	if (payload_length < sizeof(struct netagent)) {
		NETAGENTLOG(LOG_ERR, "Register message size too small for agent: (%u < %lu)",
					payload_length, sizeof(struct netagent));
		response_error = NETAGENT_MESSAGE_ERROR_INVALID_DATA;
		goto fail;
	}

	data_size = netagent_packet_get_netagent_data_size(packet, offset, &error);
	if (error || data_size < 0 || data_size > NETAGENT_MAX_DATA_SIZE) {
		NETAGENTLOG(LOG_ERR, "Register message size could not be read, error %d data_size %d",
					error, data_size);
		response_error = NETAGENT_MESSAGE_ERROR_INVALID_DATA;
		goto fail;
	}

	MALLOC(new_wrapper, struct netagent_wrapper *, sizeof(*new_wrapper) + data_size, M_NETAGENT, M_WAITOK);
	if (new_wrapper == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to allocate agent");
		response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
		goto fail;
	}

	memset(new_wrapper, 0, sizeof(*new_wrapper) + data_size);

	error = mbuf_copydata(packet, offset, sizeof(struct netagent) + data_size,
						  &new_wrapper->netagent);
	if (error) {
		NETAGENTLOG(LOG_ERR, "Failed to read data into agent structure: %d", error);
		FREE(new_wrapper, M_NETAGENT);
		response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
		goto fail;
	}

	(void)netagent_handle_register_inner(session, new_wrapper);

	NETAGENTLOG0(LOG_DEBUG, "Registered new agent");
	netagent_send_success_response(session, NETAGENT_MESSAGE_TYPE_REGISTER, message_id);
	netagent_post_event(new_wrapper->netagent.netagent_uuid, KEV_NETAGENT_REGISTERED, TRUE);
	return;
fail:
	netagent_send_error_response(session, NETAGENT_MESSAGE_TYPE_REGISTER, message_id, response_error);
}

errno_t
netagent_unregister(netagent_session_t _session)
{
	struct netagent_session *session = (struct netagent_session *)_session;
	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Cannot unregister NULL session");
		return EINVAL;
	}

	netagent_unregister_session_wrapper(session);
	return 0;
}

static errno_t
netagent_handle_unregister_setopt(struct netagent_session *session, u_int8_t *payload,
								  u_int32_t payload_length)
{
#pragma unused(payload, payload_length)
	u_int32_t response_error = 0;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to find session");
		response_error = EINVAL;
		goto done;
	}

	netagent_unregister_session_wrapper(session);

done:
	return response_error;
}

static void
netagent_handle_unregister_message(struct netagent_session *session, u_int32_t message_id,
								   u_int32_t payload_length, mbuf_t packet, int offset)
{
#pragma unused(payload_length, packet, offset)
	u_int32_t response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to find session");
		response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
		goto fail;
	}

	netagent_unregister_session_wrapper(session);

	netagent_send_success_response(session, NETAGENT_MESSAGE_TYPE_UNREGISTER, message_id);
	return;
fail:
	netagent_send_error_response(session, NETAGENT_MESSAGE_TYPE_UNREGISTER, message_id, response_error);
}

static void
netagent_send_cellular_failed_event(struct netagent_wrapper *wrapper,
									pid_t pid, uuid_t proc_uuid)
{
	if (strncmp(wrapper->netagent.netagent_domain, "Cellular", NETAGENT_DOMAINSIZE) != 0) {
		return;
	}

	struct kev_netpolicy_ifdenied ev_ifdenied;

	bzero(&ev_ifdenied, sizeof(ev_ifdenied));

	ev_ifdenied.ev_data.epid = pid;
	uuid_copy(ev_ifdenied.ev_data.euuid, proc_uuid);
	ev_ifdenied.ev_if_functional_type = IFRTYPE_FUNCTIONAL_CELLULAR;

	netpolicy_post_msg(KEV_NETPOLICY_IFFAILED, &ev_ifdenied.ev_data, sizeof(ev_ifdenied));
}

static errno_t
netagent_handle_update_inner(struct netagent_session *session, struct netagent_wrapper *new_wrapper, u_int32_t data_size, u_int8_t *agent_changed, netagent_error_domain_t error_domain)
{
	u_int32_t response_error = 0;

	if (agent_changed == NULL) {
		NETAGENTLOG0(LOG_ERR, "Invalid argument: agent_changed");
		return EINVAL;
	}

	lck_rw_lock_exclusive(&netagent_lock);

	if (uuid_compare(session->wrapper->netagent.netagent_uuid, new_wrapper->netagent.netagent_uuid) != 0 ||
		memcmp(&session->wrapper->netagent.netagent_domain, &new_wrapper->netagent.netagent_domain,
			   sizeof(new_wrapper->netagent.netagent_domain)) != 0 ||
		memcmp(&session->wrapper->netagent.netagent_type, &new_wrapper->netagent.netagent_type,
			   sizeof(new_wrapper->netagent.netagent_type)) != 0) {
			lck_rw_done(&netagent_lock);
			NETAGENTLOG0(LOG_ERR, "Basic agent parameters do not match, cannot update");
			if (error_domain == kNetagentErrorDomainPOSIX) {
				response_error = EINVAL;
			} else if (error_domain == kNetagentErrorDomainUserDefined) {
				response_error = NETAGENT_MESSAGE_ERROR_CANNOT_UPDATE;
			}
			return response_error;
		}

	new_wrapper->netagent.netagent_flags |= NETAGENT_FLAG_REGISTERED;
	if (session->wrapper->netagent.netagent_data_size == new_wrapper->netagent.netagent_data_size &&
		memcmp(&session->wrapper->netagent, &new_wrapper->netagent, sizeof(struct netagent) + data_size) == 0) {
		// Agent is exactly identical, don't increment the generation count

		// Make a copy of the list of pending clients, and clear the current list
		struct netagent_client_list_s pending_triggers_list_copy;
		LIST_INIT(&pending_triggers_list_copy);
		struct netagent_client *search_client = NULL;
		struct netagent_client *temp_client = NULL;
		LIST_FOREACH_SAFE(search_client, &session->wrapper->pending_triggers_list, client_chain, temp_client) {
			LIST_REMOVE(search_client, client_chain);
			LIST_INSERT_HEAD(&pending_triggers_list_copy, search_client, client_chain);
		}
		lck_rw_done(&netagent_lock);

		// Update pending client triggers without holding a lock
		search_client = NULL;
		temp_client = NULL;
		LIST_FOREACH_SAFE(search_client, &pending_triggers_list_copy, client_chain, temp_client) {
			necp_force_update_client(search_client->client_id, session->wrapper->netagent.netagent_uuid);
			netagent_send_cellular_failed_event(new_wrapper, search_client->client_pid, search_client->client_proc_uuid);
			LIST_REMOVE(search_client, client_chain);
			FREE(search_client, M_NETAGENT);
		}
		NETAGENTLOG0(LOG_DEBUG, "Updated agent (no changes)");
		*agent_changed = FALSE;
		return response_error;
	}

	new_wrapper->generation = g_next_generation++;
	new_wrapper->use_count = session->wrapper->use_count;

	if ((new_wrapper->netagent.netagent_flags & NETAGENT_FLAG_ACTIVE) &&
		!(session->wrapper->netagent.netagent_flags & NETAGENT_FLAG_ACTIVE)) {
		netagent_active_count++;
	} else if (!(new_wrapper->netagent.netagent_flags & NETAGENT_FLAG_ACTIVE) &&
			   (session->wrapper->netagent.netagent_flags & NETAGENT_FLAG_ACTIVE) &&
			   netagent_active_count > 0) {
		netagent_active_count--;
	}

	LIST_REMOVE(session->wrapper, master_chain);
	netagent_free_wrapper(session->wrapper);
	session->wrapper = new_wrapper;
	new_wrapper->control_unit = session->control_unit;
	new_wrapper->event_handler = session->event_handler;
	new_wrapper->event_context = session->event_context;
	LIST_INSERT_HEAD(&master_netagent_list, new_wrapper, master_chain);
	LIST_INIT(&new_wrapper->pending_triggers_list);

	NETAGENTLOG0(LOG_DEBUG, "Updated agent");
	*agent_changed = TRUE;

	lck_rw_done(&netagent_lock);

	return response_error;
}

errno_t
netagent_update(netagent_session_t _session, struct netagent *agent)
{
	u_int8_t agent_changed;
	int data_size = 0;
	struct netagent_wrapper *new_wrapper = NULL;

	struct netagent_session *session = (struct netagent_session *)_session;
	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Cannot update agent on NULL session");
		return EINVAL;
	}

	if (agent == NULL) {
		NETAGENTLOG0(LOG_ERR, "Cannot register NULL agent");
		return EINVAL;
	}

	if (session->wrapper == NULL) {
		NETAGENTLOG0(LOG_ERR, "Session has no agent to update");
		return EINVAL;
	}

	data_size = agent->netagent_data_size;
	if (data_size > NETAGENT_MAX_DATA_SIZE) {
		NETAGENTLOG(LOG_ERR, "Update message size (%u > %u) too large", data_size, NETAGENT_MAX_DATA_SIZE);
		return EINVAL;
	}

	MALLOC(new_wrapper, struct netagent_wrapper *, sizeof(*new_wrapper) + data_size, M_NETAGENT, M_WAITOK);
	if (new_wrapper == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to allocate agent");
		return ENOMEM;
	}

	memset(new_wrapper, 0, sizeof(*new_wrapper) + data_size);
	memcpy(&new_wrapper->netagent, agent, sizeof(struct netagent) + data_size);

	int error = netagent_handle_update_inner(session, new_wrapper, data_size, &agent_changed, kNetagentErrorDomainPOSIX);
	if (error == 0) {
		netagent_post_event(session->wrapper->netagent.netagent_uuid, KEV_NETAGENT_UPDATED, agent_changed);
		if (agent_changed == FALSE) {
			// The session wrapper does not need the "new_wrapper" as nothing changed
			FREE(new_wrapper, M_NETAGENT);
		}
	} else {
		FREE(new_wrapper, M_NETAGENT);
		return error;
	}

	return 0;
}

static errno_t
netagent_handle_update_setopt(struct netagent_session *session, u_int8_t *payload, u_int32_t payload_length)
{
	u_int32_t data_size = 0;
	struct netagent_wrapper *new_wrapper = NULL;
	errno_t response_error = 0;
	struct netagent *update_netagent = (struct netagent *)(void *)payload;
	u_int8_t agent_changed;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to find session");
		response_error = EINVAL;
		goto done;
	}

	if (payload == NULL) {
		NETAGENTLOG0(LOG_ERR, "No payload received");
		response_error = EINVAL;
		goto done;
	}

	if (session->wrapper == NULL) {
		NETAGENTLOG0(LOG_ERR, "Session has no agent to update");
		response_error = ENOENT;
		goto done;
	}

	if (payload_length < sizeof(struct netagent)) {
		NETAGENTLOG(LOG_ERR, "Update message size too small for agent: (%u < %lu)",
					payload_length, sizeof(struct netagent));
		response_error = EINVAL;
		goto done;
	}

	data_size = update_netagent->netagent_data_size;
	if (data_size > NETAGENT_MAX_DATA_SIZE) {
		NETAGENTLOG(LOG_ERR, "Update message size (%u > %u) too large", data_size, NETAGENT_MAX_DATA_SIZE);
		response_error = EINVAL;
		goto done;
	}

	if (payload_length != (sizeof(struct netagent) + data_size)) {
		NETAGENTLOG(LOG_ERR, "Mismatch between data size and payload length (%lu != %u)", (sizeof(struct netagent) + data_size), payload_length);
		response_error = EINVAL;
		goto done;
    }

	MALLOC(new_wrapper, struct netagent_wrapper *, sizeof(*new_wrapper) + data_size, M_NETAGENT, M_WAITOK);
	if (new_wrapper == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to allocate agent");
		response_error = ENOMEM;
		goto done;
	}

	memset(new_wrapper, 0, sizeof(*new_wrapper) + data_size);
	memcpy(&new_wrapper->netagent, update_netagent, sizeof(struct netagent) + data_size);

	response_error = netagent_handle_update_inner(session, new_wrapper, data_size, &agent_changed, kNetagentErrorDomainPOSIX);
	if (response_error == 0) {
		netagent_post_event(session->wrapper->netagent.netagent_uuid, KEV_NETAGENT_UPDATED, agent_changed);
		if (agent_changed == FALSE) {
			// The session wrapper does not need the "new_wrapper" as nothing changed
			FREE(new_wrapper, M_NETAGENT);
		}
	} else {
		FREE(new_wrapper, M_NETAGENT);
	}

done:
	return response_error;
}

static void
netagent_handle_update_message(struct netagent_session *session, u_int32_t message_id,
					           u_int32_t payload_length, mbuf_t packet, int offset)
{
	int error;
	int data_size = 0;
	struct netagent_wrapper *new_wrapper = NULL;
	u_int32_t response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
	u_int8_t agent_changed;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to find session");
		response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
		goto fail;
	}

	if (session->wrapper == NULL) {
		NETAGENTLOG0(LOG_ERR, "Session has no agent to update");
		response_error = NETAGENT_MESSAGE_ERROR_NOT_REGISTERED;
		goto fail;
	}

	if (payload_length < sizeof(struct netagent)) {
		NETAGENTLOG(LOG_ERR, "Update message size too small for agent: (%u < %lu)",
					payload_length, sizeof(struct netagent));
		response_error = NETAGENT_MESSAGE_ERROR_INVALID_DATA;
		goto fail;
	}

	data_size = netagent_packet_get_netagent_data_size(packet, offset, &error);
	if (error || data_size < 0 || data_size > NETAGENT_MAX_DATA_SIZE) {
		NETAGENTLOG(LOG_ERR, "Update message size could not be read, error %d data_size %d",
					error, data_size);
		response_error = NETAGENT_MESSAGE_ERROR_INVALID_DATA;
		goto fail;
	}

	MALLOC(new_wrapper, struct netagent_wrapper *, sizeof(*new_wrapper) + data_size, M_NETAGENT, M_WAITOK);
	if (new_wrapper == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to allocate agent");
		response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
		goto fail;
	}

	memset(new_wrapper, 0, sizeof(*new_wrapper) + data_size);

	error = mbuf_copydata(packet, offset, sizeof(struct netagent) + data_size, &new_wrapper->netagent);
	if (error) {
		NETAGENTLOG(LOG_ERR, "Failed to read data into agent structure: %d", error);
		FREE(new_wrapper, M_NETAGENT);
		response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
		goto fail;
	}

	response_error = netagent_handle_update_inner(session, new_wrapper, data_size, &agent_changed , kNetagentErrorDomainUserDefined);
	if (response_error != 0) {
		FREE(new_wrapper, M_NETAGENT);
		goto fail;
	}

	netagent_send_success_response(session, NETAGENT_MESSAGE_TYPE_UPDATE, message_id);
	netagent_post_event(session->wrapper->netagent.netagent_uuid, KEV_NETAGENT_UPDATED, agent_changed);

	if (agent_changed == FALSE) {
		// The session wrapper does not need the "new_wrapper" as nothing changed
		FREE(new_wrapper, M_NETAGENT);
	}

	return;
fail:
	netagent_send_error_response(session, NETAGENT_MESSAGE_TYPE_UPDATE, message_id, response_error);
}

static void
netagent_handle_get(struct netagent_session *session, u_int32_t message_id,
					u_int32_t payload_length, mbuf_t packet, int offset)
{
#pragma unused(payload_length, packet, offset)
	u_int8_t *response = NULL;
	u_int8_t *cursor = NULL;
	u_int32_t response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to find session");
		response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
		goto fail;
	}

	if (session->wrapper == NULL) {
		NETAGENTLOG0(LOG_ERR, "Session has no agent to get");
		response_error = NETAGENT_MESSAGE_ERROR_NOT_REGISTERED;
		goto fail;
	}

	lck_rw_lock_shared(&netagent_lock);

	size_t response_size = sizeof(struct netagent_message_header) + sizeof(session->wrapper->netagent)
								+ session->wrapper->netagent.netagent_data_size;
	MALLOC(response, u_int8_t *, response_size, M_NETAGENT, M_WAITOK);
	if (response == NULL) {
		goto fail;
	}

	cursor = response;
	cursor = netagent_buffer_write_message_header(cursor, NETAGENT_MESSAGE_TYPE_GET,
												  NETAGENT_MESSAGE_FLAGS_RESPONSE, message_id, 0,
												  response_size - sizeof(struct netagent_message_header));
	memcpy(cursor, &session->wrapper->netagent, sizeof(session->wrapper->netagent) +
		   session->wrapper->netagent.netagent_data_size);

	lck_rw_done(&netagent_lock);

	if (!netagent_send_ctl_data(session->control_unit, (u_int8_t *)response, response_size)) {
		NETAGENTLOG0(LOG_ERR, "Failed to send response");
	}
	FREE(response, M_NETAGENT);
	return;
fail:
	netagent_send_error_response(session, NETAGENT_MESSAGE_TYPE_GET, message_id, response_error);
}

errno_t
netagent_assign_nexus(netagent_session_t _session, uuid_t necp_client_uuid,
					  void *assign_message, size_t assigned_results_length)
{
	struct netagent_session *session = (struct netagent_session *)_session;
	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Cannot assign nexus from NULL session");
		return EINVAL;
	}

	if (session->wrapper == NULL) {
		NETAGENTLOG0(LOG_ERR, "Session has no agent");
		return ENOENT;
	}

	// Note that if the error is 0, NECP has taken over our malloc'ed buffer
	int error = necp_assign_client_result(session->wrapper->netagent.netagent_uuid, necp_client_uuid, assign_message, assigned_results_length);
	if (error) {
		// necp_assign_client_result returns POSIX errors; don't error for ENOENT
		NETAGENTLOG((error == ENOENT ? LOG_DEBUG : LOG_ERR), "Client assignment failed: %d", error);
		return error;
	}

	NETAGENTLOG0(LOG_DEBUG, "Agent assigned nexus properties to client");
	return 0;
}

errno_t
netagent_update_flow_protoctl_event(netagent_session_t _session,
    uuid_t client_id, uint32_t protoctl_event_code,
    uint32_t protoctl_event_val, uint32_t protoctl_event_tcp_seq_number)
{
	struct netagent_session *session = (struct netagent_session *)_session;
	int error = 0;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Cannot assign nexus from NULL session");
		return (EINVAL);
	}

	if (session->wrapper == NULL) {
		NETAGENTLOG0(LOG_ERR, "Session has no agent");
		return (ENOENT);
	}

	error = necp_update_flow_protoctl_event(session->wrapper->netagent.netagent_uuid,
	    client_id, protoctl_event_code, protoctl_event_val, protoctl_event_tcp_seq_number);

	return (error);
}

static errno_t
netagent_handle_assign_nexus_setopt(struct netagent_session *session, u_int8_t *payload,
									u_int32_t payload_length)
{
	errno_t response_error = 0;
	struct netagent_assign_nexus_message *assign_nexus_netagent = (struct netagent_assign_nexus_message *)(void *)payload;
	uuid_t client_id;
	u_int8_t *assigned_results = NULL;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to find session");
		response_error = ENOENT;
		goto done;
	}

	if (payload == NULL) {
		NETAGENTLOG0(LOG_ERR, "No payload received");
		response_error = EINVAL;
		goto done;
	}

	if (session->wrapper == NULL) {
		NETAGENTLOG0(LOG_ERR, "Session has no agent to get");
		response_error = ENOENT;
		goto done;
	}

	if (payload_length < sizeof(uuid_t)) {
		NETAGENTLOG0(LOG_ERR, "Assign message is too short");
		response_error = EINVAL;
		goto done;
	}

	memcpy(client_id, assign_nexus_netagent->assign_client_id, sizeof(client_id));
	size_t assigned_results_length = (payload_length - sizeof(client_id));

	if (assigned_results_length > 0) {
		MALLOC(assigned_results, u_int8_t *, assigned_results_length, M_NETAGENT, M_WAITOK);
		if (assigned_results == NULL) {
			NETAGENTLOG(LOG_ERR, "Failed to allocate assign message (%lu bytes)", assigned_results_length);
			response_error = ENOMEM;
			goto done;
		}
		memcpy(assigned_results, assign_nexus_netagent->assign_necp_results, assigned_results_length);
	}

	// Note that if the error is 0, NECP has taken over our malloc'ed buffer
	response_error = necp_assign_client_result(session->wrapper->netagent.netagent_uuid, client_id, assigned_results, assigned_results_length);
	if (response_error) {
		// necp_assign_client_result returns POSIX errors
		if (assigned_results) {
			FREE(assigned_results, M_NETAGENT);
		}
		NETAGENTLOG(LOG_ERR, "Client assignment failed: %d", response_error);
		goto done;
	}

	NETAGENTLOG0(LOG_DEBUG, "Agent assigned nexus properties to client");
done:
	return response_error;
}


static void
netagent_handle_assign_nexus_message(struct netagent_session *session, u_int32_t message_id,
									 u_int32_t payload_length, mbuf_t packet, int offset)
{
	int error = 0;
	u_int32_t response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
	uuid_t client_id;
	u_int8_t *assigned_results = NULL;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to find session");
		response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
		goto fail;
	}

	if (session->wrapper == NULL) {
		NETAGENTLOG0(LOG_ERR, "Session has no agent to get");
		response_error = NETAGENT_MESSAGE_ERROR_NOT_REGISTERED;
		goto fail;
	}

	if (payload_length < sizeof(uuid_t)) {
		NETAGENTLOG0(LOG_ERR, "Assign message is too short");
		response_error = NETAGENT_MESSAGE_ERROR_INVALID_DATA;
		goto fail;
	}

	error = mbuf_copydata(packet, offset, sizeof(client_id), &client_id);
	if (error) {
		NETAGENTLOG(LOG_ERR, "Failed to read uuid for assign message: %d", error);
		response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
		goto fail;
	}

	size_t assigned_results_length = (payload_length - sizeof(client_id));
	if (assigned_results_length > 0) {
		MALLOC(assigned_results, u_int8_t *, assigned_results_length, M_NETAGENT, M_WAITOK);
		if (assigned_results == NULL) {
			NETAGENTLOG(LOG_ERR, "Failed to allocate assign message (%lu bytes)", assigned_results_length);
			response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
			goto fail;
		}

		error = mbuf_copydata(packet, offset + sizeof(client_id), assigned_results_length, assigned_results);
		if (error) {
			FREE(assigned_results, M_NETAGENT);
			NETAGENTLOG(LOG_ERR, "Failed to read assign message: %d", error);
			response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
			goto fail;
		}
	}

	// Note that if the error is 0, NECP has taken over our malloc'ed buffer
	error = necp_assign_client_result(session->wrapper->netagent.netagent_uuid, client_id, assigned_results, assigned_results_length);
	if (error) {
		if (assigned_results) {
			FREE(assigned_results, M_NETAGENT);
		}
		NETAGENTLOG(LOG_ERR, "Client assignment failed: %d", error);
		response_error = NETAGENT_MESSAGE_ERROR_CANNOT_ASSIGN;
		goto fail;
	}

	NETAGENTLOG0(LOG_DEBUG, "Agent assigned nexus properties to client");
	netagent_send_success_response(session, NETAGENT_MESSAGE_TYPE_ASSIGN_NEXUS, message_id);
	return;
fail:
	netagent_send_error_response(session, NETAGENT_MESSAGE_TYPE_ASSIGN_NEXUS, message_id, response_error);
}

errno_t
netagent_handle_use_count_setopt(struct netagent_session *session, u_int8_t *payload, size_t payload_length)
{
	errno_t response_error = 0;
	uint64_t use_count = 0;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to find session");
		response_error = ENOENT;
		goto done;
	}

	if (payload == NULL) {
		NETAGENTLOG0(LOG_ERR, "No payload received");
		response_error = EINVAL;
		goto done;
	}

	if (payload_length != sizeof(use_count)) {
		NETAGENTLOG(LOG_ERR, "Payload length is invalid (%lu)", payload_length);
		response_error = EINVAL;
		goto done;
	}

	memcpy(&use_count, payload, sizeof(use_count));

	lck_rw_lock_shared(&netagent_lock);

	if (session->wrapper == NULL) {
		NETAGENTLOG0(LOG_ERR, "Session has no agent registered");
		response_error = ENOENT;
		lck_rw_done(&netagent_lock);
		goto done;
	}

	session->wrapper->use_count = use_count;

	lck_rw_done(&netagent_lock);

done:
	return response_error;
}

errno_t
netagent_handle_use_count_getopt(struct netagent_session *session, u_int8_t *buffer, size_t *buffer_length)
{
	errno_t response_error = 0;
	uint64_t use_count = 0;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to find session");
		response_error = ENOENT;
		goto done;
	}

	if (buffer == NULL) {
		NETAGENTLOG0(LOG_ERR, "No payload received");
		response_error = EINVAL;
		goto done;
	}

	if (*buffer_length != sizeof(use_count)) {
		NETAGENTLOG(LOG_ERR, "Buffer length is invalid (%lu)", *buffer_length);
		response_error = EINVAL;
		goto done;
	}

	lck_rw_lock_shared(&netagent_lock);

	if (session->wrapper == NULL) {
		NETAGENTLOG0(LOG_ERR, "Session has no agent registered");
		response_error = ENOENT;
		lck_rw_done(&netagent_lock);
		goto done;
	}

	use_count = session->wrapper->use_count;
	lck_rw_done(&netagent_lock);

	memcpy(buffer, &use_count, sizeof(use_count));
	*buffer_length = sizeof(use_count);

done:
	return response_error;
}

static struct netagent_wrapper *
netagent_find_agent_with_uuid(uuid_t uuid)
{
	struct netagent_wrapper *search_netagent = NULL;

	LIST_FOREACH(search_netagent, &master_netagent_list, master_chain) {
		if (uuid_compare(search_netagent->netagent.netagent_uuid, uuid) == 0) {
			return (search_netagent);
		}
	}

	return (NULL);
}

void
netagent_post_updated_interfaces(uuid_t uuid)
{
	struct netagent_wrapper *wrapper = NULL;
	lck_rw_lock_shared(&netagent_lock);
	wrapper = netagent_find_agent_with_uuid(uuid);
	lck_rw_done(&netagent_lock);

	if (wrapper != NULL) {
		netagent_post_event(uuid, KEV_NETAGENT_UPDATED_INTERFACES, TRUE);
	} else {
		NETAGENTLOG0(LOG_DEBUG, "Interface event with no associated agent");
	}

	return;
}

static u_int32_t
netagent_dump_get_data_size_locked()
{
	struct netagent_wrapper *search_netagent = NULL;
	u_int32_t total_netagent_data_size = 0;
	// Traverse the master list to know how much data the client needs to allocate to get the list of agent UUIDs
	LIST_FOREACH(search_netagent, &master_netagent_list, master_chain) {
		total_netagent_data_size += sizeof(search_netagent->netagent.netagent_uuid);
	}
	return total_netagent_data_size;
}

static void
netagent_dump_copy_data_locked(u_int8_t *buffer, u_int32_t buffer_length)
{
	size_t response_size = 0;
	u_int8_t *cursor = NULL;
	struct netagent_wrapper *search_netagent = NULL;

	response_size = buffer_length; // We already know that buffer_length is the same as total_netagent_data_size.
	cursor = buffer;
	LIST_FOREACH(search_netagent, &master_netagent_list, master_chain) {
		memcpy(cursor, search_netagent->netagent.netagent_uuid, sizeof(search_netagent->netagent.netagent_uuid));
		cursor += sizeof(search_netagent->netagent.netagent_uuid);
	}
}

int
netagent_ioctl(u_long cmd, caddr_t data)
{
	int error = 0;

	switch (cmd) {
		case SIOCGIFAGENTLIST32:
		case SIOCGIFAGENTLIST64: {
			/* Check entitlement if the client requests agent dump */
			errno_t cred_result = priv_check_cred(kauth_cred_get(), PRIV_NET_PRIVILEGED_NECP_POLICIES, 0);
			if (cred_result != 0) {
				NETAGENTLOG0(LOG_ERR, "Client does not hold the necessary entitlement to get netagent information");
				return EINVAL;
			}
			break;
		}
		default:
			break;
	}

	lck_rw_lock_shared(&netagent_lock);
	switch (cmd) {
		case SIOCGIFAGENTDATA32: {
			struct netagent_req32 *ifsir32 = (struct netagent_req32 *)(void *)data;
			struct netagent_wrapper *wrapper = netagent_find_agent_with_uuid(ifsir32->netagent_uuid);
			if (wrapper == NULL) {
				error = ENOENT;
				break;
			}
			uuid_copy(ifsir32->netagent_uuid, wrapper->netagent.netagent_uuid);
			memcpy(ifsir32->netagent_domain, wrapper->netagent.netagent_domain, sizeof(ifsir32->netagent_domain));
			memcpy(ifsir32->netagent_type, wrapper->netagent.netagent_type, sizeof(ifsir32->netagent_type));
			memcpy(ifsir32->netagent_desc, wrapper->netagent.netagent_desc, sizeof(ifsir32->netagent_desc));
			ifsir32->netagent_flags = wrapper->netagent.netagent_flags;
			if (ifsir32->netagent_data_size == 0) {
				// First pass, client wants data size
				ifsir32->netagent_data_size = wrapper->netagent.netagent_data_size;
			} else if (ifsir32->netagent_data != USER_ADDR_NULL &&
					   ifsir32->netagent_data_size == wrapper->netagent.netagent_data_size) {
				// Second pass, client wants data buffer filled out
				error = copyout(wrapper->netagent.netagent_data, ifsir32->netagent_data, wrapper->netagent.netagent_data_size);
			} else {
				error = EINVAL;
			}
			break;
		}
		case SIOCGIFAGENTDATA64: {
			struct netagent_req64 *ifsir64 = (struct netagent_req64 *)(void *)data;
			struct netagent_wrapper *wrapper = netagent_find_agent_with_uuid(ifsir64->netagent_uuid);
			if (wrapper == NULL) {
				error = ENOENT;
				break;
			}
			uuid_copy(ifsir64->netagent_uuid, wrapper->netagent.netagent_uuid);
			memcpy(ifsir64->netagent_domain, wrapper->netagent.netagent_domain, sizeof(ifsir64->netagent_domain));
			memcpy(ifsir64->netagent_type, wrapper->netagent.netagent_type, sizeof(ifsir64->netagent_type));
			memcpy(ifsir64->netagent_desc, wrapper->netagent.netagent_desc, sizeof(ifsir64->netagent_desc));
			ifsir64->netagent_flags = wrapper->netagent.netagent_flags;
			if (ifsir64->netagent_data_size == 0) {
				// First pass, client wants data size
				ifsir64->netagent_data_size = wrapper->netagent.netagent_data_size;
			} else if (ifsir64->netagent_data != USER_ADDR_NULL &&
					   ifsir64->netagent_data_size == wrapper->netagent.netagent_data_size) {
				// Second pass, client wants data buffer filled out
				error = copyout(wrapper->netagent.netagent_data, ifsir64->netagent_data, wrapper->netagent.netagent_data_size);
			} else {
				error = EINVAL;
			}
			break;
		}
		case SIOCGIFAGENTLIST32: {
			struct netagentlist_req32 *ifsir32 = (struct netagentlist_req32 *)(void *)data;
			if (ifsir32->data_size == 0) {
				// First pass, client wants data size
				ifsir32->data_size = netagent_dump_get_data_size_locked();
			} else if (ifsir32->data != USER_ADDR_NULL &&
						ifsir32->data_size > 0 &&
						ifsir32->data_size == netagent_dump_get_data_size_locked()) {
				// Second pass, client wants data buffer filled out
				u_int8_t *response = NULL;
				MALLOC(response, u_int8_t *, ifsir32->data_size, M_NETAGENT, M_NOWAIT | M_ZERO);
				if (response == NULL) {
					error = ENOMEM;
					break;
				}

				netagent_dump_copy_data_locked(response, ifsir32->data_size);
				error = copyout(response, ifsir32->data, ifsir32->data_size);
				FREE(response, M_NETAGENT);
			} else {
				error = EINVAL;
			}
			break;
		}
		case SIOCGIFAGENTLIST64: {
			struct netagentlist_req64 *ifsir64 = (struct netagentlist_req64 *)(void *)data;
			if (ifsir64->data_size == 0) {
				// First pass, client wants data size
				ifsir64->data_size = netagent_dump_get_data_size_locked();
			} else if (ifsir64->data != USER_ADDR_NULL &&
				ifsir64->data_size > 0 &&
				ifsir64->data_size == netagent_dump_get_data_size_locked()) {
				// Second pass, client wants data buffer filled out
				u_int8_t *response = NULL;
				MALLOC(response, u_int8_t *, ifsir64->data_size, M_NETAGENT, M_NOWAIT | M_ZERO);
				if (response == NULL) {
					error = ENOMEM;
					break;
				}

				netagent_dump_copy_data_locked(response, ifsir64->data_size);
				error = copyout(response, ifsir64->data, ifsir64->data_size);
				FREE(response, M_NETAGENT);
			} else {
				error = EINVAL;
			}
			break;
		}
		default: {
			error = EINVAL;
			break;
		}
	}
	lck_rw_done(&netagent_lock);
	return (error);
}

u_int32_t
netagent_get_flags(uuid_t uuid)
{
	u_int32_t flags = 0;
	lck_rw_lock_shared(&netagent_lock);
	struct netagent_wrapper *wrapper = netagent_find_agent_with_uuid(uuid);
	if (wrapper != NULL) {
		flags = wrapper->netagent.netagent_flags;
	} else {
		NETAGENTLOG0(LOG_DEBUG, "Flags requested for invalid netagent");
	}
	lck_rw_done(&netagent_lock);

	return (flags);
}

u_int32_t
netagent_get_generation(uuid_t uuid)
{
	u_int32_t generation = 0;
	lck_rw_lock_shared(&netagent_lock);
	struct netagent_wrapper *wrapper = netagent_find_agent_with_uuid(uuid);
	if (wrapper != NULL) {
		generation = wrapper->generation;
	} else {
		NETAGENTLOG0(LOG_DEBUG, "Generation requested for invalid netagent");
	}
	lck_rw_done(&netagent_lock);

	return (generation);
}

bool
netagent_get_agent_domain_and_type(uuid_t uuid, char *domain, char *type)
{
	bool found = FALSE;
	if (domain == NULL || type == NULL) {
		NETAGENTLOG(LOG_ERR, "Invalid arguments for netagent_get_agent_domain_and_type %p %p", domain, type);
		return (FALSE);
	}

	lck_rw_lock_shared(&netagent_lock);
	struct netagent_wrapper *wrapper = netagent_find_agent_with_uuid(uuid);
	if (wrapper != NULL) {
		found = TRUE;
		memcpy(domain, wrapper->netagent.netagent_domain, NETAGENT_DOMAINSIZE);
		memcpy(type, wrapper->netagent.netagent_type, NETAGENT_TYPESIZE);
	} else {
		NETAGENTLOG0(LOG_DEBUG, "Type requested for invalid netagent");
	}
	lck_rw_done(&netagent_lock);

	return (found);
}

int
netagent_kernel_trigger(uuid_t uuid)
{
	int error = 0;

	lck_rw_lock_shared(&netagent_lock);
	struct netagent_wrapper *wrapper = netagent_find_agent_with_uuid(uuid);
	if (wrapper == NULL) {
		NETAGENTLOG0(LOG_ERR, "Requested netagent for kernel trigger could not be found");
		error = ENOENT;
		goto done;
	}

	if ((wrapper->netagent.netagent_flags & NETAGENT_FLAG_KERNEL_ACTIVATED) == 0) {
		NETAGENTLOG0(LOG_ERR, "Requested netagent for kernel trigger is not kernel activated");
		// Agent does not accept kernel triggers
		error = EINVAL;
		goto done;
	}

	if ((wrapper->netagent.netagent_flags & NETAGENT_FLAG_ACTIVE)) {
		// Agent already active
		NETAGENTLOG0(LOG_INFO, "Requested netagent for kernel trigger is already active");
		error = 0;
		goto done;
	}

	error = netagent_send_trigger(wrapper, current_proc(), NETAGENT_TRIGGER_FLAG_KERNEL, NETAGENT_MESSAGE_TYPE_TRIGGER);
	NETAGENTLOG((error ? LOG_ERR : LOG_INFO), "Triggered netagent from kernel (error %d)", error);
done:
	lck_rw_done(&netagent_lock);
	return (error);
}

int
netagent_client_message_with_params(uuid_t agent_uuid,
									uuid_t necp_client_uuid,
									pid_t pid,
									u_int8_t message_type,
									struct necp_client_nexus_parameters *parameters,
									void **assigned_results,
									size_t *assigned_results_length)
{
	int error = 0;

	if (message_type != NETAGENT_MESSAGE_TYPE_CLIENT_TRIGGER &&
		message_type != NETAGENT_MESSAGE_TYPE_CLIENT_ASSERT &&
		message_type != NETAGENT_MESSAGE_TYPE_CLIENT_UNASSERT &&
		message_type != NETAGENT_MESSAGE_TYPE_REQUEST_NEXUS &&
		message_type != NETAGENT_MESSAGE_TYPE_CLOSE_NEXUS &&
		message_type != NETAGENT_MESSAGE_TYPE_ABORT_NEXUS) {
		NETAGENTLOG(LOG_ERR, "Client netagent message type (%d) is invalid", message_type);
		return(EINVAL);
	}

	lck_rw_lock_shared(&netagent_lock);
	bool should_unlock = TRUE;
	struct netagent_wrapper *wrapper = netagent_find_agent_with_uuid(agent_uuid);
	if (wrapper == NULL) {
		NETAGENTLOG0(LOG_DEBUG, "Requested netagent for nexus instance could not be found");
		error = ENOENT;
		goto done;
	}

	if (message_type == NETAGENT_MESSAGE_TYPE_CLIENT_TRIGGER) {
		if ((wrapper->netagent.netagent_flags & NETAGENT_FLAG_USER_ACTIVATED) == 0) {
			// Agent does not accept user triggers
			// Don't log, since this is a common case used to trigger events that cellular data is blocked, etc.
			error = ENOTSUP;


			pid_t report_pid = 0;
			uuid_t report_proc_uuid = {};
			if (parameters != NULL) {
				report_pid = parameters->epid;
				uuid_copy(report_proc_uuid, parameters->euuid);
			} else {
				struct proc *p = current_proc();
				if (p != NULL) {
					report_pid = proc_pid(p);
					proc_getexecutableuuid(p, report_proc_uuid, sizeof(report_proc_uuid));
				}
			}
			netagent_send_cellular_failed_event(wrapper, report_pid, report_proc_uuid);
			goto done;
		}
	} else if (message_type == NETAGENT_MESSAGE_TYPE_REQUEST_NEXUS ||
			   message_type == NETAGENT_MESSAGE_TYPE_CLOSE_NEXUS ||
			   message_type == NETAGENT_MESSAGE_TYPE_ABORT_NEXUS) {
		if ((wrapper->netagent.netagent_flags & NETAGENT_FLAG_NEXUS_PROVIDER) == 0) {
			NETAGENTLOG0(LOG_ERR, "Requested netagent for nexus instance is not a nexus provider");
			// Agent is not a nexus provider
			error = EINVAL;
			goto done;
		}

		if ((wrapper->netagent.netagent_flags & NETAGENT_FLAG_ACTIVE) == 0) {
			// Agent not active
			NETAGENTLOG0(LOG_INFO, "Requested netagent for nexus instance is not active");
			error = EINVAL;
			goto done;
		}
	}

	if (wrapper->control_unit == 0) {
		should_unlock = FALSE;
		lck_rw_done(&netagent_lock);
		if (wrapper->event_handler == NULL) {
			// No event handler registered for kernel agent
			error = EINVAL;
		} else {
			error = wrapper->event_handler(message_type, necp_client_uuid, pid, wrapper->event_context, parameters, assigned_results, assigned_results_length);
			if (error != 0) {
				VERIFY(assigned_results == NULL || *assigned_results == NULL);
				VERIFY(assigned_results_length == NULL || *assigned_results_length == 0);
			}
		}
	} else {
		// ABORT_NEXUS is kernel-private, so translate it for userspace nexus
		if (message_type == NETAGENT_MESSAGE_TYPE_ABORT_NEXUS) {
			message_type = NETAGENT_MESSAGE_TYPE_CLOSE_NEXUS;
		}

		error = netagent_send_client_message(wrapper, necp_client_uuid, message_type);
		if (error == 0 && message_type == NETAGENT_MESSAGE_TYPE_CLIENT_TRIGGER) {
			if (lck_rw_lock_shared_to_exclusive(&netagent_lock)) {
				// Grab the lock exclusively to add a pending client to the list
				struct netagent_client *new_pending_client = NULL;
				MALLOC(new_pending_client, struct netagent_client *, sizeof(*new_pending_client), M_NETAGENT, M_WAITOK);
				if (new_pending_client == NULL) {
					NETAGENTLOG0(LOG_ERR, "Failed to allocate client for trigger");
				} else {
					uuid_copy(new_pending_client->client_id, necp_client_uuid);
					if (parameters != NULL) {
						new_pending_client->client_pid = parameters->epid;
						uuid_copy(new_pending_client->client_proc_uuid, parameters->euuid);
					} else {
						struct proc *p = current_proc();
						if (p != NULL) {
							new_pending_client->client_pid = proc_pid(p);
							proc_getexecutableuuid(p, new_pending_client->client_proc_uuid, sizeof(new_pending_client->client_proc_uuid));
						}
					}
					LIST_INSERT_HEAD(&wrapper->pending_triggers_list, new_pending_client, client_chain);
				}
			} else {
				// If lck_rw_lock_shared_to_exclusive fails, it unlocks automatically
				should_unlock = FALSE;
			}
		}
	}
	NETAGENTLOG(((error && error != ENOENT) ? LOG_ERR : LOG_INFO), "Send message %d for client (error %d)", message_type, error);
	if (message_type == NETAGENT_MESSAGE_TYPE_CLIENT_TRIGGER) {
		uuid_string_t uuid_str;
		uuid_unparse(agent_uuid, uuid_str);
		NETAGENTLOG(LOG_NOTICE, "Triggered network agent %s, error = %d", uuid_str, error);
	}
done:
	if (should_unlock) {
		lck_rw_done(&netagent_lock);
	}
	return (error);
}

int
netagent_client_message(uuid_t agent_uuid, uuid_t necp_client_uuid, pid_t pid, u_int8_t message_type)
{
	return (netagent_client_message_with_params(agent_uuid, necp_client_uuid, pid, message_type, NULL, NULL, NULL));
}

int
netagent_use(uuid_t agent_uuid, uint64_t *out_use_count)
{
	int error = 0;

	lck_rw_lock_exclusive(&netagent_lock);
	struct netagent_wrapper *wrapper = netagent_find_agent_with_uuid(agent_uuid);
	if (wrapper == NULL) {
		NETAGENTLOG0(LOG_ERR, "netagent_assert: Requested netagent UUID is not registered");
		error = ENOENT;
		goto done;
	}

	uint64_t current_count = wrapper->use_count;
	wrapper->use_count++;

	if (out_use_count != NULL) {
		*out_use_count = current_count;
	}

done:
	lck_rw_done(&netagent_lock);
	return (error);
}

int
netagent_copyout(uuid_t agent_uuid, user_addr_t user_addr, u_int32_t user_size)
{
	int error = 0;

	lck_rw_lock_shared(&netagent_lock);
	struct netagent_wrapper *wrapper = netagent_find_agent_with_uuid(agent_uuid);
	if (wrapper == NULL) {
		NETAGENTLOG0(LOG_DEBUG, "Requested netagent for nexus instance could not be found");
		error = ENOENT;
		goto done;
	}

	u_int32_t total_size = (sizeof(struct netagent) + wrapper->netagent.netagent_data_size);
	if (user_size < total_size) {
		NETAGENTLOG(LOG_ERR, "Provided user buffer is too small (%u < %u)", user_size, total_size);
		error = EINVAL;
		goto done;
	}

	error = copyout(&wrapper->netagent, user_addr, total_size);

	NETAGENTLOG((error ? LOG_ERR : LOG_DEBUG), "Copied agent content (error %d)", error);
done:
	lck_rw_done(&netagent_lock);
	return (error);
}

int
netagent_trigger(struct proc *p, struct netagent_trigger_args *uap, int32_t *retval)
{
#pragma unused(p, retval)
	uuid_t agent_uuid;
	int error = 0;

	if (uap == NULL) {
		NETAGENTLOG0(LOG_ERR, "uap == NULL");
		return (EINVAL);
	}

	if (uap->agent_uuid) {
		if (uap->agent_uuidlen != sizeof(uuid_t)) {
			NETAGENTLOG(LOG_ERR, "Incorrect length (got %llu, expected %lu)",
						uap->agent_uuidlen, sizeof(uuid_t));
			return (ERANGE);
		}

		error = copyin(uap->agent_uuid, agent_uuid, sizeof(uuid_t));
		if (error) {
			NETAGENTLOG(LOG_ERR, "copyin error (%d)", error);
			return (error);
		}
	}

	if (uuid_is_null(agent_uuid)) {
		NETAGENTLOG0(LOG_ERR, "Requested netagent UUID is empty");
		return (EINVAL);
	}

	lck_rw_lock_shared(&netagent_lock);
	struct netagent_wrapper *wrapper = netagent_find_agent_with_uuid(agent_uuid);
	if (wrapper == NULL) {
		NETAGENTLOG0(LOG_ERR, "Requested netagent UUID is not registered");
		error = ENOENT;
		goto done;
	}

	if ((wrapper->netagent.netagent_flags & NETAGENT_FLAG_USER_ACTIVATED) == 0) {
		// Agent does not accept triggers
		NETAGENTLOG0(LOG_ERR, "Requested netagent UUID is not eligible for triggering");
		error = ENOTSUP;
		goto done;
	}

	if ((wrapper->netagent.netagent_flags & NETAGENT_FLAG_ACTIVE)) {
		// Agent already active
		NETAGENTLOG0(LOG_INFO, "Requested netagent UUID is already active");
		error = 0;
		goto done;
	}

	error = netagent_send_trigger(wrapper, p, NETAGENT_TRIGGER_FLAG_USER, NETAGENT_MESSAGE_TYPE_TRIGGER);
	NETAGENTLOG((error ? LOG_ERR : LOG_INFO), "Triggered netagent (error %d)", error);
done:
	lck_rw_done(&netagent_lock);
	return (error);
}
