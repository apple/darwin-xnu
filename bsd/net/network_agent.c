/*
 * Copyright (c) 2014 Apple Inc. All rights reserved.
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

struct netagent_assertion {
	LIST_ENTRY(netagent_assertion) assertion_chain;
	uuid_t asserted_uuid;
};

struct netagent_wrapper {
	LIST_ENTRY(netagent_wrapper) master_chain;
	u_int32_t control_unit;
	struct netagent netagent;
};

struct netagent_session {
	u_int32_t control_unit;
	struct netagent_wrapper *wrapper;
	LIST_HEAD(_netagent_assertion_list, netagent_assertion) assertion_list;
};

static LIST_HEAD(_netagent_list, netagent_wrapper) master_netagent_list;

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

static void netagent_handle_register(struct netagent_session *session, u_int32_t message_id,
									 u_int32_t payload_length, mbuf_t packet, int offset);
static void netagent_handle_unregister(struct netagent_session *session, u_int32_t message_id,
									   u_int32_t payload_length, mbuf_t packet, int offset);
static void netagent_handle_update(struct netagent_session *session, u_int32_t message_id,
								   u_int32_t payload_length, mbuf_t packet, int offset);
static void netagent_handle_get(struct netagent_session *session, u_int32_t message_id,
								u_int32_t payload_length, mbuf_t packet, int offset);
static void netagent_handle_assert(struct netagent_session *session, u_int32_t message_id,
								   u_int32_t payload_length, mbuf_t packet, int offset);
static void netagent_handle_unassert(struct netagent_session *session, u_int32_t message_id,
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
netagent_post_event(uuid_t agent_uuid, u_int32_t event_code)
{
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
			netagent_handle_register(session, header.message_id, header.message_payload_length,
									 packet, sizeof(header));
			break;
		}
		case NETAGENT_MESSAGE_TYPE_UNREGISTER: {
			netagent_handle_unregister(session, header.message_id, header.message_payload_length,
									   packet, sizeof(header));
			break;
		}
		case NETAGENT_MESSAGE_TYPE_UPDATE: {
			netagent_handle_update(session, header.message_id, header.message_payload_length,
								   packet, sizeof(header));
			break;
		}
		case NETAGENT_MESSAGE_TYPE_GET: {
			netagent_handle_get(session, header.message_id, header.message_payload_length,
								packet, sizeof(header));
			break;
		}
		case NETAGENT_MESSAGE_TYPE_ASSERT: {
			netagent_handle_assert(session, header.message_id, header.message_payload_length,
								packet, sizeof(header));
			break;
		}
		case NETAGENT_MESSAGE_TYPE_UNASSERT: {
			netagent_handle_unassert(session, header.message_id, header.message_payload_length,
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
#pragma unused(kctlref, unit, unitinfo, opt, data, len)
	return (0);
}

static errno_t
netagent_ctl_setopt(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, int opt,
					void *data, size_t len)
{
#pragma unused(kctlref, unit, unitinfo, opt, data, len)
	return (0);
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
	LIST_INIT(&new_session->assertion_list);
	new_session->wrapper = NULL;
done:
	return (new_session);
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

			FREE(wrapper, M_NETAGENT);
			session->wrapper = NULL;
			NETAGENTLOG0(LOG_DEBUG, "Unregistered agent");
		}
	}
	lck_rw_done(&netagent_lock);

	if (unregistered) {
		netagent_post_event(unregistered_uuid, KEV_NETAGENT_UNREGISTERED);
		ifnet_clear_netagent(unregistered_uuid);
	}
}

static void
netagent_delete_session(struct netagent_session *session)
{
	if (session != NULL) {
		netagent_unregister_session_wrapper(session);

		// Unassert any pending assertions
		lck_rw_lock_shared(&netagent_lock);
		struct netagent_assertion *search_assertion = NULL;
		struct netagent_assertion *temp_assertion = NULL;
		LIST_FOREACH_SAFE(search_assertion, &session->assertion_list, assertion_chain, temp_assertion) {
			struct netagent_wrapper *wrapper = netagent_find_agent_with_uuid(search_assertion->asserted_uuid);
			if (wrapper != NULL) {
				netagent_send_trigger(wrapper, current_proc(), NETAGENT_TRIGGER_FLAG_USER, NETAGENT_MESSAGE_TYPE_TRIGGER_UNASSERT);
			}
			LIST_REMOVE(search_assertion, assertion_chain);
			FREE(search_assertion, M_NETAGENT);
		}
		lck_rw_done(&netagent_lock);

		FREE(session, M_NETAGENT);
	}
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

static void
netagent_handle_register(struct netagent_session *session, u_int32_t message_id,
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
		NETAGENTLOG(LOG_ERR, "Register message size too small for agent: (%d < %d)",
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

	lck_rw_lock_exclusive(&netagent_lock);

	new_wrapper->control_unit = session->control_unit;

	session->wrapper = new_wrapper;
	LIST_INSERT_HEAD(&master_netagent_list, new_wrapper, master_chain);

	new_wrapper->netagent.netagent_flags |= NETAGENT_FLAG_REGISTERED;
	netagent_registered_count++;
	if (new_wrapper->netagent.netagent_flags & NETAGENT_FLAG_ACTIVE) {
		netagent_active_count++;
	}

	lck_rw_done(&netagent_lock);

	NETAGENTLOG0(LOG_DEBUG, "Registered new agent");
	netagent_send_success_response(session, NETAGENT_MESSAGE_TYPE_REGISTER, message_id);
	netagent_post_event(new_wrapper->netagent.netagent_uuid, KEV_NETAGENT_REGISTERED);
	return;
fail:
	netagent_send_error_response(session, NETAGENT_MESSAGE_TYPE_REGISTER, message_id, response_error);
}

static void
netagent_handle_unregister(struct netagent_session *session, u_int32_t message_id,
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
netagent_handle_update(struct netagent_session *session, u_int32_t message_id,
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

	if (session->wrapper == NULL) {
		NETAGENTLOG0(LOG_ERR, "Session has no agent to update");
		response_error = NETAGENT_MESSAGE_ERROR_NOT_REGISTERED;
		goto fail;
	}

	if (payload_length < sizeof(struct netagent)) {
		NETAGENTLOG(LOG_ERR, "Update message size too small for agent: (%d < %d)",
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

	lck_rw_lock_exclusive(&netagent_lock);

	if (uuid_compare(session->wrapper->netagent.netagent_uuid, new_wrapper->netagent.netagent_uuid) != 0 ||
		memcmp(&session->wrapper->netagent.netagent_domain, &new_wrapper->netagent.netagent_domain,
			   sizeof(new_wrapper->netagent.netagent_domain)) != 0 ||
		memcmp(&session->wrapper->netagent.netagent_type, &new_wrapper->netagent.netagent_type,
			   sizeof(new_wrapper->netagent.netagent_type)) != 0) {
		NETAGENTLOG0(LOG_ERR, "Basic agent parameters do not match, cannot update");
		FREE(new_wrapper, M_NETAGENT);
		response_error = NETAGENT_MESSAGE_ERROR_CANNOT_UPDATE;
		lck_rw_done(&netagent_lock);
		goto fail;
	}

	new_wrapper->netagent.netagent_flags |= NETAGENT_FLAG_REGISTERED;
	if ((new_wrapper->netagent.netagent_flags & NETAGENT_FLAG_ACTIVE) &&
		!(session->wrapper->netagent.netagent_flags & NETAGENT_FLAG_ACTIVE)) {
		netagent_active_count++;
	} else if (!(new_wrapper->netagent.netagent_flags & NETAGENT_FLAG_ACTIVE) &&
			   (session->wrapper->netagent.netagent_flags & NETAGENT_FLAG_ACTIVE) &&
			   netagent_active_count > 0) {
		netagent_active_count--;
	}

	LIST_REMOVE(session->wrapper, master_chain);
	FREE(session->wrapper, M_NETAGENT);
	session->wrapper = new_wrapper;
	new_wrapper->control_unit = session->control_unit;
	LIST_INSERT_HEAD(&master_netagent_list, new_wrapper, master_chain);

	lck_rw_done(&netagent_lock);

	NETAGENTLOG0(LOG_DEBUG, "Updated agent");
	netagent_send_success_response(session, NETAGENT_MESSAGE_TYPE_UPDATE, message_id);
	netagent_post_event(new_wrapper->netagent.netagent_uuid, KEV_NETAGENT_UPDATED);
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

static void
netagent_handle_assert(struct netagent_session *session, u_int32_t message_id,
					   u_int32_t payload_length, mbuf_t packet, int offset)
{
	int error;
	struct netagent_assertion *new_assertion = NULL;
	u_int32_t response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
	uuid_t netagent_uuid;
	uuid_clear(netagent_uuid);

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to find session");
		response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
		goto fail;
	}

	if (payload_length < sizeof(uuid_t)) {
		NETAGENTLOG(LOG_ERR, "Assert message size too small for uuid: (%d < %d)",
					payload_length, sizeof(uuid_t));
		response_error = NETAGENT_MESSAGE_ERROR_INVALID_DATA;
		goto fail;
	}

	error = mbuf_copydata(packet, offset, sizeof(uuid_t), &netagent_uuid);
	if (error) {
		NETAGENTLOG(LOG_ERR, "Failed to read uuid: %d", error);
		response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
		goto fail;
	}

	MALLOC(new_assertion, struct netagent_assertion *, sizeof(*new_assertion), M_NETAGENT, M_WAITOK);
	if (new_assertion == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to allocate assertion");
		response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
		goto fail;
	}

	uuid_copy(new_assertion->asserted_uuid, netagent_uuid);

	lck_rw_lock_shared(&netagent_lock);

	struct netagent_wrapper *wrapper = netagent_find_agent_with_uuid(netagent_uuid);
	if (wrapper == NULL) {
		lck_rw_done(&netagent_lock);
		response_error = NETAGENT_MESSAGE_ERROR_NOT_REGISTERED;
		FREE(new_assertion, M_NETAGENT);
		goto fail;
	}

	error = netagent_send_trigger(wrapper, current_proc(), NETAGENT_TRIGGER_FLAG_USER, NETAGENT_MESSAGE_TYPE_TRIGGER_ASSERT);
	if (error) {
		lck_rw_done(&netagent_lock);
		NETAGENTLOG(LOG_ERR, "Failed to trigger assert agent: %d", error);
		response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
		FREE(new_assertion, M_NETAGENT);
		goto fail;
	}

	LIST_INSERT_HEAD(&session->assertion_list, new_assertion, assertion_chain);

	lck_rw_done(&netagent_lock);

	NETAGENTLOG0(LOG_DEBUG, "Asserted agent");
	netagent_send_success_response(session, NETAGENT_MESSAGE_TYPE_ASSERT, message_id);
	return;
fail:
	netagent_send_error_response(session, NETAGENT_MESSAGE_TYPE_ASSERT, message_id, response_error);
}

static void
netagent_handle_unassert(struct netagent_session *session, u_int32_t message_id,
						 u_int32_t payload_length, mbuf_t packet, int offset)
{
	int error;
	u_int32_t response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
	uuid_t netagent_uuid;
	uuid_clear(netagent_uuid);

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to find session");
		response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
		goto fail;
	}

	if (payload_length < sizeof(uuid_t)) {
		NETAGENTLOG(LOG_ERR, "Unassert message size too small for uuid: (%d < %d)",
					payload_length, sizeof(uuid_t));
		response_error = NETAGENT_MESSAGE_ERROR_INVALID_DATA;
		goto fail;
	}

	error = mbuf_copydata(packet, offset, sizeof(uuid_t), &netagent_uuid);
	if (error) {
		NETAGENTLOG(LOG_ERR, "Failed to read uuid: %d", error);
		response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
		goto fail;
	}

	struct netagent_assertion *found_assertion = NULL;
	struct netagent_assertion *search_assertion = NULL;
	LIST_FOREACH(search_assertion, &session->assertion_list, assertion_chain) {
		if (uuid_compare(search_assertion->asserted_uuid, netagent_uuid) == 0) {
			found_assertion = search_assertion;
			break;
		}
	}

	if (found_assertion == NULL) {
		NETAGENTLOG0(LOG_ERR, "Netagent uuid not previously asserted");
		response_error = NETAGENT_MESSAGE_ERROR_INVALID_DATA;
		goto fail;
	}

	LIST_REMOVE(found_assertion, assertion_chain);
	FREE(found_assertion, M_NETAGENT);
	found_assertion = NULL;

	lck_rw_lock_shared(&netagent_lock);

	struct netagent_wrapper *wrapper = netagent_find_agent_with_uuid(netagent_uuid);
	if (wrapper == NULL) {
		lck_rw_done(&netagent_lock);
		response_error = NETAGENT_MESSAGE_ERROR_NOT_REGISTERED;
		goto fail;
	}

	error = netagent_send_trigger(wrapper, current_proc(), NETAGENT_TRIGGER_FLAG_USER, NETAGENT_MESSAGE_TYPE_TRIGGER_UNASSERT);
	if (error) {
		lck_rw_done(&netagent_lock);
		NETAGENTLOG(LOG_ERR, "Failed to trigger assert agent: %d", error);
		response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
		goto fail;
	}

	lck_rw_done(&netagent_lock);

	NETAGENTLOG0(LOG_DEBUG, "Unasserted agent");
	netagent_send_success_response(session, NETAGENT_MESSAGE_TYPE_UNASSERT, message_id);
	return;
fail:
	netagent_send_error_response(session, NETAGENT_MESSAGE_TYPE_UNASSERT, message_id, response_error);
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
		netagent_post_event(uuid, KEV_NETAGENT_UPDATED_INTERFACES);
	} else {
		NETAGENTLOG0(LOG_DEBUG, "Interface event with no associated agent");
	}

	return;
}

int
netagent_ioctl(u_long cmd, caddr_t data)
{
	int error = 0;

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
			NETAGENTLOG(LOG_ERR, "Incorrect length (got %d, expected %d)",
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
		error = EINVAL;
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
