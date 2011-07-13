/*
 * Copyright (c) 2008 Apple Inc. All rights reserved.
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
#include <mach/mach_types.h>
#include <mach/notify.h>
#include <ipc/ipc_port.h>
#include <kern/ipc_kobject.h>
#include <kern/audit_sessionport.h>
#include <libkern/OSAtomic.h>

#if CONFIG_AUDIT
/*
 * audit_session_mksend
 *
 * Description: Obtain a send right for given audit session.
 *
 * Parameters:	*aia_p		Audit session information to assosiate with
 * 				the new port.
 * 		*sessionport	Pointer to the current session port.  This may
 * 				actually be set to IPC_PORT_NULL.
 *
 * Returns:	!NULL		Resulting send right.	
 * 		NULL		Failed to allocate port (due to lack of memory
 * 				resources).

 * Assumptions: Caller holds a reference on the session during the call.
 *		If there were no outstanding send rights against the port,
 *		hold a reference on the session and arm a new no-senders
 *		notification to determine when to release that reference.
 *		Otherwise, by creating an additional send right, we share
 *		the port's reference until all send rights go away.
 */
ipc_port_t
audit_session_mksend(struct auditinfo_addr *aia_p, ipc_port_t *sessionport)
{
	ipc_port_t sendport = IPC_PORT_NULL;
	ipc_port_t port;

	/*
	 * If we don't have an existing session port, then create one.
	 */
	port = *sessionport;
	if (!IP_VALID(port)) {
		ipc_port_t new_port = ipc_port_alloc_kernel();
		if (!IP_VALID(new_port))
			return new_port;
		ipc_kobject_set(new_port, (ipc_kobject_t)aia_p, IKOT_AU_SESSIONPORT);
		if (!OSCompareAndSwapPtr(port, new_port, sessionport))
			ipc_port_dealloc_kernel(new_port);
		port = *sessionport;
	}

	assert(ip_active(port) && IKOT_AU_SESSIONPORT == ip_kotype(port));
	sendport = ipc_port_make_send(port);

	/*
	 * If we don't have a no-senders notification outstanding against
	 * the port, take a reference on the session and request one.
	 */
	if (IP_NULL == port->ip_nsrequest) {
		ipc_port_t notifyport;

		audit_session_aiaref(aia_p);

		/* Need a send-once right for the target of the notification */
		notifyport = ipc_port_make_sonce(port);

		/* Request a no-senders notification (at the new make-send threshold) */
		ip_lock(port);
		ipc_port_nsrequest(port, port->ip_mscount, notifyport, &notifyport);
		/* port unlocked */

		if (IP_NULL != notifyport) {
			/* race requesting notification */
			audit_session_aiaunref(aia_p);
			ipc_port_release_sonce(notifyport);
		}
	}

	return (sendport);
}


/*
 * audit_session_porttoaia
 *
 * Description: Obtain the audit session info associated with the given port.
 
 * Parameters: port		A Mach port.
 *
 * Returns:    NULL		The given Mach port did not reference audit
 * 				session info.
 *	       !NULL		The audit session info that is associated with
 *				the Mach port.
 *
 * Notes: The caller must have a reference on the sessionport.
 */
struct auditinfo_addr *
audit_session_porttoaia(ipc_port_t port)
{
	struct auditinfo_addr *aia_p = NULL;

	if (IP_VALID(port)) {
		ip_lock(port);
		if (IKOT_AU_SESSIONPORT == ip_kotype(port)) {
			assert(ip_active(port));
			aia_p = (struct auditinfo_addr *)port->ip_kobject;
		}
		ip_unlock(port);
	}

	return (aia_p);
}


/*
 * audit_session_nosenders
 *
 * Description: Handle a no-senders notification for a sessionport.
 *
 * Parameters: msg		A Mach no-senders notification message.
 *
 * Notes: It is possible that new send rights are created after a
 *	  no-senders notification has been sent (i.e. via audit_session_mksend).
 *	  We check the port's mscount against the notification's not_count
 *	  to detect when this happens, and re-arm the notification in that
 *	  case.
 *
 *	  In the normal case (no new senders), we first mark the port
 *	  as dying by setting its object type to IKOT_NONE so that
 *	  audit_session_mksend will no longer use it to create
 *	  additional send rights.  We can then safely call
 *	  audit_session_port_destroy with no locks.
 */
void
audit_session_nosenders(mach_msg_header_t *msg)
{
	mach_no_senders_notification_t *notification = (void *)msg;
	ipc_port_t port = notification->not_header.msgh_remote_port;
	ipc_port_t notifyport;
	struct auditinfo_addr *port_aia_p = NULL;

	assert(IKOT_AU_SESSIONPORT == ip_kotype(port));
	ip_lock(port);
	assert(ip_active(port));
	port_aia_p = (struct auditinfo_addr *)port->ip_kobject;
	assert(NULL != port_aia_p);

	/*
	 * if new send rights have been made since the last notify
	 * request, re-arm the notification with the new threshold.
	 */
	if (port->ip_mscount > notification->not_count) {
		ip_unlock(port);
		notifyport = ipc_port_make_sonce(port);
		ip_lock(port);
		ipc_port_nsrequest(port, port->ip_mscount, notifyport, &notifyport);
		/* port unlocked */

		if (IP_NULL != notifyport) {
			/* race re-arming the notification */
			ipc_port_release_sonce(notifyport);
			audit_session_aiaunref(port_aia_p);
		}
		return;
	}

	/*
	 * Otherwise, no more extant send rights, so release the
	 * reference held on the session by those send rights.
	 */
	ip_unlock(port);
	audit_session_aiaunref(port_aia_p);
}

void
audit_session_portdestroy(ipc_port_t *sessionport)
{
	ipc_port_t port = *sessionport;

	if (IP_VALID(port)) {
		assert (ip_active(port));
		assert(IKOT_AU_SESSIONPORT == ip_kotype(port));
		ipc_kobject_set_atomically(port, IKO_NULL, IKOT_NONE);
		ipc_port_dealloc_kernel(port);
		*sessionport = IP_NULL;
	}
}
#endif /* CONFIG_AUDIT */
