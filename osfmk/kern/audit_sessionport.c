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

#if CONFIG_AUDIT
/*
 * audit_session_mksend
 *
 * Description: Obtain a send right for given audit session information. 
 *
 * Parameters:	*aia_p		Audit session information to assosiate with
 * 				the new port.
 * 		*sessionport	Pointer to the current session port.  This may
 * 				actually be set to IPC_PORT_NULL.
 *
 * Returns:	!NULL		Resulting send right.	
 * 		NULL		Failed to allocate port (due to lack of memory
 * 				resources).
 *
 * 		*sessionport	The session port that may have been allocated.
 *
 * Notes: On return, sendport will be set to the new send right on success,
 *	  or null/dead on error.
 */
ipc_port_t
audit_session_mksend(struct auditinfo_addr *aia_p, ipc_port_t *sessionport)
{
	ipc_port_t notifyport;
	ipc_port_t sendport = IPC_PORT_NULL;

	/*
	 * If we have an existing, active session port then use it. 
	 */
	sendport = ipc_port_make_send(*sessionport);
	if (IP_VALID(sendport)) {
		ip_lock(sendport);
		if (ip_active(sendport) && 
		    IKOT_AU_SESSIONPORT == ip_kotype(sendport)) {
			ip_unlock(sendport);
			return (sendport);
		}
		ip_unlock(sendport);
		ipc_port_release_send(sendport);
	}

	/*
	 * Otherwise, create a new one for this session.
	 */
	*sessionport = ipc_port_alloc_kernel();
	if (IP_VALID(*sessionport)) {
		ipc_kobject_set(*sessionport, (ipc_kobject_t)aia_p,
		    IKOT_AU_SESSIONPORT);

		/* Request a no-senders notification. */
		notifyport = ipc_port_make_sonce(*sessionport);
		ip_lock(*sessionport);
		/* unlocked by ipc_port_nsrequest */
		ipc_port_nsrequest(*sessionport, 1, notifyport, &notifyport);
	}
	sendport = ipc_port_make_send(*sessionport);

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
		if (ip_active(port) && IKOT_AU_SESSIONPORT == ip_kotype(port))
			aia_p = (struct auditinfo_addr *)port->ip_kobject;
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

	if (!IP_VALID(port))
		return;
	ip_lock(port);
	if (ip_active(port) && IKOT_AU_SESSIONPORT == ip_kotype(port)) {
		port_aia_p = (struct auditinfo_addr *)port->ip_kobject;
		assert(NULL != port_aia_p);
		if (port->ip_mscount <= notification->not_count)
			ipc_kobject_set_atomically(port, IKO_NULL, IKOT_NONE);
		else {
			/* re-arm the notification */
			ip_unlock(port);
			notifyport = ipc_port_make_sonce(port);
			ip_lock(port);
			/* unlocked by ipc_port_nsrequest */
			ipc_port_nsrequest(port, port->ip_mscount, notifyport,
			    &notifyport);
			return;
		}
	}
	ip_unlock(port);
	if (NULL != port_aia_p)
		audit_session_portaiadestroy(port_aia_p);
	ipc_port_dealloc_kernel(port);
}
#endif /* CONFIG_AUDIT */
