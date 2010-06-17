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
#include <kern/ipc_misc.h>

extern void fileport_releasefg(struct fileglob *);

/*
 * fileport_alloc
 *
 * Description: Obtain a send right for the given fileglob, which must be
 *		referenced.
 *
 * Parameters: 	fg		A fileglob.
 *
 * Returns: 	Port of type IKOT_FILEPORT with fileglob set as its kobject. 
 * 		Port is returned with a send right.
 */
ipc_port_t
fileport_alloc(struct fileglob *fg)
{
	ipc_port_t fileport;
	ipc_port_t sendport;
	ipc_port_t notifyport;

	fileport = ipc_port_alloc_kernel();
	if (fileport == IP_NULL) {
		goto out;
	}

	ipc_kobject_set(fileport, (ipc_kobject_t)fg, IKOT_FILEPORT);
	notifyport = ipc_port_make_sonce(fileport);
	ip_lock(fileport); /* unlocked by ipc_port_nsrequest */
	ipc_port_nsrequest(fileport, 1, notifyport, &notifyport);

	sendport = ipc_port_make_send(fileport);
	if (!IP_VALID(sendport)) {
		panic("Couldn't allocate send right for fileport!\n");
	}

out:
	return fileport;
}


/*
 * fileport_get_fileglob
 *
 * Description: Obtain the fileglob associated with a given port.
 *
 * Parameters: port		A Mach port of type IKOT_FILEPORT.
 *
 * Returns:    NULL		The given Mach port did not reference a
 *				fileglob.
 *	       !NULL		The fileglob that is associated with the
 *				Mach port.
 *
 * Notes: The caller must have a reference on the fileport.
 */
struct fileglob *
fileport_port_to_fileglob(ipc_port_t port)
{
	struct fileglob *fg = NULL;

	if (!IP_VALID(port))
		return NULL;

	ip_lock(port);
	if (ip_active(port) && IKOT_FILEPORT == ip_kotype(port))
		fg = (void *)port->ip_kobject;
	ip_unlock(port);

	return fg;
}


/*
 * fileport_notify
 *
 * Description: Handle a no-senders notification for a fileport.  Unless
 * 		the message is spoofed, destroys the port and releases
 * 		its reference on the fileglob.
 *
 * Parameters: msg		A Mach no-senders notification message.
 */
void
fileport_notify(mach_msg_header_t *msg)
{
	mach_no_senders_notification_t *notification = (void *)msg;
	ipc_port_t port = notification->not_header.msgh_remote_port;
	struct fileglob *fg = NULL;

	if (!IP_VALID(port))
		panic("Invalid port passed to fileport_notify()\n");

	ip_lock(port);

	fg = (struct fileglob *)port->ip_kobject;

	if (!ip_active(port)) 
		panic("Inactive port passed to fileport_notify()\n");
	if (ip_kotype(port) != IKOT_FILEPORT) 
		panic("Port of type other than IKOT_FILEPORT passed to fileport_notify()\n");
	if (fg == NULL) 
		panic("fileport without an assocated fileglob\n");

	if (port->ip_srights == 0) {
		ip_unlock(port);

		fileport_releasefg(fg);
		ipc_port_dealloc_kernel(port);
	} else {
		ip_unlock(port);
	}

	return;
}
