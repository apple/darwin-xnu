/*
 * Copyright (c) 2019-2020 Apple Inc. All rights reserved.
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

/*
 *
 * An SUID credential is a port type which allows a process to create a new
 * process with a specific user id. It provides an alternative means to acheive
 * this to the more traditional SUID bit file permission.
 *
 * To create a new SUID credential the process must be running as root and must
 * have a special entitlement. When created, the credential is associated with a
 * specific vnode and UID so the unprivileged owner of the credential may only
 * create a new process from the file associated with that vnode and the
 * resulting effective UID will be that of the UID in the credential.
 */

#include <kern/ipc_kobject.h>
#include <kern/queue.h>
#include <kern/suid_cred.h>

#include <mach/mach_types.h>
#include <mach/task.h>

#include <IOKit/IOBSD.h>

/* Declarations necessary to call vnode_lookup()/vnode_put(). */
struct vnode;
struct vfs_context;
extern int vnode_lookup(const char *, int, struct vnode **,
    struct vfs_context *);
extern struct vfs_context * vfs_context_current(void);
extern int vnode_put(struct vnode *);

/* Declarations necessary to call kauth_cred_issuser(). */
struct ucred;
extern int kauth_cred_issuser(struct ucred *);
extern struct ucred *kauth_cred_get(void);

/* Data associated with the suid cred port. Consumed during posix_spawn(). */
struct suid_cred {
	ipc_port_t port;
	struct vnode *vnode;
	uint32_t uid;
};

static ZONE_DECLARE(suid_cred_zone, "suid_cred",
    sizeof(struct suid_cred), ZC_NONE);

/* Allocs a new suid credential. The vnode reference will be owned by the newly
 * created suid_cred_t. */
static suid_cred_t
suid_cred_alloc(struct vnode *vnode, uint32_t uid)
{
	suid_cred_t sc = SUID_CRED_NULL;

	assert(vnode != NULL);

	sc = zalloc(suid_cred_zone);
	if (sc != NULL) {
		// Lazily allocated in convert_suid_cred_to_port().
		sc->port = IP_NULL;
		sc->vnode = vnode;
		sc->uid = uid;
	}

	return sc;
}

static void
suid_cred_free(suid_cred_t sc)
{
	assert(sc != NULL);
	assert(sc->vnode != NULL);

	vnode_put(sc->vnode);

	sc->uid = UINT32_MAX;
	sc->vnode = NULL;
	sc->port = IP_NULL;

	zfree(suid_cred_zone, sc);
}

void
suid_cred_destroy(ipc_port_t port)
{
	suid_cred_t sc = NULL;

	ip_lock(port);
	assert(ip_kotype(port) == IKOT_SUID_CRED);
	sc = (suid_cred_t)port->ip_kobject;
	ipc_kobject_set_atomically(port, IKO_NULL, IKOT_NONE);
	ip_unlock(port);

	assert(sc->port == port);

	suid_cred_free(sc);
}

void
suid_cred_notify(mach_msg_header_t *msg)
{
	assert(msg->msgh_id == MACH_NOTIFY_NO_SENDERS);

	mach_no_senders_notification_t *not = (mach_no_senders_notification_t *)msg;
	ipc_port_t port = not->not_header.msgh_remote_port;

	if (IP_VALID(port)) {
		ipc_port_dealloc_kernel(port);
	}
}

ipc_port_t
convert_suid_cred_to_port(suid_cred_t sc)
{
	if (sc == NULL) {
		return IP_NULL;
	}

	if (!ipc_kobject_make_send_lazy_alloc_port(&sc->port,
	    (ipc_kobject_t) sc, IKOT_SUID_CRED, false, 0)) {
		suid_cred_free(sc);
		return IP_NULL;
	}

	return sc->port;
}

/*
 * Verify the suid cred port. The cached vnode should match the passed vnode.
 * The uid to be used to spawn the new process is returned in 'uid'.
 */
int
suid_cred_verify(ipc_port_t port, struct vnode *vnode, uint32_t *uid)
{
	suid_cred_t sc = NULL;
	int ret = -1;

	if (!IP_VALID(port)) {
		return -1;
	}

	ip_lock(port);

	if (ip_kotype(port) != IKOT_SUID_CRED) {
		ip_unlock(port);
		return -1;
	}

	if (!ip_active(port)) {
		ip_unlock(port);
		return -1;
	}

	sc = (suid_cred_t)port->ip_kobject;

	if (vnode != sc->vnode) {
		ip_unlock(port);
		return -1;
	}

	*uid = sc->uid;
	ret = 0;

	ipc_port_destroy(port);
	return ret;
}

kern_return_t
task_create_suid_cred(
	task_t task,
	suid_cred_path_t path,
	suid_cred_uid_t uid,
	suid_cred_t *sc_p)
{
	suid_cred_t sc = NULL;
	struct vnode *vnode;
	int  err = -1;

	if (task == TASK_NULL || task != current_task()) {
		return KERN_INVALID_ARGUMENT;
	}

	// Task must have entitlement.
	if (!IOTaskHasEntitlement(task, "com.apple.private.suid_cred")) {
		return KERN_NO_ACCESS;
	}

	// Thread must be root owned.
	if (!kauth_cred_issuser(kauth_cred_get())) {
		return KERN_NO_ACCESS;
	}

	// Find the vnode for the path.
	err = vnode_lookup(path, 0, &vnode, vfs_context_current());
	if (err != 0) {
		return KERN_INVALID_ARGUMENT;
	}

	sc = suid_cred_alloc(vnode, uid);
	if (sc == NULL) {
		(void) vnode_put(vnode);
		return KERN_RESOURCE_SHORTAGE;
	}

	*sc_p = sc;

	return KERN_SUCCESS;
}
