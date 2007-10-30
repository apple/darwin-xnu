/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
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
/*-
 * Copyright (c) 2005-2006 SPARTA, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <ipc/ipc_space.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_labelh.h>
#include <kern/ipc_kobject.h>
#include <mach/security.h>
#include <security/mac_mach_internal.h>

#if CONFIG_MACF_MACH
zone_t ipc_labelh_zone;

/*
 * Create a new label handle in the task described by the specified space.
 * The specified label is used in the label handle.  The associated port
 * name is copied out to namep and the task is granted send and receive rights.
 */
kern_return_t
labelh_new_user(ipc_space_t space, struct label *inl, mach_port_name_t *namep)
{
	kern_return_t kr;
	ipc_labelh_t lh;
	ipc_entry_t entry;
	ipc_port_t port;

	if (space == IS_NULL || space->is_task == NULL)
		return (KERN_INVALID_TASK);

	/* XXX - perform entrypoint check here? */

	/*
	 * Note: the calling task will have a receive right for the port.
	 * This is different from label handles that reference tasks
	 * where the kernel holds the receive right and the caller only
	 * gets a send right.
	 */
	kr = ipc_port_alloc(space, namep, &port);
	if (kr != KERN_SUCCESS)
		return (kr);
	ip_reference(port);	/* ipc_port_alloc() does not add a reference */

	/* Convert right to MACH_PORT_TYPE_SEND_RECEIVE */
	port->ip_mscount++;
	port->ip_srights++;
	is_write_lock(space);
	entry = ipc_entry_lookup(space, *namep);
	if (entry != IE_NULL)
		entry->ie_bits |= MACH_PORT_TYPE_SEND;
	is_write_unlock(space);

	/* Allocate new label handle, insert port and label. */
	lh = (ipc_labelh_t)zalloc(ipc_labelh_zone);
	lh_lock_init(lh);
	lh->lh_port = port;
	lh->lh_label = *inl;
	lh->lh_type = LABELH_TYPE_USER;
	lh->lh_references = 1;		/* unused for LABELH_TYPE_USER */

	/* Must call ipc_kobject_set() with port unlocked. */
	ip_unlock(lh->lh_port);
	ipc_kobject_set(lh->lh_port, (ipc_kobject_t)lh, IKOT_LABELH);

	return (KERN_SUCCESS);
}

kern_return_t
mac_label_new(ipc_space_t space, mach_port_name_t *namep, labelstr_t labelstr)
{
	struct label inl;
	kern_return_t kr;

	mac_task_label_init(&inl);
	if (mac_task_label_internalize(&inl, labelstr))
		return (KERN_INVALID_ARGUMENT);

	kr = labelh_new_user(space, &inl, namep);
	if (kr != KERN_SUCCESS) {
		mac_task_label_destroy(&inl);
		return (kr);
	}

	return (KERN_SUCCESS);
}

/*
 * This function should be used to allocate label handles
 * that are stored in other kernel objects, such as tasks.
 * They must be released along with that object.
 * The caller gets one reference, which can be applied to either the
 * port or the ipc_label_t structure itself.
 */
ipc_labelh_t
labelh_new(int canblock)
{
	ipc_labelh_t lh;

	lh = (ipc_labelh_t)zalloc_canblock(ipc_labelh_zone, canblock);
	lh_lock_init(lh);
	lh->lh_port = ipc_port_alloc_kernel();
	lh->lh_type = LABELH_TYPE_KERN;
	lh->lh_references = 1;
	ipc_kobject_set(lh->lh_port, (ipc_kobject_t)lh, IKOT_LABELH);

	return (lh);
}

/*
 * Call with old label handle locked.
 * Returned label handle is unlocked.
 */
ipc_labelh_t
labelh_duplicate(ipc_labelh_t old)
{
	ipc_labelh_t lh;

	lh = labelh_new(0);
	ip_lock(lh->lh_port);
	mac_task_label_init(&lh->lh_label);
	mac_task_label_copy(&old->lh_label, &lh->lh_label);
	ip_unlock(lh->lh_port);
	return (lh);
}

/*
 * Call with old label handle locked.
 * Returned label handle is locked.
 */
ipc_labelh_t
labelh_modify(ipc_labelh_t old)
{
	ipc_labelh_t lh;

	/*
	 * A label handle may only have a single reference. 
	 * If there are no other references this is a no-op.
	 * Otherwise, make a copy we can write to and return it.
	 */
	if (old->lh_references == 1)
		return (old);
	lh = labelh_duplicate(old);
	lh_release(old);
	lh_check_unlock(old);
	lh_lock(lh);
	return (lh);
}

/*
 * Add or drop a reference on an (unlocked) label handle.
 */
ipc_labelh_t
labelh_reference(ipc_labelh_t lh)
{
	lh_lock(lh);
	lh_reference(lh);
	lh_unlock(lh);
	return (lh);
}

/*
 * Release a reference on an (unlocked) label handle.
 */
void
labelh_release(ipc_labelh_t lh)
{
	lh_lock(lh);
	lh_release(lh);
	lh_check_unlock(lh);
}

/*
 * Deallocate space associated with the label handle backed by the
 * specified port.  For kernel-allocated label handles the
 * label handle reference count should be 0.  For user-allocated
 * handles the ref count is not used (it was initialized to 1).
 */
void
labelh_destroy(ipc_port_t port)
{
	ipc_labelh_t lh = (ipc_labelh_t) port->ip_kobject;

	mac_task_label_destroy(&lh->lh_label);
	zfree(ipc_labelh_zone, (vm_offset_t)lh);
}
#else
kern_return_t
mac_label_new(__unused ipc_space_t space, 
	      __unused mach_port_name_t *namep,
	      __unused labelstr_t labelstr)
{
	return KERN_FAILURE;
}
#endif /* MAC_MACH */
