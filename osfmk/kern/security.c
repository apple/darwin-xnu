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
 * Copyright (c) 2005-2007 SPARTA, Inc.
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

#include <mach/message.h>
#include <kern/kern_types.h>
#include <kern/ipc_kobject.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_right.h>
#include <ipc/ipc_labelh.h>
#include <kern/task.h>
#include <security/mac_mach_internal.h> 
#include <mach/security.h> 

#if CONFIG_MACF_MACH
kern_return_t
mach_get_task_label(
	ipc_space_t	 space,
	mach_port_name_t *outlabel)
{
	kern_return_t	kr;
	ipc_labelh_t	lh;

	if (space == IS_NULL || space->is_task == NULL)
		return KERN_INVALID_TASK;

	lh = space->is_task->label;
	ip_lock(lh->lh_port);
	lh->lh_port->ip_mscount++;
	lh->lh_port->ip_srights++;
	ip_reference(lh->lh_port);
	ip_unlock(lh->lh_port);
	kr = ipc_object_copyout(space, (ipc_object_t) lh->lh_port,
	    MACH_MSG_TYPE_PORT_SEND, 0, outlabel);
	if (kr != KERN_SUCCESS) {
		ip_lock(lh->lh_port);
		ip_release(lh->lh_port);
		ip_check_unlock(lh->lh_port);
		*outlabel = MACH_PORT_NULL;
	}
  
	return (KERN_SUCCESS);
}
#else
kern_return_t
mach_get_task_label(
	ipc_space_t	 space __unused,
	mach_port_name_t *outlabel __unused)
{
	return KERN_FAILURE;
}
#endif

#if CONFIG_MACF_MACH
kern_return_t
mach_get_task_label_text(
	ipc_space_t	space,
	labelstr_t	policies,
	labelstr_t	outl)
{

	if (space == IS_NULL || space->is_task == NULL)
		return KERN_INVALID_TASK;

	tasklabel_lock(space->is_task);
	mac_task_label_externalize(&space->is_task->maclabel, policies, outl,
	    512, 0);
	tasklabel_unlock(space->is_task);
  
	return KERN_SUCCESS;
}
#else
kern_return_t
mach_get_task_label_text(
	ipc_space_t	space __unused,
	labelstr_t	policies __unused,
	labelstr_t	outl __unused)
{
	return KERN_FAILURE;
}
#endif

#if CONFIG_MACF_MACH
int
mac_task_check_service(
	task_t       self,
	task_t       obj,
	const char * perm)
{
	tasklabel_lock2(self, obj);

	int rc = mac_port_check_service(
		&self->maclabel, &obj->maclabel, 
		"mach_task", perm);

	tasklabel_unlock2(self, obj);

	return rc;
}
#else
int
mac_task_check_service(
	task_t       self __unused,
	task_t       obj __unused,
	const char * perm __unused)
{
	return KERN_SUCCESS;
}
#endif

#if CONFIG_MACF_MACH
kern_return_t
mac_check_service(
	__unused ipc_space_t space,
	labelstr_t  subj,
	labelstr_t  obj,
	labelstr_t  serv,
	labelstr_t  perm)
{
	struct label subjl, objl;

	mac_task_label_init(&subjl);
	int rc = mac_port_label_internalize(&subjl, subj);
	if (rc) {
		mac_task_label_destroy(&subjl);
		return KERN_INVALID_ARGUMENT;
	}
	mac_task_label_init(&objl);
	rc = mac_port_label_internalize(&objl, obj);
	if (rc) {
		mac_task_label_destroy(&subjl);
		mac_task_label_destroy(&objl);
		return KERN_INVALID_ARGUMENT;
	}

	rc = mac_port_check_service(&subjl, &objl, serv, perm);
	mac_task_label_destroy(&subjl);
	mac_task_label_destroy(&objl);

	return rc ? KERN_NO_ACCESS : KERN_SUCCESS;
}
#else
kern_return_t
mac_check_service(
	__unused ipc_space_t space,
	__unused labelstr_t  subj,
	__unused labelstr_t  obj,
	__unused labelstr_t  serv,
	__unused labelstr_t  perm)
{
	return KERN_FAILURE;
}
#endif 

#if CONFIG_MACF_MACH
kern_return_t
mac_port_check_service_obj(
	ipc_space_t      space,
	labelstr_t       subj,
	mach_port_name_t obj,
	labelstr_t       serv,
	labelstr_t       perm)
{
	struct label  subjl;
	ipc_entry_t   entry;
	ipc_object_t  objp;
	kern_return_t kr;
	struct label  *objl;
	int	      dead;

	if (space == IS_NULL || space->is_task == NULL)
		return KERN_INVALID_TASK;

	if (!MACH_PORT_VALID(obj))
		return KERN_INVALID_NAME;

	mac_task_label_init(&subjl);
	int rc = mac_port_label_internalize(&subjl, subj);
	if (rc) {
		mac_task_label_destroy(&subjl);
		return KERN_INVALID_ARGUMENT;
	}

	kr = ipc_right_lookup_write(space, obj, &entry);
	if (kr != KERN_SUCCESS) {
		mac_task_label_destroy(&subjl);
		return kr;
	}

	dead = ipc_right_check(space, (ipc_port_t) entry->ie_object, obj, entry);
	if (dead) {
		is_write_unlock(space);
		mac_task_label_destroy(&subjl);
		return KERN_INVALID_RIGHT;
	}

	objp = entry->ie_object;
	io_lock (objp);
	is_write_unlock (space);

	objl = io_getlabel(objp);
	if (objl == NULL) {
		io_unlock(objp);
		return KERN_INVALID_ARGUMENT;
	}

	rc = mac_port_check_service(&subjl, objl, serv, perm);
	io_unlocklabel(objp);
	io_unlock (objp);

	mac_task_label_destroy(&subjl);
	return rc ? KERN_NO_ACCESS : KERN_SUCCESS;
}
#else
kern_return_t
mac_port_check_service_obj(
	__unused ipc_space_t      space,
	__unused labelstr_t       subj,
	__unused mach_port_name_t obj,
	__unused labelstr_t       serv,
	__unused labelstr_t       perm)
{
	return KERN_FAILURE;
}
#endif

#if CONFIG_MACF_MACH
kern_return_t
mac_port_check_access(
	ipc_space_t      space,
	mach_port_name_t sub,
	mach_port_name_t obj,
	labelstr_t       serv,
	labelstr_t       perm)
{
	ipc_entry_t    subi, obji;
	ipc_object_t   subp, objp;
	kern_return_t  kr;
	struct label  *objl, *subl;
	int            rc;

	if (space == IS_NULL || space->is_task == NULL)
		return KERN_INVALID_TASK;

	if (!MACH_PORT_VALID(obj) || !MACH_PORT_VALID(sub))
		return KERN_INVALID_NAME;

	kr = ipc_right_lookup_two_write(space, obj, &obji, sub, &subi);
	if (kr != KERN_SUCCESS)
		return kr;

	objp = obji->ie_object;
	subp = subi->ie_object;

	ipc_port_multiple_lock(); /* serialize (not necessary for LH, but simpler) */
	io_lock(objp);
	io_lock(subp);
	is_write_unlock (space);

	objl = io_getlabel(objp);
	if (objl == NULL)
		goto errout;
	subl = io_getlabel(subp);
	if (subl == NULL)
		goto errout;

	rc = mac_port_check_service(subl, objl, serv, perm);
	io_unlocklabel(subp);
	io_unlock(subp);
	io_unlocklabel(objp);
	io_unlock(objp);
	ipc_port_multiple_unlock();

	return rc ? KERN_NO_ACCESS : KERN_SUCCESS;

errout:
	io_unlocklabel(subp);
	io_unlock(subp);
	io_unlocklabel(objp);
	io_unlock(objp);
	ipc_port_multiple_unlock();
	return KERN_INVALID_ARGUMENT;
}
#else
kern_return_t
mac_port_check_access(
	__unused ipc_space_t      space,
	__unused mach_port_name_t sub,
	__unused mach_port_name_t obj,
	__unused labelstr_t       serv,
	__unused labelstr_t       perm)
{
	return KERN_FAILURE;
}
#endif

#if CONFIG_MACF_MACH
kern_return_t
mac_request_label(
	ipc_space_t      space,
	mach_port_name_t sub,
	mach_port_name_t obj,
	labelstr_t       serv,
	mach_port_name_t *outlabel)
{
	ipc_entry_t    subi, obji;
	ipc_object_t   subp, objp;
	kern_return_t  kr;
	struct label  *objl, *subl, outl;
	int            rc;

	if (space == IS_NULL || space->is_task == NULL)
		return KERN_INVALID_TASK;

	if (!MACH_PORT_VALID(obj) || !MACH_PORT_VALID(sub))
		return KERN_INVALID_NAME;

	kr = ipc_right_lookup_two_write(space, obj, &obji, sub, &subi);
	if (kr != KERN_SUCCESS)
		return kr;

	objp = obji->ie_object;
	subp = subi->ie_object;

	ipc_port_multiple_lock(); /* serialize (not necessary for LH, but simpler) */
	io_lock(objp);
	io_lock(subp);
	is_write_unlock (space);

	objl = io_getlabel(objp);
	if (objl == NULL)
		goto errout;
	subl = io_getlabel(subp);
	if (subl == NULL)
		goto errout;

	mac_port_label_init(&outl);
	rc = mac_port_label_compute(subl, objl, serv, &outl);
	io_unlocklabel(subp);
	io_unlock(subp);
	io_unlocklabel(objp);
	io_unlock(objp);
	ipc_port_multiple_unlock();

	if (rc == 0)
		kr = labelh_new_user(space, &outl, outlabel);
	else
		kr = KERN_NO_ACCESS;

	if (kr != KERN_SUCCESS)
		mac_port_label_destroy(&outl);

	return kr;

errout:
	io_unlocklabel(subp);
	io_unlock(subp);
	io_unlocklabel(objp);
	io_unlock(objp);
	ipc_port_multiple_unlock();
	return KERN_INVALID_ARGUMENT;
}
#else /* !MAC_MACH */

kern_return_t
mac_request_label(
	__unused ipc_space_t      space,
	__unused mach_port_name_t sub,
	__unused mach_port_name_t obj,
	__unused labelstr_t       serv,
	__unused mach_port_name_t *outlabel)
{
	return KERN_FAILURE;
}

#endif /* MAC_MACH */
