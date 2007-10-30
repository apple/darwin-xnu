/*
 * Copyright (c) 2006-2007 Apple Inc. All rights reserved.
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
 * Copyright (c) 1999, 2000, 2001, 2002 Robert N. M. Watson
 * Copyright (c) 2001 Ilmar S. Habibulin
 * Copyright (c) 2001, 2002, 2003, 2004 Networks Associates Technology, Inc.
 *
 * This software was developed by Robert Watson and Ilmar Habibulin for the
 * TrustedBSD Project.
 *
 * This software was developed for the FreeBSD Project in part by Network
 * Associates Laboratories, the Security Research Division of Network
 * Associates, Inc. under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"),
 * as part of the DARPA CHATS research program.
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
 *
 */
#include <sys/param.h>
#include <sys/types.h>  
#include <sys/vnode.h>  
#include <sys/vnode_internal.h>
#include <sys/kauth.h>
#include <sys/queue.h>  
#include <security/mac_internal.h>
#include <bsd/bsm/audit.h>
#include <bsd/bsm/audit_kernel.h>
#include <bsd/sys/malloc.h>
#include <vm/vm_kern.h>
#include <kern/kalloc.h>
#include <kern/zalloc.h>

#ifdef AUDIT

/* The zone allocator is initialized in mac_base.c. */
zone_t mac_audit_data_zone;

int
mac_system_check_audit(struct ucred *cred, void *record, int length)
{
	int error;

	MAC_CHECK(system_check_audit, cred, record, length);

	return (error);
}

int
mac_system_check_auditon(struct ucred *cred, int cmd)
{
	int error;

	MAC_CHECK(system_check_auditon, cred, cmd);

	return (error);
}

int
mac_system_check_auditctl(struct ucred *cred, struct vnode *vp)
{
	int error;
	struct label *vl = vp ? vp->v_label : NULL;

	MAC_CHECK(system_check_auditctl, cred, vp, vl);

	return (error);
}

int
mac_proc_check_getauid(struct proc *curp)
{
	kauth_cred_t cred;
	int error;

	if (!mac_proc_enforce ||
	    !mac_proc_check_enforce(curp, MAC_PROC_ENFORCE))
		return 0;

	cred = kauth_cred_proc_ref(curp);
	MAC_CHECK(proc_check_getauid, cred);
	kauth_cred_unref(&cred);

	return (error);
}

int
mac_proc_check_setauid(struct proc *curp, uid_t auid)
{
	kauth_cred_t cred;
	int error;

	if (!mac_proc_enforce ||
	    !mac_proc_check_enforce(curp, MAC_PROC_ENFORCE))
		return 0;

	cred = kauth_cred_proc_ref(curp);
	MAC_CHECK(proc_check_setauid, cred, auid);
	kauth_cred_unref(&cred);

	return (error);
}

int 
mac_proc_check_getaudit(struct proc *curp) 
{
	kauth_cred_t cred;
	int error;

	if (!mac_proc_enforce ||
	    !mac_proc_check_enforce(curp, MAC_PROC_ENFORCE))
		return 0;

	cred = kauth_cred_proc_ref(curp);
	MAC_CHECK(proc_check_getaudit, cred);
	kauth_cred_unref(&cred);

	return (error);
}

int
mac_proc_check_setaudit(struct proc *curp, struct auditinfo *ai)
{
	kauth_cred_t cred;
	int error;

	if (!mac_proc_enforce ||
	    !mac_proc_check_enforce(curp, MAC_PROC_ENFORCE))
		return 0;

	cred = kauth_cred_proc_ref(curp);
	MAC_CHECK(proc_check_setaudit, cred, ai);
	kauth_cred_unref(&cred);

	return (error);
}

#if 0
/*
 * This is the framework entry point for MAC policies to use to add
 * arbitrary data to the current audit record.
 * (Currently not supported, as no existing audit viewers would 
 * display this format)
 * 
 */
int
mac_audit_data(int len, u_char *data, mac_policy_handle_t handle)
{
	char *sanitized;

	if ((len <= 0) || (len > MAC_AUDIT_DATA_LIMIT))
		return (EINVAL);

	sanitized = (char *)zalloc(mac_audit_data_zone);

	bcopy(data, sanitized, len);
	return (audit_mac_data(MAC_AUDIT_DATA_TYPE, len, sanitized));
}
#endif

/*
 * This is the entry point a MAC policy will call to add NULL-
 * terminated ASCII text to the current audit record.
 */
int
mac_audit_text(char *text, mac_policy_handle_t handle)
{
	char *sanitized;
	const char *name;
	int i, size, plen, len;

	name = mac_get_mpc(handle)->mpc_name;
	len = strlen(text);
	plen = 2 + strlen(name);
	if (plen + len >= MAC_AUDIT_DATA_LIMIT)
		return (EINVAL);

	/*
	 * Make sure the text is only composed of only ASCII printable
	 * characters.
	 */
	for (i=0; i < len; i++)
		if (text[i] < (char) 32 || text[i] > (char) 126)
			return (EINVAL);

	size = len + plen + 1;
 	sanitized = (char *)zalloc(mac_audit_data_zone);

	strlcpy(sanitized, name, MAC_AUDIT_DATA_LIMIT);
	strncat(sanitized, ": ", MAC_AUDIT_DATA_LIMIT - plen + 2);
	strncat(sanitized, text, MAC_AUDIT_DATA_LIMIT - plen);

	return (audit_mac_data(MAC_AUDIT_TEXT_TYPE, size, (u_char *)sanitized));
}

int
mac_audit_check_preselect(struct ucred *cred, unsigned short syscode, void *args)
{
	struct mac_policy_conf *mpc;
	int ret, error;
	u_int i;

	ret = MAC_AUDIT_DEFAULT;
	for (i = 0; i < mac_policy_list.staticmax; i++) {
		mpc = mac_policy_list.entries[i].mpc;
		if (mpc == NULL)
			continue;

		if (mpc->mpc_ops->mpo_audit_check_preselect != NULL) {
			error = mpc->mpc_ops->mpo_audit_check_preselect(cred,
			    syscode, args);
			ret = (ret > error ? ret : error);
		}
	}
	if (mac_policy_list_conditional_busy() != 0) {
		for (; i <= mac_policy_list.maxindex; i++) {
			mpc = mac_policy_list.entries[i].mpc;
			if (mpc == NULL)
				continue;

			if (mpc->mpc_ops->mpo_audit_check_preselect != NULL) {
				error = mpc->mpc_ops->mpo_audit_check_preselect(cred,
				    syscode, args);
				ret = (ret > error ? ret : error);
			}
		}
		mac_policy_list_unbusy();
	}

	return (ret);
}

int
mac_audit_check_postselect(struct ucred *cred, unsigned short syscode,
    void *args, int error, int retval, int mac_forced)
{
	struct mac_policy_conf *mpc;
	int ret, mac_error;
	u_int i;

	/*
	 * If the audit was forced by a MAC policy by mac_audit_check_preselect(),
	 * echo that.
	 */
	if (mac_forced)
		return (MAC_AUDIT_YES);

	ret = MAC_AUDIT_DEFAULT;
	for (i = 0; i < mac_policy_list.staticmax; i++) {
		mpc = mac_policy_list.entries[i].mpc;
		if (mpc == NULL)
			continue;

		if (mpc->mpc_ops->mpo_audit_check_postselect != NULL) {
			mac_error = mpc->mpc_ops->mpo_audit_check_postselect(cred,
			    syscode, args, error, retval);
			ret = (ret > mac_error ? ret : mac_error);
		}
	}
	if (mac_policy_list_conditional_busy() != 0) {
		for (; i <= mac_policy_list.maxindex; i++) {
			mpc = mac_policy_list.entries[i].mpc;
			if (mpc == NULL)
				continue;

			if (mpc->mpc_ops->mpo_audit_check_postselect != NULL) {
				mac_error = mpc->mpc_ops->mpo_audit_check_postselect(cred,
				    syscode, args, error, retval);
				ret = (ret > mac_error ? ret : mac_error);
			}
		}
		mac_policy_list_unbusy();
	}

	return (ret);
}

#else	/* AUDIT */

/*
 * Function stubs for when AUDIT isn't defined.
 */

int
mac_system_check_audit(struct ucred *cred, void *record, int length)
{

	return (0);
}

int
mac_system_check_auditon(struct ucred *cred, int cmd)
{

	return (0);
}

int
mac_system_check_auditctl(struct ucred *cred, struct vnode *vp)
{

	return (0);
}

int
mac_proc_check_getauid(__unused struct proc *curp)
{

	return (0);
}

int
mac_proc_check_setauid(__unused struct proc *curp, __unused uid_t auid)
{

	return (0);
}

int
mac_proc_check_getaudit(__unused struct proc *curp)
{

	return (0);
}

int
mac_proc_check_setaudit(__unused struct proc *curp, struct auditinfo *ai)
{

	return (0);
}

int
mac_audit_check_preselect(__unused struct ucred *cred, __unused unsigned short syscode,
    __unused void *args)
{

	return (MAC_AUDIT_DEFAULT);
}

int
mac_audit_check_postselect(__unused struct ucred *cred, __unused unsigned short syscode,
    __unused void *args, __unused int error, __unused int retval, __unused int mac_forced)
{

	return (MAC_AUDIT_DEFAULT);
}

int
mac_audit(int len, u_char *data)
{

	return (0);
}
#endif	/* !AUDIT */
