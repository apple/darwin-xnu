/*
 * Copyright (c) 2007-2010 Apple Inc. All rights reserved.
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

#include <string.h>
#include <sys/param.h>
#include <sys/ucred.h>
#include <sys/malloc.h>
#include <sys/sbuf.h>
#include <sys/vnode.h>
#include <sys/proc.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/imgact.h>
#include <mach/mach_types.h>
#include <kern/task.h>

#include <security/mac_internal.h>
#include <security/mac_mach_internal.h>

#include <bsd/security/audit/audit.h>

struct label *
mac_cred_label_alloc(void)
{
	struct label *label;

	label = mac_labelzone_alloc(MAC_WAITOK);
	if (label == NULL) {
		return NULL;
	}
	MAC_PERFORM(cred_label_init, label);
	return label;
}

void
mac_cred_label_init(struct ucred *cred)
{
	cred->cr_label = mac_cred_label_alloc();
}

void
mac_cred_label_free(struct label *label)
{
	MAC_PERFORM(cred_label_destroy, label);
	mac_labelzone_free(label);
}

int
mac_cred_label_compare(struct label *a, struct label *b)
{
	return bcmp(a, b, sizeof(*a)) == 0;
}

int
mac_cred_label_externalize_audit(struct proc *p, struct mac *mac)
{
	kauth_cred_t cr;
	int error;

	cr = kauth_cred_proc_ref(p);

	error = MAC_EXTERNALIZE_AUDIT(cred, cr->cr_label,
	    mac->m_string, mac->m_buflen);

	kauth_cred_unref(&cr);
	return error;
}

void
mac_cred_label_destroy(kauth_cred_t cred)
{
	mac_cred_label_free(cred->cr_label);
	cred->cr_label = NULL;
}

int
mac_cred_label_externalize(struct label *label, char *elements,
    char *outbuf, size_t outbuflen, int flags __unused)
{
	int error = 0;

	error = MAC_EXTERNALIZE(cred, label, elements, outbuf, outbuflen);

	return error;
}

int
mac_cred_label_internalize(struct label *label, char *string)
{
	int error;

	error = MAC_INTERNALIZE(cred, label, string);

	return error;
}

/*
 * By default, fork just adds a reference to the parent
 * credential.  Policies may need to know about this reference
 * if they are tracking exit calls to know when to free the
 * label.
 */
void
mac_cred_label_associate_fork(kauth_cred_t cred, proc_t proc)
{
	MAC_PERFORM(cred_label_associate_fork, cred, proc);
}

/*
 * Initialize MAC label for the first kernel process, from which other
 * kernel processes and threads are spawned.
 */
void
mac_cred_label_associate_kernel(kauth_cred_t cred)
{
	MAC_PERFORM(cred_label_associate_kernel, cred);
}

/*
 * Initialize MAC label for the first userland process, from which other
 * userland processes and threads are spawned.
 */
void
mac_cred_label_associate_user(kauth_cred_t cred)
{
	MAC_PERFORM(cred_label_associate_user, cred);
}

/*
 * When a new process is created, its label must be initialized.  Generally,
 * this involves inheritence from the parent process, modulo possible
 * deltas.  This function allows that processing to take place.
 */
void
mac_cred_label_associate(struct ucred *parent_cred, struct ucred *child_cred)
{
	MAC_PERFORM(cred_label_associate, parent_cred, child_cred);
}

int
mac_execve_enter(user_addr_t mac_p, struct image_params *imgp)
{
	struct user_mac mac;
	struct label *execlabel;
	char *buffer;
	int error;
	size_t ulen;

	if (mac_p == USER_ADDR_NULL) {
		return 0;
	}

	if (IS_64BIT_PROCESS(current_proc())) {
		struct user64_mac mac64;
		error = copyin(mac_p, &mac64, sizeof(mac64));
		mac.m_buflen = mac64.m_buflen;
		mac.m_string = mac64.m_string;
	} else {
		struct user32_mac mac32;
		error = copyin(mac_p, &mac32, sizeof(mac32));
		mac.m_buflen = mac32.m_buflen;
		mac.m_string = mac32.m_string;
	}
	if (error) {
		return error;
	}

	error = mac_check_structmac_consistent(&mac);
	if (error) {
		return error;
	}

	execlabel = mac_cred_label_alloc();
	MALLOC(buffer, char *, mac.m_buflen, M_MACTEMP, M_WAITOK);
	error = copyinstr(CAST_USER_ADDR_T(mac.m_string), buffer, mac.m_buflen, &ulen);
	if (error) {
		goto out;
	}
	AUDIT_ARG(mac_string, buffer);

	error = mac_cred_label_internalize(execlabel, buffer);
out:
	if (error) {
		mac_cred_label_free(execlabel);
		execlabel = NULL;
	}
	imgp->ip_execlabelp = execlabel;
	FREE(buffer, M_MACTEMP);
	return error;
}

/*
 * When the subject's label changes, it may require revocation of privilege
 * to mapped objects.  This can't be done on-the-fly later with a unified
 * buffer cache.
 *
 * XXX:		CRF_MAC_ENFORCE should be in a kauth_cred_t field, rather
 * XXX:		than a posix_cred_t field.
 */
void
mac_cred_label_update(kauth_cred_t cred, struct label *newlabel)
{
	posix_cred_t pcred = posix_cred_get(cred);

	/* force label to be part of "matching" for credential */
	pcred->cr_flags |= CRF_MAC_ENFORCE;

	/* inform the policies of the update */
	MAC_PERFORM(cred_label_update, cred, newlabel);
}

int
mac_cred_check_label_update(kauth_cred_t cred, struct label *newlabel)
{
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_proc_enforce) {
		return 0;
	}
#endif

	MAC_CHECK(cred_check_label_update, cred, newlabel);

	return error;
}

int
mac_cred_check_visible(kauth_cred_t u1, kauth_cred_t u2)
{
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_proc_enforce) {
		return 0;
	}
#endif

	MAC_CHECK(cred_check_visible, u1, u2);

	return error;
}

int
mac_proc_check_debug(proc_t curp, struct proc *proc)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_proc_enforce) {
		return 0;
	}
#endif
	if (!mac_proc_check_enforce(curp)) {
		return 0;
	}

	cred = kauth_cred_proc_ref(curp);
	MAC_CHECK(proc_check_debug, cred, proc);
	kauth_cred_unref(&cred);

	return error;
}

int
mac_proc_check_fork(proc_t curp)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_proc_enforce) {
		return 0;
	}
#endif
	if (!mac_proc_check_enforce(curp)) {
		return 0;
	}

	cred = kauth_cred_proc_ref(curp);
	MAC_CHECK(proc_check_fork, cred, curp);
	kauth_cred_unref(&cred);

	return error;
}

int
mac_proc_check_get_task_name(struct ucred *cred, struct proc *p)
{
	int error;

	MAC_CHECK(proc_check_get_task_name, cred, p);

	return error;
}

int
mac_proc_check_get_task(struct ucred *cred, struct proc *p)
{
	int error;

	MAC_CHECK(proc_check_get_task, cred, p);

	return error;
}

int
mac_proc_check_expose_task(struct ucred *cred, struct proc *p)
{
	int error;

	MAC_CHECK(proc_check_expose_task, cred, p);

	return error;
}

int
mac_proc_check_inherit_ipc_ports(struct proc *p, struct vnode *cur_vp, off_t cur_offset, struct vnode *img_vp, off_t img_offset, struct vnode *scriptvp)
{
	int error;

	MAC_CHECK(proc_check_inherit_ipc_ports, p, cur_vp, cur_offset, img_vp, img_offset, scriptvp);

	return error;
}

/*
 * The type of maxprot in proc_check_map_anon must be equivalent to vm_prot_t
 * (defined in <mach/vm_prot.h>). mac_policy.h does not include any header
 * files, so cannot use the typedef itself.
 */
int
mac_proc_check_map_anon(proc_t proc, user_addr_t u_addr,
    user_size_t u_size, int prot, int flags, int *maxprot)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vm_enforce) {
		return 0;
	}
#endif
	if (!mac_proc_check_enforce(proc)) {
		return 0;
	}

	cred = kauth_cred_proc_ref(proc);
	MAC_CHECK(proc_check_map_anon, proc, cred, u_addr, u_size, prot, flags, maxprot);
	kauth_cred_unref(&cred);

	return error;
}

int
mac_proc_check_mprotect(proc_t proc,
    user_addr_t addr, user_size_t size, int prot)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vm_enforce) {
		return 0;
	}
#endif
	if (!mac_proc_check_enforce(proc)) {
		return 0;
	}

	cred = kauth_cred_proc_ref(proc);
	MAC_CHECK(proc_check_mprotect, cred, proc, addr, size, prot);
	kauth_cred_unref(&cred);

	return error;
}

int
mac_proc_check_run_cs_invalid(proc_t proc)
{
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vm_enforce) {
		return 0;
	}
#endif

	MAC_CHECK(proc_check_run_cs_invalid, proc);

	return error;
}

int
mac_proc_check_sched(proc_t curp, struct proc *proc)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_proc_enforce) {
		return 0;
	}
#endif
	if (!mac_proc_check_enforce(curp)) {
		return 0;
	}

	cred = kauth_cred_proc_ref(curp);
	MAC_CHECK(proc_check_sched, cred, proc);
	kauth_cred_unref(&cred);

	return error;
}

int
mac_proc_check_signal(proc_t curp, struct proc *proc, int signum)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_proc_enforce) {
		return 0;
	}
#endif
	if (!mac_proc_check_enforce(curp)) {
		return 0;
	}

	cred = kauth_cred_proc_ref(curp);
	MAC_CHECK(proc_check_signal, cred, proc, signum);
	kauth_cred_unref(&cred);

	return error;
}

int
mac_proc_check_syscall_unix(proc_t curp, int scnum)
{
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_proc_enforce) {
		return 0;
	}
#endif
	if (!mac_proc_check_enforce(curp)) {
		return 0;
	}

	MAC_CHECK(proc_check_syscall_unix, curp, scnum);

	return error;
}

int
mac_proc_check_wait(proc_t curp, struct proc *proc)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_proc_enforce) {
		return 0;
	}
#endif
	if (!mac_proc_check_enforce(curp)) {
		return 0;
	}

	cred = kauth_cred_proc_ref(curp);
	MAC_CHECK(proc_check_wait, cred, proc);
	kauth_cred_unref(&cred);

	return error;
}

void
mac_proc_notify_exit(struct proc *proc)
{
	MAC_PERFORM(proc_notify_exit, proc);
}

int
mac_proc_check_suspend_resume(proc_t curp, int sr)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_proc_enforce) {
		return 0;
	}
#endif
	if (!mac_proc_check_enforce(curp)) {
		return 0;
	}

	cred = kauth_cred_proc_ref(curp);
	MAC_CHECK(proc_check_suspend_resume, cred, curp, sr);
	kauth_cred_unref(&cred);

	return error;
}

int
mac_proc_check_ledger(proc_t curp, proc_t proc, int ledger_op)
{
	kauth_cred_t cred;
	int error = 0;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_proc_enforce) {
		return 0;
	}
#endif
	if (!mac_proc_check_enforce(curp)) {
		return 0;
	}

	cred = kauth_cred_proc_ref(curp);
	MAC_CHECK(proc_check_ledger, cred, proc, ledger_op);
	kauth_cred_unref(&cred);

	return error;
}

int
mac_proc_check_proc_info(proc_t curp, proc_t target, int callnum, int flavor)
{
	kauth_cred_t cred;
	int error = 0;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_proc_enforce) {
		return 0;
	}
#endif
	if (!mac_proc_check_enforce(curp)) {
		return 0;
	}

	cred = kauth_cred_proc_ref(curp);
	MAC_CHECK(proc_check_proc_info, cred, target, callnum, flavor);
	kauth_cred_unref(&cred);

	return error;
}

int
mac_proc_check_get_cs_info(proc_t curp, proc_t target, unsigned int op)
{
	kauth_cred_t cred;
	int error = 0;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_proc_enforce) {
		return 0;
	}
#endif
	if (!mac_proc_check_enforce(curp)) {
		return 0;
	}

	cred = kauth_cred_proc_ref(curp);
	MAC_CHECK(proc_check_get_cs_info, cred, target, op);
	kauth_cred_unref(&cred);

	return error;
}

int
mac_proc_check_set_cs_info(proc_t curp, proc_t target, unsigned int op)
{
	kauth_cred_t cred;
	int error = 0;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_proc_enforce) {
		return 0;
	}
#endif
	if (!mac_proc_check_enforce(curp)) {
		return 0;
	}

	cred = kauth_cred_proc_ref(curp);
	MAC_CHECK(proc_check_set_cs_info, cred, target, op);
	kauth_cred_unref(&cred);

	return error;
}
