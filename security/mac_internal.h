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
 * Copyright (c) 1999, 2000, 2001, 2002 Robert N. M. Watson
 * Copyright (c) 2001 Ilmar S. Habibulin
 * Copyright (c) 2001, 2002, 2003, 2004 Networks Associates Technology, Inc.
 * Copyright (c) 2005 SPARTA, Inc.
 * All rights reserved.
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

#ifndef _SECURITY_MAC_INTERNAL_H_
#define _SECURITY_MAC_INTERNAL_H_

#ifndef PRIVATE
#warning "MAC policy is not KPI, see Technical Q&A QA1574, this header will be removed in next version"
#endif

#include <string.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <security/mac.h>
#include <security/mac_framework.h>
#include <security/mac_policy.h>
#include <security/mac_data.h>
#include <sys/sysctl.h>
#include <kern/wait_queue.h>
#include <kern/locks.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/sbuf.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/vnode.h>

/*
 * MAC Framework sysctl namespace.
 */

SYSCTL_DECL(_security);
SYSCTL_DECL(_security_mac);

extern int mac_late;

struct mac_policy_list_element {
        struct mac_policy_conf *mpc;
};    

struct mac_policy_list {
	u_int				numloaded;
	u_int 				max;
	u_int				maxindex;
	u_int				staticmax;
	u_int				chunks;
	u_int				freehint;
	struct mac_policy_list_element	*entries;
};

typedef struct mac_policy_list mac_policy_list_t;


/*
 * Policy that has registered with the framework for a specific
 * label namespace name.
 */
struct mac_label_listener {
	mac_policy_handle_t		mll_handle;
	LIST_ENTRY(mac_label_listener)	mll_list;
};

LIST_HEAD(mac_label_listeners_t, mac_label_listener);

/* 
 * Type of list used to manage label namespace names.
 */   
struct mac_label_element {
	char				mle_name[MAC_MAX_LABEL_ELEMENT_NAME];
	struct mac_label_listeners_t	mle_listeners;
	LIST_ENTRY(mac_label_element)	mle_list;
};

LIST_HEAD(mac_label_element_list_t, mac_label_element);

/*
 * MAC Framework global variables.
 */

extern struct mac_label_element_list_t mac_label_element_list;
extern struct mac_label_element_list_t mac_static_label_element_list;

extern struct mac_policy_list mac_policy_list;

/*
 * global flags to control whether a MACF subsystem is configured
 * at all in the system.
 */
extern unsigned int mac_device_enforce;
extern unsigned int mac_pipe_enforce;
extern unsigned int mac_posixsem_enforce;
extern unsigned int mac_posixshm_enforce;
extern unsigned int mac_proc_enforce;
extern unsigned int mac_socket_enforce;
extern unsigned int mac_system_enforce;
extern unsigned int mac_sysvmsg_enforce;
extern unsigned int mac_sysvsem_enforce;
extern unsigned int mac_sysvshm_enforce;
extern unsigned int mac_vm_enforce;
extern unsigned int mac_vnode_enforce;

#if CONFIG_MACF_NET
extern unsigned int mac_label_mbufs;
#endif

extern unsigned int mac_label_vnodes;

static int mac_proc_check_enforce(proc_t p, int enforce_flags);

static __inline__ int mac_proc_check_enforce(proc_t p, int enforce_flags)
{
#if CONFIG_MACF
	return ((p->p_mac_enforce & enforce_flags) != 0);
#else
#pragma unused(p,enforce_flags)
	return 0;
#endif
}

static int mac_context_check_enforce(vfs_context_t ctx, int enforce_flags);
static void mac_context_set_enforce(vfs_context_t ctx, int enforce_flags);

static __inline__ int mac_context_check_enforce(vfs_context_t ctx, int enforce_flags)
{
	proc_t proc = vfs_context_proc(ctx);

	if (proc == NULL)
		return 0;

	return (mac_proc_check_enforce(proc, enforce_flags));
}

static __inline__ void mac_context_set_enforce(vfs_context_t ctx, int enforce_flags)
{
#if CONFIG_MACF
	proc_t proc = vfs_context_proc(ctx);

	if (proc == NULL)
		return;

	mac_proc_set_enforce(proc, enforce_flags);
#else
#pragma unused(ctx,enforce_flags)
#endif
}


/*
 * MAC Framework infrastructure functions.
 */

int mac_error_select(int error1, int error2);

void  mac_policy_list_busy(void);
int   mac_policy_list_conditional_busy(void);
void  mac_policy_list_unbusy(void);

void           mac_labelzone_init(void);
struct label  *mac_labelzone_alloc(int flags);
void           mac_labelzone_free(struct label *label);

void  mac_label_init(struct label *label);
void  mac_label_destroy(struct label *label);
#if KERNEL
int   mac_check_structmac_consistent(struct user_mac *mac);
#else
int   mac_check_structmac_consistent(struct mac *mac);
#endif
	
int mac_cred_label_externalize(struct label *, char *e, char *out, size_t olen, int flags);
int mac_lctx_label_externalize(struct label *, char *e, char *out, size_t olen);
#if CONFIG_MACF_SOCKET
int mac_socket_label_externalize(struct label *, char *e, char *out, size_t olen);
#endif /* CONFIG_MACF_SOCKET */
int mac_vnode_label_externalize(struct label *, char *e, char *out, size_t olen, int flags);
int mac_pipe_label_externalize(struct label *label, char *elements,
 char *outbuf, size_t outbuflen);

int mac_cred_label_internalize(struct label *label, char *string);
int mac_lctx_label_internalize(struct label *label, char *string);
#if CONFIG_MACF_SOCKET
int mac_socket_label_internalize(struct label *label, char *string);
#endif /* CONFIG_MACF_SOCKET */
int mac_vnode_label_internalize(struct label *label, char *string);
int mac_pipe_label_internalize(struct label *label, char *string);

#if CONFIG_MACF_SOCKET
/* internal socket label manipulation functions */
struct  label *mac_socket_label_alloc(int flags);
void    mac_socket_label_free(struct label *l);
int     mac_socket_label_update(struct ucred *cred, struct socket *so, struct label *l);
#endif /* MAC_SOCKET */

#if CONFIG_MACF_NET
struct label *mac_mbuf_to_label(struct mbuf *m);
#else
#define mac_mbuf_to_label(m) (NULL)
#endif

/*
 * MAC_CHECK performs the designated check by walking the policy
 * module list and checking with each as to how it feels about the
 * request.  Note that it returns its value via 'error' in the scope
 * of the caller.
 */
#define	MAC_CHECK(check, args...) do {					\
	struct mac_policy_conf *mpc;					\
	u_int i;                                               		\
									\
	error = 0;							\
	for (i = 0; i < mac_policy_list.staticmax; i++) {		\
		mpc = mac_policy_list.entries[i].mpc;              	\
		if (mpc == NULL)                                	\
			continue;                               	\
									\
		if (mpc->mpc_ops->mpo_ ## check != NULL)		\
			error = mac_error_select(      			\
			    mpc->mpc_ops->mpo_ ## check (args),		\
			    error);					\
	}								\
	if (mac_policy_list_conditional_busy() != 0) {			\
		for (; i <= mac_policy_list.maxindex; i++) {		\
			mpc = mac_policy_list.entries[i].mpc;		\
			if (mpc == NULL)                                \
				continue;                               \
                                                                        \
			if (mpc->mpc_ops->mpo_ ## check != NULL)	\
				error = mac_error_select(      		\
				    mpc->mpc_ops->mpo_ ## check (args),	\
				    error);				\
		}							\
		mac_policy_list_unbusy();				\
	}								\
} while (0)

/*
 * MAC_GRANT performs the designated check by walking the policy
 * module list and checking with each as to how it feels about the
 * request.  Unlike MAC_CHECK, it grants if any policies return '0',
 * and otherwise returns EPERM.  Note that it returns its value via
 * 'error' in the scope of the caller.
 */
#define MAC_GRANT(check, args...) do {					\
	struct mac_policy_conf *mpc;					\
	u_int i;							\
									\
	error = EPERM;							\
	for (i = 0; i < mac_policy_list.staticmax; i++) {		\
		mpc = mac_policy_list.entries[i].mpc;			\
		if (mpc == NULL)					\
			continue;					\
									\
		if (mpc->mpc_ops->mpo_ ## check != NULL) {		\
			if (mpc->mpc_ops->mpo_ ## check (args) == 0)	\
				error = 0;				\
		}							\
	}								\
	if (mac_policy_list_conditional_busy() != 0) {			\
		for (; i <= mac_policy_list.maxindex; i++) {		\
			mpc = mac_policy_list.entries[i].mpc;		\
			if (mpc == NULL)				\
				continue;				\
									\
			if (mpc->mpc_ops->mpo_ ## check != NULL) {	\
				if (mpc->mpc_ops->mpo_ ## check (args)	\
				    == 0)				\
					error = 0;			\
			}						\
		}							\
		mac_policy_list_unbusy();				\
	}								\
} while (0)

/*
 * MAC_BOOLEAN performs the designated boolean composition by walking
 * the module list, invoking each instance of the operation, and
 * combining the results using the passed C operator.  Note that it
 * returns its value via 'result' in the scope of the caller, which
 * should be initialized by the caller in a meaningful way to get
 * a meaningful result.
 */
#define	MAC_BOOLEAN(operation, composition, args...) do {		\
	struct mac_policy_conf *mpc;					\
	u_int i;							\
									\
	for (i = 0; i < mac_policy_list.staticmax; i++) {		\
		mpc = mac_policy_list.entries[i].mpc;			\
		if (mpc == NULL)                                	\
			continue;                               	\
									\
		if (mpc->mpc_ops->mpo_ ## operation != NULL)		\
			result = result composition			\
			    mpc->mpc_ops->mpo_ ## operation		\
			    (args);					\
	}								\
	if (mac_policy_list_conditional_busy() != 0) {			\
		for (; i <= mac_policy_list.maxindex; i++) {		\
			mpc = mac_policy_list.entries[i].mpc;		\
			if (mpc == NULL)                                \
				continue;                               \
                                                                        \
			if (mpc->mpc_ops->mpo_ ## operation != NULL)	\
				result = result composition		\
				    mpc->mpc_ops->mpo_ ## operation	\
				    (args);				\
		}							\
		mac_policy_list_unbusy();				\
	}								\
} while (0)

#define	MAC_INTERNALIZE(obj, label, instring)				\
	mac_internalize(offsetof(struct mac_policy_ops, mpo_ ## obj ## _label_internalize), label, instring)

#define MAC_EXTERNALIZE(obj, label, elementlist, outbuf, outbuflen)	\
	mac_externalize(offsetof(struct mac_policy_ops, mpo_ ## obj ## _label_externalize), label, elementlist, outbuf, outbuflen)

#define MAC_EXTERNALIZE_AUDIT(obj, label, outbuf, outbuflen)	\
	mac_externalize(offsetof(struct mac_policy_ops, mpo_ ## obj ## _label_externalize_audit), label, "*", outbuf, outbuflen)

/*
 * MAC_PERFORM performs the designated operation by walking the policy
 * module list and invoking that operation for each policy.
 */
#define	MAC_PERFORM(operation, args...) do {				\
	struct mac_policy_conf *mpc;					\
	u_int i;							\
									\
	for (i = 0; i < mac_policy_list.staticmax; i++) {		\
		mpc = mac_policy_list.entries[i].mpc;			\
		if (mpc == NULL)					\
			continue;					\
									\
		if (mpc->mpc_ops->mpo_ ## operation != NULL)		\
			mpc->mpc_ops->mpo_ ## operation (args);		\
	}								\
	if (mac_policy_list_conditional_busy() != 0) {			\
		for (; i <= mac_policy_list.maxindex; i++) {		\
			mpc = mac_policy_list.entries[i].mpc;		\
			if (mpc == NULL)				\
				continue;				\
									\
			if (mpc->mpc_ops->mpo_ ## operation != NULL)	\
				mpc->mpc_ops->mpo_ ## operation (args);	\
		}							\
		mac_policy_list_unbusy();				\
	}								\
} while (0)

struct __mac_get_pid_args;
struct __mac_get_proc_args;
struct __mac_set_proc_args;
struct __mac_get_lcid_args;
struct __mac_get_lctx_args;
struct __mac_set_lctx_args;
struct __mac_get_fd_args;
struct __mac_get_file_args;
struct __mac_get_link_args;
struct __mac_set_fd_args;
struct __mac_set_file_args;
struct __mac_syscall_args;

void mac_policy_addto_labellist(const mac_policy_handle_t, int);
void mac_policy_removefrom_labellist(const mac_policy_handle_t);

int mac_externalize(size_t mpo_externalize_off, struct label *label,
    const char *elementlist, char *outbuf, size_t outbuflen);
int mac_internalize(size_t mpo_internalize_off, struct label *label,
    char *elementlist);
#endif	/* !_SECURITY_MAC_INTERNAL_H_ */
