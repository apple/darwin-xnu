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
 * Copyright (c) 2005 SPARTA, Inc.
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

#ifndef _SECURITY_MAC_MACH_INTERNAL_H_
#define _SECURITY_MAC_MACH_INTERNAL_H_

int mac_task_check_service(task_t self, task_t obj, const char *perm);
void mac_task_label_update_internal(struct label *pl, struct task *t);
int mac_port_label_compute(struct label *subj, struct label *obj,
    const char *serv, struct label *out);
int mac_port_check_method(task_t task, struct label *sub, struct label *obj, int msgid);

/* mac_do_machexc() flags */
#define	MAC_DOEXCF_TRACED	0x01	/* Only do mach exeception if
					   being ptrace()'ed */
struct uthread;
int	mac_do_machexc(int64_t code, int64_t subcode, uint32_t flags __unused);
int	mac_schedule_userret(void);
struct label *mac_thread_get_threadlabel(struct thread *thread);
struct label *mac_thread_get_uthreadlabel(struct uthread *uthread);

#if CONFIG_MACF
void mac_policy_init(void);
void mac_policy_initmach(void);

/* tasks */
void mac_task_label_init(struct label *);
void mac_task_label_copy(struct label *src, struct label *dest);
void mac_task_label_destroy(struct label *);
void mac_task_label_associate(struct task *, struct task *, struct label *,
    struct label *, struct label *);
void mac_task_label_associate_kernel(struct task *, struct label *, struct label *);
void mac_task_label_modify( struct task *pt, void *arg,
    void (*f)(struct label *l, void *arg));
struct label *mac_task_get_label(struct task *task);

/* ports */
void mac_port_label_init(struct label *l);
void mac_port_label_destroy(struct label *l);
void mac_port_label_associate(struct label *it, struct label *st, struct label *plabel);
void mac_port_label_associate_kernel(struct label *plabel, int isreply);
void mac_port_label_update_kobject(struct label *plabel, int kotype);
void mac_port_label_copy(struct label *src, struct label *dest);
void mac_port_label_update_cred(struct label *src, struct label *dest);
int mac_port_check_label_update(struct label *task, struct label *oldl, struct label *newl);

int mac_port_check_send(struct label *task, struct label *port);
int mac_port_check_receive(struct label *task, struct label *sender);
int mac_port_check_make_send(struct label *task, struct label *port);
int mac_port_check_make_send_once(struct label *task, struct label *port);
int mac_port_check_move_receive(struct label *task, struct label *port);
int mac_port_check_copy_send(struct label *task, struct label *port);
int mac_port_check_move_send(struct label *task, struct label *port);
int mac_port_check_move_send_once(struct label *task, struct label *port);

int mac_port_check_hold_send(struct label *task, struct label *port);
int mac_port_check_hold_send_once(struct label *task, struct label *port);
int mac_port_check_hold_receive(struct label *task, struct label *port);

int mac_task_label_externalize(struct label *, char *e, char *out, size_t olen, int flags);
int mac_task_label_internalize(struct label *label, char *string);
int mac_port_label_externalize(struct label *, char *e, char *out, size_t olen, int flags);
int mac_port_label_internalize(struct label *label, char *string);

void	mac_task_label_update(struct label *cred, struct label *task);
int	mac_port_check_service(struct label *subj, struct label *obj,
	    const char *serv, const char *perm);

/* threads */
void	act_set_astmacf(struct thread *);
void	mac_thread_userret(struct thread *);
#endif /* MAC */

#endif	/* !_SECURITY_MAC_MACH_INTERNAL_H_ */
