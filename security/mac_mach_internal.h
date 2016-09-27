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

#ifndef PRIVATE
#warning "MAC policy is not KPI, see Technical Q&A QA1574, this header will be removed in next version"
#endif

/* mac_do_machexc() flags */
#define	MAC_DOEXCF_TRACED	0x01	/* Only do mach exeception if
					   being ptrace()'ed */
struct uthread;
int	mac_do_machexc(int64_t code, int64_t subcode, uint32_t flags __unused);
int	mac_schedule_userret(void);

#if CONFIG_MACF
void mac_policy_init(void);
void mac_policy_initmach(void);

/* tasks */
int	mac_task_check_expose_task(struct task *t);

int	mac_task_check_set_host_special_port(struct task *task,
	    int id, struct ipc_port *port);
int	mac_task_check_set_host_exception_port(struct task *task,
	    unsigned int exception);
int	mac_task_check_set_host_exception_ports(struct task *task,
	    unsigned int exception_mask);

/* threads */
void	act_set_astmacf(struct thread *);
void	mac_thread_userret(struct thread *);

/* exception actions */
void mac_exc_action_label_init(struct exception_action *action);
void mac_exc_action_label_inherit(struct exception_action *parent, struct exception_action *child);
void mac_exc_action_label_destroy(struct exception_action *action);
int mac_exc_action_label_update(struct task *task, struct exception_action *action);
void mac_exc_action_label_reset(struct exception_action *action);

void mac_exc_action_label_task_update(struct task *task, struct proc *proc);
void mac_exc_action_label_task_destroy(struct task *task);

int mac_exc_action_check_exception_send(struct task *victim_task, struct exception_action *action);
#endif /* MAC */

#endif	/* !_SECURITY_MAC_MACH_INTERNAL_H_ */
