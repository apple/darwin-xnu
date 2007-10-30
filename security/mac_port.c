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
 * Copyright (c) 2003, 2004 Networks Associates Technology, Inc.
 * Copyright (c) 2005-2006 SPARTA, Inc.
 * All rights reserved.
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

#include <security/mac_internal.h>
#include <security/mac_mach_internal.h>
#include <mach/message.h>
#include <kern/task.h>

void
mac_port_label_init(struct label *l)
{

	mac_label_init(l);
	if (mac_late == 0) {
		mac_label_journal_add(l, MLJ_TYPE_PORT);
		mac_label_journal(l, MLJ_PORT_OP_INIT);
	}
	MAC_PERFORM (port_label_init, l);
}

void
mac_port_label_destroy(struct label *l)
{

	MAC_PERFORM (port_label_destroy, l);
	if (mac_late == 0)
		mac_label_journal_remove(l);
	mac_label_destroy(l);
}

void
mac_port_label_copy(struct label *src, struct label *dest)
{

	MAC_PERFORM(port_label_copy, src, dest);
}

void
mac_port_label_update_cred(struct label *src, struct label *dest)
{

	MAC_PERFORM(port_label_update_cred, src, dest);
}

void
mac_port_label_associate(struct label *it, struct label *st, struct label *port)
{

	if (mac_late == 0)
		mac_label_journal(port, MLJ_PORT_OP_CREATE);
	MAC_PERFORM(port_label_associate, it, st, port);
}

void
mac_port_label_associate_kernel(struct label *port, int isreply)
{

	if (mac_late == 0)
		mac_label_journal(port, MLJ_PORT_OP_CREATE_K);
	MAC_PERFORM(port_label_associate_kernel, port, isreply);
}

void
mac_port_label_update_kobject(struct label *port, int kotype)
{

	if (mac_late == 0)
		mac_label_journal(port, MLJ_PORT_OP_UPDATE, kotype);
	MAC_PERFORM(port_label_update_kobject, port, kotype);
}

int
mac_port_label_internalize(struct label *label, char *string)
{
	int error;

	/* XXX - should have mpo_port_label_internalize */
	error = MAC_INTERNALIZE(cred, label, string);

	return (error);
}

int
mac_port_label_externalize(struct label *label, char *elements,
    char *outbuf, size_t outbuflen, int flags __unused)
{
	int error;

	/* XXX - should have mpo_port_label_externalize */
	error = MAC_EXTERNALIZE(cred, label, elements, outbuf, outbuflen);

	return (error);
}

int
mac_port_check_label_update(struct label *task, struct label *old,
    struct label *newlabel)
{
	int error;

	MAC_CHECK(port_check_label_update, task, old, newlabel);

	return (error);
}

int
mac_port_check_send(struct label *task, struct label *port)
{
	int error;

	MAC_CHECK(port_check_send, task, port);

	return (error);
}

int
mac_port_check_receive(struct label *task, struct label *sender)
{
	int error;
 
	MAC_CHECK(port_check_receive, task, sender);
 
	return (error);
}

int
mac_port_check_make_send(struct label *task, struct label *port)
{
	int error;

	MAC_CHECK(port_check_make_send, task, port);

	return (error);
}

int
mac_port_check_make_send_once(struct label *task, struct label *port)
{
	int error;

	MAC_CHECK(port_check_make_send_once, task, port);

	return (error);
}

int
mac_port_check_copy_send(struct label *task, struct label *port)
{
	int error;

	MAC_CHECK(port_check_copy_send, task, port);

	return (error);
}

int
mac_port_check_move_send(struct label *task, struct label *port)
{
	int error;

	MAC_CHECK(port_check_move_send, task, port);

	return (error);
}

int
mac_port_check_move_send_once(struct label *task, struct label *port)
{
	int error;

	MAC_CHECK(port_check_move_send_once, task, port);

	return (error);
}

int
mac_port_check_move_receive(struct label *task, struct label *port)
{
	int error;

	MAC_CHECK(port_check_move_receive, task, port);

	return (error);
}

int
mac_port_check_hold_send(struct label *task, struct label *port)
{
	int error;

	MAC_CHECK(port_check_hold_send, task, port);

	return (error);
}

int
mac_port_check_hold_send_once(struct label *task, struct label *port)
{
	int error;

	MAC_CHECK(port_check_hold_send_once, task, port);

	return (error);
}

int
mac_port_check_hold_receive(struct label *task, struct label *port)
{
	int error;

	MAC_CHECK(port_check_hold_receive, task, port);

	return (error);
}

int
mac_port_check_method(task_t task, struct label *sub, struct label *obj, int msgid)
{
	int error;

	MAC_CHECK(port_check_method, get_bsdtask_info(task), sub, obj, msgid);

	return (error);
}
