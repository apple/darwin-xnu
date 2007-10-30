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
 * Copyright (c) 2005 SPARTA, Inc.
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

void
mac_task_label_init(struct label *label)
{

	mac_label_init(label);
	if (mac_late == 0) {
		mac_label_journal_add(label, MLJ_TYPE_TASK);
		mac_label_journal(label, MLJ_TASK_OP_INIT);
	}
	MAC_PERFORM(task_label_init, label);
}

void
mac_task_label_update(struct label *cred, struct label *task)
{

	MAC_PERFORM(task_label_update, cred, task);
}

void
mac_task_label_copy(struct label *src, struct label *dest)
{

	MAC_PERFORM(task_label_copy, src, dest);
}

void
mac_task_label_destroy(struct label *label)
{

	MAC_PERFORM(task_label_destroy, label);
	if (mac_late == 0)
		mac_label_journal_remove(label);
	mac_label_destroy(label);
}

void
mac_task_label_associate(struct task *parent, struct task *child, struct label *pl,
    struct label *chl, struct label *chportl)
{

	MAC_PERFORM(task_label_associate, parent, child, pl, chl, chportl);
}

void
mac_task_label_associate_kernel(struct task *t, struct label *tl, struct label *tportl)
{

	if (mac_late == 0)
		mac_label_journal(tl, MLJ_TASK_OP_CREATE_K);
	MAC_PERFORM(task_label_associate_kernel, t, tl, tportl);
}

int
mac_task_label_externalize(struct label *label, char *elements,
    char *outbuf, size_t outbuflen, int flags __unused)
{
	int error = 0;

	error = MAC_EXTERNALIZE(task, label, elements, outbuf, outbuflen);

	return (error);
}

int
mac_task_label_internalize(struct label *label, char *string)
{
	int error;

	error = MAC_INTERNALIZE(task, label, string);

	return (error);
}
