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
 * Copyright (c) 2003-2005 Networks Associates Technology, Inc.
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
 */

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/sbuf.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/file.h>
#include <sys/namei.h>
#include <sys/sysctl.h>
#include <sys/msg.h>

#include <security/mac_internal.h>

static struct label *
mac_sysv_msgmsg_label_alloc(void)
{
	struct label *label;

	label = mac_labelzone_alloc(MAC_WAITOK);
	if (label == NULL)
		return (NULL);
	MAC_PERFORM(sysvmsg_label_init, label);
	return (label);
}

void
mac_sysvmsg_label_init(struct msg *msgptr)
{

	msgptr->label = mac_sysv_msgmsg_label_alloc();
}

static struct label *
mac_sysv_msgqueue_label_alloc(void)
{
	struct label *label;

	label = mac_labelzone_alloc(MAC_WAITOK);
	if (label == NULL)
		return (NULL);
	MAC_PERFORM(sysvmsq_label_init, label);
	return (label);
}

void
mac_sysvmsq_label_init(struct msqid_kernel *msqptr)
{

	msqptr->label = mac_sysv_msgqueue_label_alloc();
}

void
mac_sysvmsg_label_associate(kauth_cred_t cred, struct msqid_kernel *msqptr, 
    struct msg *msgptr)
{
				
	MAC_PERFORM(sysvmsg_label_associate, cred, msqptr, msqptr->label, 
		msgptr, msgptr->label);
}

void
mac_sysvmsq_label_associate(kauth_cred_t cred, struct msqid_kernel *msqptr)
{
				
	MAC_PERFORM(sysvmsq_label_associate, cred, msqptr, msqptr->label);
}

void
mac_sysvmsg_label_recycle(struct msg *msgptr)
{

	MAC_PERFORM(sysvmsg_label_recycle, msgptr->label);
}

void
mac_sysvmsq_label_recycle(struct msqid_kernel *msqptr)
{
				
	MAC_PERFORM(sysvmsq_label_recycle, msqptr->label);
}

int
mac_sysvmsq_check_enqueue(kauth_cred_t cred, struct msg *msgptr,
	struct msqid_kernel *msqptr)
{
	int error;

	if (!mac_sysvmsg_enforce)
		return (0);

	MAC_CHECK(sysvmsq_check_enqueue, cred,  msgptr, msgptr->label, msqptr,
	    msqptr->label);

	return(error);
}

int
mac_sysvmsq_check_msgrcv(kauth_cred_t cred, struct msg *msgptr)
{
	int error;

	if (!mac_sysvmsg_enforce)
		return (0);

	MAC_CHECK(sysvmsq_check_msgrcv, cred, msgptr, msgptr->label);

	return(error);
}

int
mac_sysvmsq_check_msgrmid(kauth_cred_t cred, struct msg *msgptr)
{
	int error;

	if (!mac_sysvmsg_enforce)
		return (0);

	MAC_CHECK(sysvmsq_check_msgrmid, cred,  msgptr, msgptr->label);

	return(error);
}

int
mac_sysvmsq_check_msqget(kauth_cred_t cred, struct msqid_kernel *msqptr)
{
	int error;

	if (!mac_sysvmsg_enforce)
		return (0);

	MAC_CHECK(sysvmsq_check_msqget, cred, msqptr, msqptr->label);

	return(error);
}

int
mac_sysvmsq_check_msqsnd(kauth_cred_t cred, struct msqid_kernel *msqptr)
{
	int error;

	if (!mac_sysvmsg_enforce)
		return (0);

	MAC_CHECK(sysvmsq_check_msqsnd, cred, msqptr, msqptr->label);

	return(error);
}

int
mac_sysvmsq_check_msqrcv(kauth_cred_t cred, struct msqid_kernel *msqptr)
{
	int error;

	if (!mac_sysvmsg_enforce)
		return (0);

	MAC_CHECK(sysvmsq_check_msqrcv, cred, msqptr, msqptr->label);

	return(error);
}

int
mac_sysvmsq_check_msqctl(kauth_cred_t cred, struct msqid_kernel *msqptr,
    int cmd)
{
	int error;

	if (!mac_sysvmsg_enforce)
		return (0);

	MAC_CHECK(sysvmsq_check_msqctl, cred, msqptr, msqptr->label, cmd);

	return(error);
}
