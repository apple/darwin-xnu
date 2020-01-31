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
 * Copyright (c) 2002, 2003 Networks Associates Technology, Inc.
 * Copyright (c) 2005 SPARTA, Inc.
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
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/sbuf.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/pipe.h>
#include <sys/sysctl.h>

#include <security/mac_internal.h>


struct label *
mac_pipe_label_alloc(void)
{
	struct label *label;

	label = mac_labelzone_alloc(MAC_WAITOK);
	if (label == NULL) {
		return NULL;
	}
	MAC_PERFORM(pipe_label_init, label);
	return label;
}

void
mac_pipe_label_init(struct pipe *cpipe)
{
	cpipe->pipe_label = mac_pipe_label_alloc();
}

void
mac_pipe_label_free(struct label *label)
{
	MAC_PERFORM(pipe_label_destroy, label);
	mac_labelzone_free(label);
}

void
mac_pipe_label_destroy(struct pipe *cpipe)
{
	mac_pipe_label_free(cpipe->pipe_label);
	cpipe->pipe_label = NULL;
}

void
mac_pipe_label_copy(struct label *src, struct label *dest)
{
	MAC_PERFORM(pipe_label_copy, src, dest);
}

int
mac_pipe_label_externalize(struct label *label, char *elements,
    char *outbuf, size_t outbuflen)
{
	int error;

	error = MAC_EXTERNALIZE(pipe, label, elements, outbuf, outbuflen);

	return error;
}

int
mac_pipe_label_internalize(struct label *label, char *string)
{
	int error;

	error = MAC_INTERNALIZE(pipe, label, string);

	return error;
}

void
mac_pipe_label_associate(kauth_cred_t cred, struct pipe *cpipe)
{
	MAC_PERFORM(pipe_label_associate, cred, cpipe, cpipe->pipe_label);
}

int
mac_pipe_check_kqfilter(kauth_cred_t cred, struct knote *kn,
    struct pipe *cpipe)
{
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_pipe_enforce) {
		return 0;
	}
#endif
	MAC_CHECK(pipe_check_kqfilter, cred, kn, cpipe, cpipe->pipe_label);
	return error;
}
int
mac_pipe_check_ioctl(kauth_cred_t cred, struct pipe *cpipe, u_int cmd)
{
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_pipe_enforce) {
		return 0;
	}
#endif

	MAC_CHECK(pipe_check_ioctl, cred, cpipe, cpipe->pipe_label, cmd);

	return error;
}

int
mac_pipe_check_read(kauth_cred_t cred, struct pipe *cpipe)
{
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_pipe_enforce) {
		return 0;
	}
#endif

	MAC_CHECK(pipe_check_read, cred, cpipe, cpipe->pipe_label);

	return error;
}

static int
mac_pipe_check_label_update(kauth_cred_t cred, struct pipe *cpipe,
    struct label *newlabel)
{
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_pipe_enforce) {
		return 0;
	}
#endif

	MAC_CHECK(pipe_check_label_update, cred, cpipe, cpipe->pipe_label, newlabel);

	return error;
}

int
mac_pipe_check_select(kauth_cred_t cred, struct pipe *cpipe, int which)
{
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_pipe_enforce) {
		return 0;
	}
#endif

	MAC_CHECK(pipe_check_select, cred, cpipe, cpipe->pipe_label, which);

	return error;
}

int
mac_pipe_check_stat(kauth_cred_t cred, struct pipe *cpipe)
{
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_pipe_enforce) {
		return 0;
	}
#endif

	MAC_CHECK(pipe_check_stat, cred, cpipe, cpipe->pipe_label);

	return error;
}

int
mac_pipe_check_write(kauth_cred_t cred, struct pipe *cpipe)
{
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_pipe_enforce) {
		return 0;
	}
#endif

	MAC_CHECK(pipe_check_write, cred, cpipe, cpipe->pipe_label);

	return error;
}

int
mac_pipe_label_update(kauth_cred_t cred, struct pipe *cpipe,
    struct label *label)
{
	int error;

	error = mac_pipe_check_label_update(cred, cpipe, label);
	if (error) {
		return error;
	}

	MAC_PERFORM(pipe_label_update, cred, cpipe, cpipe->pipe_label, label);

	return 0;
}
