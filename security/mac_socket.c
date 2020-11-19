/*
 * Copyright (c) 2007-2012 Apple Inc. All rights reserved.
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
 * Copyright (c) 1999-2002 Robert N. M. Watson
 * Copyright (c) 2001 Ilmar S. Habibulin
 * Copyright (c) 2001-2005 Networks Associates Technology, Inc.
 * Copyright (c) 2005 SPARTA, Inc.
 * All rights reserved.
 *
 * This software was developed by Robert Watson and Ilmar Habibulin for the
 * TrustedBSD Project.
 *
 * This software was developed for the FreeBSD Project in part by McAfee
 * Research, the Technology Research Division of Network Associates, Inc.
 * under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"), as part of the
 * DARPA CHATS research program.
 *
 * This software was enhanced by SPARTA ISSO under SPAWAR contract
 * N66001-04-C-6019 ("SEFOS").
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
#include <sys/mount.h>
#include <sys/file.h>
#include <sys/namei.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/kpi_socket.h>

#include <security/mac_internal.h>

int
mac_socket_check_accept(kauth_cred_t cred, struct socket *so)
{
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_socket_enforce) {
		return 0;
	}
#endif

	MAC_CHECK(socket_check_accept, cred,
	    (socket_t)so, so->so_label);
	return error;
}

#if CONFIG_MACF_SOCKET_SUBSET
int
mac_socket_check_accepted(kauth_cred_t cred, struct socket *so)
{
	struct sockaddr *sockaddr;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_socket_enforce) {
		return 0;
	}
#endif

	if (sock_getaddr((socket_t)so, &sockaddr, 1) != 0) {
		error = ECONNABORTED;
	} else {
		MAC_CHECK(socket_check_accepted, cred,
		    (socket_t)so, so->so_label, sockaddr);
		sock_freeaddr(sockaddr);
	}
	return error;
}
#endif

int
mac_socket_check_bind(kauth_cred_t ucred, struct socket *so,
    struct sockaddr *sockaddr)
{
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_socket_enforce) {
		return 0;
	}
#endif

	MAC_CHECK(socket_check_bind, ucred,
	    (socket_t)so, so->so_label, sockaddr);
	return error;
}

int
mac_socket_check_connect(kauth_cred_t cred, struct socket *so,
    struct sockaddr *sockaddr)
{
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_socket_enforce) {
		return 0;
	}
#endif

	MAC_CHECK(socket_check_connect, cred,
	    (socket_t)so, so->so_label,
	    sockaddr);
	return error;
}

int
mac_socket_check_create(kauth_cred_t cred, int domain, int type, int protocol)
{
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_socket_enforce) {
		return 0;
	}
#endif

	MAC_CHECK(socket_check_create, cred, domain, type, protocol);
	return error;
}

int
mac_socket_check_ioctl(kauth_cred_t cred, struct socket *so, u_long cmd)
{
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_socket_enforce) {
		return 0;
	}
#endif

	MAC_CHECK(socket_check_ioctl, cred,
	    (socket_t)so, cmd, so->so_label);
	return error;
}

int
mac_socket_check_stat(kauth_cred_t cred, struct socket *so)
{
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_socket_enforce) {
		return 0;
	}
#endif

	MAC_CHECK(socket_check_stat, cred,
	    (socket_t)so, so->so_label);
	return error;
}

int
mac_socket_check_listen(kauth_cred_t cred, struct socket *so)
{
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_socket_enforce) {
		return 0;
	}
#endif

	MAC_CHECK(socket_check_listen, cred,
	    (socket_t)so, so->so_label);
	return error;
}

int
mac_socket_check_receive(kauth_cred_t cred, struct socket *so)
{
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_socket_enforce) {
		return 0;
	}
#endif

	MAC_CHECK(socket_check_receive, cred,
	    (socket_t)so, so->so_label);
	return error;
}

int
mac_socket_check_received(kauth_cred_t cred, struct socket *so, struct sockaddr *saddr)
{
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_socket_enforce) {
		return 0;
	}
#endif

	MAC_CHECK(socket_check_received, cred,
	    so, so->so_label, saddr);
	return error;
}

int
mac_socket_check_send(kauth_cred_t cred, struct socket *so,
    struct sockaddr *sockaddr)
{
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_socket_enforce) {
		return 0;
	}
#endif

	MAC_CHECK(socket_check_send, cred,
	    (socket_t)so, so->so_label, sockaddr);
	return error;
}

int
mac_socket_check_setsockopt(kauth_cred_t cred, struct socket *so,
    struct sockopt *sopt)
{
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_socket_enforce) {
		return 0;
	}
#endif

	MAC_CHECK(socket_check_setsockopt, cred,
	    (socket_t)so, so->so_label, sopt);
	return error;
}

int
mac_socket_check_getsockopt(kauth_cred_t cred, struct socket *so,
    struct sockopt *sopt)
{
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_socket_enforce) {
		return 0;
	}
#endif

	MAC_CHECK(socket_check_getsockopt, cred,
	    (socket_t)so, so->so_label, sopt);
	return error;
}
