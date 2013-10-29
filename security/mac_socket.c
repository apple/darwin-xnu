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

#if CONFIG_MACF_SOCKET
struct label *
mac_socket_label_alloc(int flag)
{
	struct label *label;
	int error;

	label = mac_labelzone_alloc(flag);
	if (label == NULL)
		return (NULL);

	MAC_CHECK(socket_label_init, label, flag);
	if (error) {
		MAC_PERFORM(socket_label_destroy, label);
		mac_labelzone_free(label);
		return (NULL);
	}

	return (label);
}

static struct label *
mac_socket_peer_label_alloc(int flag)
{
	struct label *label;
	int error;

	label = mac_labelzone_alloc(flag);
	if (label == NULL)
		return (NULL);

	MAC_CHECK(socketpeer_label_init, label, flag);
	if (error) {
		MAC_PERFORM(socketpeer_label_destroy, label);
		mac_labelzone_free(label);
		return (NULL);
	}

	return (label);
}

int
mac_socket_label_init(struct socket *so, int flag)
{

	so->so_label = mac_socket_label_alloc(flag);
	if (so->so_label == NULL)
		return (ENOMEM);
	so->so_peerlabel = mac_socket_peer_label_alloc(flag);
	if (so->so_peerlabel == NULL) {
		mac_socket_label_free(so->so_label);
		so->so_label = NULL;
		return (ENOMEM);
	}
	return (0);
}

void
mac_socket_label_free(struct label *label)
{

	MAC_PERFORM(socket_label_destroy, label);
	mac_labelzone_free(label);
}

static void
mac_socket_peer_label_free(struct label *label)
{

	MAC_PERFORM(socketpeer_label_destroy, label);
	mac_labelzone_free(label);
}

void
mac_socket_label_destroy(struct socket *so)
{

	if (so->so_label != NULL) {
		mac_socket_label_free(so->so_label);
		so->so_label = NULL;
	}
	if (so->so_peerlabel != NULL) {
		mac_socket_peer_label_free(so->so_peerlabel);
		so->so_peerlabel = NULL;
	}
}

void
mac_socket_label_copy(struct label *src, struct label *dest)
{

	MAC_PERFORM(socket_label_copy, src, dest);
}

int
mac_socket_label_externalize(struct label *label, char *elements,
    char *outbuf, size_t outbuflen)
{
	int error;

	error = MAC_EXTERNALIZE(socket, label, elements, outbuf, outbuflen);

	return (error);
}

static int
mac_socketpeer_label_externalize(struct label *label, char *elements,
    char *outbuf, size_t outbuflen)
{
	int error;

	error = MAC_EXTERNALIZE(socketpeer, label, elements, outbuf, outbuflen);

	return (error);
}

int
mac_socket_label_internalize(struct label *label, char *string)
{
	int error;

	error = MAC_INTERNALIZE(socket, label, string);

	return (error);
}

void
mac_socket_label_associate(struct ucred *cred, struct socket *so)
{
	if (!mac_socket_enforce)
		return;

	MAC_PERFORM(socket_label_associate, cred, 
		    (socket_t)so, so->so_label);
}

void
mac_socket_label_associate_accept(struct socket *oldsocket,
    struct socket *newsocket)
{
	if (!mac_socket_enforce)
		return;

	MAC_PERFORM(socket_label_associate_accept, 
		    (socket_t)oldsocket, oldsocket->so_label,
		    (socket_t)newsocket, newsocket->so_label);
}

#if CONFIG_MACF_SOCKET && CONFIG_MACF_NET
void
mac_socketpeer_label_associate_mbuf(struct mbuf *mbuf, struct socket *so)
{
	struct label *label;

	if (!mac_socket_enforce && !mac_net_enforce)
		return;

	label = mac_mbuf_to_label(mbuf);

	/* Policy must deal with NULL label (unlabeled mbufs) */
	MAC_PERFORM(socketpeer_label_associate_mbuf, mbuf, label,
		    (socket_t)so, so->so_peerlabel);
}
#else
void
mac_socketpeer_label_associate_mbuf(__unused struct mbuf *mbuf, 
	__unused struct socket *so)
{
	return;
}
#endif

void
mac_socketpeer_label_associate_socket(struct socket *oldsocket,
    struct socket *newsocket)
{
	if (!mac_socket_enforce)
		return;

	MAC_PERFORM(socketpeer_label_associate_socket,
		    (socket_t)oldsocket, oldsocket->so_label,
		    (socket_t)newsocket, newsocket->so_peerlabel);
}

int
mac_socket_check_kqfilter(kauth_cred_t cred, struct knote *kn,
			  struct socket *so)
{
	int error;

	if (!mac_socket_enforce)
		return 0;

	MAC_CHECK(socket_check_kqfilter, cred, kn, 
		  (socket_t)so, so->so_label);
	return (error);
}

static int
mac_socket_check_label_update(kauth_cred_t cred, struct socket *so,
    struct label *newlabel)
{
	int error;

	if (!mac_socket_enforce)
		return 0;

	MAC_CHECK(socket_check_label_update, cred,
		  (socket_t)so, so->so_label,
		  newlabel);
	return (error);
}

int
mac_socket_check_select(kauth_cred_t cred, struct socket *so, int which)
{
	int error;

	if (!mac_socket_enforce)
		return 0;

	MAC_CHECK(socket_check_select, cred,
		  (socket_t)so, so->so_label, which);
	return (error);
}

int
mac_socket_check_stat(kauth_cred_t cred, struct socket *so)
{
	int error;

	if (!mac_socket_enforce)
		return 0;

	MAC_CHECK(socket_check_stat, cred,
		  (socket_t)so, so->so_label);
	return (error);
}


int
mac_socket_label_update(kauth_cred_t cred, struct socket *so, struct label *label)
{
	int error;
#if 0
	if (!mac_socket_enforce)
		return;
#endif
	error = mac_socket_check_label_update(cred, so, label);
	if (error)
		return (error);

	MAC_PERFORM(socket_label_update, cred,
		    (socket_t)so, so->so_label, label);

#if CONFIG_MACF_NET
	/*
	 * If the protocol has expressed interest in socket layer changes,
	 * such as if it needs to propagate changes to a cached pcb
	 * label from the socket, notify it of the label change while
	 * holding the socket lock.
	 * XXXMAC - are there cases when we should not do this?
	 */
	mac_inpcb_label_update(so);
#endif
	return (0);
}

int
mac_setsockopt_label(kauth_cred_t cred, struct socket *so, struct mac *mac)
{
	struct label *intlabel;
	char *buffer;
	int error;
	size_t len;

	error = mac_check_structmac_consistent(mac);
	if (error)
		return (error);

	MALLOC(buffer, char *, mac->m_buflen, M_MACTEMP, M_WAITOK);
	error = copyinstr(CAST_USER_ADDR_T(mac->m_string), buffer,
		mac->m_buflen, &len);
	if (error) {
		FREE(buffer, M_MACTEMP);
		return (error);
	}

	intlabel = mac_socket_label_alloc(MAC_WAITOK);
	error = mac_socket_label_internalize(intlabel, buffer);
	FREE(buffer, M_MACTEMP);
	if (error)
		goto out;

	error = mac_socket_label_update(cred, so, intlabel);
out:
	mac_socket_label_free(intlabel);
	return (error);
}

int
mac_socket_label_get(__unused kauth_cred_t cred, struct socket *so,
    struct mac *mac)
{
	char *buffer, *elements;
	struct label *intlabel;
	int error;
	size_t len;

	error = mac_check_structmac_consistent(mac);
	if (error)
		return (error);

	MALLOC(elements, char *, mac->m_buflen, M_MACTEMP, M_WAITOK);
	error = copyinstr(CAST_USER_ADDR_T(mac->m_string), elements,
		mac->m_buflen, &len);
	if (error) {
		FREE(elements, M_MACTEMP);
		return (error);
	}

	MALLOC(buffer, char *, mac->m_buflen, M_MACTEMP, M_WAITOK | M_ZERO);
	intlabel = mac_socket_label_alloc(MAC_WAITOK);
	mac_socket_label_copy(so->so_label, intlabel);
	error = mac_socket_label_externalize(intlabel, elements, buffer,
	    mac->m_buflen);
	mac_socket_label_free(intlabel);
	if (error == 0)
		error = copyout(buffer, CAST_USER_ADDR_T(mac->m_string),
			strlen(buffer)+1);

	FREE(buffer, M_MACTEMP);
	FREE(elements, M_MACTEMP);

	return (error);
}

int
mac_socketpeer_label_get(__unused kauth_cred_t cred, struct socket *so,
    struct mac *mac)
{
	char *elements, *buffer;
	struct label *intlabel;
	int error;
	size_t len;

	error = mac_check_structmac_consistent(mac);
	if (error)
		return (error);

	MALLOC(elements, char *, mac->m_buflen, M_MACTEMP, M_WAITOK);
	error = copyinstr(CAST_USER_ADDR_T(mac->m_string), elements,
		mac->m_buflen, &len);
	if (error) {
		FREE(elements, M_MACTEMP);
		return (error);
	}

	MALLOC(buffer, char *, mac->m_buflen, M_MACTEMP, M_WAITOK | M_ZERO);
	intlabel = mac_socket_label_alloc(MAC_WAITOK);
	mac_socket_label_copy(so->so_peerlabel, intlabel);
	error = mac_socketpeer_label_externalize(intlabel, elements, buffer,
	    mac->m_buflen);
	mac_socket_label_free(intlabel);
	if (error == 0)
		error = copyout(buffer, CAST_USER_ADDR_T(mac->m_string),
				strlen(buffer)+1);

	FREE(buffer, M_MACTEMP);
	FREE(elements, M_MACTEMP);

	return (error);
}
#endif /* MAC_SOCKET */

int
mac_socket_check_accept(kauth_cred_t cred, struct socket *so)
{
	int error;

	if (!mac_socket_enforce)
		return 0;

	MAC_CHECK(socket_check_accept, cred,
		  (socket_t)so, so->so_label);
	return (error);
}

#if CONFIG_MACF_SOCKET_SUBSET
int
mac_socket_check_accepted(kauth_cred_t cred, struct socket *so)
{
	struct sockaddr *sockaddr;
	int error;

	if (!mac_socket_enforce)
		return 0;

	if (sock_getaddr((socket_t)so, &sockaddr, 1) != 0) {
		error = ECONNABORTED;
	} else {
		MAC_CHECK(socket_check_accepted, cred,
			  (socket_t)so, so->so_label, sockaddr);
		sock_freeaddr(sockaddr);
	}
	return (error);
}
#endif

int
mac_socket_check_bind(kauth_cred_t ucred, struct socket *so,
    struct sockaddr *sockaddr)
{
	int error;

	if (!mac_socket_enforce)
		return 0;

	MAC_CHECK(socket_check_bind, ucred,
		  (socket_t)so, so->so_label, sockaddr);
	return (error);
}

int
mac_socket_check_connect(kauth_cred_t cred, struct socket *so,
    struct sockaddr *sockaddr)
{
	int error;

	if (!mac_socket_enforce)
		return 0;

	MAC_CHECK(socket_check_connect, cred,
		  (socket_t)so, so->so_label,
		  sockaddr);
	return (error);
}

int
mac_socket_check_create(kauth_cred_t cred, int domain, int type, int protocol)
{
	int error;

	if (!mac_socket_enforce)
		return 0;

	MAC_CHECK(socket_check_create, cred, domain, type, protocol);
	return (error);
}

#if CONFIG_MACF_SOCKET && CONFIG_MACF_NET
int
mac_socket_check_deliver(struct socket *so, struct mbuf *mbuf)
{
	struct label *label;
	int error;

	if (!mac_socket_enforce)
		return 0;

	label = mac_mbuf_to_label(mbuf);

	/* Policy must deal with NULL label (unlabeled mbufs) */
	MAC_CHECK(socket_check_deliver,
		  (socket_t)so, so->so_label, mbuf, label);
	return (error);
}
#else
int
mac_socket_check_deliver(__unused struct socket *so, __unused struct mbuf *mbuf)
{
	return (0);
}
#endif

int
mac_socket_check_listen(kauth_cred_t cred, struct socket *so)
{
	int error;

	if (!mac_socket_enforce)
		return 0;

	MAC_CHECK(socket_check_listen, cred,
		  (socket_t)so, so->so_label);
	return (error);
}

int
mac_socket_check_receive(kauth_cred_t cred, struct socket *so)
{
	int error;

	if (!mac_socket_enforce)
		return 0;

	MAC_CHECK(socket_check_receive, cred,
		  (socket_t)so, so->so_label);
	return (error);
}

int
mac_socket_check_received(kauth_cred_t cred, struct socket *so, struct sockaddr *saddr)
{
	int error;

	if (!mac_socket_enforce)
		return 0;
	
	MAC_CHECK(socket_check_received, cred,
		  so, so->so_label, saddr);
	return (error);
}

int
mac_socket_check_send(kauth_cred_t cred, struct socket *so,
		      struct sockaddr *sockaddr)
{
	int error;

	if (!mac_socket_enforce)
		return 0;

	MAC_CHECK(socket_check_send, cred,
		  (socket_t)so, so->so_label, sockaddr);
	return (error);
}

int
mac_socket_check_setsockopt(kauth_cred_t cred, struct socket *so,
			    struct sockopt *sopt)
{
	int error;

	if (!mac_socket_enforce)
		return (0);

	MAC_CHECK(socket_check_setsockopt, cred,
		  (socket_t)so, so->so_label, sopt);
	return (error);
}

int mac_socket_check_getsockopt(kauth_cred_t cred, struct socket *so,
				struct sockopt *sopt)
{
	int error;

	if (!mac_socket_enforce)
		return (0);

	MAC_CHECK(socket_check_getsockopt, cred,
		  (socket_t)so, so->so_label, sopt);
	return (error);
}
