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
 * Copyright (c) 1999-2002 Robert N. M. Watson
 * Copyright (c) 2001 Ilmar S. Habibulin
 * Copyright (c) 2001-2004 Networks Associates Technology, Inc.
 * Copyright (c) 2006 SPARTA, Inc.
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

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>

#include <net/bpf.h>
#include <net/if.h>

#include <bsd/bsm/audit.h>
#include <bsd/bsm/audit_kernel.h>

#include <security/mac_internal.h>

struct label *
mac_mbuf_to_label(struct mbuf *mbuf)
{
	struct m_tag *tag;
	struct label *label;

	if (mbuf == NULL)
		return (NULL);

	if ((mbuf->m_flags & M_PKTHDR) == 0) {
		printf("%s() got non-header MBUF!\n", __func__);
		return (NULL);
	}

	tag = m_tag_locate(mbuf, KERNEL_MODULE_TAG_ID, KERNEL_TAG_TYPE_MACLABEL,
			   NULL);
	if (tag == NULL) {
		printf("%s() m_tag_locate() returned NULL! (m->flags %04x)\n",
			__func__, mbuf->m_flags);
		return (NULL);
	}
	label = (struct label *)(tag+1);
	return (label);
}

static struct label *
mac_bpfdesc_label_alloc(void)
{
	struct label *label;

	label = mac_labelzone_alloc(M_WAITOK);
	if (label == NULL)
		return (NULL);
	MAC_PERFORM(bpfdesc_label_init, label);
	return (label);
}

void
mac_bpfdesc_label_init(struct bpf_d *bpf_d)
{
	struct label *label;

	label = mac_bpfdesc_label_alloc();
	mac_bpfdesc_label_set(bpf_d, label);
}

static struct label *
mac_ifnet_label_alloc(void)
{
	struct label *label;

	label = mac_labelzone_alloc(M_WAITOK);
	if (label == NULL)
		return (NULL);
	MAC_PERFORM(ifnet_label_init, label);
	return (label);
}

void
mac_ifnet_label_init(struct ifnet *ifp)
{

	ifp->if_label = mac_ifnet_label_alloc();
}

/*
 * On failure, caller should cleanup with m_tag_free().
 */
int
mac_mbuf_tag_init(struct m_tag *tag, int flag)
{
	struct label *label;
	int error;

	label = (struct label *) (tag + 1);
	mac_label_init(label);

	MAC_CHECK(mbuf_label_init, label, flag);
	if (error)
		printf("%s(): mpo_mbuf_label_init() failed!\n", __func__);

	return (error);
}

static void
mac_bpfdesc_label_free(struct label *label)
{

	MAC_PERFORM(bpfdesc_label_destroy, label);
	mac_labelzone_free(label);
}

void
mac_bpfdesc_label_destroy(struct bpf_d *bpf_d)
{
	struct label *label;

	label = mac_bpfdesc_label_get(bpf_d);
	mac_bpfdesc_label_free(label);
	mac_bpfdesc_label_set(bpf_d, NULL);
}

static void
mac_ifnet_label_free(struct label *label)
{

	MAC_PERFORM(ifnet_label_destroy, label);
	mac_labelzone_free(label);
}

void
mac_ifnet_label_destroy(struct ifnet *ifp)
{

	mac_ifnet_label_free(ifp->if_label);
	ifp->if_label = NULL;
}

void
mac_ifnet_label_recycle(struct ifnet *ifp)
{

	MAC_PERFORM(ifnet_label_recycle, ifp->if_label);
}

void
mac_mbuf_tag_destroy(struct m_tag *tag)
{
	struct label *label;

	label = (struct label *)(tag + 1);
	MAC_PERFORM(mbuf_label_destroy, label);
	mac_label_destroy(label);

	return;
}

void
mac_mbuf_tag_copy(struct m_tag *src, struct m_tag *dest)
{
	struct label *src_label, *dest_label;

	src_label = (struct label *)(src + 1);
	dest_label = (struct label *)(dest + 1);

	if (src_label == NULL || dest_label == NULL)
		return;

	/*
	 * mac_mbuf_tag_init() is called on the target tag
	 * in m_tag_copy(), so we don't need to call it here.
	 */
	MAC_PERFORM(mbuf_label_copy, src_label, dest_label);

	return;
}

void
mac_mbuf_label_copy(struct mbuf *m_from, struct mbuf *m_to)
{
	struct label *src_label, *dest_label;

	src_label = mac_mbuf_to_label(m_from);
	dest_label = mac_mbuf_to_label(m_to);

	MAC_PERFORM(mbuf_label_copy, src_label, dest_label);
}

static void
mac_ifnet_label_copy(struct label *src, struct label *dest)
{

	MAC_PERFORM(ifnet_label_copy, src, dest);
}

static int
mac_ifnet_label_externalize(struct label *label, char *elements,
    char *outbuf, size_t outbuflen)
{

	return (MAC_EXTERNALIZE(ifnet, label, elements, outbuf, outbuflen));
}

static int
mac_ifnet_label_internalize(struct label *label, char *string)
{

	return (MAC_INTERNALIZE(ifnet, label, string));
}

void
mac_ifnet_label_associate(struct ifnet *ifp)
{

	MAC_PERFORM(ifnet_label_associate, ifp, ifp->if_label);
}

void
mac_bpfdesc_label_associate(struct ucred *cred, struct bpf_d *bpf_d)
{
	struct label *label;

	label = mac_bpfdesc_label_get(bpf_d);
	MAC_PERFORM(bpfdesc_label_associate, cred, bpf_d, label);
}

int
mac_bpfdesc_check_receive(struct bpf_d *bpf_d, struct ifnet *ifp)
{
	struct label *label;
	int error;

	label = mac_bpfdesc_label_get(bpf_d);
	ifnet_lock_shared(ifp);
	MAC_CHECK(bpfdesc_check_receive, bpf_d, label, ifp,
	    ifp->if_label);
	ifnet_lock_done(ifp);

	return (error);
}

int
mac_mbuf_label_init(struct mbuf *m, int flag)
{
	struct m_tag *tag;
	int error;

	if (mac_label_mbufs == 0)
		return (0);

	tag = m_tag_alloc(KERNEL_MODULE_TAG_ID, KERNEL_TAG_TYPE_MACLABEL,
			  sizeof(struct label), flag);
	if (tag == NULL) {
		printf("%s(): m_tag_alloc() failed!\n", __func__);
		return (ENOBUFS);
	}
	error = mac_mbuf_tag_init(tag, flag);
	if (error) {
		printf("%s(): mac_mbuf_tag_init() failed!\n", __func__);
		m_tag_free(tag);
		return (error);
	}
	m_tag_prepend(m, tag);
	return (0);
}

void
mac_mbuf_label_associate_bpfdesc(struct bpf_d *bpf_d, struct mbuf *mbuf)
{
	struct label *m_label, *b_label;

	/* bpf_d must be locked */

	m_label = mac_mbuf_to_label(mbuf);
	b_label = mac_bpfdesc_label_get(bpf_d);

	MAC_PERFORM(mbuf_label_associate_bpfdesc, bpf_d, b_label, mbuf,
	    m_label);
}

void
mac_mbuf_label_associate_ifnet(struct ifnet *ifp, struct mbuf *mbuf)
{
	struct label *m_label;

	/* ifp must be locked */

	m_label = mac_mbuf_to_label(mbuf);

	MAC_PERFORM(mbuf_label_associate_ifnet, ifp, ifp->if_label, mbuf,
	    m_label);
}

void
mac_mbuf_label_associate_linklayer(struct ifnet *ifp, struct mbuf *mbuf)
{
	struct label *m_label;

	/* ifp must be locked */

	m_label = mac_mbuf_to_label(mbuf);

	MAC_PERFORM(mbuf_label_associate_linklayer, ifp, ifp->if_label, mbuf,
	    m_label);
}

void
mac_mbuf_label_associate_multicast_encap(struct mbuf *oldmbuf,
    struct ifnet *ifp, struct mbuf *newmbuf)
{
	struct label *oldmbuflabel, *newmbuflabel;

	oldmbuflabel = mac_mbuf_to_label(oldmbuf);
	newmbuflabel = mac_mbuf_to_label(newmbuf);

	/* ifp must be locked */

	MAC_PERFORM(mbuf_label_associate_multicast_encap, oldmbuf, oldmbuflabel,
	    ifp, ifp->if_label, newmbuf, newmbuflabel);
}

void
mac_mbuf_label_associate_netlayer(struct mbuf *oldmbuf, struct mbuf *newmbuf)
{
	struct label *oldmbuflabel, *newmbuflabel;

	oldmbuflabel = mac_mbuf_to_label(oldmbuf);
	newmbuflabel = mac_mbuf_to_label(newmbuf);

	MAC_PERFORM(mbuf_label_associate_netlayer, oldmbuf, oldmbuflabel,
	    newmbuf, newmbuflabel);
}

void
mac_mbuf_label_associate_socket(struct socket *socket, struct mbuf *mbuf)
{
	struct label *label;
	struct xsocket xso;

	/* socket must be locked */

	label = mac_mbuf_to_label(mbuf);

	sotoxsocket(socket, &xso);
	MAC_PERFORM(mbuf_label_associate_socket, &xso, socket->so_label,
		    mbuf, label);
}

int
mac_ifnet_check_transmit(struct ifnet *ifp, struct mbuf *mbuf, int family,
    int type)
{
	struct label *label;
	int error;

	label = mac_mbuf_to_label(mbuf);

	ifnet_lock_shared(ifp);
	MAC_CHECK(ifnet_check_transmit, ifp, ifp->if_label, mbuf, label,
	    family, type);
	ifnet_lock_done(ifp);

	return (error);
}

int
mac_ifnet_label_get(__unused struct ucred *cred, struct ifreq *ifr,
    struct ifnet *ifp)
{
	char *elements, *buffer;
	struct label *intlabel;
	struct mac mac;
	int error;
	size_t len;

	error = copyin(CAST_USER_ADDR_T(ifr->ifr_ifru.ifru_data),
	    &mac, sizeof(mac));
	if (error)
		return (error);

	error = mac_check_structmac_consistent(&mac);
	if (error)
		return (error);

	MALLOC(elements, char *, mac.m_buflen, M_MACTEMP, M_WAITOK);
	error = copyinstr(CAST_USER_ADDR_T(mac.m_string), elements,
	    mac.m_buflen, &len);
	if (error) {
		FREE(elements, M_MACTEMP);
		return (error);
	}
	AUDIT_ARG(mac_string, elements);

	MALLOC(buffer, char *, mac.m_buflen, M_MACTEMP, M_WAITOK | M_ZERO);
	intlabel = mac_ifnet_label_alloc();
	ifnet_lock_shared(ifp);
	mac_ifnet_label_copy(ifp->if_label, intlabel);
	ifnet_lock_done(ifp);
	error = mac_ifnet_label_externalize(intlabel, elements,
	    buffer, mac.m_buflen);
	mac_ifnet_label_free(intlabel);
	FREE(elements, M_MACTEMP);

	if (error == 0)
		error = copyout(buffer, CAST_USER_ADDR_T(mac.m_string),
		    strlen(buffer) + 1);
	FREE(buffer, M_MACTEMP);

	return (error);
}

int
mac_ifnet_label_set(struct ucred *cred, struct ifreq *ifr,
    struct ifnet *ifp)
{
	struct label *intlabel;
	struct mac mac;
	char *buffer;
	int error;
	size_t len;

	error = copyin(CAST_USER_ADDR_T(ifr->ifr_ifru.ifru_data),
	    &mac, sizeof(mac));
	if (error)
		return (error);

	error = mac_check_structmac_consistent(&mac);
	if (error)
		return (error);

	MALLOC(buffer, char *, mac.m_buflen, M_MACTEMP, M_WAITOK);
	error = copyinstr(CAST_USER_ADDR_T(mac.m_string), buffer,
	    mac.m_buflen, &len);
	if (error) {
		FREE(buffer, M_MACTEMP);
		return (error);
	}
	AUDIT_ARG(mac_string, buffer);

	intlabel = mac_ifnet_label_alloc();
	error = mac_ifnet_label_internalize(intlabel, buffer);
	FREE(buffer, M_MACTEMP);
	if (error) {
		mac_ifnet_label_free(intlabel);
		return (error);
	}

	/*
	 * XXX: Note that this is a redundant privilege check, since
	 * policies impose this check themselves if required by the
	 * policy.  Eventually, this should go away.
	 */
	error = suser(cred, NULL);
	if (error) {
		mac_ifnet_label_free(intlabel);
		return (error);
	}

	ifnet_lock_exclusive(ifp);
	MAC_CHECK(ifnet_check_label_update, cred, ifp, ifp->if_label,
	    intlabel);
	if (error) {
		ifnet_lock_done(ifp);
		mac_ifnet_label_free(intlabel);
		return (error);
	}

	MAC_PERFORM(ifnet_label_update, cred, ifp, ifp->if_label, intlabel);
	ifnet_lock_done(ifp);
	mac_ifnet_label_free(intlabel);

	return (0);
}
