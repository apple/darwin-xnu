/*
 * Copyright (c) 2007-2011 Apple Inc. All rights reserved.
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
 * Copyright (c) 2006-2007 SPARTA, Inc.
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
#include <sys/socket.h>
#include <sys/socketvar.h>

#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>

#include <security/mac_internal.h>

static struct label *
mac_inpcb_label_alloc(int flag)
{
	struct label *label;
	int error;

	label = mac_labelzone_alloc(flag);
	if (label == NULL)
		return (NULL);
	MAC_CHECK(inpcb_label_init, label, flag);
	if (error) {
		MAC_PERFORM(inpcb_label_destroy, label);
		mac_labelzone_free(label);
		return (NULL);
	}
	return (label);
}

int
mac_inpcb_label_init(struct inpcb *inp, int flag)
{

	inp->inp_label = mac_inpcb_label_alloc(flag);
	if (inp->inp_label == NULL)
		return (ENOMEM);
	return (0);
}

static struct label *
mac_ipq_label_alloc(int flag)
{
	struct label *label;
	int error;

	label = mac_labelzone_alloc(flag);
	if (label == NULL)
		return (NULL);

	MAC_CHECK(ipq_label_init, label, flag);
	if (error) {
		MAC_PERFORM(ipq_label_destroy, label);
		mac_labelzone_free(label);
		return (NULL);
	}
	return (label);
}

int
mac_ipq_label_init(struct ipq *ipq, int flag)
{

	ipq->ipq_label = mac_ipq_label_alloc(flag);
	if (ipq->ipq_label == NULL)
		return (ENOMEM);
	return (0);
}

static void
mac_inpcb_label_free(struct label *label)
{

	MAC_PERFORM(inpcb_label_destroy, label);
	mac_labelzone_free(label);
}

void
mac_inpcb_label_destroy(struct inpcb *inp)
{

	mac_inpcb_label_free(inp->inp_label);
	inp->inp_label = NULL;
}

void
mac_inpcb_label_recycle(struct inpcb *inp)
{

	MAC_PERFORM(inpcb_label_recycle, inp->inp_label);
}

static void
mac_ipq_label_free(struct label *label)
{

	MAC_PERFORM(ipq_label_destroy, label);
	mac_labelzone_free(label);
}

void
mac_ipq_label_destroy(struct ipq *ipq)
{

	mac_ipq_label_free(ipq->ipq_label);
	ipq->ipq_label = NULL;
}

void
mac_inpcb_label_associate(struct socket *so, struct inpcb *inp)
{

	MAC_PERFORM(inpcb_label_associate, so, so->so_label, inp,
	    inp->inp_label);
}

void
mac_mbuf_label_associate_ipq(struct ipq *ipq, struct mbuf *m)
{
	struct label *label;

	label = mac_mbuf_to_label(m);

	MAC_PERFORM(mbuf_label_associate_ipq, ipq, ipq->ipq_label, m, label);
}

void
mac_netinet_fragment(struct mbuf *datagram, struct mbuf *fragment)
{
	struct label *datagramlabel, *fragmentlabel;

	datagramlabel = mac_mbuf_to_label(datagram);
	fragmentlabel = mac_mbuf_to_label(fragment);

	MAC_PERFORM(netinet_fragment, datagram, datagramlabel, fragment,
	    fragmentlabel);
}

void
mac_ipq_label_associate(struct mbuf *fragment, struct ipq *ipq)
{
	struct label *label;

	label = mac_mbuf_to_label(fragment);

	MAC_PERFORM(ipq_label_associate, fragment, label, ipq, ipq->ipq_label);
}

void
mac_mbuf_label_associate_inpcb(struct inpcb *inp, struct mbuf *m)
{
	struct label *mlabel;

	/* INP_LOCK_ASSERT(inp); */
	mlabel = mac_mbuf_to_label(m);

	MAC_PERFORM(mbuf_label_associate_inpcb, inp, inp->inp_label, m, mlabel);
}

int
mac_ipq_label_compare(struct mbuf *fragment, struct ipq *ipq)
{
	struct label *label;
	int result;

	label = mac_mbuf_to_label(fragment);

	result = 1;
	MAC_BOOLEAN(ipq_label_compare, &&, fragment, label, ipq, ipq->ipq_label);

	return (result);
}

void
mac_netinet_icmp_reply(struct mbuf *m)
{
	struct label *label;

	label = mac_mbuf_to_label(m);

	MAC_PERFORM(netinet_icmp_reply, m, label);
}

void
mac_netinet_tcp_reply(struct mbuf *m)
{
	struct label *label;

	label = mac_mbuf_to_label(m);

	MAC_PERFORM(netinet_tcp_reply, m, label);
}

void
mac_ipq_label_update(struct mbuf *fragment, struct ipq *ipq)
{
	struct label *label;

	label = mac_mbuf_to_label(fragment);

	MAC_PERFORM(ipq_label_update, fragment, label, ipq, ipq->ipq_label);
}

int
mac_inpcb_check_deliver(struct inpcb *inp, struct mbuf *m, int family, int type)
{
	struct label *label;
	int error;

	if ((m->m_flags & M_PKTHDR) == 0)
		panic("%s: no mbuf packet header!", __func__);

	label = mac_mbuf_to_label(m);

	MAC_CHECK(inpcb_check_deliver, inp, inp->inp_label, m, label,
	    family, type);

	return (error);
}

/*
 * Propagate a change in the socket label to the inpcb label.
 */
void
mac_inpcb_label_update(struct socket *so)
{
	struct inpcb *inp;

	/* XXX: assert socket lock. */
	inp = sotoinpcb(so);	/* XXX: inp locking */

	if (inp != NULL) {
		/* INP_LOCK_ASSERT(inp); */
		MAC_PERFORM(inpcb_label_update, so, so->so_label, inp,
		    inp->inp_label);
	}
}
