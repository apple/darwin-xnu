/*
 * Copyright (c) 2000-2013 Apple Inc. All rights reserved.
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
/*
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)in_proto.c	8.2 (Berkeley) 2/9/95
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/mbuf.h>

#include <kern/debug.h>

#include <net/if.h>
#include <net/route.h>
#include <net/kpi_protocol.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/igmp_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcpip.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/ip_encap.h>
#include <netinet/ip_divert.h>


/*
 * TCP/IP protocol family: IP, ICMP, UDP, TCP.
 */

#if IPSEC
#include <netinet6/ipsec.h>
#include <netinet6/ah.h>
#if IPSEC_ESP
#include <netinet6/esp.h>
#endif
#include <netinet6/ipcomp.h>
#endif /* IPSEC */

static void in_dinit(struct domain *);
static void ip_proto_input(protocol_family_t, mbuf_t);

extern struct domain inetdomain_s;
static struct pr_usrreqs nousrreqs;
extern struct pr_usrreqs icmp_dgram_usrreqs;
extern int icmp_dgram_ctloutput(struct socket *, struct sockopt *);

struct domain *inetdomain = NULL;

/* Thanks to PPP, this still needs to be exported */
lck_mtx_t       *inet_domain_mutex;

static struct protosw inetsw[] = {
	{
		.pr_type =              0,
		.pr_protocol =          0,
		.pr_init =              ip_init,
		.pr_drain =             ip_drain,
		.pr_usrreqs =           &nousrreqs,
	},
	{
		.pr_type =              SOCK_DGRAM,
		.pr_protocol =          IPPROTO_UDP,
		.pr_flags =             PR_ATOMIC | PR_ADDR | PR_PROTOLOCK | PR_PCBLOCK |
    PR_EVCONNINFO | PR_PRECONN_WRITE,
		.pr_input =             udp_input,
		.pr_ctlinput =          udp_ctlinput,
		.pr_ctloutput =         udp_ctloutput,
		.pr_init =              udp_init,
		.pr_usrreqs =           &udp_usrreqs,
		.pr_lock =              udp_lock,
		.pr_unlock =            udp_unlock,
		.pr_getlock =           udp_getlock,
	},
	{
		.pr_type =              SOCK_STREAM,
		.pr_protocol =          IPPROTO_TCP,
		.pr_flags =             PR_CONNREQUIRED | PR_WANTRCVD | PR_PCBLOCK |
    PR_PROTOLOCK | PR_DISPOSE | PR_EVCONNINFO |
    PR_PRECONN_WRITE | PR_DATA_IDEMPOTENT,
		.pr_input =             tcp_input,
		.pr_ctlinput =          tcp_ctlinput,
		.pr_ctloutput =         tcp_ctloutput,
		.pr_init =              tcp_init,
		.pr_drain =             tcp_drain,
		.pr_usrreqs =           &tcp_usrreqs,
		.pr_lock =              tcp_lock,
		.pr_unlock =            tcp_unlock,
		.pr_getlock =           tcp_getlock,
	},
	{
		.pr_type =              SOCK_RAW,
		.pr_protocol =          IPPROTO_RAW,
		.pr_flags =             PR_ATOMIC | PR_ADDR,
		.pr_input =             rip_input,
		.pr_ctlinput =          rip_ctlinput,
		.pr_ctloutput =         rip_ctloutput,
		.pr_usrreqs =           &rip_usrreqs,
		.pr_unlock =            rip_unlock,
	},
	{
		.pr_type =              SOCK_RAW,
		.pr_protocol =          IPPROTO_ICMP,
		.pr_flags =             PR_ATOMIC | PR_ADDR | PR_LASTHDR,
		.pr_input =             icmp_input,
		.pr_ctloutput =         rip_ctloutput,
		.pr_usrreqs =           &rip_usrreqs,
		.pr_unlock =            rip_unlock,
	},
	{
		.pr_type =              SOCK_DGRAM,
		.pr_protocol =          IPPROTO_ICMP,
		.pr_flags =             PR_ATOMIC | PR_ADDR | PR_LASTHDR,
		.pr_input =             icmp_input,
		.pr_ctloutput =         icmp_dgram_ctloutput,
		.pr_usrreqs =           &icmp_dgram_usrreqs,
		.pr_unlock =            rip_unlock,
	},
	{
		.pr_type =              SOCK_RAW,
		.pr_protocol =          IPPROTO_IGMP,
		.pr_flags =             PR_ATOMIC | PR_ADDR | PR_LASTHDR,
		.pr_input =             igmp_input,
		.pr_ctloutput =         rip_ctloutput,
		.pr_init =              igmp_init,
		.pr_usrreqs =           &rip_usrreqs,
		.pr_unlock =            rip_unlock,
	},
	{
		.pr_type =              SOCK_RAW,
		.pr_protocol =          IPPROTO_GRE,
		.pr_flags =             PR_ATOMIC | PR_ADDR,
		.pr_input =             gre_input,
		.pr_ctlinput =          rip_ctlinput,
		.pr_ctloutput =         rip_ctloutput,
		.pr_usrreqs =           &rip_usrreqs,
		.pr_unlock =            rip_unlock,
	},
#if IPSEC
	{
		.pr_type =              SOCK_RAW,
		.pr_protocol =          IPPROTO_AH,
		.pr_flags =             PR_ATOMIC | PR_ADDR | PR_PROTOLOCK,
		.pr_input =             ah4_input,
		.pr_usrreqs =           &nousrreqs,
	},
#if IPSEC_ESP
	{
		.pr_type =              SOCK_RAW,
		.pr_protocol =          IPPROTO_ESP,
		.pr_flags =             PR_ATOMIC | PR_ADDR | PR_PROTOLOCK,
		.pr_input =             esp4_input,
		.pr_usrreqs =           &nousrreqs,
	},
#endif /* IPSEC_ESP */
	{
		.pr_type =              SOCK_RAW,
		.pr_protocol =          IPPROTO_IPCOMP,
		.pr_flags =             PR_ATOMIC | PR_ADDR | PR_PROTOLOCK,
		.pr_input =             ipcomp4_input,
		.pr_init =              ipcomp_init,
		.pr_usrreqs =           &nousrreqs,
	},
#endif /* IPSEC */
	{
		.pr_type =              SOCK_RAW,
		.pr_protocol =          IPPROTO_IPV4,
		.pr_flags =             PR_ATOMIC | PR_ADDR | PR_LASTHDR,
		.pr_input =             encap4_input,
		.pr_ctloutput =         rip_ctloutput,
		.pr_init =              encap4_init,
		.pr_usrreqs =           &rip_usrreqs,
		.pr_unlock =            rip_unlock,
	},
#if INET6
	{
		.pr_type =              SOCK_RAW,
		.pr_protocol =          IPPROTO_IPV6,
		.pr_flags =             PR_ATOMIC | PR_ADDR | PR_LASTHDR,
		.pr_input =             encap4_input,
		.pr_ctloutput =         rip_ctloutput,
		.pr_init =              encap4_init,
		.pr_usrreqs =           &rip_usrreqs,
		.pr_unlock =            rip_unlock,
	},
#endif /* INET6 */
#if IPDIVERT
	{
		.pr_type =              SOCK_RAW,
		.pr_protocol =          IPPROTO_DIVERT,
		.pr_flags =             PR_ATOMIC | PR_ADDR | PR_PCBLOCK,
		.pr_input =             div_input,
		.pr_ctloutput =         ip_ctloutput,
		.pr_init =              div_init,
		.pr_usrreqs =           &div_usrreqs,
		.pr_lock =              div_lock,
		.pr_unlock =            div_unlock,
		.pr_getlock =           div_getlock,
	},
#endif /* IPDIVERT */
/* raw wildcard */
	{
		.pr_type =              SOCK_RAW,
		.pr_flags =             PR_ATOMIC | PR_ADDR | PR_LASTHDR,
		.pr_input =             rip_input,
		.pr_ctloutput =         rip_ctloutput,
		.pr_init =              rip_init,
		.pr_usrreqs =           &rip_usrreqs,
		.pr_unlock =            rip_unlock,
	},
};

static int in_proto_count = (sizeof(inetsw) / sizeof(struct protosw));

struct domain inetdomain_s = {
	.dom_family =           PF_INET,
	.dom_flags =            DOM_REENTRANT,
	.dom_name =             "internet",
	.dom_init =             in_dinit,
	.dom_rtattach =         in_inithead,
	.dom_rtoffset =         32,
	.dom_maxrtkey =         sizeof(struct sockaddr_in),
	.dom_protohdrlen =      sizeof(struct tcpiphdr),
};

/* Initialize the PF_INET domain, and add in the pre-defined protos */
void
in_dinit(struct domain *dp)
{
	struct protosw *pr;
	int i;
	domain_unguard_t unguard;

	VERIFY(!(dp->dom_flags & DOM_INITIALIZED));
	VERIFY(inetdomain == NULL);

	inetdomain = dp;

	/*
	 * Verify that the maximum possible tcp/ip header will still
	 * fit in a small mbuf because m_pullup only puls into 256
	 * byte mbuf
	 */
	_CASSERT((sizeof(struct tcpiphdr) + TCP_MAXOLEN) <= _MHLEN);

	/*
	 * Attach first, then initialize; ip_init() needs raw IP handler.
	 */
	for (i = 0, pr = &inetsw[0]; i < in_proto_count; i++, pr++) {
		net_add_proto(pr, dp, 0);
	}
	for (i = 0, pr = &inetsw[0]; i < in_proto_count; i++, pr++) {
		net_init_proto(pr, dp);
	}

	inet_domain_mutex = dp->dom_mtx;

	unguard = domain_unguard_deploy();
	i = proto_register_input(PF_INET, ip_proto_input, NULL, 1);
	if (i != 0) {
		panic("%s: failed to register PF_INET protocol: %d\n",
		    __func__, i);
		/* NOTREACHED */
	}
	domain_unguard_release(unguard);
}

static void
ip_proto_input(protocol_family_t protocol, mbuf_t packet_list)
{
#pragma unused(protocol)

	if (packet_list->m_nextpkt != NULL) {
		ip_input_process_list(packet_list);
	} else {
		/*
		 * XXX remove this path if ip_input_process_list is proven
		 * to be stable and has minimum overhead on most platforms.
		 */
		ip_input(packet_list);
	}
}

SYSCTL_NODE(_net, PF_INET, inet,
    CTLFLAG_RW | CTLFLAG_LOCKED, 0, "Internet Family");

SYSCTL_NODE(_net_inet, IPPROTO_IP, ip,
    CTLFLAG_RW | CTLFLAG_LOCKED, 0, "IP");
SYSCTL_NODE(_net_inet, IPPROTO_ICMP, icmp,
    CTLFLAG_RW | CTLFLAG_LOCKED, 0, "ICMP");
SYSCTL_NODE(_net_inet, IPPROTO_UDP, udp,
    CTLFLAG_RW | CTLFLAG_LOCKED, 0, "UDP");
SYSCTL_NODE(_net_inet, IPPROTO_TCP, tcp,
    CTLFLAG_RW | CTLFLAG_LOCKED, 0, "TCP");
SYSCTL_NODE(_net_inet, IPPROTO_IGMP, igmp,
    CTLFLAG_RW | CTLFLAG_LOCKED, 0, "IGMP");
#if IPSEC
SYSCTL_NODE(_net_inet, IPPROTO_AH, ipsec,
    CTLFLAG_RW | CTLFLAG_LOCKED, 0, "IPSEC");
#endif /* IPSEC */
SYSCTL_NODE(_net_inet, IPPROTO_RAW, raw,
    CTLFLAG_RW | CTLFLAG_LOCKED, 0, "RAW");
#if IPDIVERT
SYSCTL_NODE(_net_inet, IPPROTO_DIVERT, div,
    CTLFLAG_RW | CTLFLAG_LOCKED, 0, "DIVERT");
#endif /* IPDIVERT */
