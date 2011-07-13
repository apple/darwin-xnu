/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
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

#if IPXIP
#include <netipx/ipx_ip.h>
#endif

extern	struct domain inetdomain;
static	struct pr_usrreqs nousrreqs;
extern struct   pr_usrreqs icmp_dgram_usrreqs;
extern int icmp_dgram_ctloutput(struct socket *, struct sockopt *);


struct protosw inetsw[] = {
{ 0,		&inetdomain,	0,		0,
  0,		0,		0,		0,
  0,
  ip_init,	0,		ip_slowtimo,	ip_drain,
  0,	
  &nousrreqs,
  0,		0,		0,	{ 0, 0 },	0,	{ 0 }
},
{ SOCK_DGRAM,	&inetdomain,	IPPROTO_UDP,	PR_ATOMIC|PR_ADDR|PR_PROTOLOCK|PR_PCBLOCK,
  udp_input,	0,		udp_ctlinput,	udp_ctloutput,
  0,
  udp_init,	0,		udp_slowtimo,		0,
  0,
  &udp_usrreqs,
  udp_lock,	udp_unlock,	udp_getlock,	{ 0, 0 },	0,	{ 0 }
},
{ SOCK_STREAM,	&inetdomain,	IPPROTO_TCP, 
	PR_CONNREQUIRED|PR_WANTRCVD|PR_PCBLOCK|PR_PROTOLOCK|PR_DISPOSE,
  tcp_input,	0,		tcp_ctlinput,	tcp_ctloutput,
  0,
  tcp_init,	0,	tcp_slowtimo,	tcp_drain,
  0,
  &tcp_usrreqs,
  tcp_lock,	tcp_unlock,	tcp_getlock,	{ 0, 0 },	0,	{ 0 }
},
{ SOCK_RAW,	&inetdomain,	IPPROTO_RAW,	PR_ATOMIC|PR_ADDR,
  rip_input,	0,		rip_ctlinput,	rip_ctloutput,
  0,
  0,		0,		0,		0,
  0,
  &rip_usrreqs,
  0,		rip_unlock,		0,	{ 0, 0 },	0,	{ 0 }
},
{ SOCK_RAW,	&inetdomain,	IPPROTO_ICMP,	PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  icmp_input,	0,		0,		rip_ctloutput,
  0,
  0,		0,		0,		0,
  0,
  &rip_usrreqs,
  0,		rip_unlock,	0,	{ 0, 0 },	0,	{ 0 }
},
{ SOCK_DGRAM, &inetdomain,	IPPROTO_ICMP,   PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  icmp_input,	0,		0,              icmp_dgram_ctloutput,
  0,
  0,		0,              0,              0,
  0,	
  &icmp_dgram_usrreqs,
  0,		rip_unlock,	  	0,	{ 0, 0 },	0,	{ 0 }
},
{ SOCK_RAW,	&inetdomain,	IPPROTO_IGMP,	PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  igmp_input,	0,		0,		rip_ctloutput,
  0,
  igmp_init,	0,		igmp_slowtimo,	0,
  0,
  &rip_usrreqs,
  0,		rip_unlock,	0,	{ 0, 0 },	0,	{ 0 }
},
#if MROUTING
{ SOCK_RAW,	&inetdomain,	IPPROTO_RSVP,	PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  rsvp_input,	0,		0,		rip_ctloutput,
  0,
  0,		0,		0,		0,
  0,
  &rip_usrreqs,
  0,		rip_unlock,		0,	{ 0, 0 },	0,	{ 0 }
},
#endif /* MROUTING */
#if IPSEC
{ SOCK_RAW,	&inetdomain,	IPPROTO_AH,	PR_ATOMIC|PR_ADDR|PR_PROTOLOCK,
  ah4_input,	0,	 	0,		0,
  0,	  
  0,		0,		0,		0,
  0,
  &nousrreqs,
  0,		0,		0,	{ 0, 0 },	0,	{ 0 }
},
#if IPSEC_ESP
{ SOCK_RAW,	&inetdomain,	IPPROTO_ESP,	PR_ATOMIC|PR_ADDR|PR_PROTOLOCK,
  esp4_input,	0,	 	0,		0,
  0,	  
  0,		0,		0,		0,
  0,
  &nousrreqs,
  0,		0,		0,	{ 0, 0 },	0,	{ 0 }
},
#endif
{ SOCK_RAW,	&inetdomain,	IPPROTO_IPCOMP,	PR_ATOMIC|PR_ADDR|PR_PROTOLOCK,
  ipcomp4_input, 0,	 	0,		0,
  0,	  
  0,		0,		0,		0,
  0,
  &nousrreqs,
  0,		0,		0,	{ 0, 0 },	0,	{ 0 }
},
#endif /* IPSEC */
{ SOCK_RAW,	&inetdomain,	IPPROTO_IPV4,	PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  encap4_input,	0,	 	0,		rip_ctloutput,
  0,
  encap_init,		0,		0,		0,
  0,
  &rip_usrreqs,
  0,		0,		0,	{ 0, 0 },	0,	{ 0 }
},
# if INET6
{ SOCK_RAW,	&inetdomain,	IPPROTO_IPV6,	PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  encap4_input,	0,	 	0,		rip_ctloutput,
  0,
  encap_init,	0,		0,		0,
  0,
  &rip_usrreqs,
  0,		0,		0,	{ 0, 0 },	0,	{ 0 }
},
#endif
#if IPDIVERT
{ SOCK_RAW,	&inetdomain,	IPPROTO_DIVERT,	PR_ATOMIC|PR_ADDR|PR_PCBLOCK,
  div_input,	0,	 	0,		ip_ctloutput,
  0,
  div_init,	0,		0,		0,
  0,
  &div_usrreqs,
  div_lock,		div_unlock,		div_getlock,	{ 0, 0 },	0,	{ 0 }
},
#endif
#if IPXIP
{ SOCK_RAW,	&inetdomain,	IPPROTO_IDP,	PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  ipxip_input,	0,		ipxip_ctlinput,	0,
  0,
  0,		0,		0,		0,
  0,
  &rip_usrreqs,
  0,		0,		0,	{ 0, 0 },	0,	{ 0 }
},
#endif
#if NSIP
{ SOCK_RAW,	&inetdomain,	IPPROTO_IDP,	PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  idpip_input,	0,		nsip_ctlinput,	0,
  0,
  0,		0,		0,		0,
  0,
  &rip_usrreqs,
  0,		0,		0,	{ 0, 0 },	0,	{ 0 }
},
#endif
	/* raw wildcard */
{ SOCK_RAW,	&inetdomain,	0,		PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  rip_input,	0,		0,		rip_ctloutput,
  0,
  rip_init,	0,		0,		0,
  0,
  &rip_usrreqs,
  0,			rip_unlock,		0,	{ 0, 0 },	0,	{ 0 }
},
};

extern int in_inithead(void **, int);

int in_proto_count = (sizeof (inetsw) / sizeof (struct protosw));

extern void in_dinit(void) __attribute__((section("__TEXT, initcode")));
/* A routing init function, and a header size */
struct domain inetdomain =
    { AF_INET, 
      "internet", 
      in_dinit, 
      0, 
      0, 
      inetsw, 
      0,
      in_inithead, 
      32, 
      sizeof(struct sockaddr_in),
      sizeof(struct tcpiphdr), 
      0, 
      0, 
      0, 
      { 0, 0}
    };

DOMAIN_SET(inet);

SYSCTL_NODE(_net,      PF_INET,		inet,	CTLFLAG_RW|CTLFLAG_LOCKED, 0,
	"Internet Family");

SYSCTL_NODE(_net_inet, IPPROTO_IP,	ip,	CTLFLAG_RW|CTLFLAG_LOCKED, 0,	"IP");
SYSCTL_NODE(_net_inet, IPPROTO_ICMP,	icmp,	CTLFLAG_RW|CTLFLAG_LOCKED, 0,	"ICMP");
SYSCTL_NODE(_net_inet, IPPROTO_UDP,	udp,	CTLFLAG_RW|CTLFLAG_LOCKED, 0,	"UDP");
SYSCTL_NODE(_net_inet, IPPROTO_TCP,	tcp,	CTLFLAG_RW|CTLFLAG_LOCKED, 0,	"TCP");
SYSCTL_NODE(_net_inet, IPPROTO_IGMP,	igmp,	CTLFLAG_RW|CTLFLAG_LOCKED, 0,	"IGMP");
#if IPSEC
SYSCTL_NODE(_net_inet, IPPROTO_AH,	ipsec,	CTLFLAG_RW|CTLFLAG_LOCKED, 0,	"IPSEC");
#endif /* IPSEC */
SYSCTL_NODE(_net_inet, IPPROTO_RAW,	raw,	CTLFLAG_RW|CTLFLAG_LOCKED, 0,	"RAW");
#if IPDIVERT
SYSCTL_NODE(_net_inet, IPPROTO_DIVERT,	div,	CTLFLAG_RW|CTLFLAG_LOCKED, 0,	"DIVERT");
#endif

