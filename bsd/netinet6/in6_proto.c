/*
 * Copyright (c) 2008-2018 Apple Inc. All rights reserved.
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
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
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
 *	@(#)in_proto.c	8.1 (Berkeley) 6/10/93
 */


#include <sys/param.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/kernel.h>
#include <sys/domain.h>
#include <sys/mbuf.h>
#include <sys/systm.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/radix.h>
#include <net/route.h>
#include <net/nat464_utils.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip_encap.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_var.h>
#include <netinet/icmp6.h>

#include <netinet/tcp.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet6/tcp6_var.h>
#include <netinet6/raw_ip6.h>
#include <netinet6/udp6_var.h>
#include <netinet6/nd6.h>
#include <netinet6/mld6_var.h>

#if IPSEC
#include <netinet6/ipsec.h>
#if INET6
#include <netinet6/ipsec6.h>
#endif
#include <netinet6/ah.h>
#if INET6
#include <netinet6/ah6.h>
#endif
#if IPSEC_ESP
#include <netinet6/esp.h>
#if INET6
#include <netinet6/esp6.h>
#endif
#endif
#include <netinet6/ipcomp.h>
#if INET6
#include <netinet6/ipcomp6.h>
#endif
#endif /*IPSEC*/

#include <netinet6/ip6protosw.h>

#include <net/net_osdep.h>

/*
 * TCP/IP protocol family: IP6, ICMP6, UDP, TCP.
 */

extern struct domain inet6domain_s;
struct domain *inet6domain = NULL;

static struct pr_usrreqs nousrreqs;
lck_mtx_t *inet6_domain_mutex;

static void in6_dinit(struct domain *);
static int rip6_pr_output(struct mbuf *, struct socket *,
    struct sockaddr_in6 *, struct mbuf *);

struct ip6protosw inet6sw[] = {
	{
		.pr_type =              0,
		.pr_protocol =          IPPROTO_IPV6,
		.pr_init =              ip6_init,
		.pr_drain =             ip6_drain,
		.pr_usrreqs =           &nousrreqs,
	},
	{
		.pr_type =              SOCK_DGRAM,
		.pr_protocol =          IPPROTO_UDP,
		.pr_flags =             PR_ATOMIC | PR_ADDR | PR_PROTOLOCK | PR_PCBLOCK |
    PR_EVCONNINFO | PR_PRECONN_WRITE,
		.pr_input =             udp6_input,
		.pr_ctlinput =          udp6_ctlinput,
		.pr_ctloutput =         ip6_ctloutput,
#if !INET       /* don't call initialization twice */
		.pr_init =              udp_init,
#endif /* !INET */
		.pr_usrreqs =           &udp6_usrreqs,
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
		.pr_input =             tcp6_input,
		.pr_ctlinput =          tcp6_ctlinput,
		.pr_ctloutput =         tcp_ctloutput,
#if !INET       /* don't call initialization and timeout routines twice */
		.pr_init =              tcp_init,
#endif /* !INET */
		.pr_drain =             tcp_drain,
		.pr_usrreqs =           &tcp6_usrreqs,
		.pr_lock =              tcp_lock,
		.pr_unlock =            tcp_unlock,
		.pr_getlock =           tcp_getlock,
	},
	{
		.pr_type =              SOCK_RAW,
		.pr_protocol =          IPPROTO_RAW,
		.pr_flags =             PR_ATOMIC | PR_ADDR,
		.pr_input =             rip6_input,
		.pr_output =            rip6_pr_output,
		.pr_ctlinput =          rip6_ctlinput,
		.pr_ctloutput =         rip6_ctloutput,
#if !INET       /* don't call initialization and timeout routines twice */
		.pr_init =              rip_init,
#endif /* !INET */
		.pr_usrreqs =           &rip6_usrreqs,
		.pr_unlock =            rip_unlock,
	},
	{
		.pr_type =              SOCK_RAW,
		.pr_protocol =          IPPROTO_ICMPV6,
		.pr_flags =             PR_ATOMIC | PR_ADDR | PR_LASTHDR,
		.pr_input =             icmp6_input,
		.pr_output =            rip6_pr_output,
		.pr_ctlinput =          rip6_ctlinput,
		.pr_ctloutput =         rip6_ctloutput,
		.pr_init =              icmp6_init,
		.pr_usrreqs =           &rip6_usrreqs,
		.pr_unlock =            rip_unlock,
	},
	{
		.pr_type =              SOCK_DGRAM,
		.pr_protocol =          IPPROTO_ICMPV6,
		.pr_flags =             PR_ATOMIC | PR_ADDR | PR_LASTHDR,
		.pr_input =             icmp6_input,
		.pr_output =            rip6_pr_output,
		.pr_ctlinput =          rip6_ctlinput,
		.pr_ctloutput =         icmp6_dgram_ctloutput,
		.pr_init =              icmp6_init,
		.pr_usrreqs =           &icmp6_dgram_usrreqs,
		.pr_unlock =            rip_unlock,
	},
	{
		.pr_type =              SOCK_RAW,
		.pr_protocol =          IPPROTO_DSTOPTS,
		.pr_flags =             PR_ATOMIC | PR_ADDR,
		.pr_input =             dest6_input,
		.pr_usrreqs =           &nousrreqs,
	},
	{
		.pr_type =              SOCK_RAW,
		.pr_protocol =          IPPROTO_ROUTING,
		.pr_flags =             PR_ATOMIC | PR_ADDR,
		.pr_input =             route6_input,
		.pr_usrreqs =           &nousrreqs,
	},
	{
		.pr_type =              SOCK_RAW,
		.pr_protocol =          IPPROTO_FRAGMENT,
		.pr_flags =             PR_ATOMIC | PR_ADDR | PR_PROTOLOCK,
		.pr_input =             frag6_input,
		.pr_usrreqs =           &nousrreqs,
	},
#if IPSEC
	{
		.pr_type =              SOCK_RAW,
		.pr_protocol =          IPPROTO_AH,
		.pr_flags =             PR_ATOMIC | PR_ADDR | PR_PROTOLOCK,
		.pr_input =             ah6_input,
		.pr_usrreqs =           &nousrreqs,
	},
#if IPSEC_ESP
	{
		.pr_type =              SOCK_RAW,
		.pr_protocol =          IPPROTO_ESP,
		.pr_flags =             PR_ATOMIC | PR_ADDR | PR_PROTOLOCK,
		.pr_input =             esp6_input,
		.pr_ctlinput =          esp6_ctlinput,
		.pr_usrreqs =           &nousrreqs,
	},
#endif /* IPSEC_ESP */
	{
		.pr_type =              SOCK_RAW,
		.pr_protocol =          IPPROTO_IPCOMP,
		.pr_flags =             PR_ATOMIC | PR_ADDR | PR_PROTOLOCK,
		.pr_input =             ipcomp6_input,
#if !INET       /* don't call initialization and timeout routines twice */
		.pr_init =              ipcomp_init,
#endif /* !INET */
		.pr_usrreqs =           &nousrreqs,
	},
#endif /* IPSEC */
#if INET
	{
		.pr_type =              SOCK_RAW,
		.pr_protocol =          IPPROTO_IPV4,
		.pr_flags =             PR_ATOMIC | PR_ADDR | PR_LASTHDR,
		.pr_input =             encap6_input,
		.pr_output =            rip6_pr_output,
		.pr_ctloutput =         rip6_ctloutput,
		.pr_init =              encap6_init,
		.pr_usrreqs =           &rip6_usrreqs,
		.pr_unlock =            rip_unlock,
	},
#endif /*INET*/
	{
		.pr_type =              SOCK_RAW,
		.pr_protocol =          IPPROTO_IPV6,
		.pr_flags =             PR_ATOMIC | PR_ADDR | PR_LASTHDR,
		.pr_input =             encap6_input,
		.pr_output =            rip6_pr_output,
		.pr_ctloutput =         rip6_ctloutput,
		.pr_init =              encap6_init,
		.pr_usrreqs =           &rip6_usrreqs,
		.pr_unlock =            rip_unlock,
	},
/* raw wildcard */
	{
		.pr_type =              SOCK_RAW,
		.pr_protocol =          0,
		.pr_flags =             PR_ATOMIC | PR_ADDR | PR_LASTHDR,
		.pr_input =             rip6_input,
		.pr_output =            rip6_pr_output,
		.pr_ctloutput =         rip6_ctloutput,
		.pr_usrreqs =           &rip6_usrreqs,
		.pr_unlock =            rip_unlock,
	},
};

int in6_proto_count = (sizeof(inet6sw) / sizeof(struct ip6protosw));

struct domain inet6domain_s = {
	.dom_family =           PF_INET6,
	.dom_flags =            DOM_REENTRANT,
	.dom_name =             "internet6",
	.dom_init =             in6_dinit,
	.dom_rtattach =         in6_inithead,
	.dom_rtoffset =         offsetof(struct sockaddr_in6, sin6_addr) << 3,
	        .dom_maxrtkey =         sizeof(struct sockaddr_in6),
	        .dom_protohdrlen =      sizeof(struct sockaddr_in6),
};

/* Initialize the PF_INET6 domain, and add in the pre-defined protos */
void
in6_dinit(struct domain *dp)
{
	struct ip6protosw *pr;
	int i;

	VERIFY(!(dp->dom_flags & DOM_INITIALIZED));
	VERIFY(inet6domain == NULL);

	inet6domain = dp;

	_CASSERT(sizeof(struct protosw) == sizeof(struct ip6protosw));
	_CASSERT(offsetof(struct ip6protosw, pr_entry) ==
	    offsetof(struct protosw, pr_entry));
	_CASSERT(offsetof(struct ip6protosw, pr_domain) ==
	    offsetof(struct protosw, pr_domain));
	_CASSERT(offsetof(struct ip6protosw, pr_protosw) ==
	    offsetof(struct protosw, pr_protosw));
	_CASSERT(offsetof(struct ip6protosw, pr_type) ==
	    offsetof(struct protosw, pr_type));
	_CASSERT(offsetof(struct ip6protosw, pr_protocol) ==
	    offsetof(struct protosw, pr_protocol));
	_CASSERT(offsetof(struct ip6protosw, pr_flags) ==
	    offsetof(struct protosw, pr_flags));
	_CASSERT(offsetof(struct ip6protosw, pr_input) ==
	    offsetof(struct protosw, pr_input));
	_CASSERT(offsetof(struct ip6protosw, pr_output) ==
	    offsetof(struct protosw, pr_output));
	_CASSERT(offsetof(struct ip6protosw, pr_ctlinput) ==
	    offsetof(struct protosw, pr_ctlinput));
	_CASSERT(offsetof(struct ip6protosw, pr_ctloutput) ==
	    offsetof(struct protosw, pr_ctloutput));
	_CASSERT(offsetof(struct ip6protosw, pr_usrreqs) ==
	    offsetof(struct protosw, pr_usrreqs));
	_CASSERT(offsetof(struct ip6protosw, pr_init) ==
	    offsetof(struct protosw, pr_init));
	_CASSERT(offsetof(struct ip6protosw, pr_drain) ==
	    offsetof(struct protosw, pr_drain));
	_CASSERT(offsetof(struct ip6protosw, pr_sysctl) ==
	    offsetof(struct protosw, pr_sysctl));
	_CASSERT(offsetof(struct ip6protosw, pr_lock) ==
	    offsetof(struct protosw, pr_lock));
	_CASSERT(offsetof(struct ip6protosw, pr_unlock) ==
	    offsetof(struct protosw, pr_unlock));
	_CASSERT(offsetof(struct ip6protosw, pr_getlock) ==
	    offsetof(struct protosw, pr_getlock));
	_CASSERT(offsetof(struct ip6protosw, pr_filter_head) ==
	    offsetof(struct protosw, pr_filter_head));
	_CASSERT(offsetof(struct ip6protosw, pr_old) ==
	    offsetof(struct protosw, pr_old));

	/*
	 * Attach first, then initialize.  ip6_init() needs raw IP6 handler.
	 */
	for (i = 0, pr = &inet6sw[0]; i < in6_proto_count; i++, pr++) {
		net_add_proto((struct protosw *)pr, dp, 0);
	}
	for (i = 0, pr = &inet6sw[0]; i < in6_proto_count; i++, pr++) {
		net_init_proto((struct protosw *)pr, dp);
	}

	inet6_domain_mutex = dp->dom_mtx;
}

static int
rip6_pr_output(struct mbuf *m, struct socket *so, struct sockaddr_in6 *sin6,
    struct mbuf *m1)
{
#pragma unused(m, so, sin6, m1)
	panic("%s\n", __func__);
	/* NOTREACHED */
	return 0;
}

/*
 * Internet configuration info
 */
#ifndef IPV6FORWARDING
#if GATEWAY6
#define IPV6FORWARDING  1       /* forward IP6 packets not for us */
#else
#define IPV6FORWARDING  0       /* don't forward IP6 packets not for us */
#endif /* GATEWAY6 */
#endif /* !IPV6FORWARDING */

#ifndef IPV6_SENDREDIRECTS
#define IPV6_SENDREDIRECTS      1
#endif

int     ip6_forwarding = IPV6FORWARDING;        /* act as router? */
int     ip6_sendredirects = IPV6_SENDREDIRECTS;
int     ip6_defhlim = IPV6_DEFHLIM;
int     ip6_defmcasthlim = IPV6_DEFAULT_MULTICAST_HOPS;
int     ip6_accept_rtadv = 1;   /* deprecated */
int     ip6_log_interval = 5;
int     ip6_hdrnestlimit = 15;  /* How many header options will we process? */
int     ip6_dad_count = 1;      /* DupAddrDetectionTransmits */
int     ip6_auto_flowlabel = 1;
int     ip6_gif_hlim = 0;
int     ip6_use_deprecated = 1; /* allow deprecated addr [RFC 4862, 5.5.4] */
int     ip6_rr_prune = 5;       /* router renumbering prefix
                                 * walk list every 5 sec.    */
int     ip6_mcast_pmtu = 0;     /* enable pMTU discovery for multicast? */
int     ip6_v6only = 0;         /* Mapped addresses off by default -  Radar 3347718  -- REVISITING FOR 10.7 -- TESTING WITH MAPPED@ OFF */

int     ip6_neighborgcthresh = 1024;    /* Threshold # of NDP entries for GC */
int     ip6_maxifprefixes = 16;         /* Max acceptable prefixes via RA per IF */
int     ip6_maxifdefrouters = 16;       /* Max acceptable def routers via RA */
int     ip6_maxdynroutes = 1024;        /* Max # of routes created via redirect */
int     ip6_only_allow_rfc4193_prefix = 0;      /* Only allow RFC4193 style Unique Local IPv6 Unicast prefixes */

static int ip6_keepfaith = 0;
uint64_t ip6_log_time = 0;
int     nd6_onlink_ns_rfc4861 = 0; /* allow 'on-link' nd6 NS (as in RFC 4861) */

/* icmp6 */
/*
 * BSDI4 defines these variables in in_proto.c...
 * XXX: what if we don't define INET? Should we define pmtu6_expire
 * or so? (jinmei@kame.net 19990310)
 */
int pmtu_expire = 60 * 10;
int pmtu_probe = 60 * 2;

/* raw IP6 parameters */
/*
 * Nominal space allocated to a raw ip socket.
 */
#define RIPV6SNDQ       8192
#define RIPV6RCVQ       8192

u_int32_t       rip6_sendspace = RIPV6SNDQ;
u_int32_t       rip6_recvspace = RIPV6RCVQ;

/* ICMPV6 parameters */
int     icmp6_rediraccept = 1;          /* accept and process redirects */
int     icmp6_redirtimeout = 10 * 60;   /* 10 minutes */
int     icmp6errppslim = 500;           /* 500 packets per second */
int     icmp6rappslim = 10;             /* 10 packets per second */
int     icmp6_nodeinfo = 3;             /* enable/disable NI response */

/* UDP on IP6 parameters */
int     udp6_sendspace = 9216;          /* really max datagram size */
int     udp6_recvspace = 40 * (1024 + sizeof(struct sockaddr_in6));
/* 40 1K datagrams */

/*
 * sysctl related items.
 */
SYSCTL_NODE(_net, PF_INET6, inet6,
    CTLFLAG_RW | CTLFLAG_LOCKED, 0, "Internet6 Family");

/* net.inet6 */
SYSCTL_NODE(_net_inet6, IPPROTO_IPV6, ip6,
    CTLFLAG_RW | CTLFLAG_LOCKED, 0, "IP6");
SYSCTL_NODE(_net_inet6, IPPROTO_ICMPV6, icmp6,
    CTLFLAG_RW | CTLFLAG_LOCKED, 0, "ICMP6");
SYSCTL_NODE(_net_inet6, IPPROTO_UDP, udp6,
    CTLFLAG_RW | CTLFLAG_LOCKED, 0, "UDP6");
SYSCTL_NODE(_net_inet6, IPPROTO_TCP, tcp6,
    CTLFLAG_RW | CTLFLAG_LOCKED, 0, "TCP6");
#if IPSEC
SYSCTL_NODE(_net_inet6, IPPROTO_ESP, ipsec6,
    CTLFLAG_RW | CTLFLAG_LOCKED, 0, "IPSEC6");
#endif /* IPSEC */

/* net.inet6.ip6 */
static int
sysctl_ip6_temppltime SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg2)
	int error = 0;
	int old;

	error = SYSCTL_OUT(req, arg1, sizeof(int));
	if (error || !req->newptr) {
		return error;
	}
	old = ip6_temp_preferred_lifetime;
	error = SYSCTL_IN(req, arg1, sizeof(int));
	if (ip6_temp_preferred_lifetime > ND6_MAX_LIFETIME ||
	    ip6_temp_preferred_lifetime <
	    ip6_desync_factor + ip6_temp_regen_advance) {
		ip6_temp_preferred_lifetime = old;
		return EINVAL;
	}
	return error;
}

static int
sysctl_ip6_tempvltime SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg2)
	int error = 0;
	int old;

	error = SYSCTL_OUT(req, arg1, sizeof(int));
	if (error || !req->newptr) {
		return error;
	}
	old = ip6_temp_valid_lifetime;
	error = SYSCTL_IN(req, arg1, sizeof(int));
	if (ip6_temp_valid_lifetime > ND6_MAX_LIFETIME ||
	    ip6_temp_valid_lifetime < ip6_temp_preferred_lifetime) {
		ip6_temp_valid_lifetime = old;
		return EINVAL;
	}
	return error;
}

static int
ip6_getstat SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	if (req->oldptr == USER_ADDR_NULL) {
		req->oldlen = (size_t)sizeof(struct ip6stat);
	}

	return SYSCTL_OUT(req, &ip6stat, MIN(sizeof(ip6stat), req->oldlen));
}

SYSCTL_INT(_net_inet6_ip6, IPV6CTL_FORWARDING,
    forwarding, CTLFLAG_RW | CTLFLAG_LOCKED, &ip6_forwarding, 0, "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_SENDREDIRECTS,
    redirect, CTLFLAG_RW | CTLFLAG_LOCKED, &ip6_sendredirects, 0, "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_DEFHLIM,
    hlim, CTLFLAG_RW | CTLFLAG_LOCKED, &ip6_defhlim, 0, "");
SYSCTL_PROC(_net_inet6_ip6, IPV6CTL_STATS, stats,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, ip6_getstat, "S,ip6stat", "");

#if (DEVELOPMENT || DEBUG)
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_ACCEPT_RTADV,
    accept_rtadv, CTLFLAG_RW | CTLFLAG_LOCKED,
    &ip6_accept_rtadv, 0, "");
#else
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_ACCEPT_RTADV,
    accept_rtadv, CTLFLAG_RD | CTLFLAG_LOCKED,
    &ip6_accept_rtadv, 0, "");
#endif /* (DEVELOPMENT || DEBUG) */
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_KEEPFAITH,
    keepfaith, CTLFLAG_RD | CTLFLAG_LOCKED, &ip6_keepfaith, 0, "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_LOG_INTERVAL,
    log_interval, CTLFLAG_RW | CTLFLAG_LOCKED, &ip6_log_interval, 0, "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_HDRNESTLIMIT,
    hdrnestlimit, CTLFLAG_RW | CTLFLAG_LOCKED, &ip6_hdrnestlimit, 0, "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_DAD_COUNT,
    dad_count, CTLFLAG_RW | CTLFLAG_LOCKED, &ip6_dad_count, 0, "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_AUTO_FLOWLABEL,
    auto_flowlabel, CTLFLAG_RW | CTLFLAG_LOCKED, &ip6_auto_flowlabel, 0, "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_DEFMCASTHLIM,
    defmcasthlim, CTLFLAG_RW | CTLFLAG_LOCKED, &ip6_defmcasthlim, 0, "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_GIF_HLIM,
    gifhlim, CTLFLAG_RW | CTLFLAG_LOCKED, &ip6_gif_hlim, 0, "");
SYSCTL_STRING(_net_inet6_ip6, IPV6CTL_KAME_VERSION,
    kame_version, CTLFLAG_RD | CTLFLAG_LOCKED, (void *)((uintptr_t)(__KAME_VERSION)), 0, "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_USE_DEPRECATED,
    use_deprecated, CTLFLAG_RW | CTLFLAG_LOCKED, &ip6_use_deprecated, 0, "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_RR_PRUNE,
    rr_prune, CTLFLAG_RW | CTLFLAG_LOCKED, &ip6_rr_prune, 0, "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_USETEMPADDR,
    use_tempaddr, CTLFLAG_RW | CTLFLAG_LOCKED, &ip6_use_tempaddr, 0, "");
SYSCTL_OID(_net_inet6_ip6, IPV6CTL_TEMPPLTIME, temppltime,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &ip6_temp_preferred_lifetime, 0,
    sysctl_ip6_temppltime, "I", "");
SYSCTL_OID(_net_inet6_ip6, IPV6CTL_TEMPVLTIME, tempvltime,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &ip6_temp_valid_lifetime, 0,
    sysctl_ip6_tempvltime, "I", "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_V6ONLY,
    v6only, CTLFLAG_RW | CTLFLAG_LOCKED, &ip6_v6only, 0, "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_AUTO_LINKLOCAL,
    auto_linklocal, CTLFLAG_RW | CTLFLAG_LOCKED, &ip6_auto_linklocal, 0, "");
SYSCTL_STRUCT(_net_inet6_ip6, IPV6CTL_RIP6STATS, rip6stats, CTLFLAG_RD | CTLFLAG_LOCKED,
    &rip6stat, rip6stat, "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_PREFER_TEMPADDR,
    prefer_tempaddr, CTLFLAG_RW | CTLFLAG_LOCKED, &ip6_prefer_tempaddr, 0, "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_USE_DEFAULTZONE,
    use_defaultzone, CTLFLAG_RW | CTLFLAG_LOCKED, &ip6_use_defzone, 0, "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_MCAST_PMTU,
    mcast_pmtu, CTLFLAG_RW | CTLFLAG_LOCKED, &ip6_mcast_pmtu, 0, "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_NEIGHBORGCTHRESH,
    neighborgcthresh, CTLFLAG_RW | CTLFLAG_LOCKED, &ip6_neighborgcthresh, 0, "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_MAXIFPREFIXES,
    maxifprefixes, CTLFLAG_RW | CTLFLAG_LOCKED, &ip6_maxifprefixes, 0, "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_MAXIFDEFROUTERS,
    maxifdefrouters, CTLFLAG_RW | CTLFLAG_LOCKED, &ip6_maxifdefrouters, 0, "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_MAXDYNROUTES,
    maxdynroutes, CTLFLAG_RW | CTLFLAG_LOCKED, &ip6_maxdynroutes, 0, "");
SYSCTL_INT(_net_inet6_ip6, OID_AUTO,
    only_allow_rfc4193_prefixes, CTLFLAG_RW | CTLFLAG_LOCKED,
    &ip6_only_allow_rfc4193_prefix, 0, "");
SYSCTL_INT(_net_inet6_ip6, OID_AUTO,
    clat_debug, CTLFLAG_RW | CTLFLAG_LOCKED, &clat_debug, 0, "");

/* net.inet6.icmp6 */
SYSCTL_INT(_net_inet6_icmp6, ICMPV6CTL_REDIRACCEPT,
    rediraccept, CTLFLAG_RW | CTLFLAG_LOCKED, &icmp6_rediraccept, 0, "");
SYSCTL_INT(_net_inet6_icmp6, ICMPV6CTL_REDIRTIMEOUT,
    redirtimeout, CTLFLAG_RW | CTLFLAG_LOCKED, &icmp6_redirtimeout, 0, "");
SYSCTL_STRUCT(_net_inet6_icmp6, ICMPV6CTL_STATS, stats, CTLFLAG_RD | CTLFLAG_LOCKED,
    &icmp6stat, icmp6stat, "");
SYSCTL_INT(_net_inet6_icmp6, ICMPV6CTL_ND6_PRUNE,
    nd6_prune, CTLFLAG_RW | CTLFLAG_LOCKED, &nd6_prune, 0, "");
SYSCTL_INT(_net_inet6_icmp6, OID_AUTO,
    nd6_prune_lazy, CTLFLAG_RW | CTLFLAG_LOCKED, &nd6_prune_lazy, 0, "");
SYSCTL_INT(_net_inet6_icmp6, ICMPV6CTL_ND6_DELAY,
    nd6_delay, CTLFLAG_RW | CTLFLAG_LOCKED, &nd6_delay, 0, "");
SYSCTL_INT(_net_inet6_icmp6, ICMPV6CTL_ND6_UMAXTRIES,
    nd6_umaxtries, CTLFLAG_RW | CTLFLAG_LOCKED, &nd6_umaxtries, 0, "");
SYSCTL_INT(_net_inet6_icmp6, ICMPV6CTL_ND6_MMAXTRIES,
    nd6_mmaxtries, CTLFLAG_RW | CTLFLAG_LOCKED, &nd6_mmaxtries, 0, "");
SYSCTL_INT(_net_inet6_icmp6, ICMPV6CTL_ND6_USELOOPBACK,
    nd6_useloopback, CTLFLAG_RW | CTLFLAG_LOCKED, &nd6_useloopback, 0, "");
SYSCTL_INT(_net_inet6_icmp6, ICMPV6CTL_ND6_ACCEPT_6TO4,
    nd6_accept_6to4, CTLFLAG_RW | CTLFLAG_LOCKED, &nd6_accept_6to4, 0, "");
SYSCTL_INT(_net_inet6_icmp6, ICMPV6CTL_NODEINFO,
    nodeinfo, CTLFLAG_RW | CTLFLAG_LOCKED, &icmp6_nodeinfo, 0, "");
SYSCTL_INT(_net_inet6_icmp6, ICMPV6CTL_ERRPPSLIMIT,
    errppslimit, CTLFLAG_RW | CTLFLAG_LOCKED, &icmp6errppslim, 0, "");
SYSCTL_INT(_net_inet6_icmp6, OID_AUTO,
    rappslimit, CTLFLAG_RW | CTLFLAG_LOCKED, &icmp6rappslim, 0, "");
SYSCTL_INT(_net_inet6_icmp6, ICMPV6CTL_ND6_DEBUG,
    nd6_debug, CTLFLAG_RW | CTLFLAG_LOCKED, &nd6_debug, 0, "");
SYSCTL_INT(_net_inet6_icmp6, ICMPV6CTL_ND6_ONLINKNSRFC4861,
    nd6_onlink_ns_rfc4861, CTLFLAG_RW | CTLFLAG_LOCKED, &nd6_onlink_ns_rfc4861, 0,
    "Accept 'on-link' nd6 NS in compliance with RFC 4861.");
SYSCTL_INT(_net_inet6_icmp6, ICMPV6CTL_ND6_OPTIMISTIC_DAD,
    nd6_optimistic_dad, CTLFLAG_RW | CTLFLAG_LOCKED, &nd6_optimistic_dad, 0, "");
