/*	$KAME: in6_proto.c,v 1.47 2000/03/29 07:37:22 sumikawa Exp $	*/

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

#if (defined(__FreeBSD__) && __FreeBSD__ >= 3) || defined(__NetBSD__)
#include "opt_inet.h"
#if __NetBSD__	/*XXX*/
#include "opt_ipsec.h"
#endif
#endif

#include <sys/param.h>
#include <sys/socket.h>
#if defined(__FreeBSD__) || defined (__APPLE__)
#include <sys/socketvar.h>
#endif
#include <sys/protosw.h>
#include <sys/kernel.h>
#include <sys/domain.h>
#include <sys/mbuf.h>
#if defined (__FreeBSD__) || defined (__APPLE__)
#include <sys/systm.h>
#include <sys/sysctl.h>
#endif

#include <net/if.h>
#include <net/radix.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip_encap.h>
#if defined (__APPLE__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3) || (defined(__NetBSD__) && !defined(TCP6)) || defined(__OpenBSD__) || (defined(__bsdi__) && _BSDI_VERSION >= 199802)
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#endif
#if (defined(__NetBSD__) && !defined(TCP6)) || defined(__OpenBSD__) || (defined(__bsdi__) && _BSDI_VERSION >= 199802)
#include <netinet/in_pcb.h>
#endif
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>

#if defined (__APPLE__)
#include <netinet/tcp.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
# if (defined(__FreeBSD__) && __FreeBSD__ >= 4)
#include <netinet6/tcp6_var.h>
# endif
#else
#if defined(__NetBSD__) && !defined(TCP6)
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcpip.h>
#include <netinet/tcp_debug.h>
#else
#include <netinet6/tcp6.h>
#include <netinet6/tcp6_fsm.h>
#include <netinet6/tcp6_seq.h>
#include <netinet6/tcp6_timer.h>
#include <netinet6/tcp6_var.h>
#endif
#endif

#include <netinet6/udp6.h>
#include <netinet6/udp6_var.h>

#include <netinet6/pim6_var.h>

#include <netinet6/nd6.h>
#if defined (__APPLE__)
#include <netinet6/in6_prefix.h>
#endif

#if IPSEC
#include <netinet6/ipsec.h>
#include <netinet6/ah.h>
#if IPSEC_ESP
#include <netinet6/esp.h>
#endif
#include <netinet6/ipcomp.h>
#endif /*IPSEC*/

#include <netinet6/ip6protosw.h>
#include <netinet/tcpip.h>

#include "gif.h"
#if NGIF > 0
#include <netinet6/in6_gif.h>
#endif

#if MIP6
#include <netinet6/mip6.h>
#endif

#include <net/net_osdep.h>

#define	offsetof(type, member)	((size_t)(&((type *)0)->member))

/*
 * TCP/IP protocol family: IP6, ICMP6, UDP, TCP.
 */

extern	struct domain inet6domain;
#if defined(__FreeBSD__) && __FreeBSD__ >= 3 || defined (__APPLE__)
static struct pr_usrreqs nousrreqs;
#endif

struct ip6protosw inet6sw[] = {
{ 0,		&inet6domain,	IPPROTO_IPV6,	0,
  0,		0,		0,		0,
  0,
  ip6_init,	0,		frag6_slowtimo,	frag6_drain,
  0, &nousrreqs
},
{ SOCK_DGRAM,	&inet6domain,	IPPROTO_UDP,	PR_ATOMIC | PR_ADDR,
  udp6_input,	0,		udp6_ctlinput,	ip6_ctloutput,
  0,
  0,		0,		0,		0,
  0, &udp6_usrreqs
},
{ SOCK_STREAM,	&inet6domain,	IPPROTO_TCP,	PR_CONNREQUIRED | PR_WANTRCVD,
  tcp6_input,	0,		tcp6_ctlinput,	tcp_ctloutput,
  0,
  tcp_init,	0,		0,		tcp_drain,
  0, &tcp6_usrreqs
},
{ SOCK_RAW,	&inet6domain,	IPPROTO_RAW,	PR_ATOMIC | PR_ADDR,
  rip6_input,	rip6_output,	rip6_ctlinput,		rip6_ctloutput,
  0,
  0,		0,		0,		0,
  0, &rip6_usrreqs
},
{ SOCK_RAW,	&inet6domain,	IPPROTO_ICMPV6,	PR_ATOMIC | PR_ADDR,
  icmp6_input,	rip6_output,	0,		rip6_ctloutput,
  0,
  icmp6_init,	icmp6_fasttimo,	0,		0,
  0, &rip6_usrreqs
},
{ SOCK_RAW,	&inet6domain,	IPPROTO_DSTOPTS,PR_ATOMIC|PR_ADDR,
  dest6_input,	0,	 	0,		0,
  0,
  0,		0,		0,		0,
  0, &nousrreqs
},
{ SOCK_RAW,	&inet6domain,	IPPROTO_ROUTING,PR_ATOMIC|PR_ADDR,
  route6_input,	0,	 	0,		0,
  0,	  
  0,		0,		0,		0,
  0, &nousrreqs
},
{ SOCK_RAW,	&inet6domain,	IPPROTO_FRAGMENT,PR_ATOMIC|PR_ADDR,
  frag6_input,	0,	 	0,		0,
  0,	  
  0,		0,		0,		0,
  0, &nousrreqs
},
#if IPSEC
{ SOCK_RAW,	&inet6domain,	IPPROTO_AH,	PR_ATOMIC|PR_ADDR,
  ah6_input,	0,	 	0,		0,
  0,	  
  0,		0,		0,		0,
  0, &nousrreqs
},
#if IPSEC_ESP
{ SOCK_RAW,	&inet6domain,	IPPROTO_ESP,	PR_ATOMIC|PR_ADDR,
  esp6_input,	0,	 	0,		0,
  0,	  
  0,		0,		0,		0,
  0, &nousrreqs
},
#endif
{ SOCK_RAW,	&inet6domain,	IPPROTO_IPCOMP,	PR_ATOMIC|PR_ADDR,
  ipcomp6_input, 0,	 	0,		0,
  0,	  
  0,		0,		0,		0,
  0, &nousrreqs
},
#endif /* IPSEC */
{ SOCK_RAW,	&inet6domain,	IPPROTO_IPV4,	PR_ATOMIC|PR_ADDR,
  encap6_input,	rip6_output, 	0,		rip6_ctloutput,
  0,	  
  0,		0,		0,		0,
  0, &nousrreqs
},
#if INET6
{ SOCK_RAW,	&inet6domain,	IPPROTO_IPV6,	PR_ATOMIC|PR_ADDR,
  encap6_input, rip6_output,	 0,	rip6_ctloutput,
  0,	  
  0,		0,		0,		0,
  0, &rip6_usrreqs
},
#endif /*INET6*/
{ SOCK_RAW,     &inet6domain,	IPPROTO_PIM,	PR_ATOMIC|PR_ADDR,
  pim6_input,    rip6_output,	0,              rip6_ctloutput, 
  0,
  0,            0,              0,              0,
  0, &rip6_usrreqs
},
/* raw wildcard */
{ SOCK_RAW,	&inet6domain,	0,		PR_ATOMIC | PR_ADDR,
  rip6_input,	rip6_output,	0,		rip6_ctloutput,
  0,
  0,		0,		0,		0,
  0, &rip6_usrreqs
},
};

#if NGIF > 0
struct ip6protosw in6_gif_protosw =
{ SOCK_RAW,	&inet6domain,	0/*IPPROTO_IPV[46]*/,	PR_ATOMIC|PR_ADDR,
  in6_gif_input, rip6_output,	0,		rip6_ctloutput,
  0,
  0,		0,		0,		0,
  0, &rip6_usrreqs
};
#endif /*NGIF*/

#if MIP6
struct ip6protosw mip6_tunnel_protosw =
{ SOCK_RAW,	&inet6domain,	0/*IPPROTO_IPV[46]*/,	PR_ATOMIC|PR_ADDR,
  mip6_tunnel_input, rip6_output,	0,		rip6_ctloutput,
  0,
  0,		0,		0,		0,
  0, &rip6_usrreqs
};
#endif /* MIP6 */

extern int in6_inithead __P((void **, int));
int in6_proto_count = (sizeof (inet6sw) / sizeof (struct ip6protosw));
extern void in6_dinit(void);

struct domain inet6domain =
    { AF_INET6, "internet6", in6_dinit, 0, 0, 
      inet6sw, 0,
      in6_inithead, offsetof(struct sockaddr_in6, sin6_addr) << 3, sizeof(struct sockaddr_in6) ,
      sizeof(struct sockaddr_in6), 0
    };

DOMAIN_SET(inet6);

/*
 * Internet configuration info
 */
#ifndef	IPV6FORWARDING
#if GATEWAY6
#define	IPV6FORWARDING	1	/* forward IP6 packets not for us */
#else
#define	IPV6FORWARDING	0	/* don't forward IP6 packets not for us */
#endif /* GATEWAY6 */
#endif /* !IPV6FORWARDING */

#ifndef	IPV6_SENDREDIRECTS
#define	IPV6_SENDREDIRECTS	1
#endif

int	ip6_forwarding = IPV6FORWARDING;	/* act as router? */
int	ip6_sendredirects = IPV6_SENDREDIRECTS;
int	ip6_defhlim = IPV6_DEFHLIM;
int	ip6_defmcasthlim = IPV6_DEFAULT_MULTICAST_HOPS;
int	ip6_accept_rtadv = 0;	/* "IPV6FORWARDING ? 0 : 1" is dangerous */
int	ip6_maxfragpackets = 200;
int	ip6_log_interval = 5;
int	ip6_hdrnestlimit = 50;	/* appropriate? */
int	ip6_dad_count = 1;	/* DupAddrDetectionTransmits */
u_int32_t ip6_flow_seq;
int	ip6_auto_flowlabel = 1;
#if NGIF > 0
int	ip6_gif_hlim = GIF_HLIM;
#else
int	ip6_gif_hlim = 0;
#endif
int	ip6_use_deprecated = 1;	/* allow deprecated addr (RFC2462 5.5.4) */
int	ip6_rr_prune = 5;	/* router renumbering prefix
				 * walk list every 5 sec.    */
#if MAPPED_ADDR_ENABLED
int	ip6_mapped_addr_on = 1;
#endif /* MAPPED_ADDR_ENABLED */

u_int32_t ip6_id = 0UL;
int	ip6_keepfaith = 0;
time_t	ip6_log_time = (time_t)0L;

/* icmp6 */
#ifndef __bsdi__
/*
 * BSDI4 defines these variables in in_proto.c...
 * XXX: what if we don't define INET? Should we define pmtu6_expire
 * or so? (jinmei@kame.net 19990310)
 */
int pmtu_expire = 60*10;
int pmtu_probe = 60*2;
#endif

/* raw IP6 parameters */
/*
 * Nominal space allocated to a raw ip socket.
 */
#define	RIPV6SNDQ	8192
#define	RIPV6RCVQ	8192

u_long	rip6_sendspace = RIPV6SNDQ;
u_long	rip6_recvspace = RIPV6RCVQ;

/* ICMPV6 parameters */
int	icmp6_rediraccept = 1;		/* accept and process redirects */
int	icmp6_redirtimeout = 10 * 60;	/* 10 minutes */
u_int	icmp6errratelim = 1000;		/* 1000usec = 1msec */
int	icmp6_nodeinfo = 1;		/* enable/disable NI response */

#if TCP6
/* TCP on IP6 parameters */
int	tcp6_sendspace = 1024 * 8;
int	tcp6_recvspace = 1024 * 8;
int 	tcp6_mssdflt = TCP6_MSS;
int 	tcp6_rttdflt = TCP6TV_SRTTDFLT / PR_SLOWHZ;
int	tcp6_do_rfc1323 = 1;
int	tcp6_conntimeo = TCP6TV_KEEP_INIT;	/* initial connection timeout */
int	tcp6_43maxseg = 0;
int	tcp6_pmtu = 0;

/*
 * Parameters for keepalive option.
 * Connections for which SO_KEEPALIVE is set will be probed
 * after being idle for a time of tcp6_keepidle (in units of PR_SLOWHZ).
 * Starting at that time, the connection is probed at intervals
 * of tcp6_keepintvl (same units) until a response is received
 * or until tcp6_keepcnt probes have been made, at which time
 * the connection is dropped.  Note that a tcp6_keepidle value
 * under 2 hours is nonconformant with RFC-1122, Internet Host Requirements.
 */
int	tcp6_keepidle = TCP6TV_KEEP_IDLE;	/* time before probing idle */
int	tcp6_keepintvl = TCP6TV_KEEPINTVL;	/* interval betwn idle probes */
int	tcp6_keepcnt = TCP6TV_KEEPCNT;		/* max idle probes */
int	tcp6_maxpersistidle = TCP6TV_KEEP_IDLE;	/* max idle time in persist */

#ifndef INET_SERVER
#define	TCP6_LISTEN_HASH_SIZE	17
#define	TCP6_CONN_HASH_SIZE	97
#define	TCP6_SYN_HASH_SIZE	293
#define	TCP6_SYN_BUCKET_SIZE	35
#else
#define	TCP6_LISTEN_HASH_SIZE	97
#define	TCP6_CONN_HASH_SIZE	9973
#define	TCP6_SYN_HASH_SIZE	997
#define	TCP6_SYN_BUCKET_SIZE	35
#endif
int	tcp6_listen_hash_size = TCP6_LISTEN_HASH_SIZE;
int	tcp6_conn_hash_size = TCP6_CONN_HASH_SIZE;
struct	tcp6_hash_list tcp6_listen_hash[TCP6_LISTEN_HASH_SIZE],
	tcp6_conn_hash[TCP6_CONN_HASH_SIZE];

int	tcp6_syn_cache_size = TCP6_SYN_HASH_SIZE;
int	tcp6_syn_cache_limit = TCP6_SYN_HASH_SIZE*TCP6_SYN_BUCKET_SIZE;
int	tcp6_syn_bucket_limit = 3*TCP6_SYN_BUCKET_SIZE;
struct	syn_cache_head6 tcp6_syn_cache[TCP6_SYN_HASH_SIZE];
struct	syn_cache_head6 *tcp6_syn_cache_first;
int	tcp6_syn_cache_interval = 8;	/* runs timer every 4 seconds */
int	tcp6_syn_cache_timeo = TCP6TV_KEEP_INIT;

/*
 * Parameters for computing a desirable data segment size
 * given an upper bound (either interface MTU, or peer's MSS option)_.
 * As applications tend to use a buffer size that is a multiple
 * of kilobytes, try for something that divides evenly. However,
 * do not round down too much.
 *
 * Round segment size down to a multiple of TCP6_ROUNDSIZE if this
 * does not result in lowering by more than (size/TCP6_ROUNDFRAC).
 * For example, round 536 to 512.  Older versions of the system
 * effectively used MCLBYTES (1K or 2K) as TCP6_ROUNDSIZE, with
 * a value of 1 for TCP6_ROUNDFRAC (eliminating its effect).
 * We round to a multiple of 256 for SLIP.
 */
#ifndef	TCP6_ROUNDSIZE
#define	TCP6_ROUNDSIZE	256	/* round to multiple of 256 */
#endif
#ifndef	TCP6_ROUNDFRAC
#define	TCP6_ROUNDFRAC	10	/* round down at most N/10, or 10% */
#endif

int	tcp6_roundsize = TCP6_ROUNDSIZE;
int	tcp6_roundfrac = TCP6_ROUNDFRAC;
#endif /*TCP6*/

/* UDP on IP6 parameters */
int	udp6_sendspace = 9216;		/* really max datagram size */
int	udp6_recvspace = 40 * (1024 + sizeof(struct sockaddr_in6));
					/* 40 1K datagrams */

#if defined(__FreeBSD__) || defined(__APPLE__)
/*
 * sysctl related items.
 */
SYSCTL_NODE(_net,	PF_INET6,	inet6,	CTLFLAG_RW,	0,
	"Internet6 Family");

/* net.inet6 */
SYSCTL_NODE(_net_inet6,	IPPROTO_IPV6,	ip6,	CTLFLAG_RW, 0,	"IP6");
SYSCTL_NODE(_net_inet6,	IPPROTO_ICMPV6,	icmp6,	CTLFLAG_RW, 0,	"ICMP6");
SYSCTL_NODE(_net_inet6,	IPPROTO_UDP,	udp6,	CTLFLAG_RW, 0,	"UDP6");
SYSCTL_NODE(_net_inet6,	IPPROTO_TCP,	tcp6,	CTLFLAG_RW, 0,	"TCP6");
#if IPSEC
SYSCTL_NODE(_net_inet6,	IPPROTO_ESP,	ipsec6,	CTLFLAG_RW, 0,	"IPSEC6");
#endif /* IPSEC */

/* net.inet6.ip6 */
static int
sysctl_ip6_forwarding SYSCTL_HANDLER_ARGS
{
	int error = 0;
	int old_ip6_forwarding;
	int changed;

	error = SYSCTL_OUT(req, arg1, sizeof(int));
	if (error || !req->newptr)
		return (error);
	old_ip6_forwarding = ip6_forwarding;
	error = SYSCTL_IN(req, arg1, sizeof(int));
	if (error != 0)
		return (error);
	changed = (ip6_forwarding ? 1 : 0) ^ (old_ip6_forwarding ? 1 : 0);
	if (changed == 0)
		return (error);
	/*
	 * XXX while host->router removes prefix got from RA,
	 * router->host case nukes all the prefixes managed by in6_prefix.c
	 * (both RR and static).  therefore, switching from host->router->host
	 * will remove statically configured addresses/prefixes.
	 * not sure if it is intended behavior or not.
	 */
	if (ip6_forwarding != 0) {	/* host becomes router */
		int s = splnet();
		struct nd_prefix *pr, *next;

		for (pr = nd_prefix.lh_first; pr; pr = next) {
			next = pr->ndpr_next;
			if (!IN6_IS_ADDR_UNSPECIFIED(&pr->ndpr_addr))
				in6_ifdel(pr->ndpr_ifp, &pr->ndpr_addr);
			prelist_remove(pr);
		}
		splx(s);
	} else {			/* router becomes host */
		while(!LIST_EMPTY(&rr_prefix))
			delete_each_prefix(LIST_FIRST(&rr_prefix),
					   PR_ORIG_KERNEL);
	}

	return (error);
}

SYSCTL_OID(_net_inet6_ip6, IPV6CTL_FORWARDING, forwarding,
	   CTLTYPE_INT|CTLFLAG_RW, &ip6_forwarding, 0, sysctl_ip6_forwarding,
	   "I", "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_SENDREDIRECTS,
	redirect, CTLFLAG_RW,		&ip6_sendredirects,	0, "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_DEFHLIM,
	hlim, CTLFLAG_RW,		&ip6_defhlim,	0, "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_MAXFRAGPACKETS,
	maxfragpackets, CTLFLAG_RW,	&ip6_maxfragpackets,	0, "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_ACCEPT_RTADV,
	accept_rtadv, CTLFLAG_RW,	&ip6_accept_rtadv,	0, "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_KEEPFAITH,
	keepfaith, CTLFLAG_RW,		&ip6_keepfaith,	0, "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_LOG_INTERVAL,
	log_interval, CTLFLAG_RW,	&ip6_log_interval,	0, "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_HDRNESTLIMIT,
	hdrnestlimit, CTLFLAG_RW,	&ip6_hdrnestlimit,	0, "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_DAD_COUNT,
	dad_count, CTLFLAG_RW,	&ip6_dad_count,	0, "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_AUTO_FLOWLABEL,
	auto_flowlabel, CTLFLAG_RW,	&ip6_auto_flowlabel,	0, "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_DEFMCASTHLIM,
	defmcasthlim, CTLFLAG_RW,	&ip6_defmcasthlim,	0, "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_GIF_HLIM,
	gifhlim, CTLFLAG_RW,	&ip6_gif_hlim,			0, "");
SYSCTL_STRING(_net_inet6_ip6, IPV6CTL_KAME_VERSION,
	kame_version, CTLFLAG_RD,	__KAME_VERSION,		0, "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_USE_DEPRECATED,
	use_deprecated, CTLFLAG_RW,	&ip6_use_deprecated,	0, "");
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_RR_PRUNE,
	rr_prune, CTLFLAG_RW,	&ip6_rr_prune,			0, "");
#if MAPPED_ADDR_ENABLED
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_MAPPED_ADDR,
	mapped_addr, CTLFLAG_RW,	&ip6_mapped_addr_on,	0, "");
#endif /* MAPPED_ADDR_ENABLED */

/* net.inet6.icmp6 */
SYSCTL_INT(_net_inet6_icmp6, ICMPV6CTL_REDIRACCEPT,
	rediraccept, CTLFLAG_RW,	&icmp6_rediraccept,	0, "");
SYSCTL_INT(_net_inet6_icmp6, ICMPV6CTL_REDIRTIMEOUT,
	redirtimeout, CTLFLAG_RW,	&icmp6_redirtimeout,	0, "");
SYSCTL_STRUCT(_net_inet6_icmp6, ICMPV6CTL_STATS, stats, CTLFLAG_RD,
	&icmp6stat, icmp6stat, "");
SYSCTL_INT(_net_inet6_icmp6, ICMPV6CTL_ERRRATELIMIT,
	errratelimit, CTLFLAG_RW,	&icmp6errratelim,	0, "");
SYSCTL_INT(_net_inet6_icmp6, ICMPV6CTL_ND6_PRUNE,
	nd6_prune, CTLFLAG_RW,		&nd6_prune,	0, "");
SYSCTL_INT(_net_inet6_icmp6, ICMPV6CTL_ND6_DELAY,
	nd6_delay, CTLFLAG_RW,		&nd6_delay,	0, "");
SYSCTL_INT(_net_inet6_icmp6, ICMPV6CTL_ND6_UMAXTRIES,
	nd6_umaxtries, CTLFLAG_RW,	&nd6_umaxtries,	0, "");
SYSCTL_INT(_net_inet6_icmp6, ICMPV6CTL_ND6_MMAXTRIES,
	nd6_mmaxtries, CTLFLAG_RW,	&nd6_mmaxtries,	0, "");
SYSCTL_INT(_net_inet6_icmp6, ICMPV6CTL_ND6_USELOOPBACK,
	nd6_useloopback, CTLFLAG_RW,	&nd6_useloopback, 0, "");
//SYSCTL_INT(_net_inet6_icmp6, ICMPV6CTL_ND6_PROXYALL,
//	nd6_proxyall, CTLFLAG_RW,	&nd6_proxyall, 0, "");
SYSCTL_INT(_net_inet6_icmp6, ICMPV6CTL_NODEINFO,
	nodeinfo, CTLFLAG_RW,	&icmp6_nodeinfo,	0, "");


#if defined(__FreeBSD__) && __FreeBSD__ < 3
/* net.inet6.udp6 */
SYSCTL_INT(_net_inet6_udp6, UDP6CTL_SENDMAX,
	sendmax, CTLFLAG_RW,	&udp6_sendspace,	0, "");
SYSCTL_INT(_net_inet6_udp6, UDP6CTL_RECVSPACE,
	recvspace, CTLFLAG_RW,	&udp6_recvspace,	0, "");

/* net.inet6.tcp6 */
SYSCTL_INT(_net_inet6_tcp6, TCP6CTL_MSSDFLT,
	mssdflt, CTLFLAG_RW,	&tcp6_mssdflt, 0, "");
SYSCTL_INT(_net_inet6_tcp6, TCP6CTL_DO_RFC1323,
	do_rfc1323, CTLFLAG_RW,	&tcp6_do_rfc1323, 0, "");
SYSCTL_INT(_net_inet6_tcp6, TCP6CTL_KEEPIDLE,
	keepidle, CTLFLAG_RW,	&tcp6_keepidle, 0, "");
SYSCTL_INT(_net_inet6_tcp6, TCP6CTL_KEEPINTVL,
	keepintvl, CTLFLAG_RW,	&tcp6_keepintvl, 0, "");
SYSCTL_INT(_net_inet6_tcp6, TCP6CTL_KEEPCNT,
	keepcnt, CTLFLAG_RW,	&tcp6_keepcnt, 0, "");
SYSCTL_INT(_net_inet6_tcp6, TCP6CTL_MAXPERSISTIDLE,
	maxpersistidle, CTLFLAG_RW,	&tcp6_maxpersistidle, 0, "");
SYSCTL_INT(_net_inet6_tcp6, TCP6CTL_SENDSPACE,
	sendspace, CTLFLAG_RW,	&tcp6_sendspace, 0, "");
SYSCTL_INT(_net_inet6_tcp6, TCP6CTL_RECVSPACE,
	recvspace, CTLFLAG_RW,	&tcp6_recvspace, 0, "");
SYSCTL_INT(_net_inet6_tcp6, TCP6CTL_CONNTIMEO,
	conntimeo, CTLFLAG_RW,	&tcp6_conntimeo, 0, "");
SYSCTL_INT(_net_inet6_tcp6, TCP6CTL_PMTU,
	pmtu, CTLFLAG_RW,	&tcp6_pmtu, 0, "");
SYSCTL_INT(_net_inet6_tcp6, TCP6CTL_PMTU_EXPIRE,
	pmtu_expire, CTLFLAG_RW,	&pmtu_expire, 0, "");
SYSCTL_INT(_net_inet6_tcp6, TCP6CTL_PMTU_PROBE,
	pmtu_probe, CTLFLAG_RW,	&pmtu_probe, 0, "");
SYSCTL_INT(_net_inet6_tcp6, TCP6CTL_43MAXSEG,
	pmtu_43maxseg, CTLFLAG_RW,	&tcp6_43maxseg, 0, "");
SYSCTL_STRUCT(_net_inet6_tcp6, TCP6CTL_STATS, stats, CTLFLAG_RD,
	&tcp6stat, tcp6stat, "");
SYSCTL_INT(_net_inet6_tcp6, TCP6CTL_SYN_CACHE_LIMIT,
	syn_cache_limit, CTLFLAG_RW,	&tcp6_syn_cache_limit, 0, "");
SYSCTL_INT(_net_inet6_tcp6, TCP6CTL_SYN_BUCKET_LIMIT,
	syn_bucket_limit, CTLFLAG_RW,	&tcp6_syn_bucket_limit, 0, "");
SYSCTL_INT(_net_inet6_tcp6, TCP6CTL_SYN_CACHE_INTER,
	syn_cache_interval, CTLFLAG_RW, &tcp6_syn_cache_interval, 0, "");
#endif /* !(defined(__FreeBSD__) && __FreeBSD__ >= 3) */

#endif /* __FreeBSD__ */
