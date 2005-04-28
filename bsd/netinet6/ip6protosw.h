/*	$FreeBSD: src/sys/netinet6/ip6protosw.h,v 1.2.2.3 2001/07/03 11:01:54 ume Exp $	*/
/*	$KAME: ip6protosw.h,v 1.22 2001/02/08 18:02:08 itojun Exp $	*/

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
 *
 */

/*	BSDI protosw.h,v 2.3 1996/10/11 16:02:40 pjd Exp	*/

/*-
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
 *	@(#)protosw.h	8.1 (Berkeley) 6/2/93
 */

#ifndef _NETINET6_IP6PROTOSW_H_
#define _NETINET6_IP6PROTOSW_H_
#include <sys/appleapiopts.h>

#ifdef KERNEL_PRIVATE
#include <kern/locks.h>

/*
 * Protocol switch table for IPv6.
 * All other definitions should refer to sys/protosw.h
 */

struct mbuf;
struct sockaddr;
struct socket;
struct domain;
struct proc;
struct ip6_hdr;
struct icmp6_hdr;
struct in6_addr;
struct pr_usrreqs;

/*
 * argument type for the last arg of pr_ctlinput().
 * should be consulted only with AF_INET6 family.
 *
 * IPv6 ICMP IPv6 [exthdrs] finalhdr paylaod
 * ^    ^    ^              ^
 * |    |    ip6c_ip6       ip6c_off
 * |    ip6c_icmp6
 * ip6c_m
 *
 * ip6c_finaldst usually points to ip6c_ip6->ip6_dst.  if the original
 * (internal) packet carries a routing header, it may point the final
 * dstination address in the routing header.
 *
 * ip6c_src: ip6c_ip6->ip6_src + scope info + flowlabel in ip6c_ip6
 *	(beware of flowlabel, if you try to compare it against others)
 * ip6c_dst: ip6c_finaldst + scope info
 */
struct ip6ctlparam {
	struct mbuf *ip6c_m;		/* start of mbuf chain */
	struct icmp6_hdr *ip6c_icmp6;	/* icmp6 header of target packet */
	struct ip6_hdr *ip6c_ip6;	/* ip6 header of target packet */
	int ip6c_off;			/* offset of the target proto header */
	struct sockaddr_in6 *ip6c_src;	/* srcaddr w/ additional info */
	struct sockaddr_in6 *ip6c_dst;	/* (final) dstaddr w/ additional info */
	struct in6_addr *ip6c_finaldst;	/* final destination address */
	void *ip6c_cmdarg;		/* control command dependent data */
	u_int8_t ip6c_nxt;		/* final next header field */
};

struct ip6protosw {
	short	pr_type;		/* socket type used for */
	struct	domain *pr_domain;	/* domain protocol a member of */
	short	pr_protocol;		/* protocol number */
        unsigned int pr_flags;          /* see below */
/* protocol-protocol hooks */
	int	(*pr_input)(struct mbuf **, int *);
					/* input to protocol (from below) */
	int	(*pr_output)(struct mbuf *m, struct socket *so,
				     struct sockaddr_in6 *, struct mbuf *);
					/* output to protocol (from above) */
	void	(*pr_ctlinput)(int, struct sockaddr *, void *);
					/* control input (from below) */
	int	(*pr_ctloutput)(struct socket *, struct sockopt *);
					/* control output (from above) */
/* user-protocol hook */
	int	(*pr_usrreq)(struct socket *, int, struct mbuf *,
			     struct mbuf *, struct mbuf *, struct proc *);
					/* user request: see list below */

/* utility hooks */
	void	(*pr_init)(void);	/* initialization hook */
	void	(*pr_fasttimo)(void);
					/* fast timeout (200ms) */
	void	(*pr_slowtimo)(void);
					/* slow timeout (500ms) */
	void	(*pr_drain)(void);
					/* flush any excess space possible */
#ifdef __APPLE__
	/* for compat. with IPv4 protosw */
	int	(*pr_sysctl)();		/* sysctl for protocol */
#endif

	struct	pr_usrreqs *pr_usrreqs;	/* supersedes pr_usrreq() */
#ifdef __APPLE__
	int     	(*pr_lock)      (struct socket *so, int locktype, int debug); /* lock function for protocol */
	int     	(*pr_unlock)    (struct socket *so, int locktype, int debug); /* unlock for protocol */
#ifdef _KERN_LOCKS_H_
	lck_mtx_t *	(*pr_getlock)   (struct socket *so, int locktype); /* unlock for protocol */
#else
	void *	(*pr_getlock)   (struct socket *so, int locktype); /* unlock for protocol */
#endif
	/* Filter hooks */
	TAILQ_HEAD(pr6_sfilter, NFDescriptor) pr_sfilter;
	struct ip6protosw *pr_next;	/* Chain for domain */
	u_long reserved[1];
#endif
};

#endif KERNEL_PRIVATE
#endif _NETINET6_IP6PROTOSW_H_
