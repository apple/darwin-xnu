/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/* Copyright (c) 1998, 1999 Apple Computer, Inc. All Rights Reserved */
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
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
 *	@(#)protosw.h	8.1 (Berkeley) 6/2/93
 */

/*
 * Protocol switch table.
 *
 * Each protocol has a handle initializing one of these structures,
 * which is used for protocol-protocol and system-protocol communication.
 *
 * A protocol is called through the pr_init entry before any other.
 * Thereafter it is called every 200ms through the pr_fasttimo entry and
 * every 500ms through the pr_slowtimo for timer based actions.
 * The system will call the pr_drain entry if it is low on space and
 * this should throw away any non-critical data.
 *
 * Protocols pass data between themselves as chains of mbufs using
 * the pr_input and pr_output hooks.  Pr_input passes data up (towards
 * UNIX) and pr_output passes it down (towards the imps); control
 * information passes up and down on pr_ctlinput and pr_ctloutput.
 * The protocol is responsible for the space occupied by any the
 * arguments to these entries and must dispose it.
 *
 * The userreq routine interfaces protocols to the system and is
 * described below.
 */
 
#ifndef	_SYS_PROTOSW_H_
#define _SYS_PROTOSW_H_

#include <sys/socketvar.h>
#include <sys/queue.h>

struct protosw {
	short	pr_type;		/* socket type used for */
	struct	domain *pr_domain;	/* domain protocol a member of */
	short	pr_protocol;		/* protocol number */
	unsigned int pr_flags;		/* see below */
/* protocol-protocol hooks */
	void	(*pr_input) __P((struct mbuf *, int len));
					/* input to protocol (from below) */
	int	(*pr_output)	__P((struct mbuf *m, struct socket *so));
					/* output to protocol (from above) */
	void	(*pr_ctlinput)__P((int, struct sockaddr *, void *));
					/* control input (from below) */
	int	(*pr_ctloutput)__P((struct socket *, struct sockopt *));
					/* control output (from above) */
/* user-protocol hook */
	void	*pr_ousrreq;
/* utility hooks */
	void	(*pr_init) __P((void));	/* initialization hook */
	void	(*pr_fasttimo) __P((void));
					/* fast timeout (200ms) */
	void	(*pr_slowtimo) __P((void));
					/* slow timeout (500ms) */
	void	(*pr_drain) __P((void));
					/* flush any excess space possible */

	int	(*pr_sysctl)();		/* sysctl for protocol */

	struct	pr_usrreqs *pr_usrreqs;	/* supersedes pr_usrreq() */
/* Implant hooks */
	TAILQ_HEAD(pr_sfilter, NFDescriptor) pr_sfilter;
	struct protosw *pr_next;	/* Chain for domain */
};

#define	PR_SLOWHZ	2		/* 2 slow timeouts per second */
#define	PR_FASTHZ	5		/* 5 fast timeouts per second */

/*
 * Values for pr_flags.
 * PR_ADDR requires PR_ATOMIC;
 * PR_ADDR and PR_CONNREQUIRED are mutually exclusive.
 */
#define	PR_ATOMIC	0x01		/* exchange atomic messages only */
#define	PR_ADDR		0x02		/* addresses given with messages */
#define	PR_CONNREQUIRED	0x04		/* connection required by protocol */
#define	PR_WANTRCVD	0x08		/* want PRU_RCVD calls */
#define	PR_RIGHTS	0x10		/* passes capabilities */
#define PR_IMPLOPCL	0x20		/* implied open/close */

/*
 * The arguments to usrreq are:
 *	(*protosw[].pr_usrreq)(up, req, m, nam, opt);
 * where up is a (struct socket *), req is one of these requests,
 * m is a optional mbuf chain containing a message,
 * nam is an optional mbuf chain containing an address,
 * and opt is a pointer to a socketopt structure or nil.
 * The protocol is responsible for disposal of the mbuf chain m,
 * the caller is responsible for any space held by nam and opt.
 * A non-zero return from usrreq gives an
 * UNIX error number which should be passed to higher level software.
 */
#define	PRU_ATTACH		0	/* attach protocol to up */
#define	PRU_DETACH		1	/* detach protocol from up */
#define	PRU_BIND		2	/* bind socket to address */
#define	PRU_LISTEN		3	/* listen for connection */
#define	PRU_CONNECT		4	/* establish connection to peer */
#define	PRU_ACCEPT		5	/* accept connection from peer */
#define	PRU_DISCONNECT		6	/* disconnect from peer */
#define	PRU_SHUTDOWN		7	/* won't send any more data */
#define	PRU_RCVD		8	/* have taken data; more room now */
#define	PRU_SEND		9	/* send this data */
#define	PRU_ABORT		10	/* abort (fast DISCONNECT, DETATCH) */
#define	PRU_CONTROL		11	/* control operations on protocol */
#define	PRU_SENSE		12	/* return status into m */
#define	PRU_RCVOOB		13	/* retrieve out of band data */
#define	PRU_SENDOOB		14	/* send out of band data */
#define	PRU_SOCKADDR		15	/* fetch socket's address */
#define	PRU_PEERADDR		16	/* fetch peer's address */
#define	PRU_CONNECT2		17	/* connect two sockets */
/* begin for protocols internal use */
#define	PRU_FASTTIMO		18	/* 200ms timeout */
#define	PRU_SLOWTIMO		19	/* 500ms timeout */
#define	PRU_PROTORCV		20	/* receive from below */
#define	PRU_PROTOSEND		21	/* send to below */
/* end for protocol's internal use */
#define PRU_SEND_EOF		22	/* send and close */
#define PRU_NREQ		22

#ifdef PRUREQUESTS
char *prurequests[] = {
	"ATTACH",	"DETACH",	"BIND",		"LISTEN",
	"CONNECT",	"ACCEPT",	"DISCONNECT",	"SHUTDOWN",
	"RCVD",		"SEND",		"ABORT",	"CONTROL",
	"SENSE",	"RCVOOB",	"SENDOOB",	"SOCKADDR",
	"PEERADDR",	"CONNECT2",	"FASTTIMO",	"SLOWTIMO",
	"PROTORCV",	"PROTOSEND",
	"SEND_EOF",
};
#endif

#ifdef	KERNEL			/* users shouldn't see this decl */

struct ifnet;
struct stat;
struct ucred;
struct uio;

/*
 * If the ordering here looks odd, that's because it's alphabetical.
 * Having this structure separated out from the main protoswitch is allegedly
 * a big (12 cycles per call) lose on high-end CPUs.  We will eventually
 * migrate this stuff back into the main structure.
 */
struct pr_usrreqs {
	int	(*pru_abort) __P((struct socket *so));
	int	(*pru_accept) __P((struct socket *so, struct sockaddr **nam));
	int	(*pru_attach) __P((struct socket *so, int proto,
				   struct proc *p));
	int	(*pru_bind) __P((struct socket *so, struct sockaddr *nam,
				 struct proc *p));
	int	(*pru_connect) __P((struct socket *so, struct sockaddr *nam,
				    struct proc *p));
	int	(*pru_connect2) __P((struct socket *so1, struct socket *so2));
	int	(*pru_control) __P((struct socket *so, u_long cmd, caddr_t data,
				    struct ifnet *ifp, struct proc *p));
	int	(*pru_detach) __P((struct socket *so));
	int	(*pru_disconnect) __P((struct socket *so));
	int	(*pru_listen) __P((struct socket *so, struct proc *p));
	int	(*pru_peeraddr) __P((struct socket *so, 
				     struct sockaddr **nam));
	int	(*pru_rcvd) __P((struct socket *so, int flags));
	int	(*pru_rcvoob) __P((struct socket *so, struct mbuf *m,
				   int flags));
	int	(*pru_send) __P((struct socket *so, int flags, struct mbuf *m, 
				 struct sockaddr *addr, struct mbuf *control,
				 struct proc *p));
#define	PRUS_OOB	0x1
#define	PRUS_EOF	0x2
#define	PRUS_MORETOCOME	0x4
	int	(*pru_sense) __P((struct socket *so, struct stat *sb));
	int	(*pru_shutdown) __P((struct socket *so));
	int	(*pru_sockaddr) __P((struct socket *so, 
				     struct sockaddr **nam));
	 
	/*
	 * These three added later, so they are out of order.  They are used
	 * for shortcutting (fast path input/output) in some protocols.
	 * XXX - that's a lie, they are not implemented yet
	 * Rather than calling sosend() etc. directly, calls are made
	 * through these entry points.  For protocols which still use
	 * the generic code, these just point to those routines.
	 */
	int	(*pru_sosend) __P((struct socket *so, struct sockaddr *addr,
				   struct uio *uio, struct mbuf *top,
				   struct mbuf *control, int flags));
	int	(*pru_soreceive) __P((struct socket *so, 
				      struct sockaddr **paddr,
				      struct uio *uio, struct mbuf **mp0,
				      struct mbuf **controlp, int *flagsp));
	int	(*pru_sopoll) __P((struct socket *so, int events, 
				   struct ucred *cred));
};


extern int	pru_abort_notsupp(struct socket *so);
extern int	pru_accept_notsupp(struct socket *so, struct sockaddr **nam);
extern int	pru_attach_notsupp(struct socket *so, int proto,
				   struct proc *p);
extern int	pru_bind_notsupp(struct socket *so, struct sockaddr *nam,
				 struct proc *p);
extern int	pru_connect_notsupp(struct socket *so, struct sockaddr *nam,
				    struct proc *p);
extern int	pru_connect2_notsupp(struct socket *so1, struct socket *so2);
extern int	pru_control_notsupp(struct socket *so, u_long cmd, caddr_t data,
				    struct ifnet *ifp, struct proc *p);
extern int	pru_detach_notsupp(struct socket *so);
extern int	pru_disconnect_notsupp(struct socket *so);
extern int	pru_listen_notsupp(struct socket *so, struct proc *p);
extern int	pru_peeraddr_notsupp(struct socket *so, 
				     struct sockaddr **nam);
extern int	pru_rcvd_notsupp(struct socket *so, int flags);
extern int	pru_rcvoob_notsupp(struct socket *so, struct mbuf *m,
				   int flags);
extern int	pru_send_notsupp(struct socket *so, int flags, struct mbuf *m, 
				 struct sockaddr *addr, struct mbuf *control,
				 struct proc *p);
extern int	pru_sense_null(struct socket *so, struct stat *sb);
extern int	pru_shutdown_notsupp(struct socket *so);
extern int	pru_sockaddr_notsupp(struct socket *so, 
				     struct sockaddr **nam);
extern int	pru_sosend_notsupp(struct socket *so, struct sockaddr *addr,
				   struct uio *uio, struct mbuf *top,
				   struct mbuf *control, int flags);
extern int	pru_soreceive_notsupp(struct socket *so, 
				      struct sockaddr **paddr,
				      struct uio *uio, struct mbuf **mp0,
				      struct mbuf **controlp, int *flagsp);
extern int	pru_sopoll_notsupp(struct socket *so, int events, 
				   struct ucred *cred);


#endif /* KERNEL */

/*
 * The arguments to the ctlinput routine are
 *	(*protosw[].pr_ctlinput)(cmd, sa, arg);
 * where cmd is one of the commands below, sa is a pointer to a sockaddr,
 * and arg is a `void *' argument used within a protocol family.
 */
#define	PRC_IFDOWN		0	/* interface transition */
#define	PRC_ROUTEDEAD		1	/* select new route if possible ??? */
#define	PRC_IFUP		2 	/* interface has come back up */
#define	PRC_QUENCH2		3	/* DEC congestion bit says slow down */
#define	PRC_QUENCH		4	/* some one said to slow down */
#define	PRC_MSGSIZE		5	/* message size forced drop */
#define	PRC_HOSTDEAD		6	/* host appears to be down */
#define	PRC_HOSTUNREACH		7	/* deprecated (use PRC_UNREACH_HOST) */
#define	PRC_UNREACH_NET		8	/* no route to network */
#define	PRC_UNREACH_HOST	9	/* no route to host */
#define	PRC_UNREACH_PROTOCOL	10	/* dst says bad protocol */
#define	PRC_UNREACH_PORT	11	/* bad port # */
/* was	PRC_UNREACH_NEEDFRAG	12	   (use PRC_MSGSIZE) */
#define	PRC_UNREACH_SRCFAIL	13	/* source route failed */
#define	PRC_REDIRECT_NET	14	/* net routing redirect */
#define	PRC_REDIRECT_HOST	15	/* host routing redirect */
#define	PRC_REDIRECT_TOSNET	16	/* redirect for type of service & net */
#define	PRC_REDIRECT_TOSHOST	17	/* redirect for tos & host */
#define	PRC_TIMXCEED_INTRANS	18	/* packet lifetime expired in transit */
#define	PRC_TIMXCEED_REASS	19	/* lifetime expired on reass q */
#define	PRC_PARAMPROB		20	/* header incorrect */

#define	PRC_NCMDS		21

#define	PRC_IS_REDIRECT(cmd)	\
	((cmd) >= PRC_REDIRECT_NET && (cmd) <= PRC_REDIRECT_TOSHOST)

#ifdef PRCREQUESTS
char	*prcrequests[] = {
	"IFDOWN", "ROUTEDEAD", "IFUP", "DEC-BIT-QUENCH2",
	"QUENCH", "MSGSIZE", "HOSTDEAD", "#7",
	"NET-UNREACH", "HOST-UNREACH", "PROTO-UNREACH", "PORT-UNREACH",
	"#12", "SRCFAIL-UNREACH", "NET-REDIRECT", "HOST-REDIRECT",
	"TOSNET-REDIRECT", "TOSHOST-REDIRECT", "TX-INTRANS", "TX-REASS",
	"PARAMPROB"
};
#endif

/*
 * The arguments to ctloutput are:
 *	(*protosw[].pr_ctloutput)(req, so, level, optname, optval, p);
 * req is one of the actions listed below, so is a (struct socket *),
 * level is an indication of which protocol layer the option is intended.
 * optname is a protocol dependent socket option request,
 * optval is a pointer to a mbuf-chain pointer, for value-return results.
 * The protocol is responsible for disposal of the mbuf chain *optval
 * if supplied,
 * the caller is responsible for any space held by *optval, when returned.
 * A non-zero return from usrreq gives an
 * UNIX error number which should be passed to higher level software.
 */
#define	PRCO_GETOPT	0
#define	PRCO_SETOPT	1

#define	PRCO_NCMDS	2

#ifdef PRCOREQUESTS
char	*prcorequests[] = {
	"GETOPT", "SETOPT",
};
#endif

#ifdef KERNEL
void	pfctlinput __P((int, struct sockaddr *));
struct protosw *pffindproto __P((int family, int protocol, int type));
struct protosw *pffindtype __P((int family, int type));

extern int net_add_proto(struct protosw *, struct domain *);
extern int net_del_proto(int, int, struct domain *);

/* Temp hack to link static domains together */

#define LINK_PROTOS(psw) \
static void link_ ## psw ## _protos() \
{ \
      int i; \
		 \
    for (i=0; i < ((sizeof(psw)/sizeof(psw[0])) - 1); i++) \
	     psw[i].pr_next = &psw[i + 1]; \
} 

#endif
#endif	/* !_SYS_PROTOSW_H_ */
