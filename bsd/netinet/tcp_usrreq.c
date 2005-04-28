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
/*
 * Copyright (c) 1982, 1986, 1988, 1993
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
 *	From: @(#)tcp_usrreq.c	8.2 (Berkeley) 1/3/94
 * $FreeBSD: src/sys/netinet/tcp_usrreq.c,v 1.51.2.9 2001/08/22 00:59:12 silby Exp $
 */


#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/mbuf.h>
#if INET6
#include <sys/domain.h>
#endif /* INET6 */
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#if INET6
#include <netinet/ip6.h>
#endif
#include <netinet/in_pcb.h>
#if INET6
#include <netinet6/in6_pcb.h>
#endif
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#if INET6
#include <netinet6/ip6_var.h>
#endif
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcpip.h>
#if TCPDEBUG
#include <netinet/tcp_debug.h>
#endif

#if IPSEC
#include <netinet6/ipsec.h>
#endif /*IPSEC*/

/*
 * TCP protocol interface to socket abstraction.
 */
extern	char *tcpstates[];	/* XXX ??? */

static int	tcp_attach(struct socket *, struct proc *);
static int	tcp_connect(struct tcpcb *, struct sockaddr *, struct proc *);
#if INET6
static int	tcp6_connect(struct tcpcb *, struct sockaddr *, struct proc *);
#endif /* INET6 */
static struct tcpcb *
		tcp_disconnect(struct tcpcb *);
static struct tcpcb *
		tcp_usrclosed(struct tcpcb *);

#if TCPDEBUG
#define	TCPDEBUG0	int ostate = 0
#define	TCPDEBUG1()	ostate = tp ? tp->t_state : 0
#define	TCPDEBUG2(req)	if (tp && (so->so_options & SO_DEBUG)) \
				tcp_trace(TA_USER, ostate, tp, 0, 0, req)
#else
#define	TCPDEBUG0
#define	TCPDEBUG1()
#define	TCPDEBUG2(req)
#endif

/*
 * TCP attaches to socket via pru_attach(), reserving space,
 * and an internet control block.
 */
static int
tcp_usr_attach(struct socket *so, int proto, struct proc *p)
{
	int error;
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp = 0;
	TCPDEBUG0;

	TCPDEBUG1();
	if (inp) {
		error = EISCONN;
		goto out;
	}

	error = tcp_attach(so, p);
	if (error)
		goto out;

	if ((so->so_options & SO_LINGER) && so->so_linger == 0)
		so->so_linger = TCP_LINGERTIME * hz;
	tp = sototcpcb(so);
out:
	TCPDEBUG2(PRU_ATTACH);
	return error;
}

/*
 * pru_detach() detaches the TCP protocol from the socket.
 * If the protocol state is non-embryonic, then can't
 * do this directly: have to initiate a pru_disconnect(),
 * which may finish later; embryonic TCB's can just
 * be discarded here.
 */
static int
tcp_usr_detach(struct socket *so)
{
	int error = 0;
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp;
	TCPDEBUG0;

	if (inp == 0 || (inp->inp_state == INPCB_STATE_DEAD)) {
		return EINVAL;	/* XXX */
	}
#if 1
	lck_mtx_assert(((struct inpcb *)so->so_pcb)->inpcb_mtx, LCK_MTX_ASSERT_OWNED);
#endif
	tp = intotcpcb(inp);
	/* In case we got disconnected from the peer */
        if (tp == 0) 
	    goto out;
	TCPDEBUG1();
	tp = tcp_disconnect(tp);
out:
	TCPDEBUG2(PRU_DETACH);
	return error;
}

#define	COMMON_START()	TCPDEBUG0; \
			do { \
				     if (inp == 0 || (inp->inp_state == INPCB_STATE_DEAD)) { \
					     return EINVAL; \
				     } \
				     tp = intotcpcb(inp); \
				     TCPDEBUG1(); \
		     } while(0)
			     
#define COMMON_END(req)	out: TCPDEBUG2(req); return error; goto out


/*
 * Give the socket an address.
 */
static int
tcp_usr_bind(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	int error = 0;
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp;
	struct sockaddr_in *sinp;

	COMMON_START();

	/*
	 * Must check for multicast addresses and disallow binding
	 * to them.
	 */
	sinp = (struct sockaddr_in *)nam;
	if (sinp->sin_family == AF_INET &&
	    IN_MULTICAST(ntohl(sinp->sin_addr.s_addr))) {
		error = EAFNOSUPPORT;
		goto out;
	}
	error = in_pcbbind(inp, nam, p);
	if (error)
		goto out;
	COMMON_END(PRU_BIND);

}

#if INET6
static int
tcp6_usr_bind(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	int error = 0;
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp;
	struct sockaddr_in6 *sin6p;

	COMMON_START();

	/*
	 * Must check for multicast addresses and disallow binding
	 * to them.
	 */
	sin6p = (struct sockaddr_in6 *)nam;
	if (sin6p->sin6_family == AF_INET6 &&
	    IN6_IS_ADDR_MULTICAST(&sin6p->sin6_addr)) {
		error = EAFNOSUPPORT;
		goto out;
	}
	inp->inp_vflag &= ~INP_IPV4;
	inp->inp_vflag |= INP_IPV6;
	if ((inp->inp_flags & IN6P_IPV6_V6ONLY) == 0) {
		if (IN6_IS_ADDR_UNSPECIFIED(&sin6p->sin6_addr))
			inp->inp_vflag |= INP_IPV4;
		else if (IN6_IS_ADDR_V4MAPPED(&sin6p->sin6_addr)) {
			struct sockaddr_in sin;

			in6_sin6_2_sin(&sin, sin6p);
			inp->inp_vflag |= INP_IPV4;
			inp->inp_vflag &= ~INP_IPV6;
			error = in_pcbbind(inp, (struct sockaddr *)&sin, p);
			goto out;
		}
	}
	error = in6_pcbbind(inp, nam, p);
	if (error)
		goto out;
	COMMON_END(PRU_BIND);
}
#endif /* INET6 */

/*
 * Prepare to accept connections.
 */
static int
tcp_usr_listen(struct socket *so, struct proc *p)
{
	int error = 0;
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp;

	COMMON_START();
	if (inp->inp_lport == 0)
		error = in_pcbbind(inp, (struct sockaddr *)0, p);
	if (error == 0)
		tp->t_state = TCPS_LISTEN;
	COMMON_END(PRU_LISTEN);
}

#if INET6
static int
tcp6_usr_listen(struct socket *so, struct proc *p)
{
	int error = 0;
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp;

	COMMON_START();
	if (inp->inp_lport == 0) {
		inp->inp_vflag &= ~INP_IPV4;
		if ((inp->inp_flags & IN6P_IPV6_V6ONLY) == 0)
			inp->inp_vflag |= INP_IPV4;
		error = in6_pcbbind(inp, (struct sockaddr *)0, p);
	}
	if (error == 0)
		tp->t_state = TCPS_LISTEN;
	COMMON_END(PRU_LISTEN);
}
#endif /* INET6 */

/*
 * Initiate connection to peer.
 * Create a template for use in transmissions on this connection.
 * Enter SYN_SENT state, and mark socket as connecting.
 * Start keep-alive timer, and seed output sequence space.
 * Send initial segment on connection.
 */
static int
tcp_usr_connect(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	int error = 0;
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp;
	struct sockaddr_in *sinp;

	COMMON_START();

	/*
	 * Must disallow TCP ``connections'' to multicast addresses.
	 */
	sinp = (struct sockaddr_in *)nam;
	if (sinp->sin_family == AF_INET
	    && IN_MULTICAST(ntohl(sinp->sin_addr.s_addr))) {
		error = EAFNOSUPPORT;
		goto out;
	}

#ifndef __APPLE__
	prison_remote_ip(p, 0, &sinp->sin_addr.s_addr);
#endif

	if ((error = tcp_connect(tp, nam, p)) != 0)
		goto out;
	error = tcp_output(tp);
	COMMON_END(PRU_CONNECT);
}

#if INET6
static int
tcp6_usr_connect(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	int error = 0;
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp;
	struct sockaddr_in6 *sin6p;

	COMMON_START();

	/*
	 * Must disallow TCP ``connections'' to multicast addresses.
	 */
	sin6p = (struct sockaddr_in6 *)nam;
	if (sin6p->sin6_family == AF_INET6
	    && IN6_IS_ADDR_MULTICAST(&sin6p->sin6_addr)) {
		error = EAFNOSUPPORT;
		goto out;
	}

	if (IN6_IS_ADDR_V4MAPPED(&sin6p->sin6_addr)) {
		struct sockaddr_in sin;

		if ((inp->inp_flags & IN6P_IPV6_V6ONLY) != 0)
			return (EINVAL);

		in6_sin6_2_sin(&sin, sin6p);
		inp->inp_vflag |= INP_IPV4;
		inp->inp_vflag &= ~INP_IPV6;
		if ((error = tcp_connect(tp, (struct sockaddr *)&sin, p)) != 0)
			goto out;
		error = tcp_output(tp);
		goto out;
	}
	inp->inp_vflag &= ~INP_IPV4;
	inp->inp_vflag |= INP_IPV6;
	if ((error = tcp6_connect(tp, nam, p)) != 0)
		goto out;
	error = tcp_output(tp);
	if (error)
		goto out;
	COMMON_END(PRU_CONNECT);
}
#endif /* INET6 */

/*
 * Initiate disconnect from peer.
 * If connection never passed embryonic stage, just drop;
 * else if don't need to let data drain, then can just drop anyways,
 * else have to begin TCP shutdown process: mark socket disconnecting,
 * drain unread data, state switch to reflect user close, and
 * send segment (e.g. FIN) to peer.  Socket will be really disconnected
 * when peer sends FIN and acks ours.
 *
 * SHOULD IMPLEMENT LATER PRU_CONNECT VIA REALLOC TCPCB.
 */
static int
tcp_usr_disconnect(struct socket *so)
{
	int error = 0;
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp;
	
#if 1
	lck_mtx_assert(((struct inpcb *)so->so_pcb)->inpcb_mtx, LCK_MTX_ASSERT_OWNED);
#endif
	COMMON_START();
        /* In case we got disconnected from the peer */
        if (tp == 0)
            goto out;
	tp = tcp_disconnect(tp);
	COMMON_END(PRU_DISCONNECT);
}

/*
 * Accept a connection.  Essentially all the work is
 * done at higher levels; just return the address
 * of the peer, storing through addr.
 */
static int
tcp_usr_accept(struct socket *so, struct sockaddr **nam)
{
	int error = 0;
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp = NULL;
	TCPDEBUG0;

	if (so->so_state & SS_ISDISCONNECTED) {
		error = ECONNABORTED;
		goto out;
	}
	if (inp == 0 || (inp->inp_state == INPCB_STATE_DEAD)) {
		return (EINVAL);
	}
	tp = intotcpcb(inp);
	TCPDEBUG1();
	in_setpeeraddr(so, nam);
	COMMON_END(PRU_ACCEPT);
}

#if INET6
static int
tcp6_usr_accept(struct socket *so, struct sockaddr **nam)
{
	int error = 0;
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp = NULL;
	TCPDEBUG0;

	if (so->so_state & SS_ISDISCONNECTED) {
		error = ECONNABORTED;
		goto out;
	}
	if (inp == 0 || (inp->inp_state == INPCB_STATE_DEAD)) {
		return (EINVAL);
	}
	tp = intotcpcb(inp);
	TCPDEBUG1();
	in6_mapped_peeraddr(so, nam);
	COMMON_END(PRU_ACCEPT);
}
#endif /* INET6 */
/*
 * Mark the connection as being incapable of further output.
 */
static int
tcp_usr_shutdown(struct socket *so)
{
	int error = 0;
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp;

	COMMON_START();
	socantsendmore(so);
        /* In case we got disconnected from the peer */
        if (tp == 0)
            goto out;
	tp = tcp_usrclosed(tp);
	if (tp)
		error = tcp_output(tp);
	COMMON_END(PRU_SHUTDOWN);
}

/*
 * After a receive, possibly send window update to peer.
 */
static int
tcp_usr_rcvd(struct socket *so, int flags)
{
	int error = 0;
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp;

	COMMON_START();
        /* In case we got disconnected from the peer */
        if (tp == 0)
            goto out;
	tcp_output(tp);
	COMMON_END(PRU_RCVD);
}

/*
 * Do a send by putting data in output queue and updating urgent
 * marker if URG set.  Possibly send more data.  Unlike the other
 * pru_*() routines, the mbuf chains are our responsibility.  We
 * must either enqueue them or free them.  The other pru_* routines
 * generally are caller-frees.
 */
static int
tcp_usr_send(struct socket *so, int flags, struct mbuf *m, 
	     struct sockaddr *nam, struct mbuf *control, struct proc *p)
{
	int error = 0;
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp;
#if INET6
	int isipv6;
#endif
	TCPDEBUG0;

	if (inp == NULL || inp->inp_state == INPCB_STATE_DEAD) {
		/*
		 * OOPS! we lost a race, the TCP session got reset after
		 * we checked SS_CANTSENDMORE, eg: while doing uiomove or a
		 * network interrupt in the non-splnet() section of sosend().
		 */
		if (m)
			m_freem(m);
		if (control)
			m_freem(control);
		error = ECONNRESET;	/* XXX EPIPE? */
		tp = NULL;
		TCPDEBUG1();
		goto out;
	}
#if INET6
	isipv6 = nam && nam->sa_family == AF_INET6;
#endif /* INET6 */
	tp = intotcpcb(inp);
	TCPDEBUG1();
	if (control) {
		/* TCP doesn't do control messages (rights, creds, etc) */
		if (control->m_len) {
			m_freem(control);
			if (m)
				m_freem(m);
			error = EINVAL;
			goto out;
		}
		m_freem(control);	/* empty control, just free it */
	}
	if(!(flags & PRUS_OOB)) {
		sbappend(&so->so_snd, m);
		if (nam && tp->t_state < TCPS_SYN_SENT) {
			/*
			 * Do implied connect if not yet connected,
			 * initialize window to default value, and
			 * initialize maxseg/maxopd using peer's cached
			 * MSS.
			 */
#if INET6
			if (isipv6)
				error = tcp6_connect(tp, nam, p);
			else
#endif /* INET6 */
			error = tcp_connect(tp, nam, p);
			if (error)
				goto out;
			tp->snd_wnd = TTCP_CLIENT_SND_WND;
			tcp_mss(tp, -1);
		}

		if (flags & PRUS_EOF) {
			/*
			 * Close the send side of the connection after
			 * the data is sent.
			 */
			socantsendmore(so);
			tp = tcp_usrclosed(tp);
		}
		if (tp != NULL) {
			if (flags & PRUS_MORETOCOME)
				tp->t_flags |= TF_MORETOCOME;
			error = tcp_output(tp);
			if (flags & PRUS_MORETOCOME)
				tp->t_flags &= ~TF_MORETOCOME;
		}
	} else {
		if (sbspace(&so->so_snd) < -512) {
			m_freem(m);
			error = ENOBUFS;
			goto out;
		}
		/*
		 * According to RFC961 (Assigned Protocols),
		 * the urgent pointer points to the last octet
		 * of urgent data.  We continue, however,
		 * to consider it to indicate the first octet
		 * of data past the urgent section.
		 * Otherwise, snd_up should be one lower.
		 */
		sbappend(&so->so_snd, m);
		if (nam && tp->t_state < TCPS_SYN_SENT) {
			/*
			 * Do implied connect if not yet connected,
			 * initialize window to default value, and
			 * initialize maxseg/maxopd using peer's cached
			 * MSS.
			 */
#if INET6
			if (isipv6)
				error = tcp6_connect(tp, nam, p);
			else
#endif /* INET6 */
			error = tcp_connect(tp, nam, p);
			if (error)
				goto out;
			tp->snd_wnd = TTCP_CLIENT_SND_WND;
			tcp_mss(tp, -1);
		}
		tp->snd_up = tp->snd_una + so->so_snd.sb_cc;
		tp->t_force = 1;
		error = tcp_output(tp);
		tp->t_force = 0;
	}
	COMMON_END((flags & PRUS_OOB) ? PRU_SENDOOB : 
		   ((flags & PRUS_EOF) ? PRU_SEND_EOF : PRU_SEND));
}

/*
 * Abort the TCP.
 */
static int
tcp_usr_abort(struct socket *so)
{
	int error = 0;
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp;

	COMMON_START();
        /* In case we got disconnected from the peer */
        if (tp == 0)
            goto out;
	tp = tcp_drop(tp, ECONNABORTED);
	so->so_usecount--;
	COMMON_END(PRU_ABORT);
}

/*
 * Receive out-of-band data.
 */
static int
tcp_usr_rcvoob(struct socket *so, struct mbuf *m, int flags)
{
	int error = 0;
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp;

	COMMON_START();
	if ((so->so_oobmark == 0 &&
	     (so->so_state & SS_RCVATMARK) == 0) ||
	    so->so_options & SO_OOBINLINE ||
	    tp->t_oobflags & TCPOOB_HADDATA) {
		error = EINVAL;
		goto out;
	}
	if ((tp->t_oobflags & TCPOOB_HAVEDATA) == 0) {
		error = EWOULDBLOCK;
		goto out;
	}
	m->m_len = 1;
	*mtod(m, caddr_t) = tp->t_iobc;
	if ((flags & MSG_PEEK) == 0)
		tp->t_oobflags ^= (TCPOOB_HAVEDATA | TCPOOB_HADDATA);
	COMMON_END(PRU_RCVOOB);
}

/* xxx - should be const */
struct pr_usrreqs tcp_usrreqs = {
	tcp_usr_abort, tcp_usr_accept, tcp_usr_attach, tcp_usr_bind,
	tcp_usr_connect, pru_connect2_notsupp, in_control, tcp_usr_detach,
	tcp_usr_disconnect, tcp_usr_listen, in_setpeeraddr, tcp_usr_rcvd,
	tcp_usr_rcvoob, tcp_usr_send, pru_sense_null, tcp_usr_shutdown,
	in_setsockaddr, sosend, soreceive, pru_sopoll_notsupp
};

#if INET6
struct pr_usrreqs tcp6_usrreqs = {
	tcp_usr_abort, tcp6_usr_accept, tcp_usr_attach, tcp6_usr_bind,
	tcp6_usr_connect, pru_connect2_notsupp, in6_control, tcp_usr_detach,
	tcp_usr_disconnect, tcp6_usr_listen, in6_mapped_peeraddr, tcp_usr_rcvd,
	tcp_usr_rcvoob, tcp_usr_send, pru_sense_null, tcp_usr_shutdown,
	in6_mapped_sockaddr, sosend, soreceive, pru_sopoll_notsupp
};
#endif /* INET6 */

/*
 * Common subroutine to open a TCP connection to remote host specified
 * by struct sockaddr_in in mbuf *nam.  Call in_pcbbind to assign a local
 * port number if needed.  Call in_pcbladdr to do the routing and to choose
 * a local host address (interface).  If there is an existing incarnation
 * of the same connection in TIME-WAIT state and if the remote host was
 * sending CC options and if the connection duration was < MSL, then
 * truncate the previous TIME-WAIT state and proceed.
 * Initialize connection parameters and enter SYN-SENT state.
 */
static int
tcp_connect(tp, nam, p)
	register struct tcpcb *tp;
	struct sockaddr *nam;
	struct proc *p;
{
	struct inpcb *inp = tp->t_inpcb, *oinp;
	struct socket *so = inp->inp_socket;
	struct tcpcb *otp;
	struct sockaddr_in *sin = (struct sockaddr_in *)nam;
	struct sockaddr_in *ifaddr;
	struct rmxp_tao *taop;
	struct rmxp_tao tao_noncached;
	int error;

	if (inp->inp_lport == 0) {
		error = in_pcbbind(inp, (struct sockaddr *)0, p);
		if (error)
			return error;
	}

	/*
	 * Cannot simply call in_pcbconnect, because there might be an
	 * earlier incarnation of this same connection still in
	 * TIME_WAIT state, creating an ADDRINUSE error.
	 */
	error = in_pcbladdr(inp, nam, &ifaddr);
	if (error)
		return error;

	tcp_unlock(inp->inp_socket, 0, 0);
	oinp = in_pcblookup_hash(inp->inp_pcbinfo,
	    sin->sin_addr, sin->sin_port,
	    inp->inp_laddr.s_addr != INADDR_ANY ? inp->inp_laddr
						: ifaddr->sin_addr,
	    inp->inp_lport,  0, NULL);

	tcp_lock(inp->inp_socket, 0, 0);
	if (oinp) {
		tcp_lock(oinp->inp_socket, 1, 0);
		if (in_pcb_checkstate(oinp, WNT_RELEASE, 1) == WNT_STOPUSING) {
			tcp_unlock(oinp->inp_socket, 1, 0);
			goto skip_oinp;
		}

		if (oinp != inp && (otp = intotcpcb(oinp)) != NULL &&
		otp->t_state == TCPS_TIME_WAIT &&
		    otp->t_starttime < tcp_msl &&
		    (otp->t_flags & TF_RCVD_CC))
			otp = tcp_close(otp);
		else {
			printf("tcp_connect: inp=%x err=EADDRINUSE\n", inp);
			tcp_unlock(oinp->inp_socket, 1, 0);
			return EADDRINUSE;
		}
		tcp_unlock(oinp->inp_socket, 1, 0);
	}
skip_oinp:
	if ((inp->inp_laddr.s_addr == INADDR_ANY ? ifaddr->sin_addr.s_addr :
		 inp->inp_laddr.s_addr) == sin->sin_addr.s_addr &&
	    inp->inp_lport == sin->sin_port)
			return EINVAL;
	if (!lck_rw_try_lock_exclusive(inp->inp_pcbinfo->mtx)) {
		/*lock inversion issue, mostly with udp multicast packets */
		socket_unlock(inp->inp_socket, 0);
		lck_rw_lock_exclusive(inp->inp_pcbinfo->mtx);
		socket_lock(inp->inp_socket, 0);
	}
	if (inp->inp_laddr.s_addr == INADDR_ANY)
		inp->inp_laddr = ifaddr->sin_addr;
	inp->inp_faddr = sin->sin_addr;
	inp->inp_fport = sin->sin_port;
	in_pcbrehash(inp);
	lck_rw_done(inp->inp_pcbinfo->mtx);

	/* Compute window scaling to request.  */
	while (tp->request_r_scale < TCP_MAX_WINSHIFT &&
	    (TCP_MAXWIN << tp->request_r_scale) < so->so_rcv.sb_hiwat)
		tp->request_r_scale++;

	soisconnecting(so);
	tcpstat.tcps_connattempt++;
	tp->t_state = TCPS_SYN_SENT;
	tp->t_timer[TCPT_KEEP] = tcp_keepinit;
	tp->iss = tcp_new_isn(tp);
	tcp_sendseqinit(tp);

	/*
	 * Generate a CC value for this connection and
	 * check whether CC or CCnew should be used.
	 */
	if ((taop = tcp_gettaocache(tp->t_inpcb)) == NULL) {
		taop = &tao_noncached;
		bzero(taop, sizeof(*taop));
	}

	tp->cc_send = CC_INC(tcp_ccgen);
	if (taop->tao_ccsent != 0 &&
	    CC_GEQ(tp->cc_send, taop->tao_ccsent)) {
		taop->tao_ccsent = tp->cc_send;
	} else {
		taop->tao_ccsent = 0;
		tp->t_flags |= TF_SENDCCNEW;
	}

	return 0;
}

#if INET6
static int
tcp6_connect(tp, nam, p)
	register struct tcpcb *tp;
	struct sockaddr *nam;
	struct proc *p;
{
	struct inpcb *inp = tp->t_inpcb, *oinp;
	struct socket *so = inp->inp_socket;
	struct tcpcb *otp;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)nam;
	struct in6_addr addr6;
	struct rmxp_tao *taop;
	struct rmxp_tao tao_noncached;
	int error;

	if (inp->inp_lport == 0) {
		error = in6_pcbbind(inp, (struct sockaddr *)0, p);
		if (error)
			return error;
	}

	/*
	 * Cannot simply call in_pcbconnect, because there might be an
	 * earlier incarnation of this same connection still in
	 * TIME_WAIT state, creating an ADDRINUSE error.
	 */
	error = in6_pcbladdr(inp, nam, &addr6);
	if (error)
		return error;
	tcp_unlock(inp->inp_socket, 0, 0);
	oinp = in6_pcblookup_hash(inp->inp_pcbinfo,
				  &sin6->sin6_addr, sin6->sin6_port,
				  IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr)
				  ? &addr6
				  : &inp->in6p_laddr,
				  inp->inp_lport,  0, NULL);
	tcp_lock(inp->inp_socket, 0, 0);
	if (oinp) {
		if (oinp != inp && (otp = intotcpcb(oinp)) != NULL &&
		    otp->t_state == TCPS_TIME_WAIT &&
		    otp->t_starttime < tcp_msl &&
		    (otp->t_flags & TF_RCVD_CC))
			otp = tcp_close(otp);
		else
			return EADDRINUSE;
	}
	if (!lck_rw_try_lock_exclusive(inp->inp_pcbinfo->mtx)) {
		/*lock inversion issue, mostly with udp multicast packets */
		socket_unlock(inp->inp_socket, 0);
		lck_rw_lock_exclusive(inp->inp_pcbinfo->mtx);
		socket_lock(inp->inp_socket, 0);
	}
	if (IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr))
		inp->in6p_laddr = addr6;
	inp->in6p_faddr = sin6->sin6_addr;
	inp->inp_fport = sin6->sin6_port;
	if ((sin6->sin6_flowinfo & IPV6_FLOWINFO_MASK) != NULL)
		inp->in6p_flowinfo = sin6->sin6_flowinfo;
	in_pcbrehash(inp);
	lck_rw_done(inp->inp_pcbinfo->mtx);

	/* Compute window scaling to request.  */
	while (tp->request_r_scale < TCP_MAX_WINSHIFT &&
	    (TCP_MAXWIN << tp->request_r_scale) < so->so_rcv.sb_hiwat)
		tp->request_r_scale++;

	soisconnecting(so);
	tcpstat.tcps_connattempt++;
	tp->t_state = TCPS_SYN_SENT;
	tp->t_timer[TCPT_KEEP] = tcp_keepinit;
	tp->iss = tcp_new_isn(tp);
	tcp_sendseqinit(tp);

	/*
	 * Generate a CC value for this connection and
	 * check whether CC or CCnew should be used.
	 */
	if ((taop = tcp_gettaocache(tp->t_inpcb)) == NULL) {
		taop = &tao_noncached;
		bzero(taop, sizeof(*taop));
	}

	tp->cc_send = CC_INC(tcp_ccgen);
	if (taop->tao_ccsent != 0 &&
	    CC_GEQ(tp->cc_send, taop->tao_ccsent)) {
		taop->tao_ccsent = tp->cc_send;
	} else {
		taop->tao_ccsent = 0;
		tp->t_flags |= TF_SENDCCNEW;
	}

	return 0;
}
#endif /* INET6 */

/*
 * The new sockopt interface makes it possible for us to block in the
 * copyin/out step (if we take a page fault).  Taking a page fault at
 * splnet() is probably a Bad Thing.  (Since sockets and pcbs both now
 * use TSM, there probably isn't any need for this function to run at
 * splnet() any more.  This needs more examination.)
 */
int
tcp_ctloutput(so, sopt)
	struct socket *so;
	struct sockopt *sopt;
{
	int	error, opt, optval;
	struct	inpcb *inp;
	struct	tcpcb *tp;

	error = 0;
	inp = sotoinpcb(so);
	if (inp == NULL) {
		return (ECONNRESET);
	}
	if (sopt->sopt_level != IPPROTO_TCP) {
#if INET6
		if (INP_CHECK_SOCKAF(so, AF_INET6))
			error = ip6_ctloutput(so, sopt);
		else
#endif /* INET6 */
		error = ip_ctloutput(so, sopt);
		return (error);
	}
	tp = intotcpcb(inp);
        if (tp == NULL) {
                return (ECONNRESET);
        }

	switch (sopt->sopt_dir) {
	case SOPT_SET:
		switch (sopt->sopt_name) {
		case TCP_NODELAY:
		case TCP_NOOPT:
		case TCP_NOPUSH:
			error = sooptcopyin(sopt, &optval, sizeof optval,
					    sizeof optval);
			if (error)
				break;

			switch (sopt->sopt_name) {
			case TCP_NODELAY:
				opt = TF_NODELAY;
				break;
			case TCP_NOOPT:
				opt = TF_NOOPT;
				break;
			case TCP_NOPUSH:
				opt = TF_NOPUSH;
				break;
			default:
				opt = 0; /* dead code to fool gcc */
				break;
			}

			if (optval)
				tp->t_flags |= opt;
			else
				tp->t_flags &= ~opt;
			break;

		case TCP_MAXSEG:
			error = sooptcopyin(sopt, &optval, sizeof optval,
					    sizeof optval);
			if (error)
				break;

			if (optval > 0 && optval <= tp->t_maxseg &&
			    optval + 40 >= tcp_minmss)
				tp->t_maxseg = optval;
			else
				error = EINVAL;
			break;

                case TCP_KEEPALIVE:
                        error = sooptcopyin(sopt, &optval, sizeof optval,
                                            sizeof optval);
                        if (error)
                                break;
                        if (optval < 0)
                                error = EINVAL;
			else
				tp->t_keepidle = optval * PR_SLOWHZ;
                        break;
		
		default:
			error = ENOPROTOOPT;
			break;
		}
		break;

	case SOPT_GET:
		switch (sopt->sopt_name) {
		case TCP_NODELAY:
			optval = tp->t_flags & TF_NODELAY;
			break;
		case TCP_MAXSEG:
			optval = tp->t_maxseg;
			break;
		case TCP_KEEPALIVE:
			optval = tp->t_keepidle / PR_SLOWHZ;
			break;
		case TCP_NOOPT:
			optval = tp->t_flags & TF_NOOPT;
			break;
		case TCP_NOPUSH:
			optval = tp->t_flags & TF_NOPUSH;
			break;
		default:
			error = ENOPROTOOPT;
			break;
		}
		if (error == 0)
			error = sooptcopyout(sopt, &optval, sizeof optval);
		break;
	}
	return (error);
}

/*
 * tcp_sendspace and tcp_recvspace are the default send and receive window
 * sizes, respectively.  These are obsolescent (this information should
 * be set by the route).
 */
u_long	tcp_sendspace = 1024*16;
SYSCTL_INT(_net_inet_tcp, TCPCTL_SENDSPACE, sendspace, CTLFLAG_RW, 
    &tcp_sendspace , 0, "Maximum outgoing TCP datagram size");
u_long	tcp_recvspace = 1024*16;
SYSCTL_INT(_net_inet_tcp, TCPCTL_RECVSPACE, recvspace, CTLFLAG_RW, 
    &tcp_recvspace , 0, "Maximum incoming TCP datagram size");

__private_extern__ int	tcp_sockthreshold = 256;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, sockthreshold, CTLFLAG_RW, 
    &tcp_sockthreshold , 0, "TCP Socket size increased if less than threshold");

#define TCP_INCREASED_SPACE	65535	/* Automatically increase tcp send/rcv space to this value */
/*
 * Attach TCP protocol to socket, allocating
 * internet protocol control block, tcp control block,
 * bufer space, and entering LISTEN state if to accept connections.
 */
static int
tcp_attach(so, p)
	struct socket *so;
	struct proc *p;
{
	register struct tcpcb *tp;
	struct inpcb *inp;
	int error;
#if INET6
	int isipv6 = INP_CHECK_SOCKAF(so, AF_INET6) != NULL;
#endif

	error = in_pcballoc(so, &tcbinfo, p);
	if (error)
		return (error);

	inp = sotoinpcb(so);

	if (so->so_snd.sb_hiwat == 0 || so->so_rcv.sb_hiwat == 0) {
		/*
		 * The goal is to let clients have large send/rcv default windows (TCP_INCREASED_SPACE)
		 * while not hogging mbuf space for servers. This is done by watching a threshold
		 * of tcpcbs in use and bumping the default send and rcvspace only if under that threshold.
		 * The theory being that busy servers have a lot more active tcpcbs and don't want the potential
		 * memory penalty of having much larger sockbuffs. The sysctl allows to fine tune that threshold value.		 */

		if (inp->inp_pcbinfo->ipi_count < tcp_sockthreshold)
			error = soreserve(so, MAX(TCP_INCREASED_SPACE, tcp_sendspace), MAX(TCP_INCREASED_SPACE,tcp_recvspace));
		else	
			error = soreserve(so, tcp_sendspace, tcp_recvspace);
		if (error)
			return (error);
	}

#if INET6
	if (isipv6) {
		inp->inp_vflag |= INP_IPV6;
		inp->in6p_hops = -1;	/* use kernel default */
	}
	else
#endif /* INET6 */
	inp->inp_vflag |= INP_IPV4;
	tp = tcp_newtcpcb(inp);
	if (tp == 0) {
		int nofd = so->so_state & SS_NOFDREF;	/* XXX */

		so->so_state &= ~SS_NOFDREF;	/* don't free the socket yet */
#if INET6
		if (isipv6)
			in6_pcbdetach(inp);
		else
#endif /* INET6 */
		in_pcbdetach(inp);
		so->so_state |= nofd;
		return (ENOBUFS);
	}
	tp->t_state = TCPS_CLOSED;
	return (0);
}

/*
 * Initiate (or continue) disconnect.
 * If embryonic state, just send reset (once).
 * If in ``let data drain'' option and linger null, just drop.
 * Otherwise (hard), mark socket disconnecting and drop
 * current input data; switch states based on user close, and
 * send segment to peer (with FIN).
 */
static struct tcpcb *
tcp_disconnect(tp)
	register struct tcpcb *tp;
{
	struct socket *so = tp->t_inpcb->inp_socket;

	if (tp->t_state < TCPS_ESTABLISHED)
		tp = tcp_close(tp);
	else if ((so->so_options & SO_LINGER) && so->so_linger == 0)
		tp = tcp_drop(tp, 0);
	else {
		soisdisconnecting(so);
		sbflush(&so->so_rcv);
		tp = tcp_usrclosed(tp);
		if (tp)
			(void) tcp_output(tp);
	}
	return (tp);
}

/*
 * User issued close, and wish to trail through shutdown states:
 * if never received SYN, just forget it.  If got a SYN from peer,
 * but haven't sent FIN, then go to FIN_WAIT_1 state to send peer a FIN.
 * If already got a FIN from peer, then almost done; go to LAST_ACK
 * state.  In all other cases, have already sent FIN to peer (e.g.
 * after PRU_SHUTDOWN), and just have to play tedious game waiting
 * for peer to send FIN or not respond to keep-alives, etc.
 * We can let the user exit from the close as soon as the FIN is acked.
 */
static struct tcpcb *
tcp_usrclosed(tp)
	register struct tcpcb *tp;
{

	switch (tp->t_state) {

	case TCPS_CLOSED:
	case TCPS_LISTEN:
		tp->t_state = TCPS_CLOSED;
		tp = tcp_close(tp);
		break;

	case TCPS_SYN_SENT:
	case TCPS_SYN_RECEIVED:
		tp->t_flags |= TF_NEEDFIN;
		break;

	case TCPS_ESTABLISHED:
		tp->t_state = TCPS_FIN_WAIT_1;
		break;

	case TCPS_CLOSE_WAIT:
		tp->t_state = TCPS_LAST_ACK;
		break;
	}
	if (tp && tp->t_state >= TCPS_FIN_WAIT_2) {
		soisdisconnected(tp->t_inpcb->inp_socket);
		/* To prevent the connection hanging in FIN_WAIT_2 forever. */
		if (tp->t_state == TCPS_FIN_WAIT_2)
			tp->t_timer[TCPT_2MSL] = tcp_maxidle;
	}
	return (tp);
}

