/*
 * Copyright (c) 2000-2019 Apple Inc. All rights reserved.
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
#if !CONFIG_EMBEDDED
#include <sys/kasl.h>
#endif
#include <sys/priv.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/syslog.h>

#include <net/if.h>
#include <net/route.h>
#include <net/ntstat.h>
#include <net/content_filter.h>
#include <net/multi_layer_pkt_log.h>

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
#include <netinet/tcp_cc.h>
#include <netinet/tcp_log.h>
#include <mach/sdt.h>
#if TCPDEBUG
#include <netinet/tcp_debug.h>
#endif
#if MPTCP
#include <netinet/mptcp_var.h>
#endif /* MPTCP */

#if IPSEC
#include <netinet6/ipsec.h>
#endif /*IPSEC*/

#if FLOW_DIVERT
#include <netinet/flow_divert.h>
#endif /* FLOW_DIVERT */

errno_t tcp_fill_info_for_info_tuple(struct info_tuple *, struct tcp_info *);

int tcp_sysctl_info(struct sysctl_oid *, void *, int, struct sysctl_req *);
static void tcp_connection_fill_info(struct tcpcb *tp,
    struct tcp_connection_info *tci);
static int tcp_get_mpkl_send_info(struct mbuf *, struct so_mpkl_send_info *);

/*
 * TCP protocol interface to socket abstraction.
 */
static int      tcp_attach(struct socket *, struct proc *);
static int      tcp_connect(struct tcpcb *, struct sockaddr *, struct proc *);
#if INET6
static int      tcp6_connect(struct tcpcb *, struct sockaddr *, struct proc *);
static int      tcp6_usr_connect(struct socket *, struct sockaddr *,
    struct proc *);
#endif /* INET6 */
static struct tcpcb *tcp_disconnect(struct tcpcb *);
static struct tcpcb *tcp_usrclosed(struct tcpcb *);
extern void tcp_sbrcv_trim(struct tcpcb *tp, struct sockbuf *sb);

#if TCPDEBUG
#define TCPDEBUG0       int ostate = 0
#define TCPDEBUG1()     ostate = tp ? tp->t_state : 0
#define TCPDEBUG2(req)  if (tp && (so->so_options & SO_DEBUG)) \
	                        tcp_trace(TA_USER, ostate, tp, 0, 0, req)
#else
#define TCPDEBUG0
#define TCPDEBUG1()
#define TCPDEBUG2(req)
#endif

SYSCTL_PROC(_net_inet_tcp, OID_AUTO, info,
    CTLFLAG_RW | CTLFLAG_LOCKED | CTLFLAG_ANYBODY | CTLFLAG_KERN,
    0, 0, tcp_sysctl_info, "S", "TCP info per tuple");

/*
 * TCP attaches to socket via pru_attach(), reserving space,
 * and an internet control block.
 *
 * Returns:	0			Success
 *		EISCONN
 *	tcp_attach:ENOBUFS
 *	tcp_attach:ENOMEM
 *	tcp_attach:???			[IPSEC specific]
 */
static int
tcp_usr_attach(struct socket *so, __unused int proto, struct proc *p)
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
	if (error) {
		goto out;
	}

	if ((so->so_options & SO_LINGER) && so->so_linger == 0) {
		so->so_linger = TCP_LINGERTIME * hz;
	}
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
		return EINVAL;  /* XXX */
	}
	socket_lock_assert_owned(so);
	tp = intotcpcb(inp);
	/* In case we got disconnected from the peer */
	if (tp == NULL) {
		goto out;
	}
	TCPDEBUG1();

	calculate_tcp_clock();

	tp = tcp_disconnect(tp);
out:
	TCPDEBUG2(PRU_DETACH);
	return error;
}

#if NECP
#define COMMON_START()  TCPDEBUG0;                                      \
do {                                                                    \
	if (inp == NULL || inp->inp_state == INPCB_STATE_DEAD)          \
	        return (EINVAL);                                        \
	if (necp_socket_should_use_flow_divert(inp))                    \
	        return (EPROTOTYPE);                                    \
	tp = intotcpcb(inp);                                            \
	TCPDEBUG1();                                                    \
	calculate_tcp_clock();                                          \
} while (0)
#else /* NECP */
#define COMMON_START()  TCPDEBUG0;                                      \
do {                                                                    \
	if (inp == NULL || inp->inp_state == INPCB_STATE_DEAD)          \
	        return (EINVAL);                                        \
	tp = intotcpcb(inp);                                            \
	TCPDEBUG1();                                                    \
	calculate_tcp_clock();                                          \
} while (0)
#endif /* !NECP */

#define COMMON_END(req) out: TCPDEBUG2(req); return error; goto out


/*
 * Give the socket an address.
 *
 * Returns:	0			Success
 *		EINVAL			Invalid argument [COMMON_START]
 *		EAFNOSUPPORT		Address family not supported
 *	in_pcbbind:EADDRNOTAVAIL	Address not available.
 *	in_pcbbind:EINVAL		Invalid argument
 *	in_pcbbind:EAFNOSUPPORT		Address family not supported [notdef]
 *	in_pcbbind:EACCES		Permission denied
 *	in_pcbbind:EADDRINUSE		Address in use
 *	in_pcbbind:EAGAIN		Resource unavailable, try again
 *	in_pcbbind:EPERM		Operation not permitted
 */
static int
tcp_usr_bind(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	int error = 0;
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp;
	struct sockaddr_in *sinp;

	COMMON_START();

	if (nam->sa_family != 0 && nam->sa_family != AF_INET) {
		error = EAFNOSUPPORT;
		goto out;
	}

	/*
	 * Must check for multicast addresses and disallow binding
	 * to them.
	 */
	sinp = (struct sockaddr_in *)(void *)nam;
	if (sinp->sin_family == AF_INET &&
	    IN_MULTICAST(ntohl(sinp->sin_addr.s_addr))) {
		error = EAFNOSUPPORT;
		goto out;
	}
	error = in_pcbbind(inp, nam, p);
	if (error) {
		goto out;
	}

#if NECP
	/* Update NECP client with bind result if not in middle of connect */
	if ((inp->inp_flags2 & INP2_CONNECT_IN_PROGRESS) &&
	    !uuid_is_null(inp->necp_client_uuid)) {
		socket_unlock(so, 0);
		necp_client_assign_from_socket(so->last_pid, inp->necp_client_uuid, inp);
		socket_lock(so, 0);
	}
#endif /* NECP */

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

	if (nam->sa_family != 0 && nam->sa_family != AF_INET6) {
		error = EAFNOSUPPORT;
		goto out;
	}

	/*
	 * Must check for multicast addresses and disallow binding
	 * to them.
	 */
	sin6p = (struct sockaddr_in6 *)(void *)nam;
	if (sin6p->sin6_family == AF_INET6 &&
	    IN6_IS_ADDR_MULTICAST(&sin6p->sin6_addr)) {
		error = EAFNOSUPPORT;
		goto out;
	}
	inp->inp_vflag &= ~INP_IPV4;
	inp->inp_vflag |= INP_IPV6;
	if ((inp->inp_flags & IN6P_IPV6_V6ONLY) == 0) {
		if (IN6_IS_ADDR_UNSPECIFIED(&sin6p->sin6_addr)) {
			inp->inp_vflag |= INP_IPV4;
		} else if (IN6_IS_ADDR_V4MAPPED(&sin6p->sin6_addr)) {
			struct sockaddr_in sin;

			in6_sin6_2_sin(&sin, sin6p);
			inp->inp_vflag |= INP_IPV4;
			inp->inp_vflag &= ~INP_IPV6;
			error = in_pcbbind(inp, (struct sockaddr *)&sin, p);
			goto out;
		}
	}
	error = in6_pcbbind(inp, nam, p);
	if (error) {
		goto out;
	}
	COMMON_END(PRU_BIND);
}
#endif /* INET6 */

/*
 * Prepare to accept connections.
 *
 * Returns:	0			Success
 *		EINVAL [COMMON_START]
 *	in_pcbbind:EADDRNOTAVAIL	Address not available.
 *	in_pcbbind:EINVAL		Invalid argument
 *	in_pcbbind:EAFNOSUPPORT		Address family not supported [notdef]
 *	in_pcbbind:EACCES		Permission denied
 *	in_pcbbind:EADDRINUSE		Address in use
 *	in_pcbbind:EAGAIN		Resource unavailable, try again
 *	in_pcbbind:EPERM		Operation not permitted
 */
static int
tcp_usr_listen(struct socket *so, struct proc *p)
{
	int error = 0;
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp;

	COMMON_START();
	if (inp->inp_lport == 0) {
		error = in_pcbbind(inp, NULL, p);
	}
	if (error == 0) {
		tp->t_state = TCPS_LISTEN;
	}
	TCP_LOG_LISTEN(tp, error);
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
		if ((inp->inp_flags & IN6P_IPV6_V6ONLY) == 0) {
			inp->inp_vflag |= INP_IPV4;
		}
		error = in6_pcbbind(inp, NULL, p);
	}
	if (error == 0) {
		tp->t_state = TCPS_LISTEN;
	}
	TCP_LOG_LISTEN(tp, error);
	COMMON_END(PRU_LISTEN);
}
#endif /* INET6 */

static int
tcp_connect_complete(struct socket *so)
{
	struct tcpcb *tp = sototcpcb(so);
	struct inpcb *inp = sotoinpcb(so);
	int error = 0;

	/* TFO delays the tcp_output until later, when the app calls write() */
	if (so->so_flags1 & SOF1_PRECONNECT_DATA) {
		if (!necp_socket_is_allowed_to_send_recv(sotoinpcb(so), NULL, NULL, NULL, NULL)) {
			TCP_LOG_DROP_NECP(NULL, NULL, tp, true);
			return EHOSTUNREACH;
		}

		/* Initialize enough state so that we can actually send data */
		tcp_mss(tp, -1, IFSCOPE_NONE);
		tp->snd_wnd = tp->t_maxseg;
		tp->max_sndwnd = tp->snd_wnd;
	} else {
		error = tcp_output(tp);
	}

#if NECP
	/* Update NECP client with connected five-tuple */
	if (error == 0 && !uuid_is_null(inp->necp_client_uuid)) {
		socket_unlock(so, 0);
		necp_client_assign_from_socket(so->last_pid, inp->necp_client_uuid, inp);
		socket_lock(so, 0);
	}
#endif /* NECP */

	return error;
}

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

	TCPDEBUG0;
	if (inp == NULL) {
		return EINVAL;
	} else if (inp->inp_state == INPCB_STATE_DEAD) {
		if (so->so_error) {
			error = so->so_error;
			so->so_error = 0;
			return error;
		} else {
			return EINVAL;
		}
	}
#if NECP
#if CONTENT_FILTER
	error = cfil_sock_attach(so, NULL, nam, CFS_CONNECTION_DIR_OUT);
	if (error != 0) {
		return error;
	}
#endif /* CONTENT_FILTER */
#if FLOW_DIVERT
	if (necp_socket_should_use_flow_divert(inp)) {
		uint32_t fd_ctl_unit = necp_socket_get_flow_divert_control_unit(inp);
		if (fd_ctl_unit > 0) {
			error = flow_divert_pcb_init(so, fd_ctl_unit);
			if (error == 0) {
				error = flow_divert_connect_out(so, nam, p);
			}
		} else {
			error = ENETDOWN;
		}

		return error;
	}
#endif /* FLOW_DIVERT */
#endif /* NECP */
	tp = intotcpcb(inp);
	TCPDEBUG1();

	calculate_tcp_clock();

	if (nam->sa_family != 0 && nam->sa_family != AF_INET) {
		error = EAFNOSUPPORT;
		goto out;
	}
	/*
	 * Must disallow TCP ``connections'' to multicast addresses.
	 */
	sinp = (struct sockaddr_in *)(void *)nam;
	if (sinp->sin_family == AF_INET
	    && IN_MULTICAST(ntohl(sinp->sin_addr.s_addr))) {
		error = EAFNOSUPPORT;
		goto out;
	}

	if ((error = tcp_connect(tp, nam, p)) != 0) {
		TCP_LOG_CONNECT(tp, true, error);
		goto out;
	}

	error = tcp_connect_complete(so);

	TCP_LOG_CONNECT(tp, true, error);

	COMMON_END(PRU_CONNECT);
}

static int
tcp_usr_connectx_common(struct socket *so, int af,
    struct sockaddr *src, struct sockaddr *dst,
    struct proc *p, uint32_t ifscope, sae_associd_t aid, sae_connid_t *pcid,
    uint32_t flags, void *arg, uint32_t arglen, struct uio *auio,
    user_ssize_t *bytes_written)
{
#pragma unused(aid, flags, arg, arglen)
	struct inpcb *inp = sotoinpcb(so);
	int error = 0;
	user_ssize_t datalen = 0;

	if (inp == NULL) {
		return EINVAL;
	}

	VERIFY(dst != NULL);

	ASSERT(!(inp->inp_flags2 & INP2_CONNECT_IN_PROGRESS));
	inp->inp_flags2 |= INP2_CONNECT_IN_PROGRESS;

#if NECP
	inp_update_necp_policy(inp, src, dst, ifscope);
#endif /* NECP */

	if ((so->so_flags1 & SOF1_DATA_IDEMPOTENT) &&
	    (tcp_fastopen & TCP_FASTOPEN_CLIENT)) {
		sototcpcb(so)->t_flagsext |= TF_FASTOPEN;
	}

	/* bind socket to the specified interface, if requested */
	if (ifscope != IFSCOPE_NONE &&
	    (error = inp_bindif(inp, ifscope, NULL)) != 0) {
		goto done;
	}

	/* if source address and/or port is specified, bind to it */
	if (src != NULL) {
		error = sobindlock(so, src, 0); /* already locked */
		if (error != 0) {
			goto done;
		}
	}

	switch (af) {
	case AF_INET:
		error = tcp_usr_connect(so, dst, p);
		break;
#if INET6
	case AF_INET6:
		error = tcp6_usr_connect(so, dst, p);
		break;
#endif /* INET6 */
	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	if (error != 0) {
		goto done;
	}

	/* if there is data, copy it */
	if (auio != NULL) {
		socket_unlock(so, 0);

		VERIFY(bytes_written != NULL);

		datalen = uio_resid(auio);
		error = so->so_proto->pr_usrreqs->pru_sosend(so, NULL,
		    (uio_t)auio, NULL, NULL, 0);
		socket_lock(so, 0);

		if (error == 0 || error == EWOULDBLOCK) {
			*bytes_written = datalen - uio_resid(auio);
		}

		/*
		 * sosend returns EWOULDBLOCK if it's a non-blocking
		 * socket or a timeout occured (this allows to return
		 * the amount of queued data through sendit()).
		 *
		 * However, connectx() returns EINPROGRESS in case of a
		 * blocking socket. So we change the return value here.
		 */
		if (error == EWOULDBLOCK) {
			error = EINPROGRESS;
		}
	}

	if (error == 0 && pcid != NULL) {
		*pcid = 1; /* there is only one connection in regular TCP */
	}
done:
	if (error && error != EINPROGRESS) {
		so->so_flags1 &= ~SOF1_PRECONNECT_DATA;
	}

	inp->inp_flags2 &= ~INP2_CONNECT_IN_PROGRESS;
	return error;
}

static int
tcp_usr_connectx(struct socket *so, struct sockaddr *src,
    struct sockaddr *dst, struct proc *p, uint32_t ifscope,
    sae_associd_t aid, sae_connid_t *pcid, uint32_t flags, void *arg,
    uint32_t arglen, struct uio *uio, user_ssize_t *bytes_written)
{
	return tcp_usr_connectx_common(so, AF_INET, src, dst, p, ifscope, aid,
	           pcid, flags, arg, arglen, uio, bytes_written);
}

#if INET6
static int
tcp6_usr_connect(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	int error = 0;
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp;
	struct sockaddr_in6 *sin6p;

	TCPDEBUG0;
	if (inp == NULL) {
		return EINVAL;
	} else if (inp->inp_state == INPCB_STATE_DEAD) {
		if (so->so_error) {
			error = so->so_error;
			so->so_error = 0;
			return error;
		} else {
			return EINVAL;
		}
	}
#if NECP
#if CONTENT_FILTER
	error = cfil_sock_attach(so, NULL, nam, CFS_CONNECTION_DIR_OUT);
	if (error != 0) {
		return error;
	}
#endif /* CONTENT_FILTER */
#if FLOW_DIVERT
	if (necp_socket_should_use_flow_divert(inp)) {
		uint32_t fd_ctl_unit = necp_socket_get_flow_divert_control_unit(inp);
		if (fd_ctl_unit > 0) {
			error = flow_divert_pcb_init(so, fd_ctl_unit);
			if (error == 0) {
				error = flow_divert_connect_out(so, nam, p);
			}
		} else {
			error = ENETDOWN;
		}

		return error;
	}
#endif /* FLOW_DIVERT */
#endif /* NECP */

	tp = intotcpcb(inp);
	TCPDEBUG1();

	calculate_tcp_clock();

	if (nam->sa_family != 0 && nam->sa_family != AF_INET6) {
		error = EAFNOSUPPORT;
		goto out;
	}

	/*
	 * Must disallow TCP ``connections'' to multicast addresses.
	 */
	sin6p = (struct sockaddr_in6 *)(void *)nam;
	if (sin6p->sin6_family == AF_INET6
	    && IN6_IS_ADDR_MULTICAST(&sin6p->sin6_addr)) {
		error = EAFNOSUPPORT;
		goto out;
	}

	if (IN6_IS_ADDR_V4MAPPED(&sin6p->sin6_addr)) {
		struct sockaddr_in sin;

		if ((inp->inp_flags & IN6P_IPV6_V6ONLY) != 0) {
			return EINVAL;
		}

		in6_sin6_2_sin(&sin, sin6p);
		inp->inp_vflag |= INP_IPV4;
		inp->inp_vflag &= ~INP_IPV6;
		if ((error = tcp_connect(tp, (struct sockaddr *)&sin, p)) != 0) {
			TCP_LOG_CONNECT(tp, true, error);
			goto out;
		}

		error = tcp_connect_complete(so);
		goto out;
	}
	inp->inp_vflag &= ~INP_IPV4;
	inp->inp_vflag |= INP_IPV6;
	if ((error = tcp6_connect(tp, nam, p)) != 0) {
		TCP_LOG_CONNECT(tp, true, error);
		goto out;
	}

	error = tcp_connect_complete(so);

	TCP_LOG_CONNECT(tp, true, error);

	COMMON_END(PRU_CONNECT);
}

static int
tcp6_usr_connectx(struct socket *so, struct sockaddr*src,
    struct sockaddr *dst, struct proc *p, uint32_t ifscope,
    sae_associd_t aid, sae_connid_t *pcid, uint32_t flags, void *arg,
    uint32_t arglen, struct uio *uio, user_ssize_t *bytes_written)
{
	return tcp_usr_connectx_common(so, AF_INET6, src, dst, p, ifscope, aid,
	           pcid, flags, arg, arglen, uio, bytes_written);
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

	socket_lock_assert_owned(so);
	COMMON_START();
	/* In case we got disconnected from the peer */
	if (tp == NULL) {
		goto out;
	}
	tp = tcp_disconnect(tp);
	COMMON_END(PRU_DISCONNECT);
}

/*
 * User-protocol pru_disconnectx callback.
 */
static int
tcp_usr_disconnectx(struct socket *so, sae_associd_t aid, sae_connid_t cid)
{
#pragma unused(cid)
	if (aid != SAE_ASSOCID_ANY && aid != SAE_ASSOCID_ALL) {
		return EINVAL;
	}

	return tcp_usr_disconnect(so);
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

	in_getpeeraddr(so, nam);

	if (so->so_state & SS_ISDISCONNECTED) {
		error = ECONNABORTED;
		goto out;
	}
	if (inp == NULL || inp->inp_state == INPCB_STATE_DEAD) {
		return EINVAL;
	}
#if NECP
	else if (necp_socket_should_use_flow_divert(inp)) {
		return EPROTOTYPE;
	}

#endif /* NECP */

	tp = intotcpcb(inp);
	TCPDEBUG1();

	TCP_LOG_ACCEPT(tp, 0);

	calculate_tcp_clock();

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
	if (inp == NULL || inp->inp_state == INPCB_STATE_DEAD) {
		return EINVAL;
	}
#if NECP
	else if (necp_socket_should_use_flow_divert(inp)) {
		return EPROTOTYPE;
	}

#endif /* NECP */

	tp = intotcpcb(inp);
	TCPDEBUG1();

	TCP_LOG_ACCEPT(tp, 0);

	calculate_tcp_clock();

	in6_mapped_peeraddr(so, nam);
	COMMON_END(PRU_ACCEPT);
}
#endif /* INET6 */

/*
 * Mark the connection as being incapable of further output.
 *
 * Returns:	0			Success
 *		EINVAL [COMMON_START]
 *	tcp_output:EADDRNOTAVAIL
 *	tcp_output:ENOBUFS
 *	tcp_output:EMSGSIZE
 *	tcp_output:EHOSTUNREACH
 *	tcp_output:ENETUNREACH
 *	tcp_output:ENETDOWN
 *	tcp_output:ENOMEM
 *	tcp_output:EACCES
 *	tcp_output:EMSGSIZE
 *	tcp_output:ENOBUFS
 *	tcp_output:???			[ignorable: mostly IPSEC/firewall/DLIL]
 */
static int
tcp_usr_shutdown(struct socket *so)
{
	int error = 0;
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp;

	TCPDEBUG0;
	if (inp == NULL || inp->inp_state == INPCB_STATE_DEAD) {
		return EINVAL;
	}

	socantsendmore(so);

	/*
	 * In case we got disconnected from the peer, or if this is
	 * a socket that is to be flow-diverted (but not yet).
	 */
	tp = intotcpcb(inp);
	TCPDEBUG1();

	if (tp == NULL
#if NECP
	    || (necp_socket_should_use_flow_divert(inp))
#endif /* NECP */
	    ) {
		if (tp != NULL) {
			error = EPROTOTYPE;
		}
		goto out;
	}

	calculate_tcp_clock();

	tp = tcp_usrclosed(tp);
#if MPTCP
	/* A reset has been sent but socket exists, do not send FIN */
	if ((so->so_flags & SOF_MP_SUBFLOW) &&
	    (tp) && (tp->t_mpflags & TMPF_RESET)) {
		goto out;
	}
#endif
#if CONTENT_FILTER
	/* Don't send a FIN yet */
	if (tp && !(so->so_state & SS_ISDISCONNECTED) &&
	    cfil_sock_data_pending(&so->so_snd)) {
		goto out;
	}
#endif /* CONTENT_FILTER */
	if (tp) {
		error = tcp_output(tp);
	}
	COMMON_END(PRU_SHUTDOWN);
}

/*
 * After a receive, possibly send window update to peer.
 */
static int
tcp_usr_rcvd(struct socket *so, __unused int flags)
{
	int error = 0;
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp;

	COMMON_START();
	/* In case we got disconnected from the peer */
	if (tp == NULL) {
		goto out;
	}
	tcp_sbrcv_trim(tp, &so->so_rcv);

	/*
	 * This tcp_output is solely there to trigger window-updates.
	 * However, we really do not want these window-updates while we
	 * are still in SYN_SENT or SYN_RECEIVED.
	 */
	if (TCPS_HAVEESTABLISHED(tp->t_state)) {
		tcp_output(tp);
	}

#if CONTENT_FILTER
	cfil_sock_buf_update(&so->so_rcv);
#endif /* CONTENT_FILTER */

	COMMON_END(PRU_RCVD);
}

/*
 * Do a send by putting data in output queue and updating urgent
 * marker if URG set.  Possibly send more data.  Unlike the other
 * pru_*() routines, the mbuf chains are our responsibility.  We
 * must either enqueue them or free them.  The other pru_* routines
 * generally are caller-frees.
 *
 * Returns:	0			Success
 *		ECONNRESET
 *		EINVAL
 *		ENOBUFS
 *	tcp_connect:EADDRINUSE		Address in use
 *	tcp_connect:EADDRNOTAVAIL	Address not available.
 *	tcp_connect:EINVAL		Invalid argument
 *	tcp_connect:EAFNOSUPPORT	Address family not supported [notdef]
 *	tcp_connect:EACCES		Permission denied
 *	tcp_connect:EAGAIN		Resource unavailable, try again
 *	tcp_connect:EPERM		Operation not permitted
 *	tcp_output:EADDRNOTAVAIL
 *	tcp_output:ENOBUFS
 *	tcp_output:EMSGSIZE
 *	tcp_output:EHOSTUNREACH
 *	tcp_output:ENETUNREACH
 *	tcp_output:ENETDOWN
 *	tcp_output:ENOMEM
 *	tcp_output:EACCES
 *	tcp_output:EMSGSIZE
 *	tcp_output:ENOBUFS
 *	tcp_output:???			[ignorable: mostly IPSEC/firewall/DLIL]
 *	tcp6_connect:???		[IPV6 only]
 */
static int
tcp_usr_send(struct socket *so, int flags, struct mbuf *m,
    struct sockaddr *nam, struct mbuf *control, struct proc *p)
{
	int error = 0;
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp;
	uint32_t msgpri = MSG_PRI_DEFAULT;
	uint32_t mpkl_len = 0; /* length of mbuf chain */
	uint32_t mpkl_seq; /* sequence number where new data is added */
	struct so_mpkl_send_info mpkl_send_info = {};

#if INET6
	int isipv6;
#endif
	TCPDEBUG0;

	if (inp == NULL || inp->inp_state == INPCB_STATE_DEAD
#if NECP
	    || (necp_socket_should_use_flow_divert(inp))
#endif /* NECP */
	    ) {
		/*
		 * OOPS! we lost a race, the TCP session got reset after
		 * we checked SS_CANTSENDMORE, eg: while doing uiomove or a
		 * network interrupt in the non-splnet() section of sosend().
		 */
		if (m != NULL) {
			m_freem(m);
		}
		if (control != NULL) {
			m_freem(control);
			control = NULL;
		}

		if (inp == NULL) {
			error = ECONNRESET;     /* XXX EPIPE? */
		} else {
			error = EPROTOTYPE;
		}
		tp = NULL;
		TCPDEBUG1();
		goto out;
	}
#if INET6
	isipv6 = nam && nam->sa_family == AF_INET6;
#endif /* INET6 */
	tp = intotcpcb(inp);
	TCPDEBUG1();

	calculate_tcp_clock();

	if (net_mpklog_enabled) {
		mpkl_seq = tp->snd_una + so->so_snd.sb_cc;
		if (m) {
			mpkl_len = m_length(m);
		}
		if (so->so_flags1 & SOF1_MPKL_SEND_INFO) {
			uuid_copy(mpkl_send_info.mpkl_uuid, so->so_mpkl_send_uuid);
			mpkl_send_info.mpkl_proto = so->so_mpkl_send_proto;
		}
	}

	if (control != NULL) {
		if (so->so_flags & SOF_ENABLE_MSGS) {
			/* Get the msg priority from control mbufs */
			error = tcp_get_msg_priority(control, &msgpri);
			if (error) {
				m_freem(control);
				if (m != NULL) {
					m_freem(m);
				}
				control = NULL;
				m = NULL;
				goto out;
			}
		}
		if (control->m_len > 0 && net_mpklog_enabled) {
			error = tcp_get_mpkl_send_info(control, &mpkl_send_info);
			/*
			 * Intepretation of the returned code:
			 *  0: client wants us to use value passed in SCM_MPKL_SEND_INFO
			 *  1: SCM_MPKL_SEND_INFO was not present
			 *  other: failure
			 */
			if (error != 0 && error != ENOMSG) {
				m_freem(control);
				if (m != NULL) {
					m_freem(m);
				}
				control = NULL;
				m = NULL;
				goto out;
			}
		}
		/*
		 * Silently drop unsupported ancillary data messages
		 */
		m_freem(control);
		control = NULL;
	}

	if (so->so_flags & SOF_ENABLE_MSGS) {
		VERIFY(m->m_flags & M_PKTHDR);
		m->m_pkthdr.msg_pri = msgpri;
	}

	/* MPTCP sublow socket buffers must not be compressed */
	VERIFY(!(so->so_flags & SOF_MP_SUBFLOW) ||
	    (so->so_snd.sb_flags & SB_NOCOMPRESS));

	if (!(flags & PRUS_OOB) || (so->so_flags1 & SOF1_PRECONNECT_DATA)) {
		/* Call msg send if message delivery is enabled */
		if (so->so_flags & SOF_ENABLE_MSGS) {
			sbappendmsg_snd(&so->so_snd, m);
		} else {
			sbappendstream(&so->so_snd, m);
		}

		if (nam && tp->t_state < TCPS_SYN_SENT) {
			/*
			 * Do implied connect if not yet connected,
			 * initialize window to default value, and
			 * initialize maxseg/maxopd using peer's cached
			 * MSS.
			 */
#if INET6
			if (isipv6) {
				error = tcp6_connect(tp, nam, p);
			} else
#endif /* INET6 */
			error = tcp_connect(tp, nam, p);
			if (error) {
				TCP_LOG_CONNECT(tp, true, error);
				goto out;
			}
			tp->snd_wnd = TTCP_CLIENT_SND_WND;
			tp->max_sndwnd = tp->snd_wnd;
			tcp_mss(tp, -1, IFSCOPE_NONE);

			TCP_LOG_CONNECT(tp, true, error);

			/* The sequence number of the data is past the SYN */
			mpkl_seq = tp->iss + 1;
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
			if (flags & PRUS_MORETOCOME) {
				tp->t_flags |= TF_MORETOCOME;
			}
			error = tcp_output(tp);
			if (flags & PRUS_MORETOCOME) {
				tp->t_flags &= ~TF_MORETOCOME;
			}
		}
	} else {
		if (sbspace(&so->so_snd) == 0) {
			/* if no space is left in sockbuf,
			 * do not try to squeeze in OOB traffic */
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
		sbappendstream(&so->so_snd, m);
		if (nam && tp->t_state < TCPS_SYN_SENT) {
			/*
			 * Do implied connect if not yet connected,
			 * initialize window to default value, and
			 * initialize maxseg/maxopd using peer's cached
			 * MSS.
			 */
#if INET6
			if (isipv6) {
				error = tcp6_connect(tp, nam, p);
			} else
#endif /* INET6 */
			error = tcp_connect(tp, nam, p);
			if (error) {
				TCP_LOG_CONNECT(tp, true, error);
				goto out;
			}
			tp->snd_wnd = TTCP_CLIENT_SND_WND;
			tp->max_sndwnd = tp->snd_wnd;
			tcp_mss(tp, -1, IFSCOPE_NONE);

			TCP_LOG_CONNECT(tp, true, error);
		}
		tp->snd_up = tp->snd_una + so->so_snd.sb_cc;
		tp->t_flagsext |= TF_FORCE;
		error = tcp_output(tp);
		tp->t_flagsext &= ~TF_FORCE;
	}

	if (net_mpklog_enabled && (inp = tp->t_inpcb) != NULL &&
	    ((inp->inp_last_outifp != NULL &&
	    (inp->inp_last_outifp->if_xflags & IFXF_MPK_LOG)) ||
	    (inp->inp_boundifp != NULL &&
	    (inp->inp_boundifp->if_xflags & IFXF_MPK_LOG)))) {
		MPKL_TCP_SEND(tcp_mpkl_log_object,
		    mpkl_send_info.mpkl_proto, mpkl_send_info.mpkl_uuid,
		    ntohs(inp->inp_lport), ntohs(inp->inp_fport),
		    mpkl_seq, mpkl_len,
		    so->last_pid, so->so_log_seqn++);
	}

	/*
	 * We wait for the socket to successfully connect before returning.
	 * This allows us to signal a timeout to the application.
	 */
	if (so->so_state & SS_ISCONNECTING) {
		if (so->so_state & SS_NBIO) {
			error = EWOULDBLOCK;
		} else {
			error = sbwait(&so->so_snd);
		}
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
	if (tp == NULL) {
		goto out;
	}
	tp = tcp_drop(tp, ECONNABORTED);
	VERIFY(so->so_usecount > 0);
	so->so_usecount--;
	COMMON_END(PRU_ABORT);
}

/*
 * Receive out-of-band data.
 *
 * Returns:	0			Success
 *		EINVAL [COMMON_START]
 *		EINVAL
 *		EWOULDBLOCK
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
	so->so_state &= ~SS_RCVATMARK;
	if ((flags & MSG_PEEK) == 0) {
		tp->t_oobflags ^= (TCPOOB_HAVEDATA | TCPOOB_HADDATA);
	}
	COMMON_END(PRU_RCVOOB);
}

static int
tcp_usr_preconnect(struct socket *so)
{
	struct inpcb *inp = sotoinpcb(so);
	int error = 0;

#if NECP
	if (necp_socket_should_use_flow_divert(inp)) {
		/* May happen, if in tcp_usr_connect we did not had a chance
		 * to set the usrreqs (due to some error). So, let's get out
		 * of here.
		 */
		goto out;
	}
#endif /* NECP */

	error = tcp_output(sototcpcb(so));

	soclearfastopen(so);

	COMMON_END(PRU_PRECONNECT);
}

/* xxx - should be const */
struct pr_usrreqs tcp_usrreqs = {
	.pru_abort =            tcp_usr_abort,
	.pru_accept =           tcp_usr_accept,
	.pru_attach =           tcp_usr_attach,
	.pru_bind =             tcp_usr_bind,
	.pru_connect =          tcp_usr_connect,
	.pru_connectx =         tcp_usr_connectx,
	.pru_control =          in_control,
	.pru_detach =           tcp_usr_detach,
	.pru_disconnect =       tcp_usr_disconnect,
	.pru_disconnectx =      tcp_usr_disconnectx,
	.pru_listen =           tcp_usr_listen,
	.pru_peeraddr =         in_getpeeraddr,
	.pru_rcvd =             tcp_usr_rcvd,
	.pru_rcvoob =           tcp_usr_rcvoob,
	.pru_send =             tcp_usr_send,
	.pru_shutdown =         tcp_usr_shutdown,
	.pru_sockaddr =         in_getsockaddr,
	.pru_sosend =           sosend,
	.pru_soreceive =        soreceive,
	.pru_preconnect =       tcp_usr_preconnect,
};

#if INET6
struct pr_usrreqs tcp6_usrreqs = {
	.pru_abort =            tcp_usr_abort,
	.pru_accept =           tcp6_usr_accept,
	.pru_attach =           tcp_usr_attach,
	.pru_bind =             tcp6_usr_bind,
	.pru_connect =          tcp6_usr_connect,
	.pru_connectx =         tcp6_usr_connectx,
	.pru_control =          in6_control,
	.pru_detach =           tcp_usr_detach,
	.pru_disconnect =       tcp_usr_disconnect,
	.pru_disconnectx =      tcp_usr_disconnectx,
	.pru_listen =           tcp6_usr_listen,
	.pru_peeraddr =         in6_mapped_peeraddr,
	.pru_rcvd =             tcp_usr_rcvd,
	.pru_rcvoob =           tcp_usr_rcvoob,
	.pru_send =             tcp_usr_send,
	.pru_shutdown =         tcp_usr_shutdown,
	.pru_sockaddr =         in6_mapped_sockaddr,
	.pru_sosend =           sosend,
	.pru_soreceive =        soreceive,
	.pru_preconnect =       tcp_usr_preconnect,
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
 *
 * Returns:	0			Success
 *		EADDRINUSE
 *		EINVAL
 *	in_pcbbind:EADDRNOTAVAIL	Address not available.
 *	in_pcbbind:EINVAL		Invalid argument
 *	in_pcbbind:EAFNOSUPPORT		Address family not supported [notdef]
 *	in_pcbbind:EACCES		Permission denied
 *	in_pcbbind:EADDRINUSE		Address in use
 *	in_pcbbind:EAGAIN		Resource unavailable, try again
 *	in_pcbbind:EPERM		Operation not permitted
 *	in_pcbladdr:EINVAL		Invalid argument
 *	in_pcbladdr:EAFNOSUPPORT	Address family not supported
 *	in_pcbladdr:EADDRNOTAVAIL	Address not available
 */
static int
tcp_connect(struct tcpcb *tp, struct sockaddr *nam, struct proc *p)
{
	struct inpcb *inp = tp->t_inpcb, *oinp;
	struct socket *so = inp->inp_socket;
	struct tcpcb *otp;
	struct sockaddr_in *sin = (struct sockaddr_in *)(void *)nam;
	struct in_addr laddr;
	int error = 0;
	struct ifnet *outif = NULL;

	if (inp->inp_lport == 0) {
		error = in_pcbbind(inp, NULL, p);
		if (error) {
			goto done;
		}
	}

	/*
	 * Cannot simply call in_pcbconnect, because there might be an
	 * earlier incarnation of this same connection still in
	 * TIME_WAIT state, creating an ADDRINUSE error.
	 */
	error = in_pcbladdr(inp, nam, &laddr, IFSCOPE_NONE, &outif, 0);
	if (error) {
		goto done;
	}

	socket_unlock(inp->inp_socket, 0);
	oinp = in_pcblookup_hash(inp->inp_pcbinfo,
	    sin->sin_addr, sin->sin_port,
	    inp->inp_laddr.s_addr != INADDR_ANY ? inp->inp_laddr : laddr,
	    inp->inp_lport, 0, NULL);

	socket_lock(inp->inp_socket, 0);
	if (oinp) {
		if (oinp != inp) { /* 4143933: avoid deadlock if inp == oinp */
			socket_lock(oinp->inp_socket, 1);
		}
		if (in_pcb_checkstate(oinp, WNT_RELEASE, 1) == WNT_STOPUSING) {
			if (oinp != inp) {
				socket_unlock(oinp->inp_socket, 1);
			}
			goto skip_oinp;
		}

		if (oinp != inp && (otp = intotcpcb(oinp)) != NULL &&
		    otp->t_state == TCPS_TIME_WAIT &&
		    ((int)(tcp_now - otp->t_starttime)) < tcp_msl &&
		    (otp->t_flags & TF_RCVD_CC)) {
			otp = tcp_close(otp);
		} else {
			printf("tcp_connect: inp=0x%llx err=EADDRINUSE\n",
			    (uint64_t)VM_KERNEL_ADDRPERM(inp));
			if (oinp != inp) {
				socket_unlock(oinp->inp_socket, 1);
			}
			error = EADDRINUSE;
			goto done;
		}
		if (oinp != inp) {
			socket_unlock(oinp->inp_socket, 1);
		}
	}
skip_oinp:
	if ((inp->inp_laddr.s_addr == INADDR_ANY ? laddr.s_addr :
	    inp->inp_laddr.s_addr) == sin->sin_addr.s_addr &&
	    inp->inp_lport == sin->sin_port) {
		error = EINVAL;
		goto done;
	}
	if (!lck_rw_try_lock_exclusive(inp->inp_pcbinfo->ipi_lock)) {
		/*lock inversion issue, mostly with udp multicast packets */
		socket_unlock(inp->inp_socket, 0);
		lck_rw_lock_exclusive(inp->inp_pcbinfo->ipi_lock);
		socket_lock(inp->inp_socket, 0);
	}
	if (inp->inp_laddr.s_addr == INADDR_ANY) {
		inp->inp_laddr = laddr;
		/* no reference needed */
		inp->inp_last_outifp = outif;

		inp->inp_flags |= INP_INADDR_ANY;
	}
	inp->inp_faddr = sin->sin_addr;
	inp->inp_fport = sin->sin_port;
	in_pcbrehash(inp);
	lck_rw_done(inp->inp_pcbinfo->ipi_lock);

	if (inp->inp_flowhash == 0) {
		inp->inp_flowhash = inp_calc_flowhash(inp);
	}

	tcp_set_max_rwinscale(tp, so, outif);

	soisconnecting(so);
	tcpstat.tcps_connattempt++;
	tp->t_state = TCPS_SYN_SENT;
	tp->t_timer[TCPT_KEEP] = OFFSET_FROM_START(tp, TCP_CONN_KEEPINIT(tp));
	tp->iss = tcp_new_isn(tp);
	tcp_sendseqinit(tp);
	tp->t_connect_time = tcp_now;
	if (nstat_collect) {
		nstat_route_connect_attempt(inp->inp_route.ro_rt);
	}

done:
	if (outif != NULL) {
		ifnet_release(outif);
	}

	return error;
}

#if INET6
static int
tcp6_connect(struct tcpcb *tp, struct sockaddr *nam, struct proc *p)
{
	struct inpcb *inp = tp->t_inpcb, *oinp;
	struct socket *so = inp->inp_socket;
	struct tcpcb *otp;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)(void *)nam;
	struct in6_addr addr6;
	int error = 0;
	struct ifnet *outif = NULL;

	if (inp->inp_lport == 0) {
		error = in6_pcbbind(inp, NULL, p);
		if (error) {
			goto done;
		}
	}

	/*
	 * Cannot simply call in_pcbconnect, because there might be an
	 * earlier incarnation of this same connection still in
	 * TIME_WAIT state, creating an ADDRINUSE error.
	 *
	 * in6_pcbladdr() might return an ifp with its reference held
	 * even in the error case, so make sure that it's released
	 * whenever it's non-NULL.
	 */
	error = in6_pcbladdr(inp, nam, &addr6, &outif);
	if (error) {
		goto done;
	}
	socket_unlock(inp->inp_socket, 0);
	oinp = in6_pcblookup_hash(inp->inp_pcbinfo,
	    &sin6->sin6_addr, sin6->sin6_port,
	    IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr)
	    ? &addr6
	    : &inp->in6p_laddr,
	    inp->inp_lport, 0, NULL);
	socket_lock(inp->inp_socket, 0);
	if (oinp) {
		if (oinp != inp && (otp = intotcpcb(oinp)) != NULL &&
		    otp->t_state == TCPS_TIME_WAIT &&
		    ((int)(tcp_now - otp->t_starttime)) < tcp_msl &&
		    (otp->t_flags & TF_RCVD_CC)) {
			otp = tcp_close(otp);
		} else {
			error = EADDRINUSE;
			goto done;
		}
	}
	if (!lck_rw_try_lock_exclusive(inp->inp_pcbinfo->ipi_lock)) {
		/*lock inversion issue, mostly with udp multicast packets */
		socket_unlock(inp->inp_socket, 0);
		lck_rw_lock_exclusive(inp->inp_pcbinfo->ipi_lock);
		socket_lock(inp->inp_socket, 0);
	}
	if (IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr)) {
		inp->in6p_laddr = addr6;
		inp->in6p_last_outifp = outif;  /* no reference needed */
		inp->in6p_flags |= INP_IN6ADDR_ANY;
	}
	inp->in6p_faddr = sin6->sin6_addr;
	inp->inp_fport = sin6->sin6_port;
	if ((sin6->sin6_flowinfo & IPV6_FLOWINFO_MASK) != 0) {
		inp->inp_flow = sin6->sin6_flowinfo;
	}
	in_pcbrehash(inp);
	lck_rw_done(inp->inp_pcbinfo->ipi_lock);

	if (inp->inp_flowhash == 0) {
		inp->inp_flowhash = inp_calc_flowhash(inp);
	}
	/* update flowinfo - RFC 6437 */
	if (inp->inp_flow == 0 && inp->in6p_flags & IN6P_AUTOFLOWLABEL) {
		inp->inp_flow &= ~IPV6_FLOWLABEL_MASK;
		inp->inp_flow |=
		    (htonl(inp->inp_flowhash) & IPV6_FLOWLABEL_MASK);
	}

	tcp_set_max_rwinscale(tp, so, outif);

	soisconnecting(so);
	tcpstat.tcps_connattempt++;
	tp->t_state = TCPS_SYN_SENT;
	tp->t_timer[TCPT_KEEP] = OFFSET_FROM_START(tp,
	    TCP_CONN_KEEPINIT(tp));
	tp->iss = tcp_new_isn(tp);
	tcp_sendseqinit(tp);
	tp->t_connect_time = tcp_now;
	if (nstat_collect) {
		nstat_route_connect_attempt(inp->inp_route.ro_rt);
	}

done:
	if (outif != NULL) {
		ifnet_release(outif);
	}

	return error;
}
#endif /* INET6 */

/*
 * Export TCP internal state information via a struct tcp_info
 */
void
tcp_fill_info(struct tcpcb *tp, struct tcp_info *ti)
{
	struct inpcb *inp = tp->t_inpcb;

	bzero(ti, sizeof(*ti));

	ti->tcpi_state = tp->t_state;
	ti->tcpi_flowhash = inp->inp_flowhash;

	if (tp->t_state > TCPS_LISTEN) {
		if (TSTMP_SUPPORTED(tp)) {
			ti->tcpi_options |= TCPI_OPT_TIMESTAMPS;
		}
		if (SACK_ENABLED(tp)) {
			ti->tcpi_options |= TCPI_OPT_SACK;
		}
		if (TCP_WINDOW_SCALE_ENABLED(tp)) {
			ti->tcpi_options |= TCPI_OPT_WSCALE;
			ti->tcpi_snd_wscale = tp->snd_scale;
			ti->tcpi_rcv_wscale = tp->rcv_scale;
		}
		if (TCP_ECN_ENABLED(tp)) {
			ti->tcpi_options |= TCPI_OPT_ECN;
		}

		/* Are we in retranmission episode */
		if (IN_FASTRECOVERY(tp) || tp->t_rxtshift > 0) {
			ti->tcpi_flags |= TCPI_FLAG_LOSSRECOVERY;
		}

		if (tp->t_flags & TF_STREAMING_ON) {
			ti->tcpi_flags |= TCPI_FLAG_STREAMING_ON;
		}

		ti->tcpi_rto = tp->t_timer[TCPT_REXMT] ? tp->t_rxtcur : 0;
		ti->tcpi_snd_mss = tp->t_maxseg;
		ti->tcpi_rcv_mss = tp->t_maxseg;

		ti->tcpi_rttcur = tp->t_rttcur;
		ti->tcpi_srtt = tp->t_srtt >> TCP_RTT_SHIFT;
		ti->tcpi_rttvar = tp->t_rttvar >> TCP_RTTVAR_SHIFT;
		ti->tcpi_rttbest = tp->t_rttbest >> TCP_RTT_SHIFT;

		ti->tcpi_snd_ssthresh = tp->snd_ssthresh;
		ti->tcpi_snd_cwnd = tp->snd_cwnd;
		ti->tcpi_snd_sbbytes = inp->inp_socket->so_snd.sb_cc;

		ti->tcpi_rcv_space = tp->rcv_wnd;

		ti->tcpi_snd_wnd = tp->snd_wnd;
		ti->tcpi_snd_nxt = tp->snd_nxt;
		ti->tcpi_rcv_nxt = tp->rcv_nxt;

		/* convert bytes/msec to bits/sec */
		if ((tp->t_flagsext & TF_MEASURESNDBW) != 0 &&
		    tp->t_bwmeas != NULL) {
			ti->tcpi_snd_bw = (tp->t_bwmeas->bw_sndbw * 8000);
		}

		ti->tcpi_last_outif = (tp->t_inpcb->inp_last_outifp == NULL) ? 0 :
		    tp->t_inpcb->inp_last_outifp->if_index;

		//atomic_get_64(ti->tcpi_txbytes, &inp->inp_stat->txbytes);
		ti->tcpi_txpackets = inp->inp_stat->txpackets;
		ti->tcpi_txbytes = inp->inp_stat->txbytes;
		ti->tcpi_txretransmitbytes = tp->t_stat.txretransmitbytes;
		ti->tcpi_txretransmitpackets = tp->t_stat.rxmitpkts;
		ti->tcpi_txunacked = tp->snd_max - tp->snd_una;

		//atomic_get_64(ti->tcpi_rxbytes, &inp->inp_stat->rxbytes);
		ti->tcpi_rxpackets = inp->inp_stat->rxpackets;
		ti->tcpi_rxbytes = inp->inp_stat->rxbytes;
		ti->tcpi_rxduplicatebytes = tp->t_stat.rxduplicatebytes;
		ti->tcpi_rxoutoforderbytes = tp->t_stat.rxoutoforderbytes;

		if (tp->t_state > TCPS_LISTEN) {
			ti->tcpi_synrexmits = tp->t_stat.rxmitsyns;
		}
		ti->tcpi_cell_rxpackets = inp->inp_cstat->rxpackets;
		ti->tcpi_cell_rxbytes = inp->inp_cstat->rxbytes;
		ti->tcpi_cell_txpackets = inp->inp_cstat->txpackets;
		ti->tcpi_cell_txbytes = inp->inp_cstat->txbytes;

		ti->tcpi_wifi_rxpackets = inp->inp_wstat->rxpackets;
		ti->tcpi_wifi_rxbytes = inp->inp_wstat->rxbytes;
		ti->tcpi_wifi_txpackets = inp->inp_wstat->txpackets;
		ti->tcpi_wifi_txbytes = inp->inp_wstat->txbytes;

		ti->tcpi_wired_rxpackets = inp->inp_Wstat->rxpackets;
		ti->tcpi_wired_rxbytes = inp->inp_Wstat->rxbytes;
		ti->tcpi_wired_txpackets = inp->inp_Wstat->txpackets;
		ti->tcpi_wired_txbytes = inp->inp_Wstat->txbytes;
		tcp_get_connectivity_status(tp, &ti->tcpi_connstatus);

		ti->tcpi_tfo_syn_data_rcv = !!(tp->t_tfo_stats & TFO_S_SYNDATA_RCV);
		ti->tcpi_tfo_cookie_req_rcv = !!(tp->t_tfo_stats & TFO_S_COOKIEREQ_RECV);
		ti->tcpi_tfo_cookie_sent = !!(tp->t_tfo_stats & TFO_S_COOKIE_SENT);
		ti->tcpi_tfo_cookie_invalid = !!(tp->t_tfo_stats & TFO_S_COOKIE_INVALID);

		ti->tcpi_tfo_cookie_req = !!(tp->t_tfo_stats & TFO_S_COOKIE_REQ);
		ti->tcpi_tfo_cookie_rcv = !!(tp->t_tfo_stats & TFO_S_COOKIE_RCV);
		ti->tcpi_tfo_syn_data_sent = !!(tp->t_tfo_stats & TFO_S_SYN_DATA_SENT);
		ti->tcpi_tfo_syn_data_acked = !!(tp->t_tfo_stats & TFO_S_SYN_DATA_ACKED);
		ti->tcpi_tfo_syn_loss = !!(tp->t_tfo_stats & TFO_S_SYN_LOSS);
		ti->tcpi_tfo_cookie_wrong = !!(tp->t_tfo_stats & TFO_S_COOKIE_WRONG);
		ti->tcpi_tfo_no_cookie_rcv = !!(tp->t_tfo_stats & TFO_S_NO_COOKIE_RCV);
		ti->tcpi_tfo_heuristics_disable = !!(tp->t_tfo_stats & TFO_S_HEURISTICS_DISABLE);
		ti->tcpi_tfo_send_blackhole = !!(tp->t_tfo_stats & TFO_S_SEND_BLACKHOLE);
		ti->tcpi_tfo_recv_blackhole = !!(tp->t_tfo_stats & TFO_S_RECV_BLACKHOLE);
		ti->tcpi_tfo_onebyte_proxy = !!(tp->t_tfo_stats & TFO_S_ONE_BYTE_PROXY);

		ti->tcpi_ecn_client_setup = !!(tp->ecn_flags & TE_SETUPSENT);
		ti->tcpi_ecn_server_setup = !!(tp->ecn_flags & TE_SETUPRECEIVED);
		ti->tcpi_ecn_success = (tp->ecn_flags & TE_ECN_ON) == TE_ECN_ON ? 1 : 0;
		ti->tcpi_ecn_lost_syn = !!(tp->ecn_flags & TE_LOST_SYN);
		ti->tcpi_ecn_lost_synack = !!(tp->ecn_flags & TE_LOST_SYNACK);

		ti->tcpi_local_peer = !!(tp->t_flags & TF_LOCAL);

		if (tp->t_inpcb->inp_last_outifp != NULL) {
			if (IFNET_IS_CELLULAR(tp->t_inpcb->inp_last_outifp)) {
				ti->tcpi_if_cell = 1;
			}
			if (IFNET_IS_WIFI(tp->t_inpcb->inp_last_outifp)) {
				ti->tcpi_if_wifi = 1;
			}
			if (IFNET_IS_WIRED(tp->t_inpcb->inp_last_outifp)) {
				ti->tcpi_if_wired = 1;
			}
			if (IFNET_IS_WIFI_INFRA(tp->t_inpcb->inp_last_outifp)) {
				ti->tcpi_if_wifi_infra = 1;
			}
			if (tp->t_inpcb->inp_last_outifp->if_eflags & IFEF_AWDL) {
				ti->tcpi_if_wifi_awdl = 1;
			}
		}
		if (tp->tcp_cc_index == TCP_CC_ALGO_BACKGROUND_INDEX) {
			ti->tcpi_snd_background = 1;
		}
		if (tcp_recv_bg == 1 ||
		    IS_TCP_RECV_BG(tp->t_inpcb->inp_socket)) {
			ti->tcpi_rcv_background = 1;
		}

		ti->tcpi_ecn_recv_ce = tp->t_ecn_recv_ce;
		ti->tcpi_ecn_recv_cwr = tp->t_ecn_recv_cwr;

		ti->tcpi_rcvoopack = tp->t_rcvoopack;
		ti->tcpi_pawsdrop = tp->t_pawsdrop;
		ti->tcpi_sack_recovery_episode = tp->t_sack_recovery_episode;
		ti->tcpi_reordered_pkts = tp->t_reordered_pkts;
		ti->tcpi_dsack_sent = tp->t_dsack_sent;
		ti->tcpi_dsack_recvd = tp->t_dsack_recvd;
	}
}

__private_extern__ errno_t
tcp_fill_info_for_info_tuple(struct info_tuple *itpl, struct tcp_info *ti)
{
	struct inpcbinfo *pcbinfo = NULL;
	struct inpcb *inp = NULL;
	struct socket *so;
	struct tcpcb *tp;

	if (itpl->itpl_proto == IPPROTO_TCP) {
		pcbinfo = &tcbinfo;
	} else {
		return EINVAL;
	}

	if (itpl->itpl_local_sa.sa_family == AF_INET &&
	    itpl->itpl_remote_sa.sa_family == AF_INET) {
		inp = in_pcblookup_hash(pcbinfo,
		    itpl->itpl_remote_sin.sin_addr,
		    itpl->itpl_remote_sin.sin_port,
		    itpl->itpl_local_sin.sin_addr,
		    itpl->itpl_local_sin.sin_port,
		    0, NULL);
	} else if (itpl->itpl_local_sa.sa_family == AF_INET6 &&
	    itpl->itpl_remote_sa.sa_family == AF_INET6) {
		struct in6_addr ina6_local;
		struct in6_addr ina6_remote;

		ina6_local = itpl->itpl_local_sin6.sin6_addr;
		if (IN6_IS_SCOPE_LINKLOCAL(&ina6_local) &&
		    itpl->itpl_local_sin6.sin6_scope_id) {
			ina6_local.s6_addr16[1] = htons(itpl->itpl_local_sin6.sin6_scope_id);
		}

		ina6_remote = itpl->itpl_remote_sin6.sin6_addr;
		if (IN6_IS_SCOPE_LINKLOCAL(&ina6_remote) &&
		    itpl->itpl_remote_sin6.sin6_scope_id) {
			ina6_remote.s6_addr16[1] = htons(itpl->itpl_remote_sin6.sin6_scope_id);
		}

		inp = in6_pcblookup_hash(pcbinfo,
		    &ina6_remote,
		    itpl->itpl_remote_sin6.sin6_port,
		    &ina6_local,
		    itpl->itpl_local_sin6.sin6_port,
		    0, NULL);
	} else {
		return EINVAL;
	}
	if (inp == NULL || (so = inp->inp_socket) == NULL) {
		return ENOENT;
	}

	socket_lock(so, 0);
	if (in_pcb_checkstate(inp, WNT_RELEASE, 1) == WNT_STOPUSING) {
		socket_unlock(so, 0);
		return ENOENT;
	}
	tp = intotcpcb(inp);

	tcp_fill_info(tp, ti);
	socket_unlock(so, 0);

	return 0;
}

static void
tcp_connection_fill_info(struct tcpcb *tp, struct tcp_connection_info *tci)
{
	struct inpcb *inp = tp->t_inpcb;

	bzero(tci, sizeof(*tci));
	tci->tcpi_state = tp->t_state;
	if (tp->t_state > TCPS_LISTEN) {
		if (TSTMP_SUPPORTED(tp)) {
			tci->tcpi_options |= TCPCI_OPT_TIMESTAMPS;
		}
		if (SACK_ENABLED(tp)) {
			tci->tcpi_options |= TCPCI_OPT_SACK;
		}
		if (TCP_WINDOW_SCALE_ENABLED(tp)) {
			tci->tcpi_options |= TCPCI_OPT_WSCALE;
			tci->tcpi_snd_wscale = tp->snd_scale;
			tci->tcpi_rcv_wscale = tp->rcv_scale;
		}
		if (TCP_ECN_ENABLED(tp)) {
			tci->tcpi_options |= TCPCI_OPT_ECN;
		}
		if (IN_FASTRECOVERY(tp) || tp->t_rxtshift > 0) {
			tci->tcpi_flags |= TCPCI_FLAG_LOSSRECOVERY;
		}
		if (tp->t_flagsext & TF_PKTS_REORDERED) {
			tci->tcpi_flags |= TCPCI_FLAG_REORDERING_DETECTED;
		}
		tci->tcpi_rto = (tp->t_timer[TCPT_REXMT] > 0) ?
		    tp->t_rxtcur : 0;
		tci->tcpi_maxseg = tp->t_maxseg;
		tci->tcpi_snd_ssthresh = tp->snd_ssthresh;
		tci->tcpi_snd_cwnd = tp->snd_cwnd;
		tci->tcpi_snd_wnd = tp->snd_wnd;
		tci->tcpi_snd_sbbytes = inp->inp_socket->so_snd.sb_cc;
		tci->tcpi_rcv_wnd = tp->rcv_wnd;
		tci->tcpi_rttcur = tp->t_rttcur;
		tci->tcpi_srtt = (tp->t_srtt >> TCP_RTT_SHIFT);
		tci->tcpi_rttvar = (tp->t_rttvar >> TCP_RTTVAR_SHIFT);
		tci->tcpi_txpackets = inp->inp_stat->txpackets;
		tci->tcpi_txbytes = inp->inp_stat->txbytes;
		tci->tcpi_txretransmitbytes = tp->t_stat.txretransmitbytes;
		tci->tcpi_txretransmitpackets = tp->t_stat.rxmitpkts;
		tci->tcpi_rxpackets = inp->inp_stat->rxpackets;
		tci->tcpi_rxbytes = inp->inp_stat->rxbytes;
		tci->tcpi_rxoutoforderbytes = tp->t_stat.rxoutoforderbytes;

		tci->tcpi_tfo_syn_data_rcv = !!(tp->t_tfo_stats & TFO_S_SYNDATA_RCV);
		tci->tcpi_tfo_cookie_req_rcv = !!(tp->t_tfo_stats & TFO_S_COOKIEREQ_RECV);
		tci->tcpi_tfo_cookie_sent = !!(tp->t_tfo_stats & TFO_S_COOKIE_SENT);
		tci->tcpi_tfo_cookie_invalid = !!(tp->t_tfo_stats & TFO_S_COOKIE_INVALID);
		tci->tcpi_tfo_cookie_req = !!(tp->t_tfo_stats & TFO_S_COOKIE_REQ);
		tci->tcpi_tfo_cookie_rcv = !!(tp->t_tfo_stats & TFO_S_COOKIE_RCV);
		tci->tcpi_tfo_syn_data_sent = !!(tp->t_tfo_stats & TFO_S_SYN_DATA_SENT);
		tci->tcpi_tfo_syn_data_acked = !!(tp->t_tfo_stats & TFO_S_SYN_DATA_ACKED);
		tci->tcpi_tfo_syn_loss = !!(tp->t_tfo_stats & TFO_S_SYN_LOSS);
		tci->tcpi_tfo_cookie_wrong = !!(tp->t_tfo_stats & TFO_S_COOKIE_WRONG);
		tci->tcpi_tfo_no_cookie_rcv = !!(tp->t_tfo_stats & TFO_S_NO_COOKIE_RCV);
		tci->tcpi_tfo_heuristics_disable = !!(tp->t_tfo_stats & TFO_S_HEURISTICS_DISABLE);
		tci->tcpi_tfo_send_blackhole = !!(tp->t_tfo_stats & TFO_S_SEND_BLACKHOLE);
		tci->tcpi_tfo_recv_blackhole = !!(tp->t_tfo_stats & TFO_S_RECV_BLACKHOLE);
		tci->tcpi_tfo_onebyte_proxy = !!(tp->t_tfo_stats & TFO_S_ONE_BYTE_PROXY);
	}
}


__private_extern__ int
tcp_sysctl_info(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int error;
	struct tcp_info ti = {};
	struct info_tuple itpl;

	if (req->newptr == USER_ADDR_NULL) {
		return EINVAL;
	}
	if (req->newlen < sizeof(struct info_tuple)) {
		return EINVAL;
	}
	error = SYSCTL_IN(req, &itpl, sizeof(struct info_tuple));
	if (error != 0) {
		return error;
	}
	error = tcp_fill_info_for_info_tuple(&itpl, &ti);
	if (error != 0) {
		return error;
	}
	error = SYSCTL_OUT(req, &ti, sizeof(struct tcp_info));
	if (error != 0) {
		return error;
	}

	return 0;
}

static int
tcp_lookup_peer_pid_locked(struct socket *so, pid_t *out_pid)
{
	int error = EHOSTUNREACH;
	*out_pid = -1;
	if ((so->so_state & SS_ISCONNECTED) == 0) {
		return ENOTCONN;
	}

	struct inpcb    *inp = (struct inpcb*)so->so_pcb;
	uint16_t                lport = inp->inp_lport;
	uint16_t                fport = inp->inp_fport;
	struct inpcb    *finp = NULL;
	struct  in6_addr laddr6, faddr6;
	struct in_addr laddr4, faddr4;

	if (inp->inp_vflag & INP_IPV6) {
		laddr6 = inp->in6p_laddr;
		faddr6 = inp->in6p_faddr;
	} else if (inp->inp_vflag & INP_IPV4) {
		laddr4 = inp->inp_laddr;
		faddr4 = inp->inp_faddr;
	}

	socket_unlock(so, 0);
	if (inp->inp_vflag & INP_IPV6) {
		finp = in6_pcblookup_hash(&tcbinfo, &laddr6, lport, &faddr6, fport, 0, NULL);
	} else if (inp->inp_vflag & INP_IPV4) {
		finp = in_pcblookup_hash(&tcbinfo, laddr4, lport, faddr4, fport, 0, NULL);
	}

	if (finp) {
		*out_pid = finp->inp_socket->last_pid;
		error = 0;
		in_pcb_checkstate(finp, WNT_RELEASE, 0);
	}
	socket_lock(so, 0);

	return error;
}

void
tcp_getconninfo(struct socket *so, struct conninfo_tcp *tcp_ci)
{
	(void) tcp_lookup_peer_pid_locked(so, &tcp_ci->tcpci_peer_pid);
	tcp_fill_info(sototcpcb(so), &tcp_ci->tcpci_tcp_info);
}

void
tcp_clear_keep_alive_offload(struct socket *so)
{
	struct inpcb *inp;
	struct ifnet *ifp;

	inp = sotoinpcb(so);
	if (inp == NULL) {
		return;
	}

	if ((inp->inp_flags2 & INP2_KEEPALIVE_OFFLOAD) == 0) {
		return;
	}

	ifp = inp->inp_boundifp != NULL ? inp->inp_boundifp :
	    inp->inp_last_outifp;
	if (ifp == NULL) {
		panic("%s: so %p inp %p ifp NULL",
		    __func__, so, inp);
	}

	ifnet_lock_exclusive(ifp);

	if (ifp->if_tcp_kao_cnt == 0) {
		panic("%s: so %p inp %p ifp %p if_tcp_kao_cnt == 0",
		    __func__, so, inp, ifp);
	}
	ifp->if_tcp_kao_cnt--;
	inp->inp_flags2 &= ~INP2_KEEPALIVE_OFFLOAD;

	ifnet_lock_done(ifp);
}

static int
tcp_set_keep_alive_offload(struct socket *so, struct proc *proc)
{
	int error = 0;
	struct inpcb *inp;
	struct ifnet *ifp;

	inp = sotoinpcb(so);
	if (inp == NULL) {
		return ECONNRESET;
	}
	if ((inp->inp_flags2 & INP2_KEEPALIVE_OFFLOAD) != 0) {
		return 0;
	}

	ifp = inp->inp_boundifp != NULL ? inp->inp_boundifp :
	    inp->inp_last_outifp;
	if (ifp == NULL) {
		error = ENXIO;
		os_log_info(OS_LOG_DEFAULT,
		    "%s: error %d for proc %s[%u] out ifp is not set\n",
		    __func__, error,
		    proc != NULL ? proc->p_comm : "kernel",
		    proc != NULL ? proc->p_pid : 0);
		return ENXIO;
	}

	error = if_get_tcp_kao_max(ifp);
	if (error != 0) {
		return error;
	}

	ifnet_lock_exclusive(ifp);
	if (ifp->if_tcp_kao_cnt < ifp->if_tcp_kao_max) {
		ifp->if_tcp_kao_cnt++;
		inp->inp_flags2 |= INP2_KEEPALIVE_OFFLOAD;
	} else {
		error = ETOOMANYREFS;
		os_log_info(OS_LOG_DEFAULT,
		    "%s: error %d for proc %s[%u] if_tcp_kao_max %u\n",
		    __func__, error,
		    proc != NULL ? proc->p_comm : "kernel",
		    proc != NULL ? proc->p_pid : 0,
		    ifp->if_tcp_kao_max);
	}
	ifnet_lock_done(ifp);

	return error;
}

/*
 * The new sockopt interface makes it possible for us to block in the
 * copyin/out step (if we take a page fault).  Taking a page fault at
 * splnet() is probably a Bad Thing.  (Since sockets and pcbs both now
 * use TSM, there probably isn't any need for this function to run at
 * splnet() any more.  This needs more examination.)
 */
int
tcp_ctloutput(struct socket *so, struct sockopt *sopt)
{
	int     error = 0, opt = 0, optval = 0;
	struct  inpcb *inp;
	struct  tcpcb *tp;

	inp = sotoinpcb(so);
	if (inp == NULL) {
		return ECONNRESET;
	}
	/* Allow <SOL_SOCKET,SO_FLUSH/SO_TRAFFIC_MGT_BACKGROUND> at this level */
	if (sopt->sopt_level != IPPROTO_TCP &&
	    !(sopt->sopt_level == SOL_SOCKET && (sopt->sopt_name == SO_FLUSH ||
	    sopt->sopt_name == SO_TRAFFIC_MGT_BACKGROUND))) {
#if INET6
		if (SOCK_CHECK_DOM(so, PF_INET6)) {
			error = ip6_ctloutput(so, sopt);
		} else
#endif /* INET6 */
		error = ip_ctloutput(so, sopt);
		return error;
	}
	tp = intotcpcb(inp);
	if (tp == NULL) {
		return ECONNRESET;
	}

	calculate_tcp_clock();

	switch (sopt->sopt_dir) {
	case SOPT_SET:
		switch (sopt->sopt_name) {
		case TCP_NODELAY:
		case TCP_NOOPT:
		case TCP_NOPUSH:
			error = sooptcopyin(sopt, &optval, sizeof optval,
			    sizeof optval);
			if (error) {
				break;
			}

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

			if (optval) {
				tp->t_flags |= opt;
			} else {
				tp->t_flags &= ~opt;
			}
			break;
		case TCP_RXT_FINDROP:
		case TCP_NOTIMEWAIT:
			error = sooptcopyin(sopt, &optval, sizeof optval,
			    sizeof optval);
			if (error) {
				break;
			}
			switch (sopt->sopt_name) {
			case TCP_RXT_FINDROP:
				opt = TF_RXTFINDROP;
				break;
			case TCP_NOTIMEWAIT:
				opt = TF_NOTIMEWAIT;
				break;
			default:
				opt = 0;
				break;
			}
			if (optval) {
				tp->t_flagsext |= opt;
			} else {
				tp->t_flagsext &= ~opt;
			}
			break;
		case TCP_MEASURE_SND_BW:
			error = sooptcopyin(sopt, &optval, sizeof optval,
			    sizeof optval);
			if (error) {
				break;
			}
			opt = TF_MEASURESNDBW;
			if (optval) {
				if (tp->t_bwmeas == NULL) {
					tp->t_bwmeas = tcp_bwmeas_alloc(tp);
					if (tp->t_bwmeas == NULL) {
						error = ENOMEM;
						break;
					}
				}
				tp->t_flagsext |= opt;
			} else {
				tp->t_flagsext &= ~opt;
				/* Reset snd bw measurement state */
				tp->t_flagsext &= ~(TF_BWMEAS_INPROGRESS);
				if (tp->t_bwmeas != NULL) {
					tcp_bwmeas_free(tp);
				}
			}
			break;
		case TCP_MEASURE_BW_BURST: {
			struct tcp_measure_bw_burst in;
			uint32_t minpkts, maxpkts;
			bzero(&in, sizeof(in));

			error = sooptcopyin(sopt, &in, sizeof(in),
			    sizeof(in));
			if (error) {
				break;
			}
			if ((tp->t_flagsext & TF_MEASURESNDBW) == 0 ||
			    tp->t_bwmeas == NULL) {
				error = EINVAL;
				break;
			}
			minpkts = (in.min_burst_size != 0) ? in.min_burst_size :
			    tp->t_bwmeas->bw_minsizepkts;
			maxpkts = (in.max_burst_size != 0) ? in.max_burst_size :
			    tp->t_bwmeas->bw_maxsizepkts;
			if (minpkts > maxpkts) {
				error = EINVAL;
				break;
			}
			tp->t_bwmeas->bw_minsizepkts = minpkts;
			tp->t_bwmeas->bw_maxsizepkts = maxpkts;
			tp->t_bwmeas->bw_minsize = (minpkts * tp->t_maxseg);
			tp->t_bwmeas->bw_maxsize = (maxpkts * tp->t_maxseg);
			break;
		}
		case TCP_MAXSEG:
			error = sooptcopyin(sopt, &optval, sizeof optval,
			    sizeof optval);
			if (error) {
				break;
			}

			if (optval > 0 && optval <= tp->t_maxseg &&
			    optval + 40 >= tcp_minmss) {
				tp->t_maxseg = optval;
			} else {
				error = EINVAL;
			}
			break;

		case TCP_KEEPALIVE:
			error = sooptcopyin(sopt, &optval, sizeof optval,
			    sizeof optval);
			if (error) {
				break;
			}
			if (optval < 0 || optval > UINT32_MAX / TCP_RETRANSHZ) {
				error = EINVAL;
			} else {
				tp->t_keepidle = optval * TCP_RETRANSHZ;
				/* reset the timer to new value */
				tp->t_timer[TCPT_KEEP] = OFFSET_FROM_START(tp,
				    TCP_CONN_KEEPIDLE(tp));
				tcp_check_timer_state(tp);
			}
			break;

		case TCP_CONNECTIONTIMEOUT:
			error = sooptcopyin(sopt, &optval, sizeof optval,
			    sizeof optval);
			if (error) {
				break;
			}
			if (optval < 0 || optval > UINT32_MAX / TCP_RETRANSHZ) {
				error = EINVAL;
			} else {
				tp->t_keepinit = optval * TCP_RETRANSHZ;
				if (tp->t_state == TCPS_SYN_RECEIVED ||
				    tp->t_state == TCPS_SYN_SENT) {
					tp->t_timer[TCPT_KEEP] = OFFSET_FROM_START(tp,
					    TCP_CONN_KEEPINIT(tp));
					tcp_check_timer_state(tp);
				}
			}
			break;

		case TCP_KEEPINTVL:
			error = sooptcopyin(sopt, &optval, sizeof(optval),
			    sizeof(optval));
			if (error) {
				break;
			}
			if (optval < 0 || optval > UINT32_MAX / TCP_RETRANSHZ) {
				error = EINVAL;
			} else {
				tp->t_keepintvl = optval * TCP_RETRANSHZ;
				if (tp->t_state == TCPS_FIN_WAIT_2 &&
				    TCP_CONN_MAXIDLE(tp) > 0) {
					tp->t_timer[TCPT_2MSL] = OFFSET_FROM_START(tp,
					    TCP_CONN_MAXIDLE(tp));
					tcp_check_timer_state(tp);
				}
			}
			break;

		case TCP_KEEPCNT:
			error = sooptcopyin(sopt, &optval, sizeof(optval),
			    sizeof(optval));
			if (error) {
				break;
			}
			if (optval < 0 || optval > INT32_MAX) {
				error = EINVAL;
			} else {
				tp->t_keepcnt = optval;
				if (tp->t_state == TCPS_FIN_WAIT_2 &&
				    TCP_CONN_MAXIDLE(tp) > 0) {
					tp->t_timer[TCPT_2MSL] = OFFSET_FROM_START(tp,
					    TCP_CONN_MAXIDLE(tp));
					tcp_check_timer_state(tp);
				}
			}
			break;

		case TCP_KEEPALIVE_OFFLOAD:
			if ((error = priv_check_cred(kauth_cred_get(),
			    PRIV_NETINET_TCP_KA_OFFLOAD, 0)) != 0) {
				break;
			}
			error = sooptcopyin(sopt, &optval, sizeof(optval),
			    sizeof(optval));
			if (error) {
				break;
			}
			if (optval < 0 || optval > INT32_MAX) {
				error = EINVAL;
				break;
			}
			if (optval != 0) {
				error = tcp_set_keep_alive_offload(so,
				    sopt->sopt_p);
			} else {
				tcp_clear_keep_alive_offload(so);
			}
			break;

		case PERSIST_TIMEOUT:
			error = sooptcopyin(sopt, &optval, sizeof optval,
			    sizeof optval);
			if (error) {
				break;
			}
			if (optval < 0) {
				error = EINVAL;
			} else {
				tp->t_persist_timeout = optval * TCP_RETRANSHZ;
			}
			break;
		case TCP_RXT_CONNDROPTIME:
			error = sooptcopyin(sopt, &optval, sizeof(optval),
			    sizeof(optval));
			if (error) {
				break;
			}
			if (optval < 0) {
				error = EINVAL;
			} else {
				tp->t_rxt_conndroptime = optval * TCP_RETRANSHZ;
			}
			break;
		case TCP_NOTSENT_LOWAT:
			error = sooptcopyin(sopt, &optval, sizeof(optval),
			    sizeof(optval));
			if (error) {
				break;
			}
			if (optval < 0) {
				error = EINVAL;
				break;
			} else {
				if (optval == 0) {
					so->so_flags &= ~(SOF_NOTSENT_LOWAT);
					tp->t_notsent_lowat = 0;
				} else {
					so->so_flags |= SOF_NOTSENT_LOWAT;
					tp->t_notsent_lowat = optval;
				}
			}
			break;
		case TCP_ADAPTIVE_READ_TIMEOUT:
			error = sooptcopyin(sopt, &optval, sizeof(optval),
			    sizeof(optval));
			if (error) {
				break;
			}
			if (optval < 0 ||
			    optval > TCP_ADAPTIVE_TIMEOUT_MAX) {
				error = EINVAL;
				break;
			} else if (optval == 0) {
				tp->t_adaptive_rtimo = 0;
				tcp_keepalive_reset(tp);

				if (tp->t_mpsub) {
					mptcp_reset_keepalive(tp);
				}
			} else {
				tp->t_adaptive_rtimo = optval;
			}
			break;
		case TCP_ADAPTIVE_WRITE_TIMEOUT:
			error = sooptcopyin(sopt, &optval, sizeof(optval),
			    sizeof(optval));
			if (error) {
				break;
			}
			if (optval < 0 ||
			    optval > TCP_ADAPTIVE_TIMEOUT_MAX) {
				error = EINVAL;
				break;
			} else {
				tp->t_adaptive_wtimo = optval;
			}
			break;
		case TCP_ENABLE_MSGS:
			error = sooptcopyin(sopt, &optval, sizeof(optval),
			    sizeof(optval));
			if (error) {
				break;
			}
			if (optval < 0 || optval > 1) {
				error = EINVAL;
			} else if (optval == 1) {
				/*
				 * Check if messages option is already
				 * enabled, if so return.
				 */
				if (so->so_flags & SOF_ENABLE_MSGS) {
					VERIFY(so->so_msg_state != NULL);
					break;
				}

				/*
				 * allocate memory for storing message
				 * related state
				 */
				VERIFY(so->so_msg_state == NULL);
				MALLOC(so->so_msg_state,
				    struct msg_state *,
				    sizeof(struct msg_state),
				    M_TEMP, M_WAITOK | M_ZERO);
				if (so->so_msg_state == NULL) {
					error = ENOMEM;
					break;
				}

				/* Enable message delivery */
				so->so_flags |= SOF_ENABLE_MSGS;
			} else {
				/*
				 * Can't disable message delivery on socket
				 * because of restrictions imposed by
				 * encoding/decoding
				 */
				error = EINVAL;
			}
			break;
		case TCP_SENDMOREACKS:
			error = sooptcopyin(sopt, &optval, sizeof(optval),
			    sizeof(optval));
			if (error) {
				break;
			}
			if (optval < 0 || optval > 1) {
				error = EINVAL;
			} else if (optval == 0) {
				tp->t_flagsext &= ~(TF_NOSTRETCHACK);
			} else {
				tp->t_flagsext |= TF_NOSTRETCHACK;
			}
			break;
		case TCP_DISABLE_BLACKHOLE_DETECTION:
			error = sooptcopyin(sopt, &optval, sizeof(optval),
			    sizeof(optval));
			if (error) {
				break;
			}
			if (optval < 0 || optval > 1) {
				error = EINVAL;
			} else if (optval == 0) {
				tp->t_flagsext &= ~TF_NOBLACKHOLE_DETECTION;
			} else {
				tp->t_flagsext |= TF_NOBLACKHOLE_DETECTION;
				if ((tp->t_flags & TF_BLACKHOLE) &&
				    tp->t_pmtud_saved_maxopd > 0) {
					tcp_pmtud_revert_segment_size(tp);
				}
			}
			break;
		case TCP_FASTOPEN:
			if (!(tcp_fastopen & TCP_FASTOPEN_SERVER)) {
				error = ENOTSUP;
				break;
			}

			error = sooptcopyin(sopt, &optval, sizeof(optval),
			    sizeof(optval));
			if (error) {
				break;
			}
			if (optval < 0 || optval > 1) {
				error = EINVAL;
				break;
			}
			if (tp->t_state != TCPS_LISTEN) {
				error =  EINVAL;
				break;
			}
			if (optval) {
				tp->t_flagsext |= TF_FASTOPEN;
			} else {
				tcp_disable_tfo(tp);
			}
			break;
		case TCP_FASTOPEN_FORCE_HEURISTICS:

			break;
		case TCP_FASTOPEN_FORCE_ENABLE:
			error = sooptcopyin(sopt, &optval, sizeof(optval),
			    sizeof(optval));

			if (error) {
				break;
			}
			if (optval < 0 || optval > 1) {
				error = EINVAL;
				break;
			}

			if (tp->t_state != TCPS_CLOSED) {
				error =  EINVAL;
				break;
			}
			if (optval) {
				tp->t_flagsext |= TF_FASTOPEN_FORCE_ENABLE;
			} else {
				tp->t_flagsext &= ~TF_FASTOPEN_FORCE_ENABLE;
			}

			break;
		case TCP_ENABLE_ECN:
			error = sooptcopyin(sopt, &optval, sizeof optval,
			    sizeof optval);
			if (error) {
				break;
			}
			if (optval) {
				tp->ecn_flags |= TE_ECN_MODE_ENABLE;
				tp->ecn_flags &= ~TE_ECN_MODE_DISABLE;
			} else {
				tp->ecn_flags &= ~TE_ECN_MODE_ENABLE;
				tp->ecn_flags |= TE_ECN_MODE_DISABLE;
			}
			break;
		case TCP_ECN_MODE:
			error = sooptcopyin(sopt, &optval, sizeof optval,
			    sizeof optval);
			if (error) {
				break;
			}
			if (optval == ECN_MODE_DEFAULT) {
				tp->ecn_flags &= ~TE_ECN_MODE_ENABLE;
				tp->ecn_flags &= ~TE_ECN_MODE_DISABLE;
			} else if (optval == ECN_MODE_ENABLE) {
				tp->ecn_flags |= TE_ECN_MODE_ENABLE;
				tp->ecn_flags &= ~TE_ECN_MODE_DISABLE;
			} else if (optval == ECN_MODE_DISABLE) {
				tp->ecn_flags &= ~TE_ECN_MODE_ENABLE;
				tp->ecn_flags |= TE_ECN_MODE_DISABLE;
			} else {
				error = EINVAL;
			}
			break;
		case TCP_NOTIFY_ACKNOWLEDGEMENT:
			error = sooptcopyin(sopt, &optval,
			    sizeof(optval), sizeof(optval));
			if (error) {
				break;
			}
			if (optval <= 0) {
				error = EINVAL;
				break;
			}
			if (tp->t_notify_ack_count >= TCP_MAX_NOTIFY_ACK) {
				error = ETOOMANYREFS;
				break;
			}

			/*
			 * validate that the given marker id is not
			 * a duplicate to avoid ambiguity
			 */
			if ((error = tcp_notify_ack_id_valid(tp, so,
			    optval)) != 0) {
				break;
			}
			error = tcp_add_notify_ack_marker(tp, optval);
			break;
		case SO_FLUSH:
			if ((error = sooptcopyin(sopt, &optval, sizeof(optval),
			    sizeof(optval))) != 0) {
				break;
			}

			error = inp_flush(inp, optval);
			break;

		case SO_TRAFFIC_MGT_BACKGROUND:
			if ((error = sooptcopyin(sopt, &optval, sizeof(optval),
			    sizeof(optval))) != 0) {
				break;
			}

			if (optval) {
				socket_set_traffic_mgt_flags_locked(so,
				    TRAFFIC_MGT_SO_BACKGROUND);
			} else {
				socket_clear_traffic_mgt_flags_locked(so,
				    TRAFFIC_MGT_SO_BACKGROUND);
			}
			break;
		case TCP_RXT_MINIMUM_TIMEOUT:
			error = sooptcopyin(sopt, &optval, sizeof(optval),
			    sizeof(optval));
			if (error) {
				break;
			}
			if (optval < 0) {
				error = EINVAL;
				break;
			}
			if (optval == 0) {
				tp->t_rxt_minimum_timeout = 0;
			} else {
				tp->t_rxt_minimum_timeout = min(optval,
				    TCP_RXT_MINIMUM_TIMEOUT_LIMIT);
				/* convert to milliseconds */
				tp->t_rxt_minimum_timeout *= TCP_RETRANSHZ;
			}
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
			if (tp->t_keepidle > 0) {
				optval = tp->t_keepidle / TCP_RETRANSHZ;
			} else {
				optval = tcp_keepidle  / TCP_RETRANSHZ;
			}
			break;
		case TCP_KEEPINTVL:
			if (tp->t_keepintvl > 0) {
				optval = tp->t_keepintvl / TCP_RETRANSHZ;
			} else {
				optval = tcp_keepintvl / TCP_RETRANSHZ;
			}
			break;
		case TCP_KEEPCNT:
			if (tp->t_keepcnt > 0) {
				optval = tp->t_keepcnt;
			} else {
				optval = tcp_keepcnt;
			}
			break;
		case TCP_KEEPALIVE_OFFLOAD:
			optval = !!(inp->inp_flags2 & INP2_KEEPALIVE_OFFLOAD);
			break;
		case TCP_NOOPT:
			optval = tp->t_flags & TF_NOOPT;
			break;
		case TCP_NOPUSH:
			optval = tp->t_flags & TF_NOPUSH;
			break;
		case TCP_ENABLE_ECN:
			optval = (tp->ecn_flags & TE_ECN_MODE_ENABLE) ? 1 : 0;
			break;
		case TCP_ECN_MODE:
			if (tp->ecn_flags & TE_ECN_MODE_ENABLE) {
				optval = ECN_MODE_ENABLE;
			} else if (tp->ecn_flags & TE_ECN_MODE_DISABLE) {
				optval = ECN_MODE_DISABLE;
			} else {
				optval = ECN_MODE_DEFAULT;
			}
			break;
		case TCP_CONNECTIONTIMEOUT:
			optval = tp->t_keepinit / TCP_RETRANSHZ;
			break;
		case PERSIST_TIMEOUT:
			optval = tp->t_persist_timeout / TCP_RETRANSHZ;
			break;
		case TCP_RXT_CONNDROPTIME:
			optval = tp->t_rxt_conndroptime / TCP_RETRANSHZ;
			break;
		case TCP_RXT_FINDROP:
			optval = tp->t_flagsext & TF_RXTFINDROP;
			break;
		case TCP_NOTIMEWAIT:
			optval = (tp->t_flagsext & TF_NOTIMEWAIT) ? 1 : 0;
			break;
		case TCP_FASTOPEN:
			if (tp->t_state != TCPS_LISTEN ||
			    !(tcp_fastopen & TCP_FASTOPEN_SERVER)) {
				error = ENOTSUP;
				break;
			}
			optval = tfo_enabled(tp);
			break;
		case TCP_FASTOPEN_FORCE_HEURISTICS:
			optval = 0;
			break;
		case TCP_FASTOPEN_FORCE_ENABLE:
			optval = (tp->t_flagsext & TF_FASTOPEN_FORCE_ENABLE) ? 1 : 0;
			break;
		case TCP_MEASURE_SND_BW:
			optval = tp->t_flagsext & TF_MEASURESNDBW;
			break;
		case TCP_INFO: {
			struct tcp_info ti;

			tcp_fill_info(tp, &ti);
			error = sooptcopyout(sopt, &ti, sizeof(struct tcp_info));
			goto done;
			/* NOT REACHED */
		}
		case TCP_CONNECTION_INFO: {
			struct tcp_connection_info tci;
			tcp_connection_fill_info(tp, &tci);
			error = sooptcopyout(sopt, &tci,
			    sizeof(struct tcp_connection_info));
			goto done;
		}
		case TCP_MEASURE_BW_BURST: {
			struct tcp_measure_bw_burst out = {};
			if ((tp->t_flagsext & TF_MEASURESNDBW) == 0 ||
			    tp->t_bwmeas == NULL) {
				error = EINVAL;
				break;
			}
			out.min_burst_size = tp->t_bwmeas->bw_minsizepkts;
			out.max_burst_size = tp->t_bwmeas->bw_maxsizepkts;
			error = sooptcopyout(sopt, &out, sizeof(out));
			goto done;
		}
		case TCP_NOTSENT_LOWAT:
			if ((so->so_flags & SOF_NOTSENT_LOWAT) != 0) {
				optval = tp->t_notsent_lowat;
			} else {
				optval = 0;
			}
			break;

		case TCP_ENABLE_MSGS:
			if (so->so_flags & SOF_ENABLE_MSGS) {
				optval = 1;
			} else {
				optval = 0;
			}
			break;
		case TCP_SENDMOREACKS:
			if (tp->t_flagsext & TF_NOSTRETCHACK) {
				optval = 1;
			} else {
				optval = 0;
			}
			break;
		case TCP_DISABLE_BLACKHOLE_DETECTION:
			if (tp->t_flagsext & TF_NOBLACKHOLE_DETECTION) {
				optval = 1;
			} else {
				optval = 0;
			}
			break;
		case TCP_PEER_PID: {
			pid_t   pid;
			error = tcp_lookup_peer_pid_locked(so, &pid);
			if (error == 0) {
				error = sooptcopyout(sopt, &pid, sizeof(pid));
			}
			goto done;
		}
		case TCP_ADAPTIVE_READ_TIMEOUT:
			optval = tp->t_adaptive_rtimo;
			break;
		case TCP_ADAPTIVE_WRITE_TIMEOUT:
			optval = tp->t_adaptive_wtimo;
			break;
		case SO_TRAFFIC_MGT_BACKGROUND:
			optval = (so->so_flags1 &
			    SOF1_TRAFFIC_MGT_SO_BACKGROUND) ? 1 : 0;
			break;
		case TCP_NOTIFY_ACKNOWLEDGEMENT: {
			struct tcp_notify_ack_complete retid;

			if (sopt->sopt_valsize != sizeof(retid)) {
				error = EINVAL;
				break;
			}
			bzero(&retid, sizeof(retid));
			tcp_get_notify_ack_count(tp, &retid);
			if (retid.notify_complete_count > 0) {
				tcp_get_notify_ack_ids(tp, &retid);
			}

			error = sooptcopyout(sopt, &retid, sizeof(retid));
			goto done;
		}
		case TCP_RXT_MINIMUM_TIMEOUT:
			optval = tp->t_rxt_minimum_timeout / TCP_RETRANSHZ;
			break;
		default:
			error = ENOPROTOOPT;
			break;
		}
		if (error == 0) {
			error = sooptcopyout(sopt, &optval, sizeof optval);
		}
		break;
	}
done:
	return error;
}

/*
 * tcp_sendspace and tcp_recvspace are the default send and receive window
 * sizes, respectively.  These are obsolescent (this information should
 * be set by the route).
 */
u_int32_t       tcp_sendspace = 1448 * 256;
u_int32_t       tcp_recvspace = 1448 * 384;

/* During attach, the size of socket buffer allocated is limited to
 * sb_max in sbreserve. Disallow setting the tcp send and recv space
 * to be more than sb_max because that will cause tcp_attach to fail
 * (see radar 5713060)
 */
static int
sysctl_tcp_sospace(struct sysctl_oid *oidp, __unused void *arg1,
    int arg2, struct sysctl_req *req)
{
#pragma unused(arg2)
	u_int32_t new_value = 0, *space_p = NULL;
	int changed = 0, error = 0;
	u_quad_t sb_effective_max = (sb_max / (MSIZE + MCLBYTES)) * MCLBYTES;

	switch (oidp->oid_number) {
	case TCPCTL_SENDSPACE:
		space_p = &tcp_sendspace;
		break;
	case TCPCTL_RECVSPACE:
		space_p = &tcp_recvspace;
		break;
	default:
		return EINVAL;
	}
	error = sysctl_io_number(req, *space_p, sizeof(u_int32_t),
	    &new_value, &changed);
	if (changed) {
		if (new_value > 0 && new_value <= sb_effective_max) {
			*space_p = new_value;
			SYSCTL_SKMEM_UPDATE_AT_OFFSET(arg2, new_value);
		} else {
			error = ERANGE;
		}
	}
	return error;
}

#if SYSCTL_SKMEM
SYSCTL_PROC(_net_inet_tcp, TCPCTL_SENDSPACE, sendspace,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_sendspace,
    offsetof(skmem_sysctl, tcp.sendspace), sysctl_tcp_sospace,
    "IU", "Maximum outgoing TCP datagram size");
SYSCTL_PROC(_net_inet_tcp, TCPCTL_RECVSPACE, recvspace,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_recvspace,
    offsetof(skmem_sysctl, tcp.recvspace), sysctl_tcp_sospace,
    "IU", "Maximum incoming TCP datagram size");
#else /* SYSCTL_SKMEM */
SYSCTL_PROC(_net_inet_tcp, TCPCTL_SENDSPACE, sendspace, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_sendspace, 0, &sysctl_tcp_sospace, "IU", "Maximum outgoing TCP datagram size");
SYSCTL_PROC(_net_inet_tcp, TCPCTL_RECVSPACE, recvspace, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_recvspace, 0, &sysctl_tcp_sospace, "IU", "Maximum incoming TCP datagram size");
#endif /* SYSCTL_SKMEM */

/*
 * Attach TCP protocol to socket, allocating
 * internet protocol control block, tcp control block,
 * bufer space, and entering LISTEN state if to accept connections.
 *
 * Returns:	0			Success
 *	in_pcballoc:ENOBUFS
 *	in_pcballoc:ENOMEM
 *	in_pcballoc:???			[IPSEC specific]
 *	soreserve:ENOBUFS
 */
static int
tcp_attach(struct socket *so, struct proc *p)
{
	struct tcpcb *tp;
	struct inpcb *inp;
	int error;
#if INET6
	int isipv6 = SOCK_CHECK_DOM(so, PF_INET6) != 0;
#endif

	error = in_pcballoc(so, &tcbinfo, p);
	if (error) {
		return error;
	}

	inp = sotoinpcb(so);

	if (so->so_snd.sb_hiwat == 0 || so->so_rcv.sb_hiwat == 0) {
		error = soreserve(so, tcp_sendspace, tcp_recvspace);
		if (error) {
			return error;
		}
	}

	if (so->so_snd.sb_preconn_hiwat == 0) {
		soreserve_preconnect(so, 2048);
	}

	if ((so->so_rcv.sb_flags & SB_USRSIZE) == 0) {
		so->so_rcv.sb_flags |= SB_AUTOSIZE;
	}
	if ((so->so_snd.sb_flags & SB_USRSIZE) == 0) {
		so->so_snd.sb_flags |= SB_AUTOSIZE;
	}

#if INET6
	if (isipv6) {
		inp->inp_vflag |= INP_IPV6;
		inp->in6p_hops = -1;    /* use kernel default */
	} else
#endif /* INET6 */
	inp->inp_vflag |= INP_IPV4;
	tp = tcp_newtcpcb(inp);
	if (tp == NULL) {
		int nofd = so->so_state & SS_NOFDREF;   /* XXX */

		so->so_state &= ~SS_NOFDREF;    /* don't free the socket yet */
#if INET6
		if (isipv6) {
			in6_pcbdetach(inp);
		} else
#endif /* INET6 */
		in_pcbdetach(inp);
		so->so_state |= nofd;
		return ENOBUFS;
	}
	if (nstat_collect) {
		nstat_tcp_new_pcb(inp);
	}
	tp->t_state = TCPS_CLOSED;
	return 0;
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
tcp_disconnect(struct tcpcb *tp)
{
	struct socket *so = tp->t_inpcb->inp_socket;

	if (so->so_rcv.sb_cc != 0 || tp->t_reassqlen != 0) {
		return tcp_drop(tp, 0);
	}

	if (tp->t_state < TCPS_ESTABLISHED) {
		tp = tcp_close(tp);
	} else if ((so->so_options & SO_LINGER) && so->so_linger == 0) {
		tp = tcp_drop(tp, 0);
	} else {
		soisdisconnecting(so);
		sbflush(&so->so_rcv);
		tp = tcp_usrclosed(tp);
#if MPTCP
		/* A reset has been sent but socket exists, do not send FIN */
		if ((so->so_flags & SOF_MP_SUBFLOW) &&
		    (tp) && (tp->t_mpflags & TMPF_RESET)) {
			return tp;
		}
#endif
		if (tp) {
			(void) tcp_output(tp);
		}
	}
	return tp;
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
tcp_usrclosed(struct tcpcb *tp)
{
	switch (tp->t_state) {
	case TCPS_CLOSED:
	case TCPS_LISTEN:
	case TCPS_SYN_SENT:
		tp = tcp_close(tp);
		break;

	case TCPS_SYN_RECEIVED:
		tp->t_flags |= TF_NEEDFIN;
		break;

	case TCPS_ESTABLISHED:
		DTRACE_TCP4(state__change, void, NULL,
		    struct inpcb *, tp->t_inpcb,
		    struct tcpcb *, tp,
		    int32_t, TCPS_FIN_WAIT_1);
		tp->t_state = TCPS_FIN_WAIT_1;
		TCP_LOG_CONNECTION_SUMMARY(tp);
		break;

	case TCPS_CLOSE_WAIT:
		DTRACE_TCP4(state__change, void, NULL,
		    struct inpcb *, tp->t_inpcb,
		    struct tcpcb *, tp,
		    int32_t, TCPS_LAST_ACK);
		tp->t_state = TCPS_LAST_ACK;
		TCP_LOG_CONNECTION_SUMMARY(tp);
		break;
	}
	if (tp && tp->t_state >= TCPS_FIN_WAIT_2) {
		soisdisconnected(tp->t_inpcb->inp_socket);
		/* To prevent the connection hanging in FIN_WAIT_2 forever. */
		if (tp->t_state == TCPS_FIN_WAIT_2) {
			tp->t_timer[TCPT_2MSL] = OFFSET_FROM_START(tp,
			    TCP_CONN_MAXIDLE(tp));
		}
	}
	return tp;
}

void
tcp_in_cksum_stats(u_int32_t len)
{
	tcpstat.tcps_rcv_swcsum++;
	tcpstat.tcps_rcv_swcsum_bytes += len;
}

void
tcp_out_cksum_stats(u_int32_t len)
{
	tcpstat.tcps_snd_swcsum++;
	tcpstat.tcps_snd_swcsum_bytes += len;
}

#if INET6
void
tcp_in6_cksum_stats(u_int32_t len)
{
	tcpstat.tcps_rcv6_swcsum++;
	tcpstat.tcps_rcv6_swcsum_bytes += len;
}

void
tcp_out6_cksum_stats(u_int32_t len)
{
	tcpstat.tcps_snd6_swcsum++;
	tcpstat.tcps_snd6_swcsum_bytes += len;
}
#endif /* INET6 */

/*
 * When messages are enabled on a TCP socket, the message priority
 * is sent as a control message. This function will extract it.
 */
int
tcp_get_msg_priority(struct mbuf *control, uint32_t *msgpri)
{
	struct cmsghdr *cm;

	if (control == NULL) {
		return EINVAL;
	}

	for (cm = M_FIRST_CMSGHDR(control);
	    is_cmsg_valid(control, cm);
	    cm = M_NXT_CMSGHDR(control, cm)) {
		if (cm->cmsg_level == SOL_SOCKET &&
		    cm->cmsg_type == SCM_MSG_PRIORITY) {
			if (cm->cmsg_len != CMSG_LEN(sizeof(uint32_t))) {
				return EINVAL;
			}
			*msgpri = *(uint32_t *)(void *)CMSG_DATA(cm);
			if (*msgpri < MSG_PRI_MIN || *msgpri > MSG_PRI_MAX) {
				return EINVAL;
			}
			break;
		}
	}
	return 0;
}

int
tcp_get_mpkl_send_info(struct mbuf *control,
    struct so_mpkl_send_info *mpkl_send_info)
{
	struct cmsghdr *cm;

	if (control == NULL || mpkl_send_info == NULL) {
		return EINVAL;
	}

	for (cm = M_FIRST_CMSGHDR(control); cm;
	    cm = M_NXT_CMSGHDR(control, cm)) {
		if (cm->cmsg_len < sizeof(struct cmsghdr) ||
		    cm->cmsg_len > control->m_len) {
			return EINVAL;
		}
		if (cm->cmsg_level != SOL_SOCKET ||
		    cm->cmsg_type != SCM_MPKL_SEND_INFO) {
			continue;
		}
		if (cm->cmsg_len != CMSG_LEN(sizeof(struct so_mpkl_send_info))) {
			return EINVAL;
		}
		memcpy(mpkl_send_info, CMSG_DATA(cm),
		    sizeof(struct so_mpkl_send_info));
		return 0;
	}
	return ENOMSG;
}
