/*
 * Copyright (c) 2003-2012 Apple Inc. All rights reserved.
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

#define	__KPI__
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/protosw.h>
#include <sys/domain.h>
#include <sys/mbuf.h>
#include <sys/fcntl.h>
#include <sys/filio.h>
#include <sys/uio_internal.h>
#include <kern/locks.h>
#include <netinet/in.h>
#include <libkern/OSAtomic.h>

static errno_t sock_send_internal(socket_t, const struct msghdr	*,
    mbuf_t, int, size_t	*);
static void sock_setupcalls_common(socket_t, sock_upcall, void *,
    sock_upcall, void *);

errno_t
sock_accept(socket_t sock, struct sockaddr *from, int fromlen, int flags,
    sock_upcall callback, void *cookie, socket_t *new_sock)
{
	struct sockaddr *sa;
	struct socket *new_so;
	lck_mtx_t *mutex_held;
	int dosocklock;
	errno_t	error = 0;

	if (sock == NULL || new_sock == NULL)
		return (EINVAL);

	socket_lock(sock, 1);
	if ((sock->so_options & SO_ACCEPTCONN) == 0) {
		socket_unlock(sock, 1);
		return (EINVAL);
	}
	if ((flags & ~(MSG_DONTWAIT)) != 0) {
		socket_unlock(sock, 1);
		return (ENOTSUP);
	}
	if (((flags & MSG_DONTWAIT) != 0 || (sock->so_state & SS_NBIO) != 0) &&
	    sock->so_comp.tqh_first == NULL) {
		socket_unlock(sock, 1);
		return (EWOULDBLOCK);
	}

	if (sock->so_proto->pr_getlock != NULL)  {
		mutex_held = (*sock->so_proto->pr_getlock)(sock, 0);
		dosocklock = 1;
	} else {
		mutex_held = sock->so_proto->pr_domain->dom_mtx;
		dosocklock = 0;
	}

	while (TAILQ_EMPTY(&sock->so_comp) && sock->so_error == 0) {
		if (sock->so_state & SS_CANTRCVMORE) {
			sock->so_error = ECONNABORTED;
			break;
		}
		error = msleep((caddr_t)&sock->so_timeo, mutex_held,
		    PSOCK | PCATCH, "sock_accept", NULL);
		if (error != 0) {
			socket_unlock(sock, 1);
			return (error);
		}
	}
	if (sock->so_error != 0) {
		error = sock->so_error;
		sock->so_error = 0;
		socket_unlock(sock, 1);
		return (error);
	}

	new_so = TAILQ_FIRST(&sock->so_comp);
	TAILQ_REMOVE(&sock->so_comp, new_so, so_list);
	sock->so_qlen--;

	/*
	 * Pass the pre-accepted socket to any interested socket filter(s).
	 * Upon failure, the socket would have been closed by the callee.
	 */
	if (new_so->so_filt != NULL) {
		/*
		 * Temporarily drop the listening socket's lock before we
		 * hand off control over to the socket filter(s), but keep
		 * a reference so that it won't go away.  We'll grab it
		 * again once we're done with the filter(s).
		 */
		socket_unlock(sock, 0);
		if ((error = soacceptfilter(new_so)) != 0) {
			/* Drop reference on listening socket */
			sodereference(sock);
			return (error);
		}
		socket_lock(sock, 0);
	}

	if (dosocklock)	{
		lck_mtx_assert(new_so->so_proto->pr_getlock(new_so, 0),
		    LCK_MTX_ASSERT_NOTOWNED);
		socket_lock(new_so, 1);
	}

	new_so->so_state &= ~SS_COMP;
	new_so->so_head = NULL;
	(void) soacceptlock(new_so, &sa, 0);

	socket_unlock(sock, 1);	/* release the head */

	/* see comments in sock_setupcall() */
	if (callback != NULL) {
		sock_setupcalls_common(new_so, callback, cookie, NULL, NULL);
	}

	if (sa != NULL && from != NULL) {
		if (fromlen > sa->sa_len)
			fromlen = sa->sa_len;
		memcpy(from, sa, fromlen);
	}
	if (sa != NULL)
		FREE(sa, M_SONAME);

	/*
	 * If the socket has been marked as inactive by sosetdefunct(),
	 * disallow further operations on it.
	 */
	if (new_so->so_flags & SOF_DEFUNCT) {
		(void) sodefunct(current_proc(), new_so,
		    SHUTDOWN_SOCKET_LEVEL_DISCONNECT_INTERNAL);
	}
	*new_sock = new_so;
	if (dosocklock)
		socket_unlock(new_so, 1);
	return (error);
}

errno_t
sock_bind(socket_t sock, const struct sockaddr *to)
{
	int error = 0;
	struct sockaddr *sa = NULL;
	struct sockaddr_storage ss;
	boolean_t want_free = TRUE;

	if (sock == NULL || to == NULL)
		return (EINVAL);

	if (to->sa_len > sizeof (ss)) {
		MALLOC(sa, struct sockaddr *, to->sa_len, M_SONAME, M_WAITOK);
		if (sa == NULL)
			return (ENOBUFS);
	} else {
		sa = (struct sockaddr *)&ss;
		want_free = FALSE;
	}
	memcpy(sa, to, to->sa_len);

	error = sobindlock(sock, sa, 1);	/* will lock socket */

	if (sa != NULL && want_free == TRUE)
		FREE(sa, M_SONAME);

	return (error);
}

errno_t
sock_connect(socket_t sock, const struct sockaddr *to, int flags)
{
	int error = 0;
	lck_mtx_t *mutex_held;
	struct sockaddr *sa = NULL;
	struct sockaddr_storage ss;
	boolean_t want_free = TRUE;

	if (sock == NULL || to == NULL)
		return (EINVAL);

	if (to->sa_len > sizeof (ss)) {
		MALLOC(sa, struct sockaddr *, to->sa_len, M_SONAME,
		    (flags & MSG_DONTWAIT) ? M_NOWAIT : M_WAITOK);
		if (sa == NULL)
			return (ENOBUFS);
	} else {
		sa = (struct sockaddr *)&ss;
		want_free = FALSE;
	}
	memcpy(sa, to, to->sa_len);

	socket_lock(sock, 1);

	if ((sock->so_state & SS_ISCONNECTING) &&
	    ((sock->so_state & SS_NBIO) != 0 || (flags & MSG_DONTWAIT) != 0)) {
		error = EALREADY;
		goto out;
	}
	error = soconnectlock(sock, sa, 0);
	if (!error) {
		if ((sock->so_state & SS_ISCONNECTING) &&
		    ((sock->so_state & SS_NBIO) != 0 ||
		    (flags & MSG_DONTWAIT) != 0)) {
			error = EINPROGRESS;
			goto out;
		}

		if (sock->so_proto->pr_getlock != NULL)
			mutex_held = (*sock->so_proto->pr_getlock)(sock, 0);
		else
			mutex_held = sock->so_proto->pr_domain->dom_mtx;

		while ((sock->so_state & SS_ISCONNECTING) &&
		    sock->so_error == 0) {
			error = msleep((caddr_t)&sock->so_timeo,
			    mutex_held, PSOCK | PCATCH, "sock_connect", NULL);
			if (error != 0)
				break;
		}

		if (error == 0) {
			error = sock->so_error;
			sock->so_error = 0;
		}
	} else {
		sock->so_state &= ~SS_ISCONNECTING;
	}
out:
	socket_unlock(sock, 1);

	if (sa != NULL && want_free == TRUE)
		FREE(sa, M_SONAME);

	return (error);
}

errno_t
sock_connectwait(socket_t sock, const struct timeval *tv)
{
	lck_mtx_t *mutex_held;
	errno_t	retval = 0;
	struct timespec ts;

	socket_lock(sock, 1);

	/* Check if we're already connected or if we've already errored out */
	if ((sock->so_state & SS_ISCONNECTING) == 0 || sock->so_error != 0) {
		if (sock->so_error != 0) {
			retval = sock->so_error;
			sock->so_error = 0;
		} else {
			if ((sock->so_state & SS_ISCONNECTED) != 0)
				retval = 0;
			else
				retval = EINVAL;
		}
		goto done;
	}

	/* copied translation from timeval to hertz from SO_RCVTIMEO handling */
	if (tv->tv_sec < 0 || tv->tv_sec > SHRT_MAX / hz ||
	    tv->tv_usec < 0 || tv->tv_usec >= 1000000) {
		retval = EDOM;
		goto done;
	}

	ts.tv_sec = tv->tv_sec;
	ts.tv_nsec = (tv->tv_usec * (integer_t)NSEC_PER_USEC);
	if ((ts.tv_sec + (ts.tv_nsec/(long)NSEC_PER_SEC))/100  >  SHRT_MAX)  {
		retval = EDOM;
		goto done;
	}

	if (sock->so_proto->pr_getlock != NULL)
		mutex_held = (*sock->so_proto->pr_getlock)(sock, 0);
	else
		mutex_held = sock->so_proto->pr_domain->dom_mtx;

	msleep((caddr_t)&sock->so_timeo, mutex_held,
	    PSOCK, "sock_connectwait", &ts);

	/* Check if we're still waiting to connect */
	if ((sock->so_state & SS_ISCONNECTING) && sock->so_error == 0) {
		retval = EINPROGRESS;
		goto done;
	}

	if (sock->so_error != 0) {
		retval = sock->so_error;
		sock->so_error = 0;
	}

done:
	socket_unlock(sock, 1);
	return (retval);
}

errno_t
sock_nointerrupt(socket_t sock, int on)
{
	socket_lock(sock, 1);

	if (on) {
		sock->so_rcv.sb_flags |= SB_NOINTR;	/* This isn't safe */
		sock->so_snd.sb_flags |= SB_NOINTR;	/* This isn't safe */
	} else {
		sock->so_rcv.sb_flags &= ~SB_NOINTR;	/* This isn't safe */
		sock->so_snd.sb_flags &= ~SB_NOINTR;	/* This isn't safe */
	}

	socket_unlock(sock, 1);

	return (0);
}

errno_t
sock_getpeername(socket_t sock, struct sockaddr	*peername, int peernamelen)
{
	int error;
	struct sockaddr	*sa = NULL;

	if (sock == NULL || peername == NULL || peernamelen < 0)
		return (EINVAL);

	socket_lock(sock, 1);
	if (!(sock->so_state & (SS_ISCONNECTED|SS_ISCONFIRMING))) {
		socket_unlock(sock, 1);
		return (ENOTCONN);
	}
	error = sogetaddr_locked(sock, &sa, 1);
	socket_unlock(sock, 1);
	if (error == 0) {
		if (peernamelen > sa->sa_len)
			peernamelen = sa->sa_len;
		memcpy(peername, sa, peernamelen);
		FREE(sa, M_SONAME);
	}
	return (error);
}

errno_t
sock_getsockname(socket_t sock, struct sockaddr	*sockname, int socknamelen)
{
	int error;
	struct sockaddr	*sa = NULL;

	if (sock == NULL || sockname == NULL || socknamelen < 0)
		return (EINVAL);

	socket_lock(sock, 1);
	error = sogetaddr_locked(sock, &sa, 0);
	socket_unlock(sock, 1);
	if (error == 0) {
		if (socknamelen > sa->sa_len)
			socknamelen = sa->sa_len;
		memcpy(sockname, sa, socknamelen);
		FREE(sa, M_SONAME);
	}
	return (error);
}

__private_extern__ int
sogetaddr_locked(struct socket *so, struct sockaddr **psa, int peer)
{
	int error;

	if (so == NULL || psa == NULL)
		return (EINVAL);

	*psa = NULL;
	error = peer ? so->so_proto->pr_usrreqs->pru_peeraddr(so, psa) :
	    so->so_proto->pr_usrreqs->pru_sockaddr(so, psa);

	if (error == 0 && *psa == NULL) {
		error = ENOMEM;
	} else if (error != 0 && *psa != NULL) {
		FREE(*psa, M_SONAME);
		*psa = NULL;
	}
	return (error);
}

errno_t
sock_getaddr(socket_t sock, struct sockaddr **psa, int peer)
{
	int error;

	if (sock == NULL || psa == NULL)
		return (EINVAL);

	socket_lock(sock, 1);
	error = sogetaddr_locked(sock, psa, peer);
	socket_unlock(sock, 1);

	return (error);
}

void
sock_freeaddr(struct sockaddr *sa)
{
	if (sa != NULL)
		FREE(sa, M_SONAME);
}

errno_t
sock_getsockopt(socket_t sock, int level, int optname, void *optval,
    int	*optlen)
{
	int error = 0;
	struct sockopt	sopt;

	if (sock == NULL || optval == NULL || optlen == NULL)
		return (EINVAL);

	sopt.sopt_dir = SOPT_GET;
	sopt.sopt_level = level;
	sopt.sopt_name = optname;
	sopt.sopt_val = CAST_USER_ADDR_T(optval);
	sopt.sopt_valsize = *optlen;
	sopt.sopt_p = kernproc;
	error = sogetoptlock(sock, &sopt, 1);	/* will lock socket */
	if (error == 0)
		*optlen = sopt.sopt_valsize;
	return (error);
}

errno_t
sock_ioctl(socket_t sock, unsigned long request, void *argp)
{
	return (soioctl(sock, request, argp, kernproc)); /* will lock socket */
}

errno_t
sock_setsockopt(socket_t sock, int level, int optname, const void *optval,
    int	optlen)
{
	struct sockopt	sopt;

	if (sock == NULL || optval == NULL)
		return (EINVAL);

	sopt.sopt_dir = SOPT_SET;
	sopt.sopt_level = level;
	sopt.sopt_name = optname;
	sopt.sopt_val = CAST_USER_ADDR_T(optval);
	sopt.sopt_valsize = optlen;
	sopt.sopt_p = kernproc;
	return (sosetoptlock(sock, &sopt, 1)); /* will lock socket */
}

/*
 * This follows the recommended mappings between DSCP code points
 * and WMM access classes.
 */
static u_int32_t so_tc_from_dscp(u_int8_t dscp);
static u_int32_t
so_tc_from_dscp(u_int8_t dscp)
{
	u_int32_t tc;

	if (dscp >= 0x30 && dscp <= 0x3f)
		tc = SO_TC_VO;
	else if (dscp >= 0x20 && dscp <= 0x2f)
		tc = SO_TC_VI;
	else if (dscp >= 0x08 && dscp <= 0x17)
		tc = SO_TC_BK;
	else
		tc = SO_TC_BE;

	return (tc);
}

errno_t
sock_settclassopt(socket_t sock, const void *optval, size_t optlen)
{
	errno_t error = 0;
	struct sockopt sopt;
	int sotc;

	if (sock == NULL || optval == NULL || optlen != sizeof (int))
		return (EINVAL);

	socket_lock(sock, 1);
	if (!(sock->so_state & SS_ISCONNECTED)) {
		/*
		 * If the socket is not connected then we don't know
		 * if the destination is on LAN  or not. Skip
		 * setting traffic class in this case
		 */
		error = ENOTCONN;
		goto out;
	}

	if (sock->so_proto == NULL || sock->so_proto->pr_domain == NULL ||
	    sock->so_pcb == NULL) {
		error = EINVAL;
		goto out;
	}

	/*
	 * Set the socket traffic class based on the passed DSCP code point
	 * regardless of the scope of the destination
	 */
	sotc = so_tc_from_dscp((*(const int *)optval) >> 2);

	sopt.sopt_dir = SOPT_SET;
	sopt.sopt_val = CAST_USER_ADDR_T(&sotc);
	sopt.sopt_valsize = sizeof (sotc);
	sopt.sopt_p = kernproc;
	sopt.sopt_level = SOL_SOCKET;
	sopt.sopt_name = SO_TRAFFIC_CLASS;

	error = sosetoptlock(sock, &sopt, 0);	/* already locked */

	if (error != 0) {
		printf("%s: sosetopt SO_TRAFFIC_CLASS failed %d\n",
		    __func__, error);
		goto out;
	}

	/*
	 * Check if the destination address is LAN or link local address.
	 * We do not want to set traffic class bits if the destination
	 * is not local.
	 */
	if (!so_isdstlocal(sock))
		goto out;

	sopt.sopt_dir = SOPT_SET;
	sopt.sopt_val = CAST_USER_ADDR_T(optval);
	sopt.sopt_valsize = optlen;
	sopt.sopt_p = kernproc;

	switch (SOCK_DOM(sock)) {
	case PF_INET:
		sopt.sopt_level = IPPROTO_IP;
		sopt.sopt_name = IP_TOS;
		break;
	case PF_INET6:
		sopt.sopt_level = IPPROTO_IPV6;
		sopt.sopt_name = IPV6_TCLASS;
		break;
	default:
		error = EINVAL;
		goto out;
	}

	error = sosetoptlock(sock, &sopt, 0);	/* already locked */
	socket_unlock(sock, 1);
	return (error);
out:
	socket_unlock(sock, 1);
	return (error);
}

errno_t
sock_gettclassopt(socket_t sock, void *optval, size_t *optlen)
{
	errno_t error = 0;
	struct sockopt sopt;

	if (sock == NULL || optval == NULL || optlen == NULL)
		return (EINVAL);

	sopt.sopt_dir = SOPT_GET;
	sopt.sopt_val = CAST_USER_ADDR_T(optval);
	sopt.sopt_valsize = *optlen;
	sopt.sopt_p = kernproc;

	socket_lock(sock, 1);
	if (sock->so_proto == NULL || sock->so_proto->pr_domain == NULL) {
		socket_unlock(sock, 1);
		return (EINVAL);
	}

	switch (SOCK_DOM(sock)) {
	case PF_INET:
		sopt.sopt_level = IPPROTO_IP;
		sopt.sopt_name = IP_TOS;
		break;
	case PF_INET6:
		sopt.sopt_level = IPPROTO_IPV6;
		sopt.sopt_name = IPV6_TCLASS;
		break;
	default:
		socket_unlock(sock, 1);
		return (EINVAL);

	}
	error = sogetoptlock(sock, &sopt, 0);	/* already locked */
	socket_unlock(sock, 1);
	if (error == 0)
		*optlen = sopt.sopt_valsize;
	return (error);
}

errno_t
sock_listen(socket_t sock, int backlog)
{
	if (sock == NULL)
		return (EINVAL);

	return (solisten(sock, backlog)); /* will lock socket */
}

errno_t
sock_receive_internal(socket_t sock, struct msghdr *msg, mbuf_t *data,
    int flags, size_t *recvdlen)
{
	uio_t auio;
	struct mbuf *control = NULL;
	int error = 0;
	int length = 0;
	struct sockaddr	*fromsa = NULL;
	char uio_buf[ UIO_SIZEOF((msg != NULL) ? msg->msg_iovlen : 0) ];

	if (sock == NULL)
		return (EINVAL);

	auio = uio_createwithbuffer(((msg != NULL) ? msg->msg_iovlen : 0),
	    0, UIO_SYSSPACE, UIO_READ, &uio_buf[0], sizeof (uio_buf));
	if (msg != NULL && data == NULL) {
		int i;
		struct iovec *tempp = msg->msg_iov;

		for (i = 0; i < msg->msg_iovlen; i++) {
			uio_addiov(auio,
			    CAST_USER_ADDR_T((tempp + i)->iov_base),
			    (tempp + i)->iov_len);
		}
		if (uio_resid(auio) < 0)
			return (EINVAL);
	} else if (recvdlen != NULL) {
		uio_setresid(auio, (uio_resid(auio) + *recvdlen));
	}
	length = uio_resid(auio);

	if (recvdlen != NULL)
		*recvdlen = 0;

	/* let pru_soreceive handle the socket locking */
	error = sock->so_proto->pr_usrreqs->pru_soreceive(sock, &fromsa, auio,
	    data, (msg && msg->msg_control) ? &control : NULL, &flags);
	if (error != 0)
		goto cleanup;

	if (recvdlen != NULL)
		*recvdlen = length - uio_resid(auio);
	if (msg != NULL) {
		msg->msg_flags = flags;

		if (msg->msg_name != NULL) {
			int salen;
			salen = msg->msg_namelen;
			if (msg->msg_namelen > 0 && fromsa != NULL) {
				salen = MIN(salen, fromsa->sa_len);
				memcpy(msg->msg_name, fromsa,
				    msg->msg_namelen > fromsa->sa_len ?
				    fromsa->sa_len : msg->msg_namelen);
			}
		}

		if (msg->msg_control != NULL) {
			struct mbuf *m = control;
			u_char *ctlbuf = msg->msg_control;
			int clen = msg->msg_controllen;

			msg->msg_controllen = 0;

			while (m != NULL && clen > 0) {
				unsigned int tocopy;

				if (clen >= m->m_len) {
					tocopy = m->m_len;
				} else {
					msg->msg_flags |= MSG_CTRUNC;
					tocopy = clen;
				}
				memcpy(ctlbuf, mtod(m, caddr_t), tocopy);
				ctlbuf += tocopy;
				clen -= tocopy;
				m = m->m_next;
			}
			msg->msg_controllen =
			    (uintptr_t)ctlbuf - (uintptr_t)msg->msg_control;
		}
	}

cleanup:
	if (control != NULL)
		m_freem(control);
	if (fromsa != NULL)
		FREE(fromsa, M_SONAME);
	return (error);
}

errno_t
sock_receive(socket_t sock, struct msghdr *msg, int flags, size_t *recvdlen)
{
	if ((msg == NULL) || (msg->msg_iovlen < 1) ||
	    (msg->msg_iov[0].iov_len == 0) ||
	    (msg->msg_iov[0].iov_base == NULL))
		return (EINVAL);

	return (sock_receive_internal(sock, msg, NULL, flags, recvdlen));
}

errno_t
sock_receivembuf(socket_t sock, struct msghdr *msg, mbuf_t *data, int flags,
    size_t *recvlen)
{
	if (data == NULL || recvlen == 0 || *recvlen <= 0 || (msg != NULL &&
	    (msg->msg_iov != NULL || msg->msg_iovlen != 0)))
		return (EINVAL);

	return (sock_receive_internal(sock, msg, data, flags, recvlen));
}

errno_t
sock_send_internal(socket_t sock, const struct msghdr *msg, mbuf_t data,
    int flags, size_t *sentlen)
{
	uio_t auio = NULL;
	struct mbuf *control = NULL;
	int error = 0;
	int datalen = 0;
	char uio_buf[ UIO_SIZEOF((msg != NULL ? msg->msg_iovlen : 1)) ];

	if (sock == NULL) {
		error = EINVAL;
		goto errorout;
	}

	if (data == NULL && msg != NULL) {
		struct iovec *tempp = msg->msg_iov;

		auio = uio_createwithbuffer(msg->msg_iovlen, 0,
		    UIO_SYSSPACE, UIO_WRITE, &uio_buf[0], sizeof (uio_buf));
		if (tempp != NULL) {
			int i;

			for (i = 0; i < msg->msg_iovlen; i++) {
				uio_addiov(auio,
				    CAST_USER_ADDR_T((tempp + i)->iov_base),
				    (tempp + i)->iov_len);
			}

			if (uio_resid(auio) < 0) {
				error = EINVAL;
				goto errorout;
			}
		}
	}

	if (sentlen != NULL)
		*sentlen = 0;

	if (auio != NULL)
		datalen = uio_resid(auio);
	else
		datalen = data->m_pkthdr.len;

	if (msg != NULL && msg->msg_control) {
		if ((size_t)msg->msg_controllen < sizeof (struct cmsghdr)) {
			error = EINVAL;
			goto errorout;
		}

		if ((size_t)msg->msg_controllen > MLEN) {
			error = EINVAL;
			goto errorout;
		}

		control = m_get(M_NOWAIT, MT_CONTROL);
		if (control == NULL) {
			error = ENOMEM;
			goto errorout;
		}
		memcpy(mtod(control, caddr_t), msg->msg_control,
		    msg->msg_controllen);
		control->m_len = msg->msg_controllen;
	}

	error = sock->so_proto->pr_usrreqs->pru_sosend(sock, msg != NULL ?
	    (struct sockaddr *)msg->msg_name : NULL, auio, data,
	    control, flags);

	/*
	 * Residual data is possible in the case of IO vectors but not
	 * in the mbuf case since the latter is treated as atomic send.
	 * If pru_sosend() consumed a portion of the iovecs data and
	 * the error returned is transient, treat it as success; this
	 * is consistent with sendit() behavior.
	 */
	if (auio != NULL && uio_resid(auio) != datalen &&
	    (error == ERESTART || error == EINTR || error == EWOULDBLOCK))
		error = 0;

	if (error == 0 && sentlen != NULL) {
		if (auio != NULL)
			*sentlen = datalen - uio_resid(auio);
		else
			*sentlen = datalen;
	}

	return (error);

/*
 * In cases where we detect an error before returning, we need to
 * free the mbuf chain if there is one. sosend (and pru_sosend) will
 * free the mbuf chain if they encounter an error.
 */
errorout:
	if (control)
		m_freem(control);
	if (data)
		m_freem(data);
	if (sentlen)
		*sentlen = 0;
	return (error);
}

errno_t
sock_send(socket_t sock, const struct msghdr *msg, int flags, size_t *sentlen)
{
	if (msg == NULL || msg->msg_iov == NULL || msg->msg_iovlen < 1)
		return (EINVAL);

	return (sock_send_internal(sock, msg, NULL, flags, sentlen));
}

errno_t
sock_sendmbuf(socket_t sock, const struct msghdr *msg, mbuf_t data,
    int	flags, size_t *sentlen)
{
	if (data == NULL || (msg != NULL && (msg->msg_iov != NULL ||
	    msg->msg_iovlen != 0))) {
		if (data != NULL)
			m_freem(data);
		return (EINVAL);
	}
	return (sock_send_internal(sock, msg, data, flags, sentlen));
}

errno_t
sock_shutdown(socket_t sock, int how)
{
	if (sock == NULL)
		return (EINVAL);

	return (soshutdown(sock, how));
}


errno_t
sock_socket(int	domain, int type, int protocol, sock_upcall callback,
    void *context, socket_t *new_so)
{
	int error = 0;

	if (new_so == NULL)
		return (EINVAL);

	/* socreate will create an initial so_count */
	error = socreate(domain, new_so, type, protocol);
	if (error == 0) {
		/* see comments in sock_setupcall() */
		if (callback != NULL) {
			sock_setupcalls_common(*new_so, callback, context,
			    NULL, NULL);
		}
		/* 
		 * last_pid and last_upid should be zero for sockets
		 * created using sock_socket
		 */
		(*new_so)->last_pid = 0;
		(*new_so)->last_upid = 0;
	}
	return (error);
}

void
sock_close(socket_t sock)
{
	if (sock == NULL)
		return;

	soclose(sock);
}

/* Do we want this to be APPLE_PRIVATE API?: YES (LD 12/23/04) */
void
sock_retain(socket_t sock)
{
	if (sock == NULL)
		return;

	socket_lock(sock, 1);
	sock->so_retaincnt++;
	sock->so_usecount++;	/* add extra reference for holding the socket */
	socket_unlock(sock, 1);
}

/* Do we want this to be APPLE_PRIVATE API? */
void
sock_release(socket_t sock)
{
	if (sock == NULL)
		return;

	socket_lock(sock, 1);
	if (sock->so_upcallusecount > 0)
		soclose_wait_locked(sock);

	sock->so_retaincnt--;
	if (sock->so_retaincnt < 0) {
		panic("%s: negative retain count (%d) for sock=%p\n",
		    __func__, sock->so_retaincnt, sock);
		/* NOTREACHED */
	}
	if ((sock->so_retaincnt == 0) && (sock->so_usecount == 2)) {
		/* close socket only if the FD is not holding it */
		soclose_locked(sock);
	} else {
		/* remove extra reference holding the socket */
		sock->so_usecount--;
	}
	socket_unlock(sock, 1);
}

errno_t
sock_setpriv(socket_t sock, int on)
{
	if (sock == NULL)
		return (EINVAL);

	socket_lock(sock, 1);
	if (on)
		sock->so_state |= SS_PRIV;
	else
		sock->so_state &= ~SS_PRIV;
	socket_unlock(sock, 1);
	return (0);
}

int
sock_isconnected(socket_t sock)
{
	int retval;

	socket_lock(sock, 1);
	retval = ((sock->so_state & SS_ISCONNECTED) ? 1 : 0);
	socket_unlock(sock, 1);
	return (retval);
}

int
sock_isnonblocking(socket_t sock)
{
	int retval;

	socket_lock(sock, 1);
	retval = ((sock->so_state & SS_NBIO) ? 1 : 0);
	socket_unlock(sock, 1);
	return (retval);
}

errno_t
sock_gettype(socket_t sock, int *outDomain, int *outType, int *outProtocol)
{
	socket_lock(sock, 1);
	if (outDomain != NULL)
		*outDomain = SOCK_DOM(sock);
	if (outType != NULL)
		*outType = sock->so_type;
	if (outProtocol != NULL)
		*outProtocol = SOCK_PROTO(sock);
	socket_unlock(sock, 1);
	return (0);
}

/*
 * Return the listening socket of a pre-accepted socket.  It returns the
 * listener (so_head) value of a given socket.  This is intended to be
 * called by a socket filter during a filter attach (sf_attach) callback.
 * The value returned by this routine is safe to be used only in the
 * context of that callback, because we hold the listener's lock across
 * the sflt_initsock() call.
 */
socket_t
sock_getlistener(socket_t sock)
{
	return (sock->so_head);
}

static inline void
sock_set_tcp_stream_priority(socket_t sock)
{
	if ((SOCK_DOM(sock) == PF_INET || SOCK_DOM(sock) == PF_INET6) &&
	    SOCK_TYPE(sock) == SOCK_STREAM) {
		set_tcp_stream_priority(sock);
	}
}

/*
 * Caller must have ensured socket is valid and won't be going away.
 */
void
socket_set_traffic_mgt_flags_locked(socket_t sock, u_int8_t flags)
{
	(void) OSBitOrAtomic8(flags, &sock->so_traffic_mgt_flags);
	sock_set_tcp_stream_priority(sock);
}

void
socket_set_traffic_mgt_flags(socket_t sock, u_int8_t flags)
{
	socket_lock(sock, 1);
	socket_set_traffic_mgt_flags_locked(sock, flags);
	socket_unlock(sock, 1);
}

/*
 * Caller must have ensured socket is valid and won't be going away.
 */
void
socket_clear_traffic_mgt_flags_locked(socket_t sock, u_int8_t flags)
{
	(void) OSBitAndAtomic8(~flags, &sock->so_traffic_mgt_flags);
	sock_set_tcp_stream_priority(sock);
}

void
socket_clear_traffic_mgt_flags(socket_t sock, u_int8_t flags)
{
	socket_lock(sock, 1);
	socket_clear_traffic_mgt_flags_locked(sock, flags);
	socket_unlock(sock, 1);
}


/*
 * Caller must have ensured socket is valid and won't be going away.
 */
errno_t
socket_defunct(struct proc *p, socket_t so, int level)
{
	errno_t retval;

	if (level != SHUTDOWN_SOCKET_LEVEL_DISCONNECT_SVC &&
	    level != SHUTDOWN_SOCKET_LEVEL_DISCONNECT_ALL)
		return (EINVAL);

	socket_lock(so, 1);
	/*
	 * SHUTDOWN_SOCKET_LEVEL_DISCONNECT_SVC level is meant to tear down
	 * all of mDNSResponder IPC sockets, currently those of AF_UNIX; note
	 * that this is an implementation artifact of mDNSResponder.  We do
	 * a quick test against the socket buffers for SB_UNIX, since that
	 * would have been set by unp_attach() at socket creation time.
	 */
	if (level == SHUTDOWN_SOCKET_LEVEL_DISCONNECT_SVC &&
	    (so->so_rcv.sb_flags & so->so_snd.sb_flags & SB_UNIX) != SB_UNIX) {
		socket_unlock(so, 1);
		return (EOPNOTSUPP);
	}
	retval = sosetdefunct(p, so, level, TRUE);
	if (retval == 0)
		retval = sodefunct(p, so, level);
	socket_unlock(so, 1);
	return (retval);
}

static void
sock_setupcalls_common(socket_t sock, sock_upcall rcallback, void *rcontext,
    sock_upcall wcallback, void *wcontext)
{
	if (rcallback != NULL) {
		sock->so_rcv.sb_flags |= SB_UPCALL;
		sock->so_rcv.sb_upcall = rcallback;
		sock->so_rcv.sb_upcallarg = rcontext;
	} else {
		sock->so_rcv.sb_flags &= ~SB_UPCALL;
		sock->so_rcv.sb_upcall = NULL;
		sock->so_rcv.sb_upcallarg = NULL;
	}

	if (wcallback != NULL) {
		sock->so_snd.sb_flags |= SB_UPCALL;
		sock->so_snd.sb_upcall = wcallback;
		sock->so_snd.sb_upcallarg = wcontext;
	} else {
		sock->so_snd.sb_flags &= ~SB_UPCALL;
		sock->so_snd.sb_upcall = NULL;
		sock->so_snd.sb_upcallarg = NULL;
	}
}

errno_t
sock_setupcall(socket_t sock, sock_upcall callback, void *context)
{
	if (sock == NULL)
		return (EINVAL);

	/*
	 * Note that we don't wait for any in progress upcall to complete.
	 * On embedded, sock_setupcall() causes both read and write
	 * callbacks to be set; on desktop, only read callback is set
	 * to maintain legacy KPI behavior.
	 *
	 * The newer sock_setupcalls() KPI should be used instead to set
	 * the read and write callbacks and their respective parameters.
	 */
	socket_lock(sock, 1);
	sock_setupcalls_common(sock, callback, context, NULL, NULL);
	socket_unlock(sock, 1);

	return (0);
}

errno_t
sock_setupcalls(socket_t sock, sock_upcall rcallback, void *rcontext,
    sock_upcall wcallback, void *wcontext)
{
	if (sock == NULL)
		return (EINVAL);

	/*
	 * Note that we don't wait for any in progress upcall to complete.
	 */
	socket_lock(sock, 1);
	sock_setupcalls_common(sock, rcallback, rcontext, wcallback, wcontext);
	socket_unlock(sock, 1);

	return (0);
}

errno_t
sock_catchevents(socket_t sock, sock_evupcall ecallback, void *econtext,
    u_int32_t emask)
{
	if (sock == NULL)
		return (EINVAL);

	/*
	 * Note that we don't wait for any in progress upcall to complete.
	 */
	socket_lock(sock, 1);
	if (ecallback != NULL) {
		sock->so_event = ecallback;
		sock->so_eventarg = econtext;
		sock->so_eventmask = emask;
	} else {
		sock->so_event = sonullevent;
		sock->so_eventarg = NULL;
		sock->so_eventmask = 0;
	}
	socket_unlock(sock, 1);

	return (0);
}

/*
 * Returns true whether or not a socket belongs to the kernel.
 */
int
sock_iskernel(socket_t so)
{
	return (so && so->last_pid == 0);
}
