/*	$KAME: keysock.c,v 1.13 2000/03/25 07:24:13 sumikawa Exp $	*/

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

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include "opt_inet.h"
#endif

/* This code has derived from sys/net/rtsock.c on FreeBSD2.2.5 */

#if defined(__NetBSD__) || defined (__APPLE__)
# ifdef _KERNEL
#  define KERNEL
# endif
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#if defined(__FreeBSD__) || defined (__APPLE__)
#include <sys/sysctl.h>
#endif
#include <sys/mbuf.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3 || defined (__APPLE__)
#include <sys/malloc.h>
#endif
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/errno.h>
#ifdef __NetBSD__
#include <sys/proc.h>
#include <sys/queue.h>
#endif

#ifdef __FreeBSD__
#if __FreeBSD__ >= 3
#include <machine/ipl.h>
#else
#include <machine/spl.h>
#endif
#endif

#include <net/raw_cb.h>
#include <net/route.h>

#include <net/pfkeyv2.h>
#include <netkey/keydb.h>
#include <netkey/key.h>
#include <netkey/keysock.h>
#include <netkey/key_debug.h>


struct sockaddr key_dst = { 2, PF_KEY, };
struct sockaddr key_src = { 2, PF_KEY, };
struct sockproto key_proto = { PF_KEY, PF_KEY_V2 };

static int key_sendup0 __P((struct rawcb *, struct mbuf *, int));

struct pfkeystat pfkeystat;

#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3) && !defined(__APPLE__)
/*
 * key_usrreq()
 * derived from net/rtsock.c:route_usrreq()
 */
#ifndef __NetBSD__
int
key_usrreq(so, req, m, nam, control)
	register struct socket *so;
	int req;
	struct mbuf *m, *nam, *control;
#else
int
key_usrreq(so, req, m, nam, control, p)
	register struct socket *so;
	int req;
	struct mbuf *m, *nam, *control;
	struct proc *p;
#endif /*__NetBSD__*/
{
	register int error = 0;
	register struct keycb *kp = (struct keycb *)sotorawcb(so);
	int s;

#ifdef __NetBSD__
	s = splsoftnet();
#else
	s = splnet();
#endif
	if (req == PRU_ATTACH) {
		kp = (struct keycb *)_MALLOC(sizeof(*kp), M_PCB, M_WAITOK);
		so->so_pcb = (caddr_t)kp;
		if (so->so_pcb)
			bzero(so->so_pcb, sizeof(*kp));
	}
	if (req == PRU_DETACH && kp) {
		int af = kp->kp_raw.rcb_proto.sp_protocol;
		if (af == PF_KEY) /* XXX: AF_KEY */
			key_cb.key_count--;
		key_cb.any_count--;

		key_freereg(so);
	}

#ifndef __NetBSD__
	error = raw_usrreq(so, req, m, nam, control);
#else
	error = raw_usrreq(so, req, m, nam, control, p);
#endif
	m = control = NULL;	/* reclaimed in raw_usrreq */
	kp = (struct keycb *)sotorawcb(so);
	if (req == PRU_ATTACH && kp) {
		int af = kp->kp_raw.rcb_proto.sp_protocol;
		if (error) {
#if IPSEC_DEBUG
			printf("key_usrreq: key_usrreq results %d\n", error);
#endif
			pfkeystat.sockerr++;
			_FREE((caddr_t)kp, M_PCB);
			so->so_pcb = (caddr_t) 0;
			splx(s);
			return(error);
		}

		kp->kp_promisc = kp->kp_registered = 0;

		if (af == PF_KEY) /* XXX: AF_KEY */
			key_cb.key_count++;
		key_cb.any_count++;
#ifndef __bsdi__
		kp->kp_raw.rcb_laddr = &key_src;
		kp->kp_raw.rcb_faddr = &key_dst;
#else
		/*
		 * XXX rcb_faddr must be dynamically allocated, otherwise
		 * raw_disconnect() will be angry.
		 */
	    {
		struct mbuf *m, *n;
		MGET(m, M_WAITOK, MT_DATA);
		if (!m) {
			error = ENOBUFS;
			pfkeystat.in_nomem++;
			_FREE((caddr_t)kp, M_PCB);
			so->so_pcb = (caddr_t) 0;
			splx(s);
			return(error);
		}
		MGET(n, M_WAITOK, MT_DATA);
		if (!n) {
			error = ENOBUFS;
			m_freem(m);
			pfkeystat.in_nomem++;
			_FREE((caddr_t)kp, M_PCB);
			so->so_pcb = (caddr_t) 0;
			splx(s);
			return(error);
		}
		m->m_len = sizeof(key_src);
		kp->kp_raw.rcb_laddr = mtod(m, struct sockaddr *);
		bcopy(&key_src, kp->kp_raw.rcb_laddr, sizeof(key_src));
		n->m_len = sizeof(key_dst);
		kp->kp_raw.rcb_faddr = mtod(n, struct sockaddr *);
		bcopy(&key_dst, kp->kp_raw.rcb_faddr, sizeof(key_dst));
	    }
#endif
		soisconnected(so);
		so->so_options |= SO_USELOOPBACK;
	}
	splx(s);
	return(error);
}
#endif /* other than FreeBSD >= 3 */

/*
 * key_output()
 */
int
key_output(m, so)
	register struct mbuf *m;
	struct socket *so;
{
	struct sadb_msg *msg = NULL;
	int len, error = 0;
	int s;
	int target;

	if (m == 0)
		panic("key_output: NULL pointer was passed.\n");

	pfkeystat.out_total++;
	pfkeystat.out_bytes += m->m_pkthdr.len;

	len = m->m_pkthdr.len;
	if (len < sizeof(struct sadb_msg)) {
#if IPSEC_DEBUG
		printf("key_output: Invalid message length.\n");
#endif
		pfkeystat.out_tooshort++;
		error = EINVAL;
		goto end;
	}

	if (m->m_len < sizeof(struct sadb_msg)) {
		if ((m = m_pullup(m, sizeof(struct sadb_msg))) == 0) {
#if IPSEC_DEBUG
			printf("key_output: can't pullup mbuf\n");
#endif
			pfkeystat.out_nomem++;
			error = ENOBUFS;
			goto end;
		}
	}

	if ((m->m_flags & M_PKTHDR) == 0)
		panic("key_output: not M_PKTHDR ??");

#if defined(IPSEC_DEBUG)
	KEYDEBUG(KEYDEBUG_KEY_DUMP, kdebug_mbuf(m));
#endif /* defined(IPSEC_DEBUG) */

	msg = mtod(m, struct sadb_msg *);
	pfkeystat.out_msgtype[msg->sadb_msg_type]++;
	if (len != PFKEY_UNUNIT64(msg->sadb_msg_len)) {
#if IPSEC_DEBUG
		printf("key_output: Invalid message length.\n");
#endif
		pfkeystat.out_invlen++;
		error = EINVAL;
		goto end;
	}

	/*
	 * allocate memory for sadb_msg, and copy to sadb_msg from mbuf
	 * XXX: To be processed directly without a copy.
	 */
	msg = (struct sadb_msg *)_MALLOC(len, M_SECA, M_NOWAIT);
	if (msg == NULL) {
#if IPSEC_DEBUG
		printf("key_output: No more memory.\n");
#endif
		error = ENOBUFS;
		pfkeystat.out_nomem++;
		goto end;
		/* or do panic ? */
	}
	m_copydata(m, 0, len, (caddr_t)msg);

	/*XXX giant lock*/
#ifdef __NetBSD__
	s = splsoftnet();
#else
	s = splnet();
#endif
	if ((len = key_parse(&msg, so, &target)) == 0) {
		/* discard. i.e. no need to reply. */
		/* msg has been freed at key_parse() */
		error = 0;
		splx(s);
		goto end;
	}

	/* send up message to the socket */
	error = key_sendup(so, msg, len, target);
	splx(s);
	_FREE(msg, M_SECA);
end:
	m_freem(m);
	return (error);
}

/*
 * send message to the socket.
 */
static int
key_sendup0(rp, m, promisc)
	struct rawcb *rp;
	struct mbuf *m;
	int promisc;
{
	if (promisc) {
		struct sadb_msg *pmsg;

		M_PREPEND(m, sizeof(struct sadb_msg), M_NOWAIT);
		if (m && m->m_len < sizeof(struct sadb_msg))
			m = m_pullup(m, sizeof(struct sadb_msg));
		if (!m) {
#if IPSEC_DEBUG
			printf("key_sendup0: cannot pullup\n");
#endif
		pfkeystat.in_nomem++;
			m_freem(m);
			return ENOBUFS;
		}
		m->m_pkthdr.len += sizeof(*pmsg);

		pmsg = mtod(m, struct sadb_msg *);
		bzero(pmsg, sizeof(*pmsg));
		pmsg->sadb_msg_version = PF_KEY_V2;
		pmsg->sadb_msg_type = SADB_X_PROMISC;
		pmsg->sadb_msg_len = PFKEY_UNIT64(m->m_pkthdr.len);
		/* pid and seq? */

		pfkeystat.in_msgtype[pmsg->sadb_msg_type]++;
	}

	if (!sbappendaddr(&rp->rcb_socket->so_rcv,
			(struct sockaddr *)&key_src, m, NULL)) {
#if IPSEC_DEBUG
		printf("key_sendup0: sbappendaddr failed\n");
#endif
		pfkeystat.in_nomem++;
		m_freem(m);
		return ENOBUFS;
	}
	sorwakeup(rp->rcb_socket);
	return 0;
}

/* XXX this interface should be obsoleted. */
int
key_sendup(so, msg, len, target)
	struct socket *so;
	struct sadb_msg *msg;
	u_int len;
	int target;	/*target of the resulting message*/
{
	struct mbuf *m, *n, *mprev;
	int tlen;

	/* sanity check */
	if (so == 0 || msg == 0)
		panic("key_sendup: NULL pointer was passed.\n");

	KEYDEBUG(KEYDEBUG_KEY_DUMP,
		printf("key_sendup: \n");
		kdebug_sadb(msg));

	/*
	 * we increment statistics here, just in case we have ENOBUFS
	 * in this function.
	 */
	pfkeystat.in_total++;
	pfkeystat.in_bytes += len;
	pfkeystat.in_msgtype[msg->sadb_msg_type]++;

	/*
	 * Get mbuf chain whenever possible (not clusters),
	 * to save socket buffer.  We'll be generating many SADB_ACQUIRE
	 * messages to listening key sockets.  If we simmply allocate clusters,
	 * sbappendaddr() will raise ENOBUFS due to too little sbspace().
	 * sbspace() computes # of actual data bytes AND mbuf region.
	 *
	 * TODO: SADB_ACQUIRE filters should be implemented.
	 */
	tlen = len;
	m = mprev = NULL;
	while (tlen > 0) {
		if (tlen == len) {
			MGETHDR(n, M_DONTWAIT, MT_DATA);
			n->m_len = MHLEN;
		} else {
			MGET(n, M_DONTWAIT, MT_DATA);
			n->m_len = MLEN;
		}
		if (!n) {
			pfkeystat.in_nomem++;
			return ENOBUFS;
		}
		if (tlen >= MCLBYTES) {	/*XXX better threshold? */
			MCLGET(n, M_DONTWAIT);
			if ((n->m_flags & M_EXT) == 0) {
				m_free(n);
				m_freem(m);
				pfkeystat.in_nomem++;
				return ENOBUFS;
			}
			n->m_len = MCLBYTES;
		}

		if (tlen < n->m_len)
			n->m_len = tlen;
		n->m_next = NULL;
		if (m == NULL)
			m = mprev = n;
		else {
			mprev->m_next = n;
			mprev = n;
		}
		tlen -= n->m_len;
		n = NULL;
	}
	m->m_pkthdr.len = len;
	m->m_pkthdr.rcvif = NULL;
	m_copyback(m, 0, len, (caddr_t)msg);

	/* avoid duplicated statistics */
	pfkeystat.in_total--;
	pfkeystat.in_bytes -= len;
	pfkeystat.in_msgtype[msg->sadb_msg_type]--;

	return key_sendup_mbuf(so, m, target);
}

int
key_sendup_mbuf(so, m, target)
	struct socket *so;
	struct mbuf *m;
	int target;
{
	struct mbuf *n;
	struct keycb *kp;
	int sendup;
	struct rawcb *rp;
	int error;

	if (so == NULL || m == NULL)
		panic("key_sendup_mbuf: NULL pointer was passed.\n");

	pfkeystat.in_total++;
	pfkeystat.in_bytes += m->m_pkthdr.len;
	if (m->m_len < sizeof(struct sadb_msg)) {
#if 1
		m = m_pullup(m, sizeof(struct sadb_msg));
		if (m == NULL) {
			pfkeystat.in_nomem++;
			return ENOBUFS;
		}
#else
		/* don't bother pulling it up just for stats */
#endif
	}
	if (m->m_len >= sizeof(struct sadb_msg)) {
		struct sadb_msg *msg;
		msg = mtod(m, struct sadb_msg *);
		pfkeystat.in_msgtype[msg->sadb_msg_type]++;
	}

#ifdef __NetBSD__
	for (rp = rawcb.lh_first; rp; rp = rp->rcb_list.le_next)
#elif defined(__FreeBSD__) && __FreeBSD__ >= 3 || defined (__APPLE__)
	LIST_FOREACH(rp, &rawcb_list, list)
#else
	for (rp = rawcb.rcb_next; rp != &rawcb; rp = rp->rcb_next)
#endif
	{
		if (rp->rcb_proto.sp_family != PF_KEY)
			continue;
		if (rp->rcb_proto.sp_protocol
		 && rp->rcb_proto.sp_protocol != PF_KEY_V2) {
			continue;
		}

		kp = (struct keycb *)rp;

		/*
		 * If you are in promiscuous mode, and when you get broadcasted
		 * reply, you'll get two PF_KEY messages.
		 * (based on pf_key@inner.net message on 14 Oct 1998)
		 */
		if (((struct keycb *)rp)->kp_promisc) {
			if ((n = m_copy(m, 0, (int)M_COPYALL)) != NULL) {
				(void)key_sendup0(rp, n, 1);
				n = NULL;
			}
		}

		/* the exact target will be processed later */
		if (sotorawcb(so) == rp)
			continue;

		sendup = 0;
		switch (target) {
		case KEY_SENDUP_ONE:
			/* the statement has no effect */
			if (sotorawcb(so) == rp)
				sendup++;
			break;
		case KEY_SENDUP_ALL:
			sendup++;
			break;
		case KEY_SENDUP_REGISTERED:
			if (kp->kp_registered)
				sendup++;
			break;
		}
		pfkeystat.in_msgtarget[target]++;

		if (!sendup)
			continue;

		if ((n = m_copy(m, 0, (int)M_COPYALL)) == NULL) {
#if IPSEC_DEBUG
			printf("key_sendup: m_copy fail\n");
#endif
			m_freem(m);
			pfkeystat.in_nomem++;
			return ENOBUFS;
		}

		if ((error = key_sendup0(rp, n, 0)) != 0) {
			m_freem(m);
			return error;
		}

		n = NULL;
	}

	error = key_sendup0(sotorawcb(so), m, 0);
	m = NULL;
	return error;
}

#if defined(__FreeBSD__) && __FreeBSD__ >= 3 || defined (__APPLE__)
/*
 * key_abort()
 * derived from net/rtsock.c:rts_abort()
 */
static int
key_abort(struct socket *so)
{
	int s, error;
	s = splnet();
	error = raw_usrreqs.pru_abort(so);
	splx(s);
	return error;
}

/*
 * key_attach()
 * derived from net/rtsock.c:rts_attach()
 */
static int
key_attach(struct socket *so, int proto, struct proc *p)
{
	struct keycb *kp;
	int s, error;

	if (sotorawcb(so) != 0)
		return EISCONN;	/* XXX panic? */
	kp = (struct keycb *)_MALLOC(sizeof *kp, M_PCB, M_WAITOK); /* XXX */
	if (kp == 0)
		return ENOBUFS;
	bzero(kp, sizeof *kp);

	/*
	 * The splnet() is necessary to block protocols from sending
	 * error notifications (like RTM_REDIRECT or RTM_LOSING) while
	 * this PCB is extant but incompletely initialized.
	 * Probably we should try to do more of this work beforehand and
	 * eliminate the spl.
	 */
	s = splnet();
	so->so_pcb = (caddr_t)kp;
	error = raw_usrreqs.pru_attach(so, proto, p);
	kp = (struct keycb *)sotorawcb(so);
	if (error) {
		_FREE(kp, M_PCB);
		so->so_pcb = (caddr_t) 0;
		splx(s);
		printf("key_usrreq: key_usrreq results %d\n", error);
		return error;
	}

	kp->kp_promisc = kp->kp_registered = 0;

	if (kp->kp_raw.rcb_proto.sp_protocol == PF_KEY) /* XXX: AF_KEY */
		key_cb.key_count++;
	key_cb.any_count++;
	kp->kp_raw.rcb_laddr = &key_src;
	kp->kp_raw.rcb_faddr = &key_dst;
	soisconnected(so);
	so->so_options |= SO_USELOOPBACK;

	splx(s);
	return 0;
}

/*
 * key_bind()
 * derived from net/rtsock.c:rts_bind()
 */
static int
key_bind(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	int s, error;
	s = splnet();
	error = raw_usrreqs.pru_bind(so, nam, p); /* xxx just EINVAL */
	splx(s);
	return error;
}

/*
 * key_connect()
 * derived from net/rtsock.c:rts_connect()
 */
static int
key_connect(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	int s, error;
	s = splnet();
	error = raw_usrreqs.pru_connect(so, nam, p); /* XXX just EINVAL */
	splx(s);
	return error;
}

/*
 * key_detach()
 * derived from net/rtsock.c:rts_detach()
 */
static int
key_detach(struct socket *so)
{
	struct keycb *kp = (struct keycb *)sotorawcb(so);
	int s, error;

	s = splnet();
	if (kp != 0) {
		if (kp->kp_raw.rcb_proto.sp_protocol
		    == PF_KEY) /* XXX: AF_KEY */
			key_cb.key_count--;
		key_cb.any_count--;

		key_freereg(so);
	}
	error = raw_usrreqs.pru_detach(so);
	splx(s);
	return error;
}

/*
 * key_disconnect()
 * derived from net/rtsock.c:key_disconnect()
 */
static int
key_disconnect(struct socket *so)
{
	int s, error;
	s = splnet();
	error = raw_usrreqs.pru_disconnect(so);
	splx(s);
	return error;
}

/*
 * key_peeraddr()
 * derived from net/rtsock.c:rts_peeraddr()
 */
static int
key_peeraddr(struct socket *so, struct sockaddr **nam)
{
	int s, error;
	s = splnet();
	error = raw_usrreqs.pru_peeraddr(so, nam);
	splx(s);
	return error;
}

/*
 * key_send()
 * derived from net/rtsock.c:rts_send()
 */
static int
key_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *nam,
	 struct mbuf *control, struct proc *p)
{
	int s, error;
	s = splnet();
	error = raw_usrreqs.pru_send(so, flags, m, nam, control, p);
	splx(s);
	return error;
}

/*
 * key_shutdown()
 * derived from net/rtsock.c:rts_shutdown()
 */
static int
key_shutdown(struct socket *so)
{
	int s, error;
	s = splnet();
	error = raw_usrreqs.pru_shutdown(so);
	splx(s);
	return error;
}

/*
 * key_sockaddr()
 * derived from net/rtsock.c:rts_sockaddr()
 */
static int
key_sockaddr(struct socket *so, struct sockaddr **nam)
{
	int s, error;
	s = splnet();
	error = raw_usrreqs.pru_sockaddr(so, nam);
	splx(s);
	return error;
}

struct pr_usrreqs key_usrreqs = {
	key_abort, pru_accept_notsupp, key_attach, key_bind,
	key_connect,
	pru_connect2_notsupp, pru_control_notsupp, key_detach,
	key_disconnect, pru_listen_notsupp, key_peeraddr,
	pru_rcvd_notsupp,
	pru_rcvoob_notsupp, key_send, pru_sense_null, key_shutdown,
	key_sockaddr, sosend, soreceive, sopoll
};
#endif /* __FreeBSD__ >= 3 */

#if __FreeBSD__ || defined (__APPLE__)
/* sysctl */
SYSCTL_NODE(_net, PF_KEY, key, CTLFLAG_RW, 0, "Key Family");
#endif

/*
 * Definitions of protocols supported in the KEY domain.
 */

extern struct domain keydomain;

struct protosw keysw[] = {
{ SOCK_RAW,	&keydomain,	PF_KEY_V2,	PR_ATOMIC|PR_ADDR,
  0,		key_output,	raw_ctlinput,	0,
  0,
  raw_init,	0,		0,		0,
  0, &key_usrreqs
}
};

struct domain keydomain =
    { PF_KEY, "key", key_init, 0, 0,
      keysw, 0,
      0,0,
      sizeof(struct key_cb), 0
    };

DOMAIN_SET(key);
