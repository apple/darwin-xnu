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
 * Copyright (c) 1980, 1986, 1993
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
 *	@(#)raw_usrreq.c	8.1 (Berkeley) 6/10/93
 * $FreeBSD: src/sys/net/raw_usrreq.c,v 1.18 1999/08/28 00:48:28 peter Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>

#include <net/raw_cb.h>

/*
 * Initialize raw connection block q.
 */
void
raw_init()
{
	LIST_INIT(&rawcb_list);
}


/*
 * Raw protocol input routine.  Find the socket
 * associated with the packet(s) and move them over.  If
 * nothing exists for this packet, drop it.
 */
/*
 * Raw protocol interface.
 */
void
raw_input(m0, proto, src, dst)
	struct mbuf *m0;
	register struct sockproto *proto;
	struct sockaddr *src, *dst;
{
	register struct rawcb *rp;
	register struct mbuf *m = m0;
	register int sockets = 0;
	struct socket *last;

	last = 0;
	LIST_FOREACH(rp, &rawcb_list, list) {
		if (rp->rcb_proto.sp_family != proto->sp_family)
			continue;
		if (rp->rcb_proto.sp_protocol  &&
		    rp->rcb_proto.sp_protocol != proto->sp_protocol)
			continue;
		/*
		 * We assume the lower level routines have
		 * placed the address in a canonical format
		 * suitable for a structure comparison.
		 *
		 * Note that if the lengths are not the same
		 * the comparison will fail at the first byte.
		 */
#define	equal(a1, a2) \
  (bcmp((caddr_t)(a1), (caddr_t)(a2), a1->sa_len) == 0)
		if (rp->rcb_laddr && !equal(rp->rcb_laddr, dst))
			continue;
		if (rp->rcb_faddr && !equal(rp->rcb_faddr, src))
			continue;
		if (last) {
			struct mbuf *n;
			n = m_copy(m, 0, (int)M_COPYALL);
			if (n) {
				if (sbappendaddr(&last->so_rcv, src,
				    n, (struct mbuf *)0) == 0)
					/* should notify about lost packet */
					m_freem(n);
				else {
					sorwakeup(last);
					sockets++;
				}
			}
		}
		last = rp->rcb_socket;
	}
	if (last) {
		if (sbappendaddr(&last->so_rcv, src,
		    m, (struct mbuf *)0) == 0)
			m_freem(m);
		else {
			sorwakeup(last);
			sockets++;
		}
	} else
		m_freem(m);
}

/*ARGSUSED*/
void
raw_ctlinput(cmd, arg, dummy)
	int cmd;
	struct sockaddr *arg;
	void *dummy;
{

	if (cmd < 0 || cmd > PRC_NCMDS)
		return;
	/* INCOMPLETE */
}

static int
raw_uabort(struct socket *so)
{
	struct rawcb *rp = sotorawcb(so);

	if (rp == 0)
		return EINVAL;
	raw_disconnect(rp);
	sofree(so);
	soisdisconnected(so);
	return 0;
}

/* pru_accept is EOPNOTSUPP */

static int
raw_uattach(struct socket *so, int proto, struct proc *p)
{
	struct rawcb *rp = sotorawcb(so);
	int error;

	if (rp == 0)
		return EINVAL;
#ifdef __APPLE__
		if ((so->so_state & SS_PRIV) == 0)
			return (EPERM);
#else
	if (p && (error = suser(p)) != 0)
		return error;
#endif
	return raw_attach(so, proto);
}

static int
raw_ubind(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	return EINVAL;
}

static int
raw_uconnect(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	return EINVAL;
}

/* pru_connect2 is EOPNOTSUPP */
/* pru_control is EOPNOTSUPP */

static int
raw_udetach(struct socket *so)
{
	struct rawcb *rp = sotorawcb(so);

	if (rp == 0)
		return EINVAL;

	raw_detach(rp);
	return 0;
}

static int
raw_udisconnect(struct socket *so)
{
	struct rawcb *rp = sotorawcb(so);

	if (rp == 0)
		return EINVAL;
	if (rp->rcb_faddr == 0) {
		return ENOTCONN;
	}
	raw_disconnect(rp);
	soisdisconnected(so);
	return 0;
}

/* pru_listen is EOPNOTSUPP */

static int
raw_upeeraddr(struct socket *so, struct sockaddr **nam)
{
	struct rawcb *rp = sotorawcb(so);

	if (rp == 0)
		return EINVAL;
	if (rp->rcb_faddr == 0) {
		return ENOTCONN;
	}
	*nam = dup_sockaddr(rp->rcb_faddr, 1);
	return 0;
}

/* pru_rcvd is EOPNOTSUPP */
/* pru_rcvoob is EOPNOTSUPP */

static int
raw_usend(struct socket *so, int flags, struct mbuf *m,
	  struct sockaddr *nam, struct mbuf *control, struct proc *p)
{
	int error;
	struct rawcb *rp = sotorawcb(so);

	if (rp == 0) {
		error = EINVAL;
		goto release;
	}

	if (flags & PRUS_OOB) {
		error = EOPNOTSUPP;
		goto release;
	}

	if (control && control->m_len) {
		error = EOPNOTSUPP;
		goto release;
	}
	if (nam) {
		if (rp->rcb_faddr) {
			error = EISCONN;
			goto release;
		}
		rp->rcb_faddr = nam;
	} else if (rp->rcb_faddr == 0) {
		error = ENOTCONN;
		goto release;
	}
	error = (*so->so_proto->pr_output)(m, so);
	m = NULL;
	if (nam)
		rp->rcb_faddr = 0;
release:
	if (m != NULL)
		m_freem(m);
	return (error);
}

/* pru_sense is null */

static int
raw_ushutdown(struct socket *so)
{
	struct rawcb *rp = sotorawcb(so);

	if (rp == 0)
		return EINVAL;
	socantsendmore(so);
	return 0;
}

static int
raw_usockaddr(struct socket *so, struct sockaddr **nam)
{
	struct rawcb *rp = sotorawcb(so);

	if (rp == 0)
		return EINVAL;
	if (rp->rcb_laddr == 0)
		return EINVAL;
	*nam = dup_sockaddr(rp->rcb_laddr, 1);
	return 0;
}

struct pr_usrreqs raw_usrreqs = {
	raw_uabort, pru_accept_notsupp, raw_uattach, raw_ubind, raw_uconnect,
	pru_connect2_notsupp, pru_control_notsupp, raw_udetach, 
	raw_udisconnect, pru_listen_notsupp, raw_upeeraddr, pru_rcvd_notsupp,
	pru_rcvoob_notsupp, raw_usend, pru_sense_null, raw_ushutdown,
	raw_usockaddr, sosend, soreceive, sopoll
};
