/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <kern/locks.h>

#include <net/raw_cb.h>

lck_mtx_t 	*raw_mtx;	/*### global raw cb mutex for now */
lck_attr_t 	*raw_mtx_attr;
lck_grp_t 	*raw_mtx_grp;
lck_grp_attr_t 	*raw_mtx_grp_attr;
/*
 * Initialize raw connection block q.
 */
void
raw_init(void)
{
	raw_mtx_grp_attr = lck_grp_attr_alloc_init();

	raw_mtx_grp = lck_grp_alloc_init("rawcb", raw_mtx_grp_attr);

	raw_mtx_attr = lck_attr_alloc_init();

	if ((raw_mtx = lck_mtx_alloc_init(raw_mtx_grp, raw_mtx_attr)) == NULL) {
		printf("raw_init: can't alloc raw_mtx\n");
		return;
	}
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
raw_input(struct mbuf *m0, struct sockproto *proto, struct sockaddr *src,
	  struct sockaddr *dst)
{
	struct rawcb *rp;
	struct mbuf *m = m0;
	int sockets = 0;
	struct socket *last;
	int error;

//####LD raw_input is called from many places, input & output path. We have to assume the 
//####LD socket we'll find and need to append to is unlocked.
//####LD calls from the output (locked) path need to make sure the socket is not locked when
//####LD we call in raw_input
	last = NULL;
	lck_mtx_lock(raw_mtx);
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
				socket_lock(last, 1);
				if (sbappendaddr(&last->so_rcv, src,
				    n, (struct mbuf *)0, &error) != 0) {
					sorwakeup(last);
					sockets++;
				}
				socket_unlock(last, 1);
			}
		}
		last = rp->rcb_socket;
	}
	if (last) {
		socket_lock(last, 1);
		if (sbappendaddr(&last->so_rcv, src,
		    m, (struct mbuf *)0, &error) != 0) {
			sorwakeup(last);
			sockets++;
		}
		socket_unlock(last, 1);
	} else
		m_freem(m);
	lck_mtx_unlock(raw_mtx);
}

/*ARGSUSED*/
void
raw_ctlinput(int cmd, __unused struct sockaddr *arg, __unused void *dummy)
{

	if (cmd < 0 || cmd > PRC_NCMDS)
		return;
	/* INCOMPLETE */
}

static int
raw_uabort(struct socket *so)
{
	struct rawcb *rp = sotorawcb(so);

	lck_mtx_t * mutex_held;
	if (so->so_proto->pr_getlock != NULL)
		mutex_held = (*so->so_proto->pr_getlock)(so, 0);
	else
		mutex_held = so->so_proto->pr_domain->dom_mtx;
	lck_mtx_assert(mutex_held, LCK_MTX_ASSERT_OWNED);

	if (rp == 0)
		return EINVAL;
	raw_disconnect(rp);
	sofree(so);
	soisdisconnected(so);
	return 0;
}

/* pru_accept is EOPNOTSUPP */

static int
raw_uattach(struct socket *so, int proto, __unused struct proc *p)
{
	struct rawcb *rp = sotorawcb(so);

	if (rp == 0)
		return EINVAL;
		if ((so->so_state & SS_PRIV) == 0)
			return (EPERM);
	return raw_attach(so, proto);
}

static int
raw_ubind(__unused struct socket *so, __unused struct sockaddr *nam, __unused struct proc *p)
{
	return EINVAL;
}

static int
raw_uconnect(__unused struct socket *so, __unused struct sockaddr *nam, __unused struct proc *p)
{
	return EINVAL;
}

/* pru_connect2 is EOPNOTSUPP */
/* pru_control is EOPNOTSUPP */

static int
raw_udetach(struct socket *so)
{
	struct rawcb *rp = sotorawcb(so);

	lck_mtx_t * mutex_held;
	if (so->so_proto->pr_getlock != NULL)
		mutex_held = (*so->so_proto->pr_getlock)(so, 0);
	else
		mutex_held = so->so_proto->pr_domain->dom_mtx;
	lck_mtx_assert(mutex_held, LCK_MTX_ASSERT_OWNED);
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
	  struct sockaddr *nam, struct mbuf *control, __unused struct proc *p)
{
	int error;
	struct rawcb *rp = sotorawcb(so);

	lck_mtx_t * mutex_held;
	if (so->so_proto->pr_getlock != NULL)
		mutex_held = (*so->so_proto->pr_getlock)(so, 0);
	else
		mutex_held = so->so_proto->pr_domain->dom_mtx;
	lck_mtx_assert(mutex_held, LCK_MTX_ASSERT_OWNED);

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
		rp->rcb_faddr = NULL;
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
	lck_mtx_t * mutex_held;
	if (so->so_proto->pr_getlock != NULL)
		mutex_held = (*so->so_proto->pr_getlock)(so, 0);
	else
		mutex_held = so->so_proto->pr_domain->dom_mtx;
	lck_mtx_assert(mutex_held, LCK_MTX_ASSERT_OWNED);

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
	raw_usockaddr, sosend, soreceive, pru_sopoll_notsupp
};
