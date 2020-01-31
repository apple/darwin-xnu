/*
 * Copyright (c) 2000-2012 Apple Inc. All rights reserved.
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
 *	@(#)raw_cb.c	8.1 (Berkeley) 6/10/93
 */

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <kern/locks.h>

#include <net/raw_cb.h>

/*
 * Routines to manage the raw protocol control blocks.
 *
 * TODO:
 *	hash lookups by protocol family/protocol + address family
 *	take care of unique address problems per AF?
 *	redo address binding to allow wildcards
 */

struct rawcb_list_head rawcb_list;

static uint32_t raw_sendspace = RAWSNDQ;
static uint32_t raw_recvspace = RAWRCVQ;
extern lck_mtx_t        *raw_mtx;       /*### global raw cb mutex for now */

/*
 * Allocate a control block and a nominal amount
 * of buffer space for the socket.
 */
int
raw_attach(struct socket *so, int proto)
{
	struct rawcb *rp = sotorawcb(so);
	int error;

	/*
	 * It is assumed that raw_attach is called
	 * after space has been allocated for the
	 * rawcb.
	 */
	if (rp == 0) {
		return ENOBUFS;
	}
	error = soreserve(so, raw_sendspace, raw_recvspace);
	if (error) {
		return error;
	}
	rp->rcb_socket = so;
	rp->rcb_proto.sp_family = SOCK_DOM(so);
	rp->rcb_proto.sp_protocol = proto;
	lck_mtx_lock(raw_mtx);
	LIST_INSERT_HEAD(&rawcb_list, rp, list);
	lck_mtx_unlock(raw_mtx);
	return 0;
}

/*
 * Detach the raw connection block and discard
 * socket resources.
 */
void
raw_detach(struct rawcb *rp)
{
	struct socket *so = rp->rcb_socket;

	so->so_pcb = 0;
	so->so_flags |= SOF_PCBCLEARING;
	sofree(so);
	if (!lck_mtx_try_lock(raw_mtx)) {
		socket_unlock(so, 0);
		lck_mtx_lock(raw_mtx);
		socket_lock(so, 0);
	}
	LIST_REMOVE(rp, list);
	lck_mtx_unlock(raw_mtx);
#ifdef notdef
	if (rp->rcb_laddr) {
		m_freem(dtom(rp->rcb_laddr));
	}
	rp->rcb_laddr = 0;
#endif
	rp->rcb_socket = NULL;
	FREE(rp, M_PCB);
}

/*
 * Disconnect and possibly release resources.
 */
void
raw_disconnect(struct rawcb *rp)
{
	struct socket *so = rp->rcb_socket;

#ifdef notdef
	if (rp->rcb_faddr) {
		m_freem(dtom(rp->rcb_faddr));
	}
	rp->rcb_faddr = 0;
#endif
	/*
	 * A multipath subflow socket would have its SS_NOFDREF set by default,
	 * so check for SOF_MP_SUBFLOW socket flag before detaching the PCB;
	 * when the socket is closed for real, SOF_MP_SUBFLOW would be cleared.
	 */
	if (!(so->so_flags & SOF_MP_SUBFLOW) && (so->so_state & SS_NOFDREF)) {
		raw_detach(rp);
	}
}

#ifdef notdef
#include <sys/mbuf.h>

int
raw_bind(struct socket *so, struct mbuf *nam)
{
	struct sockaddr *addr = mtod(nam, struct sockaddr *);
	struct rawcb *rp;

	if (ifnet == 0) {
		return EADDRNOTAVAIL;
	}
	rp = sotorawcb(so);
	nam = m_copym(nam, 0, M_COPYALL, M_WAITOK);
	if (nam == NULL) {
		return ENOBUFS;
	}
	rp->rcb_laddr = mtod(nam, struct sockaddr *);
	return 0;
}
#endif
