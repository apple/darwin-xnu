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
 * Copyright (c) 1992, 1993
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
 *	@(#)idrp_usrreq.c	8.1 (Berkeley) 6/10/93
 */

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/errno.h>

#include <net/route.h>
#include <net/if.h>

#include <netiso/argo_debug.h>
#include <netiso/iso.h>
#include <netiso/clnp.h>
#include <netiso/clnl.h>
#include <netiso/iso_pcb.h>
#include <netiso/iso_var.h>

int idrp_input();
struct	isopcb	idrp_isop;
static	struct	sockaddr_iso idrp_addrs[2] =
{  { sizeof(idrp_addrs), AF_ISO, }, { sizeof(idrp_addrs[1]), AF_ISO, } };
/*
 * IDRP initialization
 */
idrp_init()
{
	extern struct clnl_protosw clnl_protox[256];

	idrp_isop.isop_next = idrp_isop.isop_prev = &idrp_isop;
	idrp_isop.isop_faddr = &idrp_isop.isop_sfaddr;
	idrp_isop.isop_laddr = &idrp_isop.isop_sladdr;
	idrp_isop.isop_sladdr = idrp_addrs[1];
	idrp_isop.isop_sfaddr = idrp_addrs[1];
	clnl_protox[ISO10747_IDRP].clnl_input = idrp_input;
}

/*
 * CALLED FROM:
 * 	tpclnp_input().
 * FUNCTION and ARGUMENTS:
 * Take a packet (m) from clnp, strip off the clnp header
 * and mke suitable for the idrp socket.
 * No return value.  
 */
idrp_input(m, src, dst)
	register struct mbuf *m;
	struct sockaddr_iso *src, *dst;
{
	if (idrp_isop.isop_socket == 0) {
	bad:	m_freem(m);
		return 0;
	}
	bzero(idrp_addrs[0].siso_data, sizeof(idrp_addrs[0].siso_data));
	bcopy((caddr_t)&(src->siso_addr), (caddr_t)&idrp_addrs[0].siso_addr,
		1 + src->siso_nlen);
	bzero(idrp_addrs[1].siso_data, sizeof(idrp_addrs[1].siso_data));
	bcopy((caddr_t)&(dst->siso_addr), (caddr_t)&idrp_addrs[1].siso_addr,
		1 + dst->siso_nlen);
	if (sbappendaddr(&idrp_isop.isop_socket->so_rcv,
		(struct sockaddr *)idrp_addrs, m, (struct mbuf *)0) == 0)
		goto bad;
	sorwakeup(idrp_isop.isop_socket);
	return 0;
}

idrp_output(m, addr)
	struct mbuf *m, *addr;
{
	register struct sockaddr_iso *siso = mtod(addr, struct sockaddr_iso *);
	int s = splnet(), i;

	bcopy((caddr_t)&(siso->siso_addr),
	      (caddr_t)&idrp_isop.isop_sfaddr.siso_addr, 1 + siso->siso_nlen);
	siso++;
	bcopy((caddr_t)&(siso->siso_addr),
	      (caddr_t)&idrp_isop.isop_sladdr.siso_addr, 1 + siso->siso_nlen);
	i = clnp_output(m, idrp_isop, m->m_pkthdr.len, 0);
	splx(s);
	return (i);
}

u_long	idrp_sendspace = 3072;		/* really max datagram size */
u_long	idrp_recvspace = 40 * 1024;	/* 40 1K datagrams */

/*ARGSUSED*/
idrp_usrreq(so, req, m, addr, control)
	struct socket *so;
	int req;
	struct mbuf *m, *addr, *control;
{
	int error = 0;

	 /* Note: need to block idrp_input while changing
	 * the udp pcb queue and/or pcb addresses.
	 */
	switch (req) {

	case PRU_ATTACH:
		if (idrp_isop.isop_socket != NULL) {
			error = ENXIO;
			break;
		}
		idrp_isop.isop_socket = so;
		error = soreserve(so, idrp_sendspace, idrp_recvspace);
		break;

	case PRU_SHUTDOWN:
		socantsendmore(so);
		break;

	case PRU_SEND:
		return (idrp_output(m, addr));

	case PRU_ABORT:
		soisdisconnected(so);
	case PRU_DETACH:
		idrp_isop.isop_socket = 0;
		break;


	case PRU_SENSE:
		/*
		 * stat: don't bother with a blocksize.
		 */
		return (0);

	default:
		return (EOPNOTSUPP);	/* do not free mbuf's */
	}

release:
	if (control) {
		printf("idrp control data unexpectedly retained\n");
		m_freem(control);
	}
	if (m)
		m_freem(m);
	return (error);
}
