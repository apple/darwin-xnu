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
 * Copyright (c) University of British Columbia, 1984
 * Copyright (C) Computer Science Department IV, 
 * 		 University of Erlangen-Nuremberg, Germany, 1992
 * Copyright (c) 1991, 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by the
 * Laboratory for Computation Vision and the Computer Science Department
 * of the the University of British Columbia and the Computer Science
 * Department (IV) of the University of Erlangen-Nuremberg, Germany.
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
 *	@(#)pk_subr.c	8.1 (Berkeley) 6/10/93
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/protosw.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/malloc.h>

#include <net/if.h>
#include <net/route.h>

#include <netccitt/dll.h>
#include <netccitt/x25.h>
#include <netccitt/x25err.h>
#include <netccitt/pk.h>
#include <netccitt/pk_var.h>

int     pk_sendspace = 1024 * 2 + 8;
int     pk_recvspace = 1024 * 2 + 8;

struct pklcd_q pklcd_q = {&pklcd_q, &pklcd_q};

struct x25bitslice x25_bitslice[] = {
/*	  mask, shift value */
	{ 0xf0, 0x4 },
	{ 0xf,  0x0 },
	{ 0x80, 0x7 },
	{ 0x40, 0x6 },
	{ 0x30, 0x4 },
	{ 0xe0, 0x5 },
	{ 0x10, 0x4 },
	{ 0xe,  0x1 },
	{ 0x1,  0x0 }
};


/* 
 *  Attach X.25 protocol to socket, allocate logical channel descripter
 *  and buffer space, and enter LISTEN state if we are to accept
 *  IN-COMMING CALL packets.  
 *
 */

struct pklcd *
pk_attach (so)
struct socket *so;
{
	register struct pklcd *lcp;
	register int error = ENOBUFS;
	int pk_output ();

	MALLOC(lcp, struct pklcd *, sizeof (*lcp), M_PCB, M_NOWAIT);
	if (lcp) {
		bzero ((caddr_t)lcp, sizeof (*lcp));
		insque (&lcp -> lcd_q, &pklcd_q);
		lcp -> lcd_state = READY;
		lcp -> lcd_send = pk_output;
		if (so) {
			error = soreserve (so, pk_sendspace, pk_recvspace);
			lcp -> lcd_so = so;
			if (so -> so_options & SO_ACCEPTCONN)
				lcp -> lcd_state = LISTEN;
		} else
			sbreserve (&lcp -> lcd_sb, pk_sendspace);
	}
	if (so) {
		so -> so_pcb = (caddr_t) lcp;
		so -> so_error = error;
	}
	return (lcp);
}

/* 
 *  Disconnect X.25 protocol from socket.
 */

pk_disconnect (lcp)
register struct pklcd *lcp;
{
	register struct socket *so = lcp -> lcd_so;
	register struct pklcd *l, *p;

	switch (lcp -> lcd_state) {
	case LISTEN: 
		for (p = 0, l = pk_listenhead; l && l != lcp; p = l, l = l -> lcd_listen);
		if (p == 0) {
			if (l != 0)
				pk_listenhead = l -> lcd_listen;
		}
		else
		if (l != 0)
			p -> lcd_listen = l -> lcd_listen;
		pk_close (lcp);
		break;

	case READY: 
		pk_acct (lcp);
		pk_close (lcp);
		break;

	case SENT_CLEAR: 
	case RECEIVED_CLEAR: 
		break;

	default: 
		pk_acct (lcp);
		if (so) {
			soisdisconnecting (so);
			sbflush (&so -> so_rcv);
		}
		pk_clear (lcp, 241, 0); /* Normal Disconnect */

	}
}

/* 
 *  Close an X.25 Logical Channel. Discard all space held by the
 *  connection and internal descriptors. Wake up any sleepers.
 */

pk_close (lcp)
struct pklcd *lcp;
{
	register struct socket *so = lcp -> lcd_so;

	/*
	 * If the X.25 connection is torn down due to link
	 * level failure (e.g. LLC2 FRMR) and at the same the user
	 * level is still filling up the socket send buffer that
	 * send buffer is locked. An attempt to sbflush () that send
	 * buffer will lead us into - no, not temptation but - panic!
	 * So - we'll just check wether the send buffer is locked
	 * and if that's the case we'll mark the lcp as zombie and 
	 * have the pk_timer () do the cleaning ...
	 */
	
	if (so && so -> so_snd.sb_flags & SB_LOCK)
		lcp -> lcd_state = LCN_ZOMBIE;
	else
		pk_freelcd (lcp);

	if (so == NULL)
		return;

	so -> so_pcb = 0;
	soisdisconnected (so);
	/* sofree (so);	/* gak!!! you can't do that here */
}

/* 
 *  Create a template to be used to send X.25 packets on a logical
 *  channel. It allocates an mbuf and fills in a skeletal packet
 *  depending on its type. This packet is passed to pk_output where
 *  the remainer of the packet is filled in.
*/

struct mbuf *
pk_template (lcn, type)
int lcn, type;
{
	register struct mbuf *m;
	register struct x25_packet *xp;

	MGETHDR (m, M_DONTWAIT, MT_HEADER);
	if (m == 0)
		panic ("pk_template");
	m -> m_act = 0;

	/*
	 * Efficiency hack: leave a four byte gap at the beginning
	 * of the packet level header with the hope that this will
	 * be enough room for the link level to insert its header.
	 */
	m -> m_data += max_linkhdr;
	m -> m_pkthdr.len = m -> m_len = PKHEADERLN;

	xp = mtod (m, struct x25_packet *);
	*(long *)xp = 0;		/* ugly, but fast */
/*	xp -> q_bit = 0;*/
	X25SBITS(xp -> bits, fmt_identifier, 1);
/*	xp -> lc_group_number = 0;*/

	SET_LCN(xp, lcn);
	xp -> packet_type = type;

	return (m);
}

/* 
 *  This routine restarts all the virtual circuits. Actually,
 *  the virtual circuits are not "restarted" as such. Instead,
 *  any active switched circuit is simply returned to READY
 *  state.
 */

pk_restart (pkp, restart_cause)
register struct pkcb *pkp;
int restart_cause;
{
	register struct mbuf *m;
	register struct pklcd *lcp;
	register int i;

	/* Restart all logical channels. */
	if (pkp -> pk_chan == 0)
		return;

	/*
	 * Don't do this if we're doing a restart issued from
	 * inside pk_connect () --- which is only done if and
	 * only if the X.25 link is down, i.e. a RESTART needs
	 * to be done to get it up.
	 */
	if (!(pkp -> pk_dxerole & DTE_CONNECTPENDING)) {
		for (i = 1; i <= pkp -> pk_maxlcn; ++i)
			if ((lcp = pkp -> pk_chan[i]) != NULL) {
				if (lcp -> lcd_so) {
					lcp -> lcd_so -> so_error = ENETRESET;
					pk_close (lcp);
				} else {
					pk_flush (lcp);
					lcp -> lcd_state = READY;
					if (lcp -> lcd_upper)
						lcp -> lcd_upper (lcp, 0);
				}
			}
	}

	if (restart_cause < 0)
		return;

	pkp -> pk_state = DTE_SENT_RESTART;
	pkp -> pk_dxerole &= ~(DTE_PLAYDCE | DTE_PLAYDTE);
	lcp = pkp -> pk_chan[0];
	m = lcp -> lcd_template = pk_template (lcp -> lcd_lcn, X25_RESTART);
	m -> m_pkthdr.len = m -> m_len += 2;
	mtod (m, struct x25_packet *) -> packet_data = 0;	/* DTE only */
	mtod (m, octet *)[4]  = restart_cause;
	pk_output (lcp);
}


/* 
 *  This procedure frees up the Logical Channel Descripter.
 */

pk_freelcd (lcp)
register struct pklcd *lcp;
{
	if (lcp == NULL)
		return;

	if (lcp -> lcd_lcn > 0)
		lcp -> lcd_pkp -> pk_chan[lcp -> lcd_lcn] = NULL;

	pk_flush (lcp);
	remque (&lcp -> lcd_q);
	FREE((caddr_t)lcp, M_PCB);
}

static struct x25_ifaddr *
pk_ifwithaddr (sx)
	struct sockaddr_x25 *sx;
{
	struct ifnet *ifp;
	struct ifaddr *ifa;
	register struct x25_ifaddr *ia;
	char *addr = sx -> x25_addr;

	for (ifp = ifnet; ifp; ifp = ifp -> if_next)
		for (ifa = ifp -> if_addrlist; ifa; ifa = ifa -> ifa_next)
			if (ifa -> ifa_addr -> sa_family == AF_CCITT) {
				ia = (struct x25_ifaddr *)ifa;
				if (bcmp (addr, ia -> ia_xc.xc_addr.x25_addr,
					 16) == 0)
					return (ia);
				
			}
	return ((struct x25_ifaddr *)0);
}


/* 
 *  Bind a address and protocol value to a socket.  The important
 *  part is the protocol value - the first four characters of the 
 *  Call User Data field.
 */

#define XTRACTPKP(rt)	((rt) -> rt_flags & RTF_GATEWAY ? \
			 ((rt) -> rt_llinfo ? \
			  (struct pkcb *) ((struct rtentry *)((rt) -> rt_llinfo)) -> rt_llinfo : \
			  (struct pkcb *) NULL) : \
			 (struct pkcb *)((rt) -> rt_llinfo))

pk_bind (lcp, nam)
struct pklcd *lcp;
struct mbuf *nam;
{
	register struct pklcd *pp;
	register struct sockaddr_x25 *sa;

	if (nam == NULL)
		return (EADDRNOTAVAIL);
	if (lcp -> lcd_ceaddr)				/* XXX */
		return (EADDRINUSE);
	if (pk_checksockaddr (nam))
		return (EINVAL);
	sa = mtod (nam, struct sockaddr_x25 *);

	/*
	 * If the user wishes to accept calls only from a particular
	 * net (net != 0), make sure the net is known
	 */

	if (sa -> x25_addr[0]) {
		if (!pk_ifwithaddr (sa))
			return (ENETUNREACH);
	} else if (sa -> x25_net) {
		if (!ifa_ifwithnet ((struct sockaddr *)sa))
			return (ENETUNREACH);
	}

	/*
	 * For ISO's sake permit default listeners, but only one such . . .
	 */
	for (pp = pk_listenhead; pp; pp = pp -> lcd_listen) {
		register struct sockaddr_x25 *sa2 = pp -> lcd_ceaddr;
		if ((sa2 -> x25_udlen == sa -> x25_udlen) &&
		    (sa2 -> x25_udlen == 0 ||
		     (bcmp (sa2 -> x25_udata, sa -> x25_udata,
			    min (sa2 -> x25_udlen, sa -> x25_udlen)) == 0)))
				return (EADDRINUSE);
	}
	lcp -> lcd_laddr = *sa;
	lcp -> lcd_ceaddr = &lcp -> lcd_laddr;
	return (0);
}

/*
 * Include a bound control block in the list of listeners.
 */
pk_listen (lcp)
register struct pklcd *lcp;
{
	register struct pklcd **pp;

	if (lcp -> lcd_ceaddr == 0)
		return (EDESTADDRREQ);

	lcp -> lcd_state = LISTEN;
	/*
	 * Add default listener at end, any others at start.
	 */
	if (lcp -> lcd_ceaddr -> x25_udlen == 0) {
		for (pp = &pk_listenhead; *pp; )
			pp = &((*pp) -> lcd_listen);
		*pp = lcp;
	} else {
		lcp -> lcd_listen = pk_listenhead;
		pk_listenhead = lcp;
	}
	return (0);
}
/*
 * Include a listening control block for the benefit of other protocols.
 */
pk_protolisten (spi, spilen, callee)
int (*callee) ();
{
	register struct pklcd *lcp = pk_attach ((struct socket *)0);
	register struct mbuf *nam;
	register struct sockaddr_x25 *sa;
	int error = ENOBUFS;

	if (lcp) {
		if (nam = m_getclr (MT_SONAME, M_DONTWAIT)) {
			sa = mtod (nam, struct sockaddr_x25 *);
			sa -> x25_family = AF_CCITT;
			sa -> x25_len = nam -> m_len = sizeof (*sa);
			sa -> x25_udlen = spilen;
			sa -> x25_udata[0] = spi;
			lcp -> lcd_upper = callee;
			lcp -> lcd_flags = X25_MBS_HOLD;
			if ((error = pk_bind (lcp, nam)) == 0)
				error = pk_listen (lcp);
			(void) m_free (nam);
		}
		if (error)
			pk_freelcd (lcp);
	}
	return error; /* Hopefully Zero !*/
}

/*
 * Associate a logical channel descriptor with a network.
 * Fill in the default network specific parameters and then
 * set any parameters explicitly specified by the user or
 * by the remote DTE.
 */

pk_assoc (pkp, lcp, sa)
register struct pkcb *pkp;
register struct pklcd *lcp;
register struct sockaddr_x25 *sa;
{

	lcp -> lcd_pkp = pkp;
	lcp -> lcd_packetsize = pkp -> pk_xcp -> xc_psize;
	lcp -> lcd_windowsize = pkp -> pk_xcp -> xc_pwsize;
	lcp -> lcd_rsn = MODULUS - 1;
	pkp -> pk_chan[lcp -> lcd_lcn] = lcp;

	if (sa -> x25_opts.op_psize)
		lcp -> lcd_packetsize = sa -> x25_opts.op_psize;
	else
		sa -> x25_opts.op_psize = lcp -> lcd_packetsize;
	if (sa -> x25_opts.op_wsize)
		lcp -> lcd_windowsize = sa -> x25_opts.op_wsize;
	else
		sa -> x25_opts.op_wsize = lcp -> lcd_windowsize;
	sa -> x25_net = pkp -> pk_xcp -> xc_addr.x25_net;
	lcp -> lcd_flags |= sa -> x25_opts.op_flags;
	lcp -> lcd_stime = time.tv_sec;
}

pk_connect (lcp, sa)
register struct pklcd *lcp;
register struct sockaddr_x25 *sa;
{
	register struct pkcb *pkp;
	register struct rtentry *rt;
	register struct rtentry *nrt;

	struct rtentry *npaidb_enter ();
	struct pkcb *pk_newlink ();

	if (sa -> x25_addr[0] == '\0')
		return (EDESTADDRREQ);

	/*
	 * Is the destination address known?
	 */
	if (!(rt = rtalloc1 ((struct sockaddr *)sa, 1)))
		return (ENETUNREACH);

	if (!(pkp = XTRACTPKP(rt)))
		pkp = pk_newlink ((struct x25_ifaddr *) (rt -> rt_ifa), 
				 (caddr_t) 0);

	/*
	 * Have we entered the LLC address?
	 */
	if (nrt = npaidb_enter (rt -> rt_gateway, rt_key (rt), rt, 0))
		pkp -> pk_llrt = nrt;

	/*
	 * Have we allocated an LLC2 link yet?
	 */
	if (pkp -> pk_llnext == (caddr_t)0 && pkp -> pk_llctlinput) {
		struct dll_ctlinfo ctlinfo;

		ctlinfo.dlcti_rt = rt;
		ctlinfo.dlcti_pcb = (caddr_t) pkp;
		ctlinfo.dlcti_conf = 
			(struct dllconfig *) (&((struct x25_ifaddr *)(rt -> rt_ifa)) -> ia_xc);
		pkp -> pk_llnext = 
			(pkp -> pk_llctlinput) (PRC_CONNECT_REQUEST, 0, &ctlinfo);
	}

	if (pkp -> pk_state != DTE_READY && pkp -> pk_state != DTE_WAITING)
			return (ENETDOWN);
	if ((lcp -> lcd_lcn = pk_getlcn (pkp)) == 0)
		return (EMFILE);

	lcp -> lcd_faddr = *sa;
	lcp -> lcd_ceaddr = & lcp -> lcd_faddr;
	pk_assoc (pkp, lcp, lcp -> lcd_ceaddr);

	/*
	 * If the link is not up yet, initiate an X.25 RESTART
	 */
	if (pkp -> pk_state == DTE_WAITING) {
		pkp -> pk_dxerole |= DTE_CONNECTPENDING;
		pk_ctlinput (PRC_LINKUP, (struct sockaddr *)0, pkp);
		if (lcp -> lcd_so)
			soisconnecting (lcp -> lcd_so);
		return 0;
	}

	if (lcp -> lcd_so)
		soisconnecting (lcp -> lcd_so);
	lcp -> lcd_template = pk_template (lcp -> lcd_lcn, X25_CALL);
	pk_callrequest (lcp, lcp -> lcd_ceaddr, pkp -> pk_xcp);
	return (*pkp -> pk_ia -> ia_start) (lcp);
}

/*
 * Complete all pending X.25 call requests --- this gets called after
 * the X.25 link has been restarted.
 */
#define RESHUFFLELCN(maxlcn, lcn) ((maxlcn) - (lcn) + 1)

pk_callcomplete (pkp)
	register struct pkcb *pkp;
{
	register struct pklcd *lcp;
	register int i;
	register int ni;
	

	if (pkp -> pk_dxerole & DTE_CONNECTPENDING) 
		pkp -> pk_dxerole &= ~DTE_CONNECTPENDING;
	else return;

	if (pkp -> pk_chan == 0)
		return;
	
	/*
	 * We pretended to be a DTE for allocating lcns, if
	 * it turns out that we are in reality performing as a
	 * DCE we need to reshuffle the lcps.
	 *			        	  	      
         *             /+---------------+--------     -	      
	 *            / | a  (maxlcn-1) |              \      
	 *           /  +---------------+              	\     
	 *     +--- *   | b  (maxlcn-2) |         	 \    
	 *     |     \  +---------------+         	  \   
	 *   r |      \ | c  (maxlcn-3) |         	   \  
	 *   e |       \+---------------+         	    | 
	 *   s |        |	 .                	    |  
	 *   h |        |        .                	    | m
	 *   u |        |	 .      	  	    | a
	 *   f |        |	 .      	  	    | x
	 *   f |        |	 .                	    | l
	 *   l |       /+---------------+         	    | c
	 *   e |      / | c' (   3    ) |         	    | n
	 *     |     /  +---------------+         	    | 
	 *     +--> *   | b' (   2    ) |         	   /
	 *           \  +---------------+         	  / 
	 *            \ | a' (   1    ) |         	 /  
    	 *             \+---------------+               /   
         *              | 0             |              /    
	 *              +---------------+--------     -     
	 *	    
	 */	    
	if (pkp -> pk_dxerole & DTE_PLAYDCE) {
		/* Sigh, reshuffle it */
		for (i = pkp -> pk_maxlcn; i > 0; --i)
			if (pkp -> pk_chan[i]) {
				ni = RESHUFFLELCN(pkp -> pk_maxlcn, i);
				pkp -> pk_chan[ni] = pkp -> pk_chan[i];
				pkp -> pk_chan[i] = NULL;
				pkp -> pk_chan[ni] -> lcd_lcn = ni;
			}
	}

	for (i = 1; i <= pkp -> pk_maxlcn; ++i)
		if ((lcp = pkp -> pk_chan[i]) != NULL) {
			/* if (lcp -> lcd_so)
				soisconnecting (lcp -> lcd_so); */
			lcp -> lcd_template = pk_template (lcp -> lcd_lcn, X25_CALL);
			pk_callrequest (lcp, lcp -> lcd_ceaddr, pkp -> pk_xcp);
			(*pkp -> pk_ia -> ia_start) (lcp);
		}
}

struct bcdinfo {
	octet *cp;
	unsigned posn;
};
/* 
 *  Build the rest of the CALL REQUEST packet. Fill in calling
 *  address, facilities fields and the user data field.
 */

pk_callrequest (lcp, sa, xcp)
struct pklcd *lcp;
register struct sockaddr_x25 *sa;
register struct x25config *xcp;
{
	register struct x25_calladdr *a;
	register struct mbuf *m = lcp -> lcd_template;
	register struct x25_packet *xp = mtod (m, struct x25_packet *);
	struct bcdinfo b;

	if (lcp -> lcd_flags & X25_DBIT)
		X25SBITS(xp -> bits, d_bit, 1);
	a = (struct x25_calladdr *) &xp -> packet_data;
	b.cp = (octet *) a -> address_field;
	b.posn = 0;
	X25SBITS(a -> addrlens, called_addrlen, to_bcd (&b, sa, xcp));
	X25SBITS(a -> addrlens, calling_addrlen, to_bcd (&b, &xcp -> xc_addr, xcp));
	if (b.posn & 0x01)
		*b.cp++ &= 0xf0;
	m -> m_pkthdr.len = m -> m_len += b.cp - (octet *) a;

	if (lcp -> lcd_facilities) {
		m -> m_pkthdr.len += 
			(m -> m_next = lcp -> lcd_facilities) -> m_pkthdr.len;
		lcp -> lcd_facilities = 0;
	} else
		pk_build_facilities (m, sa, (int)xcp -> xc_type);

	m_copyback (m, m -> m_pkthdr.len, sa -> x25_udlen, sa -> x25_udata);
}

pk_build_facilities (m, sa, type)
register struct mbuf *m;
struct sockaddr_x25 *sa;
{
	register octet *cp;
	register octet *fcp;
	register int revcharge;

	cp = mtod (m, octet *) + m -> m_len;
	fcp = cp + 1;
	revcharge = sa -> x25_opts.op_flags & X25_REVERSE_CHARGE ? 1 : 0;
	/*
	 * This is specific to Datapac X.25(1976) DTEs.  International
	 * calls must have the "hi priority" bit on.
	 */
	if (type == X25_1976 && sa -> x25_opts.op_psize == X25_PS128)
		revcharge |= 02;
	if (revcharge) {
		*fcp++ = FACILITIES_REVERSE_CHARGE;
		*fcp++ = revcharge;
	}
	switch (type) {
	case X25_1980:
	case X25_1984:
		*fcp++ = FACILITIES_PACKETSIZE;
		*fcp++ = sa -> x25_opts.op_psize;
		*fcp++ = sa -> x25_opts.op_psize;

		*fcp++ = FACILITIES_WINDOWSIZE;
		*fcp++ = sa -> x25_opts.op_wsize;
		*fcp++ = sa -> x25_opts.op_wsize;
	}
	*cp = fcp - cp - 1;
	m -> m_pkthdr.len = (m -> m_len += *cp + 1);
}

to_bcd (b, sa, xcp)
register struct bcdinfo *b;
struct sockaddr_x25 *sa;
register struct x25config *xcp;
{
	register char *x = sa -> x25_addr;
	unsigned start = b -> posn;
	/*
	 * The nodnic and prepnd0 stuff looks tedious,
	 * but it does allow full X.121 addresses to be used,
	 * which is handy for routing info (& OSI type 37 addresses).
	 */
	if (xcp -> xc_addr.x25_net && (xcp -> xc_nodnic || xcp -> xc_prepnd0)) {
		char dnicname[sizeof (long) * NBBY/3 + 2];
		register char *p = dnicname;

		sprintf (p, "%d", xcp -> xc_addr.x25_net & 0x7fff);
		for (; *p; p++) /* *p == 0 means dnic matched */
			if ((*p ^ *x++) & 0x0f)
				break;
		if (*p || xcp -> xc_nodnic == 0)
			x = sa -> x25_addr;
		if (*p && xcp -> xc_prepnd0) {
			if ((b -> posn)++ & 0x01)
				*(b -> cp)++;
			else
				*(b -> cp) = 0;
		}
	}
	while (*x)
		if ((b -> posn)++ & 0x01)
			*(b -> cp)++ |= *x++ & 0x0F;
		else
			*(b -> cp) = *x++ << 4;
	return ((b -> posn) - start);
}

/* 
 *  This routine gets the  first available logical channel number.  The
 *  search is 
 *  		- from the highest number to lowest number if playing DTE, and
 *		- from lowest to highest number if playing DCE.
 */

pk_getlcn (pkp)
register struct pkcb *pkp;
{
	register int i;

	if (pkp -> pk_chan == 0)
		return (0);
	if ( pkp -> pk_dxerole & DTE_PLAYDCE ) {
		for (i = 1; i <= pkp -> pk_maxlcn; ++i)
			if (pkp -> pk_chan[i] == NULL)
				break;
	} else { 
		for (i = pkp -> pk_maxlcn; i > 0; --i)
			if (pkp -> pk_chan[i] == NULL)
				break;
	}
	i = ( i > pkp -> pk_maxlcn ? 0 : i );
	return (i);
}

/* 
 *  This procedure sends a CLEAR request packet. The lc state is
 *  set to "SENT_CLEAR". 
 */

pk_clear (lcp, diagnostic, abortive)
register struct pklcd *lcp;
{
	register struct mbuf *m = pk_template (lcp -> lcd_lcn, X25_CLEAR);

	m -> m_len += 2;
	m -> m_pkthdr.len += 2;
	mtod (m, struct x25_packet *) -> packet_data = 0;
	mtod (m, octet *)[4] = diagnostic;
	if (lcp -> lcd_facilities) {
		m -> m_next = lcp -> lcd_facilities;
		m -> m_pkthdr.len += m -> m_next -> m_len;
		lcp -> lcd_facilities = 0;
	}
	if (abortive)
		lcp -> lcd_template = m;
	else {
		struct socket *so = lcp -> lcd_so;
		struct sockbuf *sb = so ? & so -> so_snd : & lcp -> lcd_sb;
		sbappendrecord (sb, m);
	}
	pk_output (lcp);

}

/*
 * This procedure generates RNR's or RR's to inhibit or enable
 * inward data flow, if the current state changes (blocked ==> open or
 * vice versa), or if forced to generate one.  One forces RNR's to ack data.  
 */
pk_flowcontrol (lcp, inhibit, forced)
register struct pklcd *lcp;
{
	inhibit = (inhibit != 0);
	if (lcp == 0 || lcp -> lcd_state != DATA_TRANSFER ||
	    (forced == 0 && lcp -> lcd_rxrnr_condition == inhibit))
		return;
	lcp -> lcd_rxrnr_condition = inhibit;
	lcp -> lcd_template =
		pk_template (lcp -> lcd_lcn, inhibit ? X25_RNR : X25_RR);
	pk_output (lcp);
}

/* 
 *  This procedure sends a RESET request packet. It re-intializes
 *  virtual circuit.
 */

static
pk_reset (lcp, diagnostic)
register struct pklcd *lcp;
{
	register struct mbuf *m;
	register struct socket *so = lcp -> lcd_so;

	if (lcp -> lcd_state != DATA_TRANSFER)
		return;

	if (so)
		so -> so_error = ECONNRESET;
	lcp -> lcd_reset_condition = TRUE;

	/* Reset all the control variables for the channel. */
	pk_flush (lcp);
	lcp -> lcd_window_condition = lcp -> lcd_rnr_condition =
		lcp -> lcd_intrconf_pending = FALSE;
	lcp -> lcd_rsn = MODULUS - 1;
	lcp -> lcd_ssn = 0;
	lcp -> lcd_output_window = lcp -> lcd_input_window =
		lcp -> lcd_last_transmitted_pr = 0;
	m = lcp -> lcd_template = pk_template (lcp -> lcd_lcn, X25_RESET);
	m -> m_pkthdr.len = m -> m_len += 2;
	mtod (m, struct x25_packet *) -> packet_data = 0;
	mtod (m, octet *)[4] = diagnostic;
	pk_output (lcp);

}

/*
 * This procedure frees all data queued for output or delivery on a
 *  virtual circuit.
 */

pk_flush (lcp)
register struct pklcd *lcp;
{
	register struct socket *so;

	if (lcp -> lcd_template)
		m_freem (lcp -> lcd_template);

	if (lcp -> lcd_cps) {
		m_freem (lcp -> lcd_cps);
		lcp -> lcd_cps = 0;
	}
	if (lcp -> lcd_facilities) {
		m_freem (lcp -> lcd_facilities);
		lcp -> lcd_facilities = 0;
	}
	if (so = lcp -> lcd_so) 
		sbflush (&so -> so_snd);
	else 
		sbflush (&lcp -> lcd_sb);
}

/* 
 *  This procedure handles all local protocol procedure errors.
 */

pk_procerror (error, lcp, errstr, diagnostic)
register struct pklcd *lcp;
char *errstr;
{

	pk_message (lcp -> lcd_lcn, lcp -> lcd_pkp -> pk_xcp, errstr);

	switch (error) {
	case CLEAR: 
		if (lcp -> lcd_so) {
			lcp -> lcd_so -> so_error = ECONNABORTED;
			soisdisconnecting (lcp -> lcd_so);
		}
		pk_clear (lcp, diagnostic, 1);
		break;

	case RESET: 
		pk_reset (lcp, diagnostic);
	}
}

/* 
 *  This procedure is called during the DATA TRANSFER state to check 
 *  and  process  the P(R) values  received  in the DATA,  RR OR RNR
 *  packets.
 */

pk_ack (lcp, pr)
struct pklcd *lcp;
unsigned pr;
{
	register struct socket *so = lcp -> lcd_so;

	if (lcp -> lcd_output_window == pr)
		return (PACKET_OK);
	if (lcp -> lcd_output_window < lcp -> lcd_ssn) {
		if (pr < lcp -> lcd_output_window || pr > lcp -> lcd_ssn) {
			pk_procerror (RESET, lcp,
				"p(r) flow control error", 2);
			return (ERROR_PACKET);
		}
	}
	else {
		if (pr < lcp -> lcd_output_window && pr > lcp -> lcd_ssn) {
			pk_procerror (RESET, lcp,
				"p(r) flow control error #2", 2);
			return (ERROR_PACKET);
		}
	}

	lcp -> lcd_output_window = pr;		/* Rotate window. */
	if (lcp -> lcd_window_condition == TRUE)
		lcp -> lcd_window_condition = FALSE;

	if (so && ((so -> so_snd.sb_flags & SB_WAIT) || 
		   (so -> so_snd.sb_flags & SB_NOTIFY)))
		sowwakeup (so);

	return (PACKET_OK);
}

/* 
 *  This procedure decodes the X.25 level 3 packet returning a 
 *  code to be used in switchs or arrays.
 */

pk_decode (xp)
register struct x25_packet *xp;
{
	register int type;

	if (X25GBITS(xp -> bits, fmt_identifier) != 1)
		return (INVALID_PACKET);
#ifdef ancient_history
	/* 
	 *  Make sure that the logical channel group number is 0.
	 *  This restriction may be removed at some later date.
	 */
	if (xp -> lc_group_number != 0)
		return (INVALID_PACKET);
#endif
	/* 
	 *  Test for data packet first.
	 */
	if (!(xp -> packet_type & DATA_PACKET_DESIGNATOR))
		return (DATA);

	/* 
	 *  Test if flow control packet (RR or RNR).
	 */
	if (!(xp -> packet_type & RR_OR_RNR_PACKET_DESIGNATOR))
		switch (xp -> packet_type & 0x1f) {
		case X25_RR:
			return (RR);
		case X25_RNR:
			return (RNR);
		case X25_REJECT:
			return (REJECT);
		}

	/* 
	 *  Determine the rest of the packet types.
	 */
	switch (xp -> packet_type) {
	case X25_CALL: 
		type = CALL;
		break;

	case X25_CALL_ACCEPTED: 
		type = CALL_ACCEPTED;
		break;

	case X25_CLEAR: 
		type = CLEAR;
		break;

	case X25_CLEAR_CONFIRM: 
		type = CLEAR_CONF;
		break;

	case X25_INTERRUPT: 
		type = INTERRUPT;
		break;

	case X25_INTERRUPT_CONFIRM: 
		type = INTERRUPT_CONF;
		break;

	case X25_RESET: 
		type = RESET;
		break;

	case X25_RESET_CONFIRM: 
		type = RESET_CONF;
		break;

	case X25_RESTART: 
		type = RESTART;
		break;

	case X25_RESTART_CONFIRM: 
		type = RESTART_CONF;
		break;

	case X25_DIAGNOSTIC:
		type = DIAG_TYPE;
		break;

	default: 
		type = INVALID_PACKET;
	}
	return (type);
}

/* 
 *  A restart packet has been received. Print out the reason
 *  for the restart.
 */

pk_restartcause (pkp, xp)
struct pkcb *pkp;
register struct x25_packet *xp;
{
	register struct x25config *xcp = pkp -> pk_xcp;
	register int lcn = LCN(xp);

	switch (xp -> packet_data) {
	case X25_RESTART_LOCAL_PROCEDURE_ERROR: 
		pk_message (lcn, xcp, "restart: local procedure error");
		break;

	case X25_RESTART_NETWORK_CONGESTION: 
		pk_message (lcn, xcp, "restart: network congestion");
		break;

	case X25_RESTART_NETWORK_OPERATIONAL: 
		pk_message (lcn, xcp, "restart: network operational");
		break;

	default: 
		pk_message (lcn, xcp, "restart: unknown cause");
	}
}

#define MAXRESETCAUSE	7

int     Reset_cause[] = {
	EXRESET, EXROUT, 0, EXRRPE, 0, EXRLPE, 0, EXRNCG
};

/* 
 *  A reset packet has arrived. Return the cause to the user.
 */

pk_resetcause (pkp, xp)
struct pkcb *pkp;
register struct x25_packet *xp;
{
	register struct pklcd *lcp =
				pkp -> pk_chan[LCN(xp)];
	register int code = xp -> packet_data;

	if (code > MAXRESETCAUSE)
		code = 7;	/* EXRNCG */

	pk_message (LCN(xp), lcp -> lcd_pkp, "reset code 0x%x, diagnostic 0x%x",
			xp -> packet_data, 4[(u_char *)xp]);
			
	if (lcp -> lcd_so)
		lcp -> lcd_so -> so_error = Reset_cause[code];
}

#define MAXCLEARCAUSE	25

int     Clear_cause[] = {
	EXCLEAR, EXCBUSY, 0, EXCINV, 0, EXCNCG, 0,
	0, 0, EXCOUT, 0, EXCAB, 0, EXCNOB, 0, 0, 0, EXCRPE,
	0, EXCLPE, 0, 0, 0, 0, 0, EXCRRC
};

/* 
 *  A clear packet has arrived. Return the cause to the user.
 */

pk_clearcause (pkp, xp)
struct pkcb *pkp;
register struct x25_packet *xp;
{
	register struct pklcd *lcp =
		pkp -> pk_chan[LCN(xp)];
	register int code = xp -> packet_data;

	if (code > MAXCLEARCAUSE)
		code = 5;	/* EXRNCG */
	if (lcp -> lcd_so)
		lcp -> lcd_so -> so_error = Clear_cause[code];
}

char *
format_ntn (xcp)
register struct x25config *xcp;
{

	return (xcp -> xc_addr.x25_addr);
}

/* VARARGS1 */
pk_message (lcn, xcp, fmt, a1, a2, a3, a4, a5, a6)
struct x25config *xcp;
char *fmt;
{

	if (lcn)
		if (!PQEMPTY)
			printf ("X.25(%s): lcn %d: ", format_ntn (xcp), lcn);
		else
			printf ("X.25: lcn %d: ", lcn);
	else
		if (!PQEMPTY)
			printf ("X.25(%s): ", format_ntn (xcp));
		else
			printf ("X.25: ");

	printf (fmt, a1, a2, a3, a4, a5, a6);
	printf ("\n");
}

pk_fragment (lcp, m0, qbit, mbit, wait)
struct mbuf *m0;
register struct pklcd *lcp;
{
	register struct mbuf *m = m0;
	register struct x25_packet *xp;
	register struct sockbuf *sb;
	struct mbuf *head = 0, *next, **mp = &head, *m_split ();
	int totlen, psize = 1 << (lcp -> lcd_packetsize);

	if (m == 0)
		return 0;
	if (m -> m_flags & M_PKTHDR == 0)
		panic ("pk_fragment");
	totlen = m -> m_pkthdr.len;
	m -> m_act = 0;
	sb = lcp -> lcd_so ? &lcp -> lcd_so -> so_snd : & lcp -> lcd_sb;
	do {
		if (totlen > psize) {
			if ((next = m_split (m, psize, wait)) == 0)
				goto abort;
			totlen -= psize;
		} else
			next = 0;
		M_PREPEND(m, PKHEADERLN, wait);
		if (m == 0)
			goto abort;
		*mp = m;
		mp = & m -> m_act;
		*mp = 0;
		xp = mtod (m, struct x25_packet *);
		0[(char *)xp] = 0;
		if (qbit)
			X25SBITS(xp -> bits, q_bit, 1);
		if (lcp -> lcd_flags & X25_DBIT)
			X25SBITS(xp -> bits, d_bit, 1);
		X25SBITS(xp -> bits, fmt_identifier, 1);
		xp -> packet_type = X25_DATA;
		SET_LCN(xp, lcp -> lcd_lcn);
		if (next || (mbit && (totlen == psize ||
				      (lcp -> lcd_flags & X25_DBIT))))
			SMBIT(xp, 1);
	} while (m = next);
	for (m = head; m; m = next) {
		next = m -> m_act;
		m -> m_act = 0;
		sbappendrecord (sb, m);
	}
	return 0;
abort:
	if (wait)
		panic ("pk_fragment null mbuf after wait");
	if (next)
		m_freem (next);
	for (m = head; m; m = next) {
		next = m -> m_act;
		m_freem (m);
	}
	return ENOBUFS;
}
