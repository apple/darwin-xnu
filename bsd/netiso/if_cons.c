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
/*-
 * Copyright (c) 1991, 1993
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
 *	@(#)if_cons.c	8.1 (Berkeley) 6/10/93
 */

/***********************************************************
		Copyright IBM Corporation 1987

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its 
documentation for any purpose and without fee is hereby granted, 
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in 
supporting documentation, and that the name of IBM not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.  

IBM DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
IBM BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.

******************************************************************/

/*
 * ARGO Project, Computer Sciences Dept., University of Wisconsin - Madison
 */
/*
 * cons.c - Connection Oriented Network Service:
 * including support for a) user transport-level service, 
 *	b) COSNS below CLNP, and c) CONS below TP.
 */

#if TPCONS
#ifdef KERNEL
#ifdef ARGO_DEBUG
#define Static  
unsigned LAST_CALL_PCB;
#else /* ARGO_DEBUG */
#define Static static
#endif /* ARGO_DEBUG */

#ifndef SOCK_STREAM
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/tsleep.h>

#include <net/if.h>
#include <net/netisr.h>
#include <net/route.h>

#include <netiso/iso_errno.h>
#include <netiso/argo_debug.h>
#include <netiso/tp_trace.h>
#include <netiso/iso.h>
#include <netiso/cons.h>
#include <netiso/iso_pcb.h>

#include <netccitt/x25.h>
#include <netccitt/pk.h>
#include <netccitt/pk_var.h>
#endif

#ifdef ARGO_DEBUG
#define MT_XCONN	0x50
#define MT_XCLOSE	0x51
#define MT_XCONFIRM	0x52
#define MT_XDATA	0x53
#define MT_XHEADER	0x54
#else
#define MT_XCONN	MT_DATA
#define MT_XCLOSE	MT_DATA
#define MT_XCONFIRM	MT_DATA
#define MT_XDATA	MT_DATA
#define MT_XHEADER	MT_HEADER
#endif /* ARGO_DEBUG */

#define DONTCLEAR	 -1

/*********************************************************************	
 * cons.c - CONS interface to the x.25 layer
 *
 * TODO: figure out what resources we might run out of besides mbufs.
 *  If we run out of any of them (including mbufs) close and recycle
 *  lru x% of the connections, for some parameter x.
 *
 * There are 2 interfaces from above:
 * 1) from TP0: 
 *    cons CO network service
 *    TP associates a transport connection with a network connection.
 * 	  cons_output( isop, m, len, isdgm==0 ) 
 *        co_flags == 0
 * 2) from TP4:
 *	  It's a datagram service, like clnp is. - even though it calls
 *			cons_output( isop, m, len, isdgm==1 ) 
 *	  it eventually goes through
 *			cosns_output(ifp, m, dst).
 *    TP4 permits multiplexing (reuse, possibly simultaneously) of the 
 *	  network connections.
 *    This means that many sockets (many tpcbs) may be associated with
 *    this pklcd, hence cannot have a back ptr from pklcd to a tpcb.
 *        co_flags & CONSF_DGM 
 *    co_socket is null since there may be many sockets that use this pklcd.
 *
NOTE:
	streams would really be nice. sigh.
NOTE:
	PVCs could be handled by config-ing a cons with an address and with the
	IFF_POINTTOPOINT flag on.  This code would then have to skip the
	connection setup stuff for pt-to-pt links.  


 *********************************************************************/


#define CONS_IFQMAXLEN 5


/* protosw pointers for getting to higher layer */
Static 	struct protosw	*CLNP_proto;
Static 	struct protosw	*TP_proto;
Static 	struct protosw	*X25_proto;
Static 	int				issue_clear_req();

#ifndef	PHASEONE
extern	struct ifaddr	*ifa_ifwithnet();
#endif	/* PHASEONE */

extern	struct ifaddr	*ifa_ifwithaddr();

extern struct	isopcb	tp_isopcb; /* chain of all TP pcbs */


Static 	int parse_facil(), NSAPtoDTE(), make_partial_x25_packet();
Static	int FACILtoNSAP(), DTEtoNSAP();
Static	struct pklcd *cons_chan_to_pcb();

#define HIGH_NIBBLE 1
#define LOW_NIBBLE 0

/*
 * NAME:	nibble_copy()
 * FUNCTION and ARGUMENTS:
 * 	copies (len) nibbles from (src_octet), high or low nibble
 *  to (dst_octet), high or low nibble,
 * src_nibble & dst_nibble should be:
 * 	HIGH_NIBBLE (1) if leftmost 4 bits/ most significant nibble
 * 	LOW_NIBBLE (0) if rightmost 4 bits/ least significant nibble
 * RETURNS: VOID
 */
void
nibble_copy(src_octet, src_nibble, dst_octet, dst_nibble, len)
	register char  	*src_octet;
	register char  	*dst_octet;
	register unsigned		src_nibble;
	register unsigned 		dst_nibble;
	int		len;
{

	register 	i;
	register 	unsigned dshift, sshift;

	IFDEBUG(D_CADDR)
		printf("nibble_copy ( 0x%x, 0x%x, 0x%x, 0x%x 0x%x)\n", 
		 src_octet, src_nibble, dst_octet, dst_nibble, len);
	ENDDEBUG
#define SHIFT 0x4

	dshift = dst_nibble << 2;
	sshift = src_nibble << 2;

	for (i=0; i<len; i++) {
		/* clear dst_nibble  */
		*dst_octet 	&= ~(0xf<< dshift);

		/* set dst nibble */
		*dst_octet 	|= ( 0xf & (*src_octet >> sshift))<< dshift;

		dshift		^= SHIFT;
		sshift		^= SHIFT;
		src_nibble 	= 1-src_nibble;
		dst_nibble 	= 1-dst_nibble;
		src_octet	+= src_nibble;
		dst_octet 	+= dst_nibble;
	}
	IFDEBUG(D_CADDR)
		printf("nibble_copy DONE\n");
	ENDDEBUG
}

/*
 * NAME:	nibble_match()
 * FUNCTION and ARGUMENTS:
 * 	compares src_octet/src_nibble and dst_octet/dst_nibble  for len nibbles.
 * RETURNS: 0 if they differ, 1 if they are the same.
 */
int
nibble_match( src_octet, src_nibble, dst_octet, dst_nibble, len)
	register char  	*src_octet;
	register char  	*dst_octet;
	register unsigned		src_nibble;
	register unsigned 		dst_nibble;
	int		len;
{

	register 	i;
	register 	unsigned dshift, sshift;
	u_char		nibble_a, nibble_b;

	IFDEBUG(D_CADDR)
		printf("nibble_match ( 0x%x, 0x%x, 0x%x, 0x%x 0x%x)\n", 
		 src_octet, src_nibble, dst_octet, dst_nibble, len);
	ENDDEBUG
#define SHIFT 0x4

	dshift = dst_nibble << 2;
	sshift = src_nibble << 2;

	for (i=0; i<len; i++) {
		nibble_b = ((*dst_octet)>>dshift) & 0xf;
		nibble_a = ( 0xf & (*src_octet >> sshift));
		if (nibble_b != nibble_a)
			return 0;

		dshift		^= SHIFT;
		sshift		^= SHIFT;
		src_nibble 	= 1-src_nibble;
		dst_nibble 	= 1-dst_nibble;
		src_octet	+= src_nibble;
		dst_octet 	+= dst_nibble;
	}
	IFDEBUG(D_CADDR)
		printf("nibble_match DONE\n");
	ENDDEBUG
	return 1;
}

/*
 **************************** NET PROTOCOL cons ***************************
 */
/*
 * NAME:	cons_init()
 * CALLED FROM:
 *	autoconf
 * FUNCTION:
 *	initialize the protocol
 */
cons_init()
{
	int tp_incoming(), clnp_incoming();


	CLNP_proto = pffindproto(AF_ISO, ISOPROTO_CLNP, SOCK_DGRAM); 
	X25_proto = pffindproto(AF_ISO, ISOPROTO_X25, SOCK_STREAM);
	TP_proto = pffindproto(AF_ISO, ISOPROTO_TP0, SOCK_SEQPACKET);
	IFDEBUG(D_CCONS)
		printf("cons_init end : cnlp_proto 0x%x cons proto 0x%x tp proto 0x%x\n",
			CLNP_proto, X25_proto, TP_proto);
	ENDDEBUG
#ifdef notdef
	pk_protolisten(0x81, 0, clnp_incoming);
	pk_protolisten(0x82, 0, esis_incoming);
	pk_protolisten(0x84, 0, tp8878_A_incoming);
	pk_protolisten(0, 0, tp_incoming);
#endif
}

tp_incoming(lcp, m)
struct pklcd *lcp;
register struct mbuf *m;
{
	register struct isopcb *isop;
	int cons_tpinput();

	if (iso_pcballoc((struct socket *)0, &tp_isopcb)) {
		pk_close(lcp);
		return;
	}
	isop = tp_isopcb.isop_next;
	lcp->lcd_upper = cons_tpinput;
	lcp->lcd_upnext = (caddr_t)isop;
	lcp->lcd_send(lcp); /* Confirms call */
	isop->isop_chan = (caddr_t)lcp;
	isop->isop_laddr = &isop->isop_sladdr;
	isop->isop_faddr = &isop->isop_sfaddr;
	DTEtoNSAP(isop->isop_laddr, &lcp->lcd_laddr);
	DTEtoNSAP(isop->isop_faddr, &lcp->lcd_faddr);
	parse_facil(lcp, isop, &(mtod(m, struct x25_packet *)->packet_data),
		m->m_pkthdr.len - PKHEADERLN);
}

cons_tpinput(lcp, m0)
struct mbuf *m0;
struct pklcd *lcp;
{
	register struct isopcb *isop = (struct isopcb *)lcp->lcd_upnext;
	register struct x25_packet *xp;
	int cmd, ptype = CLEAR;

	if (isop == 0)
		return;
	if (m0 == 0)
		goto dead;
	switch(m0->m_type) {
	case MT_DATA:
	case MT_OOBDATA:
		tpcons_input(m0, isop->isop_faddr, isop->isop_laddr, (caddr_t)lcp);
		return;

	case MT_CONTROL:
		switch (ptype = pk_decode(mtod(m0, struct x25_packet *))) {

		case RR:
			cmd = PRC_CONS_SEND_DONE;
			break;

		case CALL_ACCEPTED:
			if (lcp->lcd_sb.sb_mb)
				lcp->lcd_send(lcp); /* XXX - fix this */
			/*FALLTHROUGH*/
		default:
			return;

		dead:
		case CLEAR:
		case CLEAR_CONF:
			lcp->lcd_upper = 0;
			lcp->lcd_upnext = 0;
			isop->isop_chan = 0;
		case RESET:
			cmd = PRC_ROUTEDEAD;
		}
		tpcons_ctlinput(cmd, isop->isop_faddr, isop);
		if (cmd = PRC_ROUTEDEAD && isop->isop_refcnt == 0) 
			iso_pcbdetach(isop);
	}
}

/*
 * NAME:	cons_connect()
 * CALLED FROM:
 *	tpcons_pcbconnect() when opening a new connection.  
 * FUNCTION anD ARGUMENTS:
 *  Figures out which device to use, finding a route if one doesn't
 *  already exist.
 * RETURN VALUE:
 *  returns E*
 */
cons_connect(isop)
	register struct isopcb *isop;
{
	register struct pklcd *lcp = (struct pklcd *)isop->isop_chan;
	register struct mbuf 	*m;
	struct ifaddr 			*ifa;
	int error;

	IFDEBUG(D_CCONN)
		printf("cons_connect(0x%x): ", isop);
		dump_isoaddr(isop->isop_faddr);
		printf("myaddr: ");
		dump_isoaddr(isop->isop_laddr);
		printf("\n" );
	ENDDEBUG
	NSAPtoDTE(isop->isop_faddr, &lcp->lcd_faddr);
	lcp->lcd_upper = cons_tpinput;
	lcp->lcd_upnext = (caddr_t)isop;
	IFDEBUG(D_CCONN)
		printf(
		"calling make_partial_x25_packet( 0x%x, 0x%x, 0x%x)\n",
			&lcp->lcd_faddr, &lcp->lcd_laddr, 
			isop->isop_socket->so_proto->pr_protocol); 
	ENDDEBUG
	if ((error = make_partial_x25_packet(isop, lcp, m)) == 0)
		error = pk_connect(lcp, &lcp->lcd_faddr);
	return error;
}

/*
 **************************** DEVICE cons ***************************
 */


/* 
 * NAME:	cons_ctlinput()
 * CALLED FROM:
 *  lower layer when ECN_CLEAR occurs : this routine is here
 *  for consistency - cons subnet service calls its higher layer
 *  through the protosw entry.
 * FUNCTION & ARGUMENTS:
 *  cmd is a PRC_* command, list found in ../sys/protosw.h
 *  copcb is the obvious.
 *  This serves the higher-layer cons service.
 * NOTE: this takes 3rd arg. because cons uses it to inform itself
 *  of things (timeouts, etc) but has a pcb instead of an address.
 */
cons_ctlinput(cmd, sa, copcb)
	int cmd;
	struct sockaddr *sa;
	register struct pklcd *copcb;
{
}


find_error_reason( xp )
	register struct x25_packet *xp;
{
	extern u_char x25_error_stats[];
	int error, cause;

	if (xp) {
		cause = 4[(char *)xp];
		switch (cause) {
			case 0x00:
			case 0x80:
				/* DTE originated; look at the diagnostic */
				error = (CONL_ERROR_MASK | cause);
				goto done;

			case 0x01: /* number busy */
			case 0x81:
			case 0x09: /* Out of order */
			case 0x89:
			case 0x11: /* Remot Procedure Error */
			case 0x91:
			case 0x19: /* reverse charging accept not subscribed */
			case 0x99:
			case 0x21: /* Incampat destination */
			case 0xa1:
			case 0x29: /* fast select accept not subscribed */
			case 0xa9:
			case 0x39: /* ship absent */
			case 0xb9:
			case 0x03: /* invalid facil request */
			case 0x83:
			case 0x0b: /* access barred */
			case 0x8b:
			case 0x13: /* local procedure error */
			case 0x93:
			case 0x05: /* network congestion */
			case 0x85:
			case 0x8d: /* not obtainable */
			case 0x0d:
			case 0x95: /* RPOA out of order */
			case 0x15:
				/* take out bit 8 
				 * so we don't have to have so many perror entries 
				 */
				error = (CONL_ERROR_MASK | 0x100 | (cause & ~0x80));
				goto done;

			case 0xc1: /* gateway-detected proc error */
			case 0xc3: /* gateway congestion */

				error = (CONL_ERROR_MASK | 0x100 | cause);
				goto done;
		} 
	} 
	/* otherwise, a *hopefully* valid perror exists in the e_reason field */
	error = xp->packet_data;
	if (error = 0) {
		printf("Incoming PKT TYPE 0x%x with reason 0x%x\n",
			pk_decode(xp),
			cause);
		error = E_CO_HLI_DISCA;
	} 

done:
	return error;
}



#endif /* KERNEL */

/*
 * NAME:	make_partial_x25_packet()
 *
 * FUNCTION and ARGUMENTS:
 *	Makes part of an X.25 call packet, for use by x25.
 *  (src) and (dst) are the NSAP-addresses of source and destination.
 *	(buf) is a ptr to a buffer into which to write this partial header.
 *
 *	 0			Facility length (in octets)
 *	 1			Facility field, which is a set of:
 *	  m			facil code
 *	  m+1		facil param len (for >2-byte facilities) in octets
 *	  m+2..p	facil param field
 *  q			user data (protocol identification octet)
 * 
 *
 * RETURNS: 
 *  0 if OK
 *  E* if failed.
 *
 * SIDE EFFECTS:
 * Stores facilites mbuf in X.25 control block, where the connect
 * routine knows where to look for it.
 */

#ifdef X25_1984 
int cons_use_facils = 1;
#else /* X25_1984  */
int cons_use_facils = 0;
#endif /* X25_1984  */

int cons_use_udata = 1; /* KLUDGE FOR DEBUGGING */

Static int
make_partial_x25_packet(isop, lcp)
	struct isopcb *isop;
	struct pklcd *lcp;
{
	u_int				proto;
	int					flag;
	caddr_t 			buf;
	register caddr_t	ptr;
	register int		len	= 0;
	int 				buflen	=0;
	caddr_t				facil_len;
	int 				oddness	= 0;
	struct mbuf *m;


	IFDEBUG(D_CCONN)
		printf("make_partial_x25_packet(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n",
			isop->isop_laddr, isop->isop_faddr, proto, m, flag);
	ENDDEBUG
	if (cons_use_udata) {
		if (isop->isop_x25crud_len > 0) {
			/*
			 *	The user specified something. Stick it in
			 */
			bcopy(isop->isop_x25crud, lcp->lcd_faddr.x25_udata,
					isop->isop_x25crud_len);
			lcp->lcd_faddr.x25_udlen = isop->isop_x25crud_len;
		}
	}

	if (cons_use_facils == 0) {
		lcp->lcd_facilities = 0;
		return 0;
	}
	MGETHDR(m, MT_DATA, M_WAITOK);
	if (m == 0)
		return ENOBUFS;
	buf = mtod(m, caddr_t);
	ptr = buf;
	
	/* ptr now points to facil length (len of whole facil field in OCTETS */
	facil_len = ptr ++;
	m->m_len = 0;
	pk_build_facilities(m, &lcp->lcd_faddr, 0);

	IFDEBUG(D_CADDR)
		printf("make_partial  calling: ptr 0x%x, len 0x%x\n", ptr, 
				isop->isop_laddr->siso_addr.isoa_len);
	ENDDEBUG
	if (cons_use_facils) {
		*ptr++ = 0;	 /* Marker to separate X.25 facitilies from CCITT ones */
		*ptr++ = 0x0f;
		*ptr = 0xcb; /* calling facility code */
		ptr ++;
		ptr ++; /* leave room for facil param len (in OCTETS + 1) */
		ptr ++; /* leave room for the facil param len (in nibbles),
				 * high two bits of which indicate full/partial NSAP
				 */
		len = isop->isop_laddr->siso_addr.isoa_len;
		bcopy( isop->isop_laddr->siso_data, ptr, len);
		*(ptr-2) = len+1; /* facil param len in octets */
		*(ptr-1) = len<<1; /* facil param len in nibbles */
		ptr += len;

		IFDEBUG(D_CADDR)
			printf("make_partial  called: ptr 0x%x, len 0x%x\n", ptr, 
					isop->isop_faddr->siso_addr.isoa_len);
		ENDDEBUG
		*ptr = 0xc9; /* called facility code */
		ptr ++;
		ptr ++; /* leave room for facil param len (in OCTETS + 1) */
		ptr ++; /* leave room for the facil param len (in nibbles),
				 * high two bits of which indicate full/partial NSAP
				 */
		len = isop->isop_faddr->siso_nlen;
		bcopy(isop->isop_faddr->siso_data, ptr, len);
		*(ptr-2) = len+1; /* facil param len = addr len + 1 for each of these
						  * two length fields, in octets */
		*(ptr-1) = len<<1; /* facil param len in nibbles */
		ptr += len;

	}
	*facil_len = ptr - facil_len - 1;
	if (*facil_len > MAX_FACILITIES)
		return E_CO_PNA_LONG;

	buflen = (int)(ptr - buf);

	IFDEBUG(D_CDUMP_REQ)
		register int i;

		printf("ECN_CONNECT DATA buf 0x%x len %d (0x%x)\n", 
			buf, buflen, buflen);
		for( i=0; i < buflen; ) {
			printf("+%d: %x %x %x %x    %x %x %x %x\n",
				i,
				*(buf+i), *(buf+i+1), *(buf+i+2), *(buf+i+3),
				*(buf+i+4), *(buf+i+5), *(buf+i+6), *(buf+i+7));
			i+=8;
		}
	ENDDEBUG
	IFDEBUG(D_CADDR)
		printf("make_partial returns buf 0x%x size 0x%x bytes\n", 
			mtod(m, caddr_t), buflen);
	ENDDEBUG

	if (buflen > MHLEN)
		return E_CO_PNA_LONG;

	m->m_pkthdr.len = m->m_len = buflen;
	lcp->lcd_facilities = m;
	return  0;
}

/*
 * NAME:	NSAPtoDTE()
 * CALLED FROM:
 *  make_partial_x25_packet()
 * FUNCTION and ARGUMENTS: 
 *  get a DTE address from an NSAP-address (struct sockaddr_iso)
 *  (dst_octet) is the octet into which to begin stashing the DTE addr
 *  (dst_nibble) takes 0 or 1.  1 means begin filling in the DTE addr
 * 		in the high-order nibble of dst_octet.  0 means low-order nibble.
 *  (addr) is the NSAP-address
 *  (flag) is true if the transport suffix is to become the
 *		last two digits of the DTE address
 *  A DTE address is a series of ASCII digits
 *
 *	A DTE address may have leading zeros. The are significant.
 *		1 digit per nibble, may be an odd number of nibbles.
 *
 *  An NSAP-address has the DTE address in the IDI. Leading zeros are
 *		significant. Trailing hex f indicates the end of the DTE address.
 *  	The IDI is a series of BCD digits, one per nibble.
 *
 * RETURNS
 *  # significant digits in the DTE address, -1 if error.
 */

Static int
NSAPtoDTE(siso, sx25)
	register struct sockaddr_iso *siso;
	register struct sockaddr_x25 *sx25;
{
	int		dtelen = -1;

	IFDEBUG(D_CADDR)
		printf("NSAPtoDTE: nsap: %s\n", clnp_iso_addrp(&siso->siso_addr));
	ENDDEBUG

	if (siso->siso_data[0] == AFI_37) {
		register char *out = sx25->x25_addr;
		register char *in = siso->siso_data + 1;
		register int nibble;
		char *lim = siso->siso_data + siso->siso_nlen;
		char *olim = out+15;
		int lowNibble = 0;

		while (in < lim) {
			nibble = ((lowNibble ? *in++ : (*in >> 4)) & 0xf) | 0x30;
			lowNibble ^= 1;
			if (nibble != 0x3f && out < olim)
				*out++ = nibble;
		}
		dtelen = out - sx25->x25_addr;
		*out++ = 0;
	} else {
		/* error = iso_8208snparesolve(addr, x121string, &x121strlen);*/
		register struct rtentry *rt;
		extern struct sockaddr_iso blank_siso;
		struct sockaddr_iso nsiso;

		nsiso = blank_siso;
		bcopy(nsiso.siso_data, siso->siso_data,
				nsiso.siso_nlen = siso->siso_nlen);
		if (rt = rtalloc1(&nsiso, 1)) {
			register struct sockaddr_x25 *sxx =
							(struct sockaddr_x25 *)rt->rt_gateway;
			register char *in = sxx->x25_addr;

			rt->rt_use--;
			if (sxx && sxx->x25_family == AF_CCITT) {
				bcopy(sx25->x25_addr, sxx->x25_addr, sizeof(sx25->x25_addr));
				while (*in++) {}
				dtelen = in - sxx->x25_addr;
			}
		}
	}
	return dtelen;
}

/*
 * NAME:	FACILtoNSAP()
 * CALLED FROM:
 *  parse_facil()
 * FUNCTION and ARGUMENTS:
 * 	Creates and NSAP in the sockaddr_iso (addr) from the
 *  x.25 facility found at buf - 1.
 * RETURNS:
 *  0 if ok, -1 if error.
 */

Static int
FACILtoNSAP(addr, buf)
	register u_char 		*buf;
	register struct sockaddr_iso *addr;
{
	int			len_in_nibbles = *++buf & 0x3f;
	u_char		buf_len = (len_in_nibbles + 1) >> 1;; /* in bytes */

	IFDEBUG(D_CADDR)
		printf("FACILtoNSAP( 0x%x, 0x%x, 0x%x )\n", 
			buf, buf_len, addr );
	ENDDEBUG

	len_in_nibbles = *buf & 0x3f;
	/* despite the fact that X.25 makes us put a length in nibbles
	 * here, the NSAP-addrs are always in full octets
	 */
	switch (*buf++ & 0xc0) {
	case 0:
		/* Entire OSI NSAP address */
		bcopy((caddr_t)buf, addr->siso_data, addr->siso_nlen = buf_len);
		break;

	case 40:
		/* Partial OSI NSAP address, assume trailing */
		if (buf_len + addr->siso_nlen > sizeof(addr->siso_addr))
			return -1;
		bcopy((caddr_t)buf, TSEL(addr), buf_len);
		addr->siso_nlen += buf_len;
		break;

	default:
		/* Rather than blow away the connection, just ignore and use
		   NSAP from DTE */;
	}
	return 0;
}

Static
init_siso(siso)
register struct sockaddr_iso *siso;
{
	siso->siso_len = sizeof (*siso);
	siso->siso_family = AF_ISO;
	siso->siso_data[0] = AFI_37;
	siso->siso_nlen = 8;
}

/*
 * NAME:	DTEtoNSAP()
 * CALLED FROM:
 *  parse_facil()
 * FUNCTION and ARGUMENTS:
 *  Creates a type 37 NSAP in the sockaddr_iso (addr)
 * 	from a DTE address found in a sockaddr_x25.
 *  
 * RETURNS:
 *  0 if ok; E* otherwise.
 */

Static  int
DTEtoNSAP(addr, sx)
	struct sockaddr_iso *addr;
	struct sockaddr_x25 *sx;
{
	register char		*in, *out;
	register int		first;
	int					pad_tail = 0;
	int 				src_len;


	init_siso(addr);
	in = sx->x25_addr;
	src_len = strlen(in);
	addr->siso_nlen = (src_len + 3) / 2;
	out = addr->siso_data;
	*out++ = 0x37;
	if (src_len & 1) {
		pad_tail = 0xf;
		src_len++;
	}
	for (first = 0; src_len > 0; src_len--) {
		first |= 0xf & *in++;
		if (src_len & 1) {
			*out++ = first;
			first = 0;
		}
		else first <<= 4;
	}
	if (pad_tail)
		out[-1] |= 0xf;
	return 0; /* ok */
}

/*
 * FUNCTION and ARGUMENTS:
 *	parses (buf_len) bytes beginning at (buf) and finds
 *  a called nsap, a calling nsap, and protocol identifier.
 * RETURNS:
 *  0 if ok, E* otherwise.
 */

Static int
parse_facil(lcp, isop, buf, buf_len)
	caddr_t 		buf;
	u_char			buf_len; /* in bytes */
	struct			isopcb *isop;
	struct			pklcd *lcp;
{
	register int 	i;
	register u_char 	*ptr = (u_char *)buf;
	u_char			*ptr_lim, *facil_lim;
	int 			facil_param_len, facil_len;

	IFDEBUG(D_CADDR)
		printf("parse_facil(0x%x, 0x%x, 0x%x, 0x%x)\n", 
			lcp, isop, buf, buf_len);
		dump_buf(buf, buf_len);
	ENDDEBUG

	/* find the beginnings of the facility fields in buf 
	 * by skipping over the called & calling DTE addresses
	 * i <- # nibbles in called + # nibbles in calling
	 * i += 1 so that an odd nibble gets rounded up to even  
	 * before dividing by 2, then divide by two to get # octets
	 */
	i = (int)(*ptr >> 4) + (int)(*ptr&0xf);
	i++;
	ptr += i >> 1;
	ptr ++; /* plus one for the DTE lengths byte */

	/* ptr now is at facil_length field */
	facil_len = *ptr++;
	facil_lim = ptr + facil_len;
	IFDEBUG(D_CADDR)
		printf("parse_facils: facil length is  0x%x\n", (int) facil_len);
	ENDDEBUG

	while (ptr < facil_lim) {
		/* get NSAP addresses from facilities */
		switch (*ptr++) {
			case 0xcb:
				/* calling NSAP */
				facil_param_len = FACILtoNSAP(isop->isop_faddr, ptr);
				break;
			case 0xc9:
				/* called NSAP */
				facil_param_len = FACILtoNSAP(isop->isop_laddr, ptr);
				break;

				/* from here to default are legit cases that I ignore */
				/* variable length */
			case 0xca:  /* end-to-end transit delay negot */
			case 0xc6:  /* network user id */
			case 0xc5: 	/* charging info : indicating monetary unit */
			case 0xc2: 	/* charging info : indicating segment count */
			case 0xc1: 	/* charging info : indicating call duration */
			case 0xc4: 	/* RPOA extended format */
			case 0xc3: 	/* call redirection notification */
				facil_param_len = 0;
				break;

				/* 1 octet */
			case 0x0a:  /* min. throughput class negot */
			case 0x02:  /* throughput class */
			case 0x03:  case 0x47:  /* CUG stuff */
			case 0x0b:  /* expedited data negot */
			case 0x01:  /* Fast select or reverse charging 
						(example of intelligent protocol design) */
			case 0x04: 	/* charging info : requesting service */
			case 0x08: 	/* called line addr modified notification */
			case 0x00:  /* marker to indicate beginning of CCITT facils */
				facil_param_len = 1;
				break;

				/* any 2 octets */
			case 0x42:  /* pkt size */
			case 0x43:  /* win size */
			case 0x44:  /* RPOA basic format */
			case 0x41:  /* bilateral CUG stuff */
			case 0x49: 	/* transit delay selection and indication */
				facil_param_len = 2;
				break;

			default:
				printf(
"BOGUS FACILITY CODE facil_lim 0x%x facil_len %d, ptr 0x%x *ptr 0x%x\n",
					facil_lim, facil_len, ptr - 1, ptr[-1]);
				/* facil that we don't handle
				return E_CO_HLI_REJI; */
				switch (ptr[-1] & 0xc0) {
				case 0x00:	facil_param_len = 1; break;
				case 0x40:	facil_param_len = 2; break;
				case 0x80:	facil_param_len = 3; break;
				case 0xc0:	facil_param_len = 0; break;
				}
		}
		if (facil_param_len == -1)
			return E_CO_REG_ICDA;
		if (facil_param_len == 0) /* variable length */ 
			facil_param_len = (int)*ptr++; /* 1 + the real facil param */
		ptr += facil_param_len;
	}
	return 0;
}

#endif /* TPCONS */
