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
 *	@(#)pk_input.c	8.1 (Berkeley) 6/10/93
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/protosw.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/malloc.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_llc.h>
#include <net/route.h>

#include <netccitt/dll.h>
#include <netccitt/x25.h>
#include <netccitt/pk.h>
#include <netccitt/pk_var.h>
#include <netccitt/llc_var.h>

struct pkcb_q pkcb_q = {&pkcb_q, &pkcb_q};

/*
 * ccittintr() is the generic interrupt handler for HDLC, LLC2, and X.25. This
 * allows to have kernel running X.25 but no HDLC or LLC2 or both (in case we
 * employ boards that do all the stuff themselves, e.g. ADAX X.25 or TPS ISDN.)
 */
void
ccittintr ()
{
	extern struct ifqueue pkintrq;
	extern struct ifqueue hdintrq;
	extern struct ifqueue llcintrq;

#if HDLC
	if (hdintrq.ifq_len)
		hdintr ();
#endif
#if LLC
	if (llcintrq.ifq_len)
		llcintr ();
#endif
	if (pkintrq.ifq_len)
		pkintr ();
}

struct pkcb *
pk_newlink (ia, llnext)
struct x25_ifaddr *ia;
caddr_t llnext;
{
	register struct x25config *xcp = &ia -> ia_xc;
	register struct pkcb *pkp;
	register struct pklcd *lcp;
	register struct protosw *pp;
	unsigned size;

	pp = pffindproto (AF_CCITT, (int) xcp -> xc_lproto, 0);
	if (pp == 0 || pp -> pr_output == 0) {
		pk_message (0, xcp, "link level protosw error");
		return ((struct pkcb *)0);
	}
	/*
	 * Allocate a network control block structure
	 */
	size = sizeof (struct pkcb);
//	pkp = (struct pkcb *) malloc (size, M_PCB, M_WAITOK);
	MALLOC(pkp, struct pkcb *, size, M_PCB, M_WAITOK);
	if (pkp == 0)
		return ((struct pkcb *)0);
	bzero ((caddr_t) pkp, size);
	pkp -> pk_lloutput = pp -> pr_output;
	pkp -> pk_llctlinput = (caddr_t (*)()) pp -> pr_ctlinput;
	pkp -> pk_xcp = xcp;
	pkp -> pk_ia = ia;
	pkp -> pk_state = DTE_WAITING;
	pkp -> pk_llnext = llnext;
	insque (pkp, &pkcb_q);

	/*
	 * set defaults
	 */

	if (xcp -> xc_pwsize == 0)
		xcp -> xc_pwsize = DEFAULT_WINDOW_SIZE;
	if (xcp -> xc_psize == 0)
		xcp -> xc_psize = X25_PS128;
	/*
	 * Allocate logical channel descriptor vector
	 */

	(void) pk_resize (pkp);
	return (pkp);
}


pk_dellink (pkp)
register struct pkcb *pkp;
{
	register int i;
	register struct protosw *pp;
	
	/*
	 * Essentially we have the choice to
	 * (a) go ahead and let the route be deleted and
	 *     leave the pkcb associated with that route
	 *     as it is, i.e. the connections stay open
	 * (b) do a pk_disconnect() on all channels associated
	 *     with the route via the pkcb and then proceed.
	 *
	 * For the time being we stick with (b)
	 */
	
	for (i = 1; i < pkp -> pk_maxlcn; ++i)
		if (pkp -> pk_chan[i])
			pk_disconnect (pkp -> pk_chan[i]);

	/*
	 * Free the pkcb
	 */

	/*
	 * First find the protoswitch to get hold of the link level
	 * protocol to be notified that the packet level entity is
	 * dissolving ...
	 */
	pp = pffindproto (AF_CCITT, (int) pkp -> pk_xcp -> xc_lproto, 0);
	if (pp == 0 || pp -> pr_output == 0) {
		pk_message (0, pkp -> pk_xcp, "link level protosw error");
		return (EPROTONOSUPPORT);
	}

	pkp -> pk_refcount--;
	if (!pkp -> pk_refcount) {
		struct dll_ctlinfo ctlinfo;

		remque (pkp);
		if (pkp -> pk_rt -> rt_llinfo == (caddr_t) pkp)
			pkp -> pk_rt -> rt_llinfo = (caddr_t) NULL;
		
		/*
		 * Tell the link level that the pkcb is dissolving
		 */
		if (pp -> pr_ctlinput && pkp -> pk_llnext) {
			ctlinfo.dlcti_pcb = pkp -> pk_llnext;
			ctlinfo.dlcti_rt = pkp -> pk_rt;
			(pp -> pr_ctlinput)(PRC_DISCONNECT_REQUEST, 
					    pkp -> pk_xcp, &ctlinfo);
		}
		FREE((caddr_t) pkp -> pk_chan, M_IFADDR);
		FREE((caddr_t) pkp, M_PCB);
	}

	return (0);
}


pk_resize (pkp)
register struct pkcb *pkp;
{
	struct pklcd *dev_lcp = 0;
	struct x25config *xcp = pkp -> pk_xcp;
	if (pkp -> pk_chan &&
	    (pkp -> pk_maxlcn != xcp -> xc_maxlcn)) {
		pk_restart (pkp, X25_RESTART_NETWORK_CONGESTION);
		dev_lcp = pkp -> pk_chan[0];
		FREE((caddr_t) pkp -> pk_chan, M_IFADDR);
		pkp -> pk_chan = 0;
	}
	if (pkp -> pk_chan == 0) {
		unsigned size;
		pkp -> pk_maxlcn = xcp -> xc_maxlcn;
		size = (pkp -> pk_maxlcn + 1) * sizeof (struct pklcd *);
//		pkp -> pk_chan =
//			(struct pklcd **) malloc (size, M_IFADDR, M_WAITOK);
		MALLOC(pkp->pk_chan, struct pklcd **, size, M_IFADDR, M_WAITOK);
		if (pkp -> pk_chan) {
			bzero ((caddr_t) pkp -> pk_chan, size);
			/*
			 * Allocate a logical channel descriptor for lcn 0
			 */
			if (dev_lcp == 0 &&
			    (dev_lcp = pk_attach ((struct socket *)0)) == 0)
				return (ENOBUFS);
			dev_lcp -> lcd_state = READY;
			dev_lcp -> lcd_pkp = pkp;
			pkp -> pk_chan[0] = dev_lcp;
		} else {
			if (dev_lcp)
				pk_close (dev_lcp);
			return (ENOBUFS);
		}
	}
	return 0;
}

/* 
 *  This procedure is called by the link level whenever the link
 *  becomes operational, is reset, or when the link goes down. 
 */
/*VARARGS*/
caddr_t
pk_ctlinput (code, src, addr)
	int code;
	struct sockaddr *src;
	caddr_t addr;
{
	register struct pkcb *pkp = (struct pkcb *) addr;

	switch (code) {
	case PRC_LINKUP: 
		if (pkp -> pk_state == DTE_WAITING)
			pk_restart (pkp, X25_RESTART_NETWORK_CONGESTION);
		break;

	case PRC_LINKDOWN: 
		pk_restart (pkp, -1);	/* Clear all active circuits */
		pkp -> pk_state = DTE_WAITING;
		break;

	case PRC_LINKRESET: 
		pk_restart (pkp, X25_RESTART_NETWORK_CONGESTION);
		break;
		
	case PRC_CONNECT_INDICATION: {
		struct rtentry *llrt;

		if ((llrt = rtalloc1(src, 0)) == 0)
			return 0;
		else llrt -> rt_refcnt--;
		
		pkp = (((struct npaidbentry *) llrt -> rt_llinfo) -> np_rt) ?
			(struct pkcb *)(((struct npaidbentry *) llrt -> rt_llinfo) -> np_rt -> rt_llinfo) : (struct pkcb *) 0;
		if (pkp == (struct pkcb *) 0)
			return 0;
		pkp -> pk_llnext = addr;

		return ((caddr_t) pkp);
	}
	case PRC_DISCONNECT_INDICATION:
		pk_restart (pkp, -1) ;  /* Clear all active circuits */
		pkp -> pk_state = DTE_WAITING;
		pkp -> pk_llnext = (caddr_t) 0;
	}
	return (0);
}
struct ifqueue pkintrq;
/*
 * This routine is called if there are semi-smart devices that do HDLC
 * in hardware and want to queue the packet and call level 3 directly
 */
pkintr ()
{
	register struct mbuf *m;
	register struct ifaddr *ifa;
	register struct ifnet *ifp;
	register int s;

	for (;;) {
		s = splimp ();
		IF_DEQUEUE (&pkintrq, m);
		splx (s);
		if (m == 0)
			break;
		if (m -> m_len < PKHEADERLN) {
			printf ("pkintr: packet too short (len=%d)\n",
				m -> m_len);
			m_freem (m);
			continue;
		}
		pk_input (m);
	}
}
struct mbuf *pk_bad_packet;
struct mbuf_cache pk_input_cache = {0 };
/* 
 *  X.25 PACKET INPUT
 *
 *  This procedure is called by a link level procedure whenever
 *  an information frame is received. It decodes the packet and
 *  demultiplexes based on the logical channel number.
 *
 *  We change the original conventions of the UBC code here --
 *  since there may be multiple pkcb's for a given interface
 *  of type 802.2 class 2, we retrieve which one it is from
 *  m_pkthdr.rcvif (which has been overwritten by lower layers);
 *  That field is then restored for the benefit of upper layers which
 *  may make use of it, such as CLNP.
 *
 */

#define RESTART_DTE_ORIGINATED(xp) (((xp) -> packet_cause == X25_RESTART_DTE_ORIGINATED) || \
			    ((xp) -> packet_cause >= X25_RESTART_DTE_ORIGINATED2))

pk_input (m)
register struct mbuf *m;
{
	register struct x25_packet *xp;
	register struct pklcd *lcp;
	register struct socket *so = 0;
	register struct pkcb *pkp;
	int  ptype, lcn, lcdstate = LISTEN;

	if (pk_input_cache.mbc_size || pk_input_cache.mbc_oldsize)
		mbuf_cache (&pk_input_cache, m);
	if ((m -> m_flags & M_PKTHDR) == 0)
		panic ("pkintr");

	if ((pkp = (struct pkcb *) m -> m_pkthdr.rcvif) == 0)
		return;
	xp = mtod (m, struct x25_packet *);
	ptype = pk_decode (xp);
	lcn = LCN(xp);
	lcp = pkp -> pk_chan[lcn];

	/* 
	 *  If the DTE is in Restart  state, then it will ignore data, 
	 *  interrupt, call setup and clearing, flow control and reset 
	 *  packets.
	 */
	if (lcn < 0 || lcn > pkp -> pk_maxlcn) {
		pk_message (lcn, pkp -> pk_xcp, "illegal lcn");
		m_freem (m);
		return;
	}

	pk_trace (pkp -> pk_xcp, m, "P-In");

	if (pkp -> pk_state != DTE_READY && ptype != RESTART && ptype != RESTART_CONF) {
		m_freem (m);
		return;
	}
	if (lcp) {
		so = lcp -> lcd_so;
		lcdstate = lcp -> lcd_state;
	} else {
		if (ptype == CLEAR) {	/* idle line probe (Datapac specific) */
			/* send response on lcd 0's output queue */
			lcp = pkp -> pk_chan[0];
			lcp -> lcd_template = pk_template (lcn, X25_CLEAR_CONFIRM);
			pk_output (lcp);
			m_freem (m);
			return;
		}
		if (ptype != CALL)
			ptype = INVALID_PACKET;
	}

	if (lcn == 0 && ptype != RESTART && ptype != RESTART_CONF) {
		pk_message (0, pkp -> pk_xcp, "illegal ptype (%d, %s) on lcn 0",
			ptype, pk_name[ptype / MAXSTATES]);
		if (pk_bad_packet)
			m_freem (pk_bad_packet);
		pk_bad_packet = m;
		return;
	}

	m -> m_pkthdr.rcvif = pkp -> pk_ia -> ia_ifp;

	switch (ptype + lcdstate) {
	/* 
	 *  Incoming Call packet received. 
	 */
	case CALL + LISTEN: 
		pk_incoming_call (pkp, m);
		break;

	/* 	
	 *  Call collision: Just throw this "incoming call" away since 
	 *  the DCE will ignore it anyway. 
	 */
	case CALL + SENT_CALL: 
		pk_message ((int) lcn, pkp -> pk_xcp, 
			"incoming call collision");
		break;

	/* 
	 *  Call confirmation packet received. This usually means our
	 *  previous connect request is now complete.
	 */
	case CALL_ACCEPTED + SENT_CALL: 
		MCHTYPE(m, MT_CONTROL);
		pk_call_accepted (lcp, m);
		break;

	/* 
	 *  This condition can only happen if the previous state was
	 *  SENT_CALL. Just ignore the packet, eventually a clear 
	 *  confirmation should arrive.
	 */
	case CALL_ACCEPTED + SENT_CLEAR: 
		break;

	/* 
	 *  Clear packet received. This requires a complete tear down
	 *  of the virtual circuit.  Free buffers and control blocks.
	 *  and send a clear confirmation.
	 */
	case CLEAR + READY:
	case CLEAR + RECEIVED_CALL: 
	case CLEAR + SENT_CALL: 
	case CLEAR + DATA_TRANSFER: 
		lcp -> lcd_state = RECEIVED_CLEAR;
		lcp -> lcd_template = pk_template (lcp -> lcd_lcn, X25_CLEAR_CONFIRM);
		pk_output (lcp);
		pk_clearcause (pkp, xp);
		if (lcp -> lcd_upper) {
			MCHTYPE(m, MT_CONTROL);
			lcp -> lcd_upper (lcp, m);
		}
		pk_close (lcp);
		lcp = 0;
		break;

	/* 
	 *  Clear collision: Treat this clear packet as a confirmation.
	 */
	case CLEAR + SENT_CLEAR: 
		pk_close (lcp);
		break;

	/* 
	 *  Clear confirmation received. This usually means the virtual
	 *  circuit is now completely removed.
	 */
	case CLEAR_CONF + SENT_CLEAR: 
		pk_close (lcp);
		break;

	/* 
	 *  A clear confirmation on an unassigned logical channel - just
	 *  ignore it. Note: All other packets on an unassigned channel
	 *  results in a clear.
	 */
	case CLEAR_CONF + READY:
	case CLEAR_CONF + LISTEN:
		break;

	/* 
	 *  Data packet received. Pass on to next level. Move the Q and M
	 *  bits into the data portion for the next level.
	 */
	case DATA + DATA_TRANSFER: 
		if (lcp -> lcd_reset_condition) {
			ptype = DELETE_PACKET;
			break;
		}

		/* 
		 *  Process the P(S) flow control information in this Data packet. 
		 *  Check that the packets arrive in the correct sequence and that 
		 *  they are within the "lcd_input_window". Input window rotation is 
		 *  initiated by the receive interface.
		 */

		if (PS(xp) != ((lcp -> lcd_rsn + 1) % MODULUS) ||
			PS(xp) == ((lcp -> lcd_input_window + lcp -> lcd_windowsize) % MODULUS)) {
			m_freem (m);
			pk_procerror (RESET, lcp, "p(s) flow control error", 1);
			break;
		}
		lcp -> lcd_rsn = PS(xp);

		if (pk_ack (lcp, PR(xp)) != PACKET_OK) {
			m_freem (m);
			break;
		}
		m -> m_data += PKHEADERLN;
		m -> m_len -= PKHEADERLN;
		m -> m_pkthdr.len -= PKHEADERLN;

		lcp -> lcd_rxcnt++;
		if (lcp -> lcd_flags & X25_MBS_HOLD) {
			register struct mbuf *n = lcp -> lcd_cps;
			int mbit = MBIT(xp);
			octet q_and_d_bits;

			if (n) {
				n -> m_pkthdr.len += m -> m_pkthdr.len;
				while (n -> m_next)
					n = n -> m_next;
				n -> m_next = m;
				m = lcp -> lcd_cps;

				if (lcp -> lcd_cpsmax &&
				    n -> m_pkthdr.len > lcp -> lcd_cpsmax) {
					pk_procerror (RESET, lcp,
						"C.P.S. overflow", 128);
					return;
				}
				q_and_d_bits = 0xc0 & *(octet *) xp;
				xp = (struct x25_packet *)
					(mtod (m, octet *) - PKHEADERLN);
				*(octet *) xp |= q_and_d_bits;
			}
			if (mbit) {
				lcp -> lcd_cps = m;
				pk_flowcontrol (lcp, 0, 1);
				return;
			}
			lcp -> lcd_cps = 0;
		}
		if (so == 0)
			break;
		if (lcp -> lcd_flags & X25_MQBIT) {
			octet t = (X25GBITS(xp -> bits, q_bit)) ? t = 0x80 : 0;

			if (MBIT(xp))
				t |= 0x40;
			m -> m_data -= 1;
			m -> m_len += 1;
			m -> m_pkthdr.len += 1;
			*mtod (m, octet *) = t;
		}

		/*
		 * Discard Q-BIT packets if the application
		 * doesn't want to be informed of M and Q bit status
		 */
		if (X25GBITS(xp -> bits, q_bit) 
		    && (lcp -> lcd_flags & X25_MQBIT) == 0) {
			m_freem (m);
			/*
			 * NB.  This is dangerous: sending a RR here can
			 * cause sequence number errors if a previous data
			 * packet has not yet been passed up to the application
			 * (RR's are normally generated via PRU_RCVD).
			 */
			pk_flowcontrol (lcp, 0, 1);
		} else {
			sbappendrecord (&so -> so_rcv, m);
			sorwakeup (so);
		}
		break;

	/* 
	 *  Interrupt packet received.
	 */
	case INTERRUPT + DATA_TRANSFER: 
		if (lcp -> lcd_reset_condition)
			break;
		lcp -> lcd_intrdata = xp -> packet_data;
		lcp -> lcd_template = pk_template (lcp -> lcd_lcn, X25_INTERRUPT_CONFIRM);
		pk_output (lcp);
		m -> m_data += PKHEADERLN;
		m -> m_len -= PKHEADERLN;
		m -> m_pkthdr.len -= PKHEADERLN;
		MCHTYPE(m, MT_OOBDATA);
		if (so) {
			if (so -> so_options & SO_OOBINLINE)
				sbinsertoob (&so -> so_rcv, m);
			else
				m_freem (m);
			sohasoutofband (so);
		}
		break;

	/* 
	 *  Interrupt confirmation packet received.
	 */
	case INTERRUPT_CONF + DATA_TRANSFER: 
		if (lcp -> lcd_reset_condition)
			break;
		if (lcp -> lcd_intrconf_pending == TRUE)
			lcp -> lcd_intrconf_pending = FALSE;
		else
			pk_procerror (RESET, lcp, "unexpected packet", 43);
		break;

	/* 
	 *  Receiver ready received. Rotate the output window and output
	 *  any data packets waiting transmission.
	 */
	case RR + DATA_TRANSFER: 
		if (lcp -> lcd_reset_condition ||
		    pk_ack (lcp, PR(xp)) != PACKET_OK) {
			ptype = DELETE_PACKET;
			break;
		}
		if (lcp -> lcd_rnr_condition == TRUE)
			lcp -> lcd_rnr_condition = FALSE;
		pk_output (lcp);
		break;

	/* 
	 *  Receiver Not Ready received. Packets up to the P(R) can be
	 *  be sent. Condition is cleared with a RR.
	 */
	case RNR + DATA_TRANSFER: 
		if (lcp -> lcd_reset_condition ||
		    pk_ack (lcp, PR(xp)) != PACKET_OK) {
			ptype = DELETE_PACKET;
			break;
		}
		lcp -> lcd_rnr_condition = TRUE;
		break;

	/* 
	 *  Reset packet received. Set state to FLOW_OPEN.  The Input and
	 *  Output window edges ar set to zero. Both the send and receive
	 *  numbers are reset. A confirmation is returned.
	 */
	case RESET + DATA_TRANSFER: 
		if (lcp -> lcd_reset_condition)
			/* Reset collision. Just ignore packet. */
			break;

		pk_resetcause (pkp, xp);
		lcp -> lcd_window_condition = lcp -> lcd_rnr_condition =
			lcp -> lcd_intrconf_pending = FALSE;
		lcp -> lcd_output_window = lcp -> lcd_input_window =
			lcp -> lcd_last_transmitted_pr = 0;
		lcp -> lcd_ssn = 0;
		lcp -> lcd_rsn = MODULUS - 1;

		lcp -> lcd_template = pk_template (lcp -> lcd_lcn, X25_RESET_CONFIRM);
		pk_output (lcp);

		pk_flush (lcp);
		if (so == 0)
			break;
		wakeup ((caddr_t) & so -> so_timeo);
		sorwakeup (so);
		sowwakeup (so);
		break;

	/* 
	 *  Reset confirmation received.
	 */
	case RESET_CONF + DATA_TRANSFER: 
		if (lcp -> lcd_reset_condition) {
			lcp -> lcd_reset_condition = FALSE;
			pk_output (lcp);
		}
		else
			pk_procerror (RESET, lcp, "unexpected packet", 32);
		break;

	case DATA + SENT_CLEAR: 
		ptype = DELETE_PACKET;
	case RR + SENT_CLEAR: 
	case RNR + SENT_CLEAR: 
	case INTERRUPT + SENT_CLEAR: 
	case INTERRUPT_CONF + SENT_CLEAR: 
	case RESET + SENT_CLEAR: 
	case RESET_CONF + SENT_CLEAR: 
		/* Just ignore p if we have sent a CLEAR already.
		   */
		break;

	/* 
	 *  Restart sets all the permanent virtual circuits to the "Data
	 *  Transfer" stae and  all the switched virtual circuits to the
	 *  "Ready" state.
	 */
	case RESTART + READY: 
		switch (pkp -> pk_state) {
		case DTE_SENT_RESTART: 
			/* 
			 * Restart collision.
			 * If case the restart cause is "DTE originated" we
			 * have a DTE-DTE situation and are trying to resolve
			 * who is going to play DTE/DCE [ISO 8208:4.2-4.5]
			 */
			if (RESTART_DTE_ORIGINATED(xp)) {
				pk_restart (pkp, X25_RESTART_DTE_ORIGINATED);
				pk_message (0, pkp -> pk_xcp,
					    "RESTART collision");
				if ((pkp -> pk_restartcolls++) > MAXRESTARTCOLLISIONS) {
					pk_message (0, pkp -> pk_xcp,
						    "excessive RESTART collisions");
					pkp -> pk_restartcolls = 0;
				}
				break;
			}
			pkp -> pk_state = DTE_READY;
			pkp -> pk_dxerole |= DTE_PLAYDTE;
			pkp -> pk_dxerole &= ~DTE_PLAYDCE;
			pk_message (0, pkp -> pk_xcp,
				"Packet level operational");
			pk_message (0, pkp -> pk_xcp, 
				    "Assuming DTE role");
			if (pkp -> pk_dxerole & DTE_CONNECTPENDING)
				pk_callcomplete (pkp);
			break;

		default: 
			pk_restart (pkp, -1);
			pk_restartcause (pkp, xp);
			pkp -> pk_chan[0] -> lcd_template = pk_template (0,
				X25_RESTART_CONFIRM);
			pk_output (pkp -> pk_chan[0]);
			pkp -> pk_state = DTE_READY;
			pkp -> pk_dxerole |= RESTART_DTE_ORIGINATED(xp) ? DTE_PLAYDCE :
				DTE_PLAYDTE;
			if (pkp -> pk_dxerole & DTE_PLAYDTE) {
				pkp -> pk_dxerole &= ~DTE_PLAYDCE;
				pk_message (0, pkp -> pk_xcp, 
					    "Assuming DTE role");
			} else {
				pkp -> pk_dxerole &= ~DTE_PLAYDTE;
				pk_message (0, pkp -> pk_xcp, 
					 "Assuming DCE role");
			}
			if (pkp -> pk_dxerole & DTE_CONNECTPENDING)
				pk_callcomplete (pkp);
		}
		break;

	/* 
	 *  Restart confirmation received. All logical channels are set
	 *  to READY. 
	 */
	case RESTART_CONF + READY: 
		switch (pkp -> pk_state) {
		case DTE_SENT_RESTART: 
			pkp -> pk_state = DTE_READY;
			pkp -> pk_dxerole |= DTE_PLAYDTE;
			pkp -> pk_dxerole &= ~DTE_PLAYDCE;
			pk_message (0, pkp -> pk_xcp,
				    "Packet level operational");
			pk_message (0, pkp -> pk_xcp,
				    "Assuming DTE role");
			if (pkp -> pk_dxerole & DTE_CONNECTPENDING)
				pk_callcomplete (pkp);
			break;

		default: 
			/* Restart local procedure error. */
			pk_restart (pkp, X25_RESTART_LOCAL_PROCEDURE_ERROR);
			pkp -> pk_state = DTE_SENT_RESTART;
			pkp -> pk_dxerole &= ~(DTE_PLAYDTE | DTE_PLAYDCE);
		}
		break;

	default: 
		if (lcp) {
			pk_procerror (CLEAR, lcp, "unknown packet error", 33);
			pk_message (lcn, pkp -> pk_xcp,
				"\"%s\" unexpected in \"%s\" state",
				pk_name[ptype/MAXSTATES], pk_state[lcdstate]);
		} else
			pk_message (lcn, pkp -> pk_xcp,
				"packet arrived on unassigned lcn");
		break;
	}
	if (so == 0 && lcp && lcp -> lcd_upper && lcdstate == DATA_TRANSFER) {
		if (ptype != DATA && ptype != INTERRUPT)
			MCHTYPE(m, MT_CONTROL);
		lcp -> lcd_upper (lcp, m);
	} else if (ptype != DATA && ptype != INTERRUPT)
		m_freem (m);
}

static
prune_dnic (from, to, dnicname, xcp)
char *from, *to, *dnicname;
register struct x25config *xcp;
{
	register char *cp1 = from, *cp2 = from;
	if (xcp -> xc_prepnd0 && *cp1 == '0') {
		from = ++cp1;
		goto copyrest;
	}
	if (xcp -> xc_nodnic) {
		for (cp1 = dnicname; *cp2 = *cp1++;)
			cp2++;
		cp1 = from;
	}
copyrest:
	for (cp1 = dnicname; *cp2 = *cp1++;)
		cp2++;
}
/* static */
pk_simple_bsd (from, to, lower, len)
register octet *from, *to;
register len, lower;
{
	register int c;
	while (--len >= 0) {
		c = *from;
		if (lower & 0x01)
			*from++;
		else
			c >>= 4;
		c &= 0x0f; c |= 0x30; *to++ = c; lower++;
	}
	*to = 0;
}

/*static octet * */
pk_from_bcd (a, iscalling, sa, xcp)
register struct x25_calladdr *a;
int	iscalling;
register struct sockaddr_x25 *sa;
register struct x25config *xcp;
{
	octet buf[MAXADDRLN+1];
	octet *cp;
	unsigned count;

	bzero ((caddr_t) sa, sizeof (*sa));
	sa -> x25_len = sizeof (*sa);
	sa -> x25_family = AF_CCITT;
	if (iscalling) {
		cp = a -> address_field + (X25GBITS(a -> addrlens, called_addrlen) / 2);
		count = X25GBITS(a -> addrlens, calling_addrlen);
		pk_simple_bsd (cp, buf, X25GBITS(a -> addrlens, called_addrlen), count);
	} else {
		count = X25GBITS(a -> addrlens, called_addrlen);
		pk_simple_bsd (a -> address_field, buf, 0, count);
	}
	if (xcp -> xc_addr.x25_net && (xcp -> xc_nodnic || xcp -> xc_prepnd0)) {
		octet dnicname[sizeof (long) * NBBY/3 + 2];

		sprintf ((char *) dnicname, "%d", xcp -> xc_addr.x25_net);
		prune_dnic ((char *) buf, sa -> x25_addr, dnicname, xcp);
	} else
		bcopy ((caddr_t) buf, (caddr_t) sa -> x25_addr, count + 1);
}

static
save_extra (m0, fp, so)
struct mbuf *m0;
octet *fp;
struct socket *so;
{
	register struct mbuf *m;
	struct cmsghdr cmsghdr;
	if (m = m_copy (m, 0, (int)M_COPYALL)) {
		int off = fp - mtod (m0, octet *);
		int len = m -> m_pkthdr.len - off + sizeof (cmsghdr);
		cmsghdr.cmsg_len = len;
		cmsghdr.cmsg_level = AF_CCITT;
		cmsghdr.cmsg_type = PK_FACILITIES;
		m_adj (m, off);
		M_PREPEND (m, sizeof (cmsghdr), M_DONTWAIT);
		if (m == 0)
			return;
		bcopy ((caddr_t)&cmsghdr, mtod (m, caddr_t), sizeof (cmsghdr));
		MCHTYPE(m, MT_CONTROL);
		sbappendrecord (&so -> so_rcv, m);
	}
}

/* 
 * This routine handles incoming call packets. It matches the protocol
 * field on the Call User Data field (usually the first four bytes) with 
 * sockets awaiting connections.
 */

pk_incoming_call (pkp, m0)
struct mbuf *m0;
struct pkcb *pkp;
{
	register struct pklcd *lcp = 0, *l;
	register struct sockaddr_x25 *sa;
	register struct x25_calladdr *a;
	register struct socket *so = 0;
	struct	x25_packet *xp = mtod (m0, struct x25_packet *);
	struct	mbuf *m;
	struct	x25config *xcp = pkp -> pk_xcp;
	int len = m0 -> m_pkthdr.len;
	int udlen;
	char *errstr = "server unavailable";
	octet *u, *facp;
	int lcn = LCN(xp);

	/* First, copy the data from the incoming call packet to a X25 address
	   descriptor. It is to be regretted that you have
	   to parse the facilities into a sockaddr to determine
	   if reverse charging is being requested */
	if ((m = m_get (M_DONTWAIT, MT_SONAME)) == 0)
		return;
	sa = mtod (m, struct sockaddr_x25 *);
	a = (struct x25_calladdr *) &xp -> packet_data;
	facp = u = (octet *) (a -> address_field +
		((X25GBITS(a -> addrlens, called_addrlen) + X25GBITS(a -> addrlens, calling_addrlen) + 1) / 2));
	u += *u + 1;
	udlen = min (16, ((octet *) xp) + len - u);
	if (udlen < 0)
		udlen = 0;
	pk_from_bcd (a, 1, sa, pkp -> pk_xcp); /* get calling address */
	pk_parse_facilities (facp, sa);
	bcopy ((caddr_t) u, sa -> x25_udata, udlen);
	sa -> x25_udlen = udlen;

	/*
	 * Now, loop through the listen sockets looking for a match on the
	 * PID. That is the first few octets of the user data field.
	 * This is the closest thing to a port number for X.25 packets.
	 * It does provide a way of multiplexing services at the user level. 
	 */

	for (l = pk_listenhead; l; l = l -> lcd_listen) {
		struct sockaddr_x25 *sxp = l -> lcd_ceaddr;

		if (bcmp (sxp -> x25_udata, u, sxp -> x25_udlen))
			continue;
		if (sxp -> x25_net &&
		    sxp -> x25_net != xcp -> xc_addr.x25_net)
			continue;
		/*
		 * don't accept incoming calls with the D-Bit on
		 * unless the server agrees
		 */
		if (X25GBITS(xp -> bits, d_bit) && !(sxp -> x25_opts.op_flags & X25_DBIT)) {
			errstr = "incoming D-Bit mismatch";
			break;
		}
		/*
		 * don't accept incoming collect calls unless
		 * the server sets the reverse charging option.
		 */
		if ((sxp -> x25_opts.op_flags & (X25_OLDSOCKADDR|X25_REVERSE_CHARGE)) == 0 &&
			sa -> x25_opts.op_flags & X25_REVERSE_CHARGE) {
			errstr = "incoming collect call refused";
			break;
		}
		if (l -> lcd_so) {
			if (so = sonewconn (l -> lcd_so, SS_ISCONNECTED))
				    lcp = (struct pklcd *) so -> so_pcb;
		} else 
			lcp = pk_attach ((struct socket *) 0);
		if (lcp == 0) {
			/*
			 * Insufficient space or too many unaccepted
			 * connections.  Just throw the call away.
			 */
			errstr = "server malfunction";
			break;
		}
		lcp -> lcd_upper = l -> lcd_upper;
		lcp -> lcd_upnext = l -> lcd_upnext;
		lcp -> lcd_lcn = lcn;
		lcp -> lcd_state = RECEIVED_CALL;
		sa -> x25_opts.op_flags |= (sxp -> x25_opts.op_flags &
			~X25_REVERSE_CHARGE) | l -> lcd_flags;
		pk_assoc (pkp, lcp, sa);
		lcp -> lcd_faddr = *sa;
		lcp -> lcd_laddr.x25_udlen = sxp -> x25_udlen;
		lcp -> lcd_craddr = &lcp -> lcd_faddr;
		lcp -> lcd_template = pk_template (lcp -> lcd_lcn, X25_CALL_ACCEPTED);
		if (lcp -> lcd_flags & X25_DBIT) {
			if (X25GBITS(xp -> bits, d_bit))
				X25SBITS(mtod (lcp -> lcd_template,
					struct x25_packet *) -> bits, d_bit, 1);
			else
				lcp -> lcd_flags &= ~X25_DBIT;
		}
		if (so) {
			pk_output (lcp);
			soisconnected (so);
			if (so -> so_options & SO_OOBINLINE)
				save_extra (m0, facp, so);
		} else if (lcp -> lcd_upper) {
			(*lcp -> lcd_upper) (lcp, m0);
		}
		(void) m_free (m);
		return;
	}

	/*
	 * If the call fails for whatever reason, we still need to build a
	 * skeleton LCD in order to be able to properly  receive the CLEAR
	 * CONFIRMATION.
	 */
#ifdef WATERLOO		/* be explicit */
	if (l == 0 && bcmp (sa -> x25_udata, "ean", 3) == 0)
		pk_message (lcn, pkp -> pk_xcp, "host=%s ean%c: %s",
			sa -> x25_addr, sa -> x25_udata[3] & 0xff, errstr);
	else if (l == 0 && bcmp (sa -> x25_udata, "\1\0\0\0", 4) == 0)
		pk_message (lcn, pkp -> pk_xcp, "host=%s x29d: %s",
			sa -> x25_addr, errstr);
	else
#endif
	pk_message (lcn, pkp -> pk_xcp, "host=%s pid=%x %x %x %x: %s",
		sa -> x25_addr, sa -> x25_udata[0] & 0xff,
		sa -> x25_udata[1] & 0xff, sa -> x25_udata[2] & 0xff,
		sa -> x25_udata[3] & 0xff, errstr);
	if ((lcp = pk_attach ((struct socket *)0)) == 0) {
		(void) m_free (m);
		return;
	}
	lcp -> lcd_lcn = lcn;
	lcp -> lcd_state = RECEIVED_CALL;
	pk_assoc (pkp, lcp, sa);
	(void) m_free (m);
	pk_clear (lcp, 0, 1);
}

pk_call_accepted (lcp, m)
struct pklcd *lcp;
struct mbuf *m;
{
	register struct x25_calladdr *ap;
	register octet *fcp;
	struct x25_packet *xp = mtod (m, struct x25_packet *);
	int len = m -> m_len;

	lcp -> lcd_state = DATA_TRANSFER;
	if (lcp -> lcd_so)
		soisconnected (lcp -> lcd_so);
	if ((lcp -> lcd_flags & X25_DBIT) && (X25GBITS(xp -> bits, d_bit) == 0))
		lcp -> lcd_flags &= ~X25_DBIT;
	if (len > 3) {
		ap = (struct x25_calladdr *) &xp -> packet_data;
		fcp = (octet *) ap -> address_field + (X25GBITS(ap -> addrlens, calling_addrlen) +
			X25GBITS(ap -> addrlens, called_addrlen) + 1) / 2;
		if (fcp + *fcp <= ((octet *) xp) + len)
			pk_parse_facilities (fcp, lcp -> lcd_ceaddr);
	}
	pk_assoc (lcp -> lcd_pkp, lcp, lcp -> lcd_ceaddr);
	if (lcp -> lcd_so == 0 && lcp -> lcd_upper)
		lcp -> lcd_upper (lcp, m);
}

pk_parse_facilities (fcp, sa)
register octet *fcp;
register struct sockaddr_x25 *sa;
{
	register octet *maxfcp;

	maxfcp = fcp + *fcp;
	fcp++;
	while (fcp < maxfcp) {
		/*
		 * Ignore national DCE or DTE facilities
		 */
		if (*fcp == 0 || *fcp == 0xff)
			break;
		switch (*fcp) {
		case FACILITIES_WINDOWSIZE:
			sa -> x25_opts.op_wsize = fcp[1];
			fcp += 3;
			break;

		case FACILITIES_PACKETSIZE:
			sa -> x25_opts.op_psize = fcp[1];
			fcp += 3;
			break;

		case FACILITIES_THROUGHPUT:
			sa -> x25_opts.op_speed = fcp[1];
			fcp += 2;
			break;

		case FACILITIES_REVERSE_CHARGE:
			if (fcp[1] & 01)
				sa -> x25_opts.op_flags |= X25_REVERSE_CHARGE;
			/*
			 * Datapac specific: for a X.25(1976) DTE, bit 2
			 * indicates a "hi priority" (eg. international) call.
			 */
			if (fcp[1] & 02 && sa -> x25_opts.op_psize == 0)
				sa -> x25_opts.op_psize = X25_PS128;
			fcp += 2;
			break;

		default:
/*printf("unknown facility %x, class=%d\n", *fcp, (*fcp & 0xc0) >> 6);*/
			switch ((*fcp & 0xc0) >> 6) {
			case 0:			/* class A */
				fcp += 2;
				break;

			case 1:
				fcp += 3;
				break;

			case 2:
				fcp += 4;
				break;

			case 3:
				fcp++;
				fcp += *fcp;
			}
		}
	}
}
