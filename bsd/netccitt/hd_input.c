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
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Laboratory for Computation Vision and the Computer Science Department
 * of the University of British Columbia.
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
 *	@(#)hd_input.c	8.1 (Berkeley) 6/10/93
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/socket.h>
#include <sys/protosw.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kernel.h>

#include <net/if.h>

#include <netccitt/hdlc.h>
#include <netccitt/hd_var.h>
#include <netccitt/x25.h>

static frame_reject();
static rej_routine();
static free_iframes();
/*
 *      HDLC INPUT INTERFACE
 *
 *      This routine is called when the HDLC physical device has
 *      completed reading a frame.
 */

hdintr ()
{
	register struct mbuf *m;
	register struct hdcb *hdp;
	register struct ifnet *ifp;
	register int s;
	static struct ifnet *lastifp;
	static struct hdcb *lasthdp;

	for (;;) {
		s = splimp ();
		IF_DEQUEUE (&hdintrq, m);
		splx (s);
		if (m == 0)
			break;
		if (m->m_len < HDHEADERLN) {
			printf ("hdintr: packet too short (len=%d)\n",
				m->m_len);
			m_freem (m);
			continue;
		}
		if ((m->m_flags & M_PKTHDR) == 0)
			panic("hdintr");
		ifp = m->m_pkthdr.rcvif;

		/*
		 * look up the appropriate hdlc control block
		 */

		if (ifp == lastifp)
			hdp = lasthdp;
		else {
			for (hdp = hdcbhead; hdp; hdp = hdp->hd_next)
				if (hdp->hd_ifp == ifp)
					break;
			if (hdp == 0) {
				printf ("hdintr: unknown interface %x\n", ifp);
				m_freem (m);
				continue;
			}
			lastifp = ifp;
			lasthdp = hdp;
		}

		/* Process_rxframe returns FALSE if the frame was NOT queued
		   for the next higher layers. */
		if (process_rxframe (hdp, m) == FALSE)
			m_freem (m);
	}
}

process_rxframe (hdp, fbuf)
register struct hdcb *hdp;
register struct mbuf *fbuf;
{
	register int queued = FALSE, frametype, pf;
	register struct Hdlc_frame *frame;

	frame = mtod (fbuf, struct Hdlc_frame *);
	pf = ((struct Hdlc_iframe *) frame) -> pf;

	hd_trace (hdp, RX, frame);
	if (frame -> address != ADDRESS_A && frame -> address != ADDRESS_B)
		return (queued);

	switch ((frametype = hd_decode (hdp, frame)) + hdp->hd_state) {
	case DM + DISC_SENT:
	case UA + DISC_SENT:
		/*
		 * Link now closed.  Leave timer running
		 * so hd_timer() can periodically check the
		 * status of interface driver flag bit IFF_UP.
		 */
		hdp->hd_state = DISCONNECTED;
		break;

	case DM + INIT:
	case UA + INIT:
		/*
		 * This is a non-standard state change needed for DCEs
		 * that do dynamic link selection.  We can't go into the
		 * usual "SEND DM" state because a DM is a SARM in LAP.
		 */
		hd_writeinternal (hdp, SABM, POLLOFF);
		hdp->hd_state = SABM_SENT;
		SET_TIMER (hdp);
		break;

	case SABM + DM_SENT: 
	case SABM + WAIT_SABM: 
		hd_writeinternal (hdp, UA, pf);
	case UA + SABM_SENT: 
	case UA + WAIT_UA: 
		KILL_TIMER (hdp);
		hd_initvars (hdp);
		hdp->hd_state = ABM;
		hd_message (hdp, "Link level operational");
		/* Notify the packet level - to send RESTART. */
		(void) pk_ctlinput (PRC_LINKUP, hdp->hd_pkp);
		break;

	case SABM + SABM_SENT: 
		/* Got a SABM collision. Acknowledge the remote's SABM
		   via UA but still wait for UA. */
		hd_writeinternal (hdp, UA, pf);
		break;

	case SABM + ABM: 
		/* Request to reset the link from the remote. */
		KILL_TIMER (hdp);
		hd_message (hdp, "Link reset");
#ifdef HDLCDEBUG
		hd_dumptrace (hdp);
#endif
		hd_flush (hdp->hd_ifp);
		hd_writeinternal (hdp, UA, pf);
		hd_initvars (hdp);
		(void) pk_ctlinput (PRC_LINKRESET, hdp->hd_pkp);
		hdp->hd_resets++;
		break;

	case SABM + WAIT_UA: 
		hd_writeinternal (hdp, UA, pf);
		break;

	case DM + ABM: 
		hd_message (hdp, "DM received: link down");
#ifdef HDLCDEBUG
		hd_dumptrace (hdp);
#endif
		(void) pk_ctlinput (PRC_LINKDOWN, hdp->hd_pkp);
		hd_flush (hdp->hd_ifp);
	case DM + DM_SENT: 
	case DM + WAIT_SABM: 
	case DM + WAIT_UA: 
		hd_writeinternal (hdp, SABM, pf);
		hdp->hd_state = SABM_SENT;
		SET_TIMER (hdp);
		break;

	case DISC + INIT:
	case DISC + DM_SENT: 
	case DISC + SABM_SENT: 
		/* Note: This is a non-standard state change. */
		hd_writeinternal (hdp, UA, pf);
		hd_writeinternal (hdp, SABM, POLLOFF);
		hdp->hd_state = SABM_SENT;
		SET_TIMER (hdp);
		break;

	case DISC + WAIT_UA: 
		hd_writeinternal (hdp, DM, pf);
		SET_TIMER (hdp);
		hdp->hd_state = DM_SENT;
		break;

	case DISC + ABM: 
		hd_message (hdp, "DISC received: link down");
		(void) pk_ctlinput (PRC_LINKDOWN, hdp->hd_pkp);
	case DISC + WAIT_SABM: 
		hd_writeinternal (hdp, UA, pf);
		hdp->hd_state = DM_SENT;
		SET_TIMER (hdp);
		break;

	case UA + ABM: 
		hd_message (hdp, "UA received: link down");
		(void) pk_ctlinput (PRC_LINKDOWN, hdp->hd_pkp);
	case UA + WAIT_SABM: 
		hd_writeinternal (hdp, DM, pf);
		hdp->hd_state = DM_SENT;
		SET_TIMER (hdp);
		break;

	case FRMR + DM_SENT: 
		hd_writeinternal (hdp, SABM, pf);
		hdp->hd_state = SABM_SENT;
		SET_TIMER (hdp);
		break;

	case FRMR + WAIT_SABM: 
		hd_writeinternal (hdp, DM, pf);
		hdp->hd_state = DM_SENT;
		SET_TIMER (hdp);
		break;

	case FRMR + ABM: 
		hd_message (hdp, "FRMR received: link down");
		(void) pk_ctlinput (PRC_LINKDOWN, hdp->hd_pkp);
#ifdef HDLCDEBUG
		hd_dumptrace (hdp);
#endif
		hd_flush (hdp->hd_ifp);
		hd_writeinternal (hdp, SABM, pf);
		hdp->hd_state = WAIT_UA;
		SET_TIMER (hdp);
		break;

	case RR + ABM: 
	case RNR + ABM: 
	case REJ + ABM: 
		process_sframe (hdp, (struct Hdlc_sframe *)frame, frametype);
		break;

	case IFRAME + ABM: 
		queued = process_iframe (hdp, fbuf, (struct Hdlc_iframe *)frame);
		break;

	case IFRAME + SABM_SENT: 
	case RR + SABM_SENT: 
	case RNR + SABM_SENT: 
	case REJ + SABM_SENT: 
		hd_writeinternal (hdp, DM, POLLON);
		hdp->hd_state = DM_SENT;
		SET_TIMER (hdp);
		break;

	case IFRAME + WAIT_SABM: 
	case RR + WAIT_SABM: 
	case RNR + WAIT_SABM: 
	case REJ + WAIT_SABM: 
		hd_writeinternal (hdp, FRMR, POLLOFF);
		SET_TIMER (hdp);
		break;

	case ILLEGAL + SABM_SENT: 
		hdp->hd_unknown++;
		hd_writeinternal (hdp, DM, POLLOFF);
		hdp->hd_state = DM_SENT;
		SET_TIMER (hdp);
		break;

	case ILLEGAL + ABM: 
		hd_message (hdp, "Unknown frame received: link down");
		(void) pk_ctlinput (PRC_LINKDOWN, hdp->hd_pkp);
	case ILLEGAL + WAIT_SABM:
		hdp->hd_unknown++;
#ifdef HDLCDEBUG
		hd_dumptrace (hdp);
#endif
		hd_writeinternal (hdp, FRMR, POLLOFF);
		hdp->hd_state = WAIT_SABM;
		SET_TIMER (hdp);
		break;
	}

	return (queued);
}

process_iframe (hdp, fbuf, frame)
register struct hdcb *hdp;
struct mbuf *fbuf;
register struct Hdlc_iframe *frame;
{
	register int    nr = frame -> nr,
	                ns = frame -> ns,
	                pf = frame -> pf;
	register int    queued = FALSE;

	/* 
	 *  Validate the iframe's N(R) value. It's N(R) value must be in
	 *   sync with our V(S) value and our "last received nr".
	 */

	if (valid_nr (hdp, nr, FALSE) == FALSE) {
		frame_reject (hdp, Z, frame);
		return (queued);
	}


	/* 
	 *  This section tests the IFRAME for proper sequence. That is, it's
	 *  sequence number N(S) MUST be equal to V(S).
	 */

	if (ns != hdp->hd_vr) {
		hdp->hd_invalid_ns++;
		if (pf || (hdp->hd_condition & REJ_CONDITION) == 0) {
			hdp->hd_condition |= REJ_CONDITION;
			/*
			 * Flush the transmit queue. This is ugly but we
			 * have no choice.  A reject response must be
			 * immediately sent to the DCE.  Failure to do so
			 * may result in another out of sequence iframe
			 * arriving (and thus sending another reject)
			 * before the first reject is transmitted. This
			 * will cause the DCE to receive two or more
			 * rejects back to back, which must never happen.
			 */
			hd_flush (hdp->hd_ifp);
			hd_writeinternal (hdp, REJ, pf);
		}
		return (queued);
	}
	hdp->hd_condition &= ~REJ_CONDITION;

	/* 
	 *  This section finally tests the IFRAME's sequence number against
	 *  the window size (K)  and the sequence number of the  last frame
	 *  we have acknowledged.  If the IFRAME is completely correct then 
	 *  it is queued for the packet level.
	 */

	if (ns != (hdp -> hd_lasttxnr + hdp -> hd_xcp -> xc_lwsize) % MODULUS) {
		hdp -> hd_vr = (hdp -> hd_vr + 1) % MODULUS;
		if (pf == 1) {
			/* Must generate a RR or RNR with final bit on. */
			hd_writeinternal (hdp, RR, POLLON);
		} else
			/*    
			 *  Hopefully we can piggyback the RR, if not we will generate
			 *  a RR when T3 timer expires.
			 */
			if (hdp -> hd_rrtimer == 0)
				hdp->hd_rrtimer = hd_t3;

		/* Forward iframe to packet level of X.25. */
		fbuf -> m_data += HDHEADERLN;
		fbuf -> m_len -= HDHEADERLN;
		fbuf -> m_pkthdr.len -= HDHEADERLN;
		fbuf -> m_pkthdr.rcvif = (struct ifnet *)hdp -> hd_pkp;
#ifdef BSD4_3
		fbuf->m_act = 0;	/* probably not necessary */
#else
		{
			register struct mbuf *m;
			
			for (m = fbuf; m -> m_next; m = m -> m_next)
				m -> m_act = (struct mbuf *) 0;
			m -> m_act = (struct mbuf *) 1;
		}
#endif
		pk_input (fbuf);
		queued = TRUE;
		hd_start (hdp);
	} else {
		/* 
		 *  Here if the remote station has transmitted more iframes then
		 *  the number which have been acknowledged plus K. 
		 */
		hdp->hd_invalid_ns++;
		frame_reject (hdp, W, frame);
	}
	return (queued);
}

/* 
 *  This routine is used to determine if a value (the middle parameter)
 *  is between two other values. The low value is  the first  parameter
 *  the high value is the last parameter. The routine checks the middle
 *  value to see if it is within the range of the first and last values.
 *  The reason we need this routine is the values are modulo some  base
 *  hence a simple test for greater or less than is not sufficient.
 */

bool
range_check (rear, value, front)
int     rear,
        value,
        front;
{
	register bool result = FALSE;

	if (front > rear)
		result = (rear <= value) && (value <= front);
	else
		result = (rear <= value) || (value <= front);

	return (result);
}

/* 
 *  This routine handles all the frame reject conditions which can
 *  arise as a result  of secondary  processing.  The frame reject
 *  condition Y (frame length error) are handled elsewhere.
 */

static
frame_reject (hdp, rejectcode, frame)
struct hdcb *hdp;
struct Hdlc_iframe *frame;
{
	register struct Frmr_frame *frmr = &hd_frmr;

	frmr -> frmr_control = ((struct Hdlc_frame *) frame) -> control;

	frmr -> frmr_ns = frame -> ns;
	frmr -> frmr_f1_0 = 0;
	frmr -> frmr_nr = frame -> nr;
	frmr -> frmr_f2_0 = 0;

	frmr -> frmr_0000 = 0;
	frmr -> frmr_w = frmr -> frmr_x = frmr -> frmr_y =
		frmr -> frmr_z = 0;
	switch (rejectcode) {
	case Z: 
		frmr -> frmr_z = 1;/* invalid N(R). */
		break;

	case Y: 
		frmr -> frmr_y = 1;/* iframe length error. */
		break;

	case X: 
		frmr -> frmr_x = 1;/* invalid information field. */
		frmr -> frmr_w = 1;
		break;

	case W: 
		frmr -> frmr_w = 1;/* invalid N(S). */
	}

	hd_writeinternal (hdp, FRMR, POLLOFF);

	hdp->hd_state = WAIT_SABM;
	SET_TIMER (hdp);
}

/* 
 *  This procedure is invoked when ever we receive a supervisor
 *  frame such as RR, RNR and REJ. All processing for these
 *  frames is done here.
 */

process_sframe (hdp, frame, frametype)
register struct hdcb *hdp;
register struct Hdlc_sframe *frame;
int frametype;
{
	register int nr = frame -> nr, pf = frame -> pf, pollbit = 0;

	if (valid_nr (hdp, nr, pf) == TRUE) {
		switch (frametype) {
		case RR: 
			hdp->hd_condition &= ~REMOTE_RNR_CONDITION;
			break;

		case RNR: 
			hdp->hd_condition |= REMOTE_RNR_CONDITION;
			hdp->hd_retxcnt = 0;
			break;

		case REJ: 
			hdp->hd_condition &= ~REMOTE_RNR_CONDITION;
			rej_routine (hdp, nr);
		}

		if (pf == 1) {
			hdp->hd_retxcnt = 0;
			hdp->hd_condition &= ~TIMER_RECOVERY_CONDITION;

			if (frametype == RR && hdp->hd_lastrxnr == hdp->hd_vs
				&& hdp->hd_timer == 0 && hdp->hd_txq.head == 0)
				hd_writeinternal(hdp, RR, pf);
			else
			/* If any iframes have been queued because of the
			   timer condition, transmit then now. */
			if (hdp->hd_condition & REMOTE_RNR_CONDITION) {
				/* Remote is busy or timer condition, so only
				   send one. */
				if (hdp->hd_vs != hdp->hd_retxqi)
					hd_send_iframe (hdp, hdp->hd_retxq[hdp->hd_vs], pollbit);
			}
			else	/* Flush the retransmit list first. */
				while (hdp->hd_vs != hdp->hd_retxqi)
					hd_send_iframe (hdp, hdp->hd_retxq[hdp->hd_vs], POLLOFF);
		}

		hd_start (hdp);
	} else
		frame_reject (hdp, Z, (struct Hdlc_iframe *)frame);	/* Invalid N(R). */
}

/* 
 *  This routine tests the validity of the N(R) which we have received.
 *  If it is ok,  then all the  iframes which it acknowledges  (if any)
 *  will be freed.
 */

bool
valid_nr (hdp, nr, finalbit)
register struct hdcb *hdp;
register int finalbit;
{
	/* Make sure it really does acknowledge something. */
	if (hdp->hd_lastrxnr == nr)
		return (TRUE);

	/* 
	 *  This section validates the frame's  N(R) value.  It's N(R) value
	 *  must be  in syncronization  with  our V(S)  value and  our "last
	 *  received nr" variable. If it is correct then we are able to send
	 *  more IFRAME's, else frame reject condition is entered.
	 */

	if (range_check (hdp->hd_lastrxnr, nr, hdp->hd_vs) == FALSE) {
		if ((hdp->hd_condition & TIMER_RECOVERY_CONDITION) &&
				range_check (hdp->hd_vs, nr, hdp->hd_xx) == TRUE)
			hdp->hd_vs = nr;

		else {
			hdp->hd_invalid_nr++;
			return (FALSE);
		}
	}

	/* 
	 *  If we get to here, we do have a valid frame  but it might be out
	 *  of sequence.  However, we should  still accept the receive state
	 *  number N(R) since it has already passed our previous test and it
	 *  does acknowledge frames which we are sending.
	 */

	KILL_TIMER (hdp);
	free_iframes (hdp, &nr, finalbit);/* Free all acknowledged iframes */
	if (nr != hdp->hd_vs)
		SET_TIMER (hdp);

	return (TRUE);
}

/* 
 *  This routine determines how many iframes need to be retransmitted.
 *  It then resets the Send State Variable V(S) to accomplish this.
 */

static
rej_routine (hdp, rejnr)
register struct hdcb *hdp;
register int rejnr;
{
	register int anchor;

	/*
	 * Flush the output queue.  Any iframes queued for
	 * transmission will be out of sequence.
	 */

	hd_flush (hdp->hd_ifp);

	/* 
	 *  Determine how many frames should be re-transmitted. In the case 
	 *  of a normal REJ this  should be 1 to K.  In the case of a timer
	 *  recovery REJ (ie. a REJ with the Final Bit on) this could be 0. 
	 */

	anchor = hdp->hd_vs;
	if (hdp->hd_condition & TIMER_RECOVERY_CONDITION)
		anchor = hdp->hd_xx;

	anchor = (anchor - rejnr + 8) % MODULUS;

	if (anchor > 0) {

		/* There is at least one iframe to retransmit. */
		KILL_TIMER (hdp);
		hdp->hd_vs = rejnr;

		while (hdp->hd_vs != hdp->hd_retxqi)
			hd_send_iframe (hdp, hdp->hd_retxq[hdp->hd_vs], POLLOFF);

	}
	hd_start (hdp);
}

/* 
 *  This routine frees iframes from the retransmit queue. It is called
 *  when a previously written iframe is acknowledged.
 */

static
free_iframes (hdp, nr, finalbit)
register struct hdcb *hdp;
int *nr;
register int finalbit;

{
	register int    i, k;

	/* 
	 *  We  need to do the  following  because  of a  funny quirk  in  the 
	 *  protocol.  This case  occures  when  in Timer  recovery  condition 
	 *  we get  a  N(R)  which  acknowledges all  the outstanding  iframes
	 *  but with  the Final Bit off. In this case we need to save the last
	 *  iframe for possible retransmission even though it has already been 
	 *  acknowledged!
	 */

	if ((hdp->hd_condition & TIMER_RECOVERY_CONDITION) && *nr == hdp->hd_xx && finalbit == 0) {
		*nr = (*nr - 1 + 8) % MODULUS;
/*		printf ("QUIRK\n"); */
	}

	k = (*nr - hdp->hd_lastrxnr + 8) % MODULUS;

	/* Loop here freeing all acknowledged iframes. */
	for (i = 0; i < k; ++i) {
		m_freem (hdp->hd_retxq[hdp->hd_lastrxnr]);
		hdp->hd_retxq[hdp->hd_lastrxnr] = 0;
		hdp->hd_lastrxnr = (hdp->hd_lastrxnr + 1) % MODULUS;
	}

}
