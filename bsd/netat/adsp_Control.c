/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
 * http://www.opensource.apple.com/apsl/ and read it before using this 
 * file.
 *
 * The Original Code and all software distributed under the License are 
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, 
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. 
 * Please see the License for the specific language governing rights and 
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/*
 *	Copyright (c) 1990, 1995-1998 Apple Computer, Inc.
 *	All Rights Reserved.
 */

/* Control.c 
 * From Mike Shoemaker v01.25 07/02/90 for MacOS
 * 09/07/95 - Modified for performance (Tuyen Nguyen)
 *    Modified for MP, 1996 by Tuyen Nguyen
 *   Modified, April 9, 1997 by Tuyen Nguyen for MacOSX.
 */

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <machine/spl.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/filedesc.h>
#include <sys/fcntl.h>
#include <sys/mbuf.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <netat/sysglue.h>
#include <netat/appletalk.h>
#include <netat/ddp.h>
#include <netat/at_pcb.h>
#include <netat/debug.h>
#include <netat/adsp.h>
#include <netat/adsp_internal.h>

/* # of additional ticks to add to any timer that we're queuing up.  For 
 * very short delays (1 and 2), the timer fires before the transmit 
 * even takes place */
#define TX_DLY	2

int adsp_window = 1;

/*
 * CalcRecvWdw
 *
 * INPUTS:
 *		sp		ADSP Stream
 * OUTPUTS:
 *		# of bytes in avail in local receive queue
 */
int CalcRecvWdw(sp)		/* (CCBPtr sp) */
    CCBPtr sp;
{
    int bytes;

    bytes = calcRecvQ(sp);
    bytes = sp->rbuflen - bytes; /* get what is left */

    if (bytes <= 16) {		/* %%% this should be zero */
	sp->rbufFull = 1;	/* Save flag that our recv buf is full */
	return 0;
    }
    else
	return ((bytes+bytes+bytes) >> 2) + 1; /* %%% */
}

calcRecvQ(sp)
    CCBPtr sp;
{
    int bytes = 0;
#ifdef AT_Socket
    register struct mbuf *m, *p;

    if (((sp->gref)->so)->so_rcv.sb_mb)
      for (p = ((sp->gref)->so)->so_rcv.sb_mb; p; p = p->m_nextpkt)
	for (m = p; m; m = m->m_next)
	  bytes += m->m_len;
#else
    register gbuf_t *mb;

    if (sp->rData) {		/* There is data in buffer */
	if (mb = sp->rbuf_mb) {
	    do {
		bytes += gbuf_msgsize(mb);
		mb = gbuf_next(mb);
	    } while (mb);
	}
	if (mb = sp->crbuf_mb)
	    bytes += gbuf_msgsize(mb);
    }
#endif
    return bytes;
}

/*
 * CheckSend
 * 
 * Check to see if the transmit PB is available and if there is anything 
 * to transmit. Start off any pending transmit.
 *
 * Normally called from the write completion routine
 *
 * INPUTS:
 * 		sp		Connection control block
 * OUTPUTS:
 * 		true if sent a packet	
 */
void CheckSend(sp)		/* (CCBPtr sp) */
    register CCBPtr sp;
{
    int i;
    int	attnMsg;		/* True if attention message */
    register gbuf_t *mp;	/* send message block */
#ifdef notdef
    register gbuf_t *tmp;
    u_char current;
#endif
    char *dp;			/* a data pointer */
    int use_attention_code;
    int len;			/* length used in allocd mblk */
    int datalen;		/* amount of data attached to mblk */
    gbuf_t *mprev, *mlist = 0;

top:

    if (sp->state == sClosed)
	return;

				/* get a message block to hold DDP and
				 * ADSP headers + 2 bytes of attention
				 * code if necessary */
    if ((mp = gbuf_alloc(AT_WR_OFFSET + DDPL_FRAME_LEN + ADSP_FRAME_LEN + ADSP_OPEN_FRAME_LEN + 2,
		     PRI_LO)) == 0) {
	if (mlist)
		gbuf_freel(mlist);
	return;		/* can't get buffers... do nothing! */
    }
    sp->callSend = 0;		/* Clear flag */
    use_attention_code = 0;
    len = 0;
    datalen = 0;

    gbuf_rinc(mp,AT_WR_OFFSET);
    gbuf_wset(mp,DDPL_FRAME_LEN); /* leave room for DDP header */

    if (sp->sendCtl) {
	short mask = 0;
		
	i = sp->sendCtl;	/* get local copy bitmap of */
				/* which ctl packets to send. */
	attnMsg = 0;
		
	if (i & 0x1E)		/* One of the open ctrl packets */
	{

	    /* point past ADSP header (no attention) */
	    dp = ((char *) gbuf_wptr(mp)) + ADSP_FRAME_LEN; 
	    UAL_ASSIGN_HTON(sp->f.pktFirstByteSeq, sp->firstRtmtSeq);
	    
	    UAS_ASSIGN_HTON(sp->of.version, netw(0x0100)); /* Fill in open connection parms */
	    UAS_ASSIGN_HTON(sp->of.dstCID, sp->remCID);	/* Destination CID */
	    UAL_ASSIGN_HTON(sp->of.pktAttnRecvSeq, sp->attnRecvSeq);
	    bcopy((caddr_t) &sp->of, (caddr_t) dp, ADSP_OPEN_FRAME_LEN);
	    len += ADSP_OPEN_FRAME_LEN;

	    if (i & B_CTL_OREQ) {
		UAS_ASSIGN_HTON(sp->f.CID, sp->locCID);
		mask = B_CTL_OREQ;
		sp->f.descriptor = ADSP_CONTROL_BIT | ADSP_CTL_OREQ;
	    } else if (i & B_CTL_OACK) {
		UAS_ASSIGN_HTON(sp->f.CID, sp->locCID);
		mask = B_CTL_OACK;
		sp->f.descriptor = ADSP_CONTROL_BIT | ADSP_CTL_OACK;
	    } else if (i & B_CTL_OREQACK) {
		UAS_ASSIGN_HTON(sp->f.CID, sp->locCID);
		mask = B_CTL_OREQACK;
		sp->f.descriptor = ADSP_CONTROL_BIT | ADSP_CTL_OREQACK;
	    } else 		/* Deny */
	    {
		UAS_ASSIGN(sp->f.CID, 0);
		mask = B_CTL_ODENY;
		sp->f.descriptor = ADSP_CONTROL_BIT | ADSP_CTL_ODENY;
		UAL_ASSIGN(sp->f.pktFirstByteSeq, 0);
	    }
			
	    if (i & (B_CTL_OREQ | B_CTL_OREQACK)) 
		/* Need to start up a timer for it */
	    {
		/* It's possible that we've received a duplicate 
		 * open request.  In this case, there will already be 
		 * a timer queued up for the request+ack 
		 *  packet we sent the first time.  So remove the timer 
		 * and start another. 
		 */
	        RemoveTimerElem(&adspGlobal.slowTimers, &sp->ProbeTimer);
		InsertTimerElem(&adspGlobal.slowTimers, &sp->ProbeTimer, 
				sp->openInterval+1);
	    }
	} else {
	    /* seq # of next byte to send */
	    UAL_ASSIGN_HTON(sp->f.pktFirstByteSeq, sp->sendSeq);	
			
	    if (i & B_CTL_CLOSE) {
		sp->state = sClosed; /* Now we're closed */
		mask = B_CTL_CLOSE;
		sp->f.descriptor = ADSP_CONTROL_BIT | ADSP_CTL_CLOSE;
	    } else if (i & B_CTL_PROBE) {
		mask = B_CTL_PROBE;
		sp->f.descriptor = 
		    ADSP_CONTROL_BIT | ADSP_CTL_PROBE | ADSP_ACK_REQ_BIT;
	    } else if (i & B_CTL_FRESET) {
		mask = B_CTL_FRESET;
		sp->f.descriptor = ADSP_CONTROL_BIT | ADSP_CTL_FRESET;
		InsertTimerElem(&adspGlobal.fastTimers, 
				&sp->ResetTimer, sp->rtmtInterval+TX_DLY);
	    } else if (i & B_CTL_FRESETACK) {
		mask = B_CTL_FRESETACK;
		sp->f.descriptor = ADSP_CONTROL_BIT | ADSP_CTL_FRESET_ACK;
	    }
	    else if (i & B_CTL_RETRANSMIT) {
		mask = B_CTL_RETRANSMIT;
		sp->f.descriptor = ADSP_CONTROL_BIT | ADSP_CTL_RETRANSMIT;
	    } 
	    else {
		dPrintf(D_M_ADSP, D_L_ERROR, ("CheckSend: Control bit error\n"));
	   }
	}			/* non open control packet */

	sp->sendCtl &= ~mask; 
	goto sendit;
    }				/* send control packet */

    if (sp->sendAttnData)	/* Send attn ready to go? */
    {
	sp->sendAttnData = 0;	/* Clear Flags */
	if (sp->sapb) {
	    sp->sendAttnAck  = 0; /* This will also do an Attn Ack */
	
	    attnMsg = 1;
	    sp->f.descriptor = ADSP_ATTENTION_BIT | ADSP_ACK_REQ_BIT;
	    if (gbuf_cont(sp->sapb->mp)) {
		gbuf_cont(mp) = gbuf_dupm(gbuf_cont(sp->sapb->mp)); 
		/* Major hack here.  The ADSP Attn code is butted up against 
		 * the end of the adsp packet header, and the length is 
		 * increased by 2.  (There is a pad field behind the adsp
		 * header in the CCB just for this purpose.)
		 */
	    }
	    use_attention_code++;

	    sp->f.data[0] = high(sp->sapb->u.attnParams.attnCode);
	    sp->f.data[1] = low(sp->sapb->u.attnParams.attnCode);
	    InsertTimerElem(&adspGlobal.fastTimers, &sp->AttnTimer, 
			                             sp->rtmtInterval+TX_DLY);
	    goto sendit;
	}
    }				/* attn data */
    
    if (sp->sendAttnAck)	/* Send attn ack ready to go? */
    {	
	attnMsg = 1;
	sp->f.descriptor = ADSP_CONTROL_BIT | ADSP_ATTENTION_BIT;
	sp->sendAttnAck = 0;	
	goto sendit;
    }				/* attn ack */
	
    if ((sp->state == sOpen || sp->state == sClosing) && /* Correct state */
	(!sp->waitingAck) &&	/* not waiting for an ACK */
	(sp->sData) &&		/* have data to send */
	(GTE(sp->sendWdwSeq,sp->sendSeq)) && /* he has room to accept it */
	(sp->pktSendCnt < sp->pktSendMax)) /* haven't sent too many pkts 
					    * in a row. */
    {
	attnMsg = 0;
	if (datalen = attachData(sp, mp)) /* attach data to mp */
	    goto sendit;	/* if successful, sendit */
    }

    if (sp->sendDataAck) {
	UAL_ASSIGN_HTON(sp->f.pktFirstByteSeq, sp->sendSeq); /* seq # of next byte */
	attnMsg = 0;
	sp->f.descriptor = ADSP_CONTROL_BIT;
	goto sendit;
    }

    /*
     * Nothing left to do...
     */
    if (mp)
	gbuf_freem(mp);
    if (mlist)
	adsp_sendddp(sp, mlist, 0, &sp->remoteAddress, DDP_ADSP);
    return;

sendit:

    if (attnMsg) {
	UAL_ASSIGN_HTON(sp->f.pktFirstByteSeq, sp->attnSendSeq);
	UAL_ASSIGN_HTON(sp->f.pktNextRecvSeq, sp->attnRecvSeq);
	UAS_ASSIGN(sp->f.pktRecvWdw, 0);	/* Always zero in attn pkt */
    } else {
	sp->sendDataAck = 0;
	UAL_ASSIGN_HTON(sp->f.pktNextRecvSeq, sp->recvSeq);
	UAS_ASSIGN_HTON(sp->f.pktRecvWdw, CalcRecvWdw(sp));
    }
    if (use_attention_code) {
	bcopy((caddr_t) &sp->f, (caddr_t) gbuf_wptr(mp), ADSP_FRAME_LEN + 2);
	len += ADSP_FRAME_LEN + 2;
    } else {
	bcopy((caddr_t) &sp->f, (caddr_t) gbuf_wptr(mp), ADSP_FRAME_LEN);
	len += ADSP_FRAME_LEN;
    }
    gbuf_winc(mp,len);		/* update mblk length  */
    if (mlist)
	gbuf_next(mprev) = mp;
    else
	mlist = mp;
    mprev = mp;

    if (sp->state == sClosed) {	/* must have sent a close advice */
				/* send header + data */
	adsp_sendddp(sp, mlist, 0, &sp->remoteAddress, DDP_ADSP);
	DoClose(sp, 0, -1);	/* complete close! */
	return;
    }
    if (sp->state == sClosing) /* See if we were waiting on this write */
	CheckOkToClose(sp);
    goto top;
}

/*
 * completepb delivers a paramater block with all its appropriate fields
 * set back to the user.  
 *
 * The assumptions here are that the PB is not linked to any queue, 
 * that the fields including ioResult are set, and that the 
 * kernel is no longer interested in the mblks that may or
 * maynot be linked to this pb.
 */
void completepb(sp, pb)
    register CCBPtr sp;
    register struct adspcmd *pb;
{
    if (sp->gref && (sp->gref->info == (caddr_t)sp->sp_mp)) {
	if (gbuf_len(pb->mp) > sizeof(struct adspcmd))
		gbuf_wset(pb->mp,sizeof(struct adspcmd));
	SndMsgUp(sp->gref, pb->mp);
	NotifyUser(sp);
    } else
	gbuf_freem(pb->mp);
}

attachData(sp, mp)
    register CCBPtr sp;
    register gbuf_t *mp;
{
    int	seq;
    int cnt;
    char eom = 0;
    int bsize;
    int diff;
    char sendAckReq;
    int partial = 0;		/* flag for a partial send */
    int tcnt = 0;
    register gbuf_t *smp;	/* send data message block */
    register gbuf_t *psmp;	/* previous message block */

    sendAckReq = 0;

    if (LT(sp->sendSeq, sp->firstRtmtSeq)) /* Sanity check on send seq */
	sp->sendSeq = sp->firstRtmtSeq; /* seq must be oldest in buffer. */

    /* This test and assignment was necessary because the retry VBL could 
     * have fired and reset send Seq to first Rtmt Seq, and then an 
     * expected ACK comes in that bumps first Rtmt Seq up.  Then we 
     * have the problem that send Seq is less than first Rtmt Seq.
     * The easiest fix to this timing dilemma seems to be to reset 
     * sendSeq to first Rtmt Seq if we're sending the first packet.
     */
    UAL_ASSIGN_HTON(sp->f.pktFirstByteSeq, sp->sendSeq);
		
    if (smp = sp->sbuf_mb) /* Get oldest header */
	eom = 1;
    else if (smp = sp->csbuf_mb)
	eom = 0;

    if (smp == 0) {		/* this shouldn't happen... */
	    sp->sData = 0;
	    return 0;
    }
    /*
     * Must find next byte to transmit
     */
    seq = sp->firstRtmtSeq;	/* Seq # of oldest in buffer */
    while ((diff = (sp->sendSeq - seq)) >= ((bsize = gbuf_msgsize(smp)) + eom)) {
	seq += bsize + eom;	/* update sequence # */
	if (gbuf_next(smp)) { /* if another send buffer */
	    smp = gbuf_next(smp);
	    eom = 1;
	} else if (smp == sp->csbuf_mb) { /* seen the current one? */
	    smp = 0;
	    break;
	} else if (sp->csbuf_mb) { /* look at it */
	    smp = sp->csbuf_mb;
	    eom = 0;
	} else {		/* no more buffers */
	    smp = 0;
	    break;
	}
    }			/* while */
    
    if (smp) {
	if (gbuf_next(smp) == 0)	/* last block */
	    sendAckReq = 1;
	cnt = bsize - diff;	/* # of bytes in this block */
    } else
	cnt = 0;

    /*
     * Check to see if the number of bytes is less than the 'send 
     * Blocking' setting. If so, then we won't send this data unless 
     * we're flushing.  So we set up a timer to force a flush later.
     */
    if ((cnt < sp->sendBlocking) && !sp->writeFlush) {
        InsertTimerElem(&adspGlobal.fastTimers, &sp->FlushTimer, 
			                         sp->sendInterval);
	return 0;		/* no data to send */
    }

    if (cnt > ADSP_MAX_DATA_LEN) { /* truncate to one packet */
	cnt = ADSP_MAX_DATA_LEN;
	eom = 0;
	sendAckReq = 0;	/* Won't send ack because end of data */
	partial++;
    }

    if (smp) {
	/* trim extra bytes off the beginning of the "block" before the copy */
	while (diff) {
	    if (gbuf_len(smp) > diff)
		break;
	    else
		diff -= gbuf_len(smp);
	    smp = gbuf_cont(smp);
        }
	if((gbuf_cont(mp) = gbuf_dupm(smp)) == 0) /* copy the data */
	    return 0;
	smp = gbuf_cont(mp);	/* use the new message blocks */
        gbuf_rinc(smp,diff);	/* and get to the first byte of data to send */
    }
    /*
     * Check to see if this many bytes will close the other end's 
     * receive window. If so, we need to send an ack request along 
     * with this.  sendWdwSeq is the seq # of the last byte that 
     * the remote has room for
     */
    if ((diff = sp->sendWdwSeq + 1 - sp->sendSeq) <= cnt) {
	if (diff < cnt) { /* Won't fit exactly */
	    eom = 0;	/* so can't send EOM */
	    cnt = diff;
	    partial++;
	}
	sendAckReq = 1;		/* Make him tell us new recv. window */
	sp->noXmitFlow = 1;	/* Don't do flow control calc. */
    }
    
    /* trim extra bytes off the tail of the "block" after the copy */
    if (partial && smp) {
	psmp = smp;
	tcnt = cnt;
	while (tcnt && smp) { /* while there are message blocks and data */
	    if (tcnt >= gbuf_len(smp)) {
		tcnt -= gbuf_len(smp);
		if (tcnt) {
		    psmp = smp;
		    smp = gbuf_cont(smp);
		} else {
		    if (psmp != smp) { /* not the first item on the list */
			gbuf_cont(psmp) = 0;
			gbuf_freem(smp);
			smp = psmp;
		    } else {
			gbuf_freem(gbuf_cont(smp));
			gbuf_cont(smp) = 0;
		    }
		    break;
		}
	    } else {
		gbuf_wset(smp,tcnt);
		if (gbuf_cont(smp)) {
		    gbuf_freem(gbuf_cont(smp));
		    gbuf_cont(smp) = 0;
		}
		break;
	    }
	}
    }

    sp->sendSeq += cnt + eom;	/* Update sendSeq field */

    if (GT(sp->sendSeq, sp->maxSendSeq)) /* Keep track of >st ever sent */
	sp->maxSendSeq = sp->sendSeq;
	
    if (eom)
	sp->f.descriptor = ADSP_EOM_BIT;
    else
	sp->f.descriptor = 0;
	
    if (sendAckReq || (++sp->pktSendCnt >= sp->pktSendMax)) {
	/* Last packet in a series */
	sp->f.descriptor |= ADSP_ACK_REQ_BIT; /* We want an ack to this */
	sp->waitingAck = 1;	/* Flag that we're waiting */
	sp->sendStamp = SysTicks(); /* Save time we sent request */
	sp->timerSeq = sp->sendSeq; /* Save seq # we want acked */
	InsertTimerElem(&adspGlobal.fastTimers, &sp->RetryTimer, 
			sp->rtmtInterval+TX_DLY);
    }
    return cnt + eom;
}



