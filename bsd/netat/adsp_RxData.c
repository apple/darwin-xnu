/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
 */
/* 
 * RxData.c 
 *
 * From v01.28   Handle an incoming Data Packet       06/21/90 mbs
 */
/*
 * Change log:
 *   06/29/95 - Modified to handle flow control for writing (Tuyen Nguyen)
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
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/time.h>

#include <netat/sysglue.h>
#include <netat/appletalk.h>
#include <netat/at_pcb.h>
#include <netat/debug.h>
#include <netat/adsp.h>
#include <netat/adsp_internal.h>

gbuf_t *releaseData(mp, len)
    gbuf_t *mp;
    int len;
{
    register gbuf_t *tmp;
    register int cnt;
    int freeit;

    dPrintf(D_M_ADSP, D_L_TRACE, 
	    ("releaseData: mbuf=0x%x, len=%d\n", (unsigned)mp, len));

    KERNEL_DEBUG(DBG_ADSP_RCV, 0, mp, len, 0, 0);

    do {
	freeit = 1;		/* assume we use the whole mblk */
	if ((cnt = gbuf_len(mp)) > len) {
	    freeit = 0;		/* using only part of the mblk */
	    cnt = len;
	}
	gbuf_rinc(mp,cnt);
	len -= cnt;
	tmp = mp;
	mp = gbuf_cont(mp);
	if (freeit) {
	    gbuf_freeb(tmp);
	} else
	    return tmp;		/* if we don't use the whole block */
				/* pass back the partial gbuf_t pointer */
    } while (len && mp);
    return mp;
}

/*
 * CheckRecvSeq
 *
 * We just got a non-attention packet.  Check the pktNextRecvSeq field
 * to see if it acknowledges any of our sent data.
 *
 * If any data was acked, check to see if we have anything to fill the
 * newly opened up remote receive window. Otherwise, if the ACK request
 * bit was set, we need to send an Ack Packet
 *
 * Always called as the result of receiving a packet.  Interrupts 
 * are completely masked when this routine is called.
 *
 * INPUTS:
 *    sp stream
 *    f  pointer to ASDP header
 * OUTPUTS:
 *    none
 */
void CheckRecvSeq(sp, f)	/* (CCBPtr sp, ADSP_FRAMEPtr f) */
    register CCBPtr sp;
    register ADSP_FRAMEPtr f;
{
    int s;
    int pktNextRecvSeq;
    int sendWdwSeq;
    int eom;
    int hlen;
    register gbuf_t *mp;
	
    ATDISABLE(s, sp->lock);
    if (f->descriptor & ADSP_ACK_REQ_BIT) { /* He wants an Ack */
	sp->sendDataAck = 1;
	sp->callSend = 1;
    }
	
    pktNextRecvSeq = netdw(UAL_VALUE(f->pktNextRecvSeq)); /* Local copy */

    /*
     * Make sure the sequence number corresponds to reality -- i.e. for 
     * unacknowledged data that we have sent
     */

    if (GT(pktNextRecvSeq, sp->maxSendSeq)) /* We've never sent this seq #! */
	goto noack;

    if (GTE(pktNextRecvSeq, sp->timerSeq) && sp->waitingAck) {
	/* This acks our Ack Request */
	sp->waitingAck = 0;	/* Allow sending more */
	sp->pktSendCnt = 0;	/* Reset packet count */
	/* Remove retry timer */
	RemoveTimerElem(&adspGlobal.fastTimers, &sp->RetryTimer); 
		
	if (!sp->resentData) {	/* Data sent without retries */
	    short diff;		/* Signed!! */
	    /* All timings done in 6th second base */
	    /* The contortions here are to prevent C from promoting 
	     * everything to longs and then using a library routine 
	     * to do the division. As 16-bit words, a DIVU instruction 
	     * is used. 
	     */
	    
	    diff = (((word)(SysTicks() - sp->sendStamp)) / (word)10) - 
		sp->roundTrip + 1;

	    sp->roundTrip += diff >> 3;	/* Update average */

	    if (diff < 0)	/* Take absolute value */
		diff = -diff;
	    sp->deviation += (diff - sp->deviation) >> 2; /* Update deviation*/

	    sp->rtmtInterval = sp->roundTrip + 
		((short)2 * (short)sp->deviation);

	    if (!sp->noXmitFlow && 
		sp->pktSendMax < 50) /* Bump # of sequential */
		sp->pktSendMax++; /* Packets we'll send */
				
	    sp->noXmitFlow = 0;
	}
	else
	    sp->resentData = 0;
			
    }				/* Acked our data */

    if (LTE(pktNextRecvSeq, 
	    sp->firstRtmtSeq)) /* Was duplicate ack, so ignore */
	goto noack;
		
    if (!sp->sData)		/* If nothing in send queue, ignore */
	goto noack;


    do {			/* This acks bytes in our buffer */
	if (mp = sp->sbuf_mb) {	/* Get ptr to oldest data header */
	    sp->sbuf_mb = gbuf_next(mp); /* unlink it from send queue */
	    eom = 1;
	} else {
	    mp = sp->csbuf_mb;
	    sp->csbuf_mb = 0;
	    eom = 0;
	}

	if (mp == 0) {		/* shouldn't happen! */
	    sp->sData = 0;
	    goto noack;
	}
	/*
	 * Does this ack the entire data block we're now pointing at?
	 */
	if (LTE((sp->firstRtmtSeq + eom + (hlen = gbuf_msgsize(mp))),
		 pktNextRecvSeq)) {

	    gbuf_freem(mp);

	    /* Update seq # of oldest byte in bfr */
	    sp->firstRtmtSeq += eom + hlen; 

	    if ((sp->sbuf_mb == 0) && (sp->csbuf_mb == 0)) {
		/* If this was only block, then ... */
		sp->sData = 0;	/* ... no data in queue */
		sp->writeFlush = 0;
		if (sp->state == sClosing) /* this may allow us to close... */
		    CheckOkToClose(sp);
		atalk_enablew(sp->gref);
		break;
	    }
	}			/* whole data block acked */
	else			/* Only some of the data was acked */
	{
	    short acked;

	    acked = (pktNextRecvSeq - sp->firstRtmtSeq);
	    mp = releaseData(mp, acked);
	    if (eom) {
		if (mp) {
			gbuf_next(mp) = sp->sbuf_mb;
			sp->sbuf_mb = mp;
		}
	    } else
		sp->csbuf_mb = mp;
			
	    sp->firstRtmtSeq = pktNextRecvSeq; /* Update seq # oldest byte */
	    break;
	}
    } while (LT(sp->firstRtmtSeq, pktNextRecvSeq));

    if (sp->sData)		/* We've got stuff to send */
	sp->callSend = 1;

noack:
    sendWdwSeq = netw(UAS_VALUE(f->pktRecvWdw)) - 1 + pktNextRecvSeq;

    if (GT(sendWdwSeq, sp->sendWdwSeq))	/* Don't make send window smaller */
    {
	sp->callSend = 1;	/* His recv wdw opened, so see */
				/* if we can send more data */
	sp->sendWdwSeq	= sendWdwSeq;
    }
    ATENABLE(s, sp->lock);
}

/*
 * RXData
 *
 * We just got a Data Packet
 * See if it came from anybody we know.
 *
 * Called from ADSP Packet with interrupts masked completely OFF
 *  *** In MacOSX interrupts do not seem to be off! ***
 * 
 * INPUTS:
 *    Stream pointer
 *    gbuf_t pointer
 *    Pointer to ADSP header, (part of the mblk pointer to by mp)
 *    Length of header plus data
 * OUTPUTS:
 *    Returns 1 if packet was ignored
 */
int RXData(sp, mp, f, len)	/* (CCBPtr sp, ADSP_FRAMEPtr f, word len) */
    CCBPtr sp;
    register gbuf_t *mp;
    ADSP_FRAMEPtr f;
    int len;
{
    int s, offset;
    int PktFirstByteSeq;
    short cnt;
    char eom;

    len	-= ADSP_FRAME_LEN;

    /* Does packet have eom bit set? */
    eom = (f->descriptor & ADSP_EOM_BIT) ? 1 : 0; 

    dPrintf(D_M_ADSP, D_L_TRACE, 
	    ("RXData: sp=0x%x, mbuf=0x%x, f=0x%x, len=%d, eom=%d\n", 
	     (unsigned)sp, (unsigned)mp, (unsigned)f, len, eom));

    KERNEL_DEBUG(DBG_ADSP_RCV, 1, sp, mp, len, eom);

    trace_mbufs(D_M_ADSP, "  mp", mp);

    PktFirstByteSeq = netdw(UAL_VALUE(f->pktFirstByteSeq)); /* Local copy */

    ATDISABLE(s, sp->lock);
    if (GT(PktFirstByteSeq, sp->recvSeq)) /* missed a packet (out of order) */
    {
	if (sp->badSeqCnt++ > sp->badSeqCnt) /* Need to send rexmit advice */
	    sp->sendCtl |= B_CTL_RETRANSMIT;
	ATENABLE(s, sp->lock);
	CheckRecvSeq(sp, f);	/* Will set send ACK flag if requested */
	CheckReadQueue(sp);
	gbuf_freem(mp);

    	KERNEL_DEBUG(DBG_ADSP_RCV, 2, sp, 0, 0, 0);
	trace_mbufs(D_M_ADSP, "  exRXD m", sp->rbuf_mb);
	dPrintf(D_M_ADSP, D_L_TRACE, ("    End RXData - missed a packet\n"));

	return 0;
    }
	
    if (LTE(PktFirstByteSeq + len + eom, sp->recvSeq)) { /* duplicate data? */
	ATENABLE(s, sp->lock);
	CheckRecvSeq(sp, f);	/* Will set send ACK flag if requested */
	CheckReadQueue(sp);
	gbuf_freem(mp);

    	KERNEL_DEBUG(DBG_ADSP_RCV, 3, sp, 0, 0, 0);
	trace_mbufs(D_M_ADSP, "  exRXD m", sp->rbuf_mb);
	dPrintf(D_M_ADSP, D_L_TRACE, ("    End RXData - duplicate data\n"));

	return 0;
    }

    sp->badSeqCnt = 0;		/* reset out of sequence pckt counter */

    cnt = sp->recvSeq - PktFirstByteSeq; /* # bytes we've seen already */
	
    offset = ((unsigned char *)&f->data[cnt]) - (unsigned char *)gbuf_rptr(mp);
    gbuf_rinc(mp,offset);
				/* point recv mblk to data (past headers) */

    len -= cnt;			/* # of new data bytes */

    cnt = len;			/* # bytes left to deal with */
    
    if (!sp->rData)		/* Recv bfr is empty */
    {
	sp->rData = 1;		/* Not empty any more */

	if ((sp->rpb)->ioc == (caddr_t)mp) {
	   dPrintf(D_M_ADSP, D_L_TRACE, 
		   ("RXData: (pb->ioc == mp) no stored data\n"));
    	   KERNEL_DEBUG(DBG_ADSP_RCV, 4, sp, sp->rpb, 0, 0);
	}
	if (eom)
	    sp->rbuf_mb = mp;
	else
	    sp->crbuf_mb = mp;
    }				/* Recv queue is empty */
	
    /*
     * Else, there's already stored data.
     */
    else {
        gbuf_t *rmp;
	/*
	 * Is this a new "message?"
	 */
	if (eom) {
	    if (sp->crbuf_mb) {
		gbuf_linkb(sp->crbuf_mb, mp);
		mp = sp->crbuf_mb;
		sp->crbuf_mb = 0;
	    }
	    if (rmp = sp->rbuf_mb) {
		/*
		 * Add it to the end
		 */
		while(gbuf_next(rmp))
		    rmp = gbuf_next(rmp);
		gbuf_next(rmp) = mp;
	    } else
		sp->rbuf_mb = mp;
	} else if (sp->crbuf_mb) 
	    gbuf_linkb(sp->crbuf_mb, mp);
	else
	    sp->crbuf_mb = mp;
    }
    sp->recvSeq += (cnt + eom);	/* We've got these bytes */

    /* %%% We really should call check recv seq first, but let's 
     * continue to do it down here.  We really want to service the 
     * received packet first, and maybe reenable scc ints before
     * doing anything that might take a long while
     */

    ATENABLE(s, sp->lock);
    CheckRecvSeq(sp, f);	/* Will set send ACK flag if requested */
    CheckReadQueue(sp);
    KERNEL_DEBUG(DBG_ADSP_RCV, 5, sp, sp->rbuf_mb, 0, 0);
    trace_mbufs(D_M_ADSP, "  eRXD m", sp->rbuf_mb);
    return 0;
} /* RXData */
