/*
 * Copyright (c) 2006 Apple Computer, Inc. All Rights Reserved.
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
 * Reset.c
 *
 * From  v01.15 07/11/90 mbs
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
#include <sys/time.h>

#include <netat/sysglue.h>
#include <netat/appletalk.h>
#include <netat/at_pcb.h>
#include <netat/debug.h>
#include <netat/adsp.h>
#include <netat/adsp_internal.h>

/*
 * RXFReset
 *
 * We just got a Forward Reset Packet.
 *
 * Called with interrupts OFF
 *
 * INPUTS:
 *	stream pointer
 *    	Pointer to ADSP header,
 * OUTPUTS:
 *	Returns 1 if packet was ignored
 */
int RXFReset(sp, f)		/* (CCBPtr sp, ADSP_FRAMEPtr f) */
    CCBPtr sp;
    ADSP_FRAMEPtr f;
{
    unsigned int pktFirstByteSeq;
    unsigned int hi;
    register gbuf_t *mp;
    register struct adspcmd *pb;
    int s;

    ATDISABLE(s, sp->lock);
    pktFirstByteSeq = netdw(UAL_VALUE(f->pktFirstByteSeq));
    
    hi = sp->recvSeq + CalcRecvWdw(sp);

    /*
     * Must do this with interrupts OFF
     */
    if (BETWEEN(sp->recvSeq, pktFirstByteSeq, hi)) /* Is this acceptable? */
    {
	sp->recvSeq = pktFirstByteSeq;
	while (mp = sp->rbuf_mb) { /* clear the receive queue */
	    sp->rbuf_mb = gbuf_next(mp);
	    gbuf_freem(mp);
	}
	if (sp->crbuf_mb) {
	    gbuf_freem(sp->crbuf_mb);
	    sp->crbuf_mb = 0;
	}
	sp->rData = 0;
	sp->rbufFull = 0;
	sp->userFlags |= eFwdReset; /* Set forward reset received Flag */

	mp = gbuf_alloc(sizeof(struct adspcmd), PRI_HI);
	pb = (struct adspcmd *)gbuf_rptr(mp);
	gbuf_winc(mp,sizeof(struct adspcmd));
	pb->ioc = 0;
	pb->mp = mp;

	pb->csCode = dspReset;
	pb->ioResult = 0;
	completepb(sp, pb);
	sp->userFlags &= ~eFwdReset;
    }

    if (LTE(pktFirstByteSeq, hi)) {
	sp->sendCtl |= B_CTL_FRESETACK;	/* Ack it if it's OK, or a duplicate */
	sp->callSend = 1;
    }

    ATENABLE(s, sp->lock);
    return 0;
}


/*
 * RXFResetAck
 *
 * We just got a Forward Reset Acknowledgement packet
 *
 * Called with interrupts OFF
 *
 * INPUTS:
 *	  stream pointer
 *    Pointer to ADSP header,
 * OUTPUTS:
 *    Returns 1 if packet was ignored
 */
int RXFResetAck(sp, f)		/* (CCBPtr sp, ADSP_FRAMEPtr f) */
    CCBPtr sp;
    ADSP_FRAMEPtr f;
{
    unsigned int  PktNextRecvSeq;
    int s;

    if (sp->frpb == 0)		/* Not expecting frwd reset Ack packet */
	return 1;

    ATDISABLE(s, sp->lock);
    PktNextRecvSeq = netdw(UAL_VALUE(f->pktNextRecvSeq));

    if (BETWEEN(sp->sendSeq, PktNextRecvSeq, sp->sendWdwSeq+1)) {
	struct adspcmd *pb;

	RemoveTimerElem(&adspGlobal.fastTimers, &sp->ResetTimer); 
				/* Remove timer */

	/*
	 * Interrupts are OFF here while we muck with the linked list
	 */
	pb = sp->frpb;		/* Unlink copy of user's parameter block */
	sp->frpb = (struct adspcmd *)pb->qLink;

	pb->ioResult = 0;
	completepb(sp, pb);	/* complete(pb, 0); */
		
	if (sp->state == sClosing) /* this ack may allow us to close... */
	    CheckOkToClose(sp);
			
	if (sp->frpb)		/* Another to send? */
	{
	    sp->callSend = 1;
	    sp->sendCtl |= B_CTL_FRESET;
	}
    }

    ATENABLE(s, sp->lock);
    return 0;
}


/*
 * dspReset
 * 
 * INPUTS:
 * 	--> ccbRefNum		refnum of connection end
 *
 * OUTPUTS:
 *	none
 *
 * ERRORS:
 *	errRefNum		bad connection refnum
 *	errState		connection is not open
 *	errAborted		request aborted by Remove or Close call
 */
int adspReset(sp, pb)		/* (DSPPBPtr pb) */
    CCBPtr sp;
    struct adspcmd *pb;
{
    int s;
    register gbuf_t *mp;
    register struct adspcmd *rpb;
	
    if (sp == 0) {
	pb->ioResult = errRefNum;
	return EINVAL;
    }

    if (sp->state != sOpen) {
	pb->ioResult = errState;
	return EINVAL;
    }
	
    ATDISABLE(s, sp->lock);

    while (mp = sp->sbuf_mb) { /* clear the send queue */
	sp->sbuf_mb = gbuf_next(mp);
	gbuf_freem(mp);
    }
    if (sp->csbuf_mb) {
	gbuf_freem(sp->csbuf_mb);
	sp->csbuf_mb = 0;
    }
    sp->sData = 0;
    sp->writeFlush = 0;
    sp->sendCtl |= B_CTL_FRESET;

    sp->firstRtmtSeq = sp->sendSeq; /* Reset sequence #'s */
    if (mp = gbuf_copym(pb->mp)) {	/* copy the parameter block */
	    adspioc_ack(0, pb->ioc, pb->gref); /* release user */
	    rpb = (struct adspcmd *)gbuf_rptr(mp);
	    rpb->ioc = 0;		/* unlink copy */
	    rpb->mp = mp;

	    qAddToEnd(&sp->frpb, rpb); 
				/* Hold on to pb (will be completed when */
				/* forward reset ack is received). */
    } else {			/* assume it will work... but keep no
				 * bookkeeping for it.  yetch! */
	    adspioc_ack(0, pb->ioc, pb->gref);
    }
    ATENABLE(s, sp->lock);

    CheckSend(sp);
    return STR_IGNORE;

}
