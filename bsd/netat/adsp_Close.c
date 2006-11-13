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

/* dspClose.c 
 * From Mike Shoemaker v01.16 06/29/90 mbs
 */
/*
 * Change log:
 *   06/29/95 - Modified to handle flow control for writing (Tuyen Nguyen)
 *    Modified for MP, 1996 by Tuyen Nguyen
 *    Modified, April 9, 1997 by Tuyen Nguyen for MacOSX.
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
#include <netat/ddp.h>
#include <netat/at_pcb.h>
#include <netat/debug.h>
#include <netat/adsp.h>
#include <netat/adsp_internal.h>


static void qRemove(CCBPtr, CCBPtr);


/*
 * CheckOkToClose
 * 
 * Check to see if it is OK to close this connection cleanly.
 *
 * INPUTS:
 * 		Stream pointer
 * OUTPUTS:
 * 		True if no outstanding transactions and we can close cleanly
 */
int CheckOkToClose(sp)		/* (CCBPtr sp) */
    CCBPtr sp;
{
    
    if (sp->sData)		/* Outstanding data ? */
	return 0;

    if (sp->sapb)		/* Outstanding send attention ? */
	return 0;

    if (sp->frpb)		/* Outstanding forward reset ? */
	return 0;
		
    if (sp->sendAttnAck)
	return 0;
		
    if (sp->sendDataAck)
	return 0;
	
    /*
     * Must be OK to close
     */
    sp->sendCtl	|= B_CTL_CLOSE;	/* So, need to send close advice */
    sp->callSend = 1;

    return 1;			/* It's OK to close */
}


/*
 * CompleteQueue
 * 
 * Given the address of the head of a queue of DSP parameter blocks, zero 
 * the queue, and complete each item on the queue with the given result 
 * code.
 *
 * INPUTS:
 *		qhead		Address of ptr to first queue element
 *		code		The result code
 * OUTPUTS:
 * 		none
 */
int  CompleteQueue(qhead, code)	/* (DSPPBPtr FPTR qhead, OSErr code) */
    struct adspcmd **qhead;
    int code;
{
    register struct adspcmd *p;
    register struct adspcmd *n;
    register gref_t *gref;
    register int    total = 0;
    CCBPtr sp = 0;

    n = *qhead;			/* Get first item */
    *qhead = 0;			/* Zero out the queue */
    if (n) {
	gref = n->gref;
	if (gref->info) {
	    sp = (CCBPtr)gbuf_rptr(((gbuf_t *)gref->info));
	    atalk_flush(sp->gref);
	    }
    }

    while (p = n) {		/* while items left */
	n = (struct adspcmd *)(p->qLink); /* Save next guy */
	p->ioResult = code;
	if (sp) {
	    completepb(sp, p); 	/* complete the copy of the request */
	    total++;
	} else
	    gbuf_freem(p->mp);
    }				/* while */
    return(total);
}

/*
 * RemoveCCB
 * 
 * Called from do close to free up the user's CCB.  So, we remove the 
 * CCB from the list of CCB's.
 *
 * INPUTS:
 * 		sp	pointer to ccb
 *		pb	a remove param block to complete when done
 * OUTPUTS:
 * 		none
 */

void RemoveCCB(sp, pb)		/* (CCBPtr sp, DSPPBPtr pb) */
    CCBPtr sp;
    struct adspcmd *pb;
{
	gref_t *gref;
	
	if (sp->gref == 0)
		return;
    /*
     * Unlink CCB from list
     */
    qRemove((CCB *)AT_ADSP_STREAMS, sp); /* remove sp from active streams queue */

    if (pb) {
	pb->ioResult = 0;
	if (pb->ioc)		/* is this a current or queued request */
	    adspioc_ack(0, pb->ioc, pb->gref);	/* current */
	else {
	    completepb(sp, pb);	/* queued */
	}
	
	if (sp->opb && (pb != sp->opb)) { /* if the pb requested is not the */
	    pb = sp->opb;		/* waiting open pb, complete it too */
	    sp->opb = 0;
	    pb->ioResult = 0;
	    completepb(sp, pb);
	} else {
	    sp->opb = 0;
        }
    }
    gref = sp->gref;
    sp->gref = 0;
    if (gref->info == (char *)sp->sp_mp) { /* queue head is still valid */
	    unsigned char skt;

	    if ((skt = sp->localSocket) != 0) {
	      if (adspDeassignSocket(sp) == 0)
		  ddp_notify_nbp(skt, sp->pid, DDP_ADSP);
	    }

	  if (gref->info) {
	    gbuf_freem((gbuf_t *)gref->info);	/* free the CCB */
	    gref->info = 0;
	  }
    } else
	gbuf_freem(sp->sp_mp);	/* our head is already gone, be sure
				 * to release our resources too */
}

int  AbortIO(sp, err)
    CCBPtr sp;
    short err;
{
    register int    total;

	if (sp->gref == 0)
		return 0;
    /*
     * Complete all outstanding transactions.  
     */
    total = CompleteQueue(&sp->sapb, err); /* Abort outstanding send attentions */
    CompleteQueue(&sp->frpb, err); /* Abort outstanding forward resets */

    if (sp->sbuf_mb) { /* clear the send queue */
	gbuf_freel(sp->sbuf_mb);
	sp->sbuf_mb = 0;
    }

    if (sp->csbuf_mb) {
	gbuf_freem(sp->csbuf_mb);
	sp->csbuf_mb = 0;
    }
    sp->sData = 0;
    
    return(total);
}

/*
 * DoClose
 * 
 * Called from several places (probe timeout, recv close advice, 
 * dspRemove, etc.) to change state of connection to closed and 
 * complete all outstanding I/O.
 *
 * Will also remove the CCB if there is a dsp remove pending.
 *
 * INPUTS:
 *		sp		An ADSP stream
 * OUTPUTS:
 * 		none
 */
void DoClose(sp, err, force_abort)	/* (CCBPtr sp, OSErr err) */
    register CCBPtr sp;
    int err;
{
    register struct adspcmd *pb, *np;
    register gbuf_t *mp;
    int      aborted_count;
	
    dPrintf(D_M_ADSP, D_L_TRACE, ("DoClose: pid=%d,e=%d,a=%d,s=%d,r=%d\n",
		sp->pid, err, force_abort, sp->localSocket, sp->removing));
    sp->userFlags |= eClosed; /* Set flag */
    sp->state = sClosed;
    sp->openState = O_STATE_NOTHING;

    /*
     * Clean up any timer elements
     */
    RemoveTimerElem(&adspGlobal.slowTimers, &sp->ProbeTimer);
    RemoveTimerElem(&adspGlobal.fastTimers, &sp->FlushTimer);
    RemoveTimerElem(&adspGlobal.fastTimers, &sp->RetryTimer);
    RemoveTimerElem(&adspGlobal.fastTimers, &sp->AttnTimer);
    RemoveTimerElem(&adspGlobal.fastTimers, &sp->ResetTimer);

    aborted_count = AbortIO(sp, err);
    np = sp->opb;		/* Get list of close/removes to complete */
    sp->opb = 0;		/* set this list null */
	
    while (pb = np) {		/* Handle all of the close/remove param blks */
	np = (struct adspcmd *)pb->qLink; /* Get next guy (if any) */
	pb->qLink = 0;
	pb->ioResult = err;
	completepb(sp, pb);
    }
    if (sp->removing && (force_abort >= 0)) {        /* Abort outstanding receives */
	aborted_count += CompleteQueue(&sp->rpb, err);

	if (sp->deferred_mb) {
		gbuf_freel(sp->deferred_mb);
		sp->deferred_mb = 0;
	}
	if (sp->attn_mb) {
		gbuf_freem(sp->attn_mb);
		sp->attn_mb = 0;
	}
	if (sp->rbuf_mb) { /* clear the rcv queue */
		gbuf_freem(sp->rbuf_mb);
		sp->rbuf_mb = 0;
	}
	if (sp->crbuf_mb) {
		gbuf_freem(sp->crbuf_mb);
		sp->crbuf_mb = 0;
	}
	sp->rData = 0;

	/* if our connection has been timed out */
	/* and the user wasn't notified of the TearDown */
	/* because of pending requests on this socket */
	/* then fake a read completion to force the notification */

	if (force_abort && aborted_count == 0) {
	    if (mp = gbuf_alloc(sizeof(struct adspcmd), PRI_HI)) {
	        pb = (struct adspcmd *)gbuf_rptr(mp);
		gbuf_wset(mp,sizeof(struct adspcmd));

		bzero((caddr_t) pb, sizeof(struct adspcmd));
		pb->mp = mp;
		pb->csCode = dspRead;
		pb->ioResult = errAborted;
		completepb(sp, pb);		/* send fake read completion */
	    }
	}
	sp->removing = 0;
	RemoveCCB(sp, 0); /* Will call completion routine */
    }
    sp->userFlags &= ~eClosed;
}


/*
 * dspClose
 * 
 * Also called for dspRemove and dspCLRemove.
 * Must handle case of multiple close calls being issued (without 
 * abort bit set) Can only allow one pending remove though.
 *
 * INPUTS:
 * 	-->	ccbRefNum		refnum of connection end
 *	-->	abort			abort the connection
 *
 * OUTPUTS:
 *	none
 *
 * ERRORS:
 *		errRefNum		Bad connection Refnum
 */
int adspClose(sp, pb)		/* (DSPPBPtr pb) */
    register CCBPtr sp;
    register struct adspcmd *pb;
{
    register gbuf_t *mp;
	
    /* Must execute nearly all of this with ints off because user could 
     * be issuing a second dspRemove while the first is pending.  Until 
     * we can detect this, we must not allow interrupts.
     * Also, we can't handle the case where a close was issued earlier, 
     * and now this is the remove.  If the write completion for the 
     * close advice packet occurs in the middle of this, we might
     * foul up.
     */

    if (sp == 0) {
	pb->ioResult = errRefNum;
	return EINVAL;
    }

    /*
     * Handle dspCLRemove
     */
    if (pb->csCode == (short)dspCLRemove) { /* Remove connection listener */
	if (sp->state != (short)sListening) { /* But it's not a listener! */
	    pb->ioResult = errState;
	    return EINVAL;
	}
	CompleteQueue(&sp->opb, errAborted); /* Complete all dspListens */
	RemoveCCB(sp, pb);	/* Will call completion routine */
	return 0;
    }


    /*
     * Either dspClose or dspRemove
     */

    if (sp->removing) {		/* Don't allow dspRemove or dspClose */
				/* after one dspRemove has been issued. */
	pb->ioResult = errState;
	return EINVAL;
    }


    /*
     * The previous Macintosh ADSP allowed you to call close on a 
     * connection that was in the process of opening or passively 
     * waiting for an open request. It is also legal to close a 
     * connection that is already closed.  No error will be generated.
     *
     * It is also legal to issue a second close call while the first 
     * is still pending.
     */
    if (pb->csCode == (short)dspClose) {
	if ((sp->state == (short)sPassive) || (sp->state == (short)sOpening)) {
	    sp->state = sClosed;
	    DoClose(sp, errAborted, 0);
	    pb->ioResult = 0;
	    adspioc_ack(0, pb->ioc, pb->gref);
	    return 0;
	}
		
	if (sp->state == (word)sClosed)	{ /* Ok to close a closed connection */
	    pb->ioResult = 0;
	    adspioc_ack(0, pb->ioc, pb->gref);
	    return 0;
	}
	if ((sp->state != (word)sOpen) && (sp->state != (word)sClosing)) {
	    pb->ioResult = errState;
	    return EINVAL;
	}
		
	sp->state = sClosing;	/* No matter what, we're closing */
    } 				/* dspClose */
    
    else {			/* dspRemove */
	sp->removing = 1;	/* Prevent allowing another dspClose. */
				/* Tells completion routine of close */
				/* packet to remove us. */

	if (sp->state == sPassive || sp->state == sClosed || 
	    sp->state == sOpening) {
	    sp->state = sClosed;
	    DoClose(sp, errAborted, 0); /* Will remove CCB! */
	    return 0;
	} else			/* sClosing & sOpen */
	    sp->state = sClosing;
	
    }				/* dspRemove */

    if (pb->u.closeParams.abort || CheckOkToClose(sp)) /* going to close */
    {
	AbortIO(sp, errAborted);
	sp->sendCtl = B_CTL_CLOSE; /* Send close advice */
    }

    pb->ioResult = 1;
    if ( (mp = gbuf_copym(pb->mp)) ) {	/* duplicate user request */
	    adspioc_ack(0, pb->ioc, pb->gref); /* release user */
	    pb = (struct adspcmd *)gbuf_rptr(mp); /* get new parameter block */
	    pb->ioc = 0;
	    pb->mp = mp;
	    qAddToEnd(&sp->opb, pb);	/* and save it */
    } else {
	    pb->ioResult = 0;
	    adspioc_ack(0, pb->ioc, pb->gref); /* release user, and keep no copy
					     * for kernel bookkeeping, yetch!
					     */
    }
    CheckSend(sp);

    return 0;
}

static void qRemove(qptr, elem)
    register CCBPtr qptr;
    register CCBPtr elem;
{

    while(qptr->ccbLink) {
	if ((DSPPBPtr)(qptr->ccbLink) == (DSPPBPtr)elem) {
	    qptr->ccbLink = elem->ccbLink;
	    elem->ccbLink = 0;
	    return;
	}
	qptr = qptr->ccbLink;
    }
}

int RxClose(sp)
    register CCBPtr sp;
{
    register gbuf_t *mp;
    register struct adspcmd *pb;

	if ((sp->state == sClosing) || (sp->state == sClosed))
		return 0;
	
    sp->state = sClosed;
    CheckReadQueue(sp);		/* try to deliver all remaining data */

    if ( (mp = gbuf_alloc(sizeof(struct adspcmd), PRI_HI)) ) {
        pb = (struct adspcmd *)gbuf_rptr(mp);
	gbuf_wset(mp,sizeof(struct adspcmd));
	pb->ioc = 0;
	pb->mp = mp;

	pb->csCode = dspClose;
	pb->ioResult = 0;
	completepb(sp, pb);		/* send close completion */
    }

if ((sp->userFlags & eClosed) == 0)
    DoClose(sp, errAborted, -1);	/* abort send requests and timers */

    return 0;
}
