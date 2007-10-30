/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
 *
 * dspRead.c 
 *
 * From v01.17 08/22/90 mbs
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

#include <netat/sysglue.h>
#include <netat/appletalk.h>
#include <netat/at_pcb.h>
#include <netat/debug.h>
#include <netat/adsp.h>
#include <netat/adsp_internal.h>

/*
 * CheckReadQueue
 *
 * Checks to see if there is any data in the receive queue.  If there
 * is data, a pb and the data are queued to the user.
 * 
 * 	
 */
extern int adsp_check;

int CheckReadQueue(sp)		/* (CCBPtr sp) */
    register CCBPtr sp;
{
    register struct adspcmd *pb;
    unsigned short cnt;
    char eom = 0;
    register gbuf_t *mp;
    register gbuf_t *tmp;
    gref_t *gref;
	
    dPrintf(D_M_ADSP, D_L_TRACE, ("CheckReadQueue: sp=0x%x\n", (unsigned)sp));
    KERNEL_DEBUG(DBG_ADSP_READ, 0, sp, sp->rbuf_mb, sp->rpb, sp->delay);
    trace_mbufs(D_M_ADSP_LOW, "    bCQR m", sp->rbuf_mb);

    while (sp->rData && (pb = sp->rpb)) {		/* have data */
        dPrintf(D_M_ADSP, D_L_TRACE, 
		 (" pb=0x%p, gref=0x%p, ioc=0x%p, reqCount=%d (have data)\n", 
		  pb, pb->gref, pb->ioc, pb->u.ioParams.reqCount));
    	KERNEL_DEBUG(DBG_ADSP_READ, 1, pb, pb->gref, pb->ioc, pb->u.ioParams.reqCount);
	if (pb->u.ioParams.reqCount == 0) {
	    pb->ioResult = 0;
	    sp->rpb = pb->qLink;
	    if (pb->ioc) {
    		KERNEL_DEBUG(DBG_ADSP_READ, 2, pb, pb->gref, pb->ioc, 0); 
		adspioc_ack(0, (gbuf_t *)pb->ioc, pb->gref);
	    } else {
    		KERNEL_DEBUG(DBG_ADSP_READ, 3, pb, pb->gref, 0, 0);
		completepb(sp, pb);
	    }
	    continue;
	}
	    
	/* take the first packet off of sp->rbuf_mb or sp->crbuf_mb */
	if ((mp = sp->rbuf_mb)) {	/* Get header for oldest data */
    	    KERNEL_DEBUG(DBG_ADSP_READ, 4, pb, mp, gbuf_msgsize(mp), gbuf_next(mp));
	    sp->rbuf_mb = gbuf_next(mp);
	    gbuf_next(mp) = 0;
	    eom = 1;
	} else if ((mp = sp->crbuf_mb)) {
    	    KERNEL_DEBUG(DBG_ADSP_READ, 5, pb, mp, gbuf_msgsize(mp), gbuf_next(mp));
	    sp->crbuf_mb = 0;
	    eom = 0;
	}

	/* Get the first (reqCount-actCount) bytes and tack them onto 
	   the end of pb->mp.  If eom is set, put the remainder of the 
	   data onto the front of sp->rbuf_mb, otherwise sp->crbuf_mb. */
	cnt = gbuf_msgsize(mp);	/* # of data bytes in it. */
	if (cnt > (unsigned short)(pb->u.ioParams.reqCount - pb->u.ioParams.actCount)) {
	    cnt = pb->u.ioParams.reqCount - pb->u.ioParams.actCount;
	    /* m_split returns the tail */
	    if (!(tmp = (gbuf_t *)m_split(mp, cnt, M_DONTWAIT))) {
	    	cnt = 0;
		tmp = mp;
	    }
	    if (eom) {
		gbuf_next(tmp) = sp->rbuf_mb;
		sp->rbuf_mb = tmp;
		eom = 0;
	    } else
	    	sp->crbuf_mb = tmp;	
	}
	if (cnt) {
	    pb->u.ioParams.actCount += cnt;
	    gbuf_linkb(pb->mp, mp);
        }

	pb->u.ioParams.eom = eom;
	/*
	 * Now clean up receive buffer to remove all of the data 
	 * we just copied
	 */
	if ((sp->rbuf_mb == 0) && 
	    (sp->crbuf_mb == 0)) /* no more data blocks */
	    sp->rData = 0;
	/*
	 * If we've filled the parameter block, unlink it from read 
	 * queue and complete it. We also need to do this if the connection
	 * is closed && there is no more stuff to read.
	 */
	if (eom || (pb->u.ioParams.actCount >= pb->u.ioParams.reqCount) ||
	    ((sp->state == sClosed) && (!sp->rData)) ) {
	      /* end of message, message is full, connection
	       * is closed and all data has been delivered,
	       * or we are not to "delay" data delivery.
	       */
	    pb->ioResult = 0;
	    sp->rpb = pb->qLink; /* dequeue request */
	    if (pb->ioc) {	/* data to be delivered at the time of the */
		mp = gbuf_cont(pb->mp); /* ioctl call */
		gbuf_cont(pb->mp) = 0;
		gref = (gref_t *)pb->gref;
		adspioc_ack(0, (gbuf_t *)pb->ioc, pb->gref);
		dPrintf(D_M_ADSP, D_L_TRACE, ("    (pb->ioc) mp=%p\n", mp));
    		KERNEL_DEBUG(DBG_ADSP_READ, 0x0A, pb,  mp, 
			     gbuf_next(mp), gbuf_cont(mp));
		SndMsgUp(gref, mp);
		dPrintf(D_M_ADSP, D_L_TRACE, 
			("    (data) size req=%d\n", pb->u.ioParams.actCount));
    		KERNEL_DEBUG(DBG_ADSP_READ, 0x0B, pb, pb->ioc, 
			     pb->u.ioParams.reqCount, pb->u.ioParams.actCount);
	    } else {		/* complete an queued async request */
    		KERNEL_DEBUG(DBG_ADSP_READ, 0x0C, pb, sp, 
			     pb->u.ioParams.actCount, sp->delay);
		completepb(sp, pb);
	    }
	}
    }	/* while */

    if ((pb = sp->rpb)) {		/* if there is an outstanding request */
        dPrintf(D_M_ADSP, D_L_TRACE, 
		 (" pb=0x%p, ioc=0x%p, reqCount=%d (no more data)\n", 
		  pb, pb->ioc, pb->u.ioParams.reqCount));
    	KERNEL_DEBUG(DBG_ADSP_READ, 0x0D, pb, pb->ioc, 
		     pb->u.ioParams.reqCount, pb->u.ioParams.actCount);

	if (sp->state == sClosed) {
	    while (pb) {
    		    KERNEL_DEBUG(DBG_ADSP_READ, 0x0E, pb, sp, pb->ioc, 0);
		    pb->ioResult = 0;
		    pb->u.ioParams.actCount = 0;
		    pb->u.ioParams.eom = 0;
		    sp->rpb = pb->qLink;
		    if (pb->ioc) {
			    adspioc_ack(0, (gbuf_t *)pb->ioc, pb->gref);
		    } else {
			    completepb(sp, pb);
		    }
		    pb = sp->rpb;
	    }
	} else if (pb->ioc) {	/* if request not complete and this
				 * is an active ioctl, release user */
	    sp->rpb = pb->qLink;
	    pb->ioResult = 1;
	    tmp = gbuf_cont(pb->mp); /* detatch perhaps delayed data */
	    gbuf_cont(pb->mp) = 0;
	    if ((mp = gbuf_copym(pb->mp))) { /* otherwise, duplicate user request */
    		    KERNEL_DEBUG(DBG_ADSP_READ, 0x0F, pb, sp, pb->mp, 0);
		    adspioc_ack(0, (gbuf_t *)pb->ioc, pb->gref); 	/* release user */
		    pb = (struct adspcmd *)gbuf_rptr(mp); /* get new parameter block */
		    pb->ioc = 0;
		    pb->mp = mp;
		    gbuf_cont(pb->mp) = tmp; /* reattach data */
		    pb->qLink = sp->rpb; /* requeue the duplicate at the head */
		    sp->rpb = pb;
	    } else {		/* there is no data left, but no space
				 * to duplicate the parameter block, so
				 * put what must be a non EOM message 
				 * back on the current receive queue, and
				 * error out the user
				 */
    		    KERNEL_DEBUG(DBG_ADSP_READ, 0x10, pb, sp, pb->mp, 0);
		    if (tmp) {
			    sp->crbuf_mb = tmp;
			    sp->rData = 1;
		    }
		    pb->ioResult = errDSPQueueSize;
		    adspioc_ack(ENOBUFS, (gbuf_t *)pb->ioc, pb->gref);
	    }
	} 
    }
    /* 
     * The receive window has opened.  If was previously closed, then we
     * need to notify the other guy that we now have room to receive more
     * data.  But, in order to cut down on lots of small data packets,
     * we'll wait until the recieve buffer  is /14 empy before telling
     * him that there's room in our receive buffer.
     */
    if (sp->rbufFull && (CalcRecvWdw(sp) > (sp->rbuflen >> 2))) {
	sp->rbufFull = 0;
	sp->sendDataAck = 1;
	sp->callSend = 1;
    }

    KERNEL_DEBUG(DBG_ADSP_READ, 0x11, sp, 0, 0, 0);
    trace_mbufs(D_M_ADSP_LOW, "    eCQR m", sp->rbuf_mb);
    return 0;
}

/*
 * CheckAttn
 *
 * Checks to see if there is any attention data and passes the data back
 * in the passed in pb.
 * 
 * INPUTS:
 *	sp
 *	pb
 * 	
 * OUTPUTS:
 * 	
 */
int CheckAttn(CCBPtr, struct adspcmd *); 

int CheckAttn(sp, pb)		/* (CCBPtr sp) */
    register CCBPtr sp;
    register struct adspcmd *pb;
{
    gbuf_t *mp;
    gref_t *gref = 0;
	
    dPrintf(D_M_ADSP, D_L_TRACE, 
	    ("CheckAttn: sp=0x%x, pb=0x%x\n", (unsigned)sp, (unsigned)pb));

    if ((mp = sp->attn_mb)) {

	/*
	 * Deliver the attention data to the user. 
	 */
	gref = (gref_t *)pb->gref;
	pb->u.attnParams.attnSize = sp->attnSize;
	pb->u.attnParams.attnCode = sp->attnCode;
	if (!sp->attnSize) {
	    gbuf_freem(mp);
	    mp = 0;
	}
	sp->userFlags &= ~eAttention;
	/*
	 * Now clean up receive buffer to remove all of the data 
	 * we just copied
	 */
	sp->attn_mb = 0;
	pb->ioResult = 0;
    } else {
	/*
	 * No data...
	 */
	pb->u.attnParams.attnSize = 0;
	pb->u.attnParams.attnCode = 0;
	pb->ioResult = 1;	/* not done */
    }
    adspioc_ack(0, (gbuf_t *)pb->ioc, pb->gref);
    if (mp) {
	SndMsgUp(gref, mp);
	}
    return 0;
}

/*
 * adspRead
 * 
 * INPUTS:
 *	--> sp			stream pointer
 *	--> pb			user request parameter block
 *
 * OUTPUTS:
 *	<-- actCount		actual number of bytes read
 *	<-- eom			one if end-of-message, zero otherwise
 *
 * ERRORS:
 *	errRefNum		bad connection refnum
 *	errState
 *	errFwdReset		read terminated by forward reset
 *	errAborted		request aborted by Remove or Close call
 */
int adspRead(sp, pb)		/* (DSPPBPtr pb) */
    register CCBPtr sp;
    register struct adspcmd *pb;
{
    register gbuf_t *mp;

    dPrintf(D_M_ADSP, D_L_TRACE, 
	    ("adspRead: sp=0x%x, pb=0x%x\n", (unsigned)sp, (unsigned)pb));

    KERNEL_DEBUG(DBG_ADSP_READ, 0x12, sp, pb, sp->state, sp->rData); 

    if (sp == 0) {
	pb->ioResult = errRefNum;
	return EINVAL;
    }
	
    /*
     * It's OK to read on a closed, or closing session
     */
    if (sp->state != sOpen && sp->state != sClosing && sp->state != sClosed) {
	pb->ioResult = errState;
	return EINVAL;
    }
    if (sp->rData && (sp->rpb == 0)) { /* if data, and no queue of pbs */
	qAddToEnd((struct qlink **)&sp->rpb, (struct qlink *)pb); /* deliver data to user directly */
	CheckReadQueue(sp);
    } else if ((pb->u.ioParams.reqCount == 0) && (sp->rpb == 0)) {
	    /* empty read */
	    pb->ioResult = 0;
	    adspioc_ack(0, (gbuf_t *)pb->ioc, pb->gref);
	    return 0;
    } else {
	pb->ioResult = 1;
	if ((mp = gbuf_copym(pb->mp))) { /* otherwise, duplicate user request */
		adspioc_ack(0, (gbuf_t *)pb->ioc, pb->gref); 	/* release user */
		pb = (struct adspcmd *)gbuf_rptr(mp); 	/* get new parameter block */
		pb->ioc = 0;
		pb->mp = mp;
		qAddToEnd((struct qlink **)&sp->rpb, (struct qlink *)pb); /* and queue it for later */
	} else {
		pb->ioResult = errDSPQueueSize;
		return ENOBUFS;
	}
    }

    if (sp->callSend) {
	CheckSend(sp);		/* If recv window opened, we might */
				/* send an unsolicited ACK. */
    }
    return 0;
}

/*
 * dspReadAttention
 * 
 * INPUTS:
 *	--> sp			stream pointer
 *	--> pb			user request parameter block
 *
 * OUTPUTS:
 *	<-- NONE
 *
 * ERRORS:
 *	errRefNum		bad connection refnum
 *	errState		connection is not in the right state
 */
int adspReadAttention(sp, pb)		/* (DSPPBPtr pb) */
    register CCBPtr sp;
    register struct adspcmd *pb;
{
    dPrintf(D_M_ADSP, D_L_TRACE, 
	    ("adspReadAttention: sp=0x%x, pb=0x%x\n", (unsigned)sp, (unsigned)pb));
    if (sp == 0) {
	pb->ioResult = errRefNum;
	return EINVAL;
    }
	
    /*
     * It's OK to read on a closed, or closing session
     */
    if (sp->state != sOpen && sp->state != sClosing && sp->state != sClosed) {
	pb->ioResult = errState;
	return EINVAL;
    }

    CheckAttn(sp, pb);		/* Anything in the attention queue */
    CheckReadQueue(sp);		/* check to see if receive window has opened */
    if (sp->callSend) {
	CheckSend(sp);		/* If recv window opened, we might */
				/* send an unsolicited ACK. */
	}
    return 0;
} /* adspReadAttention */
