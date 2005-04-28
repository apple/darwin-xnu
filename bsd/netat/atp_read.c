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
 *	Copyright (c) 1996-1998 Apple Computer, Inc.
 *	All Rights Reserved.
 */

/*    Modified for MP, 1996 by Tuyen Nguyen
 *   Modified, March 17, 1997 by Tuyen Nguyen for MacOSX.
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
#include <sys/ioctl.h>
#include <sys/malloc.h>
#include <sys/socket.h>

#include <netat/sysglue.h>
#include <netat/appletalk.h>
#include <netat/ddp.h>
#include <netat/at_pcb.h>
#include <netat/atp.h>
#include <netat/debug.h>

static void atp_trans_complete();
void atp_x_done();
void atp_x_done_locked(void *);
extern void atp_req_timeout();

/*
 *	Decide what to do about received messages
 *	Version 1.7 of atp_read.c on 89/02/09 17:53:16
 */

void atp_treq_event(void *arg)
{
	register gref_t *gref = (gref_t *)arg;
	register gbuf_t *m;
	register struct atp_state *atp;

	atalk_lock();
	atp = (struct atp_state *)gref->info;	
	if (atp->dflag)
		atp = (struct atp_state *)atp->atp_msgq;

	if (atp->dflag) {
		if ((m = gbuf_alloc(sizeof(ioc_t), PRI_HI)) != NULL) {
			gbuf_set_type(m, MSG_IOCTL);
			gbuf_wset(m,sizeof(ioc_t));
			((ioc_t *)gbuf_rptr(m))->ioc_cmd = AT_ATP_GET_POLL;
			atp_wput(gref, m);
		}
	}
	else if ((m = gbuf_alloc(1, PRI_HI)) != NULL) {
		*gbuf_rptr(m) = 0;
		gbuf_wset(m,1);
		atalk_putnext(gref, m);
	}

	if (m == 0)
		timeout(atp_treq_event, gref, 10);
	atalk_unlock();
}

void atp_rput(gref, m)
gref_t  *gref;
gbuf_t   *m;
{
	register at_atp_t *athp;
	register struct atp_state *atp;
	register int s, s_gen;
	gbuf_t *m_asp = NULL;
	struct timeval timenow;

	atp = (struct atp_state *)gref->info;	
	if (atp->dflag)
		atp = (struct atp_state *)atp->atp_msgq;

	switch(gbuf_type(m)) {
	case MSG_DATA:
	    /*
	     *	Decode the message, make sure it is an atp
	     *		message
	     */
	    if (((AT_DDP_HDR(m))->type != DDP_ATP) ||
		        (atp->atp_flags & ATP_CLOSING)) {
	        gbuf_freem(m);
		dPrintf(D_M_ATP_LOW, (D_L_INPUT|D_L_ERROR), 
			("atp_rput: dropping MSG, not atp\n"));
		break;
	    }

	    athp = AT_ATP_HDR(m);
	    dPrintf(D_M_ATP_LOW, D_L_INPUT,
		    ("atp_rput MSG_DATA: %s (%d)\n", 
		    (athp->cmd == ATP_CMD_TRESP)? "TRESP":
		    (athp->cmd == ATP_CMD_TREL)? "TREL":
		    (athp->cmd == ATP_CMD_TREQ)? "TREQ": "unknown",
		    athp->cmd));
	    trace_mbufs(D_M_ATP_LOW, "  r", m);

	    switch (athp->cmd) {

	    case ATP_CMD_TRESP:
	    {   
		register struct atp_trans *trp;
		register int    seqno;
	        register at_ddp_t       *ddp;

		/*
		 * we just got a response, find the trans record
		 */

		ATDISABLE(s, atp->atp_lock);
		for (trp = atp->atp_trans_wait.head; trp; trp = trp->tr_list.next) {
		    if (trp->tr_tid == UAS_VALUE(athp->tid))
			break;
		}

		/*
		 *	If we can't find one then ignore the message
		 */
		seqno = athp->bitmap;
		if (trp == NULL) {
	        ATENABLE(s, atp->atp_lock);
	        ddp = AT_DDP_HDR(m);
		    dPrintf(D_M_ATP_LOW, (D_L_INPUT|D_L_ERROR),
		("atp_rput: dropping TRESP, no trp,tid=%d,loc=%d,rem=%d.%d,seqno=%d\n",
			    UAS_VALUE(athp->tid),
			    ddp->dst_socket,ddp->src_node,ddp->src_socket,seqno));
		    gbuf_freem(m);
		    return;
		}

		/*
		 * If no longer valid, drop it
		 */
		if (trp->tr_state == TRANS_FAILED) {
	        ATENABLE(s, atp->atp_lock);
	        ddp = AT_DDP_HDR(m);
		    dPrintf(D_M_ATP_LOW, (D_L_INPUT|D_L_ERROR),
		("atp_rput: dropping TRESP, failed trp,tid=%d,loc=%d,rem=%d.%d\n",
			    UAS_VALUE(athp->tid),
			    ddp->dst_socket, ddp->src_node, ddp->src_socket));
		    gbuf_freem(m);
		    return;
		}

		/*
		 * If we have already received it, ignore it
		 */
		if (!(trp->tr_bitmap&atp_mask[seqno]) || trp->tr_rcv[seqno]) {
	        ATENABLE(s, atp->atp_lock);
	        ddp = AT_DDP_HDR(m);
		    dPrintf(D_M_ATP_LOW, (D_L_INPUT|D_L_ERROR),
		("atp_rput: dropping TRESP, duplicate,tid=%d,loc=%d,rem=%d.%d,seqno=%d\n",
			    UAS_VALUE(athp->tid),
			    ddp->dst_socket, ddp->src_node, ddp->src_socket, seqno));
		    gbuf_freem(m);
		    return;
		}

		/*
		 * Update the received packet bitmap
		 */
		if (athp->eom)
		    trp->tr_bitmap &= atp_lomask[seqno];
		else
		    trp->tr_bitmap &= ~atp_mask[seqno];

		/*
		 *	Save the message in the trans record
		 */
		trp->tr_rcv[seqno] = m;

		/*
		 *	If it isn't the first message then
		 *		can the header
		 */
		if (seqno)
		    gbuf_rinc(m,DDP_X_HDR_SIZE);

		/*
		 *	If we now have all the responses then return
		 *		the message to the user
		 */
		if (trp->tr_bitmap == 0) {
		    ATENABLE(s, atp->atp_lock);

		    /*
		     *	Cancel the request timer and any
		     *		pending transmits
		     */
		    atp_untimout(atp_req_timeout, trp);

		    /*
		     *	Send the results back to the user
		     */
		    atp_x_done(trp);
		    return;
		}
		if (athp->sts) {
		    /*
		     *	If they want treq again, send them
		     */
		    ATENABLE(s, atp->atp_lock);
		    atp_untimout(atp_req_timeout, trp);
		    atp_send(trp);
		    return;
		}
		ATENABLE(s, atp->atp_lock);
		return;
	    }

	    case ATP_CMD_TREL:
	    {   register struct atp_rcb *rcbp;
	        register at_ddp_t       *ddp;

		/*
		 *	Search for a matching transaction
		 */
	        ddp = AT_DDP_HDR(m);

		ATDISABLE(s, atp->atp_lock);
		for (rcbp = atp->atp_rcb.head; rcbp; rcbp = rcbp->rc_list.next) {
		    if (rcbp->rc_tid == UAS_VALUE(athp->tid) &&
			rcbp->rc_socket.node == ddp->src_node &&
			rcbp->rc_socket.net == NET_VALUE(ddp->src_net) &&
			rcbp->rc_socket.socket == ddp->src_socket) {
		            /*
			     *	Mark the rcb released
			     */
			    rcbp->rc_not_sent_bitmap = 0;
		            if (rcbp->rc_state == RCB_SENDING)
			        rcbp->rc_state = RCB_RELEASED;
			    else
				{
				ddp = 0;
				atp_rcb_free(rcbp);
				ATENABLE(s, atp->atp_lock);
				}
			    break;
		    }
		}

		if (ddp)
			ATENABLE(s, atp->atp_lock);
		gbuf_freem(m);
		return;
	   }


	   case ATP_CMD_TREQ:
	   {    register struct atp_rcb *rcbp;
	        register at_ddp_t       *ddp;
	        gbuf_t                  *m2;

		/*
		 *	If it is a request message, first 
		 *	check to see
		 *	if matches something in our active
		 *	request queue
		 */
	        ddp = AT_DDP_HDR(m);

		ATDISABLE(s, atp->atp_lock);
		for (rcbp = atp->atp_rcb.head; rcbp; rcbp = rcbp->rc_list.next) {
		    if (rcbp->rc_tid == UAS_VALUE(athp->tid) &&
			rcbp->rc_socket.node == ddp->src_node &&
			rcbp->rc_socket.net == NET_VALUE(ddp->src_net) &&
			rcbp->rc_socket.socket == ddp->src_socket)
			break;
		}
		/*
		 *	If this is a new req then do 
		 *	something with it
		 */
		if (rcbp == NULL) {
		    /*
		     * see if it matches something in the
		     * attached request queue
		     * if it does, just release the message
		     * and go on about our buisness
		     */
					/* we just did this, why do again? -jjs 4-10-95 */
		    for (rcbp = atp->atp_attached.head; rcbp; rcbp = rcbp->rc_list.next) {
		        if (rcbp->rc_tid == UAS_VALUE(athp->tid) &&
			    rcbp->rc_socket.node == ddp->src_node &&
			    rcbp->rc_socket.net == NET_VALUE(ddp->src_net) &&
			    rcbp->rc_socket.socket == ddp->src_socket) {
			    ATENABLE(s, atp->atp_lock);
			    gbuf_freem(m);
			    dPrintf(D_M_ATP_LOW, D_L_INPUT, 
				    ("atp_rput: dropping TREQ, matches req queue\n"));
			    return;
			}
		    }

			/*
			 * assume someone is interested in 
			 * in an asynchronous incoming request
			 */
			ATENABLE(s, atp->atp_lock);
			if ((rcbp = atp_rcb_alloc(atp)) == NULL) {
			    gbuf_freem(m);
			    return;
			}
			rcbp->rc_state = RCB_UNQUEUED;
			ATDISABLE(s, atp->atp_lock);

		    rcbp->rc_local_node = ddp->dst_node;
		    NET_NET(rcbp->rc_local_net, ddp->dst_net);
		    rcbp->rc_socket.socket = ddp->src_socket;
		    rcbp->rc_socket.node = ddp->src_node;
		    rcbp->rc_socket.net = NET_VALUE(ddp->src_net);
		    rcbp->rc_tid = UAS_VALUE(athp->tid);
		    rcbp->rc_bitmap = athp->bitmap;
		    rcbp->rc_not_sent_bitmap = athp->bitmap;
		    rcbp->rc_xo = athp->xo;
		    /*
		     *	if async then send it as
		     *		data
		     *	otherwise, it is a synchronous ioctl so
		     *		complete it
		     */
			if (atp->dflag) { /* for ASP? */
			  if ((m2 = gbuf_alloc(sizeof(ioc_t), PRI_HI))) {
			    gbuf_set_type(m2, MSG_DATA);
			    gbuf_wset(m2,sizeof(ioc_t));
			    ((ioc_t *)gbuf_rptr(m2))->ioc_cmd = AT_ATP_GET_POLL;
			    m_asp = m2;
			  }
			} else if ((m2 = gbuf_alloc(1, PRI_HI))) {
			    *gbuf_rptr(m2) = 0;
			    gbuf_wset(m2,1);
			    atalk_putnext(gref, m2);
			}
			if (m2 == 0) {
				dPrintf(D_M_ATP,D_L_WARNING,
					("atp_rput: out of buffer for TREQ\n"));
				timeout(atp_treq_event, gref, 10);
			}
			rcbp->rc_ioctl = m;

			/*
			 *	move it to the attached list
			 */
			dPrintf(D_M_ATP_LOW, D_L_INPUT, 
				("atp_rput: moving to attached list\n"));
			rcbp->rc_state = RCB_PENDING;
			ATP_Q_APPEND(atp->atp_attached, rcbp, rc_list);
			if (m_asp != NULL) {
			    ATENABLE(s, atp->atp_lock);
			    atp_req_ind(atp, m_asp);
			    return;
			}
		} else {
		    dPrintf(D_M_ATP_LOW, D_L_INPUT, 
			    ("atp_rput: found match, state:%d\n",
			    rcbp->rc_state));

		    /*
		     *	Otherwise we have found a matching request
		     *		look for what to do
		     */
		    switch (rcbp->rc_state) {
		    case RCB_RESPONDING:
		    case RCB_RESPONSE_FULL:
			/*
			 *	If it is one we have in progress 
			 *		(either have all the responses
			 *		or are waiting for them)
			 *		update the bitmap and resend
			 *		the replies
			 */
			getmicrouptime(&timenow);
			ATDISABLE(s_gen, atpgen_lock);
			if (rcbp->rc_timestamp) {
			  rcbp->rc_timestamp = timenow.tv_sec;
			  if (rcbp->rc_timestamp == 0)
			    rcbp->rc_timestamp = 1;
			}
			ATENABLE(s_gen, atpgen_lock);
			rcbp->rc_bitmap = athp->bitmap;
			rcbp->rc_not_sent_bitmap = athp->bitmap;
			ATENABLE(s, atp->atp_lock);
			gbuf_freem(m);
			atp_reply(rcbp);
			return;

		    case RCB_RELEASED:
		    default:
			/*
			 *	If we have a release or
			 *      we haven't sent any data yet
			 *      ignore the request
			 */
			ATENABLE(s, atp->atp_lock);
			gbuf_freem(m);
			return;
		    }
		}
		ATENABLE(s, atp->atp_lock);
		return;
	   }

           default:
		gbuf_freem(m);
		break;
	   }	  
	   break;

	case MSG_IOCACK:
		if (atp->dflag)
			asp_ack_reply(gref, m);
		else
			atalk_putnext(gref, m);
		break;

	case MSG_IOCNAK:
		if (atp->dflag)
			asp_nak_reply(gref, m);
		else
			atalk_putnext(gref, m);
		break;

	default:
		gbuf_freem(m);
	}
} /* atp_rput */

void 
atp_x_done_locked(trp)
void *trp;
{
	atalk_lock();
	atp_x_done((struct atp_trans *)trp);
	atalk_unlock();

}

void
atp_x_done(trp)
register struct atp_trans *trp;
{
	struct atp_state *atp;
        gbuf_t  *m;


	if ( !trp->tr_xo)
	        atp_trans_complete(trp);
	else {
	        /*
		 *	If execute once send a release
		 */
	        if ((m = (gbuf_t *)atp_build_release(trp)) != NULL) {
		        AT_DDP_HDR(m)->src_socket = ((struct atp_state *)
		            trp->tr_queue)->atp_socket_no;
		        DDP_OUTPUT(m);
			/*
			 *	Now send back the transaction reply to the process
			 *		or notify the process if required
			 */
			atp_trans_complete(trp);
		} else {

			atp = trp->tr_queue;
			trp->tr_state = TRANS_RELEASE;
			timeout(atp_x_done_locked, trp, 10);
		}
	}
}

static void
atp_trans_complete(trp) 
register struct atp_trans *trp;
{	register gbuf_t *m;
	register int    type;
	struct atp_state *atp;

	/* we could gbuf_freem(trp->tr_xmt) here if were not planning to
	   re-use the mbuf later */
	m = trp->tr_xmt;               
	trp->tr_xmt = NULL;
	trp->tr_state = TRANS_DONE;

	if (gbuf_cont(m) == NULL)  /* issued via the new interface */
		type = AT_ATP_ISSUE_REQUEST_NOTE;
	else {
		type = ((ioc_t *)(gbuf_rptr(m)))->ioc_cmd;
		/*
		 * free any data following the ioctl blk
		 */
		gbuf_freem(gbuf_cont(m));
		gbuf_cont(m) = NULL;
	}
	dPrintf(D_M_ATP_LOW, D_L_INPUT, ("atp_trans_comp: trp=0x%x type = %s\n", 
		(u_int) trp,
		(type==AT_ATP_ISSUE_REQUEST)? "AT_ATP_ISSUE_REQUEST":
		(type==AT_ATP_ISSUE_REQUEST_NOTE)? "AT_ATP_ISSUE_REQUEST_NOTE" :
		"unknown"));

	switch(type) {
	case AT_ATP_ISSUE_REQUEST:
	 atp = trp->tr_queue;
	 if (atp->dflag) {
		((ioc_t *)gbuf_rptr(m))->ioc_count = 0;
		((ioc_t *)gbuf_rptr(m))->ioc_error = 0;
		((ioc_t *)gbuf_rptr(m))->ioc_rval = trp->tr_tid;
		((ioc_t *)gbuf_rptr(m))->ioc_cmd = AT_ATP_REQUEST_COMPLETE;
		gbuf_set_type(m, MSG_IOCTL);
		atp_rsp_ind(trp, m);
	 } else {
	  if (trp->tr_bdsp == NULL) {
		gbuf_freem(m);
		if (trp->tr_rsp_wait)
			wakeup(&trp->tr_event);
	  } else {
		gbuf_set_type(m, MSG_IOCACK);
		((ioc_t *)gbuf_rptr(m))->ioc_count = 0;
		((ioc_t *)gbuf_rptr(m))->ioc_error = 0;
		((ioc_t *)gbuf_rptr(m))->ioc_rval = 0;
		atalk_putnext(trp->tr_queue->atp_gref, m);
	  }
	 }
	 break;

	case AT_ATP_ISSUE_REQUEST_NOTE:
		gbuf_wset(m,1);
		*gbuf_rptr(m) = 1;
		gbuf_set_type(m, MSG_DATA);
		atalk_putnext(trp->tr_queue->atp_gref, m);
		break;
	}
} /* atp_trans_complete */
