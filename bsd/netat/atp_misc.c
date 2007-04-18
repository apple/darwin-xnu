/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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

void atp_free();
void atp_send(struct atp_trans *);

/*
 *	The request timer retries a request, if all retries are used up
 *		it returns a NAK
 */

void
atp_req_timeout(trp)
register struct atp_trans *trp;
{
	register gbuf_t *m;
	gref_t *gref;
	struct atp_state *atp;
	struct atp_trans *ctrp;

	if ((atp = trp->tr_queue) == 0)
		return;
	if (atp->atp_flags & ATP_CLOSING)
		return;
	
	for (ctrp = atp->atp_trans_wait.head; ctrp; ctrp = ctrp->tr_list.next) {
		if (ctrp == trp)
			break;
	}
	if (ctrp != trp)
		return;

	if ((m = gbuf_cont(trp->tr_xmt)) == NULL)
	        m = trp->tr_xmt;               /* issued via the new interface */

	if (trp->tr_retry == 0) {
		trp->tr_state = TRANS_FAILED;
		if (m == trp->tr_xmt) {
			trp->tr_xmt = NULL;
l_notify:
				gbuf_wset(m,1);
				*gbuf_rptr(m) = 99;
				gbuf_set_type(m, MSG_DATA);
				gref = trp->tr_queue->atp_gref;
				atalk_putnext(gref, m);

			return;
		}
		dPrintf(D_M_ATP_LOW,D_L_INFO, ("atp_req_timeout: skt=%d\n",
			trp->tr_local_socket));
		m = trp->tr_xmt;
		switch(((ioc_t *)(gbuf_rptr(trp->tr_xmt)))->ioc_cmd) {
		case AT_ATP_ISSUE_REQUEST:
			trp->tr_xmt = NULL;
			if (trp->tr_queue->dflag)
				((ioc_t *)gbuf_rptr(m))->ioc_cmd = AT_ATP_REQUEST_COMPLETE;
			else if (trp->tr_bdsp == NULL) {
				gbuf_freem(m);
				if (trp->tr_rsp_wait)
					wakeup(&trp->tr_event);
				break;
			}
			atp_iocnak(trp->tr_queue, m, ETIMEDOUT);
			atp_free(trp);
			return;

		case AT_ATP_ISSUE_REQUEST_NOTE:
		case AT_ATP_ISSUE_REQUEST_TICKLE:
			trp->tr_xmt = gbuf_cont(m);
			gbuf_cont(m) = NULL;
			goto l_notify;
		}
	} else {
		(AT_ATP_HDR(m))->bitmap = trp->tr_bitmap;

		if (trp->tr_retry != (unsigned int) ATP_INFINITE_RETRIES)
			trp->tr_retry--;
		atp_send(trp);
	}
}


/*
 *	atp_free frees up a request, cleaning up the queues and freeing
 *		the request packet
 *      always called at 'lock'
 */

void atp_free(trp)
register struct atp_trans *trp;
{	
	register struct atp_state *atp;
	register int i;
	
	dPrintf(D_M_ATP_LOW, D_L_TRACE,
		("atp_free: freeing trp 0x%x\n", (u_int) trp));


	if (trp->tr_state == TRANS_ABORTING) {
		ATP_Q_REMOVE(atp_trans_abort, trp, tr_list);
		trp->tr_state = TRANS_DONE;
	}
	else {
		if (trp->tr_tmo_func)
	        atp_untimout(atp_req_timeout, trp);

		atp = trp->tr_queue;
		ATP_Q_REMOVE(atp->atp_trans_wait, trp, tr_list);
	
		if (trp->tr_xmt) {
		  	gbuf_freem(trp->tr_xmt);
			trp->tr_xmt = NULL;
		}
		for (i = 0; i < 8; i++) {
		        if (trp->tr_rcv[i]) {
			        gbuf_freem(trp->tr_rcv[i]);
				trp->tr_rcv[i] = NULL;
			}
		}
		if (trp->tr_bdsp) {
			gbuf_freem(trp->tr_bdsp);
			trp->tr_bdsp = NULL;
		}
		
		if (trp->tr_rsp_wait) {
			trp->tr_state = TRANS_ABORTING;
			ATP_Q_APPEND(atp_trans_abort, trp, tr_list);
			wakeup(&trp->tr_event);
			return;
		}
	}
	
	atp_trans_free(trp);
} /* atp_free */


/*
 *	atp_send transmits a request packet by queuing it (if it isn't already) and
 *		scheduling the queue
 */

void atp_send(trp)
register struct atp_trans *trp;
{
	gbuf_t *m;
	struct atp_state *atp;

	dPrintf(D_M_ATP_LOW, D_L_OUTPUT, ("atp_send: trp=0x%x, loc=%d\n",
		(u_int) trp->tr_queue, trp->tr_local_socket));

	if ((atp = trp->tr_queue) != 0) {
	  if (trp->tr_state == TRANS_TIMEOUT) {
	    if ((m = gbuf_cont(trp->tr_xmt)) == NULL)
	        m = trp->tr_xmt;

	    /*
	     *	Now either release the transaction or start the timer
	     */
	    if (!trp->tr_retry && !trp->tr_bitmap && !trp->tr_xo) {
		m = (gbuf_t *)gbuf_copym(m);
		atp_x_done(trp);
	    } else {
		m = (gbuf_t *)gbuf_dupm(m);

		atp_timout(atp_req_timeout, trp, trp->tr_timeout);
	    }

	    if (m) {	
	        trace_mbufs(D_M_ATP_LOW, "  m", m);
		DDP_OUTPUT(m);
	    }
	}
  }
}


/*
 *	atp_reply sends all the available messages in the bitmap again
 *		by queueing us to the write service routine
 */

void atp_reply(rcbp)
register struct atp_rcb *rcbp;
{
	register struct atp_state *atp;
	register int i;

  if ((atp = rcbp->rc_queue) != 0) {
	for (i = 0; i < rcbp->rc_pktcnt; i++) {
		if (rcbp->rc_bitmap&atp_mask[i])
			rcbp->rc_snd[i] = 1;
		else
			rcbp->rc_snd[i] = 0;
	}
        if (rcbp->rc_rep_waiting == 0) {
	        rcbp->rc_state = RCB_SENDING;
	        rcbp->rc_rep_waiting = 1;
	        atp_send_replies(atp, rcbp);
	}
  }
}


/*
 *	The rcb timer just frees the rcb, this happens when we missed a release for XO
 */

void atp_rcb_timer()
{  
    register struct atp_rcb *rcbp;
	register struct atp_rcb *next_rcbp;
	extern   struct atp_rcb_qhead atp_need_rel;
	extern struct atp_trans *trp_tmo_rcb;
	struct timeval timenow;

l_again:
	getmicrouptime(&timenow);
	for (rcbp = atp_need_rel.head; rcbp; rcbp = next_rcbp) {
	        next_rcbp = rcbp->rc_tlist.next;

	        if ((timenow.tv_sec - rcbp->rc_timestamp) > 30) {
		        atp_rcb_free(rcbp);
		        goto l_again;
		}
	}
	atp_timout(atp_rcb_timer, trp_tmo_rcb, 10 * HZ);
}

atp_iocack(atp, m)
struct   atp_state *atp;
register gbuf_t *m;
{
	if (gbuf_type(m) == MSG_IOCTL)
		gbuf_set_type(m, MSG_IOCACK);
	if (gbuf_cont(m))
		((ioc_t *)gbuf_rptr(m))->ioc_count = gbuf_msgsize(gbuf_cont(m));
	else
		((ioc_t *)gbuf_rptr(m))->ioc_count = 0;

	if (atp->dflag)
		asp_ack_reply(atp->atp_gref, m);
	else
		atalk_putnext(atp->atp_gref, m);
}

atp_iocnak(atp, m, err)
struct   atp_state *atp;
register gbuf_t *m;
register int err;
{
	if (gbuf_type(m) == MSG_IOCTL)
		gbuf_set_type(m, MSG_IOCNAK);
	((ioc_t *)gbuf_rptr(m))->ioc_count = 0;
	((ioc_t *)gbuf_rptr(m))->ioc_error = err ? err : ENXIO;
	((ioc_t *)gbuf_rptr(m))->ioc_rval = -1;
	if (gbuf_cont(m)) {
		gbuf_freem(gbuf_cont(m));
		gbuf_cont(m) = NULL;
	}

	if (atp->dflag)
		asp_nak_reply(atp->atp_gref, m);
	else
		atalk_putnext(atp->atp_gref, m);
}

/*
 *	Generate a transaction id for a socket
 */
static int lasttid;
atp_tid(atp)
register struct atp_state *atp;
{
	register int i;
	register struct atp_trans *trp;

	for (i = lasttid;;) {
		i = (i+1)&0xffff;

		for (trp = atp->atp_trans_wait.head; trp; trp = trp->tr_list.next) {
		        if (trp->tr_tid == i)
			        break;
		}
		if (trp == NULL) {
			lasttid = i;
			return(i);
		}
	}
}
